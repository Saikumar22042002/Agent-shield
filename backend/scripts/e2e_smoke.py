"""End-to-end check against a real AgentShield server process, over HTTP, on a throwaway database.

  python scripts/e2e_smoke.py            (from backend/, with the API venv)

Starts uvicorn on a free port, then runs the operator workflow the console drives: register the local stub, check
connectivity, document a profile, open a run, exchange the greeting, draft and approve a plan, execute it with the
real PyRIT and garak adapters under the Deep Agents coordinator, inspect cases, invocations, the run audit and the
live stream, import sample data (no findings on a stub), engage and reset the emergency stop, export the PDF and
verify the audit chain. Exits non-zero on the first failed check. Never touches data/agentshield.db.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
SECRET = "AKIAABCDEFGHIJKLMNOP"
checks = 0


def ok(cond: bool, what: str) -> None:
    global checks
    if not cond:
        print(f"FAIL  {what}")
        sys.exit(1)
    checks += 1
    print(f"ok    {what}")


class Api:
    def __init__(self, base: str):
        self.base = base

    def call(self, method: str, path: str, body=None, raw: bool = False, headers: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "X-Operator": "e2e-operator",
                                              **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                content = r.read()
                return r.status, (content if raw else json.loads(content or b"null"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.call("POST", path, body if body is not None else {}, **kw)

    def put(self, path, body):
        return self.call("PUT", path, body)

    def multipart(self, path: str, tool: str, name: str, content: bytes):
        boundary = "----agentshielde2e"
        parts = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"tool\"\r\n\r\n{tool}\r\n"
                 f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                 "Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(self.base + path, data=parts, method="POST",
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                                              "X-Operator": "e2e-operator"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())


def wait_done(api: Api, rid: str, timeout: float = 300) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        _, st = api.get(f"/api/runs/{rid}/assessment")
        if st["status"] not in ("queued", "running"):
            return st
        time.sleep(0.5)
    raise SystemExit(f"FAIL  execution of {rid} did not finish in {timeout}s")


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="agentshield-e2e-"))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    env = os.environ | {
        "DATABASE_URL": f"sqlite:///{(tmp / 'e2e.db').as_posix()}", "REPORTS_DIR": str(tmp / "reports"),
        "EVIDENCE_DIR": str(tmp / "evidence"), "TARGET_HARNESS_ARN": "", "PORT": str(port),
        "COORDINATOR_MODEL": "deterministic", "AUTH_TOKENS": "", "CONNECTIVITY_MIN_INTERVAL_S": "0",
        "ASSESSMENT_PROVIDERS": "local_stub,local_model",
        "CONNECTIVITY_MESSAGE": f"Hello from the e2e check, key {SECRET}. Reply briefly."}
    log = open(tmp / "server.log", "wb")
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "agentshield.app:app", "--host", "127.0.0.1",
                               "--port", str(port)], cwd=str(BACKEND), env=env, stdout=log, stderr=subprocess.STDOUT)
    api = Api(f"http://127.0.0.1:{port}")
    try:
        for _ in range(120):
            try:
                if api.get("/api/health")[0] == 200:
                    break
            except (urllib.error.URLError, ConnectionError):
                pass
            time.sleep(0.5)
        status, health = api.get("/api/health")
        ok(status == 200 and health["audit_chain_ok"], f"server up on :{port}, audit chain intact")
        _, eng = api.get("/api/engines")
        ok({"pyrit", "garak"} <= set(eng["adapters"]), f"adapters registered at startup: {eng['adapters']}")

        status, t = api.post("/api/targets", {"provider": "local_stub", "name": "E2E stub", "environment": "staging",
                                              "owner_attestation": "Built-in development stub for the e2e check."})
        ok(status == 201, "local stub target registered")
        status, _ = api.post("/api/targets", {"provider": "local_stub", "name": "prod", "environment": "production",
                                              "owner_attestation": "Should be refused by the staging guard."})
        ok(status == 422, "production target refused")
        _, chk = api.post(f"/api/targets/{t['id']}/check")
        ok(chk["status"] == "connected" and chk["provenance"] == "local-stub", "connectivity check through the gateway")
        status, prof = api.put(f"/api/targets/{t['id']}/profile", {"role": "IT service desk assistant",
                                                                   "forbidden_actions": ["reset another user's password"]})
        ok(status == 200 and prof["documented"], "target profile documented")
        status, t2 = api.call("PUT", f"/api/targets/{t['id']}", {"name": "E2E stub (edited)"})
        ok(status == 200 and t2["name"] == "E2E stub (edited)", "target edited")

        status, run = api.post("/api/runs", {"target_id": t["id"], "label": "e2e"})
        ok(status == 201, f"run {run['id']} opened")
        rid = run["id"]
        _, ex = api.post(f"/api/runs/{rid}/exchange")
        ok(ex["status"] == "connected", "benign greeting exchanged inside the run")

        status, opts = api.get(f"/api/runs/{rid}/plan-options")
        ok(status == 200 and any(o["id"] == "PLUMB-GARAK" and o["executable"] for o in opts["techniques"]),
           "plan options list executable techniques")
        status, plan = api.post(f"/api/runs/{rid}/plans", {"techniques": ["PLUMB-PYRIT", "PLUMB-GARAK"],
                                                           "benign_prompt": "Hello. Please reply in one sentence."})
        ok(status == 201 and len(plan["content"]["cases"]) == 2, "plan v1 drafted (PyRIT + garak)")
        status, _ = api.post(f"/api/runs/{rid}/assessment/start")
        ok(status == 409, "execution refused before approval")
        status, appr = api.post(f"/api/runs/{rid}/plans/{plan['version']}/approve")
        ok(status == 200 and appr["status"] == "approved", "plan approved")
        status, _ = api.post(f"/api/runs/{rid}/assessment/start")
        ok(status == 200, "execution started")
        st = wait_done(api, rid)
        ok(st["status"] == "completed", f"execution completed ({st['reason'] or 'no stop reason'})")
        cases = {c["id"]: c for c in st["cases"]}
        ok(cases["C01"]["result"]["source_verdict"] == "UNDETERMINED", "PyRIT case: PyRIT outcome recorded verbatim")
        ok(cases["C02"]["result"]["verdict"] == "pass", "garak case: always.Pass detector verdict recorded")
        coord = st["assessment"]["coordinator"]
        ok(coord["framework"] == "deepagents" and coord["steps"] > 0, f"Deep Agents coordinator ran ({coord['mode']})")
        _, inv = api.get(f"/api/runs/{rid}/invocations")
        garak_rows = [i for i in inv if i["engine"] == "garak"]
        ok([i["status"] for i in inv if i["engine"] == "pyrit"] == ["ok"], "PyRIT prompt went through the gateway")
        ok(sum(i["status"] == "ok" for i in garak_rows) == 5 and sum(i["status"] == "refused" for i in garak_rows) == 3,
           "garak: 5 prompts answered, 3 refused at the technique budget")

        _, tl = api.get(f"/api/runs/{rid}/timeline")
        types = {i["type"] for i in tl["items"]}
        ok({"coordinator.step", "assessment.case", "scorer.result", "gateway.refused"} <= types,
           "timeline shows coordinator decisions, cases, scores and refusals")
        replies = [i for i in tl["items"] if i["kind"] == "message" and i["role"] == "target"]
        ok(replies and all(r["meta"].get("session_id") for r in replies), "every reply carries its session id")
        _, ra = api.get(f"/api/audit?run_id={rid}&limit=1000")
        ok({"plan.approve", "assessment.start", "assessment.completed", "gateway.invoke"} <= {a["action"] for a in ra},
           "run-scoped audit trail")
        ok(SECRET not in json.dumps(ra) and SECRET not in json.dumps(tl), "credential-shaped string redacted everywhere")

        fixture = BACKEND.parent / "data" / "qa" / "fixtures" / "qa-garak.report.jsonl"
        sample = fixture.read_bytes() if fixture.exists() else (json.dumps({
            "entry_type": "attempt", "uuid": "s1", "status": 2, "probe_classname": "probes.promptinject.X",
            "prompt": {"turns": [{"role": "user", "content": "x"}]}, "outputs": [{"text": "y"}],
            "detector_results": {"d": [0.9]}}) + "\n").encode()
        status, imp = api.multipart(f"/api/runs/{rid}/imports", "garak", "qa-garak.report.jsonl", sample)
        ok(status == 201 and "sample data" in imp["warnings"][0], "sample import on a stub run is flagged")
        _, findings = api.get(f"/api/runs/{rid}/findings")
        ok(findings == [], "a stub run produces no findings")

        status, k = api.post("/api/kill", {"reason": "e2e drill"})
        ok(status == 200 and rid in k["halted_runs"], "emergency stop halts the run")
        status, _ = api.post("/api/runs", {"target_id": t["id"]})
        ok(status == 423, "new runs blocked while stopped")
        status, _ = api.post("/api/kill/reset")
        ok(status == 200, "emergency stop reset")

        status, pdf = api.get(f"/api/runs/{rid}/report.pdf", raw=True)
        ok(status == 200 and pdf.startswith(b"%PDF-"), f"PDF report exported ({len(pdf)} bytes)")
        _, ver = api.get("/api/audit/verify")
        ok(ver["ok"] is True, "audit hash chain verifies")
        print(f"\nPASS  {checks} end-to-end checks against a live server")
    finally:
        server.terminate()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()
        log.close()


if __name__ == "__main__":
    main()
