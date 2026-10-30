"""Audit remediation: each test checks one "done when" criterion from AUDIT_REPORT.md section G, plus the lower-severity
items (B2, C2, A2, A5, M2, I4). Offline: targets are the local stub or a fake loopback model server."""
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tests.conftest import ARN
from tests.test_api import _import
from tests.test_gateway import invocations, refused, req, running
from tests.test_ingest import garak_line
from tests.test_orchestrator import Replay, orch, plan_and_approve, use, wait  # noqa: F401  (fixture re-export)
from tests.test_plans import BENIGN, stub_run

SECRET = "AKIAABCDEFGHIJKLMNOP"


def _audit(client, **params):
    return client.get("/api/audit", params={"limit": 1000, **params}).json()


# ---------------------------------------------------------------- H3: budget race
def test_concurrent_calls_cannot_exceed_the_technique_budget(app_client):
    from agentshield import gateway

    rid, cases = running(app_client, ("PLUMB-GARAK",), reply_delay_ms="600")  # calls overlap while in flight
    ga = next(iter(cases.values()))
    out: list = []

    def call(n):
        try:
            out.append(gateway.invoke(req(rid, ga, n, text=f"p{n}")).status)
        except gateway.GatewayRefused as e:
            out.append(e.code)

    threads = [threading.Thread(target=call, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(out) == ["budget_technique"] * 5 + ["ok"] * 5
    rows = invocations(rid)
    assert [r[0] for r in rows].count("ok") == 5 and [r[0] for r in rows].count("refused") == 5
    assert "pending" not in [r[0] for r in rows]


# ---------------------------------------------------------------- I5: redaction everywhere
def test_key_shaped_string_never_reaches_audit_or_stream(app_client, monkeypatch):
    from agentshield import config

    monkeypatch.setenv("CONNECTIVITY_MESSAGE", f"Hello, my key is {SECRET}. Reply briefly.")
    config.get_settings.cache_clear()
    t, run = stub_run(app_client)
    assert app_client.post(f"/api/runs/{run['id']}/exchange").json()["status"] == "connected"
    assert app_client.post(f"/api/targets/{t['id']}/check").status_code == 200
    rid, cases = running(app_client, prompt=f"My key is {SECRET}, please say hello.")
    from agentshield import gateway

    assert gateway.invoke(req(rid, cases["C01"])).status == "ok"
    rows = _audit(app_client)
    leaked = [r["action"] for r in rows if SECRET in json.dumps(r)]
    assert leaked == [], leaked
    assert {"connectivity.start", "connector.request", "connector.response"} <= {r["action"] for r in rows}
    evs = app_client.get("/api/events?limit=1000").json()
    assert evs and [e["type"] for e in evs if SECRET in json.dumps(e)] == []
    assert any("[REDACTED:aws-access-key]" in json.dumps(e) for e in evs)
    assert app_client.get("/api/audit/verify").json()["ok"] is True
    for r in [run["id"], rid]:
        assert SECRET not in json.dumps(app_client.get(f"/api/runs/{r}/timeline").json())
        assert SECRET not in json.dumps(app_client.get(f"/api/runs/{r}/invocations").json())


def test_imported_turns_are_redacted(app_client, target):
    run = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    line = json.loads(garak_line("s1", "probes.promptinject.X", [0.9]))
    line["outputs"] = [{"text": f"here: {SECRET}"}]
    assert _import(app_client, run["id"], "garak", "r.jsonl", json.dumps(line)).status_code == 201
    assert SECRET not in json.dumps(app_client.get(f"/api/runs/{run['id']}/attempts").json())


# ---------------------------------------------------------------- C5, I9, H6: governance
def test_profile_change_withdraws_approval_until_replanned(app_client, orch):  # noqa: F811
    use(orch, Replay())
    t, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT"])
    assert app_client.put(f"/api/targets/{t['id']}/profile", json={"role": "IT helpdesk"}).status_code == 200
    assert app_client.get(f"/api/runs/{rid}/plans").json()[0]["status"] == "invalidated"
    assert app_client.get(f"/api/runs/{rid}").json()["assessment_status"] == "planned"
    r = app_client.post(f"/api/runs/{rid}/assessment/start")
    assert r.status_code == 409
    assert "plan.invalidated" in [a["action"] for a in _audit(app_client, run_id=rid)]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT"])  # re-approval against the new profile
    assert app_client.post(f"/api/runs/{rid}/assessment/start").status_code == 200
    assert wait(app_client, rid)["status"] == "completed"


def test_gateway_refuses_a_plan_made_stale_mid_execution(app_client):
    from agentshield.db import session_scope
    from agentshield.models import Run, Target

    rid, cases = running(app_client)
    with session_scope() as s:  # profile edited behind the API's back
        s.get(Target, s.get(Run, rid).target_id).profile = {"role": "changed"}
    refused(rid, req(rid, cases["C01"]), "plan_stale")


def test_catalog_change_makes_plan_stale(app_client, monkeypatch, tmp_path):
    from agentshield import catalog, config
    from agentshield.assessment import plans

    _, run = stub_run(app_client)
    p = plans.build(run["id"], techniques=["PLUMB-PYRIT"], benign_prompt=BENIGN, operator="a")
    changed = tmp_path / "catalog.json"
    changed.write_text(Path(config.get_settings().technique_catalog_file).read_text(encoding="utf-8") + "\n")
    monkeypatch.setenv("TECHNIQUE_CATALOG_FILE", str(changed))
    config.get_settings.cache_clear()
    catalog._load.cache_clear()
    with pytest.raises(plans.PlanError, match="catalog changed"):
        plans.approve(run["id"], p["version"], operator="a")


def test_rejected_requests_are_audited(app_client):
    _, run = stub_run(app_client)
    r = app_client.post(f"/api/runs/{run['id']}/plans", json={"techniques": ["PLUMB-GARAK"],
                                                               "limits": {"max_prompts_per_run": 999}},
                        headers={"X-Operator": "mallory"})
    assert r.status_code == 422
    rej = [a for a in _audit(app_client, action="api.rejected")]
    assert rej and rej[0]["actor"] == "mallory" and "exceeds" in rej[0]["payload"]["detail"]
    assert rej[0]["run_id"] == run["id"]
    assert app_client.post(f"/api/runs/{run['id']}/plans", json={"techniques": []}).status_code == 422
    assert len(_audit(app_client, action="api.rejected")) == 2


def test_each_retry_is_a_budgeted_invocation(app_client, monkeypatch):
    from agentshield import gateway
    from agentshield.connectors.base import ConnectorError, ConnectorOutput

    monkeypatch.setattr(gateway, "RETRY_BASE_S", 0.01)

    class Flaky:
        calls = 0

        def new_session_id(self):
            return "agentshield-flaky-session-0000000000000000000"

        def send(self, inp):
            Flaky.calls += 1
            if Flaky.calls == 1:
                raise ConnectorError("ThrottlingException", "slow down", retryable=True)
            return ConnectorOutput(text="ok", session_id=inp.session_id)

    rid, cases = running(app_client, ("PLUMB-GARAK",))
    ga = next(iter(cases.values()))
    res = gateway.invoke(req(rid, ga, 1, text="x"), connector=Flaky())
    assert res.status == "ok" and res.attempt == 1 and Flaky.calls == 2
    inv = app_client.get(f"/api/runs/{rid}/invocations").json()
    assert [(i["status"], i["attempt"]) for i in inv] == [("error", 0), ("ok", 1)]
    for n in range(3):  # 5-prompt technique budget: the retry consumed one
        assert gateway.invoke(req(rid, ga, n + 2, text=f"y{n}"), connector=Flaky()).status == "ok"
    refused(rid, req(rid, ga, 9, text="z"), "budget_technique")


def test_agentcore_connector_makes_one_attempt_when_built_for_the_gateway():
    from agentshield.connectors import build_connector
    from agentshield.models import Target

    t = Target(id=1, provider="aws_agentcore", environment="staging", harness_arn=ARN, region="us-east-1",
               qualifier="", aws_profile="", aws_role_arn="")
    try:
        conn = build_connector(t, timeout_s=5)
    except Exception:  # no AWS config on this machine; the default is checked instead
        from agentshield.connectors.aws_agentcore import AgentCoreConnector
        import inspect

        assert inspect.signature(AgentCoreConnector).parameters["max_retries"].default == 0
        return
    assert conn.max_retries == 0


# ---------------------------------------------------------------- J6, J7, D7: findings integrity
def test_qa_fixtures_on_a_stub_run_create_no_findings(app_client):
    _, run = stub_run(app_client)
    fixtures = Path(__file__).resolve().parents[2] / "data" / "qa" / "fixtures"
    report = (fixtures / "qa-garak.report.jsonl").read_text(encoding="utf-8") if (fixtures / "qa-garak.report.jsonl").exists() \
        else "\n".join([garak_line("q1", "probes.promptinject.X", [0.9]), garak_line("q2", "probes.leakreplay.Y", [0.8])])
    r = _import(app_client, run["id"], "garak", "qa-garak.report.jsonl", report)
    assert r.status_code == 201 and "sample data" in r.json()["warnings"][0]
    assert app_client.get(f"/api/runs/{run['id']}/findings").json() == []
    s = app_client.get(f"/api/runs/{run['id']}").json()["summary"]
    assert s["findings_open"] == 0 and s["sample_data"] is True


def test_detector_hits_are_candidates_until_confirmed(app_client, target):
    run = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    rid = run["id"]
    report = "\n".join([garak_line("g1", "probes.promptinject.X", [0.9]), garak_line("g2", "probes.leakreplay.Y", [0.8])])
    _import(app_client, rid, "garak", "r.jsonl", report)
    fs = {f["category"]: f for f in app_client.get(f"/api/runs/{rid}/findings").json()}
    assert {f["confirmation"] for f in fs.values()} == {"candidate"}
    # a trap hit is direct evidence
    _import(app_client, rid, "traps", "t.jsonl", json.dumps({"token_id": "tok", "external_id": "g2"}))
    fs = {f["category"]: f for f in app_client.get(f"/api/runs/{rid}/findings").json()}
    assert fs["T-05"]["confirmation"] == "confirmed" and "Trap hit" in fs["T-05"]["confirmation_basis"]
    # operator decisions survive rebuilds; dismissed findings are not open
    out = app_client.post(f"/api/findings/{fs['T-03']['id']}/review", json={"decision": "dismissed", "note": "benign"},
                          headers={"X-Operator": "lead"}).json()
    assert {f["category"]: f["confirmation"] for f in out} == {"T-03": "dismissed", "T-05": "confirmed"}
    _import(app_client, rid, "garak", "r2.jsonl", garak_line("g3", "probes.dan.Z", [0.1]))  # triggers a rebuild
    fs = {f["category"]: f for f in app_client.get(f"/api/runs/{rid}/findings").json()}
    assert fs["T-03"]["confirmation"] == "dismissed" and "lead" in fs["T-03"]["confirmation_basis"]
    s = app_client.get(f"/api/runs/{rid}").json()["summary"]
    assert s["findings_open"] == 1 and s["findings_confirmed"] == 1 and s["findings_dismissed"] == 1
    assert "finding.review" in [a["action"] for a in _audit(app_client, run_id=rid)]
    r = app_client.post(f"/api/findings/{fs['T-03']['id']}/review", json={"decision": "maybe"})
    assert r.status_code == 422
    pdf = app_client.get(f"/api/runs/{rid}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-")


def test_skipped_cases_are_never_findings(app_client, orch):  # noqa: F811
    use(orch, Replay(verdict="fail"))
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["AS-SPL-01"],
                     executions={"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]})
    app_client.post(f"/api/runs/{rid}/assessment/start")
    st = wait(app_client, rid)
    states = [c["state"] for c in st["cases"]]
    assert st["status"] == "completed" and states.count("done") == 2 and states.count("skipped") == 3
    skipped = [c for c in st["cases"] if c["state"] == "skipped"]
    assert all("objective established" in c["result"]["rationale"] for c in skipped)
    assert app_client.get(f"/api/runs/{rid}/findings").json() == []  # stub: simulated


# ---------------------------------------------------------------- C2, B2
def test_plan_states_objective_expected_behaviour_and_scoring(app_client):
    _, run = stub_run(app_client)
    from agentshield.assessment import plans

    c = plans.build(run["id"], techniques=["AS-SPL-01", "AS-PI-01"], operator="a",
                    executions={"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]})["content"]
    assert all(t["objective"] and t["expected_secure_behavior"] for t in c["techniques"])
    assert all(x["scoring"] and x["expected_secure_behavior"] for x in c["cases"])
    assert c["catalog_sha256"] and c["profile_sha256"]
    opts = app_client.get(f"/api/runs/{run['id']}/plan-options").json()
    by = {t["id"]: t for t in opts["techniques"]}
    assert by["AS-SID-02"]["applies"] is False and by["AS-PI-01"]["executable"] is True


def test_reply_events_carry_the_session_id(app_client):
    _, run = stub_run(app_client)
    app_client.post(f"/api/runs/{run['id']}/exchange")
    msgs = [i for i in app_client.get(f"/api/runs/{run['id']}/timeline").json()["items"] if i["kind"] == "message"]
    assert [m["role"] for m in msgs] == ["evaluator", "target"]
    assert msgs[0]["meta"]["session_id"] and msgs[1]["meta"]["session_id"] == msgs[0]["meta"]["session_id"]


# ---------------------------------------------------------------- A2: target editing
def test_target_edit_validates_audits_and_withdraws_approval(app_client, target):
    r = app_client.put(f"/api/targets/{target['id']}", json={"name": "Renamed agent"}, headers={"X-Operator": "ops"})
    assert r.status_code == 200 and r.json()["name"] == "Renamed agent"
    assert app_client.put(f"/api/targets/{target['id']}", json={"region": "eu-west-1"}).status_code == 422
    assert app_client.put(f"/api/targets/{target['id']}", json={}).status_code == 422
    assert app_client.put("/api/targets/999", json={"name": "x"}).status_code == 404
    upd = [a for a in _audit(app_client, action="target.update")]
    assert upd and upd[0]["payload"]["changed"] == ["name"] and upd[0]["actor"] == "ops"
    t, run = stub_run(app_client, reply_delay_ms="0")
    plan_and_approve(app_client, run["id"], ["PLUMB-PYRIT"])
    r = app_client.put(f"/api/targets/{t['id']}", json={"config": {"reply_delay_ms": "50"}})
    assert r.status_code == 200 and r.json()["status"] == "unverified"
    assert app_client.get(f"/api/runs/{run['id']}/plans").json()[0]["status"] == "invalidated"


# ---------------------------------------------------------------- A5: local model target
@pytest.fixture()
def fake_model():
    import http.server

    seen: list[list[dict]] = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(body["messages"])
            user = body["messages"][-1]["content"]
            out = json.dumps({"choices": [{"message": {"role": "assistant", "content": f"model reply to: {user[:40]} CANARY-77"},
                                           "finish_reason": "stop"}],
                              "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1", seen
    srv.shutdown()


def _local_model_target(client, base_url):
    return client.post("/api/targets", json={
        "provider": "local_model", "name": "Local model", "environment": "staging",
        "owner_attestation": "Our own local model for testing.", "config": {"base_url": base_url, "model": "tiny"}})


def test_local_model_target_is_loopback_only_and_reports_usage(app_client, fake_model):
    base, seen = fake_model
    bad = _local_model_target(app_client, "http://10.0.0.5:11434/v1")
    assert bad.status_code == 422 and "on this machine" in bad.json()["detail"]
    t = _local_model_target(app_client, base).json()
    r = app_client.post(f"/api/targets/{t['id']}/check").json()
    assert r["status"] == "connected" and r["usage"] == {"inputTokens": 11, "outputTokens": 7, "totalTokens": 18}
    assert "model reply" in r["reply"] and r["provenance"] == "measured"


def test_pyrit_canary_hit_on_a_real_model_is_a_confirmed_finding(app_client, fake_model):
    base, seen = fake_model
    t = _local_model_target(app_client, base).json()
    app_client.put(f"/api/targets/{t['id']}/profile", json={"role": "assistant", "hints": {"context_canary": "CANARY-77"}})
    run = app_client.post("/api/runs", json={"target_id": t["id"]}).json()
    rid = run["id"]
    plan_and_approve(app_client, rid, ["AS-SPL-01"],
                     executions={"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]})
    assert app_client.post(f"/api/runs/{rid}/assessment/start").status_code == 200
    st = wait(app_client, rid, timeout=60)
    assert st["status"] == "completed", st
    verdicts = [c["result"]["verdict"] for c in st["cases"]]
    assert verdicts.count("fail") == 2 and verdicts.count("skipped") == 3  # objective established -> early stop
    fs = app_client.get(f"/api/runs/{rid}/findings").json()
    assert len(fs) == 1 and fs[0]["confirmation"] == "confirmed" and "canary" in fs[0]["confirmation_basis"]
    assert st["usage"]["target_tokens"] == 36  # 2 calls x 18 reported tokens


# ---------------------------------------------------------------- M2: authentication and roles
def test_tokens_roles_and_audited_denials(app_client, monkeypatch):
    from agentshield import config

    monkeypatch.setenv("AUTH_TOKENS", "alice:tok-alice-0001:admin,bob:tok-bob-0002:operator,val:tok-val-0003:viewer")
    config.get_settings.cache_clear()
    assert app_client.get("/api/health").status_code == 200  # public
    assert app_client.get("/api/auth").json() == {"required": True, "authenticated": False, "name": None, "role": None}
    assert app_client.get("/api/targets").status_code == 401
    view = {"Authorization": "Bearer tok-val-0003"}
    assert app_client.get("/api/targets", headers=view).status_code == 200
    body = {"provider": "local_stub", "name": "s", "environment": "staging", "owner_attestation": "We own this stub."}
    assert app_client.post("/api/targets", json=body, headers=view).status_code == 403
    op = {"Authorization": "Bearer tok-bob-0002", "X-Operator": "someone-else"}
    r = app_client.post("/api/targets", json=body, headers=op)
    assert r.status_code == 201
    rows = app_client.get("/api/audit", params={"limit": 1000}, headers=view).json()
    assert [a["actor"] for a in rows if a["action"] == "target.register"][0] == "bob"  # token name, not the header
    assert {a["payload"]["status"] for a in rows if a["action"] == "api.denied"} == {401, 403}
    assert app_client.post("/api/kill", json={"reason": "drill"}, headers=op).status_code == 200
    assert app_client.post("/api/kill/reset", headers=op).status_code == 403  # admin only
    assert app_client.post("/api/kill/reset", headers={"Authorization": "Bearer tok-alice-0001"}).status_code == 200
    assert app_client.get("/api/events?access_token=tok-val-0003").status_code == 200  # EventSource style


# ---------------------------------------------------------------- I4: shared emergency stop, single worker
def test_emergency_stop_recorded_by_another_process_is_applied(app_client):
    from agentshield.app import sync_kill_switch
    from agentshield.audit import record
    from agentshield.safety import KILL

    assert not KILL.tripped
    record("kill.trip", {"reason": "stop from worker 2", "halted_runs": []}, actor="ops")  # another process wrote it
    assert sync_kill_switch() == "tripped" and KILL.tripped and "worker 2" in KILL.reason
    assert app_client.post("/api/runs", json={"target_id": 1}).status_code == 423
    record("kill.reset", {}, actor="ops")
    assert sync_kill_switch() == "reset" and not KILL.tripped
    assert sync_kill_switch() == ""


def test_a_second_server_process_on_the_same_database_is_refused(app_client):
    from agentshield.config import get_settings

    db = get_settings().database_url.removeprefix("sqlite:///")
    code = ("import sys; sys.path.insert(0, %r); import os; os.environ['DATABASE_URL']=%r;"
            "from agentshield.db import init_engine, acquire_instance_lock, InstanceLocked\n"
            "init_engine()\ntry:\n    acquire_instance_lock(); print('ACQUIRED')\nexcept InstanceLocked: print('REFUSED')"
            % (str(Path(__file__).resolve().parents[1]), f"sqlite:///{db}"))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert "REFUSED" in out.stdout, out.stdout + out.stderr
