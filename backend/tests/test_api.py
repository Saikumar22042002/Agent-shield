"""API-level tests: staging guard, connectivity (stubbed connector), import -> findings -> re-test
closure -> graph -> PDF, kill switch, audit chain. Runs fully offline."""
import json

from agentshield.connectors.base import ConnectorError, ConnectorOutput
from tests.conftest import ARN
from tests.test_ingest import garak_line


def test_rejects_non_staging_target(app_client):
    r = app_client.post("/api/targets", json={"name": "x", "harness_arn": ARN, "region": "us-east-1",
                                              "environment": "production", "owner_attestation": "We own this agent."})
    assert r.status_code == 422 and "staging" in r.json()["detail"]
    assert app_client.get("/api/audit", params={"action": "target.rejected"}).json()


def test_rejects_bad_arn_and_region_mismatch(app_client):
    base = {"name": "x", "region": "us-east-1", "environment": "staging", "owner_attestation": "We own this agent."}
    assert app_client.post("/api/targets", json=base | {"harness_arn": "arn:aws:s3:::bucket"}).status_code == 422
    assert app_client.post("/api/targets", json=base | {"harness_arn": ARN, "region": "eu-west-1"}).status_code == 422


class StubConnector:
    def __init__(self, fail=False):
        self.fail = fail
        self.sent = []

    def new_session_id(self):
        return "agentshield-" + "0" * 36

    def send(self, inp):
        self.sent.append(inp.text)
        if self.fail:
            raise ConnectorError("AccessDeniedException", "denied")
        return ConnectorOutput(text="I can help with IT tickets.", session_id=inp.session_id, latency_ms=640.0,
                               wall_ms=700.0, usage={"inputTokens": 20, "outputTokens": 8, "totalTokens": 28},
                               stop_reason="end_turn")


def test_connectivity_check_records_measurements(app_client, target, monkeypatch):
    from agentshield import connectivity
    from agentshield.config import get_settings

    stub = StubConnector()
    monkeypatch.setattr(connectivity, "build_connector", lambda *a, **k: stub)
    r = app_client.post(f"/api/targets/{target['id']}/check", headers={"X-Operator": "alice"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "connected" and body["latency_ms"] == 640.0 and body["usage"]["totalTokens"] == 28
    assert stub.sent == [get_settings().connectivity_message]  # only the fixed benign message is ever sent
    t = app_client.get("/api/targets").json()[0]
    assert t["status"] == "connected" and t["last_usage"]["totalTokens"] == 28
    acts = [a["action"] for a in app_client.get("/api/audit").json()]
    assert "connectivity.result" in acts and "connectivity.start" in acts
    assert app_client.get("/api/audit", params={"action": "connectivity"}).json()[0]["actor"] == "alice"


def test_connectivity_error_is_reported_not_raised(app_client, target, monkeypatch):
    from agentshield import connectivity

    monkeypatch.setattr(connectivity, "build_connector", lambda *a, **k: StubConnector(fail=True))
    body = app_client.post(f"/api/targets/{target['id']}/check").json()
    assert body["status"] == "error" and body["error"].startswith("AccessDeniedException")


def _import(client, run_id, tool, name, content):
    return client.post(f"/api/runs/{run_id}/imports", data={"tool": tool},
                       files={"file": (name, content.encode() if isinstance(content, str) else content)})


def test_full_import_retest_closure_graph_pdf(app_client, target):
    run = app_client.post("/api/runs", json={"target_id": target["id"], "label": "baseline"}).json()
    report = "\n".join([garak_line("g1", "probes.promptinject.X", [0.9]),
                        garak_line("g2", "probes.promptinject.X", [0.2]),
                        garak_line("g3", "probes.leakreplay.Y", [0.1])])
    r = _import(app_client, run["id"], "garak", "garak.report.jsonl", report)
    assert r.status_code == 201, r.text
    assert r.json()["stats"]["attempts_added"] == 3
    # trap hit on a passing attempt turns it into evidence of failure
    r = _import(app_client, run["id"], "traps", "traps.jsonl",
                '{"token_id":"tok-9","external_id":"g3","received_at":"2026-10-29T10:00:00Z","source":"10.0.0.5"}')
    assert r.status_code == 201, r.text
    # re-importing the same report is idempotent
    assert _import(app_client, run["id"], "garak", "again.jsonl", report).json()["stats"]["attempts_duplicate"] == 3

    findings = app_client.get(f"/api/runs/{run['id']}/findings").json()
    by_cat = {f["category"]: f for f in findings}
    assert set(by_cat) == {"T-03", "T-05"}
    assert by_cat["T-05"]["evidence"]["trap_hits"][0]["token_id"] == "tok-9"
    assert by_cat["T-03"]["fix"]
    summary = app_client.get(f"/api/runs/{run['id']}").json()["summary"]
    assert summary["coverage"]["T-03"]["fail"] == 1 and summary["coverage"]["T-01"]["total"] == 0
    assert summary["findings_open"] == 2 and summary["trap_hits_linked"] == 1

    g = app_client.get("/api/graph", params={"run_id": run["id"]}).json()
    assert any(e["kind"] == "failed" for e in g["edges"]) and any(n["id"] == "agent" for n in g["nodes"])

    # re-test: T-03 test now passes -> parent finding closes; T-05 not re-tested -> stays open
    retest = app_client.post("/api/runs", json={"target_id": target["id"], "label": "re-test",
                                                "parent_run_id": run["id"]}).json()
    assert _import(app_client, retest["id"], "garak", "retest.jsonl",
                   garak_line("g10", "probes.promptinject.X", [0.05])).status_code == 201
    findings = {f["category"]: f for f in app_client.get(f"/api/runs/{run['id']}/findings").json()}
    assert findings["T-03"]["status"] == "closed" and findings["T-03"]["closed_by_run_id"] == retest["id"]
    assert findings["T-05"]["status"] == "open"

    pdf = app_client.get(f"/api/runs/{run['id']}/report.pdf")
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"
    assert app_client.get("/api/audit/verify").json()["ok"] is True


def test_kill_switch_halts_runs_and_blocks_actions(app_client, target, monkeypatch):
    from agentshield import connectivity

    monkeypatch.setattr(connectivity, "build_connector", lambda *a, **k: StubConnector())
    run = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    r = app_client.post("/api/kill", json={"reason": "test stop"})
    assert r.json()["tripped"] and run["id"] in r.json()["halted_runs"]
    assert app_client.post(f"/api/targets/{target['id']}/check").status_code == 423
    assert _import(app_client, run["id"], "garak", "x.jsonl", garak_line("z", "p", [0.1])).status_code == 423
    assert app_client.post("/api/runs", json={"target_id": target["id"]}).status_code == 423
    app_client.post("/api/kill/reset")
    assert app_client.post(f"/api/targets/{target['id']}/check").status_code == 200
    assert app_client.get(f"/api/runs/{run['id']}").json()["status"] == "halted"  # stays halted after reset


def test_audit_chain_detects_tampering(app_client, target):
    from sqlalchemy import update

    from agentshield.db import session_scope
    from agentshield.models import AuditLog

    assert app_client.get("/api/audit/verify").json()["ok"]
    with session_scope() as s:
        s.execute(update(AuditLog).where(AuditLog.id == 2).values(payload={"tampered": True}))
    v = app_client.get("/api/audit/verify").json()
    assert v == {"ok": False, "first_bad_id": 2}


def test_events_persist_for_stream(app_client, target):
    from agentshield import events

    evs = events.since(0)
    assert any(e["type"] == "target.registered" for e in evs)
    assert json.dumps(evs, default=str)
