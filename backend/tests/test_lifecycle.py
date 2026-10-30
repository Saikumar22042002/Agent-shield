"""Run controls, provider registry/placeholders, persistence across restart, event history. Offline."""
from fastapi.testclient import TestClient

from tests.test_api import StubConnector, _import
from tests.test_ingest import garak_line


def _run(client, target):
    return client.post("/api/runs", json={"target_id": target["id"], "label": "lc"}).json()


def test_pause_resume_stop_lifecycle(app_client, target):
    run = _run(app_client, target)
    rid = run["id"]
    assert app_client.post(f"/api/runs/{rid}/pause").json()["status"] == "paused"
    assert app_client.post(f"/api/runs/{rid}/pause").status_code == 409  # duplicate
    r = _import(app_client, rid, "garak", "r.jsonl", garak_line("x1", "probes.dan.Y", [0.9]))
    assert r.status_code == 409 and "paused" in r.json()["detail"]
    assert app_client.post(f"/api/runs/{rid}/resume").json()["status"] == "open"
    assert _import(app_client, rid, "garak", "r.jsonl", garak_line("x1", "probes.dan.Y", [0.9])).status_code == 201
    stopped = app_client.post(f"/api/runs/{rid}/stop", json={"reason": "scope change"}).json()
    assert stopped["status"] == "stopped" and stopped["halt_reason"] == "scope change" and stopped["finished_at"]
    for action in ("resume", "pause", "stop", "complete"):
        assert app_client.post(f"/api/runs/{rid}/{action}").status_code == 409  # final state
    # findings and the PDF still work on a stopped run (read-only)
    assert app_client.get(f"/api/runs/{rid}/findings").json()
    assert app_client.get(f"/api/runs/{rid}/report.pdf").status_code == 200
    acts = [a["action"] for a in app_client.get("/api/audit", params={"run_id": rid}).json()]
    for a in ("run.pause", "run.resume", "run.stop"):
        assert a in acts
    statuses = [e["data"]["status"] for e in app_client.get("/api/events").json() if e["type"] == "run.status"]
    assert statuses == ["paused", "open", "stopped"]


def test_complete_from_paused_and_reviews_blocked_when_paused(app_client, target, monkeypatch):
    from agentshield import config, judge

    monkeypatch.setenv("DECISION_MODEL", "groq:test-model")
    config.get_settings.cache_clear()
    monkeypatch.setattr(judge, "decision_llm", lambda *a, **k: object())
    run = _run(app_client, target)
    _import(app_client, run["id"], "garak", "r.jsonl", garak_line("y1", "probes.dan.Y", []))
    app_client.post(f"/api/runs/{run['id']}/pause")
    assert app_client.post(f"/api/runs/{run['id']}/judge").status_code == 409
    assert app_client.post(f"/api/runs/{run['id']}/complete").json()["status"] == "complete"


def test_kill_halts_open_and_paused_runs_and_blocks_resume(app_client, target):
    a, b = _run(app_client, target), _run(app_client, target)
    app_client.post(f"/api/runs/{b['id']}/pause")
    halted = app_client.post("/api/kill", json={"reason": "drill"}).json()["halted_runs"]
    assert set(halted) == {a["id"], b["id"]}
    assert app_client.post(f"/api/runs/{a['id']}/resume").status_code in (409, 423)


def test_providers_registry_and_placeholder_connectivity(app_client):
    from agentshield.db import session_scope
    from agentshield.models import Target

    provs = {p["key"]: p for p in app_client.get("/api/providers").json()}
    assert provs["aws_agentcore"]["implemented"] is True
    assert provs["azure_ai_foundry"]["implemented"] is False and provs["gcp_agent"]["implemented"] is False
    with session_scope() as s:  # placeholder targets are stored in the same table
        t = Target(provider="azure_ai_foundry", name="Foundry agent", harness_arn="", region="", environment="staging",
                   config={"endpoint": "https://example.invalid", "agent_id": "a1"}, status="unsupported")
        s.add(t)
        s.flush()
        tid = t.id
    r = app_client.post(f"/api/targets/{tid}/check")
    assert r.status_code == 501 and "not implemented" in r.json()["detail"]
    listed = {t["id"]: t for t in app_client.get("/api/targets").json()}
    assert listed[tid]["provider_label"] == "Azure AI Foundry" and listed[tid]["provider_implemented"] is False
    assert not [a for a in app_client.get("/api/audit").json() if a["action"] == "connectivity.start"]  # nothing sent


def test_archived_target_cannot_be_checked(app_client, target, monkeypatch):
    from agentshield import connectivity
    from agentshield.db import session_scope
    from agentshield.models import Target

    monkeypatch.setattr(connectivity, "build_connector", lambda *a, **k: StubConnector())
    with session_scope() as s:
        s.get(Target, target["id"]).archived = True
    assert app_client.post(f"/api/targets/{target['id']}/check").status_code == 409


def test_aws_client_setup_error_is_recorded_not_raised(app_client, target, monkeypatch):
    from agentshield import connectivity

    def boom(*a, **k):
        raise RuntimeError("The config profile (missing) could not be found")

    monkeypatch.setattr(connectivity, "build_connector", boom)
    body = app_client.post(f"/api/targets/{target['id']}/check").json()
    assert body["status"] == "error" and "could not be found" in body["error"]


def test_state_and_kill_switch_survive_restart(app_client, target):
    from agentshield.app import app
    from agentshield.safety import KILL

    run = _run(app_client, target)
    app_client.post(f"/api/runs/{run['id']}/pause")
    app_client.post("/api/kill", json={"reason": "before restart"})
    KILL.reset()  # simulate a fresh process: in-memory flag gone
    with TestClient(app) as fresh:  # lifespan runs again against the same SQLite file
        assert fresh.get("/api/kill").json()["tripped"] is True
        assert fresh.get(f"/api/runs/{run['id']}").json()["status"] == "halted"
        assert [t["id"] for t in fresh.get("/api/targets").json()] == [target["id"]]
        assert fresh.get("/api/audit/verify").json()["ok"] is True
        fresh.post("/api/kill/reset")
    KILL.reset()
    with TestClient(app) as again:
        assert again.get("/api/kill").json()["tripped"] is False


def test_migration_adds_columns_to_pre_existing_db(tmp_path):
    import sqlite3

    from agentshield.db import init_engine

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)  # a v1-era targets table without provider/config/archived
    con.executescript("""
        CREATE TABLE schema_version (version INTEGER NOT NULL); INSERT INTO schema_version VALUES (2);
        CREATE TABLE targets (id INTEGER PRIMARY KEY, name VARCHAR(200));
        INSERT INTO targets (id, name) VALUES (1, 'legacy');""")
    con.close()
    init_engine(f"sqlite:///{db.as_posix()}")
    con = sqlite3.connect(db)
    cols = {r[1] for r in con.execute("PRAGMA table_info(targets)")}
    assert {"provider", "config", "archived"} <= cols
    assert con.execute("SELECT provider, archived FROM targets WHERE id = 1").fetchone() == ("aws_agentcore", 0)
