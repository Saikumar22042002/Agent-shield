"""Real framework execution: the PyRIT adapter (in-process, PyRIT 1.1.0), the garak adapter (garak 0.17.1 subprocess in
backend/.venv-garak posting to the gateway endpoint over HTTP) and the Deep Agents coordinator. The target is the
local stub, so every result is plumbing or simulated and none becomes a finding. Offline."""
import hashlib
import json
import socket
import threading
import time
from pathlib import Path

import pytest

from tests.test_gateway import running
from tests.test_orchestrator import Replay, orch, plan_and_approve, use, wait, wait_for  # noqa: F401
from tests.test_plans import BENIGN, stub_run


@pytest.fixture()
def real_adapters(app_client):
    """The adapters registered at startup (not the test Replay adapter)."""
    from agentshield.assessment import orchestrator

    assert {"pyrit", "garak"} <= set(orchestrator.ADAPTERS)
    orchestrator.reset_for_tests()
    yield orchestrator
    orchestrator.reset_for_tests()


def _attempt(rid):
    from agentshield.db import session_scope
    from agentshield.models import TestAttempt

    with session_scope() as s:
        rows = s.query(TestAttempt).filter_by(run_id=rid, provenance="local-execution").order_by(TestAttempt.id).all()
        s.expunge_all()
        return rows


# ---------------------------------------------------------------- F1: PyRIT
def test_pyrit_plumbing_run_completes_through_the_api(app_client, real_adapters):
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT"])
    assert app_client.post(f"/api/runs/{rid}/assessment/start").status_code == 200
    st = wait(app_client, rid, timeout=60)
    assert st["status"] == "completed", st
    (a,) = _attempt(rid)
    assert a.engine == "pyrit" and a.source_verdict == "UNDETERMINED" and a.verdict == "inconclusive"
    assert a.engine_version == "1.1.0" and a.evidence["kind"] == "plumbing"
    data = Path(a.evidence["file"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == a.evidence["sha256"]
    doc = json.loads(data)
    assert doc["attack_results"][0]["outcome"] == "UNDETERMINED"
    assert [p["role"] for p in doc["message_pieces"]] == ["user", "assistant"]
    inv = app_client.get(f"/api/runs/{rid}/invocations").json()
    assert [(i["engine"], i["status"], i["prompt"]) for i in inv] == [("pyrit", "ok", BENIGN)]
    assert a.invocation_ids == [inv[0]["id"]]
    assert st["assessment"]["coordinator"]["framework"] == "deepagents"
    # the exported file is a valid AgentShield PyRIT import
    from agentshield.ingest import pyrit as pyrit_parser

    parsed = pyrit_parser.parse(data, fail_threshold=0.5)
    assert parsed.attempts[0].verdict == "inconclusive"


def test_pyrit_multi_turn_keeps_one_isolated_session(app_client, real_adapters):
    _, run = stub_run(app_client)
    rid = run["id"]
    turns = ["Hi.", "What can you help with?", "Thanks."]
    r = app_client.post(f"/api/runs/{rid}/plans", json={"techniques": ["PLUMB-PYRIT-MT"], "benign_turns": turns})
    app_client.post(f"/api/runs/{rid}/plans/{r.json()['version']}/approve")
    app_client.post(f"/api/runs/{rid}/assessment/start")
    assert wait(app_client, rid, timeout=60)["status"] == "completed"
    inv = app_client.get(f"/api/runs/{rid}/invocations").json()
    assert [i["prompt"] for i in inv] == turns and [i["turn"] for i in inv] == [1, 2, 3]
    assert len({i["session_id"] for i in inv}) == 1
    assert "Session turn 3" in inv[-1]["response"]
    (a,) = _attempt(rid)
    assert a.source_detail["executed_turns"] == 3 and len(a.turns) == 6


def test_pyrit_input_that_differs_from_the_plan_is_refused(app_client):
    from agentshield.assessment import pyrit_adapter
    from agentshield.assessment.orchestrator import CaseContext
    from agentshield.gateway import GatewayRefused

    rid, cases = running(app_client, ("PLUMB-PYRIT",))
    case = dict(cases["C01"]) | {"turns": ["A prompt nobody approved."]}
    ctx = CaseContext(rid, case, {}, {"id": 1, "kind": "local-stub"}, "t", threading.Event())
    with pytest.raises(GatewayRefused) as e:
        pyrit_adapter.run_case(ctx)
    assert e.value.code == "input_not_approved"
    assert [i["status"] for i in app_client.get(f"/api/runs/{rid}/invocations").json()] == ["refused"]


def test_stopping_mid_run_cancels_the_pyrit_case(app_client, real_adapters):
    t, run = stub_run(app_client, reply_delay_ms="4000")
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT"])
    app_client.post(f"/api/runs/{rid}/assessment/start")
    wait_for(lambda: any(i["status"] == "pending" for i in app_client.get(f"/api/runs/{rid}/invocations").json()))
    t0 = time.monotonic()
    r = app_client.post(f"/api/runs/{rid}/assessment/stop", json={"reason": "operator stop"})
    assert r.status_code == 200 and r.json()["status"] == "stopped" and time.monotonic() - t0 < 6
    st = app_client.get(f"/api/runs/{rid}/assessment").json()
    assert st["cases"][0]["state"] == "pending" and "operator stop" in st["reason"]
    inv = app_client.get(f"/api/runs/{rid}/invocations").json()
    assert inv[0]["status"] == "error" and inv[0]["error"].startswith("Cancelled")


# ---------------------------------------------------------------- G1: garak
@pytest.fixture()
def live_api(app_client, monkeypatch):
    """The same app served over HTTP, so the garak subprocess can reach /api/gateway/garak."""
    import uvicorn

    from agentshield import config
    from agentshield.app import app

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    monkeypatch.setenv("GATEWAY_PUBLIC_URL", f"http://127.0.0.1:{port}")
    config.get_settings.cache_clear()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, lifespan="off", log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    wait_for(lambda: server.started, timeout=15)
    yield port
    server.should_exit = True
    th.join(10)


def test_garak_test_probe_runs_through_the_gateway(app_client, real_adapters, live_api):
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-GARAK"])
    assert app_client.post(f"/api/runs/{rid}/assessment/start").status_code == 200
    st = wait(app_client, rid, timeout=240)
    assert st["status"] == "completed", st
    (a,) = _attempt(rid)
    assert a.error == "" and a.engine == "garak" and a.test_id == "probes.test.Test", a.error
    d = a.source_detail
    assert d["prompts_seen"] == 8 and d["prompts_answered"] == 5 and d["refusals"] == {"budget_technique": 3}
    assert a.verdict == "pass" and a.detector.startswith("always.Pass")
    report = Path(a.evidence["file"])
    assert report.name == "garak.report.jsonl" and hashlib.sha256(report.read_bytes()).hexdigest() == a.evidence["sha256"]
    rows = [json.loads(x) for x in report.read_text(encoding="utf-8").splitlines() if x.strip()]
    evaluated = [r for r in rows if r.get("entry_type") == "attempt" and r.get("status") == 2]
    assert len(evaluated) == 8 and all("detector_results" in r for r in evaluated)
    assert len(d["attempts"]) == 8
    inv = app_client.get(f"/api/runs/{rid}/invocations").json()
    assert [i["status"] for i in inv].count("ok") == 5 and [i["status"] for i in inv].count("refused") == 3
    assert len({i["session_id"] for i in inv if i["status"] == "ok"}) == 5  # one conversation per garak attempt
    assert app_client.get(f"/api/runs/{rid}/findings").json() == []


def test_garak_endpoint_rejects_wrong_token_and_idle_cases(app_client):
    r = app_client.post("/api/gateway/garak/RUN-X/C01", json={"prompt": "hi"}, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 403  # testclient host is not loopback, and no case is executing
    from agentshield.assessment.garak_adapter import handle_prompt

    assert handle_prompt("RUN-X", "C01", "nope", "127.0.0.1", "hi")[0] == 403
    assert handle_prompt("RUN-X", "C01", "nope", "10.1.2.3", "hi")[0] == 403


# ---------------------------------------------------------------- E1, D4, D5, H5: coordinator
def test_coordinator_tools_cannot_reach_a_connector():
    import ast
    import inspect

    from agentshield.assessment import coordinator

    names = [t.name for t in coordinator.build_tools(object())]
    assert names == list(coordinator.TOOL_NAMES)
    imported = set()
    for node in ast.walk(ast.parse(inspect.getsource(coordinator))):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    assert not {m for m in imported if "connector" in m or "gateway" in m or m in ("send", "invoke")}


def test_attacker_token_budget_stops_the_coordinator(app_client, orch, monkeypatch):  # noqa: F811
    from agentshield.assessment import coordinator

    use(orch, Replay())
    original = coordinator.ScriptedCoordinatorModel._generate

    def metered(self, messages, stop=None, run_manager=None, **kw):
        res = original(self, messages, stop, run_manager, **kw)
        res.generations[0].message.usage_metadata = {"input_tokens": 60, "output_tokens": 40, "total_tokens": 100}
        return res

    monkeypatch.setattr(coordinator.ScriptedCoordinatorModel, "_generate", metered)
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["AS-SPL-01"], limits={"attacker_token_budget": 250},
                     executions={"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]})
    app_client.post(f"/api/runs/{rid}/assessment/start")
    st = wait(app_client, rid)
    assert st["status"] == "stopped" and "budget_attacker" in st["reason"], st
    assert st["assessment"]["attacker_tokens"] == 300
    assert sum(1 for c in st["cases"] if c["state"] == "pending") >= 1


def test_coordinator_stops_when_the_target_is_unavailable(app_client, orch):  # noqa: F811
    class Down(Replay):
        def __call__(self, ctx):
            raise RuntimeError("connection refused")

    use(orch, Down())
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["AS-SPL-01"],
                     executions={"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]})
    app_client.post(f"/api/runs/{rid}/assessment/start")
    st = wait(app_client, rid)
    assert st["status"] == "stopped" and "target unavailable" in st["reason"]
    states = [c["state"] for c in st["cases"]]
    assert states.count("done") == 4 and states.count("pending") == 1


def test_coordinator_streams_its_decisions_and_falls_back_without_a_model(app_client, orch, monkeypatch):  # noqa: F811
    from agentshield import config

    monkeypatch.setenv("COORDINATOR_MODEL", "llm")
    monkeypatch.setenv("GENERATION_MODEL", "")
    config.get_settings.cache_clear()
    use(orch, Replay())
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT", "PLUMB-GARAK"])
    app_client.post(f"/api/runs/{rid}/assessment/start")
    st = wait(app_client, rid)
    assert st["status"] == "completed"
    coord = st["assessment"]["coordinator"]
    assert coord["mode"] == "llm" and "ModelNotConfigured" in coord["fallback"] and coord["steps"] > 0
    evs = [e for e in app_client.get("/api/events?limit=1000").json() if e["run_id"] == rid]
    steps = [e["data"] for e in evs if e["type"] == "coordinator.step"]
    called = [c["name"] for s in steps for c in s["tool_calls"]]
    assert "list_approved_cases" in called and called.count("execute_approved_case") == 2
    assert "coordinator.fallback" in [a["action"] for a in app_client.get("/api/audit", params={"run_id": rid}).json()]
