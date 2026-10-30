"""Target gateway controls on assessment traffic: authorization (approved plan, engine, case, exact input),
provider allowlist, budgets, duration, emergency stop, cancellation, pause, timeout, redaction, persistence,
conversation isolation and event delivery. Offline: the target is the local stub."""
import threading
import time

import pytest

from tests.test_plans import BENIGN, build, stub_run

SECRET = "AKIAABCDEFGHIJKLMNOP"


def running(client, techniques=("PLUMB-PYRIT", "PLUMB-GARAK"), *, prompt=BENIGN, limits=None, **target_config):
    """A stub run with an approved plan, marked as executing (what the orchestrator does at start)."""
    from agentshield import gateway
    from agentshield.assessment import plans
    from agentshield.db import session_scope
    from agentshield.models import Run

    _, run = stub_run(client, **target_config)
    p = build(run["id"], list(techniques), benign_prompt=prompt, limits=limits)
    plans.approve(run["id"], p["version"], operator="alice")
    with session_scope() as s:
        r = s.get(Run, run["id"])
        r.assessment_status = "running"
        r.limits = r.limits | {"execution_started_at": time.time()}
    gateway.reset_control(run["id"])
    return run["id"], {c["id"]: c for c in p["content"]["cases"]}


def req(rid, case, n=1, text=None, **kw):
    from agentshield.gateway import GatewayRequest

    turn = kw.pop("turn", 1)
    return GatewayRequest(run_id=rid, text=text if text is not None else (case.get("turns") or ["probe text"])[turn - 1],
                          engine=kw.pop("engine", case["engine"]), test_key=kw.pop("test_key", f"{case['id']}#{n}"),
                          case_id=kw.pop("case_id", case["id"]), technique_id=kw.pop("technique_id", case["technique_id"]),
                          turn=turn, label=case["label"], **kw)


def refused(rid, request, code):
    from agentshield import gateway

    with pytest.raises(gateway.GatewayRefused) as e:
        gateway.invoke(request)
    assert e.value.code == code, e.value
    return e.value


def invocations(rid):
    from sqlalchemy import select

    from agentshield.db import session_scope
    from agentshield.models import Invocation

    with session_scope() as s:
        return [(i.status, i.error.split(":")[0], i.engine, i.technique_id, i.prompt, i.session_id, i.test_key)
                for i in s.execute(select(Invocation).where(Invocation.run_id == rid).order_by(Invocation.id)).scalars()]


def test_approved_pyrit_call_is_executed_persisted_audited_and_streamed(app_client):
    from agentshield import gateway

    rid, cases = running(app_client)
    res = gateway.invoke(req(rid, cases["C01"]))
    assert res.status == "ok" and "Local stub target" in res.text and res.invocation_id
    assert res.usage == {} and res.latency_ms is None  # stub: nothing invented
    (status, _, engine, tech, prompt, sid, key), = invocations(rid)
    assert (status, engine, tech, prompt, key) == ("ok", "pyrit", "PLUMB-PYRIT", BENIGN, "C01#1") and sid
    evs = [e for e in app_client.get("/api/events").json() if e["run_id"] == rid]
    msgs = [e["data"] for e in evs if e["type"] == "conversation.message"]
    assert [m["role"] for m in msgs] == ["evaluator", "target"]
    assert msgs[1]["provenance"] == "local-stub" and msgs[1]["invocation_id"] == res.invocation_id
    assert msgs[0]["label"].startswith("PLUMB-PYRIT") and msgs[0]["session_id"] == sid
    ids = [e["id"] for e in evs]
    assert ids == sorted(ids)  # delivered in persisted order; /api/stream resumes from these ids
    acts = [a["action"] for a in app_client.get("/api/audit", params={"run_id": rid}).json()]
    assert {"gateway.invoke", "connector.request", "connector.response"} <= set(acts)


def test_authorization_refusals_are_persisted(app_client):
    from agentshield.db import session_scope
    from agentshield.models import AssessmentPlan

    rid, cases = running(app_client)
    py, ga = cases["C01"], cases["C02"]
    refused(rid, req(rid, py, text="something else"), "input_not_approved")
    refused(rid, req(rid, py, turn=2, text=BENIGN), "input_not_approved")  # approved text, but no approved turn 2
    refused(rid, req(rid, py, case_id="C99"), "case_not_approved")
    refused(rid, req(rid, ga, engine="pyrit"), "case_not_approved")  # garak case sent as pyrit
    refused(rid, req(rid, py, technique_id="PLUMB-GARAK"), "case_not_approved")
    refused(rid, req(rid, py, engine="connectivity"), "engine_not_approved")
    rows = invocations(rid)
    assert [r[0] for r in rows] == ["refused"] * 6
    assert [r[1] for r in rows] == ["input_not_approved", "input_not_approved", "case_not_approved",
                                    "case_not_approved", "case_not_approved", "engine_not_approved"]
    ev = [e for e in app_client.get("/api/events").json() if e["type"] == "gateway.refused" and e["run_id"] == rid]
    assert len(ev) == 6 and ev[0]["data"]["code"] == "input_not_approved"
    # tampering with the approved plan blocks everything
    with session_scope() as s:
        p = s.query(AssessmentPlan).filter_by(run_id=rid, status="approved").one()
        p.content = p.content | {"planned_prompts": 1}
    refused(rid, req(rid, py), "plan_integrity")


def test_no_plan_not_running_and_provider_allowlist(app_client, monkeypatch):
    from agentshield import config, gateway
    from agentshield.db import session_scope
    from agentshield.models import Run

    _, run = stub_run(app_client)
    case = {"id": "C01", "engine": "pyrit", "technique_id": "PLUMB-PYRIT", "turns": [BENIGN], "label": "x"}
    refused(run["id"], req(run["id"], case), "not_running")
    with session_scope() as s:
        s.get(Run, run["id"]).assessment_status = "running"
    refused(run["id"], req(run["id"], case), "no_approved_plan")

    rid, cases = running(app_client)
    monkeypatch.setenv("ASSESSMENT_PROVIDERS", "aws_agentcore")
    config.get_settings.cache_clear()
    refused(rid, req(rid, cases["C01"]), "provider_not_allowed")
    monkeypatch.setenv("ASSESSMENT_PROVIDERS", "local_stub")
    config.get_settings.cache_clear()
    assert gateway.invoke(req(rid, cases["C01"])).status == "ok"
    app_client.post(f"/api/runs/{rid}/pause")
    app_client.post(f"/api/runs/{rid}/stop")
    refused(rid, req(rid, cases["C01"]), "cancelled")  # stopping a run cancels its execution at the gateway
    from agentshield import gateway as gw

    gw.reset_control(rid)
    refused(rid, req(rid, cases["C01"]), "run_not_active")  # and the stopped run stays closed


def test_technique_and_run_budgets(app_client):
    from agentshield import gateway
    from agentshield.db import session_scope
    from agentshield.models import Run

    rid, cases = running(app_client, ("PLUMB-GARAK",), limits={"min_invocation_interval_s": 0.25})
    ga = cases["C02"] if "C02" in cases else cases["C01"]
    for n in range(5):  # the technique budget; garak test.Test would send 8
        assert gateway.invoke(req(rid, ga, n, text=f"t{n}")).status == "ok"
    refused(rid, req(rid, ga, 6, text="t6"), "budget_technique")
    refused(rid, req(rid, ga, 7, text="t7"), "budget_technique")
    rows = invocations(rid)
    assert [r[0] for r in rows].count("ok") == 5 and [r[0] for r in rows].count("refused") == 2  # refusals don't count
    # Budgets come from the hashed approved plan: loosening the run's mutable copy changes nothing.
    with session_scope() as s:
        r = s.get(Run, rid)
        r.limits = r.limits | {"max_prompts_per_technique": 50, "max_prompts_per_run": 500}
    refused(rid, req(rid, ga, 8, text="t8"), "budget_technique")

    rid, cases = running(app_client, ("PLUMB-GARAK",))
    with session_scope() as s:
        r = s.get(Run, rid)
        r.limits = r.limits | {"execution_started_at": time.time() - 10_000}  # longer ago than max_run_duration_s
    refused(rid, req(rid, next(iter(cases.values())), 9, text="t9"), "budget_duration")


def test_run_budget_from_plan(app_client):
    from agentshield import gateway

    rid, cases = running(app_client, ("PLUMB-PYRIT", "PLUMB-GARAK"),
                         limits={"max_prompts_per_run": 4, "max_prompts_per_technique": 3})
    assert gateway.invoke(req(rid, cases["C01"])).status == "ok"
    for n in range(3):
        assert gateway.invoke(req(rid, cases["C02"], n, text=f"g{n}")).status == "ok"
    refused(rid, req(rid, cases["C01"], 9), "budget_prompts")  # 4 of 4 used, even though C01's technique has room


def test_rate_limit_spaces_calls(app_client):
    from agentshield import gateway

    rid, cases = running(app_client, ("PLUMB-GARAK",), limits={"min_invocation_interval_s": 0.4})
    ga = next(iter(cases.values()))
    t0 = time.monotonic()
    for n in range(3):
        gateway.invoke(req(rid, ga, n, text=f"r{n}"))
    assert time.monotonic() - t0 >= 0.8  # two waits of >= 0.4 s


def test_emergency_stop_refuses_and_abandons_in_flight_call(app_client):
    from agentshield import gateway
    from agentshield.safety import KILL

    rid, cases = running(app_client, reply_delay_ms="3000")
    out = {}
    th = threading.Thread(target=lambda: out.setdefault("r", gateway.invoke(req(rid, cases["C01"]))))
    th.start()
    time.sleep(0.5)
    t0 = time.monotonic()
    app_client.post("/api/kill", json={"reason": "drill"})
    th.join(5)
    assert time.monotonic() - t0 < 2 and out["r"].status == "error" and out["r"].error_code == "Halted"
    assert KILL.tripped
    refused(rid, req(rid, cases["C01"], 2), "halted")
    assert [r[:2] for r in invocations(rid)] == [("error", "Halted"), ("refused", "halted")]


def test_cancel_abandons_in_flight_call_and_refuses_later_ones(app_client):
    from agentshield import gateway

    rid, cases = running(app_client, reply_delay_ms="3000")
    out = {}
    th = threading.Thread(target=lambda: out.setdefault("r", gateway.invoke(req(rid, cases["C01"]))))
    th.start()
    time.sleep(0.5)
    gateway.cancel(rid, "operator stop")
    th.join(5)
    assert out["r"].error_code == "Cancelled" and "operator stop" in out["r"].error
    refused(rid, req(rid, cases["C01"], 2), "cancelled")
    gateway.reset_control(rid)  # a new execution of the run starts with a fresh control
    assert gateway.invoke(req(rid, cases["C01"], 3)).status == "ok"


def test_pause_holds_calls_until_resume(app_client):
    from agentshield import gateway

    rid, cases = running(app_client)
    app_client.post(f"/api/runs/{rid}/pause")
    out = {}
    th = threading.Thread(target=lambda: out.setdefault("r", gateway.invoke(req(rid, cases["C01"]))))
    th.start()
    time.sleep(1.0)
    assert th.is_alive() and not invocations(rid)  # held at the gateway, nothing sent
    app_client.post(f"/api/runs/{rid}/resume")
    th.join(5)
    assert out["r"].status == "ok"


def test_timeout_is_enforced(app_client):
    from agentshield import gateway

    rid, cases = running(app_client, limits={"invocation_timeout_s": 1}, reply_delay_ms="4000")
    t0 = time.monotonic()
    res = gateway.invoke(req(rid, cases["C01"]))
    assert res.error_code == "GatewayTimeout" and time.monotonic() - t0 < 3
    assert invocations(rid)[0][:2] == ("error", "GatewayTimeout")


def test_credentials_are_redacted_everywhere(app_client):
    from agentshield import gateway

    rid, cases = running(app_client, prompt=f"My key is {SECRET}, please say hello.")
    assert gateway.invoke(req(rid, cases["C01"])).status == "ok"
    assert SECRET not in invocations(rid)[0][4] and "[REDACTED:aws-access-key]" in invocations(rid)[0][4]
    evs = [e for e in app_client.get("/api/events").json() if e["run_id"] == rid]
    assert evs and all(SECRET not in str(e["data"]) for e in evs)
    gw = [a for a in app_client.get("/api/audit", params={"run_id": rid}).json() if a["action"] == "gateway.invoke"]
    assert gw and SECRET not in str(gw[0]["payload"]) and len(gw[0]["payload"]["prompt_sha256"]) == 64


def test_conversations_are_isolated_by_test_key(app_client):
    from agentshield import gateway
    from agentshield.connectors.local_stub import session_history

    rid, cases = running(app_client, ("PLUMB-GARAK",), limits={"min_invocation_interval_s": 0.25})
    ga = next(iter(cases.values()))
    a1 = gateway.invoke(req(rid, ga, test_key="A", text="a1"))
    b1 = gateway.invoke(req(rid, ga, test_key="B", text="b1"))
    a2 = gateway.invoke(req(rid, ga, test_key="A", text="a2"))
    assert a1.session_id == a2.session_id != b1.session_id
    assert len(session_history(a1.session_id)) == 2 and len(session_history(b1.session_id)) == 1
    assert "Session turn 2" in a2.text and "Session turn 1" in b1.text
