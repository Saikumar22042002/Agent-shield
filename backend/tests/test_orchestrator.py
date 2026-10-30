"""Run orchestrator + assessment API: lifecycle persistence, bounded concurrency, queueing, stop / emergency stop,
resume after stop or restart, error capture, evidence kinds, and the plan / profile / catalog endpoints.

The PyRIT and garak adapters are not exercised here. A test-only adapter stands in for them: it replays each case's
approved turns through ctx.invoke (the gateway), which is the contract real adapters must follow. Offline."""
import threading
import time

import pytest

from tests.test_plans import BENIGN, stub_run


class Replay:
    """Test adapter. Records concurrency; can block on an event or raise for a chosen case."""

    def __init__(self, verdict="inconclusive", hold: threading.Event | None = None, fail_case: str = ""):
        self.verdict, self.hold, self.fail_case = verdict, hold, fail_case
        self.active = self.peak = 0
        self.lock = threading.Lock()
        self.sessions: list[str] = []

    def __call__(self, ctx):
        from agentshield.assessment.orchestrator import CaseResult

        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            if self.hold is not None:
                while not self.hold.wait(0.05):
                    if ctx.cancel.is_set():
                        break
            if ctx.case["id"] == self.fail_case:
                raise RuntimeError("framework exploded")
            turns = ctx.case.get("turns") or [f"probe prompt {n}" for n in range(ctx.case.get("prompt_cap", 1))]
            out = []
            for n, text in enumerate(turns, start=1):
                pyrit = ctx.case["engine"] == "pyrit"
                r = ctx.invoke(text, turn=n if pyrit else 1, test_key=None if pyrit else f"{ctx.case['id']}#{n}")
                self.sessions.append(r.session_id)
                out += [{"role": "user", "text": text}, {"role": "assistant", "text": r.text}]
            return CaseResult(verdict=self.verdict, source_verdict="TEST", test_id="replay", turns=out,
                              engine_version="test", rationale="test adapter")
        finally:
            with self.lock:
                self.active -= 1


@pytest.fixture()
def orch(app_client, monkeypatch):
    from agentshield.assessment import orchestrator

    orchestrator.reset_for_tests()
    monkeypatch.setattr(orchestrator, "ADAPTERS", {})
    yield orchestrator
    orchestrator.reset_for_tests()


def use(orch, adapter):
    orch.register("pyrit", adapter)
    orch.register("garak", adapter)
    return adapter


def plan_and_approve(client, rid, techniques, **body):
    r = client.post(f"/api/runs/{rid}/plans", json={"techniques": techniques, "benign_prompt": BENIGN, **body})
    assert r.status_code == 201, r.text
    v = r.json()["version"]
    r = client.post(f"/api/runs/{rid}/plans/{v}/approve", headers={"X-Operator": "approver"})
    assert r.status_code == 200, r.text
    return r.json()


def wait(client, rid, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        st = client.get(f"/api/runs/{rid}/assessment").json()
        if st["status"] not in ("queued", "running"):
            return st
        time.sleep(0.1)
    raise AssertionError(f"still executing: {st}")


def wait_for(fn, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return
        time.sleep(0.05)
    raise AssertionError("condition not reached")


def test_start_requires_approved_plan_and_adapter(app_client, orch):
    _, run = stub_run(app_client)
    rid = run["id"]
    r = app_client.post(f"/api/runs/{rid}/assessment/start")
    assert r.status_code == 409 and "approve a plan first" in r.json()["detail"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT"])
    r = app_client.post(f"/api/runs/{rid}/assessment/start")
    assert r.status_code == 409 and "No execution adapter" in r.json()["detail"]
    use(orch, Replay())
    app_client.post("/api/kill", json={"reason": "drill"})
    assert app_client.post(f"/api/runs/{rid}/assessment/start").status_code == 423
    assert app_client.get("/api/runs/NOPE/assessment").status_code == 404


def test_full_lifecycle_persists_results_and_events(app_client, orch):
    adapter = use(orch, Replay())
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT", "PLUMB-GARAK"])
    r = app_client.post(f"/api/runs/{rid}/assessment/start", headers={"X-Operator": "alice"})
    assert r.status_code == 200 and r.json()["status"] == "queued"
    st = wait(app_client, rid)
    assert st["status"] == "completed" and st["reason"] == ""
    assert [c["state"] for c in st["cases"]] == ["done", "done"]
    assert st["usage"]["invocations"] == {"ok": 6, "error": 0, "refused": 0, "pending": 0}
    assert st["assessment"]["progress"]["cases_done"] == 2 and st["assessment"]["active_seconds"] > 0

    attempts = app_client.get(f"/api/runs/{rid}/attempts").json()
    assert {a["source"] for a in attempts} == {"pyrit", "garak"}
    from agentshield.db import session_scope
    from agentshield.models import TestAttempt

    with session_scope() as s:
        rows = s.query(TestAttempt).filter_by(run_id=rid).all()
        assert all(a.provenance == "local-execution" and a.import_id is None for a in rows)
        assert {a.evidence["kind"] for a in rows} == {"plumbing"}
        garak = next(a for a in rows if a.source == "garak")
        assert len(garak.invocation_ids) == 5 and garak.severity == "Info"
    assert app_client.get(f"/api/runs/{rid}/findings").json() == []  # plumbing never produces findings
    summary = app_client.get(f"/api/runs/{rid}").json()["summary"]
    assert summary["executed"] == {"total": 2, "by_kind": {"plumbing": 2}, "by_verdict": {"inconclusive": 2}}
    assert summary["provenance"] == "executed"

    statuses = [e["data"]["status"] for e in app_client.get("/api/events?limit=1000").json()
                if e["type"] == "assessment.status" and e["run_id"] == rid]
    assert statuses == ["queued", "running", "completed"]
    tl = app_client.get(f"/api/runs/{rid}/timeline").json()
    msgs = [i for i in tl["items"] if i["kind"] == "message"]
    assert len(msgs) == 12  # 6 prompts + 6 replies, each once (executed turns are not re-added as imported turns)
    scores = [i for i in tl["items"] if i["type"] == "scorer.result"]
    assert len(scores) == 2 and {i["provenance"] for i in scores} == {"executed"}
    assert tl["run"]["phase"]["steps"][4]["done"]
    acts = [a["action"] for a in app_client.get("/api/audit", params={"run_id": rid}).json()]
    assert {"assessment.start", "assessment.result", "assessment.completed", "plan.approve"} <= set(acts)
    assert len(set(adapter.sessions)) == 6  # garak prompts are separate conversations; one PyRIT session
    # a completed assessment cannot be restarted or resumed, the run can be completed
    assert app_client.post(f"/api/runs/{rid}/assessment/start").status_code == 409
    assert app_client.post(f"/api/runs/{rid}/assessment/resume").status_code == 409
    assert app_client.post(f"/api/runs/{rid}/complete").json()["status"] == "complete"


def test_cases_run_in_parallel_up_to_the_limit(app_client, orch):
    hold = threading.Event()
    adapter = use(orch, Replay(hold=hold))
    _, run = stub_run(app_client)
    rid = run["id"]
    ex = {"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]}
    plan_and_approve(app_client, rid, ["AS-SPL-01"], executions=ex)  # 5 single-turn cases
    app_client.post(f"/api/runs/{rid}/assessment/start")
    wait_for(lambda: adapter.active == 2)
    time.sleep(0.3)
    assert adapter.active == 2  # technique_concurrency default 2
    running = [c for c in app_client.get(f"/api/runs/{rid}/assessment").json()["cases"] if c["state"] == "running"]
    assert len(running) == 2
    hold.set()
    st = wait(app_client, rid)
    assert st["status"] == "completed" and adapter.peak == 2
    with __import__("agentshield.db", fromlist=["session_scope"]).session_scope() as s:
        from agentshield.models import TestAttempt

        rows = s.query(TestAttempt).filter_by(run_id=rid).all()
        assert {a.evidence["kind"] for a in rows} == {"simulated"}  # security cases against the stub
    assert app_client.get(f"/api/runs/{rid}/findings").json() == []


def test_simulated_failures_never_become_findings(app_client, orch):
    use(orch, Replay(verdict="fail"))
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["AS-PI-01"])
    app_client.post(f"/api/runs/{rid}/assessment/start")
    assert wait(app_client, rid)["status"] == "completed"
    assert [a["verdict"] for a in app_client.get(f"/api/runs/{rid}/attempts").json()] == ["fail"]
    assert app_client.get(f"/api/runs/{rid}/findings").json() == []


def test_second_run_queues_until_a_slot_frees(app_client, orch):
    hold = threading.Event()
    use(orch, Replay(hold=hold))
    _, a = stub_run(app_client)
    _, b = stub_run(app_client)
    for run in (a, b):
        plan_and_approve(app_client, run["id"], ["PLUMB-PYRIT"])
        app_client.post(f"/api/runs/{run['id']}/assessment/start")
    wait_for(lambda: app_client.get(f"/api/runs/{a['id']}/assessment").json()["status"] == "running")
    time.sleep(0.3)
    assert app_client.get(f"/api/runs/{b['id']}/assessment").json()["status"] == "queued"  # MAX_ACTIVE_ASSESSMENTS=1
    hold.set()
    assert wait(app_client, a["id"])["status"] == "completed"
    assert wait(app_client, b["id"])["status"] == "completed"


def test_stop_then_resume_skips_finished_cases(app_client, orch):
    hold = threading.Event()
    adapter = use(orch, Replay(hold=hold))
    _, run = stub_run(app_client)
    rid = run["id"]
    ex = {"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]}
    plan_and_approve(app_client, rid, ["AS-SPL-01"], executions=ex)
    app_client.post(f"/api/runs/{rid}/assessment/start")
    wait_for(lambda: adapter.active == 2)
    hold.set()  # let the first cases finish, then stop before all are done
    wait_for(lambda: app_client.get(f"/api/runs/{rid}/assessment").json()["assessment"].get("progress", {})
             .get("cases_done", 0) >= 1)
    hold.clear()
    r = app_client.post(f"/api/runs/{rid}/assessment/stop", json={"reason": "operator pause for review"})
    assert r.status_code == 200 and r.json()["status"] == "stopped"
    st = app_client.get(f"/api/runs/{rid}/assessment").json()
    done_before = {c["id"] for c in st["cases"] if c["state"] == "done"}
    assert 1 <= len(done_before) < 5 and "operator pause" in st["reason"]
    sent_before = st["usage"]["invocations"]["ok"]
    hold.set()
    assert app_client.post(f"/api/runs/{rid}/assessment/resume").status_code == 200
    st = wait(app_client, rid)
    assert st["status"] == "completed" and all(c["state"] == "done" for c in st["cases"])
    assert st["usage"]["invocations"]["ok"] == 5 and sent_before == len(done_before)  # no case re-sent
    acts = [a["action"] for a in app_client.get("/api/audit", params={"run_id": rid}).json()]
    assert "assessment.stop" in acts and "assessment.resume" in acts


def test_emergency_stop_halts_execution_and_blocks_resume(app_client, orch):
    hold = threading.Event()
    use(orch, Replay(hold=hold))
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-GARAK"])
    app_client.post(f"/api/runs/{rid}/assessment/start")
    wait_for(lambda: app_client.get(f"/api/runs/{rid}/assessment").json()["status"] == "running")
    t0 = time.monotonic()
    assert rid in app_client.post("/api/kill", json={"reason": "drill"}).json()["halted_runs"]
    st = app_client.get(f"/api/runs/{rid}/assessment").json()
    assert st["status"] == "stopped" and "drill" in st["reason"] and time.monotonic() - t0 < 5
    assert app_client.get(f"/api/runs/{rid}").json()["status"] == "halted"
    assert app_client.post(f"/api/runs/{rid}/assessment/resume").status_code == 423
    app_client.post("/api/kill/reset")
    assert app_client.post(f"/api/runs/{rid}/assessment/resume").status_code == 409  # halted runs stay halted


def test_run_stop_and_complete_during_execution(app_client, orch):
    hold = threading.Event()
    use(orch, Replay(hold=hold))
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT"])
    app_client.post(f"/api/runs/{rid}/assessment/start")
    wait_for(lambda: app_client.get(f"/api/runs/{rid}/assessment").json()["status"] == "running")
    r = app_client.post(f"/api/runs/{rid}/complete")
    assert r.status_code == 409 and "executing" in r.json()["detail"]
    r = app_client.post(f"/api/runs/{rid}/stop", json={"reason": "scope change"})
    assert r.status_code == 200 and r.json()["status"] == "stopped" and r.json()["assessment_status"] == "stopped"


def test_restart_marks_interrupted_and_resume_completes(app_client, orch):
    from agentshield.db import session_scope
    from agentshield.models import Run

    use(orch, Replay())
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT", "PLUMB-GARAK"])
    with session_scope() as s:  # what a crash mid-execution leaves behind
        s.get(Run, rid).assessment_status = "running"
    assert orch.recover_after_restart() == [rid]
    st = app_client.get(f"/api/runs/{rid}/assessment").json()
    assert st["status"] == "interrupted" and "Resume" in st["reason"]
    assert app_client.post(f"/api/runs/{rid}/assessment/start").status_code == 409  # must resume, not start
    assert app_client.post(f"/api/runs/{rid}/assessment/resume").status_code == 200
    assert wait(app_client, rid)["status"] == "completed"


def test_adapter_error_is_recorded_and_run_continues(app_client, orch):
    use(orch, Replay(fail_case="C01"))
    _, run = stub_run(app_client)
    rid = run["id"]
    plan_and_approve(app_client, rid, ["PLUMB-PYRIT", "PLUMB-GARAK"])
    app_client.post(f"/api/runs/{rid}/assessment/start")
    st = wait(app_client, rid)
    assert st["status"] == "completed" and st["assessment"]["progress"]["errors"] == 1
    c01 = next(c for c in st["cases"] if c["id"] == "C01")
    assert c01["result"]["verdict"] == "error" and "framework exploded" in c01["result"]["error"]


def test_plan_endpoints_validate(app_client, orch, target):
    _, run = stub_run(app_client)
    rid = run["id"]
    assert app_client.post(f"/api/runs/{rid}/plans", json={"techniques": []}).status_code == 422
    r = app_client.post(f"/api/runs/{rid}/plans", json={"techniques": ["PLUMB-GARAK"],
                                                       "limits": {"max_prompts_per_run": 999}})
    assert r.status_code == 422 and "exceeds" in r.json()["detail"]
    aws = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    r = app_client.post(f"/api/runs/{aws['id']}/plans", json={"techniques": ["PLUMB-PYRIT"]})
    assert r.status_code == 422 and "ASSESSMENT_PROVIDERS" in r.json()["detail"]
    assert app_client.post(f"/api/runs/{rid}/plans/7/approve").status_code == 404
    p = plan_and_approve(app_client, rid, ["PLUMB-PYRIT"])
    assert app_client.post(f"/api/runs/{rid}/plans/{p['version']}/approve").status_code == 422  # not a draft
    plans = app_client.get(f"/api/runs/{rid}/plans").json()
    assert plans[0]["status"] == "approved" and plans[0]["integrity_ok"]
    run_row = app_client.get(f"/api/runs/{rid}").json()
    assert run_row["assessment_status"] == "approved"


def test_profile_catalog_and_engines_endpoints(app_client, orch):
    t, _ = stub_run(app_client)
    body = {"role": "IT helpdesk assistant", "tools": [{"name": "reset_password", "privileged": True}],
            "has_rag": True, "hints": {"context_canary": "CANARY-SECRET-123"}}
    r = app_client.put(f"/api/targets/{t['id']}/profile", json=body, headers={"X-Operator": "alice"})
    assert r.status_code == 200 and r.json()["capabilities"] == ["rag", "tools"] and r.json()["documented"]
    assert app_client.get(f"/api/targets/{t['id']}/profile").json()["hints"]["context_canary"] == "CANARY-SECRET-123"
    assert app_client.put(f"/api/targets/{t['id']}/profile", json={"tools": [{"name": ""}]}).status_code == 422
    audit = [a for a in app_client.get("/api/audit").json() if a["action"] == "target.profile"]
    assert audit and "CANARY-SECRET-123" not in str(audit[0]["payload"])
    cat = app_client.get("/api/catalog").json()
    assert cat["catalog_version"] == "2026.10.2" and cat["engines"]["pyrit"]["available"]
    eng = app_client.get("/api/engines").json()
    assert eng["adapters"] == [] and eng["assessment_providers"] == ["local_stub", "local_model"]
    assert eng["limits"]["max_prompts_per_technique"] == 5 and eng["limits"]["max_prompts_per_run"] == 50
