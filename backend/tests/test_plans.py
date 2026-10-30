"""Assessment plans: multi-engine plans, budget allocation, limits that can only tighten, supersession, approval
and its record on the run. Offline (PyRIT's bundled dataset is read from the installed package)."""
import pytest

from tests.test_workspace import _stub

BENIGN = "Hello. Please reply with one short sentence."


def stub_run(client, **target_config):
    body = {"provider": "local_stub", "name": "Local stub", "environment": "staging",
            "owner_attestation": "We own and operate this development target.", "config": target_config}
    t = client.post("/api/targets", json=body).json() if target_config else _stub(client)
    run = client.post("/api/runs", json={"target_id": t["id"], "label": "plan"}).json()
    return t, run


def set_profile(target_id: int, profile: dict) -> None:
    from agentshield.db import session_scope
    from agentshield.models import Target

    with session_scope() as s:
        s.get(Target, target_id).profile = profile


def build(run_id, techniques, **kw):
    from agentshield.assessment import plans

    return plans.build(run_id, techniques=techniques, operator="alice", **kw)


def test_multi_engine_plan_has_cases_budgets_and_notes(app_client):
    _, run = stub_run(app_client)
    p = build(run["id"], ["PLUMB-PYRIT", "PLUMB-GARAK"], benign_prompt=BENIGN)
    c = p["content"]
    assert p["version"] == 1 and p["status"] == "draft" and p["integrity_ok"]
    assert c["engines"] == ["garak", "pyrit"] and set(c["engine_versions"]) == {"garak", "pyrit"}
    assert c["kind"] == "plumbing" and c["target_kind"] == "local-stub"
    py, ga = c["cases"]
    assert py["id"] == "C01" and py["engine"] == "pyrit" and py["turns"] == [BENIGN] and py["scorer"] is None
    assert ga["id"] == "C02" and ga["engine"] == "garak" and ga["probe"] == "test.Test" and ga["prompt_cap"] == 5
    assert c["planned_prompts"] == 6 and c["limits"]["max_prompts_per_technique"] == 5
    assert any("refuse the 3" in n for n in c["notes"])  # test.Test sends 8 and ignores the cap
    acts = [a["action"] for a in app_client.get("/api/audit", params={"run_id": run["id"]}).json()]
    assert "plan.create" in acts


def test_dataset_cases_come_from_pyrit_and_scorer_needs_canary(app_client):
    from agentshield.assessment.plans import pyrit_dataset

    t, run = stub_run(app_client)
    seeds, meta = pyrit_dataset("garak_system_prompt_extraction")
    ex = {"AS-SPL-01": ["pyrit:PromptSendingAttack:garak_system_prompt_extraction"]}
    c = build(run["id"], ["AS-SPL-01"], executions=ex)["content"]
    assert [x["turns"] for x in c["cases"]] == [[s] for s in seeds[:5]]  # verbatim, first 5 (technique budget)
    assert all(x["scorer"] is None and x["dataset"]["sha256"] == meta["sha256"] for x in c["cases"])
    assert any("UNDETERMINED" in n for n in c["notes"]) and any("simulated" in n for n in c["notes"])
    set_profile(t["id"], {"role": "IT helpdesk", "hints": {"context_canary": "CANARY-7f3a"}})
    c = build(run["id"], ["AS-SPL-01"], executions=ex)["content"]
    assert c["cases"][0]["scorer"] == {"class": "SubStringScorer", "substring": "CANARY-7f3a",
                                       "input": "profile.hints.context_canary"}


def test_technique_budget_is_split_across_executions(app_client):
    _, run = stub_run(app_client)
    both = ["garak:sysprompt_extraction.SystemPromptExtraction", "pyrit:PromptSendingAttack:garak_system_prompt_extraction"]
    c = build(run["id"], ["AS-SPL-01"], executions={"AS-SPL-01": both})["content"]
    assert [x["engine"] for x in c["cases"]] == ["garak", "pyrit", "pyrit"]
    assert c["cases"][0]["prompt_cap"] == 3 and c["planned_prompts"] == 5


def test_limits_can_only_tighten(app_client):
    from agentshield.assessment.plans import PlanError

    _, run = stub_run(app_client)
    with pytest.raises(PlanError, match="exceeds"):
        build(run["id"], ["PLUMB-GARAK"], limits={"max_prompts_per_technique": 10})
    with pytest.raises(PlanError, match="below"):
        build(run["id"], ["PLUMB-GARAK"], limits={"min_invocation_interval_s": 0})
    with pytest.raises(PlanError, match="Unknown limit"):
        build(run["id"], ["PLUMB-GARAK"], limits={"max_everything": 1})
    c = build(run["id"], ["PLUMB-GARAK"], limits={"max_prompts_per_technique": 2})["content"]
    assert c["cases"][0]["prompt_cap"] == 2 and any("refuse the 6" in n for n in c["notes"])
    with pytest.raises(PlanError, match="run budget"):
        build(run["id"], ["PLUMB-GARAK", "PLUMB-PYRIT"], limits={"max_prompts_per_run": 5})


def test_plan_rejections(app_client, target):
    from agentshield.assessment.plans import PlanError

    _, run = stub_run(app_client)
    for techs, msg in [([], "at least one"), (["NOPE"], "Unknown technique"), (["AS-JB-01"], "not executable"),
                       (["PLUMB-PYRIT-MT"], "two benign turns")]:
        with pytest.raises(PlanError, match=msg):
            build(run["id"], techs)
    with pytest.raises(PlanError, match="unknown execution"):
        build(run["id"], ["AS-SPL-01"], executions={"AS-SPL-01": ["garak:nope"]})
    aws_run = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    with pytest.raises(PlanError, match="ASSESSMENT_PROVIDERS"):
        build(aws_run["id"], ["PLUMB-PYRIT"])
    app_client.post(f"/api/runs/{run['id']}/pause")
    with pytest.raises(PlanError, match="paused"):
        build(run["id"], ["PLUMB-PYRIT"])


def test_multi_turn_plumbing_case(app_client):
    _, run = stub_run(app_client)
    c = build(run["id"], ["PLUMB-PYRIT-MT"], benign_turns=["Hi.", "What can you do?", "Thanks."])["content"]
    assert c["cases"][0]["strategy"] == "MultiPromptSendingAttack" and len(c["cases"][0]["turns"]) == 3


def test_approval_records_sha_and_supersedes(app_client):
    from agentshield.assessment import plans
    from agentshield.db import session_scope
    from agentshield.models import AssessmentPlan, Run

    _, run = stub_run(app_client)
    rid = run["id"]
    v1 = build(rid, ["PLUMB-PYRIT", "PLUMB-GARAK"])
    v2 = build(rid, ["PLUMB-PYRIT"])
    assert [p["status"] for p in plans.list_plans(rid)] == ["draft", "superseded"]  # newest first
    with pytest.raises(plans.PlanError, match="only a draft"):
        plans.approve(rid, v1["version"], operator="bob")
    ok = plans.approve(rid, v2["version"], operator="bob")
    assert ok["status"] == "approved" and ok["approved_by"] == "bob"
    with session_scope() as s:
        r = s.get(Run, rid)
        assert r.assessment_status == "approved"
        assert r.limits["plan_sha256"] == v2["sha256"] and r.limits["plan_version"] == 2
        assert r.limits["max_prompts_per_run"] == 50
    v3 = build(rid, ["PLUMB-GARAK"])
    plans.approve(rid, v3["version"], operator="bob")
    assert [p["status"] for p in plans.list_plans(rid)] == ["approved", "superseded", "superseded"]
    assert plans.approved(rid)["version"] == 3
    # tampering with the stored content is detected before approval
    v4 = build(rid, ["PLUMB-PYRIT"])
    with session_scope() as s:
        p = s.query(AssessmentPlan).filter_by(run_id=rid, version=v4["version"]).one()
        p.content = p.content | {"planned_prompts": 999}
    with pytest.raises(plans.PlanError, match="no longer matches"):
        plans.approve(rid, v4["version"], operator="bob")
    acts = [a["action"] for a in app_client.get("/api/audit", params={"run_id": rid}).json()]
    assert acts.count("plan.approve") == 2
