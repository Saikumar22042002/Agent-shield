"""DECISION_MODEL review: parsing, persistence, advisory-only behaviour, API errors. Offline (stub model)."""
import pytest

from agentshield.judge import JudgeError, parse_decision
from tests.test_api import _import
from tests.test_ingest import garak_line


class Reply:
    def __init__(self, content):
        self.content = content


class StubLLM:
    def __init__(self, content):
        self.content = content
        self.calls = []

    def invoke(self, messages):
        self.calls.append(messages)
        return Reply(self.content)


@pytest.mark.parametrize("content,expected", [
    ('{"decision": "fail", "rationale": "Agent repeated the token."}', ("fail", "Agent repeated the token.")),
    ('<think>hmm {"decision":"pass"}</think>\n```json\n{"decision": "PASS", "rationale": "Refused."}\n```', ("pass", "Refused.")),
    ([{"type": "text", "text": '{"decision": "inconclusive", "rationale": "Too short."}'}], ("inconclusive", "Too short.")),
])
def test_parse_decision(content, expected):
    assert parse_decision(content) == expected


def test_parse_decision_rejects_garbage():
    with pytest.raises(JudgeError):
        parse_decision('{"decision": "maybe"}')


def _run_with_attempts(app_client, target):
    run = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    report = "\n".join([garak_line("j1", "probes.promptinject.X", []),      # inconclusive
                        garak_line("j2", "probes.promptinject.X", [0.9])])  # tool fail -> finding
    assert _import(app_client, run["id"], "garak", "r.jsonl", report).status_code == 201
    return run


def test_review_is_stored_and_advisory(app_client, target, monkeypatch):
    from agentshield import config, judge

    monkeypatch.setenv("DECISION_MODEL", "groq:test-model")
    config.get_settings.cache_clear()
    stub = StubLLM('{"decision": "fail", "rationale": "Placeholder rationale."}')
    monkeypatch.setattr(judge, "decision_llm", lambda *a, **k: stub)
    run = _run_with_attempts(app_client, target)
    findings_before = app_client.get(f"/api/runs/{run['id']}/findings").json()

    r = app_client.post(f"/api/runs/{run['id']}/judge?verdict=inconclusive")
    assert r.status_code == 200 and r.json()["judged"] == 1
    a = {x["external_id"]: x for x in app_client.get(f"/api/runs/{run['id']}/attempts").json()}
    assert a["j1"]["model_review"] == {**a["j1"]["model_review"], "verdict": "fail", "model": "groq:test-model",
                                       "rationale": "Placeholder rationale."}
    assert a["j1"]["verdict"] == "inconclusive"  # tool verdict untouched
    assert app_client.get(f"/api/runs/{run['id']}/findings").json() == findings_before  # findings untouched
    assert "Placeholder" not in str(stub.calls[0][0])  # system prompt is fixed
    assert app_client.get("/api/audit", params={"action": "judge"}).json()[0]["payload"]["model_id"] == "groq:test-model"
    # second batch has nothing left to review
    assert app_client.post(f"/api/runs/{run['id']}/judge").json()["judged"] == 0


def test_review_requires_decision_model(app_client, target, monkeypatch):
    from agentshield import config

    monkeypatch.setenv("DECISION_MODEL", "")
    config.get_settings.cache_clear()
    run = _run_with_attempts(app_client, target)
    aid = app_client.get(f"/api/runs/{run['id']}/attempts").json()[0]["id"]
    r = app_client.post(f"/api/attempts/{aid}/judge")
    assert r.status_code == 503 and "DECISION_MODEL is not set" in r.json()["detail"]


def test_review_blocked_by_kill_switch(app_client, target, monkeypatch):
    from agentshield import config, judge

    monkeypatch.setenv("DECISION_MODEL", "groq:test-model")
    config.get_settings.cache_clear()
    monkeypatch.setattr(judge, "decision_llm", lambda *a, **k: StubLLM('{"decision":"pass","rationale":"x"}'))
    run = _run_with_attempts(app_client, target)
    aid = app_client.get(f"/api/runs/{run['id']}/attempts").json()[0]["id"]
    app_client.post("/api/kill", json={"reason": "t"})
    assert app_client.post(f"/api/attempts/{aid}/judge").status_code == 423
