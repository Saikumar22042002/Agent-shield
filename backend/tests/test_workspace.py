"""Evaluation workspace: local stub target, run-scoped live exchange, timeline, phases, onboarding. Offline."""
from tests.test_api import _import
from tests.test_ingest import garak_line

ATTEST = "We own and operate this development target."


def _stub(client):
    r = client.post("/api/targets", json={"provider": "local_stub", "name": "Local stub", "environment": "staging",
                                          "owner_attestation": ATTEST})
    assert r.status_code == 201, r.text
    return r.json()


def test_local_stub_registers_without_aws_fields(app_client):
    t = _stub(app_client)
    assert t["provider"] == "local_stub" and t["harness_arn"] == "" and t["status"] == "unverified"
    assert t["provider_implemented"] is True


def test_placeholder_provider_needs_its_config_and_is_unsupported(app_client):
    body = {"provider": "azure_ai_foundry", "name": "Foundry", "environment": "staging", "owner_attestation": ATTEST}
    r = app_client.post("/api/targets", json=body)
    assert r.status_code == 422 and "endpoint" in r.json()["detail"]
    r = app_client.post("/api/targets", json=body | {"config": {"endpoint": "https://example.invalid", "agent_id": "a1"}})
    assert r.status_code == 201 and r.json()["status"] == "unsupported"
    assert app_client.post(f"/api/targets/{r.json()['id']}/check").status_code == 501
    assert app_client.post("/api/targets", json=body | {"provider": "nope"}).status_code == 422


def test_stub_exchange_records_both_sides_and_streams(app_client):
    from agentshield.config import get_settings

    t = _stub(app_client)
    run = app_client.post("/api/runs", json={"target_id": t["id"], "label": "dev"}).json()
    assert run["phase"]["current"] == 2  # connectivity not yet verified
    r = app_client.post(f"/api/runs/{run['id']}/exchange", headers={"X-Operator": "bob"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "connected" and body["provenance"] == "local-stub"
    assert body["usage"] == {} and body["latency_ms"] is None  # nothing invented: no model, no service latency

    tl = app_client.get(f"/api/runs/{run['id']}/timeline").json()
    msgs = [i for i in tl["items"] if i["kind"] == "message"]
    assert [m["role"] for m in msgs] == ["evaluator", "target"]
    assert msgs[0]["text"] == get_settings().connectivity_message and msgs[0]["provenance"] == "sent"
    assert msgs[1]["provenance"] == "local-stub" and "Local stub target" in msgs[1]["text"]
    assert msgs[1]["turn"] == msgs[0]["turn"] + 1
    assert tl["run"]["phase"]["current"] == 5  # results imported is next
    deltas = [e for e in app_client.get("/api/events").json() if e["type"] == "conversation.delta"]
    assert "".join(d["data"]["text"] for d in deltas).strip() == msgs[1]["text"].strip()
    acts = {a["action"] for a in app_client.get("/api/audit", params={"run_id": run["id"]}).json()}
    assert {"connectivity.start", "connectivity.result", "connector.request", "connector.response"} <= acts


def test_exchange_respects_run_state_and_kill_switch(app_client):
    t = _stub(app_client)
    run = app_client.post("/api/runs", json={"target_id": t["id"]}).json()
    app_client.post(f"/api/runs/{run['id']}/pause")
    assert app_client.post(f"/api/runs/{run['id']}/exchange").status_code == 409
    app_client.post(f"/api/runs/{run['id']}/resume")
    app_client.post("/api/kill", json={"reason": "drill"})
    assert app_client.post(f"/api/runs/{run['id']}/exchange").status_code == 423
    tl = app_client.get(f"/api/runs/{run['id']}/timeline").json()
    assert not [i for i in tl["items"] if i["kind"] == "message"]
    assert any(i["type"] == "kill.tripped" for i in tl["items"])


def test_exchange_error_keeps_original_message_and_hint(app_client, target, monkeypatch):
    from agentshield import connectivity
    from agentshield.connectors.base import ConnectorError

    class Denied:
        def new_session_id(self):
            return "agentshield-" + "1" * 36

        def send(self, inp):
            raise ConnectorError("AccessDeniedException", "User: arn:aws:iam::1:user/x is not authorized",
                                 hint="AWS denied the call.")

    monkeypatch.setattr(connectivity, "build_connector", lambda *a, **k: Denied())
    run = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    body = app_client.post(f"/api/runs/{run['id']}/exchange").json()
    assert body["status"] == "error" and "is not authorized" in body["error"] and body["hint"] == "AWS denied the call."
    err = [i for i in app_client.get(f"/api/runs/{run['id']}/timeline").json()["items"] if i.get("error")]
    assert err and err[0]["error"]["code"] == "AccessDeniedException" and "not authorized" in err[0]["error"]["message"]


def test_timeline_includes_imported_turns_scores_and_findings(app_client, target):
    run = app_client.post("/api/runs", json={"target_id": target["id"]}).json()
    _import(app_client, run["id"], "garak", "r.jsonl", garak_line("t1", "probes.promptinject.X", [0.9]))
    tl = app_client.get(f"/api/runs/{run['id']}/timeline").json()
    types = [i["type"] for i in tl["items"]]
    assert types.index("attempt.start") < types.index("imported.turn") < types.index("scorer.result") < types.index("finding")
    turns = [i for i in tl["items"] if i["type"] == "imported.turn"]
    assert {t["provenance"] for t in turns} == {"imported"} and turns[0]["source"] == "garak"
    assert [t["role"] for t in turns] == ["evaluator", "target"]
    assert tl["run"]["phase"]["steps"][4]["done"] and tl["run"]["phase"]["steps"][5]["done"]


def test_archive_blocks_runs_and_checks(app_client):
    t = _stub(app_client)
    assert app_client.post(f"/api/targets/{t['id']}/archive", json={"archived": True}).json()["archived"]
    assert app_client.post("/api/runs", json={"target_id": t["id"]}).status_code == 409
    assert app_client.post(f"/api/targets/{t['id']}/check").status_code == 409
    assert not app_client.post(f"/api/targets/{t['id']}/archive", json={"archived": False}).json()["archived"]


def test_aws_stream_deltas_forwarded():
    from agentshield.connectors.aws_agentcore import assemble_stream

    got = []
    assemble_stream([{"contentBlockDelta": {"delta": {"text": "a"}}}, {"contentBlockDelta": {"delta": {"text": "b"}}}],
                    "s" * 40, on_delta=got.append)
    assert got == ["a", "b"]


def test_access_denied_hint_distinguishes_bad_token_from_missing_permission():
    from agentshield.connectors.aws_agentcore import TOKEN_HINT, hint_for

    assert hint_for("AccessDeniedException", "The security token included in the request is invalid.") == TOKEN_HINT
    assert "InvokeHarness" in hint_for("AccessDeniedException", "User: arn:aws:iam::1:user/x is not authorized")
    assert hint_for("SomethingNew") == ""


def _pdf_text(data: bytes) -> str:
    import re
    import zlib

    out = [data.decode("latin-1")]
    import base64

    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        raw = m.group(1).strip()
        try:  # ReportLab streams are ASCII85, then Flate
            raw = base64.a85decode(raw.removesuffix(b"~>"), adobe=False) if raw.endswith(b"~>") else raw
            out.append(zlib.decompress(raw).decode("latin-1"))
        except (ValueError, zlib.error):
            pass
    return "".join(out)


def test_stub_run_pdf_is_labelled_as_development_stub(app_client):
    t = _stub(app_client)
    run = app_client.post("/api/runs", json={"target_id": t["id"]}).json()
    app_client.post(f"/api/runs/{run['id']}/exchange")
    pdf = app_client.get(f"/api/runs/{run['id']}/report.pdf")
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"
    text = _pdf_text(pdf.content)
    assert "LOCAL STUB TARGET" in text and "AWS Bedrock AgentCore" not in text
