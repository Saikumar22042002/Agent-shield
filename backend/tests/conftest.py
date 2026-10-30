import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("TARGET_HARNESS_ARN", "")
    monkeypatch.setenv("CONNECTIVITY_MIN_INTERVAL_S", "0")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("COORDINATOR_MODEL", "deterministic")  # tests never call a hosted model
    monkeypatch.setenv("AUTH_TOKENS", "")
    monkeypatch.setenv("ASSESSMENT_PROVIDERS", "local_stub,local_model")
    from agentshield import config, connectivity
    from agentshield.safety import KILL

    config.get_settings.cache_clear()
    connectivity._interval = None
    KILL.reset()
    from fastapi.testclient import TestClient

    from agentshield.app import app

    with TestClient(app) as c:
        yield c
    KILL.reset()
    config.get_settings.cache_clear()


ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/snowAgent-abcdefghij"


@pytest.fixture()
def target(app_client):
    r = app_client.post("/api/targets", json={
        "name": "ServiceNow agent", "harness_arn": ARN, "region": "us-east-1", "environment": "staging",
        "owner_attestation": "We own and operate this staging agent."})
    assert r.status_code == 201, r.text
    return r.json()
