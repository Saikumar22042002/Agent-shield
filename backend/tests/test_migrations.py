"""Schema migration safety: a real v3 schema (tests/fixtures/schema_v3.sql) with data is migrated to the current
version without losing rows, breaking foreign keys or the audit hash chain; migration is idempotent and backs the
database up first. Offline; works on a temporary file only."""
import json
import sqlite3
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "schema_v3.sql"
TS = "2026-10-29 10:00:00.000000"  # SQLAlchemy's SQLite DateTime storage format
TS_ISO = "2026-10-29T10:00:00+00:00"  # what audit.verify_chain hashes after reading it back as UTC
TABLES = ["targets", "runs", "imports", "test_attempts", "findings", "trap_hits", "audit_log", "events"]


def _v3_db(path: Path) -> None:
    from agentshield.audit import GENESIS, _digest

    c = sqlite3.connect(path)
    c.executescript(FIXTURE.read_text(encoding="utf-8"))
    c.execute("INSERT INTO targets VALUES (1,'Legacy agent','arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/a-abcdefghij',"
              "'','us-east-1','staging','','','We own it.','error',NULL,NULL,NULL,NULL,'AccessDeniedException: x',?,"
              "'aws_agentcore','{}',0)", (TS,))
    c.execute("INSERT INTO runs VALUES ('RUN-1',1,'baseline','open',NULL,'{\"attempts\": 2}','',?,NULL)", (TS,))
    c.execute("INSERT INTO runs VALUES ('RUN-2',1,'re-test','complete','RUN-1',NULL,'',?,?)", (TS, TS))
    c.execute("INSERT INTO imports VALUES (1,'RUN-1','garak','r.jsonl','ab0','0.9','alice','{}','[]',?)", (TS,))
    c.execute("INSERT INTO test_attempts VALUES (1,'RUN-1',1,'garak','u1','T-03','probes.dan.X','[]','d',0.9,'fail','r',0,"
              "'Medium',NULL,'pass','advisory','groq:m',?)", (TS,))
    c.execute("INSERT INTO test_attempts VALUES (2,'RUN-1',1,'garak','u2','T-03','probes.dan.X','[]','d',0.1,'pass','r',1,"
              "'Medium',NULL,NULL,NULL,NULL,NULL)")
    c.execute("INSERT INTO findings VALUES (1,'RUN-1',1,'T-03','probes.dan.X','Medium','t','{}','k','open',NULL,?)", (TS,))
    c.execute("INSERT INTO trap_hits VALUES (1,'RUN-1',1,'tok','u2',NULL,'10.0.0.5',2)")
    c.execute("INSERT INTO events VALUES (1,?,'run.created','RUN-1','{}')", (TS,))
    prev = GENESIS
    for i, (action, payload) in enumerate([("server.start", {}), ("run.create", {"label": "baseline"})], start=1):
        h = _digest(prev, TS_ISO, "alice", action, "RUN-1", payload)
        c.execute("INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?,?)",
                  (i, TS, "alice", action, "RUN-1", None, json.dumps(payload), prev, h))
        prev = h
    c.commit()
    c.close()


def _counts(path: Path) -> dict:
    c = sqlite3.connect(path)
    out = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}
    out["version"] = c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    c.close()
    return out


@pytest.fixture()
def fresh_engine_state():
    from agentshield import db

    yield db
    if db._engine is not None:
        db._engine.dispose()
    db._engine = db._SessionLocal = None


def test_v3_database_migrates_without_data_loss(tmp_path, fresh_engine_state):
    db = fresh_engine_state
    from agentshield import audit

    path = tmp_path / "agentshield.db"
    _v3_db(path)
    before = _counts(path)
    assert before["version"] == 3

    db.init_engine(f"sqlite:///{path.as_posix()}")
    after = _counts(path)
    assert after["version"] == len(db.MIGRATIONS) == 11
    assert {k: v for k, v in after.items() if k != "version"} == {k: v for k, v in before.items() if k != "version"}
    assert audit.verify_chain() == (True, None)

    c = sqlite3.connect(path)
    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert c.execute("PRAGMA foreign_key_check").fetchall() == []
    run_cols = {r[1] for r in c.execute("PRAGMA table_info(runs)")}
    assert {"assessment_status", "assessment_phase", "stop_reason", "limits", "assessment"} <= run_cols
    assert "profile" in {r[1] for r in c.execute("PRAGMA table_info(targets)")}
    ta = {r[1]: r for r in c.execute("PRAGMA table_info(test_attempts)")}
    assert ta["import_id"][3] == 0  # nullable now, for executed tests
    assert {"provenance", "engine", "source_verdict", "invocation_ids"} <= set(ta)
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"invocations", "assessment_plans"} <= tables
    # existing values kept, new columns defaulted
    row = c.execute("SELECT verdict, model_verdict, model_id, provenance, import_id FROM test_attempts WHERE id=1").fetchone()
    assert row == ("fail", "pass", "groq:m", "imported", 1)
    assert c.execute("SELECT assessment_status, assessment FROM runs WHERE id='RUN-1'").fetchone() == ("idle", "{}")
    assert c.execute("SELECT attempt_id FROM trap_hits WHERE id=1").fetchone() == (2,)
    c.close()

    backups = sorted(tmp_path.glob("agentshield.db.bak-v3-*"))
    assert len(backups) == 1 and _counts(backups[0]) == before  # untouched pre-migration copy

    # idempotent: a second start changes nothing and takes no new backup
    db._engine.dispose()
    db.init_engine(f"sqlite:///{path.as_posix()}")
    assert _counts(path) == after
    assert len(list(tmp_path.glob("agentshield.db.bak-*"))) == 1


def test_migrated_database_accepts_executed_attempts(tmp_path, fresh_engine_state):
    db = fresh_engine_state
    from agentshield.models import TestAttempt

    path = tmp_path / "agentshield.db"
    _v3_db(path)
    db.init_engine(f"sqlite:///{path.as_posix()}")
    with db.session_scope() as s:
        s.add(TestAttempt(run_id="RUN-1", import_id=None, provenance="local-execution", engine="garak",
                          source="garak", external_id="C01", category="PLUMB-GARAK", test_id="test.Test",
                          verdict="pass"))
    c = sqlite3.connect(path)
    assert c.execute("SELECT COUNT(*) FROM test_attempts WHERE import_id IS NULL").fetchone()[0] == 1
    c.close()


def test_fresh_database_is_created_at_current_version_without_backup(tmp_path, fresh_engine_state):
    db = fresh_engine_state
    path = tmp_path / "new.db"
    db.init_engine(f"sqlite:///{path.as_posix()}")
    assert _counts(path)["version"] == len(db.MIGRATIONS)
    assert not list(tmp_path.glob("new.db.bak-*"))
