"""SQLite engine (WAL) + a minimal ordered migration runner."""
from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _sqlite_pragmas(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


def init_engine(url: str | None = None) -> Engine:
    global _engine, _SessionLocal
    url = url or get_settings().database_url
    if url.startswith("sqlite:///") and ":memory:" not in url:
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(url, connect_args={"check_same_thread": False}, future=True)
    event.listen(_engine, "connect", _sqlite_pragmas)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    migrate(_engine)
    return _engine


def _add_columns(table: str, columns: dict[str, str]):
    """Idempotent ADD COLUMN step: a fresh DB already has them from create_all."""

    def step(conn) -> None:
        have = {r[1] for r in conn.execute(text(f"PRAGMA table_info({table})"))}
        if not have:  # table not created yet; a later create step builds it with every column
            return
        for name, ddl in columns.items():
            if name not in have:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))

    return step


# Ordered migrations. Version 1 is the declarative schema in models.py; later entries are
# raw DDL or idempotent callables applied once each. Append only — never edit a shipped entry.
MIGRATIONS: list = [
    "__create_all__",
    _add_columns("test_attempts", {"model_verdict": "VARCHAR(16)", "model_rationale": "TEXT",
                                   "model_id": "VARCHAR(200)", "model_judged_at": "DATETIME"}),
    _add_columns("targets", {"provider": "VARCHAR(32) NOT NULL DEFAULT 'aws_agentcore'",
                             "config": "JSON NOT NULL DEFAULT '{}'",
                             "archived": "BOOLEAN NOT NULL DEFAULT 0"}),
    # v4: assessment execution — target profiles, run assessment state, plans, gateway invocations,
    # and executed-test columns on test_attempts (import_id becomes nullable, so that table is rebuilt).
    _add_columns("targets", {"profile": "JSON NOT NULL DEFAULT '{}'"}),
    _add_columns("runs", {"assessment_status": "VARCHAR(16) NOT NULL DEFAULT 'idle'",
                          "assessment_phase": "VARCHAR(32) NOT NULL DEFAULT ''",
                          "stop_reason": "TEXT NOT NULL DEFAULT ''",
                          "limits": "JSON NOT NULL DEFAULT '{}'"}),
    "__create_missing__",
    "__rebuild_test_attempts__",
    # v8: execution bookkeeping per run (coordinator, attacker token usage, progress)
    _add_columns("runs", {"assessment": "JSON NOT NULL DEFAULT '{}'"}),
    # v9: gateway retries are their own invocations
    _add_columns("invocations", {"attempt": "INTEGER NOT NULL DEFAULT 0"}),
    # v10: candidate / confirmed / dismissed findings, and the operator decisions that drive them
    _add_columns("findings", {"confirmation": "VARCHAR(16) NOT NULL DEFAULT 'candidate'",
                              "confirmation_basis": "TEXT NOT NULL DEFAULT ''"}),
    "__create_missing__",
]


def _rebuild_test_attempts(engine: Engine) -> None:
    """SQLite cannot drop NOT NULL in place. Recreate test_attempts from the current model and copy the rows,
    following https://www.sqlite.org/lang_altertable.html#otheralter (foreign keys off for the swap)."""
    from sqlalchemy.schema import CreateTable

    from .models import TestAttempt

    with engine.connect() as conn:
        cols = {r[1]: r for r in conn.execute(text("PRAGMA table_info(test_attempts)"))}
        if cols and not cols["import_id"][3]:  # notnull flag already 0: fresh schema, nothing to do
            return
    import json

    table = TestAttempt.__table__
    shared = [c for c in cols if c in table.c]
    # Columns new to this table get the model's default; existing rows would otherwise violate NOT NULL.
    fill: dict[str, object] = {}
    for c in table.c:
        if c.name in cols or c.default is None:
            continue
        arg = c.default.arg(None) if c.default.is_callable else c.default.arg  # e.g. default=dict -> {}
        fill[c.name] =json.dumps(arg) if isinstance(arg, (dict, list)) else arg
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        cur.execute("PRAGMA foreign_keys=OFF")
        cur.execute("BEGIN")
        try:
            ddl = str(CreateTable(table).compile(engine)).replace(
                "CREATE TABLE test_attempts", "CREATE TABLE test_attempts_new", 1)
            cur.execute(ddl)
            names = shared + list(fill)
            exprs = shared + ["?"] * len(fill)
            cur.execute(f"INSERT INTO test_attempts_new ({', '.join(names)}) "
                        f"SELECT {', '.join(exprs)} FROM test_attempts", list(fill.values()))
            cur.execute("DROP TABLE test_attempts")
            cur.execute("ALTER TABLE test_attempts_new RENAME TO test_attempts")
            for idx in table.indexes:
                cur.execute(f"CREATE INDEX IF NOT EXISTS {idx.name} ON test_attempts ({', '.join(c.name for c in idx.columns)})")
            bad = cur.execute("PRAGMA foreign_key_check").fetchall()
            if bad:
                raise RuntimeError(f"foreign key check failed after rebuilding test_attempts: {bad[:5]}")
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise
        finally:
            cur.execute("PRAGMA foreign_keys=ON")
    finally:
        raw.close()


def _backup_before_migration(engine: Engine, current: int) -> Path | None:
    """Copy an existing file database before applying pending migrations (sqlite3 online backup API, so a WAL
    database is copied consistently). The copy sits next to the database and is never deleted automatically."""
    import sqlite3
    from datetime import datetime

    database = engine.url.database  # str(engine.url) percent-encodes the drive colon on Windows
    if engine.url.get_backend_name() != "sqlite" or not database or ":memory:" in database:
        return None
    src = Path(database)
    if not src.exists():
        return None
    dst = src.with_name(f"{src.name}.bak-v{current}-{datetime.now():%Y%m%d-%H%M%S}")
    with sqlite3.connect(src) as a, sqlite3.connect(dst) as b:
        a.backup(b)
    return dst


def migrate(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"))
        row = conn.execute(text("SELECT MAX(version) FROM schema_version")).scalar()
        current = row or 0
    if 0 < current < len(MIGRATIONS):
        backup = _backup_before_migration(engine, current)
        if backup:
            import logging

            logging.getLogger("agentshield.db").warning("Backed up database to %s before migrating v%d -> v%d",
                                                         backup, current, len(MIGRATIONS))
    for idx, step in enumerate(MIGRATIONS, start=1):
        if idx <= current:
            continue
        if step == "__rebuild_test_attempts__":
            _rebuild_test_attempts(engine)  # manages its own transaction
            with engine.begin() as conn:
                conn.execute(text("INSERT INTO schema_version (version) VALUES (:v)"), {"v": idx})
            continue
        with engine.begin() as conn:
            if step in ("__create_all__", "__create_missing__"):
                Base.metadata.create_all(conn)  # checkfirst: only tables that do not exist yet
            elif callable(step):
                step(conn)
            else:
                conn.execute(text(step))
            conn.execute(text("INSERT INTO schema_version (version) VALUES (:v)"), {"v": idx})


class InstanceLocked(RuntimeError):
    """Another AgentShield server process already serves this database."""


_held: dict[str, list] = {}  # lock path -> [file handle, users in this process]
_held_lock = __import__("threading").Lock()


def acquire_instance_lock():
    """OS-level exclusive lock on '<database>.lock'. The gateway's budget reservation lock, run controls, rate
    limits and executing assessments live in process memory, so exactly one server process may serve a database
    (run uvicorn with a single worker). Re-entrant inside one process, which shares that state. Returns a key to pass
    to release_instance_lock, or None for in-memory and non-SQLite databases. The OS drops the lock if the process
    dies."""
    e = engine()
    database = e.url.database
    if e.url.get_backend_name() != "sqlite" or not database or ":memory:" in database:
        return None
    key = str(Path(database).resolve()) + ".lock"
    with _held_lock:
        if key in _held:
            _held[key][1] += 1
            return key
        fh = open(key, "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as err:
            fh.close()
            raise InstanceLocked(f"Another AgentShield process is already serving {database}. Run a single server "
                                 "process (one uvicorn worker) per database.") from err
        _held[key] = [fh, 1]
        return key


def release_instance_lock(key) -> None:
    if key is None:
        return
    with _held_lock:
        entry = _held.get(key)
        if entry is None:
            return
        entry[1] -= 1
        if entry[1] > 0:
            return
        del _held[key]
        fh = entry[0]
        try:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            fh.close()


def engine() -> Engine:
    if _engine is None:
        init_engine()
    assert _engine is not None
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    if _SessionLocal is None:
        init_engine()
    assert _SessionLocal is not None
    s = _SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
