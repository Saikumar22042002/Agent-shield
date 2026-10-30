"""Hash-chained, append-only audit log. Each row's hash covers its content + the previous hash,
so any edit or deletion breaks `verify_chain`."""
from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from sqlalchemy import select

from .db import session_scope
from .models import AuditLog, utcnow
from .redact import redact, redact_text

_lock = threading.Lock()
GENESIS = "0" * 64


def _digest(prev: str, ts: str, actor: str, action: str, run_id: str | None, payload: dict) -> str:
    body = json.dumps(
        {"prev": prev, "ts": ts, "actor": actor, "action": action, "run": run_id, "payload": payload},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(body.encode()).hexdigest()


def record(action: str, payload: dict[str, Any], *, actor: str = "system", run_id: str | None = None,
           target_id: int | None = None) -> None:
    # Redacted before hashing: the chain is append-only, so a secret written here could never be removed.
    payload, _ = redact(payload)
    actor, _ = redact_text(actor)
    with _lock, session_scope() as s:
        last = s.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
        prev = last or GENESIS
        ts = utcnow()
        h = _digest(prev, ts.isoformat(), actor, action, run_id, payload)
        s.add(AuditLog(ts=ts, actor=actor, action=action, run_id=run_id, target_id=target_id,
                       payload=payload, prev_hash=prev, hash=h))


def verify_chain() -> tuple[bool, int | None]:
    """Returns (ok, first_bad_id)."""
    with session_scope() as s:
        prev = GENESIS
        for row in s.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
            ts = row.ts.isoformat() if row.ts.tzinfo else row.ts.replace(tzinfo=utcnow().tzinfo).isoformat()
            if row.prev_hash != prev or _digest(prev, ts, row.actor, row.action, row.run_id, row.payload) != row.hash:
                return False, row.id
            prev = row.hash
    return True, None
