"""Console event bus. Events are persisted (table `events`) and the SSE endpoint tails the table,
so a reconnecting browser resumes from Last-Event-ID with nothing lost."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from .db import session_scope
from .models import Event
from .redact import redact


def publish(type_: str, data: dict[str, Any], run_id: str | None = None) -> int:
    data, _ = redact(data)  # every stream event is redacted here, whatever the caller already did
    with session_scope() as s:
        ev = Event(type=type_, run_id=run_id, data=data)
        s.add(ev)
        s.flush()
        return ev.id


def since(last_id: int, limit: int = 200) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.execute(select(Event).where(Event.id > last_id).order_by(Event.id).limit(limit)).scalars().all()
        return [{"id": r.id, "ts": r.ts.isoformat(), "type": r.type, "run_id": r.run_id, "data": r.data} for r in rows]


def recent(limit: int = 200) -> list[dict[str, Any]]:
    with session_scope() as s:
        rows = s.execute(select(Event).order_by(Event.id.desc()).limit(limit)).scalars().all()
        return [{"id": r.id, "ts": r.ts.isoformat(), "type": r.type, "run_id": r.run_id, "data": r.data}
                for r in reversed(rows)]


def latest_id() -> int:
    with session_scope() as s:
        return s.execute(select(Event.id).order_by(Event.id.desc()).limit(1)).scalar() or 0
