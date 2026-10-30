"""Local development stub target. No network call, no model, no AWS.

It exists so the console, gateway, run lifecycle, live stream, persistence and audit trail can be exercised
without cloud credentials. Its reply is fixed text that names itself as a stub, so it can never be mistaken for
a real agent (ServiceNow, AgentCore or otherwise). It does not evaluate, obey or refuse anything: every reply has
the same shape regardless of the message, so it cannot produce a security finding.

What it does track is per-session turn count and a fingerprint of the previous message *in the same session*,
which is what makes conversation isolation testable: two concurrent conversations each see only their own
history. Latency is the measured in-process round trip (plus the optional configured delay); token usage is
left empty because no model is involved.

Target.config (optional): reply_delay_ms — sleep this long while "streaming" the reply, in 4 chunks, so pause,
stop, timeouts and the live stream can be observed mid-call.
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid

from ..audit import record as audit
from .base import ConnectorInput, ConnectorOutput

STUB_REPLY = (
    "[Local stub target] Message received ({chars} characters). "
    "This reply comes from AgentShield's built-in development stub. "
    "It is not a real agent, not ServiceNow and not AWS, and it does not call a model. "
    "Session turn {turn}; previous message in this session: {prev}."
)

_sessions: dict[str, list[str]] = {}  # session id -> sha256[:12] of each message received, in order
_lock = threading.Lock()


def session_history(session_id: str) -> list[str]:
    with _lock:
        return list(_sessions.get(session_id, []))


class LocalStubConnector:
    def __init__(self, *, run_id: str | None = None, target_id: int | None = None, config: dict | None = None, **_kw):
        self.run_id = run_id
        self.target_id = target_id
        try:
            self.delay_s = max(0.0, min(float((config or {}).get("reply_delay_ms", 0) or 0), 60000.0)) / 1000
        except (TypeError, ValueError):
            self.delay_s = 0.0
        self._on_delta = None

    def set_delta_handler(self, fn) -> None:
        self._on_delta = fn

    def new_session_id(self) -> str:
        return f"agentshield-stub-{uuid.uuid4()}"

    def send(self, inp: ConnectorInput) -> ConnectorOutput:
        audit("connector.request", {"provider": "local_stub", "session": inp.session_id, "text": inp.text},
              run_id=self.run_id, target_id=self.target_id)
        t0 = time.perf_counter()
        fp = hashlib.sha256(inp.text.encode()).hexdigest()[:12]
        with _lock:
            hist = _sessions.setdefault(inp.session_id, [])
            prev = hist[-1] if hist else "none"
            hist.append(fp)
            turn = len(hist)
        text = STUB_REPLY.format(chars=len(inp.text), turn=turn, prev=f"sha256 {prev}" if prev != "none" else "none")
        pieces = [p if p.endswith(".") else p + ". " for p in text.split(". ")]
        for i, piece in enumerate(pieces):  # emitted in pieces so the console's streaming path is exercised
            if self.delay_s:
                time.sleep(self.delay_s / len(pieces))
            if self._on_delta:
                self._on_delta(piece if i == len(pieces) - 1 else piece)
        wall = (time.perf_counter() - t0) * 1000
        out = ConnectorOutput(text=text, session_id=inp.session_id, latency_ms=None, wall_ms=wall, usage={},
                              stop_reason="end_turn")
        audit("connector.response", {"provider": "local_stub", "session": inp.session_id, "text": text,
                                     "wallMs": wall}, run_id=self.run_id, target_id=self.target_id)
        return out
