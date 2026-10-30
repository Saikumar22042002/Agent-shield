"""Cloud-neutral connector interface. AWS is the only implementation in this POC."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ConnectorInput:
    text: str
    session_id: str  # reused across turns for multi-turn tests


@dataclass
class ConnectorOutput:
    text: str
    session_id: str
    latency_ms: float | None = None  # service-reported (metadata.metrics.latencyMs)
    wall_ms: float | None = None  # client-measured round trip
    usage: dict = field(default_factory=dict)
    stop_reason: str = ""
    tool_events: list[dict] = field(default_factory=list)  # toolUse/hook events seen in the stream


class ConnectorError(Exception):
    """Operator-facing error. `code` is the provider error name and `message` the provider's own message,
    kept verbatim. `hint` is AgentShield's guidance on what to fix; it is shown next to, never instead of,
    the original message."""

    def __init__(self, code: str, message: str, retryable: bool = False, hint: str = ""):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.retryable = retryable
        self.hint = hint


class Connector(Protocol):
    def send(self, inp: ConnectorInput) -> ConnectorOutput: ...

    def new_session_id(self) -> str: ...
