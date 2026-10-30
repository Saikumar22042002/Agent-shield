"""Safety controls enforced in code.

Two kinds of traffic reach a target, both through `gateway.py`: the fixed, benign connectivity greeting
(`connectivity.py`, gated by the staging guard, the kill switch and a per-target rate limit), and prompts from an
operator-approved assessment plan (`gateway.invoke`, which adds plan, input, budget, rate and stop controls).

The kill switch is held in memory for speed, restored from the audit log at startup, and re-synchronised from the
audit log every second by the API (`sync_from_audit`), so a stop recorded by any process sharing the database is
honoured everywhere.
"""
from __future__ import annotations

import threading
import time

ALLOWED_ENVIRONMENT = "staging"  # deliberately not configurable


class SafetyViolation(Exception):
    pass


class Halted(Exception):
    pass


class RunNotActive(Exception):
    """The run is paused, stopped, halted or complete, so it accepts no imports or reviews."""


def assert_staging(environment: str) -> None:
    if (environment or "").strip().lower() != ALLOWED_ENVIRONMENT:
        raise SafetyViolation(
            f"Target environment is '{environment}'. AgentShield only works with staging targets.")


class KillSwitch:
    """Global halt flag. While tripped, no connector call is made and imports are refused."""

    def __init__(self) -> None:
        self._ev = threading.Event()
        self.reason = ""
        self.tripped_at: float | None = None

    def trip(self, reason: str = "") -> None:
        self.reason = reason
        self.tripped_at = time.time()
        self._ev.set()

    def reset(self) -> None:
        self.reason = ""
        self.tripped_at = None
        self._ev.clear()

    @property
    def tripped(self) -> bool:
        return self._ev.is_set()

    def check(self) -> None:
        if self._ev.is_set():
            raise Halted(self.reason or "Emergency stop is active.")


class MinInterval:
    """At most one call per `seconds` per key (e.g. per target)."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._last: dict[object, float] = {}
        self._lock = threading.Lock()

    def acquire(self, key: object) -> None:
        with self._lock:
            now = time.monotonic()
            last = self._last.get(key)
            if last is not None and now - last < self.seconds:
                raise SafetyViolation(f"Rate limited: wait {self.seconds - (now - last):.0f}s before checking again.")
            self._last[key] = now


KILL = KillSwitch()
