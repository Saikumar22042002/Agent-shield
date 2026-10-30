"""Registers the framework adapters that are installed and usable (called once at API start)."""
from __future__ import annotations

import logging

from . import engines, orchestrator

log = logging.getLogger("agentshield.adapters")


def register_defaults() -> list[str]:
    status = engines.status()
    registered = []
    if status["pyrit"]["available"]:
        from .pyrit_adapter import run_case as pyrit_case

        orchestrator.register("pyrit", pyrit_case)
        registered.append("pyrit")
    if status["garak"]["available"]:
        from .garak_adapter import run_case as garak_case

        orchestrator.register("garak", garak_case)
        registered.append("garak")
    missing = [e for e in ("pyrit", "garak") if e not in registered]
    if missing:
        log.warning("No execution adapter for: %s (%s)", ", ".join(missing),
                    "; ".join(status[e]["detail"] for e in missing))
    return registered
