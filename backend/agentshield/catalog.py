"""Versioned technique catalog (backend/technique_catalog.json) and the merged taxonomy used by findings.

Terms kept distinct throughout AgentShield:
  risk category  — an OWASP entry (LLM01..LLM10, ASI01..ASI10)
  technique      — a catalog entry (AS-PI-01 ...) that tests one or more risk categories
  execution      — a documented framework strategy that tests a technique (garak probe, PyRIT attack + dataset)
  test case      — one approved unit of work in a run's plan (a PyRIT conversation or one garak probe run)
  finding        — derived from executed or imported tests whose framework verdict shows the failure
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .config import get_settings
from .ingest.common import load_category_map


@lru_cache
def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def catalog() -> dict:
    return _load(str(get_settings().technique_catalog_file))


def technique(tid: str) -> dict:
    t = catalog()["techniques"].get(tid)
    if t is None:
        raise KeyError(f"unknown technique {tid}")
    return t | {"id": tid}


def taxonomy() -> dict:
    """category_map.json (import categories T-01..) merged with catalog techniques, so findings from both
    paths resolve title, severity and remediation the same way."""
    cmap = load_category_map(str(get_settings().category_map_file))
    cat = catalog()
    cats = dict(cmap["categories"])
    for tid, t in cat["techniques"].items():
        cats[tid] = {"title": t["title"], "severity": t["severity"], "remediation_key": t["remediation_key"],
                     "risks": t["risks"], "match_prefixes": [], "kind": t.get("kind", "security")}
    return {"categories": cats, "remediations": cmap["remediations"] | cat["remediations"],
            "import_categories": list(cmap["categories"])}


def execution_key(e: dict) -> str:
    """Stable id of one execution inside a technique, e.g. 'garak:encoding.InjectBase64' or
    'pyrit:PromptSendingAttack:garak_system_prompt_extraction'."""
    if e["engine"] == "garak":
        return f"garak:{e['probe']}"
    return ":".join(x for x in ("pyrit", e["strategy"], e.get("dataset", "")) if x)


def inventory(engines: dict[str, dict]) -> dict:
    """What this installation can actually execute: catalog executions x installed, working engines.
    Nothing here claims coverage; an executable technique is one whose framework strategy can run."""
    cat = catalog()
    rows = []
    for tid, t in cat["techniques"].items():
        execs = [e | {"key": execution_key(e), "available": bool(engines.get(e["engine"], {}).get("available")),
                      "engine_version": engines.get(e["engine"], {}).get("version", "")} for e in t["executions"]]
        rows.append({"id": tid, "kind": t.get("kind", "security"), "title": t["title"], "risks": t["risks"],
                     "severity": t["severity"], "requires": t["requires"], "objective": t["objective"],
                     "expected_secure_behavior": t.get("expected_secure_behavior", ""), "executions": execs,
                     "executable": any(e["available"] for e in execs),
                     "not_executable_reason": t.get("not_executable_reason", "") if not execs else (
                         "" if any(e["available"] for e in execs) else "Required engine is not installed or not working.")})
    sec = [r for r in rows if r["kind"] == "security"]
    return {"catalog_version": cat["version"], "techniques": rows, "engines": engines,
            "executable_security_techniques": sum(1 for r in sec if r["executable"]),
            "security_techniques": len(sec),
            "risk_categories": [{"id": k, **v, "tested_by": [t["id"] for t in sec if k in t["risks"] and t["executable"]],
                                 "unsupported_reason": cat["unsupported"].get(k, "")}
                                for k, v in cat["risk_categories"].items()],
            "unsupported": [{"id": k, "title": cat["risk_categories"][k]["title"], "reason": v}
                            for k, v in cat["unsupported"].items()]}
