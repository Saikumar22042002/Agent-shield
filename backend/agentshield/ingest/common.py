"""Shared ingest types + category mapping. Parsers produce `ParsedAttempt`s; `store.py` persists."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path

UNMAPPED = "unmapped"


@dataclass
class ParsedAttempt:
    external_id: str
    test_id: str
    turns: list[dict]  # [{"role": "user"|"assistant"|..., "text": str}]
    detector: str
    score: float | None
    verdict: str  # pass|fail|inconclusive
    rationale: str
    category_hint: str = ""  # explicit label from the tool, if any
    recorded_at: datetime | None = None


@dataclass
class ParsedTrapHit:
    token_id: str
    external_id: str
    received_at: datetime | None
    source: str


@dataclass
class ParseResult:
    tool: str
    tool_version: str = ""
    attempts: list[ParsedAttempt] = field(default_factory=list)
    trap_hits: list[ParsedTrapHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class IngestError(ValueError):
    pass


@lru_cache
def load_category_map(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def categorize(test_id: str, hint: str, cmap: dict) -> str:
    cats = cmap["categories"]
    if hint and hint in cats:
        return hint
    for cid, spec in cats.items():
        if any(test_id.startswith(p) for p in spec.get("match_prefixes", [])):
            return cid
    return UNMAPPED


def parse_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
