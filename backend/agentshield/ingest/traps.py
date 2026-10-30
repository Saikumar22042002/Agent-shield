"""Trap-hit log reader (read-only). The team's own trap/callback infrastructure records hits;
AgentShield imports them as evidence and links each to an imported attempt.

Format (AgentShield's contract): JSON Lines, one object per hit:
  {"token_id": "...", "external_id": "<garak attempt uuid | pyrit conversation_id>",
   "received_at": "2026-10-29T12:00:00Z", "source": "<ip or host, optional>"}
"""
from __future__ import annotations

import json
from collections.abc import Iterable

from .common import IngestError, ParsedTrapHit, ParseResult, parse_ts


def parse(lines: Iterable[str]) -> ParseResult:
    res = ParseResult(tool="traps")
    for n, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            res.warnings.append(f"line {n}: not JSON, skipped")
            continue
        if not row.get("token_id") or not row.get("external_id"):
            res.warnings.append(f"line {n}: needs token_id and external_id, skipped")
            continue
        res.trap_hits.append(ParsedTrapHit(token_id=str(row["token_id"]), external_id=str(row["external_id"]),
                                           received_at=parse_ts(row.get("received_at")),
                                           source=str(row.get("source", ""))))
    if not res.trap_hits and not res.warnings:
        raise IngestError("Trap log is empty.")
    return res
