"""garak report.jsonl reader (read-only).

Doc-verified schema (2026-10-29):
  https://reference.garak.ai/en/latest/reporting.html
  https://github.com/NVIDIA/garak/blob/main/garak/attempt.py  (Attempt.as_dict)
  Every line is JSON with `entry_type`. We consume `attempt` lines:
    uuid: str, seq: int, status: int (0 new, 1 response not evaluated, 2 evaluated),
    probe_classname: str, prompt: {"turns": [{"role", "content": Message|str}], "notes"},
    outputs: [Message{"text", "lang", ...} | None] | None,
    detector_results: {detector_name: [score per output]}, notes: dict, goal: str
  Legacy form: a turn's `content` may be a plain string — handled.
  garak detector scores are 0..1 where higher = the detector fired (a hit).
UNVERIFIED: the exact key carrying the garak version in setup/init lines, so tool_version is
best-effort from any line that has `garak_version`.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

from .common import IngestError, ParsedAttempt, ParseResult


def _text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return content.get("text") or ""
    return str(content)


def parse(lines: Iterable[str], *, fail_threshold: float) -> ParseResult:
    res = ParseResult(tool="garak")
    seen_entry = False
    for n, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            res.warnings.append(f"line {n}: not JSON, skipped")
            continue
        if not isinstance(row, dict) or "entry_type" not in row:
            res.warnings.append(f"line {n}: no entry_type, skipped")
            continue
        seen_entry = True
        if not res.tool_version and row.get("garak_version"):
            res.tool_version = str(row["garak_version"])
        if row["entry_type"] != "attempt":
            continue
        if row.get("status") != 2:
            continue  # not evaluated by a detector — nothing to score
        uuid = str(row.get("uuid") or f"line-{n}")
        turns = [{"role": t.get("role", "user"), "text": _text(t.get("content"))}
                 for t in (row.get("prompt") or {}).get("turns", [])]
        outputs = row.get("outputs") or []
        for i, out in enumerate(outputs):
            turns.append({"role": "assistant", "text": _text(out), "generation": i})

        best_det, best_score = "", None
        for det, scores in (row.get("detector_results") or {}).items():
            for sc in scores or []:
                if sc is None:
                    continue
                if best_score is None or float(sc) > best_score:
                    best_det, best_score = det, float(sc)
        if best_score is None:
            verdict, why = "inconclusive", "no detector scores recorded"
        elif best_score >= fail_threshold:
            verdict, why = "fail", f"garak detector {best_det} scored {best_score:.2f} (threshold {fail_threshold})"
        else:
            verdict, why = "pass", f"highest garak detector score {best_score:.2f} below threshold {fail_threshold}"
        res.attempts.append(ParsedAttempt(
            external_id=uuid, test_id=str(row.get("probe_classname", "")), turns=turns,
            detector=best_det, score=best_score, verdict=verdict, rationale=why))
    if not seen_entry:
        raise IngestError("File does not look like a garak report.jsonl (no lines with entry_type).")
    return res
