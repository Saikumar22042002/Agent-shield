"""PyRIT results reader (read-only).

Field names are from the PyRIT 1.1.0 memory docs (verified 2026-10-29):
  https://microsoft.github.io/PyRIT/1.1.0/code/memory/memory-data-types
  MessagePiece: id, conversation_id, sequence, role, original_value, converted_value, labels, timestamp, ...
  Score: score_value, score_type ("true_false" | "float_scale"), score_category, score_rationale,
         scorer_class_identifier, message_piece_id, objective, ...
  AttackResult: conversation_id, objective, atomic_attack_identifier, outcome
                ("SUCCESS" | "FAILURE" | "UNDETERMINED"), outcome_reason, ...

UNVERIFIED: PyRIT's own export method/file layout. AgentShield therefore accepts one JSON file
with these three lists, which the team dumps from PyRIT memory (see README "Importing PyRIT"):
  {"pyrit_version": "...", "message_pieces": [...], "scores": [...], "attack_results": [...]}

Verdict rules — evidence only, from the team's own scorers:
  attack_results present for a conversation: outcome SUCCESS (objective achieved) -> fail,
     FAILURE -> pass, UNDETERMINED -> inconclusive.
  else scores: true_false "true" -> fail; float_scale >= threshold -> fail; otherwise pass.
  no scores and no outcome -> inconclusive.
"""
from __future__ import annotations

import json
from collections import defaultdict

from .common import IngestError, ParsedAttempt, ParseResult, parse_ts


def _is_true(v) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


def parse(data: bytes, *, fail_threshold: float) -> ParseResult:
    try:
        doc = json.loads(data)
    except json.JSONDecodeError as e:
        raise IngestError(f"PyRIT file is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or "message_pieces" not in doc:
        raise IngestError("PyRIT file must be an object with a 'message_pieces' list (see README).")

    res = ParseResult(tool="pyrit", tool_version=str(doc.get("pyrit_version", "")))
    pieces = doc.get("message_pieces") or []
    by_conv: dict[str, list[dict]] = defaultdict(list)
    piece_conv: dict[str, str] = {}
    for p in pieces:
        cid = str(p.get("conversation_id") or "")
        if not cid:
            res.warnings.append("message piece without conversation_id skipped")
            continue
        by_conv[cid].append(p)
        if p.get("id"):
            piece_conv[str(p["id"])] = cid

    scores_by_conv: dict[str, list[dict]] = defaultdict(list)
    for sc in doc.get("scores") or []:
        cid = piece_conv.get(str(sc.get("message_piece_id", "")))
        if cid:
            scores_by_conv[cid].append(sc)
        else:
            res.warnings.append(f"score for unknown message_piece_id {sc.get('message_piece_id')} skipped")

    outcomes = {str(a.get("conversation_id")): a for a in doc.get("attack_results") or [] if a.get("conversation_id")}

    for cid, plist in by_conv.items():
        plist.sort(key=lambda p: p.get("sequence", 0))
        turns = [{"role": p.get("role", ""),
                  # what was actually sent/received after converters
                  "text": p.get("converted_value") if p.get("converted_value") is not None else p.get("original_value", "")}
                 for p in plist]
        labels: dict = {}
        for p in plist:
            labels.update(p.get("labels") or {})
        ar = outcomes.get(cid)
        test_id = str(labels.get("test_id") or (ar or {}).get("atomic_attack_identifier") or "pyrit")
        if isinstance((ar or {}).get("atomic_attack_identifier"), dict) and not labels.get("test_id"):
            ident = ar["atomic_attack_identifier"]
            test_id = str(ident.get("__type__") or ident.get("class_name") or ident)

        detector, score, verdict, why = "", None, "inconclusive", "no scorer output or outcome recorded"
        scs = scores_by_conv.get(cid, [])
        if ar and ar.get("outcome"):
            outcome = str(ar["outcome"]).upper().split(".")[-1]
            verdict = {"SUCCESS": "fail", "FAILURE": "pass"}.get(outcome, "inconclusive")
            why = f"PyRIT outcome {outcome}" + (f": {ar['outcome_reason']}" if ar.get("outcome_reason") else "")
        elif scs:
            verdict, why = "pass", "all scorer results below failure threshold"
            for sc in scs:
                stype = str(sc.get("score_type", ""))
                val = sc.get("score_value")
                name = str(sc.get("scorer_class_identifier", {}).get("__type__", "") if isinstance(sc.get("scorer_class_identifier"), dict) else sc.get("scorer_class_identifier", ""))
                hit = _is_true(val) if stype == "true_false" else (float(val) >= fail_threshold if val is not None else False)
                if stype == "float_scale" and val is not None:
                    score = max(score or 0.0, float(val))
                if hit:
                    detector, verdict = name, "fail"
                    why = f"{name}: {sc.get('score_rationale') or 'scored as failure'}"
                    if stype == "true_false":
                        score = 1.0
                    break
                detector = detector or name
        res.attempts.append(ParsedAttempt(
            external_id=cid, test_id=test_id, turns=turns, detector=detector, score=score, verdict=verdict,
            rationale=why, category_hint=str(labels.get("agentshield_category", "")),
            recorded_at=parse_ts(plist[0].get("timestamp"))))
    return res
