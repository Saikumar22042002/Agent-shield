"""PyRIT adapter: runs approved PyRIT cases with PyRIT's own attack strategies and scorers.

APIs used (PyRIT 1.1.0, checked against the installed package and the PyRIT docs):
  pyrit.prompt_target.PromptTarget            subclass; override `_send_prompt_to_target_async(*, normalized_conversation)`
                                              (`send_prompt_async` is final). Multi-turn support is declared with
                                              TargetConfiguration(capabilities=TargetCapabilities(supports_multi_turn=True)),
                                              which MultiPromptSendingAttack requires natively.
  pyrit.models.construct_response_from_request(request_piece, [text]) -> Message   the target's reply
  pyrit.executor.attack.PromptSendingAttack(objective_target=, attack_scoring_config=)
      .execute_async(objective=, next_message=Message)                              single turn
  pyrit.executor.attack.MultiPromptSendingAttack(objective_target=, attack_scoring_config=)
      .execute_async(objective=, user_messages=[Message, ...])                      fixed multi-turn sequence
  pyrit.executor.attack.AttackScoringConfig(objective_scorer=SubStringScorer(substring=...))
  AttackResult.outcome: AttackOutcome.SUCCESS | FAILURE | UNDETERMINED | ERROR
  pyrit.memory.CentralMemory / SQLiteMemory(db_path=":memory:")                    PyRIT's own memory

The target's only transport is `CaseContext.invoke`, i.e. the AgentShield gateway: every PyRIT prompt passes the
approved-input, budget, rate-limit, pause, stop and emergency-stop controls, and is persisted as an Invocation.

Outcome mapping (AgentShield verdict <- PyRIT outcome): SUCCESS (objective achieved, so the target failed) -> fail,
FAILURE -> pass, UNDETERMINED -> inconclusive, ERROR -> error. A SubStringScorer hit on the profile's planted canary is
an exact match on a value only the operator planted, so that failure is recorded as direct evidence (confirmed).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from pathlib import Path

from ..config import get_settings
from ..gateway import GatewayRefused
from ..redact import redact, redact_text
from .orchestrator import CaseContext, CaseResult

_memory_lock = threading.Lock()
_memory_ready = False
OUTCOME_VERDICT = {"success": "fail", "failure": "pass", "undetermined": "inconclusive", "error": "error"}


class TargetCallFailed(RuntimeError):
    """The gateway reached the target but the call failed (timeout, provider error). PyRIT surfaces it as an error."""


def ensure_memory() -> None:
    """PyRIT keeps conversations in CentralMemory. AgentShield uses an in-memory SQLite memory per process (PyRIT
    serialises its sessions on that connection, so parallel cases are safe); the evidence AgentShield keeps is the
    exported case file plus the gateway's Invocation rows."""
    global _memory_ready
    with _memory_lock:
        if _memory_ready:
            return
        from pyrit.memory import CentralMemory, SQLiteMemory

        CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:", silent=True))
        _memory_ready = True


def _gateway_target_class():
    from pyrit.models import construct_response_from_request
    from pyrit.prompt_target import PromptTarget, TargetCapabilities, TargetConfiguration

    class AgentShieldGatewayTarget(PromptTarget):
        """A PyRIT target whose only way out is the AgentShield gateway."""

        _DEFAULT_CONFIGURATION = TargetConfiguration(capabilities=TargetCapabilities(supports_multi_turn=True))

        def __init__(self, *, ctx: CaseContext) -> None:
            super().__init__(model_name="agentshield-gateway", endpoint="agentshield-gateway")
            self._ctx = ctx

        async def _send_prompt_to_target_async(self, *, normalized_conversation):
            request = normalized_conversation[-1].get_piece()
            turn = sum(1 for m in normalized_conversation if m.get_piece().api_role == "user")
            res = await asyncio.to_thread(self._ctx.invoke, request.converted_value, turn=turn)
            if res.status != "ok":
                raise TargetCallFailed(res.error or "target call failed")
            return [construct_response_from_request(request, [res.text])]

    return AgentShieldGatewayTarget


def _find(exc: BaseException | None, kind: type) -> BaseException | None:
    """PyRIT wraps exceptions raised by a target; find the original (GatewayRefused, TargetCallFailed)."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, kind):
            return exc
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return None


async def _execute(ctx: CaseContext):
    from pyrit.executor.attack import AttackScoringConfig, MultiPromptSendingAttack, PromptSendingAttack
    from pyrit.models import Message, MessagePiece
    from pyrit.score import SubStringScorer

    case = ctx.case
    target = _gateway_target_class()(ctx=ctx)
    scorer = case.get("scorer") or None
    scoring = AttackScoringConfig(objective_scorer=SubStringScorer(substring=scorer["substring"])) if scorer else None
    objective = case.get("objective") or case["label"]
    labels = {"agentshield_run": ctx.run_id, "agentshield_case": case["id"], "test_id": case["technique_id"]}
    msgs = [Message(message_pieces=[MessagePiece(role="user", original_value=t)]) for t in case["turns"]]
    if case["strategy"] == "MultiPromptSendingAttack":
        attack = MultiPromptSendingAttack(objective_target=target, attack_scoring_config=scoring)
        return await attack.execute_async(objective=objective, user_messages=msgs, memory_labels=labels)
    if case["strategy"] == "PromptSendingAttack":
        attack = PromptSendingAttack(objective_target=target, attack_scoring_config=scoring)
        return await attack.execute_async(objective=objective, next_message=msgs[0], memory_labels=labels)
    raise ValueError(f"Unsupported PyRIT strategy {case['strategy']!r}")


def _export(ctx: CaseContext, result, version: str) -> tuple[list[dict], dict]:
    """Write PyRIT's record of the case in AgentShield's PyRIT import layout (message_pieces, scores,
    attack_results), redacted, and return (turns, evidence)."""
    from pyrit.memory import CentralMemory

    mem = CentralMemory.get_memory_instance()
    pieces = sorted(mem.get_message_pieces(conversation_id=result.conversation_id), key=lambda p: p.sequence)
    scores = mem.get_prompt_scores(conversation_id=result.conversation_id)
    doc = {
        "pyrit_version": version,
        "message_pieces": [{"id": str(p.id), "conversation_id": str(p.conversation_id), "sequence": p.sequence,
                            "role": p.api_role, "original_value": p.original_value, "converted_value": p.converted_value,
                            "labels": dict(getattr(p, "labels", None) or {}) | {"test_id": ctx.case["technique_id"], "agentshield_case": ctx.case["id"]},
                            "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                            "response_error": p.response_error} for p in pieces],
        "scores": [{"message_piece_id": str(s.message_piece_id), "score_value": s.score_value,
                    "score_type": s.score_type, "score_rationale": s.score_rationale,
                    "score_category": s.score_category,
                    "scorer_class_identifier": {"__type__": getattr(s.scorer_class_identifier, "class_name", "")
                                                or str(s.scorer_class_identifier)}} for s in scores],
        "attack_results": [{"conversation_id": result.conversation_id, "objective": result.objective,
                            "outcome": result.outcome.value.upper(), "outcome_reason": result.outcome_reason,
                            "executed_turns": result.executed_turns, "execution_time_ms": result.execution_time_ms,
                            "atomic_attack_identifier": ctx.case["strategy"]}],
    }
    doc, _ = redact(doc)
    folder = Path(get_settings().evidence_dir) / ctx.run_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{ctx.case['id']}-pyrit.json"
    data = json.dumps(doc, indent=2, default=str).encode()
    path.write_bytes(data)
    turns = [{"role": p["role"], "text": p["converted_value"] if p["converted_value"] is not None else p["original_value"]}
             for p in doc["message_pieces"]]
    return turns, {"file": str(path), "sha256": hashlib.sha256(data).hexdigest(), "format": "agentshield-pyrit-json"}


def run_case(ctx: CaseContext) -> CaseResult:
    from importlib.metadata import version as dist_version

    ensure_memory()
    version = dist_version("pyrit")
    case = ctx.case
    try:
        result = asyncio.run(_execute(ctx))
    except Exception as e:
        refused = _find(e, GatewayRefused)
        if refused is not None:
            raise refused from None  # the orchestrator decides: stop, skip or error
        failed = _find(e, TargetCallFailed)
        msg, _ = redact_text(str(failed or e))
        return CaseResult(verdict="error", source_verdict="ERROR", test_id=case["strategy"], engine_version=version,
                          strategy=case["strategy"], error=msg[:800], detector=(case.get("scorer") or {}).get("class", ""),
                          source_detail={"exception": type(e).__name__})
    outcome = result.outcome.value  # success | failure | undetermined | error
    verdict = OUTCOME_VERDICT.get(outcome, "inconclusive")
    turns, evidence = _export(ctx, result, version)
    score = None
    if result.last_score is not None:
        raw = result.last_score.get_value()
        score = 1.0 if raw is True else 0.0 if raw is False else (float(raw) if isinstance(raw, (int, float)) else None)
    reason, _ = redact_text(result.outcome_reason or "")
    if verdict == "fail" and case.get("scorer"):
        evidence["confirmation"] = (f"PyRIT {case['scorer']['class']} found the operator-planted canary in the "
                                    "target's reply (exact match).")
    return CaseResult(
        verdict=verdict, source_verdict=outcome.upper(), test_id=case["strategy"],
        detector=(case.get("scorer") or {}).get("class", ""), score=score,
        rationale=f"PyRIT outcome {outcome.upper()}" + (f": {reason}" if reason else ""),
        turns=turns, engine_version=version, strategy=case["strategy"], evidence=evidence,
        error=(result.error_message or "") if outcome == "error" else "",
        source_detail={"conversation_id": result.conversation_id, "outcome": outcome.upper(),
                       "outcome_reason": reason, "executed_turns": result.executed_turns,
                       "execution_time_ms": result.execution_time_ms,
                       "objective_scorer": case.get("scorer"), "attack_result_id": result.attack_result_id})
