"""Benign connectivity check: one fixed, configurable greeting to a registered staging target.

It is the only message sent outside an approved assessment plan (plan traffic goes through `gateway.invoke`, with
every plan control). It shares the gateway's send path, so it is timed out, redacted, persisted and audited the same
way. When it runs inside a run (`run_id`), the
greeting and the reply are also published as `conversation.*` events so the evaluation workspace can
show the exchange live; reply text arrives as `conversation.delta` events while the target streams.

Doc-verified signature used (via connectors/aws_agentcore.py):
  boto3.client("bedrock-agentcore").invoke_harness(harnessArn, runtimeSessionId (33..100 chars), messages)
  -> {"stream": EventStream}; usage from metadata.usage, latency from metadata.metrics.latencyMs
"""
from __future__ import annotations

import time
import uuid

from .audit import record as audit
from .config import get_settings
from .connectors import ConnectorError, ConnectorInput, ConnectorUnsupported, build_connector
from .connectors.aws_agentcore import hint_for
from .connectors.registry import get_provider
from .db import session_scope
from .events import publish
from .gateway import RETRY_BASE_S, DeltaPublisher
from .gateway import send as gateway_send
from .models import Run, Target, utcnow
from .safety import KILL, MinInterval, RunNotActive, assert_staging

_interval: MinInterval | None = None


def _limiter() -> MinInterval:
    global _interval
    if _interval is None:
        _interval = MinInterval(get_settings().connectivity_min_interval_s)
    return _interval


class TargetArchived(Exception):
    pass


def _build(target: Target, timeout_s: int, run_id: str | None):
    try:
        return build_connector(target, timeout_s=timeout_s, run_id=run_id)
    except ConnectorError:
        raise
    except Exception as e:  # botocore ProfileNotFound / NoRegionError / STS assume-role failures etc.
        code = type(e).__name__
        response = getattr(e, "response", None)
        if isinstance(response, dict):  # botocore ClientError from STS assume-role
            code = response.get("Error", {}).get("Code", code)
        raise ConnectorError(code, f"Could not create the AWS client: {e}", hint=hint_for(code, str(e))) from e


def check_target(target_id: int, *, operator: str, connector=None, run_id: str | None = None) -> dict:
    """Returns a dict with status/latency/usage. Raises SafetyViolation / Halted before sending."""
    settings = get_settings()
    with session_scope() as s:
        target = s.get(Target, target_id)
        if target is None:
            raise LookupError(f"target {target_id} not found")
        if target.archived:
            raise TargetArchived(f"target {target_id} is archived")
        assert_staging(target.environment)
        spec = get_provider(target.provider or "aws_agentcore")
        if not spec.implemented:
            raise ConnectorUnsupported(f"{spec.label}: connector not implemented — connectivity checks are unsupported.")
        KILL.check()  # before run-state checks, so a halted run reports the emergency stop
        if run_id is not None:
            run = s.get(Run, run_id)
            if run is None:
                raise LookupError(f"run {run_id} not found")
            if run.target_id != target_id:
                raise LookupError(f"run {run_id} belongs to another target")
            if run.status != "open":
                raise RunNotActive(f"Run {run_id} is {run.status}; live exchanges only run on open runs.")
        _limiter().acquire(target_id)
        tid, name, provider = target.id, target.name, spec.key
        target_snapshot = Target(id=target.id, provider=target.provider, environment=target.environment,
                                 harness_arn=target.harness_arn, region=target.region, qualifier=target.qualifier,
                                 aws_profile=target.aws_profile, aws_role_arn=target.aws_role_arn,
                                 config=dict(target.config or {}))

    provenance = "local-stub" if provider == "local_stub" else "measured"
    session_id = ""
    audit("connectivity.start", {"message": settings.connectivity_message, "provider": provider},
          actor=operator, target_id=tid, run_id=run_id)
    publish("connectivity.start", {"target_id": tid, "name": name, "provider": provider}, run_id=run_id)
    turn = _next_turn(run_id) if run_id else 0
    sent_id, reply_id = f"msg-{uuid.uuid4().hex[:12]}", f"msg-{uuid.uuid4().hex[:12]}"
    deltas = DeltaPublisher(run_id, reply_id) if run_id else None
    try:
        # Built outside the DB session; credential/profile problems surface here as ConnectorError.
        conn = connector or _build(target_snapshot, settings.connector_timeout_s, run_id)
        session_id = conn.new_session_id()
        if run_id:
            publish("conversation.message", {
                "message_id": sent_id, "turn": turn, "role": "evaluator", "kind": "connectivity", "test_key": "connectivity",
                "text": settings.connectivity_message, "session_id": session_id, "target_id": tid,
                "provider": provider, "provenance": "sent", "status": "complete"}, run_id=run_id)
            publish("conversation.pending", {"message_id": reply_id, "turn": turn + 1, "target_id": tid, "test_key": "connectivity",
                                             "provider": provider, "session_id": session_id}, run_id=run_id)
        # Same call path as assessment traffic: timeout, redaction, Invocation evidence and gateway audit.
        # Transient errors are retried here (INVOCATION_RETRIES); each attempt is its own audited Invocation.
        for attempt in range(max(0, settings.invocation_retries) + 1):
            res = gateway_send(conn, text=settings.connectivity_message, session_id=session_id, run_id=run_id,
                               target_id=tid, engine="connectivity", actor=operator,
                               timeout_s=float(settings.connector_timeout_s), on_delta=deltas,
                               test_key="connectivity", turn=turn, provenance=provenance, attempt=attempt)
            if res.status == "ok" or not res.retryable or attempt >= settings.invocation_retries or KILL.tripped:
                break
            time.sleep(min(2 ** attempt, 8) * RETRY_BASE_S)
        if res.status == "ok":
            result = {"status": "connected", "latency_ms": res.latency_ms, "wall_ms": res.wall_ms, "usage": res.usage,
                      "stop_reason": res.stop_reason, "reply": res.text, "error": "", "error_code": "", "hint": "",
                      "provenance": provenance, "tool_events": res.tool_events}
        else:
            result = {"status": "error", "latency_ms": None, "wall_ms": None, "usage": {}, "stop_reason": "",
                      "reply": "", "error": res.error, "error_code": res.error_code, "hint": res.hint,
                      "provenance": provenance, "tool_events": []}
    except ConnectorError as e:  # client setup (credentials, profile, assume-role) failed before any call
        result = {"status": "error", "latency_ms": None, "wall_ms": None, "usage": {}, "stop_reason": "",
                  "reply": "", "error": f"{e.code}: {e.message}", "error_code": e.code, "hint": e.hint,
                  "provenance": provenance, "tool_events": []}
    if deltas:
        deltas.flush()

    with session_scope() as s:
        t = s.get(Target, tid)
        t.status = result["status"]
        t.last_check_at = utcnow()
        t.last_latency_ms = result["latency_ms"]
        t.last_wall_ms = result["wall_ms"]
        t.last_usage = result["usage"]
        t.last_error = result["error"] + (f"\n{result['hint']}" if result["hint"] else "")
    audit("connectivity.result", {k: v for k, v in result.items() if k != "reply"} | {"reply_chars": len(result["reply"])},
          actor=operator, target_id=tid, run_id=run_id)
    if run_id:
        if result["status"] == "connected":
            publish("conversation.message", {
                "message_id": reply_id, "turn": turn + 1, "role": "target", "kind": "connectivity", "test_key": "connectivity",
                "text": result["reply"], "target_id": tid, "session_id": session_id, "provider": provider, "provenance": provenance,
                "latency_ms": result["latency_ms"], "wall_ms": result["wall_ms"], "usage": result["usage"],
                "stop_reason": result["stop_reason"], "tool_events": result["tool_events"], "status": "complete"},
                run_id=run_id)
        else:
            publish("conversation.error", {
                "message_id": reply_id, "turn": turn + 1, "target_id": tid, "provider": provider, "test_key": "connectivity",
                "kind": "connectivity", "session_id": session_id, "error": result["error"], "error_code": result["error_code"], "hint": result["hint"]}, run_id=run_id)
    publish("connectivity.result", {"target_id": tid, **result}, run_id=run_id)
    return result


def _next_turn(run_id: str) -> int:
    from sqlalchemy import select

    from .models import Event

    # Turns count within the connectivity conversation; assessment conversations number their own turns.
    with session_scope() as s:
        rows = s.execute(select(Event.data).where(
            Event.run_id == run_id, Event.type.in_(["conversation.message", "conversation.error"]))).scalars().all()
    return sum(1 for d in rows if (d or {}).get("kind", "connectivity") == "connectivity"
               or (d or {}).get("test_key") == "connectivity") + 1
