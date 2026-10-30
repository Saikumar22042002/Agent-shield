"""Target gateway: the single path by which anything in AgentShield reaches a target.

Every caller goes through here: the connectivity check (`send`), the PyRIT adapter (its PromptTarget calls
`invoke`), the garak adapter (garak's REST generator posts to /api/gateway/garak/..., which calls `invoke`), and
the Deep Agents coordinator (whose only execution tool asks the orchestrator to run an approved case).

Enforced in code, in this order, before a prompt leaves the process:
  emergency stop -> run cancelled -> run paused (waits) -> run open + assessment running -> target staging,
  not archived, connector implemented -> provider allowlisted for assessments -> approved plan whose sha256
  matches the one recorded at approval -> plan not stale (profile and catalog unchanged since it was built) ->
  engine and case approved for that technique -> prompt is the approved input (exact text for PyRIT cases; garak
  prompts come from the approved probe) -> budgets (prompts per run, per technique, run duration, target tokens)
  -> rate limit (waits) -> every check again, and the Invocation row reserved as "pending", under one per-run lock
Then the call runs with a hard timeout and cancellation, and the result is redacted, written into the reserved
`Invocation` row, written to the audit chain and published to the live stream. Transient connector errors are
retried here (INVOCATION_RETRIES); each retry passes every control again and is its own budgeted Invocation.

A refused call is persisted too (status "refused") so the evidence shows what the gateway blocked and why.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select

from .audit import record as audit
from .config import get_settings
from .connectors import ConnectorError, ConnectorInput, build_connector
from .connectors.registry import get_provider
from .db import session_scope
from .events import publish
from .integrity import plan_sha, staleness
from .models import AssessmentPlan, Invocation, Run, Target, utcnow
from .redact import redact, redact_text
from .safety import KILL, Halted, SafetyViolation, assert_staging

SPENT = ("ok", "error", "pending")  # statuses that consume budget; "pending" is a reservation for an in-flight call
DELTA_FLUSH_S = 0.15  # deltas are batched so a fast stream does not write one event row per token
_pool = concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="gateway")


class GatewayRefused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class DeltaPublisher:
    def __init__(self, run_id: str, message_id: str):
        self.run_id, self.message_id = run_id, message_id
        self.buf: list[str] = []
        self.seq = 0
        self.last = time.monotonic()

    def __call__(self, text: str) -> None:
        self.buf.append(text)
        if time.monotonic() - self.last >= DELTA_FLUSH_S:
            self.flush()

    def flush(self) -> None:
        if not self.buf:
            return
        text, _ = redact_text("".join(self.buf))
        publish("conversation.delta", {"message_id": self.message_id, "seq": self.seq, "text": text}, run_id=self.run_id)
        self.seq += 1
        self.buf.clear()
        self.last = time.monotonic()


# ---------------------------------------------------------------- per-run control (in memory)
@dataclass
class RunControl:
    run_id: str
    cancel: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)  # rate-limit spacing
    last_call: float = 0.0
    connector: object | None = None
    reason: str = ""


_controls: dict[str, RunControl] = {}
_controls_lock = threading.Lock()
# Budget check + reservation of the Invocation row happen under one lock per run, so concurrent calls can never
# both pass a budget that has room for only one of them. Kept outside RunControl: a reset must not swap the lock
# while calls are in flight. Process-local, which is why AgentShield runs as a single worker (see app.py).
_budget_locks: dict[str, threading.Lock] = {}


def budget_lock(run_id: str) -> threading.Lock:
    with _controls_lock:
        return _budget_locks.setdefault(run_id, threading.Lock())


def control(run_id: str) -> RunControl:
    with _controls_lock:
        ctl = _controls.get(run_id)
        if ctl is None:
            ctl = _controls[run_id] = RunControl(run_id)
        return ctl


def cancel(run_id: str, reason: str) -> None:
    ctl = control(run_id)
    ctl.reason = reason
    ctl.cancel.set()


def reset_control(run_id: str) -> RunControl:
    """Fresh control for a new execution of the run (after resume from interrupted, or a new start)."""
    with _controls_lock:
        ctl = _controls[run_id] = RunControl(run_id)
        return ctl


def cancel_all(reason: str) -> None:
    with _controls_lock:
        ctls = list(_controls.values())
    for c in ctls:
        c.reason = reason
        c.cancel.set()


# ---------------------------------------------------------------- request / result
@dataclass
class GatewayRequest:
    run_id: str
    text: str
    engine: str  # pyrit | garak
    test_key: str = ""  # logical conversation; one connector session per (run, test_key)
    case_id: str = ""
    technique_id: str = ""
    turn: int = 1
    label: str = ""  # human label of the conversation, e.g. "AS-SPL-01 · garak sysprompt_extraction #3"


@dataclass
class GatewayResult:
    invocation_id: int | None
    status: str  # ok | error
    text: str
    session_id: str
    error: str = ""
    error_code: str = ""
    hint: str = ""
    latency_ms: float | None = None
    wall_ms: float | None = None
    usage: dict = field(default_factory=dict)
    stop_reason: str = ""
    tool_events: list = field(default_factory=list)
    redactions: int = 0
    retryable: bool = False  # the connector marked the error transient (throttling, 5xx)
    attempt: int = 0  # 0 = first try; n = n-th retry (each retry is its own Invocation and counts toward budgets)




def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


# ---------------------------------------------------------------- checks
def _refuse(req: GatewayRequest, target_id: int | None, code: str, message: str, actor: str) -> GatewayRefused:
    text, _ = redact_text(req.text)
    with session_scope() as s:
        if s.get(Run, req.run_id) is not None:
            s.add(Invocation(run_id=req.run_id, target_id=target_id or 0, technique_id=req.technique_id,
                             test_key=req.test_key, engine=req.engine, turn=req.turn, prompt=text, status="refused",
                             error=f"{code}: {message}", provenance="gateway"))
    audit("gateway.refused", {"code": code, "message": message, "engine": req.engine, "test_key": req.test_key,
                              "turn": req.turn, "prompt_sha256": hashlib.sha256(req.text.encode()).hexdigest()},
          actor=actor, run_id=req.run_id, target_id=target_id)
    publish("gateway.refused", {"code": code, "message": message, "engine": req.engine, "test_key": req.test_key,
                                "case_id": req.case_id, "technique_id": req.technique_id, "turn": req.turn,
                                "label": req.label, "prompt": text[:300]}, run_id=req.run_id)
    return GatewayRefused(code, message)


def _approved_texts(content: dict) -> dict[str, list[str]]:
    return {c["id"]: list(c.get("turns", [])) for c in content.get("cases", [])}


def _wait_while_paused(req: GatewayRequest, ctl: RunControl) -> None:
    """Pause holds calls at the gateway; resume releases them. Stop, cancel and the emergency stop end the wait."""
    while True:
        with session_scope() as s:
            status = s.get(Run, req.run_id).status
        if status != "paused" or ctl.cancel.is_set() or KILL.tripped:
            return
        ctl.cancel.wait(0.3)


def _check_assessment(s, req: GatewayRequest, run: Run, target: Target) -> tuple[str, str] | None:
    """Returns (code, message) if the call must be refused."""
    st = get_settings()
    if run.assessment_status != "running":
        return "not_running", f"Run assessment is '{run.assessment_status}', not running."
    if target.provider not in st.assessment_provider_list:
        return "provider_not_allowed", (f"Provider '{target.provider}' is not in ASSESSMENT_PROVIDERS "
                                        f"({', '.join(st.assessment_provider_list) or 'empty'}).")
    plan = s.execute(select(AssessmentPlan).where(AssessmentPlan.run_id == run.id, AssessmentPlan.status == "approved")
                     .order_by(AssessmentPlan.version.desc()).limit(1)).scalar()
    if plan is None:
        return "no_approved_plan", "The run has no approved assessment plan."
    if plan.sha256 != plan_sha(plan.content) or plan.sha256 != (run.limits or {}).get("plan_sha256"):
        return "plan_integrity", "The approved plan's sha256 does not match the one recorded at approval."
    stale = staleness(plan.content, target.profile)
    if stale:
        return "plan_stale", f"Approval no longer applies: {stale}. Build and approve a new plan."
    content = plan.content
    engines = content.get("engines") or [content.get("engine")]
    if req.engine not in engines:
        return "engine_not_approved", f"Plan approves engines {', '.join(map(str, engines))}, not '{req.engine}'."
    case = next((c for c in content.get("cases", []) if c.get("id") == req.case_id), None)
    if case is None or case.get("engine") != req.engine:
        return "case_not_approved", f"Case '{req.case_id}' is not an approved {req.engine} case in the plan."
    if case.get("technique_id") != req.technique_id:
        return "case_not_approved", f"Case '{req.case_id}' is approved for {case.get('technique_id')}, not {req.technique_id}."
    if req.engine == "pyrit":  # PyRIT inputs are fixed at approval (dataset seeds / operator turns, converters applied)
        turns = _approved_texts(content).get(req.case_id) or []
        if req.turn < 1 or req.turn > len(turns) or turns[req.turn - 1] != req.text:
            return "input_not_approved", f"Turn {req.turn} of case '{req.case_id}' does not match the approved input."
    # garak generates its prompts inside the approved probe; the probe name and prompt cap are what is approved.
    # Budgets come from the hashed plan content, never from mutable run state; only the execution start time
    # (set when execution begins) is read from the run.
    limits = dict(content.get("limits") or {}) | {"execution_started_at": (run.limits or {}).get("execution_started_at")}
    used = s.execute(select(func.count(Invocation.id)).where(
        Invocation.run_id == run.id, Invocation.status.in_(SPENT), Invocation.engine != "connectivity")).scalar() or 0
    if used >= limits.get("max_prompts_per_run", st.max_prompts_per_run):
        return "budget_prompts", f"Prompt budget for the run is spent ({used})."
    if req.technique_id:
        per = s.execute(select(func.count(Invocation.id)).where(
            Invocation.run_id == run.id, Invocation.technique_id == req.technique_id,
            Invocation.status.in_(SPENT))).scalar() or 0
        if per >= limits.get("max_prompts_per_technique", st.max_prompts_per_technique):
            return "budget_technique", f"Prompt budget for technique {req.technique_id} is spent ({per})."
    started = limits.get("execution_started_at")
    if started:
        elapsed = time.time() - float(started)
        if elapsed > limits.get("max_run_duration_s", st.max_run_duration_s):
            return "budget_duration", f"Run duration limit reached ({elapsed:.0f}s)."
    token_cap = limits.get("target_token_budget", st.target_token_budget)
    if token_cap:
        spent = sum(int((u or {}).get("totalTokens", 0)) for u in s.execute(
            select(Invocation.usage).where(Invocation.run_id == run.id)).scalars())
        if spent >= token_cap:
            return "budget_tokens", f"Target token budget is spent ({spent} of {token_cap})."
    return None


def _approved_limits(s, run_id: str) -> dict:
    plan = s.execute(select(AssessmentPlan).where(AssessmentPlan.run_id == run_id, AssessmentPlan.status == "approved")
                     .order_by(AssessmentPlan.version.desc()).limit(1)).scalar()
    return dict((plan.content or {}).get("limits") or {}) if plan else {}


def _session_id_for(run_id: str, test_key: str, conn) -> str:
    """One connector session per (run, conversation). Reused after a restart so a resumed case continues
    the same target-side session."""
    with session_scope() as s:
        sid = s.execute(select(Invocation.session_id).where(
            Invocation.run_id == run_id, Invocation.test_key == test_key, Invocation.session_id != "")
            .order_by(Invocation.id).limit(1)).scalar()
    return sid or conn.new_session_id()


# ---------------------------------------------------------------- the call
RETRY_BASE_S = 1.0  # backoff before retry n is RETRY_BASE_S * 2**(n-1), capped at 8x


def send(conn, *, text: str, session_id: str, run_id: str | None, target_id: int, engine: str, actor: str,
         timeout_s: float, on_delta=None, ctl: RunControl | None = None, test_key: str = "", technique_id: str = "",
         turn: int = 1, provenance: str = "measured", invocation_id: int | None = None,
         attempt: int = 0) -> GatewayResult:
    """Run one connector call with timeout + cancellation; redact, persist (when inside a run) and audit it.
    Shared by the connectivity check and assessment invocations so both use one code path. `invocation_id` is the
    row the gateway reserved for this call (assessment traffic); without it a new row is written."""
    if hasattr(conn, "set_delta_handler"):
        conn.set_delta_handler(on_delta)
    prompt_red, n_in = redact_text(text)
    t0 = time.perf_counter()
    fut = _pool.submit(conn.send, ConnectorInput(text=text, session_id=session_id))
    out, err = None, None
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            out = fut.result(timeout=0.25)
            break
        except concurrent.futures.TimeoutError:
            if KILL.tripped:  # first: the emergency stop also cancels every run, and should be reported as itself
                err = ConnectorError("Halted", "Call abandoned: emergency stop.")
                break
            if ctl is not None and ctl.cancel.is_set():
                err = ConnectorError("Cancelled", f"Call abandoned: {ctl.reason or 'run cancelled'}.")
                break
            if time.monotonic() > deadline:
                err = ConnectorError("GatewayTimeout", f"No reply within {timeout_s:.0f}s.", hint=(
                    "The target did not answer within INVOCATION_TIMEOUT_S / CONNECTOR_TIMEOUT_S."))
                break
        except ConnectorError as e:
            err = e
            break
        except Exception as e:  # connector bug or SDK error not mapped to ConnectorError
            err = ConnectorError(type(e).__name__, str(e)[:500])
            break
    wall = (time.perf_counter() - t0) * 1000
    if out is not None:
        reply, n_out = redact_text(out.text)
        tools, n_tools = redact(out.tool_events)
        res = GatewayResult(None, "ok", reply, session_id, latency_ms=out.latency_ms,
                            wall_ms=out.wall_ms if out.wall_ms is not None else wall, usage=out.usage,
                            stop_reason=out.stop_reason, tool_events=tools, redactions=n_in + n_out + n_tools,
                            attempt=attempt)
    else:
        msg, n_err = redact_text(err.message)
        res = GatewayResult(None, "error", "", session_id, error=f"{err.code}: {msg}", error_code=err.code,
                            hint=err.hint, wall_ms=wall, redactions=n_in + n_err, retryable=bool(err.retryable),
                            attempt=attempt)
    if run_id is not None:
        with session_scope() as s:
            inv = s.get(Invocation, invocation_id) if invocation_id else None
            if inv is None:
                inv = Invocation(run_id=run_id, target_id=target_id, technique_id=technique_id, test_key=test_key,
                                 engine=engine, turn=turn, provenance=provenance)
                s.add(inv)
            inv.session_id, inv.prompt, inv.response, inv.status, inv.error = (
                session_id, prompt_red, res.text, res.status, res.error)
            inv.latency_ms, inv.wall_ms, inv.usage, inv.tool_events = (
                res.latency_ms, res.wall_ms, res.usage or {}, res.tool_events)
            inv.attempt = attempt
            s.flush()
            res.invocation_id = inv.id
    audit("gateway.invoke", {"engine": engine, "test_key": test_key, "turn": turn, "session": session_id,
                             "status": res.status, "error_code": res.error_code, "invocation_id": res.invocation_id,
                             "attempt": attempt, "prompt_sha256": hashlib.sha256(text.encode()).hexdigest(),
                             "reply_chars": len(res.text), "wall_ms": res.wall_ms, "usage": res.usage,
                             "redactions": res.redactions}, actor=actor, run_id=run_id, target_id=target_id)
    return res


def _gate(req: GatewayRequest, ctl: RunControl, target_id: int, actor: str) -> None:
    """Emergency stop, cancellation and pause, in that order. Pause holds the call here until resumed."""
    if KILL.tripped:
        raise _refuse(req, target_id, "halted", KILL.reason or "Emergency stop is active.", actor)
    if ctl.cancel.is_set():
        raise _refuse(req, target_id, "cancelled", ctl.reason or "Run execution was cancelled.", actor)
    _wait_while_paused(req, ctl)
    if KILL.tripped:
        raise _refuse(req, target_id, "halted", KILL.reason or "Emergency stop is active.", actor)
    if ctl.cancel.is_set():
        raise _refuse(req, target_id, "cancelled", ctl.reason or "Run execution was cancelled.", actor)


def _authorize(s, req: GatewayRequest) -> tuple[tuple[str, str] | None, Run, Target | None]:
    run = s.get(Run, req.run_id)
    target = s.get(Target, run.target_id)
    if run.status != "open":
        return ("run_not_active", f"Run is {run.status}."), run, target
    if target is None or target.archived:
        return ("target_unavailable", "Target is missing or archived."), run, target
    try:
        assert_staging(target.environment)
    except SafetyViolation as e:
        return ("not_staging", str(e)), run, target
    if not get_provider(target.provider or "aws_agentcore").implemented:
        return ("connector_not_implemented", f"{target.provider} has no implemented connector."), run, target
    return _check_assessment(s, req, run, target), run, target


def invoke(req: GatewayRequest, *, actor: str = "gateway", connector=None) -> GatewayResult:
    """Assessment invocation. Raises GatewayRefused (persisted + audited) when any control blocks it,
    LookupError for an unknown run. Transient connector errors are retried here, up to the approved
    `invocation_retries`; every retry is a new Invocation that passes every control and counts toward budgets."""
    st = get_settings()
    ctl = control(req.run_id)
    with session_scope() as s:
        run = s.get(Run, req.run_id)
        if run is None:
            raise LookupError(f"run {req.run_id} not found")
        target_id = run.target_id
        retries = int(_approved_limits(s, run.id).get("invocation_retries", st.invocation_retries))
    attempt = 0
    while True:
        res = _invoke_once(req, ctl, actor, connector, target_id, attempt)
        if res.status == "ok" or not res.retryable or attempt >= retries:
            return res
        attempt += 1
        delay = RETRY_BASE_S * min(2 ** (attempt - 1), 8)
        publish("gateway.retry", {"case_id": req.case_id, "technique_id": req.technique_id, "test_key": req.test_key,
                                  "turn": req.turn, "attempt": attempt, "of": retries, "error_code": res.error_code,
                                  "delay_s": delay, "label": req.label}, run_id=req.run_id)
        if ctl.cancel.wait(delay) or KILL.tripped:
            return res


def _invoke_once(req: GatewayRequest, ctl: RunControl, actor: str, connector, target_id: int,
                 attempt: int) -> GatewayResult:
    st = get_settings()
    _gate(req, ctl, target_id, actor)
    # First pass: refuse early, without waiting for the rate limit.
    with session_scope() as s:
        problem, run, _ = _authorize(s, req)
        plan_limits = _approved_limits(s, run.id)
    if problem:
        raise _refuse(req, target_id, *problem, actor)
    timeout = plan_limits.get("invocation_timeout_s", st.invocation_timeout_s)
    interval = plan_limits.get("min_invocation_interval_s", st.min_invocation_interval_s)

    # rate limit: one call per `interval` per run (waits, cancel-aware)
    with ctl.lock:
        wait = ctl.last_call + interval - time.monotonic()
        if wait > 0 and ctl.cancel.wait(wait):
            raise _refuse(req, target_id, "cancelled", ctl.reason or "Run execution was cancelled.", actor)
        ctl.last_call = time.monotonic()

    # Second pass + reservation, atomically: re-check every control (state may have changed while waiting) and
    # write the Invocation as "pending" so concurrent calls count it against the budgets immediately.
    provider, snapshot, inv_id = "", None, None
    with budget_lock(req.run_id):
        with session_scope() as s:
            problem, run, target = _authorize(s, req)
            if problem is None and KILL.tripped:
                problem = ("halted", KILL.reason or "Emergency stop is active.")
            elif problem is None and ctl.cancel.is_set():
                problem = ("cancelled", ctl.reason or "Run execution was cancelled.")
            if problem is None:
                provider = target.provider
                snapshot = Target(
                    id=target.id, provider=target.provider, environment=target.environment,
                    harness_arn=target.harness_arn, region=target.region, qualifier=target.qualifier,
                    aws_profile=target.aws_profile, aws_role_arn=target.aws_role_arn, config=dict(target.config or {}))
                shown_prompt, _ = redact_text(req.text)
                inv = Invocation(run_id=req.run_id, target_id=target_id, technique_id=req.technique_id,
                                 test_key=req.test_key, engine=req.engine, turn=req.turn, prompt=shown_prompt,
                                 status="pending", attempt=attempt,
                                 provenance="local-stub" if provider == "local_stub" else "measured")
                s.add(inv)
                s.flush()
                inv_id = inv.id
    if problem:
        raise _refuse(req, target_id, *problem, actor)

    conn = connector or ctl.connector
    if conn is None:
        try:
            conn = ctl.connector = build_connector(snapshot, timeout_s=int(timeout), run_id=req.run_id)
        except Exception as e:  # credential / profile errors from the SDK, or an unsupported connector
            _release(inv_id)
            detail = f"{e.code}: {e.message}" if isinstance(e, ConnectorError) else f"{type(e).__name__}: {e}"
            raise _refuse(req, target_id, "connector_setup", detail, actor) from e
    session_id = _session_id_for(req.run_id, req.test_key, conn)
    provenance = "local-stub" if provider == "local_stub" else "measured"
    sent_id, reply_id = f"msg-{uuid.uuid4().hex[:12]}", f"msg-{uuid.uuid4().hex[:12]}"
    head = {"session_id": session_id, "test_key": req.test_key, "case_id": req.case_id, "engine": req.engine,
            "technique_id": req.technique_id, "target_id": target_id, "provider": provider, "kind": "assessment",
            "label": req.label, "attempt": attempt}
    shown, _ = redact_text(req.text)
    publish("conversation.message", head | {"message_id": sent_id, "turn": req.turn, "role": "evaluator",
                                            "text": shown, "provenance": "sent", "status": "complete"},
            run_id=req.run_id)
    publish("conversation.pending", head | {"message_id": reply_id, "turn": req.turn}, run_id=req.run_id)
    deltas = DeltaPublisher(req.run_id, reply_id)
    res = send(conn, text=req.text, session_id=session_id, run_id=req.run_id, target_id=target_id, engine=req.engine,
               actor=actor, timeout_s=float(timeout), on_delta=deltas, ctl=ctl, test_key=req.test_key,
               technique_id=req.technique_id, turn=req.turn, provenance=provenance, invocation_id=inv_id,
               attempt=attempt)
    deltas.flush()
    if res.status == "ok":
        publish("conversation.message", head | {
            "message_id": reply_id, "turn": req.turn, "role": "target", "text": res.text, "provenance": provenance,
            "latency_ms": res.latency_ms, "wall_ms": res.wall_ms, "usage": res.usage, "stop_reason": res.stop_reason,
            "tool_events": res.tool_events, "invocation_id": res.invocation_id, "status": "complete"}, run_id=req.run_id)
    else:
        publish("conversation.error", head | {"message_id": reply_id, "turn": req.turn, "error": res.error,
                                              "error_code": res.error_code, "hint": res.hint,
                                              "retryable": res.retryable, "invocation_id": res.invocation_id},
                run_id=req.run_id)
    return res


def _release(invocation_id: int | None) -> None:
    """Drop a reservation whose call never left the process (the refusal is recorded separately)."""
    if invocation_id is None:
        return
    with session_scope() as s:
        inv = s.get(Invocation, invocation_id)
        if inv is not None and inv.status == "pending":
            s.delete(inv)


def fail_pending(run_id: str | None = None, reason: str = "the API stopped while this call was in flight") -> int:
    """Reservations left by a process that died mid-call become errors: they may have reached the target, so they
    keep counting toward the budgets."""
    with session_scope() as s:
        q = select(Invocation).where(Invocation.status == "pending")
        if run_id:
            q = q.where(Invocation.run_id == run_id)
        rows = s.execute(q).scalars().all()
        for inv in rows:
            inv.status, inv.error = "error", f"Interrupted: {reason}"
        return len(rows)


def usage_summary(run_id: str) -> dict:
    with session_scope() as s:
        rows = s.execute(select(Invocation.status, Invocation.engine, Invocation.usage, Invocation.wall_ms)
                         .where(Invocation.run_id == run_id)).all()
    by = {"ok": 0, "error": 0, "refused": 0, "pending": 0}
    tokens = 0
    for status, engine, usage, _ in rows:
        if engine == "connectivity":
            continue
        by[status] = by.get(status, 0) + 1
        tokens += int((usage or {}).get("totalTokens", 0))
    return {"invocations": by, "target_tokens": tokens}


__all__ = ["GatewayRefused", "GatewayRequest", "GatewayResult", "Halted", "RunControl", "budget_lock", "cancel",
           "cancel_all", "control", "fail_pending", "invoke", "plan_sha", "reset_control", "send", "usage_summary",
           "utcnow", "_iso"]
