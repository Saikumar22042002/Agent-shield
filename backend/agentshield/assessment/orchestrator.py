"""Run orchestrator: executes a run's approved plan with persistent lifecycle state.

Lifecycle (Run.assessment_status):
  planned -> approved -> queued -> running -> completed | stopped | error
  running/queued at API start -> interrupted (the process died mid-execution)
  stopped / interrupted -> running again via resume, which skips cases that already have a result

Who decides what runs next is the LangChain Deep Agents coordinator (coordinator.py). Its only execution tool asks
this module to run one approved case (`Execution.run_case`); it can also skip a pending case when the objective is
already established, or stop the assessment when the target is unavailable. It has no tool that reaches a connector.

Concurrency is bounded twice: MAX_ACTIVE_ASSESSMENTS runs execute at once (others wait as "queued"), and inside a run
at most `technique_concurrency` cases execute in parallel (a semaphore in `Execution`, whatever the coordinator asks
for), each in its own conversation (test_key) and therefore its own target session. Run pause holds cases at the
gateway; stop, the run's final Stop and the emergency stop cancel in-flight calls through gateway.cancel / cancel_all.

Execution of a case is delegated to engine adapters (ADAPTERS: engine -> callable, registered at startup by
adapters.register_defaults). An adapter receives a CaseContext and must send every target prompt through
`ctx.invoke` (the gateway). It returns a CaseResult with the framework's own verdict and record; the orchestrator
persists it as a TestAttempt (provenance local-execution) and re-derives findings. An engine without a registered
adapter cannot start.

Result states (TestAttempt.verdict for executed cases):
  pass | fail | inconclusive  mapped from the framework's own verdict by the adapter
  error                       the adapter or framework failed, or the gateway refused the case for a non-stop reason
  skipped                     not executed by decision: objective already established for the technique, the
                              technique's prompt budget was spent, or the coordinator skipped it (reason recorded)
"""
from __future__ import annotations

import logging
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import or_, select

from .. import gateway
from ..audit import record as audit
from ..config import get_settings
from ..db import session_scope
from ..events import publish
from ..gateway import GatewayRefused, GatewayRequest, GatewayResult
from ..integrity import staleness
from ..models import Invocation, Run, Target, TestAttempt, utcnow
from ..safety import KILL
from . import plans

log = logging.getLogger("agentshield.orchestrator")
ACTIVE = ("queued", "running")
# Gateway refusals that end the whole execution (the case stays pending, so a resume can run it).
STOP_CODES = {"halted", "cancelled", "run_not_active", "budget_duration", "budget_prompts", "budget_tokens",
              "plan_stale", "plan_integrity", "no_approved_plan", "not_running", "target_unavailable"}
# Refusals that end only the case, as "skipped" (budget for that technique is spent).
SKIP_CODES = {"budget_technique"}


class OrchestratorError(Exception):
    """The request cannot be honoured in the run's current state (HTTP 409)."""


# ---------------------------------------------------------------- adapter contract
@dataclass
class CaseContext:
    run_id: str
    case: dict
    plan: dict  # approved plan content
    target: dict  # id, name, provider, kind
    operator: str
    cancel: threading.Event

    def invoke(self, text: str, *, turn: int = 1, test_key: str | None = None) -> GatewayResult:
        """The only way an adapter reaches the target. Raises GatewayRefused when a control blocks the call."""
        return gateway.invoke(GatewayRequest(
            run_id=self.run_id, text=text, engine=self.case["engine"], test_key=test_key or self.case["id"],
            case_id=self.case["id"], technique_id=self.case["technique_id"], turn=turn, label=self.case["label"]),
            actor=f"{self.case['engine']}:{self.operator}")


@dataclass
class CaseResult:
    verdict: str  # pass | fail | inconclusive | error | skipped (AgentShield outcome from the framework verdict)
    source_verdict: str  # the framework's own verdict, verbatim (e.g. PyRIT "UNDETERMINED", garak detector score)
    test_id: str
    detector: str = ""
    score: float | None = None
    rationale: str = ""
    turns: list = field(default_factory=list)
    source_detail: dict = field(default_factory=dict)  # framework record: ids, scores, raw outcome, versions
    engine_version: str = ""
    strategy: str = ""
    error: str = ""
    evidence: dict = field(default_factory=dict)  # e.g. raw output file + sha256, confirmation basis


Adapter = Callable[[CaseContext], CaseResult]
ADAPTERS: dict[str, Adapter] = {}


def register(engine: str, fn: Adapter) -> None:
    ADAPTERS[engine] = fn


# ---------------------------------------------------------------- state helpers
_slots: threading.Semaphore | None = None
_slots_lock = threading.Lock()
_threads: dict[str, threading.Thread] = {}


def _semaphore() -> threading.Semaphore:
    global _slots
    with _slots_lock:
        if _slots is None:
            _slots = threading.BoundedSemaphore(max(1, get_settings().max_active_assessments))
        return _slots


def reset_for_tests() -> None:
    global _slots
    with _slots_lock:
        _slots = None
    _threads.clear()


def _set(run_id: str, *, status: str | None = None, phase: str | None = None, reason: str | None = None,
         **assessment) -> dict:
    with session_scope() as s:
        r = s.get(Run, run_id)
        prev = r.assessment_status
        if status:
            r.assessment_status = status
        if phase is not None:
            r.assessment_phase = phase
        if reason is not None:
            r.stop_reason = reason
        if assessment:
            r.assessment = dict(r.assessment or {}) | assessment
        out = {"run_id": run_id, "from": prev, "status": r.assessment_status, "phase": r.assessment_phase,
               "reason": r.stop_reason, "progress": (r.assessment or {}).get("progress", {})}
    if status and status != prev:
        publish("assessment.status", out, run_id=run_id)
    return out


def _results(run_id: str) -> dict[str, TestAttempt]:
    with session_scope() as s:
        rows = s.execute(select(TestAttempt).where(
            TestAttempt.run_id == run_id, TestAttempt.provenance == "local-execution")).scalars().all()
        s.expunge_all()
        return {a.external_id: a for a in rows}


def _done_case_ids(run_id: str) -> set[str]:
    return set(_results(run_id))


def _progress(run_id: str, plan: dict) -> dict:
    total = len(plan["cases"])
    verdicts = [a.verdict for a in _results(run_id).values()]
    use = gateway.usage_summary(run_id)
    return {"cases_total": total, "cases_done": len(verdicts), "errors": verdicts.count("error"),
            "skipped": verdicts.count("skipped"), "failed": verdicts.count("fail"),
            "prompts_sent": use["invocations"].get("ok", 0) + use["invocations"].get("error", 0),
            "prompts_refused": use["invocations"].get("refused", 0), "prompt_budget": plan["limits"]["max_prompts_per_run"],
            "target_tokens": use["target_tokens"]}


# ---------------------------------------------------------------- public API
def status(run_id: str) -> dict:
    with session_scope() as s:
        r = s.get(Run, run_id)
        if r is None:
            raise LookupError(f"run {run_id} not found")
        out = {"run_id": run_id, "status": r.assessment_status, "phase": r.assessment_phase, "reason": r.stop_reason,
               "limits": r.limits or {}, "assessment": r.assessment or {}}
        target = s.get(Target, r.target_id)
        raw_profile = dict(target.profile or {}) if target else {}
    results = {k: {"attempt_id": a.id, "verdict": a.verdict, "source_verdict": a.source_verdict, "error": a.error,
                   "kind": (a.evidence or {}).get("kind", ""), "rationale": a.rationale[:500]}
               for k, a in _results(run_id).items()}
    plan = plans.approved(run_id)
    out["plan"] = ({"version": plan["version"], "sha256": plan["sha256"], "kind": plan["content"]["kind"],
                    "engines": plan["content"]["engines"], "planned_prompts": plan["content"]["planned_prompts"],
                    "stale": staleness(plan["content"], raw_profile)}
                   if plan else None)
    in_flight = out["assessment"].get("in_flight") or []
    out["cases"] = [{"id": c["id"], "label": c["label"], "engine": c["engine"], "technique_id": c["technique_id"],
                     "kind": c["kind"], "planned_prompts": c["planned_prompts"],
                     "state": ("skipped" if (results.get(c["id"]) or {}).get("verdict") == "skipped" else "done")
                     if c["id"] in results else ("running" if c["id"] in in_flight else "pending"),
                     "result": results.get(c["id"])} for c in (plan["content"]["cases"] if plan else [])]
    out["usage"] = gateway.usage_summary(run_id)
    out["adapters"] = sorted(ADAPTERS)
    return out


def start(run_id: str, *, operator: str, resume: bool = False) -> dict:
    """Begin (or resume) executing the approved plan in a background thread. Returns the status row."""
    KILL.check()
    plan = plans.approved(run_id)
    with session_scope() as s:
        r = s.get(Run, run_id)
        if r is None:
            raise LookupError(f"run {run_id} not found")
        if r.status != "open":
            raise OrchestratorError(f"Run {run_id} is {r.status}; execution needs an open run.")
        allowed = ("stopped", "interrupted", "error") if resume else ("approved",)
        if r.assessment_status not in allowed:
            verb = "resume" if resume else "start"
            raise OrchestratorError(f"Cannot {verb}: assessment is {r.assessment_status}"
                                    f"{'' if resume else ' (approve a plan first)' if r.assessment_status in ('idle', 'planned') else ''}.")
        if plan is None or plan["sha256"] != (r.limits or {}).get("plan_sha256") or not plan["integrity_ok"]:
            raise OrchestratorError("The run has no intact approved plan.")
        t = s.get(Target, r.target_id)
        if t is None or t.archived:
            raise OrchestratorError("The run's target is missing or archived.")
        stale = staleness(plan["content"], t.profile)
        if stale:
            raise OrchestratorError(f"The approved plan is stale: {stale}. Build and approve a new plan.")
        missing = [e for e in plan["content"]["engines"] if e not in ADAPTERS]
        if missing:
            raise OrchestratorError(f"No execution adapter is installed for: {', '.join(missing)}.")
        target = {"id": t.id, "name": t.name, "provider": t.provider, "kind": plan["content"]["target_kind"]}
        # The duration budget counts active execution time only: carry over what earlier executions used.
        used = float((r.assessment or {}).get("active_seconds", 0.0))
        r.limits = dict(r.limits or {}) | {"execution_started_at": time.time() - used}
        execution_id = uuid.uuid4().hex[:12]
        r.assessment = dict(r.assessment or {}) | {"execution_id": execution_id, "started_by": operator,
                                                   "started_at": utcnow().isoformat(), "finished_at": None,
                                                   "in_flight": [], "last_error": ""}
        r.stop_reason = ""
    gateway.fail_pending(run_id, "a previous execution of this run ended while the call was in flight")
    gateway.reset_control(run_id)
    out = _set(run_id, status="queued", phase="waiting for an execution slot")
    audit("assessment.resume" if resume else "assessment.start",
          {"plan_version": plan["version"], "plan_sha256": plan["sha256"], "execution_id": execution_id,
           "skipping_done": sorted(_done_case_ids(run_id)) if resume else []}, actor=operator, run_id=run_id)
    th = threading.Thread(target=_execute, name=f"assessment-{run_id}", daemon=True,
                          args=(run_id, plan, target, operator, execution_id))
    _threads[run_id] = th
    th.start()
    return out


def stop(run_id: str, *, operator: str, reason: str = "Stopped by operator", final: bool = False) -> dict:
    """Cancel execution: in-flight calls are abandoned at the gateway and no further case starts.
    `final` is used when the run itself is being stopped/completed/halted."""
    with session_scope() as s:
        r = s.get(Run, run_id)
        if r is None:
            raise LookupError(f"run {run_id} not found")
        active = r.assessment_status in ACTIVE
    if not active:
        if final:
            return status(run_id)
        raise OrchestratorError(f"Assessment is not executing ({status(run_id)['status']}).")
    gateway.cancel(run_id, reason)
    audit("assessment.stop", {"reason": reason}, actor=operator, run_id=run_id)
    th = _threads.get(run_id)
    if th is not None:
        th.join(timeout=10)
    with session_scope() as s:
        still = s.get(Run, run_id).assessment_status in ACTIVE
    if still:  # worker has not acknowledged yet (or died); record the stop ourselves
        _set(run_id, status="stopped", phase="", reason=reason)
    return status(run_id)


def halt_all(reason: str) -> list[str]:
    """Emergency stop: cancel every executing assessment."""
    gateway.cancel_all(reason)
    with session_scope() as s:
        ids = list(s.execute(select(Run.id).where(Run.assessment_status.in_(ACTIVE))).scalars())
    for rid in ids:
        th = _threads.get(rid)
        if th is not None:
            th.join(timeout=10)
        with session_scope() as s:
            still = s.get(Run, rid).assessment_status in ACTIVE
        if still:
            _set(rid, status="stopped", phase="", reason=f"Emergency stop: {reason}")
    return ids


def recover_after_restart() -> list[str]:
    """Called at API start: executions that were in flight when the process ended are marked interrupted, and
    calls that were in flight become errors (they may have reached the target, so they keep their budget)."""
    gateway.fail_pending()
    with session_scope() as s:
        ids = list(s.execute(select(Run.id).where(Run.assessment_status.in_(ACTIVE))).scalars())
    for rid in ids:
        _set(rid, status="interrupted", phase="", reason="The API stopped while this assessment was executing. "
                                                          "Resume continues with the cases that have no result.")
        audit("assessment.interrupted", {}, run_id=rid)
    return ids


# ---------------------------------------------------------------- one execution of a run
class Execution:
    """The state of one execution, and the only operations the coordinator can ask for."""

    def __init__(self, run_id: str, content: dict, target: dict, operator: str, ctl: gateway.RunControl):
        self.run_id, self.content, self.target, self.operator, self.ctl = run_id, content, target, operator, ctl
        self.cases = {c["id"]: c for c in content["cases"]}
        self.order = [c["id"] for c in content["cases"]]
        self.workers = max(1, int(content["limits"].get("technique_concurrency", 1)))
        self._sem = threading.BoundedSemaphore(self.workers)
        self._lock = threading.Lock()
        self.in_flight: set[str] = set()
        self.stop_reason = ""
        self.completed: list[str] = []  # case ids in completion order (this execution)
        self.results: dict[str, dict] = {k: self._summary(a) for k, a in _results(run_id).items()}

    @staticmethod
    def _summary(a: TestAttempt | None, case_id: str = "") -> dict:
        if a is None:
            return {"case_id": case_id, "state": "not-run"}
        return {"case_id": a.external_id, "state": "skipped" if a.verdict == "skipped" else "done",
                "verdict": a.verdict, "source_verdict": a.source_verdict, "error": a.error[:300],
                "rationale": a.rationale[:300], "technique_id": a.category}

    # ---- queries
    def halted(self) -> str:
        if self.stop_reason:
            return self.stop_reason
        if KILL.tripped:
            return f"halted: {KILL.reason or 'emergency stop'}"
        if self.ctl.cancel.is_set():
            return f"cancelled: {self.ctl.reason or 'run cancelled'}"
        return ""

    def pending(self) -> list[str]:
        with self._lock:
            return [c for c in self.order if c not in self.results and c not in self.in_flight]

    def error_streak(self) -> int:
        """Consecutive errors at the end of this execution's completion order (target health signal)."""
        n = 0
        for cid in reversed(self.completed):
            if self.results.get(cid, {}).get("verdict") != "error":
                break
            n += 1
        return n

    def state(self) -> dict:
        with self._lock:
            cases = [{"case_id": c, "label": self.cases[c]["label"], "technique_id": self.cases[c]["technique_id"],
                      "engine": self.cases[c]["engine"], "kind": self.cases[c]["kind"],
                      "planned_prompts": self.cases[c]["planned_prompts"],
                      "state": self.results[c]["state"] if c in self.results
                      else "running" if c in self.in_flight else "pending",
                      "verdict": self.results.get(c, {}).get("verdict", "")} for c in self.order]
        return {"cases": cases, "stop_reason": self.halted(), "max_parallel": self.workers,
                "error_streak": self.error_streak(), "target_kind": self.target["kind"]}

    def evidence(self, case_id: str) -> dict:
        """What the case produced, redacted and truncated (no connector access: read from persisted evidence)."""
        if case_id not in self.cases:
            return {"error": f"'{case_id}' is not an approved case."}
        with session_scope() as s:
            a = s.execute(select(TestAttempt).where(TestAttempt.run_id == self.run_id,
                                                    TestAttempt.provenance == "local-execution",
                                                    TestAttempt.external_id == case_id)).scalar()
            if a is None:
                return {"case_id": case_id, "state": "pending"}
            invs = s.execute(select(Invocation.status, Invocation.prompt, Invocation.response, Invocation.error)
                             .where(Invocation.id.in_(a.invocation_ids or [])).order_by(Invocation.id)).all()
            return {"case_id": case_id, "verdict": a.verdict, "source_verdict": a.source_verdict,
                    "detector": a.detector, "score": a.score, "rationale": a.rationale[:600], "error": a.error[:300],
                    "invocations": [{"status": st, "prompt": p[:300], "reply": r[:400], "error": e[:200]}
                                    for st, p, r, e in invs[:10]]}

    # ---- actions
    def request_stop(self, reason: str) -> dict:
        with self._lock:
            self.stop_reason = self.stop_reason or reason
        audit("coordinator.stop", {"reason": reason}, actor="coordinator", run_id=self.run_id)
        return {"stopped": True, "reason": self.stop_reason}

    def skip_case(self, case_id: str, reason: str) -> dict:
        case = self.cases.get(case_id)
        if case is None:
            return {"error": f"'{case_id}' is not an approved case."}
        with self._lock:
            if case_id in self.results or case_id in self.in_flight:
                return {"case_id": case_id, "state": self.results.get(case_id, {}).get("state", "running"),
                        "note": "already started or finished; not skipped"}
            self.in_flight.add(case_id)
        res = CaseResult(verdict="skipped", source_verdict="", test_id=case.get("probe") or case.get("strategy", ""),
                         rationale=f"Skipped by the coordinator: {reason}", evidence={"skip_reason": reason})
        return self._finish(case, res)

    def run_case(self, case_id: str) -> dict:
        case = self.cases.get(case_id)
        if case is None:
            return {"error": f"'{case_id}' is not an approved case; only cases in the approved plan can run."}
        with self._lock:
            if case_id in self.results or case_id in self.in_flight:
                return {"case_id": case_id, "state": self.results.get(case_id, {}).get("state", "running"),
                        "note": "already started or finished"}
            if self.halted():
                return {"case_id": case_id, "state": "not-run", "reason": self.halted()}
            self.in_flight.add(case_id)
        with self._sem:  # hard bound on parallel cases, whatever the coordinator asks for
            if self.halted():
                with self._lock:
                    self.in_flight.discard(case_id)
                return {"case_id": case_id, "state": "not-run", "reason": self.halted()}
            _set(self.run_id, in_flight=sorted(self.in_flight))
            publish("assessment.case", {"case_id": case_id, "label": case["label"], "engine": case["engine"],
                                        "technique_id": case["technique_id"], "state": "started"}, run_id=self.run_id)
            res = self._run_adapter(case)
        return self._finish(case, res)

    def _run_adapter(self, case: dict) -> CaseResult | None:
        ctx = CaseContext(self.run_id, case, self.content, self.target, self.operator, self.ctl.cancel)
        test_id = case.get("probe") or case.get("strategy", "")
        try:
            res = ADAPTERS[case["engine"]](ctx)
        except GatewayRefused as e:
            if e.code in STOP_CODES:
                with self._lock:
                    self.stop_reason = self.stop_reason or f"{e.code}: {e.message}"
                return None  # not a result: the case is left pending so resume can run it
            if e.code in SKIP_CODES:
                return CaseResult(verdict="skipped", source_verdict="", test_id=test_id,
                                  rationale=f"Not executed: {e.message}", evidence={"skip_reason": e.code})
            return CaseResult(verdict="error", source_verdict="", test_id=test_id,
                              error=f"Gateway refused: {e.code}: {e.message}")
        except Exception as e:  # adapter or framework failure: recorded, the run continues
            log.exception("case %s failed", case["id"])
            return CaseResult(verdict="error", source_verdict="", test_id=test_id,
                              error=f"{type(e).__name__}: {str(e)[:800]}",
                              source_detail={"traceback": traceback.format_exc()[-4000:]})
        if (self.ctl.cancel.is_set() or KILL.tripped) and res.verdict == "error":
            return None  # abandoned by a stop, not a real error
        return res

    def _finish(self, case: dict, res: CaseResult | None) -> dict:
        if res is not None:
            _persist(self.run_id, case, self.target, res, self.content)
        a = _results(self.run_id).get(case["id"]) if res is not None else None
        with self._lock:
            self.in_flight.discard(case["id"])
            if a is not None:
                self.results[case["id"]] = self._summary(a)
                self.completed.append(case["id"])
            in_flight = sorted(self.in_flight)
        _set(self.run_id, in_flight=in_flight, progress=_progress(self.run_id, self.content))
        publish("assessment.case", {"case_id": case["id"], "label": case["label"], "engine": case["engine"],
                                    "technique_id": case["technique_id"],
                                    "state": ("skipped" if res.verdict == "skipped" else "finished") if res else "not-run",
                                    "verdict": res.verdict if res else "", "error": res.error if res else "",
                                    "reason": res.rationale if res and res.verdict == "skipped" else ""},
                run_id=self.run_id)
        return self._summary(a, case["id"]) if a else {"case_id": case["id"], "state": "not-run",
                                                       "reason": self.halted()}


# ---------------------------------------------------------------- worker
def _execute(run_id: str, plan: dict, target: dict, operator: str, execution_id: str) -> None:
    slots = _semaphore()
    ctl = gateway.control(run_id)
    while not slots.acquire(timeout=0.5):  # queued: wait for a slot, but stay cancellable
        if ctl.cancel.is_set() or KILL.tripped:
            _set(run_id, status="stopped", phase="", reason=ctl.reason or KILL.reason or "Cancelled while queued")
            return
    try:
        t0 = time.monotonic()
        content = plan["content"]
        _set(run_id, status="running", phase="executing", progress=_progress(run_id, content))
        ex = Execution(run_id, content, target, operator, ctl)
        from .coordinator import coordinate

        coord = coordinate(ex)
        progress = _progress(run_id, content)
        if ctl.cancel.is_set() or KILL.tripped:
            final, reason = "stopped", ctl.reason or KILL.reason or "Cancelled"
        elif ex.stop_reason:
            final, reason = "stopped", ex.stop_reason
        elif progress["cases_done"] >= progress["cases_total"]:
            final, reason = "completed", ""
        else:
            final, reason = "stopped", "Some cases did not run."
        from ..ingest import rebuild

        rebuild(run_id)
        t_active = time.monotonic() - t0
        prev_active = _accumulated(run_id)
        _set(run_id, status=final, phase="", reason=reason, progress=progress, in_flight=[], coordinator=coord,
             finished_at=utcnow().isoformat(), active_seconds=prev_active + t_active)
        audit(f"assessment.{final}", {"reason": reason, "progress": progress, "execution_id": execution_id,
                                      "coordinator": coord}, actor=operator, run_id=run_id)
    except Exception as e:
        log.exception("assessment %s failed", run_id)
        _set(run_id, status="error", phase="", reason=f"{type(e).__name__}: {e}", last_error=traceback.format_exc()[-4000:])
        audit("assessment.error", {"error": f"{type(e).__name__}: {e}"}, run_id=run_id)
    finally:
        slots.release()
        _threads.pop(run_id, None)


def _accumulated(run_id: str) -> float:
    with session_scope() as s:
        return float((s.get(Run, run_id).assessment or {}).get("active_seconds", 0.0))


def _persist(run_id: str, case: dict, target: dict, res: CaseResult, content: dict) -> None:
    from ..catalog import taxonomy

    kind = case["kind"] if case["kind"] == "plumbing" else ("simulated" if target["kind"] == "local-stub" else "security")
    spec = taxonomy()["categories"].get(case["technique_id"], {})
    with session_scope() as s:
        inv_ids = list(s.execute(select(Invocation.id).where(
            Invocation.run_id == run_id, or_(Invocation.test_key == case["id"], Invocation.test_key.like(f"{case['id']}#%")))
            .order_by(Invocation.id)).scalars())
        row = s.execute(select(TestAttempt).where(TestAttempt.run_id == run_id, TestAttempt.source == case["engine"],
                                                  TestAttempt.external_id == case["id"])).scalar()
        if row is None:
            row = TestAttempt(run_id=run_id, source=case["engine"], external_id=case["id"])
            s.add(row)
        row.import_id, row.provenance, row.engine = None, "local-execution", case["engine"]
        row.engine_version, row.strategy = res.engine_version, res.strategy or case.get("strategy") or case.get("probe", "")
        row.objective = case.get("objective") or case.get("source", "")
        row.selection_reason = next((t["rationale"] for t in content["techniques"] if t["id"] == case["technique_id"]), "")
        row.category, row.test_id = case["technique_id"], res.test_id
        row.turns, row.detector, row.score = res.turns, res.detector, res.score
        row.verdict, row.source_verdict, row.rationale = res.verdict, res.source_verdict, res.rationale
        row.source_detail, row.error = res.source_detail, res.error
        row.evidence = dict(res.evidence) | {"kind": kind, "case_id": case["id"], "label": case["label"],
                                             "scoring": case.get("scoring", "")}
        row.invocation_ids = inv_ids
        row.severity = "Info" if kind == "plumbing" else spec.get("severity", "Unrated")
        row.recorded_at = utcnow()
    audit("assessment.result", {"case_id": case["id"], "engine": case["engine"], "verdict": res.verdict,
                                "source_verdict": res.source_verdict, "kind": kind, "invocations": len(inv_ids),
                                "error": res.error[:300]}, run_id=run_id)
