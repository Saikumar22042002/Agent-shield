"""FastAPI app. Run: uvicorn agentshield.app:app --reload  (see Makefile / dev.ps1)."""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import secrets
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Body, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import http_exception_handler, request_validation_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from . import events
from .audit import record as audit
from .audit import verify_chain
from .config import get_settings
from .connectivity import TargetArchived, check_target
from .connectors import ConnectorUnsupported
from .connectors.registry import PROVIDERS, UnknownProvider, get_provider, provider_list
from .db import acquire_instance_lock, init_engine, release_instance_lock, session_scope
from .ingest import IngestError, import_file, rebuild
from .ingest.common import load_category_map
from .models import (AuditLog, Event, Finding, FindingReview, GraphEdge, GraphNode, ImportBatch, Run, Target,
                     TestAttempt, utcnow)
from .safety import KILL, Halted, RunNotActive, SafetyViolation, assert_staging

log = logging.getLogger("agentshield")


def _seed_target_from_env() -> None:
    st = get_settings()
    if not st.target_harness_arn:
        return
    try:
        assert_staging(st.target_environment)
    except SafetyViolation as e:
        log.error("Not registering TARGET_HARNESS_ARN from .env: %s", e)
        return
    with session_scope() as s:
        if s.execute(select(Target).where(Target.harness_arn == st.target_harness_arn)).scalar():
            return
        s.add(Target(name=st.target_name, harness_arn=st.target_harness_arn, qualifier=st.target_qualifier,
                     region=st.target_region, environment=st.target_environment.lower(), aws_profile=st.aws_profile,
                     aws_role_arn=st.aws_role_arn, owner_attestation="Registered from operator .env"))
    audit("target.register", {"harness_arn": st.target_harness_arn, "via": ".env"}, actor="operator(.env)")


def _restore_kill_switch() -> None:
    """An emergency stop survives restarts: the latest kill.trip / kill.reset audit record wins."""
    with session_scope() as s:
        last = s.execute(select(AuditLog).where(AuditLog.action.in_(["kill.trip", "kill.reset"]))
                         .order_by(AuditLog.id.desc()).limit(1)).scalar()
        if last is not None and last.action == "kill.trip":
            KILL.trip((last.payload or {}).get("reason", "") + " (restored after restart)")


_kill_lock = threading.Lock()  # a local trip/reset and the background sync never interleave


def sync_kill_switch() -> str:
    """Apply the latest kill.trip / kill.reset in the audit log to this process (another process sharing the
    database may have recorded it). Returns what changed: "tripped", "reset" or ""."""
    from .assessment import orchestrator

    with _kill_lock:
        with session_scope() as s:
            last = s.execute(select(AuditLog.action, AuditLog.payload).where(
                AuditLog.action.in_(["kill.trip", "kill.reset"])).order_by(AuditLog.id.desc()).limit(1)).first()
        if last is None:
            return ""
        action, payload = last
        if action == "kill.trip" and not KILL.tripped:
            reason = (payload or {}).get("reason", "") or "Emergency stop"
            KILL.trip(reason)
            orchestrator.halt_all(reason)
            return "tripped"
        if action == "kill.reset" and KILL.tripped:
            KILL.reset()
            return "reset"
    return ""


async def _kill_sync_loop() -> None:
    while True:
        await asyncio.sleep(1.0)
        try:
            await asyncio.to_thread(sync_kill_switch)
        except Exception:  # database briefly locked; next tick retries
            log.debug("kill-switch sync failed", exc_info=True)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    st = get_settings()
    logging.basicConfig(level=st.log_level,
                        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    init_engine()
    # In-process state (run controls, budget locks, rate limits, executing threads) must not be split across
    # workers: refuse to start a second server process on the same database.
    lock = acquire_instance_lock()
    _seed_target_from_env()
    _restore_kill_switch()
    from .assessment import adapters, orchestrator

    interrupted = orchestrator.recover_after_restart()
    if interrupted:
        log.warning("Assessments interrupted by the previous shutdown: %s", ", ".join(interrupted))
    registered = adapters.register_defaults()
    if not st.auth_entries and st.host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("AUTH_TOKENS is empty but HOST=%s is not loopback: anyone who can reach the API can operate "
                    "it. Set AUTH_TOKENS before exposing AgentShield.", st.host)
    audit("server.start", {"version": app.version, "kill_switch": KILL.tripped, "adapters": registered,
                           "auth": "tokens" if st.auth_entries else "local"})
    sync = asyncio.create_task(_kill_sync_loop())
    try:
        yield
    finally:
        sync.cancel()
        audit("server.stop", {})
        release_instance_lock(lock)


app = FastAPI(title="AgentShield", version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_list, allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["Content-Disposition"])

PUBLIC_PATHS = {"/api/health", "/api/auth"}
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
ADMIN_PATHS = {"/api/kill/reset"}


def _token_identity(token: str) -> tuple[str, str] | None:
    entries = get_settings().auth_entries
    match = None
    for known, ident in entries.items():  # constant-time compare against every entry
        if hmac.compare_digest(known.encode(), (token or "").encode()):
            match = ident
    return match


@app.middleware("http")
async def access_control(request: Request, call_next):
    """With AUTH_TOKENS set, every /api route needs a bearer token (or ?access_token= for EventSource and file
    downloads, which cannot send headers). viewer = read only; operator = everything except resetting the
    emergency stop; admin = everything. The garak gateway endpoint has its own per-case token."""
    path = request.url.path
    request.state.identity = None
    if (request.method == "OPTIONS" or not path.startswith("/api/") or path in PUBLIC_PATHS
            or path.startswith("/api/gateway/garak/") or not get_settings().auth_entries):
        return await call_next(request)
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else request.query_params.get("access_token", "")
    ident = _token_identity(token)
    if ident is None:
        await asyncio.to_thread(audit, "api.denied", {"path": path, "method": request.method, "status": 401,
                                                      "reason": "missing or unknown token"})
        return JSONResponse({"detail": "Authentication required: send a valid AgentShield access token."}, 401,
                            headers={"WWW-Authenticate": "Bearer"})
    name, role = ident
    if (request.method not in READ_METHODS and role == "viewer") or (path in ADMIN_PATHS and role != "admin"):
        await asyncio.to_thread(audit, "api.denied", {"path": path, "method": request.method, "status": 403,
                                                      "role": role}, actor=name)
        return JSONResponse({"detail": f"Role '{role}' may not do this."}, 403)
    request.state.identity = ident
    return await call_next(request)


def operator(request: Request, x_operator: str | None = Header(default=None)) -> str:
    """The audited actor: the token's name when AUTH_TOKENS is set, otherwise the console's X-Operator header
    (local single-operator mode)."""
    ident = getattr(request.state, "identity", None)
    if ident:
        return ident[0]
    return (x_operator or "operator").strip()[:200]


def _audit_rejection(request: Request, status: int, detail) -> None:
    """Denied mutating requests leave an audit record (the response is unchanged)."""
    if request.method in READ_METHODS or not request.url.path.startswith("/api/") or status < 400 or status >= 500:
        return
    if status == 404:
        return
    ident = getattr(request.state, "identity", None)
    actor = ident[0] if ident else (request.headers.get("x-operator") or "operator").strip()[:200]
    text = detail if isinstance(detail, str) else json.dumps(detail, default=str)[:1000]
    audit("api.rejected", {"path": request.url.path, "method": request.method, "status": status,
                           "detail": text[:1000]}, actor=actor, run_id=request.path_params.get("run_id"))


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    await asyncio.to_thread(_audit_rejection, request, exc.status_code, exc.detail)
    return await http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError):
    await asyncio.to_thread(_audit_rejection, request, 422, exc.errors())
    return await request_validation_exception_handler(request, exc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _target_dict(t: Target) -> dict:
    spec = PROVIDERS.get(t.provider or "aws_agentcore")
    return {"id": t.id, "provider": t.provider or "aws_agentcore", "provider_label": spec.label if spec else t.provider,
            "provider_implemented": bool(spec and spec.implemented), "config": t.config or {},
            "archived": bool(t.archived), "owner_attestation": t.owner_attestation,
            "name": t.name, "harness_arn": t.harness_arn, "qualifier": t.qualifier, "region": t.region,
            "environment": t.environment, "aws_profile": t.aws_profile, "aws_role_arn": t.aws_role_arn,
            "status": t.status, "last_check_at": _iso(t.last_check_at), "last_latency_ms": t.last_latency_ms,
            "last_wall_ms": t.last_wall_ms, "last_usage": t.last_usage or {}, "last_error": t.last_error,
            "created_at": _iso(t.created_at)}


PHASES = ["Onboard target", "Verify connectivity", "Open run", "Live exchange", "Execute or import results",
          "Derive findings", "Review & close"]


def _phases(s, r: Run) -> dict:
    """Seven evaluation phases, each derived from persisted state. `current` is the first phase not done."""
    t = s.get(Target, r.target_id)
    exchanged = any((e.data or {}).get("role") == "target" for e in s.execute(select(Event).where(
        Event.run_id == r.id, Event.type == "conversation.message")).scalars())
    imported = s.execute(select(ImportBatch.id).where(ImportBatch.run_id == r.id).limit(1)).scalar() or s.execute(
        select(TestAttempt.id).where(TestAttempt.run_id == r.id, TestAttempt.provenance == "local-execution").limit(1)).scalar()
    attempts = (r.summary or {}).get("attempts", 0)
    done = [t is not None, bool(t and t.status == "connected"), True, exchanged, bool(imported),
            attempts > 0, r.status in {"complete", "stopped", "halted"}]
    current = next((i for i, d in enumerate(done) if not d), len(done) - 1)
    label = f"Closed ({r.status})" if all(done) else PHASES[current]
    return {"total": len(PHASES), "current": current + 1, "label": label, "all_done": all(done),
            "steps": [{"label": lbl, "done": d} for lbl, d in zip(PHASES, done)]}


def _run_dict(r: Run, s=None) -> dict:
    out = {"id": r.id, "target_id": r.target_id, "label": r.label, "status": r.status,
           "parent_run_id": r.parent_run_id, "summary": r.summary, "halt_reason": r.halt_reason,
           "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
           "assessment_status": r.assessment_status, "assessment_phase": r.assessment_phase,
           "stop_reason": r.stop_reason}
    if s is not None:
        out["phase"] = _phases(s, r)
    return out


def _require_not_halted() -> None:
    try:
        KILL.check()
    except Halted as e:
        raise HTTPException(423, f"Emergency stop is active: {e}") from e


# ---------------------------------------------------------------- config / health
@app.get("/api/health")
def health():
    ok, bad = verify_chain()
    return {"ok": True, "kill_switch": KILL.tripped, "audit_chain_ok": ok, "audit_first_bad": bad}


@app.get("/api/auth")
def auth_info(request: Request):
    """Whether tokens are required, and who the presented token belongs to (never the token itself)."""
    st = get_settings()
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else request.query_params.get("access_token", "")
    ident = _token_identity(token) if st.auth_entries else None
    return {"required": bool(st.auth_entries), "authenticated": bool(ident) or not st.auth_entries,
            "name": ident[0] if ident else None, "role": ident[1] if ident else ("operator" if not st.auth_entries else None)}


@app.get("/api/config")
def config():
    from .assessment.engines import coordinator_mode

    st = get_settings()
    return {
        "engine": {
            "harness": " · ".join(f"{p.label}{'' if p.implemented else ' (pending)'}" for p in PROVIDERS.values()),
            "decision": {"model": st.decision_model, "key_configured": bool(st.api_key_for(st.decision_model))},
            "generation": {"model": st.generation_model, "key_configured": bool(st.api_key_for(st.generation_model))},
            "sandbox": "Staging only (enforced)",
            "test_source": "PyRIT / garak executed through the gateway, or imported results",
            "outbound": "Approved plan prompts (gateway-enforced) + fixed connectivity greeting",
            "coordinator": coordinator_mode(),
            "store": f"SQLite (WAL) · {st.database_url.rsplit('/', 1)[-1]}",
        },
        "connectivity_message": st.connectivity_message,
        "garak_fail_threshold": st.garak_fail_threshold,
        "categories": load_category_map(str(st.category_map_file))["categories"],
        "auth_required": bool(st.auth_entries),
        "assessment_providers": st.assessment_provider_list,
    }


# ---------------------------------------------------------------- targets
ARN_RE = r"^arn:[^:]*:bedrock-agentcore:[a-z0-9-]+:[0-9]{12}:harness/.+$"


class TargetIn(BaseModel):
    provider: str = "aws_agentcore"
    name: str = Field(min_length=1, max_length=200)
    harness_arn: str = ""
    qualifier: str = ""
    region: str = ""
    environment: str
    aws_profile: str = ""
    aws_role_arn: str = ""
    config: dict[str, str] = Field(default_factory=dict)
    owner_attestation: str = Field(min_length=10, description="Operator statement that they own/are authorised for this staging agent")


def _validate_target(body: TargetIn) -> None:
    import re

    try:
        spec = get_provider(body.provider)
    except UnknownProvider as e:
        raise HTTPException(422, str(e)) from e
    if spec.key == "aws_agentcore":
        if not re.match(ARN_RE, body.harness_arn):
            raise HTTPException(422, "Harness ARN must look like arn:aws:bedrock-agentcore:<region>:<account-id>:harness/<name>.")
        if not body.region or body.region not in body.harness_arn.split(":")[3]:
            raise HTTPException(422, "Region does not match the region in the harness ARN.")
    elif spec.config_fields:
        missing = [f for f in spec.config_fields if not str(body.config.get(f, "")).strip()]
        if missing:
            raise HTTPException(422, f"{spec.label} needs: {', '.join(missing)}.")
    if spec.key == "local_model":
        from .connectors.local_model import validate_base_url

        try:
            validate_base_url(body.config.get("base_url", ""))
        except ValueError as e:
            raise HTTPException(422, str(e)) from e


@app.get("/api/targets")
def list_targets():
    with session_scope() as s:
        return [_target_dict(t) for t in s.execute(select(Target).order_by(Target.id)).scalars()]


@app.post("/api/targets", status_code=201)
def create_target(body: TargetIn, who: str = Depends(operator)):
    try:
        assert_staging(body.environment)
    except SafetyViolation as e:
        audit("target.rejected", {"harness_arn": body.harness_arn, "environment": body.environment}, actor=who)
        raise HTTPException(422, str(e)) from e
    _validate_target(body)
    spec = get_provider(body.provider)
    fields = body.model_dump()
    if spec.key != "aws_agentcore":  # AWS-only columns stay empty for other providers
        fields |= {"harness_arn": "", "region": "local" if spec.kind == "local" else body.region,
                   "qualifier": "", "aws_profile": "", "aws_role_arn": ""}
    fields["config"] = {k: str(v) for k, v in body.config.items() if k in spec.config_fields + spec.optional_fields}
    with session_scope() as s:
        t = Target(**fields | {"environment": body.environment.lower(),
                               "status": "unverified" if spec.implemented else "unsupported"})
        s.add(t)
        s.flush()
        data = _target_dict(t)
    audit("target.register", {"provider": body.provider, "harness_arn": data["harness_arn"], "config": data["config"],
                               "attestation": body.owner_attestation}, actor=who, target_id=data["id"])
    events.publish("target.registered", data)
    return data


class TargetUpdate(BaseModel):
    """Editable fields. Provider and environment cannot change (register a new target instead)."""
    name: str | None = Field(None, min_length=1, max_length=200)
    harness_arn: str | None = None
    qualifier: str | None = None
    region: str | None = None
    aws_profile: str | None = None
    aws_role_arn: str | None = None
    config: dict[str, str] | None = None
    owner_attestation: str | None = Field(None, min_length=10)


IDENTITY_FIELDS = {"harness_arn", "qualifier", "region", "aws_profile", "aws_role_arn", "config"}


@app.put("/api/targets/{target_id}")
def update_target(target_id: int, body: TargetUpdate, who: str = Depends(operator)):
    from .assessment import plans

    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(422, "Nothing to update.")
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        current = TargetIn(provider=t.provider or "aws_agentcore", name=t.name, harness_arn=t.harness_arn,
                           qualifier=t.qualifier, region=t.region, environment=t.environment,
                           aws_profile=t.aws_profile, aws_role_arn=t.aws_role_arn, config=dict(t.config or {}),
                           owner_attestation=t.owner_attestation if len(t.owner_attestation) >= 10 else "x" * 10)
        merged = TargetIn(**(current.model_dump() | changes))
        _validate_target(merged)
        spec = get_provider(merged.provider)
        if spec.key != "aws_agentcore":
            changes = {k: v for k, v in changes.items() if k not in ("harness_arn", "region", "qualifier",
                                                                     "aws_profile", "aws_role_arn")}
        if "config" in changes:
            changes["config"] = {k: str(v) for k, v in changes["config"].items()
                                 if k in spec.config_fields + spec.optional_fields}
        changed = sorted(k for k, v in changes.items() if getattr(t, k) != v)
        for k in changed:
            setattr(t, k, changes[k])
        identity_changed = bool(IDENTITY_FIELDS & set(changed))
        if identity_changed:  # the connection must be proven again for the new identity
            t.status, t.last_error = ("unverified" if spec.implemented else "unsupported"), ""
        data = _target_dict(t)
    invalidated = plans.invalidate_for_target(target_id, reason=f"target changed ({', '.join(changed)})",
                                              operator=who) if identity_changed else []
    audit("target.update", {"changed": changed, "name": data["name"], "invalidated_runs": invalidated},
          actor=who, target_id=target_id)
    events.publish("target.updated", data)
    return data


class ArchiveIn(BaseModel):
    archived: bool = True


@app.post("/api/targets/{target_id}/archive")
def archive_target(target_id: int, body: ArchiveIn, who: str = Depends(operator)):
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        t.archived = body.archived
        data = _target_dict(t)
    audit("target.archive" if body.archived else "target.restore", {"name": data["name"]}, actor=who, target_id=target_id)
    events.publish("target.updated", data)
    return data


@app.post("/api/targets/{target_id}/check")
def connectivity_check(target_id: int, who: str = Depends(operator)):
    try:
        return check_target(target_id, operator=who)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except Halted as e:
        raise HTTPException(423, f"Emergency stop is active: {e}") from e
    except ConnectorUnsupported as e:
        raise HTTPException(501, str(e)) from e
    except TargetArchived as e:
        raise HTTPException(409, str(e)) from e
    except SafetyViolation as e:
        raise HTTPException(429 if "Rate limited" in str(e) else 422, str(e)) from e


# ---------------------------------------------------------------- runs
class RunIn(BaseModel):
    target_id: int
    label: str = ""
    parent_run_id: str | None = None


@app.get("/api/runs")
def list_runs():
    with session_scope() as s:
        return [_run_dict(r, s) for r in s.execute(select(Run).order_by(Run.started_at.desc())).scalars()]


@app.post("/api/runs", status_code=201)
def create_run(body: RunIn, who: str = Depends(operator)):
    _require_not_halted()
    with session_scope() as s:
        t = s.get(Target, body.target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        assert_staging(t.environment)
        if t.archived:
            raise HTTPException(409, "Target is archived; restore it before opening a run.")
        if body.parent_run_id and s.get(Run, body.parent_run_id) is None:
            raise HTTPException(404, "parent run not found")
        run = Run(id=f"RUN-{utcnow():%Y%m%d}-{secrets.token_hex(2).upper()}", target_id=t.id, label=body.label,
                  parent_run_id=body.parent_run_id)
        s.add(run)
        s.flush()
        rid = run.id
    audit("run.create", body.model_dump(), actor=who, run_id=rid)
    summary = rebuild(rid)
    with session_scope() as s:
        data = _run_dict(s.get(Run, rid), s)
    events.publish("run.created", data, run_id=rid)
    return data | {"summary": summary}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    with session_scope() as s:
        r = s.get(Run, run_id)
        if r is None:
            raise HTTPException(404, "run not found")
        imports = [{"id": i.id, "tool": i.tool, "filename": i.filename, "sha256": i.sha256, "tool_version": i.tool_version,
                    "imported_by": i.imported_by, "stats": i.stats, "warnings": i.warnings[:20],
                    "imported_at": _iso(i.imported_at)}
                   for i in s.execute(select(ImportBatch).where(ImportBatch.run_id == run_id).order_by(ImportBatch.id)).scalars()]
        return _run_dict(r, s) | {"imports": imports}


# Run lifecycle. open <-> paused; open|paused -> stopped | complete; the emergency stop -> halted.
# stopped, halted and complete are final. Invalid or repeated transitions return 409.
RUN_TRANSITIONS = {"pause": ({"open"}, "paused"), "resume": ({"paused"}, "open"),
                   "stop": ({"open", "paused"}, "stopped"), "complete": ({"open", "paused"}, "complete")}


class RunAction(BaseModel):
    reason: str = ""


def _transition(run_id: str, action: str, who: str, reason: str = "") -> dict:
    from .assessment import orchestrator

    allowed, new = RUN_TRANSITIONS[action]
    if action == "resume":
        _require_not_halted()
    with session_scope() as s:
        r = s.get(Run, run_id)
        if r is None:
            raise HTTPException(404, "run not found")
        if r.status not in allowed:
            raise HTTPException(409, f"Cannot {action} run {run_id}: it is {r.status}.")
        executing = r.assessment_status in orchestrator.ACTIVE
    if action == "complete" and executing:
        raise HTTPException(409, "An assessment is executing; stop it before completing the run.")
    if action == "stop" and executing:
        orchestrator.stop(run_id, operator=who, reason=reason or "Run stopped by operator", final=True)
    with session_scope() as s:
        r = s.get(Run, run_id)
        if r.status not in allowed:
            raise HTTPException(409, f"Cannot {action} run {run_id}: it is {r.status}.")
        previous = r.status
        r.status = new
        if new in {"stopped", "complete"}:
            r.finished_at = utcnow()
        if new == "stopped":
            r.halt_reason = reason or "Stopped by operator"
    audit(f"run.{action}", {"from": previous, "to": new, "reason": reason}, actor=who, run_id=run_id)
    events.publish("run.status", {"run_id": run_id, "from": previous, "status": new, "reason": reason, "by": who},
                   run_id=run_id)
    if new == "complete":
        rebuild(run_id)
        events.publish("run.completed", {"run_id": run_id}, run_id=run_id)
    return get_run(run_id)


@app.post("/api/runs/{run_id}/pause")
def pause_run(run_id: str, body: RunAction | None = None, who: str = Depends(operator)):
    return _transition(run_id, "pause", who, (body or RunAction()).reason)


@app.post("/api/runs/{run_id}/resume")
def resume_run(run_id: str, who: str = Depends(operator)):
    return _transition(run_id, "resume", who)


@app.post("/api/runs/{run_id}/stop")
def stop_run(run_id: str, body: RunAction | None = None, who: str = Depends(operator)):
    return _transition(run_id, "stop", who, (body or RunAction()).reason)


@app.post("/api/runs/{run_id}/complete")
def complete_run(run_id: str, who: str = Depends(operator)):
    return _transition(run_id, "complete", who)


@app.post("/api/runs/{run_id}/exchange")
def run_exchange(run_id: str, who: str = Depends(operator)):
    """Send the fixed benign connectivity greeting to the run's target and record both sides in the run's
    conversation. This is the only message AgentShield sends; test execution stays in PyRIT / garak."""
    with session_scope() as s:
        r = s.get(Run, run_id)
        if r is None:
            raise HTTPException(404, "run not found")
        target_id = r.target_id
    try:
        return check_target(target_id, operator=who, run_id=run_id)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except Halted as e:
        raise HTTPException(423, f"Emergency stop is active: {e}") from e
    except RunNotActive as e:
        raise HTTPException(409, str(e)) from e
    except ConnectorUnsupported as e:
        raise HTTPException(501, str(e)) from e
    except TargetArchived as e:
        raise HTTPException(409, str(e)) from e
    except SafetyViolation as e:
        raise HTTPException(429 if "Rate limited" in str(e) else 422, str(e)) from e


ACTIVITY_EVENTS = {"run.created", "run.status", "run.completed", "connectivity.start", "connectivity.result",
                   "import.done", "judge.done", "kill.tripped", "kill.reset", "plan.created", "plan.approved",
                   "plan.invalidated", "assessment.status", "assessment.case", "gateway.refused", "gateway.retry",
                   "coordinator.start", "coordinator.step", "coordinator.done", "finding.review"}


@app.get("/api/runs/{run_id}/timeline")
def run_timeline(run_id: str, attempt_limit: int = Query(200, le=1000)):
    """Everything the evaluation workspace shows for a run, from persisted data only, in chronological order.

    kind=message: live exchanges (conversation.* events) and the turns of imported tool attempts.
    kind=activity: run lifecycle, connectivity, imports, reviews and stops (run-scoped events plus global stops).
    kind=evidence: imported files, tool scorer results, advisory reviews and findings.
    Every item carries `provenance` (sent | measured | local-stub | imported | model-judged | derived | system).
    """
    from .catalog import taxonomy

    cmap = taxonomy()
    items: list[dict] = []
    with session_scope() as s:
        run = s.get(Run, run_id)
        if run is None:
            raise HTTPException(404, "run not found")
        target = s.get(Target, run.target_id)
        provider = (target.provider if target else "") or "aws_agentcore"
        evs = s.execute(select(Event).where(
            (Event.run_id == run_id) | (Event.type.in_(["kill.tripped", "kill.reset"]) & (Event.ts >= run.started_at)))
            .order_by(Event.id)).scalars().all()
        for ev in evs:
            base = {"id": f"ev-{ev.id}", "event_id": ev.id, "ts": _iso(ev.ts), "type": ev.type}
            d = ev.data or {}
            if ev.type == "conversation.message":
                items.append(base | {"kind": "message", "role": d.get("role"), "text": d.get("text", ""),
                                     "turn": d.get("turn"), "message_id": d.get("message_id"),
                                     "provenance": d.get("provenance"), "provider": d.get("provider", provider),
                                     "source": "agentshield", "meta": {k: d.get(k) for k in (
                                         "latency_ms", "wall_ms", "usage", "stop_reason", "tool_events",
                                         "session_id", "kind") if d.get(k) not in (None, "", {}, [])}})
            elif ev.type == "conversation.error":
                items.append(base | {"kind": "message", "role": "target", "text": "", "turn": d.get("turn"),
                                     "message_id": d.get("message_id"), "provenance": "measured",
                                     "provider": d.get("provider", provider), "source": "agentshield",
                                     "error": {"message": d.get("error"), "code": d.get("error_code"),
                                               "hint": d.get("hint")}, "meta": {}})
            elif ev.type in ACTIVITY_EVENTS:
                items.append(base | {"kind": "activity", "data": d,
                                     "provenance": "measured" if ev.type.startswith("connectivity")
                                     else "gateway" if ev.type.startswith("gateway.") else "system"})

        imports = {i.id: i for i in s.execute(select(ImportBatch).where(ImportBatch.run_id == run_id)).scalars()}
        for i in imports.values():
            items.append({"id": f"imp-{i.id}", "kind": "evidence", "type": "import", "ts": _iso(i.imported_at),
                          "provenance": "imported", "data": {"tool": i.tool, "filename": i.filename, "sha256": i.sha256,
                                                             "tool_version": i.tool_version, "stats": i.stats,
                                                             "imported_by": i.imported_by}})
        attempts = s.execute(select(TestAttempt).where(TestAttempt.run_id == run_id).order_by(TestAttempt.id)
                             .limit(attempt_limit)).scalars().all()
        for a in attempts:
            imp = imports.get(a.import_id)
            ts = _iso(imp.imported_at if imp else a.recorded_at)
            spec = cmap["categories"].get(a.category, {})
            head = {"attempt_id": a.id, "external_id": a.external_id, "test_id": a.test_id, "category": a.category,
                    "category_title": spec.get("title", "Unmapped"), "source_tool": a.source,
                    "recorded_at": _iso(a.recorded_at)}
            executed = a.provenance == "local-execution"
            if executed:  # its turns are already in the feed as live gateway messages; add only the verdict
                head |= {"engine": a.engine, "engine_version": a.engine_version, "strategy": a.strategy,
                         "source_verdict": a.source_verdict, "kind": (a.evidence or {}).get("kind", ""),
                         "case_id": (a.evidence or {}).get("case_id", ""), "label": (a.evidence or {}).get("label", ""),
                         "error": a.error, "invocation_ids": a.invocation_ids}
                items.append({"id": f"score-{a.id}", "kind": "evidence", "type": "scorer.result",
                              "ts": _iso(a.recorded_at), "provenance": "executed",
                              "data": head | {"detector": a.detector, "score": a.score, "verdict": a.verdict,
                                              "rationale": a.rationale, "trap_hit": a.trap_hit}})
                continue
            items.append({"id": f"att-{a.id}", "kind": "activity", "type": "attempt.start", "ts": ts,
                          "provenance": "imported", "data": head | {"turns": len(a.turns)}})
            for n, t in enumerate(a.turns):
                role = {"assistant": "target", "user": "evaluator"}.get(t.get("role"), "system")
                items.append({"id": f"att-{a.id}-{n:04d}", "kind": "message", "type": "imported.turn", "ts": ts,
                              "role": role, "text": t.get("text", ""), "turn": n + 1, "provenance": "imported",
                              "provider": provider, "source": a.source,
                              "meta": head | ({"generation": t["generation"]} if "generation" in t else {})
                                      | {"recorded_role": t.get("role")}})
            items.append({"id": f"score-{a.id}", "kind": "evidence", "type": "scorer.result", "ts": ts,
                          "provenance": "imported", "data": head | {"detector": a.detector, "score": a.score,
                                                                    "verdict": a.verdict, "rationale": a.rationale,
                                                                    "trap_hit": a.trap_hit}})
            if a.model_verdict:
                items.append({"id": f"review-{a.id}", "kind": "evidence", "type": "model.review",
                              "ts": _iso(a.model_judged_at), "provenance": "model-judged",
                              "data": head | {"verdict": a.model_verdict, "rationale": a.model_rationale,
                                              "model": a.model_id}})
        for f in s.execute(select(Finding).where(Finding.run_id == run_id)).scalars():
            items.append({"id": f"finding-{f.id}", "kind": "evidence", "type": "finding", "ts": _iso(f.created_at),
                          "provenance": "derived", "data": {"finding_id": f.id, "attempt_id": f.attempt_id,
                                                            "title": f.title, "severity": f.severity,
                                                            "status": f.status, "category": f.category}})
        total_attempts = (run.summary or {}).get("attempts", 0)
        run_data = _run_dict(run, s)
    # Group an imported attempt's header, turns and score together; findings go after what they derive from.
    rank = {"attempt.start": 0, "imported.turn": 1, "scorer.result": 2, "model.review": 3, "finding": 9}
    items.sort(key=lambda x: (x["ts"] or "", 1 if x["type"] == "finding" else 0, x.get("event_id") or 0,
                              (x.get("data") or x.get("meta") or {}).get("attempt_id") or 0,
                              rank.get(x["type"], 0), x.get("turn") or 0, x["id"]))
    return {"run": run_data, "items": items, "truncated": total_attempts > attempt_limit,
            "attempt_limit": attempt_limit, "last_event_id": max((x.get("event_id") or 0 for x in items), default=0)}


@app.post("/api/runs/{run_id}/imports", status_code=201)
async def upload_import(run_id: str, tool: str = Form(...), file: UploadFile = File(...), who: str = Depends(operator)):
    _require_not_halted()
    limit = get_settings().max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"File larger than {get_settings().max_upload_mb} MB")
    try:
        return await asyncio.to_thread(import_file, run_id, tool, file.filename or "upload", data, operator=who)
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except RunNotActive as e:
        raise HTTPException(409, str(e)) from e
    except IngestError as e:
        raise HTTPException(422, str(e)) from e


@app.get("/api/runs/{run_id}/attempts")
def list_attempts(run_id: str, category: str | None = None, verdict: str | None = None,
                  limit: int = Query(200, le=1000), offset: int = 0):
    with session_scope() as s:
        q = select(TestAttempt).where(TestAttempt.run_id == run_id)
        if category:
            q = q.where(TestAttempt.category == category)
        if verdict:
            q = q.where(TestAttempt.verdict == verdict)
        rows = s.execute(q.order_by(TestAttempt.id).offset(offset).limit(limit)).scalars().all()
        return [{"id": a.id, "source": a.source, "external_id": a.external_id, "category": a.category,
                 "test_id": a.test_id, "turns": a.turns, "detector": a.detector, "score": a.score, "verdict": a.verdict,
                 "rationale": a.rationale, "trap_hit": a.trap_hit, "severity": a.severity,
                 "recorded_at": _iso(a.recorded_at),
                 "model_review": ({"verdict": a.model_verdict, "rationale": a.model_rationale, "model": a.model_id,
                                   "judged_at": _iso(a.model_judged_at)} if a.model_verdict else None)} for a in rows]


# ---------------------------------------------------------------- DECISION_MODEL review (advisory)
def _judge_call(fn, *args, **kw):
    from .judge import JudgeError
    from .llm import ModelNotConfigured

    try:
        return fn(*args, **kw)
    except Halted as e:
        raise HTTPException(423, f"Emergency stop is active: {e}") from e
    except RunNotActive as e:
        raise HTTPException(409, str(e)) from e
    except ModelNotConfigured as e:
        raise HTTPException(503, str(e)) from e
    except LookupError as e:
        raise HTTPException(404, str(e)) from e
    except JudgeError as e:
        raise HTTPException(502, str(e)) from e
    except Exception as e:  # provider/network errors from the model SDK
        log.exception("DECISION_MODEL call failed")
        raise HTTPException(502, f"DECISION_MODEL call failed: {type(e).__name__}: {str(e)[:300]}") from e


@app.post("/api/attempts/{attempt_id}/judge")
def judge_one(attempt_id: int, who: str = Depends(operator)):
    from .judge import judge_attempt

    return _judge_call(judge_attempt, attempt_id, operator=who)


@app.post("/api/runs/{run_id}/judge")
def judge_many(run_id: str, verdict: str | None = "inconclusive", limit: int | None = None,
               who: str = Depends(operator)):
    from .judge import judge_run

    return _judge_call(judge_run, run_id, operator=who, verdict=verdict or None, limit=limit)


@app.get("/api/runs/{run_id}/findings")
def list_findings(run_id: str):
    from .catalog import taxonomy

    cmap = taxonomy()
    with session_scope() as s:
        rows = s.execute(select(Finding).where(Finding.run_id == run_id).order_by(Finding.id)).scalars().all()
        return [{"id": f.id, "attempt_id": f.attempt_id, "category": f.category, "test_id": f.test_id,
                 "severity": f.severity, "title": f.title, "evidence": f.evidence, "status": f.status,
                 "closed_by_run_id": f.closed_by_run_id, "remediation_key": f.remediation_key,
                 "confirmation": f.confirmation, "confirmation_basis": f.confirmation_basis,
                 "fix": cmap["remediations"].get(f.remediation_key, ""), "created_at": _iso(f.created_at)} for f in rows]


class FindingReviewIn(BaseModel):
    decision: str = Field(pattern="^(confirmed|dismissed|candidate)$")
    note: str = Field("", max_length=1000)


@app.post("/api/findings/{finding_id}/review")
def review_finding(finding_id: int, body: FindingReviewIn, who: str = Depends(operator)):
    """Operator decision on a finding: confirmed, dismissed, or back to candidate. Kept across rebuilds."""
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            raise HTTPException(404, "finding not found")
        run_id, category, test_id = f.run_id, f.category, f.test_id
        r = s.get(Run, run_id)
        if r is not None and r.status in ("halted",):
            raise HTTPException(409, f"Run {run_id} is halted.")
        existing = s.execute(select(FindingReview).where(FindingReview.run_id == run_id, FindingReview.category == category,
                                                         FindingReview.test_id == test_id)).scalar()
        if body.decision == "candidate":
            if existing is not None:
                s.delete(existing)
        elif existing is None:
            s.add(FindingReview(run_id=run_id, category=category, test_id=test_id, decision=body.decision,
                                note=body.note, decided_by=who))
        else:
            existing.decision, existing.note, existing.decided_by, existing.decided_at = (
                body.decision, body.note, who, utcnow())
    audit("finding.review", {"finding_id": finding_id, "category": category, "test_id": test_id,
                             "decision": body.decision, "note": body.note}, actor=who, run_id=run_id)
    rebuild(run_id)
    events.publish("finding.review", {"category": category, "test_id": test_id, "decision": body.decision,
                                      "by": who}, run_id=run_id)
    return list_findings(run_id)


@app.get("/api/runs/{run_id}/report.pdf")
def report_pdf(run_id: str, who: str = Depends(operator)):
    from .report import build_pdf

    try:
        path = build_pdf(run_id)
    except LookupError as e:
        raise HTTPException(404, "run not found") from e
    audit("report.export", {"file": path.name}, actor=who, run_id=run_id)
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@app.get("/api/graph")
def graph(run_id: str):
    with session_scope() as s:
        nodes = [{"id": n.key, "kind": n.kind, "label": n.label, "meta": n.meta}
                 for n in s.execute(select(GraphNode).where(GraphNode.run_id == run_id)).scalars()]
        edges = [{"source": e.src, "target": e.dst, "kind": e.kind, "meta": e.meta}
                 for e in s.execute(select(GraphEdge).where(GraphEdge.run_id == run_id)).scalars()]
    return {"run_id": run_id, "nodes": nodes, "edges": edges}


# ---------------------------------------------------------------- audit
@app.get("/api/audit")
def audit_log(limit: int = Query(100, le=1000), before_id: int | None = None, run_id: str | None = None,
              action: str | None = None):
    with session_scope() as s:
        q = select(AuditLog)
        if before_id:
            q = q.where(AuditLog.id < before_id)
        if run_id:
            q = q.where(AuditLog.run_id == run_id)
        if action:
            q = q.where(AuditLog.action.like(f"{action}%"))
        rows = s.execute(q.order_by(AuditLog.id.desc()).limit(limit)).scalars().all()
        return [{"id": r.id, "ts": _iso(r.ts), "actor": r.actor, "action": r.action, "run_id": r.run_id,
                 "target_id": r.target_id, "payload": r.payload, "hash": r.hash, "prev_hash": r.prev_hash} for r in rows]


@app.get("/api/audit/verify")
def audit_verify():
    ok, bad = verify_chain()
    return {"ok": ok, "first_bad_id": bad}


# ---------------------------------------------------------------- kill switch
class KillIn(BaseModel):
    reason: str = "Emergency stop from console"


@app.get("/api/kill")
def kill_state():
    return {"tripped": KILL.tripped, "reason": KILL.reason, "tripped_at": KILL.tripped_at}


@app.post("/api/kill")
def kill(body: KillIn, who: str = Depends(operator)):
    from .assessment import orchestrator

    with _kill_lock:
        KILL.trip(body.reason)
        orchestrator.halt_all(body.reason)
        halted = []
        with session_scope() as s:
            for r in s.execute(select(Run).where(Run.status.in_(["open", "paused"]))).scalars():
                r.status, r.halt_reason, r.finished_at = "halted", body.reason, utcnow()
                halted.append(r.id)
        audit("kill.trip", {"reason": body.reason, "halted_runs": halted}, actor=who)
    events.publish("kill.tripped", {"reason": body.reason, "halted_runs": halted, "by": who})
    return kill_state() | {"halted_runs": halted}


@app.post("/api/kill/reset")
def kill_reset(who: str = Depends(operator)):
    with _kill_lock:
        KILL.reset()
        audit("kill.reset", {}, actor=who)
    events.publish("kill.reset", {"by": who})
    return kill_state()


# ---------------------------------------------------------------- profiles, catalog, plans, execution
def _assess_call(fn, *args, **kw):
    from .assessment.orchestrator import OrchestratorError
    from .assessment.plans import PlanError

    try:
        return fn(*args, **kw)
    except Halted as e:
        raise HTTPException(423, f"Emergency stop is active: {e}") from e
    except LookupError as e:
        raise HTTPException(404, str(e).strip("'")) from e
    except PlanError as e:
        raise HTTPException(422, str(e)) from e
    except OrchestratorError as e:
        raise HTTPException(409, str(e)) from e


@app.get("/api/targets/{target_id}/profile")
def get_profile(target_id: int):
    from .profile import load

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        p = load(t.profile)
    return p.model_dump() | {"documented": p.documented, "capabilities": sorted(p.capabilities)}


@app.put("/api/targets/{target_id}/profile")
def put_profile(target_id: int, body: dict, who: str = Depends(operator)):
    import hashlib

    from pydantic import ValidationError

    from .profile import TargetProfile, load

    try:
        p = TargetProfile.model_validate(body)
    except ValidationError as e:
        raise HTTPException(422, e.errors(include_url=False, include_context=False)) from e
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        unchanged = load(t.profile).model_dump() == p.model_dump()
        t.profile = p.model_dump()
    if unchanged:
        return get_profile(target_id)
    from .assessment import plans

    # The audit keeps a hash of the hints, not the canary values themselves.
    audit("target.profile", {"role": p.role, "tools": [x.name for x in p.tools], "capabilities": sorted(p.capabilities),
                             "hints_sha256": hashlib.sha256(p.hints.model_dump_json().encode()).hexdigest()},
          actor=who, target_id=target_id)
    plans.invalidate_for_target(target_id, reason="target profile changed", operator=who)
    events.publish("target.updated", {"id": target_id, "profile": True})
    return get_profile(target_id)


@app.get("/api/engines")
def engines_status():
    from .assessment import engines, orchestrator

    st = get_settings()
    return {"engines": engines.status(), "adapters": sorted(orchestrator.ADAPTERS),
            "assessment_providers": st.assessment_provider_list, "limits": st.limits()}


@app.get("/api/catalog")
def technique_catalog():
    from .assessment import engines
    from .catalog import inventory

    return inventory(engines.status())


class PlanIn(BaseModel):
    techniques: list[str] = Field(min_length=1)
    executions: dict[str, list[str]] = Field(default_factory=dict)
    benign_prompt: str = Field("", max_length=2000)
    benign_turns: list[str] = Field(default_factory=list, max_length=5)
    limits: dict[str, float | int] = Field(default_factory=dict)
    note: str = Field("", max_length=1000)


@app.get("/api/runs/{run_id}/plans")
def run_plans(run_id: str):
    from .assessment import plans

    with session_scope() as s:
        if s.get(Run, run_id) is None:
            raise HTTPException(404, "run not found")
    return plans.list_plans(run_id)


@app.get("/api/runs/{run_id}/plan-options")
def plan_options(run_id: str):
    from .assessment import plans

    return _assess_call(plans.options, run_id)


@app.post("/api/runs/{run_id}/plans", status_code=201)
def create_plan(run_id: str, body: PlanIn, who: str = Depends(operator)):
    from .assessment import plans

    _require_not_halted()
    return _assess_call(plans.build, run_id, techniques=body.techniques, executions=body.executions,
                        benign_prompt=body.benign_prompt, benign_turns=body.benign_turns, limits=body.limits,
                        note=body.note, operator=who)


@app.post("/api/runs/{run_id}/plans/{version}/approve")
def approve_plan(run_id: str, version: int, who: str = Depends(operator)):
    from .assessment import plans

    _require_not_halted()
    return _assess_call(plans.approve, run_id, version, operator=who)


@app.get("/api/runs/{run_id}/assessment")
def assessment_status(run_id: str):
    from .assessment import orchestrator

    return _assess_call(orchestrator.status, run_id)


@app.post("/api/runs/{run_id}/assessment/start")
def assessment_start(run_id: str, who: str = Depends(operator)):
    from .assessment import orchestrator

    _require_not_halted()
    return _assess_call(orchestrator.start, run_id, operator=who)


@app.post("/api/runs/{run_id}/assessment/resume")
def assessment_resume(run_id: str, who: str = Depends(operator)):
    from .assessment import orchestrator

    _require_not_halted()
    return _assess_call(orchestrator.start, run_id, operator=who, resume=True)


@app.post("/api/runs/{run_id}/assessment/stop")
def assessment_stop(run_id: str, body: RunAction | None = None, who: str = Depends(operator)):
    from .assessment import orchestrator

    return _assess_call(orchestrator.stop, run_id, operator=who,
                        reason=(body or RunAction()).reason or "Stopped by operator")


class GarakPrompt(BaseModel):
    prompt: str = ""


@app.post("/api/gateway/garak/{run_id}/{case_id}")
def garak_gateway(run_id: str, case_id: str, request: Request, body: GarakPrompt = Body(...)):
    """garak's REST generator posts each prompt here while an approved garak case executes. Loopback clients with
    the case's one-time token only; every prompt goes through gateway.invoke with all plan controls."""
    from .assessment.garak_adapter import handle_prompt

    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    status_code, payload = handle_prompt(run_id, case_id, token, request.client.host if request.client else "",
                                         body.prompt)
    return JSONResponse(payload, status_code=status_code)


@app.get("/api/runs/{run_id}/invocations")
def run_invocations(run_id: str, status: str | None = None, limit: int = Query(500, le=2000)):
    """Every target prompt the gateway sent or refused for this run: the canonical execution evidence."""
    from .models import Invocation

    with session_scope() as s:
        q = select(Invocation).where(Invocation.run_id == run_id)
        if status:
            q = q.where(Invocation.status == status)
        rows = s.execute(q.order_by(Invocation.id).limit(limit)).scalars().all()
        return [{"id": i.id, "technique_id": i.technique_id, "test_key": i.test_key, "engine": i.engine,
                 "session_id": i.session_id, "turn": i.turn, "attempt": i.attempt, "prompt": i.prompt,
                 "response": i.response,
                 "status": i.status, "error": i.error, "latency_ms": i.latency_ms, "wall_ms": i.wall_ms,
                 "usage": i.usage, "tool_events": i.tool_events, "provenance": i.provenance,
                 "created_at": _iso(i.created_at)} for i in rows]


@app.get("/api/providers")
def providers():
    return provider_list()


@app.get("/api/events")
def event_history(limit: int = Query(200, le=1000)):
    """Most recent persisted events, oldest first — lets the console rebuild its activity feed after a
    reload or server restart, then continue live from /api/stream."""
    return events.recent(limit)


# ---------------------------------------------------------------- live stream (SSE)
@app.get("/api/stream")
async def stream(request: Request, last_event_id: str | None = Header(default=None),
                 since: str | None = Query(default=None, alias="last_event_id")):
    # Resume point: the browser's Last-Event-ID header on a native reconnect, or ?last_event_id= when the
    # console reopens a stalled stream itself (EventSource cannot set headers).
    resume = last_event_id or since
    start = int(resume) if resume and resume.isdigit() else await asyncio.to_thread(events.latest_id)

    async def gen():
        # Bounded lifetime: the browser's EventSource reconnects with Last-Event-ID, so nothing is
        # lost, and server reload/shutdown is never blocked for long by an open console.
        cursor, idle = start, 0.0
        deadline = asyncio.get_running_loop().time() + 300
        yield "retry: 1000\n\n"
        while not await request.is_disconnected() and asyncio.get_running_loop().time() < deadline:
            batch = await asyncio.to_thread(events.since, cursor)
            for ev in batch:
                cursor = ev["id"]
                yield f"id: {ev['id']}\nevent: {ev['type']}\ndata: {json.dumps(ev, default=str)}\n\n"
            if batch:
                idle = 0.0
            else:
                await asyncio.sleep(0.4)
                idle += 0.4
                if idle >= 10:  # named event (no id), so the console's watchdog can tell a live stream from a stalled one
                    yield "event: ping\ndata: {}\n\n"
                    idle = 0.0

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
