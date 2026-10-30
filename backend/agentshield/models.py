"""SQLite schema. See ARCHITECTURE.md §4 for the table-by-table rationale.

Attempts come from two separate paths, told apart by `TestAttempt.provenance`:
  imported        — read from PyRIT / garak / trap files the operator's team produced elsewhere
  local-execution — executed by AgentShield's assessment engines through the target gateway
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), default="aws_agentcore")  # key in connectors/registry.py
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # provider-specific settings (non-AWS providers)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    name: Mapped[str] = mapped_column(String(200))
    harness_arn: Mapped[str] = mapped_column(String(400))
    qualifier: Mapped[str] = mapped_column(String(64), default="")
    region: Mapped[str] = mapped_column(String(32))
    environment: Mapped[str] = mapped_column(String(32))
    aws_profile: Mapped[str] = mapped_column(String(128), default="")
    aws_role_arn: Mapped[str] = mapped_column(String(400), default="")
    owner_attestation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="unverified")  # unverified|connected|error|unsupported
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_latency_ms: Mapped[float | None] = mapped_column(Float)
    last_wall_ms: Mapped[float | None] = mapped_column(Float)
    last_usage: Mapped[dict | None] = mapped_column(JSON)
    last_error: Mapped[str] = mapped_column(Text, default="")
    # Operator-documented role, tools, permissions, data sensitivity and policies (profile.py).
    profile: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Run(Base):
    """An assessment of one target: holds one or more imports. A re-test is a new Run with
    parent_run_id set; findings in the parent are closed when the re-test shows them passing."""

    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    label: Mapped[str] = mapped_column(String(200), default="")
    # open: accepts imports + reviews · paused: blocked, resumable · stopped: ended by operator (final)
    # halted: emergency stop (final) · complete: closed normally (final)
    status: Mapped[str] = mapped_column(String(24), default="open")
    parent_run_id: Mapped[str | None] = mapped_column(String(32))
    summary: Mapped[dict | None] = mapped_column(JSON)
    halt_reason: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Assessment execution state, separate from the run lifecycle above:
    # idle | planned | approved | running | completed | stopped | interrupted | error
    assessment_status: Mapped[str] = mapped_column(String(16), default="idle")
    assessment_phase: Mapped[str] = mapped_column(String(32), default="")
    stop_reason: Mapped[str] = mapped_column(Text, default="")
    limits: Mapped[dict] = mapped_column(JSON, default=dict)  # effective limits approved with the plan
    # Execution bookkeeping: coordinator mode/model, attacker-side token usage, progress, last error.
    assessment: Mapped[dict] = mapped_column(JSON, default=dict)


class AssessmentPlan(Base):
    """A versioned test plan for one run. Only an approved plan can execute; approving supersedes older ones."""

    __tablename__ = "assessment_plans"
    __table_args__ = (UniqueConstraint("run_id", "version"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    # draft|approved|superseded|invalidated (approval withdrawn because the profile, catalog or target changed)
    status: Mapped[str] = mapped_column(String(16), default="draft")
    content: Mapped[dict] = mapped_column(JSON)  # techniques, limits, engine, catalog version, profile snapshot
    sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_by: Mapped[str] = mapped_column(String(200), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Invocation(Base):
    """One target prompt sent through the gateway (or refused by it). The canonical evidence record:
    every engine's traffic lands here, and budgets are counted from these rows."""

    __tablename__ = "invocations"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    target_id: Mapped[int] = mapped_column(Integer)
    technique_id: Mapped[str] = mapped_column(String(64), default="")
    test_key: Mapped[str] = mapped_column(String(100), default="")  # groups the turns of one test case
    engine: Mapped[str] = mapped_column(String(32), default="")  # native|deepagents|pyrit|garak|connectivity
    session_id: Mapped[str] = mapped_column(String(120), default="")
    turn: Mapped[int] = mapped_column(Integer, default=1)
    prompt: Mapped[str] = mapped_column(Text, default="")
    response: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="ok")  # pending|ok|error|refused
    attempt: Mapped[int] = mapped_column(Integer, default=0)  # 0 = first try, n = n-th gateway retry
    error: Mapped[str] = mapped_column(Text, default="")
    latency_ms: Mapped[float | None] = mapped_column(Float)
    wall_ms: Mapped[float | None] = mapped_column(Float)
    usage: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_events: Mapped[list] = mapped_column(JSON, default=list)
    provenance: Mapped[str] = mapped_column(String(24), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ImportBatch(Base):
    """Provenance for every imported file: which tool, which file (sha256), who imported it."""

    __tablename__ = "imports"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    tool: Mapped[str] = mapped_column(String(16))  # garak|pyrit|traps
    filename: Mapped[str] = mapped_column(String(400))
    sha256: Mapped[str] = mapped_column(String(64))
    tool_version: Mapped[str] = mapped_column(String(64), default="")
    imported_by: Mapped[str] = mapped_column(String(200), default="")
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestAttempt(Base):
    __tablename__ = "test_attempts"
    __table_args__ = (UniqueConstraint("run_id", "source", "external_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    import_id: Mapped[int | None] = mapped_column(ForeignKey("imports.id"))  # null for executed tests
    # --- executed tests (provenance local-execution); empty for imported rows ---
    provenance: Mapped[str] = mapped_column(String(24), default="imported")
    engine: Mapped[str] = mapped_column(String(32), default="")
    engine_version: Mapped[str] = mapped_column(String(64), default="")
    strategy: Mapped[str] = mapped_column(String(120), default="")
    objective: Mapped[str] = mapped_column(Text, default="")
    selection_reason: Mapped[str] = mapped_column(Text, default="")
    source_verdict: Mapped[str] = mapped_column(String(32), default="")  # framework's own verdict, verbatim
    source_detail: Mapped[dict] = mapped_column(JSON, default=dict)  # framework record (scores, probe, ids)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # AgentShield scorer signals + reason
    invocation_ids: Mapped[list] = mapped_column(JSON, default=list)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    usage: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16))  # garak|pyrit
    external_id: Mapped[str] = mapped_column(String(100))  # garak attempt uuid / pyrit conversation_id
    category: Mapped[str] = mapped_column(String(16))  # T-01..T-05 or "unmapped"
    test_id: Mapped[str] = mapped_column(String(300))  # garak probe_classname / pyrit attack identifier
    turns: Mapped[list] = mapped_column(JSON, default=list)  # [{"role","text"}] as recorded by the tool
    detector: Mapped[str] = mapped_column(String(200), default="")  # garak detector / pyrit scorer
    score: Mapped[float | None] = mapped_column(Float)
    # imported: the tool's verdict (pass|fail|inconclusive). executed: AgentShield's outcome from evidence
    # (pass|fail|inconclusive|error|skipped); the framework's own verdict stays in source_verdict.
    verdict: Mapped[str] = mapped_column(String(16))
    rationale: Mapped[str] = mapped_column(Text, default="")  # scorer rationale, verbatim from the tool
    trap_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(8), default="")
    recorded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Advisory review by DECISION_MODEL. Kept separate from the tool verdict above, which stays primary.
    model_verdict: Mapped[str | None] = mapped_column(String(16))  # pass|fail|inconclusive
    model_rationale: Mapped[str | None] = mapped_column(Text)
    model_id: Mapped[str | None] = mapped_column(String(200))  # exact DECISION_MODEL value used
    model_judged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TrapHit(Base):
    """Trap/callback hits recorded by the team's own infrastructure, imported as evidence."""

    __tablename__ = "trap_hits"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    import_id: Mapped[int] = mapped_column(ForeignKey("imports.id"))
    token_id: Mapped[str] = mapped_column(String(200))
    external_id: Mapped[str] = mapped_column(String(100), default="")  # attempt uuid / conversation id it belongs to
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(200), default="")
    attempt_id: Mapped[int | None] = mapped_column(ForeignKey("test_attempts.id"))


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    attempt_id: Mapped[int] = mapped_column(ForeignKey("test_attempts.id"))
    category: Mapped[str] = mapped_column(String(16))
    test_id: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(String(300))
    evidence: Mapped[dict] = mapped_column(JSON)  # detector/scorer, score, rationale, trap hits, import sha
    remediation_key: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|closed
    closed_by_run_id: Mapped[str | None] = mapped_column(String(32))
    # A detector hit is a candidate, not a confirmed exploit. confirmed: direct evidence (trap hit, exact
    # canary match by an objective scorer) or an operator decision; dismissed: an operator ruled it out.
    confirmation: Mapped[str] = mapped_column(String(16), default="candidate")  # candidate|confirmed|dismissed
    confirmation_basis: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingReview(Base):
    """An operator's confirm / dismiss decision for one (run, category, test). Findings are regenerated on every
    rebuild, so the decision is kept here and re-applied each time."""

    __tablename__ = "finding_reviews"
    __table_args__ = (UniqueConstraint("run_id", "category", "test_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    category: Mapped[str] = mapped_column(String(16))
    test_id: Mapped[str] = mapped_column(String(300))
    decision: Mapped[str] = mapped_column(String(16))  # confirmed|dismissed
    note: Mapped[str] = mapped_column(Text, default="")
    decided_by: Mapped[str] = mapped_column(String(200), default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    """Append-only, hash-chained. Every connector request/response and every operator action."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(64))
    run_id: Mapped[str | None] = mapped_column(String(32), index=True)
    target_id: Mapped[int | None] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Event(Base):
    """Every event pushed to the console's live stream. Persisted so a reconnecting client can
    resume from Last-Event-ID."""

    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    type: Mapped[str] = mapped_column(String(32))
    run_id: Mapped[str | None] = mapped_column(String(32), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class GraphNode(Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("run_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(String(32), index=True)
    key: Mapped[str] = mapped_column(String(300))  # e.g. "agent", "category:T-01", "test:<id>"
    kind: Mapped[str] = mapped_column(String(16))  # agent|category|test|tool
    label: Mapped[str] = mapped_column(String(300))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (UniqueConstraint("run_id", "src", "dst", "kind"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(String(32), index=True)
    src: Mapped[str] = mapped_column(String(300))
    dst: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(16))  # covers|tested|failed
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
