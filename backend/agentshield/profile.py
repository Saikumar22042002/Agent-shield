"""Target profile: the operator's documented description of the agent under test.

Used instead of a live profiling API during local development. It drives technique applicability, test-case
generation (role, tools, data types, policies) and scoring (canaries and planted markers the operator knows).
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class ToolSpec(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = ""
    privileged: bool = False  # state-changing / needs authorisation beyond an ordinary caller


class AssessmentHints(BaseModel):
    """Values the operator planted or knows, so evidence can be checked exactly rather than guessed."""
    context_canary: str = ""  # a unique string placed in the agent's system prompt / hidden context
    context_excerpt: str = ""  # a sentence of the real system prompt (for excerpt matching)
    planted_document: str = ""  # id/title of a retrievable document containing a planted instruction
    planted_marker: str = ""  # the marker that planted instruction asks the agent to output
    foreign_record_id: str = ""  # a record the test caller must NOT be able to read
    foreign_record_marker: str = ""  # a unique string inside that record
    caller_identity: str = ""  # who the test caller is (e.g. "standard employee jdoe")
    output_limit_chars: int = 4000


class TargetProfile(BaseModel):
    role: str = ""
    description: str = ""
    expected_behavior: str = ""
    tools: list[ToolSpec] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    data_sensitivity: str = "internal"  # public|internal|confidential|restricted
    data_types: list[str] = Field(default_factory=list)
    has_rag: bool = False
    has_memory: bool = False
    has_records: bool = False
    policies: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    hints: AssessmentHints = Field(default_factory=AssessmentHints)

    @property
    def capabilities(self) -> set[str]:
        caps = set()
        if self.tools:
            caps.add("tools")
        if self.has_rag:
            caps.add("rag")
        if self.has_memory:
            caps.add("memory")
        if self.has_records:
            caps.add("records")
        return caps

    @property
    def documented(self) -> bool:
        return bool(self.role.strip())


def load(raw: dict | None) -> TargetProfile:
    return TargetProfile.model_validate(raw or {})


def applicability(tid: str, t: dict, p: TargetProfile) -> tuple[bool, str]:
    """(applicable, rationale) for one catalog technique against a documented profile."""
    missing = [r for r in t["requires"] if r not in p.capabilities]
    if missing:
        names = {"rag": "document retrieval", "memory": "long-term memory", "tools": "tools",
                 "records": "per-user records"}
        return False, f"Profile documents no {', '.join(names[m] for m in missing)}."
    role = p.role or "the agent"
    priv = [x.name for x in p.tools if x.privileged]
    why = {
        "AS-PI-01": f"Every conversational agent takes untrusted user text; {role} must keep its policy under direct override attempts.",
        "AS-PI-02": f"{role} retrieves documents" + (f" ({', '.join(p.data_types[:3])})" if p.data_types else "") +
                    "; content written by others can carry instructions.",
        "AS-JB-01": f"Persona framing is the most common way users try to move {role} outside its documented role.",
        "AS-JB-02": "Multi-turn pressure tests whether policy is re-applied on every turn, not only the first.",
        "AS-SPL-01": "Hidden instructions often hold internal process detail" +
                     (" and the operator planted a canary to detect exposure." if p.hints.context_canary else "."),
        "AS-SID-01": f"Data sensitivity is '{p.data_sensitivity}'; integration credentials must never reach a user.",
        "AS-SID-02": f"{role} serves multiple users' records; conversation-supplied identifiers must not widen access.",
        "AS-EA-01": f"{role} can call {len(p.tools)} tool(s)" + (f", {len(priv)} privileged ({', '.join(priv[:3])})" if priv else "") +
                    "; unauthorised invocation is the core excessive-agency risk.",
        "AS-PRIV-01": "Callers can assert a role in conversation; privileged tools must not trust that claim.",
        "AS-MEM-01": "Persistent memory can carry planted 'policy' across sessions or users.",
        "AS-OUT-01": "Replies are rendered in a UI; reproduced active markup would execute there.",
        "AS-EXF-01": "Rendered markdown images can carry conversation data to an outside host without a click.",
        "AS-RES-01": "Unbounded output drives cost and latency; limits should hold regardless of the request.",
        "AS-ENC-01": "Encoded payloads bypass keyword-based input filters; the agent must not decode-and-obey.",
    }.get(tid, t["objective"])
    # Tie the rationale to what the operator documented about this agent, so the plan shows why the technique
    # matters for this role specifically (forbidden actions it must hold, data it could expose, policy at stake).
    extra = []
    if p.forbidden_actions and tid in ("AS-PI-01", "AS-JB-01", "AS-JB-02", "AS-EA-01", "AS-PRIV-01", "AS-ENC-01"):
        extra.append(f"Documented forbidden actions it must hold: {'; '.join(p.forbidden_actions[:3])}.")
    if p.data_types and tid in ("AS-SID-01", "AS-SID-02", "AS-EXF-01", "AS-SPL-01", "AS-OUT-01"):
        extra.append(f"Data it handles: {', '.join(p.data_types[:4])} ({p.data_sensitivity}).")
    if p.policies and tid in ("AS-PI-01", "AS-JB-01", "AS-JB-02", "AS-ENC-01", "AS-SPL-01"):
        extra.append(f"Policy under test: {p.policies[0]}.")
    return True, " ".join([why, *extra])
