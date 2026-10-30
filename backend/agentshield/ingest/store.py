"""Persist parsed results and (re)derive findings, coverage, re-test closure and the posture graph.

`rebuild(run_id)` is idempotent: findings/graph/summary are pure functions of the stored rows plus the operator's
finding reviews.

Finding integrity:
  - A run against the local development stub never produces findings, whatever is imported or executed: its replies
    are fixed text. Imports into such a run are kept, flagged as sample data, and excluded.
  - A failed verdict creates a *candidate* finding. It becomes *confirmed* only with direct evidence (an imported trap
    hit, or an objective scorer's exact match on a value the operator planted) or an operator decision; an operator
    can also *dismiss* it. Dismissed findings are not open findings.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from sqlalchemy import delete, select

from ..audit import record as audit
from ..config import get_settings
from ..db import session_scope
from ..events import publish
from ..models import Finding, FindingReview, GraphEdge, GraphNode, ImportBatch, Run, Target, TestAttempt, TrapHit
from ..redact import redact, redact_text
from ..safety import RunNotActive
from . import garak, pyrit, traps
from .common import UNMAPPED, IngestError, ParseResult, categorize, load_category_map

SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Unrated": 3}


def _taxonomy(cmap: dict) -> dict:
    """Import categories plus catalog techniques (executed attempts are categorised by technique id). Imported
    lazily: catalog imports ingest.common, so a module-level import would be circular."""
    from ..catalog import taxonomy

    return taxonomy() | {"categories": taxonomy()["categories"] | cmap["categories"]}


def counts_as_security_evidence(a: TestAttempt, target_provider: str = "") -> bool:
    """Imported tool results count, unless the run's target is the local stub (sample data). Executed ones count
    only when they are real security tests: plumbing checks and anything run against the local stub are labelled in
    `evidence.kind` and never create or close a finding. Skipped and errored cases are never evidence."""
    if target_provider == "local_stub":
        return False
    if a.verdict in ("skipped", "error"):
        return False
    return a.provenance != "local-execution" or (a.evidence or {}).get("kind") == "security"


def _provider(s, run_id: str) -> str:
    run = s.get(Run, run_id)
    t = s.get(Target, run.target_id) if run else None
    return (t.provider if t else "") or "aws_agentcore"


def parse_file(tool: str, data: bytes) -> ParseResult:
    th = get_settings().garak_fail_threshold
    text_lines = lambda: data.decode("utf-8-sig", errors="replace").splitlines()  # noqa: E731
    if tool == "garak":
        return garak.parse(text_lines(), fail_threshold=th)
    if tool == "pyrit":
        return pyrit.parse(data, fail_threshold=th)
    if tool == "traps":
        return traps.parse(text_lines())
    raise IngestError(f"unknown tool '{tool}' (expected garak, pyrit or traps)")


def import_file(run_id: str, tool: str, filename: str, data: bytes, *, operator: str) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    parsed = parse_file(tool, data)
    cmap = load_category_map(str(get_settings().category_map_file))
    with session_scope() as s:
        run = s.get(Run, run_id)
        if run is None:
            raise LookupError(f"run {run_id} not found")
        if run.status != "open":
            raise RunNotActive(f"Run {run_id} is {run.status}; imports are only accepted into open runs.")
        sample = _provider(s, run_id) == "local_stub"
        if sample:
            parsed.warnings.insert(0, "This run's target is the local development stub: imported results are kept "
                                      "as sample data and never create findings.")
        batch = ImportBatch(run_id=run_id, tool=tool, filename=filename, sha256=sha, tool_version=parsed.tool_version,
                            imported_by=operator, warnings=parsed.warnings[:200])
        s.add(batch)
        s.flush()
        existing = set(s.execute(select(TestAttempt.source, TestAttempt.external_id)
                                 .where(TestAttempt.run_id == run_id)).all())
        added = dup = 0
        for a in parsed.attempts:
            if (tool, a.external_id) in existing:
                dup += 1
                continue
            cat = categorize(a.test_id, a.category_hint, cmap)
            sev = cmap["categories"].get(cat, {}).get("severity", "Unrated")
            turns, _ = redact(a.turns)  # stored evidence never keeps credential-shaped values
            rationale, _ = redact_text(a.rationale)
            s.add(TestAttempt(run_id=run_id, import_id=batch.id, source=tool, external_id=a.external_id,
                              category=cat, test_id=a.test_id, turns=turns, detector=a.detector, score=a.score,
                              verdict=a.verdict, rationale=rationale, severity=sev, recorded_at=a.recorded_at,
                              evidence={"kind": "sample"} if sample else {}))
            existing.add((tool, a.external_id))
            added += 1
        for h in parsed.trap_hits:
            s.add(TrapHit(run_id=run_id, import_id=batch.id, token_id=h.token_id, external_id=h.external_id,
                          received_at=h.received_at, source=h.source))
        batch.stats = {"attempts_added": added, "attempts_duplicate": dup, "trap_hits": len(parsed.trap_hits),
                       "warnings": len(parsed.warnings)} | ({"sample_data": 1} if sample else {})
        stats, batch_id = dict(batch.stats), batch.id
    audit("import", {"tool": tool, "filename": filename, "sha256": sha, "stats": stats}, actor=operator, run_id=run_id)
    publish("import.done", {"import_id": batch_id, "tool": tool, "filename": filename, "sha256": sha, **stats},
            run_id=run_id)
    summary = rebuild(run_id)
    return {"import_id": batch_id, "sha256": sha, "stats": stats, "warnings": parsed.warnings[:50], "summary": summary}


def _link_traps(s, run_id: str) -> None:
    attempts = {(a.external_id): a for a in s.execute(select(TestAttempt).where(TestAttempt.run_id == run_id)).scalars()}
    for hit in s.execute(select(TrapHit).where(TrapHit.run_id == run_id)).scalars():
        a = attempts.get(hit.external_id)
        if a is None:
            continue
        hit.attempt_id = a.id
        if not a.trap_hit:
            a.trap_hit = True
            note = f"trap hit {hit.token_id} recorded {hit.received_at.isoformat() if hit.received_at else ''}".strip()
            a.rationale = f"{a.rationale}; {note}" if a.rationale else note
            a.verdict = "fail"  # an observed trap hit is direct evidence


def _confirmation(atts: list[TestAttempt], review: FindingReview | None) -> tuple[str, str]:
    if review is not None:
        verb = "Confirmed" if review.decision == "confirmed" else "Dismissed"
        return review.decision, f"{verb} by {review.decided_by}" + (f": {review.note}" if review.note else "")
    trap = next((a for a in atts if a.trap_hit), None)
    if trap is not None:
        return "confirmed", f"Trap hit recorded for attempt {trap.external_id} (direct evidence)."
    exact = next((a for a in atts if (a.evidence or {}).get("confirmation")), None)
    if exact is not None:
        return "confirmed", exact.evidence["confirmation"]
    return "candidate", "Detector or scorer hit only; needs operator confirmation (or a trap hit) to be confirmed."


def _rebuild_findings(s, run_id: str, cmap: dict) -> None:
    s.execute(delete(Finding).where(Finding.run_id == run_id))
    provider = _provider(s, run_id)
    groups: dict[tuple[str, str], list[TestAttempt]] = defaultdict(list)
    for a in s.execute(select(TestAttempt).where(TestAttempt.run_id == run_id, TestAttempt.verdict == "fail")).scalars():
        if counts_as_security_evidence(a, provider):
            groups[(a.category, a.test_id)].append(a)
    reviews = {(r.category, r.test_id): r for r in s.execute(
        select(FindingReview).where(FindingReview.run_id == run_id)).scalars()}
    for (cat, test_id), atts in groups.items():
        primary = sorted(atts, key=lambda a: (not a.trap_hit, -(a.score or 0)))[0]
        spec = cmap["categories"].get(cat, {})
        hits = s.execute(select(TrapHit).where(TrapHit.run_id == run_id,
                                               TrapHit.attempt_id.in_([a.id for a in atts]))).scalars().all()
        imp = s.get(ImportBatch, primary.import_id) if primary.import_id else None
        confirmation, basis = _confirmation(atts, reviews.get((cat, test_id)))
        s.add(Finding(
            run_id=run_id, attempt_id=primary.id, category=cat, test_id=test_id,
            confirmation=confirmation, confirmation_basis=basis,
            severity=spec.get("severity", "Unrated"),
            title=f"{spec.get('title', 'Unmapped result')} — {test_id}",
            remediation_key=spec.get("remediation_key", ""),
            evidence={"failed_attempts": len(atts), "attempt_ids": [a.id for a in atts][:100],
                      "detector": primary.detector, "score": primary.score, "rationale": primary.rationale,
                      "trap_hits": [{"token_id": h.token_id, "received_at": h.received_at.isoformat() if h.received_at else None,
                                     "source": h.source} for h in hits],
                      "source": primary.source, "provenance": primary.provenance,
                      "engine_version": primary.engine_version, "invocation_ids": (primary.invocation_ids or [])[:50],
                      "evidence_file": (primary.evidence or {}).get("file", ""),
                      "evidence_sha256": (primary.evidence or {}).get("sha256", ""),
                      "import_sha256": imp.sha256 if imp else "",
                      "import_file": imp.filename if imp else ""}))


def _apply_closure(s, run_id: str) -> None:
    """Close this run's findings when a later re-test (child run) covers the same test with no failures."""
    children = s.execute(select(Run).where(Run.parent_run_id == run_id).order_by(Run.started_at)).scalars().all()
    for f in s.execute(select(Finding).where(Finding.run_id == run_id)).scalars():
        f.status, f.closed_by_run_id = "open", None
        for child in children:
            child_provider = _provider(s, child.id)
            verdicts = [a.verdict for a in s.execute(select(TestAttempt).where(
                TestAttempt.run_id == child.id, TestAttempt.category == f.category,
                TestAttempt.test_id == f.test_id)).scalars() if counts_as_security_evidence(a, child_provider)]
            if verdicts and "fail" not in verdicts and "pass" in verdicts:
                f.status, f.closed_by_run_id = "closed", child.id
            elif "fail" in verdicts:
                f.status, f.closed_by_run_id = "open", None


def _rebuild_graph(s, run: Run, target: Target, cmap: dict) -> None:
    s.execute(delete(GraphEdge).where(GraphEdge.run_id == run.id))
    s.execute(delete(GraphNode).where(GraphNode.run_id == run.id))
    s.add(GraphNode(run_id=run.id, key="agent", kind="agent", label=target.name,
                    meta={"harness_arn": target.harness_arn, "environment": target.environment}))
    per_test: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"pass": 0, "fail": 0, "inconclusive": 0})
    for cat, test_id, verdict in s.execute(select(TestAttempt.category, TestAttempt.test_id, TestAttempt.verdict)
                                           .where(TestAttempt.run_id == run.id)).all():
        per_test[(cat, test_id)][verdict] = per_test[(cat, test_id)].get(verdict, 0) + 1
    cats = sorted({c for c, _ in per_test} | set(cmap.get("categories_shown", cmap["categories"])))
    for cat in cats:
        spec = cmap["categories"].get(cat, {})
        s.add(GraphNode(run_id=run.id, key=f"category:{cat}", kind="category",
                        label=f"{cat} {spec.get('title', 'Unmapped')}", meta={"severity": spec.get("severity", "Unrated")}))
        s.add(GraphEdge(run_id=run.id, src="agent", dst=f"category:{cat}", kind="covers",
                        meta={"tested": any(c == cat for c, _ in per_test)}))
    for (cat, test_id), counts in per_test.items():
        key = f"test:{cat}:{test_id}"
        s.add(GraphNode(run_id=run.id, key=key, kind="test", label=test_id, meta=counts))
        s.add(GraphEdge(run_id=run.id, src=f"category:{cat}", dst=key, kind="tested", meta={}))
        if counts.get("fail"):
            s.add(GraphEdge(run_id=run.id, src=key, dst="agent", kind="failed", meta={"count": counts["fail"]}))


def compute_summary(s, run_id: str, cmap: dict) -> dict:
    cov: dict[str, dict] = {cid: {"title": spec["title"], "severity": spec["severity"], "total": 0, "fail": 0, "pass": 0,
                                  "inconclusive": 0} for cid, spec in cmap["categories"].items()}
    tx = _taxonomy(cmap)["categories"]
    executed: dict[str, dict] = {"total": 0, "by_kind": {}, "by_verdict": {}}
    for a in s.execute(select(TestAttempt).where(TestAttempt.run_id == run_id, TestAttempt.provenance == "local-execution")).scalars():
        kind = (a.evidence or {}).get("kind", "security")
        executed["total"] += 1
        executed["by_kind"][kind] = executed["by_kind"].get(kind, 0) + 1
        executed["by_verdict"][a.verdict] = executed["by_verdict"].get(a.verdict, 0) + 1
    for cat, verdict in s.execute(select(TestAttempt.category, TestAttempt.verdict).where(TestAttempt.run_id == run_id)).all():
        spec = tx.get(cat, {})
        c = cov.setdefault(cat, {"title": spec.get("title", "Unmapped"), "severity": spec.get("severity", "Unrated"),
                                 "total": 0, "fail": 0, "pass": 0, "inconclusive": 0})
        c["total"] += 1
        c[verdict] = c.get(verdict, 0) + 1
    findings = s.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all()
    traps_total = s.execute(select(TrapHit.id).where(TrapHit.run_id == run_id)).scalars().all()
    traps_linked = [t for t in s.execute(select(TrapHit.attempt_id).where(TrapHit.run_id == run_id)).scalars() if t]
    mapped = [k for k in cmap["categories"] if cov[k]["total"] > 0]
    return {
        "coverage": cov,
        "categories_covered": len(mapped),
        "categories_total": len(cmap["categories"]),
        "attempts": sum(c["total"] for c in cov.values()),
        "findings_open": sum(1 for f in findings if f.status == "open" and f.confirmation != "dismissed"),
        "findings_closed": sum(1 for f in findings if f.status == "closed"),
        "findings_confirmed": sum(1 for f in findings if f.confirmation == "confirmed" and f.status == "open"),
        "findings_candidate": sum(1 for f in findings if f.confirmation == "candidate" and f.status == "open"),
        "findings_dismissed": sum(1 for f in findings if f.confirmation == "dismissed"),
        "sample_data": _provider(s, run_id) == "local_stub",
        "findings_by_severity": {sev: sum(1 for f in findings if f.severity == sev and f.confirmation != "dismissed")
                                 for sev in SEV_ORDER},
        "trap_hits": len(traps_total),
        "trap_hits_linked": len(traps_linked),
        "unmapped_attempts": cov.get(UNMAPPED, {}).get("total", 0),
        "executed": executed,
        "imported_attempts": sum(c["total"] for c in cov.values()) - executed["total"],
        "provenance": ("executed" if executed["total"] and executed["total"] == sum(c["total"] for c in cov.values())
                       else "mixed" if executed["total"] else "imported"),
    }


def rebuild(run_id: str) -> dict:
    cmap = load_category_map(str(get_settings().category_map_file))
    with session_scope() as s:
        run = s.get(Run, run_id)
        target = s.get(Target, run.target_id)
        _link_traps(s, run_id)
        s.flush()
        _rebuild_findings(s, run_id, _taxonomy(cmap))
        s.flush()
        _apply_closure(s, run_id)
        _rebuild_graph(s, run, target, _taxonomy(cmap) | {"categories_shown": cmap["categories"]})
        s.flush()
        run.summary = compute_summary(s, run_id, cmap)
        summary, parent = dict(run.summary), run.parent_run_id
    publish("run.summary", summary, run_id=run_id)
    if parent:
        rebuild(parent)  # a re-test may close the parent's findings
    return summary
