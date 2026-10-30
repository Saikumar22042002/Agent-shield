"""Proof PDF (reportlab platypus).

API used (https://docs.reportlab.com/reportlab/userguide/ch5_platypus/ , ch7_tables/):
  SimpleDocTemplate(filename, pagesize=A4, leftMargin=..., title=...).build(story, onFirstPage=, onLaterPages=)
  Paragraph(xml_text, style)  — text is mini-XML, so all imported content is escaped
  Table(data, colWidths=[...], repeatRows=1).setStyle(TableStyle([(cmd, (c0,r0), (c1,r1), value), ...]))
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select

from .audit import verify_chain
from .config import get_settings
from .db import session_scope
from .ingest.common import load_category_map
from .models import AssessmentPlan, Finding, ImportBatch, Run, Target, TestAttempt
from .connectors.registry import PROVIDERS

INK = colors.HexColor("#14151a")
MUTED = colors.HexColor("#5d6170")
LINE = colors.HexColor("#e3e4ea")
ACCENT = colors.HexColor("#5b54e8")
SEV = {"High": colors.HexColor("#d23c3c"), "Medium": colors.HexColor("#c98a0b"),
       "Low": colors.HexColor("#64748b"), "Unrated": colors.HexColor("#94a3b8")}
GREEN = colors.HexColor("#1f9d55")

LIMITS = [
    "Endpoint testing proves observable behaviour of the agent through its endpoint; it does not prove or disprove "
    "internal permissions, data access paths or model internals.",
    "AgentShield sends a target only (a) a fixed, benign connectivity greeting and (b) the prompts of an "
    "operator-approved, hashed assessment plan, executed by PyRIT or garak through the AgentShield gateway, which "
    "enforces the plan's inputs, budgets, rate limit and stops. Imported results were produced by the operator's "
    "team with their own tools.",
    "Verdicts come from the frameworks' own scorers and detectors and from trap-hit logs. A detector hit is a "
    "candidate finding; only direct evidence (a trap hit, an exact match on an operator-planted canary) or an "
    "operator decision confirms it. Advisory model reviews never change a verdict.",
    "Fixes are recommendations. Without greybox access (agent configuration, IAM policies, application ACLs) they "
    "cannot be verified other than by re-testing.",
    "Only staging targets are accepted. Results do not imply production posture unless production configuration "
    "is identical. Techniques that were not executed or imported are untested, not passing.",
]


def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=ss["Normal"], fontName="Helvetica", fontSize=9, leading=12.5, textColor=INK)
    return {
        "base": base,
        "muted": ParagraphStyle("muted", parent=base, textColor=MUTED, fontSize=8),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=18, leading=22, spaceAfter=4),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=12, leading=16, spaceBefore=12,
                             spaceAfter=6, textColor=INK),
        "warn": ParagraphStyle("warn", parent=base, fontName="Helvetica-Bold", fontSize=9, leading=12.5,
                               textColor=colors.HexColor("#7a4a00"), backColor=colors.HexColor("#fff4dc"), borderPadding=6,
                               spaceBefore=2, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=10, leading=13, spaceAfter=2),
        "mono": ParagraphStyle("mono", parent=base, fontName="Courier", fontSize=7.5, leading=10, alignment=TA_LEFT,
                               backColor=colors.HexColor("#f5f5f8"), borderPadding=4, spaceBefore=4, spaceAfter=8),
    }


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _grid(data, widths, header=True) -> Table:
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    cmds = [("FONT", (0, 0), (-1, -1), "Helvetica", 8.5), ("TEXTCOLOR", (0, 0), (-1, -1), INK),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if header:
        cmds += [("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8), ("TEXTCOLOR", (0, 0), (-1, 0), MUTED)]
    t.setStyle(TableStyle(cmds))
    return t


def _clip(s: str, n: int = 1200) -> str:
    return s if len(s) <= n else s[:n] + f"\n… [{len(s) - n} more characters in AgentShield]"


def build_pdf(run_id: str) -> Path:
    settings = get_settings()
    cmap = load_category_map(str(settings.category_map_file))
    st = _styles()
    with session_scope() as s:
        run = s.get(Run, run_id)
        if run is None:
            raise LookupError(run_id)
        target = s.get(Target, run.target_id)
        summary = run.summary or {}
        findings = sorted(s.execute(select(Finding).where(Finding.run_id == run_id)).scalars().all(),
                          key=lambda f: ({"High": 0, "Medium": 1, "Low": 2}.get(f.severity, 3), f.category))
        attempts = {a.id: a for a in s.execute(select(TestAttempt).where(
            TestAttempt.id.in_([f.attempt_id for f in findings]))).scalars()}
        imports = s.execute(select(ImportBatch).where(ImportBatch.run_id == run_id)).scalars().all()
        executed = s.execute(select(TestAttempt).where(TestAttempt.run_id == run_id,
                                                       TestAttempt.provenance == "local-execution")
                             .order_by(TestAttempt.id)).scalars().all()
        plan = s.execute(select(AssessmentPlan).where(AssessmentPlan.run_id == run_id,
                                                      AssessmentPlan.status.in_(["approved", "invalidated"]))
                         .order_by(AssessmentPlan.version.desc()).limit(1)).scalar()
        children = s.execute(select(Run).where(Run.parent_run_id == run_id)).scalars().all()
        parent = s.get(Run, run.parent_run_id) if run.parent_run_id else None
        chain_ok, bad_id = verify_chain()

        provider = target.provider or "aws_agentcore"
        spec = PROVIDERS.get(provider)
        is_stub = provider == "local_stub"
        story = [
            _p("AgentShield · Proof report", st["muted"]),
            _p(f"{target.name} — {run.label or run.id}", st["h1"]),
            _p(f"Run {run.id} · {spec.label if spec else provider} · {target.environment.capitalize()} · generated "
               f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} · status {run.status}", st["muted"]),
            Spacer(1, 8),
        ]
        if is_stub:
            story += [_p("DEVELOPMENT RUN — LOCAL STUB TARGET. The target in this run is AgentShield's built-in development "
                         "stub, not a real agent, model or cloud service. Its replies are fixed text. Nothing in this report "
                         "describes the security of any real system.", st["warn"]), Spacer(1, 6)]
        meta = [["Platform", spec.label if spec else provider]]
        if provider == "aws_agentcore":
            meta += [["Harness ARN", target.harness_arn], ["Region", target.region]]
        meta += [[k, v] for k, v in (target.config or {}).items()]
        meta += [["Environment", target.environment],
                 ["Last connectivity check", f"{target.status} · " + (
                     f"{target.last_latency_ms or '—'} ms service latency · usage {target.last_usage or {}} (measured)"
                     if not is_stub else "local stub (no service latency or token usage)")],
                ["Run started", f"{run.started_at:%Y-%m-%d %H:%M} UTC"],
                ["Re-test of", parent.id if parent else "—"],
                ["Audit chain", "verified intact" if chain_ok else f"BROKEN at row {bad_id}"]]
        story.append(_grid([[_p(k, st["muted"]), _p(v, st["base"])] for k, v in meta], [42 * mm, 128 * mm], header=False))

        ex = summary.get("executed") or {}
        story.append(_p("Summary", st["h2"]))
        story.append(_p(
            f"{summary.get('findings_open', 0)} open findings ({summary.get('findings_confirmed', 0)} confirmed, "
            f"{summary.get('findings_candidate', 0)} candidate), {summary.get('findings_closed', 0)} closed by re-test, "
            f"{summary.get('findings_dismissed', 0)} dismissed · {ex.get('total', 0)} executed test cases · "
            f"{summary.get('imported_attempts', 0)} imported attempts · {summary.get('trap_hits', 0)} trap hits "
            f"({summary.get('trap_hits_linked', 0)} linked to attempts). Provenance: {summary.get('provenance', 'imported')}.",
            st["base"]))
        if summary.get("sample_data"):
            story.append(_p("Results in this run are sample data (local stub target) and produce no findings.",
                            st["muted"]))

        if executed or plan is not None:
            story.append(_p("Executed assessment", st["h2"]))
            if plan is not None:
                c = plan.content or {}
                story.append(_p(
                    f"Plan v{plan.version} ({plan.status}) · sha256 {plan.sha256[:20]}… · approved by "
                    f"{plan.approved_by or '—'} · engines {', '.join(f'{k} {v}' for k, v in (c.get('engine_versions') or {}).items())}"
                    f" · {c.get('planned_prompts', 0)} planned prompts · catalog {c.get('catalog_version', '')}",
                    st["muted"]))
                coord = (run.assessment or {}).get("coordinator") or {}
                if coord:
                    story.append(_p(f"Coordinator: LangChain Deep Agents, {coord.get('mode')} model "
                                    f"({coord.get('model')}), {coord.get('attacker_tokens', 0)} attacker-side tokens."
                                    + (f" Fallback: {coord.get('fallback')}" if coord.get("fallback") else ""),
                                    st["muted"]))
            rows = [["Case", "Technique", "Engine", "Verdict", "Framework verdict", "Evidence"]]
            for a in executed:
                ev = a.evidence or {}
                rows.append([_p(ev.get("case_id", a.external_id), st["base"]), _p(a.category, st["base"]),
                             _p(f"{a.engine} {a.engine_version}", st["muted"]),
                             _p(a.verdict + (f" ({ev.get('kind')})" if ev.get("kind") else ""), st["base"]),
                             _p(a.source_verdict or "—", st["muted"]),
                             _p((ev.get("sha256", "")[:16] + "…") if ev.get("sha256") else (a.error[:60] or "—"),
                                st["muted"])])
            story.append(_grid(rows, [16 * mm, 24 * mm, 26 * mm, 32 * mm, 36 * mm, 40 * mm]))

        story.append(_p("Findings", st["h2"]))
        if not findings:
            story.append(_p("No failed verdicts in the executed or imported results.", st["base"]))
        for f in findings:
            a = attempts.get(f.attempt_id)
            ev = f.evidence or {}
            first_user = next((t["text"] for t in (a.turns if a else []) if t.get("role") == "user"), "")
            first_reply = next((t["text"] for t in (a.turns if a else []) if t.get("role") == "assistant"), "")
            sev_color = SEV.get(f.severity, MUTED).hexval()[2:]
            status = (f"<font color='#{GREEN.hexval()[2:]}'>CLOSED by {f.closed_by_run_id}</font>"
                      if f.status == "closed" else "OPEN")
            block = [
                Paragraph(f"<font color='#{sev_color}'>■ {f.severity.upper()}</font> &nbsp; "
                          f"{escape(f.category)} · {escape(f.title)} &nbsp; <font size=8>{status} · "
                          f"{escape(f.confirmation.upper())}</font>", st["h3"]),
                _p(f"Confirmation: {f.confirmation_basis}", st["muted"]),
                _p(f"Test id: {f.test_id} · source: {ev.get('source')} · detector/scorer: {ev.get('detector') or '—'} · "
                   f"score: {ev.get('score') if ev.get('score') is not None else '—'} · failed attempts: "
                   f"{ev.get('failed_attempts')}", st["muted"]),
                _p(f"Evidence: {ev.get('rationale', '')}", st["base"]),
            ]
            for h in ev.get("trap_hits") or []:
                block.append(_p(f"Trap hit {h['token_id']} at {h.get('received_at') or '—'} from {h.get('source') or '—'}",
                                st["base"]))
            block += [_p("Recorded test input (from tool output):", st["muted"]), _p(_clip(first_user), st["mono"]),
                      _p("Recorded agent reply:", st["muted"]), _p(_clip(first_reply), st["mono"]),
                      _p(f"Fix: {cmap['remediations'].get(f.remediation_key, 'No remediation mapped — add one to category_map.json.')}",
                         st["base"]),
                      _p(f"Imported from {ev.get('import_file')} (sha256 {ev.get('import_sha256', '')[:16]}…)"
                         if ev.get("import_file") else
                         f"Executed by AgentShield ({ev.get('source')}) · evidence sha256 "
                         f"{(ev.get('evidence_sha256') or '')[:16]}… · invocations {ev.get('invocation_ids', [])[:10]}",
                         st["muted"]),
                      Spacer(1, 8)]
            story.append(KeepTogether(block[:5]))
            story += block[5:]

        if children or parent:
            story.append(_p("Re-test", st["h2"]))
            rows = [["Run", "Relation", "Open findings", "Closed", "Attempts"]]
            for r, rel in ([(parent, "previous")] if parent else []) + [(run, "this run")] + [(c, "re-test") for c in children]:
                sm = r.summary or {}
                rows.append([r.id, rel, sm.get("findings_open", 0), sm.get("findings_closed", 0), sm.get("attempts", 0)])
            story.append(_grid(rows, [40 * mm, 30 * mm, 30 * mm, 25 * mm, 25 * mm]))

        story.append(_p("Imported evidence files", st["h2"]))
        rows = [["Tool", "File", "sha256", "Version", "By", "Stats"]]
        for i in imports:
            rows.append([i.tool, _p(i.filename, st["base"]), _p(i.sha256[:20] + "…", st["muted"]), i.tool_version or "—",
                         _p(i.imported_by or "—", st["base"]), _p(", ".join(f"{k}={v}" for k, v in (i.stats or {}).items()), st["muted"])])
        story.append(_grid(rows, [14 * mm, 40 * mm, 34 * mm, 16 * mm, 24 * mm, 42 * mm]))

        story.append(_p("Honest limits", st["h2"]))
        for line in LIMITS:
            story.append(_p(f"• {line}", st["base"]))

    out_dir = settings.reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"agentshield-{run_id}.pdf"

    def _frame(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(ACCENT)
        canvas.rect(0, A4[1] - 4, A4[0], 4, stroke=0, fill=1)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"AgentShield · {run_id} · staging · confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"AgentShield proof report {run_id}", author="AgentShield")
    doc.build(story, onFirstPage=_frame, onLaterPages=_frame)
    return path
