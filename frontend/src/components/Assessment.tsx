import { Fragment, useEffect, useMemo, useState } from "react";
import { api, type AuditRow, type Invocation, type Plan, type PlanIn, type PlanOptions, type Run, type Target } from "../api";
import { useAction } from "../hooks";
import { useStore } from "../store";
import { AssessmentBadge, Empty, fmtDate, fmtMs, fmtTime, Icon, Meter, Verdict } from "./ui";

const LIMIT_FIELDS: [string, string, string][] = [
  ["max_prompts_per_technique", "Prompts per technique", "Technique budget"],
  ["max_prompts_per_run", "Prompts per run", "Run budget"],
  ["technique_concurrency", "Parallel cases", "Isolated conversations at once"],
  ["attacker_token_budget", "Coordinator tokens", "Attacker-side token cap"],
];

/* ---------------------------------------------------------------- execution status + controls */
function ExecutionHeader({ run }: { run: Run }) {
  const { assessment, kill, refreshAssessment, refreshRun } = useStore();
  const { busy, run: act } = useAction();
  const st = assessment?.status ?? run.assessment_status;
  const after = async () => { await Promise.all([refreshAssessment(), refreshRun()]); };
  const open = run.status === "open";
  const coord = assessment?.assessment.coordinator;
  const stale = assessment?.plan?.stale;
  const missing = (assessment?.plan?.engines ?? []).filter((e) => !(assessment?.adapters ?? []).includes(e));
  const why = kill.tripped ? "Emergency stop is active." : !open ? `Run is ${run.status}.` : stale ? `Plan is stale: ${stale}.`
    : missing.length ? `No adapter for ${missing.join(", ")}.` : "";
  return (
    <div className="assess-head">
      <div className="assess-title">
        <AssessmentBadge status={st} />
        {assessment?.plan && <span className="muted sm">Plan v{assessment.plan.version} · <span className="mono">{assessment.plan.sha256.slice(0, 12)}</span>
          · {assessment.plan.engines.join(" + ")} · {assessment.plan.planned_prompts} planned prompts</span>}
        <div className="spacer" />
        {st === "approved" && <button className="btn primary" disabled={busy || !!why}
          title={why || "Execute the approved plan through the gateway"}
          onClick={() => act(() => api.startAssessment(run.id), "Execution started.").then(after)}><Icon name="play" size={14} />Start execution</button>}
        {["stopped", "interrupted", "error"].includes(st) && <button className="btn" disabled={busy || !!why}
          title={why || "Run the cases that have no result yet"}
          onClick={() => act(() => api.resumeAssessment(run.id), "Execution resumed.").then(after)}><Icon name="refresh" size={14} />Resume</button>}
        {["queued", "running"].includes(st) && <button className="btn danger" disabled={busy}
          onClick={() => act(() => api.stopAssessment(run.id, "Stopped from the assessment panel"), "Execution stopped.").then(after)}>
          <Icon name="stop" size={14} />Stop execution</button>}
      </div>
      {assessment?.reason && <p className={`assess-reason ${st === "completed" ? "" : "warn"}`}>{assessment.reason}</p>}
      {why && st === "approved" && <p className="warn-text sm">{why}</p>}
      {coord && <p className="muted sm coord-line"><Icon name="cpu" size={13} />Coordinator: LangChain Deep Agents · {coord.mode} ({coord.model})
        · {coord.steps} decision{coord.steps === 1 ? "" : "s"} · {coord.attacker_tokens} attacker tokens{coord.fallback ? ` · fell back: ${coord.fallback}` : ""}
        {coord.summary && <span className="coord-summary">“{coord.summary}”</span>}</p>}
    </div>
  );
}

function Progress({ run }: { run: Run }) {
  const { assessment } = useStore();
  if (!assessment?.plan) return null;
  const p = assessment.assessment.progress;
  const lim = run.status ? assessment.limits : {};
  const sent = assessment.usage.invocations.ok + assessment.usage.invocations.error;
  const budget = Number(lim.max_prompts_per_run ?? p?.prompt_budget ?? 0);
  const attackerBudget = Number(lim.attacker_token_budget ?? 0);
  const done = p?.cases_done ?? assessment.cases.filter((c) => c.state === "done" || c.state === "skipped").length;
  const total = p?.cases_total ?? assessment.cases.length;
  return (
    <div className="assess-meters">
      <Meter label="Cases" value={done} max={total} budget={false} note={`${p?.skipped ?? 0} skipped · ${p?.errors ?? 0} errors`} />
      <Meter label="Prompts sent" value={sent} max={budget} note={`${assessment.usage.invocations.refused} refused by the gateway`} />
      <Meter label="Target tokens" value={assessment.usage.target_tokens} max={Number(lim.target_token_budget ?? 0)}
             note={Number(lim.target_token_budget) ? "of the approved cap" : "reported by the target · no cap"} />
      <Meter label="Coordinator tokens" value={assessment.assessment.attacker_tokens ?? 0} max={attackerBudget}
             note={attackerBudget ? "attacker-side budget" : "no cap"} />
    </div>
  );
}

/* ---------------------------------------------------------------- cases + evidence */
function CaseEvidence({ runId, caseId, invocations }: { runId: string; caseId: string; invocations: Invocation[] }) {
  const mine = invocations.filter((i) => i.test_key === caseId || i.test_key.startsWith(`${caseId}#`));
  if (!mine.length) return <p className="muted sm">No gateway traffic for this case yet.</p>;
  return (
    <div className="inv-list" aria-label={`Gateway invocations of ${caseId} in ${runId}`}>
      {mine.map((i) => (
        <div key={i.id} className={`inv inv-${i.status}`}>
          <div className="inv-h"><span className="mono">#{i.id}</span><span className={`inv-status ${i.status}`}>{i.status}</span>
            <span className="muted">turn {i.turn}{i.attempt ? ` · retry ${i.attempt}` : ""} · {fmtMs(i.wall_ms)}</span>
            {i.usage?.totalTokens != null && <span className="muted">{i.usage.totalTokens} tokens</span>}
            <span className="mono muted ellipsis" title={i.session_id}>{i.session_id}</span></div>
          <div className="inv-q"><span>Prompt</span>{i.prompt || <em className="muted">(empty)</em>}</div>
          {i.response && <div className="inv-a"><span>Reply</span>{i.response.slice(0, 1200)}</div>}
          {i.error && <div className="inv-e"><span>{i.status === "refused" ? "Refused" : "Error"}</span>{i.error}</div>}
        </div>))}
    </div>
  );
}

function Cases({ run }: { run: Run }) {
  const { assessment } = useStore();
  const [open, setOpen] = useState<string | null>(null);
  const [invocations, setInvocations] = useState<Invocation[]>([]);
  const progressKey = `${assessment?.usage.invocations.ok}:${assessment?.usage.invocations.refused}:${assessment?.status}`;
  useEffect(() => {
    if (!open) return;
    let live = true;
    api.invocations(run.id).then((x) => { if (live) setInvocations(x); }).catch(() => undefined);
    return () => { live = false; };
  }, [open, run.id, progressKey]);
  if (!assessment?.cases.length) return null;
  return (
    <div className="case-table" role="table" aria-label="Approved cases">
      <div className="case-row head" role="row"><span>Case</span><span>Technique</span><span>Engine</span><span>State</span><span>Result</span></div>
      {assessment.cases.map((c) => (
        <Fragment key={c.id}>
          <button className={`case-row ${open === c.id ? "on" : ""}`} role="row" onClick={() => setOpen(open === c.id ? null : c.id)}
                  aria-expanded={open === c.id}>
            <span className="mono">{c.id}</span>
            <span className="ellipsis" title={c.label}>{c.label}</span>
            <span className="muted">{c.engine}</span>
            <span><span className={`state state-${c.state}`}>{c.state === "running" && <span className="spin" />}{c.state}</span></span>
            <span className="case-result">{c.result ? <><Verdict v={c.result.verdict} /><span className="muted ellipsis"
              title={c.result.error || c.result.rationale}>{c.result.error || c.result.rationale || c.result.source_verdict}</span></> : <span className="muted">—</span>}</span>
          </button>
          {open === c.id && <div className="case-detail"><CaseEvidence runId={run.id} caseId={c.id} invocations={invocations} /></div>}
        </Fragment>))}
    </div>
  );
}

/* ---------------------------------------------------------------- plan builder */
function PlanBuilder({ run, onCreated }: { run: Run; onCreated: () => void }) {
  const [opts, setOpts] = useState<PlanOptions | null>(null);
  const [error, setError] = useState("");
  const [picked, setPicked] = useState<Record<string, string[]>>({});
  const [benign, setBenign] = useState("Hello. Please reply with one short sentence describing what you can help with.");
  const [turns, setTurns] = useState("Hi.\nWhat can you help me with?\nThanks, that is all.");
  const [limits, setLimits] = useState<Record<string, string>>({});
  const [note, setNote] = useState("");
  const { busy, run: act } = useAction();
  useEffect(() => {
    let live = true;
    api.planOptions(run.id).then((o) => { if (live) setOpts(o); }).catch((e) => setError((e as Error).message));
    return () => { live = false; };
  }, [run.id]);
  if (error) return <p className="note-err">{error}</p>;
  if (!opts) return <div className="skeleton s1" />;
  const toggle = (id: string, key: string) => setPicked((p) => {
    const cur = p[id] ?? [];
    const next = cur.includes(key) ? cur.filter((k) => k !== key) : [...cur, key];
    const out = { ...p, [id]: next };
    if (!next.length) delete out[id];
    return out;
  });
  const chosen = Object.keys(picked);
  const needsPrompt = chosen.some((id) => opts.techniques.find((t) => t.id === id)?.input === "operator_benign_prompt");
  const needsTurns = chosen.some((id) => opts.techniques.find((t) => t.id === id)?.input === "operator_benign_turns");
  const submit = async () => {
    const body: PlanIn = { techniques: chosen, executions: picked, note,
      limits: Object.fromEntries(Object.entries(limits).filter(([, v]) => v.trim() !== "").map(([k, v]) => [k, Number(v)])) };
    if (needsPrompt) body.benign_prompt = benign;
    if (needsTurns) body.benign_turns = turns.split("\n").map((x) => x.trim()).filter(Boolean);
    const p = await act(() => api.createPlan(run.id, body), (x) => `Plan v${x.version} drafted: ${x.content.cases.length} case(s).`);
    if (p) { setPicked({}); onCreated(); }
  };
  const groups: [string, typeof opts.techniques][] = [
    ["Plumbing checks (benign, never findings)", opts.techniques.filter((t) => t.kind === "plumbing")],
    ["Security techniques", opts.techniques.filter((t) => t.kind === "security")]];
  return (
    <div className="plan-builder">
      {!opts.assessable && <div className="callout warn"><b>{opts.provider} is not in ASSESSMENT_PROVIDERS.</b>
        This target can be checked for connectivity, but plans cannot be executed against it on this deployment.</div>}
      {opts.target_kind === "local-stub" && <div className="callout stub"><Icon name="cpu" size={15} />Local stub target: security cases exercise the pipeline only and are labelled simulated.</div>}
      {!opts.profile_documented && <p className="hint">The target has no documented profile yet. Document it on the Targets page so technique selection and rationale are specific to this agent.</p>}
      {groups.map(([title, rows]) => (
        <div key={title} className="tech-group">
          <h5>{title}</h5>
          {rows.map((t) => {
            const disabled = !t.executable || !t.applies;
            return (
              <div key={t.id} className={`tech ${disabled ? "off" : ""} ${picked[t.id] ? "on" : ""}`}>
                <div className="tech-h">
                  <b className="mono">{t.id}</b><span>{t.title}</span>
                  {t.risks.map((r) => <span key={r} className="tag">{r}</span>)}
                  {t.kind === "security" && <span className={`sev sev-${t.severity}`}>{t.severity}</span>}
                </div>
                <p className="tech-why">{!t.applies ? <span className="warn-text">Does not apply: {t.rationale}</span>
                  : !t.executable ? <span className="muted">{t.not_executable_reason || "No installed engine can execute it."}</span> : t.rationale}</p>
                {!disabled && <div className="tech-ex">
                  {t.executions.map((e) => (
                    <label key={e.key} className="check sm" title={e.note}>
                      <input type="checkbox" disabled={!e.available} checked={(picked[t.id] ?? []).includes(e.key)} onChange={() => toggle(t.id, e.key)} />
                      <span className="mono">{e.key}</span>{!e.available && <span className="muted"> (engine unavailable)</span>}
                    </label>))}
                </div>}
                {!disabled && <p className="tech-exp"><span>Expected secure behaviour</span>{t.expected_secure_behavior}</p>}
              </div>);
          })}
        </div>))}
      {needsPrompt && <div className="field"><label htmlFor="pb-prompt">Benign prompt for PyRIT plumbing</label>
        <input id="pb-prompt" value={benign} onChange={(e) => setBenign(e.target.value)} maxLength={2000} /></div>}
      {needsTurns && <div className="field"><label htmlFor="pb-turns">Benign turns for multi-turn plumbing <i>one per line, 2–5</i></label>
        <textarea id="pb-turns" value={turns} onChange={(e) => setTurns(e.target.value)} /></div>}
      <div className="limits-grid">
        {LIMIT_FIELDS.map(([k, label, hint]) => (
          <div key={k} className="field"><label htmlFor={`lim-${k}`}>{label} <i>≤ {opts.limits[k]}</i></label>
            <input id={`lim-${k}`} type="number" min={0} placeholder={String(opts.limits[k])} value={limits[k] ?? ""}
                   onChange={(e) => setLimits({ ...limits, [k]: e.target.value })} aria-describedby={`lim-${k}-h`} />
            <span className="hint" id={`lim-${k}-h`}>{hint}. Plans can only tighten configured limits.</span></div>))}
      </div>
      <div className="field"><label htmlFor="pb-note">Note <i>optional, recorded in the plan</i></label>
        <input id="pb-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} /></div>
      <div className="form-actions">
        <span className="muted sm">{chosen.length} technique(s) selected</span>
        <button className="btn primary" disabled={busy || !chosen.length || !opts.assessable || run.status !== "open"} onClick={submit}>
          {busy ? <><span className="spin" />Drafting…</> : <><Icon name="file" size={14} />Draft plan</>}</button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- plans */
function PlanCard({ plan, run, onApproved }: { plan: Plan; run: Run; onApproved: () => void }) {
  const [open, setOpen] = useState(plan.status === "draft");
  const { busy, run: act } = useAction();
  const c = plan.content;
  const tone = { draft: "neutral", approved: "ok", superseded: "neutral", invalidated: "warn" }[plan.status];
  return (
    <div className={`plan-card plan-${plan.status}`}>
      <button className="plan-h" onClick={() => setOpen(!open)} aria-expanded={open}>
        <b>Plan v{plan.version}</b><span className={`badge ${tone}`}><span className="dot" />{plan.status}</span>
        <span className="muted sm">{c.cases.length} case(s) · {c.planned_prompts} prompt(s) · {c.engines.join(" + ")} · by {plan.created_by}</span>
        <span className="mono muted sm">{plan.sha256.slice(0, 12)}</span>
        {!plan.integrity_ok && <span className="badge err"><span className="dot" />integrity broken</span>}
        <div className="spacer" /><Icon name="down" size={14} className={open ? "rot" : ""} />
      </button>
      {open && <div className="plan-b">
        {plan.approved_by && <p className="muted sm">Approved by {plan.approved_by} · {fmtDate(plan.approved_at)}</p>}
        {c.notes.length > 0 && <ul className="plan-notes">{c.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}
        {c.techniques.map((t) => (
          <div key={t.id} className="plan-tech">
            <div className="row gap-2 wrap"><b className="mono">{t.id}</b><span>{t.title}</span><span className="muted sm">{t.planned_prompts}/{t.budget} prompts</span></div>
            <dl className="kv wide">
              <dt>Why for this agent</dt><dd>{t.rationale}</dd>
              {t.objective && <><dt>Objective</dt><dd>{t.objective}</dd></>}
              {t.expected_secure_behavior && <><dt>Secure behaviour</dt><dd>{t.expected_secure_behavior}</dd></>}
            </dl>
            {c.cases.filter((x) => x.technique_id === t.id).map((x) => (
              <div key={x.id} className="plan-case"><span className="mono">{x.id}</span><span>{x.label}</span>
                <span className="muted sm">{x.planned_prompts} prompt(s) · {x.source}</span>
                {x.scoring && <p className="hint">Scoring: {x.scoring}</p>}</div>))}
          </div>))}
        <dl className="kv wide">{Object.entries(c.limits).map(([k, v]) => <Fragment key={k}><dt className="mono">{k}</dt><dd>{v}</dd></Fragment>)}</dl>
        {plan.status === "draft" && <div className="form-actions"><span className="muted sm">Approval fixes this plan's sha256; any change needs a new plan.</span>
          <button className="btn primary" disabled={busy || run.status !== "open" || !plan.integrity_ok}
                  onClick={() => act(() => api.approvePlan(run.id, plan.version), `Plan v${plan.version} approved.`).then((r) => { if (r) onApproved(); })}>
            <Icon name="check" size={14} />Approve plan</button></div>}
      </div>}
    </div>
  );
}

export function AssessmentPanel({ run }: { run: Run; target?: Target }) {
  const { plans, assessment, refreshAssessment, refreshRun } = useStore();
  const [building, setBuilding] = useState(false);
  const refresh = async () => { await Promise.all([refreshAssessment(), refreshRun()]); };
  const executing = ["queued", "running"].includes(assessment?.status ?? "");
  return (
    <div className="assess" aria-label="Assessment">
      <ExecutionHeader run={run} />
      <Progress run={run} />
      <Cases run={run} />
      <div className="assess-sec">
        <div className="row gap-2"><h4>Plans</h4><div className="spacer" />
          <button className="btn sm" disabled={run.status !== "open" || executing} onClick={() => setBuilding(!building)}>
            <Icon name={building ? "x" : "plus"} size={13} />{building ? "Close builder" : "New plan"}</button></div>
        {building && <PlanBuilder run={run} onCreated={() => { setBuilding(false); void refresh(); }} />}
        {plans.length === 0 && !building ? <Empty icon="file" title="No plan yet">
          Draft a plan from the technique catalog and this target's profile, approve it, then start execution. Every prompt goes through the gateway.</Empty>
          : plans.map((p) => <PlanCard key={p.id} plan={p} run={run} onApproved={() => void refresh()} />)}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- run-scoped audit tab */
export function RunAudit({ run }: { run: Run }) {
  const events = useStore((s) => s.events);
  const auditOk = useStore((s) => s.auditOk);
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const lastMine = useMemo(() => events.filter((e) => e.run_id === run.id).slice(-1)[0]?.id ?? 0, [events, run.id]);
  useEffect(() => {
    let live = true;
    const t = window.setTimeout(() => {
      api.runAudit(run.id).then((r) => { if (live) setRows(r); }).catch(() => { if (live) setRows([]); });
    }, rows ? 400 : 0);
    return () => { live = false; window.clearTimeout(t); };
  }, [run.id, lastMine]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!rows) return <div className="skeleton-list">{[0, 1, 2].map((i) => <div key={i} className={`skeleton s${i}`} />)}</div>;
  const shown = rows.filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="run-audit">
      <div className="row gap-2 wrap">
        <span className={`badge ${auditOk ? "ok" : auditOk === false ? "err" : "neutral"}`}><span className="dot" />{auditOk ? "Hash chain intact" : auditOk === false ? "Chain broken" : "Chain not verified"}</span>
        <span className="muted sm">{rows.length} record(s) for {run.id}</span><div className="spacer" />
        <input className="input sm" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter run audit records" />
      </div>
      {shown.length === 0 ? <Empty icon="audit" title="No audit records" /> : (
        <ol className="audit-feed">
          {shown.map((r) => (
            <li key={r.id}><button onClick={() => setOpen(open === r.id ? null : r.id)} aria-expanded={open === r.id}>
              <span className="mono muted">#{r.id}</span><span className="mono">{r.action}</span><span className="muted">{r.actor}</span>
              <span className="muted sm">{fmtTime(r.ts)}</span><span className="mono muted sm" title={r.hash}>{r.hash.slice(0, 10)}</span></button>
              {open === r.id && <pre>{JSON.stringify(r.payload, null, 2)}</pre>}</li>))}
        </ol>)}
    </div>
  );
}
