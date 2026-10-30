import { Fragment, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, type Run, type Target, type TimelineItem } from "../api";
import { useAction } from "../hooks";
import { useStore, type PendingReply } from "../store";
import { AssessmentPanel, RunAudit } from "./Assessment";
import { AssessmentBadge, Empty, errorParts, fmtDate, fmtMs, fmtTime, Icon, ProvChip, RunBadge, SevPill, TargetBadge, Verdict } from "./ui";

type Tab = "all" | "messages" | "activity" | "evidence" | "audit" | "assessment";
const TABS: [Tab, string][] = [["all", "All"], ["messages", "Messages"], ["activity", "Activity"], ["evidence", "Evidence"],
  ["audit", "Audit"], ["assessment", "Assessment"]];
const FEED_TABS: Tab[] = ["all", "messages", "activity", "evidence"];

const loadPref = (k: string, d: boolean) => { try { const v = localStorage.getItem(k); return v == null ? d : v === "1"; } catch { return d; } };
const savePref = (k: string, v: boolean) => { try { localStorage.setItem(k, v ? "1" : "0"); } catch { /* ignore */ } };

/* ---------------------------------------------------------------- message body */
function RichText({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 1600;
  const long = text.length > LIMIT;
  const shown = long && !expanded ? text.slice(0, LIMIT) : text;
  const parts = shown.split(/```/);
  return (
    <div className="rich">
      {parts.map((p, i) => i % 2 === 1
        ? <pre key={i}><code>{p.replace(/^[a-zA-Z0-9_-]*\n/, "")}</code></pre>
        : <span key={i}>{p}</span>)}
      {long && <button className="link-btn" onClick={() => setExpanded(!expanded)}>
        {expanded ? "Show less" : `Show ${text.length - LIMIT} more characters`}</button>}
    </div>
  );
}

function Avatar({ who }: { who: "evaluator" | "target" | "system" }) {
  if (who === "evaluator") return <div className="avatar ha" aria-hidden>HA</div>;
  if (who === "target") return <div className="avatar ta" aria-hidden><Icon name="cpu" size={15} /></div>;
  return <div className="avatar sys" aria-hidden><Icon name="shield" size={14} /></div>;
}

function MetaLine({ it }: { it: TimelineItem }) {
  const m = it.meta ?? {};
  const bits: ReactNode[] = [];
  if (m.latency_ms != null) bits.push(<span key="l" title="Service-reported latency (metadata.metrics.latencyMs)"><Icon name="clock" size={12} />{fmtMs(m.latency_ms)} service</span>);
  if (m.wall_ms != null) bits.push(<span key="w" title="Round trip measured by AgentShield">{fmtMs(m.wall_ms)} round trip</span>);
  if (m.usage?.totalTokens != null) bits.push(<span key="t" title="Token usage reported by the target (metadata.usage)">{m.usage.inputTokens ?? "?"} in · {m.usage.outputTokens ?? "?"} out tokens</span>);
  if (m.stop_reason) bits.push(<span key="s">stop: {m.stop_reason}</span>);
  if (m.tool_events?.length) bits.push(<span key="tr" title="Tool / hook events observed in the response stream">{m.tool_events.length} trace event(s)</span>);
  if (!bits.length) return null;
  return <div className="msg-meta">{bits}</div>;
}

function Reasoning({ it }: { it: TimelineItem }) {
  const m = it.meta ?? {};
  const rows: [string, ReactNode][] = [];
  if (m.session_id) rows.push(["Session", <span className="mono">{m.session_id}</span>]);
  if (m.kind) rows.push(["Exchange", m.kind === "connectivity" ? "Fixed benign connectivity greeting"
    : m.kind === "assessment" ? "Approved plan prompt, sent through the gateway" : m.kind]);
  if (m.test_id) rows.push(["Test", <span className="mono">{m.test_id}</span>]);
  if (m.external_id) rows.push(["Tool record", <span className="mono">{m.external_id}</span>]);
  if (m.recorded_role) rows.push(["Recorded role", m.recorded_role]);
  if (m.generation != null) rows.push(["Generation", String(m.generation)]);
  if (m.tool_events?.length) rows.push(["Trace", <pre className="trace">{JSON.stringify(m.tool_events, null, 2)}</pre>]);
  if (!rows.length) return <div className="reasoning muted">No reasoning or execution metadata was recorded for this message.</div>;
  return (
    <dl className="reasoning">
      {rows.map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>)}
    </dl>
  );
}

function sourceLabel(it: TimelineItem) {
  if (it.provenance === "imported") return `via ${it.source} · recorded`;
  if (it.role === "evaluator") return it.meta?.kind === "assessment" ? "Approved plan prompt · via gateway" : "AgentShield · connectivity greeting";
  return it.provider === "local_stub" ? "Local stub target" : "Live response";
}

function Message({ it, target, showReasoning }: { it: TimelineItem; target?: Target; showReasoning: boolean }) {
  const who = it.role ?? "system";
  const name = who === "evaluator" ? "Hacker Agent" : who === "target" ? (target?.name ?? "Target agent") : "System";
  const role = who === "evaluator" ? "Evaluator" : who === "target" ? "Target" : "System";
  return (
    <article className={`msg ${who} ${it.error ? "has-error" : ""}`} id={it.id} aria-label={`${name}, turn ${it.turn ?? ""}`}>
      <Avatar who={who} />
      <div className="msg-col">
        <header className="msg-h">
          <b>{name}</b>
          <span className="msg-role">{role}</span>
          {it.turn != null && <span className="msg-turn">Turn {it.turn}</span>}
          <span className="msg-time" title={it.ts ?? ""}>{fmtTime(it.ts)}</span>
          <ProvChip p={it.provenance} />
        </header>
        <div className="bubble">
          {it.error ? (
            <div className="msg-error">
              <div className="err-code"><Icon name="alert" size={14} />{it.error.code || "Error"}</div>
              <div className="err-orig"><span>Provider message</span>{it.error.message}</div>
              {it.error.hint && <div className="err-hint"><span>What to check</span>{it.error.hint}</div>}
            </div>
          ) : it.text ? <RichText text={it.text} /> : <span className="muted">(empty message)</span>}
        </div>
        <div className="msg-foot"><span className="src">{sourceLabel(it)}</span><MetaLine it={it} /></div>
        {showReasoning && <Reasoning it={it} />}
      </div>
    </article>
  );
}

function Streaming({ p, target }: { p: PendingReply; target?: Target }) {
  return (
    <article className="msg target streaming" aria-live="polite" aria-label="Target agent is responding">
      <Avatar who="target" />
      <div className="msg-col">
        <header className="msg-h"><b>{target?.name ?? "Target agent"}</b><span className="msg-role">Target</span>
          <span className="msg-turn">Turn {p.turn}</span><span className="badge live sm"><span className="dot" />Streaming</span></header>
        <div className="bubble">{p.text ? <RichText text={p.text} /> : <span className="typing"><i /><i /><i /></span>}</div>
      </div>
    </article>
  );
}

/* ---------------------------------------------------------------- activity + evidence rows */
function activityText(it: TimelineItem): { icon: string; text: ReactNode; tone?: string } {
  const d = it.data ?? {};
  switch (it.type) {
    case "run.created": return { icon: "play", text: <>Run <b>{d.id}</b> opened{d.parent_run_id ? <> as a re-test of {d.parent_run_id}</> : null}</> };
    case "run.status": return { icon: d.status === "paused" ? "pause" : d.status === "open" ? "play" : "stop",
      text: <>Run {d.from} → <b>{d.status}</b> by {d.by}{d.reason ? ` · ${d.reason}` : ""}</>, tone: d.status === "stopped" ? "warn" : undefined };
    case "run.completed": return { icon: "check", text: <>Run marked <b>complete</b></>, tone: "ok" };
    case "connectivity.start": return { icon: "send", text: <>Connectivity exchange started with <b>{d.name}</b></> };
    case "connectivity.result": return d.status === "connected"
      ? { icon: "check", text: <>Target responded · {fmtMs(d.wall_ms)} round trip</>, tone: "ok" }
      : { icon: "alert", text: <>Exchange failed · {String(d.error_code || d.error).slice(0, 80)}</>, tone: "err" };
    case "import.done": return { icon: "upload", text: <>Imported <b>{d.tool}</b> results · {d.filename} · {d.attempts_added ?? 0} attempts</> };
    case "judge.done": return { icon: "eye", text: <>Advisory review of attempt #{d.attempt_id}: <b>{d.model_verdict}</b> ({d.model_id})</> };
    case "kill.tripped": return { icon: "alert", text: <><b>Emergency stop</b> · {d.reason} · by {d.by}</>, tone: "err" };
    case "kill.reset": return { icon: "refresh", text: <>Emergency stop reset by {d.by}</> };
    case "attempt.start": return { icon: "file", text: <><b>{d.source_tool}</b> attempt · <span className="mono">{d.test_id}</span> · {d.category} {d.category_title}</> };
    case "plan.created": return { icon: "file", text: <>Plan <b>v{d.version}</b> drafted by {d.by} · {d.cases} case(s) · {d.planned_prompts} prompt(s) · <span className="mono">{String(d.sha256).slice(0, 10)}</span></> };
    case "plan.approved": return { icon: "check", text: <>Plan <b>v{d.version}</b> approved by {d.by} · <span className="mono">{String(d.sha256).slice(0, 10)}</span></>, tone: "ok" };
    case "assessment.status": return { icon: d.status === "running" ? "play" : d.status === "completed" ? "check" : d.status === "queued" ? "clock" : "stop",
      text: <>Execution {d.from} → <b>{d.status}</b>{d.reason ? ` · ${d.reason}` : ""}</>,
      tone: d.status === "completed" ? "ok" : ["error", "interrupted"].includes(d.status) ? "err" : d.status === "stopped" ? "warn" : undefined };
    case "assessment.case": return { icon: d.state === "started" ? "play" : d.state === "skipped" ? "chevron" : "check",
      text: <>Case <b>{d.case_id}</b> {d.state} · {d.label}{d.verdict && d.state !== "skipped" ? ` · ${d.verdict}` : ""}{d.reason ? ` · ${d.reason}` : ""}{d.error ? ` · ${d.error}` : ""}</>,
      tone: d.error ? "err" : d.state === "skipped" ? "warn" : undefined };
    case "gateway.refused": return { icon: "alert", text: <>Gateway refused <b>{d.code}</b> · {d.label || d.case_id} turn {d.turn} · {d.message}</>, tone: "err" };
    case "gateway.retry": return { icon: "refresh", text: <>Gateway retry {d.attempt}/{d.of} after <b>{d.error_code}</b> · {d.label || d.case_id} · in {d.delay_s}s</>, tone: "warn" };
    case "plan.invalidated": return { icon: "alert", text: <>Plan <b>v{d.version}</b> approval withdrawn · {d.reason}</>, tone: "warn" };
    case "coordinator.start": return { icon: "cpu", text: <>Deep Agents coordinator started · {d.mode} ({d.model}) · {d.cases} case(s)</> };
    case "coordinator.step": return { icon: "cpu", text: d.tool_calls?.length
      ? <>Coordinator → {d.tool_calls.map((c: { name: string; args: Record<string, unknown> }) => `${c.name}(${Object.values(c.args ?? {}).map(String).join(", ").slice(0, 80)})`).join(" · ")}</>
      : <>Coordinator: {String(d.text).slice(0, 200)}</> };
    case "coordinator.done": return { icon: "check", text: <>Coordinator finished · {d.attacker_tokens} tokens{d.stop_reason ? ` · ${d.stop_reason}` : ""}</> };
    case "finding.review": return { icon: "eye", text: <>Finding {d.category} · <span className="mono">{d.test_id}</span> marked <b>{d.decision}</b> by {d.by}</> };
    default: return { icon: "bolt", text: it.type };
  }
}

function ActivityRow({ it }: { it: TimelineItem }) {
  const a = activityText(it);
  return (
    <div className={`divider ${a.tone ?? ""}`} id={it.id}>
      <span className="line" />
      <span className="divider-body"><Icon name={a.icon} size={13} />{a.text}<span className="divider-time">{fmtTime(it.ts)}</span></span>
      <span className="line" />
    </div>
  );
}

function EvidenceRow({ it }: { it: TimelineItem }) {
  const d = it.data ?? {};
  const { jumpToAttempt, go } = useStore();
  let body: ReactNode;
  if (it.type === "import") body = <><Icon name="file" size={14} /><div><b>{d.filename}</b><span>{d.tool} {d.tool_version && `v${d.tool_version}`} · sha256 <span className="mono">{String(d.sha256).slice(0, 16)}…</span> · by {d.imported_by}</span></div></>;
  else if (it.type === "scorer.result") body = <><Verdict v={d.verdict} /><div><b>{d.detector || "No scorer recorded"}{d.score != null && <> · score {Number(d.score).toFixed(2)}</>}{d.trap_hit && <span className="sev sev-High">trap hit</span>}</b><span>{d.rationale}</span></div></>;
  else if (it.type === "model.review") body = <><Verdict v={d.verdict} /><div><b>Advisory review · <span className="mono">{d.model}</span></b><span>{d.rationale}</span></div></>;
  else if (it.type === "finding") body = <><SevPill sev={d.severity} /><div><b>{d.title}</b><span>Finding #{d.finding_id} · {d.status}</span></div>
    <button className="link-btn" onClick={() => go("findings")}>Open</button></>;
  else body = <span>{it.type}</span>;
  return (
    <div className={`evidence ev-${it.type.replace(".", "-")}`} id={it.id}>
      {body}
      <div className="ev-side"><ProvChip p={it.provenance} />
        {it.type === "scorer.result" && <button className="link-btn" onClick={() => jumpToAttempt(d.attempt_id)}>Turns</button>}</div>
    </div>
  );
}

/* ---------------------------------------------------------------- console */
function ConsoleHeader({ run, target, tab, setTab, counts, reasoning, setReasoning, onShowCtx }:
  { run: Run; target?: Target; tab: Tab; setTab: (t: Tab) => void; counts: Partial<Record<Tab, number>>; reasoning: boolean;
    setReasoning: (v: boolean) => void; onShowCtx?: () => void }) {
  const ph = run.phase;
  return (
    <div className="console-h">
      <div className="pair">
        <div className="agent-id"><div className="avatar ha lg">HA</div><div><b>Hacker Agent</b><span>Evaluator · PyRIT / garak via gateway</span></div></div>
        <div className="pair-link" aria-hidden><span /><Icon name="link" size={14} /><span /></div>
        <div className="agent-id"><div className="avatar ta lg"><Icon name="cpu" size={18} /></div>
          <div><b>{target?.name ?? "Target agent"}</b><span>{target?.provider_label ?? "—"}</span></div></div>
        <div className="spacer" />
        <div className="phase">
          {ph && <><div className="phase-txt"><span>Phase {ph.current} of {ph.total}</span><b>{ph.label}</b></div>
            <div className="phase-bar" role="progressbar" aria-valuemin={0} aria-valuemax={ph.total}
                 aria-valuenow={ph.steps.filter((s) => s.done).length} aria-label="Evaluation phases">
              {ph.steps.map((s, i) => <i key={i} className={s.done ? "done" : i + 1 === ph.current ? "cur" : ""} title={s.label} />)}
            </div></>}
        </div>
        <RunBadge status={run.status} />
      </div>
      <div className="console-tabs">
        <div className="seg" role="tablist" aria-label="Conversation view">
          {TABS.map(([k, l]) => (
            <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}>{l}{counts[k] != null && <em>{counts[k]}</em>}</button>
          ))}
        </div>
        <div className="spacer" />
        <label className="toggle" title="Shows only metadata that was actually recorded: session ids, trace events, tool record ids. Hidden model reasoning is never available or shown.">
          <input type="checkbox" checked={reasoning} onChange={(e) => setReasoning(e.target.checked)} />
          <span className="track"><span /></span>Reasoning &amp; metadata
        </label>
        {onShowCtx && <button className="ctx-open" onClick={onShowCtx} aria-label="Show run context"><Icon name="panel" size={15} /><span>Context</span></button>}
      </div>
    </div>
  );
}

function Composer({ run, target }: { run: Run; target?: Target }) {
  const { config, kill } = useStore();
  const { busy, run: act } = useAction();
  const open = run.status === "open";
  const canSend = open && !kill.tripped && !!target?.provider_implemented && !target?.archived;
  const reason = kill.tripped ? "Emergency stop is active." : !open ? `Run is ${run.status}.`
    : !target?.provider_implemented ? `${target?.provider_label} connector is not implemented.` : "";
  const { notify, refreshTimeline, refreshTargets } = useStore();
  const send = async () => {
    const r = await act(() => api.exchange(run.id));
    await Promise.all([refreshTimeline(), refreshTargets()]);
    if (r && r.status !== "connected") notify("error", `Exchange failed: ${r.error_code || r.error}`);
  };
  return (
    <div className="composer">
      <div className="composer-box">
        <div className="composer-label"><Icon name="send" size={13} />Fixed connectivity greeting · read-only</div>
        <div className="composer-text">{config?.connectivity_message ?? "…"}</div>
      </div>
      <button className="btn primary lg" disabled={!canSend || busy} onClick={send} title={reason || "Send the fixed benign greeting to the target"}>
        {busy ? <><span className="spin" />Sending…</> : <><Icon name="send" size={15} />Send greeting</>}
      </button>
      <p className="composer-note">{reason ? <span className="warn-text">{reason} </span> : null}
        This composer sends only the benign greeting. Test traffic comes only from an approved plan (Assessment tab), executed by PyRIT / garak through the gateway; results can also be imported.</p>
    </div>
  );
}

function RunControls({ run }: { run: Run }) {
  const { kill, refreshRun, refreshRuns, refreshTimeline } = useStore();
  const { busy, run: act } = useAction();
  const [confirmStop, setConfirmStop] = useState(false);
  const after = async () => { await Promise.all([refreshRun(), refreshRuns(), refreshTimeline()]); };
  const live = run.status === "open" || run.status === "paused";
  return (
    <div className="run-controls">
      {run.status === "paused"
        ? <button className="btn" disabled={busy || kill.tripped} onClick={() => act(() => api.resumeRun(run.id), "Run resumed.").then(after)}><Icon name="play" size={13} />Resume</button>
        : <button className="btn" disabled={busy || run.status !== "open"} onClick={() => act(() => api.pauseRun(run.id), "Run paused.").then(after)}
                  title="Blocks exchanges, imports and reviews until resumed"><Icon name="pause" size={13} />Pause</button>}
      {confirmStop
        ? <span className="confirm-inline">End run?
            <button className="btn danger sm" disabled={busy} onClick={() => act(() => api.stopRun(run.id, "Stopped from evaluation workspace"), "Run stopped.").then(() => { setConfirmStop(false); void after(); })}>Stop run</button>
            <button className="btn ghost sm" onClick={() => setConfirmStop(false)}>Cancel</button></span>
        : <button className="btn" disabled={busy || !live} onClick={() => setConfirmStop(true)} title="Ends this run (final). Evidence and the PDF stay available."><Icon name="stop" size={13} />Stop</button>}
      <button className="btn" disabled={busy || !live} onClick={() => act(() => api.completeRun(run.id), "Run marked complete.").then(after)}><Icon name="check" size={13} />Complete</button>
    </div>
  );
}

function ContextPanel({ run, target, onClose, onAssessment }: { run: Run; target?: Target; onClose: () => void;
  onAssessment: () => void }) {
  const { findings, go, assessment } = useStore();
  const s = run.summary;
  const err = target ? errorParts(target.last_error) : null;
  return (
    <aside className="ctx-panel" aria-label="Run context">
      <div className="ctx-panel-h"><b>Run context</b><button className="icon-btn" onClick={onClose} aria-label="Hide context panel"><Icon name="x" size={15} /></button></div>
      <section>
        <h4>Controls</h4>
        <RunControls run={run} />
        {run.halt_reason && <p className="note-err">{run.status === "stopped" ? "Stopped" : "Halted"}: {run.halt_reason}</p>}
      </section>
      <section>
        <h4>Phases</h4>
        <ol className="stepper">
          {run.phase?.steps.map((st, i) => (
            <li key={st.label} className={st.done ? "done" : i + 1 === run.phase!.current ? "cur" : ""}>
              <span className="tick">{st.done ? <Icon name="check" size={11} /> : i + 1}</span>{st.label}
            </li>))}
        </ol>
      </section>
      {target && (
        <section>
          <h4>Target</h4>
          <div className="row gap-2 wrap" style={{ marginBottom: 10 }}><TargetBadge t={target} /><span className="muted sm">{target.provider_label}</span></div>
          <dl className="kv">
            {target.harness_arn && <><dt>ARN</dt><dd className="mono" title={target.harness_arn}>{target.harness_arn}</dd></>}
            <dt>Environment</dt><dd>Staging</dd>
            <dt>Last check</dt><dd>{fmtDate(target.last_check_at)}</dd>
            <dt>Latency</dt><dd>{fmtMs(target.last_latency_ms)}{target.last_wall_ms != null && <span className="muted"> · {fmtMs(target.last_wall_ms)} RTT</span>}</dd>
          </dl>
          {err?.code && <div className="diag"><b>{err.code}</b><span>{err.message}</span>{err.hint && <em>{err.hint}</em>}
            <button className="link-btn" onClick={() => go("targets")}>Open diagnostics</button></div>}
        </section>)}
      <section>
        <h4>Assessment</h4>
        <div className="row gap-2 wrap" style={{ marginBottom: 10 }}><AssessmentBadge status={assessment?.status ?? run.assessment_status} />
          {assessment?.assessment.progress && <span className="muted sm">{assessment.assessment.progress.cases_done}/{assessment.assessment.progress.cases_total} cases</span>}</div>
        <button className="btn sm full" onClick={onAssessment}><Icon name="bolt" size={13} />Plan &amp; execute</button>
      </section>
      <section>
        <h4>Results</h4>
        <div className="mini-stats">
          <div><b>{s?.executed?.total ?? 0}</b><span>executed cases</span></div>
          <div><b>{s?.imported_attempts ?? s?.attempts ?? 0}</b><span>imported attempts</span></div>
          <div><b>{findings.filter((f) => f.status === "open" && f.confirmation !== "dismissed").length}</b><span>open findings</span></div>
        </div>
        {s?.sample_data && <p className="hint">Local stub run: results are sample data and never become findings.</p>}
        <button className="btn sm full" onClick={() => go("runs")}><Icon name="upload" size={13} />Import results</button>
      </section>
      <section>
        <h4>Run</h4>
        <dl className="kv">
          <dt>ID</dt><dd className="mono">{run.id}</dd>
          {run.label && <><dt>Label</dt><dd>{run.label}</dd></>}
          <dt>Started</dt><dd>{fmtDate(run.started_at)}</dd>
          {run.parent_run_id && <><dt>Re-test of</dt><dd className="mono">{run.parent_run_id}</dd></>}
        </dl>
      </section>
    </aside>
  );
}

function Launch({ targets }: { targets: Target[] }) {
  const { targetId, selectRun, refreshRuns, go } = useStore();
  const kill = useStore((s) => s.kill);
  const usable = targets.filter((t) => !t.archived);
  const [tid, setTid] = useState<number | null>(targetId ?? usable[0]?.id ?? null);
  const [label, setLabel] = useState("");
  const [greet, setGreet] = useState(true);
  const { busy, run } = useAction();
  const t = usable.find((x) => x.id === tid);
  const launch = async () => {
    if (!t) return;
    const r = await run(() => api.createRun(t.id, label || "baseline"), (x) => `Run ${x.id} launched.`);
    if (!r) return;
    await refreshRuns();
    await selectRun(r.id);
    if (greet && t.provider_implemented) {
      await run(() => api.exchange(r.id));
      await Promise.all([useStore.getState().refreshTimeline(), useStore.getState().refreshTargets()]);
    }
  };
  if (!usable.length) return (
    <Empty icon="targets" title="No targets yet" action={<button className="btn primary" onClick={() => go("targets")}><Icon name="plus" size={14} />Add a target</button>}>
      Register a staging target, or add the local stub to try the workspace without cloud credentials.
    </Empty>);
  return (
    <div className="launch">
      <div className="launch-card">
        <div className="eyebrow">New evaluation</div>
        <h2>Launch a run</h2>
        <p className="sub">A run holds one target's connectivity exchange, approved assessment plans and their execution, imported tool results, findings and the audit trail.</p>
        <div className="field"><label htmlFor="l-t">Target</label>
          <select id="l-t" value={tid ?? ""} onChange={(e) => setTid(Number(e.target.value))}>
            {usable.map((x) => <option key={x.id} value={x.id}>{x.name} — {x.provider_label}</option>)}
          </select></div>
        {t && <div className="row gap-2"><TargetBadge t={t} /><span className="muted sm">{t.provider === "local_stub" ? "Development stub, not a real agent" : t.region}</span></div>}
        <div className="field"><label htmlFor="l-l">Label</label>
          <input id="l-l" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="baseline" /></div>
        <label className="check"><input type="checkbox" checked={greet && !!t?.provider_implemented} disabled={!t?.provider_implemented}
                                        onChange={(e) => setGreet(e.target.checked)} />
          Open with the benign connectivity exchange</label>
        <button className="btn primary lg full" disabled={!t || busy || kill.tripped} onClick={launch}>
          {busy ? <><span className="spin" />Launching…</> : <><Icon name="play" size={14} />Launch run</>}</button>
        {kill.tripped && <p className="note-err">Emergency stop is active. Reset it before launching.</p>}
      </div>
    </div>
  );
}

export function Workspace() {
  const { run, runId, targets, timeline, timelineError, pending, focusAttemptId, refreshTimeline } = useStore();
  const [tab, setTab] = useState<Tab>("all");
  const [reasoning, setReasoningState] = useState(() => loadPref("agentshield.reasoning", false));
  const [ctxOpen, setCtxOpenState] = useState(() => loadPref("agentshield.ctx", window.innerWidth > 1100));
  const setReasoning = (v: boolean) => { setReasoningState(v); savePref("agentshield.reasoning", v); };
  const setCtxOpen = (v: boolean) => { setCtxOpenState(v); savePref("agentshield.ctx", v); };
  const scroller = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);
  const [unseen, setUnseen] = useState(0);
  const target = targets.find((t) => t.id === run?.target_id);

  const items = timeline?.items ?? [];
  const assessment = useStore((s) => s.assessment);
  const counts = useMemo(() => ({
    all: items.length, messages: items.filter((i) => i.kind === "message").length,
    activity: items.filter((i) => i.kind === "activity").length, evidence: items.filter((i) => i.kind === "evidence").length,
    assessment: assessment?.cases.length || undefined,
  }), [items, assessment]);
  const feed = FEED_TABS.includes(tab);
  const shown = useMemo(() => !feed ? [] : tab === "all" ? items : items.filter((i) => i.kind === (tab === "messages" ? "message" : tab)), [items, tab, feed]);
  const streaming = Object.values(pending).filter((p) => p.run_id === runId);
  const contentKey = `${shown.length}:${streaming.map((p) => p.text.length).join(",")}`;

  const onScroll = () => {
    const el = scroller.current;
    if (!el) return;
    atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (atBottom.current) setUnseen(0);
  };
  const toBottom = (smooth = true) => {
    const el = scroller.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: smooth ? "smooth" : "auto" });
    setUnseen(0);
  };
  // Follow new content only while the reader is already at the bottom.
  const prevLen = useRef(0);
  const prevView = useRef("");
  useLayoutEffect(() => {
    if (focusAttemptId) return;
    const view = `${runId}:${tab}`;
    if (view !== prevView.current) { // a new run or tab opens at its natural position: feeds at the end, panels at the top
      prevView.current = view;
      prevLen.current = shown.length;
      atBottom.current = FEED_TABS.includes(tab);
      setUnseen(0);
      if (atBottom.current) toBottom(false); else scroller.current?.scrollTo({ top: 0 });
      return;
    }
    if (!FEED_TABS.includes(tab)) return;
    if (atBottom.current) toBottom(prevLen.current !== 0);
    else if (shown.length > prevLen.current) setUnseen((n) => n + shown.length - prevLen.current);
    prevLen.current = shown.length;
  }, [contentKey, runId, tab]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!focusAttemptId || !timeline) return;
    setTab("all");
    window.setTimeout(() => {
      const el = document.getElementById(`att-${focusAttemptId}`);
      el?.scrollIntoView({ behavior: "smooth", block: "start" });
      el?.classList.add("flash");
      useStore.setState({ focusAttemptId: null });
    }, 60);
  }, [focusAttemptId, timeline]);

  if (!runId || !run) return <div className="page ws-empty"><Launch targets={targets} /></div>;

  const emptyCopy: Partial<Record<Tab, [string, string]>> = {
    all: ["No conversation yet", "Send the connectivity greeting, or import garak / PyRIT results for this run, to see the exchange here."],
    messages: ["No messages yet", "Messages appear when the target answers the connectivity greeting or when tool transcripts are imported."],
    activity: ["No activity yet", "Run lifecycle changes, exchanges, imports and stops appear here as they happen."],
    evidence: ["No evidence yet", "Imported files, scorer results, advisory reviews and derived findings appear here."],
  };

  return (
    <div className={`ws ${ctxOpen ? "with-ctx" : ""}`}>
      <section className="console" aria-label="Agent-to-agent conversation">
        <ConsoleHeader run={run} target={target} tab={tab} setTab={setTab} counts={counts} reasoning={reasoning} setReasoning={setReasoning}
                       onShowCtx={ctxOpen ? undefined : () => setCtxOpen(true)} />
        <div className="convo" ref={scroller} onScroll={onScroll} role="log" aria-live="off">
          {tab === "assessment" && <AssessmentPanel run={run} target={target} />}
          {tab === "audit" && <RunAudit run={run} />}
          {feed && timelineError && <div className="inline-err"><Icon name="alert" size={14} />Could not load the conversation: {timelineError}
            <button className="link-btn" onClick={() => void refreshTimeline()}>Retry</button></div>}
          {feed && !timeline && !timelineError && <div className="skeleton-list">{[0, 1, 2].map((i) => <div key={i} className={`skeleton s${i}`} />)}</div>}
          {feed && timeline && shown.length === 0 && streaming.length === 0 && <Empty icon="workspace" title={emptyCopy[tab]![0]}>{emptyCopy[tab]![1]}</Empty>}
          {feed && timeline?.truncated && <div className="divider"><span className="line" /><span className="divider-body">Showing the first {timeline.attempt_limit} imported attempts. Full list in Runs &amp; Results.</span><span className="line" /></div>}
          {shown.map((it) => it.kind === "message"
            ? <Message key={it.id} it={it} target={target} showReasoning={reasoning} />
            : it.kind === "activity" ? <ActivityRow key={it.id} it={it} /> : <EvidenceRow key={it.id} it={it} />)}
          {(tab === "all" || tab === "messages") && streaming.map((p) => <Streaming key={p.message_id} p={p} target={target} />)}
        </div>
        {feed && unseen > 0 && <button className="new-pill" onClick={() => toBottom()}><Icon name="down" size={13} />{unseen} new</button>}
        {feed && <Composer run={run} target={target} />}
      </section>
      {ctxOpen && <ContextPanel run={run} target={target} onClose={() => setCtxOpen(false)} onAssessment={() => setTab("assessment")} />}
    </div>
  );
}
