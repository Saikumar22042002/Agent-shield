import { Fragment, useEffect, useState } from "react";
import { api, type Finding } from "../api";
import { useAction, useCountUp } from "../hooks";
import { downloadReport, useStore } from "../store";
import { Card, ConfirmationBadge, Empty, fmtDate, fmtTime, Icon, PageHead, ProvChip, RunBadge, SevPill, TargetBadge, targetState } from "./ui";

function Kpi({ label, value, note, tone = "" }: { label: string; value: number; note: string; tone?: string }) {
  const v = useCountUp(value);
  return <div className={`kpi ${tone}`}><span>{label}</span><b className="num">{v}</b><em>{note}</em></div>;
}

/* ---------------------------------------------------------------- overview */
export function Overview() {
  const { targets, runs, audit, auditOk, go, selectRun, kill, refreshAudit } = useStore();
  useEffect(() => { void refreshAudit(); }, [refreshAudit]); // audit is not refreshed in the background
  const active = targets.filter((t) => !t.archived);
  const verified = active.filter((t) => targetState(t) === "verified").length;
  const stub = active.filter((t) => t.provider === "local_stub").length;
  const failing = active.filter((t) => ["auth", "error"].includes(targetState(t))).length;
  const openRuns = runs.filter((r) => r.status === "open" || r.status === "paused").length;
  const openFindings = runs.reduce((n, r) => n + (r.summary?.findings_open ?? 0), 0);
  const confirmed = runs.reduce((n, r) => n + (r.summary?.findings_confirmed ?? 0), 0);
  const high = runs.reduce((n, r) => n + (r.summary?.findings_by_severity?.High ?? 0), 0);
  const open = (id: string) => { void selectRun(id); go("workspace"); };
  return (
    <div className="page">
      <PageHead eyebrow="Overview" title="Security assessment posture"
                sub="Targets, runs and findings across your authorised staging agents. Every number comes from recorded data."
                actions={<button className="btn primary" onClick={() => go(targets.length ? "workspace" : "targets")}>
                  <Icon name={targets.length ? "workspace" : "plus"} size={14} />{targets.length ? "Open workspace" : "Add first target"}</button>} />
      <div className="kpis">
        <Kpi label="Verified cloud targets" value={verified} note={`${active.length} active · ${stub} local stub`} tone={verified ? "ok" : ""} />
        <Kpi label="Connectivity failures" value={failing} note="authorization or connection errors" tone={failing ? "err" : ""} />
        <Kpi label="Active runs" value={openRuns} note={`${runs.length} runs in total`} />
        <Kpi label="Open findings" value={openFindings} note={`${confirmed} confirmed · ${high} high severity`} tone={openFindings ? "warn" : ""} />
      </div>
      {targets.length === 0 && (
        <div className="hero">
          <div><div className="eyebrow">Get started</div><h2>Onboard your first target</h2>
            <p>Register an AWS Bedrock AgentCore harness you own, or add the local stub to try every workflow without cloud credentials.</p></div>
          <ol className="steps-h">
            <li><b>1</b>Register a staging target and document its profile</li><li><b>2</b>Verify connectivity</li><li><b>3</b>Launch a run, draft and approve a plan</li><li><b>4</b>Execute it (PyRIT / garak via the gateway) or import results</li><li><b>5</b>Confirm findings and export the PDF</li>
          </ol>
          <button className="btn primary" onClick={() => go("targets")}><Icon name="plus" size={14} />Add target</button>
        </div>)}
      <div className="split even">
        <Card title="Targets" actions={<button className="link-btn" onClick={() => go("targets")}>Manage</button>} pad={false}>
          {active.length === 0 ? <Empty icon="targets" title="No targets" /> : (
            <ul className="list">{active.map((t) => (
              <li key={t.id}><div><b>{t.name}</b><span>{t.provider_label}</span></div><TargetBadge t={t} /></li>))}</ul>)}
        </Card>
        <Card title="Recent runs" actions={<button className="link-btn" onClick={() => go("runs")}>All runs</button>} pad={false}>
          {runs.length === 0 ? <Empty icon="runs" title="No runs yet" /> : (
            <ul className="list">{runs.slice(0, 6).map((r) => (
              <li key={r.id} className="click" onClick={() => open(r.id)}>
                <div><b className="mono">{r.id}</b><span>{r.label || "—"} · {r.phase ? `phase ${r.phase.current}/${r.phase.total}` : ""} · {r.summary?.findings_open ?? 0} open findings</span></div>
                <RunBadge status={r.status} /></li>))}</ul>)}
        </Card>
      </div>
      <Card title="Latest audit records" actions={<span className={`badge ${auditOk ? "ok" : auditOk === false ? "err" : "neutral"}`}><span className="dot" />{auditOk ? "Hash chain intact" : auditOk === false ? "Chain broken" : "Verifying"}</span>} pad={false}>
        <ul className="list dense">{audit.slice(0, 6).map((a) => (
          <li key={a.id}><div><b className="mono">{a.action}</b><span>{a.actor}{a.run_id ? ` · ${a.run_id}` : ""}</span></div><span className="muted sm">{fmtTime(a.ts)}</span></li>))}</ul>
      </Card>
      {kill.tripped && <p className="note-err">Emergency stop is active. See the banner above to reset it.</p>}
    </div>
  );
}

/* ---------------------------------------------------------------- findings */
function FindingReview({ f }: { f: Finding }) {
  const { refreshRun, run, kill } = useStore();
  const [note, setNote] = useState("");
  const { busy, run: act } = useAction();
  const decide = (d: "confirmed" | "dismissed" | "candidate") =>
    act(() => api.reviewFinding(f.id, d, note), `Finding marked ${d}.`).then(() => { setNote(""); void refreshRun(); });
  const disabled = busy || kill.tripped || run?.status === "halted";
  return (
    <div className="review-box">
      <div className="row gap-2 wrap"><ConfirmationBadge c={f.confirmation} /><span className="muted sm">{f.confirmation_basis}</span></div>
      <div className="row gap-2 wrap">
        <input className="input sm grow" placeholder="Note (audited)" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Review note" />
        {f.confirmation !== "confirmed" && <button className="btn sm" disabled={disabled} onClick={() => void decide("confirmed")}><Icon name="check" size={13} />Confirm</button>}
        {f.confirmation !== "dismissed" && <button className="btn sm" disabled={disabled} onClick={() => void decide("dismissed")}><Icon name="x" size={13} />Dismiss</button>}
        {f.confirmation !== "candidate" && <button className="btn ghost sm" disabled={disabled} onClick={() => void decide("candidate")}>Reset to candidate</button>}
      </div>
    </div>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  const { attempts, jumpToAttempt } = useStore();
  const a = attempts.find((x) => x.id === f.attempt_id);
  const input = a?.turns.find((t) => t.role === "user")?.text ?? "";
  const reply = a?.turns.find((t) => t.role === "assistant")?.text ?? "";
  return (
    <div className="finding-detail">
      <div className="row gap-2 wrap"><SevPill sev={f.severity} /><span className="mono muted">{f.category}</span>
        <span className={`badge ${f.status === "closed" ? "ok" : "warn"}`}><span className="dot" />{f.status === "closed" ? `Closed by ${f.closed_by_run_id}` : "Open"}</span>
        <ConfirmationBadge c={f.confirmation} /><ProvChip p={f.evidence.source && !f.evidence.import_file ? "executed" : "derived"} /></div>
      <h2>{f.title}</h2>
      <FindingReview f={f} />
      <dl className="kv wide">
        <dt>Evidence</dt><dd>{f.evidence.rationale}</dd>
        <dt>Scorer</dt><dd>{f.evidence.detector || "—"}{f.evidence.score != null && ` · score ${f.evidence.score.toFixed(2)}`}</dd>
        <dt>Failed attempts</dt><dd>{f.evidence.failed_attempts}</dd>
        {f.evidence.import_file
          ? <><dt>Source file</dt><dd>{f.evidence.import_file} · <span className="mono" title={f.evidence.import_sha256}>sha256 {f.evidence.import_sha256.slice(0, 16)}…</span></dd></>
          : <><dt>Executed by</dt><dd>{f.evidence.source} · gateway invocations {(f.evidence.invocation_ids ?? []).slice(0, 8).join(", ") || "—"}
            {f.evidence.evidence_sha256 && <> · <span className="mono" title={f.evidence.evidence_sha256}>sha256 {f.evidence.evidence_sha256.slice(0, 16)}…</span></>}</dd></>}
        {f.evidence.trap_hits.map((h, i) => <Fragment key={i}><dt>Trap hit</dt><dd className="mono">{h.token_id} · {h.received_at ?? "—"} · {h.source || "—"}</dd></Fragment>)}
      </dl>
      {input && <div className="quote ha"><span>Recorded input · via {f.evidence.source}</span>{input.slice(0, 900)}</div>}
      {reply && <div className="quote ta"><span>Recorded reply</span>{reply.slice(0, 900)}</div>}
      {f.fix && <div className="fix"><b>Recommended fix</b><p>{f.fix}</p></div>}
      <button className="btn" onClick={() => jumpToAttempt(f.attempt_id)}><Icon name="workspace" size={14} />Open in conversation</button>
    </div>
  );
}

export function Findings() {
  const { findings, run, refreshRuns, selectRun, kill } = useStore();
  const [sel, setSel] = useState<number | null>(null);
  const [status, setStatus] = useState<"" | "open" | "closed">("");
  const { busy, run: act } = useAction();
  const order = { High: 0, Medium: 1, Low: 2, Unrated: 3 } as const;
  const list = findings.filter((f) => !status || f.status === status)
    .sort((a, b) => (a.status === b.status ? 0 : a.status === "open" ? -1 : 1) || order[a.severity] - order[b.severity]);
  const cur = list.find((f) => f.id === sel) ?? list[0];
  const retest = async () => {
    if (!run) return;
    const r = await act(() => api.createRun(run.target_id, "re-test", run.id), (x) => `Re-test ${x.id} opened.`);
    if (r) { await refreshRuns(); await selectRun(r.id); }
  };
  return (
    <div className="page">
      <PageHead eyebrow={run ? `Run ${run.id}` : "Findings"} title="Findings"
                sub="Derived only from failed framework verdicts (executed or imported) and trap hits. A detector hit is a candidate until confirmed."
                actions={<button className="btn" disabled={!run || busy || kill.tripped || !findings.length} onClick={retest}><Icon name="refresh" size={14} />Schedule re-test</button>} />
      {!run ? <Card><Empty icon="findings" title="No run selected">Select a run in the header to see its findings.</Empty></Card>
        : findings.length === 0 ? <Card><Empty icon="findings" title="No findings for this run">Findings appear only when executed or imported results contain a failed verdict or a trap hit. Local stub runs never produce findings. Nothing is inferred.</Empty></Card> : (
        <div className="split">
          <Card pad={false} title={`${list.length} finding${list.length === 1 ? "" : "s"}`}
                actions={<div className="seg sm">{(["", "open", "closed"] as const).map((s) => <button key={s} aria-selected={status === s} onClick={() => setStatus(s)}>{s || "All"}</button>)}</div>}>
            <ul className="finding-list">{list.map((f) => (
              <li key={f.id}><button className={cur?.id === f.id ? "on" : ""} onClick={() => setSel(f.id)}>
                <SevPill sev={f.severity} /><span><b>{f.title}</b><em>{f.category} · {f.evidence.failed_attempts} failed · {f.status} · {f.confirmation}</em></span></button></li>))}</ul>
          </Card>
          <Card>{cur && <FindingDetail f={cur} />}</Card>
        </div>)}
    </div>
  );
}

/* ---------------------------------------------------------------- evidence & audit */
export function Audit() {
  const { audit, auditOk, refreshAudit, run } = useStore();
  useEffect(() => { void refreshAudit(); }, [refreshAudit]); // audit is not refreshed in the background
  const [q, setQ] = useState("");
  const [scope, setScope] = useState<"all" | "run">("all");
  const [open, setOpen] = useState<number | null>(null);
  const rows = audit.filter((r) => (scope === "all" || r.run_id === run?.id) && (!q || JSON.stringify(r).toLowerCase().includes(q.toLowerCase())));
  return (
    <div className="page">
      <PageHead eyebrow="Provenance" title="Evidence & Audit" sub="Append-only, sha256 hash-chained record of every request, response, import, export and stop."
                actions={<><span className={`badge ${auditOk ? "ok" : auditOk === false ? "err" : "neutral"}`}><span className="dot" />{auditOk ? "Hash chain verified intact" : auditOk === false ? "Hash chain BROKEN" : "Verifying…"}</span>
                  <button className="btn" onClick={() => void refreshAudit()}><Icon name="refresh" size={14} />Re-verify</button></>} />
      {run?.imports && run.imports.length > 0 && (
        <Card title={`Evidence files · ${run.id}`} pad={false}>
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Tool</th><th>File</th><th>sha256</th><th>Version</th><th>By</th><th>Imported</th></tr></thead>
            <tbody>{run.imports.map((i) => (
              <tr key={i.id}><td>{i.tool}</td><td>{i.filename}</td><td className="mono" title={i.sha256}>{i.sha256.slice(0, 20)}…</td>
                <td>{i.tool_version || "—"}</td><td>{i.imported_by}</td><td className="muted">{fmtDate(i.imported_at)}</td></tr>))}</tbody>
          </table></div>
        </Card>)}
      <Card pad={false} title="Audit log" actions={<div className="row gap-2">
        <div className="seg sm"><button aria-selected={scope === "all"} onClick={() => setScope("all")}>All</button>
          <button aria-selected={scope === "run"} disabled={!run} onClick={() => setScope("run")}>This run</button></div>
        <input className="input sm" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter audit log" /></div>}>
        {rows.length === 0 ? <Empty icon="audit" title="No matching records" /> : (
          <div className="table-wrap"><table className="table audit">
            <thead><tr><th className="r">#</th><th>Time</th><th>Actor</th><th>Action</th><th>Run</th><th>Details</th><th>Hash</th></tr></thead>
            <tbody>{rows.map((r) => (
              <tr key={r.id} onClick={() => setOpen(open === r.id ? null : r.id)} className={open === r.id ? "on" : ""}>
                <td className="r num muted">{r.id}</td><td className="mono nowrap">{fmtTime(r.ts)}</td><td>{r.actor}</td>
                <td className="mono">{r.action}</td><td className="mono muted">{r.run_id ?? "—"}</td>
                <td className="mono details">{open === r.id ? <pre>{JSON.stringify(r.payload, null, 2)}</pre> : JSON.stringify(r.payload).slice(0, 140)}</td>
                <td className="mono muted" title={r.hash}>{r.hash.slice(0, 10)}</td>
              </tr>))}</tbody>
          </table></div>)}
      </Card>
    </div>
  );
}

/* ---------------------------------------------------------------- reports */
export function Reports() {
  const { runs, targets, notify } = useStore();
  const [busy, setBusy] = useState<string | null>(null);
  const exp = async (id: string) => {
    setBusy(id);
    try { await downloadReport(id); notify("ok", `Report for ${id} exported.`); }
    catch (e) { notify("error", (e as Error).message); } finally { setBusy(null); }
  };
  return (
    <div className="page">
      <PageHead eyebrow="Deliverables" title="Reports"
                sub="Proof PDFs with run metadata, findings and evidence, re-test results, file hashes, audit-chain status and honest limits." />
      {runs.length === 0 ? <Card><Empty icon="reports" title="No runs to report on">Launch a run and import results first.</Empty></Card> : (
        <div className="report-grid">{runs.map((r) => {
          const t = targets.find((x) => x.id === r.target_id);
          const s = r.summary;
          return (
            <div key={r.id} className="report-card">
              <div className="row gap-2"><Icon name="reports" size={18} /><b className="mono">{r.id}</b><div className="spacer" /><RunBadge status={r.status} /></div>
              <div className="report-t">{t?.name ?? "—"}{r.label && <span> · {r.label}</span>}</div>
              {t?.provider === "local_stub" && <span className="badge stub sm"><span className="dot" />Local stub run</span>}
              <div className="report-stats">
                <div><b>{s?.attempts ?? 0}</b><span>attempts</span></div>
                <div><b>{s?.findings_open ?? 0}</b><span>open</span></div>
                <div><b>{s?.findings_closed ?? 0}</b><span>closed</span></div>
              </div>
              <span className="muted sm">{fmtDate(r.started_at)}{r.parent_run_id && ` · re-test of ${r.parent_run_id}`}</span>
              <button className="btn full" disabled={busy === r.id} onClick={() => void exp(r.id)}>
                {busy === r.id ? <><span className="spin" />Generating…</> : <><Icon name="download" size={14} />Export PDF</>}</button>
            </div>);
        })}</div>)}
    </div>
  );
}
