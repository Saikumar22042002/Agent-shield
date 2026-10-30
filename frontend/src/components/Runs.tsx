import { useMemo, useRef, useState } from "react";
import { api, type Attempt } from "../api";
import { useAction } from "../hooks";
import { useStore } from "../store";
import { Card, Empty, fmtDate, Icon, PageHead, ProvChip, RunBadge, Verdict } from "./ui";

const TOOLS: [string, string, string][] = [
  ["garak", "garak", "report.jsonl"], ["pyrit", "PyRIT", "JSON export"], ["traps", "Trap hits", ".jsonl log"]];

function ImportCard() {
  const { run, kill } = useStore();
  const [tool, setTool] = useState("garak");
  const [over, setOver] = useState(false);
  const [last, setLast] = useState<{ name: string; stats: Record<string, number>; warnings: string[] } | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const { busy, run: act } = useAction();
  if (!run) return null;
  const blocked = kill.tripped ? "Emergency stop is active." : run.status !== "open" ? `Run is ${run.status}; imports need an active run.` : "";
  const upload = async (file?: File | null) => {
    if (!file || blocked || busy) return;
    const r = await act(() => api.importFile(run.id, tool, file),
      (x) => `Imported ${file.name}: ${x.stats.attempts_added ?? 0} attempts, ${x.stats.trap_hits ?? 0} trap hits`);
    if (r) setLast({ name: file.name, stats: r.stats, warnings: r.warnings });
    if (inputRef.current) inputRef.current.value = "";
  };
  return (
    <Card title="Import results" actions={blocked && <span className="badge neutral">{run.status === "open" ? "blocked" : "read only"}</span>}>
      <div className="seg wide" role="radiogroup" aria-label="Result format">
        {TOOLS.map(([k, l, s]) => (
          <button key={k} role="radio" aria-checked={tool === k} aria-selected={tool === k} onClick={() => setTool(k)}><b>{l}</b><span>{s}</span></button>
        ))}
      </div>
      <div className={`drop ${over ? "over" : ""} ${blocked ? "disabled" : ""}`}
           onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
           onDrop={(e) => { e.preventDefault(); setOver(false); void upload(e.dataTransfer.files[0]); }}>
        <Icon name="upload" size={22} />
        {busy ? <b>Importing…</b> : <><b>Drop a file, or</b>
          <button className="btn sm" disabled={!!blocked} onClick={() => inputRef.current?.click()}>Choose file</button></>}
        <input ref={inputRef} type="file" hidden accept=".json,.jsonl,application/json" onChange={(e) => void upload(e.target.files?.[0])} />
      </div>
      {blocked && <p className="warn-text sm">{blocked}</p>}
      {last && <div className="import-result"><Icon name="check" size={14} /><b>{last.name}</b>
        {Object.entries(last.stats).map(([k, v]) => <span key={k}>{k.replace(/_/g, " ")}: {v}</span>)}
        {last.warnings.length > 0 && <details><summary>{last.warnings.length} warnings</summary><ul>{last.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul></details>}</div>}
      <p className="hint">Files are parsed read-only, hashed with sha256 and audited. Verdicts come from your tools' scorers and detectors, and from trap logs; AgentShield does not re-judge them. Re-importing the same results is idempotent.</p>
    </Card>
  );
}

function ReviewBlock({ a }: { a: Attempt }) {
  const { kill, config, run, refreshRun } = useStore();
  const { busy, run: act } = useAction();
  const r = a.model_review;
  const disabled = busy || kill.tripped || !config?.engine.decision.model || run?.status !== "open";
  return (
    <div className="review">
      {r ? <><div className="row gap-2 wrap"><Verdict v={r.verdict} /><ProvChip p="model-judged" /><span className="mono muted sm">{r.model}</span></div><p>{r.rationale}</p></>
        : <span className="muted sm">No advisory review yet.{!config?.engine.decision.model && " Set DECISION_MODEL in .env to enable reviews."}</span>}
      <div><button className="btn sm" disabled={disabled} onClick={() => act(() => api.judge(a.id), "Advisory review stored.").then(() => refreshRun())}>
        {busy ? "Reviewing…" : r ? "Re-review" : "Advisory review"}</button></div>
    </div>
  );
}

function Attempts() {
  const { attempts, run, kill, config, refreshRun, jumpToAttempt } = useStore();
  const [verdict, setVerdict] = useState("");
  const [cat, setCat] = useState("");
  const [q, setQ] = useState("");
  const { busy, run: act } = useAction();
  const cats = useMemo(() => [...new Set(attempts.map((a) => a.category))].sort(), [attempts]);
  const shown = attempts.filter((a) => (!verdict || a.verdict === verdict) && (!cat || a.category === cat))
    .filter((a) => !q || `${a.test_id} ${a.detector} ${a.external_id} ${a.rationale}`.toLowerCase().includes(q.toLowerCase()));
  const pendingReview = attempts.filter((a) => a.verdict === "inconclusive" && !a.model_review).length;
  if (!attempts.length) return <Card title="Attempts"><Empty icon="file" title="No imported attempts">Import a garak report or a PyRIT export to see recorded attempts and their scorer verdicts.</Empty></Card>;
  return (
    <Card title={`Attempts · ${shown.length} of ${attempts.length}`}
          actions={pendingReview > 0 && <button className="btn sm" disabled={busy || kill.tripped || !config?.engine.decision.model || run?.status !== "open"}
              title="Advisory review of unreviewed inconclusive attempts (JUDGE_BATCH_LIMIT per batch)"
              onClick={() => act(() => api.judgeRun(run!.id, "inconclusive"), (r) => `Reviewed ${r.judged} attempt(s)${r.errors.length ? `, ${r.errors.length} failed` : ""}`).then(() => refreshRun())}>
            {busy ? "Reviewing…" : `Review ${pendingReview} inconclusive`}</button>}>
      <div className="filters">
        <input className="input" placeholder="Search test, detector, id…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search attempts" />
        <select className="input" value={verdict} onChange={(e) => setVerdict(e.target.value)} aria-label="Verdict">
          <option value="">All verdicts</option><option value="fail">Fail</option><option value="pass">Pass</option><option value="inconclusive">Inconclusive</option></select>
        <select className="input" value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Category">
          <option value="">All categories</option>{cats.map((c) => <option key={c}>{c}</option>)}</select>
      </div>
      <div className="attempts">
        {shown.slice(0, 300).map((a) => (
          <details key={a.id} className="attempt">
            <summary>
              <Verdict v={a.verdict} />
              <span className="mono muted">{a.category}</span>
              <span className="mono ellipsis">{a.test_id}</span>
              <span className="muted sm">{a.score != null ? a.score.toFixed(2) : "—"}{a.trap_hit ? " · trap" : ""}{a.model_review ? ` · advisory ${a.model_review.verdict}` : ""}</span>
              <Icon name="down" size={14} className="chev" />
            </summary>
            <div className="attempt-b">
              <div className="row gap-2 wrap sm muted"><ProvChip p="imported" />{a.source} · {a.detector || "no detector"} · <span className="mono">{a.external_id}</span></div>
              <p className="sm">{a.rationale}</p>
              <ReviewBlock a={a} />
              <button className="btn sm" onClick={() => jumpToAttempt(a.id)}><Icon name="workspace" size={13} />View conversation</button>
            </div>
          </details>))}
        {shown.length > 300 && <p className="muted sm center">Showing the first 300. Narrow with filters.</p>}
      </div>
    </Card>
  );
}

export function Runs() {
  const { runs, targets, run, runId, selectRun, refreshRuns, kill, go } = useStore();
  const [tf, setTf] = useState<number | "">("");
  const { busy, run: act } = useAction();
  const list = runs.filter((r) => tf === "" || r.target_id === tf);
  const tname = (id: number) => targets.find((t) => t.id === id)?.name ?? `#${id}`;
  const retest = async () => {
    if (!run) return;
    const r = await act(() => api.createRun(run.target_id, "re-test", run.id), (x) => `Re-test ${x.id} opened. Import the re-run results there.`);
    if (r) { await refreshRuns(); await selectRun(r.id); }
  };
  return (
    <div className="page">
      <PageHead eyebrow="Assessments" title="Runs & Results" sub="Every run with its imported evidence, recorded attempts and advisory reviews."
                actions={<><button className="btn" disabled={!run || busy || kill.tripped} onClick={retest} title="Open a child run; passing re-test results close this run's findings"><Icon name="refresh" size={14} />Schedule re-test</button>
                  <button className="btn primary" onClick={() => { void selectRun(null); go("workspace"); }}><Icon name="play" size={14} />Launch run</button></>} />
      <Card pad={false} title="All runs" actions={<select className="input sm" value={tf} onChange={(e) => setTf(e.target.value ? Number(e.target.value) : "")} aria-label="Filter by target">
          <option value="">All targets</option>{targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>}>
        {list.length === 0 ? <Empty icon="runs" title="No runs yet">Launch a run from the Evaluation Workspace.</Empty> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Run</th><th>Target</th><th>Status</th><th>Phase</th><th className="r">Attempts</th><th className="r">Open findings</th><th>Started</th></tr></thead>
              <tbody>{list.map((r) => (
                <tr key={r.id} className={r.id === runId ? "on" : ""} onClick={() => void selectRun(r.id)} tabIndex={0}
                    onKeyDown={(e) => { if (e.key === "Enter") void selectRun(r.id); }}>
                  <td><span className="mono">{r.id}</span>{r.label && <span className="muted"> · {r.label}</span>}{r.parent_run_id && <span className="tag">re-test</span>}</td>
                  <td>{tname(r.target_id)}</td>
                  <td><RunBadge status={r.status} /></td>
                  <td className="muted">{r.phase ? `${r.phase.current}/${r.phase.total} · ${r.phase.label}` : "—"}</td>
                  <td className="r num">{r.summary?.attempts ?? 0}</td>
                  <td className="r num">{r.summary?.findings_open ?? 0}</td>
                  <td className="muted">{fmtDate(r.started_at)}</td>
                </tr>))}
              </tbody>
            </table>
          </div>)}
      </Card>
      {run && (
        <div className="split even">
          <div className="stack"><ImportCard />
            <Card title="Imported files">{run.imports?.length ? (
              <ul className="files">{run.imports.map((i) => (
                <li key={i.id}><Icon name="file" size={15} /><div><b>{i.filename}</b>
                  <span>{i.tool}{i.tool_version && ` v${i.tool_version}`} · {i.stats.attempts_added ?? 0} attempts · {i.stats.trap_hits ?? 0} trap hits · by {i.imported_by}</span>
                  <span className="mono" title={i.sha256}>sha256 {i.sha256.slice(0, 24)}…</span></div></li>))}</ul>
            ) : <p className="muted sm">No files imported into {run.id}.</p>}</Card>
          </div>
          <Attempts />
        </div>)}
    </div>
  );
}
