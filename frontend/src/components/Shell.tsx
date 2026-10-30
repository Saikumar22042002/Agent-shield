import { useState } from "react";
import { accessToken, api, setAccessToken } from "../api";
import { useAction } from "../hooks";
import { useStore, type View } from "../store";
import { Icon, RunBadge, TargetBadge } from "./ui";

const NAV: { view: View; label: string; icon: string }[] = [
  { view: "overview", label: "Overview", icon: "overview" },
  { view: "targets", label: "Targets", icon: "targets" },
  { view: "workspace", label: "Evaluation Workspace", icon: "workspace" },
  { view: "runs", label: "Runs & Results", icon: "runs" },
  { view: "findings", label: "Findings", icon: "findings" },
  { view: "audit", label: "Evidence & Audit", icon: "audit" },
  { view: "reports", label: "Reports", icon: "reports" },
];

function OperatorField() {
  const auth = useStore((s) => s.auth);
  const [name, setName] = useState(() => { try { return localStorage.getItem("agentshield.operator") ?? ""; } catch { return ""; } });
  if (auth?.required) return null; // with access tokens the audited name comes from the token
  return (
    <label className="operator" title="Recorded in the audit log with every action you take">
      <Icon name="user" size={14} />
      <input value={name} placeholder="Operator name" aria-label="Operator name (recorded in audit log)"
             onChange={(e) => { setName(e.target.value); try { localStorage.setItem("agentshield.operator", e.target.value); } catch { /* ignore */ } }} />
    </label>
  );
}

function TokenField() {
  const auth = useStore((s) => s.auth);
  const [token, setToken] = useState(() => accessToken());
  const [shown, setShown] = useState(false);
  if (!auth?.required && !token) return null;
  return (
    <div className="token-field">
      <label className="operator" title="Access token issued by your AgentShield administrator (AUTH_TOKENS)">
        <Icon name="hash" size={14} />
        <input type={shown ? "text" : "password"} value={token} placeholder="Access token" aria-label="Access token"
               autoComplete="off" onChange={(e) => setToken(e.target.value)}
               onKeyDown={(e) => { if (e.key === "Enter") { setAccessToken(token.trim()); window.location.reload(); } }} />
        <button className="icon-btn sm" type="button" onClick={() => setShown(!shown)} aria-label={shown ? "Hide token" : "Show token"}><Icon name="eye" size={13} /></button>
      </label>
      <button className="btn sm full" onClick={() => { setAccessToken(token.trim()); window.location.reload(); }}>Use token</button>
      {auth?.name && <span className="muted sm">Signed in as <b>{auth.name}</b> · {auth.role}</span>}
    </div>
  );
}

function ThemeToggle() {
  const cycle = () => {
    const root = document.documentElement;
    const dark = (root.dataset.theme ?? "dark") === "dark";
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("agentshield.theme", root.dataset.theme); } catch { /* ignore */ }
  };
  return <button className="icon-btn" onClick={cycle} aria-label="Toggle light or dark theme" title="Theme"><Icon name="sun" /></button>;
}

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { view, go, findings, runs } = useStore();
  const openFindings = findings.filter((f) => f.status === "open").length;
  const active = runs.filter((r) => r.status === "open").length;
  return (
    <>
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Primary">
        <div className="brand">
          <div className="brand-mark"><Icon name="shield" size={16} /></div>
          <div><b>AgentShield</b><span>AI Security Assessment</span></div>
        </div>
        <ul>
          {NAV.map((n) => (
            <li key={n.view}>
              <button className={`nav-item ${view === n.view ? "on" : ""}`} aria-current={view === n.view ? "page" : undefined}
                      onClick={() => { go(n.view); onClose(); }}>
                <Icon name={n.icon} size={17} />
                <span>{n.label}</span>
                {n.view === "findings" && openFindings > 0 && <em className="count">{openFindings}</em>}
                {n.view === "runs" && active > 0 && <em className="count live">{active}</em>}
              </button>
            </li>
          ))}
        </ul>
        <div className="sidebar-foot">
          <OperatorField />
          <TokenField />
          <p>Staging targets only · Target traffic: the connectivity greeting and operator-approved plans, through the gateway</p>
        </div>
      </nav>
      {open && <div className="scrim" onClick={onClose} />}
    </>
  );
}

export function Header({ onStop, onMenu }: { onStop: () => void; onMenu: () => void }) {
  const { targets, targetId, run, runs, runId, selectRun, selectTarget, kill, streamConnected } = useStore();
  const target = targets.find((t) => t.id === (run?.target_id ?? targetId));
  const targetRuns = runs.filter((r) => r.target_id === target?.id);
  return (
    <header className="header">
      <button className="icon-btn menu-btn" onClick={onMenu} aria-label="Open navigation"><Icon name="menu" /></button>
      <div className="ctx">
        <label className="ctx-sel">
          <span>Target</span>
          <select value={target?.id ?? ""} onChange={(e) => void selectTarget(e.target.value ? Number(e.target.value) : null)}
                  aria-label="Active target">
            {targets.length === 0 && <option value="">None registered</option>}
            {targets.filter((t) => !t.archived || t.id === target?.id).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </label>
        {target && <TargetBadge t={target} />}
        <span className="ctx-div" />
        <label className="ctx-sel">
          <span>Run</span>
          <select value={runId ?? ""} onChange={(e) => void selectRun(e.target.value || null)} aria-label="Active run">
            {targetRuns.length === 0 && <option value="">No runs</option>}
            {targetRuns.map((r) => <option key={r.id} value={r.id}>{r.id}{r.label ? ` · ${r.label}` : ""}{r.parent_run_id ? " (re-test)" : ""}</option>)}
          </select>
        </label>
        {run && <RunBadge status={run.status} />}
      </div>
      <div className="spacer" />
      <span className={`stream ${streamConnected ? "on" : ""}`} title={streamConnected ? "Live event stream connected" : "Live event stream reconnecting"}>
        <span className="live-dot" />{streamConnected ? "Live" : "Reconnecting"}
      </span>
      <ThemeToggle />
      <button className="btn danger" onClick={onStop} disabled={kill.tripped} title="Emergency stop (Esc)">
        <Icon name="stop" size={14} />Emergency stop
      </button>
    </header>
  );
}

export function HaltBanner() {
  const kill = useStore((s) => s.kill);
  const { busy, run } = useAction();
  if (!kill.tripped) return null;
  const reset = async () => {
    const r = await run(() => api.resetKill(), "Emergency stop reset. Halted runs stay halted.");
    if (r) useStore.setState({ kill: r });
  };
  return (
    <div className="halt" role="alert">
      <Icon name="alert" size={18} />
      <div><b>Emergency stop active.</b> Connectivity checks, live exchanges, imports, reviews and new runs are blocked.
        {kill.reason && <span className="reason"> Reason: {kill.reason}</span>}</div>
      <div className="spacer" />
      <ResetButton busy={busy} onReset={reset} />
    </div>
  );
}

function ResetButton({ busy, onReset }: { busy: boolean; onReset: () => void }) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) return <button className="btn light sm" onClick={() => setConfirming(true)}>Reset stop…</button>;
  return (
    <div className="row gap-2">
      <span>Resume operations?</span>
      <button className="btn light sm" disabled={busy} onClick={onReset}>Confirm reset</button>
      <button className="btn ghost-light sm" onClick={() => setConfirming(false)}>Cancel</button>
    </div>
  );
}
