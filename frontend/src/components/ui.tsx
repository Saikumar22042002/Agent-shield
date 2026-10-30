import type { ReactNode } from "react";
import type { AssessmentState, Provenance, RunStatus, Target } from "../api";

/* ---------- icons (24px stroke set, currentColor) ---------- */
const PATHS: Record<string, string> = {
  overview: "M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z",
  targets: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12zM12 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4z",
  workspace: "M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2zM8 9h8M8 13h5",
  runs: "M3 3v18h18M7 15l4-4 3 3 6-6",
  findings: "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01",
  audit: "M9 12l2 2 4-4M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5z",
  reports: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5",
  shield: "M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5z",
  plus: "M12 5v14M5 12h14",
  play: "M6 4l14 8-14 8z",
  pause: "M7 4h3v16H7zM14 4h3v16h-3z",
  stop: "M6 6h12v12H6z",
  check: "M20 6 9 17l-5-5",
  x: "M18 6 6 18M6 6l12 12",
  send: "M22 2 11 13M22 2l-7 20-4-9-9-4z",
  upload: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12",
  download: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3",
  refresh: "M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5",
  chevron: "M9 18l6-6-6-6",
  down: "M6 9l6 6 6-6",
  panel: "M3 3h18v18H3zM15 3v18",
  bolt: "M13 2 3 14h9l-1 8 10-12h-9z",
  file: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6",
  link: "M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7",
  eye: "M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
  cpu: "M4 4h16v16H4zM9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3",
  box: "M21 16V8l-9-5-9 5v8l9 5zM3.3 7 12 12l8.7-5M12 22V12",
  archive: "M21 8v13H3V8M1 3h22v5H1zM10 12h4",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  user: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",
  alert: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 8v4M12 16h.01",
  clock: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 6v6l4 2",
  hash: "M4 9h16M4 15h16M10 3 8 21M16 3l-2 18",
  menu: "M3 6h18M3 12h18M3 18h18",
};

export function Icon({ name, size = 16, className }: { name: keyof typeof PATHS | string; size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
         strokeLinecap="round" strokeLinejoin="round" aria-hidden className={className}>
      <path d={PATHS[name] ?? PATHS.box} />
    </svg>
  );
}

/* ---------- target status semantics ---------- */
const AUTH_CODES = ["AccessDeniedException", "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredToken",
  "ExpiredTokenException", "NoCredentialsError", "ProfileNotFound", "InvalidSignatureException", "SignatureDoesNotMatch"];

export type TargetState = "verified" | "stub" | "auth" | "error" | "untested" | "pending" | "archived";

export function errorParts(raw: string): { code: string; message: string; hint: string } {
  const [first, ...rest] = (raw || "").split("\n");
  const i = first.indexOf(":");
  return i > 0 ? { code: first.slice(0, i), message: first.slice(i + 1).trim(), hint: rest.join("\n").trim() }
    : { code: "", message: first, hint: rest.join("\n").trim() };
}

export function targetState(t: Target): TargetState {
  if (t.archived) return "archived";
  if (!t.provider_implemented) return "pending";
  if (t.status === "connected") return t.provider === "local_stub" ? "stub" : "verified";
  if (t.status === "error") return AUTH_CODES.some((c) => errorParts(t.last_error).code.startsWith(c)) ? "auth" : "error";
  return "untested";
}

const STATE_META: Record<TargetState, { label: string; tone: string; title: string }> = {
  verified: { label: "Verified", tone: "ok", title: "The last connectivity check reached the agent and got a reply (measured)." },
  stub: { label: "Local stub", tone: "stub", title: "Built-in development stub responding. Not a real agent." },
  auth: { label: "Authorization failed", tone: "err", title: "The cloud provider rejected the credentials or permissions." },
  error: { label: "Connection error", tone: "err", title: "The last connectivity check failed. See diagnostics." },
  untested: { label: "Untested", tone: "neutral", title: "No connectivity check has been run yet." },
  pending: { label: "Connector pending", tone: "neutral", title: "This platform's connector is not implemented yet." },
  archived: { label: "Archived", tone: "neutral", title: "Archived: no runs or checks." },
};

export function TargetBadge({ t }: { t: Target }) {
  const s = targetState(t);
  const m = STATE_META[s];
  return <span className={`badge ${m.tone}`} title={m.title}><span className="dot" />{m.label}</span>;
}

export function RunBadge({ status }: { status: RunStatus }) {
  const tone = { open: "live", paused: "warn", stopped: "neutral", halted: "err", complete: "ok" }[status];
  const label = { open: "Active", paused: "Paused", stopped: "Stopped", halted: "Halted", complete: "Complete" }[status];
  return <span className={`badge ${tone}`}><span className="dot" />{label}</span>;
}

const PROV: Record<Provenance, { label: string; title: string }> = {
  sent: { label: "Sent by AgentShield", title: "The fixed benign connectivity greeting, sent live during this run." },
  measured: { label: "Live · measured", title: "Received live from the target; metrics are as reported or measured." },
  "local-stub": { label: "Local stub", title: "Fixed reply from the built-in development stub. Not a real agent." },
  imported: { label: "Imported", title: "Recorded by your team's tool and imported from a hashed result file." },
  "model-judged": { label: "Advisory · model", title: "Advisory decision from DECISION_MODEL. Never changes the tool verdict." },
  derived: { label: "Derived", title: "Derived by AgentShield from imported verdicts and trap hits." },
  system: { label: "System", title: "Recorded by AgentShield." },
  executed: { label: "Executed", title: "Result of a framework execution through the AgentShield gateway in this run." },
  gateway: { label: "Gateway", title: "Recorded by the target gateway (for example a refused call)." },
};

const ASSESS: Record<AssessmentState, { label: string; tone: string }> = {
  idle: { label: "No plan", tone: "neutral" }, planned: { label: "Plan drafted", tone: "neutral" },
  approved: { label: "Plan approved", tone: "ok" }, queued: { label: "Queued", tone: "warn" },
  running: { label: "Executing", tone: "live" }, completed: { label: "Execution complete", tone: "ok" },
  stopped: { label: "Execution stopped", tone: "warn" }, interrupted: { label: "Interrupted", tone: "err" },
  error: { label: "Execution error", tone: "err" },
};

export function AssessmentBadge({ status }: { status: AssessmentState }) {
  const m = ASSESS[status] ?? ASSESS.idle;
  return <span className={`badge ${m.tone}`}><span className="dot" />{m.label}</span>;
}

export function ProvChip({ p }: { p: Provenance }) {
  const m = PROV[p] ?? PROV.system;
  return <span className={`prov prov-${p}`} title={m.title}>{m.label}</span>;
}

export function SevPill({ sev }: { sev: string }) {
  return <span className={`sev sev-${sev}`}>{sev}</span>;
}

export function Verdict({ v }: { v: string }) {
  return <span className={`verdict v-${v}`}>{v}</span>;
}

const CONFIRM: Record<string, { label: string; tone: string; title: string }> = {
  confirmed: { label: "Confirmed", tone: "err", title: "Direct evidence (trap hit, exact canary match) or an operator decision." },
  candidate: { label: "Candidate", tone: "warn", title: "A detector or scorer hit. Not a confirmed exploit until confirmed." },
  dismissed: { label: "Dismissed", tone: "neutral", title: "Ruled out by an operator. Not counted as open." },
};

export function ConfirmationBadge({ c }: { c: string }) {
  const m = CONFIRM[c] ?? CONFIRM.candidate;
  return <span className={`badge ${m.tone}`} title={m.title}><span className="dot" />{m.label}</span>;
}

/** A labelled bar: value of max (no bar when there is no max). */
export function Meter({ label, value, max, note, budget = true }: { label: string; value: number; max: number; note?: string;
  budget?: boolean }) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  const tone = pct >= 100 ? (budget ? "full" : "done") : "";
  return (
    <div className="meter">
      <div className="meter-h"><span>{label}</span><b className="num">{value}{max > 0 && <em> / {max}</em>}</b></div>
      <div className="meter-bar" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={max || undefined}
           aria-valuenow={value}><i style={{ width: `${pct}%` }} className={tone} /></div>
      {note && <span className="meter-note">{note}</span>}
    </div>
  );
}

export function Empty({ icon = "box", title, children, action }: { icon?: string; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-ic"><Icon name={icon} size={20} /></div>
      <b>{title}</b>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Card({ title, actions, children, className = "", pad = true }:
  { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && <header className="card-h">{title && <h3>{title}</h3>}{actions && <div className="row gap-2">{actions}</div>}</header>}
      <div className={pad ? "card-b" : ""}>{children}</div>
    </section>
  );
}

export function PageHead({ eyebrow, title, sub, actions }: { eyebrow?: string; title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {actions && <div className="row gap-2 wrap">{actions}</div>}
    </div>
  );
}

export const fmtTime = (iso: string | null | undefined) => iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
export const fmtDate = (iso: string | null | undefined) => iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—";
export const fmtMs = (ms: number | null | undefined) => ms == null ? "—" : ms < 1 ? "<1 ms" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`;

export function relTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export function providerIcon(key: string) {
  return key === "local_stub" || key === "local_model" ? "cpu" : "box";
}
