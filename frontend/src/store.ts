import { create } from "zustand";
import { api, authHeaders, type Assessment, type Attempt, type AuditRow, type AuthInfo, type Catalog, type EngineConfig,
  type EnginesStatus, type Finding, type KillState, type Plan, type Provider, type Run, type StreamEvent, type Target,
  type Timeline } from "./api";

const load = (k: string) => { try { return localStorage.getItem(k); } catch { return null; } };
const save = (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };

export type View = "overview" | "targets" | "workspace" | "runs" | "findings" | "audit" | "reports";
export const VIEWS: View[] = ["overview", "targets", "workspace", "runs", "findings", "audit", "reports"];

/** A reply the target is still streaming. Removed once the persisted conversation.message arrives. */
export interface PendingReply { message_id: string; run_id: string; turn: number; text: string; seqs: number[] }

const viewFromHash = (): View => {
  const v = window.location.hash.replace(/^#\/?/, "").split("/")[0] as View;
  return VIEWS.includes(v) ? v : "overview";
};

interface State {
  view: View;
  config: EngineConfig | null;
  providers: Provider[];
  targets: Target[];
  targetId: number | null;
  runs: Run[];
  runId: string | null;
  run: Run | null;
  timeline: Timeline | null;
  timelineError: string;
  attempts: Attempt[];
  findings: Finding[];
  audit: AuditRow[];
  auditOk: boolean | null;
  events: StreamEvent[];
  pending: Record<string, PendingReply>;
  kill: KillState;
  streamConnected: boolean;
  booted: boolean;
  focusAttemptId: number | null;
  toast: { kind: "ok" | "error"; text: string } | null;
  announce: string;
  catalog: Catalog | null;
  engines: EnginesStatus | null;
  assessment: Assessment | null;
  plans: Plan[];
  auth: AuthInfo | null;

  boot: () => Promise<void>;
  go: (v: View) => void;
  refreshTargets: () => Promise<void>;
  selectTarget: (id: number | null) => Promise<void>;
  refreshRuns: () => Promise<void>;
  selectRun: (id: string | null) => Promise<void>;
  refreshRun: () => Promise<void>;
  refreshTimeline: () => Promise<void>;
  refreshAudit: () => Promise<void>;
  refreshAssessment: () => Promise<void>;
  resync: () => Promise<void>;
  onEvent: (ev: StreamEvent) => void;
  jumpToAttempt: (id: number) => void;
  notify: (kind: "ok" | "error", text: string) => void;
  setStream: (connected: boolean) => void;
}

let timelineTimer = 0;
let auditTimer = 0;
let assessmentTimer = 0;
const finished = new Set<string>(); // message ids whose final message/error event has arrived
let booting: Promise<void> | null = null; // boot is shared: StrictMode (dev) and retries must not load everything twice

/** Runs `fn` at most once per `ms`: the first event schedules it and later events in the window join that call.
 *  (A debounce would postpone the refresh for as long as a busy stream keeps sending events.) */
function throttle(timer: number, ms: number, fn: () => void, set: (t: number) => void) {
  if (timer) return;
  set(window.setTimeout(() => { set(0); fn(); }, ms));
}

export const useStore = create<State>((set, get) => ({
  view: viewFromHash(), config: null, providers: [], targets: [], targetId: null, runs: [], runId: null, run: null,
  timeline: null, timelineError: "", attempts: [], findings: [], audit: [], auditOk: null, events: [], pending: {},
  kill: { tripped: false, reason: "", tripped_at: null }, streamConnected: false, booted: false,
  focusAttemptId: null, toast: null, announce: "", catalog: null, engines: null, assessment: null, plans: [], auth: null,

  boot: () => {
    if (!booting) booting = (async () => {
      const auth = await api.auth();
      set({ auth });
      if (!auth.authenticated) throw new Error("This AgentShield deployment requires an access token. Enter it in the sidebar, then retry.");
      const [config, kill, providers, history, catalog, engines] = await Promise.all([api.config(), api.kill(),
        api.providers(), api.events(), api.catalog(), api.engines()]);
      // persisted history first; live SSE events are merged in by id afterwards
      set((s) => ({ config, kill, providers, catalog, engines,
        events: [...history, ...s.events.filter((e) => !history.some((h) => h.id === e.id))].sort((a, b) => a.id - b.id) }));
      await Promise.all([get().refreshTargets(), get().refreshRuns(), get().refreshAudit()]);
      const savedRun = get().runs.find((r) => r.id === load("agentshield.run"));
      const savedTarget = Number(load("agentshield.target"));
      const tid = savedRun?.target_id ?? (get().targets.some((t) => t.id === savedTarget) ? savedTarget : null)
        ?? get().targets.find((t) => !t.archived)?.id ?? null;
      await get().selectTarget(tid);
      if (savedRun) await get().selectRun(savedRun.id);
      set({ booted: true });
      window.addEventListener("hashchange", () => set({ view: viewFromHash() }));
    })().catch((e) => { booting = null; throw e; }); // a failed boot can be retried
    return booting;
  },
  go: (view) => {
    if (window.location.hash !== `#/${view}`) window.location.hash = `#/${view}`;
    set({ view });
  },
  refreshTargets: async () => set({ targets: await api.targets() }),
  selectTarget: async (id) => {
    set({ targetId: id });
    if (id != null) save("agentshield.target", String(id));
    const runs = get().runs.filter((r) => r.target_id === id);
    if (!runs.some((r) => r.id === get().runId)) await get().selectRun(runs[0]?.id ?? null);
  },
  refreshRuns: async () => {
    const runs = await api.runs();
    set((s) => ({ runs, run: s.run ? { ...s.run, ...(runs.find((r) => r.id === s.run!.id) ?? {}) } : s.run }));
  },
  selectRun: async (id) => {
    if (id === get().runId && get().run) return;
    set({ runId: id, run: null, timeline: null, timelineError: "", attempts: [], findings: [], focusAttemptId: null,
      assessment: null, plans: [] });
    if (id) {
      save("agentshield.run", id);
      const r = get().runs.find((x) => x.id === id);
      if (r && r.target_id !== get().targetId) set({ targetId: r.target_id });
      await Promise.all([get().refreshRun(), get().refreshTimeline(), get().refreshAssessment()]);
    }
  },
  refreshRun: async () => {
    const id = get().runId;
    if (!id) return;
    const [run, attempts, findings] = await Promise.all([api.run(id), api.attempts(id), api.findings(id)]);
    if (get().runId !== id) return;
    const before = new Set(get().findings.map((f) => f.id));
    const fresh = findings.filter((f) => !before.has(f.id) && get().findings.length > 0);
    set({ run, attempts, findings, announce: fresh.length ? `${fresh.length} new finding(s)` : get().announce });
  },
  refreshTimeline: async () => {
    const id = get().runId;
    if (!id) return;
    try {
      const timeline = await api.timeline(id);
      if (get().runId !== id) return;
      // drop streaming placeholders whose persisted message (or error) has arrived
      const done = new Set(timeline.items.map((i) => i.message_id).filter(Boolean));
      set((s) => ({ timeline, timelineError: "", run: s.run ? { ...s.run, ...timeline.run, imports: s.run.imports } : timeline.run,
        pending: Object.fromEntries(Object.entries(s.pending).filter(([k]) => !done.has(k))) }));
    } catch (e) { set({ timelineError: (e as Error).message }); }
  },
  refreshAudit: async () => {
    const [audit, v] = await Promise.all([api.audit(), api.verifyAudit()]);
    set({ audit, auditOk: v.ok });
  },
  refreshAssessment: async () => {
    const id = get().runId;
    if (!id) return;
    try {
      const [assessment, plans] = await Promise.all([api.assessment(id), api.plans(id)]);
      if (get().runId === id) set({ assessment, plans });
    } catch { /* run removed or API restarting; the next event retries */ }
  },
  resync: async () => {
    // after a stream gap: re-read everything the stream would have told us about
    try {
      const [kill] = await Promise.all([api.kill(), get().refreshTargets(), get().refreshRuns(), get().refreshAudit()]);
      set({ kill });
      await Promise.all([get().refreshRun(), get().refreshTimeline(), get().refreshAssessment()]);
    } catch { /* API still down; the next reconnect retries */ }
  },
  onEvent: (ev) => {
    if (get().events.some((e) => e.id === ev.id)) return; // replayed after reconnect
    if (ev.type !== "conversation.delta") set((s) => ({ events: [...s.events.slice(-799), ev] }));
    const { runId } = get();
    const mine = ev.run_id != null && ev.run_id === runId;
    const scheduleTimeline = () => throttle(timelineTimer, 250, () => void get().refreshTimeline(), (t) => { timelineTimer = t; });
    const scheduleAssessment = () => throttle(assessmentTimer, 300, () => void get().refreshAssessment(), (t) => { assessmentTimer = t; });
    switch (ev.type) {
      case "conversation.pending": {
        // The stream can deliver this after a timeline fetch that already holds the finished reply; showing a
        // placeholder then would display the reply twice.
        const persisted = get().timeline?.items.some((i) => i.message_id === ev.data.message_id);
        if (mine && !persisted && !finished.has(ev.data.message_id)) set((s) => ({ pending: { ...s.pending, [ev.data.message_id]: {
          message_id: ev.data.message_id, run_id: ev.run_id!, turn: ev.data.turn, text: "", seqs: [] } } }));
        break;
      }
      case "conversation.delta": {
        if (!mine) break;
        const p = get().pending[ev.data.message_id];
        if (!p || p.seqs.includes(ev.data.seq)) break;
        set((s) => ({ pending: { ...s.pending, [p.message_id]: { ...p, text: p.text + ev.data.text, seqs: [...p.seqs, ev.data.seq] } } }));
        return; // no audit refresh per delta
      }
      case "conversation.message":
      case "conversation.error":
        if (ev.data.message_id) {
          finished.add(ev.data.message_id);
          if (get().pending[ev.data.message_id]) {
            set((s) => ({ pending: Object.fromEntries(Object.entries(s.pending).filter(([k]) => k !== ev.data.message_id)) }));
          }
        }
        if (mine) scheduleTimeline();
        break;
      case "kill.tripped":
        set({ kill: { tripped: true, reason: String(ev.data.reason ?? ""), tripped_at: Date.now() / 1000 } });
        void get().refreshRuns(); void get().refreshRun(); scheduleTimeline();
        break;
      case "kill.reset":
        set({ kill: { tripped: false, reason: "", tripped_at: null } });
        scheduleTimeline();
        break;
      case "target.registered":
      case "target.updated":
      case "connectivity.result":
        void get().refreshTargets();
        if (mine) scheduleTimeline();
        break;
      case "run.created":
      case "run.completed":
      case "run.status":
        void get().refreshRuns();
        if (mine) { void get().refreshRun(); scheduleTimeline(); }
        break;
      case "plan.created":
      case "plan.approved":
      case "plan.invalidated":
      case "assessment.case":
      case "gateway.refused":
      case "gateway.retry":
      case "coordinator.start":
      case "coordinator.step":
      case "coordinator.done":
        if (mine) { scheduleAssessment(); scheduleTimeline(); }
        if (ev.type === "plan.invalidated") void get().refreshRuns();
        break;
      case "finding.review":
        if (mine) { void get().refreshRun(); scheduleTimeline(); }
        break;
      case "assessment.status":
        if (mine) { scheduleAssessment(); scheduleTimeline(); void get().refreshRun(); }
        void get().refreshRuns();
        break;
      case "import.done":
      case "run.summary":
      case "judge.done":
        if (mine) { void get().refreshRun(); scheduleTimeline(); }
        if (ev.type === "run.summary") void get().refreshRuns();
        break;
      default:
        if (mine) scheduleTimeline();
    }
    // The audit log is fetched only while it is on screen; otherwise it is refreshed when the view opens.
    if (get().view === "audit" || get().view === "overview") {
      throttle(auditTimer, 600, () => void get().refreshAudit(), (t) => { auditTimer = t; });
    }
  },
  jumpToAttempt: (id) => { set({ focusAttemptId: id }); get().go("workspace"); },
  notify: (kind, text) => {
    set({ toast: { kind, text } });
    window.setTimeout(() => { if (get().toast?.text === text) set({ toast: null }); }, 6000);
  },
  setStream: (streamConnected) => set({ streamConnected }),
}));

/** Downloads the run's PDF with the operator header, so the export is attributed in the audit log. */
export async function downloadReport(runId: string): Promise<void> {
  const res = await fetch(`/api/runs/${runId}/report.pdf`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`Report export failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `agentshield-${runId}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}
