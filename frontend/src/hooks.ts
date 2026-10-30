import { useEffect, useRef, useState } from "react";
import { tokenQuery, type StreamEvent } from "./api";
import { useStore } from "./store";

const EVENT_TYPES = ["target.registered", "target.updated", "connectivity.start", "connectivity.result", "run.created",
  "run.completed", "run.summary", "run.status", "import.done", "kill.tripped", "kill.reset", "judge.done",
  "conversation.message", "conversation.pending", "conversation.delta", "conversation.error",
  "plan.created", "plan.approved", "plan.invalidated", "assessment.status", "assessment.case", "gateway.refused",
  "gateway.retry", "coordinator.start", "coordinator.step", "coordinator.done", "finding.review"];

const STALL_MS = 25000; // the server pings every 10 s while idle

/** Subscribes to /api/stream (SSE). EventSource reconnects on its own and sends Last-Event-ID, and the
 *  store drops any event id it has already seen, so a reconnect never duplicates messages.
 *  A watchdog also reopens the stream when it goes silent without erroring (e.g. a dev proxy that keeps
 *  the browser side open after the API restarts), resuming from the last id seen, then resyncs state. */
export function useEventStream() {
  const onEvent = useStore((s) => s.onEvent);
  const setStream = useStore((s) => s.setStream);
  useEffect(() => {
    let es: EventSource | null = null;
    let lastId = 0;
    let lastSeen = Date.now();
    let reopened = false;
    const handler = (e: MessageEvent) => {
      lastSeen = Date.now();
      const ev = JSON.parse(e.data) as StreamEvent;
      lastId = Math.max(lastId, ev.id);
      onEvent(ev);
    };
    const open = () => {
      es?.close();
      es = new EventSource(lastId ? `/api/stream?last_event_id=${lastId}${tokenQuery("&")}` : `/api/stream${tokenQuery("?")}`);
      EVENT_TYPES.forEach((t) => es!.addEventListener(t, handler as EventListener));
      es.addEventListener("ping", () => { lastSeen = Date.now(); });
      es.onopen = () => {
        lastSeen = Date.now();
        setStream(true);
        if (reopened) void useStore.getState().resync();
      };
      es.onerror = () => { setStream(false); reopened = true; };
    };
    open();
    const watchdog = window.setInterval(() => {
      if (Date.now() - lastSeen > STALL_MS) { setStream(false); reopened = true; lastSeen = Date.now(); open(); }
    }, 5000);
    return () => { window.clearInterval(watchdog); es?.close(); };
  }, [onEvent, setStream]);
}

const reduced = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/** Animates a number toward its target; instant under prefers-reduced-motion. */
export function useCountUp(value: number, ms = 600): number {
  const [shown, setShown] = useState(value);
  const from = useRef(value);
  useEffect(() => {
    if (reduced() || from.current === value) { setShown(value); from.current = value; return; }
    const start = performance.now();
    const a = from.current;
    let raf = 0;
    const tick = (t: number) => {
      const k = Math.min(1, (t - start) / ms);
      const eased = 1 - Math.pow(1 - k, 3);
      setShown(Math.round(a + (value - a) * eased));
      if (k < 1) raf = requestAnimationFrame(tick); else from.current = value;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, ms]);
  return shown;
}

/** Runs an async action with busy state and a toast on failure. */
export function useAction() {
  const notify = useStore((s) => s.notify);
  const [busy, setBusy] = useState(false);
  const run = async <T,>(fn: () => Promise<T>, ok?: string | ((r: T) => string)): Promise<T | undefined> => {
    setBusy(true);
    try {
      const r = await fn();
      if (ok) notify("ok", typeof ok === "function" ? ok(r) : ok);
      return r;
    } catch (e) {
      notify("error", (e as Error).message);
      return undefined;
    } finally { setBusy(false); }
  };
  return { busy, run };
}
