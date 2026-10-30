import { useEffect, useState } from "react";
import { useEventStream } from "./hooks";
import { useStore } from "./store";
import { Header, HaltBanner, Sidebar } from "./components/Shell";
import { Workspace } from "./components/Workspace";
import { Targets } from "./components/Targets";
import { Runs } from "./components/Runs";
import { Audit, Findings, Overview, Reports } from "./components/Pages";
import { StopConfirm } from "./components/StopConfirm";
import { Icon } from "./components/ui";

export default function App() {
  const boot = useStore((s) => s.boot);
  const booted = useStore((s) => s.booted);
  const view = useStore((s) => s.view);
  const kill = useStore((s) => s.kill);
  const toast = useStore((s) => s.toast);
  const announce = useStore((s) => s.announce);
  const [bootError, setBootError] = useState("");
  const [confirmStop, setConfirmStop] = useState(false);
  const [nav, setNav] = useState(false);
  useEventStream();

  // A new view starts at the top; otherwise it opens at the previous view's scroll offset.
  useEffect(() => {
    document.querySelector("main.content")?.scrollTo(0, 0);
    window.scrollTo(0, 0);
  }, [view]);

  const start = () => { setBootError(""); boot().catch((e) => setBootError(String(e.message ?? e))); };
  useEffect(start, [boot]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onAuth = () => useStore.getState().notify("error", "Access token missing or rejected. Enter a valid token in the sidebar.");
    window.addEventListener("agentshield:auth-required", onAuth);
    return () => window.removeEventListener("agentshield:auth-required", onAuth);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLElement && ["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName);
      if (e.key === "Escape" && !confirmStop && !kill.tripped && !typing) { e.preventDefault(); setConfirmStop(true); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [confirmStop, kill.tripped]);

  return (
    <div className={`app ${kill.tripped ? "halted" : ""}`}>
      <Sidebar open={nav} onClose={() => setNav(false)} />
      <div className="main">
        <Header onStop={() => setConfirmStop(true)} onMenu={() => setNav(true)} />
        <HaltBanner />
        <main className={`content view-${view}`}>
          {bootError ? (
            <div className="page"><div className="boot-err" role="alert">
              <Icon name="alert" size={22} />
              <div><b>Cannot reach the AgentShield API</b><p>{bootError}</p>
                <p className="muted">Start the backend with <span className="mono">.\dev.ps1</span> or <span className="mono">make dev</span>, then retry.</p></div>
              <button className="btn" onClick={start}><Icon name="refresh" size={14} />Retry</button>
            </div></div>
          ) : !booted ? (
            <div className="page"><div className="skeleton-list">{[0, 1, 2, 3].map((i) => <div key={i} className={`skeleton s${i % 3}`} />)}</div></div>
          ) : view === "overview" ? <Overview />
            : view === "targets" ? <Targets />
            : view === "workspace" ? <Workspace />
            : view === "runs" ? <Runs />
            : view === "findings" ? <Findings />
            : view === "audit" ? <Audit />
            : <Reports />}
        </main>
      </div>
      {confirmStop && <StopConfirm onClose={() => setConfirmStop(false)} />}
      {toast && <div className={`toast ${toast.kind}`} role="status"><Icon name={toast.kind === "ok" ? "check" : "alert"} size={15} />{toast.text}</div>}
      <div className="sr-only" aria-live="polite">{announce}</div>
    </div>
  );
}
