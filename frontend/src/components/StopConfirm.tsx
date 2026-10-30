import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { useStore } from "../store";

export function StopConfirm({ onClose }: { onClose: () => void }) {
  const notify = useStore((s) => s.notify);
  const [reason, setReason] = useState("Emergency stop from console");
  const [busy, setBusy] = useState(false);
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    confirmRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); onClose(); } };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  const stop = async () => {
    setBusy(true);
    try {
      const r = await api.trip(reason);
      useStore.setState({ kill: r });
      notify("ok", "Emergency stop engaged.");
      onClose();
    } catch (e) {
      notify("error", `Stop failed: ${(e as Error).message}`);
      setBusy(false);
    }
  };

  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="stop-title" onClick={(e) => e.stopPropagation()}>
        <h3 id="stop-title">Engage emergency stop?</h3>
        <p className="muted sm" style={{ margin: 0 }}>
          Halts every active and paused run immediately, and blocks connectivity checks, live exchanges, imports,
          advisory reviews and new runs until an operator resets it. Halted runs stay halted. The action is written to the audit log.
        </p>
        <div className="field">
          <label htmlFor="stop-reason">Reason (audited)</label>
          <input id="stop-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button ref={confirmRef} className="btn danger" onClick={stop} disabled={busy}>{busy ? "Stopping…" : "Stop everything"}</button>
        </div>
      </div>
    </div>
  );
}
