import { Fragment, useEffect, useState } from "react";
import { api, type Provider, type Target } from "../api";
import { useAction } from "../hooks";
import { useStore } from "../store";
import { EditTargetForm, ProfileEditor } from "./TargetEditors";
import { Card, Empty, errorParts, fmtDate, fmtMs, Icon, PageHead, providerIcon, relTime, TargetBadge, targetState } from "./ui";

const FIELD_LABELS: Record<string, string> = {
  endpoint: "Agent endpoint URL", agent_id: "Agent ID", resource_name: "Agent resource name", location: "Location",
  base_url: "Base URL (loopback)", model: "Model name", system_prompt: "System prompt", temperature: "Temperature",
  reply_delay_ms: "Reply delay (ms)",
};

function ProviderPicker({ value, onChange }: { value: string; onChange: (k: string) => void }) {
  const providers = useStore((s) => s.providers);
  return (
    <div className="provider-grid" role="radiogroup" aria-label="Platform">
      {providers.map((p) => (
        <button type="button" key={p.key} role="radio" aria-checked={value === p.key}
                className={`provider ${value === p.key ? "on" : ""}`} onClick={() => onChange(p.key)}>
          <span className="provider-ic"><Icon name={providerIcon(p.key)} size={18} /></span>
          <span className="provider-txt"><b>{p.label}</b>
            <span>{p.key === "local_stub" ? "No credentials needed" : p.key === "local_model" ? "Model on this machine" : p.implemented ? "Connector ready" : "Connector pending · inventory only"}</span></span>
          {value === p.key && <Icon name="check" size={15} className="provider-tick" />}
        </button>
      ))}
    </div>
  );
}

function RegisterForm({ onDone }: { onDone: () => void }) {
  const { providers, refreshTargets, selectTarget } = useStore();
  const [provider, setProvider] = useState("aws_agentcore");
  const spec = providers.find((p) => p.key === provider) as Provider | undefined;
  const [f, setF] = useState({ name: "", harness_arn: "", region: "us-east-1", qualifier: "", aws_profile: "", aws_role_arn: "",
    owner_attestation: "" });
  const [cfg, setCfg] = useState<Record<string, string>>({});
  const { busy, run } = useAction();
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const pick = (k: string) => {
    setProvider(k);
    if (k === "local_stub") setF((x) => ({ ...x, name: x.name || "Local stub (development)",
      owner_attestation: x.owner_attestation || "Built-in AgentShield development stub; no external system is contacted." }));
  };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const t = await run(() => api.createTarget({ ...f, provider, config: cfg, environment: "staging" }), (x) => `Target "${x.name}" registered.`);
    if (t) { await refreshTargets(); await selectTarget(t.id); onDone(); }
  };
  return (
    <form onSubmit={submit} className="form">
      <div className="form-sec"><h4>1 · Platform</h4><ProviderPicker value={provider} onChange={pick} />
        {spec?.note && <p className="hint">{spec.note}</p>}</div>
      <div className="form-sec"><h4>2 · Identity</h4>
        <div className="field"><label htmlFor="t-name">Display name</label>
          <input id="t-name" value={f.name} onChange={set("name")} required placeholder="e.g. IT service desk assistant (staging)" /></div>
        {provider === "aws_agentcore" && <>
          <div className="field"><label htmlFor="t-arn">Harness ARN</label>
            <input id="t-arn" className="mono" value={f.harness_arn} onChange={set("harness_arn")} required
                   placeholder="arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/name-abcdefghij" /></div>
          <div className="grid-2">
            <div className="field"><label htmlFor="t-region">Region</label><input id="t-region" value={f.region} onChange={set("region")} required /></div>
            <div className="field"><label htmlFor="t-q">Qualifier <i>optional</i></label><input id="t-q" value={f.qualifier} onChange={set("qualifier")} /></div>
            <div className="field"><label htmlFor="t-prof">AWS profile <i>optional</i></label><input id="t-prof" value={f.aws_profile} onChange={set("aws_profile")} placeholder="default chain / instance role" /></div>
            <div className="field"><label htmlFor="t-role">Role to assume <i>optional</i></label><input id="t-role" className="mono" value={f.aws_role_arn} onChange={set("aws_role_arn")} placeholder="arn:aws:iam::…:role/…" /></div>
          </div>
          <p className="hint">Credentials come from the AWS credential chain and are never stored. The identity needs <span className="mono">bedrock-agentcore:InvokeHarness</span> on this ARN.</p>
        </>}
        {spec && spec.config_fields.map((k) => (
          <div className="field" key={k}><label htmlFor={`c-${k}`}>{FIELD_LABELS[k] ?? k}</label>
            <input id={`c-${k}`} value={cfg[k] ?? ""} required onChange={(e) => setCfg({ ...cfg, [k]: e.target.value })} /></div>
        ))}
        {provider === "local_stub" && <p className="hint">The stub answers locally with fixed text that says it is a stub. Use it to test the console, run controls, streaming and audit trail. It is never shown as a real agent.</p>}
        {provider === "local_model" && <p className="hint">An OpenAI-compatible server on this machine, e.g. Ollama at <span className="mono">http://127.0.0.1:11434/v1</span>. Only loopback URLs are accepted. Replies come from a real model, so results count as security evidence.</p>}
      </div>
      <div className="form-sec"><h4>3 · Authorization</h4>
        <div className="field"><label>Environment</label><input value="Staging (enforced)" readOnly aria-readonly /></div>
        <div className="field"><label htmlFor="t-att">Ownership / authorization statement</label>
          <textarea id="t-att" value={f.owner_attestation} onChange={set("owner_attestation")} required minLength={10}
                    placeholder="We own and operate this staging agent; testing is authorised under engagement …" />
          <span className="hint">Recorded verbatim in the audit log.</span></div>
      </div>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onDone}>Cancel</button>
        <button className="btn primary" disabled={busy}>{busy ? "Registering…" : "Register target"}</button>
      </div>
    </form>
  );
}

function Diagnostics({ t }: { t: Target }) {
  const { kill, config, refreshTargets, notify } = useStore();
  const { busy, run } = useAction();
  const [mode, setMode] = useState<"view" | "edit" | "profile">("view");
  useEffect(() => { setMode("view"); }, [t.id]);
  const st = targetState(t);
  const err = errorParts(t.last_error);
  const test = async () => {
    const r = await run(() => api.check(t.id));
    await refreshTargets(); // don't wait for the stream event to show the result
    if (r) notify(r.status === "connected" ? "ok" : "error",
      r.status === "connected" ? `Connected · ${fmtMs(r.wall_ms)} round trip` : `${r.error_code || "Error"}: see diagnostics below`);
  };
  const archive = async () => { await run(() => api.archiveTarget(t.id, !t.archived), t.archived ? "Target restored." : "Target archived."); await refreshTargets(); };
  return (
    <div className="diag-panel">
      <div className="diag-head">
        <div className="provider-ic lg"><Icon name={providerIcon(t.provider)} size={22} /></div>
        <div><h2>{t.name}</h2><span className="muted">{t.provider_label} · Staging · registered {fmtDate(t.created_at)}</span></div>
        <div className="spacer" />
        <TargetBadge t={t} />
      </div>

      <div className="row gap-2 wrap">
        <button className="btn primary" onClick={test} disabled={busy || kill.tripped || !t.provider_implemented || t.archived}>
          {busy ? <><span className="spin" />Testing…</> : <><Icon name="refresh" size={14} />Test connection</>}</button>
        <button className="btn" onClick={() => setMode(mode === "edit" ? "view" : "edit")} aria-pressed={mode === "edit"}><Icon name="file" size={14} />Edit</button>
        <button className="btn" onClick={() => setMode(mode === "profile" ? "view" : "profile")} aria-pressed={mode === "profile"}><Icon name="user" size={14} />Profile</button>
        <button className="btn" onClick={archive} disabled={busy}><Icon name="archive" size={14} />{t.archived ? "Restore" : "Archive"}</button>
        {kill.tripped && <span className="warn-text sm">Emergency stop active: checks are blocked.</span>}
        {!t.provider_implemented && <span className="muted sm">Connector not implemented, so connectivity cannot be tested.</span>}
      </div>

      {mode === "edit" && <EditTargetForm t={t} onDone={() => setMode("view")} />}
      {mode === "profile" && <ProfileEditor t={t} onDone={() => setMode("view")} />}
      {mode === "view" && (st === "auth" || st === "error") && (
        <div className={`callout ${st === "auth" ? "err" : "warn"}`}>
          <div className="callout-h"><Icon name="alert" size={16} /><b>{st === "auth" ? "Authorization failed" : "Connection failed"}</b>
            <span className="mono">{err.code}</span></div>
          <div className="callout-row"><span>Provider message</span><p>{err.message || "—"}</p></div>
          {err.hint && <div className="callout-row"><span>What to check</span><p>{err.hint}</p></div>}
          {st === "auth" && t.provider === "aws_agentcore" && (
            <ol className="callout-steps">
              <li>Confirm the identity: <span className="mono">aws sts get-caller-identity{t.aws_profile ? ` --profile ${t.aws_profile}` : ""}</span></li>
              <li>Refresh credentials (<span className="mono">aws sso login</span> or <span className="mono">aws configure</span>) if the token is invalid or expired.</li>
              <li>Grant <span className="mono">bedrock-agentcore:InvokeHarness</span> on <span className="mono">{t.harness_arn}</span>.</li>
            </ol>)}
        </div>)}
      {st === "stub" && <div className="callout stub"><Icon name="cpu" size={16} />The local stub is responding. Its replies are fixed text from AgentShield, not from a real agent or model.</div>}
      {st === "untested" && <div className="callout neutral"><Icon name="clock" size={16} />Not tested yet. Test connection sends one fixed, benign greeting and records measured latency.</div>}

      <div className="metrics">
        <div><span>Last check</span><b>{relTime(t.last_check_at)}</b><em>{fmtDate(t.last_check_at)}</em></div>
        <div title="Service-reported latency (metadata.metrics.latencyMs)"><span>Service latency</span><b>{fmtMs(t.last_latency_ms)}</b><em>{t.provider === "local_stub" ? "n/a for stub" : "reported by target"}</em></div>
        <div title="Measured by AgentShield"><span>Round trip</span><b>{fmtMs(t.last_wall_ms)}</b><em>measured</em></div>
        <div title="Token usage reported by the target"><span>Tokens</span><b>{t.last_usage?.totalTokens ?? "—"}</b>
          <em>{t.last_usage?.totalTokens != null ? `${t.last_usage.inputTokens} in · ${t.last_usage.outputTokens} out` : "not reported"}</em></div>
      </div>

      <dl className="kv wide">
        {t.harness_arn && <><dt>Harness ARN</dt><dd className="mono">{t.harness_arn}</dd></>}
        {t.provider === "aws_agentcore" && <><dt>Region</dt><dd className="mono">{t.region}</dd>
          <dt>Qualifier</dt><dd className="mono">{t.qualifier || "—"}</dd>
          <dt>Credentials</dt><dd>{t.aws_role_arn ? <>assume <span className="mono">{t.aws_role_arn}</span></> : t.aws_profile ? <>profile <span className="mono">{t.aws_profile}</span></> : "default credential chain / instance role"}</dd></>}
        {Object.entries(t.config).map(([k, v]) => <Fragment key={k}><dt>{FIELD_LABELS[k] ?? k}</dt><dd className="mono">{v}</dd></Fragment>)}
        <dt>Greeting sent</dt><dd>{config?.connectivity_message}</dd>
        <dt>Authorization</dt><dd>{t.owner_attestation}</dd>
      </dl>
    </div>
  );
}

export function Targets() {
  const { targets, targetId, selectTarget } = useStore();
  const [adding, setAdding] = useState(targets.length === 0);
  const [showArchived, setShowArchived] = useState(false);
  const list = targets.filter((t) => showArchived || !t.archived);
  const sel = targets.find((t) => t.id === targetId) ?? list[0];
  return (
    <div className="page">
      <PageHead eyebrow="Inventory" title="Targets" sub="Staging agents you own or are authorised to assess, across platforms."
                actions={<button className="btn primary" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add target</button>} />
      <div className="split">
        <Card title={`${list.length} target${list.length === 1 ? "" : "s"}`} pad={false}
              actions={targets.some((t) => t.archived) && <label className="check sm"><input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />Archived</label>}>
          {list.length === 0 ? <Empty icon="targets" title="No targets">Add an AWS AgentCore harness, or the local stub for development.</Empty> : (
            <ul className="target-list">
              {list.map((t) => (
                <li key={t.id}>
                  <button className={`target-row ${sel?.id === t.id && !adding ? "on" : ""}`} onClick={() => { setAdding(false); void selectTarget(t.id); }}>
                    <span className="provider-ic"><Icon name={providerIcon(t.provider)} size={16} /></span>
                    <span className="target-row-txt"><b>{t.name}</b><span>{t.provider_label}</span></span>
                    <TargetBadge t={t} />
                  </button>
                </li>))}
            </ul>)}
        </Card>
        <Card>{adding || !sel ? <><h2 className="card-title">Add a target</h2><RegisterForm onDone={() => setAdding(false)} /></> : <Diagnostics t={sel} />}</Card>
      </div>
    </div>
  );
}
