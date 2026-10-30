import { useEffect, useState } from "react";
import { api, type Target, type TargetProfile, type ToolSpec } from "../api";
import { useAction } from "../hooks";
import { useStore } from "../store";
import { Icon } from "./ui";

const FIELD_LABELS: Record<string, string> = {
  endpoint: "Agent endpoint URL", agent_id: "Agent ID", resource_name: "Agent resource name", location: "Location",
  base_url: "Base URL (loopback)", model: "Model name", system_prompt: "System prompt", temperature: "Temperature",
  reply_delay_ms: "Reply delay (ms)",
};

/* ---------------------------------------------------------------- A2: edit a registered target */
export function EditTargetForm({ t, onDone }: { t: Target; onDone: () => void }) {
  const { providers, refreshTargets } = useStore();
  const spec = providers.find((p) => p.key === t.provider);
  const [f, setF] = useState({ name: t.name, harness_arn: t.harness_arn, region: t.region, qualifier: t.qualifier,
    aws_profile: t.aws_profile, aws_role_arn: t.aws_role_arn, owner_attestation: t.owner_attestation });
  const [cfg, setCfg] = useState<Record<string, string>>({ ...t.config });
  const { busy, run } = useAction();
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  const fields = [...(spec?.config_fields ?? []), ...(spec?.optional_fields ?? [])];
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = t.provider === "aws_agentcore" ? { ...f } : { name: f.name, owner_attestation: f.owner_attestation, config: cfg };
    const r = await run(() => api.updateTarget(t.id, body), "Target updated.");
    if (r) { await refreshTargets(); onDone(); }
  };
  return (
    <form onSubmit={submit} className="form" aria-label={`Edit ${t.name}`}>
      <div className="form-sec"><h4>Identity</h4>
        <div className="field"><label htmlFor="e-name">Display name</label><input id="e-name" value={f.name} onChange={set("name")} required /></div>
        {t.provider === "aws_agentcore" && <>
          <div className="field"><label htmlFor="e-arn">Harness ARN</label><input id="e-arn" className="mono" value={f.harness_arn} onChange={set("harness_arn")} required /></div>
          <div className="grid-2">
            <div className="field"><label htmlFor="e-region">Region</label><input id="e-region" value={f.region} onChange={set("region")} required /></div>
            <div className="field"><label htmlFor="e-q">Qualifier <i>optional</i></label><input id="e-q" value={f.qualifier} onChange={set("qualifier")} /></div>
            <div className="field"><label htmlFor="e-prof">AWS profile <i>optional</i></label><input id="e-prof" value={f.aws_profile} onChange={set("aws_profile")} /></div>
            <div className="field"><label htmlFor="e-role">Role to assume <i>optional</i></label><input id="e-role" className="mono" value={f.aws_role_arn} onChange={set("aws_role_arn")} /></div>
          </div></>}
        {fields.map((k) => (
          <div className="field" key={k}><label htmlFor={`e-c-${k}`}>{FIELD_LABELS[k] ?? k}{!spec?.config_fields.includes(k) && <i>optional</i>}</label>
            <input id={`e-c-${k}`} value={cfg[k] ?? ""} required={spec?.config_fields.includes(k)}
                   onChange={(e) => setCfg({ ...cfg, [k]: e.target.value })} /></div>))}
        <p className="hint">Changing how the target is reached marks it unverified and withdraws any approved plan on its open runs. Provider and environment cannot change: register a new target instead.</p>
      </div>
      <div className="form-sec"><h4>Authorization</h4>
        <div className="field"><label htmlFor="e-att">Ownership / authorization statement</label>
          <textarea id="e-att" value={f.owner_attestation} onChange={set("owner_attestation")} required minLength={10} /></div>
      </div>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onDone}>Cancel</button>
        <button className="btn primary" disabled={busy}>{busy ? "Saving…" : "Save changes"}</button>
      </div>
    </form>
  );
}

/* ---------------------------------------------------------------- A7: target profile editor */
const lines = (v: string[]) => v.join("\n");
const toList = (v: string) => v.split("\n").map((x) => x.trim()).filter(Boolean);

export function ProfileEditor({ t, onDone }: { t: Target; onDone: () => void }) {
  const [p, setP] = useState<TargetProfile | null>(null);
  const [error, setError] = useState("");
  const { busy, run } = useAction();
  useEffect(() => {
    let live = true;
    api.profile(t.id).then((x) => { if (live) setP(x); }).catch((e) => setError((e as Error).message));
    return () => { live = false; };
  }, [t.id]);
  if (error) return <p className="note-err">{error}</p>;
  if (!p) return <div className="skeleton s1" />;
  const upd = (patch: Partial<TargetProfile>) => setP({ ...p, ...patch });
  const hint = (k: keyof TargetProfile["hints"]) => (e: React.ChangeEvent<HTMLInputElement>) =>
    upd({ hints: { ...p.hints, [k]: k === "output_limit_chars" ? Number(e.target.value || 0) : e.target.value } });
  const setTool = (i: number, patch: Partial<ToolSpec>) => upd({ tools: p.tools.map((x, n) => (n === i ? { ...x, ...patch } : x)) });
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    const { documented: _d, capabilities: _c, ...body } = p;
    void _d; void _c;
    const r = await run(() => api.saveProfile(t.id, { ...body, tools: body.tools.filter((x) => x.name.trim()) }),
      "Profile saved. Plans approved against the previous profile need a new plan and approval.");
    if (r) onDone();
  };
  return (
    <form onSubmit={save} className="form" aria-label={`Profile of ${t.name}`}>
      <p className="hint">The profile drives which techniques apply, the rationale in each plan, and objective scoring (canaries you planted). Saving a changed profile withdraws approval of existing plans.</p>
      <div className="form-sec"><h4>Role</h4>
        <div className="field"><label htmlFor="p-role">Role</label><input id="p-role" value={p.role} onChange={(e) => upd({ role: e.target.value })} placeholder="e.g. IT service desk assistant for employees" /></div>
        <div className="field"><label htmlFor="p-desc">Description</label><textarea id="p-desc" value={p.description} onChange={(e) => upd({ description: e.target.value })} /></div>
        <div className="field"><label htmlFor="p-exp">Expected behaviour</label><textarea id="p-exp" value={p.expected_behavior} onChange={(e) => upd({ expected_behavior: e.target.value })} /></div>
      </div>
      <div className="form-sec"><h4>Capabilities and data</h4>
        <div className="row gap-2 wrap">
          <label className="check"><input type="checkbox" checked={p.has_rag} onChange={(e) => upd({ has_rag: e.target.checked })} />Retrieves documents (RAG)</label>
          <label className="check"><input type="checkbox" checked={p.has_memory} onChange={(e) => upd({ has_memory: e.target.checked })} />Long-term memory</label>
          <label className="check"><input type="checkbox" checked={p.has_records} onChange={(e) => upd({ has_records: e.target.checked })} />Per-user records</label>
        </div>
        <div className="grid-2">
          <div className="field"><label htmlFor="p-sens">Data sensitivity</label>
            <select id="p-sens" value={p.data_sensitivity} onChange={(e) => upd({ data_sensitivity: e.target.value })}>
              {["public", "internal", "confidential", "restricted"].map((x) => <option key={x}>{x}</option>)}</select></div>
          <div className="field"><label htmlFor="p-types">Data types <i>one per line</i></label>
            <textarea id="p-types" value={lines(p.data_types)} onChange={(e) => upd({ data_types: toList(e.target.value) })} /></div>
        </div>
      </div>
      <div className="form-sec"><h4>Tools</h4>
        {p.tools.map((x, i) => (
          <div key={i} className="tool-row">
            <input className="input" value={x.name} placeholder="tool name" aria-label={`Tool ${i + 1} name`} onChange={(e) => setTool(i, { name: e.target.value })} />
            <input className="input" value={x.description} placeholder="what it does" aria-label={`Tool ${i + 1} description`} onChange={(e) => setTool(i, { description: e.target.value })} />
            <label className="check sm"><input type="checkbox" checked={x.privileged} onChange={(e) => setTool(i, { privileged: e.target.checked })} />privileged</label>
            <button type="button" className="icon-btn" aria-label={`Remove tool ${i + 1}`} onClick={() => upd({ tools: p.tools.filter((_, n) => n !== i) })}><Icon name="x" size={14} /></button>
          </div>))}
        <button type="button" className="btn sm" onClick={() => upd({ tools: [...p.tools, { name: "", description: "", privileged: false }] })}><Icon name="plus" size={13} />Add tool</button>
      </div>
      <div className="form-sec"><h4>Policy</h4>
        <div className="grid-2">
          <div className="field"><label htmlFor="p-perm">Permissions <i>one per line</i></label><textarea id="p-perm" value={lines(p.permissions)} onChange={(e) => upd({ permissions: toList(e.target.value) })} /></div>
          <div className="field"><label htmlFor="p-pol">Policies <i>one per line</i></label><textarea id="p-pol" value={lines(p.policies)} onChange={(e) => upd({ policies: toList(e.target.value) })} /></div>
        </div>
        <div className="field"><label htmlFor="p-forb">Forbidden actions <i>one per line</i></label><textarea id="p-forb" value={lines(p.forbidden_actions)} onChange={(e) => upd({ forbidden_actions: toList(e.target.value) })} /></div>
      </div>
      <div className="form-sec"><h4>Assessment hints (values you planted or know)</h4>
        <div className="grid-2">
          <div className="field"><label htmlFor="h-canary">Context canary</label><input id="h-canary" className="mono" value={p.hints.context_canary} onChange={hint("context_canary")} placeholder="unique string in the system prompt" /></div>
          <div className="field"><label htmlFor="h-excerpt">System prompt excerpt</label><input id="h-excerpt" value={p.hints.context_excerpt} onChange={hint("context_excerpt")} /></div>
          <div className="field"><label htmlFor="h-doc">Planted document</label><input id="h-doc" value={p.hints.planted_document} onChange={hint("planted_document")} /></div>
          <div className="field"><label htmlFor="h-marker">Planted marker</label><input id="h-marker" className="mono" value={p.hints.planted_marker} onChange={hint("planted_marker")} /></div>
          <div className="field"><label htmlFor="h-rec">Foreign record id</label><input id="h-rec" value={p.hints.foreign_record_id} onChange={hint("foreign_record_id")} /></div>
          <div className="field"><label htmlFor="h-recm">Foreign record marker</label><input id="h-recm" className="mono" value={p.hints.foreign_record_marker} onChange={hint("foreign_record_marker")} /></div>
          <div className="field"><label htmlFor="h-caller">Test caller identity</label><input id="h-caller" value={p.hints.caller_identity} onChange={hint("caller_identity")} /></div>
          <div className="field"><label htmlFor="h-limit">Output limit (chars)</label><input id="h-limit" type="number" min={0} value={p.hints.output_limit_chars} onChange={hint("output_limit_chars")} /></div>
        </div>
        <p className="hint">Hint values are stored with the target; the audit log records only their sha256.</p>
      </div>
      <div className="form-actions">
        <button type="button" className="btn ghost" onClick={onDone}>Cancel</button>
        <button className="btn primary" disabled={busy}>{busy ? "Saving…" : "Save profile"}</button>
      </div>
    </form>
  );
}
