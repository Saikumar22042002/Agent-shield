export type Severity = "High" | "Medium" | "Low" | "Unrated";

export interface Provider {
  key: string; label: string; implemented: boolean; identifier_label: string; config_fields: string[]; note: string;
  optional_fields: string[]; kind: "cloud" | "local";
}

export type TargetStatus = "unverified" | "connected" | "error" | "unsupported";

export interface Target {
  provider: string; provider_label: string; provider_implemented: boolean; config: Record<string, string>;
  archived: boolean; owner_attestation: string;
  id: number; name: string; harness_arn: string; qualifier: string; region: string; environment: string;
  aws_profile: string; aws_role_arn: string; status: TargetStatus;
  last_check_at: string | null; last_latency_ms: number | null; last_wall_ms: number | null;
  last_usage: Record<string, number>; last_error: string; created_at: string;
}

export interface CoverageRow { title: string; severity: Severity; total: number; fail: number; pass: number; inconclusive: number }

export interface Summary {
  coverage: Record<string, CoverageRow>; categories_covered: number; categories_total: number; attempts: number;
  findings_open: number; findings_closed: number; findings_by_severity: Record<Severity, number>;
  findings_confirmed?: number; findings_candidate?: number; findings_dismissed?: number; sample_data?: boolean;
  trap_hits: number; trap_hits_linked: number; unmapped_attempts: number; provenance: string;
  imported_attempts?: number;
  executed?: { total: number; by_kind: Record<string, number>; by_verdict: Record<string, number> };
}

export interface ImportBatch {
  id: number; tool: string; filename: string; sha256: string; tool_version: string; imported_by: string;
  stats: Record<string, number>; warnings: string[]; imported_at: string;
}

export type RunStatus = "open" | "paused" | "stopped" | "halted" | "complete";

export interface Phase { total: number; current: number; label: string; steps: { label: string; done: boolean }[] }

export type AssessmentState = "idle" | "planned" | "approved" | "queued" | "running" | "completed" | "stopped"
  | "interrupted" | "error";

export interface Run {
  id: string; target_id: number; label: string; status: RunStatus;
  parent_run_id: string | null; summary: Summary | null; halt_reason: string; started_at: string;
  finished_at: string | null; imports?: ImportBatch[]; phase?: Phase;
  assessment_status: AssessmentState; assessment_phase: string; stop_reason: string;
}

export interface ToolSpec { name: string; description: string; privileged: boolean }
export interface TargetProfile {
  role: string; description: string; expected_behavior: string; tools: ToolSpec[]; permissions: string[];
  data_sensitivity: string; data_types: string[]; has_rag: boolean; has_memory: boolean; has_records: boolean;
  policies: string[]; forbidden_actions: string[];
  hints: { context_canary: string; context_excerpt: string; planted_document: string; planted_marker: string;
    foreign_record_id: string; foreign_record_marker: string; caller_identity: string; output_limit_chars: number };
  documented?: boolean; capabilities?: string[];
}

export interface EngineInfo { available: boolean; version: string; label: string; detail: string }
export interface CatalogExecution {
  key: string; engine: "pyrit" | "garak"; available: boolean; engine_version: string; note: string;
  probe?: string; detector?: string; strategy?: string; dataset?: string; input?: string;
}
export interface CatalogTechnique {
  id: string; kind: "plumbing" | "security"; title: string; risks: string[]; severity: string; requires: string[];
  objective: string; expected_secure_behavior: string; executions: CatalogExecution[]; executable: boolean;
  not_executable_reason: string;
}
export interface Catalog {
  catalog_version: string; techniques: CatalogTechnique[]; engines: Record<string, EngineInfo>;
  executable_security_techniques: number; security_techniques: number;
}
export interface EnginesStatus {
  engines: Record<string, EngineInfo>; adapters: string[]; assessment_providers: string[]; limits: Record<string, number>;
}

export interface PlanCase {
  id: string; technique_id: string; engine: string; execution: string; kind: string; label: string; source: string;
  planned_prompts: number; turns?: string[]; probe?: string; prompt_cap?: number; strategy?: string; detector?: string;
  scorer?: { class: string; substring: string; input: string } | null;
  objective?: string; expected_secure_behavior?: string; scoring?: string;
}
export interface Plan {
  id: number; run_id: string; version: number; status: "draft" | "approved" | "superseded" | "invalidated"; sha256: string;
  created_by: string; created_at: string; approved_by: string; approved_at: string | null; integrity_ok: boolean;
  content: {
    catalog_version: string; target_kind: string; engines: string[]; engine_versions: Record<string, string>;
    techniques: { id: string; title: string; kind: string; rationale: string; executions: string[]; budget: number;
      planned_prompts: number; objective?: string; expected_secure_behavior?: string; risks?: string[];
      severity?: string }[];
    cases: PlanCase[]; limits: Record<string, number>; planned_prompts: number; kind: string; notes: string[];
  };
}
export interface PlanIn {
  techniques: string[]; executions?: Record<string, string[]>; benign_prompt?: string; benign_turns?: string[];
  limits?: Record<string, number>; note?: string;
}
export interface AssessmentCase {
  id: string; label: string; engine: string; technique_id: string; kind: string; planned_prompts: number;
  state: "pending" | "running" | "done" | "skipped";
  result: { attempt_id: number; verdict: string; source_verdict: string; error: string; kind: string;
    rationale?: string } | null;
}
export interface CoordinatorInfo {
  mode: string; model: string; attacker_tokens: number; attacker_token_budget: number; framework: string;
  summary: string; steps: number; fallback: string;
}
export interface Assessment {
  run_id: string; status: AssessmentState; phase: string; reason: string; limits: Record<string, any>;
  assessment: { progress?: { cases_total: number; cases_done: number; errors: number; skipped?: number; failed?: number;
    prompts_sent: number; prompts_refused: number; prompt_budget: number; target_tokens: number };
    started_by?: string; started_at?: string; finished_at?: string | null; in_flight?: string[];
    coordinator?: CoordinatorInfo; attacker_tokens?: number; active_seconds?: number };
  plan: { version: number; sha256: string; kind: string; engines: string[]; planned_prompts: number; stale?: string } | null;
  cases: AssessmentCase[];
  usage: { invocations: Record<string, number>; target_tokens: number };
  adapters: string[];
}
export interface Invocation {
  id: number; technique_id: string; test_key: string; engine: string; session_id: string; turn: number; prompt: string;
  attempt: number; response: string; status: "ok" | "error" | "refused" | "pending"; error: string;
  latency_ms: number | null; wall_ms: number | null;
  usage: Record<string, number>; tool_events: unknown[]; provenance: string; created_at: string;
}

export interface PlanOption {
  id: string; title: string; kind: "plumbing" | "security"; risks: string[]; severity: string; applies: boolean;
  rationale: string; objective: string; expected_secure_behavior: string; executable: boolean;
  not_executable_reason: string; input: string;
  executions: { key: string; engine: string; note: string; available: boolean }[];
}
export interface PlanOptions {
  run_id: string; target_kind: string; profile_documented: boolean; assessable: boolean; provider: string;
  limits: Record<string, number>; techniques: PlanOption[];
}

export interface AuthInfo { required: boolean; authenticated: boolean; name: string | null; role: string | null }

export interface TargetUpdate {
  name?: string; harness_arn?: string; qualifier?: string; region?: string; aws_profile?: string; aws_role_arn?: string;
  config?: Record<string, string>; owner_attestation?: string;
}

export interface Turn { role: string; text: string; generation?: number }

export interface Attempt {
  id: number; source: string; external_id: string; category: string; test_id: string; turns: Turn[];
  detector: string; score: number | null; verdict: "pass" | "fail" | "inconclusive"; rationale: string;
  trap_hit: boolean; severity: Severity; recorded_at: string | null; model_review: ModelReview | null;
}

export interface Finding {
  id: number; attempt_id: number; category: string; test_id: string; severity: Severity; title: string;
  evidence: {
    failed_attempts: number; attempt_ids: number[]; detector: string; score: number | null; rationale: string;
    trap_hits: { token_id: string; received_at: string | null; source: string }[];
    source: string; import_sha256: string; import_file: string; provenance?: string; invocation_ids?: number[];
    evidence_sha256?: string; evidence_file?: string;
  };
  status: "open" | "closed"; closed_by_run_id: string | null; remediation_key: string; fix: string; created_at: string;
  confirmation: "candidate" | "confirmed" | "dismissed"; confirmation_basis: string;
}

export interface AuditRow {
  id: number; ts: string; actor: string; action: string; run_id: string | null; target_id: number | null;
  payload: Record<string, unknown>; hash: string; prev_hash: string;
}

export interface ModelSetting { model: string; key_configured: boolean }

export interface ModelReview { verdict: "pass" | "fail" | "inconclusive"; rationale: string; model: string; judged_at: string }

export interface EngineConfig {
  engine: {
    harness: string; decision: ModelSetting; generation: ModelSetting;
    sandbox: string; test_source: string; store: string; outbound: string; coordinator?: string;
  };
  connectivity_message: string;
  auth_required?: boolean;
  assessment_providers?: string[];
  garak_fail_threshold: number;
  categories: Record<string, { title: string; severity: Severity }>;
}

export interface StreamEvent { id: number; ts: string; type: string; run_id: string | null; data: Record<string, any> }

export interface KillState { tripped: boolean; reason: string; tripped_at: number | null }

/** Where a timeline item came from. Rendered on every message and record. */
export type Provenance = "sent" | "measured" | "local-stub" | "imported" | "model-judged" | "derived" | "system"
  | "executed" | "gateway";

export interface TimelineItem {
  id: string; kind: "message" | "activity" | "evidence"; type: string; ts: string | null; provenance: Provenance;
  event_id?: number;
  // messages
  role?: "evaluator" | "target" | "system"; text?: string; turn?: number; message_id?: string; provider?: string;
  source?: string; meta?: Record<string, any>; error?: { message: string; code: string; hint: string };
  // activity / evidence
  data?: Record<string, any>;
}

export interface Timeline { run: Run; items: TimelineItem[]; truncated: boolean; attempt_limit: number; last_event_id: number }

export interface CheckResult {
  status: "connected" | "error"; latency_ms: number | null; wall_ms: number | null; usage: Record<string, number>;
  stop_reason: string; reply: string; error: string; error_code: string; hint: string; provenance: Provenance;
}

export interface TargetIn {
  provider: string; name: string; harness_arn?: string; region?: string; qualifier?: string; aws_profile?: string;
  aws_role_arn?: string; config?: Record<string, string>; environment: string; owner_attestation: string;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export function operatorName(): string {
  try { return localStorage.getItem("agentshield.operator") || "operator"; } catch { return "operator"; }
}

/** Access token for deployments with AUTH_TOKENS set. Kept in this browser only. */
export function accessToken(): string {
  try { return localStorage.getItem("agentshield.token") || ""; } catch { return ""; }
}

export function setAccessToken(token: string): void {
  try { if (token) localStorage.setItem("agentshield.token", token); else localStorage.removeItem("agentshield.token"); }
  catch { /* storage unavailable */ }
}

/** Query suffix for URLs the browser fetches without our headers (EventSource). */
export function tokenQuery(sep: "?" | "&"): string {
  const t = accessToken();
  return t ? `${sep}access_token=${encodeURIComponent(t)}` : "";
}

export function authHeaders(): Record<string, string> {
  const t = accessToken();
  return { "X-Operator": operatorName(), ...(t ? { Authorization: `Bearer ${t}` } : {}) };
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  Object.entries(authHeaders()).forEach(([k, v]) => headers.set(k, v));
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the AgentShield API. Check that the backend is running on port 8000.");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail
        : Array.isArray(body.detail) ? body.detail.map((d: { msg?: string }) => d.msg ?? JSON.stringify(d)).join("; ")
        : JSON.stringify(body.detail);
    } catch { /* non-JSON error */ }
    if (res.status === 401) window.dispatchEvent(new CustomEvent("agentshield:auth-required"));
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body?: unknown) =>
  req<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
const put = <T>(path: string, body: unknown) => req<T>(path, { method: "PUT", body: JSON.stringify(body) });

export const api = {
  config: () => req<EngineConfig>("/config"),
  targets: () => req<Target[]>("/targets"),
  createTarget: (body: TargetIn) => post<Target>("/targets", body),
  updateTarget: (id: number, body: TargetUpdate) => put<Target>(`/targets/${id}`, body),
  auth: () => req<AuthInfo>("/auth"),
  archiveTarget: (id: number, archived: boolean) => post<Target>(`/targets/${id}/archive`, { archived }),
  check: (id: number) => post<CheckResult>(`/targets/${id}/check`),
  runs: () => req<Run[]>("/runs"),
  run: (id: string) => req<Run>(`/runs/${id}`),
  timeline: (id: string) => req<Timeline>(`/runs/${id}/timeline`),
  createRun: (target_id: number, label: string, parent_run_id?: string | null) =>
    post<Run>("/runs", { target_id, label, parent_run_id: parent_run_id ?? null }),
  exchange: (id: string) => post<CheckResult>(`/runs/${id}/exchange`),
  completeRun: (id: string) => post<Run>(`/runs/${id}/complete`),
  pauseRun: (id: string) => post<Run>(`/runs/${id}/pause`, { reason: "" }),
  resumeRun: (id: string) => post<Run>(`/runs/${id}/resume`),
  stopRun: (id: string, reason: string) => post<Run>(`/runs/${id}/stop`, { reason }),
  providers: () => req<Provider[]>("/providers"),
  events: (limit = 300) => req<StreamEvent[]>(`/events?limit=${limit}`),
  importFile: (runId: string, tool: string, file: File) => {
    const fd = new FormData();
    fd.append("tool", tool);
    fd.append("file", file);
    return req<{ stats: Record<string, number>; warnings: string[] }>(`/runs/${runId}/imports`, { method: "POST", body: fd });
  },
  attempts: (runId: string) => req<Attempt[]>(`/runs/${runId}/attempts?limit=1000`),
  findings: (runId: string) => req<Finding[]>(`/runs/${runId}/findings`),
  judge: (attemptId: number) => post<{ model_verdict: string; model_rationale: string }>(`/attempts/${attemptId}/judge`),
  judgeRun: (runId: string, verdict: string) =>
    post<{ judged: number; errors: { attempt_id: number; error: string }[] }>(
      `/runs/${runId}/judge?verdict=${encodeURIComponent(verdict)}`),
  audit: (limit = 300) => req<AuditRow[]>(`/audit?limit=${limit}`),
  runAudit: (runId: string, limit = 500) => req<AuditRow[]>(`/audit?limit=${limit}&run_id=${encodeURIComponent(runId)}`),
  reviewFinding: (id: number, decision: "confirmed" | "dismissed" | "candidate", note = "") =>
    post<Finding[]>(`/findings/${id}/review`, { decision, note }),
  verifyAudit: () => req<{ ok: boolean; first_bad_id: number | null }>("/audit/verify"),
  kill: () => req<KillState>("/kill"),
  trip: (reason: string) => post<KillState>("/kill", { reason }),
  resetKill: () => post<KillState>("/kill/reset"),
  reportUrl: (runId: string) => `/api/runs/${runId}/report.pdf`,
  profile: (targetId: number) => req<TargetProfile>(`/targets/${targetId}/profile`),
  saveProfile: (targetId: number, body: TargetProfile) => put<TargetProfile>(`/targets/${targetId}/profile`, body),
  planOptions: (runId: string) => req<PlanOptions>(`/runs/${runId}/plan-options`),
  catalog: () => req<Catalog>("/catalog"),
  engines: () => req<EnginesStatus>("/engines"),
  plans: (runId: string) => req<Plan[]>(`/runs/${runId}/plans`),
  createPlan: (runId: string, body: PlanIn) => post<Plan>(`/runs/${runId}/plans`, body),
  approvePlan: (runId: string, version: number) => post<Plan>(`/runs/${runId}/plans/${version}/approve`),
  assessment: (runId: string) => req<Assessment>(`/runs/${runId}/assessment`),
  startAssessment: (runId: string) => post<Assessment>(`/runs/${runId}/assessment/start`),
  resumeAssessment: (runId: string) => post<Assessment>(`/runs/${runId}/assessment/resume`),
  stopAssessment: (runId: string, reason: string) => post<Assessment>(`/runs/${runId}/assessment/stop`, { reason }),
  invocations: (runId: string) => req<Invocation[]>(`/runs/${runId}/invocations?limit=2000`),
};
