import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, type Assessment, type Plan, type PlanOptions, type Run } from "../api";
import { useStore } from "../store";
import { AssessmentPanel, RunAudit } from "./Assessment";

afterEach(cleanup);

const run: Run = {
  id: "RUN-1", target_id: 1, label: "", status: "open", parent_run_id: null, summary: null, halt_reason: "",
  started_at: "2026-10-30T00:00:00Z", finished_at: null, assessment_status: "approved", assessment_phase: "", stop_reason: "",
};

const plan: Plan = {
  id: 1, run_id: "RUN-1", version: 2, status: "draft", sha256: "a".repeat(64), created_by: "alice",
  created_at: "2026-10-30T00:00:00Z", approved_by: "", approved_at: null, integrity_ok: true,
  content: {
    catalog_version: "2026.10.2", target_kind: "local-stub", engines: ["pyrit"], engine_versions: { pyrit: "1.1.0" },
    techniques: [{ id: "PLUMB-PYRIT", title: "PyRIT plumbing", kind: "plumbing", rationale: "Proves the path",
      executions: ["pyrit:PromptSendingAttack"], budget: 5, planned_prompts: 1, objective: "obj", expected_secure_behavior: "esb" }],
    cases: [{ id: "C01", technique_id: "PLUMB-PYRIT", engine: "pyrit", execution: "pyrit:PromptSendingAttack", kind: "plumbing",
      label: "PLUMB-PYRIT · PyRIT PromptSendingAttack", source: "operator-supplied benign prompt", planned_prompts: 1,
      scoring: "No objective scorer" }],
    limits: { max_prompts_per_run: 50 }, planned_prompts: 1, kind: "plumbing", notes: ["Operator note: drill"],
  },
};

const assessment: Assessment = {
  run_id: "RUN-1", status: "running", phase: "executing", reason: "", limits: { max_prompts_per_run: 50, attacker_token_budget: 1000 },
  assessment: { progress: { cases_total: 3, cases_done: 1, errors: 0, skipped: 1, prompts_sent: 4, prompts_refused: 3,
    prompt_budget: 50, target_tokens: 0 }, attacker_tokens: 120,
    coordinator: { mode: "deterministic", model: "agentshield-scripted-coordinator", attacker_tokens: 120, attacker_token_budget: 1000,
      framework: "deepagents", summary: "", steps: 4, fallback: "" } },
  plan: { version: 2, sha256: "a".repeat(64), kind: "plumbing", engines: ["pyrit"], planned_prompts: 1, stale: "" },
  cases: [
    { id: "C01", label: "case one", engine: "pyrit", technique_id: "PLUMB-PYRIT", kind: "plumbing", planned_prompts: 1, state: "done",
      result: { attempt_id: 1, verdict: "inconclusive", source_verdict: "UNDETERMINED", error: "", kind: "plumbing", rationale: "PyRIT outcome UNDETERMINED" } },
    { id: "C02", label: "case two", engine: "pyrit", technique_id: "AS-SPL-01", kind: "security", planned_prompts: 1, state: "skipped",
      result: { attempt_id: 2, verdict: "skipped", source_verdict: "", error: "", kind: "simulated", rationale: "objective established" } },
    { id: "C03", label: "case three", engine: "garak", technique_id: "AS-PI-01", kind: "security", planned_prompts: 3, state: "running", result: null },
  ],
  usage: { invocations: { ok: 4, error: 0, refused: 3, pending: 1 }, target_tokens: 0 }, adapters: ["garak", "pyrit"],
};

const options: PlanOptions = {
  run_id: "RUN-1", target_kind: "local-stub", profile_documented: false, assessable: true, provider: "local_stub",
  limits: { max_prompts_per_technique: 5, max_prompts_per_run: 50, technique_concurrency: 2, attacker_token_budget: 60000 },
  techniques: [
    { id: "PLUMB-PYRIT", title: "PyRIT plumbing", kind: "plumbing", risks: [], severity: "Info", applies: true, rationale: "Proves the path",
      objective: "o", expected_secure_behavior: "Any reply", executable: true, not_executable_reason: "", input: "operator_benign_prompt",
      executions: [{ key: "pyrit:PromptSendingAttack", engine: "pyrit", note: "", available: true }] },
    { id: "AS-SID-02", title: "Cross-record data access", kind: "security", risks: ["LLM02"], severity: "High", applies: false,
      rationale: "Profile documents no per-user records.", objective: "o", expected_secure_behavior: "e", executable: false,
      not_executable_reason: "", input: "", executions: [] },
  ],
};

beforeEach(() => {
  useStore.setState({ assessment, plans: [plan], kill: { tripped: false, reason: "", tripped_at: null },
    refreshAssessment: vi.fn(async () => undefined), refreshRun: vi.fn(async () => undefined), notify: vi.fn(), events: [], auditOk: true });
});

describe("AssessmentPanel", () => {
  it("shows execution state, budgets, the coordinator and per-case results", () => {
    render(<AssessmentPanel run={run} />);
    expect(screen.getByText("Executing")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Stop execution/ })).toBeTruthy();
    expect(screen.getByRole("progressbar", { name: "Prompts sent" }).getAttribute("aria-valuenow")).toBe("4");
    expect(screen.getByText(/3 refused by the gateway/)).toBeTruthy();
    expect(screen.getByText(/LangChain Deep Agents · deterministic/)).toBeTruthy();
    expect(screen.getAllByText("skipped").length).toBeGreaterThan(0);
    expect(screen.getByText("objective established")).toBeTruthy();
  });

  it("stopping calls the API with a reason", async () => {
    const stop = vi.spyOn(api, "stopAssessment").mockResolvedValue(assessment);
    render(<AssessmentPanel run={run} />);
    fireEvent.click(screen.getByRole("button", { name: /Stop execution/ }));
    await waitFor(() => expect(stop).toHaveBeenCalledWith("RUN-1", "Stopped from the assessment panel"));
  });

  it("a draft plan shows rationale and scoring, and approving it calls the API", async () => {
    const approve = vi.spyOn(api, "approvePlan").mockResolvedValue({ ...plan, status: "approved" });
    render(<AssessmentPanel run={run} />);
    expect(screen.getByText("Proves the path")).toBeTruthy();
    expect(screen.getByText(/Scoring: No objective scorer/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Approve plan/ }));
    await waitFor(() => expect(approve).toHaveBeenCalledWith("RUN-1", 2));
  });

  it("start is disabled with a reason when the plan is stale", () => {
    useStore.setState({ assessment: { ...assessment, status: "approved", plan: { ...assessment.plan!, stale: "the target profile changed" } } });
    render(<AssessmentPanel run={run} />);
    const start = screen.getByRole("button", { name: /Start execution/ }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    expect(screen.getByText(/Plan is stale: the target profile changed/)).toBeTruthy();
  });

  it("the plan builder offers only applicable, executable techniques and drafts a plan", async () => {
    vi.spyOn(api, "planOptions").mockResolvedValue(options);
    const create = vi.spyOn(api, "createPlan").mockResolvedValue(plan);
    useStore.setState({ assessment: { ...assessment, status: "idle" }, plans: [] });
    render(<AssessmentPanel run={run} />);
    fireEvent.click(screen.getByRole("button", { name: /New plan/ }));
    await screen.findByText(/Does not apply: Profile documents no per-user records/);
    const draft = screen.getByRole("button", { name: /Draft plan/ }) as HTMLButtonElement;
    expect(draft.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /pyrit:PromptSendingAttack/ }));
    fireEvent.change(screen.getByLabelText(/Prompts per run/), { target: { value: "10" } });
    fireEvent.click(screen.getByRole("button", { name: /Draft plan/ }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    const body = create.mock.calls[0][1];
    expect(body.techniques).toEqual(["PLUMB-PYRIT"]);
    expect(body.executions).toEqual({ "PLUMB-PYRIT": ["pyrit:PromptSendingAttack"] });
    expect(body.limits).toEqual({ max_prompts_per_run: 10 });
    expect(body.benign_prompt).toBeTruthy();
  });

  it("case rows expand to the gateway evidence for that case", async () => {
    vi.spyOn(api, "invocations").mockResolvedValue([
      { id: 9, technique_id: "PLUMB-PYRIT", test_key: "C01", engine: "pyrit", session_id: "agentshield-stub-1", turn: 1, attempt: 0,
        prompt: "Hello there", response: "[Local stub target] reply", status: "ok", error: "", latency_ms: null, wall_ms: 3,
        usage: {}, tool_events: [], provenance: "local-stub", created_at: "2026-10-30T00:00:00Z" },
      { id: 10, technique_id: "AS-PI-01", test_key: "C03#1", engine: "garak", session_id: "s2", turn: 1, attempt: 0, prompt: "x",
        response: "", status: "refused", error: "budget_technique: spent", latency_ms: null, wall_ms: null, usage: {},
        tool_events: [], provenance: "gateway", created_at: "2026-10-30T00:00:00Z" }]);
    render(<AssessmentPanel run={run} />);
    fireEvent.click(screen.getByRole("row", { name: /C01/ }));
    expect(await screen.findByText("Hello there")).toBeTruthy();
    expect(screen.queryByText("budget_technique: spent")).toBeNull(); // C03's traffic is not shown under C01
  });
});

describe("RunAudit", () => {
  it("lists the run's audit records and filters them", async () => {
    vi.spyOn(api, "runAudit").mockResolvedValue([
      { id: 2, ts: "2026-10-30T00:00:01Z", actor: "alice", action: "plan.approve", run_id: "RUN-1", target_id: null,
        payload: { version: 2 }, hash: "b".repeat(64), prev_hash: "a".repeat(64) },
      { id: 1, ts: "2026-10-30T00:00:00Z", actor: "system", action: "gateway.invoke", run_id: "RUN-1", target_id: 1,
        payload: { status: "ok" }, hash: "a".repeat(64), prev_hash: "0".repeat(64) }]);
    render(<RunAudit run={run} />);
    expect(await screen.findByText("plan.approve")).toBeTruthy();
    expect(screen.getByText(/2 record\(s\) for RUN-1/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Filter run audit records"), { target: { value: "gateway" } });
    expect(screen.queryByText("plan.approve")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /gateway.invoke/ }));
    expect(screen.getByText(/"status": "ok"/)).toBeTruthy();
  });
});
