# AgentShield — Requirements-to-Codebase Audit

**Date:** 2026-10-30
**Scope:** audit only. No project files were changed during the audit. Both real databases (`data/agentshield.db`, `data/qa/agentshield-qa.db`) have identical SHA-256 checksums before and after.

**Verdict: Infrastructure and UI with incomplete assessment execution.**

The platform can register a target, check connectivity, profile it, plan, approve, import tool results, derive findings, re-test and export reports. It cannot execute an assessment: there is no PyRIT adapter, no garak adapter and no Deep Agents coordinator, so starting any approved plan returns **409 "No execution adapter is installed for: garak, pyrit."** The audit also found two broken safety controls: budgets can be exceeded under concurrent calls, and credential redaction misses some audit and stream records.

---

## How the audit was done

| # | What was run | Result |
|---|---|---|
| 1 | File inventory of `backend/agentshield` | 31 modules, 4,496 lines. `assessment/` holds `engines.py`, `plans.py`, `orchestrator.py`. **`pyrit_adapter.py` does not exist** |
| 2 | Installed versions | pyrit 1.1.0, deepagents 0.7.32, langgraph 1.2.18, fastapi 0.162.0, boto3 1.43.121; garak 0.17.1 in `backend/.venv-garak` |
| 3 | `grep` of app code for framework use | `deepagents` is never imported. `pyrit` is imported only in `plans.pyrit_dataset()` to read a dataset file. Garak is only version-detected, never executed. `orchestrator.register()` is never called. The `/api/gateway/garak` endpoint exists only in a docstring |
| 4 | Settings read by nothing | `invocation_retries`, `coordinator_model`, `gateway_public_url`, `garak_timeout_s`, `evidence_dir`. `attacker_token_budget` is copied into plan limits but never enforced |
| 5 | Route table from the live FastAPI app | 42 `/api` routes (see M1). There is no `PUT /api/targets/{id}` |
| 6 | `cd backend; .venv/Scripts/python.exe -m pytest -q` | **90 passed** (api 8, catalog 6, connector 6, gateway 12, ingest 6, judge 7, lifecycle 8, llm 5, migrations 3, orchestrator 12, plans 7, workspace 10) |
| 7 | `npx tsc -b` (frontend) | Passes. There are **no frontend tests** of any kind |
| 8 | `grep` of UI calls to the new endpoints | No calls to create plan, approve plan, start/stop/resume assessment, profile or invocations. The store only *reads* the catalog, engines, plans and assessment status |
| 9 | Audit probe: real app and SQLite on a throwaway database via an in-process test client (`audit_probe.py`, kept in the session scratchpad, not in the project) | Results quoted throughout this report |
| 10 | Connector call-path trace | `conn.send` is called in exactly one place, `gateway.send` (`gateway.py:271`). `build_connector` is called only from `gateway.py` and `connectivity.py` |
| 11 | SHA-256 of both real databases | Unchanged |

**Browser evidence** comes from a Claude Chrome session run in the step before this audit, on a throwaway database. The frontend source has not changed since. The browser was not re-run during this audit.

---

## A. Executive verdict

The non-execution parts of the pipeline work and are tested through the real API, database, live stream and UI: registration, the stub connectivity exchange, imports, findings, re-test closure, the audit chain, PDF export and the emergency stop.

The assessment engine is control-plane only. It has plans, approval, a gateway that enforces those plans and an orchestrator, but nothing can execute through them. No framework, adaptive loop or Deep Agents coordinator is connected. Two gateway safety controls are broken:

- **Budget race:** 10 of 10 concurrent calls passed a 5-prompt technique budget.
- **Redaction gaps:** a credential-shaped string reached the hash-chained audit log and the live stream unredacted.

---

## B. Requirements matrix

**Status key**

| Abbreviation | Status |
|---|---|
| FV | FULLY IMPLEMENTED AND VERIFIED |
| IU | IMPLEMENTED BUT UNVERIFIED |
| PI | PARTIALLY IMPLEMENTED |
| NI | NOT IMPLEMENTED |
| BR | BROKEN |
| BL | BLOCKED |

### A. Target registration and management

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| A1 | Register and persist multiple targets | FV | `POST/GET /api/targets` (`app.create_target`). Probe registered 3 targets. Tests; browser | — |
| A2 | Edit a target | NI | Probe `PUT /api/targets/1` → 404. UI offers only archive/restore | Add an edit endpoint and form, with audit |
| A3 | Select a target in the UI | FV | Header target selector (`Shell.tsx`), verified in browser | — |
| A4 | Clearly labelled local stub | FV | `connectors/local_stub.py`. Reply text says it is a stub; provenance `local-stub`; PDF shows "LOCAL STUB TARGET" | — |
| A5 | Optional real local-model target | NI | No such provider in `connectors/registry.py` | Add a local-model connector |
| A6 | Profiling backend (role, tools, permissions, sensitivity, policies, hints) | FV | `profile.py` `TargetProfile`; `GET/PUT /api/targets/{id}/profile`. Probe and tests pass; the audit stores a hash of the hints, not their values | — |
| A7 | Profiling UI | NI | No UI calls to `api.profile` or `api.saveProfile` | Build a profile editor |
| A8 | Staging-only rule and input validation | FV | `safety.assert_staging`. Probe: production target refused (422). ARN and region validation tests | — |
| A9 | AWS Bedrock AgentCore connector | IU | `connectors/aws_agentcore.py`. Stream assembly and errors unit-tested with mocks; code preserved | Verify on the AWS VM |
| A10 | Live AWS execution | BL | No credentials; AWS calls prohibited for this audit | Run on the VM with an instance role |
| A11 | Azure AI Foundry and Google Cloud connectors | NI | `connectors/placeholders.py` raises `NotImplemented`. Probe: status `unsupported`, check → 501. Labelled accurately as pending | Implement when needed |

### B. Connectivity and conversation

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| B1 | Benign greeting and the target's real configured reply | FV | `connectivity.check_target` → `gateway.send`. Probe: `connected`, stub reply | — |
| B2 | Record messages, conversation IDs, timestamps and turn order | PI | Probe: roles evaluator→target, turns 1→2. **The target's reply in the timeline has no session ID** (only the sent message and the invocation row have it) | Add the session ID to the reply event |
| B3 | Honest latency and usage | FV | Probe: `latency_ms=null`, `usage={}`, round trip measured. Nothing invented | — |
| B4 | Live streaming without refresh | FV | `/api/stream` (SSE) with `Last-Event-ID` resume. Browser: no duplicates | — |
| B5 | Tell stub, imported and live messages apart | FV | `ProvChip` labels, timeline provenance, PDF stub banner | — |
| B6 | Actionable connection errors | FV | `hint_for()`. Test `test_exchange_error_keeps_original_message_and_hint` uses a *simulated* AccessDenied error | Real AWS errors unverified (see A10) |

### C. Profiling, plan generation and approval

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| C1 | Generate a plan from the catalog and profile, with rationale, executions, limits and notes | FV | `plans.build`, `POST /api/runs/{id}/plans`. Probe: engines [garak, pyrit], 2 cases, 6 prompts | — |
| C2 | Plan states the expected secure behavior and scoring criteria | PI | Plan technique rows lack `objective` and `expected_secure_behavior`. A scorer is set only for PyRIT dataset cases with a canary | Copy these fields into the plan |
| C3 | Versioning, hashing, supersession | FV | `AssessmentPlan` table, `plan_sha`. 7 plan tests, including tamper detection | — |
| C4 | Operator approval required before any execution | FV | `plans.approve`. Gateway refuses with `no_approved_plan` / `plan_integrity` (tests) | — |
| C5 | Approval invalidated when the profile or catalog changes | NI | Probe: after changing the profile, the plan is still `approved` | Check profile and catalog hashes before execution |
| C6 | Modify a plan | PI | Only by drafting a new version | Acceptable; document it |
| C7 | UI for viewing, creating and approving plans and controlling execution | NI | No UI calls to `createPlan`, `approvePlan`, `start`, `stop` or `resume` (grep) | Build the assessment panel |
| C8 | Approved limits can't be loosened via the API or stale run fields | FV | Probe: 422 "exceeds the configured limit 50". Test shows edits to `run.limits` are ignored; budgets come from the hashed plan | Concurrency race is separate (H3) |

### D. Intelligent assessment engine

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| D1 | Execute approved cases through a framework adapter | NI | `orchestrator.ADAPTERS` stays empty. Probe: start → 409 | Build the adapters (F1, G1) |
| D2 | Role-specific test selection | PI | `profile.applicability` uses `requires` flags and fixed rationale text. No domain-specific selection (e.g. service-desk boundaries) | Profile-driven selection |
| D3 | Multi-turn strategies | NI | `PLUMB-PYRIT-MT` can be planned but never executed | Comes with the PyRIT adapter |
| D4 | Adaptive follow-up from responses and scores | NI | Cases are a static list. No feedback loop | Build an adapt step in the coordinator |
| D5 | Early stopping | PI | `orchestrator.STOP_CODES` handles kill, cancel and budget. No stop on "objective established" or target unavailable. Tested only with a test adapter | Add objective and target-health stops |
| D6 | Lifecycle (queued, running, stopped, resume, interrupted), conversation isolation, bounded parallelism | IU | `assessment/orchestrator.py`. 12 tests pass, **only with a test-only replay adapter**. Not reachable in the running app | Verify with a real adapter |
| D7 | Result states pass / fail / inconclusive / error / skipped | PI | Imports map to pass/fail/inconclusive. `skipped` is never produced. No mapping for executed results | Define and implement the mapping |

### E–G. Deep Agents, PyRIT and garak

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| E1 | Deep Agents as the orchestrator (supervisor, subagents, tools, state, streaming) | NI | Never imported (grep). Only listed in `engines.status()` | Build the coordinator |
| F1 | PyRIT adapter, registration and real execution through the gateway | NI | File absent; nothing registered | Build the adapter |
| F2 | PyRIT bundled datasets used for plan inputs | FV | `plans.pyrit_dataset` uses `SeedDataset.from_yaml_file`. Tests compare seeds verbatim | — |
| F3 | PyRIT JSON import | FV | `ingest/pyrit.py`. Probe: 201 | — |
| G1 | Garak execution (REST generator, gateway endpoint, probes, detectors) | NI | No endpoint and no subprocess call. The garak venv is never executed | Build the adapter and endpoint |
| G2 | Garak JSONL import | FV | `ingest/garak.py`. Probe: 3 attempts added; re-import added 0 (3 duplicates) | — |
| G3 | Trap-hit import | FV | `ingest/traps.py`. Probe and browser: the hit links to its attempt | — |
| G4 | Catalog probe and detector names exist in installed garak | FV | `test_garak_probes_exist_in_installed_garak` queries garak's own plugin registry | — |

### H. Technique catalog and limits

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| H1 | Versioned technique catalog | FV | `technique_catalog.json` v2026.10.2. Counts below | — |
| H2 | Defaults: 5 prompts per technique, 50 per run, 1 active assessment | FV | `config.py`. Test asserts the `/api/engines` limits | — |
| H3 | Budgets enforced before *every* invocation, including concurrent ones | **BR** | Probe: **10 of 10 concurrent calls succeeded against a 5-prompt budget.** Budget is checked (`gateway.py:221`) before the invocation row is written (`:312`); the lock (`:371`) only spaces calls out | Reserve budget atomically under a lock or in a DB transaction |
| H4 | Timeouts, rate limit, run duration | FV | Gateway tests: timeout, rate limit, duration | — |
| H5 | Token budgets | PI | Target tokens enforced only when the target reports usage. Attacker (coordinator) token budget never enforced | Enforce once the coordinator exists |
| H6 | Retries governed by budgets | NI | `invocation_retries` read nowhere. AgentCore retries internally up to 4 times inside one gateway call, invisible to budgets | Move retries into the gateway and count them |
| H7 | Concurrency bounds | IU | Semaphore plus thread pool in the orchestrator. Tested only with the test adapter | Verify with a real adapter |

### I. Gateway and safety controls

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| I1 | Provider allowlist | FV | `ASSESSMENT_PROVIDERS`. Tests: `provider_not_allowed`; AWS target plan → 422 | — |
| I2 | Approved-plan, engine, case and exact-input checks | FV | `gateway._check_assessment`. 6 refusal codes tested and persisted | — |
| I3 | Cancel, pause and stop | FV | Gateway tests: in-flight call abandoned within 2 s; paused calls held; stop refuses | — |
| I4 | Emergency stop, backend-enforced, survives restart | FV | `safety.KILL` restored from the audit log at startup. Probe: 4 runs halted, new runs and checks → 423. Browser: survived an API restart | Process-local; safe only with one worker |
| I5 | Credential redaction everywhere (storage, logs, audit, stream) | **BR** | Probe with a key-shaped string: **raw in audit `connectivity.start` and `connector.request`, and in the `conversation.message` stream event.** Invocation rows were redacted. Sources: `local_stub.py:59`, `aws_agentcore.py:152`, `connectivity.py:84,97` | Redact at every audit and publish call. The audit log is append-only and hash-chained, so leaked values can't be removed without breaking the chain |
| I6 | Audit hash chain and verification | FV | `audit.py`. Tamper test; probe: chain OK | — |
| I7 | Refused calls persisted and never reach the connector | FV | `_refuse` raises before `send` (tests) | — |
| I8 | No path to a connector that bypasses the gateway | FV | Call-path trace: `conn.send` only in `gateway.send` | Connectivity checks intentionally skip plan checks; they send only the fixed greeting |
| I9 | Denied API requests are audited | PI | Gateway refusals audited. Probe: a **rejected plan request is not audited** | Audit plan rejections |

### J. Evidence, scoring, findings and reports

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| J1 | Full evidence record for each executed attempt | IU | `TestAttempt` columns and `orchestrator._persist` exist; never filled by a real framework | Comes with the adapters |
| J2 | Imported findings with severity and remediation | FV | `store._rebuild_findings`. Probe: T-03 Medium and T-05 Low, each with a fix | — |
| J3 | Advisory review by `DECISION_MODEL` | IU | `judge.py`. Tests use a fake model; probe: 503 because the model isn't set. A real model has never been called | Set the model and verify |
| J4 | Re-test closure | FV | Probe and browser: T-03 closed by the child run; T-05, not re-tested, stays open | — |
| J5 | PDF report | FV | `report.py`. Probe: 200 `%PDF-`. Browser: stub label, closure, hashes, audit status | PDF still has a "Coverage" section (backend only) |
| J6 | Stub runs and sample data can't produce confirmed findings | PI | Executed plumbing and stub results excluded (tests). **Imported sample fixtures on a stub run created 2 open findings** (probe) | Exclude imports into stub runs, or mark those findings as sample data |
| J7 | A detector hit is not automatically a confirmed exploit | PI | Any score at or above the threshold becomes a "finding". No candidate-versus-confirmed tier | Add a confirmation state |

### K. Persistence and streaming

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| K1 | Migrations preserve existing data | FV | `db.py` (8 migrations, backup first). 3 migration tests; verified on copies of both real databases | Live DB is still at v3 and will migrate on its next start |
| K2 | State consistent after refresh and restart | FV | Browser: reload kept the run and conversation; emergency stop survived an API restart | — |
| K3 | Chronological stream, no duplicates, resume | FV | Browser: 0 overlaps in 119 samples; reconnected with `last_event_id=39` | — |

### L. User interface

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| L1 | Seven-section navigation | FV | `Shell.tsx` NAV, browser | — |
| L2 | Conversation console with clear identities | FV | `Workspace.tsx`, browser | — |
| L3 | Messages, Activity, Evidence and Audit tabs | PI | Tabs are All, Messages, Activity, Evidence. **No Audit tab** | Add a run-scoped Audit tab |
| L4 | Run progress, technique and budget display | NI | No component uses the assessment state | Build the assessment panel |
| L5 | Target diagnostics | FV | `Targets.tsx` diagnostics, browser | — |
| L6 | Run controls and emergency stop UI | FV | Browser: stop modal, banner, two-step reset | — |
| L7 | Imports, findings, review, re-test and PDF UI | FV | Browser (review button correctly disabled without a model) | — |
| L8 | Coverage section removed from the UI | FV | grep: no Coverage in components | — |
| L9 | Responsive layout | FV | 390 px iframe: no sideways scrolling on any of the 7 pages | — |
| L10 | Premium Big 4 visual standard | PI | Consistent dark design system, but assessment surfaces missing | Design and build the execution UI |
| L11 | Frontend automated tests | NI | None exist | Add component and end-to-end tests |
| L12 | Efficient fetching, no duplicate events | FV | Browser: 11 startup requests; placeholder overlap 0 | — |

### M. API and deployment

| ID | Requirement | Status | Implementation and evidence | Gap → next action |
|---|---|---|---|---|
| M1 | Required endpoints exist and validate input | FV | 42 routes in `app.py` (listed below), 90 backend tests | Missing: target edit, garak gateway endpoint |
| M2 | Authentication and authorization | NI | Operator name is a self-declared `X-Operator` header (POC) | Add login and roles before any shared deployment |
| M3 | AWS VM readiness (runtime credentials, no stored secrets) | IU | boto3 credential chain; no keys stored | Verify on the VM |
| M4 | Documentation accuracy | PI | README still says AgentShield never sends test content and that `make test` runs 50 tests | Update the docs |

**API routes (M1):**

```
GET   /api/health  /api/config  /api/providers  /api/engines  /api/catalog
GET   /api/targets            POST /api/targets
POST  /api/targets/{id}/archive   /api/targets/{id}/check
GET   /api/targets/{id}/profile   PUT /api/targets/{id}/profile
GET   /api/runs               POST /api/runs
GET   /api/runs/{id}  /timeline  /attempts  /findings  /invocations  /report.pdf  /plans  /assessment
POST  /api/runs/{id}/pause  /resume  /stop  /complete  /exchange  /imports  /judge
POST  /api/runs/{id}/plans    /api/runs/{id}/plans/{version}/approve
POST  /api/runs/{id}/assessment/start  /assessment/resume  /assessment/stop
POST  /api/attempts/{id}/judge
GET   /api/audit  /api/audit/verify  /api/graph  /api/events  /api/stream
GET   /api/kill               POST /api/kill  /api/kill/reset
```

### Technique counts (from the repository)

| Item | Count |
|---|---|
| Risk categories (OWASP LLM01–10, ASI01–10) | 20 (7 marked unsupported, with reasons) |
| Catalog entries | 17: 3 plumbing + 14 security |
| Security techniques with a documented framework mapping | 5 (AS-PI-01, AS-SPL-01, AS-OUT-01, AS-EXF-01, AS-ENC-01), via 7 mappings: 6 garak probes, 1 PyRIT dataset |
| Security techniques with no mapping (plan-only) | 9 |
| **Techniques executable in this build** | **0** (no adapters) |
| Tests actually executed by AgentShield | 0 |
| Confirmed findings | 0 (the probe's findings came from imported QA sample files) |

---

## C. Workflow verification

| Stage | Result | Evidence |
|---|---|---|
| Target registration | **Pass** | Probe (3 targets, production refused, Azure 501); browser |
| Connectivity check | **Pass (stub only)** | Probe: connected, honest metrics; browser; rate limit 429 |
| Target profiling | **Pass via API; no UI** | Probe `PUT` and `GET` profile |
| Plan generation | **Pass via API; no UI** | Probe: 201, 2 cases, 6 prompts |
| Operator approval | **Pass via API; no UI** | Probe: 200; loosening refused 422; not invalidated by a profile change (C5) |
| Intelligent assessment | **Fail (not implemented)** | Probe: start → 409, no adapter |
| Evidence collection | **Imported: pass. Executed: can't be tested** | Imports 201; no execution possible |
| Scoring | **Imported framework verdicts: pass. Executed: none** | garak and PyRIT verdict mapping tests |
| Findings | **Pass, with caveats** | Probe; J6 and J7 caveats |
| Review | **Blocked** | 503, `DECISION_MODEL` unset; tested only with a fake model |
| Re-test | **Pass** | Probe and browser closure |
| Report | **Pass** | Probe 200 `%PDF-`; browser content check |

---

## D. Integration truth table

| | Deep Agents 0.7.32 | PyRIT 1.1.0 | garak 0.17.1 |
|---|---|---|---|
| Installed | Yes (`.venv`) | Yes (`.venv`) | Yes (`.venv-garak`, isolated) |
| Adapter implemented | No | No | No |
| Registered at startup | No | No | No |
| Real execution | No | No | No |
| Gateway enforcement for it | Not applicable (never runs) | Gateway ready; no traffic | Gateway ready; no `/api/gateway/garak` endpoint |
| Scoring | No | Imported scores only | Imported detector results only |
| Evidence persisted | No | Imports only | Imports only |
| Reported in PDF | No | Imported results | Imported results |
| Used anywhere at all | Version detection only | Dataset loading for plans | Version detection plus plugin-name check in tests |

---

## E. Critical findings, ranked

1. **No assessment execution (D1, E1, F1, G1).** The core loop cannot run. Every execution path stops at an approved plan that returns 409.
2. **Budget race (H3).** Concurrent calls bypass the per-technique and per-run budgets: 10 of 10 succeeded against a limit of 5. Once execution exists with parallel cases, approved limits can be exceeded.
3. **Redaction gaps (I5).** Credential-shaped text reaches the audit log raw, and the audit log cannot be cleaned without breaking its hash chain. It also reaches the live stream. On a real deployment that would leak target-side secrets permanently.
4. **No adaptive or multi-turn execution (D3, D4).** Even with adapters, cases are a static list with no observe-and-adapt step.
5. **Findings from sample data, and no confirmation tier (J6, J7).** QA fixture files imported into a stub run produced open findings, and a detector hit is treated as a finding with no confirmation step.
6. **Ungoverned retries and token budget (H5, H6).** AgentCore's internal retries don't count against budgets, and the attacker token budget isn't enforced.
7. **Approval not tied to the profile; rejections unaudited (C5, I9).** A plan stays approved after the profile changes, and rejected plan requests leave no audit trace.
8. **No UI for planning or execution (C7, L4, L3).** Planning and execution can only be driven through the API, and the workspace has no Audit tab.
9. **No authentication; emergency stop held per process (M2, I4).** Acceptable for a single-process local proof of concept; unsafe for a shared or multi-worker deployment.
10. **Lower severity:** no target editing (A2), no local-model provider (A5), outdated docs (M4), no session ID on the reply event (B2).

---

## F. Scorecard

| Status | Count |
|---|---|
| FULLY IMPLEMENTED AND VERIFIED | 44 |
| IMPLEMENTED BUT UNVERIFIED | 6 |
| PARTIALLY IMPLEMENTED | 13 |
| NOT IMPLEMENTED | 16 |
| BROKEN | 2 |
| BLOCKED | 1 |
| **Total audited requirements** | **82** |

Completion: 44 of 82 = **53.7%** fully implemented and verified.

The requirements are unweighted, which flatters the result: every one of the core execution requirements (D1, D3, D4, E1, F1, G1) is not implemented. By weight, the platform is further from complete than 54% suggests.

---

## G. Remediation plan, in dependency order

1. **Fix the budget race (H3).** Reserve budget atomically, under the run lock or in one database transaction, before sending.
   *Done when:* 10 concurrent calls against a budget of 5 give exactly 5 successes and 5 `budget_technique` refusals.
2. **Fix redaction everywhere (I5).** Redact at every audit, publish and connector-audit call.
   *Done when:* a key-shaped string sent through connectivity appears in no audit action and no event type.
3. **Tighten governance (C5, I9, H6).** Re-check profile and catalog hashes at start; audit plan rejections; move retries into the gateway and count each one.
   *Done when:* a profile change blocks start until re-approval; rejections appear in the audit log; each retry is one Invocation row and counts toward the budget.
4. **PyRIT adapter (F1).** A PyRIT target whose only way out is `ctx.invoke`, registered at startup, with `PromptSendingAttack` and `MultiPromptSendingAttack`, and exported evidence.
   *Done when:* a real `PLUMB-PYRIT` run against the stub completes through the API; Invocation and TestAttempt rows persist with PyRIT's outcome; a changed input is refused (`input_not_approved`); cancellation mid-run stops the run.
5. **Garak adapter (G1).** A `/api/gateway/garak/{run}` endpoint (local-only, token-protected) plus a garak subprocess using its REST generator.
   *Done when:* `test.Test` runs against the stub; 5 prompts succeed and 3 are refused with a skip code; `report.jsonl` is stored and hashed; detector results persist.
6. **Deep Agents coordinator (E1, D4, D5, H5).** Subagents whose only tools are "list approved cases", "execute an approved case" and "read evidence".
   *Done when:* a coordinated run completes; the attacker token budget stops it; the coordinator has no tool that reaches a connector.
7. **Findings integrity (J6, J7, D7).** Exclude or flag imports into stub runs; add a candidate-versus-confirmed tier; produce `skipped`.
   *Done when:* QA fixtures on a stub run create no confirmed findings.
8. **UI (C7, L3, L4, A2, A7).** Profile editor, plan builder and approval, execution controls and progress, invocation evidence, Audit tab, target editing.
   *Done when:* a browser run covers the full sequence with no console errors.
9. **Tests and docs (L11, M4).** Frontend component and end-to-end tests; update README and ARCHITECTURE.
10. **Deployment hardening (M2, A9, A10).** Authentication and roles, a single-worker requirement (or a shared emergency stop), then AWS VM verification.

---

## H. Readiness

| Level | Ready? | Basis |
|---|---|---|
| Local plumbing demonstration | **Partly.** Ready for registration, connectivity, imports, findings, re-test, PDF and emergency stop on the stub. **Not** for framework plumbing | No adapter can run |
| Real local model-backed assessment | **No** | No local-model provider and no adapters |
| Complete framework-driven assessment workflow | **No** | Deep Agents, PyRIT and garak not integrated; budget race; no adaptive loop |
| Future AWS VM deployment | **No** for assessments. A connectivity-only proof of concept could be tried once credentials exist, but remains unverified | Connector untested live (blocked), no authentication, redaction leaks into an immutable audit log |
