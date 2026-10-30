# AgentShield — Architecture

## 1. Scope

AgentShield plans, executes and evidences authorised security assessments of an operator's own **staging** agents,
and imports results produced elsewhere. Every prompt that reaches a target passes one gateway.

```
 React console ◄──SSE── FastAPI (one process per database)
   │ REST             │
   │                  ├─ plans.py ── catalog + target profile ──► hashed plan ──► operator approval
   │                  ├─ orchestrator.py ── Execution (bounded parallel cases, lifecycle, resume)
   │                  │      ▲  only tools: list / execute / skip approved cases, read evidence, stop
   │                  │      └── coordinator.py: LangChain Deep Agents graph (supervisor + evidence-analyst, reporter)
   │                  │                │ execute_approved_case
   │                  │                ▼
   │                  ├─ adapters ── pyrit_adapter (PyRIT 1.1.0 in-process: PromptTarget -> ctx.invoke)
   │                  │              garak_adapter (garak 0.17.1 subprocess, REST generator -> /api/gateway/garak)
   │                  │                │
   │                  ├─ gateway.py ◄──┘  every control, atomic budget reservation, retries, redaction, audit
   │                  │      └─► connectors: aws_agentcore (InvokeHarness) · local_model (loopback OpenAI API) · local_stub
   │                  ├─ connectivity.py (fixed greeting, same gateway send path)
   │                  ├─ ingest/ (garak, PyRIT, traps) ─► store.rebuild ─► findings (candidate/confirmed/dismissed)
   │                  ├─ audit.py (sha256 hash chain, redacted)   events.py (persisted stream, redacted)
   └── Export PDF ◄───┴─ report.py
```

## 2. Doc-verified framework APIs (checked 2026-10-30 against the installed packages and the vendors' docs)

| Framework | API used |
|---|---|
| PyRIT 1.1.0 | Subclass `PromptTarget`, override `_send_prompt_to_target_async(*, normalized_conversation)` (`send_prompt_async` is final). Declare `TargetConfiguration(capabilities=TargetCapabilities(supports_multi_turn=True))` (`PromptChatTarget` is deprecated). Reply with `construct_response_from_request(piece, [text])`. `PromptSendingAttack(objective_target=, attack_scoring_config=).execute_async(objective=, next_message=)`; `MultiPromptSendingAttack(...).execute_async(objective=, user_messages=)`; `AttackScoringConfig(objective_scorer=SubStringScorer(substring=))`; `AttackOutcome` SUCCESS / FAILURE / UNDETERMINED / ERROR. Memory: `CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:"))`. Datasets: `SeedDataset.from_yaml_file`. |
| garak 0.17.1 | `python -m garak --config run.yaml --target_type rest --generator_option_file gen.json --spec probes.<probe> [--detectors <d>]`; generator file `{"rest": {"RestGenerator": {uri, method, headers, req_template_json_object, response_json, response_json_field, request_timeout, skip_codes, ratelimit_codes}}}`; config `run.generations`, `run.soft_probe_prompt_cap`, `system.parallel_attempts`, `reporting.report_dir/report_prefix`. A status in `skip_codes` records the prompt as unanswered and the run continues. `report.jsonl` `attempt` rows, status 2 = evaluated. `--probes` is deprecated in favour of `--spec`. |
| deepagents 0.7.32 | `create_deep_agent(model=, tools=, system_prompt=, subagents=[{name, description, system_prompt, tools}], name=)`; default `StateBackend` is an in-state virtual filesystem (no host access); streaming with `agent.stream(..., stream_mode="updates", subgraphs=True, version="v2")`. |
| AgentCore | `invoke_harness(harnessArn, runtimeSessionId (33..100), messages, qualifier?)` → event stream (see `connectors/aws_agentcore.py`). |
| reportlab | `SimpleDocTemplate`, `Paragraph`, `Table` / `TableStyle`, `KeepTogether`. |

## 3. Modules (`backend/agentshield/`)

| Module | Responsibility |
|---|---|
| `config.py` | pydantic-settings; every tunable from env / `.env` (limits, providers, coordinator mode, auth tokens) |
| `db.py` | SQLite (WAL, foreign keys, busy timeout), append-only migrations (v11) with automatic backup, single-process instance lock |
| `models.py` | schema (§4) |
| `safety.py` | `assert_staging` (hard-coded), `KillSwitch`, `MinInterval` |
| `redact.py` | credential-shaped values and configured keys → `[REDACTED:<kind>]`; applied in `audit.record`, `events.publish`, invocation rows, imports and evidence files |
| `integrity.py` | `plan_sha`, `profile_sha`, `catalog_sha`, `staleness` |
| `gateway.py` | the only path to a target (§5) |
| `connectivity.py` | the fixed greeting, through `gateway.send`; retries governed by `INVOCATION_RETRIES` |
| `connectors/` | `aws_agentcore` (one attempt per call; retries live in the gateway), `local_model` (loopback OpenAI-compatible), `local_stub`, placeholders |
| `profile.py` | target profile; technique applicability and profile-specific rationale |
| `catalog.py` | technique catalog + taxonomy |
| `assessment/plans.py` | build (objective, expected behaviour, scoring per case; profile and catalog hashes), approve (refuses stale plans), invalidate on profile/catalog/target change, plan options |
| `assessment/orchestrator.py` | lifecycle, queueing, `Execution` (bounded parallel cases, skip, stop, evidence), persistence, restart recovery |
| `assessment/coordinator.py` | Deep Agents coordinator, scripted (deterministic) chat model, attacker token budget, decision stream |
| `assessment/pyrit_adapter.py`, `garak_adapter.py`, `adapters.py` | framework execution; registered at startup |
| `ingest/` | parsers and `store.rebuild`: findings, confirmation tier, re-test closure, graph, summary |
| `judge.py`, `llm.py` | advisory `DECISION_MODEL` review |
| `audit.py`, `events.py` | hash chain; persisted SSE events |
| `report.py` | proof PDF |
| `app.py` | routes (§6), access control, audit of denied requests, kill-switch sync |

## 4. SQLite schema

| Table | Holds |
|---|---|
| `targets` | provider, config, identity (ARN/region/…), staging environment, ownership statement, profile, last measured check |
| `runs` | lifecycle status, assessment status/phase/stop reason, approved limits + plan sha, execution bookkeeping (progress, coordinator, attacker tokens) |
| `assessment_plans` | versioned plan content + sha256; draft / approved / superseded / invalidated |
| `invocations` | every gateway call: pending (reserved) / ok / error / refused, attempt number, prompt, reply, session, usage, latency |
| `imports`, `test_attempts`, `trap_hits` | imported files and attempts; executed cases (`provenance = local-execution`) with framework verdict, evidence file + sha256, invocation ids |
| `findings` | one per (category, test) with failures; open/closed; candidate/confirmed/dismissed + basis |
| `finding_reviews` | operator confirm/dismiss decisions, re-applied on every rebuild |
| `audit_log` | append-only, hash-chained, redacted |
| `events`, `graph_nodes`, `graph_edges`, `schema_version` | stream, posture graph, migrations |

## 5. Gateway (`gateway.invoke`)

In order, before a prompt leaves the process: emergency stop → run cancelled → pause (waits) → run open and assessment
running → target staging, not archived, connector implemented → provider in `ASSESSMENT_PROVIDERS` → approved plan
whose sha256 matches the one recorded at approval → plan not stale (profile and catalog unchanged) → engine and case
approved for the technique → exact approved input (PyRIT) → budgets (prompts per run and technique, duration, target
tokens) → rate limit (waits) → **every check again plus reservation of a `pending` Invocation, under one per-run lock**.
Concurrent calls therefore never overrun a budget. Then the call runs with a hard timeout and cancellation; the result
is redacted into the reserved row, audited and streamed. Transient errors are retried up to the approved
`invocation_retries`; each retry passes every control again and is its own budgeted Invocation. Refusals are
persisted and audited with a code (`budget_technique`, `input_not_approved`, `plan_stale`, …). Pending rows left by a
crash become errors at startup.

## 6. HTTP API (main routes)

| Route | Purpose |
|---|---|
| `GET /api/health`, `/api/auth`, `/api/config`, `/api/engines`, `/api/catalog`, `/api/providers` | status and configuration |
| `GET/POST /api/targets`, `PUT /api/targets/{id}`, `POST /api/targets/{id}/archive`, `POST /api/targets/{id}/check`, `GET/PUT /api/targets/{id}/profile` | targets |
| `GET/POST /api/runs`, `GET /api/runs/{id}`, `POST …/pause|resume|stop|complete|exchange|imports|judge` | runs |
| `GET /api/runs/{id}/plan-options`, `GET/POST /api/runs/{id}/plans`, `POST …/plans/{v}/approve` | planning |
| `GET /api/runs/{id}/assessment`, `POST …/assessment/start|resume|stop`, `GET …/invocations` | execution |
| `POST /api/gateway/garak/{run}/{case}` | garak REST generator endpoint (loopback + one-time case token) |
| `GET /api/runs/{id}/timeline|attempts|findings|report.pdf`, `POST /api/findings/{id}/review`, `POST /api/attempts/{id}/judge` | evidence |
| `GET /api/audit`, `/api/audit/verify`, `/api/events`, `/api/stream`, `/api/graph` | audit and stream |
| `GET/POST /api/kill`, `POST /api/kill/reset` | emergency stop (reset: admin) |

With `AUTH_TOKENS` set every route except `/api/health` and `/api/auth` needs a bearer token (or `?access_token=` for
EventSource and downloads); viewers are read-only and only admins reset the emergency stop. Denied and rejected
mutating requests are audited (`api.denied`, `api.rejected`).

## 7. Safety controls (enforced in code)

- **Staging only**: constant, checked at registration, seeding, connector build, run creation, every check and call.
- **One gateway**: connectors are built and called only in `gateway.py` (assessment) and through `gateway.send`
  (connectivity). The coordinator's tools cannot reach a connector; garak reaches the gateway only through the
  loopback, token-protected endpoint.
- **No invented test content**: PyRIT inputs are dataset seeds or operator benign turns fixed at approval; garak
  prompts come from the approved probe; the gateway refuses anything else.
- **Approval integrity**: plan sha256, and profile and catalog hashes; changes withdraw approval.
- **Budgets**: atomic reservation; retries count; attacker-side token budget for the coordinator.
- **Emergency stop**: stops in-flight calls; persisted in the audit log, restored at startup and synchronised across
  processes every second.
- **Redaction**: before storage, audit, stream and evidence files; the audit chain never holds raw secrets.
- **Findings integrity**: stub runs never produce findings; detector hits are candidates until confirmed.
- **Credentials**: from the AWS credential chain; never stored; never passed to the garak subprocess.
