# AgentShield

Authorised security assessment console for **your own staging AI agents**: AWS Bedrock AgentCore harnesses, models
served on your machine, and a labelled local stub for development.

What AgentShield does:

- **Registers and edits** staging targets (staging-only, enforced in code) with an ownership statement, and records
  each target's **profile**: role, tools, permissions, data, policies, and values you planted (canaries) for exact
  scoring.
- **Checks connectivity** with one fixed, benign greeting and records measured latency and token usage.
- **Plans** an assessment from the versioned technique catalog and the profile. Every plan states, for each
  technique, why it applies to this agent, its objective, the expected secure behaviour and how each case is scored.
  An operator **approves** the plan; approval fixes its sha256 and is withdrawn automatically if the profile, the
  catalog or the target changes.
- **Executes** approved plans with the real frameworks: **PyRIT 1.1.0** (`PromptSendingAttack`,
  `MultiPromptSendingAttack`, PyRIT datasets and scorers, in-process) and **garak 0.17.1** (its own probes and
  detectors, in an isolated venv). A **LangChain Deep Agents** coordinator decides what runs next: it can run approved
  cases, skip a technique whose objective is already established, or stop when the target is unavailable. It cannot
  write test content.
- **Enforces** every prompt at one **gateway**: approved plan and exact input, provider allowlist, prompt/token/duration
  budgets (reserved atomically, so concurrent calls cannot overrun them), rate limit, timeouts, governed retries,
  pause, stop and the emergency stop. Everything is redacted before it is stored, audited or streamed.
- **Imports** results your team produced elsewhere with garak and PyRIT, plus trap-hit logs.
- **Derives** findings, with a **candidate → confirmed / dismissed** tier: a detector hit is a candidate; a trap hit, an
  exact canary match or an operator decision confirms it. Re-test closure and a posture graph.
- **Exports** a proof PDF and **audits** everything in a hash-chained log.

Stub runs never produce findings; imports into a stub run are kept as sample data.

---

## Run it (no Docker)

Requirements: **Python 3.11+**, **Node 18+**, `make` (Linux/WSL/macOS), or PowerShell on Windows. garak runs from its
own venv in `backend/.venv-garak` (its pins conflict with PyRIT's), created once with:

```bash
python3.11 -m venv backend/.venv-garak && backend/.venv-garak/bin/python -m pip install garak==0.17.1
# Windows: py -3.11 -m venv backend\.venv-garak; backend\.venv-garak\Scripts\python -m pip install garak==0.17.1
```

```bash
make dev          # first run: creates backend/.venv, installs deps, npm install, copies .env.example -> .env
```

- Console: http://127.0.0.1:5173 (Vite proxies `/api` to the API on :8000)
- API docs: http://127.0.0.1:8000/docs
- Windows: `.\dev.ps1` (also `.\dev.ps1 test`, `.\dev.ps1 e2e`)
- Other targets: `make test` (backend + frontend), `make e2e`, `make backend`, `make frontend`, `make build`, `make clean`

Run **one** server process per database. The gateway's budget reservations, run controls and executing assessments
live in that process; a second process on the same database refuses to start. An emergency stop written by any
process is still applied everywhere within a second.

The first start after upgrading migrates `data/agentshield.db` to schema v11 and keeps a backup next to it
(`agentshield.db.bak-v<old>-<timestamp>`).

### Access control

With `AUTH_TOKENS` empty, AgentShield runs in local single-operator mode: bind it to 127.0.0.1 and tunnel in. The
operator name comes from the console's *Operator* field. For any shared deployment set tokens:

```bash
AUTH_TOKENS=alice:<long-random-token>:admin,bob:<long-random-token>:operator,audit:<long-random-token>:viewer
```

- `viewer`: read only.
- `operator`: everything except resetting the emergency stop.
- `admin`: everything.

The audited actor is the token's name. Denied requests are audited. Enter the token in the sidebar.

### On an AWS VM

1. Install Python 3.11, Node 18+ and make. Create both venvs (above).
2. Fill in `.env`: `TARGET_HARNESS_ARN`, `TARGET_REGION`, and leave `AWS_PROFILE` empty to use the **instance role**.
   The target is registered at startup; a non-staging `TARGET_ENVIRONMENT` is refused.
3. The identity needs `bedrock-agentcore:InvokeHarness` on the harness ARN:
   ```json
   {"Effect": "Allow", "Action": "bedrock-agentcore:InvokeHarness", "Resource": "<your harness ARN>"}
   ```
4. To execute plans against AgentCore, opt in explicitly: `ASSESSMENT_PROVIDERS=local_stub,local_model,aws_agentcore`.
   Connectivity checks work without it.
5. Set `AUTH_TOKENS`, then `make dev` and tunnel in (`ssh -L 5173:127.0.0.1:5173 user@vm`).

## Workflow

The console has seven sections: **Overview**, **Targets**, **Evaluation Workspace**, **Runs & Results**,
**Findings**, **Evidence & Audit** and **Reports**.

1. **Targets**: register a target.
   - **AWS Bedrock AgentCore**: harness ARN, region, optional qualifier, profile or role.
   - **Local model (OpenAI-compatible)**: `base_url` on this machine (e.g. Ollama `http://127.0.0.1:11434/v1`) and a
     model name. Loopback URLs only. Real model replies, so results count as security evidence.
   - **Local stub (development)**: no network or model; fixed replies labelled as a stub.
   - **Azure AI Foundry**, **Google Cloud agent**: inventory placeholders; connectivity checks return *Connector pending*.

   **Edit** changes a target; changing how it is reached marks it unverified and withdraws approved plans. **Profile**
   documents the agent; saving a changed profile withdraws approval of existing plans. **Test connection** sends the
   fixed greeting.
2. **Evaluation Workspace**: **Launch run**, then:
   - **All / Messages / Activity / Evidence**: the conversation, live from the gateway. Every message carries its
     provenance (*Sent by AgentShield*, *Live · measured*, *Local stub*, *Imported*). Each reply shows its session id.
   - **Audit**: this run's audit records, with hash-chain status.
   - **Assessment**: draft a plan (techniques that do not apply to the profile, or that no installed engine can run,
     are shown but disabled with the reason), set tighter limits, **Approve**, then **Start execution**. Progress shows
     cases, prompts against the run budget, gateway refusals, target and coordinator tokens, the coordinator's decisions,
     and per-case results; a case row expands to every gateway invocation (prompt, reply, status, retry, session).
     **Stop** cancels in-flight calls; **Resume** runs only the cases without a result.
3. **Runs & Results**: import garak `report.jsonl`, PyRIT JSON or trap-hit logs; attempts with advisory
   `DECISION_MODEL` reviews.
4. **Findings**: candidate / confirmed / dismissed, the basis for that state, evidence, recorded input and reply, and a
   fix. **Confirm** or **Dismiss** with an audited note; the decision survives re-imports and rebuilds.
5. **Schedule re-test**: a child run; passing re-test results close the parent's findings.
6. **Reports**: the proof PDF (executed assessment with plan hash and coordinator, findings with confirmation basis,
   evidence hashes, re-test table, audit-chain status, honest limits).
7. **Emergency stop** (header button, or `Esc`): halts every run and in-flight call; blocks checks, exchanges, imports,
   reviews, plans and new runs until an admin resets it. Survives restarts.

## Result states

| Verdict | Meaning |
|---|---|
| pass | The framework's scorer or detector found the secure behaviour |
| fail | The scorer or detector found the failure (a candidate finding unless confirmed) |
| inconclusive | No objective score (e.g. PyRIT `UNDETERMINED`, nothing scored) |
| error | The adapter, framework or target failed; the error is recorded |
| skipped | Not executed by decision: objective already established, technique budget spent, or skipped by the coordinator |

PyRIT outcomes map as SUCCESS → fail, FAILURE → pass, UNDETERMINED → inconclusive, ERROR → error. garak: any detector
score at or above `GARAK_FAIL_THRESHOLD` → fail.

## Import formats

**garak**: unmodified `report.jsonl`; evaluated `attempt` lines (`status == 2`): `uuid`, `probe_classname`,
`prompt.turns`, `outputs`, `detector_results`.

**PyRIT**: one JSON file with the PyRIT 1.1.0 memory field names (AgentShield writes its own PyRIT evidence in the same
layout, so executed evidence can be re-imported):

```json
{
  "pyrit_version": "1.1.0",
  "message_pieces": [{"id": "...", "conversation_id": "...", "sequence": 0, "role": "user",
                      "original_value": "...", "converted_value": "...",
                      "labels": {"agentshield_category": "T-02", "test_id": "my-suite.case-7"}}],
  "scores": [{"message_piece_id": "...", "score_type": "true_false", "score_value": "True",
              "score_rationale": "...", "scorer_class_identifier": {"__type__": "SomeScorer"}}],
  "attack_results": [{"conversation_id": "...", "outcome": "SUCCESS", "outcome_reason": "..."}]
}
```

**Trap hits** (`.jsonl`): `{"token_id": "...", "external_id": "<garak uuid | PyRIT conversation_id>", "received_at": "...", "source": "..."}`

**Categories**: `backend/category_map.json` maps imported results to T-01..T-05; executed results use catalog
technique ids (`backend/technique_catalog.json`).

## Configuration

Everything is set through environment variables; see `.env.example`. Key settings:

- Limits (plans can only tighten them): `MAX_PROMPTS_PER_TECHNIQUE` (5), `MAX_PROMPTS_PER_RUN` (50),
  `MAX_ACTIVE_ASSESSMENTS` (1), `TECHNIQUE_CONCURRENCY` (2), `MAX_RUN_DURATION_S`, `INVOCATION_TIMEOUT_S`,
  `MIN_INVOCATION_INTERVAL_S`, `INVOCATION_RETRIES` (each retry is a budgeted invocation), `TARGET_TOKEN_BUDGET`,
  `ATTACKER_TOKEN_BUDGET` (coordinator model tokens).
- `ASSESSMENT_PROVIDERS`: providers plans may execute against (default `local_stub,local_model`).
- `COORDINATOR_MODEL`: `deterministic` (default: scripted rules, nothing sent to a model provider), `llm` (uses
  `GENERATION_MODEL` and sends the coordinator's state, i.e. case ids, labels and verdicts, to that provider; falls
  back to deterministic on error), or `auto`.
- `DECISION_MODEL`: advisory reviews of attempts (`<provider>:<model>`, provider `google_genai` or `groq`). Never
  changes a verdict or a finding.
- `EVIDENCE_DIR`: raw framework outputs (PyRIT export, garak `report.jsonl` and log), hashed into the evidence.
- `AUTH_TOKENS`: see *Access control*.

## Tests

- `make test`: **120 backend tests** plus **14 frontend component tests** (Vitest + Testing Library). They cover:
  - every control in the gateway, including the concurrent budget race, redaction in the audit chain and stream,
    stale-plan refusal and budgeted retries;
  - real PyRIT runs (single and multi-turn, refused input, cancellation, canary-confirmed finding on a local model);
  - a real garak subprocess through the HTTP gateway endpoint;
  - the Deep Agents coordinator (tool surface, objective skip, target-down stop, attacker token budget, LLM fallback);
  - findings integrity (stub runs, candidate / confirmed / dismissed);
  - target edit, auth and roles, the shared emergency stop, the single-process lock, migrations, imports, re-test
    closure, PDF.
- `make e2e`: starts a real server on a throwaway database and drives the whole workflow over HTTP (31 checks,
  including real PyRIT and garak execution).

All tests are offline: targets are the local stub or a fake loopback model server.

## Honest limits

- Endpoint testing proves observable behaviour through the agent's endpoint, not internal permissions.
- Verdicts are only as good as the frameworks' scorers and detectors; a detector hit is a candidate until confirmed.
- 9 of 14 security techniques in the catalog have no documented PyRIT/garak execution and are plan-only (shown as not
  executable). AgentShield writes no test content of its own.
- The AWS connector is unit-tested with mocks; live AgentCore calls need credentials on the VM (not verified here).
  Azure AI Foundry and Google Cloud connectors are placeholders.
- The LLM coordinator mode and `DECISION_MODEL` reviews depend on your model provider and were verified only with
  fakes.
- Staging only. Techniques not executed or imported are untested, never passing.
