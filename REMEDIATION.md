# AgentShield — Remediation of AUDIT_REPORT.md

**Date:** 2026-10-30

**Verification:**
- `make test`: 120 backend + 14 frontend tests passing.
- `make e2e`: 31/31 checks against a live server.
- A browser walkthrough of the full sequence on a throwaway database: no console errors, no sideways scroll at 390 px.
- Both real databases migrated v3 → v11 on copies: no rows lost, audit chain intact. The originals are untouched.

Status after remediation, using the audit's IDs. **Fixed** items are verified by the named test or check.

## Critical findings (audit §E)

| # | Finding | Status | What changed · evidence |
|---|---|---|---|
| 1 | No assessment execution (D1, E1, F1, G1) | **Fixed** | PyRIT adapter (`pyrit_adapter.py`), garak adapter + `/api/gateway/garak` endpoint (`garak_adapter.py`), Deep Agents coordinator (`coordinator.py`), registered at startup. `test_adapters.py` runs real PyRIT and a real garak subprocess; e2e runs both through the API |
| 2 | Budget race (H3) | **Fixed** | Every check is repeated and a `pending` Invocation reserved under one per-run lock before sending. `test_concurrent_calls_cannot_exceed_the_technique_budget`: 10 concurrent calls → exactly 5 ok, 5 `budget_technique` |
| 3 | Redaction gaps (I5) | **Fixed** | Redaction inside `audit.record` (before hashing) and `events.publish`, plus imports and evidence files. `test_key_shaped_string_never_reaches_audit_or_stream`: the key appears in no audit action and no event |
| 4 | No adaptive / multi-turn execution (D3, D4) | **Fixed** | `MultiPromptSendingAttack` (one isolated session, tested). The coordinator observes results and skips a technique once its objective is established, or stops when the target is down. It works within the approved plan only and never invents content |
| 5 | Findings from sample data; no confirmation tier (J6, J7) | **Fixed** | Stub runs never produce findings; imports there are flagged as sample data. Candidate → confirmed (trap hit, exact canary match, operator) / dismissed. `test_qa_fixtures_on_a_stub_run_create_no_findings`, `test_detector_hits_are_candidates_until_confirmed` |
| 6 | Ungoverned retries; attacker token budget (H5, H6) | **Fixed** | Retries live in the gateway; each one is a budgeted Invocation. The AgentCore connector makes one attempt. `ATTACKER_TOKEN_BUDGET` stops the coordinator. `test_each_retry_is_a_budgeted_invocation`, `test_attacker_token_budget_stops_the_coordinator` |
| 7 | Approval not tied to the profile; rejections unaudited (C5, I9) | **Fixed** | Plans carry profile and catalog sha256. A change withdraws approval (`plan.invalidated`), start refuses, and the gateway refuses `plan_stale`. Rejected or denied requests are audited (`api.rejected`, `api.denied`) |
| 8 | No planning / execution UI; no Audit tab (C7, L3, L4) | **Fixed** | Workspace **Assessment** tab: plan builder, approval, start/stop/resume, budgets, coordinator, per-case evidence. **Audit** tab. Verified in the browser and in `Assessment.test.tsx` |
| 9 | No authentication; per-process emergency stop (M2, I4) | **Fixed** | `AUTH_TOKENS` with viewer / operator / admin roles. Emergency stop synced from the audit log every second. Single-process instance lock. `test_tokens_roles_and_audited_denials`, `test_emergency_stop_recorded_by_another_process_is_applied`, `test_a_second_server_process_on_the_same_database_is_refused` |
| 10 | A2, A5, M4, B2 | **Fixed** | `PUT /api/targets/{id}` + Edit form. Local model provider (loopback OpenAI-compatible). Docs rewritten. Session id on every reply event |

## Requirement status changes

| ID | Was | Now | Note |
|---|---|---|---|
| A2 | NI | Fixed | Edit endpoint + form; identity changes reset verification and withdraw approvals; audited |
| A5 | NI | Fixed | `local_model` provider; tested against a fake loopback server, not a real Ollama install |
| A7 | NI | Fixed | Profile editor (role, tools, data, policies, hints) |
| A9 | IU | IU | Unchanged code path except one attempt per call; needs the AWS VM |
| A10 | BL | BL | Needs credentials on the VM |
| A11 | NI | NI | Azure / Google connectors remain labelled placeholders ("implement when needed") |
| B2 | PI | Fixed | |
| C2 | PI | Fixed | Objective, expected secure behaviour and scoring criteria in every plan technique and case |
| C5 | NI | Fixed | |
| C6 | PI | Documented | A plan changes by drafting a new version; the UI says so at approval |
| C7 | NI | Fixed | |
| D1, D3, F1, G1, E1 | NI | Fixed | E1 verified with the deterministic chat model; LLM mode verified only through its tested fallback |
| D2 | PI | Improved | Profile-specific rationale (forbidden actions, data, policies) and plan options showing applicability; selection is still rule-based |
| D4, D5 | NI / PI | Fixed | Objective-established skip, target-unavailable stop, budget and attacker-token stops |
| D6, H7, J1 | IU | Verified | With real PyRIT and garak adapters |
| D7 | PI | Fixed | pass / fail / inconclusive / error / skipped |
| H3, I5 | BR | Fixed | |
| H5, H6, I9 | PI / NI | Fixed | |
| I4 | FV | Hardened | Multi-process stop sync plus single-process lock |
| J3 | IU | IU | `DECISION_MODEL` is unset in `.env`; tested with a fake model only |
| J5 | FV | Fixed | Coverage section removed from the PDF; executed-assessment section and confirmation basis added |
| J6, J7 | PI | Fixed | |
| K1 | FV | Verified | Copies of both real databases migrate v3 → v11 |
| L3, L4 | PI / NI | Fixed | |
| L10 | PI | Improved | Execution surfaces built in the existing design system |
| L11 | NI | Fixed | 14 component tests (Vitest + Testing Library) and a live-server e2e script (`make e2e`) |
| M1 | FV | Fixed | Target edit, garak gateway endpoint, plan options, finding review, auth info |
| M2 | NI | Fixed | |
| M3 | IU | IU | Needs the AWS VM |
| M4 | PI | Fixed | README, ARCHITECTURE, `.env.example` |

## Still open (needs something this environment does not have)

- **A9, A10, M3:** live AWS AgentCore. Needs credentials or an instance role on the VM. Add `aws_agentcore` to
  `ASSESSMENT_PROVIDERS` only on an authorised deployment.
- **J3, and the LLM coordinator mode:** need a configured model. `COORDINATOR_MODEL` defaults to `deterministic`, so
  nothing is sent to a model provider unless you opt in.
- **A11:** Azure AI Foundry and Google Cloud connectors.
- **Plan-only techniques:** 9 of 14 security techniques have no documented PyRIT or garak execution and stay
  plan-only by design (AgentShield writes no test content).
