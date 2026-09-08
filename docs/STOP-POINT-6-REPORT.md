# STOP POINT 6 REPORT — AI SAFETY + GOVERNANCE CONTRACT

**Status: PUBLISHED / CERTIFIED — STOPPING FOR OWNER APPROVAL.**
Per the standing directive, Stop Point 7 (Shared Partner SDK, Partner Registry Contract, Secure Webhook/Event Framework, Observability Contract) has NOT been begun. The exact owner-approved SP7 proposal is reproduced verbatim in §10. This report is the deliverable for owner review.

---

## 1. Publication record

- **Repository:** `thefsts/arma-partner-api-sandbox` (public sandbox), branch `main`
- **Final remote HEAD SHA (SP6 close):** this report, including its closing note, is the last commit of Stop Point 6 — the authoritative close SHA is `git rev-parse origin/main` at owner review. The full SP6 commit chain is listed below; no work follows this file.
- **Baseline before this stop point:** `e43ac8a699ea0e52d89dd4e430ce8c86cb08cb04` (SP5 approved close, CI GREEN run `34179962450`, 149/149 tests)
- **Pushes:** fast-forward only (`e43ac8a..6ae2baf`, then the report commit), no force push, no history rewrite — PUBLICATION RULE honored
- **Commits added this stop point:**
  - `6ae2baf` — `feat: stop point 6 — AI safety + governance contract (advisory-only AI, fail-closed protected actions, provenance, guards)` (CI run `34237287938`, completed/success) — 21 files changed, 4151 insertions(+), 6 deletions(-)
  - report commits (this file) — CI runs recorded in §2
  - final close-out commit — records the certified report-close CI run (`34239672897`, GREEN) in §2
  - **Author and committer on every SP6 commit:** `THEFSTS <amorebey@gmail.com>` (verified via `git show --format`)
- **Files in the feature commit:**
  - Added: `ai-governance/classification.ts` (173), `ai-governance/provenance.ts` (401), `ai-governance/provenanceIntegrity.ts` (47), `ai-governance/protectedActions.ts` (370), `ai-governance/deterministicRules.ts` (306), `ai-governance/externalDataGuard.ts` (238), `ai-governance/aiOutputGuard.ts` (149), `ai-governance/humanReview.ts` (157), `ai-governance/audit.ts` (134), `ai-governance/store.ts` (144), `ai-governance/index.ts` (18)
  - Added: `ai-governance/tests/helpers.mjs` (142), `ai-governance/tests/governance.test.mjs` (280), `ai-governance/tests/provenance.test.mjs` (354), `ai-governance/tests/injection.test.mjs` (365), `ai-governance/tests/protected-actions.test.mjs` (474), `ai-governance/tests/human-review.test.mjs` (148), `ai-governance/tests/e2e.synthetic.test.mjs` (229)
  - Modified: `README.md` (SP6 section, 205-test totals, ai-governance lane description, typecheck include note), `package.json` (test:aigov script), `tsconfig.json` (include `ai-governance/**/*.ts`)

## 2. CI evidence

- **Feature-commit CI run ID:** `34237287938` — workflow "CI" on commit `6ae2baf`
- **CI URL:** https://github.com/thefsts/arma-partner-api-sandbox/actions/runs/34237287938
- **Conclusion:** `completed / success`
- **Job steps (all success):** Set up job, checkout, pnpm setup, Node 24 setup, Install (`pnpm install --frozen-lockfile`), **Typecheck (`pnpm typecheck`) GREEN**, **Tests (synthetic only) (`pnpm test`) GREEN**, **Secret scan GREEN (no match)**, post steps
- Job: `verify` (all 12 steps success), started `2026-09-08T14:17:13Z`, completed `2026-09-08T14:17:35Z` (22s)
- **Report-commit CI runs (full history for the record):**
  - Run `34237668332` (first attempt, original report wording) — cancelled after the runner hung >11 min on the Tests step (runner-side stall; the identical suite passed GREEN in 22s on the feature commit and the report commit adds only this docs file)
  - Run `34237668332` (rerun of the same commit) — Tests step GREEN (~2s), but the informational secret-scan step flagged a false positive **in this report's own prose**: a hyphenated compound naming task and designation matched the `sk-[A-Za-z0-9]{8,}` informational pattern (the `sk-` prefix immediately followed by the word "designation"). No real secret was involved — the wording tripped the scanner. The failure was introduced by this report's wording, not by any repo content or code change.
  - Run `34239469635` (first addendum, commit `df78c0e`) — same scan failure, because the CI-history note quoted the offending compound while explaining it; the fix text itself tripped the same pattern.
  - Run `34239672897` (final wording, commit `5b82335`) — **completed / success**: all steps GREEN including the informational secret scan. This is the certified report-close CI run for the report wording.
  - Run `34239829043` (close-out commit `d3e8d9a`) — **completed / success**: the run stalled on the Tests step (same runner-side signature as the first report-commit run), was cancelled and re-run, and the rerun completed GREEN in ~70s. All steps GREEN including the informational secret scan.
  - This final commit's own run is visible in the repository's Actions history; per the SP5 close-out precedent the report does not embed its own run ID — the authoritative close state is `git rev-parse origin/main` at owner review.

## 3. Exact local test totals (same commands CI runs)

- `pnpm test` (all lanes): **tests 205 / pass 205 / fail 0 / cancelled 0 / skipped 0 / todo 0** — exit 0
  - law-shield lane: **71/71**
  - PATCHES partner API v1 contract lane: **30/30** (SP4 suite, unchanged from the certified baseline)
  - ARMA PATCHES adapter lane: **48/48** (SP5 suite, unchanged from the certified baseline)
  - ai-governance lane: **56/56** (new this stop point; `pnpm test:aigov` runs it in isolation)
    - `governance.test.mjs`: 10/10 — vocabulary + engine registration + task-type boundaries
    - `provenance.test.mjs`: 13/13 — envelope create/verify, HMAC metadata tamper, output tamper, freshness, expiry
    - `injection.test.mjs`: 9/9 — probe-verified injection tables (33 external-data + 31 AI-authority samples), no-content-leak audit assertions
    - `protected-actions.test.mjs`: 16/16 — 10-action registry, AI-never-allowed, unknown → DENIED, fail-closed rules, human authorization binding
    - `human-review.test.mjs`: 4/4 — review record/verify binding, eligibility fail-closed, review↔envelope binding
    - `e2e.synthetic.test.mjs`: 4/4 — full chain, injection short-circuit, post-approval tamper, cross-org isolation
- `pnpm typecheck` (strict, includes `ai-governance/**/*.ts` via tsconfig include): **GREEN, exit 0**
- Secret scan (CI `git grep` pattern over tracked files): **no match — clean**; the only key present is the declared synthetic `SYNTHETIC-sandbox-integrity-key-SP6-NOT-PRODUCTION` (see §7), and every private-engine name occurrence in the repo is a directive reference in comments/docs, never an implementation or prompt.

## 4. Governance design (what shipped)

`ai-governance/` is the reusable integration-facing AI governance layer per the owner's binding directive. It contains **no** private engine implementations, **no** prompts, **no** model keys, and **no** engine internals for MILAN, JOY, ROSE, RERE, DALINN, or any other proprietary ARMA engine — engines appear only behind registered synthetic identities (`SYNTHETIC-ADVISORY-ENGINE-1`, `SYNTHETIC-RULE-ENGINE-1`, etc.) with class/designation metadata, which is exactly how the private repo will register its real engines without exposing anything proprietary.

- **`classification.ts`** — the vocabulary and registration core. Five designations (`AI_ADVISORY` / `DETERMINISTIC_RULE` / `HUMAN_AUTHORIZATION` / `SYSTEM_AUTOMATION` / `EXTERNAL_PARTNER_DATA`); four engine classes (`GENERATIVE_AI` / `DETERMINISTIC_RULE_ENGINE` / `HUMAN_OPERATOR_CONSOLE` / `SYSTEM_AUTOMATION_ENGINE`); the seven AI_MAY task types (`analyze`, `summarize`, `classify`, `recommend`, `identify_issues`, `flag_for_review`, `advise`); deterministic task types (`policy_evaluation`) kept separate so RERE-style rule engines can never masquerade as generative AI. Registration is fail-closed: a `GENERATIVE_AI` engine **must** register `AI_ADVISORY` + `advisoryOnly: true` (structural rule — an AI engine cannot even register as anything else); rule engines cannot claim advisory; nothing can register as external data; task/designation pairs are checked against the engine class, so a generative engine cannot emit a `DETERMINISTIC_RULE` output and a rule engine cannot emit an `AI_ADVISORY` output.
- **`provenance.ts` + `provenanceIntegrity.ts`** — the AI provenance envelope exactly as directed: engine ID, engine version, task type, advisory/deterministic designation, timestamp, source references, confidence, `humanReviewRequired`, `reviewingHumanId`/review timestamp where required, output hash (SHA-256 over the exact output bytes), policy version, audit ID. Envelopes are HMAC-signed; verification is fail-closed and ordered: structural validation (including the reviewer-fields rule — reviewer fields present without `humanReviewRequired` is a structural failure before any HMAC math), then `METADATA_TAMPERED` (HMAC), then `OUTPUT_TAMPERED` (hash over the exact bytes), then freshness (±5 min window). Verified envelopes are frozen.
- **`externalDataGuard.ts`** — partner-sourced data is DATA, never instructions, never an engine lane. It rejects: embedded instruction keys (`system_prompt`, `instructions`, `role`, `goal`, `tool_call`, `function_call`, etc. — the 14-key forbidden list, normalized so `System-Prompt_2` → `SYSTEMPROMPT` still catches), injection patterns in string values (33 verified patterns: `IGNORE_PREVIOUS`, `AI_AUTHORIZATION_COMPLETE`, `HIGHER_PRIORITY_CLAIM`, …), structural depth > 24, payloads > 2 MB, non-JSON-serializable values (functions), and invalid source references. Clean data passes through **sanitized and frozen** with an `EXTERNAL_PARTNER_DATA` designation, byte length, and content hash — it can be logged, hashed, and referenced, but it can never become a system instruction.
- **`aiOutputGuard.ts`** — the AI output gate. Every advisory output must carry a registered engine ID and an approved task type; the guard rejects oversized/missing output, unregistered engines, unapproved task types, and — the core of the 15 AI prohibitions — any output text asserting authorization over a protected action (31 verified AI-authority patterns: `AI_AUTHORIZE`, `AI_SUPPRESS_REVIEW`, `AI_ACT_WITHOUT_REVIEW`, …) or containing embedded tool/function-call instruction keys. Clean advisory outputs pass marked `advisoryOnly: true` in both the sanitized record and the audit details — advisory is the only thing an AI engine is ever allowed to say.
- **`protectedActions.ts`** — the protected-action registry of exactly 10 actions where AI is never an allowed actor and unknown actions fail closed: `LAW_SHIELD_DISCLOSURE`, `EVIDENCE_DESTRUCTION`, `AUDIT_MUTATION`, `RBAC_CHANGE`, `ADMIN_GRANT`, `PARTNER_CREDENTIAL_CHANGE`, `TENANT_OWNERSHIP_CHANGE`, `ENTITLEMENT_OVERRIDE`, `SECURITY_POLICY_OVERRIDE`, `RETENTION_HOLD_CHANGE`. `evaluateProtectedAction` rules: an `AI` actor on a registry action → DENIED `AI_ACTOR_DENIED`, every time, regardless of what the output claims; an unknown action → DENIED `PROTECTED_ACTION_UNKNOWN` (fail closed — the registry is exhaustive, not illustrative); deterministic rule-engine automation is allowed only for the fail-closed subset (`AUDIT_MUTATION` never — the audit chain is append-only by construction); `HUMAN_OPERATOR` actors are authorized only through a verified human review bound to the exact output hash, org, and action; the decision record carries the reviewing provenance ID and review ID so the approval chain is inspectable end to end.
- **`humanReview.ts`** — the human authorization binding. Reviews are recorded only by authenticated, authorized, org-scoped human reviewers (actor type, session auth, org match, per-action authorization, output hash validity all enforced fail-closed) and verification binds a review to one exact (reviewer, action, org, outputHash) tuple, so an approval for one output can never authorize another. A review is only usable in a protected-action decision if the governed output still hashes to what was reviewed — tampering the output after approval invalidates the review at decision time.
- **`deterministicRules.ts`** — the rule-engine seam. Deterministic engines (RERE-style) register separately from generative AI and may only produce deterministic-designation outputs; the module encodes the rule-side of the prohibitions (fail-closed automation subsets, no advisory claims) so a rule engine can be a governed automation actor without ever being confused with a generative engine.
- **`audit.ts` + `store.ts`** — append-only, metadata-only audit. Every registration, classification, guard decision, envelope verification, review, and protected-action decision is audited with kind/reasonCode/actor/org/correlation and **never** with payload content: the guard tests assert, for every one of the 64 injection samples, that the rejected text does not appear anywhere in the serialized audit log. The audit log refuses mutation attempts (and audits the refusal), matching the SP1 pattern. The store's declared `SYNTHETIC_INTEGRITY_KEY` is the only key in the lane and is synthetic by name and value.

## 5. Required test matrix — results by category (all 56 GREEN)

**Vocabulary + registration (governance, 10):** all five designations and four engine classes are exact and frozen; the AI_MAY list is exactly the seven directed task types; a generative engine cannot register non-advisory (`AI_ENGINE_MUST_BE_ADVISORY_ONLY`); a rule engine cannot register advisory; external data cannot register as an engine; task/designation pairs are enforced per class in both directions; unknown task types rejected; engine ID/version patterns enforced — **all PASS**

**Provenance (13):** envelope round-trip verify with full metadata; HMAC metadata tamper caught on every field variant (engine version, task type, reason code, confidence, reviewing human, classification, org, source refs, correlation, protected-action flag); reviewer-fields-before-HMAC ordering verified; output byte tamper → `OUTPUT_TAMPERED` (hash over exact bytes, not a re-stringify); freshness window honored and stale envelope → `PROVENANCE_EXPIRED`; verified envelope frozen; structural rejections (null input, missing engine, missing task type, bad designation) fail closed — **all PASS**

**Injection tables (9, probe-verified):** all 33 external-data injection patterns (`IGNORE_PREVIOUS` → `HIGHER_PRIORITY_CLAIM`) and all 31 AI-authority patterns (`AI_AUTHORIZE` → `AI_SEND_INSTRUCTION`) reject with the exact pattern ID (bidirectional: every sample maps to its pattern, every pattern is covered by a sample); the 14 embedded instruction keys (normalized: `KEY_SYSTEMPROMPT` etc.) reject as `EMBEDDED_INSTRUCTION_KEY_DETECTED`; deep nesting → `STRUCTURE_DEPTH`; >2 MB → `SIZE_LIMIT`; clean partner data passes sanitized/frozen with content hash + `EXTERNAL_PARTNER_DATA` designation; clean advisory output passes `AI_ADVISORY_OUTPUT_ALLOWED` with `advisoryOnly: true` audited; safe review-language samples never false-flag; every rejection is audited with kind + reasonCode + pattern ID and **zero payload content** (asserted sample-by-sample); structural throws (`EXTERNAL_DATA_INPUT_INVALID`, `EXTERNAL_DATA_SOURCE_REF_INVALID`, `AI_OUTPUT_INPUT_INVALID`, `AI_OUTPUT_ENGINE_ID_INVALID`) fail closed; function-valued keys return `VALUE_TYPE` rejection and are audited — **all PASS**

**Protected actions (16):** the registry is exactly the 10 directed actions; `AI` actor on each of the 10 → DENIED `AI_ACTOR_DENIED` (AI never an allowed actor, no exceptions); unknown action → DENIED `PROTECTED_ACTION_UNKNOWN` (fail closed both for AI and human actors); rule-engine automation allowed only on the fail-closed subset and never `AUDIT_MUTATION`; human authorization requires a verified review bound to action + org + output hash; wrong-action, wrong-org, wrong-hash, and unbound reviews all DENY; the decision record carries `reviewId` + `reviewedProvenanceId` on ALLOW; audit decisions recorded for every evaluation — **all PASS**

**Human review (4):** valid review recorded + audited (metadata only) and durable (frozen, retrievable by ID, deep-equal on read); eligibility fail-closed — AI actor type, unauthenticated, cross-org, unauthorized-for-action, invalid ID, invalid action, invalid hash all reject with zero reviews and zero audits recorded; verification binds the exact (reviewer, action, org, hash) tuple — mismatch on any axis rejects; the review↔envelope binding — a governed output's hash verifies against its review, and a tampered output fails both `REVIEW_OUTPUT_HASH_MISMATCH` and `OUTPUT_TAMPERED` at the envelope — **all PASS**

**Synthetic E2E (4):** the full chain — partner data classified as data → advisory output allowed → provenance envelope created + verified → AI attempts the protected action → DENIED → human reviews the exact output → review recorded + verified → human operator executes with the bound review → ALLOWED `HUMAN_AUTHORIZED_ON_ADVISORY` with the provenance + review chain intact — with the complete audit chain asserted, zero content leakage, and append-only audit (mutation attempt refused + audited); the injection short-circuit — a poisoned partner payload never reaches an AI task and the AI is denied downstream; the post-approval tamper — altering the output text after approval is caught at the guard, the envelope, the review, and the protected-action decision, and the action stays DENIED; cross-org isolation — a review from another org never authorizes — **all PASS**

## 6. Verification methodology note (probe-verified tables)

The injection sample tables were not hand-asserted: `/workspace/probe_guards.mjs` drove the REAL guards with each candidate sample and printed the actual verdict/pattern ID, and those printed truths became the asserted expectations (64/64 mappings verified before the test file was written). The pattern list is therefore exhaustive in both directions — every sample maps to exactly the pattern the guard actually matches, and every pattern id in the guard tables is covered by at least one asserted sample. The probe itself stays out of the repo; the test tables are the durable record.

## 7. Sanitization statement

- Synthetic data only: every identifier is synthetic (`SYNTHETIC-ADVISORY-ENGINE-1`, `SYNTHETIC-RULE-ENGINE-1`, `ORG-…`, `partner-feed:…`); capability names remain the generic contract identifiers.
- No PII crosses any boundary; source references are opaque partner feed references.
- **No private prompts, no model keys, no engine internals** for MILAN, JOY, ROSE, RERE, DALINN, or any proprietary ARMA engine: the names appear in the repo only as directive references (the prohibition comments in `deterministicRules.ts` / `classification.ts` and the README/report directive text), never as implementations, registrations, or prompt material. Engines surface only as registered synthetic identities with class/designation metadata — the integration seam the private repo fills in.
- The only key in the lane is the declared synthetic `SYNTHETIC_INTEGRITY_KEY = 'SYNTHETIC-sandbox-integrity-key-SP6-NOT-PRODUCTION'` (`store.ts`), synthetic by name and value; production porting swaps it for the real secret store (see §9).
- No Alert ARMA UI, no Domus UI, no direct database access.

## 8. Remaining ai-governance gaps (private-repo / production-only — not expanded here)

1. **Real engine registration** — the synthetic engine identities are placeholders; the private repo registers MILAN/JOY/ROSE/RERE/DALINN (or their gateway wrappers) behind the same registration contract, supplying only IDs/versions/classes — still no prompts or keys in this repo.
2. **Production integrity key** — `SYNTHETIC_INTEGRITY_KEY` → KMS/Convex-backed secret store; the HMAC seam (`provenanceIntegrity.ts`) is the only touchpoint.
3. **Persistence port** — `store.ts` is the in-memory reference (frozen records, append-only audit); production maps it to Convex tables with the same semantics.
4. **Review workflow tooling** — `humanReview.ts` is the contract; the private repo adds the operator UI/workflow (Alert ARMA) on top, which cannot weaken the binding rules.
5. **Policy version governance** — `policyVersion` is carried on envelopes and decisions; a policy registry with versioned updates is private-repo work.

## 9. Private-repo porting notes

- `ai-governance/classification.ts` is the registration contract: lift as-is, register real engines (IDs/versions/classes only) in the private repo's bootstrap, and the advisory-only structural rule holds for every generative engine with zero code changes.
- `ai-governance/protectedActions.ts` — the 10-action registry and fail-closed semantics are the contract; private repos may extend the registry through the same exhaustive-fail-closed mechanism (never by bypassing `evaluateProtectedAction`).
- `ai-governance/provenance.ts` + `provenanceIntegrity.ts` — swap `SYNTHETIC_INTEGRITY_KEY` for the production key source; verification order and freshness window are contract behavior.
- `ai-governance/externalDataGuard.ts` / `aiOutputGuard.ts` — transport-agnostic, no sandbox dependencies; wire into the partner-data ingest and the engine output paths respectively. The 33 + 31 pattern tables and 14 forbidden keys are data, extensible without touching the guard logic.
- `ai-governance/tests/` — the 56-test matrix is the certification suite for the port: same assertions, synthetic engine identities replaced by the private registrations, `SYNTHETIC_INTEGRITY_KEY` replaced by the production key in the test bootstrap only.

## 10. Stop Point 7 proposal — SHARED PARTNER PLATFORM (PROPOSAL ONLY — not begun)

Per the standing directive, the following is the exact owner-approved scope for Stop Point 7, reproduced verbatim. No work has begun.

> STOP POINT 7 — SHARED PARTNER PLATFORM
> ====
> Once Law Shield is GREEN and PATCHES contract is approved, refactor common infrastructure into reusable components.
>
> BUILD:
>
> A. SHARED PARTNER SDK
>
> - request signing
> - signature verification
> - receipt verification
> - idempotency
> - replay protection
> - correlation/request IDs
> - API version negotiation
> - structured errors
> - retries/backoff
> - fail-closed/circuit behavior
> - audit/provenance
> - health/readiness
>
> B. PARTNER REGISTRY CONTRACT
>
> Model:
>
> organization
> → partner
> → entitlement
> → capability
> → status
> → API version
>
> Do NOT hardcode partner logic throughout ARMA.
>
> C. SECURE WEBHOOK/EVENT FRAMEWORK
>
> Support:
>
> - status changes
> - processing completed
> - revocation
> - entitlement changes
> - failures
> - reconciliation events
>
> Include:
>
> - signatures
> - event IDs
> - replay prevention
> - ordering
> - idempotency
> - retries
> - dead-letter behavior
>
> D. OBSERVABILITY CONTRACT
>
> Track WITHOUT sensitive payloads:
>
> - request/transfer ID
> - partner
> - organization reference
> - operation
> - start/completion
> - latency
> - success/failure
> - retry count
> - error category
> - reconciliation status
>
> NEVER LOG SENSITIVE PAYLOAD CONTENT.
>
> STOP FOR OWNER REVIEW.

---

**STOP.** Stop Point 6 is published and certified: feature commit `6ae2baf` (CI run `34237287938`, GREEN) + report chain (`f3fd39a`, `df78c0e`, `5b82335` with certified GREEN run `34239672897`, and this close-out), 205/205 tests (71 law-shield + 30 patches contract + 48 patches adapter + 56 ai-governance), typecheck GREEN, secret scan clean on the final tree, fast-forward publication only. The final remote HEAD is the last SP6 commit on `main` — `git rev-parse origin/main` at owner review gives the authoritative close SHA. Awaiting owner decision on the Stop Point 7 proposal above. No further work will begin without explicit approval.
