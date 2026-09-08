# STOP POINT 5 REPORT — ARMA PATCHES ADAPTER

**Status: PUBLISHED / CERTIFIED — STOPPING FOR OWNER APPROVAL.**
Per the standing directive, Stop Point 6 (AI safety + governance contract) has NOT been begun. This report is the deliverable for owner review.

---

## 1. Publication record

- **Repository:** `thefsts/arma-partner-api-sandbox` (public sandbox), branch `main`
- **Final remote HEAD SHA (SP5 close):** `a8e282fd943aa755693be2e8b287b6a025cdb8d5` (this report commit; its own CI run `34178394423` — completed/success, same gates)
- **Baseline before this stop point:** `a107548e30d352a711c1ac26b6d81529a1fa4124` (SP4 approved close, CI GREEN run 34173198420, 101/101 tests)
- **Pushes:** fast-forward only (`a107548..51182e8`, then `51182e8..a8e282f`), no force push, no history rewrite — PUBLICATION RULE honored
- **Commits added this stop point (2):**
  - `51182e8` — `feat(patches): ARMA PATCHES adapter (SP5) — signed partner client, durable activation state machine, 11-table reference schema, 48-test matrix` (CI run `34178226647`, completed/success)
  - `a8e282f` — `docs: stop point 5 report — ARMA PATCHES adapter evidence, 149-test totals, CI run, defects found/fixed, porting notes, SP6 proposal` (CI run `34178394423`, completed/success)
  - **Author and committer on both:** `THEFSTS <amorebey@gmail.com>` (verified via `git show --format`)
  - Feature commit: 8 files changed, 3039 insertions(+), 4 deletions(-)
- **Files in the commit:**
  - Added: `patches/arma/patchesPartnerClient.ts` (671), `patches/arma/activationService.ts` (704), `patches/arma/armaStore.ts` (201), `patches/arma/transferSchema.ts` (197), `patches/tests/partner.client.test.mjs` (1159), `docs/SP5-CONTRACT-SURFACES.md` (87)
  - Modified: `README.md` (ARMA PATCHES adapter section, 149-test totals, adapter testing description), `.env.example` (`ARMA_PATCHES_OUTBOUND_DISABLED` ARMA-side outbound kill-switch placeholder)

## 2. CI evidence

- **CI run ID:** `34178226647` — workflow "CI" on adapter commit `51182e8`
- **CI URL:** https://github.com/thefsts/arma-partner-api-sandbox/actions/runs/34178226647
- **Conclusion:** `completed / success`
- **Job steps (all success):** Set up job, checkout, pnpm setup, Node 24 setup, Install (`pnpm install --frozen-lockfile`), **Typecheck (`pnpm typecheck`) GREEN**, **Tests (synthetic only) (`pnpm test`) GREEN**, **Secret scan GREEN (no match)**, post steps
- Job: `verify` (all 12 steps success)

## 3. Exact local test totals (same commands CI runs)

- `pnpm test` (all lanes): **tests 149 / pass 149 / fail 0 / cancelled 0 / skipped 0 / todo 0** — exit 0
  - law-shield lane: **71/71**
  - PATCHES partner API v1 contract lane: **30/30** (SP4 suite, unchanged from the certified baseline)
  - ARMA PATCHES adapter lane: **48/48** (`patches/tests/partner.client.test.mjs`, new this stop point)
- `pnpm typecheck` (strict, includes `patches/arma/**` via the `patches/**/*.ts` include): **GREEN, exit 0**
- Secret scan (CI `git grep` pattern over tracked files): **no match — clean**; all test material is synthetic (`synthetic-secret-ARMA-1/ARMA-2`, `synthetic-secret-LUMEN-1`, `synthetic-receipt-secret-for-tests-only`, `replace-with-local-test-*` placeholders). `assertNoSecretsInStore` additionally asserts at test time that no secret value ever lands in any durable ARMA table (activations, idempotency, receipts, retries, reconciliations, audit chain), and `redactForAudit` throws (fail closed) if a live secret would ever reach an audit projection.

## 4. Adapter design (what shipped)

`patches/arma/` is the ARMA-side half of the PATCHES partner contract. It contains **no** Alert ARMA UI, **no** Domus UI, no proprietary PATCHES protection logic, and no direct database access — the only boundary is the authenticated partner API.

- **`patchesPartnerClient.ts`** — scoped partner auth (`Authorization: PATCHES-Partner <clientId>:<keyId>`; `CredentialSource` consulted fresh per attempt so rotation is picked up mid-flight), exact SP4 canonical HMAC-SHA256 signing over `METHOD\n<path>\n<timestamp>\n<nonce>\n<bodyHash>` with the **full `/api/partner/v1` pathname** (query never signed), fresh nonce/timestamp/requestId per attempt, payload hash, API version compatibility check, bounded retry/backoff (default 3 attempts) honoring 429 `retry-after` (capped), and `classifyFailure()` implementing the owner's binding amendment. Receipts are verified over the exact RAW response bytes via the shared `verifyReceipt`. Attempt records are secret-free **by construction**: the signature itself is never recorded.
- **`activationService.ts`** — durable state machine `PENDING → READY_TO_ACTIVATE → ACTIVATION_SENT → RECEIPT_VERIFIED → ACTIVE` plus `RECONCILIATION_REQUIRED`, `DEACTIVATED`, `REVOKED`, `REJECTED`, `QUARANTINED`. Stable idempotency key per ARMA activation intent (`arma-<sha256({orgId, capability, bindingId})>`, overridable by callers). `ACTIVATION_SENT` is persisted **before** the outbound await: a crash mid-send leaves durable proof that a send may have reached PATCHES, so `resume()` reconciles instead of re-sending. Entitlement/capability preflight fail-closed with zero outbound calls. In-flight intents own their binding (a different caller key collapses via `INTENT_KEY_MISMATCH`, never a parallel send that could double-activate server-side). Reconciliation queries PATCHES status via the stable identity (`patchesActivationId ?? lastIntentRequestHint`), bounded (default 3 attempts), then — only on proven 404 — a fresh create under the SAME idempotency key. Tenant-scoped status resolution: a foreign-org identity quarantines (`RECONCILIATION_ACCESS_DENIED` / `STATUS_IDENTITY_MISMATCH`), never syncs. Local outbound kill switch (`ARMA_PATCHES_OUTBOUND_DISABLED`) fails closed before any wire I/O. Secret-free audit events at every transition.
- **`transferSchema.ts` + `armaStore.ts`** — 11-table Convex-shaped reference persistence (partner config, org mappings, entitlement refs, capability refs, opaque bindings, activations, idempotency, receipts, retries, reconciliations, audit chain), no PII, opaque identifiers only; in-memory backing with snapshot/restore transactional semantics as the porting reference for Convex functions.

## 5. Required test matrix — results by category (all 48 GREEN)

Every B–J scenario drives the REAL adapter (client + service + store) against the REAL SP4 reference server over real HTTP (ephemeral port) with real contract-signed requests and an injectable synthetic clock. Section A unit-tests the classification engine directly.

**Classification engine (A1–A13):** AbortError → AMBIGUOUS `TIMEOUT`; pre-delivery `ECONNREFUSED` → CLEAN_RETRYABLE; response dropped mid-read → AMBIGUOUS `RESPONSE_LOST`/`CONNECTION_DROP`; authenticated 429 → CLEAN_RETRYABLE `RATE_LIMITED`; 503 `PARTNER_API_DISABLED` (kill switch provably first) → CLEAN_RETRYABLE; 503 `DOWNSTREAM_UNAVAILABLE` (fail-closed before persistence) → CLEAN_RETRYABLE; 500 `PARTNER_PERSISTENCE_FAILED` (atomic rollback proof) → CLEAN_RETRYABLE; unrecognized 5xx → AMBIGUOUS fail-closed; auth failure codes → TERMINAL; 400/403/404/409/413 → TERMINAL; receipt-verify failure on 2xx → AMBIGUOUS; GET 2xx non-receipt success sentinel + `SERVER_VERSION_MISMATCH` → TERMINAL; `redactForAudit` throws on secret leakage — **all PASS**

**Success path (B1):** signed activation through the real server → raw-byte receipt verified → `RECEIPT_VERIFIED` → `ACTIVE`; receipt persisted; idempotency `COLLAPSED`; full audit chain (`activation.intent.created`, `activation.state.ready_to_activate`, `activation.state.activation_sent`, `activation.receipt.verified`); `assertNoSecretsInStore` — **PASS**

**Authentication / rotation (C1–C5):** missing credential → `CREDENTIAL_SOURCE_INVALID` BLOCKED before any wire I/O; unknown partner → TERMINAL `PARTNER_UNKNOWN`, service `QUARANTINED` (credential is ops), 1 attempt; revoked credential → TERMINAL `CREDENTIAL_REVOKED`, `QUARANTINED`, never retried; rotation mid-flight → new ACTIVE key signs while the old GRACE key still authenticates during the overlap window; past grace → TERMINAL `CREDENTIAL_EXPIRED` and the rotating source recovers with the new key; secrets never in audit/state (asserted throughout) — **all PASS**

**Tenant / entitlement / capability / binding rejections (D1–D8):** wrong-tenant binding (`BINDING_ORG_MISMATCH`) → REJECTED; entitlement `ENTITLEMENT_INACTIVE` → REJECTED; capability not in the directory (`CAPABILITY_UNKNOWN`) → REJECTED; binding `BINDING_INACTIVE`/`BINDING_UNKNOWN` → REJECTED; `BINDING_CAPABILITY_MISMATCH` → REJECTED; local preflight fail-closed (`ENTITLEMENT_NOT_ENTITLED`, `ORG_MAPPING_MISSING`, `ORG_MAPPING_PAUSED`, `CAPABILITY_VERSION_UNSUPPORTED`) all with **zero outbound calls** — **all PASS**

**Idempotency (E1–E4):** duplicate collapse — second identical intent returns the SAME activation with exactly one create ever sent; same key + different payload → 409 `IDEMPOTENCY_KEY_CONFLICT` (TERMINAL); server duplicate delivery → `duplicate:true` receipt (`RCP-DUP-…`), also verified; crashed-process in-flight intent owns the binding — a different caller key collapses via `INTENT_KEY_MISMATCH` with zero outbound calls and nothing at PATCHES — **all PASS**

**Retry / reconciliation — the owner amendment core (F1–F8):** 429 bounded retry (fresh nonce + fresh requestId per attempt, stable bodyHash, server `retry-after` honored via `sleepBeforeNextMs`) → success; clean 503 `DOWNSTREAM_UNAVAILABLE` (provably not processed) → bounded retry succeeds; ambiguous timeout (AbortError after possible delivery) → `RECONCILIATION_REQUIRED`, never blind re-send, reconcile resolves `RESOLVED_ACTIVE`; response lost after acceptance → `RECONCILIATION_REQUIRED` → status reconciliation resolves ACTIVE; receipt signature corruption → AMBIGUOUS → `RECONCILIATION_REQUIRED`; forged receipt requestId field (correctly re-signed bytes) → AMBIGUOUS → `RECONCILIATION_REQUIRED`; clean 500 (provably rolled back) → bounded 3 attempts, exhausted → `QUARANTINED RETRIES_EXHAUSTED`, then a fresh create under the SAME key succeeds as a FRESH create (rollback proven — nothing persisted); ambiguous status query during reconciliation stays OPEN/PENDING (never blind re-send) and resolves on the next attempt, with exactly ONE create attempt across the whole flow — **all PASS**

**Lifecycle (G1–G4):** deactivation then revocation with signed verified receipts → `DEACTIVATED` → `REVOKED`; terminal revoked can NEVER reactivate silently (zero outbound, no new server activation); replay of a used nonce+signature+timestamp → 409 `NONCE_REPLAYED` (refused even when the idempotency key changes — SP4 scenario-16 parity); stale timestamp outside ±5 min → TERMINAL `TIMESTAMP_OUT_OF_WINDOW` (client and service) — **all PASS**

**Kill switches (H1–H3):** ARMA outbound kill switch (`ARMA_PATCHES_OUTBOUND_DISABLED`) → `QUARANTINED` with zero wire I/O and nothing at PATCHES; PATCHES kill switch (`PATCHES_PARTNER_API_DISABLED`) → 503 provably unprocessed → bounded clean retries → `QUARANTINED RETRIES_EXHAUSTED`; PATCHES downstream unavailable → same fail-closed bounded behavior — **all PASS**

**Wrong-org reconciliation resolver (I1):** a foreign-org activation identity queried through the tenant-scoped resolver → 403 → `QUARANTINED RECONCILIATION_ACCESS_DENIED`, exactly one create attempt ever, never re-sent — **PASS**

**Full synthetic E2E (J1):** capability/entitlement discovery → signed activation → real SP4 server → signed raw receipt → ARMA verification → `ACTIVE` → status sync → reconciliation probe (correctly reports "not in reconciliation" on an ACTIVE record) → deactivation (+ idempotent no-op) → status sync `DEACTIVATED` → revocation → re-activation attempt → `QUARANTINED REVOKED` duplicate (revocation is terminal) → zero secrets in durable state → complete audit chain → exactly one server activation — **PASS**

## 6. Defects found and fixed during SP5 (live-wire verification)

Two real product defects were caught by driving the REAL client against the REAL server before the matrix was finalized, and fixed in this commit:

1. **Signature path mismatch** — the client initially signed the route-relative path (`/activations`), while the SP4 server verifies the HMAC over the full `url.pathname` (`/api/partner/v1/activations`). Every real signed request would have failed with 401 `SIGNATURE_INVALID`. Fixed: the signed path now includes the `/api/partner/v1` prefix (query string never signed, per contract).
2. **POST body required on deactivate/revoke** — the SP4 server JSON-parses the raw body on ALL POST routes; an empty body returns 400 `MALFORMED_PAYLOAD` even on routes that ignore the content. Fixed: deactivate/revoke now send `{}`.

Both fixes are regression-covered by the matrix (B1, G1, and every other signed scenario).

## 7. Sanitization statement

- Synthetic data only: all identifiers are synthetic (`ARMA-ORG-*`, `ORG-ARMA-*`, `BIND-*`, `DEV-OPAQUE-*`, `SUBJ-OPAQUE-*`); capability names remain the generic contract identifiers (`traffic_stop_privacy`, `home_privacy`, `telemetry_privacy`).
- No PII crosses any boundary; bindings are opaque references only.
- No proprietary PATCHES protection/enforcement logic: the adapter consumes only the documented partner API contract (`docs/SP5-CONTRACT-SURFACES.md`).
- No Alert ARMA UI, no Domus UI, no direct database access.
- No private prompts, model keys, or production credentials; secrets in tests are synthetic by name and value.

## 8. Remaining PATCHES adapter gaps (private-repo / production-only — not expanded here)

1. **Convex persistence port** — the 11 reference tables need real Convex functions (schema migration, mutations/queries per table, transactional semantics beyond snapshot/restore, index creation per the descriptors in `transferSchema.ts`).
2. **Production credential source** — `staticCredentialSource` / `rotatingCredentialSource` are test/reference implementations; production needs the KMS-backed source with the same `CredentialSource` interface (called fresh per attempt).
3. **Production reconciliation scheduling** — `reconcile()`/`resume()` are operator-invoked here; production needs scheduled retries with backoff (Convex cron) and alerting on `QUARANTINED`.
4. **Quarantine operator tooling** — QUARANTINED records currently stop for manual intervention by design; the private repo needs the review/resolve workflow.
5. **Push/event delivery consumption** — the partner `GET /events` route exists on the PATCHES side; an ARMA-side event poller/webhook receiver is not yet built (candidate for Stop Point 7's shared event framework).
6. **Alert ARMA / Domus UI wiring** — deliberately out of scope this stop point; the adapter is contract-level only and must stay reusable and independently testable.

## 9. Private-repo porting notes

- `patches/arma/transferSchema.ts` is the Convex-shaped contract: table names, field names, and index descriptors map directly to `schema.ts` definitions; `armaStore.ts` method signatures map to Convex query/mutation function signatures (run the same 48-test matrix against the Convex-backed implementation with a store-adapter seam).
- `patches/arma/patchesPartnerClient.ts` is transport-only and has no sandbox dependencies: it can be lifted as-is, with `fetchImpl`, `sleep`, `now`, `credentials`, and `outboundDisabled` injected from production sources.
- `patches/arma/activationService.ts` depends only on the store/client seams (`ArmaStore` interface via duck-typed methods, `PatchesPartnerClient` operations); porting = re-pointing those seams at Convex functions and the KMS credential source.
- `docs/SP5-CONTRACT-SURFACES.md` documents the exact consumed contract (auth, signing, receipts, idempotency, lifecycle, error codes) — keep it in lockstep with the PATCHES private repo's partner API version.
- The test matrix (`patches/tests/partner.client.test.mjs`) is reusable as the certification suite for the Convex-backed port: replace `armaStoreFixture` with a Convex test deployment and keep every assertion.

## 10. Stop Point 6 proposal — AI SAFETY + GOVERNANCE CONTRACT (PROPOSAL ONLY — not begun)

Per the standing directive, the following is the exact owner-approved scope for Stop Point 6, reproduced for decision. No work has begun.

> DO NOT rebuild or expose private implementations/prompts for MILAN, JOY, ROSE, RERE, DALINN, or other proprietary ARMA AI engines. Build only the reusable integration-facing AI governance layer.
>
> DISTINGUISH: AI advisory output; deterministic/rule-engine output; human authorization; system automation; external partner data.
>
> AI MAY: analyze; summarize; classify within approved boundaries; recommend; identify issues; flag something for human review.
>
> AI MUST NOT: create/change RBAC; grant admin access; authorize Law Shield disclosure; override human authorization; change partner credentials; change tenant ownership; bypass entitlements; override security policy; destroy evidence; silently execute protected actions; treat external text as trusted instructions.
>
> MILAN MUST REMAIN ADVISORY-ONLY. JOY/ROSE/AI MUST NOT AUTHORIZE LAW SHIELD DISCLOSURE. RULE-BASED SYSTEMS SUCH AS RERE MUST BE IDENTIFIED SEPARATELY FROM GENERATIVE AI.
>
> CREATE AI PROVENANCE ENVELOPE: engine ID; engine/version; task type; advisory/deterministic designation; timestamp; source references; confidence where applicable; humanReviewRequired; reviewingHumanId where required; review timestamp; output hash; policy version; audit ID.
>
> BUILD GUARDS AGAINST: prompt injection through partner data; embedded tool instructions; embedded function calls; AI-generated authorization; privilege escalation; policy override; unaudited AI actions; external data becoming system instructions.
>
> NO PRIVATE PROMPTS OR MODEL KEYS IN PUBLIC REPO. TEST EVERYTHING. STOP FOR OWNER REVIEW.

**Proposed implementation shape (for owner approval or amendment):** an `ai-governance/` lane with (1) a provenance-envelope schema + verifier (mirroring the receipt-verification pattern from this stop point: envelope signed, hash over the exact output bytes, fail-closed on mismatch); (2) an advisory/deterministic designation registry; (3) guard modules that strip/reject embedded instructions in partner-sourced text before it reaches any engine, and reject any AI output claiming authorization over protected actions (Law Shield disclosure, credentials, RBAC, entitlements, tenant ownership); (4) a synthetic test matrix covering each MUST/MAY boundary, each guard, and the envelope integrity checks. One commit on `main`, additive tests only (target 149 → ~180+), same gates (typecheck, full suite, secret scan, CI GREEN), fast-forward publication, Stop Point 6 report with evidence, then STOP for owner approval.

---

**STOP.** Stop Point 5 is published and certified: final remote HEAD `a8e282fd943aa755693be2e8b287b6a025cdb8d5` (report commit; adapter commit `51182e8`, CI runs 34178226647 and 34178394423 both GREEN), 149/149 tests, typecheck GREEN, secret scan clean. Awaiting owner decision on the Stop Point 6 proposal above. No further work will begin without explicit approval.
