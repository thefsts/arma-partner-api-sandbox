# STOP POINT 7 REPORT — SHARED PARTNER INTEGRATION PLATFORM

**Status: PUBLISHED / CERTIFIED — STOPPING FOR OWNER APPROVAL.**
Per the standing directive, Stop Point 8 (synthetic partner simulators + failure-mode harness) has NOT been begun. The SP8 proposal is reproduced in §10 (authored from the SP1 roadmap language; awaiting owner approval). This report is the deliverable for owner review.

---

## 1. Publication record

- **Repository:** `thefsts/arma-partner-api-sandbox` (public sandbox), branch `main`
- **Final remote HEAD SHA (SP7 close):** this report, including its closing note, is the last commit of Stop Point 7 — the authoritative close SHA is `git rev-parse origin/main` at owner review. The full SP7 commit chain is listed below; no work follows this file.
- **Baseline before this stop point:** `920b9319a04f9d7ffb4a80a849e112d1484d93c9` (SP6 approved close, certified GREEN CI run `34239672897`, 205/205 tests)
- **Baseline preservation:** the SP6 tree was checked before any edit; all 205 baseline tests stayed green through every phase and are unchanged in this stop point — the 3 modified files (`README.md`, `package.json`, `tsconfig.json`) are additive wiring only (new lane script, new test glob, new include), zero deletions of baseline content
- **Pushes:** fast-forward only (`920b931..e39b507`, then the report commit), no force push, no history rewrite — PUBLICATION RULE honored
- **Commits added this stop point:**
  - `e39b507` — `feat: stop point 7 — shared partner integration platform (SDK signing/receipts/retries, partner registry, secure webhooks, observability)` (full SHA `e39b5077e4a9e2c96b841b80d0ac8b35762a740f`; CI run `34255886468`, completed/success) — 32 files changed, 5503 insertions(+), 7 deletions(-)
  - report commits (this file) — CI runs recorded in §2
  - **Author and committer on every SP7 commit:** `THEFSTS <amorebey@gmail.com>` (verified via `git show --format`)
- **Files in the feature commit:**
  - Added: `shared/index.ts` (20), `shared/sdk/canonical.ts` (152), `shared/sdk/receipts.ts` (162), `shared/sdk/idempotency.ts` (154), `shared/sdk/correlation.ts` (60), `shared/sdk/versions.ts` (76), `shared/sdk/errors.ts` (222), `shared/sdk/retries.ts` (152), `shared/sdk/health.ts` (79), `shared/sdk/audit.ts` (113), `shared/sdk/client.ts` (269), `shared/registry/partnerRegistry.ts` (209), `shared/webhooks/events.ts` (450), `shared/webhooks/delivery.ts` (247), `shared/observability/telemetry.ts` (239)
  - Added: `shared/tests/helpers.mjs` (88), `sdk.signing.test.mjs` (216), `sdk.receipts.test.mjs` (146), `sdk.idempotency.test.mjs` (159), `sdk.correlation.test.mjs` (136), `sdk.errors.test.mjs` (150), `sdk.retries.test.mjs` (169), `sdk.health.test.mjs` (102), `sdk.audit.test.mjs` (180), `sdk.client.test.mjs` (271), `registry.test.mjs` (194), `webhooks.test.mjs` (313), `observability.test.mjs` (203), `e2e.synthetic.test.mjs` (550)
  - Modified: `README.md` (SP7 section, 412-test totals, shared lane description, SP8 pointer), `package.json` (test:shared script + shared glob in test), `tsconfig.json` (include `shared/**/*.ts`)

## 2. CI evidence

- **Feature-commit CI run ID:** `34255886468` — workflow "CI" on commit `e39b507`
- **CI URL:** https://github.com/thefsts/arma-partner-api-sandbox/actions/runs/34255886468
- **Conclusion:** `completed / success`
- **Job:** `verify` (all steps success, 15s), started `2026-09-08T17:14:26Z` — steps: checkout, pnpm setup, Node 24 setup, Install (`pnpm install --frozen-lockfile`), **Typecheck (`pnpm typecheck`) GREEN**, **Tests (synthetic only) (`pnpm test`, all 412) GREEN**, **Secret scan GREEN (no match)**, post steps
- **Report-commit CI runs:** recorded additively in the repo Actions history; per the SP6 close-out precedent the report does not embed its own run ID — the authoritative close state is `git rev-parse origin/main` at owner review
- Local gate reruns before every push (same commands CI runs): `pnpm typecheck` exit 0; `pnpm test` 412/412; CI-pattern `git grep` secret scan over HEAD and the working tree — no match

## 3. Exact local test totals (same commands CI runs)

- `pnpm test` (all lanes): **tests 412 / pass 412 / fail 0 / cancelled 0 / skipped 0 / todo 0** — exit 0
  - law-shield lane: **71/71** (unchanged from the certified SP6 baseline)
  - PATCHES partner API v1 contract lane: **30/30** (unchanged)
  - ARMA PATCHES adapter lane: **48/48** (unchanged)
  - ai-governance lane: **56/56** (unchanged)
  - shared partner integration platform lane: **207/207** (new this stop point; `pnpm test:shared` runs it in isolation)
    - `sdk.signing.test.mjs`: 18/18 — canonical form, HMAC sign/verify, timing-safe compare, skew window, nonce/body-hash validation
    - `sdk.receipts.test.mjs`: 11/11 — receipt sign/verify over raw bytes, expected-field binding, every failure code
    - `sdk.idempotency.test.mjs`: 14/14 — FRESH/DUPLICATE/CONFLICT, TTL expiry, replay-guard window, pruning
    - `sdk.correlation.test.mjs`: 18/18 — echo-valid-or-generate, child derivation with depth bound, propagation headers, version negotiation
    - `sdk.errors.test.mjs`: 15/15 — error-class routing, safe-context allowlist, `toResponse()` shape, terminal codes never retryable
    - `sdk.retries.test.mjs`: 14/14 — schedule bounds, computeBackoff, classify/canAutoRetry, CircuitBreaker CLOSED→OPEN→HALF_OPEN canary
    - `sdk.health.test.mjs`: 12/12 — REQUIRED/OPTIONAL dependencies, DEGRADED, reasonCode requirement, frozen snapshot
    - `sdk.audit.test.mjs`: 13/13 — metadata-only records, unsafe key/value throws, secret containment, mutation refused AND audited, provenance references
    - `sdk.client.test.mjs`: 18/18 — buildRequest header set, body signed exactly as provided, 2xx-without-receipt fails closed, structured error parse, planRetry routing
    - `registry.test.mjs`: 17/17 — full-chain success, every typed failure code, boundary expiry, record validation, replacement
    - `webhooks.test.mjs`: 28/28 — envelope build/validate, sign/verify, guard nonce/event/ordering, prune, delivery outcomes, dead-letter, duplicate collapse, per-attempt fresh nonce
    - `observability.test.mjs`: 18/18 — span lifecycle, malformed-input throws, forbidden/unsafe metadata keys, secret detection, reconciliation transitions, frozen spans
    - `e2e.synthetic.test.mjs`: 11/11 — the full synthetic chain (see §5), fail-closed unknowns, no-payload-leak assertions
- `pnpm typecheck` (strict, includes `shared/**/*.ts` via tsconfig include): **GREEN, exit 0**
- Secret scan (CI `git grep` pattern over tracked files): **no match — clean**; the only secrets in the lane are the declared synthetic sandbox values (see §7)

## 4. Shared-platform design (what shipped)

`shared/` is the reusable partner integration platform per the owner-approved SP7 scope: the four components (A shared partner SDK, B partner registry contract, C secure webhook/event framework, D observability contract) extracted from the proven Law Shield + PATCHES seams so no partner lane re-implements signing, receipts, retries, or fail-closed authorization. It contains **no** private ARMA, Law Shield, or PATCHES implementation, **no** credentials or prompts, and **no** production data. Every surfaced surface is metadata-only: identifiers, reason codes, and hashes — never payload content. Everything fails closed on unknown partners, capabilities, policies, signatures, receipts, or protected actions.

- **`shared/sdk/canonical.ts`** — the signing core. Canonical 5-field form `METHOD\npath\ntimestamp\nnonce\nbodyHash`, HMAC-SHA256 hex, timing-safe comparison, ±5 min clock skew (`MAX_CLOCK_SKEW_MS`), and body-hash binding over the exact raw bytes (a signature can never be replayed against a different body). Verification is fail-closed and ordered: input shape → timestamp pattern → skew → nonce pattern → body-hash shape → secret → HMAC, each with its typed code.
- **`shared/sdk/receipts.ts`** — platform receipts. HMAC + SHA-256 content hash over the raw response bytes with the SP4/SP5 header set (`x-shared-receipt-id`, `x-shared-content-sha256`, `x-shared-signature`); `expected`-field binding so a receipt can never prove a different request, partner, operation, outcome, or entity; every defect typed (`RECEIPT_MISSING_HEADERS`, `RECEIPT_CONTENT_HASH_MISMATCH`, `RECEIPT_INVALID_SIGNATURE`, `RECEIPT_BODY_MALFORMED`, `RECEIPT_FIELD_MISMATCH`).
- **`shared/sdk/idempotency.ts`** — FRESH / DUPLICATE collapse (same key + same request hash) / CONFLICT (same key, different hash) with TTL expiry, plus the per-scope nonce `ReplayGuard` (bounded validity window, expired nonces treated as unseen, best-effort pruning) — shaped for a unique-index port (PORTING NOTE in the module).
- **`shared/sdk/correlation.ts`** — request/correlation ID contract: echo-valid-or-generate at the boundary, child ID derivation with a depth bound, propagation headers.
- **`shared/sdk/versions.ts`** — exact-match negotiation against `SUPPORTED_SDK_API_VERSIONS` with per-capability min/max windows; unknown, malformed, and out-of-window all fail closed with typed codes; `compareVersions` is a true signum (-1/0/+1).
- **`shared/sdk/errors.ts`** — the structured error contract: one error-code vocabulary, coarse error classes (`AUTHENTICATION`, `AUTHORIZATION`, `VERSION`, `INPUT`, `NOT_FOUND`, `STATE`, `IDEMPOTENCY`, `RATE_LIMIT`, `DOWNSTREAM`, `PERSISTENCE`, `TRANSPORT`, `UNAVAILABLE`), the partner-visible safe-context allowlist (scalar values, bounded strings), `toResponse()` producing `{ error, errorClass, requestId?, ...safeContext }` — payload content can never ride out in an error body; `RETRYABLE_CODES` / `AMBIGUOUS_CODES` / `TERMINAL_CODES` exported so the retry policy and the error surface share one truth.
- **`shared/sdk/retries.ts`** — the clean-retryable-only retry policy: schedule `[1s, 5s, 30s, 2m, 10m]`, `computeBackoff` with exhaustion, `classify` (clean-retryable = `TRANSPORT_ERROR` / `DOWNSTREAM_UNAVAILABLE` / `UNAVAILABLE`; ambiguous = `CIRCUIT_OPEN` / `WEBHOOK_DELIVERY_FAILED` / `PERSISTENCE_FAILED` / `RECEIPT_VERIFICATION_FAILED`; everything else terminal), `canAutoRetry` allowing only clean-retryable, and the `CircuitBreaker` (CLOSED → OPEN on the failure threshold → HALF_OPEN canary; OPEN fails closed) with an injectable clock.
- **`shared/sdk/health.ts`** — readiness: REQUIRED dependency down → UNAVAILABLE, OPTIONAL down → DEGRADED, a reasonCode mandatory on every non-AVAILABLE verdict, malformed probes rejected, frozen dependency snapshot.
- **`shared/sdk/audit.ts`** — `IntegrationAuditTrail` wrapping the SP6 append-only `AuditLog` (the SP6 module is reused, not re-implemented): metadata-only details over the integration allowlist, provenance references by ID + output hash, structural throws on unsafe keys/values/secret material, mutation refused AND audited.
- **`shared/sdk/client.ts`** — the `PartnerSdkClient` façade composing everything: `buildRequest` (canonical + signature + full `x-shared-*` header set + correlation header, body signed EXACTLY as provided), `processResponse` (2xx verified over raw bytes against `expected` binding — **a 2xx without a verifiable receipt FAILS CLOSED as `RECEIPT_VERIFICATION_FAILED`; a success is only trusted when its receipt proves it**; non-2xx parses the structured error with a `PARTNER_REQUEST_FAILED` fallback), `planRetry` (CLEAN_RETRY / AMBIGUOUS_RECONCILE / TERMINAL / EXHAUSTED — ambiguous outcomes are never blindly re-sent), `verifySignature`, `classifyFailure`. The receipt secret is a distinct option from the signing secret (defaults to it for single-secret sandboxes) so production can inject the platform receipt secret from the secret store.
- **`shared/registry/partnerRegistry.ts`** — the partner registry contract exactly as directed: the authorization chain organization → partner → binding → entitlement → capability → status → API version window, resolved as **data** (no hardcoded partner logic anywhere — a partner is a record, not a code path); every unknown or inactive element fails closed with a typed code (`PARTNER_UNKNOWN`, `PARTNER_SUSPENDED`, `PARTNER_REVOKED`, `ORG_UNKNOWN`, `ORG_SUSPENDED`, `ORG_NOT_BOUND_TO_PARTNER`, `BINDING_INACTIVE`, `BINDING_UNKNOWN`, `ENTITLEMENT_MISSING`, `ENTITLEMENT_INACTIVE`, `ENTITLEMENT_REVOKED`, `ENTITLEMENT_EXPIRED`, `CAPABILITY_UNKNOWN`, `CAPABILITY_VERSION_UNSUPPORTED`); record registration is validated fail-closed too.
- **`shared/webhooks/events.ts`** — the secure webhook/event framework. A closed event-type vocabulary covering exactly the directed events (`resource.status.changed`, `processing.completed`, `processing.failed`, `entitlement.changed`, `entitlement.revoked`, `reconciliation.required`, `reconciliation.completed`); metadata-only envelopes (allowlisted data keys, scalar values, bounded strings); canonical signing with a fresh nonce per delivery attempt; receiver-side `verifyWebhook` over raw bytes in fail-closed order (header presence → schema/timestamp skew → nonce replay → body hash → HMAC → envelope validation → event-ID replay → per-stream strict sequence ordering, first event may start at any N ≥ 1, every following event exactly last + 1); `WebhookEventGuard` with atomic check-and-consume and window pruning.
- **`shared/webhooks/delivery.ts`** — `WebhookDeliveryService`: duplicate collapse first (a definitively delivered event is `DELIVERED_DUPLICATE` and the transport is never re-invoked), per-attempt signing with a fresh nonce, clean-retryable failures advance the proven schedule, **ambiguous outcomes dead-letter immediately** (never blind re-send), exhaustion dead-letters (`RETRY_EXHAUSTED`); the transport receives only delivery/event/target IDs, raw bytes, and headers — attempt history is numbers and codes only.
- **`shared/observability/telemetry.ts`** — the observability contract tracking exactly the directed fields without sensitive payloads: request ID, partner, organization reference, operation, start/completion, latency, success/failure, retry count, error category, and reconciliation status (`NONE`/`PENDING`/`RESOLVED`/`REQUIRED_UNRESOLVED`). Metadata is allowlisted at entry; forbidden material/content keys (prompt, secret, signature, payload, ...) throw structurally; registered secret values can never appear in any span value; terminal spans are frozen.
- **`shared/index.ts`** — the public barrel; nothing else in the sandbox imports the internals directly.

## 5. Required test matrix — results by category (all 207 GREEN)

**SDK primitives (signing 18, receipts 11, idempotency 14, correlation 18, errors 15, retries 14, health 12, audit 13, client 18):** canonical form and sign/verify round-trip, timing-safe behavior, skew window honored, every malformed-input code; receipt verification over raw bytes with expected-field binding and every failure code; idempotency FRESH/DUPLICATE/CONFLICT with TTL and the replay-guard window + pruning; correlation echo/derive/propagation with the depth bound and version negotiation exact-match; error-class routing for the full vocabulary, safe-context drops of non-allowlisted/non-scalar/oversized values, `toResponse()` shape, terminal codes never retryable; the retry schedule bounds, computeBackoff, classify, canAutoRetry, and the CircuitBreaker state machine (threshold trip, still-OPEN at the boundary, HALF_OPEN canary success closes / failure re-opens); health REQUIRED/OPTIONAL → UNAVAILABLE/DEGRADED with reasonCode mandatory; audit metadata-only records with structural throws on unsafe keys/values and secret containment, mutation refused AND audited, `find` returning null on unknown; the client façade building the full header set, signing the body exactly as provided, failing closed on 2xx-without-receipt (missing/tampered/wrong-operation receipt), parsing structured errors from non-2xx, and routing planRetry CLEAN_RETRY / AMBIGUOUS_RECONCILE / TERMINAL / EXHAUSTED — **all PASS**

**Partner registry (17):** the full chain success resolving partner/org/entitlement/capability with the API version window; every typed failure code including the entitlement-expiry boundary (`now() >= validUntil` → EXPIRED) and `CAPABILITY_VERSION_UNSUPPORTED` for inverted windows; registration validation codes; record replacement updating resolution — **all PASS**

**Webhook framework (28):** envelope build/validate with unknown-type/unsafe-key/invalid-value throws; sign/verify round-trip with every failure code; guard nonce burn, event-ID dedupe, strict per-stream sequence with `detail.expectedSequence`, stream independence, and window pruning; delivery DELIVERED / DELIVERED_DUPLICATE (transport called exactly once) / RETRY_EXHAUSTED (5 attempts, dead-letter) / DEAD_LETTERED_AMBIGUOUS (1 attempt, no blind re-send) / mid-schedule success / DELIVERY_ENDPOINT_INVALID / constructor fail-closed; every attempt carrying a fresh nonce and a verifiable signed request — **all PASS**

**Observability (18):** span lifecycle RUNNING → SUCCESS/FAILED with latency from the injected clock; malformed-input throws; metadata merge; SPAN_ALREADY_COMPLETED; retry-count and reconciliation-status validation; markAmbiguous → PENDING; updateReconciliation RESOLVED/REQUIRED_UNRESOLVED; forbidden metadata keys, unsafe keys, non-scalar/oversized values; registered secret material never appearing in any value; getSpan/findByRequestId/list; frozen completed spans — **all PASS**

**Synthetic E2E (11):** the full chain — registry resolve → version negotiate → SDK sign → server-side verify → nonce burn (replay refused) → idempotency FRESH → platform receipt → client receipt verification → idempotency DUPLICATE collapse → metadata-only webhook event → retrying delivery (3 attempts, every attempt verifiable, fresh nonce per attempt) → receiver-side verification with the guard (replay of the same event refused) → telemetry span SUCCESS → audit record — with no-payload-leak assertions on every surfaced surface (audit, telemetry, event data contain neither the request payload nor any secret); fail-closed unknowns (unknown partner → structured error + TERMINAL plan; unknown capability → CAPABILITY_UNKNOWN; forged receipt → RECEIPT_VERIFICATION_FAILED + AMBIGUOUS_RECONCILE; tampered request path → SIGNATURE_SIGNATURE_MISMATCH; unknown event type refused at build; out-of-window version negotiation fails closed); exhausted delivery dead-letters with metadata-only attempt history; ambiguous delivery dead-letters after exactly one transport call; ambiguous outcome tracked as AMBIGUOUS telemetry → reconciliation.required event → RESOLVED; duplicate delivery collapses without re-invoking the transport — **all PASS**

## 6. Defects found and fixed by the test discipline (found before publication — none shipped)

The tests were written against the real module APIs (verified from source before every assertion), and the discipline caught four implementation defects during the build, all fixed and re-verified green before the feature commit:

1. **`compareVersions` signum contract** — returned a raw numeric difference instead of -1/0/+1, breaking the contract for callers comparing magnitudes; fixed to a true signum (all existing callers use only the sign, so no behavior change elsewhere).
2. **Error-class mapping gaps** — `TRANSPORT_ERROR`/`UNAVAILABLE`, `RECEIPT_VERIFICATION_FAILED`, and `PARTNER_REQUEST_FAILED` fell through to the default INPUT/400 class; fixed to TRANSPORT/UNAVAILABLE, TRANSPORT/502 (ambiguous, not retryable), and DOWNSTREAM/503 respectively.
3. **Receipt-secret separation** — `processResponse` verified response receipts with the partner's request-signing secret; receipts are platform-signed with a distinct secret, so the client now takes a separate `receiptSecret` option (defaulting to `secret` for single-secret sandboxes — additive, no breaking change).
4. **Ambiguous-code inconsistency (caught by the E2E chain itself)** — `errors.ts` classified `RECEIPT_VERIFICATION_FAILED` as AMBIGUOUS (route to reconciliation) but `retries.ts` `AMBIGUOUS_RETRY_CODES` omitted it, so `planRetry` planned TERMINAL for an unverifiable receipt instead of AMBIGUOUS_RECONCILE; fixed by adding the code to `AMBIGUOUS_RETRY_CODES`, restoring the retry-vs-reconcile discipline on both surfaces.

Also hardened during the build: type-only names moved to `import type` statements in `client.ts` and `delivery.ts` (Node 24 type-stripping executes value imports at module load; importing a type as a value is a runtime SyntaxError, and strict typecheck alone does not catch it).

## 7. Sanitization statement

- Synthetic data only: every identifier is synthetic (`partner-sandbox-1`, `org-sandbox-1`, `partner-privacy-basic`, `traffic_stop_privacy` — the generic contract identifier), every timestamp comes from an injectable fake clock, and every fixture is a synthetic partner/org record.
- The only secrets in the lane are the three declared synthetic sandbox values in `shared/tests/helpers.mjs` (`synthetic-partner-signing-secret-SP7-sandbox`, `synthetic-receipt-signing-secret-SP7-sandbox`, `synthetic-webhook-signing-secret-SP7-sandbox`) — synthetic by name and value, never a real credential; production porting swaps them for the secret store (see §9).
- No private ARMA, Law Shield, or PATCHES implementation, algorithm, prompt, or key appears anywhere in `shared/`: the modules are the extracted contracts only, and the seams they were extracted from (Law Shield signer/receipt verifier/retry policy, PATCHES security/receipts/server discipline) remain behind their own lane boundaries.
- No payload content crosses any observability surface: the e2e test asserts, on the serialized audit log, telemetry span list, and webhook event data, that neither the request payload nor any secret value appears.
- No Alert ARMA UI, no Domus UI, no direct database access.

## 8. Remaining shared-platform gaps (private-repo / production-only — not expanded here)

1. **Durable persistence** — every registry/guard/sink is the in-memory reference shaped for the port (unique-index idempotency, TTL nonce window, transactional resolve+record); the Convex port is private-repo work.
2. **Production secrets** — signing/receipt/webhook secrets come from the secret store; the sandbox values are declared synthetic.
3. **Async retry drivers** — the delivery service is synchronous drain-through-schedule; the async driver honoring the schedule delays with persistence across restarts is production work.
4. **Real partner records** — the registry is data-only by design; production record management (lifecycle tooling, bulk changes) lives in the private repos.
5. **Transport wiring** — the transport is an injectable function; real HTTP delivery (endpoints, TLS, mTLS where required) is production work.

## 9. Private-repo porting notes

- `shared/sdk/canonical.ts` + `shared/sdk/receipts.ts` — lift as-is; Law Shield/PATCHES header-name overrides already exist via `headerNames`, so each surface keeps its `x-lawshield-*` / `x-patches-*` names on the same primitives.
- `shared/registry/partnerRegistry.ts` — the registry is data-only: port the record shape to durable tables and the resolve chain runs unchanged; partner-specific behavior must be added as data (records), never as code paths — that is the directive.
- `shared/sdk/retries.ts` — the schedule and classification tables are data; production may tune values but must preserve the clean-retryable-only rule and the ambiguous-never-blindly-re-sent rule.
- `shared/webhooks/` — receiver-side verification is transport-agnostic; wire `verifyWebhook` into each inbound webhook route and `WebhookDeliveryService` behind the production transport.
- `shared/observability/telemetry.ts` — the span shape is the contract; production maps the sink to the metrics/tracing backend, keeping the allowlist and forbidden-key discipline intact.
- `shared/tests/` — the 207-test matrix is the certification suite for the port: same assertions, synthetic secrets replaced by test-store values in the bootstrap only.

## 10. Stop Point 8 proposal — PARTNER SIMULATORS + FAILURE-MODE HARNESS (PROPOSAL ONLY — not begun)

Per the standing directive, the following is the proposal for Stop Point 8, authored from the SP1 roadmap scope (`docs/STOP-POINT-1-BASELINE.md`: "No contract test harness or partner simulators — Stop Point 8 scope"; architecture line: `simulators/ — synthetic partner simulators + failure modes (Stop Point 8)`). No work has begun; this section exists for owner approval only.

> STOP POINT 8 — PARTNER SIMULATORS + FAILURE-MODE HARNESS
> ====
> With the shared platform (SP7) certified, build the contract test harness that proves every integration surface against synthetic partners before any real one is connected.
>
> BUILD:
>
> A. SYNTHETIC PARTNER SIMULATORS
>
> - in-process partner simulators built ON the shared SDK (signed requests, receipt-verified responses, webhook endpoints)
> - a well-behaved simulator (happy path through the full SP7 chain)
> - configuration-driven behavior only — no hardcoded partner logic (registry data, not code)
>
> B. FAILURE-MODE HARNESS
>
> - every failure mode the contracts define, exercisable on demand:
>   - transport failures (clean-retryable) and ambiguous outcomes (sent-but-unknown)
>   - signature/timestamp/nonce/replay rejections
>   - receipt missing/forged/tampered/wrong-operation
>   - unknown/suspended/revoked partners, orgs, entitlements, capabilities
>   - event ordering gaps, replayed events, dead-lettering
>   - downstream unavailability, circuit open, kill switches
> - deterministic, injected-clock, no real network, no real secrets
>
> C. CONTRACT TEST HARNESS
>
> - one runner driving every simulator x failure-mode combination against the shared contracts
> - metadata-only evidence (codes, hashes, counts — never payload content)
> - results feed the Stop Point 10 certification reporting shape
>
> STOP FOR OWNER REVIEW.

---

**STOP.** Stop Point 7 is published and certified: feature commit `e39b5077e4a9e2c96b841b80d0ac8b35762a740f` (CI run `34255886468`, GREEN) plus this report chain, 412/412 tests (71 law-shield + 30 patches contract + 48 patches adapter + 56 ai-governance + 207 shared), typecheck GREEN, secret scan clean on the final tree, fast-forward publication only, all 205 SP6-baseline tests preserved green throughout. The final remote HEAD is the last SP7 commit on `main` — `git rev-parse origin/main` at owner review gives the authoritative close SHA. Awaiting owner decision on the Stop Point 8 proposal above. No further work will begin without explicit approval.
