# STOP POINT 4 REPORT — PATCHES PARTNER API V1 (SANITIZED REFERENCE)

**Status: PUBLISHED / CERTIFIED — STOPPING FOR OWNER APPROVAL.**
Per the standing directive, Stop Point 5 (ARMA PATCHES adapter) has NOT been begun. This report is the deliverable for owner review.

---

## 1. Publication record

- **Repository:** `thefsts/arma-partner-api-sandbox` (public sandbox), branch `main`
- **Remote HEAD SHA:** `9228584a45f743d503966e1e034ca546518a3584`
- **Baseline before this stop point:** `409ea365e95819360c91102dcbbe1817944a6158` (SP3 approved close, CI GREEN run 34165945228, 71/71 tests)
- **Push:** fast-forward only (`409ea36..9228584`), no force push, no history rewrite — PUBLICATION RULE honored
- **Commits added this stop point (1):**
  - `9228584` — `feat(patches): complete sanitized PATCHES Partner API v1 reference — partner auth, tenant isolation, entitlements, capabilities, activations, receipts, audit (SP4)`
  - **Author:** `THEFSTS <amorebey@gmail.com>` (verified via `git show --format`)
  - 13 files changed, 2489 insertions(+), 28 deletions(-)
- **Files in the commit:**
  - Added: `patches/lib/store.ts` (478), `patches/lib/security.ts` (242), `patches/lib/policy.ts` (113), `patches/lib/receipts.ts` (124), `patches/lib/rateLimit.ts` (52), `patches/lib/server.ts` (608), `patches/tests/helpers.mjs` (198), `patches/tests/partner.api.test.mjs` (614)
  - Modified: `patches/patches/partner-v1-health-route.ts` (force-static removed; live dynamic health), `package.json` (both test lanes + `test:patches` script), `tsconfig.json` (`allowImportingTsExtensions: true`), `README.md` (PATCHES section + 101-test Testing section), `.env.example` (`PATCHES_PARTNER_API_DISABLED` kill-switch placeholder)

## 2. CI evidence

- **CI run ID:** `34172966779` — workflow "CI" on commit `9228584`
- **CI URL:** https://github.com/thefsts/arma-partner-api-sandbox/actions/runs/34172966779
- **Conclusion:** `completed / success`
- **Job steps (all success):** Set up job, checkout, pnpm setup, Node 24 setup, Install (`pnpm install --frozen-lockfile`), **Typecheck (`pnpm typecheck`) GREEN**, **Tests (synthetic only) (`pnpm test`) GREEN**, **Secret scan GREEN (no match)**, post steps
- Job ID: `101896713570` (job-level logs require admin rights; step-level conclusions above are from the GitHub Actions API)

## 3. Exact local test totals (same commands CI runs)

- `pnpm test` (all lanes): **tests 101 / pass 101 / fail 0 / cancelled 0 / skipped 0 / todo 0** — exit 0
  - law-shield lane: **71/71** (71 pass, 0 fail — verified independently via TAP reporter)
  - patches lane: **30/30** (30 pass, 0 fail — 27 mandatory scenarios + 3 sub-scenarios)
- `pnpm typecheck` (strict, includes all `patches/**/*.ts`): **GREEN, exit 0**
- Secret scan (`git grep` CI pattern over tracked files): **no match — clean**; all test material is synthetic (`synthetic-secret-ARMA/LUMEN`, `synthetic-receipt-secret-for-tests-only`, `replace-with-local-test-*` placeholders)

## 4. Required test matrix — results by category (all GREEN)

Every scenario drives the REAL reference server over real HTTP (ephemeral port) with contract-signed requests (`Authorization: PATCHES-Partner`, HMAC-SHA256 over `METHOD\npath\ntimestamp\nnonce\nbodyHash`) and an injectable synthetic clock.

**Authentication (scenarios 1–6):**
- 1 valid partner success — 200, receipt verified over raw response bytes, activation ACTIVE, event + audit persisted, status route live — PASS
- 2 missing credential (no Authorization header) — 401 — PASS
- 3 invalid credential (bad signature) — 401 SIGNATURE_INVALID — PASS
- 4 revoked credential denied immediately — 401 CREDENTIAL_REVOKED — PASS
- 5 credential rotation — new key ACTIVE (200), old key GRACE (200), then past `retiredAt` (401 CREDENTIAL_EXPIRED) — PASS
- 6 suspended partner denied — 401 PARTNER_SUSPENDED (precedes credential checks) — PASS

**Tenant isolation (scenario 7):**
- Wrong tenant/org: partner cannot touch another partner's org — activation AND reads (`entitlements`, `events`, `audit`) all 403 ORG_NOT_BOUND_TO_PARTNER — PASS

**Entitlement / capability (scenarios 8–10b):**
- 8 missing entitlement — 403 ENTITLEMENT_MISSING — PASS
- 8b inactive entitlement — 403 ENTITLEMENT_INACTIVE — PASS
- 9 revoked entitlement — 403 ENTITLEMENT_REVOKED — PASS
- 9b expired license window (future-licensed entitlement) — 403 ENTITLEMENT_EXPIRED — PASS
- 10 unsupported capability — 403 CAPABILITY_UNKNOWN (licensed-but-unregistered capability; plus pipeline-precedence probe: bogus name fails entitlement first) — PASS
- 10b capability discovery — 200, generic contract identifiers only (`traffic_stop_privacy`, `home_privacy`) — PASS

**Activation / idempotency (scenarios 11–15):**
- 11 duplicate activation, same idempotency key + same payload — 200 collapse, `duplicate:true`, original activation returned — PASS
- 12 same key + different payload — 409 IDEMPOTENCY_KEY_CONFLICT — PASS
- 13 deactivation — idempotent by status; second deactivate 200 no-op with DEACTIVATED result — PASS
- 14 revocation — REVOKED terminal; re-revoke 200 no-op; deactivate on REVOKED → 409 ACTIVATION_REVOKED — PASS
- 15 invalid device/subject binding — BINDING_UNKNOWN / BINDING_INACTIVE / BINDING_ORG_MISMATCH / BINDING_CAPABILITY_MISMATCH all 403 — PASS

**Replay / tamper (scenarios 16–19):**
- 16 replayed request (same nonce) — 401 NONCE_REPLAYED — PASS
- 17 stale request (timestamp outside ±5 min skew) — 401 TIMESTAMP_OUT_OF_WINDOW — PASS
- 18 tampered request (valid signature over a different body) — 401 — PASS
- 19 unsupported API version (`/v2/`) — 400 UNSUPPORTED_API_VERSION — PASS

**Payload / rate limit / downstream (scenarios 20–23):**
- 20 malformed payload (invalid JSON) — 400 MALFORMED_PAYLOAD — PASS
- 21 payload over limit — 413 PAYLOAD_TOO_LARGE with `limitBytes` echoed — PASS
- 22 rate limit reference behavior — 429 RATE_LIMITED + `retry-after` ≥ 1; scoping verified: the OTHER partner still gets 200 (per-clientId token bucket, checked after auth) — PASS
- 23 downstream protection service failure — 503 DOWNSTREAM_UNAVAILABLE, FAIL-CLOSED: zero activations persisted, no receipt, no event — PASS

**Receipt / audit (scenarios 24–26):**
- 24 receipt integrity — signature verifies over RAW response bytes; tampering the body breaks verification — PASS
- 25 receipt mismatch — expected-field binding detects wrong activationId (RECEIPT_FIELD_MISMATCH), missing receipt headers (RECEIPT_MISSING_HEADERS), wrong secret (RECEIPT_INVALID_SIGNATURE) — PASS
- 26 audit creation — append-only, monotonic sequence, sanitized detail, tenant-scoped read (wrong-tenant audit read 403) — PASS

**Health / readiness (scenario 27):**
- Live health: 200 `status: available`, `directDatabaseAccess: false`, `requiresScopedAuthentication: true`, `cache-control: no-store`, capabilities listed; kill switch flips health to 503 `status: disabled` AND blocks all routes 503 PARTNER_API_DISABLED; no force-static caching semantics — PASS

**23 required API capabilities mapping:** scoped partner authentication (1–6, 16–18); credential rotation (5); credential revocation (4); tenant/org authorization (7); entitlement lookup (8, 8b, 9, 9b); capability discovery (10, 10b); API/version compatibility (19); activation (1, 11); deactivation (13); revocation (14); opaque device/subject binding (15); current status (1, 13, 14); events/notifications contract (1, 7, 23); signed/integrity-verifiable receipts (1, 24, 25); audit trail (1, 26, 7); health/readiness (27); idempotency (11, 12); replay protection (16); request/correlation IDs (echo/generate verified throughout); structured errors (every negative case); payload limits (21); rate-limit reference behavior (22); fail-closed downstream behavior (23).

## 5. Sanitization statement

Generic contract identifiers only (`traffic_stop_privacy`, `home_privacy`); all identifiers are opaque synthetic values (`ORG-ARMA-ALPHA`, `DEV-OPAQUE-001`, `SUBJ-OPAQUE-001`, …); no PII; no production secrets (synthetic test secrets are named as such); no PATCHES private detection/protection logic; the downstream protection service is an injectable boundary returning synthetic results only. The CI secret scan finds nothing.

## 6. Remaining PATCHES gaps (private-repo / production-only — per owner directive, NOT expanded here)

1. **Convex persistence port** — `patches/lib/store.ts` is an in-memory synthetic store with Convex-shaped interfaces; the private PATCHES repo must port it to durable Convex tables (partners, credentials, organizations, entitlements, capabilities, bindings, activations, idempotency keys, nonces, receipts, events, audit) with the same transactional all-or-nothing semantics.
2. **Push/event delivery infrastructure** — this sandbox exposes pull-based `GET /events` with replay protection; production push/webhook delivery with per-partner endpoints, retries, and dead-lettering is a private-repo item.
3. **Production key/secret rotation** — real secret storage, distribution to ARMA, automated grace-window retirement, and audit escalation.
4. **Production rate limiting** — the reference token bucket is per-clientId in-memory; production needs shared/distributed limiter state and per-partner quotas.
5. **Production tenancy checks** — the synthetic `owningPartnerId` boundary must be backed by the real PATCHES tenant/entitlement system of record.
6. **Quarantine tooling** — operational tooling for isolating suspicious partner traffic is out of sandbox scope.
7. **Deployment wiring** — the Node reference handler maps 1:1 to the platform's HTTP layer; porting is wiring, not logic (kill switch → auth → rate limit → route logic; health route already mirrored in `patches/patches/partner-v1-health-route.ts`).

## 7. Private-repo porting notes

- `patches/lib/server.ts` route order is the porting skeleton: kill switch first (health stays LIVE and reports `status: disabled`), then request IDs, then version compatibility, then scoped partner auth, then rate limiting (after auth, so anonymous floods cannot starve partners), then route logic.
- Every response carries `x-request-id` (echoes caller's or generates) and `cache-control: no-store`; errors are structured `{ error, errorClass?, requestId, ...context }`.
- Auth verification signs over the exact full path the client signed (`url.pathname`, including the version segment; query is not signed).
- The store exposes a `runTransaction` all-or-nothing boundary with injectable fail points — map it directly onto Convex transactional writes; the idempotency key + request-hash registry and the nonce registry are the two tables that make replay/duplicate protection durable.
- Receipt contract: the response body IS the receipt, signed over the RAW response bytes; headers `X-PATCHES-Receipt-Id`, `X-PATCHES-Content-SHA256`, `X-PATCHES-Signature`; `receiptId` in the body must match the header.
- The injectable `ProtectionService.enqueueActivation` boundary is where the private repo wires real licensed protection services; failure must remain fail-closed (503, zero partial state — see scenario 23).
- `PartnerApiServerOptions` accepts injectable `now`, `rateLimiter`, `protectionService`, `resolveClientSecret`, and `store` — production replaces each with real implementations without touching route logic.

## 8. Stop Point 5 proposal (PROPOSAL ONLY — not begun)

**Objective:** build the ARMA-side PATCHES adapter (the outbound half of the contract), mirroring the Law Shield ARMA pattern from Stop Point 2.

**Proposed scope (for owner approval or amendment):**
1. `patches/arma/patchesPartnerClient.ts` — outbound client with scoped partner authentication (`clientId` + rotating keyId/secret), request signing (same HMAC-SHA256 canonical form), clock-skew handling, nonce generation, retry with backoff on 429/5xx, and raw-byte receipt verification using `verifyReceipt` semantics.
2. `patches/arma/activationService.ts` — ARMA-side durable activation state machine (PENDING → ACTIVE → DEACTIVATED/REVOKED), idempotency-key generation per activation attempt, ambiguous-failure reconciliation against the partner status route, and fail-closed behavior on receipt/verification failure.
3. `patches/arma/transferSchema.ts` — ARMA-side persistence schema (Convex-shaped, like the Law Shield transfer schema) mapping ARMA-side entities to PATCHES opaque partner identifiers; no PII crossing the boundary, opaque IDs only.
4. `patches/tests/partner.client.test.mjs` — ARMA-adapter test matrix: signed outbound success, auth failure, rotation mid-flight, tenant rejection, entitlement rejection, idempotent duplicate, 409 conflict reconciliation, downstream 503 fail-closed, replay rejection, receipt verification failure, kill switch (ARMA outbound disabled), full synthetic E2E ARMA → reference partner server → signed receipt → ARMA verification.
5. UI/UX for Alert ARMA and Domus remains OUT of scope (contract-level only; adapters must stay reusable and independently testable, per `patches/docs/API-BUILD-SCOPE.md`).

**Estimate:** one commit on `main`, additive tests only (target 101 → ~120+), same gates (typecheck, full suite, secret scan, CI GREEN), fast-forward publication, Stop Point 5 report with evidence, then STOP for owner approval.

---

**STOP.** Stop Point 4 is published and certified. Awaiting owner decision on the Stop Point 5 proposal above. No further work will begin without explicit approval.
