# STOP POINT 1 — Baseline Audit Report

Auditor: Ninja AI (SuperNinja agent)
Date: 2026-09-04
Repository: thefsts/arma-partner-api-sandbox (public sanitized sandbox)
Base commit audited: fd56c14 (origin/main, single branch, up to date)
Environment: Node v24.20.0, pnpm 10.34.5, git identity THEFSTS <amorebey@gmail.com>

This report records the baseline only. No feature build has started. No existing history was rewritten.

---

## 1. Exact existing file inventory (10 files, 10 commits, 80K)

```
.env.example                                        (11 lines)  placeholder-only env names; synthetic local URLs
.gitignore                                          (17 lines)  blocks .env, keys, node_modules, artifacts
README.md                                           (60 lines)  sandbox purpose, boundaries, lane summaries
law-shield/docs/NINJA-HANDOFF.md                    (65 lines)  continuation handoff for the Law Shield lane
law-shield/lawshield/_integrationSecurity.js        (97 lines)  HMAC-SHA256 security perimeter library
law-shield/lawshield/arma-integration.js            (21 lines)  Law Shield ARMA gateway endpoint (POST)
law-shield/lawshield/integration-readiness.js       ( 3 lines)  Law Shield readiness endpoint (GET)
law-shield/arma/lawShieldTransferSchema.ts          (13 lines)  ARMA durable transfer Convex table design (sanitized)
patches/docs/API-BUILD-SCOPE.md                     (36 lines)  PATCHES partner API v1 build lane definition
patches/patches/partner-v1-health-route.ts          (11 lines)  existing PATCHES partner health route (GET)
```

Commit history (all authored by the owner, Full Stack Teck Solutions <amorebey@gmail.com>; none rewritten):

```
fd56c14 docs(law-shield): add continuation handoff for Ninja AI
74a3fb6 docs(patches): define complete partner API build lane
16c9ca1 feat(patches): import existing partner API health contract
25d0034 feat(law-shield): import ARMA durable transfer model
5e9698b feat(law-shield): import sanitized readiness endpoint
7404e08 feat(law-shield): import sanitized ARMA gateway endpoint
b4ac177 feat(law-shield): import sanitized integration security perimeter
592cdce docs: add placeholder-only integration environment template
330d1e9 security: add public sandbox ignore rules
bd1aee0 chore: initialize sanitized ARMA partner API sandbox
```

---

## 2. What is already usable (verified by execution, not assumption)

### Law Shield security perimeter (`_integrationSecurity.js`) — STRONG, verified green

Protocol `arma-lawshield.v1` is implemented and enforced. I executed the real modules on Node 24 with a synthetic processor stub and confirmed the following behaviors end-to-end (20/22 baseline checks passed; the 2 failures are defects listed in section 7, not weakness of the security design):

- HMAC-SHA256 request authentication over canonical string `schemaVersion\ntimestamp\nnonce\nbodyHash` with timing-safe comparison — verified (invalid signature → 401 INVALID_SIGNATURE).
- Body-hash integrity (tampered body → 401 BODY_HASH_MISMATCH) — verified.
- Envelope payload-hash integrity (payload tamper inside valid signed body → 401 PAYLOAD_HASH_MISMATCH) — verified.
- Timestamp freshness ±5 min (stale → 409 STALE_OR_FUTURE_REQUEST) — verified.
- Transfer expiry (expired envelope → 409 TRANSFER_EXPIRED) — verified.
- Kill switch (LAW_SHIELD_ARMA_INTEGRATION_DISABLED → 503 INTEGRATION_DISABLED) — verified.
- Human-only authorization guard: `authorizedBy` starting `AI:`, or `AI`/`JOY`/`ROSE`, or `authorizationMode==='AI'` → 401 AI_CANNOT_AUTHORIZE_TRANSFER — verified.
- Prompt-injection / executable-instruction rejection (forbidden keys incl. normalized `systemPrompt`, `toolCall`, `authorizationOverride`; forbidden patterns incl. "ignore all previous instructions", "reveal the system prompt", "bypass security/authorization/policy", "grant admin access") — verified blocked inside payload.
- Schema/version + route validation (source ARMA_360 → destination LAW_SHIELD only; unsupported version → 422) — verified.
- Allowed-record-type allowlist (7 types) — enforced.
- Org/case mapping structural checks (mapping must match envelope orgs; incident requires case mapping) — verified (ORG_MAPPING_MISMATCH).
- 1 MB body limit enforced in both reader and verifier — enforced.
- Secure response headers (no-store, nosniff, no-referrer, DENY) on both endpoints.

### Law Shield gateway endpoint (`arma-integration.js`) — USABLE with defects

- Method/content-type gating (405/415) — verified.
- Forwards the ORIGINAL verified rawBody plus verified nonce/hash context headers to the processor under a bearer token with a 10 s abort timeout.
- Fail-closed on processor non-2xx, non-JSON, `accepted !== true`, or missing receiptId → 502, no acceptance implied.
- Processor consistency checks (transferId and payloadHash echoed by processor must match) — enforced (PROCESSOR_RECEIPT_MISMATCH) but see defect D2.
- Signed receipt returned with `X-LawShield-Content-SHA256`, `X-LawShield-Signature`, `X-LawShield-Receipt-Id` headers; HMAC signature verified against receipt body — verified.

### Readiness endpoint (`integration-readiness.js`) — USABLE

- GET-only; reports gatewayConfigured / receiptSigningConfigured / processorConfigured / killSwitchActive / limits / allowed record types; 503 when not ready; 405 on non-GET. No secrets disclosed.

### ARMA durable transfer schema (`lawShieldTransferSchema.ts`) — USABLE DESIGN (typechecks clean)

- Convex `defineTable` design with org mappings, case mappings, disclosure authorizations (policy decision, PHI categories, minimum-necessary fields, redacted fields), outbound transfers with full status machine (DRAFT → PENDING_AUTHORIZATION → AUTHORIZED → READY_TO_SEND → SENT → RECEIPT_VERIFIED → ACCEPTED / REJECTED / QUARANTINED / RECONCILIATION_REQUIRED), idempotency index, event sequence + previousEventHash chain, receipt state, retry state, reconciliation records, transfer audit with actorType HUMAN/SYSTEM/TRANSPORT.
- Compiles with convex@^1 + typescript@^5 strict mode (exit 0).

### PATCHES health route (`partner-v1-health-route.ts`) — USABLE STARTING POINT

- GET returns service/version/status/directDatabaseAccess:false/requiresScopedAuthentication:true. Executes correctly after transpile. See notes on `force-static` in section 7.

### Documentation — ACCURATE AND SUFFICIENT TO CONTINUE

- README and both lane docs agree on boundaries (no cross-database access, fail-closed, synthetic data, no attorney portal rebuild, promotion path back to private repos). No conflicting or duplicated designs found between lanes. `.env.example` names-only, placeholders only — safe.

### Secret scan — CLEAN

- No tokens, keys, private URLs, real emails, customer data, or Convex/Clerk/Vercel identifiers found anywhere in the tree. Only synthetic local URLs (localhost:4001/4002) intentionally present.

---

## 3. What is incomplete (missing infrastructure)

1. **No package.json, no test runner, no CI, no lint/typecheck scripts.** Nothing in the sandbox is runnable as a committed suite. The README states the Law Shield side "already includes security tests", but no test files were ported into the sandbox — that claim is true of the private repo only. This is the single largest infrastructure gap.
2. **No ARMA-side client at all.** Nothing builds envelopes, signs requests, verifies receipts, or drives the transfer state machine. The durable schema exists but no service implements it.
3. **No Law Shield durable processor.** The gateway forwards to `LAW_SHIELD_INTEGRATION_PROCESSOR_URL`, which does not exist in the sandbox. Nonce registry, idempotency registry, org/case authorization, disclosure policy, transactional persistence, audit, receipt creation, reconciliation — all unimplemented (Stop Point 3 scope).
4. **No minimum-necessary/redaction implementation** on the ARMA side (schema reserves fields; no logic).
5. **PATCHES is only a health route.** The entire partner API v1 (auth, rotation, revocation, entitlements, capabilities, activation lifecycle, device binding, events, receipts, rate controls) is unimplemented (Stop Point 4–5 scope).
6. **No AI governance layer** (provenance envelope, advisory/deterministic distinction, guards) — Stop Point 6 scope.
7. **No shared SDK, partner registry, webhook/event framework, observability contract** — Stop Point 7 scope.
8. **No contract test harness or partner simulators** — Stop Point 8 scope.
9. **No OpenAPI contracts** — Stop Point 9 scope.
10. **No certification reporting** — Stop Point 10 scope.
11. **Gateway-layer rate limiting / request-ID correlation** absent (rate controls are required for PATCHES and advisable for the Law Shield gateway).
12. **`authorizedBy` is an unauthenticated string at the Law Shield boundary.** The gateway can block AI-attributed strings, but it cannot verify a human actually authorized anything — that proof must come from the ARMA-side durable authorization record (Stop Point 2/3 work). This is a known architectural dependency, not a gateway defect.

---

## 4. Proposed architecture (meet-in-the-middle; preserves arma-lawshield.v1)

No redesign of the existing contract. The existing gateway/verifier stays the Law Shield entry point; everything is built to meet it.

```
law-shield/
  arma/                        ARMA-side (reference, synthetic persistence)
    transferService.js         create → authorize → ready → send → verify → accept/reject state machine
    authorizationGuard.js      human-only, role/org checks, durable authorization record, AI-denial
    redaction.js               minimum-necessary payload construction + redaction
    signer.js                  HMAC envelope signing compatible with the existing verifier
    receiptVerifier.js         raw-body receipt hash + signature verification (byte-exact)
    retryPolicy.js             backoff that can never duplicate an accepted disclosure
    reconciliation.js          status path for ambiguous outcomes
    persistence.js             synthetic in-memory store mirroring lawShieldTransferSchema tables
  lawshield/                   EXISTING FILES UNCHANGED except the 4 defect fixes below
    _integrationSecurity.js   (defect fixes D1–D4 are additive/clarifying; protocol stays v1)
    arma-integration.js        (defect fixes D1–D4)
    integration-readiness.js  (unchanged)
    processor.js               NEW durable reference processor (Stop Point 3)
  tests/                       node:test suites (synthetic only)
    gateway.security.test.mjs
    arma.transfer.test.mjs
    processor.durable.test.mjs
    e2e.flow.test.mjs
  docs/                        existing handoff + baseline + stop-point reports
patches/
  patches/                     partner API v1 reference implementation (Stop Point 4)
  tests/                       contract/security tests
  openapi/patches-partner-v1.yaml (Stop Point 9)
ai/                            governance contract, provenance envelope, guards (Stop Point 6)
shared/                        partner SDK, registry contract, webhooks, observability (Stop Point 7)
simulators/                    synthetic partner simulators + failure modes (Stop Point 8)
law-shield/openapi/arma-lawshield-v1.yaml (Stop Point 9)
certification/                 PASS/FAIL/NOT-TESTED report generator (Stop Point 10)
package.json                   root, workspaces, node:test, tsc scripts, Node 24 + pnpm
.github/workflows/ci.yml       install → typecheck → tests on push/PR
```

Key decisions (all additive; existing files and protocol untouched unless flagged):

- **Runner: Node built-in `node:test`** — zero runtime dependencies, works on Node 24, no supply-chain surface in a public sanitized repo.
- **TypeScript only where the canonical repos are TypeScript** (Convex schema, PATCHES routes); the existing JS gateway files stay ESM JavaScript to remain drop-in portable to the private repos.
- **Synthetic in-memory persistence** behind a narrow interface mirroring the Convex table shapes, so the private repos can swap in real Convex without touching service logic.
- **Fail-closed everywhere:** any verification/persistence ambiguity results in no acceptance.

---

## 5. Proposed files (first two batches, in build order)

Batch A (Stop Point 2 — contract + security completion):
1. `package.json`, `pnpm-workspace.yaml` (or single-package root — recommendation: single root package, workspaces unnecessary for this scale), `.github/workflows/ci.yml`
2. `law-shield/arma/signer.js`
3. `law-shield/arma/receiptVerifier.js`
4. `law-shield/arma/authorizationGuard.js`
5. `law-shield/arma/redaction.js`
6. `law-shield/arma/transferService.js` (+ `persistence.js` synthetic store)
7. `law-shield/arma/retryPolicy.js`, `law-shield/arma/reconciliation.js`
8. `law-shield/tests/gateway.security.test.mjs` (ports the 22-check baseline suite into the repo)
9. `law-shield/tests/arma.transfer.test.mjs`
10. Defect fixes D1–D4 inside the two existing gateway files (see section 7)

Batch B (Stop Point 3 — durable processor + E2E):
1. `law-shield/lawshield/processor.js`
2. `law-shield/tests/processor.durable.test.mjs`
3. `law-shield/tests/e2e.flow.test.mjs`

---

## 6. First implementation batch (recommended, awaiting approval)

Commit 1 `chore(sandbox): add runnable package + test baseline` — package.json, CI workflow, port of the baseline security suite into `law-shield/tests/gateway.security.test.mjs` proving the existing perimeter green in-repo.
Commit 2 `fix(law-shield): correct gateway receipt/transport failure contract` — the four defect fixes D1–D4 (details below), each covered by a new test.
Commit 3 `feat(law-shield): implement ARMA-side signing, authorization, redaction, transfer state machine` — Batch A items 2–7, 9.
Then STOP POINT 2 review with full test results.

---

## 7. Existing failures (verified by execution on Node 24; synthetic data only)

**Defects found in the existing gateway code (all reproducible):**

- **D1 — Receipt body omits `accepted`.** Success receipt returns `status:'ACCEPTED'` but no `accepted:true`; every error path returns `accepted:false`. An ARMA verifier cannot uniformly branch on `accepted`. Proposed fix: add `accepted:true` to the success receipt body (additive; error paths unchanged). Flagged as an additive contract clarification for owner approval at Stop Point 2.
- **D2 — `PROCESSOR_RECEIPT_MISMATCH` maps to HTTP 401.** This is a downstream integrity failure, not an authentication failure, and it is detected AFTER the processor may have persisted — an ambiguous outcome that ARMA must treat as RECONCILIATION_REQUIRED, never as "unauthorized". Proposed fix: 502 + structured code (keep fail-closed).
- **D3 — Processor timeout leaks raw error and returns 401.** Verified: hanging processor for the 10 s abort window returns `401 {"error":"The operation was aborted due to timeout"}`. An ARMA client would misread a transient outage as an auth failure and never retry, and the raw Node message pollutes the structured error contract. Proposed fix: classify AbortSignal.timeout as 502 `PROCESSOR_TIMEOUT` (retryable, fail-closed).
- **D4 — Processor unreachable returns 401 with `"fetch failed"`.** Verified against a closed port: `401 {"error":"fetch failed"}`. Proposed fix: 502 `PROCESSOR_UNAVAILABLE` (retryable, fail-closed, no raw message leakage).

**Confirmed architectural gaps (by design, to be closed in Stop Point 3):**

- **G1 — Replay accepted at gateway layer.** Verified: an identical nonce+signature request is accepted a second time at the gateway and reaches the processor. The nonce registry is designed to live in the durable processor (not yet built). Until Stop Point 3, replay protection is incomplete end-to-end.
- **G2 — No idempotency registry anywhere yet.** Same-stage dependency on the durable processor.

**Documentation/infrastructure discrepancies (no code change yet):**

- README claims Law Shield "security tests" are included in the sandbox; no test files were ported. The suite will be introduced in-repo by this lane (Batch A, commit 1).
- `patches/patches/partner-v1-health-route.ts` exports `dynamic = "force-static"`. A health/readiness endpoint should not be statically cached in production; it is inert in the sandbox but will be corrected when the PATCHES implementation lands (Stop Point 4), not silently now.
- `.env.example` PATCHES variables are not consumed by any code yet — expected for the Phase 2 foundation; no action needed until Stop Point 4.
- Receipt verification subtlety to encode in the ARMA verifier (Stop Point 2): the receipt signature is computed over the serialized receipt body, so ARMA must verify against the RAW received receipt bytes, never a re-serialized object (key-order sensitivity). My baseline harness confirmed raw-byte verification works.
- The gateway forwards the verified nonce and body hash to the processor but not the request timestamp; the processor replay registry should key on nonce within the clock-skew window (Stop Point 3 design note).

**Typecheck/build state:** TypeScript strict compile of both TS files → exit 0 (convex@^1, typescript@^5, @types/node). All three Law Shield JS modules import and execute correctly on Node 24 ESM. PATCHES health route executes correctly after transpile. No lint configuration exists.

---

## 8. Baseline execution evidence (outside repo, synthetic only)

- 22-point security smoke suite against the real gateway modules: 20 PASS / 2 FAIL (the 2 failures are defects D1 and D2 above — both are code defects, not test errors).
- Timeout/unreachable transport check: both misclassified as 401 with raw message leakage (D3, D4).
- Secret scan (tokens, keys, private URLs, emails, long entropy): clean.
- Git: single branch `main`, local == origin/main at fd56c14, no force operations performed.

END OF STOP POINT 1 REPORT — AWAITING OWNER APPROVAL BEFORE ANY BUILD.
