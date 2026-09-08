# ARMA Partner API Sandbox

Temporary sanitized public integration workspace for ARMA System 360 partner APIs.

## Purpose

This repository contains only the integration-facing code, contracts, synthetic tests, and documentation needed to continue development without exposing the private repositories or their Git history.

Current lanes:

- `law-shield/` — ARMA System 360 <-> Law Shield secure transfer API. Law Shield remains a legally and technically separate system.
- `patches/` — ARMA System 360 <-> PATCHES partner API. PATCHES remains an independent licensed platform and is Phase 2 for ARMA launch.

## Non-negotiable boundaries

- No production secrets, tokens, credentials, private keys, customer data, incident evidence, privileged Law Shield data, LISA/legal packages, or private Git history.
- ARMA must not directly query Law Shield or PATCHES databases.
- Law Shield and PATCHES must not directly query ARMA databases.
- All examples and tests must use synthetic data.
- Integration must fail closed when authentication, authorization, mapping, integrity, processor, or receipt verification fails.
- Do not rebuild the obsolete embedded ARMA Attorney Portal.

## Existing Law Shield work included

The Law Shield side already includes:

- HMAC-SHA256 request verification
- timestamp and nonce validation
- body and payload hashing
- schema and route validation
- human-only disclosure authorization rules
- prompt/executable-instruction rejection
- integration kill switch
- processor forwarding boundary
- signed Law Shield receipts
- readiness endpoint
- security tests

ARMA-side durable transfer design is documented in `law-shield/arma/lawShieldTransferSchema.ts`, sourced from the existing ARMA feature work and sanitized for this sandbox.

Stop Point 2 added the ARMA outbound half of the contract: a durable transfer state machine (`law-shield/arma/transferService.js`) with human-only disclosure authorization, minimum-necessary redaction, raw-byte receipt verification, ambiguous-failure reconciliation, and a bounded retry policy. See `docs/STOP-POINT-2-REPORT.md`.

## PATCHES partner API (Stop Point 4)

PATCHES remains an independent licensed privacy/protection platform; ARMA System 360 integrates through this scoped partner API only — no direct database access, no PATCHES private protection algorithms in this sandbox. `patches/lib/server.ts` implements the complete sanitized reference `PATCHES Partner API v1` built up from the original health endpoint, exercised over real HTTP in `patches/tests/partner.api.test.mjs`:

- **Routes** (all under `/api/partner/v1`): `GET /health` (live, never force-static cached), `GET /capabilities`, `GET /entitlements?orgId=`, `POST /activations` (idempotent), `GET /activations/:id`, `POST /activations/:id/deactivate`, `POST /activations/:id/revoke`, `GET /events?orgId=`, `GET /audit?orgId=`
- **Authentication** — `Authorization: PATCHES-Partner <clientId>:<keyId>` with HMAC-SHA256 request signing over method/path/timestamp/nonce/bodyHash, timing-safe comparison, ±5 min clock skew, nonce replay registry, credential lifecycle (rotation with grace, revocation, suspension)
- **Authorization chain** — partner → organization → entitlement → capability → binding; the authenticated partner principal is the only source of truth, `orgId`/`deviceId`/`subjectId` from the request body are never trusted directly
- **Tenant isolation** — organizations carry an `owningPartnerId` boundary; wrong-tenant reads AND writes fail closed
- **Activation lifecycle** — idempotency key + request hash (duplicate collapse vs. 409 conflict), opaque synthetic device/subject bindings (no PII), revocation is terminal
- **Receipts/audit** — the response body is the signed receipt (HMAC over raw response bytes; `X-PATCHES-Receipt-Id`, `X-PATCHES-Content-SHA256`, `X-PATCHES-Signature`); append-only, sanitized, tenant-scoped audit trail
- **Operational controls** — request IDs / correlation IDs, structured error codes, payload limit (413), per-clientId reference token-bucket rate limiting (429 + `retry-after`, checked after auth so anonymous floods cannot starve partners), fail-closed downstream boundary (injectable protection service; failure → 503 with zero partial state), and a kill switch (`PATCHES_PARTNER_API_DISABLED`) that fails every route closed while health reports the disabled state live
- **Test matrix** — the 27 mandatory contract scenarios (auth, tenant isolation, entitlements/capabilities, activation/idempotency, replay/tamper, receipts/audit, rate limit, downstream failure, kill switch) plus sub-scenarios, all driven against a real ephemeral-port HTTP server with contract-signed requests and an injectable clock
- Generic contract identifiers only (`traffic_stop_privacy`, `home_privacy`); synthetic data only

Remaining production-only PATCHES work (private repo): Convex persistence port, push/event delivery infrastructure, production key/secret rotation, production rate limiting, production tenancy checks, quarantine tooling. See `patches/docs/API-BUILD-SCOPE.md` and `docs/STOP-POINT-4-REPORT.md`.

## ARMA PATCHES adapter (Stop Point 5)

`patches/arma/` implements the ARMA-side integration half of the PATCHES partner contract — the client library, durable activation state machine, and reference persistence the future Alert ARMA / Domus systems will consume. It contains **no** Alert ARMA UI, **no** Domus UI, no proprietary PATCHES logic, and no direct database access: the only boundary is the authenticated partner API itself.

- **`patches/arma/patchesPartnerClient.ts`** — scoped partner auth (`PATCHES-Partner <clientId>:<keyId>` + HMAC-SHA256 canonical signing over method/path/timestamp/nonce/bodyHash with fresh nonce per attempt), bounded retry with backoff + `retry-after` honoring, and the failure classification engine implementing the owner's binding amendment: **CLEAN_RETRYABLE** (pre-delivery connection failures, authenticated 429, provably-unprocessed 503/500) get a bounded retry with a fresh nonce+signature; **AMBIGUOUS** (timeout after possible delivery, response/receipt lost, receipt integrity mismatch) **never blind re-send** — they transition the activation to `RECONCILIATION_REQUIRED`; **TERMINAL** (credential/tenant/entitlement/capability/binding denials, state conflicts) are rejected or quarantined. Receipts are verified over the exact raw response bytes; signatures are never recorded in attempt evidence (secret-free audit by construction).
- **`patches/arma/activationService.ts`** — durable state machine `PENDING → READY_TO_ACTIVATE → ACTIVATION_SENT → RECEIPT_VERIFIED → ACTIVE` plus `RECONCILIATION_REQUIRED`, `DEACTIVATED`, `REVOKED`, `REJECTED`, `QUARANTINED`. Stable idempotency key per ARMA activation intent; `ACTIVATION_SENT` persisted **before** the outbound await (crash mid-send ⇒ resume reconciles, never re-sends); entitlement/capability preflight fail-closed before any outbound call; in-flight intents own their binding (a different caller key collapses via `INTENT_KEY_MISMATCH`, never a parallel server-side activation); reconciliation via the status route with bounded attempts then a fresh create under the **same** idempotency key; tenant-scoped status resolution (a foreign-org identity is quarantined, never synced); an outbound kill switch (`ARMA_PATCHES_OUTBOUND_DISABLED`) that fails closed before any wire I/O; human/system audit events (secret-free) at every transition.
- **`patches/arma/transferSchema.ts` + `patches/arma/armaStore.ts`** — 11-table Convex-shaped reference persistence (partner config, org mappings, entitlement/capability refs, opaque bindings, activations, idempotency, receipts, retries, reconciliations, audit chain) with no PII, backed by an in-memory store with transactional snapshot/restore semantics for the port to Convex.
- **`patches/tests/partner.client.test.mjs`** — 48-test matrix: classification engine units, live signed activation through the real SP4 reference server, auth failures (unknown partner, revoked/rotating credentials with grace windows, expiry), tenant/entitlement/capability/binding rejections, idempotency duplicate/conflict/collapse, 429 bounded retry, clean 503/500 retry, ambiguous-failure reconciliation (timeout / response lost / receipt signature / field mismatch), lifecycle (deactivate/revoke, terminal revoked never silently reactivated, replay, stale timestamp), both kill switches, wrong-org reconciliation denial, and a full synthetic E2E — with `assertNoSecretsInStore` defense-in-depth throughout.

Remaining production-only adapter work (private repo): Convex function port of the 11 tables, real KMS-backed secret sources, production reconciliation scheduling, quarantine operator tooling, Alert ARMA / Domus UI wiring (deliberately out of scope). See `docs/STOP-POINT-5-REPORT.md`.

Alert ARMA / Domus UIs and the AI governance layer remain Stop Point 6+ (proposal only — not begun).

## Testing

The sandbox runs a real in-process HTTP test harness: every test posts real HTTP requests to a real gateway server wrapped around `arma-integration.js`. The ARMA side is exercised end-to-end through `law-shield/arma/transferService.js` against the same gateway, and Law Shield inbound processing is exercised against a real durable processor (`lawshield/durable/processor.js` + `lawshield/durable/store.js`: authoritative nonce registry, idempotency registry, org/case mapping checks, disclosure policy enforcement, transaction-safe persistence, audit trail, status/reconciliation path) exercised over real HTTP — both directly and through the full ARMA → gateway → processor → signed receipt → ARMA verification chain. The PATCHES lane boots the real reference partner-API server on an ephemeral port and drives every contract scenario over the wire with contract-signed requests (scoped partner auth, HMAC request signing, nonce replay guard, credential rotation, tenant isolation, entitlement/capability gates, activation idempotency, receipts, audit, rate limiting, downstream failure, kill switch) against an injectable synthetic clock. The ARMA PATCHES adapter lane then drives the real client library + activation state machine against that same live reference server: signed activation through the real wire, raw-byte receipt verification, failure classification per the retry-vs-reconciliation amendment, ambiguous-failure reconciliation via the status route, credential rotation with grace windows, lifecycle deactivation/revocation, and both kill switches — all under an injectable clock with secret-free audit assertions.

- `pnpm test` — runs all suites (149 tests: gateway security matrix, ARMA-side transfer lifecycle, v1 receipt compatibility, durable processor matrix, full synthetic E2E — 71 law-shield tests; PATCHES partner API v1 contract matrix — 30 patches tests; ARMA PATCHES adapter matrix — 48 adapter tests)
- `pnpm test:lawshield` — law-shield lane only
- `pnpm test:patches` — PATCHES partner API lane only
- `pnpm typecheck` — strict TypeScript check (law-shield schema files + patches/lib + patches/arma)
- Zero runtime dependencies; tests use only `node:test` and Node 24 built-ins
- All data is synthetic; no real secrets are required (`secret scan` must stay clean)

## Promotion back to private repos

Work here is not production merely because it passes sandbox tests. Approved changes must be reviewed, secret-scanned, and then manually ported into the canonical private repositories with production configuration and CI.
