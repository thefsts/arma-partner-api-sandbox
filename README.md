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

ARMA adapters for future Alert ARMA and Domus integration are Stop Point 5 (proposal only — not begun).

## Testing

The sandbox runs a real in-process HTTP test harness: every test posts real HTTP requests to a real gateway server wrapped around `arma-integration.js`. The ARMA side is exercised end-to-end through `law-shield/arma/transferService.js` against the same gateway, and Law Shield inbound processing is exercised against a real durable processor (`lawshield/durable/processor.js` + `lawshield/durable/store.js`: authoritative nonce registry, idempotency registry, org/case mapping checks, disclosure policy enforcement, transaction-safe persistence, audit trail, status/reconciliation path) exercised over real HTTP — both directly and through the full ARMA → gateway → processor → signed receipt → ARMA verification chain. The PATCHES lane boots the real reference partner-API server on an ephemeral port and drives every contract scenario over the wire with contract-signed requests (scoped partner auth, HMAC request signing, nonce replay guard, credential rotation, tenant isolation, entitlement/capability gates, activation idempotency, receipts, audit, rate limiting, downstream failure, kill switch) against an injectable synthetic clock.

- `pnpm test` — runs all suites (101 tests: gateway security matrix, ARMA-side transfer lifecycle, v1 receipt compatibility, durable processor matrix, full synthetic E2E — 71 law-shield tests; PATCHES partner API v1 contract matrix — 30 patches tests)
- `pnpm test:lawshield` — law-shield lane only
- `pnpm test:patches` — PATCHES partner API lane only
- `pnpm typecheck` — strict TypeScript check (law-shield schema files + patches/lib)
- Zero runtime dependencies; tests use only `node:test` and Node 24 built-ins
- All data is synthetic; no real secrets are required (`secret scan` must stay clean)

## Promotion back to private repos

Work here is not production merely because it passes sandbox tests. Approved changes must be reviewed, secret-scanned, and then manually ported into the canonical private repositories with production configuration and CI.
