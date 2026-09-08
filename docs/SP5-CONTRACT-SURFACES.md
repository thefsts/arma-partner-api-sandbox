# SP5 Grounding — PATCHES Partner API v1 Contract Surfaces (adapter-consumed)

Extracted verbatim from the SP4 reference implementation (baseline `a107548`,
CI run 34173198420, 101/101). This is the exact contract the ARMA adapter must
speak. Nothing here is invented; every line traces to `patches/lib/*` sources.

## Base URL and paths

- Base prefix: `/api/partner`, version segment `v1` → all routes under `/api/partner/v1`.
- Routes:
  - `GET  /api/partner/v1/health` — unauthenticated, live readiness, `{ service, version: 'v1', status, directDatabaseAccess: false, requiresScopedAuthentication: true, at }` (kill switch → 503 `status: 'disabled'` live payload).
  - `GET  /capabilities` — `{ requestId, capabilities: [{ capability, minApiVersion, maxApiVersion, description }] }`.
  - `GET  /entitlements?orgId=...` — `{ requestId, orgId, entitlements: [{ entitlementId, capability, status, licensedFrom, licensedUntil }] }`.
  - `POST /activations` — activation create (idempotent).
  - `GET  /activations/:activationId` — `{ requestId, activation: activationView }`.
  - `POST /activations/:id/deactivate` and `POST /activations/:id/revoke`.
  - `GET  /events?orgId=...` — `{ requestId, orgId, events: [{ eventId, capability, activationId, type, at }] }`.
  - `GET  /audit?orgId=...` — `{ requestId, orgId, audit: [{ sequence, at, actorKind, clientId, requestId, operation, outcome }] }` (partner sees only own orgs' audit rows).
- Unsupported version → 400 `{ error: 'UNSUPPORTED_API_VERSION', errorClass: 'VERSION', supported: ['v1'], requestId }`.
- Unmatched route → 404 `{ error: 'NOT_FOUND', requestId }`.

## activationView (status route + receipts `result`)

```
{ activationId, orgId, capability, bindingId, status: 'ACTIVE'|'DEACTIVATED'|'REVOKED', activatedAt, deactivatedAt: number|null, revokedAt: number|null }
```

## Authentication (client must produce; security.ts)

- Header `Authorization: PATCHES-Partner <clientId>:<keyId>` (scheme literal `PATCHES-Partner`).
- `X-PATCHES-Timestamp`: epoch ms; ±5 min skew window (MAX_CLOCK_SKEW_MS = 300000).
- `X-PATCHES-Nonce`: `[A-Za-z0-9_-]{20,128}`; validity window 10 min; single-use (server registers nonce in same transaction as the outcome).
- `X-PATCHES-Signature`: lowercase hex HMAC-SHA256 over
  `${METHOD}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`
  where `path` is the FULL url.pathname INCLUDING `/api/partner/v1` (query NOT signed), `METHOD` uppercase, and `bodyHash = sha256Hex(rawBodyBytes)` — empty body (GET/POST-no-body) → sha256 of empty string. Timestamp and nonce in the string are the EXACT header values.
- Credential statuses: ACTIVE | GRACE | RETIRED | REVOKED (GRACE validates; RETIRED/REVOKED → 401/409 auth failures). Partner status ACTIVE|SUSPENDED.
- Auth failure status: 401 or 409; body `{ error, errorClass: 'AUTHENTICATION', requestId }` plus safe context keys only: clientId, keyId, nonce, firstSeenAt, firstSeenRequestId, graceUntil, skewMs.
- Auth failure codes: AUTH_MISSING, AUTH_MALFORMED, PARTNER_UNKNOWN, PARTNER_SUSPENDED, CREDENTIAL_UNKNOWN, CREDENTIAL_REVOKED, CREDENTIAL_EXPIRED, TIMESTAMP_OUT_OF_WINDOW, NONCE_INVALID, NONCE_REPLAYED, SIGNATURE_INVALID, SECRET_UNAVAILABLE.
- Credential rotation: `rotateCredential` marks old key GRACE (graceUntil = now + window) and inserts new ACTIVE key with `rotatedFrom` = old keyId.

## Rate limiting (server behavior client must handle)

- Per clientId, token bucket capacity 30, refill 10/s, checked AFTER auth.
- 429 body: `{ error: 'RATE_LIMITED', errorClass: 'RATE_LIMIT', retryAfterMs, requestId }` + header `retry-after: <seconds, min 1>`.

## Activation create (POST /activations)

Request body: `{ orgId, capability, bindingId, idempotencyKey }` (all required strings; malformed JSON → 400 MALFORMED_PAYLOAD; missing fields → 400 with missing list).

Idempotency resolution per (clientId, idempotencyKey):
- FRESH → activationId = `ACT-<requestId>`, receiptId = `RCP-ACT-<requestId>`; downstream fail-closed check first (503 `{ error: 'DOWNSTREAM_UNAVAILABLE', errorClass: 'DOWNSTREAM' }`, zero partial state); then ONE transaction: putActivation (ACTIVE, payloadHash = sha256 of canonical JSON body), putReceipt, putIdempotency, appendEvent (`EVT-<requestId>`, type `activation.created`), audit. → 200 receipt body.
- DUPLICATE (same requestHash) → 200 duplicate receipt: receiptId `RCP-DUP-<requestId>`, body has `duplicate: true`, `activationId`, `result: activationView(existing)`.
- CONFLICT (different requestHash, same idempotencyKey) → 409 `{ error: 'IDEMPOTENCY_KEY_CONFLICT', errorClass: 'IDEMPOTENCY', existingActivationId }`.

Success receipt body (200):
```
{ schemaVersion: 'patches-partner-v1', receiptId, requestId, clientId, operation: 'activation.create', outcome: 'SUCCESS', at,
  activationId, orgId, capability, payloadHash, result: activationView }
```

## Deactivate / revoke (POST /activations/:id/deactivate|revoke)

- Unknown activation → 404 `{ error: 'ACTIVATION_UNKNOWN', errorClass: 'NOT_FOUND' }`.
- Wrong-org (cross-tenant) → 403 `{ error: <orgAuth code>, errorClass: 'AUTHORIZATION' }` (ORG_NOT_FOUND | ORG_SUSPENDED | ORG_NOT_OWNED).
- Policy pipeline re-checks org → entitlement → capability on the activation's org/capability (entitlement lapse → 403 ENTITLEMENT_*).
- Already-REVOKED revoke → 200 no-op success receipt (`result` shows REVOKED). Already-DEACTIVATED deactivate → 200 no-op. Deactivate on REVOKED → 409 `{ error: 'ACTIVATION_REVOKED', errorClass: 'STATE' }` (REVOKED is terminal).
- Success → 200 receipt body: receiptId `RCP-DEACTIVATE-<requestId>` / `RCP-REVOKE-<requestId>`, `{ ..., activationId, orgId, capability, result: activationView }` (new status persisted, event `activation.deactivated`/`activation.revoked`).

## Receipts (raw-byte verification; receipts.ts)

- Response body IS the receipt. Receipt body shape: `{ schemaVersion: 'patches-partner-v1', receiptId, requestId, clientId, operation, outcome, at, ...extras }`.
- Signed headers on receipt responses: `x-patches-receipt-id`, `x-patches-content-sha256` (sha256 of RAW response bytes), `x-patches-signature` (hex HMAC-SHA256 over RAW response bytes with receipt secret).
- verifyReceipt(raw bytes, headers, expected binding { receiptId, requestId, clientId, operation, outcome, activationId }) → reasons: RECEIPT_MISSING_HEADERS, RECEIPT_INVALID_SIGNATURE, RECEIPT_CONTENT_HASH_MISMATCH, RECEIPT_BODY_MALFORMED, RECEIPT_FIELD_MISMATCH.
- GET routes do NOT produce receipt headers; POST routes do (activation create/duplicate, deactivate/revoke success no-ops). 4xx/5xx error bodies are NOT receipts.

## Every response

- `x-request-id` header (echoes caller's `x-request-id` if present, else `req-<uuid>`), `x-api-version: v1`, `content-type: application/json`, `cache-control: no-store`, `content-length`.
- Kill switch `PATCHES_PARTNER_API_DISABLED=true` → 503 `{ error: 'PARTNER_API_DISABLED' }` on all routes except health (health → live disabled payload above).

## Persistence failure

- Transaction fail-point → 500 `{ error: 'PARTNER_PERSISTENCE_FAILED', errorClass: 'PERSISTENCE' }` (nonce NOT registered → auth replay of the same nonce remains possible client-side, but adapter never blind-retries ambiguous).

## Store record shapes (informational for adapter state modeling)

ActivationRecord { activationId, orgId, capability, bindingId, partnerId, status, activatedAt, deactivatedAt?, revokedAt?, lastRequestId?, idempotencyKey?, activatedViaIdempotencyKey?, payloadHash }. IdempotencyRecord { clientId, idempotencyKey, requestHash, outcome: 'SUCCESS'|'CONFLICT', activationId?, requestId?, at }. NonceRecord { clientId, nonce, firstSeenAt, firstSeenRequestId? }. ReceiptRecord { receiptId, requestId, clientId, operation, outcome, activationId?, orgId?, capability?, payloadHash?, at }. PartnerEventRecord { eventId, orgId, capability, activationId?, type, at, payloadDigest? }. AuditEventRecord { sequence, at, actorKind: 'PARTNER'|'SYSTEM', clientId, requestId, operation, outcome: 'SUCCESS'|'REJECTED'|'FAILED'|'QUARANTINED'|'CONFLICT', detail? (sanitized, SAFE_DETAIL_KEYS) }. CredentialRecord { clientId, keyId, kind: 'CLIENT_SECRET', secretHash, status, activatedAt, rotatedFrom?, retiredAt?, revokedAt?, revokedReason? }.
