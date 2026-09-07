# PATCHES Partner API v1 — Build Scope

PATCHES is an independent licensed privacy/protection platform. ARMA System 360 integrates through a scoped API only. Direct database access is prohibited.

## Existing implementation

The private PATCHES repository currently has only `GET /api/partner/v1/health`, represented in this sandbox under `patches/patches/partner-v1-health-route.ts`.

## Build target

Implement a versioned partner API with:

1. Partner authentication and key/credential rotation strategy.
2. Tenant/org scoped authorization. Never trust an org/device identifier from the body without validating it against the authenticated partner principal.
3. Entitlement lookup for licensed PATCHES capabilities.
4. Capability discovery/version compatibility.
5. Activation and deactivation/revocation with idempotency.
6. Device/subject binding using opaque identifiers; avoid unnecessary personal data.
7. Current activation/protection status.
8. Partner-safe event/notification delivery with replay protection.
9. Signed or otherwise integrity-verifiable receipts/audit records for state-changing operations.
10. Health/readiness endpoints that disclose no secrets.
11. Rate limiting, payload limits, schema validation, structured error codes, request IDs, and audit logging.
12. Synthetic contract/security tests covering authorized success, missing/invalid auth, wrong tenant, replay, duplicate idempotency key, tampering, revoked entitlement, revoked credential, invalid device binding, unsupported API version, downstream failure, and receipt mismatch.

## ARMA consumers

Phase 2 adapters will be used by Alert ARMA and Domus. Do not couple the API contract to either UI. Keep partner contracts reusable and independently testable.

## Public sandbox rule

Use fake identifiers and local-only secrets. Do not copy PATCHES private protection algorithms, production keys, customer/device records, billing data, or unrelated application source into this repository.

## Promotion requirement

A sandbox implementation is a reference implementation. Before production it must be reviewed and ported into the private PATCHES repository, connected to the real entitlement/protection services through approved internal interfaces, and certified by private-repo CI/security tests.
