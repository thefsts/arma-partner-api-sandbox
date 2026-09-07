# Ninja AI Handoff — ARMA <-> Law Shield

Do not start over. Continue the implementation represented in this repository.

## Architecture

Law Shield is legally and technically separate from ARMA System 360. The obsolete embedded ARMA Attorney Portal must not be rebuilt. Communication is API-only, scoped, auditable, minimum-necessary, and fail-closed.

## Already implemented / represented here

Law Shield gateway:
- HMAC-SHA256 request authentication
- content hash verification
- timestamp freshness and nonce format validation
- schema/version and route validation
- organization/case mapping checks at the envelope boundary
- allowed record types
- human-only authorization guard (JOY/ROSE/AI cannot authorize disclosure)
- payload integrity check
- executable/prompt-injection rejection
- integration kill switch
- processor forwarding boundary
- processor response consistency checks
- signed receipt response
- readiness endpoint

ARMA durable model:
- org mappings
- case mappings
- disclosure authorizations
- outbound transfers
- idempotency keys
- event sequence/hash fields
- receipt state
- retry state
- reconciliation records
- transfer audit

## Work still required

Build the missing meet-in-the-middle implementation rather than replacing the existing contract:

1. ARMA service that creates a transfer only after real authenticated user authorization and tenant/site checks.
2. Minimum-necessary payload construction/redaction.
3. ARMA request signing compatible with the existing Law Shield verifier.
4. Law Shield durable processor implementing nonce/replay storage, idempotency, explicit org/case authorization, policy checks, transactional persistence, and audit.
5. ARMA signed-receipt verification and durable state transition.
6. Retry/backoff rules that never duplicate accepted disclosures.
7. Reconciliation/status path for ambiguous outcomes.
8. Kill-switch behavior on both sides.
9. Complete synthetic tests.

Required negative cases include unauthorized/wrong-role/cross-org transfer, tampered body/payload, invalid signature, stale request, replayed nonce, duplicate idempotency key, missing mapping, processor unavailable/rejection, transfer-ID mismatch, payload-hash mismatch, invalid receipt signature, expired transfer, disabled integration, and reconciliation discrepancy.

## Rules

- No direct database access across systems.
- No production secrets or real records in this public repo.
- No AI authorization of legal disclosure.
- No acceptance when the durable Law Shield processor is unavailable.
- Preserve protocol `arma-lawshield.v1` unless a deliberate version migration is documented.
- Keep tests synthetic.
- Do not touch PATCHES files while working this lane unless explicitly assigned.

When complete, report exact files, tests, known gaps, and a private-repo porting map for both canonical repositories.
