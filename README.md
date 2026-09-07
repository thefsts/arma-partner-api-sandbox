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

## PATCHES starting point

PATCHES currently exposes only a partner API health endpoint. This sandbox is the place to design and implement the complete partner contract before approved code is ported back to the private PATCHES and ARMA repositories.

Target PATCHES API capabilities:

- scoped partner authentication
- entitlement lookup
- capability discovery
- activation/deactivation/revocation
- device or subject binding
- status
- events/notifications
- receipts/audit
- health/version compatibility
- ARMA adapters for future Alert ARMA and Domus integration

## Promotion back to private repos

Work here is not production merely because it passes sandbox tests. Approved changes must be reviewed, secret-scanned, and then manually ported into the canonical private repositories with production configuration and CI.
