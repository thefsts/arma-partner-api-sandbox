# STOP POINT 2 — Law Shield Contract + Security Build Report

Builder: Ninja AI (SuperNinja agent)
Date: 2026-09-07
Repository: thefsts/arma-partner-api-sandbox (public sanitized sandbox)
Branch: `main` (single branch; no history rewritten; no force operations)
Environment: Node v24.20.0, pnpm 10.34.5

---

## 1. Git accountability (required at every stop point)

Git Author on every commit: **THEFSTS \<amorebey@gmail.com\>** (verified with `git config` before each commit and confirmed on every commit via `git log --format`).

Commits this stop point, in order (oldest first):

| SHA | Subject |
|---|---|
| `18be30d` | docs(law-shield): record stop point 1 baseline audit |
| `152cad9` | chore(sandbox): add runnable package, typecheck and CI baseline |
| `4eb82b2` | fix(law-shield): structured transport failures, receipt accepted flag, first-layer replay guard + security suite |
| `2e47351` | feat(law-shield): ARMA-side transfer service — human-only authorization, minimum-necessary redaction, raw-byte receipt verification, reconciliation and retry policy |
| (this commit) | docs: stop point 2 report, env names, testing docs |

Base for this stop point: `fd56c14` (origin/main at start, Stop Point 1 approved).

**Push status:** the sandbox has **no authenticated write path** to GitHub. Verified exhaustively: no credential helper configured (repo, user, or system), no `~/.git-credentials` or `~/.netrc`, no `GH_*`/`GITHUB_*`/`GIT_*` credential environment variables, `gh` CLI present but not logged in, SSH publickey authentication denied on port 22 and on `ssh.github.com:443`, and no private keys present anywhere in the environment. Per owner instruction, no credential was requested or placed in the repository, chat, `.env`, scripts, or Git history. All Stop Point 2 commits (the four above plus the report and correction commits) exist locally on `main`, ahead of `origin/main` (`fd56c14`), and a `git bundle` (basis `fd56c14`, exact SHAs, no credentials required) is provided alongside this report so the owner can publish from their authenticated environment.

## 2. Scope executed (approved fixes D1–D4, no redesign)

The existing `arma-lawshield.v1` architecture was continued exactly as approved at Stop Point 1. Nothing was redesigned; `_integrationSecurity.js` was modified only additively (one exported helper, described below).

### D1 — `accepted:true` on the success receipt (additive)

The Law Shield receipt now carries both `accepted:true` (new, boolean machine-readable flag) and `status:"ACCEPTED"` (unchanged, for v1 consumers). Compatibility is proven by `law-shield/tests/contract.compat.test.mjs` (4 tests): every original v1 receipt field is still present and byte-stable; the gateway HMAC signature verifies over the RAW body including the new field; the two fields always agree; error responses carry `accepted:false` and never `status:"ACCEPTED"`. The ARMA-side `receiptVerifier.js` requires **both** `accepted===true` and `status==="ACCEPTED"` before a transfer can reach ACCEPTED.

### D2 — PROCESSOR_RECEIPT_MISMATCH is a downstream integrity condition, not 401

The gateway returns **502 PROCESSOR_RECEIPT_MISMATCH** with `reconciliationRequired:true` (never 401). On the ARMA side, a receipt that fails signature or field-consistency verification transitions the transfer to **RECONCILIATION_REQUIRED** and opens a reconciliation record — fail closed, never a blind re-send. Proven by tests: corrupted receipt signature → RECONCILIATION_REQUIRED (`RECEIPT_INVALID_SIGNATURE`); wrong-transfer-id receipt → RECONCILIATION_REQUIRED (`RECEIPT_TRANSFER_ID_MISMATCH`).

### D3 — structured PROCESSOR_TIMEOUT

Timeouts return a structured 502 `PROCESSOR_TIMEOUT` with `retryable:true`. Raw Node/runtime error messages are never exposed. The classification was verified against real Node 24 fetch shapes (TimeoutError code 23, AbortError code 20, TypeError with ECONNREFUSED cause). On the ARMA side, timeouts are treated as **ambiguous**: the transfer goes to RECONCILIATION_REQUIRED, never auto-retried, because the processor may have accepted the disclosure before the connection dropped — duplicate accepted disclosures are impossible.

### D4 — structured PROCESSOR_UNAVAILABLE

Unreachable processors return structured 502 `PROCESSOR_UNAVAILABLE` with `retryable:true`, no raw error exposure. This is classified **clean-retryable**: nothing reached the processor, so the ARMA side schedules a backoff retry (1s, 5s, 30s, 120s, 600s; max 5 attempts) with a **fresh nonce and fresh signature each attempt**, returning the transfer to READY_TO_SEND with `nextRetryAt`. After exhaustion the transfer is REJECTED with `MAX_RETRIES_EXCEEDED` — it never left the ARMA perimeter.

**Interpretation to confirm (owner message truncated at D4 "Do not expose"):** I implemented "do not expose raw runtime/Node error messages — return structured error codes only," consistent with D3's wording and the standing ERROR RULE. Please confirm this matches intent.

## 3. What was built

**Gateway-side (commit 4eb82b2):** structured transport-failure classification in `lawshield/arma-integration.js` (D2/D3/D4 codes, no raw error echo); optional first-layer nonce replay guard in `_integrationSecurity.js` (env `LAW_SHIELD_GATEWAY_REPLAY_GUARD`, default enabled in sandbox); full 31-test gateway security matrix; real in-process HTTP test harness with a stub processor supporting failure modes (`reject`, `mismatch`, `hang`, `unavailable`) plus a fake gateway for receipt-attack tests.

**ARMA-side (commit 2e47351, 12 files, +1468 lines):** `law-shield/arma/` now contains `transferService.js` (durable state machine DRAFT→PENDING_AUTHORIZATION→AUTHORIZED→READY_TO_SEND→SENT→RECEIPT_VERIFIED→ACCEPTED/REJECTED/RECONCILIATION_REQUIRED, event hash chain, idempotency keys, per-call ARMA outbound kill switch, ambiguous-vs-retryable failure routing), `authorizationGuard.js` (authenticated human-only authorization; AI actors JOY/ROSE denied; org-scoped LAW_SHIELD_DISCLOSURE_AUTHORIZER role; org and case mapping gates; durable authorization record storing field NAMES only), `redaction.js` (minimum-necessary allow-list per record type, ALWAYS_REDACTED fields, fail-closed on unknown fields, redaction proof stored with the transfer), `receiptVerifier.js` (raw-byte hash+HMAC verification, full field consistency, D1 dual-field check, failure classification), `envelope.js` and `signer.js` (envelope builder dogfooding the canonical `validateEnvelope`; HMAC signer over exact wire bytes, gateway-compatible), `reconciliation.js` (human-only resolver, RESOLVED or QUARANTINED outcomes only), `retryPolicy.js` (bounded backoff, injectable clock for tests), `persistence.js` (synthetic in-memory store mirroring the Convex table design — no real database access either direction).

`_integrationSecurity.js` was changed additively only: it now exports `assertPayloadSafe()` so the ARMA envelope builder applies the exact same prompt-injection/executable-instruction perimeter rules locally before anything leaves ARMA. All existing exports and behavior are unchanged.

## 4. Test and verification results (all GREEN)

- `pnpm test`: **48 tests, 48 pass, 0 fail** (`gateway.security.test.mjs` 31, `arma.transfer.test.mjs` 14, `contract.compat.test.mjs` 4). Includes a live end-to-end happy path (DRAFT→…→ACCEPTED against a real gateway+processor over HTTP) and every D2/D3/D4 failure path.
- `pnpm typecheck`: GREEN (strict, noEmit).
- `node --check`: clean on every module.
- Secret scan (HMAC secret patterns, AWS keys, GitHub PATs, private keys, Convex tokens): **clean**. `.env.example` carries env NAMES and placeholders only.
- No test failures were suppressed: any failing test blocked the commit until fixed (ERROR RULE honored; two interim test bugs — a stale contract-helper assertion and a case-mapping gate expectation — were fixed and re-run to green, not skipped).

## 5. Porting notes for the private repos

**Replay guard (first-layer vs authoritative):** the gateway nonce replay guard is an in-memory **defense-in-depth first layer only** — it is NOT authoritative production replay protection (per owner approval of Stop Point 2). When porting to production (multi-instance), the authoritative nonce registry belongs in the Stop Point 3 durable processor at the persistence boundary, keyed by `(schemaVersion, nonce)` with the same validity window, and must be the layer relied upon for replay protection.

**Secrets:** both HMAC secrets and the processor token are read from environment/config and are injectable in tests; nothing is hardcoded. Production values are provisioned by the private repos' secret management, never by this sandbox.

**Retry scheduling:** the retry policy uses an injectable clock/sleep for tests; production porting should move `nextRetryAt` scheduling onto the durable queue/worker rather than in-process sleeps.

## 6. Boundaries honored

Synthetic data only, in every test and seed. No direct database access in either direction (the ARMA store is a synthetic in-memory mirror of the documented Convex design; the processor is a stub). Legally and technically separate ARMA ↔ Law Shield surfaces, communicating only through the authenticated, scoped, versioned, auditable `arma-lawshield.v1` gateway. The obsolete embedded ARMA Attorney Portal was not touched. No real secrets were encountered during the work, so the secret-escalation rule was never triggered.

## 7. Not started (awaiting owner approval)

Stop Point 3 (durable processor with authoritative idempotency + nonce registry, end-to-end persistence, Convex schema port). The PATCHES lane and AI governance/SDK lanes are untouched per the phase ordering (Law Shield = Phase 1).

**STOPPED — awaiting owner review and approval before Stop Point 3.**
