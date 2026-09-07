# STOP POINT 3 — Law Shield Durable Processor + End-to-End Report

Builder: Ninja AI (SuperNinja agent)
Date: 2026-09-07
Repository: thefsts/arma-partner-api-sandbox (public sanitized sandbox)
Branch: `main` (single branch; no history rewritten; no force operations)
Environment: Node v24.20.0, pnpm 10.34.5

---

## 1. Git accountability (required at every stop point)

Git Author on every commit: **THEFSTS \<amorebey@gmail.com\>** (verified with `git config` before commit and confirmed on the commit via `git log --format`).

Commit this stop point (oldest first):

| SHA | Subject |
|---|---|
| `01d89d2` | feat(law-shield): durable synthetic processor + authoritative registries + status/reconciliation path + full E2E (SP3) |
| (this commit) | docs: stop point 3 report |

Base for this stop point: `eddf821` (origin/main at start, Stop Point 2 approved and published).

**Push status:** fast-forward push `eddf821..01d89d2` to `origin/main` succeeded (gh CLI authenticated as thefsts; no credential placed in chat, source, `.env`, scripts, or history). After the report commit, the same fast-forward path is used. Remote HEAD at report time: see Section 9.

Files changed in `01d89d2` (5 files, +1987/−2):

- `law-shield/lawshield/durable/store.js` (new, 327 lines)
- `law-shield/lawshield/durable/processor.js` (new, 625 lines)
- `law-shield/tests/processor.durable.test.mjs` (new, 805 lines)
- `law-shield/tests/e2e.synthetic.test.mjs` (new, 228 lines)
- `README.md` (testing section: 48 → 71 tests, durable-processor description)

## 2. Scope executed (the 11 approved SP3 requirements, no redesign)

The `arma-lawshield.v1` contract from Stop Points 1–2 was continued exactly as approved. The gateway (`arma-integration.js`) and the ARMA outbound half (`arma/`) are unchanged except for the README test-count line; every SP3 addition lives in new files (`lawshield/durable/`).

### Req 1 — Authoritative nonce/replay registry (durable)

`store.js` keeps nonces keyed `${schemaVersion}::${nonce}` with a validity window of `NONCE_VALIDITY_WINDOW_MS = 2 × MAX_CLOCK_SKEW_MS` (10 minutes). A duplicate nonce inside the window fails closed (`REPLAYED_NONCE`, including the first-seen transfer id) and the duplicate request is rejected — never reprocessed. Expired nonces are pruned so a nonce cannot be replayed twice within the window. Multi-instance safety is a Convex unique-index insert (see porting notes), which the in-memory map models faithfully: registration and acceptance happen inside one transaction, so a registered nonce cannot exist without its accepted transfer.

### Req 2 — Durable idempotency registry

`resolveIdempotencyKey` + `bindIdempotencyKey` in `store.js`, keyed `${schemaVersion}::${idempotencyKey}`. Same key + same payload (same payloadHash and same transferId) returns the stored deterministic receipt — a duplicate-safe collapse with no second disclosure. Same key + different payload is an integrity conflict: the response is a 200 quarantined refusal (`IDEMPOTENCY_KEY_CONFLICT`), the original record stays authoritative, and no second disclosure occurs. Both conflict shapes are tested: same transferId with altered content (audit `TRANSFER_CONTENT_CONFLICT`, original stays ACCEPTED) and a different transferId reusing the key (durable quarantine record keyed `CONFLICT-${transferId}`).

### Req 3 — Org authorization

Explicit ARMA↔Law Shield org mapping seeded in the processor directory (`seedSyntheticProcessorDirectory`: `org-arma-1 → ls-org-1`, `org-arma-2 → ls-org-2`). The mapping must exist and be active; a cross-org or mismatched mapping is denied (`ORG_MAPPING_MISSING` / `ORG_MAPPING_INACTIVE` / `ORG_MAPPING_MISMATCH`). The envelope's org pair must match the mapping exactly.

### Req 4 — Case mapping

Explicit incident↔case mapping keyed `${armaOrgId}::${incidentId}` (`INC-1001 → LS-CASE-1` under `ls-org-1`, `INC-2001 → LS-CASE-2` under `ls-org-2`). Required whenever the incidentId is present; inactive or mismatched (wrong case org or wrong case id) is denied (`CASE_MAPPING_MISSING` / `CASE_MAPPING_INACTIVE` / `CASE_MAPPING_MISMATCH`).

### Req 5 — Disclosure policy enforcement (independent of ARMA)

`enforceDisclosurePolicy` re-checks the FLAT minimum-necessary redacted payload contract: every field must be on the record-type allow-list and no `ALWAYS_REDACTED` field may be present. A wrapper-shaped payload (`data` nesting) is itself a `MINIMUM_NECESSARY_VIOLATION`. The processor also independently re-verifies the authorizer: a human directory user of the right org, active — unknown, inactive, wrong-org humans and any AI authorizer are denied (`AUTHORIZER_UNKNOWN` / `AUTHORIZER_INACTIVE` / `AUTHORIZER_ORG_MISMATCH` / `AUTHORIZER_IS_AI`). The processor trusts nothing from ARMA beyond the verified envelope.

### Req 6 — Transaction-safe processing

ALL durable writes for an acceptance — nonce registration, transfer record, receipt record, idempotency binding, audit events — happen inside ONE `runTransaction` in `store.js` (snapshot/rollback). Injectable failure points (TEST ONLY: `persistTransfer`, `persistReceipt`, `auditWrite`) prove the rollback: any mid-transaction failure returns 500 `PROCESSOR_PERSISTENCE_FAILED` with NO partial state (no nonce, no transfer, no receipt, no binding; the only durable trace is the best-effort failure audit, written in a separate transaction). Ambiguous outcomes are recoverable: a retry after a persistence failure succeeds cleanly, and a timeout after durable acceptance reconciles to the accepted state without a duplicate disclosure.

### Req 7 — Durable transfer persistence

`createDurableTransfer` stores status (ACCEPTED / REJECTED / QUARANTINED), payloadHash (not payload content), transferId, idempotencyKey, receiptId, timestamps, org/incident/case/record ids, and minimum-necessary field names. No payload content is ever stored in the processor store — verified structurally (store API takes hashes and field names only) and by test (e2e hop 4).

### Req 8 — Audit trail (append-only, no payload content)

`appendAudit` sanitizes every detail through the `SAFE_DETAIL_KEYS` allowlist with 256-char string caps and depth limits, so payload content structurally cannot reach the audit trail. Events carry actor/source classification (actor: `lawshield-processor`, source: `ARMA_GW`), outcomes, and reconciliation events (`NONCE_REPLAY_REJECTED`, `TRANSFER_ACCEPTED`, `DUPLICATE_DELIVERY_COLLAPSED`, `TRANSFER_REJECTED`, `TRANSFER_QUARANTINED`, `TRANSFER_CONTENT_CONFLICT`, `PROCESSOR_TRANSACTION_FAILED`, `IDEMPOTENCY_CONFLICT_QUARANTINED`). Test-verified: no SSN, officerNotes, or summary text appears anywhere in the processor audit trail (e2e hop 8).

### Req 9 — Signed receipt creation (exact arma-lawshield.v1 behavior)

The receipt is generated ONCE at acceptance (`createReceiptRecord`; a duplicate delivery returns the stored receipt with the original `acceptedAt`). The receipt binds `schemaVersion, receiptId, transferId, idempotencyKey, status:'ACCEPTED', accepted:true, acceptedAt, armaOrgId, lawShieldOrgId, incidentId, lawShieldCaseId, recordType, recordId, receivedPayloadHash, processingResult`. The gateway continues to sign the receipt HMAC over the RAW response bytes with `X-LawShield-Content-SHA256` / `X-LawShield-Signature` headers — byte-exact behavior unchanged from Stop Point 1 (test 17 and e2e hop 5 verify the signature over raw bytes; the contract.compat suite continues to pass).

### Req 10 — Reconciliation/status path

`GET /status?transferId=&idempotencyKey=&schemaVersion=` (Bearer auth) returns the durable state: status, receiptId, timestamps, payloadHash, org/case/record ids, idempotency outcome, the stored receipt, and scrubbed audit events. This resolves: accepted-but-response-lost (status finds ACCEPTED, ARMA `resolveReconciliation` completes the transfer), timeout ambiguity (test 14: fetch aborts after durable acceptance → status shows ACCEPTED → re-delivery collapses to the same receipt → `resolveReconciliation` resolves), receipt mismatch (test 18: corrupted signature → RECONCILIATION_REQUIRED → test 19 resolves via status inquiry), and quarantined outcomes (test 20). Resolution itself remains human-only on the ARMA side (AI and wrong-org resolvers denied, human resolves with a note — test 19).

### Req 11 — Synthetic persistence only

The store is an in-memory synthetic implementation with interfaces deliberately shaped for Convex (table-per-registry, unique-index semantics, transaction scope). No production Convex client, no real orgs/cases/users, no real data. Porting notes in Section 8.

## 3. What was built

- `lawshield/durable/store.js` (327 lines) — `SyntheticDurableLawShieldStore`: org mappings, case mappings, authorizer directory, nonce registry, idempotency registry, transfers, receipts, append-only audit, `runTransaction` all-or-nothing with injectable fail points, `SAFE_DETAIL_KEYS` sanitization, Convex PORTING NOTE, `seedSyntheticProcessorDirectory`. Exports `NONCE_VALIDITY_WINDOW_MS`, `SAFE_DETAIL_KEYS`, `SyntheticDurableLawShieldStore`, `seedSyntheticProcessorDirectory`.
- `lawshield/durable/processor.js` (625 lines) — `processTransferRequest` (the full verification pipeline), `enforceDisclosurePolicy`, `checkProcessorAuthorizer`, `checkProcessorMappings`, `buildStatusResponse`, `createDurableProcessorServer` (real HTTP server: kill switch first → Bearer timing-safe auth → envelope re-validation → mappings/policy → transaction → receipt; plus GET /status; 401/400/413/422/503 fail-closed paths). Exports listed for test reuse.
- `tests/processor.durable.test.mjs` (805 lines) — 22 tests (the 21 mandatory scenarios + 9b authorizer-org-mismatch) over a real HTTP processor, and the full stack (real ARMA service → real gateway → real durable processor) for tests 12–21.
- `tests/e2e.synthetic.test.mjs` (228 lines) — one comprehensive full-chain E2E (8 asserted hops).
- README testing section updated (71 tests; durable processor + E2E description).

## 4. Test and verification results (all GREEN)

Authoritative runner output (repo root, `pnpm test`, Node v24.20.0):

| Metric | Count |
|---|---|
| tests | 71 |
| pass | 71 |
| fail | 0 |
| cancelled | 0 |
| skipped | 0 |
| todo | 0 |
| duration | 1717 ms |

Suite breakdown: gateway.security 30, arma.transfer 14, contract.compat 4, processor.durable 22, e2e.synthetic 1. Additive only — the pre-existing 48 tests remain GREEN and unmodified.

CI: workflow "CI" run **34165773867** on pushed HEAD `01d89d2`, conclusion **success** — https://github.com/thefsts/arma-partner-api-sandbox/actions/runs/34165773867 (jobs: Install, Typecheck, Tests (synthetic only) all success; CI log shows the same 71/71 pass totals). `pnpm typecheck` exit 0 locally. Secret scan over the committed set (PAT/ghp_/AKIA/sk-/AIza/xox/JWT/PEM patterns): clean. All data synthetic; test secrets are the pre-existing SP1/SP2 fixtures (`synthetic-arma-to-lawshield-test-secret`, `synthetic-lawshield-to-arma-test-secret`, `synthetic-processor-bearer-token`).

### Authoritative replay results (mandatory tests 1–2)

Test 1 (first valid transfer accepted): full-stack delivery accepted — 200 `accepted:true`, receipt `RCP-TRX-…`, durable transfer ACCEPTED, idempotency bound, receipt count 1, `TRANSFER_ACCEPTED` audit. Test 2 (exact replayed nonce denied): byte-identical re-delivery → **409 REPLAYED_NONCE**, no second transfer, no second receipt, `NONCE_REPLAY_REJECTED` audit with the first-seen transfer id. E2E hop 6 re-proves both over the full chain.

### Idempotency results (mandatory tests 3–4)

Test 3 (same payload duplicate): fresh-nonce delivery with the same idempotencyKey and same payload → **200 with the SAME receiptId and SAME acceptedAt** (deterministic duplicate-safe collapse), transfer count and receipt count stay at 1, `DUPLICATE_DELIVERY_COLLAPSED` audit — the disclosure is never duplicated. Test 4 (different payload denied): both conflict shapes fail closed — same-transferId altered content → audit `TRANSFER_CONTENT_CONFLICT`, original record stays ACCEPTED, response quarantined `IDEMPOTENCY_KEY_CONFLICT`; different-transferId key reuse → durable `CONFLICT-TRX-…` quarantine record, original stays authoritative. No second disclosure in any case.

### Transaction / fail-closed results (mandatory tests 12, 13, 21)

Test 12 (persistence failure): fail-point on the durable transfer write → **500 PROCESSOR_PERSISTENCE_FAILED**, rollback proven by direct store inspection (no transfer, no receipt, no nonce, no idempotency binding; counts unchanged), only durable trace is the `PROCESSOR_TRANSACTION_FAILED` audit; a clean retry afterwards succeeds and accepts. Test 13 (audit write failure): audit fail-point inside the acceptance transaction → acceptance itself rolls back (no transfer, no receipt, no binding) — the processor refuses silent acceptance; the receipt-write fail point behaves identically. Test 21 (kill switch): `LAW_SHIELD_PROCESSOR_DISABLED=true` → processor refuses POST, status, and even the full-stack gateway path (503 PROCESSOR_DISABLED, fail closed); removing the switch restores service.

### Reconciliation results (mandatory tests 14, 18, 19)

Test 14 (timeout after durable acceptance): transport abort injected AFTER the response text was consumed — durable acceptance already happened; status inquiry finds ACCEPTED with the original receipt; a re-delivery through the gateway collapses to the same receipt (no duplicate disclosure); ARMA `resolveReconciliation` completes the transfer as accepted. Test 18 (tampered receipt): corrupted signature header → ARMA receipt verification fails → transfer RECONCILIATION_REQUIRED, no blind re-send. Test 19 (reconciliation resolution): truncated receipt body → RECONCILIATION_REQUIRED; AI resolver denied, wrong-org human denied, correct human resolver with a note resolves the transfer as accepted (status inquiry as evidence). E2E hop 7 re-proves the status path by transferId, by idempotencyKey, and the 404 for unknown ids.

### Remaining mandatory tests (5–11, 15–17, 20)

All GREEN: cross-org (5), inactive org (6), missing case (7), wrong case (8), unauthorized human (9), authorizer wrong org (9b), AI authorizer (10), minimum-necessary violation quarantined (11), duplicate delivery never duplicates the disclosure (15), receipt generated once and deterministic (16), raw-byte signature verification (17), quarantine path with status exposure and no receipt (20).

## 5. Full synthetic E2E (required chain, all hops asserted)

`tests/e2e.synthetic.test.mjs` — one test, eight asserted hops, real servers only (no stubs): (1) ARMA `createDraft` with redaction proof — SSN and officerNotes recorded in `redactedFields`, absent from the payload; (2) AI authorization throws, human `authorize` → AUTHORIZED with policy decision APPROVED and minimum-necessary fields recorded; (3) `ready` → READY_TO_SEND with case mapping to `LS-CASE-1`; (4) `send` → ACCEPTED — real gateway → real durable processor → receipt `RCP-…`, processor transfer ACCEPTED, idempotency bound, and no payload content persisted; (5) fresh receipt copy fetched through the gateway and `verifyReceipt` verifies the HMAC signature over the RAW bytes with matching payload hash; (6) byte-identical replay → 409 REPLAYED_NONCE; fresh-nonce duplicate → 200 same receiptId and acceptedAt, transfer/receipt counts stay 1; (7) status by transferId (ACCEPTED + idempotency outcome), by idempotencyKey, and 404 for unknown; (8) audit on both sides — processor `TRANSFER_ACCEPTED` + `DUPLICATE_DELIVERY_COLLAPSED` with no payload text (no SSN, no officerNotes, no summary text) and no `detail` leakage in status auditEvents; ARMA events `TRANSFER_DRAFT_CREATED → AUTHORIZED → READY_TO_SEND → SENT → RECEIPT_VERIFIED → ACCEPTED` with no payload text.

## 6. Boundaries honored

- Synthetic data only; no production Convex, no real orgs/cases/users, no customer data.
- No secret in chat, source, `.env`, scripts, or history; scan clean; test secrets are pre-existing synthetic fixtures.
- The ARMA↔Law Shield contract is unchanged (no redesign): gateway and ARMA modules untouched; `contract.compat` continues to pass.
- The processor trusts nothing from ARMA beyond the verified envelope — authorization, mappings, and policy are independently re-checked.
- Push was fast-forward only (`eddf821..01d89d2`); no force operations; no history rewritten.
- Stop Point 4 (PATCHES lane) NOT begun — proposal in Section 10 only.

## 7. Remaining Law Shield gaps (honest list)

1. **Persistence is in-memory only.** The store models Convex semantics (unique-index inserts, transaction scope) but a process restart loses state; production requires the Convex port (Section 8).
2. **Reconciliation is pull-only.** ARMA resolves ambiguity by querying `/status`; there is no push/webhook notification from Law Shield to ARMA when an outcome becomes known asynchronously.
3. **Key/secret rotation.** Gateway signing secret, receipt secret, and processor bearer token are static in this sandbox; no rotation story yet (same gap noted at SP2).
4. **Rate limiting at the gateway.** The processor enforces payload limits (413) and auth, but no request-rate limiting exists on either side (noted at SP1 as a cross-lane gap).
5. **Status endpoint pagination/tenancy.** `/status` requires a transferId or idempotencyKey (400 otherwise) and is processor-side only; a production version would need partner-scoped tenancy checks on lookups.
6. **Operator tooling.** No admin/ops console for quarantine review — the durable records exist and are exposed via `/status`, but there is no human review workflow UI.

## 8. Porting notes for the private repos (exact)

**Law Shield private repo (Convex):** port `lawshield/durable/store.js` as Convex tables — `orgMappings` (unique index on `armaOrgId`), `caseMappings` (unique index on `${armaOrgId}::${incidentId}` → store as two indexed columns), `authorizers` (unique index on `userId`), `nonces` (unique index on `${schemaVersion}::${nonce}` → two columns + TTL-style validity-window query; INSERT-OR-REJECT is the replay guard, exactly like `registerNonce`), `idempotency` (unique index on `${schemaVersion}::${idempotencyKey}` → two columns; resolve-then-bind inside the mutation), `transfers` (unique index on `transferId`), `receipts` (unique index on `receiptId`), `audit` (append-only table; keep the `SAFE_DETAIL_KEYS` sanitization verbatim). Every acceptance path is ONE Convex mutation (or a scheduled transaction) so nonce + transfer + receipt + idempotency + audit commit atomically — this mirrors `runTransaction`; Convex mutations are single-document-atomic per call, so implement the acceptance as one mutation performing all inserts, which fails atomically if any insert violates a unique index. Remove the TEST-ONLY `failPoints` (keep them in the sandbox). `processTransferRequest` and `buildStatusResponse` port as-is (pure functions over the store interface); `createDurableProcessorServer` is a Node HTTP wrapper — in the private repo the same handlers become an HTTP action / route handler behind the same Bearer check and kill switch. Env names: `LAW_SHIELD_PROCESSOR_DISABLED`, `LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN` already match the gateway's `LAW_SHIELD_INTEGRATION_PROCESSOR_URL`/`…TOKEN` pair.

**ARMA private repo:** nothing to port from SP3 — `arma/` is unchanged. The status-inquiry pattern (`/status` by transferId/idempotencyKey inside `resolveReconciliation`-adjacent flows) is already covered by the existing service; production just points `LAW_SHIELD_INTEGRATION_PROCESSOR_URL` at the real deployment.

**Testing to port:** both new test files run against the same synthetic harness; in the private repos, mirror `processor.durable.test.mjs` + `e2e.synthetic.test.mjs` against the real Convex deployment in a staging project (the Convex PORTING NOTE in `store.js` documents the interface mapping). The 22-test matrix is the acceptance checklist for the port.

## 9. Publication state

- Local `main`: `01d89d2` (SP3 implementation) + this report commit (the final SP3 commit).
- `origin/main`: fast-forward `eddf821..01d89d2` pushed and verified — remote HEAD after the SP3 implementation push was **`01d89d272e7f60245cc7af94804365ce33efb716`** (verified `git rev-parse HEAD origin/main` equal). This report commit follows on top and is pushed the same fast-forward way; its SHA is recorded in the stop-point completion message to the owner and is the top of `git log origin/main` after publication.
- CI run 34165773867 on `01d89d2`: **success** (71/71 tests, typecheck green).

## 10. Stop Point 4 proposal (PATCHES lane — PROPOSAL ONLY, NOT BEGUN)

Per the phase ordering (Law Shield = Phase 1, PATCHES = Phase 2), Stop Point 4 opens the PATCHES lane. Existing base: `patches/patches/partner-v1-health-route.ts` (11 lines, `GET /api/partner/v1/health`) and `patches/docs/API-BUILD-SCOPE.md` (the 12-point build target). Proposed scope for SP4, derived from that scope document:

1. **Partner auth + rotation strategy** — scoped partner authentication (per-partner synthetic credentials), token verification fail-closed, kill switch, and a rotation/revocation design (rotation itself may be a later stop point).
2. **Tenant-scoped authorization** — never trust org/device ids from the body; validate against the authenticated partner principal (mirrors the SP3 org-mapping discipline).
3. **Entitlement lookup + capability discovery** — synthetic entitlements for licensed PATCHES capabilities, with version compatibility in the health route family.
4. **Activation lifecycle with idempotency** — activate/deactivate/revoke with idempotency keys (reuse the SP3 idempotency semantics: same key + same payload → duplicate-safe collapse; different payload → conflict).
5. **Opaque device/subject binding + status** — opaque identifiers only, no unnecessary personal data.
6. **Signed receipts for state-changing ops** — integrity-verifiable receipts (raw-byte HMAC pattern from arma-lawshield.v1 reused where it fits).
7. **Replay protection** — nonce/registry discipline from SP3 adapted to the partner API.
8. **Hardening baseline** — payload limits, schema validation, structured error codes, request IDs, audit logging with the no-payload-content rule, rate-limit hooks (design-level if full limiting lands later).
9. **Synthetic tests** — the API-BUILD-SCOPE matrix: authorized success, missing/invalid auth, wrong tenant, replay, duplicate idempotency key, tampering, revoked entitlement, revoked credential, invalid device binding, unsupported API version, downstream failure, receipt mismatch.
10. **Correction of the health route** — remove `export const dynamic = "force-static"` from a health/readiness endpoint (noted as a deferred fix at SP1).

Proposed test count target: the 12-scenario matrix above as a minimum, plus E2E through the ARMA adapter path where applicable. Exact file layout: `patches/patches/` for routes, `patches/lib/` (or similar) for auth/entitlement/idempotency modules, `patches/tests/` for the synthetic suite — presented for owner approval before any code is written.

---

STOP POINT 3 — PUBLISHED. Awaiting owner approval before Stop Point 4 (PATCHES lane) begins.
