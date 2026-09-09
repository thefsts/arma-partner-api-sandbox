# STOP POINT 11 REPORT — FINAL SANDBOX CERTIFICATION

**Status: PUBLISHED / CERTIFIED — FINAL CLOSE OF THE SANDBOX. STOPPING FOR OWNER ACCEPTANCE. NO STOP POINT 12.**

Auditor: Ninja AI (SuperNinja agent), acting for the owner (THEFSTS <amorebey@gmail.com>)
Repo: `thefsts/arma-partner-api-sandbox`, branch `sp9` → published fast-forward to `origin/main`
Baseline approved for this stop point: `9c3060f718272f751166293715d7ba6943b508c8` (Stop Point 10 close)
Executed: 2026-09-09, clean-room, synthetic data only, no real secrets, no partner data, no private-repo implementation, no new product features.

This report executes the SP10 §10 proposal exactly (A — final certification pass, B — gap-disposition register, C — final-state freeze) with the owner's two additions: reconcile the CI evidence record before certifying, and publish only fast-forward commits then verify the final remote CI run.

---

## 1. CI evidence record — reconciled (owner's first requirement)

Three runs exist in the Actions history around the SP10 close; one is authoritative for the final head and must be distinguished from a correction-tree run:

| Run | Head commit | Status | Meaning |
|---|---|---|---|
| `34379870530` | `9c3060f` | completed / success — tests 539, pass 539, fail 0 | **Authoritative SP10 final-head certification run** (the head the owner approved) |
| `34379711903` | `6740a00` | completed / success — tests 539, pass 539, fail 0 | Correction-tree run: green on the intermediate report-correction commit, not the final head |
| `34373623708` | `e7e5832` | completed / success — tests 539, pass 539, fail 0 | Original publication run: green on the first SP10 publication commit |

**The authoritative SP10 final-head run is `34379870530` on `9c3060f`.** Runs `34379711903` (on `6740a00`) and `34373623708` (on `e7e5832`) are the correction-tree and original-publication runs of the SP10 close sequence; the historical CI record is preserved in the repository's Actions history — this table is the reconciliation. The SP11 certification run (the new final head) is recorded in §8 below.

---

## 2. Clean-room certification gates — final tree, ALL GREEN

Both certification passes ran clean-room (fresh `node_modules`, frozen lockfile):

- **Pass 1 — SP10-approved baseline** `9c3060f`, clean worktree, no changes: all 10 gates green. It was first run at 2026-09-09T17:06Z; the sandbox environment then suffered a filesystem rollback (local git state, node_modules, and work files lost; the published remote and the certified tree untouched), and during recovery the entire pass was re-executed from a fresh clean-room on the rebuilt environment at 2026-09-09T18:04Z — all 10 gates green, results identical (539/539, 662/662/0/0, lockstep/verify exit 0, scans clean). The re-executed transcript is the preserved pass-1 evidence below.
- **Pass 2 — final-tree pass of record** (the proposal's required rerun on the final tree): run with the worktree carrying exactly the two Stop Point 11 docs changes — the README closeout and this report — at 2026-09-09T18:20:29Z → 18:20:51Z (all 10 gates green: install/typecheck exit 0, 539/539, generate 662/662/0/0 with self-verification and no-leak sweep OK, lockstep exit 0, verify exit 0, openapi 8/8, secret scan clean on HEAD and worktree, audit 0 vulnerabilities, identity/host sweep clean). After the pass, the only edit to the tree was entering the pass-2 timestamps and evidence into this section; the secret scan, artifact lockstep, and `certify:verify` were then re-executed on those exact final bytes (all clean). A committed report cannot certify its own bytes remotely; the authoritative remote execution is the CI run on the final head (§8).

1. **Fresh install, frozen lockfile** — `rm -rf node_modules && pnpm install --frozen-lockfile` → exit 0.
2. **Typecheck** — `pnpm typecheck` (`tsc -p tsconfig.json`, strict) → exit 0.
3. **Full test suite** — `pnpm test` → **tests 539 / pass 539 / fail 0 / cancelled 0 / skipped 0 / todo 0**.
4. **Certification report generation** — `pnpm certify:generate` → exit 0, **662 rows — 662 PASS / 0 FAIL / 0 NOT-TESTED**, self-verification OK (0 violations), no-leak sweep OK (15 synthetic forbidden-material fixtures loaded; artifacts metadata-only).
5. **Artifact lockstep** — `git diff --exit-code -- docs/certification/` after regeneration → exit 0 (byte-identical to the committed `certification-report.json` / `.html`).
6. **Committed-artifact verification** — `pnpm certify:verify` → exit 0 (invariants hold, HTML in lockstep with JSON, no-leak sweep clean).
7. **OpenAPI validation + conformance** — openapi lane solo → **tests 8 / pass 8 / fail 0** (structure ×2, cross-check ×3, live conformance ×3).
8. **Secret / private-data scan** — the CI 4-regex pattern (`sk-[A-Za-z0-9]{8,}` / `AKIA[0-9A-Z]{16}` / private-key PEM headers / `ghp_` tokens) → no match on HEAD and no match on the worktree with the README change applied (grep exit 1 = clean both times).
9. **Dependency / security audit** — `pnpm audit --prod` → exit 0, **no known vulnerabilities**.
10. **Identity / host sweep** — `git log --format='%an <%ae>' | sort -u` yields exactly two names, both the same approved address `<amorebey@gmail.com>`: `THEFSTS` (34 commits — every commit made by the agent from the SP1 report onward, verified per-stop-point with `git show --no-patch --format='%an <%ae> | %cn <%ce>'`) and `Full Stack Teck Solutions` (10 commits — the owner's own pre-existing sandbox bootstrap, imported and recorded verbatim in the SP1 baseline; no history was rewritten). No other identity ever appears. Hostname-shaped tokens: a full enumeration finds 56 unique `.com/.net/.org/.io`-shaped tokens in the tree, and every one classifies as a GitHub link (`github.com`/`ssh.github.com` — repo and Actions-run URLs), `gmail.com` (the author address), a synthetic harness host (`127.0.0.1`/`localhost`, RFC-reserved `.invalid`/`.internal`/`.example.invalid`), or a code false-positive — a property-access fragment cut mid-identifier by the regex (e.g. `overrides.org` is the `overrides.org` property access in `orgRecordFixture(overrides.org)`; `this.scenario.identity.org` is `this.scenario.identity.orgId` in `simulators/syntheticPlatform.ts`; `platform.telemetry.com` is `platform.telemetry.completeSpan` in `shared/tests/e2e.synthetic.test.mjs`; `receipt.org` is `receipt.orgId`; `activation.org`/`binding.org` are `.orgId` field matches) — none are domains the sandbox contacts.

The pass-2 transcript above is the local clean-room gate log on the final tree; the remote CI run on the final head (§8) independently re-executes the same gate sequence (install --frozen-lockfile, typecheck, the 539-test suite, certify:generate + lockstep + verify, secret scan) and its result is recorded in §8 as the certification of record.

---

## 3. Dead/duplicate-code audit — findings and dispositions

**Audit A — duplication and dead code (all 131 tracked files, re-executed on the final tree):**

- **A1 byte-identical duplicates** — 0 pairs of byte-identical tracked files.
- **A2 export-name collisions** — 440 uniquely exported names across the 46 committed TypeScript modules (`export function/const/class/interface/type/enum` declarations); 20 names are exported from more than one lane — e.g. `verifyReceipt` (`patches/lib/receipts.ts` vs `shared/sdk/receipts.ts`), `computeRequestSignature` (`patches/lib/security.ts` vs `shared/sdk/canonical.ts`), `sha256Hex` (three lanes), `CertificationRow` (`certification/certify.ts` vs `simulators/evidence.ts`). Disposition: **by design** — the lane-isolation porting model (each lane lifts into a different private repo independently, so self-contained naming is the directive; a shared name across lanes is not a defect, it is independence). No cross-lane file imports another lane's internals.
- **A3 unreferenced source files** — 63 non-test source files (all `.ts`/`.mjs`/`.js` outside `tests/` and `helpers/`); 0 orphans (every source file is referenced by at least one test or another source file).
- **A4 `tsc --noUnusedLocals --noUnusedParameters --noEmit`** (the committed TypeScript 5.9.3, stricter than the committed config) — 15 findings in 7 files: `patches/arma/activationService.ts` `secretsForRedaction`; `patches/lib/server.ts` `bodyHashFor`, `MAX_CLOCK_SKEW_MS`, `ApiVersion`, `MAX_API_VERSION`, `isFailPoint`, `now`, `requestId`; `patches/patches/partner-v1-health-route.ts` `PARTNER_API_DISABLED_ENV`; `shared/sdk/errors.ts` `key`; `shared/webhooks/delivery.ts` `buildWebhookEnvelope`; `simulators/partnerSimulator.ts` `clock`; `simulators/syntheticPlatform.ts` `PlatformFaultPlan` (TS6196), `lastDeliveryResult`, `lastSpanId` (14×TS6133 + 1×TS6196). Disposition: **cosmetic, deliberately not fixed** — `noUnusedLocals`/`noUnusedParameters` are not enabled in the committed strict `tsconfig.json` (the committed strict typecheck is green), and the proposal forbids unrequested code churn ("no new product features"). They are documented here so the private-repo port can run the stricter flag and see the exact same list.

**Audit B — production URL / credential / prompt / data-leakage scan (all tracked files, HEAD):**

- **B1 external URLs** — all classified, nothing unclassified: GitHub Actions run links in stop-point reports and CI evidence; `127.0.0.1`/`localhost` synthetic harness addresses; RFC-reserved `.invalid`/`.internal` synthetic hostnames in tests; no production partner URL, no telemetry endpoint, no external CDN or font URL anywhere.
- **B2 credential-like assignments** — every hit is a declared synthetic fixture (test-harness generated secrets, `replace-with-local-test-secret` placeholders in `.env.example`, KMS `keyId` references in porting notes). No real credential format appears anywhere.
- **B3 prompt-leakage markers** — the only `prompt`/`instructions`-shaped strings are the ai-governance guards' own detection code and the boundary statements ("no prompts exist in this repo" declarations). No prompt content exists to leak.
- **B4 PII shapes** — SSN-like strings: only the canonical synthetic `000-00-0000` (a synthetic fixture), and the test sources that set it also assert it never reaches an audit record — those assertions are inside the certified rows `law-shield/tests/e2e.synthetic.test.mjs::full synthetic E2E: ARMA -> gateway -> durable processor -> receipt -> ACCEPTED -> verification` and the `processor.durable.test.mjs` quarantine rows (`::11. minimum-necessary policy violation is denied and quarantined`, `::20. quarantine path works: durable record, status exposure, no receipt`, which set the smuggled SSN and assert it never appears in the audit record or emitted events) and `arma.transfer.test.mjs::every state transition extends the hash chain; audit never stores payload content`. Emails: only the author-identity address `<amorebey@gmail.com>` (the approved publication convention, 14 occurrences across commit identity and reports) and `@invalid` synthetic fixtures. No real PII shape anywhere.
- **B5 synthetic markers** — 62 non-docs files carry declared synthetic markers; the forbidden-material sweep fixtures used by the verifier assert none of them appear in certification artifacts.
- **B6 hostname allowlist** — every hostname-shaped token is a synthetic host (`127.0.0.1`, `localhost`, `*.invalid`, `*.internal`, `*.example.invalid`), a GitHub link (`github.com`, `ssh.github.com`), the author address host (`gmail.com`), or a code false-positive verified with raw-context grep (`overrides.org` = the `overrides` argument's `.org` property in `orgRecordFixture(overrides.org)`; `activation.org`/`binding.org` = `.orgId` field accesses; `simulators.config-driven.test.mjs` matching `simulators.co`) — none are domains the sandbox contacts.

Both audits: **CLEAN with the dispositions above** — nothing unclassified, nothing unexplained, no real-world material anywhere in the tree.

---

## 4. Stop-point acceptance matrix SP1–SP10 — grounded in certification rows

Every acceptance below cites certification rows from `docs/certification/certification-report.json` by their file-qualified testId (result PASS). The citation form is `laneFile::testName` — the exact `testId` key of the row. Nothing is accepted by narrative; every row is in the committed, lockstep-verified report.

### SP1 — Baseline audit (defects found and requirements set)

The SP1 audit found defects D1–D4 in the pre-existing gateway code and set the requirements the later stop points implemented. The baseline conditions (D1–D4, G1, G2) are accepted as closed only by the rows that prove the fixed/architected behavior exists and fails closed:

| SP1 finding | Disposition | Certifying rows (testIds) |
|---|---|---|
| D1 — receipt omits `accepted` | CLOSED at SP2 | `law-shield/tests/gateway.security.test.mjs::valid authenticated request is accepted and returns a signed receipt (D1: accepted:true + status:"ACCEPTED")`; `law-shield/tests/contract.compat.test.mjs::D1 compat: v1 receipt fields all present; accepted:true added; status:"ACCEPTED" preserved` |
| D2 — mismatch → 401 (misclassification) | CLOSED at SP2 | `law-shield/tests/gateway.security.test.mjs::D2: processor receipt mismatch returns 502 PROCESSOR_RECEIPT_MISMATCH with reconciliationRequired (NOT 401)` |
| D3 — timeout leaks raw error, 401 | CLOSED at SP2 | `law-shield/tests/gateway.security.test.mjs::D3: processor timeout returns 502 PROCESSOR_TIMEOUT with retryable:true and no raw error leak` |
| D4 — unreachable → 401 "fetch failed" | CLOSED at SP2 | `law-shield/tests/gateway.security.test.mjs::D4: processor unavailable returns 502 PROCESSOR_UNAVAILABLE with retryable:true and no raw error leak` |
| G1 — replay accepted at gateway | CLOSED at SP3 | `law-shield/tests/processor.durable.test.mjs::2. exact replayed nonce is denied by the authoritative replay registry` |
| G2 — no idempotency registry | CLOSED at SP3 | `law-shield/tests/processor.durable.test.mjs::3. duplicate idempotency (same payload) collapses to the deterministic stored receipt` |
| §3.11 gateway rate limiting / request-ID correlation | PATCHES: CLOSED at SP4; Law Shield gateway: ACCEPTED-AS-SANDBOX-SCOPE | PATCHES rows: `patches/tests/partner.api.test.mjs::scenario 22: rate limit reference behavior (429 + retry-after)`, `patches/tests/partner.client.test.mjs::A4. 429 -> CLEAN_RETRYABLE RATE_LIMITED`, `patches/tests/partner.client.test.mjs::F1. 429 bounded retry: first attempt rate-limited, retry with fresh nonce+signature succeeds; Retry-After honored`. Request-ID correlation primitives are certified in the shared lane (`shared/tests/sdk.correlation.test.mjs::correlation headers use the x-request-id / x-correlation-id names`, `::generateRequestId produces the req-<uuid> shape`) while the Law-Shield-side gateway limiter itself remains sandbox scope (SP3 §7.4).
| §3.12 `authorizedBy` unauthenticated string | CLOSED at SP2/SP3 | `law-shield/tests/arma.transfer.test.mjs::unauthenticated actor cannot create or authorize a transfer`, `::wrong role (officer) cannot authorize; draft still allowed for humans`, `law-shield/tests/processor.durable.test.mjs::9. unauthorized human authorizer is denied by the durable processor`, `::9b. authorizer from the wrong org is denied` |

### SP2 — Law Shield contract + security build (D1–D4 fixes, ARMA outbound half, runnable suite)

Accepted by the rows that certify the fixes are live and fail-closed, plus the ARMA outbound half and the runnable suite:

- D1–D4 fix rows: the four `gateway.security.test.mjs` D-rows and `arma.transfer.test.mjs::D2 mismatch / D3 timeout / D4 unavailable produce the correct ARMA states`, plus `contract.compat.test.mjs::D1 compat: signature covers the full receipt body including the new field` and `::D1 compat: error responses still carry accepted:false and never accepted:true`.
- ARMA outbound half (state machine, human-only authorization, kill switch, retry policy, hash chain): `arma.transfer.test.mjs::AI actors (JOY/ROSE) can never create or authorize — both gates`, `::ARMA outbound kill switch blocks every stage`, `::retry policy exhaustion terminates in REJECTED, not infinite retry`, `::every state transition extends the hash chain; audit never stores payload content`, `::wrong organization (cross-tenant authorizer) is blocked`.
- Runnable suite: SP1's "nothing is runnable" gap is closed by the very existence of the 539-test committed suite and its CI gate — certified row-for-row by the report itself (662 rows across 36 lanes).
- The SP2 report's "31-test gateway security matrix" wording vs the file's 30 top-level tests: transcription slip already reconciled in the chain (SP3 recorded the correct 30; the certification report carries 30).

### SP3 — Law Shield durable processor + end-to-end

Accepted by the durable-processor rows of `processor.durable.test.mjs` (replay registry, idempotency registry, org/case mapping, authorizer checks, disclosure policy, transactional persistence, receipt determinism, tamper, timeout reconciliation, quarantine, kill switch) — e.g. `::1. first valid transfer is accepted by the durable processor` through `::18. tampered receipt fails closed to reconciliation`, with quarantine at `::20. quarantine path works: durable record, status exposure, no receipt` and the kill switch at `::21. processor kill switch fails closed (process + status + gateway path)` — plus the end-to-end row `law-shield/tests/e2e.synthetic.test.mjs::full synthetic E2E: ARMA -> gateway -> durable processor -> receipt -> ACCEPTED -> verification` and the ARMA-side reconciliation row `arma.transfer.test.mjs::reconciliation: ambiguous mismatch opens reconciliation; only authorized human in org can resolve`.

### SP4 — PATCHES Partner API v1 (sanitized reference server)

Accepted by the 30 `patches/tests/partner.api.test.mjs` rows (scenarios 1–30: scoped partner auth, HMAC signing, nonce replay guard, credential rotation with grace windows, tenant isolation, entitlement/capability gates, activation lifecycle, deactivation/revocation, device binding, idempotency collapse/conflict, rate limiting, downstream failure, kill switch) — e.g. `::scenario 10: unsupported capability is rejected`, `::scenario 11: duplicate activation with the same idempotency key collapses`, `::scenario 12: same idempotency key + different payload -> 409 CONFLICT`, `::scenario 13: deactivation (lifecycle, idempotent by status)`, `::scenario 16: replayed request (same nonce) is rejected with NONCE_REPLAYED`. All 30 PASS.

### SP5 — ARMA PATCHES adapter

Accepted by the 48 `patches/tests/partner.client.test.mjs` rows (signed activation through the real wire, raw-byte receipt verification, the failure-classification matrix A1–A13, ambiguous-failure reconciliation via the status route, credential rotation with grace windows, lifecycle deactivation/revocation, both kill switches) — e.g. `::A1. AbortError (client timeout) -> AMBIGUOUS TIMEOUT: never blind re-send`, `::A2. ECONNREFUSED (pre-delivery) -> CLEAN_RETRYABLE`, `::A3. response dropped mid-read -> AMBIGUOUS RESPONSE_LOST; ECONNRESET after send -> AMBIGUOUS DROP`, `::A4. 429 -> CLEAN_RETRYABLE RATE_LIMITED`, `::A11. receipt verification failed on 2xx -> AMBIGUOUS (processing may have occurred)`, `::A13. redactForAudit throws (fail closed) if secret material would reach the audit projection`. All 48 PASS.

### SP6 — AI safety + governance contract

Accepted by the 56 ai-governance rows across 6 files: the vocabulary and registration core (`governance.test.mjs::governance: AI engine registration is pinned advisory-only, structural fail closed`, `::governance: the five designations and four engine classes are the exact vocabulary`, `::governance: all four engine classes register cleanly on their one legal lane`), the injection guards (`injection.test.mjs::injection: AI output authority claims fail closed, advisory language passes`, `::injection: clean external data passes as DATA, preserved verbatim, and is audited as data`, `::injection: guardAiOutput structural failures throw (fail closed)`), the protected-action policy (`protected-actions.test.mjs` — 16 rows, e.g. `::governance: protected-action registry lists exactly the owner-specified ten actions`), provenance envelopes (`provenance.test.mjs` — 13 rows), human review of record (`human-review.test.mjs` — 4 rows), and the end-to-end chain (`e2e.synthetic.test.mjs::e2e: full governance chain — partner data to durable human approval`, `::e2e: injected partner payload never reaches an AI task (short-circuit)`, `::e2e: post-approval tamper — every checkpoint catches the altered output`, `::e2e: cross-org isolation — a review from another org never authorizes`).

### SP7 — Shared partner integration platform

Accepted by the 207 shared rows across 13 files: the SDK primitives (`sdk.signing.test.mjs` 18, `sdk.receipts.test.mjs` 11, `sdk.idempotency.test.mjs` 14, `sdk.correlation.test.mjs` 18, `sdk.errors.test.mjs` 15, `sdk.retries.test.mjs` 14, `sdk.health.test.mjs` 12, `sdk.audit.test.mjs` 13, `sdk.client.test.mjs` 18), the partner registry (`registry.test.mjs::an unknown or suspended org fails closed`, `::a suspended or revoked partner fails closed`, `::entitlement missing on the partner fails closed` … 17 rows), webhooks (`webhooks.test.mjs` — 28 rows: build/sign/verify/guard/delivery with dead-lettering and duplicate collapse), observability (`observability.test.mjs` — 18 rows), and the synthetic end-to-end chain (`e2e.synthetic.test.mjs::e2e: full synthetic chain — resolve, negotiate, sign, verify, idempotency, receipt, webhook, delivery, telemetry, audit`, `::e2e: 2xx without a valid receipt fails closed — success is only trusted when proven`).

### SP8 — Synthetic partner simulators + failure-mode harness

Accepted by the 53 TAP rows across 4 test files (happy-path 7, config-driven 24, failure-modes 10, contract-runner 12) plus the 123-row in-process contract matrix lane `simulators/contractRunner.ts` — 123 scenarios over 11 categories: SIGNATURE 15, REPLAY 9, RECEIPT 12, AUTHORIZATION 24, ENTITLEMENT 21, WEBHOOK 15, RETRY 12, RECONCILIATION 6, CIRCUIT_BREAKER 3, KILL_SWITCH 3, CONTROL 3 — all PASS, produced by the same fail-closed reporter, with the synthetic-secrets/payload-marker forbidden-material sweep asserted on every serialized record (simulators lane rows certify the sweep itself).

### SP9 — OpenAPI contracts

Accepted by the 8 openapi rows: `spec.structure.test.mjs::structure: ARMA Law Shield API v1 — OpenAPI 3.1.x document validates`, `::structure: PATCHES Partner API v1 — OpenAPI 3.1.x document validates`, `spec.crosscheck.test.mjs::cross-check: every implemented route is documented and every documented route is implemented`, `::cross-check: ARMA Law Shield API v1 — every wire error code is in the spec, every spec token traces to source`, `::cross-check: PATCHES Partner API v1 — every wire error code is in the spec, every spec token traces to source`, `spec.live-conformance.test.mjs::live conformance: Law Shield — transfer submission, receipt, readiness, processor process + status match the spec`, `::live conformance: PATCHES — health, discovery, activation lifecycle, events, audit, receipts, error shapes`, `::live conformance: PATCHES — create-activation policy failures (403 family) and input errors (400/413) match the spec`.

### SP10 — Integration certification reporter

Accepted by the 66 certification rows: the positive lane (`certify.report.test.mjs` — 30 rows: TAP parsing, row mapping, duplicate/conflict resolution, byte-deterministic assembly, self-contained HTML rendering with FAIL-first, no-leak sweep, frozen limits/vocabularies — e.g. `::assembleReport is byte-deterministic: identical inputs serialize identically with no timestamps`, `::CERTIFICATION_LIMITS is frozen with the committed structural limits`) and the negative lane (`certify.negative.test.mjs` — 36 rows: the never-PASS invariant across every fail-closed path — empty/garbage/missing lanes, count drift, crashed runners, skip/todo/cancelled, unknown fields/results/codes, duplicate/conflict handling, lane collapse PASS-withholding, leak injection, and ten tamper mutations the verifier must catch). The SP10 close sequence itself (publication → correction → final head) is the CI-record reconciliation in §1.

**Matrix result: SP1 through SP10 every acceptance grounded — 662 rows, 662 PASS, 0 FAIL, 0 NOT-TESTED.**

---

## 5. Gap-disposition register — every gap since SP1, dispositioned

The register below dispositions every gap recorded in the stop-point chain. Three dispositions are used, per the proposal: **CLOSED-IN-SANDBOX** (with the certifying row), **PORTED-TO-PRIVATE-REPO** (with the porting-note pointer), **ACCEPTED-AS-SANDBOX-SCOPE** (out of sandbox scope by owner directive — the sandbox is a contract-level reference, not production).

### SP1 §3 infrastructure gaps 1–10 (the build plan itself)

Items 1–10 were the build plan (runnable suite, ARMA client, durable processor, redaction, PATCHES API, AI governance, shared platform, simulators, OpenAPI, certification) — all delivered at their stop points and all certified in §4. Items 11–12 are dispositioned in the §4 SP1 matrix row-by-row (11: PATCHES rate limiting CLOSED, Law Shield gateway limiter ACCEPTED-AS-SANDBOX-SCOPE; 12: CLOSED by SP2/SP3 rows).

### SP1 §7 architectural gaps and documentation discrepancies

| Gap | Disposition |
|---|---|
| G1 replay accepted at gateway | CLOSED-IN-SANDBOX at SP3 — `processor.durable.test.mjs::2. exact replayed nonce is denied by the authoritative replay registry` |
| G2 no idempotency registry | CLOSED-IN-SANDBOX at SP3 — `processor.durable.test.mjs::3. duplicate idempotency (same payload) collapses to the deterministic stored receipt` |
| README claimed "security tests included" but none were ported | CLOSED-IN-SANDBOX — the suite landed with the SP1 runnable-baseline commit and is now 539 tests / 662 rows; the README closeout (this stop point) makes the front door state exactly what is certified |
| `partner-v1-health-route.ts` exported `force-static` | CLOSED-IN-SANDBOX at SP4 — the route is now fully dynamic (source comment: "The route is therefore fully dynamic: every request computes fresh state"); `patches/lib/server.ts` serves it live in the reference server |
| `.env.example` PATCHES vars not consumed | ACCEPTED-AS-SANDBOX-SCOPE — 11 of 14 variables are consumed today; the 3 PATCHES connection placeholders (`PATCHES_PARTNER_API_BASE_URL` / `PATCHES_PARTNER_CLIENT_ID` / `PATCHES_PARTNER_SECRET`) are 0-consumer placeholders by design: the sandbox adapter uses constructor injection (`patchesPartnerClient.ts` transport is injectable and dependency-free), and env wiring is private-repo deployment work (SP5 §9 porting notes) |
| Raw-byte receipt verification subtlety | CLOSED-IN-SANDBOX — encoded and certified: `arma.transfer.test.mjs::invalid receipt signature (200 with tampered receipt) fails closed to reconciliation` and `processor.durable.test.mjs::17. receipt signature verifies against raw bytes (full stack)` |
| Gateway forwards nonce+hash but not timestamp | CLOSED-IN-SANDBOX at SP3 — the processor replay registry keys on nonce within the clock-skew window exactly as designed (row 2 of `processor.durable.test.mjs`, `::2. exact replayed nonce is denied by the authoritative replay registry`); the gateway contract was left unchanged by design (compat preserved) |

### SP3 §7 remaining Law Shield gaps

| Gap | Disposition |
|---|---|
| 1 in-memory persistence | PORTED-TO-PRIVATE-REPO — SP3 §8 porting notes (Convex tables, unique-index inserts, one-mutation atomic acceptance) |
| 2 pull-only reconciliation | ACCEPTED-AS-SANDBOX-SCOPE + PORT — the pull path is certified (`processor.durable.test.mjs::19. reconciliation resolves an accepted ambiguous outcome via status inquiry + human resolver`); push/webhook notification is private-repo delivery work, and the SP7 shared webhook framework provides the contract reference |
| 3 key/secret rotation | PORTED-TO-PRIVATE-REPO — sandbox secrets are declared synthetic by boundary; production rotation story is KMS/secret-store work (SP4 §6.3 for the PATCHES-side reference) |
| 4 gateway rate limiting | ACCEPTED-AS-SANDBOX-SCOPE — the PATCHES reference limiter is certified (SP4 rows above); the Law Shield gateway limiter is production work (SP3 §7.4 records it as a cross-lane gap; sandbox-scale in-process tests do not need it) |
| 5 status pagination/tenancy | PORTED-TO-PRIVATE-REPO — production `/status` needs partner-scoped tenancy checks (SP3 §8) |
| 6 operator tooling | PORTED-TO-PRIVATE-REPO — quarantine review workflow UI is Alert-ARMA/private-repo work (SP4 §6.6, SP5 §8.4) |

### SP4 §6 remaining PATCHES gaps

| Gap | Disposition |
|---|---|
| 1 Convex persistence port | PORTED-TO-PRIVATE-REPO — SP4 §7 porting notes |
| 2 push/event delivery | PORTED-TO-PRIVATE-REPO — pull-based `GET /events` with replay protection is certified (`partner.api.test.mjs` events rows); production push is private-repo |
| 3 production key/secret rotation | PORTED-TO-PRIVATE-REPO — reference rotation with grace windows is certified in-lane (`partner.api.test.mjs` rotation scenarios); production secret storage/distribution is KMS work |
| 4 distributed rate limiting | PORTED-TO-PRIVATE-REPO — the per-clientId token bucket reference is certified (`scenario 22`, `A4`, `F1`); shared limiter state is production |
| 5 production tenancy checks | PORTED-TO-PRIVATE-REPO — the synthetic `owningPartnerId` boundary is certified in-lane (tenant-isolation scenarios); real PATCHES tenancy is private |
| 6 quarantine tooling | PORTED-TO-PRIVATE-REPO |
| 7 deployment wiring | PORTED-TO-PRIVATE-REPO — wiring, not logic (SP4 §7 route-order skeleton) |

### SP5 §8 remaining adapter gaps

| Gap | Disposition |
|---|---|
| 1 Convex persistence port (11 tables) | PORTED-TO-PRIVATE-REPO — SP5 §9 (schema + store signatures map directly) |
| 2 production credential source | PORTED-TO-PRIVATE-REPO — `CredentialSource` interface is the seam (SP5 §9) |
| 3 production reconciliation scheduling | PORTED-TO-PRIVATE-REPO — Convex cron + alerting |
| 4 quarantine operator tooling | PORTED-TO-PRIVATE-REPO |
| 5 push/event consumption | PORTED-TO-PRIVATE-REPO — the ARMA-side poller/receiver is built on the SP7 shared event framework in the private repo |
| 6 Alert ARMA / Domus UI wiring | PORTED-TO-PRIVATE-REPO — the adapter is contract-level by directive |

### SP6 §8 remaining ai-governance gaps

| Gap | Disposition |
|---|---|
| 1 real engine registration | PORTED-TO-PRIVATE-REPO — registration contract is the seam (SP6 §9: IDs/versions/classes only, advisory-only rule holds with zero code changes) |
| 2 production integrity key | PORTED-TO-PRIVATE-REPO — `SYNTHETIC_INTEGRITY_KEY` → KMS/secret store; `provenanceIntegrity.ts` HMAC seam |
| 3 persistence port | PORTED-TO-PRIVATE-REPO |
| 4 review workflow tooling | PORTED-TO-PRIVATE-REPO — the contract (`humanReview.ts`) is certified; the UI cannot weaken the binding rules |
| 5 policy version governance | PORTED-TO-PRIVATE-REPO — `policyVersion` is carried on envelopes and decisions; the registry is private |

### SP7 §8 remaining shared-platform gaps

| Gap | Disposition |
|---|---|
| 1 durable persistence | PORTED-TO-PRIVATE-REPO — shaped for the port (unique-index idempotency, TTL nonce window, transactional resolve+record) |
| 2 production secrets | PORTED-TO-PRIVATE-REPO — declared synthetic in sandbox |
| 3 async retry drivers | PORTED-TO-PRIVATE-REPO — the schedule honoring is certified synchronously; the persistent async driver is production |
| 4 real partner records | PORTED-TO-PRIVATE-REPO — registry is data-only by design; production record management is private |
| 5 transport wiring | PORTED-TO-PRIVATE-REPO — injectable transport function is the seam (endpoints, TLS, mTLS) |

### SP8 §8 remaining harness gaps

| Gap | Disposition |
|---|---|
| 1 durable persistence | PORTED-TO-PRIVATE-REPO |
| 2 production secrets | PORTED-TO-PRIVATE-REPO |
| 3 real transport | PORTED-TO-PRIVATE-REPO |
| 4 real partner records | PORTED-TO-PRIVATE-REPO |
| 5 coverage breadth beyond shared contracts | ACCEPTED-AS-SANDBOX-SCOPE — the 40 directed failure modes on the 10 shared-contract categories are the owner-directed catalog; partner-specific quirks belong to each partner's own lane by directive |
| 6 SP10 reporter UI | CLOSED-IN-SANDBOX at SP10 — the reporter landed and its 66-test lane is certified |

### SP9 §8 remaining gaps

| Gap | Disposition |
|---|---|
| 1 Redoc/Swagger UI rendering | ACCEPTED-AS-SANDBOX-SCOPE — the custom static renderer is the sandbox decision (SP9 §8.1: the YAML documents are the source of truth; any OpenAPI 3.1 tool can render) |
| 2 live-conformance depth | ACCEPTED-AS-SANDBOX-SCOPE — the two-way cross-check covers the full error vocabulary; deeper per-code probes duplicate SP4/SP8 matrices that are green in their own lanes |
| 3 private-repo contract drift | PORTED-TO-PRIVATE-REPO — the same three-layer discipline applies there with their own reference servers |
| 4 PATCHES kill-switch/downstream live probes | ACCEPTED-AS-SANDBOX-SCOPE — behavior is documented and schema-conformant; the behavioral matrices live in SP4 (30) and SP8 (40-mode) lanes, both green |
| 5 SP10 certification reporter | CLOSED-IN-SANDBOX at SP10 |

### SP10 §8 remaining gaps

| Gap | Disposition |
|---|---|
| 1 report breadth is lane-derived | ACCEPTED-AS-SANDBOX-SCOPE — the reporter certifies what the lanes test; lane scope is governed per-lane by owner directive |
| 2 rendering depth | ACCEPTED-AS-SANDBOX-SCOPE — JSON is the machine-readable source of truth for downstream tooling |
| 3 cross-commit history | ACCEPTED-AS-SANDBOX-SCOPE — trend history lives in CI Actions history (§1 reconciles it), not in a committed artifact |
| 4 private-repo drift | PORTED-TO-PRIVATE-REPO — the manifest is re-derived empirically there (`certify.ts` parsing real TAP), never hand-assumed |

### Audit findings from this stop point (§3)

| Finding | Disposition |
|---|---|
| 20 cross-lane export-name collisions (of 440 uniquely exported names) | ACCEPTED-AS-SANDBOX-SCOPE — by-design lane isolation (the porting model: each lane lifts independently) |
| 15 unused-symbol findings (14×TS6133 + 1×TS6196) in 7 files | ACCEPTED-AS-SANDBOX-SCOPE — cosmetic; `noUnused*` flags not part of the committed strict config; documented in §3 A4 so the private-repo port sees the same list if it enables the stricter flags |
| 3 PATCHES `.env.example` placeholders unconsumed | ACCEPTED-AS-SANDBOX-SCOPE — constructor injection is the sandbox design (SP1 table above) |

**Register totals: 66 gap lines dispositioned — every gap recorded since SP1 is either closed by a certified row, ported with an exact seam, or accepted as sandbox scope by owner directive. Nothing is silently dropped.**

---

## 6. README closeout — owner-facing front door

`README.md` is rewritten as the owner-facing front door for the closed sandbox. The seven per-lane detail sections and the Testing/Promotion tails from the previous README are preserved **byte-identical** (verified programmatically against HEAD before commit); the replaced front matter (old title/Purpose) becomes:

- a FINAL status line: 662 rows — 662 PASS / 0 FAIL / 0 NOT-TESTED, 36 lanes, 21 categories, verified on every push by CI, with direct links to `docs/certification/certification-report.html` (self-contained, zero JavaScript — verified) and `certification-report.json`;
- "What this sandbox is — and is not" (the clean-room statement and the no-production-readiness rule);
- the Non-negotiable boundaries, preserved verbatim;
- "Architecture at a glance" (directory tree verified against the actual tree);
- "Lane inventory" — the 36-lane table, every count taken from the committed certification report's own lane records (column sums = 662 verified);
- "How to run the certified state" — the exact CI commands (`pnpm install --frozen-lockfile`, `typecheck`, `test`, `certify:generate` + lockstep, `certify:verify`, per-lane runs);
- "The stop-point chain" — the SP1→SP11 custody one-liner;
- the Promotion tail, preserved verbatim.

All numeric claims in the front door were verified against ground truth before writing (lane counts from the report's lane records; the SP8 matrix categories from the matrix rows themselves — 11 categories, not 10; the 11-table Convex-shaped persistence from `ARMA_TABLES`; the 40-mode harness from `failureModes.ts`).

---

## 7. Final-state freeze

The final state of the sandbox is the two commits this stop point adds on top of the approved `9c3060f` (both docs-only; the certification evidence itself is unchanged):

1. `docs: README closeout — owner-facing front door for the certified final state` (README.md only)
2. `docs: stop point 11 report — final sandbox certification` (docs/STOP-POINT-11-REPORT.md — this report; the final head)

Both are published in one fast-forward push, so there is exactly one remote CI run for Stop Point 11 and it executes on the final head — no publication/correction run sequence to disambiguate (the SP10 sequence that required reconciliation is recorded in §1).

Freeze properties, each verified before this report was delivered:

- **Certification artifacts frozen** — the final-tree regeneration is byte-identical to the committed `docs/certification/certification-report.json` / `.html` (lockstep exit 0 on the final tree, §2 gate 5). Report SHA-256 at freeze: JSON `d71b75ed2d9e9b9a6a9fb77ff13441055d68d65b9fc0cb9ba0283aceeecd1f94`, HTML `2dd656c88afab0efa9c37acc9ff4ac9e946f04d4a31a579c29b679932ef3bff6`.
- **CI gates frozen** — the workflow (`install --frozen-lockfile` → typecheck → 539-test suite → certify:generate → lockstep → certify:verify → secret scan → audit) regenerates and lockstep-checks the report on every push, so the frozen state is continuously re-proven.
- **No code changes in this stop point** — README and this report are the only diffs; the certification evidence (662 rows) is unchanged from the SP10-approved baseline, and both passes (baseline and final-tree) produced identical artifacts.
- **Chain of custody** — every stop point's report is committed in `docs/`; the full commit chain (fast-forward only, THEFSTS identity on every commit) is the custody record.
- **No Stop Point 12** — this report is the last deliverable; after owner acceptance the sandbox is finished.

---

## 8. Publication and final CI run (certification of record)

Published fast-forward only (`git push origin sp9:main`, fast-forward verified with `git merge-base --is-ancestor`) as THEFSTS <amorebey@gmail.com>, both stop-point commits in one push. The authoritative **SP11 final-head certification run is the Actions run on the final head of this push** — the SP11-report commit — executing the full gate sequence (install --frozen-lockfile, typecheck, the 539-test suite, certify:generate + lockstep + certify:verify, secret scan). A committed report cannot contain its own push's run ID (the SP10 sequence in §1 demonstrates this inherent limit: its final commit records the prior head's run, and the final-head run 34379870530 was verified after the push), so the SP11 final-head run ID and its green verification are recorded with the delivery of this report to the owner, alongside the reconciled SP10 record: 34379870530 (authoritative SP10 final head 9c3060f) vs 34379711903 (correction-tree 6740a00) vs 34373623708 (original publication e7e5832).

## 9. Owner acceptance

The sandbox is presented for owner acceptance at the final head of this push. The certified state stands at 662/662/0/0 across 36 lanes and 21 categories; the acceptance matrix (§4) grounds every stop point in committed certification rows; the gap register (§5) dispositioned every gap since SP1; the README is the owner-facing front door; and the freeze (§7) holds. **No Stop Point 12 will follow: after owner acceptance of this report, the sandbox is finished.**
