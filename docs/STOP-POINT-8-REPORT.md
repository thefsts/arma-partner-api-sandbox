# STOP POINT 8 REPORT — SYNTHETIC PARTNER SIMULATORS + FAILURE-MODE HARNESS

**Status: PUBLISHED / CERTIFIED — STOPPING FOR OWNER APPROVAL.**
Per the standing directive, Stop Point 9 (OpenAPI contracts for both partner surfaces) has NOT been begun. The SP9 proposal is reproduced in §10 (authored from the SP1 roadmap language; awaiting owner approval). This report is the deliverable for owner review.

---

## 1. Publication record

- **Repository:** `thefsts/arma-partner-api-sandbox` (public sandbox), branch `main`
- **Final remote HEAD SHA (SP8 close):** this report, including its closing note, is the last commit of Stop Point 8 — the authoritative close SHA is `git rev-parse origin/main` at owner review. The full SP8 commit chain is listed below; no work follows this file.
- **Baseline before this stop point:** `4de64e4e85b700555841480c0345bc61cfc1c4a0` (SP7 approved close: feature `e39b507` + report `4de64e4`, certified GREEN CI run `34255886468`, 412/412 tests)
- **Baseline preservation:** the SP7 tree was checked before any edit; all 412 baseline tests stayed green through every phase and are unchanged in this stop point — the 3 modified files (`README.md`, `package.json`, `tsconfig.json`) are additive wiring only (new lane script, new test glob, new include), zero deletions of baseline content
- **Pushes:** fast-forward only (`4de64e4..54e498e`, then the report commit), no force push, no history rewrite — PUBLICATION RULE honored
- **Commits added this stop point:**
  - `54e498e` — `feat: stop point 8 — synthetic partner simulators + failure-mode harness` (full SHA `54e498e426a18fcb5a7d8a717eb490cda7aa1aaa`; CI run `34300027696`, completed/success) — 15 files changed, 4293 insertions(+), 7 deletions(-)
  - report commits (this file) — CI runs recorded additively in the repo Actions history; per the SP6/SP7 close-out precedent the report does not embed its own run ID — the authoritative close state is `git rev-parse origin/main` at owner review
  - **Author and committer on every SP8 commit:** `THEFSTS <amorebey@gmail.com>` (verified via `git show --format`)
- **Files in the feature commit:**
  - Added: `simulators/behaviors.ts` (420), `simulators/partnerSimulator.ts` (441), `simulators/syntheticPlatform.ts` (984), `simulators/failureModes.ts` (543), `simulators/contractRunner.ts` (565), `simulators/evidence.ts` (238), `simulators/index.ts` (17)
  - Added: `simulators/tests/helpers.mjs` (61), `simulators.happy-path.test.mjs` (151), `simulators.config-driven.test.mjs` (230), `simulators.failure-modes.test.mjs` (258), `simulators.contract-runner.test.mjs` (359)
  - Modified: `README.md` (SP8 section, 465-test totals, simulators lane description, SP9 pointer), `package.json` (test:simulators script + simulators glob in test), `tsconfig.json` (include `simulators/**/*.ts`)

## 2. CI evidence

- **Feature-commit CI run ID:** `34300027696` — workflow "CI" on commit `54e498e`
- **CI URL:** https://github.com/thefsts/arma-partner-api-sandbox/actions/runs/34300027696
- **Conclusion:** `completed / success`
- **Job:** `verify` (all steps success, 21s), started `2026-09-09T01:38:45Z`, updated `2026-09-09T01:39:06Z` — steps: checkout, pnpm setup, Node 24 setup, Install (`pnpm install --frozen-lockfile`), **Typecheck (`pnpm typecheck`) GREEN**, **Tests (synthetic only) (`pnpm test`, all 465) GREEN**, **Secret scan GREEN (no match)**, post steps
- **Report-commit CI runs:** recorded additively in the repo Actions history; per the SP6/SP7 close-out precedent the report does not embed its own run ID — the authoritative close state is `git rev-parse origin/main` at owner review
- Local gate reruns before every push (same commands CI runs): `pnpm typecheck` exit 0; `pnpm test` 465/465 (log: `tests 465 / pass 465 / fail 0 / EXIT:0`); CI-pattern `git grep` secret scan over HEAD and the working tree — no match

## 3. Exact local test totals (same commands CI runs)

- `pnpm typecheck` — exit 0 (strict, no emit; law-shield schema files + patches/lib + patches/arma + ai-governance + shared + simulators)
- `pnpm test` — 465/465 GREEN, EXIT:0 — 71 law-shield tests + 78 patches tests (30 partner API v1 contract + 48 ARMA PATCHES adapter) + 56 ai-governance tests + 207 shared tests + 53 simulator tests
- `pnpm test:lawshield` — 71/71
- `pnpm test:patches` — 78/78 (partner API v1 contract 30 + ARMA PATCHES adapter 48)
- `pnpm test:aigov` — 56/56
- `pnpm test:shared` — 207/207
- `pnpm test:simulators` — 53/53
- Contract matrix (in-process, part of the 53): 3 simulators × 40 failure modes + 3 control scenarios = 123 scenarios, all 123 PASS (tallies: CONTROL 3, SIGNATURE 15, AUTHORIZATION 24, ENTITLEMENT 21, RECEIPT 12, REPLAY 9, WEBHOOK 15, RETRY 12, RECONCILIATION 6, CIRCUIT_BREAKER 3, KILL_SWITCH 3)

## 4. Simulator harness design (what shipped)

`simulators/` is the contract test harness per the owner-approved SP8 scope: synthetic partner simulators built on the shared SDK, a configuration-driven failure-mode harness, and one contract runner driving every simulator × failure-mode combination. It contains **no** private ARMA, Law Shield, or PATCHES implementation, **no** credentials or prompts, and **no** production data. Every surfaced surface is metadata-only: identifiers, reason codes, and counts — never payload content, never envelope bodies. Everything fails closed on untrusted responses and broken harness components alike.

- **`simulators/behaviors.ts`** — the data layer. Three synthetic simulator identities (`sim-well-behaved`, `sim-alternate-entitlement`, `sim-alternate-capability`) resolved through the SP7 registry as pure data (partner/org/binding/entitlement/capability records — registry data, not code); the three synthetic sandbox secrets (`synthetic-sim-signing-secret-SP8-sandbox`, `synthetic-sim-receipt-secret-SP8-sandbox`, `synthetic-sim-webhook-secret-SP8-sandbox`, plus `synthetic-sim-wrong-secret-SP8-sandbox` for the wrong-secret mode — synthetic by name and value); the injected scenario clock (`makeScenarioClock`, deterministic start `SCENARIO_CLOCK_START_MS = 1_800_000_000_000`); the `ScenarioConfig` fault-plan vocabulary (authorization flips, partner/platform fault plans, receipt faults NONE/OMIT/FORGED/TAMPERED/WRONG_OPERATION, downstream behavior HEALTHY/UNAVAILABLE/FAILS_ONCE_THEN_HEALTHY, circuit plan, transport script steps, receiver faults, delivery plan, kill switch); and `wellBehavedScenario(identity)` — the pure happy-path seed every failure mode is derived from. `syntheticPayloadFor(scenarioKey)` generates the per-scenario synthetic payload marker `sp8-${scenarioKey}` used by the forbidden-material sweep.
- **`simulators/partnerSimulator.ts`** — a simulated partner client built ON the shared SDK: signs requests with the canonical 5-field scheme, verifies platform receipts over raw bytes, collapses duplicates through SDK idempotency, computes retry plans per attempt index (`planRetryFor(code, attempt)`), records transport calls, and fails closed on every untrusted response. Configuration-driven only — one engine runs every identity and every fault plan with zero partner-specific branching.
- **`simulators/syntheticPlatform.ts`** — the in-process partner platform: registry-resolved authorization (fail-closed typed codes), signature/timestamp/nonce/replay verification, receipt issuance and faulted receipts (omitted/forged/tampered/wrong-operation), idempotency and conflict presentation, transport scripting (ok/clean-retryable/ambiguous/timeout), downstream availability gating, circuit-breaker state transitions, webhook event emission and ordered delivery with receiver faults (re-presented deliveries, tampered bodies, ordering gaps), dead-lettering, reconciliation, and kill switches — every phase driven by the scenario's fault plan, observed through metadata-only views.
- **`simulators/failureModes.ts`** — the deterministic failure-mode harness: 40 failure modes across 10 categories (SIGNATURE 5, REPLAY 3, RECEIPT 4, AUTHORIZATION 8, ENTITLEMENT 7, WEBHOOK 5, RETRY 4, RECONCILIATION 2, CIRCUIT_BREAKER 1, KILL_SWITCH 1), each declared as a PURE injector `wellBehavedScenario(identity) → faulted ScenarioConfig` with its category, evidence surface, expected contract code, fail-closed flag, and requirement string. Modes are data transformations — the engines apply them mechanically; there is no mode-specific code path in either engine.
- **`simulators/contractRunner.ts`** — the contract test harness: `runContractMatrix()` drives every simulator × failure-mode combination (3 simulators × 40 modes + 3 control scenarios = 123 scenarios, all PASS) against the shared contracts, with contract checks per scenario (expected-code-observed, fail-closed discipline, retry-plan correctness, receipt-reason surfaced, delivery/dead-letter/attempt counts, circuit states, event emission, span status, reconciliation status) and defense-in-depth: a broken mode (`inject: () => null` surfaces the engine's typed `PLATFORM_SCENARIO_REQUIRED`) or a throwing injector (untyped prose collapses to `RUNNER_ERROR` under the typed-code pattern `^[A-Z][A-Z0-9_]{3,63}$`) fails closed as a FAIL row — never a crash, never a silent skip; the `inject()` call itself is wrapped. Single-scenario APIs (`runControlScenario`, `runFailureModeScenario`) and option narrowing (`simulators`, `modes`, `includeControl`) let the SP10 reporter drive exact slices.
- **`simulators/evidence.ts`** — metadata-only scenario evidence: 20 allowlisted SAFE_EVIDENCE_KEYS, frozen records, bounded strings/lists, no payload content; `certificationRowFor` maps each record to the SP10 certification shape `{testId, category, requirement, result, reasonCode}` — PASS rows carry the expected code, FAIL rows carry the observed code.
- **`simulators/index.ts`** — the public barrel; nothing else in the sandbox imports the internals directly.

### Fail-closed discipline (the contract the runner certifies)

Fail-closed behavior is keyed on scenario DATA, never on category labels: attack-presentation modes (detected from `partnerFaults.replayPresentation || idempotencyConflictPresentation || delivery.receiverFaults?.rePresentSameDelivery || tamperBody` flags in the faulted scenario) must refuse the ATTACK presentation itself (second presentation refused with a typed code, or RECEIVER-surface typed code in `rePresentedCode` (replay) / `receiver.code` (tamperBody), never OK); non-attack fail-closed modes never produce a trusted success on their declared surface (PLATFORM_RESPONSE/RECEIPT/PLAN/CIRCUIT: no processed OK; DELIVERY/EMIT: never DELIVERED; SPAN: never SUCCESS; RECEIVER non-attack, e.g. ordering gap: `receiver.verified === false`); fail-open modes (recovery modes: duplicate-collapse, clean-retry, resolve) observe recovery as expected. Verified as a data-keyed 40/40 sweep in the test lane (probe before test-wiring: 40/40).

## 5. Required test matrix — results by category (all 53 GREEN)

**Happy path (7):** full SP7 chain through the shared SDK for `sim-well-behaved` — registry resolve → version negotiate → signed request → platform verify → receipt verify → idempotency → webhook event → delivery → receiver verification → telemetry span → audit; all three identities complete the chain (alternate-entitlement and alternate-capability both OPERATION_COMPLETED); signature stage signing the synthetic payload exactly as provided; duplicate collapse with the event gate never re-opening; rejected requests emit nothing; byte-for-byte determinism across two full runs; synthetic secrets pattern asserted — **all PASS**

**Configuration-driven (24):** authorization flips, client faults, and platform faults flipped as data across all three identities — AUTHORIZATION_FLIPS / CLIENT_FAULT_FLIPS / PLATFORM_FAULT_FLIPS fixture tables drive the same engines; one flip flips every identity (the fault vocabulary is data, not per-partner code); fixture purity (flip fixtures mutate no shared state) — **all PASS**

**Failure modes (10):** catalog integrity (40 modes, 10 categories, unique IDs, pure injectors — `inject(wellBehavedScenario(X))` twice yields identical configs, mutation-free); category counts (Map) matching the spec table; the every-mode-observes-expected-code sweep across all 3 identities (retry plans computed at each presentation's attempt index — EXHAUSTED only exists at the schedule bound, attempt 5); the data-keyed fail-closed discipline sweep (40 modes × surface switch: attack presentations refused, non-attack fail-closed never trusted-success on the declared surface, fail-open recovery modes observed); multi-presentation counts (retry-clean-retryable 2, circuit-threshold-trip-open 4, retry-exhaustion-schedule-bound 5) — **all PASS**

**Contract runner (12):** matrix 123/123 all-PASS with exact tallies (123 scenarios = 3 control + 3×40); contract checks per scenario (multi-presentation set computed by injector projection); control evidence full-chain per simulator; frozen 20-key metadata-only evidence with the forbidden-material sweep (`['syntheticRequest', ...Object.values(SYNTHETIC_SIMULATOR_SECRETS)]` never in any serialized record); certification rows in the SP10 shape; tallies (11 categories, CONTROL 3/3, SIGNATURE 15, AUTHORIZATION 24, sum = scenarioCount); spot checks (clean-retry `[DU, OK]` + CLEAN_RETRY; circuit `[DU,DU,CO,CO]` + OPEN; exhaustion 5×DU + EXHAUSTED; kill-switch FAILED/0 events; delivery-exhaustion deadLettered/attempts>1/AMBIGUOUS/PENDING; reconcile RESOLVED/REQUIRED_UNRESOLVED; duplicate-collapse fail-open; ambiguous AMBIGUOUS_RECONCILE + RECEIPT_MISSING_HEADERS); single-scenario APIs; determinism (`stripForDeterminism` JSON compare); fail-closed runner paths (broken mode → `PLATFORM_SCENARIO_REQUIRED` FAIL row with `runner-fail-closed` check; exploding injector → `RUNNER_ERROR` with no prose in the serialized record) — **all PASS**

## 6. Defects found and fixed by the test discipline (found before publication — none shipped)

The tests were written against the real module APIs (verified from source before every assertion), and the discipline caught real defects during the build, all fixed and re-verified green before the feature commit:

1. **Event-gate re-open on re-presentation** — the platform's event gate could re-open after a re-presented delivery, letting a replay attack push a second event; fixed by holding the gate closed once the delivery phase ends for the scenario (duplicate-collapse test proves the event gate never re-opens).
2. **No record on availability failure** — the platform failed to record the transport call when downstream was UNAVAILABLE, so attempt counts underreported; fixed by recording every transport call (delivery-exhaustion spot check asserts `attempts>1`).
3. **Transport-counter aggregation semantics** — the simulator's transport counter is cumulative per instance, so the runner initially summed per-presentation observations and double-counted multi-presentation scenarios; fixed to take the latest observation via `Math.max` (the cumulative counter's latest value IS the scenario total — never a sum, never below the observed calls).
4. **Throwing injector crashed the matrix (caught by the fail-closed runner test)** — `mode.inject()` ran outside the runner's fail-closed wrap, so a throwing injector crashed the whole matrix instead of failing closed as one FAIL row; fixed by wrapping the `inject()` call — a broken mode now surfaces the engine's typed code (`PLATFORM_SCENARIO_REQUIRED`) and a throwing injector collapses to `RUNNER_ERROR` — never a crash, never a silent skip.
5. **15 typecheck errors in Phase 1 sources (caught by wiring `simulators/**/*.ts` into `tsconfig.json`)** — the Phase 1 modules had never been strict-typechecked: duplicate `export type` blocks (2 files), readonly-receiver mutation (TS2540), `safeContext.errorCode` unguarded (TS2322), `transportCalls` push-on-readonly (TS2339), `modesByCategory` map accumulation (TS2345), `ScenarioEvidence` literal-union fields fed by a plain-string helper (TS2322 — fixed with a generic `evidenceString<T extends string>` returning what it was given), and a mid-refactor record literal close (TS2322). All 15 fixed with zero runtime-behavior change (receiver assignment order preserved: `verified`/`code` computed before the tamper fault pushes into `receiverCodes`), re-verified: typecheck 0 errors + full suite 465/465.
6. **`.mjs` tests cannot carry TS cast syntax** — the `.mjs` test lane cannot use `as never` (Node 24 type-stripping applies to `.ts` only); the malformed multi-presentation check was rewritten against the real module API (injector projection, no casts).

Also hardened during the build: import-path convention (`'../failureModes.ts'` from `simulators/tests/`, matching `shared/tests/`), `FailureModeCategory`/`EVIDENCE_SURFACES` imported from `behaviors.ts` where they live, and em-dash literal (not `\u2014` escape) discipline in test comments.

## 7. Sanitization statement

- Synthetic data only: every identifier is synthetic (`sim-well-behaved`, `sim-alternate-entitlement`, `sim-alternate-capability`, `sp8-${scenarioKey}` payloads), every clock is the injected scenario clock (deterministic start `SCENARIO_CLOCK_START_MS`), and every fixture is a synthetic partner/org/binding/entitlement/capability record.
- The only secrets in the lane are the four declared synthetic sandbox values in `simulators/behaviors.ts` (`synthetic-sim-signing-secret-SP8-sandbox`, `synthetic-sim-receipt-secret-SP8-sandbox`, `synthetic-sim-webhook-secret-SP8-sandbox`, `synthetic-sim-wrong-secret-SP8-sandbox`) — synthetic by name and value, never a real credential; production porting swaps them for the secret store (see §9).
- No private ARMA, Law Shield, or PATCHES implementation, algorithm, prompt, or key appears anywhere in `simulators/`: the modules are the harness and the failure-mode catalog, and the engines apply the SP7 contracts mechanically — no partner-specific logic anywhere.
- No payload content crosses any observability surface: the contract-runner test asserts, on every serialized evidence record, that neither the synthetic request payload marker nor any synthetic secret value appears (frozen 20-key metadata-only records).
- No real network: every exchange is in-process (simulator client → synthetic platform → receiver), every transport is an injected function, every clock is injected.
- No Alert ARMA UI, no Domus UI, no direct database access.
- Secret scan: CI-pattern `git grep` over HEAD and the working tree — no match; the personal-identity scan (email/name) over the new tree — no match (the only `amorebey@gmail.com` occurrences are the git author/committer identity on commits, which is the approved publication convention).

## 8. Remaining harness gaps (private-repo / production-only — not expanded here)

1. **Durable persistence** — the platform is in-memory reference (registry, nonce/idempotency guards, delivery attempt history, circuit state); the Convex port is private-repo work.
2. **Production secrets** — signing/receipt/webhook secrets come from the secret store; the sandbox values are declared synthetic.
3. **Real transport** — the transport script steps are an injected function; real HTTP delivery (endpoints, TLS, mTLS where required) is production work.
4. **Real partner records** — the registry is data-only by design; production record management lives in the private repos.
5. **Coverage breadth beyond the shared contracts** — the catalog covers the 40 directed failure modes on the 10 shared-contract categories; partner-specific quirks (e.g. PATCHES activation flow faults) belong to each partner's own lane, not the shared harness.
6. **SP10 reporter UI** — the certification rows are produced in the SP10 shape (`{testId, category, requirement, result, reasonCode}`); the reporter that aggregates them is Stop Point 10 work.

## 9. Private-repo porting notes

- `simulators/behaviors.ts` — the identity/record/secret fixtures are data; production porting replaces the synthetic secrets with secret-store values and maps the synthetic records onto real partner records (the fault-plan vocabulary is the portable contract).
- `simulators/partnerSimulator.ts` — the engine is configuration-driven; porting to a new partner means writing records + fault plans, never engine code — that is the directive.
- `simulators/syntheticPlatform.ts` — the platform engine applies fault plans mechanically; private-repo porting wires the transport to real HTTP and the registries to durable tables, keeping the phase/observation model intact.
- `simulators/failureModes.ts` — the 40-mode catalog is data; production adds modes as new injectors (pure functions over `wellBehavedScenario`), never as engine code paths.
- `simulators/contractRunner.ts` — the runner and its fail-closed wrapper are the certification driver; the SP10 reporter consumes `runContractMatrix().rows` directly or via the single-scenario APIs.
- `simulators/evidence.ts` — the 20-key allowlist is the contract for any downstream consumer; keep the allowlist and forbidden-material sweep when adding fields.
- `simulators/tests/` — the 53-test matrix is the certification suite for the port: same assertions, synthetic secrets replaced by test-store values in the bootstrap only.

## 10. Stop Point 9 proposal — OPENAPI CONTRACTS (PROPOSAL ONLY — not begun)

Per the standing directive, the following is the proposal for Stop Point 9, authored from the SP1 roadmap scope (`docs/STOP-POINT-1-BASELINE.md`: "No OpenAPI contracts — Stop Point 9 scope"; file lines: `openapi/patches-partner-v1.yaml (Stop Point 9)`, `law-shield/openapi/arma-lawshield-v1.yaml (Stop Point 9)`). No work has begun; this section exists for owner approval only.

> STOP POINT 9 — OPENAPI CONTRACTS
> ====
> With the shared platform (SP7) certified and the simulators + failure-mode harness (SP8) published, publish the OpenAPI contracts for both partner surfaces so every integration has a machine-checkable statement of the wire format.
>
> BUILD:
>
> A. PATCHES PARTNER API V1 (`openapi/patches-partner-v1.yaml`)
>
> - the v1 contract surface exactly as implemented and tested in SP4/SP5 (the 30-test contract matrix): scoped partner auth, HMAC request signing (the SP7 canonical 5-field form over the PATCHES header names), nonce replay guard, credential rotation with grace windows, tenant isolation, entitlement/capability gates, activation idempotency, receipts, audit, rate limiting, downstream failure codes, kill switch
> - every route, header, schema, error code, and receipt shape from the reference server, in one machine-checkable document
> - validated against the live reference server in CI (schema-conformance smoke tests)
>
> B. ARMA LAW SHIELD API V1 (`law-shield/openapi/arma-lawshield-v1.yaml`)
>
> - the Law Shield inbound contract surface exactly as implemented and tested in SP1-SP5 (the 71-test law-shield matrix): the v1 receipt format, durable inbound processing (nonce registry, idempotency registry, org/case mapping, disclosure policy enforcement), status/reconciliation routes, signature verification
> - every route, header, schema, error code, and receipt shape from the gateway/processor, in one machine-checkable document
> - validated against the live gateway/processor in CI (schema-conformance smoke tests)
>
> C. CONTRACT-TEST CROSS-CHECK
>
> - a small contract-test lane asserting the OpenAPI documents stay in lockstep with the reference implementations (every route/operation present, every error code represented, no undocumented surface)
> - docs published with the repo (static rendering of both specs, no external service)
>
> STOP FOR OWNER REVIEW.

---

**STOP.** Stop Point 8 is published and certified: feature commit `54e498e426a18fcb5a7d8a717eb490cda7aa1aaa` (CI run `34300027696`, GREEN) plus this report chain, 465/465 tests (71 law-shield + 78 patches (30 contract + 48 adapter) + 56 ai-governance + 207 shared + 53 simulators), typecheck GREEN, secret scan clean on the final tree, fast-forward publication only, all 412 SP7-baseline tests preserved green throughout. The final remote HEAD is the last SP8 commit on `main` — `git rev-parse origin/main` at owner review gives the authoritative close SHA. Awaiting owner decision on the Stop Point 9 proposal above. No further work will begin without explicit approval.
