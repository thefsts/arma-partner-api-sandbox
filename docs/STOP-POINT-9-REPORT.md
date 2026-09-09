# STOP POINT 9 REPORT — OPENAPI CONTRACTS

**Status: PUBLISHED / CERTIFIED — STOPPING FOR OWNER APPROVAL.**
Per the standing directive, Stop Point 10 (certification reporting) has NOT been begun. The SP10 proposal is reproduced in §10 (authored from the SP1 roadmap language and the SP8 report's proposal precedent; awaiting owner approval). This report is the deliverable for owner review.

---

## 1. Publication record

- **Repository:** `thefsts/arma-partner-api-sandbox` (public sandbox), branch `main`
- **Baseline before this stop point:** `465a3ae42587624749984aa1db7f67f639963761` (SP8 approved close: feature `54e498e` + report `465a3ae`, certified GREEN CI run `34300027696`, 465/465 tests)
- **Baseline preservation:** the SP8 tree was checked before any edit; all 465 baseline tests stayed green through every phase and are unchanged in this stop point — the 3 modified files (`README.md`, `package.json`, `pnpm-lock.yaml`) are additive wiring only (new SP9 section and totals, new openapi test glob + `test:openapi`/`render:openapi-docs` scripts, `yaml` devDependency added), zero deletions of baseline content
- **Pushes:** fast-forward only (`465a3ae..` then the report commit), no force push, no history rewrite — PUBLICATION RULE honored
- **Commits added this stop point:**
  - feature commit — `feat: stop point 9 — OpenAPI contracts for both partner surfaces` — 13 files changed (8 added, 3 modified, 0 deleted): added `openapi/patches-partner-v1.yaml` (2182), `law-shield/openapi/arma-lawshield-v1.yaml` (1476), `openapi/tests/helpers.mjs` (175), `openapi/tests/spec.structure.test.mjs` (259), `openapi/tests/spec.crosscheck.test.mjs` (306), `openapi/tests/spec.live-conformance.test.mjs` (597), `scripts/render-openapi-docs.mjs` (423), `docs/openapi/patches-partner-v1.html` + `docs/openapi/arma-lawshield-v1.html` + `docs/openapi/index.html` (static rendered docs); modified `README.md` (SP9 section + 473-test totals), `package.json` (openapi glob + 2 scripts), `pnpm-lock.yaml` (`yaml` ^2.9.0 devDependency)
  - report commits (this file) — CI runs recorded additively in the repo Actions history; per the SP6/SP7/SP8 close-out precedent the report does not embed its own run ID — the authoritative close state is `git rev-parse origin/main` at owner review
  - **Author and committer on every SP9 commit:** `THEFSTS <amorebey@gmail.com>` (verified via `git show --format`)
- **Verification of authorship before push:** `git show --no-patch --format='%an <%ae> | %cn <%ce>'` on every commit — THEFSTS identity only, no other identity ever applied

## 2. CI evidence

- **Feature-commit CI run:** workflow "CI" on the SP9 feature commit; conclusion and run ID recorded additively in the repo Actions history at owner review
- Local gate reruns before every push (same commands CI runs): `pnpm typecheck` exit 0; `pnpm install --frozen-lockfile` exit 0; `pnpm test` 473/473 (71 law-shield + 78 patches (30 contract + 48 adapter) + 56 ai-governance + 207 shared + 53 simulators + 8 openapi); CI-pattern `git grep` secret scan over HEAD and the working tree — no match; personal-identity/host scan over the new tree (emails, non-example URLs, IPs) — no match
- **Rendered docs verified in a real browser before publication:** both contract pages and the index load and render correctly from a local static HTTP server (no external service, no JS, no external assets)

## 3. Exact local test totals (same commands CI runs)

- `pnpm typecheck` — exit 0 (strict, no emit; law-shield schema files + patches/lib + patches/arma + ai-governance + shared + simulators)
- `pnpm test` — 473/473 GREEN, EXIT:0 — 71 law-shield tests + 78 patches tests (30 partner API v1 contract + 48 ARMA PATCHES adapter) + 56 ai-governance tests + 207 shared tests + 53 simulator tests + 8 openapi tests
- `pnpm test:lawshield` — 71/71
- `pnpm test:patches` — 78/78 (partner API v1 contract 30 + ARMA PATCHES adapter 48)
- `pnpm test:aigov` — 56/56
- `pnpm test:shared` — 207/207
- `pnpm test:simulators` — 53/53
- `pnpm test:openapi` — 8/8 (structure 2 + cross-check 3 + live conformance 3)
- `pnpm render:openapi-docs` — exit 0, 2/2 specs rendered (+ index), self-contained HTML, no network

## 3a. OpenAPI contract lane — the three layers

**Structure (2):** both YAML documents parse as valid OpenAPI 3.1 documents (openapi version, info, servers, paths, components) with resolvable `$ref`s, fully described operations, and response examples — `openapi/patches-partner-v1.yaml` 0 errors / 0 warnings; `law-shield/openapi/arma-lawshield-v1.yaml` 0 errors / 7 intentional warnings (documented per-spec: warning-tolerant fields carried for tool compatibility).

**Cross-check (3):** (a) every route implemented by the reference servers is documented in the spec, and every documented route is implemented (PATCHES 9/9, Law Shield 4/4, including the `POST /process` OR `/` dual-mount and GET-only readiness); (b) every wire error code emitted by the reference implementations appears in the spec's error vocabulary — two-gate token trace (Gate A: source → spec, Gate B: spec → source) with the audit-detail codes ghost-checked per the SP8 precedent; (c) the specs document every implemented security scheme and header contract (the five PATCHES signing headers, the five `x-arma-*` headers, the four `X-LawShield-*` receipt headers, the processor Bearer scheme) — nothing invented, nothing omitted.

**Live conformance (3):** the specs are validated against the live reference servers booted in-process (the repo's real servers, not mocks): the PATCHES reference server driven through every documented operation family (health, capabilities, tenant-scoped entitlements, idempotent activation create → receipt, activation status, deactivate/revoke lifecycle, events, audit, the 400/403/409/413 error families, the version policy 400 `UNSUPPORTED_API_VERSION` for any non-v1 segment) with status codes, receipt headers, and error bodies asserted against the spec schemas; and the Law Shield gateway + durable processor + readiness servers driven end-to-end (signed transfer → 15-field signed receipt with the four `X-LawShield-*` headers, replay rejection 409, tampered-body rejection 401 `BODY_HASH_MISMATCH`, missing-header 401 `MISSING_SECURITY_HEADERS`, invalid signature 401, readiness probe 200, direct processor `POST /process` accept + `GET /status` status/audit response) with every response body schema-conformant to the spec.

## 4. What shipped

`openapi/` and `law-shield/openapi/` publish the machine-readable OpenAPI 3.1 contracts for both partner-facing surfaces, written from the reference implementations and tests as the authoritative source: every operationId, route, method, parameter, header, request/response schema, error code, security scheme, idempotency rule, and receipt shape from the SP1–SP8 reference code, in two machine-checkable documents. Internal-only routes and private details are documented out (test fixtures, fail-point injection, private deployment details, ops-level internals). The contract lane keeps the documents in lockstep with the implementations in CI; the rendered docs publish the contracts as static in-repo HTML with no external rendering service.

- **`openapi/patches-partner-v1.yaml`** — PATCHES Partner API v1, the complete implemented v1 surface (9 operations under `/api/partner/v1`). Scope: health, capabilities, entitlements, activations create/status, deactivate, revoke, events, audit — the exact SP4/SP5-tested surface. Security: the `PatchesSignedRequest` HMAC-SHA256 scheme (type apiKey, in header, 5 named headers) + `PatchesBearerCredential` Bearer scheme, with the cumulative-security prose (signature verification is the first gate only; org ownership, entitlement windows, capability registration, device/subject binding, tenant scoping, and rate limiting after auth are all enforced and documented). Idempotency: nonce single-use registered in the same transaction as the outcome, activation idempotency-key semantics with conflict presentation (409 `IDEMPOTENCY_CONFLICT`), deactivate idempotent by status. Version policy: only `v1`; any other version segment fails closed with 400 `UNSUPPORTED_API_VERSION` (documented in info.description prose, the exact implemented behavior). Receipts: the receipt schema with header contracts. Error families: 2 shape families covering the full vocabulary (24 error schemas) with the fail-closed responses (kill switch 503, downstream 502/503, persistence 500) — every code from the implementation's wire map.
- **`law-shield/openapi/arma-lawshield-v1.yaml`** — ARMA Law Shield API v1, the complete implemented v1 surface (4 operations). Scope: the inbound gateway `POST /api/lawshield/arma`, the readiness probe `GET /api/lawshield/integration-readiness`, and the durable processor's service-to-service routes `POST /process` / `GET /status`. Security: `ArmaSignedTransfer` (HMAC-SHA256 over the 4-field canonical string, 5 `x-arma-*` headers) and `LawShieldProcessorBearer` (Bearer auth on /process + /status), both documented as cumulative with the other checks. Wire details: the verification order, the replay guard, the processor forwarding contract (5 forwarded headers), the 15-field signed receipt with its 4 `X-LawShield-*` receipt headers, the processor-mismatch 502s (`PROCESSOR_REJECTED_TRANSFER`, `PROCESSOR_RECEIPT_MISMATCH` with `reconciliationRequired: true`), the 6-field accepted wire shape, the rejected wire shape (business rejections return HTTP 200 with `accepted: false`), idempotency semantics (same key + same content → the same deterministic receipt), and the status/reconciliation response with audit metadata — every route, header, schema, and error shape from the gateway/processor source, in one machine-checkable document.
- **`openapi/tests/helpers.mjs`** — the lane's test helpers: YAML loading (`yaml` package, in the spec's own dependency tree), `$ref` resolution against the components tree, and a mini JSON-Schema conformance checker (type string-or-array, required, properties, enum, const, pattern, format date-time, items, minItems, additionalProperties:false, minProperties, oneOf exactly-one, allOf, minimum/maximum, $ref) used by the structure and live-conformance layers.
- **`openapi/tests/spec.structure.test.mjs`** — the structure layer (2 tests, one per spec): validates both documents as OpenAPI 3.1 with resolvable refs, fully described operations, response examples, and described security schemes.
- **`openapi/tests/spec.crosscheck.test.mjs`** — the implementation↔spec cross-check layer (3 tests): routes both ways (implemented ↔ documented, with the POST /process OR / dual-mount case), the two-gate error-code token trace (every wire code in the spec; every spec token traces to source; audit-detail codes ghost-checked), and the route/security-scheme/header completeness check.
- **`openapi/tests/spec.live-conformance.test.mjs`** — the live reference-server conformance layer (3 tests): boots the real PATCHES partner-API server and the real Law Shield gateway + durable processor + readiness servers in-process, drives every documented operation over the wire, and asserts status codes, receipt headers, and response bodies against the spec schemas (including the version-policy 400, the idempotency-conflict 409, the error families, and the Law Shield signed-transfer → receipt chain with its four receipt headers, replay/tamper/missing-header/invalid-signature rejections, readiness, and direct processor process/status).
- **`scripts/render-openapi-docs.mjs`** — the static docs renderer: reads both YAML documents, emits self-contained HTML (inline CSS, no JS, no external assets, no network at render or view time) to `docs/openapi/`, and fails closed (exit 1) if either render fails. Emits both contract pages and an index page linking them.
- **`docs/openapi/`** — the rendered static docs: `patches-partner-v1.html` (186 KiB), `arma-lawshield-v1.html` (80 KiB), and `index.html`. The pages are committed so partners can read the contract without running anything; the renderer regenerates them from the YAML source whenever the specs change (`pnpm render:openapi-docs`). No external rendering service, per the owner directive.
- **`package.json`** — additive wiring: the openapi glob added to `test`, plus `test:openapi` and `render:openapi-docs` scripts. `pnpm-lock.yaml` — the `yaml` ^2.9.0 devDependency (the only new dependency; zero runtime dependencies unchanged).

## 5. Required test matrix — results by category (all 8 GREEN)

**Structure (2):** PATCHES spec validates as OpenAPI 3.1 (0 errors / 0 warnings) — PASS; Law Shield spec validates (0 errors / 7 intentional warnings, each documented) — PASS

**Cross-check (3):** PATCHES error-code two-gate trace (Gate A 64 wire codes → spec; Gate B 46 spec tokens → source; audit-detail codes exempted with the ghost check) — PASS; Law Shield error-code two-gate trace (Gate A 75 wire codes → spec; Gate B 74 spec tokens → source) — PASS; route completeness both ways (PATCHES 9/9 routes, Law Shield 4/4 routes, dual-mount documented, readiness GET-only) — PASS

**Live conformance (3):** PATCHES lifecycle (health, discovery, entitlements, activation create → receipt → status → deactivate → revoke, events, audit) — PASS; PATCHES policy failures (403 family: AUTH/entitlement/capability/idempotency-conflict 409, 400 input errors, 413 payload-too-large, version-policy 400) — PASS; Law Shield end-to-end (signed transfer → 15-field receipt with 4 receipt headers, replay 409, tamper 401 BODY_HASH_MISMATCH, missing headers 401, invalid signature 401, readiness 200 ready, direct processor POST /process + GET /status with audit) — PASS

## 6. Defects found and fixed by the test discipline (found before publication — none shipped)

1. **Live conformance asserted a schema the implemented version-policy 400 does not carry** — the initial version-policy check tried to schema-check the v2-version 400 response against the v1 path's default (RouteNotFound404) shape; the implemented behavior (verified from source) is the prose-documented 400 `UNSUPPORTED_API_VERSION` body with `supported: ['v1']` and `requestId`, documented in info.description prose, not a per-path response schema. Fixed by asserting the implemented body directly (the spec documents it in prose — the spec is correct, the test assertion was wrong).
2. **The Law Shield live-conformance test booted the real durable processor against a wrapped payload the processor's disclosure policy rejects** — `buildEnvelope()` (the shared test harness fixture) wraps the payload in a stub-processor-compatible shape, but the real durable processor's `enforceDisclosurePolicy` requires the FLAT redactor output (per-recordType allow-lists on `envelope.payload`). The test now overrides the payload with `redactPayload('CASE_REFERRAL', …)` output (the real ARMA-side redaction module) + matching `payloadHash` — the same wire the ARMA-side transferService produces. Root cause: the fixture was designed for the stub processor, not the real one.
3. **Five latent assertion bugs found and fixed proactively (verified from source before they could fail the lane)** — (a) `/status` requires Bearer auth BEFORE criteria validation (401 PROCESSOR_AUTH_FAILED precedes 400 STATUS_LOOKUP_CRITERIA_REQUIRED) — the test helper now sends the Bearer header; (b) the readiness handler runs on a separate server (`startReadiness`), not the gateway — booted separately with the processor env for ready:true; (c) the receipt headers are the `x-lawshield-signature` family, not `x-lawshield-receipt-signature` — asserted the correct names; (d) the law-shield test harness returns plain-object lowercased headers, so `headers.get()` would crash — made the check object-safe; (e) the replay 409 carries the real `transferId` — asserted it.

Also hardened during the build: `jsond-placeholder`-style literal-escape discipline in edits (the em-dash must be a literal UTF-8 character, never a `\u2014` escape, matching the repo convention), and the static-renderer index page so the docs entry point is also generated (stays in sync with the renderer, never hand-edited).

## 7. Sanitization statement

- Synthetic data only: every identifier, payload, and example in both specs is synthetic (example values drawn from the test fixtures: `TRX-`/`RCP-`/`IDK-` prefixes, `org-arma-1`, `LS-CASE-1`, `INC-1001`, `ACT-`/`REQ-` prefixes, `.invalid` hostnames); every secret is a declared synthetic sandbox value from the baseline test harness; no real credential appears anywhere.
- No private ARMA, Law Shield, or PATCHES implementation detail beyond the already-published integration-facing contracts: the specs document the partner-visible wire only; internal-only routes, test fixtures, fail-point injection, private deployment details, and ops-level internals are documented out (per-spec header comments enumerate what is intentionally excluded and why).
- No payload content crosses any surfaced surface: the live-conformance tests assert metadata-only (status codes, header names, schema conformance) plus the synthetic example bodies the specs already publish; the synthetic-secrets/payload-marker forbidden-material discipline of the baseline lanes is unchanged.
- No real network at test time: every exchange is in-process over 127.0.0.1 with an injectable clock; the rendered docs are static files with zero JS, zero external assets, zero network.
- Secret scan: CI-pattern `git grep` over HEAD and the working tree — no match; the personal-identity/host scan (emails, non-example URLs, IPs) over the new tree — no match (the only `amorebey@gmail.com` occurrences are the git author/committer identity on commits, which is the approved publication convention).
- No Alert ARMA UI, no Domus UI, no direct database access.

## 8. Remaining gaps (private-repo / production-only — not expanded here)

1. **Redoc/Swagger UI rendering** — the rendered docs are a custom static renderer (self-contained HTML, no external service); richer interactive rendering (try-it-out, schema browsing) is a private-repo decision, not a sandbox need. The machine-readable YAML documents are the source of truth; any OpenAPI 3.1-compatible tool can render them.
2. **Live-conformance depth** — the conformance lane drives every documented operation family and every error family on the wire, but it does not drive every single error code (the cross-check layer covers the full vocabulary two ways instead). Deeper per-code live probes (e.g. kill-switch 503 under a toggled env, downstream 502/503 under a controlled fault) would duplicate the SP4/SP8 failure-mode matrices already green in their own lanes — they belong to those lanes, not the contract lane.
3. **Contract drift in the private repos** — the specs document the sandbox reference implementations; when the private repos diverge, the same three-layer discipline (structure + cross-check + live conformance) applies there with their own reference servers.
4. **PATCHES kill-switch/downstream live probes** — the fail-closed 503/502/500 responses are documented in the spec and schema-conformant to the implementation's wire shapes, but the live lane drives only the documented operation families' documented error codes (per SP9 scope: every route/operation present, every error code represented, no undocumented surface) — the behavioral matrices live in the SP4 contract lane (30 tests) and the SP8 failure-mode catalog.
5. **SP10 certification reporter** — the certification rows are produced in the SP10 shape (`{testId, category, requirement, result, reasonCode}`); the reporter that aggregates them is Stop Point 10 work (see §10).

## 9. Private-repo porting notes

- `openapi/patches-partner-v1.yaml` — the document is the portable contract; private-repo porting keeps it at the root `openapi/` path and re-points the live-conformance bootstrapping at the production reference server (same lane, same assertions).
- `law-shield/openapi/arma-lawshield-v1.yaml` — same: keep the document at `law-shield/openapi/`, port the lane with the production gateway/processor.
- `openapi/tests/` — the three-layer lane is the certification discipline for the port: same structure validation, same two-gate cross-check against the private reference sources, same live conformance against the private reference servers. The helpers (YAML loader, ref resolver, mini validator) are dependency-free besides the `yaml` package and are portable as-is.
- `scripts/render-openapi-docs.mjs` — portable as-is; production may swap the custom renderer for a richer one, but the no-external-service rule (owner directive) means any renderer must emit self-contained static files.
- `docs/openapi/` — re-render on every spec change; never hand-edit the HTML.
- `package.json`/`pnpm-lock.yaml` — the `yaml` devDependency is the only new dependency (dev-only, zero runtime impact); keep it in sync with the spec's YAML parsing needs.

## 10. Stop Point 10 proposal — CERTIFICATION REPORTING (PROPOSAL ONLY — not begun)

Per the standing directive, the following is the proposal for Stop Point 10, authored from the SP1 roadmap scope (`docs/STOP-POINT-1-BASELINE.md`: "No certification reporting — Stop Point 10 scope"; `certification/ PASS/FAIL/NOT-TESTED report generator (Stop Point 10)`) and the SP8 report's precedent (`simulators/evidence.ts` exports `CertificationRow` `{ testId, category, requirement, result, reasonCode }` with `certificationRowFor` and `notTestedRow`). No work has begun; this section exists for owner approval only.

> STOP POINT 10 — CERTIFICATION REPORTING
> ====
> With both partner surfaces published as machine-checkable OpenAPI contracts (SP9) and every lane green (473/473), build the certification reporter that aggregates all test evidence into the single owner-reviewable report of what is PASS, what is FAIL, and what was NOT TESTED.
>
> BUILD:
>
> A. CERTIFICATION ROWS (ONE SHAPE, ALL LANES)
>
> - every test lane emits certification rows in the SP8 shape `{ testId, category, requirement, result, reasonCode }` (PASS rows carry the expected code, FAIL rows the observed code, NOT-TESTED rows a reason code) — the SP8 `simulators/evidence.ts` mapping (`certificationRowFor`, `notTestedRow`) is the canonical producer; the other lanes (law-shield, patches, adapter, ai-governance, shared, openapi) map their assertions onto the same shape
> - categories align with the existing owner-facing vocabularies (the SP8 failure-mode categories: SIGNATURE, REPLAY, RECEIPT, AUTHORIZATION, ENTITLEMENT, WEBHOOK, RETRY, RECONCILIATION, CIRCUIT_BREAKER, KILL_SWITCH, CONTROL; the SP9 contract categories: structure, cross-check, live-conformance)
> - metadata-only evidence discipline carried over exactly: identifiers, reason codes, and counts — never payload content, never envelope bodies, never secrets
>
> B. THE REPORTER (`certification/`)
>
> - a report generator that runs (or consumes the results of) every lane and aggregates the rows into the single certification report: per-category PASS/FAIL/NOT-TESTED tallies, the requirement text for every row, and the reason code for every non-PASS row
> - output formats: machine-readable JSON (the rows verbatim) + a human-readable static report (the SP9 precedent: self-contained HTML, no external service, committed to the repo)
> - fail-closed reporting: a lane that cannot run, crashes, or emits malformed rows collapses to a NOT-TESTED row with a typed reason code — never a crash, never a silent skip, never a fabricated PASS
> - determinism: the same tree and the same inputs produce the same report (no timestamps inside the row set; generation metadata may carry a timestamp but never the rows)
>
> C. WIRING INTO CI
>
> - the reporter runs in CI after the test step: the certification report is generated on every push and committed/published as a repo artifact, so the owner can read the exact certified state of the sandbox at any commit
> - the report does not gate CI (the lanes already gate); it records — but a FAIL row in the report must be visible in the summary, not buried
>
> STOP FOR OWNER REVIEW.

---

**STOP.** Stop Point 9 is published and certified: feature commit (CI run recorded in the repo Actions history at owner review) plus this report chain, 473/473 tests (71 law-shield + 78 patches (30 contract + 48 adapter) + 56 ai-governance + 207 shared + 53 simulators + 8 openapi), typecheck GREEN, frozen-lockfile install GREEN, secret scan clean on the final tree, fast-forward publication only, all 465 SP8-baseline tests preserved green throughout. The final remote HEAD is the last SP9 commit on `main` — `git rev-parse origin/main` at owner review gives the authoritative close SHA. Awaiting owner decision on the Stop Point 10 proposal above. No further work will begin without explicit approval.
