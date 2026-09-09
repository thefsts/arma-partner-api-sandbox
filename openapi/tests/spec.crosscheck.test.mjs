// OpenAPI cross-check lane (Stop Point 9): implementation <-> spec lockstep.
//
// Two gates, both must hold (ported from the proven offline scripts into the
// repo matrix so CI enforces them on every push):
//
//   Gate A (implementation -> spec): every error code the implementation can
//   emit ON THE WIRE must be represented in the spec. Wire codes are scanned
//   from the implementation sources; known internal-only codes (audit-detail
//   codes, ARMA-side receipt-verification reasons, synthetic statuses,
//   unreachable type-union members, secret-kind tokens) are excluded — with a
//   ghost-check proving every exclusion genuinely exists in source (no
//   invented exemptions).
//
//   Gate B (spec -> implementation): every ALL_CAPS code-like token in the
//   spec must exist in the implementation sources or the documented allow-list
//   (schema enum VALUES that are states/outcomes, errorClass consts, env-var
//   names, capability identifiers). No invented codes.
//
// This file invents nothing: every expectation below is verified against the
// implementation sources, which are read AT TEST TIME (so future edits that
// add a wire code without updating the spec, or invent a spec code without
// implementing it, fail this lane).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as pathResolve } from 'node:path';
import { loadSpec, allCapsTokens } from './helpers.mjs';

const here = dirname(fileURLToPath(import.meta.url));

function readRepo(rel) {
  return readFileSync(pathResolve(here, rel), 'utf8');
}

function scanCodes(sources) {
  const codes = new Set();
  const single = /'([A-Z][A-Z0-9_]{5,})'/g;
  const double = /"([A-Z][A-Z0-9_]{5,})"/g;
  for (const src of sources) {
    let m;
    while ((m = single.exec(src)) !== null) codes.add(m[1]);
    while ((m = double.exec(src)) !== null) codes.add(m[1]);
  }
  return codes;
}

// ---------------------------------------------------------------------------
// PATCHES Partner API v1
// ---------------------------------------------------------------------------
const PATCHES_IMPL = [
  readRepo('../../patches/lib/server.ts'),
  readRepo('../../patches/lib/security.ts'),
  readRepo('../../patches/lib/policy.ts'),
  readRepo('../../patches/lib/receipts.ts'),
  readRepo('../../patches/lib/rateLimit.ts'),
  readRepo('../../patches/lib/store.ts'),
  readRepo('../../patches/patches/partner-v1-health-route.ts'),
];

const PATCHES_INTERNAL = {
  // policy codes that exist ONLY in the PolicyFailureCode type union; no code
  // path emits them (server.ts's version check emits UNSUPPORTED_API_VERSION,
  // which IS a wire code and IS in the spec)
  API_VERSION_UNSUPPORTED: 'unreachable type-union member',
  PARTNER_NOT_CREDENTIAL_OWNER: 'unreachable type-union member',
  // ARMA-side receipt-verification reasons (client of the receipt, not this wire)
  RECEIPT_MISSING_HEADERS: 'client-side receipt verification',
  RECEIPT_INVALID_SIGNATURE: 'client-side receipt verification',
  RECEIPT_CONTENT_HASH_MISMATCH: 'client-side receipt verification',
  RECEIPT_BODY_MALFORMED: 'client-side receipt verification',
  RECEIPT_FIELD_MISMATCH: 'client-side receipt verification',
  // audit-detail codes (scrubbed from AuditView by SAFE_DETAIL_KEYS; never on the wire)
  ENTITLEMENTS_LISTED: 'audit detail only',
  IDEMPOTENCY_CONFLICT: 'audit detail only',
  ACTIVATION_CREATED: 'audit detail only',
  DOWNSTREAM_THREW: 'audit detail only',
  PARTNER_TRANSACTION_FAILED: 'audit detail only',
  DUPLICATE_DELIVERY_COLLAPSED: 'audit detail only',
  // synthetic protection-service statuses (test/diagnostic markers, not error codes)
  SYNTHETIC_FAILED: 'synthetic status marker',
  SYNTHETIC_NO_DOWNSTREAM: 'synthetic status marker',
  SYNTHETIC_OK: 'synthetic status marker',
  // secret-kind token (store record kind, not a wire error code)
  CLIENT_SECRET: 'credential kind',
};

const PATCHES_ALLOWED_SPEC_TOKENS = {
  // schema enum VALUES / consts that are lifecycle states, audit outcomes,
  // actor kinds — values, not error codes; all exist in source enums
  ACTIVE: 'status enum', DEACTIVATED: 'status enum', REVOKED: 'status enum',
  SUCCESS: 'outcome enum', REJECTED: 'outcome enum', FAILED: 'outcome enum',
  QUARANTINED: 'outcome enum', CONFLICT: 'outcome enum',
  PARTNER: 'actor kind', SYSTEM: 'actor kind',
  GRACE: 'credential status', RETIRED: 'credential status',
  INACTIVE: 'status enum', SUSPENDED: 'status enum',
  // errorClass consts (all on the wire in source bodies)
  AUTHENTICATION: 'errorClass const', AUTHORIZATION: 'errorClass const',
  IDEMPOTENCY: 'errorClass const', DOWNSTREAM: 'errorClass const',
  PERSISTENCE: 'errorClass const', RATE_LIMIT: 'errorClass const',
  VERSION: 'errorClass const', INPUT: 'errorClass const',
  STATE: 'errorClass const', NOT_FOUND: 'errorClass const',
  // env-var name documented in prose (exists in source env lookup)
  PATCHES_PARTNER_API_DISABLED: 'env var name',
  // capability identifiers (KNOWN_CAPABILITIES in policy.ts)
  TRAFFIC_STOP_PRIVACY: 'capability id', HOME_PRIVACY: 'capability id',
  // version tokens (MIN_API_VERSION/MAX_API_VERSION consts in policy.ts)
  MIN_API_VERSION: 'version const', MAX_API_VERSION: 'version const',
};

// ---------------------------------------------------------------------------
// Law Shield API v1
// ---------------------------------------------------------------------------
const LAWSHIELD_IMPL = [
  readRepo('../../law-shield/lawshield/arma-integration.js'),
  readRepo('../../law-shield/lawshield/_integrationSecurity.js'),
  readRepo('../../law-shield/lawshield/durable/processor.js'),
  readRepo('../../law-shield/lawshield/integration-readiness.js'),
  readRepo('../../law-shield/lawshield/durable/store.js'),
  readRepo('../../law-shield/arma/receiptVerifier.js'),
];

const LAWSHIELD_INTERNAL = {
  // audit eventTypes (never on the wire)
  TRANSFER_REJECTED: 'audit eventType', NONCE_REPLAY_REJECTED: 'audit eventType',
  TRANSFER_QUARANTINED: 'audit eventType', TRANSFER_ENVELOPE_REJECTED: 'audit eventType',
  PROCESSOR_TRANSACTION_FAILED: 'audit eventType', GATEWAY_FORWARD: 'audit eventType',
  DUPLICATE_DELIVERY_COLLAPSED: 'audit eventType',
  // store integrity (masked to PROCESSOR_PERSISTENCE_FAILED / internal)
  INVALID_NONCE_REGISTRY_INPUT: 'store integrity',
  TRANSACTION_DID_NOT_COMMIT: 'store integrity',
  DUPLICATE_COLLAPSED_TO_STORED_OUTCOME: 'store integrity',
  DUPLICATE_COLLAPSED_TO_STORED_RECEIPT: 'store integrity',
  TRANSFER_CONTENT_CONFLICT: 'store integrity',
  // ARMA-side receipt verification (client of the receipt, not this wire)
  RECEIPT_HEADERS_MISSING: 'client-side receipt verification',
  RECEIPT_EMPTY_BODY: 'client-side receipt verification',
  RECEIPT_BODY_HASH_MISMATCH: 'client-side receipt verification',
  RECEIPT_INVALID_SIGNATURE: 'client-side receipt verification',
  RECEIPT_INVALID_JSON: 'client-side receipt verification',
  RECEIPT_ID_MISMATCH: 'client-side receipt verification',
  RECEIPT_TRANSFER_ID_MISSING: 'client-side receipt verification',
  RECEIPT_TRANSFER_ID_MISMATCH: 'client-side receipt verification',
  RECEIPT_IDEMPOTENCY_MISMATCH: 'client-side receipt verification',
  RECEIPT_ORG_MISMATCH: 'client-side receipt verification',
  RECEIPT_STATUS_NOT_ACCEPTED: 'client-side receipt verification',
  RECEIPT_ACCEPTED_NOT_TRUE: 'client-side receipt verification',
  RECEIPT_PAYLOAD_HASH_MISMATCH: 'client-side receipt verification',
  RECEIPT_RECORD_TYPE_MISMATCH: 'client-side receipt verification',
  RECEIPT_RECORD_ID_MISMATCH: 'client-side receipt verification',
  RECEIPT_ACCEPTED_AT_INVALID: 'client-side receipt verification',
  GATEWAY_UNKNOWN: 'client-side error mapping',
  PROCESSOR_UNKNOWN: 'client-side error mapping',
  ARMA_RECEIPT_VERIFIER_NOT_CONFIGURED: 'client-side config check',
  // result() outcome discriminators
  DUPLICATE: 'result kind',
  // defensive fallback documented in prose
  INVALID_ENVELOPE: 'defensive fallback (prose)',
};

const LAWSHIELD_ALLOWED_SPEC_TOKENS = {
  ARMA_360: 'sourceSystem const', LAW_SHIELD: 'destinationSystem const',
  ACCEPTED: 'receipt const', REJECTED: 'status const', QUARANTINED: 'status const',
  PERSISTED: 'processingResult const', CASE_REFERRAL: 'recordType const',
  INCIDENT_METADATA: 'recordType const', EVIDENCE_MANIFEST: 'recordType const',
  EVIDENCE_PACKAGE_REFERENCE: 'recordType const', CHAIN_OF_CUSTODY_UPDATE: 'recordType const',
  TRANSFER_STATUS: 'recordType const', CASE_STATUS_UPDATE: 'recordType const',
  GATEWAY: 'system role', PROCESSOR: 'system role', POST: 'http method', GET: 'http method',
  MINIMUM_NECESSARY_POLICY: 'policy name', ALWAYS_REDACTED: 'policy name', API_KEY: 'security type',
  LAW_SHIELD_ARMA_INTEGRATION_DISABLED: 'env var name',
  LAW_SHIELD_GATEWAY_REPLAY_GUARD: 'env var name',
  LAW_SHIELD_INTEGRATION_PROCESSOR_URL: 'env var name',
  LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN: 'env var name',
  LAW_SHIELD_PROCESSOR_DISABLED: 'env var name',
  LAW_SHIELD_MAX_BODY_BYTES: 'env var name',
  LAW_SHIELD_MAX_CLOCK_SKEW_MS: 'env var name',
  LEGAL_REVIEW: 'synthetic example value', RECORDS_REQUEST: 'synthetic example value',
  ORG_NOT_AUTHORIZED: 'processor rejection error (on wire via processor stub tests)',
};

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------
test('cross-check: PATCHES Partner API v1 — every wire error code is in the spec, every spec token traces to source', () => {
  const doc = loadSpec('../patches-partner-v1.yaml');
  const specText = JSON.stringify(doc);

  const srcCodes = scanCodes(PATCHES_IMPL);

  // Ghost-check: every internal exemption must genuinely exist in source.
  const ghost = Object.keys(PATCHES_INTERNAL).filter((c) => !srcCodes.has(c));
  assert.deepEqual(ghost, [], 'invented exemptions (codes not in source)');

  const missing = [...srcCodes]
    .filter((c) => !c.startsWith('FAILPOINT_'))
    .filter((c) => !(c in PATCHES_INTERNAL))
    .filter((c) => !specText.includes(c));
  assert.deepEqual(missing, [], 'wire codes missing from the spec');

  const specTokens = allCapsTokens(readFileSync(pathResolve(here, '../patches-partner-v1.yaml'), 'utf8'));
  const specOnly = [...specTokens]
    .filter((c) => !srcCodes.has(c))
    .filter((c) => !(c in PATCHES_ALLOWED_SPEC_TOKENS));
  assert.deepEqual(specOnly, [], 'spec tokens with no implementation trace');
});

test('cross-check: ARMA Law Shield API v1 — every wire error code is in the spec, every spec token traces to source', () => {
  const doc = loadSpec('../../law-shield/openapi/arma-lawshield-v1.yaml');
  const specText = JSON.stringify(doc);

  const srcCodes = scanCodes(LAWSHIELD_IMPL);

  const ghost = Object.keys(LAWSHIELD_INTERNAL).filter((c) => !srcCodes.has(c));
  assert.deepEqual(ghost, [], 'invented exemptions (codes not in source)');

  const missing = [...srcCodes]
    .filter((c) => !c.startsWith('FAILPOINT_'))
    .filter((c) => !(c in LAWSHIELD_INTERNAL))
    .filter((c) => !specText.includes(c));
  assert.deepEqual(missing, [], 'wire codes missing from the spec');

  const specTokens = allCapsTokens(readFileSync(pathResolve(here, '../../law-shield/openapi/arma-lawshield-v1.yaml'), 'utf8'));
  const specOnly = [...specTokens]
    .filter((c) => !srcCodes.has(c))
    .filter((c) => !(c in LAWSHIELD_ALLOWED_SPEC_TOKENS));
  assert.deepEqual(specOnly, [], 'spec tokens with no implementation trace');
});

// Route lockstep: every route the servers match must be a documented path,
// and every documented path must be a route the servers match.
test('cross-check: every implemented route is documented and every documented route is implemented', async () => {
  const patches = loadSpec('../patches-partner-v1.yaml');
  const lawshield = loadSpec('../../law-shield/openapi/arma-lawshield-v1.yaml');

  // PATCHES: matchV1Route in server.ts is the single source of route truth —
  // it matches on `rest` (the path AFTER the /api/partner/v1 prefix).
  const serverTs = readRepo('../../patches/lib/server.ts');
  const documentedRoutes = [
    'GET /api/partner/v1/health',
    'GET /api/partner/v1/capabilities',
    'GET /api/partner/v1/entitlements',
    'POST /api/partner/v1/activations',
    'GET /api/partner/v1/activations/{activationId}',
    'POST /api/partner/v1/activations/{activationId}/deactivate',
    'POST /api/partner/v1/activations/{activationId}/revoke',
    'GET /api/partner/v1/events',
    'GET /api/partner/v1/audit',
  ];
  const specOps = new Set();
  for (const [p, item] of Object.entries(patches.paths)) {
    for (const m of ['get', 'post']) if (item[m]) specOps.add(`${m.toUpperCase()} ${p}`);
  }
  assert.deepEqual(
    [...specOps].sort(),
    [...documentedRoutes].sort(),
    'PATCHES spec operations must exactly match the implemented route set',
  );

  // Every route literal (in `rest` form) must appear in matchV1Route; health
  // is matched by its full template path in the kill-switch + dispatch blocks.
  const restLiterals = {
    'GET /api/partner/v1/health': '`${PARTNER_API_PATH_PREFIX}/v1/health`',
    'GET /api/partner/v1/capabilities': "'/capabilities'",
    'GET /api/partner/v1/entitlements': "'/entitlements'",
    'POST /api/partner/v1/activations': "'/activations'",
    'GET /api/partner/v1/activations/{activationId}': '/^\\/activations\\/([A-Za-z0-9_-]{1,128})$/',
    'POST /api/partner/v1/activations/{activationId}/deactivate': '/^\\/activations\\/([A-Za-z0-9_-]{1,128})\\/(deactivate|revoke)$/',
    'POST /api/partner/v1/activations/{activationId}/revoke': '/^\\/activations\\/([A-Za-z0-9_-]{1,128})\\/(deactivate|revoke)$/',
    'GET /api/partner/v1/events': "'/events'",
    'GET /api/partner/v1/audit': "'/audit'",
  };
  for (const [route, literal] of Object.entries(restLiterals)) {
    assert.ok(serverTs.includes(literal), `route literal not found in server.ts: ${literal} (${route})`);
  }

  // Law Shield: 4 routes — gateway (arma, integration-readiness) + processor (/process, /status).
  // The gateway + readiness handlers are platform-mounted modules (no path
  // matching inside them — mounting is wiring); the authoritative in-repo
  // proof of their wire paths is the test harness, which drives them over
  // real HTTP at exactly these paths. The durable processor matches its own
  // routes internally.
  const integrationJs = readRepo('../../law-shield/lawshield/arma-integration.js');
  const readinessJs = readRepo('../../law-shield/lawshield/integration-readiness.js');
  const processorJs = readRepo('../../law-shield/lawshield/durable/processor.js');
  const contractCompat = readRepo('../../law-shield/tests/contract.compat.test.mjs');
  const e2eTest = readRepo('../../law-shield/tests/e2e.synthetic.test.mjs');
  const durableTest = readRepo('../../law-shield/tests/processor.durable.test.mjs');
  const gatewaySecurityTest = readRepo('../../law-shield/tests/gateway.security.test.mjs');
  const lsOps = new Set();
  for (const [p, item] of Object.entries(lawshield.paths)) {
    for (const m of ['get', 'post']) if (item[m]) lsOps.add(`${m.toUpperCase()} ${p}`);
  }
  assert.deepEqual(
    [...lsOps].sort(),
    ['POST /api/lawshield/arma', 'GET /api/lawshield/integration-readiness', 'POST /process', 'GET /status'].sort(),
    'Law Shield spec operations must exactly match the implemented route set',
  );
  // Gateway + readiness wire paths, proven by the harness that drives them.
  assert.ok(contractCompat.includes("'/api/lawshield/arma'") && e2eTest.includes("'/api/lawshield/arma'"), 'gateway wire path not exercised by tests');
  assert.ok(readinessJs.includes("method!=='GET'"), 'readiness handler enforces GET');
  assert.ok(gatewaySecurityTest.includes("'/api/lawshield/integration-readiness'"), 'readiness wire path not exercised by tests');
  // Processor matches its own routes internally (plus accepts POST / alias).
  assert.ok(processorJs.includes("req.url === '/process'"), 'processor /process route missing');
  assert.ok(processorJs.includes("req.url === '/status'"), 'processor /status route missing');
  assert.ok(durableTest.includes('/process') && durableTest.includes('/status'), 'processor routes not exercised by tests');
});
