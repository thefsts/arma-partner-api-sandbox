// STOP POINT 5 — ARMA PATCHES adapter — mandatory test matrix.
//
// Drives the REAL SP4 reference server over the wire through the REAL
// adapter (PatchesPartnerClient + ArmaActivationService + ArmaStore), plus
// unit tests for the classification engine, credential rotation, receipt
// tampering, and the audit-redaction defense in depth.
//
// The matrix follows the owner's binding amendment: CLEAN_RETRYABLE failures
// get bounded retry with fresh nonce+signature; AMBIGUOUS failures always
// transition to RECONCILIATION_REQUIRED (never blind re-send); TERMINAL
// failures are rejected or quarantined. Synthetic data only; no secrets in
// audit/state (asserted throughout via assertNoSecretsInStore).

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootServer, signedRequest, makeClock, RECEIPT_SECRET, resolveClientSecret, injectSecret } from './helpers.mjs';
import { rotateCredential, revokeCredential, canonicalRequestString, computeRequestSignature } from '../lib/security.ts';
import { signReceiptBytes } from '../lib/receipts.ts';
import {
  PatchesPartnerClient,
  staticCredentialSource,
  classifyFailure,
  redactForAudit,
  ARMA_OUTBOUND_KILL_SWITCH_ENV,
} from '../arma/patchesPartnerClient.ts';
import { ArmaActivationService } from '../arma/activationService.ts';
import { ArmaStore } from '../arma/armaStore.ts';

const ARMA_CLIENT_ID = 'arma-client';
const ARMA_KEY_ID = 'arma-key-1';
const ARMA_SECRET = () => resolveClientSecret(ARMA_CLIENT_ID, ARMA_KEY_ID);
const ACTIVATIONS_PATH = '/api/partner/v1/activations';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function armaStoreFixture(clock) {
  const store = new ArmaStore();
  const at = clock.now();
  const DAY = 86_400_000;

  store.putPartnerConfig({
    configId: 'default', clientId: ARMA_CLIENT_ID, activeKeyId: ARMA_KEY_ID,
    graceKeyIds: [], retiredKeyIds: [],
    receiptVerificationKeyRef: 'kms-ref-receipt-verification-synthetic',
    baseUrl: 'http://patches-partner-api.invalid', outboundEnabled: true, updatedAt: at,
  });
  store.putOrgMapping({ mappingId: 'ARMA-ORG-A::ORG-ARMA-ALPHA', armaOrgId: 'ARMA-ORG-A', patchesOrgId: 'ORG-ARMA-ALPHA', status: 'ACTIVE', createdAt: at });
  store.putOrgMapping({ mappingId: 'ARMA-ORG-B::ORG-ARMA-BETA', armaOrgId: 'ARMA-ORG-B', patchesOrgId: 'ORG-ARMA-BETA', status: 'ACTIVE', createdAt: at });
  store.putOrgMapping({ mappingId: 'ARMA-ORG-DELTA::ORG-ARMA-DELTA', armaOrgId: 'ARMA-ORG-DELTA', patchesOrgId: 'ORG-ARMA-DELTA', status: 'ACTIVE', createdAt: at });
  store.putOrgMapping({ mappingId: 'ARMA-ORG-PAUSED::ORG-ARMA-DELTA', armaOrgId: 'ARMA-ORG-PAUSED', patchesOrgId: 'ORG-ARMA-DELTA', status: 'PAUSED', createdAt: at });

  store.putEntitlementRef({ refId: 'ORG-ARMA-ALPHA::traffic_stop_privacy', patchesOrgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', entitled: true, lastCheckedAt: at, licensedUntil: at + 365 * DAY });
  store.putEntitlementRef({ refId: 'ORG-ARMA-BETA::home_privacy', patchesOrgId: 'ORG-ARMA-BETA', capability: 'home_privacy', entitled: true, lastCheckedAt: at, licensedUntil: at + 365 * DAY });
  store.putEntitlementRef({ refId: 'ORG-ARMA-DELTA::traffic_stop_privacy', patchesOrgId: 'ORG-ARMA-DELTA', capability: 'traffic_stop_privacy', entitled: false, lastCheckedAt: at });

  store.putCapabilityRef({ capability: 'traffic_stop_privacy', minApiVersion: 'v1', maxApiVersion: 'v1', description: 'Traffic-stop privacy capability (generic contract)', syncedAt: at });
  store.putCapabilityRef({ capability: 'home_privacy', minApiVersion: 'v1', maxApiVersion: 'v1', description: 'Home privacy capability (generic contract)', syncedAt: at });
  store.putCapabilityRef({ capability: 'telemetry_privacy', minApiVersion: 'v0', maxApiVersion: 'v2', description: 'Stale capability ref for local preflight tests', syncedAt: at });

  store.putBinding({ bindingId: 'BIND-ALPHA-TSP', patchesOrgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-001', subjectRef: 'SUBJ-OPAQUE-001', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-ALPHA-TSP-INACTIVE', patchesOrgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-020', subjectRef: 'SUBJ-OPAQUE-020', status: 'INACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-BETA-HP', patchesOrgId: 'ORG-ARMA-BETA', capability: 'home_privacy', deviceId: 'DEV-OPAQUE-002', subjectRef: 'SUBJ-OPAQUE-002', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-CAP-MISMATCH', patchesOrgId: 'ORG-ARMA-ALPHA', capability: 'home_privacy', deviceId: 'DEV-OPAQUE-016', subjectRef: 'SUBJ-OPAQUE-016', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-LUMEN-CROSS', patchesOrgId: 'ORG-LUMEN-GAMMA', capability: 'home_privacy', deviceId: 'DEV-OPAQUE-017', subjectRef: 'SUBJ-OPAQUE-017', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-UNKNOWN-404', patchesOrgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-018', subjectRef: 'SUBJ-OPAQUE-018', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-DELTA-TSP', patchesOrgId: 'ORG-ARMA-DELTA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-019', subjectRef: 'SUBJ-OPAQUE-019', status: 'ACTIVE', boundAt: at - 3600_000 });
  return store;
}

function makeClient(h, { fetchImpl, rotatingKey, now } = {}) {
  return new PatchesPartnerClient({
    baseUrl: h.url,
    receiptVerificationKey: RECEIPT_SECRET,
    now: now ?? h.clock.now,
    fetchImpl,
    sleep: async () => { /* deterministic tests: no real waiting */ },
    credentials: rotatingKey !== undefined
      ? { current: () => ({ clientId: ARMA_CLIENT_ID, keyId: rotatingKey.keyId, secret: rotatingKey.secret }) }
      : staticCredentialSource({ clientId: ARMA_CLIENT_ID, keyId: ARMA_KEY_ID, secret: ARMA_SECRET() }),
  });
}

function makeAdapter(h, { client, fetchImpl, rotatingKey, store: sharedStore } = {}) {
  // Pass `store` to share durable state across two adapters (F8-style tests).
  const store = sharedStore ?? armaStoreFixture(h.clock);
  const resolvedClient = client ?? makeClient(h, { fetchImpl, rotatingKey });
  const service = new ArmaActivationService({
    store,
    client: resolvedClient,
    now: h.clock.now,
    reconciliationStatusAttempts: 3,
    outboundDisabled: () => false,
    secretsForRedaction: () => [ARMA_SECRET(), RECEIPT_SECRET],
  });
  return { store, client: resolvedClient, service };
}

const standardIntent = { armaOrgId: 'ARMA-ORG-A', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP' };

// Serialize EVERY durable table (Maps do not JSON.stringify by default).
function dumpStore(store) {
  return JSON.stringify({
    partnerConfig: [...store.partnerConfig.values()],
    orgMappings: [...store.orgMappings.values()],
    entitlementRefs: [...store.entitlementRefs.values()],
    capabilityRefs: [...store.capabilityRefs.values()],
    bindings: [...store.bindings.values()],
    activations: [...store.activations.values()],
    idempotency: [...store.idempotency.values()],
    receipts: [...store.receipts.values()],
    retries: [...store.retries.values()],
    reconciliations: [...store.reconciliations.values()],
    audit: store.audit,
  });
}

function assertNoSecretsInStore(store, extraSecrets = []) {
  const dump = dumpStore(store);
  for (const secret of [ARMA_SECRET(), RECEIPT_SECRET, ...extraSecrets]) {
    assert.ok(!dump.includes(secret), `secret material leaked into adapter durable state: ${secret.slice(0, 12)}...`);
  }
}

async function setup(options = {}) {
  const clock = makeClock();
  const h = await bootServer(clock, options).start();
  return { ...h, clock };
}

// A fetch wrapper that lets a test interfere with exactly ONE create call.
function onceOnCreate(interfere) {
  let armed = true;
  return async (url, init) => {
    const isCreate = (init?.method ?? 'GET') === 'POST' && new URL(url).pathname === ACTIVATIONS_PATH;
    if (armed && isCreate) {
      armed = false;
      return interfere(url, init);
    }
    return fetch(url, init);
  };
}

// ---------------------------------------------------------------------------
// A. Classification engine (unit) — the owner amendment as pure functions.
// ---------------------------------------------------------------------------

test('A1. AbortError (client timeout) -> AMBIGUOUS TIMEOUT: never blind re-send', () => {
  const c = classifyFailure({ transportError: new DOMException('aborted', 'AbortError'), receiptExpected: true });
  assert.equal(c.failureClass, 'AMBIGUOUS');
  assert.equal(c.failureReason, 'TIMEOUT');
});

test('A2. ECONNREFUSED (pre-delivery) -> CLEAN_RETRYABLE', () => {
  const e = new Error('connect refused');
  e.code = 'ECONNREFUSED';
  const c = classifyFailure({ transportError: e, receiptExpected: true });
  assert.equal(c.failureClass, 'CLEAN_RETRYABLE');
  assert.equal(c.failureReason, 'CONN_ECONNREFUSED');
});

test('A3. response dropped mid-read -> AMBIGUOUS RESPONSE_LOST; ECONNRESET after send -> AMBIGUOUS DROP', () => {
  const c = classifyFailure({ receiptExpected: true, responseComplete: false });
  assert.equal(c.failureClass, 'AMBIGUOUS');
  assert.equal(c.failureReason, 'RESPONSE_LOST');
  const reset = new Error('read ECONNRESET');
  reset.code = 'ECONNRESET';
  const c2 = classifyFailure({ transportError: reset, receiptExpected: true });
  assert.equal(c2.failureClass, 'AMBIGUOUS');
  assert.equal(c2.failureReason, 'DROP_ECONNRESET');
});

test('A4. 429 -> CLEAN_RETRYABLE RATE_LIMITED', () => {
  const c = classifyFailure({ httpStatus: 429, errorCode: 'RATE_LIMITED', receiptExpected: true });
  assert.equal(c.failureClass, 'CLEAN_RETRYABLE');
  assert.equal(c.failureReason, 'RATE_LIMITED');
});

test('A5. 503 PARTNER_API_DISABLED -> CLEAN_RETRYABLE (kill switch provably first)', () => {
  const c = classifyFailure({ httpStatus: 503, errorCode: 'PARTNER_API_DISABLED', receiptExpected: true });
  assert.equal(c.failureClass, 'CLEAN_RETRYABLE');
  assert.equal(c.failureReason, 'PATCHES_API_DISABLED');
});

test('A6. 503 DOWNSTREAM_UNAVAILABLE -> CLEAN_RETRYABLE (fail-closed before persistence)', () => {
  const c = classifyFailure({ httpStatus: 503, errorCode: 'DOWNSTREAM_UNAVAILABLE', receiptExpected: true });
  assert.equal(c.failureClass, 'CLEAN_RETRYABLE');
  assert.equal(c.failureReason, 'DOWNSTREAM_UNAVAILABLE');
});

test('A7. 500 PARTNER_PERSISTENCE_FAILED -> CLEAN_RETRYABLE (atomic rollback proof)', () => {
  const c = classifyFailure({ httpStatus: 500, errorCode: 'PARTNER_PERSISTENCE_FAILED', receiptExpected: true });
  assert.equal(c.failureClass, 'CLEAN_RETRYABLE');
  assert.equal(c.failureReason, 'PERSISTENCE_ROLLED_BACK');
});

test('A8. unrecognized 5xx -> AMBIGUOUS UNPROVABLE (fail closed)', () => {
  const c = classifyFailure({ httpStatus: 502, errorCode: null, receiptExpected: true });
  assert.equal(c.failureClass, 'AMBIGUOUS');
  assert.equal(c.failureReason, 'UNPROVABLE_5XX');
  const c2 = classifyFailure({ httpStatus: 500, errorCode: 'WEIRD_INTERNAL', receiptExpected: true });
  assert.equal(c2.failureClass, 'AMBIGUOUS');
  assert.equal(c2.failureReason, 'UNPROVABLE_WEIRD_INTERNAL');
});

test('A9. auth failure codes -> TERMINAL (never retried blindly)', () => {
  for (const code of ['AUTH_MISSING', 'CREDENTIAL_REVOKED', 'CREDENTIAL_EXPIRED', 'PARTNER_SUSPENDED', 'SIGNATURE_INVALID', 'TIMESTAMP_OUT_OF_WINDOW']) {
    const c = classifyFailure({ httpStatus: 401, errorCode: code, receiptExpected: true });
    assert.equal(c.failureClass, 'TERMINAL', `code ${code}`);
    assert.equal(c.failureReason, `AUTH_${code}`);
  }
});

test('A10. 400/403/404/409/413 -> TERMINAL (input/tenant/entitlement/state denials)', () => {
  for (const status of [400, 403, 404, 409, 413]) {
    const c = classifyFailure({ httpStatus: status, errorCode: `HTTP_${status}`, receiptExpected: true });
    assert.equal(c.failureClass, 'TERMINAL', `status ${status}`);
  }
});

test('A11. receipt verification failed on 2xx -> AMBIGUOUS (processing may have occurred)', () => {
  const c = classifyFailure({
    httpStatus: 200, errorCode: null, receiptExpected: true,
    receiptVerification: { verified: false, reason: 'RECEIPT_INVALID_SIGNATURE' },
  });
  assert.equal(c.failureClass, 'AMBIGUOUS');
  assert.equal(c.failureReason, 'RECEIPT_INVALID_SIGNATURE');
});

test('A12. GET 2xx non-receipt -> success sentinel; version mismatch -> TERMINAL SERVER_VERSION_MISMATCH', () => {
  const okRoute = classifyFailure({ httpStatus: 200, receiptExpected: false, serverApiVersion: 'v1' });
  assert.equal(okRoute.failureClass, 'TERMINAL');
  assert.equal(okRoute.failureReason, 'UNEXPECTED_2XX');
  const mismatch = classifyFailure({ httpStatus: 200, receiptExpected: false, serverApiVersion: 'v2' });
  assert.equal(mismatch.failureClass, 'TERMINAL');
  assert.equal(mismatch.failureReason, 'SERVER_VERSION_MISMATCH');
});

test('A13. redactForAudit throws (fail closed) if secret material would reach the audit projection', () => {
  const secret = 'synthetic-secret-SHOULD-NEVER-APPEAR';
  const outcome = {
    ok: false, operation: 'activation.create', failureClass: 'TERMINAL', failureReason: secret,
    retriesExhausted: false, attempts: [], httpStatus: 401, errorCode: secret,
    body: null, rawBody: null, receipt: null, receiptVerified: false, retryAfterMs: null,
    lastRequestId: null, activationIdentityHint: null, duplicate: false,
  };
  assert.throws(() => redactForAudit(outcome, [secret]), /credential secret material detected/);
  // And a clean projection contains no secret and no raw evidence:
  const clean = redactForAudit({
    ...outcome, failureReason: 'AUTH_CREDENTIAL_REVOKED', errorCode: 'CREDENTIAL_REVOKED',
    attempts: [{ attempt: 1, requestId: 'req-x', keyId: ARMA_KEY_ID, timestamp: 1, nonce: 'n', method: 'POST', path: '/api/partner/v1/activations', bodyHash: 'h', phase: 'HTTP_RESPONSE', httpStatus: 401, errorCode: 'CREDENTIAL_REVOKED', failureClass: 'TERMINAL', failureReason: 'AUTH_CREDENTIAL_REVOKED' }],
  }, [secret]);
  const serialized = JSON.stringify(clean);
  assert.ok(!serialized.includes(secret));
  assert.ok(!serialized.includes('rawBody'));
});

// ---------------------------------------------------------------------------
// B. Success path: signed outbound activation -> receipt verified -> ACTIVE.
// ---------------------------------------------------------------------------

test('B1. success path: signed activation through the real server -> receipt verified -> ACTIVE', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'ACTIVATED');
    assert.equal(result.status, 'ACTIVE');
    assert.ok(result.patchesActivationId.startsWith('ACT-req-'), `patchesActivationId: ${result.patchesActivationId}`);
    assert.equal(result.duplicate, false);
    assert.equal(result.attempts, 1);

    const record = store.getActivation(result.activationId);
    assert.equal(record.status, 'ACTIVE');
    assert.equal(record.patchesActivationId, result.patchesActivationId);
    assert.ok(record.activatedAt !== undefined);

    // Receipt persisted (keyed by receiptId, recoverable from the audit event).
    const verified = store.audit.find((e) => e.operation === 'activation.receipt.verified');
    assert.ok(verified, 'receipt.verified audit event present');
    const receipt = store.getReceipt(verified.detail.receiptId);
    assert.ok(receipt, 'verified receipt persisted');
    assert.equal(receipt.operation, 'activation.create');
    assert.equal(receipt.outcome, 'SUCCESS');
    assert.equal(receipt.clientId, ARMA_CLIENT_ID);
    assert.ok(receipt.contentSha256.length === 64, 'raw-byte content hash recorded');

    const idem = store.getIdempotency(record.idempotencyKey);
    assert.equal(idem.status, 'COLLAPSED');
    assert.equal(idem.patchesActivationId, result.patchesActivationId);

    const ops = store.audit.map((e) => e.operation);
    for (const op of ['activation.intent.created', 'activation.state.ready_to_activate', 'activation.state.activation_sent', 'activation.receipt.verified']) {
      assert.ok(ops.includes(op), `audit op present: ${op}`);
    }
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// C. Auth failures: missing/invalid/revoked credentials, rotation, secrets.
// ---------------------------------------------------------------------------

test('C1. missing credential -> TERMINAL CREDENTIAL_SOURCE_INVALID before any wire I/O', async () => {
  const h = await setup();
  try {
    const client = new PatchesPartnerClient({
      baseUrl: h.url, receiptVerificationKey: RECEIPT_SECRET, now: h.clock.now, sleep: async () => {},
      credentials: { current: () => ({ clientId: '', keyId: '', secret: '' }) },
    });
    const outcome = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-c1' });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.failureClass, 'TERMINAL');
    assert.equal(outcome.errorCode, 'CREDENTIAL_SOURCE_INVALID');
    assert.equal(outcome.attempts.length, 1);
    assert.equal(outcome.attempts[0].phase, 'BLOCKED');
    assert.equal(h.store.activationCount(), 0, 'nothing reached the server');
  } finally {
    await h.close();
  }
});

test('C2. invalid credentials (unknown clientId) -> TERMINAL PARTNER_UNKNOWN; service QUARANTINED (credential is ops)', async () => {
  const h = await setup();
  try {
    const ghostSecret = 'synthetic-secret-GHOST';
    const { store, service } = makeAdapter(h, { client: new PatchesPartnerClient({
      baseUrl: h.url, receiptVerificationKey: RECEIPT_SECRET, now: h.clock.now, sleep: async () => {},
      credentials: staticCredentialSource({ clientId: 'ghost-client', keyId: 'ghost-key', secret: ghostSecret }),
    }) });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'QUARANTINED');
    assert.equal(result.errorCode, 'PARTNER_UNKNOWN');
    assert.equal(result.status, 'QUARANTINED');
    assert.equal(store.getActivation(result.activationId).status, 'QUARANTINED');
    assertNoSecretsInStore(store, [ghostSecret]);
  } finally {
    await h.close();
  }
});

test('C3. revoked credential -> TERMINAL CREDENTIAL_REVOKED; service QUARANTINED, never retried', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    revokeCredential({ store: h.store, clientId: ARMA_CLIENT_ID, keyId: ARMA_KEY_ID, reason: 'synthetic rotation test' });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'QUARANTINED');
    assert.equal(result.errorCode, 'CREDENTIAL_REVOKED');
    assert.equal(result.attempts, 1, 'terminal auth failure: no retries');
    assert.equal(store.getActivation(result.activationId).status, 'QUARANTINED');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('C4. rotation mid-flight: new ACTIVE key signs; old GRACE key still authenticates during the overlap window', async () => {
  const h = await setup();
  try {
    rotateCredential({ store: h.store, clientId: ARMA_CLIENT_ID, newKeyId: 'arma-key-2', newSecretHash: 'synthetic-hash-2', now: h.clock.now });
    injectSecret(ARMA_CLIENT_ID, 'arma-key-2', 'synthetic-secret-ARMA-2');
    // The rotating credential source resolves the CURRENT active key per attempt.
    const { store, service } = makeAdapter(h, { rotatingKey: { keyId: 'arma-key-2', secret: 'synthetic-secret-ARMA-2' } });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'ACTIVATED');
    assert.equal(result.status, 'ACTIVE');

    // The OLD key is in GRACE (10-min overlap): a request signed with it still authenticates.
    const grace = await makeClient(h).activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-UNKNOWN-404', idempotencyKey: 'idem-c4-grace' });
    assert.equal(grace.ok, true, 'grace key still authenticates within the overlap window');
    assert.equal(grace.attempts[0].keyId, ARMA_KEY_ID);
    assertNoSecretsInStore(store, ['synthetic-secret-ARMA-2']);
  } finally {
    await h.close();
  }
});

test('C5. rotation mid-flight: key past its grace window -> TERMINAL CREDENTIAL_EXPIRED; rotating source recovers with the new key', async () => {
  const h = await setup();
  try {
    rotateCredential({ store: h.store, clientId: ARMA_CLIENT_ID, newKeyId: 'arma-key-2', newSecretHash: 'synthetic-hash-2', now: h.clock.now });
    injectSecret(ARMA_CLIENT_ID, 'arma-key-2', 'synthetic-secret-ARMA-2');
    h.clock.advance(601_000); // past the 10-minute GRACE window

    // A client still holding the retired key is terminally rejected.
    const stale = await makeClient(h).activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-c5-stale' });
    assert.equal(stale.ok, false);
    assert.equal(stale.failureClass, 'TERMINAL');
    assert.equal(stale.errorCode, 'CREDENTIAL_EXPIRED');

    // The adapter with a rotating credential source recovers immediately.
    const { store, service } = makeAdapter(h, { rotatingKey: { keyId: 'arma-key-2', secret: 'synthetic-secret-ARMA-2' } });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'ACTIVATED');
    assert.equal(result.status, 'ACTIVE');
    assertNoSecretsInStore(store, ['synthetic-secret-ARMA-2']);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// D. Tenant / entitlement / capability / binding rejections (terminal).
// ---------------------------------------------------------------------------

test('D1. wrong tenant: binding owned by another partner org -> TERMINAL BINDING_ORG_MISMATCH; service REJECTED', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    // BIND-LUMEN-CROSS belongs to ORG-LUMEN-GAMMA (PARTNER-LUMEN); the service
    // sends the mapped org ORG-ARMA-ALPHA -> cross-tenant binding rejection.
    const result = await service.activate({ armaOrgId: 'ARMA-ORG-A', capability: 'traffic_stop_privacy', bindingId: 'BIND-LUMEN-CROSS' });
    assert.equal(result.kind, 'REJECTED');
    assert.equal(result.errorCode, 'BINDING_ORG_MISMATCH');
    assert.equal(result.failureClass, 'TERMINAL');
    assert.equal(h.store.activationCount(), 0);
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('D2. entitlement rejection: INACTIVE entitlement -> TERMINAL ENTITLEMENT_INACTIVE', async () => {
  const h = await setup();
  try {
    const client = makeClient(h);
    const outcome = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'home_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-d2' });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.failureClass, 'TERMINAL');
    assert.equal(outcome.errorCode, 'ENTITLEMENT_INACTIVE');
    assert.equal(outcome.attempts.length, 1, 'terminal: no retries');
  } finally {
    await h.close();
  }
});

test('D3. capability rejection: capability not in the directory -> TERMINAL CAPABILITY_UNKNOWN', async () => {
  const h = await setup();
  try {
    const client = makeClient(h);
    // ENT-007 licenses telemetry_privacy but the capability is not registered:
    // entitlement passes, capability check fails.
    const outcome = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'telemetry_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-d3' });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.failureClass, 'TERMINAL');
    assert.equal(outcome.errorCode, 'CAPABILITY_UNKNOWN');
  } finally {
    await h.close();
  }
});

test('D4. invalid binding: INACTIVE -> BINDING_INACTIVE; unknown -> BINDING_UNKNOWN (both TERMINAL)', async () => {
  const h = await setup();
  try {
    const client = makeClient(h);
    const inactive = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP-INACTIVE', idempotencyKey: 'idem-d4a' });
    assert.equal(inactive.failureClass, 'TERMINAL');
    assert.equal(inactive.errorCode, 'BINDING_INACTIVE');
    const unknown = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-NO-SUCH', idempotencyKey: 'idem-d4b' });
    assert.equal(unknown.failureClass, 'TERMINAL');
    assert.equal(unknown.errorCode, 'BINDING_UNKNOWN');
  } finally {
    await h.close();
  }
});

test('D5. binding capability mismatch -> TERMINAL BINDING_CAPABILITY_MISMATCH', async () => {
  const h = await setup();
  try {
    const client = makeClient(h);
    const outcome = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-CAP-MISMATCH', idempotencyKey: 'idem-d5' });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.failureClass, 'TERMINAL');
    assert.equal(outcome.errorCode, 'BINDING_CAPABILITY_MISMATCH');
  } finally {
    await h.close();
  }
});

test('D6. local preflight fail-closed: not-entitled org -> REJECTED with zero outbound calls', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    const result = await service.activate({ armaOrgId: 'ARMA-ORG-DELTA', capability: 'traffic_stop_privacy', bindingId: 'BIND-DELTA-TSP' });
    assert.equal(result.kind, 'REJECTED');
    assert.equal(result.errorCode, 'ENTITLEMENT_NOT_ENTITLED');
    assert.equal(result.attempts, 0);
    assert.equal(h.store.activationCount(), 0, 'preflight rejected before any wire I/O');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('D7. local preflight: missing org mapping and paused mapping -> REJECTED before any outbound call', async () => {
  const h = await setup();
  try {
    const { service } = makeAdapter(h);
    const missing = await service.activate({ armaOrgId: 'ARMA-ORG-UNMAPPED', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP' });
    assert.equal(missing.kind, 'REJECTED');
    assert.equal(missing.errorCode, 'ORG_MAPPING_MISSING');
    assert.equal(missing.attempts, 0);
    const paused = await service.activate({ armaOrgId: 'ARMA-ORG-PAUSED', capability: 'traffic_stop_privacy', bindingId: 'BIND-DELTA-TSP' });
    assert.equal(paused.kind, 'REJECTED');
    assert.equal(paused.errorCode, 'ORG_MAPPING_PAUSED');
    assert.equal(h.store.activationCount(), 0);
  } finally {
    await h.close();
  }
});

test('D8. local preflight: capability version outside v1 -> REJECTED CAPABILITY_VERSION_UNSUPPORTED', async () => {
  const h = await setup();
  try {
    const { service } = makeAdapter(h);
    const result = await service.activate({ armaOrgId: 'ARMA-ORG-A', capability: 'telemetry_privacy', bindingId: 'BIND-ALPHA-TSP' });
    assert.equal(result.kind, 'REJECTED');
    assert.equal(result.errorCode, 'CAPABILITY_VERSION_UNSUPPORTED');
    assert.equal(result.attempts, 0);
    assert.equal(h.store.activationCount(), 0);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// E. Idempotency: duplicate collapse, conflict, no duplicate activation.
// ---------------------------------------------------------------------------

test('E1. duplicate collapse: second identical intent returns the SAME activation; exactly one create ever sent', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    const r1 = await service.activate(standardIntent);
    assert.equal(r1.kind, 'ACTIVATED');
    const r2 = await service.activate(standardIntent);
    assert.equal(r2.kind, 'DUPLICATE');
    assert.equal(r2.activationId, r1.activationId, 'same ARMA activation id — no duplicate activation');
    assert.equal(r2.duplicate, true);
    assert.equal(r2.attempts, 0, 'collapse happened locally: no second outbound create');
    assert.equal(h.store.activationCount(), 1, 'exactly one server-side activation');
    assert.equal(store.listRetries(r1.activationId).length, 1, 'exactly one recorded create attempt');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('E2. idempotency conflict: same key + different payload -> 409 IDEMPOTENCY_KEY_CONFLICT (TERMINAL)', async () => {
  const h = await setup();
  try {
    const client = makeClient(h);
    const body1 = { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-e2' };
    const r1 = await client.activate(body1);
    assert.equal(r1.ok, true);
    // Different payload that still passes the policy pipeline (binding on the
    // same org+capability) -> reaches the idempotency resolver -> 409.
    const body2 = { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-UNKNOWN-404', idempotencyKey: 'idem-e2' };
    const r2 = await client.activate(body2);
    assert.equal(r2.ok, false);
    assert.equal(r2.failureClass, 'TERMINAL');
    assert.equal(r2.errorCode, 'IDEMPOTENCY_KEY_CONFLICT');
    assert.equal(r2.httpStatus, 409);
    assert.ok(String(r2.body.existingActivationId).startsWith('ACT-'));
    assert.equal(r2.attempts.length, 1, 'terminal: never retried');
  } finally {
    await h.close();
  }
});

test('E3. server duplicate delivery: exact same idempotent create -> duplicate:true receipt, also verified', async () => {
  const h = await setup();
  try {
    const client = makeClient(h);
    const body = { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-e3' };
    const r1 = await client.activate(body);
    assert.equal(r1.ok, true);
    const r2 = await client.activate(body);
    assert.equal(r2.ok, true);
    assert.equal(r2.duplicate, true);
    assert.equal(r2.receiptVerified, true, 'duplicate receipt is verified over raw bytes too');
    assert.ok(r2.receipt.receiptId.startsWith('RCP-DUP-'));
    assert.equal(r2.receipt.activationId, r1.receipt.activationId, 'same server activation id');
  } finally {
    await h.close();
  }
});

test('E4. no duplicate activation: an in-flight intent from a crashed process owns the binding; a DIFFERENT caller key collapses via INTENT_KEY_MISMATCH (never a parallel send)', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    // Durable state left by a process that crashed after persisting the
    // intent (PENDING) but before completing the send: the in-flight intent
    // owns the binding. PATCHES does NOT dedupe by binding, so a parallel
    // send could double-activate server-side.
    const at = h.clock.now();
    const inflightId = 'ARMA-ACT-INFLIGHT-001';
    store.putActivation({
      activationId: inflightId, idempotencyKey: 'caller-key-original',
      armaOrgId: 'ARMA-ORG-A', patchesOrgId: 'ORG-ARMA-ALPHA',
      capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP',
      status: 'PENDING', createdAt: at, updatedAt: at,
    });
    store.putIdempotency({
      id: 'caller-key-original', idempotencyKey: 'caller-key-original',
      intentHash: 'synthetic-intent-hash-inflight', status: 'OPEN', createdAt: at, updatedAt: at,
    });

    const r2 = await service.activate({ ...standardIntent, idempotencyKey: 'caller-supplied-different-key' });
    assert.equal(r2.kind, 'DUPLICATE', 'collapse to the in-flight intent, never a parallel send');
    assert.equal(r2.activationId, inflightId);
    assert.equal(r2.errorCode, 'INTENT_KEY_MISMATCH', 'in-flight intent owns the binding; parallel send would double-activate');
    assert.equal(r2.attempts, 0, 'zero outbound attempts');
    assert.equal(h.store.activationCount(), 0, 'nothing reached PATCHES');
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// F. Retry / reconciliation (the owner amendment core).
// ---------------------------------------------------------------------------

test('F1. 429 bounded retry: first attempt rate-limited, retry with fresh nonce+signature succeeds; Retry-After honored', async () => {
  let checks = 0;
  const h = await setup({
    rateLimiter: { check: () => (checks++ === 0 ? { allowed: false, remaining: 0, retryAfterMs: 100 } : { allowed: true, remaining: 1 }) },
  });
  try {
    const { store, service } = makeAdapter(h);
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'ACTIVATED');
    assert.equal(result.status, 'ACTIVE');
    assert.equal(result.attempts, 2, 'one bounded retry after the 429');
    const [a1, a2] = store.listRetries(result.activationId).map((r) => JSON.parse(r.attemptRecordJson));
    assert.equal(a1.failureClass, 'CLEAN_RETRYABLE');
    assert.equal(a1.failureReason, 'RATE_LIMITED');
    assert.equal(a1.httpStatus, 429);
    assert.equal(a1.sleepBeforeNextMs, 100, 'server Retry-After honored (body retryAfterMs)');
    assert.notEqual(a1.nonce, a2.nonce, 'fresh nonce per attempt');
    assert.notEqual(a1.requestId, a2.requestId, 'fresh request id per attempt');
    assert.equal(a1.bodyHash, a2.bodyHash, 'stable payload hash across attempts (idempotency safety)');
    assert.equal(a2.signatureFreshByConstruction, undefined, 'signature is never recorded (by design)');
    assert.equal(a2.phase, 'VERIFIED');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('F2. clean 503 DOWNSTREAM_UNAVAILABLE (provably not processed) -> bounded retry succeeds', async () => {
  let calls = 0;
  const h = await setup({
    protectionService: { enqueueActivation: async () => (calls++ === 0 ? { ok: false, downstreamStatus: 'SYNTHETIC_DOWNSTREAM_DOWN' } : { ok: true, downstreamStatus: 'SYNTHETIC_OK' }) },
  });
  try {
    const client = makeClient(h);
    const outcome = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-f2' });
    assert.equal(outcome.ok, true, 'provably-not-processed 503 is clean-retried to success');
    assert.equal(outcome.attempts.length, 2);
    assert.equal(outcome.attempts[0].failureReason, 'DOWNSTREAM_UNAVAILABLE');
    assert.equal(outcome.attempts[0].httpStatus, 503);
    assert.equal(outcome.receiptVerified, true);
  } finally {
    await h.close();
  }
});

test('F3. ambiguous timeout (AbortError after possible delivery) -> RECONCILIATION_REQUIRED; reconcile resolves ACTIVE', async () => {
  const h = await setup();
  try {
    // The interference PROVES the server processed the create, then the client
    // times out anyway: the textbook ambiguous case.
    const { store, service } = makeAdapter(h, {
      fetchImpl: onceOnCreate(async (url, init) => {
        await fetch(url, init); // server processes + persists
        throw new DOMException('aborted', 'AbortError');
      }),
    });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'RECONCILIATION_REQUIRED');
    assert.equal(result.status, 'RECONCILIATION_REQUIRED');
    assert.equal(result.failureClass, 'AMBIGUOUS');
    assert.equal(result.failureReason, 'TIMEOUT');
    assert.ok(result.patchesActivationId.startsWith('ACT-req-'), 'stable identity hint from the first create attempt');
    assert.equal(result.attempts, 1, 'AMBIGUOUS: never retried');
    assert.equal(h.store.activationCount(), 1, 'server persisted the activation our client thought timed out');

    const recon = await service.reconcile(result.activationId);
    assert.equal(recon.status, 'RESOLVED_ACTIVE');
    assert.equal(recon.activationStatus, 'ACTIVE');
    const record = store.getActivation(result.activationId);
    assert.equal(record.status, 'ACTIVE');
    assert.equal(record.patchesActivationId, result.patchesActivationId);
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('F4. response lost after acceptance -> RECONCILIATION_REQUIRED; status reconciliation resolves ACTIVE', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h, {
      fetchImpl: onceOnCreate(async (url, init) => {
        const res = await fetch(url, init); // server processes + persists
        await res.arrayBuffer(); // consume (keep-alive hygiene) then drop it
        return {
          status: res.status, headers: res.headers,
          arrayBuffer: async () => { throw new Error('connection dropped mid-body'); },
        };
      }),
    });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'RECONCILIATION_REQUIRED');
    assert.equal(result.failureReason, 'CONNECTION_DROP', 'mid-body read drop: AMBIGUOUS (server may have persisted; receipt lost)');
    assert.equal(h.store.activationCount(), 1);
    const recon = await service.reconcile(result.activationId);
    assert.equal(recon.status, 'RESOLVED_ACTIVE');
    assert.equal(store.getActivation(result.activationId).status, 'ACTIVE');
  } finally {
    await h.close();
  }
});

test('F5. receipt signature failure -> AMBIGUOUS (processing may have occurred) -> RECONCILIATION_REQUIRED', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h, {
      fetchImpl: onceOnCreate(async (url, init) => {
        const res = await fetch(url, init);
        const raw = Buffer.from(await res.arrayBuffer());
        // Corrupt ONLY the receipt signature: body and content hash intact.
        const headers = new Headers(Object.fromEntries(res.headers));
        headers.set('x-patches-signature', 'deadbeef'.repeat(8));
        return new Response(raw, { status: res.status, headers });
      }),
    });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'RECONCILIATION_REQUIRED');
    assert.equal(result.failureReason, 'RECEIPT_INVALID_SIGNATURE');
    assert.equal(h.store.activationCount(), 1, 'server DID process — receipt integrity mismatch is ambiguous, not a retry');
    const recon = await service.reconcile(result.activationId);
    assert.equal(recon.status, 'RESOLVED_ACTIVE');
    assert.equal(store.getActivation(result.activationId).status, 'ACTIVE');
  } finally {
    await h.close();
  }
});

test('F6. receipt field mismatch (forged requestId) -> AMBIGUOUS -> RECONCILIATION_REQUIRED', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h, {
      fetchImpl: onceOnCreate(async (url, init) => {
        const res = await fetch(url, init);
        const raw = Buffer.from(await res.arrayBuffer());
        const obj = JSON.parse(raw.toString('utf8'));
        obj.requestId = 'req-forged-by-attacker'; // does not match our attempt's request id
        const raw2 = Buffer.from(JSON.stringify(obj));
        const { contentSha256, signature } = signReceiptBytes(raw2, RECEIPT_SECRET); // correctly re-signed garbage
        const headers = new Headers(Object.fromEntries(res.headers));
        headers.set('x-patches-content-sha256', contentSha256);
        headers.set('x-patches-signature', signature);
        return new Response(raw2, { status: res.status, headers });
      }),
    });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'RECONCILIATION_REQUIRED');
    assert.equal(result.failureReason, 'RECEIPT_FIELD_MISMATCH');
    const recon = await service.reconcile(result.activationId);
    assert.equal(recon.status, 'RESOLVED_ACTIVE');
    assert.equal(store.getActivation(result.activationId).status, 'ACTIVE');
  } finally {
    await h.close();
  }
});

test('F7. clean 500 PARTNER_PERSISTENCE_FAILED (provably rolled back) -> bounded retry, exhausted; fresh create with same key then succeeds', async () => {
  const h = await setup();
  try {
    h.store.failPoints.persistActivation = true;
    const client = makeClient(h);
    const exhausted = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-f7' });
    assert.equal(exhausted.ok, false);
    assert.equal(exhausted.failureClass, 'CLEAN_RETRYABLE');
    assert.equal(exhausted.failureReason, 'PERSISTENCE_ROLLED_BACK');
    assert.equal(exhausted.retriesExhausted, true);
    assert.equal(exhausted.attempts.length, 3, 'bounded: 1 initial + 2 retries');
    for (const a of exhausted.attempts) assert.equal(a.failureClass, 'CLEAN_RETRYABLE');
    assert.equal(h.store.activationCount(), 0, 'atomic rollback: nothing persisted');

    h.store.failPoints.persistActivation = false;
    const fresh = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-f7' });
    assert.equal(fresh.ok, true, 'fresh create with the SAME idempotency key succeeds after the rollback');
    assert.equal(fresh.duplicate, false, 'nothing had persisted, so this is a FRESH create, not a duplicate');
    assert.equal(fresh.receiptVerified, true);
  } finally {
    await h.close();
  }
});

test('F8. ambiguous status query during reconciliation stays in reconciliation (never blind re-send)', async () => {
  const h = await setup();
  try {
    // 1) Ambiguous create -> RECONCILIATION_REQUIRED.
    const { store, service } = makeAdapter(h, {
      fetchImpl: onceOnCreate(async (url, init) => {
        await fetch(url, init);
        throw new DOMException('aborted', 'AbortError');
      }),
    });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'RECONCILIATION_REQUIRED');

    // 2) The status query itself now fails ambiguously (drops once).
    let statusArmed = true;
    const dropping = makeAdapter(h, {
      store, // share the SAME durable state as the first adapter
      fetchImpl: async (url, init) => {
        const isStatus = (init?.method ?? 'GET') === 'GET' && new URL(url).pathname.startsWith(`${ACTIVATIONS_PATH}/`);
        if (statusArmed && isStatus) {
          statusArmed = false;
          throw new DOMException('aborted', 'AbortError');
        }
        return fetch(url, init);
      },
    });
    const recon1 = await dropping.service.reconcile(result.activationId);
    assert.equal(recon1.status, 'PENDING', 'ambiguous status query: stay in reconciliation');
    assert.equal(store.getActivation(result.activationId).status, 'RECONCILIATION_REQUIRED');
    const recons = store.listReconciliations(result.activationId);
    assert.equal(recons.length, 1);
    assert.equal(recons[0].status, 'OPEN');
    assert.equal(recons[0].resolution, 'PENDING');

    // 3) Next reconciliation attempt succeeds.
    const recon2 = await dropping.service.reconcile(result.activationId);
    assert.equal(recon2.status, 'RESOLVED_ACTIVE');
    assert.equal(store.getActivation(result.activationId).status, 'ACTIVE');
    // Exactly ONE create attempt was ever made across the whole flow.
    assert.equal(store.listRetries(result.activationId).filter((r) => r.operation === 'activation.create').length, 1);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// G. Lifecycle: deactivation, revocation, terminal revoked, replay, stale.
// ---------------------------------------------------------------------------

test('G1. deactivation then revocation: signed receipts verified -> DEACTIVATED -> REVOKED', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    const r = await service.activate(standardIntent);
    const d = await service.deactivate(r.activationId);
    assert.equal(d.ok, true);
    assert.equal(d.status, 'DEACTIVATED');
    assert.equal(d.outcome.receiptVerified, true);
    assert.equal(d.outcome.receipt.operation, 'activation.deactivate');
    assert.equal(store.getActivation(r.activationId).status, 'DEACTIVATED');
    // Idempotent no-op deactivate on an already-DEACTIVATED activation.
    const d2 = await service.deactivate(r.activationId);
    assert.equal(d2.ok, true);
    assert.equal(d2.status, 'DEACTIVATED');
    const rev = await service.revoke(r.activationId);
    assert.equal(rev.ok, true);
    assert.equal(rev.status, 'REVOKED');
    assert.equal(rev.outcome.receipt.operation, 'activation.revoke');
    assert.equal(store.getActivation(r.activationId).status, 'REVOKED');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('G2. terminal revoked: a revoked activation can NEVER reactivate silently (no outbound, no new server activation)', async () => {
  const h = await setup();
  try {
    const { store, service } = makeAdapter(h);
    const r = await service.activate(standardIntent);
    await service.revoke(r.activationId);
    const before = h.store.activationCount();
    const after = await service.activate(standardIntent);
    assert.equal(after.kind, 'QUARANTINED');
    assert.equal(after.status, 'REVOKED');
    assert.equal(after.duplicate, true);
    assert.equal(after.attempts, 0, 'no outbound create for a terminal intent');
    assert.equal(h.store.activationCount(), before, 'no new server-side activation');
    assert.equal(store.getActivation(after.activationId).status, 'REVOKED');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

test('G3. replay rejection: re-sending a used nonce+signature+timestamp -> 409 NONCE_REPLAYED (same key) / 401 (different key)', async () => {
  const h = await setup();
  try {
    const client = makeClient(h);
    const body = { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-g3' };
    const r1 = await client.activate(body);
    assert.equal(r1.ok, true);
    // Recompute the EXACT signed material of attempt 1 (the client never
    // records the signature itself — audit records are secret-free by design).
    const captured = r1.attempts[0];
    const rawBody = Buffer.from(JSON.stringify(body), 'utf8');
    const { createHash } = await import('node:crypto');
    const bodyHash = createHash('sha256').update(rawBody).digest('hex');
    assert.equal(bodyHash, captured.bodyHash, 'recomputed body hash matches the recorded attempt');
    const canonical = canonicalRequestString('POST', ACTIVATIONS_PATH, String(captured.timestamp), captured.nonce, bodyHash);
    const signature = computeRequestSignature(ARMA_SECRET(), canonical);
    const replay = await signedRequest(h.url, {
      method: 'POST', path: ACTIVATIONS_PATH, body,
      timestamp: captured.timestamp, nonce: captured.nonce, signature, clock: h.clock,
    });
    assert.equal(replay.status, 409);
    assert.equal(replay.json.error, 'NONCE_REPLAYED', 'exact replay (same nonce+body+key) is refused by the server nonce window');
    // Replay is refused even if the idempotency key changes (nonce owns the
    // window) — SP4 scenario 16 parity.
    const replay2 = await signedRequest(h.url, {
      method: 'POST', path: ACTIVATIONS_PATH,
      body: { ...body, idempotencyKey: 'idem-g3-other' },
      timestamp: captured.timestamp, nonce: captured.nonce, signature, clock: h.clock,
    });
    assert.equal(replay2.status, 409);
    assert.equal(replay2.json.error, 'NONCE_REPLAYED');
  } finally {
    await h.close();
  }
});

test('G4. stale request: timestamp outside the +/-5 min window -> TERMINAL TIMESTAMP_OUT_OF_WINDOW (client and service)', async () => {
  const h = await setup();
  try {
    const staleNow = () => h.clock.now() - 10 * 60 * 1000;
    const client = makeClient(h, { now: staleNow });
    const outcome = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-g4' });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.failureClass, 'TERMINAL');
    assert.equal(outcome.errorCode, 'TIMESTAMP_OUT_OF_WINDOW');
    assert.equal(outcome.attempts.length, 1);

    const { store, service } = makeAdapter(h, { client: makeClient(h, { now: staleNow }) });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'QUARANTINED', 'auth-like terminal: operator must fix the clock/config');
    assert.equal(result.errorCode, 'TIMESTAMP_OUT_OF_WINDOW');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// H. Kill switches (fail-closed in both directions).
// ---------------------------------------------------------------------------

test('H1. ARMA outbound kill switch (ARMA_PATCHES_OUTBOUND_DISABLED) -> QUARANTINED, zero wire I/O, nothing at PATCHES', async () => {
  const h = await setup();
  try {
    process.env[ARMA_OUTBOUND_KILL_SWITCH_ENV] = 'true';
    // Client-level: every operation is BLOCKED before any socket I/O.
    const client = makeClient(h);
    const blocked = await client.activate({ orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-h1' });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.failureClass, 'TERMINAL');
    assert.equal(blocked.errorCode, 'ARMA_OUTBOUND_DISABLED');
    assert.equal(blocked.attempts[0].phase, 'BLOCKED');

    // Service-level: the intent is quarantined for manual intervention.
    const store = armaStoreFixture(h.clock);
    const service = new ArmaActivationService({
      store, client, now: h.clock.now,
      outboundDisabled: () => true,
      secretsForRedaction: () => [ARMA_SECRET(), RECEIPT_SECRET],
    });
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'QUARANTINED');
    assert.equal(result.errorCode, 'ARMA_OUTBOUND_DISABLED');
    assert.equal(h.store.activationCount(), 0, 'nothing reached PATCHES');
    const record = store.getActivation(result.activationId);
    assert.equal(record.status, 'QUARANTINED');
    assert.equal(record.quarantineReason, 'ARMA_OUTBOUND_DISABLED');
    assertNoSecretsInStore(store);
  } finally {
    delete process.env[ARMA_OUTBOUND_KILL_SWITCH_ENV];
    await h.close();
  }
});

test('H2. PATCHES kill switch (PATCHES_PARTNER_API_DISABLED) -> 503 provably unprocessed -> bounded clean retries -> QUARANTINED', async () => {
  const h = await setup();
  try {
    process.env.PATCHES_PARTNER_API_DISABLED = 'true';
    const { store, service } = makeAdapter(h);
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'QUARANTINED');
    assert.equal(result.errorCode, 'PARTNER_API_DISABLED');
    assert.equal(result.failureClass, 'CLEAN_RETRYABLE');
    assert.equal(result.failureReason, 'PATCHES_API_DISABLED');
    assert.equal(result.attempts, 3, 'bounded clean retries before quarantining for operator decision');
    const record = store.getActivation(result.activationId);
    assert.equal(record.quarantineReason, 'RETRIES_EXHAUSTED');
    assert.equal(h.store.activationCount(), 0, 'kill switch proves nothing was processed');
    assertNoSecretsInStore(store);
  } finally {
    delete process.env.PATCHES_PARTNER_API_DISABLED;
    await h.close();
  }
});

test('H3. PATCHES downstream unavailable (fail-closed) -> provably not processed -> bounded clean retries exhausted -> QUARANTINED', async () => {
  const h = await setup({ protectionService: { enqueueActivation: async () => ({ ok: false, downstreamStatus: 'SYNTHETIC_DOWNSTREAM_DOWN' }) } });
  try {
    const { store, service } = makeAdapter(h);
    const result = await service.activate(standardIntent);
    assert.equal(result.kind, 'QUARANTINED');
    assert.equal(result.errorCode, 'DOWNSTREAM_UNAVAILABLE');
    assert.equal(result.failureClass, 'CLEAN_RETRYABLE');
    assert.equal(result.attempts, 3);
    assert.equal(store.getActivation(result.activationId).quarantineReason, 'RETRIES_EXHAUSTED');
    assert.equal(h.store.activationCount(), 0, 'downstream check fails closed: zero partial state server-side');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// I. Wrong-org reconciliation resolver denied (tenant-scoped identity).
// ---------------------------------------------------------------------------

test('I1. wrong-org reconciliation resolver denied: querying another partner activation -> 403 -> QUARANTINED, never re-sent', async () => {
  const h = await setup();
  try {
    // A LUMEN-owned activation exists server-side (foreign tenant).
    const lumen = await signedRequest(h.url, {
      method: 'POST', path: ACTIVATIONS_PATH,
      body: { orgId: 'ORG-LUMEN-GAMMA', capability: 'home_privacy', bindingId: 'BIND-LUMEN-CROSS', idempotencyKey: 'idem-lumen-i1' },
      clientId: 'lumen-client', keyId: 'lumen-key-1', clock: h.clock,
    });
    assert.equal(lumen.status, 200);
    const lumenActivationId = lumen.json.activationId;

    const { store, service } = makeAdapter(h);
    const r = await service.activate(standardIntent);
    assert.equal(r.kind, 'ACTIVATED');

    // Simulate an ambiguous state whose recorded identity points at the
    // FOREIGN activation (mis-recorded identity / cross-tenant data): the
    // resolver must be denied by PATCHES tenant scoping.
    const rec = store.getActivation(r.activationId);
    store.putActivation({ ...rec, status: 'RECONCILIATION_REQUIRED', patchesActivationId: lumenActivationId });

    const recon = await service.reconcile(r.activationId);
    assert.equal(recon.status, 'RESOLVED_TERMINAL');
    assert.equal(recon.activationStatus, 'QUARANTINED');
    const record = store.getActivation(r.activationId);
    assert.equal(record.status, 'QUARANTINED');
    assert.equal(record.quarantineReason, 'RECONCILIATION_ACCESS_DENIED');
    const recons = store.listReconciliations(r.activationId);
    assert.equal(recons.at(-1).resolution, 'ACCESS_DENIED');
    // NEVER a blind re-send: exactly one create attempt ever made.
    assert.equal(store.listRetries(r.activationId).filter((x) => x.operation === 'activation.create').length, 1);
    assert.equal(h.store.activationCount(), 2, 'only the original ARMA activation + the LUMEN one: no re-send created anything');
    assertNoSecretsInStore(store);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// J. Full synthetic E2E.
// ---------------------------------------------------------------------------

test('J1. full synthetic E2E: adapter -> signed request -> real SP4 server -> activation -> signed raw receipt -> ARMA verification -> ACTIVE -> status sync -> deactivate -> revoke', async () => {
  const h = await setup();
  try {
    const { store, service, client } = makeAdapter(h);

    // 1) Preflight over signed GET routes.
    const caps = await client.listCapabilities();
    assert.equal(caps.ok, true);
    assert.ok(caps.body.capabilities.some((c) => c.capability === 'traffic_stop_privacy'));
    const ents = await client.listEntitlements('ORG-ARMA-ALPHA');
    assert.equal(ents.ok, true);
    assert.ok(ents.body.entitlements.some((e) => e.capability === 'traffic_stop_privacy' && e.status === 'ACTIVE'));

    // 2) Signed activation through the durable state machine.
    const r = await service.activate(standardIntent);
    assert.equal(r.kind, 'ACTIVATED');
    assert.equal(r.status, 'ACTIVE');
    const record = store.getActivation(r.activationId);
    assert.equal(record.patchesActivationId, r.patchesActivationId);
    assert.ok(record.patchesActivationId.startsWith('ACT-req-'));

    // 3) Raw-byte receipt verification is what moved us to ACTIVE.
    assert.equal(r.attempts, 1);
    const verified = store.audit.find((e) => e.operation === 'activation.receipt.verified');
    assert.ok(verified);
    assert.ok(store.getReceipt(verified.detail.receiptId));

    // 4) Status synchronization (signed GET) confirms ACTIVE.
    const sync = await service.syncStatus(r.activationId);
    assert.equal(sync.status, 'ACTIVE');
    assert.equal(sync.errorCode, null);

    // 5) Reconcile on a resolved activation is a no-op (not in reconciliation).
    const recon = await service.reconcile(r.activationId);
    assert.equal(recon.status, 'PENDING');
    assert.equal(recon.detail, 'not in reconciliation');

    // 6) Deactivate: signed receipt verified -> DEACTIVATED (idempotent no-op on repeat).
    const d = await service.deactivate(r.activationId);
    assert.equal(d.ok, true);
    assert.equal(d.status, 'DEACTIVATED');
    assert.equal(d.outcome.receipt.operation, 'activation.deactivate');
    const d2 = await service.deactivate(r.activationId);
    assert.equal(d2.ok, true);
    assert.equal(d2.status, 'DEACTIVATED');

    // 7) Status sync re-aligns local state with the server.
    const sync2 = await service.syncStatus(r.activationId);
    assert.equal(sync2.status, 'DEACTIVATED');

    // 8) Revoke: terminal, signed receipt verified.
    const rev = await service.revoke(r.activationId);
    assert.equal(rev.ok, true);
    assert.equal(rev.status, 'REVOKED');
    assert.equal(rev.outcome.receipt.operation, 'activation.revoke');

    // 9) REVOKED is terminal: no silent reactivation.
    const after = await service.activate(standardIntent);
    assert.equal(after.kind, 'QUARANTINED');
    assert.equal(after.status, 'REVOKED');
    assert.equal(after.duplicate, true);

    // 10) No secrets anywhere in the durable state, across the whole lifecycle.
    assertNoSecretsInStore(store);

    // 11) The audit chain covers the full lifecycle.
    const ops = store.audit.map((e) => e.operation);
    for (const op of [
      'activation.intent.created', 'activation.state.ready_to_activate', 'activation.state.activation_sent',
      'activation.receipt.verified', 'activation.deactivate', 'activation.revoke',
    ]) {
      assert.ok(ops.includes(op), `audit op present: ${op}`);
    }
    assert.equal(h.store.activationCount(), 1, 'exactly one server-side activation for the whole E2E');
  } finally {
    await h.close();
  }
});
