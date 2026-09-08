// Stop Point 7 — shared SDK composed client tests.
//
// Proves the composed call flow: buildRequest signs a canonical request with
// the full x-shared-* header set and a generated/echoed request id;
// processResponse trusts a 2xx ONLY behind a byte-exact verified receipt
// (else fails closed as RECEIPT_VERIFICATION_FAILED) and parses structured
// errors from non-2xx bodies; planRetry routes clean-retryable only.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PartnerSdkClient,
  SDK_TIMESTAMP_HEADER,
  SDK_NONCE_HEADER,
  SDK_SIGNATURE_HEADER,
  SDK_BODY_HASH_HEADER,
  SDK_API_VERSION_HEADER,
  SDK_PARTNER_HEADER,
} from '../sdk/client.ts';
import { signReceiptBytes, DEFAULT_RECEIPT_HEADERS, RECEIPT_SCHEMA_VERSION } from '../sdk/receipts.ts';
import { verifyCanonicalRequestSignature } from '../sdk/canonical.ts';
import { PARTNER_SECRET, RECEIPT_SECRET, makeClock, validNonce } from './helpers.mjs';
import { REQUEST_ID_HEADER } from '../sdk/correlation.ts';

const { clock, now, advance } = makeClock(1_700_000_000_000);

function makeClient(overrides = {}) {
  return new PartnerSdkClient({
    partnerId: 'partner-sandbox-1',
    secret: PARTNER_SECRET,
    receiptSecret: RECEIPT_SECRET,
    now,
    nonceSource: () => validNonce('client'),
    ...overrides,
  });
}

function receiptBody(overrides = {}) {
  return {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    receiptId: 'rcpt-client-0001',
    requestId: 'req-client-0001',
    partnerId: 'partner-sandbox-1',
    operation: 'activation.create',
    outcome: 'SUCCESS',
    at: now(),
    entityRef: 'entity-activation-001',
    ...overrides,
  };
}

function signedReceipt(bodyOverrides = {}) {
  const body = receiptBody(bodyOverrides);
  const raw = Buffer.from(JSON.stringify(body), 'utf8');
  const { contentSha256, signature } = signReceiptBytes(raw, RECEIPT_SECRET);
  return { raw, headers: { ...signedHeaders(body.receiptId, contentSha256, signature) }, body };
}

function signedHeaders(receiptId, contentSha256, signature) {
  return {
    [DEFAULT_RECEIPT_HEADERS.receiptId]: receiptId,
    [DEFAULT_RECEIPT_HEADERS.contentSha256]: contentSha256,
    [DEFAULT_RECEIPT_HEADERS.signature]: signature,
    [REQUEST_ID_HEADER]: 'req-client-0001',
  };
}

// --- Construction ---

test('client rejects malformed options (fail closed)', () => {
  assert.throws(() => new PartnerSdkClient({}), /SDK_PARTNER_ID_REQUIRED/);
  assert.throws(() => new PartnerSdkClient({ partnerId: ' ', secret: 'x' }), /SDK_PARTNER_ID_REQUIRED/);
  assert.throws(() => new PartnerSdkClient({ partnerId: 'p', secret: '' }), /SDK_SECRET_REQUIRED/);
  assert.throws(() => new PartnerSdkClient(null), /SDK_CLIENT_OPTIONS_REQUIRED/);
});

// --- buildRequest ---

test('buildRequest produces the full signed x-shared-* header set', () => {
  const client = makeClient();
  const built = client.buildRequest({ method: 'POST', path: '/v1/activations', body: '{"k":1}' });
  assert.equal(built.method, 'POST');
  assert.equal(built.path, '/v1/activations');
  assert.equal(built.headers[SDK_TIMESTAMP_HEADER], String(now()));
  assert.equal(built.headers[SDK_NONCE_HEADER], validNonce('client'));
  assert.equal(built.headers[SDK_PARTNER_HEADER], 'partner-sandbox-1');
  assert.equal(built.headers[SDK_API_VERSION_HEADER], 'v1');
  assert.equal(built.headers[SDK_BODY_HASH_HEADER], built.bodyHash);
  assert.equal(built.headers[SDK_SIGNATURE_HEADER].length, 64);
  assert.equal(Object.isFrozen(built.headers), true);
});

test('buildRequest signs the body EXACTLY as provided (no re-serialization)', () => {
  const client = makeClient();
  const exact = '{"a":1,"b":2}';
  const built = client.buildRequest({ method: 'POST', path: '/v1/x', body: Buffer.from(exact, 'utf8') });
  const v = verifyCanonicalRequestSignature({
    method: 'POST',
    path: '/v1/x',
    timestamp: String(built.timestamp),
    nonce: built.nonce,
    bodyHash: built.bodyHash,
    providedSignature: built.headers[SDK_SIGNATURE_HEADER],
    secret: PARTNER_SECRET,
    now: now(),
  });
  assert.equal(v.ok, true);
});

test('the server can verify a client-built request via verifySignature', () => {
  const client = makeClient();
  const built = client.buildRequest({ method: 'post', path: '/v1/y', body: 'payload-bytes' });
  // method is normalized to upper case in the canonical form
  const server = client.verifySignature({
    method: 'post',
    path: '/v1/y',
    timestamp: String(built.timestamp),
    nonce: built.nonce,
    bodyHash: built.bodyHash,
    providedSignature: built.headers[SDK_SIGNATURE_HEADER],
  });
  assert.equal(server.ok, true);
});

test('buildRequest echoes a valid caller request id and generates when absent', () => {
  const client = makeClient();
  const echoed = client.buildRequest({ method: 'GET', path: '/v1/z', requestId: 'caller-id-0001' });
  assert.equal(echoed.requestId, 'caller-id-0001');
  const generated = client.buildRequest({ method: 'GET', path: '/v1/z' });
  assert.match(generated.requestId, /^req-/);
  const malformed = client.buildRequest({ method: 'GET', path: '/v1/z', requestId: 'bad id!' });
  assert.match(malformed.requestId, /^req-/); // fail-safe: generated, not failed
});

test('buildRequest fails closed on malformed input', () => {
  const client = makeClient();
  assert.throws(() => client.buildRequest(null), /SDK_BUILD_INPUT_INVALID/);
  assert.throws(() => client.buildRequest({ method: '', path: '/x' }), /SDK_METHOD_INVALID/);
  assert.throws(() => client.buildRequest({ method: 'GET', path: 'no-slash' }), /SDK_PATH_INVALID/);
});

test('an empty body is signed as zero bytes', () => {
  const client = makeClient();
  const built = client.buildRequest({ method: 'POST', path: '/v1/empty' });
  assert.equal(built.rawBody.length, 0);
  assert.equal(built.bodyHash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

// --- processResponse ---

test('a 2xx behind a verified receipt is trusted', () => {
  const client = makeClient();
  const { raw, headers } = signedReceipt();
  const r = client.processResponse({
    status: 200,
    rawBody: raw,
    headers,
    expected: { requestId: 'req-client-0001', operation: 'activation.create', outcome: 'SUCCESS' },
  });
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  assert.ok(r.receipt);
  assert.equal(r.receipt.receiptId, 'rcpt-client-0001');
});

test('a 2xx without a receipt FAILS CLOSED (never trust an unsigned success)', () => {
  const client = makeClient();
  const body = receiptBody();
  const r = client.processResponse({
    status: 200,
    rawBody: Buffer.from(JSON.stringify(body), 'utf8'),
    headers: { [REQUEST_ID_HEADER]: 'req-client-0001' },
    expected: { operation: 'activation.create' },
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'RECEIPT_VERIFICATION_FAILED');
  assert.equal(r.error.errorClass, 'TRANSPORT');
  assert.equal(r.error.status, 502);
});

test('a 2xx with a tampered receipt fails closed', () => {
  const client = makeClient();
  const { raw } = signedReceipt();
  const r = client.processResponse({
    status: 200,
    rawBody: raw.subarray(0, raw.length - 2), // truncated mid-JSON
    headers: signedHeaders('rcpt-client-0001', '0'.repeat(64), '0'.repeat(64)),
    expected: { operation: 'activation.create' },
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'RECEIPT_VERIFICATION_FAILED');
});

test('a receipt proving the WRONG operation is rejected (binding)', () => {
  const client = makeClient();
  const { raw, headers } = signedReceipt({ operation: 'transfer.send' });
  const r = client.processResponse({
    status: 200,
    rawBody: raw,
    headers,
    expected: { operation: 'activation.create' },
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'RECEIPT_VERIFICATION_FAILED');
});

test('non-2xx parses a structured error body', () => {
  const client = makeClient();
  const r = client.processResponse({
    status: 403,
    rawBody: Buffer.from(JSON.stringify({ error: 'CAPABILITY_UNKNOWN', requestId: 'req-remote-0001' })),
    headers: {},
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'CAPABILITY_UNKNOWN');
  assert.equal(r.error.requestId, 'req-remote-0001');
  assert.equal(r.requestId, null);
});

test('a non-JSON non-2xx body falls back to PARTNER_REQUEST_FAILED', () => {
  const client = makeClient();
  const r = client.processResponse({
    status: 500,
    rawBody: 'Internal Server Error',
    headers: {},
  });
  assert.equal(r.ok, false);
  assert.equal(r.error.code, 'PARTNER_REQUEST_FAILED');
  assert.equal(r.error.errorClass, 'DOWNSTREAM');
  assert.equal(r.error.status, 500);
});

// --- planRetry ---

test('planRetry routes clean-retryable codes to CLEAN_RETRY with backoff', () => {
  const client = makeClient();
  const plan = client.planRetry('TRANSPORT_ERROR', 0);
  assert.equal(plan.kind, 'CLEAN_RETRY');
  assert.deepEqual(plan.classification, { retryable: true, ambiguous: false, cleanRetryable: true });
  assert.equal(plan.backoff.delayMs, 1_000);
});

test('planRetry routes ambiguous codes to AMBIGUOUS_RECONCILE (never blind re-send)', () => {
  const client = makeClient();
  for (const code of ['CIRCUIT_OPEN', 'WEBHOOK_DELIVERY_FAILED', 'PERSISTENCE_FAILED']) {
    const plan = client.planRetry(code, 0);
    assert.equal(plan.kind, 'AMBIGUOUS_RECONCILE', code);
  }
});

test('planRetry routes terminal codes to TERMINAL', () => {
  const client = makeClient();
  const plan = client.planRetry('PARTNER_UNKNOWN', 0);
  assert.equal(plan.kind, 'TERMINAL');
  assert.deepEqual(plan.classification, { retryable: false, ambiguous: false, cleanRetryable: false });
});

test('planRetry reports EXHAUSTED past the schedule bound', () => {
  const client = makeClient();
  const plan = client.planRetry('TRANSPORT_ERROR', 5);
  assert.equal(plan.kind, 'EXHAUSTED');
  assert.equal(plan.attempts, 5);
});

// --- classifyFailure passthrough ---

test('classifyFailure exposes the shared classification', () => {
  const client = makeClient();
  assert.deepEqual(client.classifyFailure('TRANSPORT_ERROR'), { retryable: true, ambiguous: false, cleanRetryable: true });
  assert.deepEqual(client.classifyFailure('PERSISTENCE_FAILED'), { retryable: true, ambiguous: true, cleanRetryable: false });
});
