// Stop Point 7 — shared SDK structured-error tests.
//
// Proves the shared structured error contract: a stable machine code, a
// coarse error CLASS routing vocabulary, an HTTP status, a retryable flag,
// and safe partner-visible context where allowlisted keys only, scalar
// values only, and bounded string lengths structurally prevent payload
// content, secrets, and free-form detail from reaching partners.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  StructuredError,
  errorClassForCode,
  safeContextFor,
  isRetryableCode,
  isAmbiguousCode,
  isTerminalCode,
  ERROR_CLASSES,
} from '../sdk/errors.ts';

// --- Classification ---

test('errorClassForCode routes each family to its coarse class', () => {
  assert.equal(errorClassForCode('AUTH_MISSING'), 'AUTHENTICATION');
  assert.equal(errorClassForCode('PARTNER_UNKNOWN'), 'AUTHENTICATION');
  assert.equal(errorClassForCode('ORG_NOT_BOUND_TO_PARTNER'), 'AUTHORIZATION');
  assert.equal(errorClassForCode('CAPABILITY_VERSION_UNSUPPORTED'), 'AUTHORIZATION');
  assert.equal(errorClassForCode('VERSION_OUT_OF_CAPABILITY_WINDOW'), 'VERSION');
  assert.equal(errorClassForCode('INPUT_MALFORMED'), 'INPUT');
  assert.equal(errorClassForCode('ENTITY_UNKNOWN'), 'NOT_FOUND');
  assert.equal(errorClassForCode('ENTITY_STATE_CONFLICT'), 'STATE');
  assert.equal(errorClassForCode('IDEMPOTENCY_KEY_CONFLICT'), 'IDEMPOTENCY');
  assert.equal(errorClassForCode('REPLAY_DETECTED'), 'REPLAY');
  assert.equal(errorClassForCode('RATE_LIMITED'), 'RATE_LIMIT');
  assert.equal(errorClassForCode('DOWNSTREAM_UNAVAILABLE'), 'DOWNSTREAM');
  assert.equal(errorClassForCode('PERSISTENCE_FAILED'), 'PERSISTENCE');
  assert.equal(errorClassForCode('CIRCUIT_OPEN'), 'UNAVAILABLE');
  assert.equal(errorClassForCode('TRANSPORT_ERROR'), 'TRANSPORT');
});

test('receipt and partner-request failures route to the partner-outbound families', () => {
  assert.equal(errorClassForCode('RECEIPT_VERIFICATION_FAILED'), 'TRANSPORT');
  assert.equal(errorClassForCode('PARTNER_REQUEST_FAILED'), 'DOWNSTREAM');
});

test('ERROR_CLASSES is the fixed coarse vocabulary', () => {
  assert.equal(ERROR_CLASSES.length, 13);
});

// --- Retry semantics ---

test('CLEAN-RETRYABLE ONLY: transport-level failures are auto-retryable', () => {
  assert.equal(isRetryableCode('TRANSPORT_ERROR'), true);
  assert.equal(isRetryableCode('DOWNSTREAM_UNAVAILABLE'), true);
  assert.equal(isRetryableCode('UNAVAILABLE'), true);
});

test('ambiguous outcomes are never auto-retried (retry-vs-reconcile)', () => {
  assert.equal(isRetryableCode('CIRCUIT_OPEN'), false);
  assert.equal(isRetryableCode('WEBHOOK_DELIVERY_FAILED'), false);
  assert.equal(isRetryableCode('RECEIPT_VERIFICATION_FAILED'), false);
  assert.equal(isAmbiguousCode('CIRCUIT_OPEN'), true);
  assert.equal(isAmbiguousCode('RECEIPT_VERIFICATION_FAILED'), true);
  assert.equal(isAmbiguousCode('TRANSPORT_ERROR'), false);
});

// --- StructuredError shape ---

test('StructuredError carries code, class, status, retryable, requestId', () => {
  const e = new StructuredError({ code: 'TRANSPORT_ERROR', requestId: 'req-test-0001' });
  assert.equal(e.code, 'TRANSPORT_ERROR');
  assert.equal(e.errorClass, 'TRANSPORT');
  assert.equal(e.status, 502);
  assert.equal(e.retryable, true);
  assert.equal(e.requestId, 'req-test-0001');
});

test('retryable defaults to the code classification', () => {
  assert.equal(new StructuredError({ code: 'PARTNER_UNKNOWN' }).retryable, false);
  assert.equal(new StructuredError({ code: 'TRANSPORT_ERROR' }).retryable, true);
});

test('explicit status and retryable override the defaults', () => {
  const e = new StructuredError({ code: 'TRANSPORT_ERROR', status: 429, retryable: false });
  assert.equal(e.status, 429);
  assert.equal(e.retryable, false);
});

// --- Safe context discipline ---

test('safeContextFor keeps allowlisted scalar keys and drops everything else', () => {
  const clean = safeContextFor({
    requestId: 'req-ok-0001',
    partnerId: 'partner-sandbox-1',
    apiKey: 'synthetic-secret', // not allowlisted
    blob: { a: 1 }, // not scalar
  });
  assert.deepEqual(clean, { requestId: 'req-ok-0001', partnerId: 'partner-sandbox-1' });
});

test('safeContextFor bounds string values to 256 chars', () => {
  const clean = safeContextFor({ requestId: 'x'.repeat(300) });
  assert.deepEqual(clean, {});
});

test('safeContextFor returns an empty object for absent context', () => {
  assert.deepEqual(safeContextFor(undefined), {});
  assert.deepEqual(safeContextFor(null), {});
});

test('safeContextFor returns a new object (no aliasing)', () => {
  const src = { requestId: 'req-alias-0001' };
  const out = safeContextFor(src);
  assert.notEqual(out, src);
  out.requestId = 'mutated';
  assert.equal(src.requestId, 'req-alias-0001');
  assert.notEqual(out.requestId, 'req-alias-0001');
});

// --- Partner-visible response body ---

test('toResponse emits exactly the safe partner-visible body', () => {
  const e = new StructuredError({
    code: 'PARTNER_UNKNOWN',
    requestId: 'req-shape-0001',
    context: {
      partnerId: 'partner-sandbox-1',
      token: 'synthetic-token', // not allowlisted — must not appear
      blob: [1, 2, 3], // non-scalar — must not appear
    },
  });
  assert.deepEqual(e.toResponse(), {
    error: 'PARTNER_UNKNOWN',
    errorClass: 'AUTHENTICATION',
    requestId: 'req-shape-0001',
    partnerId: 'partner-sandbox-1',
  });
});

test('toResponse omits requestId when none was supplied', () => {
  const body = new StructuredError({ code: 'INPUT_MALFORMED' }).toResponse();
  assert.deepEqual(body, { error: 'INPUT_MALFORMED', errorClass: 'INPUT' });
});

test('terminal codes fail closed and are never retryable', () => {
  for (const code of ['AUTH_MISSING', 'PARTNER_UNKNOWN', 'CAPABILITY_UNKNOWN', 'VERSION_UNKNOWN', 'INPUT_MALFORMED', 'REPLAY_DETECTED', 'WEBHOOK_DEAD_LETTERED']) {
    assert.equal(isTerminalCode(code), true, code);
    assert.equal(isRetryableCode(code), false, code);
  }
});
