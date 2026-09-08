// Stop Point 7 — secure webhook/event framework tests.
//
// Proves the signed-envelope contract: metadata-only envelopes, HMAC over
// exact bytes, replay guard (nonce + event ID), strict per-stream sequence
// ordering, and the retry-vs-reconcile delivery service with duplicate
// collapse and dead-lettering.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  WEBHOOK_SCHEMA_VERSION,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_HEADERS,
  buildWebhookEnvelope,
  validateWebhookEnvelope,
  signWebhookEnvelope,
  verifyWebhook,
  WebhookEventGuard,
} from '../webhooks/events.ts';
import { WebhookDeliveryService } from '../webhooks/delivery.ts';
import { WEBHOOK_SECRET, makeClock, validNonce } from './helpers.mjs';

const { clock, now, advance } = makeClock(1_700_000_000_000);

const BASE = {
  eventType: 'resource.status.changed',
  stream: 'partner-sandbox-1',
  sequence: 1,
  at: now(),
  partnerId: 'partner-sandbox-1',
  orgRef: 'org-sandbox-1',
  requestId: 'req-webhook-0001',
  data: { entityRef: 'entity-activation-001', status: 'ACTIVE' },
};

function envelope(overrides = {}) {
  // `at` is taken fresh from the clock so tests that advance time keep the
  // envelope inside the skew window.
  return buildWebhookEnvelope({ ...BASE, at: now(), ...overrides });
}

function signed(overrides = {}, nonce = validNonce('evt')) {
  return signWebhookEnvelope(envelope(overrides), WEBHOOK_SECRET, nonce);
}

// --- Envelope construction ---

test('WEBHOOK_EVENT_TYPES is the fixed metadata-only vocabulary', () => {
  assert.deepEqual([...WEBHOOK_EVENT_TYPES], [
    'resource.status.changed', 'processing.completed', 'processing.failed',
    'entitlement.changed', 'entitlement.revoked', 'reconciliation.required',
    'reconciliation.completed',
  ]);
});

test('buildWebhookEnvelope creates a frozen metadata-only envelope', () => {
  const env = envelope();
  assert.equal(env.schemaVersion, WEBHOOK_SCHEMA_VERSION);
  assert.match(env.eventId, /^evt-[0-9a-f-]{36}$/);
  assert.equal(env.eventType, 'resource.status.changed');
  assert.equal(env.stream, 'partner-sandbox-1');
  assert.equal(env.sequence, 1);
  assert.equal(env.partnerId, 'partner-sandbox-1');
  assert.deepEqual({ ...env.data }, { entityRef: 'entity-activation-001', status: 'ACTIVE' });
  assert.equal(Object.isFrozen(env), true);
  assert.equal(Object.isFrozen(env.data), true);
});

test('buildWebhookEnvelope fails closed on every defect', () => {
  assert.throws(() => envelope({ eventType: 'not.a.type' }), /WEBHOOK_EVENT_TYPE_UNKNOWN/);
  assert.throws(() => envelope({ stream: '' }), /WEBHOOK_STREAM_INVALID/);
  assert.throws(() => envelope({ sequence: 0 }), /WEBHOOK_SEQUENCE_INVALID/);
  assert.throws(() => envelope({ sequence: 1.5 }), /WEBHOOK_SEQUENCE_INVALID/);
  assert.throws(() => envelope({ at: NaN }), /WEBHOOK_TIMESTAMP_INVALID/);
  assert.throws(() => envelope({ partnerId: '' }), /WEBHOOK_PARTNER_INVALID/);
  assert.throws(() => envelope({ data: { payload: 'leak' } }), /WEBHOOK_DATA_KEY_UNSAFE/);
  assert.throws(() => envelope({ data: { status: 'x'.repeat(300) } }), /WEBHOOK_DATA_VALUE_INVALID/);
  assert.throws(() => envelope({ data: { status: { nested: true } } }), /WEBHOOK_DATA_VALUE_INVALID/);
});

test('validateWebhookEnvelope accepts a built envelope and rejects defects', () => {
  const env = envelope();
  assert.equal(validateWebhookEnvelope(env).ok, true);
  const bad = { ...env, schemaVersion: 'other-v9' };
  assert.equal(validateWebhookEnvelope(bad).ok, false);
});

// --- Signing + verification ---

test('sign + verify round trip over exact bytes', () => {
  const s = signed();
  const v = verifyWebhook({ rawBody: s.rawBody, headers: s.headers, secret: WEBHOOK_SECRET, now: now() });
  assert.equal(v.ok, true);
});

test('signing requires a secret and a well-formed nonce', () => {
  assert.throws(() => signWebhookEnvelope(envelope(), '', validNonce('x')), /WEBHOOK_SECRET_REQUIRED/);
  assert.throws(() => signWebhookEnvelope(envelope(), WEBHOOK_SECRET, 'short'), /WEBHOOK_NONCE_INVALID/);
});

test('verify fails closed when headers are missing', () => {
  const s = signed();
  for (const key of Object.values(WEBHOOK_HEADERS)) {
    const headers = { ...s.headers };
    delete headers[key];
    const v = verifyWebhook({ rawBody: s.rawBody, headers, secret: WEBHOOK_SECRET, now: now() });
    assert.equal(v.ok, false, key);
    if (!v.ok) assert.equal(v.code, 'WEBHOOK_MISSING_HEADERS', key);
  }
});

test('verify fails closed on body-hash and signature tampering', () => {
  const s = signed();
  const tamperedBody = verifyWebhook({ rawBody: s.rawBody.subarray(0, s.rawBody.length - 2), headers: s.headers, secret: WEBHOOK_SECRET, now: now() });
  assert.equal(tamperedBody.ok, false);
  if (!tamperedBody.ok) assert.equal(tamperedBody.code, 'WEBHOOK_SIGNATURE_INVALID');
  const badSig = verifyWebhook({ rawBody: s.rawBody, headers: { ...s.headers, [WEBHOOK_HEADERS.signature]: '0'.repeat(64) }, secret: WEBHOOK_SECRET, now: now() });
  assert.equal(badSig.ok, false);
  if (!badSig.ok) assert.equal(badSig.code, 'WEBHOOK_SIGNATURE_INVALID');
  const wrongSecret = verifyWebhook({ rawBody: s.rawBody, headers: s.headers, secret: 'synthetic-other-secret', now: now() });
  assert.equal(wrongSecret.ok, false);
});

test('verify fails closed outside the clock-skew window', () => {
  const s = signed();
  const v = verifyWebhook({ rawBody: s.rawBody, headers: s.headers, secret: WEBHOOK_SECRET, now: now() + 5 * 60 * 1000 + 1 });
  assert.equal(v.ok, false);
  if (!v.ok) assert.equal(v.code, 'WEBHOOK_TIMESTAMP_INVALID');
});

test('verify rejects an eventId/header mismatch', () => {
  const s = signed();
  const v = verifyWebhook({
    rawBody: s.rawBody,
    headers: { ...s.headers, [WEBHOOK_HEADERS.eventId]: 'evt-00000000-0000-0000-0000-000000000000' },
    secret: WEBHOOK_SECRET, now: now(),
  });
  assert.equal(v.ok, false);
});

// --- Guard: replay + ordering ---

test('the guard burns nonce and event ID on first success', () => {
  const guard = new WebhookEventGuard();
  const env = envelope();
  const first = guard.check({ eventId: env.eventId, stream: env.stream, sequence: env.sequence, nonce: validNonce('g1'), at: now() });
  assert.deepEqual(first, { ok: true });
  const nonceReplay = guard.check({ eventId: 'evt-11111111-1111-1111-1111-111111111111', stream: env.stream, sequence: env.sequence + 1, nonce: validNonce('g1'), at: now() });
  assert.equal(nonceReplay.ok, false);
  if (!nonceReplay.ok) assert.equal(nonceReplay.code, 'WEBHOOK_NONCE_REPLAYED');
  const eventReplay = guard.check({ eventId: env.eventId, stream: env.stream, sequence: env.sequence + 1, nonce: validNonce('g2'), at: now() });
  assert.equal(eventReplay.ok, false);
});

test('the guard enforces strict per-stream sequence ordering', () => {
  const guard = new WebhookEventGuard();
  guard.check({ eventId: 'evt-11111111-1111-1111-1111-111111111111', stream: 'partner-sandbox-1', sequence: 5, nonce: validNonce('s1'), at: now() });
  const gap = guard.check({ eventId: 'evt-22222222-2222-2222-2222-222222222222', stream: 'partner-sandbox-1', sequence: 7, nonce: validNonce('s2'), at: now() });
  assert.equal(gap.ok, false);
  if (!gap.ok) {
    assert.equal(gap.code, 'WEBHOOK_ORDERING_GAP');
    assert.equal(gap.detail.expectedSequence, 6);
  }
  const inOrder = guard.check({ eventId: 'evt-33333333-3333-3333-3333-333333333333', stream: 'partner-sandbox-1', sequence: 6, nonce: validNonce('s3'), at: now() });
  assert.equal(inOrder.ok, true);
});

test('streams are independent; first event may start at any sequence >= 1', () => {
  const guard = new WebhookEventGuard();
  guard.check({ eventId: 'evt-11111111-1111-1111-1111-111111111111', stream: 'stream-a', sequence: 9, nonce: validNonce('x1'), at: now() });
  const other = guard.check({ eventId: 'evt-22222222-2222-2222-2222-222222222222', stream: 'stream-b', sequence: 3, nonce: validNonce('x2'), at: now() });
  assert.equal(other.ok, true);
});

test('the guard rejects a malformed nonce', () => {
  const guard = new WebhookEventGuard();
  const r = guard.check({ eventId: 'evt-11111111-1111-1111-1111-111111111111', stream: 's', sequence: 1, nonce: 'short', at: now() });
  assert.equal(r.ok, false);
});

test('nonce replay window expires (prune) so aged nonces are reusable', () => {
  const guard = new WebhookEventGuard();
  guard.check({ eventId: 'evt-11111111-1111-1111-1111-111111111111', stream: 's', sequence: 1, nonce: validNonce('p1'), at: now() });
  advance(10 * 60 * 1000 + 1);
  const aged = guard.check({ eventId: 'evt-22222222-2222-2222-2222-222222222222', stream: 's', sequence: 2, nonce: validNonce('p1'), at: now() });
  assert.equal(aged.ok, true);
});

test('verifyWebhook with a guard rejects a full replay of the same signed bytes', () => {
  const guard = new WebhookEventGuard({ now });
  const s = signed();
  const first = verifyWebhook({ rawBody: s.rawBody, headers: s.headers, secret: WEBHOOK_SECRET, now: now(), guard });
  assert.equal(first.ok, true);
  const replay = verifyWebhook({ rawBody: s.rawBody, headers: s.headers, secret: WEBHOOK_SECRET, now: now(), guard });
  assert.equal(replay.ok, false);
  if (!replay.ok) assert.equal(replay.code, 'WEBHOOK_NONCE_REPLAYED');
});

// --- Delivery service ---

function makeDelivery(transport, options = {}) {
  return new WebhookDeliveryService({ transport, now, ...options });
}

test('delivery succeeds first attempt and records DELIVERED', () => {
  let calls = 0;
  const svc = makeDelivery(() => { calls += 1; return { ok: true }; });
  const r = svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(calls, 1);
  assert.equal(r.outcome, 'DELIVERED');
  assert.equal(r.deadLettered, false);
  assert.equal(r.attempts.length, 1);
  assert.equal(r.attempts[0].outcome, 'SUCCEEDED');
  assert.equal(r.partnerId, 'partner-sandbox-1');
  assert.equal(r.stream, 'partner-sandbox-1');
  assert.equal(r.attempt0?.outcome ?? r.attempts[0].outcome, 'SUCCEEDED');
});

test('a duplicate event collapses to DELIVERED_DUPLICATE (no re-send)', () => {
  let calls = 0;
  const svc = makeDelivery(() => { calls += 1; return { ok: true }; });
  const env = envelope();
  const first = svc.deliver({ envelope: env, secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(first.outcome, 'DELIVERED');
  const dup = svc.deliver({ envelope: env, secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(dup.outcome, 'DELIVERED_DUPLICATE');
  assert.equal(calls, 1); // transport NEVER re-invoked
});

test('clean-retryable failures exhaust the schedule and dead-letter', () => {
  let calls = 0;
  const svc = makeDelivery(() => { calls += 1; return { ok: false, code: 'TRANSPORT_ERROR' }; });
  const r = svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(calls, 5); // maxAttempts default = schedule length
  assert.equal(r.outcome, 'RETRY_EXHAUSTED');
  assert.equal(r.deadLettered, true);
  assert.equal(r.attempts.length, 5);
  assert.equal(svc.deadLetterCount(), 1);
  assert.deepEqual([...svc.listDeadLetters()], [r.eventId]);
});

test('ambiguous outcomes dead-letter immediately (never blind re-send)', () => {
  let calls = 0;
  const svc = makeDelivery(() => { calls += 1; return { ok: false, code: 'TRANSPORT_ERROR', ambiguous: true }; });
  const r = svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(calls, 1);
  assert.equal(r.outcome, 'DEAD_LETTERED_AMBIGUOUS');
  assert.equal(r.deadLettered, true);
  assert.equal(r.attempts[0].outcome, 'AMBIGUOUS');
});

test('a non-retryable failure dead-letters immediately', () => {
  let calls = 0;
  const svc = makeDelivery(() => { calls += 1; return { ok: false, code: 'WEBHOOK_SIGNATURE_INVALID' }; });
  const r = svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(calls, 1);
  assert.equal(r.outcome, 'DEAD_LETTERED_AMBIGUOUS');
});

test('a retry that succeeds mid-schedule delivers on that attempt', () => {
  let calls = 0;
  const svc = makeDelivery(() => { calls += 1; return calls < 3 ? { ok: false, code: 'TRANSPORT_ERROR' } : { ok: true }; });
  const r = svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(calls, 3);
  assert.equal(r.outcome, 'DELIVERED');
  assert.equal(r.attempts.length, 3);
  assert.equal(r.attempts[2].outcome, 'SUCCEEDED');
});

test('every attempt is signed with a fresh nonce', () => {
  const seen = [];
  const svc = makeDelivery((d) => { seen.push(d.headers[WEBHOOK_HEADERS.nonce]); return { ok: false, code: 'TRANSPORT_ERROR' }; }, { maxAttempts: 3, scheduleMs: [10, 20, 30] });
  const r = svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.equal(r.outcome, 'RETRY_EXHAUSTED');
  assert.equal(seen.length, 3);
  assert.equal(new Set(seen).size, 3); // all distinct
});

test('delivery refuses an invalid endpoint (fail closed)', () => {
  const svc = makeDelivery(() => ({ ok: true }));
  const r = svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: '' } });
  assert.equal(r.outcome, 'DELIVERY_ENDPOINT_INVALID');
  assert.equal(r.deadLettered, false);
});

test('delivery fails closed on malformed input', () => {
  const svc = makeDelivery(() => ({ ok: true }));
  assert.throws(() => svc.deliver(null), /DELIVERY_INPUT_INVALID/);
  assert.throws(() => svc.deliver({ envelope: envelope(), secret: '', target: { targetId: 't' } }), /DELIVERY_SECRET_REQUIRED/);
});

test('the service constructor fails closed on malformed options', () => {
  assert.throws(() => new WebhookDeliveryService({}), /DELIVERY_TRANSPORT_REQUIRED/);
  assert.throws(() => new WebhookDeliveryService({ transport: () => ({ ok: true }), maxAttempts: 0 }), /DELIVERY_MAX_ATTEMPTS_INVALID/);
});

test('the transport receives a verifiable signed request', () => {
  let captured = null;
  const svc = makeDelivery((d) => { captured = d; return { ok: true }; });
  svc.deliver({ envelope: envelope(), secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  const v = verifyWebhook({ rawBody: captured.rawBody, headers: captured.headers, secret: WEBHOOK_SECRET, now: now() });
  assert.equal(v.ok, true);
});

test('a delivered event is idempotent across delivery ids', () => {
  const delivered = [];
  const svc = makeDelivery((d) => { delivered.push(d); return { ok: true }; });
  const env = envelope();
  const first = svc.deliver({ envelope: env, secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  const dup = svc.deliver({ envelope: env, secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-1' } });
  assert.notEqual(first.deliveryId, dup.deliveryId);
  assert.equal(delivered.length, 1); // exactly one transport call
});
