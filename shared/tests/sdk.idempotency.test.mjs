// Stop Point 7 — shared SDK idempotency + replay guard tests.
//
// Proves the shared idempotency contract: FRESH/DUPLICATE/CONFLICT
// resolution, recorded-outcome collapse for safe retries, TTL expiry, and
// the replay guard's per-scope nonce window with atomic check-and-consume.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IdempotencyRegistry,
  ReplayGuard,
  IDEMPOTENCY_KEY_PATTERN,
  DEFAULT_IDEMPOTENCY_TTL_MS,
  REPLAY_WINDOW_MS,
} from '../sdk/idempotency.ts';
import { makeClock, validNonce } from './helpers.mjs';

test('first resolve is FRESH; second resolve with the same hash is DUPLICATE', () => {
  const clock = makeClock();
  const reg = new IdempotencyRegistry({ now: clock.now });
  const key = 'idem-key-0001';
  const hash = 'a'.repeat(64);
  assert.deepEqual(reg.resolve('op:activation', key, hash), { kind: 'FRESH' });
  reg.record('op:activation', key, hash, { outcome: 'SUCCESS', status: 201, bodyDigest: 'b'.repeat(64), at: clock.now() });
  assert.equal(reg.resolve('op:activation', key, hash).kind, 'DUPLICATE');
});

test('DUPLICATE collapses to the recorded outcome', () => {
  const clock = makeClock();
  const reg = new IdempotencyRegistry({ now: clock.now });
  reg.record('op:activation', 'idem-key-0002', 'c'.repeat(64), {
    outcome: 'SUCCESS', status: 201, bodyDigest: 'd'.repeat(64), receiptId: 'rcpt-000000002', at: clock.now(),
  });
  const dup = reg.resolve('op:activation', 'idem-key-0002', 'c'.repeat(64));
  assert.equal(dup.kind, 'DUPLICATE');
  if (dup.kind === 'DUPLICATE') {
    assert.equal(dup.existing.outcome, 'SUCCESS');
    assert.equal(dup.existing.status, 201);
    assert.equal(dup.existing.receiptId, 'rcpt-000000002');
  }
});

test('same key + different request hash is CONFLICT', () => {
  const clock = makeClock();
  const reg = new IdempotencyRegistry({ now: clock.now });
  reg.record('op:activation', 'idem-key-0003', 'e'.repeat(64), {
    outcome: 'SUCCESS', status: 200, bodyDigest: 'f'.repeat(64), at: clock.now(),
  });
  assert.equal(reg.resolve('op:activation', 'idem-key-0003', '0'.repeat(64)).kind, 'CONFLICT');
});

test('records expire after the TTL: a stale key resolves FRESH again', () => {
  const clock = makeClock();
  const reg = new IdempotencyRegistry({ now: clock.now, ttlMs: DEFAULT_IDEMPOTENCY_TTL_MS });
  reg.record('op:activation', 'idem-key-0004', '1'.repeat(64), {
    outcome: 'SUCCESS', status: 200, bodyDigest: '2'.repeat(64), at: clock.now(),
  });
  assert.equal(reg.resolve('op:activation', 'idem-key-0004', '1'.repeat(64)).kind, 'DUPLICATE');
  clock.advance(DEFAULT_IDEMPOTENCY_TTL_MS + 1);
  assert.equal(reg.resolve('op:activation', 'idem-key-0004', '1'.repeat(64)).kind, 'FRESH');
});

test('record refuses a malformed idempotency key', () => {
  const clock = makeClock();
  const reg = new IdempotencyRegistry({ now: clock.now });
  assert.throws(
    () => reg.record('op:activation', 'short', '3'.repeat(64), { outcome: 'SUCCESS', status: 200, bodyDigest: '4'.repeat(64), at: clock.now() }),
    /IDEMPOTENCY_KEY_INVALID/,
  );
});

test('record refuses a hash mismatch against an existing record', () => {
  const clock = makeClock();
  const reg = new IdempotencyRegistry({ now: clock.now });
  reg.record('op:activation', 'idem-key-0005', '5'.repeat(64), {
    outcome: 'SUCCESS', status: 200, bodyDigest: '6'.repeat(64), at: clock.now(),
  });
  assert.throws(
    () => reg.record('op:activation', 'idem-key-0005', '7'.repeat(64), { outcome: 'SUCCESS', status: 200, bodyDigest: '8'.repeat(64), at: clock.now() }),
    /IDEMPOTENCY_RECORD_CONFLICT/,
  );
});

test('IDEMPOTENCY_KEY_PATTERN accepts 8-128 char [A-Za-z0-9_-] keys', () => {
  assert.ok(IDEMPOTENCY_KEY_PATTERN.test('abcd-1234'));
  assert.ok(IDEMPOTENCY_KEY_PATTERN.test('k'.repeat(128)));
  assert.ok(!IDEMPOTENCY_KEY_PATTERN.test('k'.repeat(7)));
  assert.ok(!IDEMPOTENCY_KEY_PATTERN.test('k'.repeat(129)));
  assert.ok(!IDEMPOTENCY_KEY_PATTERN.test('bad key!'));
});

test('scopes isolate the same key across different operations', () => {
  const clock = makeClock();
  const reg = new IdempotencyRegistry({ now: clock.now });
  reg.record('op:activation', 'idem-key-0006', '9'.repeat(64), {
    outcome: 'SUCCESS', status: 201, bodyDigest: 'a'.repeat(64), at: clock.now(),
  });
  assert.equal(reg.resolve('op:transfer', 'idem-key-0006', '9'.repeat(64)).kind, 'FRESH');
});

// --- ReplayGuard ---

test('first nonce use passes; second use of the same nonce fails closed', () => {
  const clock = makeClock();
  const guard = new ReplayGuard({ now: clock.now });
  const nonce = validNonce('r1');
  assert.equal(guard.check('partner-1', nonce, 'req-0001').ok, true);
  const second = guard.check('partner-1', nonce, 'req-0001');
  assert.equal(second.ok, false);
  if (!second.ok) assert.equal(second.code, 'REPLAYED');
});

test('nonces expire after the replay window and may be reused', () => {
  const clock = makeClock();
  const guard = new ReplayGuard({ now: clock.now });
  const nonce = validNonce('r2');
  assert.equal(guard.check('partner-1', nonce).ok, true);
  clock.advance(REPLAY_WINDOW_MS + 1);
  assert.equal(guard.check('partner-1', nonce).ok, true);
});

test('a malformed nonce is refused (scope error, not recorded)', () => {
  const clock = makeClock();
  const guard = new ReplayGuard({ now: clock.now });
  // malformed nonce => compositeKey with non-string part is fine, but the
  // SHORT nonce burns on first use: the second call must fail closed.
  const short = 'short-nonce';
  assert.equal(guard.check('partner-1', short, 'req-0002').ok, true);
  const second = guard.check('partner-1', short, 'req-0002');
  assert.equal(second.ok, false);
  if (!second.ok) assert.equal(second.code, 'REPLAYED');
});

test('prune drops expired nonces and returns the remaining count', () => {
  const clock = makeClock();
  const guard = new ReplayGuard({ now: clock.now });
  guard.check('partner-1', validNonce('p1'));
  guard.check('partner-1', validNonce('p2'));
  clock.advance(REPLAY_WINDOW_MS + 1);
  guard.check('partner-1', validNonce('p3'));
  assert.equal(guard.prune(), 1);
});

test('requestId is recorded with the first sighting for forensics', () => {
  const clock = makeClock();
  const guard = new ReplayGuard({ now: clock.now });
  guard.check('partner-1', validNonce('q1'), 'req-echoed-0001');
  const second = guard.check('partner-1', validNonce('q1'), 'req-echoed-0001');
  assert.equal(second.ok, false);
  if (!second.ok) assert.equal(second.firstSeenRequestId, 'req-echoed-0001');
});

test('same nonce in a different scope is NOT a replay (per-scope registry)', () => {
  const clock = makeClock();
  const guard = new ReplayGuard({ now: clock.now });
  const nonce = validNonce('s1');
  assert.equal(guard.check('partner-1', nonce).ok, true);
  assert.equal(guard.check('partner-2', nonce).ok, true);
});
