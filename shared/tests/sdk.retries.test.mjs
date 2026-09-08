// Stop Point 7 — shared SDK retry + circuit breaker tests.
//
// Proves the CLEAN-RETRYABLE ONLY retry discipline and the fail-closed
// circuit breaker state machine (CLOSED -> OPEN -> HALF_OPEN canary) with a
// deterministic injected clock.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RETRY_SCHEDULE_MS,
  MAX_RETRY_ATTEMPTS,
  RetryPolicy,
  CLEAN_RETRYABLE_CODES,
  AMBIGUOUS_RETRY_CODES,
  CircuitBreaker,
} from '../sdk/retries.ts';
import { makeClock } from './helpers.mjs';

const { clock, now, advance } = makeClock(1_700_000_000_000);

// --- Backoff schedule ---

test('the shared backoff schedule is 1s, 5s, 30s, 2m, 10m', () => {
  assert.deepEqual([...RETRY_SCHEDULE_MS], [1_000, 5_000, 30_000, 120_000, 600_000]);
  assert.equal(MAX_RETRY_ATTEMPTS, 5);
});

test('computeBackoff walks the schedule and stops at the bound', () => {
  const policy = new RetryPolicy({ now });
  let r = policy.computeBackoff(0);
  assert.deepEqual(r, { allowed: true, delayMs: 1_000, nextAttempt: 1, retryAt: now() + 1_000 });
  r = policy.computeBackoff(4);
  assert.deepEqual(r, { allowed: true, delayMs: 600_000, nextAttempt: 5, retryAt: now() + 600_000 });
  r = policy.computeBackoff(5);
  assert.deepEqual(r, { allowed: false, reason: 'MAX_RETRIES_EXCEEDED', attempts: 5 });
  assert.deepEqual(policy.computeBackoff(99), { allowed: false, reason: 'MAX_RETRIES_EXCEEDED', attempts: 99 });
});

test('computeBackoff clamps a null retryCount to zero', () => {
  const r = new RetryPolicy({ now }).computeBackoff(null);
  assert.deepEqual(r, { allowed: true, delayMs: 1_000, nextAttempt: 1, retryAt: now() + 1_000 });
});

test('computeBackoff honors a custom schedule', () => {
  const policy = new RetryPolicy({ scheduleMs: [100, 200], now });
  assert.deepEqual(policy.computeBackoff(0), { allowed: true, delayMs: 100, nextAttempt: 1, retryAt: now() + 100 });
  assert.deepEqual(policy.computeBackoff(2), { allowed: false, reason: 'MAX_RETRIES_EXCEEDED', attempts: 2 });
});

// --- Clean-retryable-only classification ---

test('only pre-processing transport failures are CLEAN-RETRYABLE', () => {
  assert.equal(CLEAN_RETRYABLE_CODES.has('TRANSPORT_ERROR'), true);
  assert.equal(CLEAN_RETRYABLE_CODES.has('DOWNSTREAM_UNAVAILABLE'), true);
  assert.equal(CLEAN_RETRYABLE_CODES.has('UNAVAILABLE'), true);
  assert.equal(CLEAN_RETRYABLE_CODES.has('CIRCUIT_OPEN'), false);
  assert.equal(CLEAN_RETRYABLE_CODES.has('PERSISTENCE_FAILED'), false);
});

test('ambiguous outcomes route to reconciliation, never blind re-send', () => {
  assert.equal(AMBIGUOUS_RETRY_CODES.has('CIRCUIT_OPEN'), true);
  assert.equal(AMBIGUOUS_RETRY_CODES.has('WEBHOOK_DELIVERY_FAILED'), true);
  assert.equal(AMBIGUOUS_RETRY_CODES.has('PERSISTENCE_FAILED'), true);
  assert.equal(AMBIGUOUS_RETRY_CODES.has('TRANSPORT_ERROR'), false);
});

test('classify separates clean-retryable, ambiguous, and terminal', () => {
  const policy = new RetryPolicy();
  const clean = policy.classify('TRANSPORT_ERROR');
  assert.deepEqual(clean, { retryable: true, ambiguous: false, cleanRetryable: true });
  const ambiguous = policy.classify('CIRCUIT_OPEN');
  assert.deepEqual(ambiguous, { retryable: true, ambiguous: true, cleanRetryable: false });
  const terminal = policy.classify('PARTNER_UNKNOWN');
  assert.deepEqual(terminal, { retryable: false, ambiguous: false, cleanRetryable: false });
});

test('canAutoRetry allows only clean-retryable failures', () => {
  const policy = new RetryPolicy();
  assert.equal(policy.canAutoRetry({ cleanRetryable: true }), true);
  assert.equal(policy.canAutoRetry({ ambiguous: true }), false);
  assert.equal(policy.canAutoRetry({ ambiguous: true, retryable: true }), false);
  assert.equal(policy.canAutoRetry({ retryable: false }), false);
  assert.equal(policy.canAutoRetry({ retryable: true }), true);
  assert.equal(policy.canAutoRetry({}), false);
});

// --- Circuit breaker state machine ---

test('circuit breaker rejects invalid options (fail closed)', () => {
  assert.throws(() => new CircuitBreaker({ failureThreshold: 0 }), /CIRCUIT_OPTIONS_INVALID/);
  assert.throws(() => new CircuitBreaker({ failureThreshold: -1 }), /CIRCUIT_OPTIONS_INVALID/);
  assert.throws(() => new CircuitBreaker({}), /CIRCUIT_OPTIONS_INVALID/);
  assert.throws(() => new CircuitBreaker({ failureThreshold: '2' }), /CIRCUIT_OPTIONS_INVALID/);
});

test('CLOSED allows work; failures trip OPEN at the threshold', () => {
  const breaker = new CircuitBreaker({ failureThreshold: 3, now });
  assert.deepEqual(breaker.check(), { allowed: true, state: 'CLOSED' });
  breaker.recordFailure();
  breaker.recordFailure();
  assert.equal(breaker.getState(), 'CLOSED');
  assert.equal(breaker.getConsecutiveFailures(), 2);
  breaker.recordFailure();
  assert.equal(breaker.getState(), 'OPEN');
  const d = breaker.check();
  assert.equal(d.allowed, false);
  assert.equal(d.state, 'OPEN');
  assert.equal(d.reason, 'CIRCUIT_OPEN');
});

test('OPEN fails closed until the reset timeout, then allows ONE canary (HALF_OPEN)', () => {
  const breaker = new CircuitBreaker({ failureThreshold: 1, resetTimeoutMs: 30_000, now });
  breaker.recordFailure();
  assert.equal(breaker.getState(), 'OPEN');
  // Just before the timeout: still refused.
  advance(29_999);
  let d = breaker.check();
  assert.equal(d.allowed, false);
  assert.equal(d.state, 'OPEN');
  assert.equal(d.reason, 'CIRCUIT_OPEN');
  // At the timeout: the canary is allowed (HALF_OPEN).
  advance(1);
  d = breaker.check();
  assert.equal(d.allowed, true);
  assert.equal(d.state, 'HALF_OPEN');
  assert.equal(d.probe, true);
  // A second call while HALF_OPEN fails closed — only the canary proceeds.
  d = breaker.check();
  assert.equal(d.allowed, false);
  assert.equal(d.state, 'HALF_OPEN');
  assert.equal(d.reason, 'CIRCUIT_OPEN');
});

test('canary success closes the circuit and resets counters', () => {
  const breaker = new CircuitBreaker({ failureThreshold: 2, resetTimeoutMs: 10_000, now });
  breaker.recordFailure();
  breaker.recordFailure();
  assert.equal(breaker.getState(), 'OPEN');
  advance(10_000);
  const canary = breaker.check();
  assert.equal(canary.probe, true);
  breaker.recordSuccess();
  assert.equal(breaker.getState(), 'CLOSED');
  assert.equal(breaker.getConsecutiveFailures(), 0);
  assert.deepEqual(breaker.check(), { allowed: true, state: 'CLOSED' });
});

test('canary failure re-opens the circuit immediately', () => {
  const breaker = new CircuitBreaker({ failureThreshold: 2, resetTimeoutMs: 10_000, now });
  breaker.recordFailure();
  breaker.recordFailure();
  advance(10_000);
  assert.equal(breaker.check().probe, true);
  breaker.recordFailure();
  assert.equal(breaker.getState(), 'OPEN');
  const d = breaker.check();
  assert.equal(d.allowed, false);
  assert.equal(d.state, 'OPEN');
  assert.equal(d.reason, 'CIRCUIT_OPEN');
});

test('success in CLOSED resets the consecutive-failure counter', () => {
  const breaker = new CircuitBreaker({ failureThreshold: 2, now });
  breaker.recordFailure();
  breaker.recordSuccess();
  breaker.recordFailure();
  assert.equal(breaker.getState(), 'CLOSED');
  assert.equal(breaker.getConsecutiveFailures(), 1);
});
