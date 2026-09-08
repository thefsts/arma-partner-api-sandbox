// Stop Point 7 — shared SDK dependency health / readiness tests.
//
// Proves the aggregate readiness verdict: a REQUIRED dependency down forces
// UNAVAILABLE (fail closed — refuse new work), an OPTIONAL dependency down
// only DEGRADES, and every non-AVAILABLE probe requires a machine-readable
// reason code.

import test from 'node:test';
import assert from 'node:assert/strict';
import { DependencyHealthCheck } from '../sdk/health.ts';
import { makeClock } from './helpers.mjs';

const { clock, now } = makeClock(1_700_000_000_000);
const health = new DependencyHealthCheck({ clock });

const probe = (name, criticality, status, reasonCode) =>
  reasonCode === undefined ? { name, criticality, status } : { name, criticality, status, reasonCode };

test('all AVAILABLE aggregates to AVAILABLE', () => {
  const r = health.compute([
    probe('receipt-registry', 'REQUIRED', 'AVAILABLE'),
    probe('partner-registry', 'REQUIRED', 'AVAILABLE'),
    probe('metrics-sink', 'OPTIONAL', 'AVAILABLE'),
  ]);
  assert.equal(r.status, 'AVAILABLE');
  assert.equal(r.checkedAt, now());
  assert.equal(r.dependencies.length, 3);
});

test('a REQUIRED dependency down forces UNAVAILABLE (fail closed)', () => {
  const r = health.compute([
    probe('receipt-registry', 'REQUIRED', 'UNAVAILABLE', 'RECEIPT_REGISTRY_DOWN'),
    probe('metrics-sink', 'OPTIONAL', 'AVAILABLE'),
  ]);
  assert.equal(r.status, 'UNAVAILABLE');
});

test('an OPTIONAL dependency down only DEGRADES', () => {
  const r = health.compute([
    probe('receipt-registry', 'REQUIRED', 'AVAILABLE'),
    probe('metrics-sink', 'OPTIONAL', 'UNAVAILABLE', 'METRICS_SINK_DOWN'),
  ]);
  assert.equal(r.status, 'DEGRADED');
});

test('any DEGRADED probe degrades the aggregate', () => {
  const r = health.compute([probe('partner-registry', 'REQUIRED', 'DEGRADED', 'PARTNER_REGISTRY_READ_ONLY')]);
  assert.equal(r.status, 'DEGRADED');
});

test('REQUIRED degraded beats OPTIONAL down (both are DEGRADED)', () => {
  const r = health.compute([
    probe('receipt-registry', 'REQUIRED', 'DEGRADED', 'RECEIPT_REGISTRY_SLOW'),
    probe('metrics-sink', 'OPTIONAL', 'UNAVAILABLE', 'METRICS_SINK_DOWN'),
  ]);
  assert.equal(r.status, 'DEGRADED');
});

test('a non-AVAILABLE probe requires a machine-readable reason code', () => {
  assert.throws(() => health.compute([probe('receipt-registry', 'REQUIRED', 'UNAVAILABLE')]), /HEALTH_REASON_CODE_REQUIRED/);
  assert.throws(() => health.compute([probe('metrics-sink', 'OPTIONAL', 'DEGRADED', '')]), /HEALTH_REASON_CODE_REQUIRED/);
  assert.throws(() => health.compute([probe('metrics-sink', 'OPTIONAL', 'DEGRADED', '   ')]), /HEALTH_REASON_CODE_REQUIRED/);
});

test('reason codes are optional only when AVAILABLE', () => {
  const r = health.compute([probe('receipt-registry', 'REQUIRED', 'AVAILABLE')]);
  assert.equal(r.status, 'AVAILABLE');
});

test('malformed probes fail closed (HEALTH_INPUT_INVALID)', () => {
  assert.throws(() => health.compute('not-an-array'), /HEALTH_INPUT_INVALID/);
  assert.throws(() => health.compute([null]), /HEALTH_INPUT_INVALID/);
  assert.throws(() => health.compute([probe('', 'REQUIRED', 'AVAILABLE')]), /HEALTH_INPUT_INVALID/);
  assert.throws(() => health.compute([probe('   ', 'REQUIRED', 'AVAILABLE')]), /HEALTH_INPUT_INVALID/);
  assert.throws(() => health.compute([probe('dep-1', 'CRITICAL', 'AVAILABLE')]), /HEALTH_INPUT_INVALID/);
  assert.throws(() => health.compute([probe('dep-1', 'REQUIRED', 'SLOW')]), /HEALTH_INPUT_INVALID/);
  assert.throws(() => health.compute([{ name: 'dep-1', criticality: 'REQUIRED' }]), /HEALTH_INPUT_INVALID/);
});

test('an empty probe list is AVAILABLE', () => {
  assert.equal(health.compute([]).status, 'AVAILABLE');
});

test('the report freezes the dependency snapshot', () => {
  const deps = [probe('receipt-registry', 'REQUIRED', 'AVAILABLE')];
  const r = health.compute(deps);
  assert.equal(Object.isFrozen(r.dependencies), true);
  // Mutating the input array afterwards cannot alter the report.
  deps.push(probe('metrics-sink', 'OPTIONAL', 'UNAVAILABLE', 'METRICS_SINK_DOWN'));
  assert.equal(r.dependencies.length, 1);
});

test('constructor rejects a malformed injected clock', () => {
  assert.throws(() => new DependencyHealthCheck({ clock: {} }), /HEALTH_CLOCK_INVALID/);
  assert.throws(() => new DependencyHealthCheck({ clock: { now: 'not-a-fn' } }), /HEALTH_CLOCK_INVALID/);
});

test('the default clock is Date.now when none is injected', () => {
  const r = new DependencyHealthCheck().compute([probe('dep-1', 'REQUIRED', 'AVAILABLE')]);
  assert.ok(Number.isFinite(r.checkedAt));
  assert.ok(Math.abs(r.checkedAt - Date.now()) < 5_000);
});
