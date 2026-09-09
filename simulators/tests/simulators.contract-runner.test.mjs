// Stop Point 8 — contract-runner tests.
//
// Proves the ONE runner holds across the full simulator × failure-mode
// matrix: every scenario produces evidence that PASSES its declared
// contract, the evidence records are metadata-only (20 allowlisted keys,
// no payload or secret material anywhere), the certification rows match the
// SP10 reporting shape, category tallies sum correctly, and the whole
// matrix is deterministic across runs. The runner also fails CLOSED when a
// scenario cannot be driven: a FAIL row with a typed code, never a crash
// and never a silent skip.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  runContractMatrix,
  runControlScenario,
  runFailureModeScenario,
  talliesByCategory,
} from '../contractRunner.ts';
import {
  SYNTHETIC_SIMULATORS,
  WELL_BEHAVED_SIMULATOR,
  SYNTHETIC_SIMULATOR_SECRETS,
  wellBehavedScenario,
} from '../behaviors.ts';
import { FAILURE_MODES, findFailureMode } from '../failureModes.ts';

const evidenceFor = (summary, simulatorId, modeId) =>
  summary.evidence.find((e) => e.simulatorId === simulatorId && e.modeId === modeId);

const stripForDeterminism = (summary) => JSON.stringify({
  rows: summary.rows,
  evidence: summary.evidence,
  counts: [summary.scenarioCount, summary.passedCount, summary.failedCount],
});

test('runner: the full matrix passes — 3 simulators × 40 modes + 3 control', () => {
  const matrix = runContractMatrix();

  assert.equal(matrix.simulatorCount, 3);
  assert.equal(matrix.modeCount, 40);
  assert.equal(matrix.controlCount, 3);
  assert.equal(matrix.scenarioCount, 123);
  assert.equal(matrix.passedCount + matrix.failedCount, matrix.scenarioCount);
  assert.equal(matrix.allPassed, true);
  assert.deepEqual(matrix.failedScenarioIds, []);
  assert.equal(matrix.failedCount, 0);

  // Every mode × every simulator passed.
  for (const mode of FAILURE_MODES) {
    for (const identity of SYNTHETIC_SIMULATORS) {
      const record = evidenceFor(matrix, identity.simulatorId, mode.modeId);
      assert.ok(record, `missing evidence for ${identity.simulatorId}:${mode.modeId}`);
      assert.equal(record.passed, true, `${identity.simulatorId}:${mode.modeId} failed`);
    }
  }
});

test('runner: every scenario carries its contract checks', () => {
  const matrix = runContractMatrix();

  for (const record of matrix.evidence) {
    assert.ok(record.checks.includes('expected-code-observed'),
      `${record.scenarioId} missing expected-code-observed`);
    assert.ok(record.checks.includes('metadata-only-views'),
      `${record.scenarioId} missing metadata-only-views`);
    assert.ok(record.checks.includes('metadata-only-evidence'),
      `${record.scenarioId} missing metadata-only-evidence`);
  }

  // Fail-closed modes that passed carry the refusal check; fail-open modes
  // that passed carry the recovery check.
  const byId = new Map(FAILURE_MODES.map((m) => [m.modeId, m]));
  for (const record of matrix.evidence) {
    const mode = byId.get(record.modeId);
    if (!mode) continue; // control rows
    if (mode.failClosed) {
      assert.ok(record.checks.includes('fail-closed-refusal'),
        `${record.scenarioId} missing fail-closed-refusal`);
    } else {
      assert.ok(record.checks.includes('contract-recovery'),
        `${record.scenarioId} missing contract-recovery`);
    }
  }

  // Multi-presentation scenarios carry the same-key discipline check.
  const multiPresentationModeIds = FAILURE_MODES
    .filter((m) => (m.inject(wellBehavedScenario(WELL_BEHAVED_SIMULATOR)).presentations ?? 1) > 1)
    .map((m) => m.modeId);
  assert.deepEqual(
    [...multiPresentationModeIds].sort(),
    ['circuit-threshold-trip-open', 'retry-clean-retryable', 'retry-exhaustion-schedule-bound'],
  );
  const multiPresentation = new Set(multiPresentationModeIds);
  for (const record of matrix.evidence) {
    if (multiPresentation.has(record.modeId)) {
      assert.ok(record.checks.includes('same-key-retry-discipline'),
        `${record.scenarioId} missing same-key-retry-discipline`);
    }
  }
});

test('runner: control evidence is the full SP7 chain for every simulator', () => {
  const matrix = runContractMatrix();

  for (const identity of SYNTHETIC_SIMULATORS) {
    const control = evidenceFor(matrix, identity.simulatorId, 'control');
    assert.ok(control, `${identity.simulatorId} control evidence missing`);
    assert.equal(control.passed, true);
    assert.equal(control.category, 'CONTROL');
    assert.equal(control.expectedCode, 'OPERATION_COMPLETED');
    assert.ok(control.checks.includes('full-chain-completed'));
    assert.equal(control.spanStatus, 'SUCCESS');
    assert.equal(control.observedCode, 'OPERATION_COMPLETED');
    assert.deepEqual([...control.operationCodes], ['OK']);
    assert.equal(control.eventsEmitted.length >= 1, true);
    assert.equal(control.failClosed, false);
  }
});

test('runner: evidence records are frozen, 20-key, metadata-only', () => {
  const matrix = runContractMatrix();

  const forbidden = [
    'syntheticRequest',
    ...Object.values(SYNTHETIC_SIMULATOR_SECRETS),
  ];
  for (const record of matrix.evidence) {
    assert.equal(Object.isFrozen(record), true, `${record.scenarioId} not frozen`);
    assert.equal(Object.keys(record).length, 20, `${record.scenarioId} keys`);
    const serialized = JSON.stringify(record);
    for (const value of forbidden) {
      assert.ok(
        !serialized.includes(value),
        `${record.scenarioId} leaks ${value.slice(0, 24)}…`,
      );
    }
  }
});

test('runner: certification rows match the SP10 reporting shape', () => {
  const matrix = runContractMatrix();

  assert.equal(matrix.rows.length, 123);
  const modeById = new Map(FAILURE_MODES.map((m) => [m.modeId, m]));
  for (const row of matrix.rows) {
    assert.match(row.testId, /^[a-z0-9-]+:[a-z0-9-]+$/);
    assert.equal(row.result, 'PASS');
    const [, modeId] = row.testId.split(':');
    const mode = modeById.get(modeId);
    if (mode) {
      assert.equal(row.category, mode.category);
      assert.equal(row.reasonCode, mode.expectedCode);
      assert.ok(row.requirement.length > 0);
    } else {
      assert.equal(modeId, 'control');
      assert.equal(row.category, 'CONTROL');
      assert.ok(row.requirement.includes('full SP7 chain'));
    }
  }
});

test('runner: category tallies sum to the matrix', () => {
  const matrix = runContractMatrix();
  const tallies = talliesByCategory(matrix);
  const tallyMap = new Map(tallies.map((t) => [t.category, t]));

  assert.equal(tallies.length, 11); // 10 failure-mode categories + CONTROL
  assert.equal(tallyMap.get('CONTROL')?.total, 3);
  assert.equal(tallyMap.get('CONTROL')?.passed, 3);
  assert.equal(tallyMap.get('SIGNATURE')?.total, 15); // 5 modes × 3 sims
  assert.equal(tallyMap.get('AUTHORIZATION')?.total, 24); // 8 modes × 3 sims
  assert.ok(tallies.every((t) => t.failed === 0));
  const total = tallies.reduce((sum, t) => sum + t.total, 0);
  assert.equal(total, matrix.scenarioCount);
});

test('runner: contract-heavy modes surface their verdicts in evidence', () => {
  const matrix = runContractMatrix();
  const sim = 'sim-well-behaved';

  // Same-key retry discipline: DU then OK, recovery plan.
  {
    const r = evidenceFor(matrix, sim, 'retry-clean-retryable');
    assert.deepEqual([...r.operationCodes], ['DOWNSTREAM_UNAVAILABLE', 'OK']);
    assert.equal(r.retryPlan, 'CLEAN_RETRY');
    assert.ok(r.checks.includes('same-key-retry-discipline'));
    assert.ok(r.checks.includes('contract-recovery'));
    assert.equal(r.passed, true);
  }
  // Circuit threshold: [DU, DU, CO, CO] and OPEN recorded.
  {
    const r = evidenceFor(matrix, sim, 'circuit-threshold-trip-open');
    assert.deepEqual(
      [...r.operationCodes],
      ['DOWNSTREAM_UNAVAILABLE', 'DOWNSTREAM_UNAVAILABLE', 'CIRCUIT_OPEN', 'CIRCUIT_OPEN'],
    );
    assert.ok(r.circuitStates.includes('OPEN'));
    assert.equal(r.observedCode, 'CIRCUIT_OPEN');
  }
  // Schedule bound: 5 presentations, all DU, plan EXHAUSTED at the bound.
  {
    const r = evidenceFor(matrix, sim, 'retry-exhaustion-schedule-bound');
    assert.equal(r.operationCodes.length, 5);
    assert.ok(r.operationCodes.every((c) => c === 'DOWNSTREAM_UNAVAILABLE'));
    assert.equal(r.retryPlan, 'EXHAUSTED');
  }
  // Kill switch: nothing processed, nothing emitted, span FAILED.
  {
    const r = evidenceFor(matrix, sim, 'kill-switch-refuses-all');
    assert.equal(r.observedCode, 'PLATFORM_KILL_SWITCH');
    assert.equal(r.spanStatus, 'FAILED');
    assert.deepEqual([...r.eventsEmitted], []);
    assert.deepEqual([...r.operationCodes], ['PLATFORM_KILL_SWITCH']);
  }
  // Delivery exhaustion: dead-lettered, multi-attempt, AMBIGUOUS/PENDING.
  {
    const r = evidenceFor(matrix, sim, 'webhook-delivery-exhaustion');
    assert.equal(r.deadLettered, true);
    assert.ok(r.attempts > 1);
    assert.equal(r.spanStatus, 'AMBIGUOUS');
    assert.equal(r.reconciliationStatus, 'PENDING');
  }
  // Reconciliation: RESOLVE -> RESOLVED; ESCALATE -> REQUIRED_UNRESOLVED.
  {
    const resolve = evidenceFor(matrix, sim, 'reconciliation-resolve');
    assert.equal(resolve.reconciliationStatus, 'RESOLVED');
    const escalate = evidenceFor(matrix, sim, 'reconciliation-escalate');
    assert.equal(escalate.reconciliationStatus, 'REQUIRED_UNRESOLVED');
  }
  // Duplicate collapse: fail-open — re-delivery of the recorded outcome.
  {
    const r = evidenceFor(matrix, sim, 'replay-duplicate-collapse');
    assert.equal(r.passed, true);
    assert.equal(r.failClosed, false);
    assert.equal(r.observedCode, 'IDEMPOTENCY_DUPLICATE_COLLAPSED');
    assert.ok(r.checks.includes('contract-recovery'));
  }
  // Ambiguous receipt: client fails closed, plan routes to reconcile.
  {
    const r = evidenceFor(matrix, sim, 'retry-ambiguous-reconcile');
    assert.equal(r.retryPlan, 'AMBIGUOUS_RECONCILE');
    assert.equal(r.receiptReason, 'RECEIPT_MISSING_HEADERS');
  }
});

test('runner: single-scenario APIs return the same verdicts as the matrix', () => {
  const one = runFailureModeScenario(
    WELL_BEHAVED_SIMULATOR,
    findFailureMode('signature-tampered-signature'),
  );
  assert.equal(one.passed, true);
  assert.equal(one.observedCode, 'SIGNATURE_SIGNATURE_MISMATCH');
  assert.equal(one.scenarioId, 'sim-well-behaved:signature-tampered-signature');

  const control = runControlScenario(WELL_BEHAVED_SIMULATOR);
  assert.equal(control.passed, true);
  assert.equal(control.scenarioId, 'sim-well-behaved:control');
  assert.equal(control.spanStatus, 'SUCCESS');
});

test('runner: the matrix is deterministic across runs', () => {
  const a = runContractMatrix();
  const b = runContractMatrix();
  assert.equal(stripForDeterminism(a), stripForDeterminism(b));
  assert.equal(b.allPassed, true);
});

test('runner: a scenario that cannot be driven fails CLOSED — FAIL row, never a crash', () => {
  // A faulted scenario whose world cannot even be assembled (the platform
  // constructor rejects an unusable scenario record) must surface as a FAIL
  // row with a TYPED code, never an unhandled crash and never a silent
  // skip. The runner's fail-closed wrap is the last line of defense.
  const brokenMode = {
    modeId: 'harness-broken-scenario',
    category: 'SIGNATURE',
    surface: 'PLATFORM_RESPONSE',
    expectedCode: 'SIGNATURE_SIGNATURE_MISMATCH',
    failClosed: true,
    requirement: 'harness probe: runner fails closed on undriveable scenarios',
    inject: () => null,
  };
  const summary = runContractMatrix({
    simulators: [WELL_BEHAVED_SIMULATOR],
    modes: [brokenMode],
    includeControl: false,
  });

  assert.equal(summary.scenarioCount, 1);
  assert.equal(summary.allPassed, false);
  assert.equal(summary.failedCount, 1);
  assert.deepEqual([...summary.failedScenarioIds], ['sim-well-behaved:harness-broken-scenario']);
  const record = summary.evidence[0];
  assert.equal(record.passed, false);
  // The engine's TYPED code is surfaced (it matches the code pattern) —
  // message text beyond a typed code never enters evidence.
  assert.equal(record.observedCode, 'PLATFORM_SCENARIO_REQUIRED');
  assert.deepEqual([...record.checks], ['runner-fail-closed']);
  assert.equal(summary.rows[0].result, 'FAIL');
  assert.equal(summary.rows[0].reasonCode, 'PLATFORM_SCENARIO_REQUIRED');

  // And the failure evidence is metadata-only too (no thrown message text).
  const serialized = JSON.stringify(record);
  for (const value of Object.values(SYNTHETIC_SIMULATOR_SECRETS)) {
    assert.ok(!serialized.includes(value));
  }
});

test('runner: untyped engine errors collapse to the generic RUNNER_ERROR code', () => {
  // When a thrown error carries no typed code (a raw Error with prose), the
  // runner still fails closed — with the generic RUNNER_ERROR code, never
  // the prose. Nothing untyped ever reaches the evidence surface.
  const explodeMode = {
    modeId: 'harness-exploding-injector',
    category: 'SIGNATURE',
    surface: 'PLATFORM_RESPONSE',
    expectedCode: 'SIGNATURE_SIGNATURE_MISMATCH',
    failClosed: true,
    requirement: 'harness probe: untyped errors collapse to RUNNER_ERROR',
    inject: () => {
      throw new Error('secret prose that must never be surfaced');
    },
  };
  const summary = runContractMatrix({
    simulators: [WELL_BEHAVED_SIMULATOR],
    modes: [explodeMode],
    includeControl: false,
  });

  assert.equal(summary.allPassed, false);
  const record = summary.evidence[0];
  assert.equal(record.observedCode, 'RUNNER_ERROR');
  assert.equal(record.passed, false);
  assert.deepEqual([...record.checks], ['runner-fail-closed']);
  const serialized = JSON.stringify(record);
  assert.ok(!serialized.includes('secret prose'));
  for (const value of Object.values(SYNTHETIC_SIMULATOR_SECRETS)) {
    assert.ok(!serialized.includes(value));
  }
});

test('runner: options narrow the matrix without changing verdicts', () => {
  const narrow = runContractMatrix({
    simulators: [WELL_BEHAVED_SIMULATOR],
    modes: [
      findFailureMode('signature-tampered-signature'),
      findFailureMode('retry-clean-retryable'),
    ],
    includeControl: true,
  });

  assert.equal(narrow.simulatorCount, 1);
  assert.equal(narrow.modeCount, 2);
  assert.equal(narrow.controlCount, 1);
  assert.equal(narrow.scenarioCount, 3);
  assert.equal(narrow.allPassed, true);
  assert.ok(narrow.evidence.every((r) => r.passed));
});
