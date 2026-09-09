// Stop Point 8 — failure-mode catalog tests.
//
// Proves the catalog is a closed, deterministic, configuration-only record
// set: unique ids across the 10 owner-directed categories, every injector
// pure (identical base in, identical faulted config out), every mode's
// expected contract code actually observable on its declared evidence
// surface when driven through the engines, and the CONTROL mode describing
// the well-behaved baseline.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  FAILURE_MODES,
  CONTROL_MODE,
  failureModeIds,
  categoryCounts,
  categoriesCovered,
  modesByCategory,
  findFailureMode,
  injectorIsDeterministic,
  allInjectorsDeterministic,
} from '../failureModes.ts';
import {
  FAILURE_MODE_CATEGORIES,
  SYNTHETIC_SIMULATORS,
  WELL_BEHAVED_SIMULATOR,
  wellBehavedScenario,
} from '../behaviors.ts';
import { driveScenario } from './helpers.mjs';

const EXPECTED_CATEGORY_COUNTS = new Map([
  ['SIGNATURE', 5],
  ['REPLAY', 3],
  ['RECEIPT', 4],
  ['AUTHORIZATION', 8],
  ['ENTITLEMENT', 7],
  ['WEBHOOK', 5],
  ['RETRY', 4],
  ['RECONCILIATION', 2],
  ['CIRCUIT_BREAKER', 1],
  ['KILL_SWITCH', 1],
]);

test('catalog: 40 modes with unique ids', () => {
  assert.equal(FAILURE_MODES.length, 40);
  const ids = failureModeIds();
  assert.equal(new Set(ids).size, ids.length);
  for (const id of ids) {
    assert.match(id, /^[a-z0-9-]+$/);
  }
});

test('catalog: all 10 owner-directed categories are covered with the designed counts', () => {
  assert.ok(categoriesCovered());
  for (const [category, expected] of EXPECTED_CATEGORY_COUNTS) {
    assert.equal(categoryCounts().get(category), expected, category);
  }
  // Every category from the closed vocabulary has at least one mode.
  for (const category of FAILURE_MODE_CATEGORIES) {
    assert.ok((modesByCategory().get(category) ?? []).length >= 1, category);
  }
  // Total adds up.
  let total = 0;
  for (const n of categoryCounts().values()) total += n;
  assert.equal(total, 40);
});

test('catalog: every mode declares a valid category, surface, expected code, and requirement', () => {
  for (const mode of FAILURE_MODES) {
    assert.ok(FAILURE_MODE_CATEGORIES.includes(mode.category), mode.modeId);
    assert.equal(typeof mode.surface, 'string', mode.modeId);
    assert.match(mode.expectedCode, /^[A-Z][A-Z0-9_]+$/, mode.modeId);
    assert.equal(typeof mode.failClosed, 'boolean', mode.modeId);
    assert.ok(mode.requirement.length > 0 && mode.requirement.length <= 256, mode.modeId);
  }
});

test('catalog: injectors are pure — identical input, identical output', () => {
  assert.ok(allInjectorsDeterministic());
  for (const mode of FAILURE_MODES) {
    assert.ok(injectorIsDeterministic(mode), mode.modeId);
  }
});

test('catalog: injectors only flip data — the identity and request plan stay intact', () => {
  const base = wellBehavedScenario(WELL_BEHAVED_SIMULATOR);
  for (const mode of FAILURE_MODES) {
    const injected = mode.inject(base);
    // The same simulator identity (the engines never branch on identity).
    assert.equal(injected.identity.simulatorId, base.identity.simulatorId, mode.modeId);
    // The same operation shape (faults flip data, not the request contract).
    assert.equal(injected.request.operation, base.request.operation, mode.modeId);
    assert.equal(injected.request.method, base.request.method, mode.modeId);
    assert.equal(injected.request.path, base.request.path, mode.modeId);
    // The injector never mutated the base (purity).
    assert.deepEqual(mode.inject(base), mode.inject(wellBehavedScenario(WELL_BEHAVED_SIMULATOR)));
  }
});

test('catalog: findFailureMode resolves known ids and fails closed on unknown', () => {
  assert.ok(findFailureMode('signature-tampered-signature') !== null);
  assert.ok(findFailureMode('kill-switch-refuses-all') !== null);
  assert.equal(findFailureMode('not-a-mode'), null);
  assert.equal(findFailureMode(''), null);
});

test('catalog: the CONTROL mode is the well-behaved baseline', () => {
  assert.equal(CONTROL_MODE.modeId, 'control');
  assert.equal(CONTROL_MODE.category, 'CONTROL');
  assert.equal(CONTROL_MODE.surface, 'CONTROL');
  assert.equal(CONTROL_MODE.expectedCode, 'OPERATION_COMPLETED');
  assert.equal(CONTROL_MODE.failClosed, false);
  assert.ok(CONTROL_MODE.requirement.includes('full SP7 chain'));
});

test('catalog: every mode observes its expected code when driven (all simulators)', () => {
  // The catalog correctness sweep: every mode, on every simulator identity,
  // surfaces its expected contract code somewhere on the run's surfaces.
  // Retry plans are read at each presentation's attempt index — the
  // schedule-bound classification (EXHAUSTED) only exists AT the bound.
  for (const identity of SYNTHETIC_SIMULATORS) {
    for (const mode of FAILURE_MODES) {
      const scenario = mode.inject(wellBehavedScenario(identity));
      const run = driveScenario(scenario);

      const observed = new Set();
      const add = (code) => { if (typeof code === 'string' && code.length > 0) observed.add(code); };
      run.outcomes.forEach((o, i) => {
        add(o.processed.errorCode);
        add(o.processed.receiptFailure);
        add(o.retryPlan);
        if (o.secondPresentation) {
          add(o.secondPresentation.errorCode);
          add(o.secondPresentation.receiptFailure);
        }
        if (o.processed.ok === false) {
          const failureCode = o.processed.errorCode ?? o.processed.receiptFailure;
          if (failureCode !== null) add(run.simulator.planRetryFor(failureCode, i + 1));
        }
      });
      add(run.platform.decisionView?.code ?? null);
      for (const c of run.phase.delivery.receiverCodes) add(c);
      add(run.phase.receiver.code);
      add(run.phase.receiver.rePresentedCode);
      add(run.phase.delivery.deliveryOutcome);
      add(run.phase.delivery.deliveredTwiceOutcome);
      for (const c of run.phase.delivery.reconciliationOutcomes) add(c);
      add(run.platform.spanViews.status);
      add(run.platform.spanViews.reconciliationStatus);
      for (const e of run.phase.events) add(e.eventType);
      for (const c of run.platform.circuitStateViews) add(c);
      for (const c of run.platform.auditViews.reasonCodes) add(c);

      assert.ok(
        observed.has(mode.expectedCode),
        `${identity.simulatorId}:${mode.modeId} expected ${mode.expectedCode}, observed [${[...observed].join(', ')}]`,
      );
    }
  }
});

test('catalog: fail-closed modes never produce a trusted success on their declared surface', () => {
  // Fail-closed discipline, keyed on DATA (never category): modes that
  // fault a SECOND presentation of an otherwise well-behaved request (the
  // replay / conflict / receiver-side attacks) must refuse the ATTACK
  // presentation — the original presentation is the well-behaved one.
  // Every other fail-closed mode must never produce a trusted success at
  // all. Fail-open modes (duplicate collapse / recovery / resolve) must
  // observe a positive outcome somewhere.
  for (const mode of FAILURE_MODES) {
    const scenario = mode.inject(wellBehavedScenario(WELL_BEHAVED_SIMULATOR));
    const run = driveScenario(scenario);
    const label = `${mode.modeId} (${mode.surface})`;

    if (!mode.failClosed) {
      const anyOk = run.outcomes.some((o) =>
        o.processed.ok === true || (o.secondPresentation && o.secondPresentation.ok === true));
      assert.ok(
        anyOk || run.phase.receiver.verified === true || run.platform.spanViews.status === 'SUCCESS',
        `fail-open mode ${label} recovered nowhere`,
      );
      continue;
    }

    const faults = scenario.partnerFaults;
    const attackPresentation = Boolean(
      faults.replayPresentation
      || faults.idempotencyConflictPresentation
      || scenario.delivery.receiverFaults?.rePresentSameDelivery
      || scenario.delivery.receiverFaults?.tamperBody,
    );
    if (attackPresentation) {
      if (mode.surface === 'RECEIVER') {
        // The attack lands on the receiver's re-presentation / tamper
        // surface: a typed refusal code, never OK.
        const attackCode = run.phase.receiver.rePresentedCode ?? run.phase.receiver.code;
        assert.ok(
          attackCode !== null && attackCode !== 'OK',
          `attack presentation on ${label} was not refused (${JSON.stringify(run.phase.receiver)})`,
        );
      } else {
        // The attack is a second request presentation: refused, never OK.
        const refused = run.outcomes.some((o) =>
          o.secondPresentation !== null && o.secondPresentation.ok === false);
        assert.ok(refused, `attack presentation on ${label} was not refused`);
      }
      continue;
    }

    // Non-attack fail-closed modes: never a trusted success on the declared
    // surface (response/plan: no processed OK; delivery/emit: never
    // DELIVERED; span: never SUCCESS).
    switch (mode.surface) {
      case 'PLATFORM_RESPONSE':
      case 'RECEIPT':
      case 'PLAN':
      case 'CIRCUIT':
        assert.ok(
          run.outcomes.every((o) => o.processed.ok === false),
          `fail-closed mode ${label} processed OK`,
        );
        break;
      case 'DELIVERY':
      case 'EMIT':
        assert.notEqual(
          run.phase.delivery.deliveryOutcome, 'DELIVERED',
          `fail-closed mode ${label} delivered`,
        );
        break;
      case 'SPAN':
        assert.notEqual(
          run.platform.spanViews.status, 'SUCCESS',
          `fail-closed mode ${label} span SUCCESS`,
        );
        break;
      case 'RECEIVER':
        assert.equal(
          run.phase.receiver.verified, false,
          `fail-closed mode ${label} receiver verified`,
        );
        break;
      default:
        assert.fail(`unknown surface ${mode.surface} on ${mode.modeId}`);
    }
  }
});

test('catalog: multi-presentation modes carry their presentation counts', () => {
  const cleanRetry = findFailureMode('retry-clean-retryable');
  assert.equal(cleanRetry.inject(wellBehavedScenario(WELL_BEHAVED_SIMULATOR)).presentations, 2);

  const exhaustion = findFailureMode('retry-exhaustion-schedule-bound');
  assert.equal(exhaustion.inject(wellBehavedScenario(WELL_BEHAVED_SIMULATOR)).presentations, 5);

  const circuit = findFailureMode('circuit-threshold-trip-open');
  assert.equal(circuit.inject(wellBehavedScenario(WELL_BEHAVED_SIMULATOR)).presentations, 4);
});
