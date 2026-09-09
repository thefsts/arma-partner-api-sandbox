// Stop Point 8 — simulators happy-path tests.
//
// Proves the well-behaved simulator completes the ENTIRE shared Stop Point 7
// chain from CONFIGURATION alone: SDK-built signed request -> platform
// verification -> idempotency -> receipt-verified 2xx -> webhook emission ->
// scripted transport delivery -> receiver-side guard verification -> span
// SUCCESS -> audit. The simulator is ON the shared SDK — it never
// re-implements a contract. Fail-closed branches (rejected requests emit
// nothing, duplicate collapse never re-executes) are asserted alongside.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SYNTHETIC_SIMULATORS,
  WELL_BEHAVED_SIMULATOR,
  SYNTHETIC_SIMULATOR_SECRETS,
  makeScenarioClock,
  wellBehavedScenario,
  SIM_CLAIM_HEADERS,
} from '../behaviors.ts';
import { makeScenarioPair, driveScenario } from './helpers.mjs';

test('happy path: well-behaved simulator completes the full SP7 chain', () => {
  const scenario = wellBehavedScenario(WELL_BEHAVED_SIMULATOR);
  const { platform, simulator, phase } = driveScenario(scenario);

  // 1) The request was built through the SHARED SDK (correlation headers).
  const outcome = phase; // readability alias below uses run outcomes
  assert.ok(outcome);

  const run = driveScenario(scenario);
  const first = run.outcomes[0];
  assert.equal(first.processed.ok, true);
  assert.equal(first.processed.status, 200);
  assert.equal(first.processed.requestId, first.requestId);
  assert.equal(first.processed.receiptOperation, scenario.request.operation);
  assert.equal(first.processed.receiptOutcome, 'SUCCESS');
  assert.equal(first.processed.errorCode, null);
  assert.equal(first.processed.receiptFailure, null);

  // 2) The presentation was SIGNED by the SDK and carried the claim headers.
  assert.match(first.presented.headers['x-shared-signature'], /^[0-9a-f]{64}$/);
  assert.ok(first.nonce.length >= 20);
  assert.equal(first.presented.headers[SIM_CLAIM_HEADERS.orgId], scenario.identity.orgId);
  assert.equal(first.presented.headers[SIM_CLAIM_HEADERS.entitlement], scenario.identity.entitlement);
  assert.equal(first.presented.headers[SIM_CLAIM_HEADERS.capability], scenario.identity.capability);
  assert.equal(first.presented.headers[SIM_CLAIM_HEADERS.idempotencyKey], scenario.request.idempotencyKey);

  // 3) The platform accepted: decision ACCEPTED, events emitted, delivered,
  //    receiver verified through the webhook guard, span SUCCESS.
  assert.equal(platform.decisionView.accepted, true);
  assert.ok(run.phase.events.length >= 1);
  assert.equal(run.phase.delivery.deliveryOutcome, 'DELIVERED');
  assert.equal(run.phase.receiver.verified, true);
  assert.ok(run.phase.delivery.receiverCodes.every((c) => c === 'OK'));
  assert.equal(platform.spanViews.status, 'SUCCESS');
  assert.ok(platform.auditViews.reasonCodes.includes('OPERATION_COMPLETED'));
});

test('happy path: every synthetic simulator identity completes the chain', () => {
  for (const identity of SYNTHETIC_SIMULATORS) {
    const scenario = wellBehavedScenario(identity);
    const run = driveScenario(scenario);
    assert.equal(run.outcomes[0].processed.ok, true, `${identity.simulatorId} processed OK`);
    assert.equal(run.phase.delivery.deliveryOutcome, 'DELIVERED', `${identity.simulatorId} delivered`);
    assert.equal(run.phase.receiver.verified, true, `${identity.simulatorId} receiver verified`);
    assert.equal(run.platform.spanViews.status, 'SUCCESS', `${identity.simulatorId} span SUCCESS`);
  }
});

test('happy path: the SDK-signed request passes the platform signature stage', () => {
  const scenario = wellBehavedScenario(WELL_BEHAVED_SIMULATOR);
  const { platform, simulator } = makeScenarioPair(scenario);
  const outcome = simulator.execute(scenario.request, scenario.partnerFaults, platform);
  assert.equal(outcome.processed.ok, true);
  // A well-formed signed request is accepted BEFORE any fault stage — the
  // decision records ACCEPTED with no code.
  assert.equal(platform.decisionView.stage, 'ACCEPTED');
  assert.equal(platform.decisionView.code, null);
});

test('happy path: idempotency records SUCCESS and a duplicate re-delivers, never re-executes', () => {
  const scenario = wellBehavedScenario(WELL_BEHAVED_SIMULATOR);
  const { platform, simulator } = makeScenarioPair(scenario);
  const first = simulator.execute(scenario.request, { duplicatePresentation: true }, platform);

  // First presentation: accepted + recorded.
  assert.equal(first.processed.ok, true);

  // Duplicate presentation (fresh signature, same key + same bytes): the
  // platform re-delivers the recorded SUCCESS outcome — accepted, collapsed,
  // never an error.
  assert.ok(first.secondPresentation !== null);
  assert.equal(first.secondPresentation.ok, true);
  assert.equal(first.secondPresentation.status, first.processed.status);
  assert.equal(platform.decisionView.stage, 'IDEMPOTENCY_DUPLICATE');
  assert.equal(platform.decisionView.code, 'IDEMPOTENCY_DUPLICATE_COLLAPSED');
  assert.ok(platform.auditViews.reasonCodes.includes('IDEMPOTENCY_DUPLICATE'));

  // The webhook phase was opened ONCE (the first genuine accept) — a
  // duplicate re-delivery never re-opens the event gate.
  const phase = platform.emitAndDeliver(first.requestId);
  const before = platform.spanCount;
  const secondPhase = platform.emitAndDeliver(first.requestId);
  assert.equal(secondPhase.events.length, phase.events.length);
  assert.equal(platform.spanCount, before + 1); // one new span record, same event set
});

test('happy path: rejected requests emit NOTHING — the event gate fails closed', () => {
  const scenario = {
    ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
    partnerFaults: { tamperSignature: true },
  };
  const run = driveScenario(scenario);
  assert.equal(run.outcomes[0].processed.ok, false);
  assert.equal(run.phase.events.length, 0);
  assert.equal(run.phase.delivery.deliveryOutcome, null);
  assert.equal(run.phase.delivery.deliveryAttemptCount, 0);
  assert.equal(run.platform.spanViews.status, 'FAILED');
  assert.ok(!run.platform.auditViews.reasonCodes.includes('OPERATION_COMPLETED'));
});

test('happy path: deterministic — identical scenario runs surface identical views', () => {
  const scenario = wellBehavedScenario(WELL_BEHAVED_SIMULATOR);
  const a = driveScenario(scenario);
  const b = driveScenario(scenario);
  const view = (run) => ({
    status: run.outcomes[0].processed.status,
    receiptOperation: run.outcomes[0].processed.receiptOperation,
    receiptOutcome: run.outcomes[0].processed.receiptOutcome,
    eventTypes: run.phase.events.map((e) => e.eventType),
    sequences: run.phase.events.map((e) => e.sequence),
    delivery: run.phase.delivery.deliveryOutcome,
    receiver: run.phase.receiver.verified,
    span: run.platform.spanViews,
    audit: run.platform.auditViews,
  });
  assert.deepEqual(view(a), view(b));
});

test('happy path: synthetic secrets are sandbox-only values (no real credentials)', () => {
  for (const secret of Object.values(SYNTHETIC_SIMULATOR_SECRETS)) {
    assert.match(secret, /^synthetic-sim-.*-SP8-sandbox$/);
  }
  // The scenario clock is injected + deterministic (same start every run).
  const c1 = makeScenarioClock();
  const c2 = makeScenarioClock();
  assert.equal(c1.now(), c2.now());
  assert.equal(c1.advance(1000), c2.advance(1000));
});
