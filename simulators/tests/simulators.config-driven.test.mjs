// Stop Point 8 — simulators config-driven tests.
//
// Proves a simulator is CONFIGURATION, not code: flipping record DATA flips
// the contract outcome, through the SAME engine code path for every
// simulator identity. No branch anywhere keys on a specific partner,
// entitlement, or capability — the data owns the behavior. Also proves the
// engine-applied fault plans are mechanical (data in, faulted request out)
// and that the platform's world assembly honors its fault records.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SYNTHETIC_SIMULATORS,
  WELL_BEHAVED_SIMULATOR,
  wellBehavedScenario,
  wellBehavedPartnerRecord,
  wellBehavedOrgRecord,
} from '../behaviors.ts';
import { makeScenarioPair, driveScenario } from './helpers.mjs';

// ---------------------------------------------------------------------------
// Registry data flips the authorization verdict (same code path, new data)
// ---------------------------------------------------------------------------

const AUTHORIZATION_FLIPS = [
  ['partner status SUSPENDED', (s) => ({ ...s, partnerRecord: { ...s.partnerRecord, status: 'SUSPENDED' } }), 'PARTNER_SUSPENDED'],
  ['partner status REVOKED', (s) => ({ ...s, partnerRecord: { ...s.partnerRecord, status: 'REVOKED' } }), 'PARTNER_REVOKED'],
  ['org status SUSPENDED', (s) => ({ ...s, orgRecord: { ...s.orgRecord, status: 'SUSPENDED' } }), 'ORG_SUSPENDED'],
  ['org binding INACTIVE', (s) => ({
    ...s,
    orgRecord: {
      ...s.orgRecord,
      partnerBindings: s.orgRecord.partnerBindings.map((b) => ({ ...b, status: 'INACTIVE' })),
    },
  }), 'BINDING_INACTIVE'],
  ['org binding lacks entitlement', (s) => ({
    ...s,
    orgRecord: {
      ...s.orgRecord,
      partnerBindings: s.orgRecord.partnerBindings.map((b) => ({ ...b, entitlements: [] })),
    },
  }), 'BINDING_UNKNOWN'],
  ['org unbound from partner', (s) => ({ ...s, orgRecord: { ...s.orgRecord, partnerBindings: [] } }), 'ORG_NOT_BOUND_TO_PARTNER'],
  ['partner entitlement INACTIVE', (s) => ({
    ...s,
    partnerRecord: {
      ...s.partnerRecord,
      entitlements: s.partnerRecord.entitlements.map((e) => ({ ...e, status: 'INACTIVE' })),
    },
  }), 'ENTITLEMENT_INACTIVE'],
  ['partner entitlement REVOKED', (s) => ({
    ...s,
    partnerRecord: {
      ...s.partnerRecord,
      entitlements: s.partnerRecord.entitlements.map((e) => ({ ...e, status: 'REVOKED' })),
    },
  }), 'ENTITLEMENT_REVOKED'],
  ['partner carries no entitlement', (s) => ({
    ...s,
    partnerRecord: { ...s.partnerRecord, entitlements: [] },
  }), 'ENTITLEMENT_MISSING'],
  ['entitlement capability unknown', (s) => ({
    ...s,
    request: { ...s.request, capability: 'sim-reports-not-listed' },
  }), 'CAPABILITY_UNKNOWN'],
];

for (const [label, flip, expectedCode] of AUTHORIZATION_FLIPS) {
  test(`config-driven: ${label} fails closed with ${expectedCode}`, () => {
    const scenario = flip(wellBehavedScenario(WELL_BEHAVED_SIMULATOR));
    const run = driveScenario(scenario);
    assert.equal(run.outcomes[0].processed.ok, false);
    assert.equal(run.outcomes[0].processed.errorCode, expectedCode);
    assert.equal(run.outcomes[0].processed.status, 403);
    assert.equal(run.platform.decisionView.stage, 'AUTHORIZATION');
    // Fail-closed: no events, no delivery, terminal FAILED span.
    assert.equal(run.phase.events.length, 0);
    assert.equal(run.phase.delivery.deliveryOutcome, null);
    assert.equal(run.platform.spanViews.status, 'FAILED');
  });
}

test('config-driven: the SAME data flip flips every simulator identity identically', () => {
  // The configuration-driven proof: one flip (suspended partner), three
  // different identities — the engine code path never changes, only data.
  for (const identity of SYNTHETIC_SIMULATORS) {
    const scenario = {
      ...wellBehavedScenario(identity),
      partnerRecord: { ...wellBehavedPartnerRecord(identity), status: 'SUSPENDED' },
    };
    const run = driveScenario(scenario);
    assert.equal(run.outcomes[0].processed.errorCode, 'PARTNER_SUSPENDED', `${identity.simulatorId}`);
    assert.equal(run.platform.spanViews.status, 'FAILED', `${identity.simulatorId}`);
  }
});

test('config-driven: world faults omit registry records (unknown partner / org)', () => {
  const unknownPartner = {
    ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
    worldFaults: { omitPartnerRecord: true },
  };
  assert.equal(driveScenario(unknownPartner).outcomes[0].processed.errorCode, 'PARTNER_UNKNOWN');

  const unknownOrg = {
    ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
    worldFaults: { omitOrgRecord: true },
  };
  assert.equal(driveScenario(unknownOrg).outcomes[0].processed.errorCode, 'ORG_UNKNOWN');
});

// ---------------------------------------------------------------------------
// Client fault-plan data drives mechanical faults (data in, request out)
// ---------------------------------------------------------------------------

const CLIENT_FAULT_FLIPS = [
  ['tamperSignature', { tamperSignature: true }, 'SIGNATURE_SIGNATURE_MISMATCH'],
  ['tamperPath', { tamperPath: true }, 'SIGNATURE_SIGNATURE_MISMATCH'],
  ['tamperBody', { tamperBody: true }, 'SIGNATURE_BODY_HASH_INVALID'],
  ['clock skew', { timestampOffsetMs: 10 * 60 * 1000 }, 'SIGNATURE_CLOCK_SKEW_EXCEEDED'],
  ['nonce pattern violation', { nonceOverride: 'short' }, 'SIGNATURE_NONCE_INVALID'],
];

for (const [label, faults, expectedCode] of CLIENT_FAULT_FLIPS) {
  test(`config-driven: ${label} is rejected with ${expectedCode}`, () => {
    const scenario = { ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR), partnerFaults: faults };
    const run = driveScenario(scenario);
    assert.equal(run.outcomes[0].processed.ok, false);
    assert.equal(run.outcomes[0].processed.errorCode, expectedCode);
    assert.equal(run.outcomes[0].processed.status, 401);
    assert.equal(run.platform.spanViews.status, 'FAILED');
    // Terminal classification — a broken signature is never retried.
    assert.equal(run.outcomes[0].retryPlan, 'TERMINAL');
  });
}

test('config-driven: replay + idempotency presentation faults are data-driven', () => {
  // Same signed bytes twice: replay guard burns the nonce.
  const replay = {
    ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
    partnerFaults: { replayPresentation: true },
  };
  const replayRun = driveScenario(replay);
  assert.equal(replayRun.outcomes[0].secondPresentation.ok, false);
  assert.equal(replayRun.outcomes[0].secondPresentation.errorCode, 'REQUEST_REPLAYED');

  // Same key, different bytes: idempotency conflict.
  const conflict = {
    ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
    partnerFaults: { idempotencyConflictPresentation: true },
  };
  const conflictRun = driveScenario(conflict);
  assert.equal(conflictRun.outcomes[0].processed.ok, true);
  assert.equal(conflictRun.outcomes[0].secondPresentation.ok, false);
  assert.equal(conflictRun.outcomes[0].secondPresentation.status, 409);
  assert.equal(conflictRun.outcomes[0].secondPresentation.errorCode, 'IDEMPOTENCY_KEY_CONFLICT');
});

// ---------------------------------------------------------------------------
// Platform fault-plan data drives server-side faults mechanically
// ---------------------------------------------------------------------------

const PLATFORM_FAULT_FLIPS = [
  ['kill switch', { killSwitch: true }, 'PLATFORM_KILL_SWITCH', 503],
  ['downstream UNAVAILABLE', { downstream: 'UNAVAILABLE' }, 'DOWNSTREAM_UNAVAILABLE', 503],
  ['receipt OMIT', { receiptFault: 'OMIT' }, 'RECEIPT_VERIFICATION_FAILED', 200],
];

for (const [label, platformFaults, expectedCode, expectedStatus] of PLATFORM_FAULT_FLIPS) {
  test(`config-driven: ${label} surfaces ${expectedCode}`, () => {
    const scenario = {
      ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
      platformFaults: { ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR).platformFaults, ...platformFaults },
    };
    const run = driveScenario(scenario);
    assert.equal(run.outcomes[0].processed.ok, false);
    assert.equal(run.outcomes[0].processed.errorCode, expectedCode);
    assert.equal(run.outcomes[0].processed.status, expectedStatus);
  });
}

test('config-driven: receipt faults are client-side fail-closed (2xx never trusted blindly)', () => {
  const receiptFaults = ['FORGED', 'TAMPERED', 'WRONG_OPERATION'];
  for (const fault of receiptFaults) {
    const scenario = {
      ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
      platformFaults: { ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR).platformFaults, receiptFault: fault },
    };
    const run = driveScenario(scenario);
    assert.equal(run.outcomes[0].processed.ok, false, fault);
    assert.equal(run.outcomes[0].processed.errorCode, 'RECEIPT_VERIFICATION_FAILED', fault);
    assert.notEqual(run.outcomes[0].processed.receiptFailure, null, fault);
    // Ambiguous, never blindly re-sent.
    assert.equal(run.outcomes[0].retryPlan, 'AMBIGUOUS_RECONCILE', fault);
  }
});

test('config-driven: a FAILS_ONCE_THEN_HEALTHY downstream recovers on the same key', () => {
  // The clean-retryable discipline: availability failures record NO
  // idempotency outcome, so the same-key retry re-executes and recovers.
  const scenario = {
    ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR),
    platformFaults: {
      ...wellBehavedScenario(WELL_BEHAVED_SIMULATOR).platformFaults,
      downstream: 'FAILS_ONCE_THEN_HEALTHY',
    },
    presentations: 2,
  };
  const run = driveScenario(scenario);
  assert.equal(run.outcomes[0].processed.ok, false);
  assert.equal(run.outcomes[0].processed.errorCode, 'DOWNSTREAM_UNAVAILABLE');
  assert.equal(run.outcomes[0].retryPlan, 'CLEAN_RETRY');
  assert.equal(run.outcomes[1].processed.ok, true);
  assert.equal(run.outcomes[1].processed.receiptOutcome, 'SUCCESS');
  assert.equal(run.phase.delivery.deliveryOutcome, 'DELIVERED');
  assert.equal(run.platform.spanViews.status, 'SUCCESS');
});

test('config-driven: scenario records are pure data (frozen identity fixtures)', () => {
  for (const identity of SYNTHETIC_SIMULATORS) {
    const partner = wellBehavedPartnerRecord(identity);
    const org = wellBehavedOrgRecord(identity);
    assert.equal(partner.partnerId, identity.partnerId);
    assert.equal(partner.status, 'ACTIVE');
    assert.equal(org.orgId, identity.orgId);
    assert.equal(org.partnerBindings[0].partnerId, identity.partnerId);
    // The fixtures are freshly built per call — no shared mutable state.
    assert.notEqual(wellBehavedPartnerRecord(identity), partner);
  }
});
