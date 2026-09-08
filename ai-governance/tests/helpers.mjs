// Stop Point 6 — shared test fixtures for the AI governance contract.
//
// Synthetic sandbox material only: a fake clock, four registered engines
// (one per legal lane), a default advisory provenance input, a deterministic
// rule result input, an authorized human reviewer, and a clean advisory
// output that passes the AI output guard. No private engine names, prompts,
// or keys — this is the public integration-facing contract.

import { GovernanceStore } from '../store.ts';
import { ACTIVE_POLICY_VERSION, PROTECTED_ACTION_KINDS } from '../protectedActions.ts';
import { recordHumanReview } from '../humanReview.ts';

export const ORG = 'org-sandbox-1';
export const OTHER_ORG = 'org-sandbox-2';

/** Deterministic fake clock — every test timestamp comes from here. */
export function makeClock(startMs = 1_700_000_000_000) {
  let t = startMs;
  return {
    clock: { now: () => t },
    now: () => t,
    advance(ms) { t += ms; return t; },
  };
}

export function makeStore(clockFixture) {
  return new GovernanceStore({ clock: clockFixture.clock });
}

// One frozen fixture engine per legal lane — advisory AI, deterministic
// rules, human console, system automation.
export const ADVISORY_ENGINE = Object.freeze({
  engineId: 'sandbox-advisory-engine-1',
  engineClass: 'GENERATIVE_AI',
  engineVersion: 'v1.0.0',
  designation: 'AI_ADVISORY',
  advisoryOnly: true,
});

export const RULE_ENGINE = Object.freeze({
  engineId: 'sandbox-rule-engine-1',
  engineClass: 'DETERMINISTIC_RULE_ENGINE',
  engineVersion: 'v2.1.0',
  designation: 'DETERMINISTIC_RULE',
  advisoryOnly: false,
});

export const HUMAN_ENGINE = Object.freeze({
  engineId: 'sandbox-human-console-1',
  engineClass: 'HUMAN_OPERATOR_CONSOLE',
  engineVersion: 'v1.0.0',
  designation: 'HUMAN_AUTHORIZATION',
  advisoryOnly: false,
});

export const SYSTEM_ENGINE = Object.freeze({
  engineId: 'sandbox-system-automation-1',
  engineClass: 'SYSTEM_AUTOMATION_ENGINE',
  engineVersion: 'v1.0.0',
  designation: 'SYSTEM_AUTOMATION',
  advisoryOnly: false,
});

/** A governed store with all four lane engines registered (and audited). */
export function makeGovernedStore(clockFixture) {
  const store = makeStore(clockFixture);
  store.registerEngine(ADVISORY_ENGINE);
  store.registerEngine(RULE_ENGINE);
  store.registerEngine(HUMAN_ENGINE);
  store.registerEngine(SYSTEM_ENGINE);
  return store;
}

/** Default advisory provenance input — a flagged-for-review advisory. */
export function provenanceInput(now, overrides = {}) {
  return {
    engineId: ADVISORY_ENGINE.engineId,
    taskType: 'analyze',
    timestamp: now,
    sourceReferences: ['partner-feed:item-001', 'partner-feed:item-002'],
    confidence: 0.82,
    humanReviewRequired: true,
    reviewingHumanId: 'human.reviewer-1',
    reviewTimestamp: now,
    requestCorrelationId: 'corr-0001',
    orgRef: ORG,
    dataClassification: 'SYNTHETIC',
    externalDataPresent: true,
    protectedActionRequested: true,
    decisionReasonCode: 'ADVISORY_FLAGGED_FOR_HUMAN_REVIEW',
    ...overrides,
  };
}

/** Default deterministic rule-engine result input — a retention auto-block. */
export function deterministicInput(now, overrides = {}) {
  return {
    engineId: RULE_ENGINE.engineId,
    ruleVersion: 'rules.v1',
    taskType: 'policy_evaluation',
    inputReferences: ['retention-hold:case-001'],
    ruling: 'AUTO_BLOCK_RETENTION_HOLD',
    decisionReasonCode: 'RETENTION_HOLD_ACTIVE',
    timestamp: now,
    orgRef: ORG,
    ...overrides,
  };
}

/** An authenticated human reviewer authorized for every protected action. */
export function makeReviewer(overrides = {}) {
  return {
    reviewerId: 'human.reviewer-1',
    actorType: 'HUMAN',
    orgId: ORG,
    authenticated: true,
    authorizedActions: [...PROTECTED_ACTION_KINDS],
    ...overrides,
  };
}

/** Advisory output that passes the AI output guard cleanly. */
export const CLEAN_ADVISORY_OUTPUT =
  'Advisory summary: the partner feed shows two flagged items. ' +
  'Recommend human review before any disclosure decision.';

/** Record a valid human review of record; returns the review record. */
export function recordValidReview(store, reviewer, action, outputHash) {
  const outcome = recordHumanReview({
    store,
    reviewer,
    action,
    orgId: reviewer.orgId,
    outputHash,
  });
  if (!outcome.ok) {
    throw new Error(`fixture review failed: ${outcome.reasonCode}`);
  }
  return outcome.review;
}

export { ACTIVE_POLICY_VERSION };
