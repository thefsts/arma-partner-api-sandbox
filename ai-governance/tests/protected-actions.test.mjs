// Stop Point 6 — protected-action registry + decision tests.
//
// Every protected action fails closed for AI actors on ALL ten actions, for
// unknown actions, stale policy versions, unknown actor classes, automation
// misuse, and missing/invalid human review; authorized humans pass; every
// decision is audited; audit mutation is denied AND audited.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateProtectedAction, PROTECTED_ACTION_KINDS, PROTECTED_ACTION_POLICIES, ACTIVE_POLICY_VERSION,
} from '../protectedActions.ts';
import {
  makeClock, makeGovernedStore, provenanceInput, deterministicInput, CLEAN_ADVISORY_OUTPUT,
  makeReviewer, recordValidReview, ORG, OTHER_ORG, ADVISORY_ENGINE,
} from './helpers.mjs';
import { createProvenanceEnvelope } from '../provenance.ts';
import { createDeterministicResult } from '../deterministicRules.ts';
import { computeOutputHash } from '../provenanceIntegrity.ts';

test('protected-actions: registry lists exactly the ten owner-specified actions with full policy shape', () => {
  const actions = Object.values(PROTECTED_ACTION_POLICIES);
  assert.deepEqual(
    actions.map((a) => a.action).sort(),
    [
      'ADMIN_GRANT', 'AUDIT_MUTATION', 'ENTITLEMENT_OVERRIDE', 'EVIDENCE_DESTRUCTION',
      'LAW_SHIELD_DISCLOSURE', 'PARTNER_CREDENTIAL_CHANGE', 'PROTECTED_PARTNER_ACTIVATION_OVERRIDE',
      'RBAC_CHANGE', 'SECURITY_POLICY_OVERRIDE', 'TENANT_OWNERSHIP_CHANGE',
    ].sort(),
  );
  assert.equal(actions.length, 10);
  for (const spec of actions) {
    assert.equal(spec.requiredPolicyVersion, ACTIVE_POLICY_VERSION, spec.action);
    assert.equal(spec.humanReviewRequired, true, spec.action);
    assert.equal(spec.aiProhibited, true, spec.action);
    assert.equal(spec.auditRequired, true, spec.action);
    assert.equal(spec.failClosedResult, 'DENIED', spec.action);
    // AI is never an allowed actor class on any protected action.
    assert.equal(spec.allowedActorClasses.includes('AI'), false, spec.action);
  }
});

test('protected-actions: AI actors are denied on ALL ten actions — AI is never authority', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const before = store.listAudit().length;
  for (const action of PROTECTED_ACTION_KINDS) {
    const decision = evaluateProtectedAction({
      store,
      request: {
        action,
        orgId: ORG,
        actorClass: 'AI',
        actorId: 'sandbox-advisory-engine-1',
        policyVersion: ACTIVE_POLICY_VERSION,
        // AI attempting to smuggle a human review of record.
        humanReview: { reviewId: 'REV-000001' },
        aiAssisted: true,
      },
    });
    assert.equal(decision.outcome, 'DENIED', action);
    assert.equal(decision.reasonCode, 'AI_ACTOR_DENIED', action);
    assert.equal(decision.failClosedResult, 'DENIED', action);
    assert.ok(decision.auditId, action);
  }
  // Every attempt was audited.
  assert.equal(store.listAudit().length, before + 10);
  for (const record of store.listAudit().slice(before)) {
    assert.equal(record.kind, 'governance.protected_action.decision');
    assert.equal(record.reasonCode, 'AI_ACTOR_DENIED');
    assert.equal(record.details.outcome, 'DENIED');
  }
});

test('protected-actions: unknown action fails closed (no policy -> deny + audit)', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const before = store.listAudit().length;
  const decision = evaluateProtectedAction({
    store,
    request: {
      action: 'MADE_UP_ACTION',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
    },
  });
  assert.equal(decision.outcome, 'DENIED');
  assert.equal(decision.reasonCode, 'PROTECTED_ACTION_UNKNOWN');
  assert.equal(decision.failClosedResult, 'DENIED');
  // The attempt was still audited (classified even on denial).
  assert.equal(store.listAudit().length, before + 1);
  const audit = store.listAudit()[store.listAudit().length - 1];
  assert.equal(audit.kind, 'governance.protected_action.decision');
  assert.equal(audit.subjectId, 'MADE_UP_ACTION');
  assert.equal(audit.reasonCode, 'PROTECTED_ACTION_UNKNOWN');
});

test('protected-actions: stale or wrong policy version fails closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  for (const presented of ['ai-governance.policy.v0', '', 'garbage']) {
    const decision = evaluateProtectedAction({
      store,
      request: {
        action: 'RBAC_CHANGE',
        orgId: ORG,
        actorClass: 'HUMAN_OPERATOR',
        actorId: 'human.reviewer-1',
        policyVersion: presented,
      },
    });
    assert.equal(decision.outcome, 'DENIED', `policy="${presented}"`);
    assert.equal(decision.reasonCode, 'POLICY_VERSION_STALE', `policy="${presented}"`);
    assert.equal(decision.failClosedResult, 'DENIED', `policy="${presented}"`);
  }
});

test('protected-actions: unknown actor class and system automation fail closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const unknown = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'GHOST',
      actorId: 'ghost-actor-1',
      policyVersion: ACTIVE_POLICY_VERSION,
    },
  });
  assert.equal(unknown.outcome, 'DENIED');
  assert.equal(unknown.reasonCode, 'ACTOR_CLASS_UNKNOWN');
  assert.equal(unknown.failClosedResult, 'DENIED');

  // SYSTEM_AUTOMATION is not an authorized actor class for any protected action in v1.
  for (const action of PROTECTED_ACTION_KINDS) {
    const decision = evaluateProtectedAction({
      store,
      request: {
        action,
        orgId: ORG,
        actorClass: 'SYSTEM_AUTOMATION',
        actorId: 'sandbox-system-automation-1',
        policyVersion: ACTIVE_POLICY_VERSION,
      },
    });
    assert.equal(decision.outcome, 'DENIED', action);
    assert.equal(decision.reasonCode, 'SYSTEM_ACTOR_DENIED', action);
    assert.equal(decision.failClosedResult, 'DENIED', action);
  }
});

test('protected-actions: missing human review fails closed with HUMAN_REVIEW_REQUIRED', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const decision = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      outputHash: 'a'.repeat(64),
    },
  });
  assert.equal(decision.outcome, 'DENIED');
  assert.equal(decision.reasonCode, 'HUMAN_REVIEW_REQUIRED');
  assert.equal(decision.failClosedResult, 'DENIED');
  const audit = store.listAudit().find((r) => r.reasonCode === 'HUMAN_REVIEW_REQUIRED');
  assert.ok(audit);
  assert.equal(audit.kind, 'governance.protected_action.decision');
});

test('protected-actions: aiAssisted without a provenance envelope fails closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const reviewer = makeReviewer();
  const review = recordValidReview(store, reviewer, 'LAW_SHIELD_DISCLOSURE', 'a'.repeat(64));
  const decision = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      aiAssisted: true,
      humanReview: { reviewId: review.reviewId },
      outputHash: 'a'.repeat(64),
    },
  });
  assert.equal(decision.outcome, 'DENIED');
  assert.equal(decision.reasonCode, 'AI_PROVENANCE_MISSING');
});

test('protected-actions: AI-linked action with invalid/tampered provenance fails closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const envelope = createProvenanceEnvelope({
    store,
    governedOutput: CLEAN_ADVISORY_OUTPUT,
    input: provenanceInput(t.now()),
  });
  const reviewer = makeReviewer();
  const review = recordValidReview(store, reviewer, 'LAW_SHIELD_DISCLOSURE', envelope.outputHash);
  // Tampered envelope metadata -> METADATA_TAMPERED surfaces as AI_PROVENANCE_INVALID.
  const tampered = { ...envelope, decisionReasonCode: 'TAMPERED_REASON' };
  const decision = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      aiAssisted: true,
      aiProvenance: tampered,
      humanReview: { reviewId: review.reviewId },
    },
  });
  assert.equal(decision.outcome, 'DENIED');
  assert.equal(decision.reasonCode, 'AI_PROVENANCE_INVALID');
  assert.equal(decision.failClosedResult, 'DENIED');
  const audit = store.listAudit().find((r) => r.reasonCode === 'AI_PROVENANCE_INVALID');
  assert.ok(audit);
  // The nested reason code is carried in the audit details (no content).
  assert.equal(audit.details.reasonCode, 'METADATA_TAMPERED');
});

test('protected-actions: human review bound to a different hash fails closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const envelope = createProvenanceEnvelope({
    store,
    governedOutput: CLEAN_ADVISORY_OUTPUT,
    input: provenanceInput(t.now()),
  });
  const reviewer = makeReviewer();
  // Review signed over a DIFFERENT output than the envelope's.
  const review = recordValidReview(store, reviewer, 'LAW_SHIELD_DISCLOSURE', 'b'.repeat(64));
  const decision = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      aiAssisted: true,
      aiProvenance: envelope,
      humanReview: { reviewId: review.reviewId },
    },
  });
  assert.equal(decision.outcome, 'DENIED');
  assert.equal(decision.reasonCode, 'HUMAN_REVIEW_INVALID');
  assert.equal(decision.failClosedResult, 'DENIED');
  const audit = store.listAudit().find((r) => r.reasonCode === 'HUMAN_REVIEW_INVALID');
  assert.equal(audit.details.reasonCode, 'REVIEW_OUTPUT_HASH_MISMATCH');
});

test('protected-actions: acting human must be the reviewer of record', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const envelope = createProvenanceEnvelope({
    store,
    governedOutput: CLEAN_ADVISORY_OUTPUT,
    input: provenanceInput(t.now()),
  });
  const reviewer = makeReviewer();
  const review = recordValidReview(store, reviewer, 'LAW_SHIELD_DISCLOSURE', envelope.outputHash);
  // A DIFFERENT human presents the review.
  const decision = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.other-operator-9',
      policyVersion: ACTIVE_POLICY_VERSION,
      aiAssisted: true,
      aiProvenance: envelope,
      humanReview: { reviewId: review.reviewId },
    },
  });
  assert.equal(decision.outcome, 'DENIED');
  assert.equal(decision.reasonCode, 'HUMAN_REVIEW_INVALID');
  const audit = store.listAudit().find((r) => r.reasonCode === 'HUMAN_REVIEW_INVALID');
  assert.equal(audit.details.reasonCode, 'REVIEWER_ACTOR_MISMATCH');
});

test('protected-actions: authorized human on verified advisory provenance is ALLOWED', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const envelope = createProvenanceEnvelope({
    store,
    governedOutput: CLEAN_ADVISORY_OUTPUT,
    input: provenanceInput(t.now()),
  });
  const reviewer = makeReviewer();
  const review = recordValidReview(store, reviewer, 'LAW_SHIELD_DISCLOSURE', envelope.outputHash);
  const before = store.listAudit().length;
  const decision = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      aiAssisted: true,
      aiProvenance: envelope,
      humanReview: { reviewId: review.reviewId },
    },
  });
  assert.equal(decision.outcome, 'ALLOWED');
  assert.equal(decision.reasonCode, 'HUMAN_AUTHORIZED_ON_ADVISORY');
  assert.equal(decision.failClosedResult, null);
  assert.equal(decision.reviewId, review.reviewId);
  assert.equal(decision.reviewedProvenanceId, envelope.provenanceId);
  // The ALLOWED decision is audited too.
  assert.equal(store.listAudit().length, before + 1);
  const audit = store.listAudit()[store.listAudit().length - 1];
  assert.equal(audit.kind, 'governance.protected_action.decision');
  assert.equal(audit.reasonCode, 'HUMAN_AUTHORIZED_ON_ADVISORY');
  assert.equal(audit.details.outcome, 'ALLOWED');
  assert.equal(audit.details.actorClass, 'HUMAN_OPERATOR');
});

test('protected-actions: non-AI-assisted action requires request outputHash + matched review', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const hash = computeOutputHash('direct human workflow payload');
  const reviewer = makeReviewer();
  const review = recordValidReview(store, reviewer, 'PARTNER_CREDENTIAL_CHANGE', hash);
  const ok = evaluateProtectedAction({
    store,
    request: {
      action: 'PARTNER_CREDENTIAL_CHANGE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      humanReview: { reviewId: review.reviewId },
      outputHash: hash,
    },
  });
  assert.equal(ok.outcome, 'ALLOWED');
  assert.equal(ok.reasonCode, 'HUMAN_AUTHORIZED');

  // Missing outputHash on a non-AI-assisted request -> fail closed.
  const missing = evaluateProtectedAction({
    store,
    request: {
      action: 'PARTNER_CREDENTIAL_CHANGE',
      orgId: ORG,
      actorClass: 'HUMAN_OPERATOR',
      actorId: 'human.reviewer-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      humanReview: { reviewId: review.reviewId },
    },
  });
  assert.equal(missing.outcome, 'DENIED');
  assert.equal(missing.reasonCode, 'HUMAN_REVIEW_INVALID');
  const audit = store.listAudit().filter((r) => r.reasonCode === 'HUMAN_REVIEW_INVALID').pop();
  assert.equal(audit.details.reasonCode, 'REVIEW_OUTPUT_HASH_ABSENT');
});

test('protected-actions: deterministic rule engines may only automate the fail-closed direction', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // Where automation is disallowed at all, the engine is denied outright.
  const denied = evaluateProtectedAction({
    store,
    request: {
      action: 'LAW_SHIELD_DISCLOSURE',
      orgId: ORG,
      actorClass: 'DETERMINISTIC_RULE_ENGINE',
      actorId: 'sandbox-rule-engine-1',
      policyVersion: ACTIVE_POLICY_VERSION,
    },
  });
  assert.equal(denied.outcome, 'DENIED');
  assert.equal(denied.reasonCode, 'DETERMINISTIC_AUTOMATION_DENIED');
  assert.equal(denied.failClosedResult, 'DENIED');

  // Where automation is allowed, a valid envelope with the fail-closed ruling
  // records the auto-block as decision-of-record; the REQUEST is denied.
  const envelope = createDeterministicResult({
    store,
    input: deterministicInput(t.now()),
  });
  const auto = evaluateProtectedAction({
    store,
    request: {
      action: 'EVIDENCE_DESTRUCTION',
      orgId: ORG,
      actorClass: 'DETERMINISTIC_RULE_ENGINE',
      actorId: 'sandbox-rule-engine-1',
      policyVersion: ACTIVE_POLICY_VERSION,
      deterministicProvenance: envelope,
    },
  });
  assert.equal(auto.outcome, 'DENIED');
  assert.equal(auto.reasonCode, 'DETERMINISTIC_AUTO_BLOCKED');
  assert.equal(auto.deterministicRuling, 'AUTO_BLOCK_RETENTION_HOLD');
  assert.equal(auto.failClosedResult, 'DENIED');
  const audit = store.listAudit().find((r) => r.reasonCode === 'DETERMINISTIC_AUTO_BLOCKED');
  assert.ok(audit);
  assert.equal(audit.details.ruling, 'AUTO_BLOCK_RETENTION_HOLD');
});

test('protected-actions: AUDIT_MUTATION is denied for every actor class (append-only by construction)', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const hash = computeOutputHash('audit mutation attempt');
  const reviewer = makeReviewer();
  // Even a fully valid human review of record cannot unlock audit rewriting.
  const review = recordValidReview(store, reviewer, 'AUDIT_MUTATION', hash);
  for (const actorClass of ['HUMAN_OPERATOR', 'AI', 'SYSTEM_AUTOMATION', 'DETERMINISTIC_RULE_ENGINE']) {
    const decision = evaluateProtectedAction({
      store,
      request: {
        action: 'AUDIT_MUTATION',
        orgId: ORG,
        actorClass,
        actorId: actorClass === 'AI' ? 'sandbox-advisory-engine-1' : 'human.reviewer-1',
        policyVersion: ACTIVE_POLICY_VERSION,
        humanReview: { reviewId: review.reviewId },
        outputHash: hash,
      },
    });
    assert.equal(decision.outcome, 'DENIED', actorClass);
    assert.equal(decision.failClosedResult, 'DENIED', actorClass);
    // AI still gets the precise AI prohibition; humans get ACTOR_CLASS_NOT_ALLOWED.
    if (actorClass === 'AI') {
      assert.equal(decision.reasonCode, 'AI_ACTOR_DENIED', actorClass);
    } else if (actorClass === 'HUMAN_OPERATOR') {
      assert.equal(decision.reasonCode, 'ACTOR_CLASS_NOT_ALLOWED', actorClass);
    } else if (actorClass === 'SYSTEM_AUTOMATION') {
      assert.equal(decision.reasonCode, 'SYSTEM_ACTOR_DENIED', actorClass);
    } else {
      assert.equal(decision.reasonCode, 'DETERMINISTIC_AUTOMATION_DENIED', actorClass);
    }
  }
  // Every attempt is audited — four decisions for AUDIT_MUTATION, one per class.
  const audits = store.listAudit().filter((r) => r.subjectId === 'AUDIT_MUTATION');
  assert.equal(audits.length, 4);
  for (const audit of audits) {
    assert.equal(audit.kind, 'governance.protected_action.decision');
    assert.equal(audit.details.outcome, 'DENIED');
  }
});

test('protected-actions: structural request failures throw fail closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  assert.throws(() => evaluateProtectedAction({ store, request: null }), /PROTECTED_ACTION_REQUEST_INVALID/);
});

test('protected-actions: audit store refuses mutation attempts and audits the refusal', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const someAudit = store.listAudit()[0];
  const result = store.auditLog.attemptMutation(someAudit.auditId, { reasonCode: 'REDACTED' });
  assert.equal(result.ok, false);
  const refusal = store.listAudit().find((r) => r.kind === 'governance.audit.mutation_denied');
  assert.ok(refusal);
  // The original record is untouched.
  const stillThere = store.auditLog.find(someAudit.auditId);
  assert.deepEqual(stillThere, someAudit);
});
