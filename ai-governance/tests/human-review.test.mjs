// Human review of record — the durable human authorization checkpoint.
// A review is either recorded by an authenticated, authorized human bound to
// the exact governed output hash, or it does not exist. Everything else
// fails closed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeClock, makeGovernedStore, makeReviewer, ORG, OTHER_ORG, ADVISORY_ENGINE, provenanceInput, recordValidReview } from './helpers.mjs';
import { recordHumanReview, verifyHumanReview } from '../humanReview.ts';
import { createProvenanceEnvelope, verifyProvenanceEnvelope } from '../provenance.ts';
import { computeOutputHash } from '../provenanceIntegrity.ts';

const ACTION = 'LAW_SHIELD_DISCLOSURE';
const HASH_A = computeOutputHash('governed output A');
const HASH_B = computeOutputHash('governed output B');

test('human review: a valid review is recorded, audited, and durable', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const reviewer = makeReviewer();
  const before = store.listAudit().length;
  const out = recordHumanReview({ store, reviewer, action: ACTION, orgId: ORG, outputHash: HASH_A });
  assert.equal(out.ok, true);
  const review = out.review;
  assert.equal(review.reviewerId, reviewer.reviewerId);
  assert.equal(review.actorType, 'HUMAN');
  assert.equal(review.orgId, ORG);
  assert.equal(review.action, ACTION);
  assert.equal(review.outputHash, HASH_A);
  assert.equal(review.at, t.now());
  assert.ok(review.reviewId);
  assert.ok(out.auditId);
  // Durable: retrievable from the store, and frozen (no mutation after the fact).
  assert.deepEqual(store.getReview(review.reviewId), review);
  assert.throws(() => { review.outputHash = HASH_B; });
  // Audited metadata-only.
  const audits = store.listAudit();
  assert.equal(audits.length, before + 1);
  const audit = audits[audits.length - 1];
  assert.equal(audit.kind, 'governance.human_review.recorded');
  assert.equal(audit.reasonCode, 'HUMAN_REVIEW_RECORDED');
  assert.equal(audit.subjectId, reviewer.reviewerId);
  assert.equal(audit.details.reviewId, review.reviewId);
  assert.equal(audit.details.outputHash, HASH_A);
  assert.ok(!JSON.stringify(audit).includes('governed output'), 'audit must not carry output content');
});

test('human review: reviewer eligibility fails closed (identity, auth, org, authorization)', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const base = { action: ACTION, orgId: ORG, outputHash: HASH_A };
  // AI identity may never be the reviewer of record.
  const aiReviewer = recordHumanReview({ store, reviewer: makeReviewer({ actorType: 'AI' }), ...base });
  assert.equal(aiReviewer.ok, false);
  assert.equal(aiReviewer.reasonCode, 'REVIEWER_MUST_BE_HUMAN');
  const systemReviewer = recordHumanReview({ store, reviewer: makeReviewer({ actorType: 'SYSTEM' }), ...base });
  assert.equal(systemReviewer.ok, false);
  assert.equal(systemReviewer.reasonCode, 'REVIEWER_MUST_BE_HUMAN');
  // Unauthenticated reviewer fails closed.
  const unauthenticated = recordHumanReview({ store, reviewer: makeReviewer({ authenticated: false }), ...base });
  assert.equal(unauthenticated.ok, false);
  assert.equal(unauthenticated.reasonCode, 'REVIEWER_NOT_AUTHENTICATED');
  // Cross-org reviewer fails closed.
  const crossOrg = recordHumanReview({ store, reviewer: makeReviewer({ orgId: OTHER_ORG }), ...base });
  assert.equal(crossOrg.ok, false);
  assert.equal(crossOrg.reasonCode, 'REVIEWER_ORG_MISMATCH');
  // Reviewer without the action's authorization fails closed.
  const unauthorized = recordHumanReview({ store, reviewer: makeReviewer({ authorizedActions: ['EVIDENCE_DESTRUCTION'] }), ...base });
  assert.equal(unauthorized.ok, false);
  assert.equal(unauthorized.reasonCode, 'REVIEWER_NOT_AUTHORIZED_FOR_ACTION');
  // Malformed reviewer identity / action / hash fail closed structurally.
  const badId = recordHumanReview({ store, reviewer: makeReviewer({ reviewerId: 'bad id!' }), ...base });
  assert.equal(badId.ok, false);
  assert.equal(badId.reasonCode, 'REVIEWER_INVALID');
  const noId = recordHumanReview({ store, reviewer: null, ...base });
  assert.equal(noId.ok, false);
  assert.equal(noId.reasonCode, 'REVIEWER_INVALID');
  const badAction = recordHumanReview({ store, reviewer: makeReviewer(), action: 'not an action', orgId: ORG, outputHash: HASH_A });
  assert.equal(badAction.ok, false);
  assert.equal(badAction.reasonCode, 'REVIEW_ACTION_INVALID');
  const badHash = recordHumanReview({ store, reviewer: makeReviewer(), action: ACTION, orgId: ORG, outputHash: 'not-a-hash' });
  assert.equal(badHash.ok, false);
  assert.equal(badHash.reasonCode, 'REVIEW_OUTPUT_HASH_INVALID');
  // Nothing above was recorded or audited.
  assert.equal(store.listAudit().filter((a) => a.kind === 'governance.human_review.recorded').length, 0);
});

test('human review: verification binds action, org, output hash, and reviewer identity', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const reviewer = makeReviewer();
  const recorded = recordValidReview(store, reviewer, ACTION, HASH_A);
  const reviewId = recorded.reviewId;
  // Exact match verifies.
  const okVerify = verifyHumanReview({ store, reviewId, action: ACTION, orgId: ORG, outputHash: HASH_A });
  assert.equal(okVerify.ok, true);
  assert.equal(okVerify.review.reviewId, reviewId);
  // Acting human is the reviewer of record.
  const actorVerify = verifyHumanReview({ store, reviewId, action: ACTION, orgId: ORG, outputHash: HASH_A, actorReviewerId: reviewer.reviewerId });
  assert.equal(actorVerify.ok, true);
  // A different acting human presenting the review fails closed.
  const actorMismatch = verifyHumanReview({ store, reviewId, action: ACTION, orgId: ORG, outputHash: HASH_A, actorReviewerId: 'human.other-operator-9' });
  assert.equal(actorMismatch.ok, false);
  assert.equal(actorMismatch.reasonCode, 'REVIEWER_ACTOR_MISMATCH');
  // Wrong action / org / output hash each fail closed.
  const wrongAction = verifyHumanReview({ store, reviewId, action: 'EVIDENCE_DESTRUCTION', orgId: ORG, outputHash: HASH_A });
  assert.equal(wrongAction.ok, false);
  assert.equal(wrongAction.reasonCode, 'REVIEW_ACTION_MISMATCH');
  const wrongOrg = verifyHumanReview({ store, reviewId, action: ACTION, orgId: OTHER_ORG, outputHash: HASH_A });
  assert.equal(wrongOrg.ok, false);
  assert.equal(wrongOrg.reasonCode, 'REVIEW_ORG_MISMATCH');
  const wrongHash = verifyHumanReview({ store, reviewId, action: ACTION, orgId: ORG, outputHash: HASH_B });
  assert.equal(wrongHash.ok, false);
  assert.equal(wrongHash.reasonCode, 'REVIEW_OUTPUT_HASH_MISMATCH');
  // Unknown review id fails closed.
  const unknown = verifyHumanReview({ store, reviewId: 'REV-999999', action: ACTION, orgId: ORG, outputHash: HASH_A });
  assert.equal(unknown.ok, false);
  assert.equal(unknown.reasonCode, 'REVIEW_NOT_FOUND');
});

test('human review: a review binds to the governed output — a changed output invalidates it', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // A real governed advisory output with its provenance envelope.
  const governedOutput = 'Advisory summary: partner feed shows two flagged items. Recommend human review before any disclosure decision.';
  const envelope = createProvenanceEnvelope({ store, governedOutput, input: provenanceInput(t.now()) });
  const reviewer = makeReviewer();
  const review = recordValidReview(store, reviewer, ACTION, envelope.outputHash);
  // The exact bytes still verify against the envelope's output hash.
  const okVerify = verifyHumanReview({ store, reviewId: review.reviewId, action: ACTION, orgId: ORG, outputHash: envelope.outputHash });
  assert.equal(okVerify.ok, true);
  // Output changed after the fact ("approval shopping" on new bytes) —
  // the old review no longer covers it and verification fails closed.
  const tamperedOutput = `${governedOutput} Actually, no review needed.`;
  const tamperedVerify = verifyHumanReview({
    store,
    reviewId: review.reviewId,
    action: ACTION,
    orgId: ORG,
    outputHash: computeOutputHash(tamperedOutput),
  });
  assert.equal(tamperedVerify.ok, false);
  assert.equal(tamperedVerify.reasonCode, 'REVIEW_OUTPUT_HASH_MISMATCH');
  // The provenance envelope ALSO flags the changed bytes.
  const envelopeCheck = verifyProvenanceEnvelope({ store, envelope, governedOutput: tamperedOutput });
  assert.equal(envelopeCheck.ok, false);
  assert.equal(envelopeCheck.reasonCode, 'OUTPUT_TAMPERED');
});

