// Stop Point 6 — human review contract.
//
// A protected action proceeds only on a durable, audited human review by an
// authenticated, org/action-authorized HUMAN reviewer bound to the exact
// governed output hash. An AI identity can never be the reviewer, and the
// acting human operator must BE the reviewer of record. Stale or changed
// output (hash mismatch) invalidates the review — fail closed.

import type { GovernanceStore } from './store.ts';

export type ReviewerActorType = 'HUMAN' | 'AI' | 'SYSTEM';

export interface HumanReviewer {
  readonly reviewerId: string;
  readonly actorType: ReviewerActorType;
  readonly orgId: string;
  readonly authenticated: boolean;
  readonly authorizedActions: readonly string[];
}

export interface HumanReviewRecord {
  readonly reviewId: string;
  readonly reviewerId: string;
  readonly actorType: 'HUMAN';
  readonly orgId: string;
  readonly action: string;
  readonly outputHash: string;
  readonly at: number;
  readonly auditId: string;
}

export interface RecordHumanReviewParams {
  store: GovernanceStore;
  reviewer: HumanReviewer;
  action: string;
  orgId: string;
  outputHash: string;
}

export type RecordReviewOutcome =
  | { ok: true; review: HumanReviewRecord; auditId: string }
  | { ok: false; reasonCode: string };

export interface VerifyHumanReviewParams {
  store: GovernanceStore;
  reviewId: string;
  action: string;
  orgId: string;
  outputHash: string;
  /** for HUMAN_OPERATOR actors the acting human must BE the reviewer. */
  actorReviewerId?: string;
}

export type VerifyReviewOutcome =
  | { ok: true; review: HumanReviewRecord }
  | { ok: false; reasonCode: string };

const REVIEWER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
const ACTION_PATTERN = /^[A-Z][A-Z0-9_]{2,63}$/;

/**
 * Record a human review — durable and audited, or not at all. Every
 * eligibility rule fails closed:
 *   REVIEWER_INVALID / REVIEWER_MUST_BE_HUMAN / REVIEWER_NOT_AUTHENTICATED /
 *   REVIEWER_ORG_MISMATCH / REVIEWER_NOT_AUTHORIZED_FOR_ACTION /
 *   REVIEW_ACTION_INVALID / REVIEW_OUTPUT_HASH_INVALID.
 * The audit record carries identifiers + hash only (never note text, never
 * output content — enforced by audit.ts key/value rules).
 */
export function recordHumanReview(params: RecordHumanReviewParams): RecordReviewOutcome {
  const { store, reviewer, action, orgId, outputHash } = params;
  if (reviewer === null || typeof reviewer !== 'object' || typeof reviewer.reviewerId !== 'string') {
    return { ok: false, reasonCode: 'REVIEWER_INVALID' };
  }
  if (reviewer.actorType !== 'HUMAN') {
    return { ok: false, reasonCode: 'REVIEWER_MUST_BE_HUMAN' };
  }
  if (reviewer.authenticated !== true) {
    return { ok: false, reasonCode: 'REVIEWER_NOT_AUTHENTICATED' };
  }
  if (typeof orgId !== 'string' || !orgId.trim() || reviewer.orgId !== orgId) {
    return { ok: false, reasonCode: 'REVIEWER_ORG_MISMATCH' };
  }
  if (typeof action !== 'string' || !ACTION_PATTERN.test(action)) {
    return { ok: false, reasonCode: 'REVIEW_ACTION_INVALID' };
  }
  if (!REVIEWER_ID_PATTERN.test(reviewer.reviewerId)) {
    return { ok: false, reasonCode: 'REVIEWER_INVALID' };
  }
  if (typeof outputHash !== 'string' || !/^[a-f0-9]{64}$/.test(outputHash)) {
    return { ok: false, reasonCode: 'REVIEW_OUTPUT_HASH_INVALID' };
  }
  if (!Array.isArray(reviewer.authorizedActions) || !reviewer.authorizedActions.includes(action)) {
    return { ok: false, reasonCode: 'REVIEWER_NOT_AUTHORIZED_FOR_ACTION' };
  }

  const reviewId = store.nextReviewId();
  const at = store.clock.now();
  const audit = store.recordAudit({
    kind: 'governance.human_review.recorded',
    subjectId: reviewer.reviewerId,
    reasonCode: 'HUMAN_REVIEW_RECORDED',
    details: {
      reviewId,
      action,
      outputHash,
      orgId,
      actorType: 'HUMAN',
      authenticated: true,
    },
    orgRef: orgId,
  });
  const review: HumanReviewRecord = Object.freeze({
    reviewId,
    reviewerId: reviewer.reviewerId,
    actorType: 'HUMAN',
    orgId,
    action,
    outputHash,
    at,
    auditId: audit.auditId,
  });
  store.putReview(review);
  return { ok: true, review, auditId: audit.auditId };
}

/**
 * Verify a review of record for a protected-action decision: the review must
 * exist (durable), be scoped to the SAME action and org, bind to the SAME
 * governed output hash, and — when an acting human presents it — the acting
 * human must be the reviewer of record. Anything else fails closed:
 *   REVIEW_NOT_FOUND / REVIEW_ACTION_MISMATCH / REVIEW_ORG_MISMATCH /
 *   REVIEW_OUTPUT_HASH_MISMATCH / REVIEWER_ACTOR_MISMATCH.
 */
export function verifyHumanReview(params: VerifyHumanReviewParams): VerifyReviewOutcome {
  const { store, reviewId, action, orgId, outputHash, actorReviewerId } = params;
  if (typeof reviewId !== 'string' || !reviewId.trim()) {
    return { ok: false, reasonCode: 'REVIEW_NOT_FOUND' };
  }
  const review = store.getReview(reviewId);
  if (review === null) {
    return { ok: false, reasonCode: 'REVIEW_NOT_FOUND' };
  }
  if (review.action !== action) {
    return { ok: false, reasonCode: 'REVIEW_ACTION_MISMATCH' };
  }
  if (review.orgId !== orgId) {
    return { ok: false, reasonCode: 'REVIEW_ORG_MISMATCH' };
  }
  if (review.outputHash !== outputHash) {
    return { ok: false, reasonCode: 'REVIEW_OUTPUT_HASH_MISMATCH' };
  }
  if (actorReviewerId !== undefined && review.reviewerId !== actorReviewerId) {
    return { ok: false, reasonCode: 'REVIEWER_ACTOR_MISMATCH' };
  }
  return { ok: true, review };
}
