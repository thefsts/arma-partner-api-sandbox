// Stop Point 6 — protected-action registry + decision contract.
//
// Ten protected actions, each with a fail-closed policy: AI is never an
// allowed actor on any of them, every decision is audited, unknown actions
// fail closed, and the only deterministic automation allowance in v1 is the
// fail-closed direction (a rule engine may AUTO-BLOCK evidence destruction
// under a retention hold). AUDIT_MUTATION is denied for every actor class —
// audit history is append-only by construction.

import type { GovernanceStore } from './store.ts';
import type { ProvenanceEnvelope } from './provenance.ts';
import type { DeterministicResultEnvelope } from './deterministicRules.ts';
import { verifyProvenanceEnvelope } from './provenance.ts';
import { verifyDeterministicResultEnvelope } from './deterministicRules.ts';
import { verifyHumanReview } from './humanReview.ts';

export type ProtectedActionKind =
  | 'LAW_SHIELD_DISCLOSURE'
  | 'RBAC_CHANGE'
  | 'ADMIN_GRANT'
  | 'TENANT_OWNERSHIP_CHANGE'
  | 'PARTNER_CREDENTIAL_CHANGE'
  | 'ENTITLEMENT_OVERRIDE'
  | 'SECURITY_POLICY_OVERRIDE'
  | 'EVIDENCE_DESTRUCTION'
  | 'PROTECTED_PARTNER_ACTIVATION_OVERRIDE'
  | 'AUDIT_MUTATION';

export type ProtectedActorClass =
  | 'HUMAN_OPERATOR'
  | 'AI'
  | 'DETERMINISTIC_RULE_ENGINE'
  | 'SYSTEM_AUTOMATION';

export const PROTECTED_ACTION_KINDS: readonly ProtectedActionKind[] = Object.freeze([
  'LAW_SHIELD_DISCLOSURE',
  'RBAC_CHANGE',
  'ADMIN_GRANT',
  'TENANT_OWNERSHIP_CHANGE',
  'PARTNER_CREDENTIAL_CHANGE',
  'ENTITLEMENT_OVERRIDE',
  'SECURITY_POLICY_OVERRIDE',
  'EVIDENCE_DESTRUCTION',
  'PROTECTED_PARTNER_ACTIVATION_OVERRIDE',
  'AUDIT_MUTATION',
]);

export const ACTIVE_POLICY_VERSION = 'ai-governance.policy.v1';

export interface ProtectedActionPolicy {
  readonly action: ProtectedActionKind;
  readonly description: string;
  /** actor classes allowed (post-review); AI is never among them. */
  readonly allowedActorClasses: readonly ProtectedActorClass[];
  /** every protected action requires a human review in v1. */
  readonly humanReviewRequired: boolean;
  /** AI is prohibited on every protected action — always true. */
  readonly aiProhibited: true;
  /** when true, a deterministic engine may automate this action (fail-closed direction only in v1). */
  readonly deterministicAllowed: boolean;
  /** the only rulings a deterministic engine may produce for this action. */
  readonly allowedDeterministicDecisions: readonly string[];
  /** minimum governance policy version that may decide this action. */
  readonly requiredPolicyVersion: string;
  /** every decision is audited — always true. */
  readonly auditRequired: true;
  /** the fail-closed result recorded when the action is denied. */
  readonly failClosedResult: 'DENIED';
}

interface PolicySpec {
  readonly action: ProtectedActionKind;
  readonly description: string;
  readonly allowedActorClasses?: readonly ProtectedActorClass[];
  readonly deterministicAllowed?: boolean;
  readonly allowedDeterministicDecisions?: readonly string[];
}

// The one deterministic automation allowance in v1: a rule engine may
// AUTO-BLOCK evidence destruction under a retention hold. The allowance is
// the fail-closed direction only — no protected action is auto-approvable.
const POLICY_SPECS: readonly PolicySpec[] = [
  { action: 'LAW_SHIELD_DISCLOSURE', description: 'Authorize a Law Shield disclosure' },
  { action: 'RBAC_CHANGE', description: 'Create or change RBAC roles/permissions' },
  { action: 'ADMIN_GRANT', description: 'Grant admin access' },
  { action: 'TENANT_OWNERSHIP_CHANGE', description: 'Change tenant ownership' },
  { action: 'PARTNER_CREDENTIAL_CHANGE', description: 'Change partner credentials' },
  { action: 'ENTITLEMENT_OVERRIDE', description: 'Bypass or override entitlements' },
  { action: 'SECURITY_POLICY_OVERRIDE', description: 'Override security policy' },
  {
    action: 'EVIDENCE_DESTRUCTION',
    description: 'Destroy evidence',
    deterministicAllowed: true,
    allowedDeterministicDecisions: ['AUTO_BLOCK_RETENTION_HOLD'],
  },
  { action: 'PROTECTED_PARTNER_ACTIVATION_OVERRIDE', description: 'Override a protected partner activation' },
  {
    action: 'AUDIT_MUTATION',
    description: 'Rewrite or delete audit records',
    // Append-only by construction: NO actor class may authorize an audit
    // rewrite. The registry entry exists so attempts are classified, audited,
    // and fail closed. Corrections are NEW audit records, never edits.
    allowedActorClasses: [],
  },
];

function buildPolicies(): Readonly<Record<ProtectedActionKind, ProtectedActionPolicy>> {
  const out = {} as Record<ProtectedActionKind, ProtectedActionPolicy>;
  for (const spec of POLICY_SPECS) {
    out[spec.action] = Object.freeze({
      action: spec.action,
      description: spec.description,
      allowedActorClasses: Object.freeze(
        spec.allowedActorClasses ?? (['HUMAN_OPERATOR'] as readonly ProtectedActorClass[]),
      ),
      humanReviewRequired: true,
      aiProhibited: true,
      deterministicAllowed: spec.deterministicAllowed ?? false,
      allowedDeterministicDecisions: Object.freeze([...(spec.allowedDeterministicDecisions ?? [])]),
      requiredPolicyVersion: ACTIVE_POLICY_VERSION,
      auditRequired: true,
      failClosedResult: 'DENIED',
    });
  }
  return out;
}

export const PROTECTED_ACTION_POLICIES: Readonly<Record<ProtectedActionKind, ProtectedActionPolicy>> =
  Object.freeze(buildPolicies());

/** Policy for one action, or null when the action is not in the registry
 *  (unknown actions fail closed). */
export function getProtectedActionPolicy(action: string): ProtectedActionPolicy | null {
  return (PROTECTED_ACTION_KINDS as readonly string[]).includes(action)
    ? PROTECTED_ACTION_POLICIES[action as ProtectedActionKind]
    : null;
}

function safeString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback;
}

export interface ProtectedActionRequest {
  action: string;
  orgId: string;
  actorClass: ProtectedActorClass;
  actorId: string;
  policyVersion: string;
  /** human review of record for this action. */
  humanReview?: { reviewId?: string };
  /** the governed output hash this action is being taken on (review binds to it). */
  outputHash?: string;
  /** true when the action is being taken on the basis of AI advisory output. */
  aiAssisted?: boolean;
  /** the AI advisory provenance envelope the action is based on, when AI-assisted. */
  aiProvenance?: ProvenanceEnvelope;
  /** deterministic rule result envelope, when a rule engine automates (fail-closed only). */
  deterministicProvenance?: DeterministicResultEnvelope;
}

export interface ProtectedActionDecision {
  readonly outcome: 'ALLOWED' | 'DENIED';
  readonly action: string;
  readonly actorClass: ProtectedActorClass | 'UNKNOWN';
  readonly actorId: string;
  readonly orgId: string;
  readonly reasonCode: string;
  readonly auditId: string;
  readonly failClosedResult: 'DENIED' | null;
  readonly reviewedProvenanceId?: string;
  readonly reviewId?: string;
  readonly deterministicRuling?: string;
}

export interface EvaluateProtectedActionParams {
  store: GovernanceStore;
  request: ProtectedActionRequest;
}

export function evaluateProtectedAction(params: EvaluateProtectedActionParams): ProtectedActionDecision {
  const { store, request } = params;
  if (request === null || typeof request !== 'object') throw new Error('PROTECTED_ACTION_REQUEST_INVALID');

  const actorClass: ProtectedActorClass | 'UNKNOWN' =
    request.actorClass === 'HUMAN_OPERATOR' ||
    request.actorClass === 'AI' ||
    request.actorClass === 'DETERMINISTIC_RULE_ENGINE' ||
    request.actorClass === 'SYSTEM_AUTOMATION'
      ? request.actorClass
      : 'UNKNOWN';
  const actorId = safeString(request.actorId, 'UNKNOWN_ACTOR');
  const orgId = safeString(request.orgId, 'UNKNOWN_ORG');
  const orgRef = orgId === 'UNKNOWN_ORG' ? null : orgId;
  const actionLabel = safeString(request.action, 'UNKNOWN_ACTION');

  const decide = (
    outcome: 'ALLOWED' | 'DENIED',
    reasonCode: string,
    details: Record<string, string | number | boolean | null>,
    extra?: { reviewedProvenanceId?: string; reviewId?: string; deterministicRuling?: string },
  ): ProtectedActionDecision => {
    const audit = store.recordAudit({
      kind: 'governance.protected_action.decision',
      subjectId: actionLabel,
      reasonCode,
      details: { actorClass, actorId, orgId, outcome, ...details },
      orgRef,
    });
    return {
      outcome,
      action: actionLabel,
      actorClass,
      actorId,
      orgId,
      reasonCode,
      auditId: audit.auditId,
      failClosedResult: outcome === 'DENIED' ? 'DENIED' : null,
      ...(extra?.reviewedProvenanceId !== undefined ? { reviewedProvenanceId: extra.reviewedProvenanceId } : {}),
      ...(extra?.reviewId !== undefined ? { reviewId: extra.reviewId } : {}),
      ...(extra?.deterministicRuling !== undefined ? { deterministicRuling: extra.deterministicRuling } : {}),
    };
  };

  // 1) Unknown protected action -> FAIL CLOSED (audited).
  const policy = getProtectedActionPolicy(request.action);
  if (policy === null) {
    return decide('DENIED', 'PROTECTED_ACTION_UNKNOWN', {
      presentedAction: safeString(request.action, 'NOT_A_STRING'),
    });
  }

  // 2) Policy version mismatch -> FAIL CLOSED (audited).
  if (typeof request.policyVersion !== 'string' || request.policyVersion !== policy.requiredPolicyVersion) {
    return decide('DENIED', 'POLICY_VERSION_STALE', {
      presentedPolicyVersion: safeString(request.policyVersion, 'POLICY_VERSION_INVALID'),
      requiredPolicyVersion: policy.requiredPolicyVersion,
    });
  }

  // 3) Unknown actor class -> FAIL CLOSED (audited).
  if (actorClass === 'UNKNOWN') {
    return decide('DENIED', 'ACTOR_CLASS_UNKNOWN', { actorClassLabel: safeString(request.actorClass, 'NOT_A_STRING') });
  }

  // 4) AI actor -> ALWAYS denied (audited). AI is never authority, and an AI
  //    identity can never stand in as the human reviewer of record.
  if (actorClass === 'AI') {
    return decide('DENIED', 'AI_ACTOR_DENIED', { reviewRef: safeString(request.humanReview?.reviewId, 'NONE') });
  }

  // 5) System automation is not an authorized actor for protected actions in
  //    v1 (no policy lists it) -> FAIL CLOSED.
  if (actorClass === 'SYSTEM_AUTOMATION') {
    return decide('DENIED', 'SYSTEM_ACTOR_DENIED', {});
  }

  // 6) Deterministic rule engine: automation only where allowed, and only
  //    the fail-closed ruling set. The engine must present a VERIFIED
  //    deterministic result envelope (its own designation — never labeled AI).
  if (actorClass === 'DETERMINISTIC_RULE_ENGINE') {
    if (!policy.deterministicAllowed) {
      return decide('DENIED', 'DETERMINISTIC_AUTOMATION_DENIED', { actionKind: policy.action });
    }
    const envelope = request.deterministicProvenance;
    if (envelope === undefined || envelope === null) {
      return decide('DENIED', 'DETERMINISTIC_DECISION_MISSING', {});
    }
    const check = verifyDeterministicResultEnvelope({
      store,
      envelope,
      expectedPolicyVersion: policy.requiredPolicyVersion,
    });
    if (!check.ok) {
      return decide('DENIED', 'DETERMINISTIC_PROVENANCE_INVALID', {
        resultRef: safeString(envelope.resultId, 'UNKNOWN_RESULT'),
        reasonCode: check.reasonCode ?? 'DETERMINISTIC_VERIFY_FAILED',
      });
    }
    const ruling = envelope.result.ruling;
    if (!policy.allowedDeterministicDecisions.includes(ruling)) {
      return decide('DENIED', 'DETERMINISTIC_DECISION_DENIED', { ruling });
    }
    // The allowed automation is the fail-closed direction: the auto-block
    // ruling stands as the decision-of-record and the REQUEST is denied.
    return decide('DENIED', 'DETERMINISTIC_AUTO_BLOCKED', {
      ruling,
      resultRef: envelope.resultId,
      deterministicRuling: ruling,
    }, { deterministicRuling: ruling });
  }

  // 7) HUMAN_OPERATOR path. Human review is required for every protected
  //    action in v1 (humanReviewRequired: true on all policies).
  if (!policy.allowedActorClasses.includes('HUMAN_OPERATOR')) {
    // AUDIT_MUTATION: no actor class may authorize rewriting audit history
    // (append-only by construction). The attempt is classified, audited, and
    // FAIL CLOSED — a valid human review can never unlock it.
    return decide('DENIED', 'ACTOR_CLASS_NOT_ALLOWED', { actionKind: policy.action });
  }
  const reviewId = request.humanReview?.reviewId;
  if (typeof reviewId !== 'string' || !reviewId.trim()) {
    return decide('DENIED', 'HUMAN_REVIEW_REQUIRED', {});
  }

  // AI-assisted requests must present the advisory provenance envelope.
  const aiLinked = request.aiProvenance !== undefined && request.aiProvenance !== null;
  if (!aiLinked && request.aiAssisted === true) {
    return decide('DENIED', 'AI_PROVENANCE_MISSING', { reviewRef: reviewId });
  }

  // The review binds to the hash of the governed output being actioned: the
  // AI envelope's outputHash when AI-linked, otherwise the request's.
  let outputHash: string;
  if (aiLinked) {
    const envelope = request.aiProvenance as ProvenanceEnvelope;
    const check = verifyProvenanceEnvelope({
      store,
      envelope,
      expectedPolicyVersion: policy.requiredPolicyVersion,
    });
    if (!check.ok) {
      return decide('DENIED', 'AI_PROVENANCE_INVALID', {
        provenanceRef: safeString(envelope.provenanceId, 'UNKNOWN_PROVENANCE'),
        reasonCode: check.reasonCode ?? 'AI_PROVENANCE_VERIFY_FAILED',
      });
    }
    // An AI-linked action must be based on AI ADVISORY output only.
    if (envelope.designation !== 'AI_ADVISORY') {
      return decide('DENIED', 'AI_PROVENANCE_INVALID', {
        provenanceRef: safeString(envelope.provenanceId, 'UNKNOWN_PROVENANCE'),
        reasonCode: 'DESIGNATION_NOT_ADVISORY',
      });
    }
    outputHash = envelope.outputHash;
  } else if (typeof request.outputHash === 'string' && /^[a-f0-9]{64}$/.test(request.outputHash)) {
    outputHash = request.outputHash;
  } else {
    return decide('DENIED', 'HUMAN_REVIEW_INVALID', {
      reviewRef: reviewId,
      reasonCode: 'REVIEW_OUTPUT_HASH_ABSENT',
    });
  }

  // Verify the human review: durable, audited, scoped to action + org, hash
  // matched, and the ACTING human must be the reviewer of record.
  const reviewCheck = verifyHumanReview({
    store,
    reviewId,
    action: policy.action,
    orgId,
    outputHash,
    actorReviewerId: actorId,
  });
  if (!reviewCheck.ok) {
    return decide('DENIED', 'HUMAN_REVIEW_INVALID', { reviewRef: reviewId, reasonCode: reviewCheck.reasonCode });
  }

  return decide(
    'ALLOWED',
    aiLinked ? 'HUMAN_AUTHORIZED_ON_ADVISORY' : 'HUMAN_AUTHORIZED',
    {
      reviewRef: reviewId,
      ...(aiLinked ? { provenanceRef: (request.aiProvenance as ProvenanceEnvelope).provenanceId } : {}),
    },
    {
      reviewId,
      ...(aiLinked ? { reviewedProvenanceId: (request.aiProvenance as ProvenanceEnvelope).provenanceId } : {}),
    },
  );
}
