// Stop Point 6 — AI output guard.
//
// Governed AI output is ADVISORY ONLY. This guard rejects any AI output that
// attempts to authorize a protected action, impersonate a human authorizer,
// claim authority, modify credentials, override entitlements / tenancy /
// security, suppress audit or human review, direct evidence destruction, or
// smuggle instructions to other systems. Impersonation is checked FIRST
// (identity fraud is the root offense). Advisory language — including
// recommendations and flags for human review — passes. Rejection carries NO
// content and is audited; allowed output is audited too (no unaudited AI
// actions).

import type { GovernanceStore } from './store.ts';
import { checkEngineDesignation } from './classification.ts';

interface PatternRule {
  readonly id: string;
  readonly pattern: RegExp;
  readonly reasonCode: string;
}

const MAX_AI_OUTPUT_BYTES = 2 * 1024 * 1024; // 2MB

const FORBIDDEN_PATTERNS: readonly PatternRule[] = Object.freeze([
  // Impersonating a human authorizer (checked first: identity fraud is the
  // root offense; an authorization verb inside an impersonated identity is a
  // secondary symptom and must not mask the impersonation diagnosis).
  { id: 'AI_IMPERSONATE_HUMAN', pattern: /\b(?:as\s+(?:a\s+)?(?:human|authorized\s+human|reviewer|approver|supervisor)|on\s+behalf\s+of\s+(?:a\s+|an\s+)?(?:human|authorized\s+human|reviewer|approver|supervisor|user))\b/i, reasonCode: 'AI_HUMAN_IMPERSONATION' },
  { id: 'AI_SIGNED_AS_HUMAN', pattern: /\b(?:signed|approved|authorized)\s+by\s*:\s*(?:a\s+)?(?:human|reviewer|approver)\b/i, reasonCode: 'AI_HUMAN_IMPERSONATION' },
  { id: 'AI_HUMAN_ID_CLAIM', pattern: /\b(?:i\s+am|this\s+is|acting\s+as)\s+(?:an?\s+)?(?:authorized\s+human|human\s+reviewer|human\s+approver|verified\s+human)\b/i, reasonCode: 'AI_HUMAN_IMPERSONATION' },

  // AI attempting to AUTHORIZE a protected action.
  { id: 'AI_AUTHORIZE', pattern: /\b(?:i\s+|we\s+)?(?:hereby\s+)?(?:authorize|approve|grant|sanction|clear)\s+(?:this\s+|the\s+|your\s+)?(?:disclosure|action|request|activation|override|transfer)\b/i, reasonCode: 'AI_AUTHORIZATION_ATTEMPT' },
  { id: 'AI_AUTHORIZATION_COMPLETE', pattern: /\b(?:authorization|approval)\s+(?:is\s+|has\s+been\s+|was\s+)?(?:granted|approved|complete[d]?|confirmed)\b/i, reasonCode: 'AI_AUTHORIZATION_ATTEMPT' },
  { id: 'AI_ACT_ON_MY_BEHALF', pattern: /\b(?:act|proceed|execute|go\s+ahead)\s+(?:on\s+)?(?:my|our)\s+behalf\b/i, reasonCode: 'AI_AUTHORIZATION_ATTEMPT' },
  { id: 'AI_LAW_SHIELD_AUTH', pattern: /\b(?:law\s*shield|disclosure)\s+(?:is\s+|has\s+been\s+)?(?:authorized|approved|cleared|permitted)\b/i, reasonCode: 'AI_AUTHORIZATION_ATTEMPT' },
  { id: 'AI_PROTECTED_ACTION_APPROVED', pattern: /\b(?:protected\s+action|evidence\s+destruction|credential\s+change|ownership\s+change|entitlement\s+override|policy\s+override|rbac\s+change|admin\s+grant)\s+(?:is\s+|has\s+been\s+)?(?:authorized|approved|permitted|allowed)\b/i, reasonCode: 'AI_AUTHORIZATION_ATTEMPT' },

  // Claiming admin/role authority.
  { id: 'AI_ADMIN_AUTHORITY', pattern: /\b(?:i|we|this\s+system)\s+(?:have|has)\s+(?:admin|administrator|root|superuser|elevated)\s+(?:access|privileges?|authority|rights?)\b/i, reasonCode: 'AI_AUTHORITY_CLAIM' },
  { id: 'AI_ROLE_CLAIM', pattern: /\b(?:acting\s+(?:with|as)|granted|holding)\s+(?:the\s+)?(?:admin|administrator|root|owner|superuser)\s+(?:role|permissions?)\b/i, reasonCode: 'AI_AUTHORITY_CLAIM' },
  { id: 'AI_GRANT_ADMIN', pattern: /\b(?:grant(?:ing)?|giving)\s+(?:you|me|them|the\s+user)\s+(?:admin|administrator|root|superuser)\s+(?:access|privileges?|role)\b/i, reasonCode: 'AI_AUTHORITY_CLAIM' },
  { id: 'AI_ROLE_CHANGE', pattern: /\b(?:i\s+|we\s+)?(?:am\s+|are\s+)?(?:promot(?:ing|e)|elevat(?:ing|e)|upgrad(?:ing|e))\s+(?:your|the|this)\s+(?:role|permissions?|access\s+level)\b/i, reasonCode: 'AI_AUTHORITY_CLAIM' },

  // Credential modification.
  { id: 'AI_CREDENTIAL_CHANGE', pattern: /\b(?:change|update|rotate|replace|set|reset|delete|remove)\s+(?:the\s+|your\s+|our\s+|their\s+)?(?:partner\s+)?(?:credentials?|api\s+keys?|secrets?|signing\s+keys?|tokens?)\b/i, reasonCode: 'AI_CREDENTIAL_MODIFICATION' },
  { id: 'AI_CREDENTIAL_DONE', pattern: /\b(?:credentials?|api\s+keys?|signing\s+keys?|secrets?)\s+(?:have\s+been|will\s+be|are\s+now)\s+(?:changed|updated|rotated|replaced|set|reset|deleted|removed)\b/i, reasonCode: 'AI_CREDENTIAL_MODIFICATION' },
  { id: 'AI_NEW_CREDENTIAL', pattern: /\b(?:new|updated)\s+(?:credential|api\s+key|signing\s+key|secret)\s+(?:value|is|:)\b/i, reasonCode: 'AI_CREDENTIAL_MODIFICATION' },

  // Entitlement override.
  { id: 'AI_ENTITLEMENT_OVERRIDE', pattern: /\b(?:override|bypass|skip|ignore|disable)\s+(?:the\s+|all\s+|any\s+)?(?:entitlement|entitlements|license|licensing)\s+(?:check|checks|restrictions?|controls?|limits?)\b/i, reasonCode: 'AI_ENTITLEMENT_OVERRIDE' },
  { id: 'AI_ENTITLED_ANYWAY', pattern: /\b(?:treat|consider|mark)\s+(?:the\s+)?(?:org|organization|tenant|user)\s+as\s+(?:entitled|licensed)\b/i, reasonCode: 'AI_ENTITLEMENT_OVERRIDE' },

  // Tenant boundary override.
  { id: 'AI_TENANT_OVERRIDE', pattern: /\b(?:override|bypass|cross|ignore|disable)\s+(?:the\s+|all\s+)?(?:tenant|org|organization)\s+(?:boundar(?:y|ies)|isolation|restrictions?|separation)\b/i, reasonCode: 'AI_TENANT_OVERRIDE' },
  { id: 'AI_CROSS_TENANT_ACCESS', pattern: /\b(?:access|read|write|query)\s+(?:(?:the|another|other)\s+)*(?:tenant'?s?|org'?s?|organization'?s?)\s+(?:data|records?|activations?|cases?)\b/i, reasonCode: 'AI_TENANT_OVERRIDE' },

  // Security control override.
  { id: 'AI_SECURITY_OVERRIDE', pattern: /\b(?:bypass|override|disable|ignore)\s+(?:the\s+|all\s+)?(?:security\s+controls?|security\s+polic(?:y|ies)|safety\s+controls?|guardrails?)\b/i, reasonCode: 'AI_SECURITY_OVERRIDE' },
  { id: 'AI_POLICY_OVERRIDE', pattern: /\b(?:override|bypass)\s+(?:this\s+|the\s+|that\s+)?polic(?:y|ies)\b/i, reasonCode: 'AI_SECURITY_OVERRIDE' },

  // Audit suppression / rewriting.
  { id: 'AI_SUPPRESS_AUDIT', pattern: /\b(?:suppress|hide|conceal)\s+(?:the\s+|all\s+)?(?:audit|audit\s+trail|audit\s+records?|logging)\b/i, reasonCode: 'AI_AUDIT_SUPPRESSION' },
  { id: 'AI_NO_AUDIT', pattern: /\b(?:off\s+the\s+record|no\s+audit(?:ing)?|without\s+(?:any\s+)?audit(?:ing)?)\b/i, reasonCode: 'AI_AUDIT_SUPPRESSION' },
  { id: 'AI_REWRITE_AUDIT', pattern: /\b(?:rewrite|edit|alter|falsify|delete)\s+(?:the\s+|all\s+)?(?:audit\s+records?|audit\s+trail|logs?)\b/i, reasonCode: 'AI_AUDIT_SUPPRESSION' },

  // Human-review suppression (AI cannot waive required human review).
  { id: 'AI_SUPPRESS_REVIEW', pattern: /\bno\s+human\s+review\s+(?:is\s+)?(?:needed|required|necessary)\b/i, reasonCode: 'AI_REVIEW_SUPPRESSION' },
  { id: 'AI_SELF_REVIEW', pattern: /\b(?:i|we)\s+will\s+self[-\s]?review\b/i, reasonCode: 'AI_REVIEW_SUPPRESSION' },
  { id: 'AI_REVIEW_NOT_REQUIRED', pattern: /\bhuman\s+review\s+is\s+not\s+required\b/i, reasonCode: 'AI_REVIEW_SUPPRESSION' },

  // Evidence destruction / retention bypass.
  { id: 'AI_EVIDENCE_DELETION', pattern: /\b(?:delete|destroy|erase|purge|shred)\s+(?:the\s+|all\s+|these\s+)?(?:evidence|evidence\s+files?|records?|artifacts?)\b/i, reasonCode: 'AI_EVIDENCE_DESTRUCTION' },
  { id: 'AI_RETENTION_BYPASS', pattern: /\b(?:ignore|bypass|skip|override)\s+(?:the\s+|our\s+)?retention\s+(?:policy|policies|requirements?|holds?)\b/i, reasonCode: 'AI_EVIDENCE_DESTRUCTION' },

  // Smuggling instructions to other systems.
  { id: 'AI_INSTRUCT_BYPASS', pattern: /\b(?:instruct|tell|direct|order)\s+(?:(?:the|another|other)\s+)*(?:system|module|service|component|process)\s+to\s+(?:skip|bypass|ignore|disable|avoid)\b/i, reasonCode: 'AI_BYPASS_INSTRUCTION' },
  { id: 'AI_SEND_INSTRUCTION', pattern: /\bsend\s+(?:this|that|the\s+following|an?)\s+instruction\s+to\s+(?:(?:the|another|other)\s+|\w+\s+)*(?:system|module|service|component|process)\b/i, reasonCode: 'AI_BYPASS_INSTRUCTION' },
]);

export interface AiOutputGuardInput {
  readonly engineId: string;
  readonly orgRef?: string | null;
  readonly output: string;
  readonly taskType: string;
}

export type AiOutputGuardResult =
  | { readonly ok: true; readonly reasonCode: 'AI_ADVISORY_OUTPUT_ALLOWED'; readonly patternId: null; readonly auditId: string }
  | { readonly ok: false; readonly reasonCode: string; readonly patternId: string; readonly auditId: string };

/**
 * Guard AI output: advisory language passes (audited as allowed); any
 * authority/impersonation/override/suppression attempt is rejected with NO
 * content in the rejection, and the rejection is audited. The engine must be
 * a registered generative-AI engine on its advisory lane — advisory output
 * from any other lane is a classification failure.
 */
export function guardAiOutput(store: GovernanceStore, input: AiOutputGuardInput): AiOutputGuardResult {
  if (input === null || typeof input !== 'object') throw new Error('AI_OUTPUT_INPUT_INVALID');
  if (typeof input.engineId !== 'string' || !input.engineId.trim()) {
    throw new Error('AI_OUTPUT_ENGINE_ID_INVALID');
  }
  if (typeof input.taskType !== 'string' || !input.taskType.trim()) {
    throw new Error('AI_OUTPUT_INPUT_INVALID');
  }
  if (typeof input.output !== 'string') throw new Error('AI_OUTPUT_BYTES_REQUIRED');
  if (Buffer.byteLength(input.output, 'utf8') > MAX_AI_OUTPUT_BYTES) {
    throw new Error('AI_OUTPUT_TOO_LARGE');
  }

  // Engine must be registered and on its one legal advisory lane.
  const engine = store.getEngine(input.engineId);
  if (engine === null) throw new Error('AI_OUTPUT_ENGINE_ID_INVALID');
  const classification = checkEngineDesignation(engine, 'AI_ADVISORY', input.taskType);
  if (!classification.ok) throw new Error(classification.reasonCode);

  for (const rule of FORBIDDEN_PATTERNS) {
    if (rule.pattern.test(input.output)) {
      const audit = store.recordAudit({
        kind: 'governance.ai_output.rejected',
        subjectId: input.engineId,
        reasonCode: rule.reasonCode,
        details: {
          patternId: rule.id,
          taskType: input.taskType,
          orgId: input.orgRef ?? 'UNKNOWN',
          designation: 'AI_ADVISORY',
        },
        orgRef: input.orgRef ?? null,
      });
      return { ok: false, reasonCode: rule.reasonCode, patternId: rule.id, auditId: audit.auditId };
    }
  }

  const audit = store.recordAudit({
    kind: 'governance.ai_output.allowed',
    subjectId: input.engineId,
    reasonCode: 'AI_ADVISORY_OUTPUT_ALLOWED',
    details: {
      taskType: input.taskType,
      orgId: input.orgRef ?? 'UNKNOWN',
      designation: 'AI_ADVISORY',
      advisoryOnly: true,
    },
    orgRef: input.orgRef ?? null,
  });
  return { ok: true, reasonCode: 'AI_ADVISORY_OUTPUT_ALLOWED', patternId: null, auditId: audit.auditId };
}
