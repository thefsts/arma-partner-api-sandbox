// Stop Point 6 — external partner-data guard.
//
// Partner/external text is DATA, never instructions. Everything entering a
// governed AI task through this guard is scanned for embedded instructions:
// prompt injection, prompt extraction, tool/function-call embedding,
// authorization override, privilege escalation, RBAC grants, policy bypass,
// secret extraction, and fake system-policy claims. A hit rejects the WHOLE
// payload (no content in the rejection — reason code + pattern id only) and
// is audited. Clean data passes VERBATIM and is recorded as
// EXTERNAL_PARTNER_DATA by hash.

import type { GovernanceStore } from './store.ts';
import { normalizeKey, EXTERNAL_DATA_DESIGNATION } from './classification.ts';
import { computeOutputHash } from './provenanceIntegrity.ts';

interface PatternRule {
  readonly id: string;
  readonly pattern: RegExp;
  readonly reasonCode: string;
}

const MAX_TOTAL_STRING_BYTES = 2 * 1024 * 1024; // 2MB total string budget
const MAX_SCAN_DEPTH = 24;

/** External data sources are namespaced refs, e.g. partner-feed:item-001. */
const SOURCE_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;

/** Keys whose mere presence means embedded instructions. */
const FORBIDDEN_INSTRUCTION_KEYS = new Set([
  'systemprompt', 'prompt', 'instruction', 'instructions', 'newinstructions',
  'developermessage', 'systemmessage', 'toolcall', 'tool', 'tools',
  'availabletools', 'functioncall', 'functionschema', 'function',
]);

const FORBIDDEN_PATTERNS: readonly PatternRule[] = Object.freeze([
  // Prompt injection / instruction override.
  { id: 'IGNORE_PREVIOUS', pattern: /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above)\s+instructions/i, reasonCode: 'PROMPT_INJECTION_DETECTED' },
  { id: 'DISREGARD_INSTRUCTIONS', pattern: /disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above|your)\s+instructions/i, reasonCode: 'PROMPT_INJECTION_DETECTED' },
  { id: 'OVERRIDE_INSTRUCTIONS', pattern: /override\s+(?:your\s+|the\s+|all\s+)?(?:instructions|directives|rules|guardrails)/i, reasonCode: 'PROMPT_INJECTION_DETECTED' },
  { id: 'NEW_INSTRUCTIONS', pattern: /new\s+instructions\s+(?:from|take)\s+(?:the\s+)?(?:system|developer|operator)/i, reasonCode: 'PROMPT_INJECTION_DETECTED' },

  // Prompt extraction.
  { id: 'REVEAL_SYSTEM_PROMPT', pattern: /reveal\s+(?:your\s+|the\s+)?system\s+prompt/i, reasonCode: 'PROMPT_EXTRACTION_DETECTED' },
  { id: 'PRINT_SYSTEM_PROMPT', pattern: /print\s+(?:your\s+|the\s+)?system\s+prompt/i, reasonCode: 'PROMPT_EXTRACTION_DETECTED' },
  { id: 'REVEAL_INSTRUCTIONS', pattern: /(?:show|reveal|share|repeat)\s+(?:your\s+|the\s+|all\s+)?(?:instructions|directives|initial\s+prompt)/i, reasonCode: 'PROMPT_EXTRACTION_DETECTED' },

  // Embedded tool / function-call instructions.
  { id: 'TOOL_CALL', pattern: /(?:call|invoke|use|run)\s+(?:the\s+|your\s+|all\s+)?tools?\s+(?:now|to|and)/i, reasonCode: 'TOOL_INSTRUCTION_DETECTED' },
  { id: 'TOOL_CALL_NOW', pattern: /tool\s*:\s*invoke\s+(?:the\s+)?\w+\s+function/i, reasonCode: 'TOOL_INSTRUCTION_DETECTED' },
  { id: 'AVAILABLE_TOOLS', pattern: /available_?tools\s*:/i, reasonCode: 'TOOL_INSTRUCTION_DETECTED' },
  { id: 'FUNCTION_CALL', pattern: /invoke\s+(?:the\s+)?function\s+\w+/i, reasonCode: 'FUNCTION_INSTRUCTION_DETECTED' },
  { id: 'FUNCTION_SCHEMA', pattern: /functions\s*:\s*\{|function_?schema\s*:/i, reasonCode: 'FUNCTION_INSTRUCTION_DETECTED' },
  { id: 'JSON_FUNCTION_INVOCATION', pattern: /"name"\s*:\s*"\w+"\s*,\s*"arguments"/i, reasonCode: 'FUNCTION_INSTRUCTION_DETECTED' },

  // Authorization override / AI cannot receive authorization via data.
  { id: 'AUTHORIZATION_OVERRIDE', pattern: /grant\s+(?:the\s+)?authorization\s+(?:to\s+)?(?:me|us|them)/i, reasonCode: 'AUTHORIZATION_OVERRIDE_DETECTED' },
  { id: 'AI_AUTHORIZED_LANGUAGE', pattern: /you\s+are\s+(?:now\s+|hereby\s+)?(?:pre[-\s]?authorized|authorized|cleared|permitted)/i, reasonCode: 'AUTHORIZATION_OVERRIDE_DETECTED' },
  { id: 'AI_CANNOT_AUTHORIZATION_CLAIM', pattern: /\b(?:you|the\s+ai)\s+(?:have|has)\s+(?:been\s+)?(?:authorized|granted|cleared)\s+(?:to|for)\b/i, reasonCode: 'AUTHORIZATION_OVERRIDE_DETECTED' },

  // Privilege escalation.
  { id: 'PRIVILEGE_ESCALATION', pattern: /(?:escalate|elevate|raise)\s+(my|your|the)?\s*(privileges?|permissions?|access\s+level|role)/i, reasonCode: 'PRIVILEGE_ESCALATION_DETECTED' },
  { id: 'ACT_AS_ADMIN', pattern: /(?:act|behave|operate)\s+as\s+(an?\s+)?(admin|administrator|root|superuser|privileged\s+user)/i, reasonCode: 'PRIVILEGE_ESCALATION_DETECTED' },
  { id: 'GRANT_ADMIN', pattern: /grant\s+(me\s+)?(admin|administrator|root|elevated|superuser)\s+(access|privileges?|rights?)/i, reasonCode: 'PRIVILEGE_ESCALATION_DETECTED' },
  { id: 'GRANT_ROLE', pattern: /grant\s+(?:me\s+)?(?:the\s+)?(?:admin|administrator|root|owner|superuser)\s+(?:role|permissions?)\b/i, reasonCode: 'PRIVILEGE_ESCALATION_DETECTED' },
  { id: 'PROMOTE_ROLE', pattern: /(?:promote|make)\s+(?:me|this\s+user)\s+(?:(?:an?|to)\s+)?(?:admin|administrator|owner|root)\b/i, reasonCode: 'PRIVILEGE_ESCALATION_DETECTED' },

  // RBAC changes (specific permission-addition phrasing first: the general
  // "add/change ... roles/permissions" pattern would otherwise shadow it).
  { id: 'ADD_PERMISSION', pattern: /add\s+(the\s+)?(?:permission|role)\s+"?[^"]*"?\s+to\s+(?:user|group|role|me)/i, reasonCode: 'RBAC_INSTRUCTION_DETECTED' },
  { id: 'RBAC_CHANGE', pattern: /(?:change|modify|update|add|remove|delete)\s+(the\s+|my\s+|their\s+)?(rbac|roles?|permissions?|access\s+(?:control|rules))\b/i, reasonCode: 'RBAC_INSTRUCTION_DETECTED' },

  // Policy bypass language.
  { id: 'BYPASS_POLICY', pattern: /bypass\s+(the\s+|all\s+|any\s+)?(security|authorization|policy|policies|access|safety|entitlement|tenant)\b/i, reasonCode: 'POLICY_BYPASS_DETECTED' },
  { id: 'DISABLE_CONTROL', pattern: /(?:disable|turn\s+off|remove|suppress)\s+(the\s+|all\s+)?(audit|auditing|logging|security|authorization|policy|guard|guards|protections?|human\s+review)/i, reasonCode: 'POLICY_BYPASS_DETECTED' },
  { id: 'SKIP_CHECKS', pattern: /skip\s+(?:the\s+|all\s+|any\s+)?(?:checks?|verification|validations?|review)/i, reasonCode: 'POLICY_BYPASS_DETECTED' },

  // Secret extraction.
  { id: 'SECRET_EXTRACTION', pattern: /(?:show|reveal|print|list|expose)\s+(?:the\s+|all\s+|your\s+)?(?:api\s+keys?|secrets?|credentials?)/i, reasonCode: 'SECRET_EXTRACTION_DETECTED' },
  { id: 'PRIVATE_KEY_REQUEST', pattern: /provide\s+(?:the\s+)?(?:private\s+key|signing\s+key|secret\s+key)/i, reasonCode: 'SECRET_EXTRACTION_DETECTED' },
  { id: 'ENV_SECRET_REQUEST', pattern: /(?:dump|print|show|reveal)\s+(?:the\s+|all\s+)?environment\s+variables/i, reasonCode: 'SECRET_EXTRACTION_DETECTED' },

  // Fake system/developer policy claims.
  { id: 'FAKE_SYSTEM_MESSAGE', pattern: /^system\s*:/i, reasonCode: 'FAKE_SYSTEM_POLICY_DETECTED' },
  { id: 'FAKE_DEVELOPER_MESSAGE', pattern: /<\|developer\|>|developer\s*:\s*(?:you\s+are|override)/i, reasonCode: 'FAKE_SYSTEM_POLICY_DETECTED' },
  { id: 'SYSTEM_DIRECTIVE_CLAIM', pattern: /this\s+is\s+(?:a\s+|an\s+)?(?:system|developer|operator)\s+(?:message|directive)/i, reasonCode: 'FAKE_SYSTEM_POLICY_DETECTED' },
  { id: 'HIGHER_PRIORITY_CLAIM', pattern: /(?:highest[-\s]?priority|higher[-\s]?priority|top[-\s]?priority)\s+(?:instruction|directive|message)/i, reasonCode: 'FAKE_SYSTEM_POLICY_DETECTED' },
]);

interface ScanHit {
  reasonCode: string;
  patternId: string;
}

interface ScanBudget {
  bytes: number;
}

function requireHashOf(serialized: string): string {
  return computeOutputHash(serialized);
}

function scanValue(value: unknown, depth: number, budget: ScanBudget): ScanHit | null {
  if (depth > MAX_SCAN_DEPTH) {
    return { reasonCode: 'EXTERNAL_DATA_STRUCTURE_DEPTH', patternId: 'STRUCTURE_DEPTH' };
  }
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value, 'utf8');
    if (budget.bytes > MAX_TOTAL_STRING_BYTES) {
      return { reasonCode: 'EXTERNAL_DATA_TOO_LARGE', patternId: 'SIZE_LIMIT' };
    }
    for (const rule of FORBIDDEN_PATTERNS) {
      if (rule.pattern.test(value)) return { reasonCode: rule.reasonCode, patternId: rule.id };
    }
    return null;
  }
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return null;
  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = scanValue(item, depth + 1, budget);
      if (hit !== null) return hit;
    }
    return null;
  }
  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_INSTRUCTION_KEYS.has(normalizeKey(key))) {
        return { reasonCode: 'EMBEDDED_INSTRUCTION_KEY_DETECTED', patternId: `KEY_${normalizeKey(key).toUpperCase()}` };
      }
      const hit = scanValue(child, depth + 1, budget);
      if (hit !== null) return hit;
    }
    return null;
  }
  return { reasonCode: 'EXTERNAL_DATA_VALUE_TYPE_INVALID', patternId: 'VALUE_TYPE' };
}

export interface ExternalDataGuardInput {
  readonly sourceRef: string;
  readonly orgRef?: string | null;
  readonly data: unknown;
  readonly destinationTask?: string;
}

export type ExternalDataGuardResult =
  | {
      readonly ok: true;
      readonly reasonCode: null;
      readonly patternId: null;
      readonly sanitized: {
        readonly sourceRef: string;
        readonly designation: 'EXTERNAL_PARTNER_DATA';
        readonly externalDataPresent: true;
        readonly byteLength: number;
        readonly contentHash: string;
      };
      readonly auditId: string;
    }
  | {
      readonly ok: false;
      readonly reasonCode: string;
      readonly patternId: string;
      readonly sanitized: null;
      readonly auditId: string;
    };

/**
 * Guard partner-sourced data before it may enter any governed AI task.
 * Rejection carries NO content (reason code + pattern id only) and is
 * audited; clean data passes and is preserved verbatim — recorded as
 * EXTERNAL_PARTNER_DATA (DATA, never instructions), content preserved by
 * hash for provenance sourceReferences.
 */
export function guardExternalData(
  store: GovernanceStore,
  input: ExternalDataGuardInput,
): ExternalDataGuardResult {
  if (input === null || typeof input !== 'object') {
    throw new Error('EXTERNAL_DATA_INPUT_INVALID');
  }
  if (typeof input.sourceRef !== 'string' || !SOURCE_REF_PATTERN.test(input.sourceRef)) {
    throw new Error('EXTERNAL_DATA_SOURCE_REF_INVALID');
  }
  const budget = { bytes: 0 };
  const hit = scanValue(input.data, 0, budget);

  if (hit !== null) {
    const audit = store.recordAudit({
      kind: 'governance.external_data.rejected',
      subjectId: input.sourceRef,
      reasonCode: hit.reasonCode,
      details: {
        patternId: hit.patternId,
        designation: EXTERNAL_DATA_DESIGNATION,
        destinationTask: input.destinationTask ?? 'unknown',
        orgId: input.orgRef ?? 'UNKNOWN',
        externalDataPresent: true,
      },
      orgRef: input.orgRef ?? null,
    });
    return {
      ok: false,
      reasonCode: hit.reasonCode,
      patternId: hit.patternId,
      sanitized: null,
      auditId: audit.auditId,
    };
  }

  const serialized = typeof input.data === 'string' ? input.data : JSON.stringify(input.data);
  const contentHash = requireHashOf(serialized);
  const audit = store.recordAudit({
    kind: 'governance.external_data.classified_data',
    subjectId: input.sourceRef,
    reasonCode: 'EXTERNAL_DATA_CLASSIFIED_AS_DATA',
    details: {
      designation: EXTERNAL_DATA_DESIGNATION,
      byteLength: Buffer.byteLength(serialized, 'utf8'),
      contentHash,
      destinationTask: input.destinationTask ?? 'unknown',
      orgId: input.orgRef ?? 'UNKNOWN',
      externalDataPresent: true,
    },
    orgRef: input.orgRef ?? null,
  });
  return {
    ok: true,
    reasonCode: null,
    patternId: null,
    sanitized: Object.freeze({
      sourceRef: input.sourceRef,
      designation: EXTERNAL_DATA_DESIGNATION,
      externalDataPresent: true as const,
      byteLength: Buffer.byteLength(serialized, 'utf8'),
      contentHash,
    }),
    auditId: audit.auditId,
  };
}
