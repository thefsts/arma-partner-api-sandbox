// Stop Point 6 — classification & engine-registry contract.
//
// The five designations and four engine classes are the exact vocabulary.
// An engine is pinned at registration to exactly ONE designation by its
// class: generative AI is advisory-only (structural, not policy-dependent);
// a deterministic rule engine is never advisory; external partner data is a
// DATA designation that no engine may claim for its own output.

/** The five designations — never blurred. */
export const DESIGNATIONS: readonly string[] = Object.freeze([
  'AI_ADVISORY',
  'DETERMINISTIC_RULE',
  'HUMAN_AUTHORIZATION',
  'SYSTEM_AUTOMATION',
  'EXTERNAL_PARTNER_DATA',
]);

/** External partner data is DATA, never instructions, never an engine lane. */
export const EXTERNAL_DATA_DESIGNATION = 'EXTERNAL_PARTNER_DATA' as const;

/** The four engine classes. */
export const ENGINE_CLASSES: readonly string[] = Object.freeze([
  'GENERATIVE_AI',
  'DETERMINISTIC_RULE_ENGINE',
  'HUMAN_OPERATOR_CONSOLE',
  'SYSTEM_AUTOMATION_ENGINE',
]);

/**
 * What AI MAY do — the complete advisory task-type vocabulary. Anything
 * outside this list is not an approved AI task in v1.
 */
export const AI_MAY_TASK_TYPES: readonly string[] = Object.freeze([
  'analyze',
  'summarize',
  'classify',
  'recommend',
  'identify_issues',
  'flag_for_review',
  'advise',
]);

/** Deterministic rule-engine task types (RERE-style engines live here). */
export const DETERMINISTIC_TASK_TYPES: readonly string[] = Object.freeze([
  'policy_evaluation',
]);

export interface EngineRegistration {
  readonly engineId: string;
  readonly engineClass: string;
  readonly engineVersion: string;
  readonly designation: string;
  readonly advisoryOnly: boolean;
}

export interface RegisteredEngine {
  readonly engineId: string;
  readonly engineClass: string;
  readonly engineVersion: string;
  readonly designation: string;
  readonly advisoryOnly: boolean;
  readonly registeredAt: number;
}

const ENGINE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
const ENGINE_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;

/** Normalize a field key: strip to alphanumerics, lowercase. */
export function normalizeKey(key: string): string {
  return key.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
}

/**
 * True when a reviewer identity looks like an AI/system identity rather
 * than a human. An AI identity can never stand in as the human reviewer.
 */
export function isAiIdentityMarker(value: string): boolean {
  return /\b(?:ai|bot|agent|assistant|model|gpt|llm|system|engine|automation)\b/i.test(value);
}

/**
 * Structural registration gate — every illegal pairing throws:
 *   ENGINE_ID_INVALID / ENGINE_VERSION_INVALID / ENGINE_CLASS_UNKNOWN /
 *   ENGINE_ADVISORY_ONLY_FLAG_INVALID / AI_ENGINE_MUST_BE_ADVISORY_ONLY /
 *   DETERMINISTIC_ENGINE_CANNOT_BE_ADVISORY /
 *   ENGINE_CANNOT_REGISTER_EXTERNAL_DATA / DESIGNATION_ENGINE_CLASS_MISMATCH.
 */
export function validateEngineRegistration(reg: EngineRegistration): void {
  if (reg === null || typeof reg !== 'object') throw new Error('ENGINE_REGISTRATION_INVALID');
  if (typeof reg.engineId !== 'string' || !ENGINE_ID_PATTERN.test(reg.engineId)) {
    throw new Error('ENGINE_ID_INVALID');
  }
  if (typeof reg.engineVersion !== 'string' || !ENGINE_VERSION_PATTERN.test(reg.engineVersion)) {
    throw new Error('ENGINE_VERSION_INVALID');
  }
  if (!ENGINE_CLASSES.includes(reg.engineClass)) throw new Error('ENGINE_CLASS_UNKNOWN');
  if (reg.designation === EXTERNAL_DATA_DESIGNATION) {
    throw new Error('ENGINE_CANNOT_REGISTER_EXTERNAL_DATA');
  }
  if (typeof reg.advisoryOnly !== 'boolean') throw new Error('ENGINE_ADVISORY_ONLY_FLAG_INVALID');

  if (reg.engineClass === 'GENERATIVE_AI') {
    if (reg.designation !== 'AI_ADVISORY') throw new Error('DESIGNATION_ENGINE_CLASS_MISMATCH');
    if (reg.advisoryOnly !== true) throw new Error('AI_ENGINE_MUST_BE_ADVISORY_ONLY');
  } else if (reg.engineClass === 'DETERMINISTIC_RULE_ENGINE') {
    if (reg.designation !== 'DETERMINISTIC_RULE') throw new Error('DESIGNATION_ENGINE_CLASS_MISMATCH');
    if (reg.advisoryOnly === true) throw new Error('DETERMINISTIC_ENGINE_CANNOT_BE_ADVISORY');
  } else if (reg.engineClass === 'HUMAN_OPERATOR_CONSOLE') {
    if (reg.designation !== 'HUMAN_AUTHORIZATION') throw new Error('DESIGNATION_ENGINE_CLASS_MISMATCH');
    if (reg.advisoryOnly === true) throw new Error('ENGINE_ADVISORY_ONLY_FLAG_INVALID');
  } else {
    if (reg.designation !== 'SYSTEM_AUTOMATION') throw new Error('DESIGNATION_ENGINE_CLASS_MISMATCH');
    if (reg.advisoryOnly === true) throw new Error('ENGINE_ADVISORY_ONLY_FLAG_INVALID');
  }
}

export type DesignationCheck =
  | { ok: true; designation: string }
  | { ok: false; reasonCode: string };

/**
 * Pair a registered engine with a claimed designation + task type. The legal
 * lane passes; every mismatch fails closed with a precise reason code:
 *   ENGINE_CANNOT_CLAIM_EXTERNAL_DATA / AI_OUTPUT_MISLABELED_DETERMINISTIC /
 *   DETERMINISTIC_OUTPUT_MISLABELED_AI / DESIGNATION_ENGINE_CLASS_MISMATCH /
 *   AI_ENGINE_NOT_ADVISORY_ONLY / TASK_TYPE_INVALID /
 *   AI_TASK_TYPE_NOT_ALLOWED / DETERMINISTIC_TASK_TYPE_NOT_ALLOWED.
 */
export function checkEngineDesignation(
  engine: RegisteredEngine,
  designation: string,
  taskType: string,
): DesignationCheck {
  const fail = (reasonCode: string): DesignationCheck => ({ ok: false, reasonCode });
  if (designation === EXTERNAL_DATA_DESIGNATION) {
    return fail('ENGINE_CANNOT_CLAIM_EXTERNAL_DATA');
  }
  if (engine.engineClass === 'GENERATIVE_AI') {
    if (designation !== 'AI_ADVISORY') {
      return fail(
        designation === 'DETERMINISTIC_RULE'
          ? 'AI_OUTPUT_MISLABELED_DETERMINISTIC'
          : 'DESIGNATION_ENGINE_CLASS_MISMATCH',
      );
    }
    if (engine.advisoryOnly !== true) return fail('AI_ENGINE_NOT_ADVISORY_ONLY');
    if (!AI_MAY_TASK_TYPES.includes(taskType)) {
      return fail(
        DETERMINISTIC_TASK_TYPES.includes(taskType)
          ? 'AI_TASK_TYPE_NOT_ALLOWED'
          : 'TASK_TYPE_INVALID',
      );
    }
  } else if (engine.engineClass === 'DETERMINISTIC_RULE_ENGINE') {
    if (designation !== 'DETERMINISTIC_RULE') {
      return fail(
        designation === 'AI_ADVISORY'
          ? 'DETERMINISTIC_OUTPUT_MISLABELED_AI'
          : 'DESIGNATION_ENGINE_CLASS_MISMATCH',
      );
    }
    if (!DETERMINISTIC_TASK_TYPES.includes(taskType)) {
      return fail(
        AI_MAY_TASK_TYPES.includes(taskType)
          ? 'DETERMINISTIC_TASK_TYPE_NOT_ALLOWED'
          : 'TASK_TYPE_INVALID',
      );
    }
  } else if (designation === 'AI_ADVISORY' || designation === 'DETERMINISTIC_RULE') {
    return fail('DESIGNATION_ENGINE_CLASS_MISMATCH');
  }
  return { ok: true, designation };
}
