// Stop Point 6 — deterministic rule-engine result contract.
//
// RERE-style rule engines are a SEPARATE lane from generative AI: their
// results carry their own envelope, registry designation ('DETERMINISTIC_RULE',
// never labeled AI-generated), rule version, and HMAC binding. The only
// deterministic automation allowance for protected actions is the fail-closed
// direction (see protectedActions.ts).

import type { GovernanceStore } from './store.ts';
import { checkEngineDesignation } from './classification.ts';
import { computeIntegrityTag, isIntegrityTagLike } from './provenanceIntegrity.ts';

export const DETERMINISTIC_SCHEMA_VERSION = 'ai-governance.deterministic.v1';
export const MAX_DETERMINISTIC_SKEW_MS = 5 * 60 * 1000;

const RULING_PATTERN = /^[A-Z][A-Z0-9_]{2,63}$/;
const RULE_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface DeterministicResultInput {
  readonly engineId: string;
  readonly ruleVersion: string;
  readonly taskType: string;
  readonly inputReferences: readonly string[];
  readonly ruling: string;
  readonly decisionReasonCode: string;
  readonly timestamp: number;
  readonly policyVersion?: string;
  readonly orgRef?: string | null;
}

export interface DeterministicResult {
  readonly engineId: string;
  readonly engineVersion: string;
  readonly ruleVersion: string;
  readonly taskType: string;
  readonly designation: 'DETERMINISTIC_RULE';
  readonly inputReferences: readonly string[];
  readonly ruling: string;
  readonly decisionReasonCode: string;
  readonly timestamp: number;
  readonly policyVersion: string;
  readonly auditId: string;
  readonly orgRef: string | null;
}

export interface DeterministicResultEnvelope {
  readonly resultId: string;
  readonly schemaVersion: string;
  readonly result: DeterministicResult;
  readonly integrityTag: string;
}

export interface CreateDeterministicResultParams {
  store: GovernanceStore;
  input: DeterministicResultInput;
}

export interface DeterministicVerification {
  readonly ok: boolean;
  readonly reasonCode?: string;
  readonly envelope?: DeterministicResultEnvelope;
}

export interface VerifyDeterministicParams {
  store: GovernanceStore;
  envelope: DeterministicResultEnvelope | null | undefined | unknown;
  expectedPolicyVersion?: string;
}

function fail(code: string): never {
  throw new Error(code);
}

/** Fixed-order bound values for the deterministic HMAC binding. */
export function boundResultValues(r: {
  resultId: string;
  schemaVersion: string;
  engineId: string;
  engineVersion: string;
  ruleVersion: string;
  taskType: string;
  designation: string;
  timestamp: number;
  inputReferences: readonly string[];
  ruling: string;
  decisionReasonCode: string;
  policyVersion: string;
  auditId: string;
  orgRef: string | null;
}): readonly unknown[] {
  return [
    r.resultId,
    r.schemaVersion,
    r.engineId,
    r.engineVersion,
    r.ruleVersion,
    r.taskType,
    r.designation,
    r.timestamp,
    r.inputReferences,
    r.ruling,
    r.decisionReasonCode,
    r.policyVersion,
    r.auditId,
    r.orgRef,
  ];
}

/**
 * Create a deterministic rule-engine result envelope — durable, audited,
 * HMAC-bound, and never labeled AI. Fail closed with a precise throw on any
 * structural, freshness, registry, classification, or policy violation.
 */
export function createDeterministicResult(params: CreateDeterministicResultParams): DeterministicResultEnvelope {
  const { store, input } = params;
  if (input === null || typeof input !== 'object') return fail('DETERMINISTIC_INPUT_INVALID');
  const raw = input as unknown as Record<string, unknown>;

  const engineId = raw.engineId;
  if (typeof engineId !== 'string' || !engineId) return fail('DETERMINISTIC_INPUT_INVALID');
  const ruleVersion = raw.ruleVersion;
  if (typeof ruleVersion !== 'string' || !RULE_VERSION_PATTERN.test(ruleVersion)) {
    return fail('DETERMINISTIC_RULE_VERSION_INVALID');
  }
  const taskType = raw.taskType;
  if (typeof taskType !== 'string' || !taskType) return fail('DETERMINISTIC_INPUT_INVALID');
  const inputReferences = raw.inputReferences;
  if (!Array.isArray(inputReferences) || inputReferences.length === 0 ||
      !(inputReferences as unknown[]).every((s) => typeof s === 'string' && s.length > 0)) {
    return fail('DETERMINISTIC_INPUT_INVALID');
  }
  const ruling = raw.ruling;
  if (typeof ruling !== 'string' || !RULING_PATTERN.test(ruling)) {
    return fail('DETERMINISTIC_RULING_INVALID');
  }
  const decisionReasonCode = raw.decisionReasonCode;
  if (typeof decisionReasonCode !== 'string' || !decisionReasonCode) {
    return fail('DETERMINISTIC_INPUT_INVALID');
  }
  const timestamp = raw.timestamp;
  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
    return fail('DETERMINISTIC_INPUT_INVALID');
  }
  if (Math.abs(timestamp - store.clock.now()) > MAX_DETERMINISTIC_SKEW_MS) {
    return fail('DETERMINISTIC_TIMESTAMP_OUT_OF_RANGE');
  }

  let orgRef: string | null = null;
  if (typeof raw.orgRef === 'string') {
    if (!raw.orgRef) return fail('DETERMINISTIC_INPUT_INVALID');
    orgRef = raw.orgRef;
  } else if (raw.orgRef !== undefined && raw.orgRef !== null) {
    return fail('DETERMINISTIC_INPUT_INVALID');
  }

  // Registry + classification pairing (deterministic lane, never AI).
  const engine = store.getEngine(engineId);
  if (engine === null) return fail('DETERMINISTIC_ENGINE_UNKNOWN');
  const classification = checkEngineDesignation(engine, 'DETERMINISTIC_RULE', taskType);
  if (!classification.ok) return fail(classification.reasonCode ?? 'DETERMINISTIC_CLASSIFICATION_INVALID');

  const policyVersion = typeof raw.policyVersion === 'string' && raw.policyVersion
    ? raw.policyVersion
    : store.policyVersion;
  if (policyVersion !== store.policyVersion) return fail('DETERMINISTIC_POLICY_VERSION_STALE');

  const resultId = store.nextDeterministicId();
  const audit = store.recordAudit({
    kind: 'governance.deterministic.created',
    subjectId: engineId,
    reasonCode: 'DETERMINISTIC_RESULT_RECORDED',
    details: {
      resultId,
      engineId,
      engineVersion: engine.engineVersion,
      ruleVersion,
      taskType,
      designation: 'DETERMINISTIC_RULE',
      ruling,
      decisionReasonCode,
      policyVersion,
      orgId: orgRef ?? 'UNKNOWN',
    },
    orgRef,
  });

  const result: DeterministicResult = Object.freeze({
    engineId,
    engineVersion: engine.engineVersion,
    ruleVersion,
    taskType,
    designation: 'DETERMINISTIC_RULE' as const,
    inputReferences: Object.freeze([...(inputReferences as string[])]),
    ruling,
    decisionReasonCode,
    timestamp,
    policyVersion,
    auditId: audit.auditId,
    orgRef,
  });
  const bound = {
    resultId,
    schemaVersion: DETERMINISTIC_SCHEMA_VERSION,
    engineId: result.engineId,
    engineVersion: result.engineVersion,
    ruleVersion: result.ruleVersion,
    taskType: result.taskType,
    designation: result.designation,
    timestamp: result.timestamp,
    inputReferences: result.inputReferences,
    ruling: result.ruling,
    decisionReasonCode: result.decisionReasonCode,
    policyVersion: result.policyVersion,
    auditId: result.auditId,
    orgRef: result.orgRef,
  };
  const integrityTag = computeIntegrityTag(boundResultValues(bound), store.integrityKey);
  const envelope: DeterministicResultEnvelope = Object.freeze({
    resultId,
    schemaVersion: DETERMINISTIC_SCHEMA_VERSION,
    result,
    integrityTag,
  });
  store.putDeterministicEnvelope(envelope);
  return envelope;
}

/**
 * Verify a deterministic result envelope — structural checks, mislabel
 * detection (never AI), HMAC metadata binding, registry + classification
 * pairing, engine version, and policy version. Fail closed with a precise
 * reason code.
 */
export function verifyDeterministicResultEnvelope(params: VerifyDeterministicParams): DeterministicVerification {
  const { store, expectedPolicyVersion } = params;
  const e = params.envelope as Record<string, unknown> | null | undefined;
  if (e === null || e === undefined || typeof e !== 'object') {
    return { ok: false, reasonCode: 'DETERMINISTIC_MISSING' };
  }
  const bad = (reasonCode: string): DeterministicVerification => ({ ok: false, reasonCode });

  if (typeof e.resultId !== 'string' || !e.resultId) return bad('DETERMINISTIC_STRUCTURE_INVALID');
  if (typeof e.schemaVersion !== 'string' || !e.schemaVersion) return bad('DETERMINISTIC_STRUCTURE_INVALID');
  const r = e.result;
  if (r === null || typeof r !== 'object') return bad('DETERMINISTIC_STRUCTURE_INVALID');
  const res = r as Record<string, unknown>;
  const requiredStrings = [
    'engineId', 'engineVersion', 'ruleVersion', 'taskType', 'ruling',
    'decisionReasonCode', 'policyVersion', 'auditId',
  ] as const;
  for (const key of requiredStrings) {
    if (typeof res[key] !== 'string' || !(res[key] as string).length) {
      return bad('DETERMINISTIC_STRUCTURE_INVALID');
    }
  }
  if (res.designation !== 'DETERMINISTIC_RULE') {
    return bad(
      res.designation === 'AI_ADVISORY'
        ? 'DETERMINISTIC_MISLABELED_AS_AI'
        : 'DETERMINISTIC_DESIGNATION_INVALID',
    );
  }
  if (!Array.isArray(res.inputReferences)) return bad('DETERMINISTIC_STRUCTURE_INVALID');
  if (typeof res.timestamp !== 'number' || !Number.isFinite(res.timestamp)) {
    return bad('DETERMINISTIC_STRUCTURE_INVALID');
  }
  if (typeof res.ruling !== 'string' || !RULING_PATTERN.test(res.ruling)) {
    return bad('DETERMINISTIC_RULING_INVALID');
  }
  if (res.orgRef !== null && typeof res.orgRef !== 'string') return bad('DETERMINISTIC_STRUCTURE_INVALID');
  if (e.schemaVersion !== DETERMINISTIC_SCHEMA_VERSION) return bad('DETERMINISTIC_SCHEMA_UNSUPPORTED');
  if (!isIntegrityTagLike(e.integrityTag)) return bad('INTEGRITY_TAG_MISSING');
  if (store.auditLog.find(res.auditId as string) === null) return bad('DETERMINISTIC_AUDIT_NOT_FOUND');

  // Metadata tamper: recompute the HMAC binding over the fixed-order list.
  const recomputed = computeIntegrityTag(boundResultValues({
    resultId: e.resultId as string,
    schemaVersion: e.schemaVersion as string,
    engineId: res.engineId as string,
    engineVersion: res.engineVersion as string,
    ruleVersion: res.ruleVersion as string,
    taskType: res.taskType as string,
    designation: res.designation as string,
    timestamp: res.timestamp as number,
    inputReferences: res.inputReferences as readonly string[],
    ruling: res.ruling as string,
    decisionReasonCode: res.decisionReasonCode as string,
    policyVersion: res.policyVersion as string,
    auditId: res.auditId as string,
    orgRef: (res.orgRef ?? null) as string | null,
  }), store.integrityKey);
  if (recomputed !== (e.integrityTag as string)) return bad('METADATA_TAMPERED');

  // Registry + classification pairing.
  const engine = store.getEngine(res.engineId as string);
  if (engine === null) return bad('DETERMINISTIC_ENGINE_UNKNOWN');
  const classification = checkEngineDesignation(engine, 'DETERMINISTIC_RULE', res.taskType as string);
  if (!classification.ok) return bad(classification.reasonCode ?? 'DETERMINISTIC_CLASSIFICATION_INVALID');
  if (res.engineVersion !== engine.engineVersion) return bad('DETERMINISTIC_ENGINE_VERSION_MISMATCH');

  // Policy version: stale -> fail closed.
  const expected = expectedPolicyVersion ?? store.policyVersion;
  if (res.policyVersion !== expected) return bad('DETERMINISTIC_POLICY_VERSION_STALE');

  return { ok: true, envelope: e as unknown as DeterministicResultEnvelope };
}
