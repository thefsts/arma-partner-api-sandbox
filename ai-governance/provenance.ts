// Stop Point 6 — AI provenance envelope contract.
//
// Every governed AI advisory output is wrapped in a strict provenance
// envelope: the exact governed-output hash, engine + task + designation,
// source references, confidence, review linkage, policy version, audit id,
// and an HMAC integrity tag binding ALL metadata fields in fixed order.
// Private material (prompts, chain-of-thought, model keys, provider tokens)
// is FORBIDDEN on the envelope by construction. Advisory output may never
// claim a protected action is allowed.

import type { GovernanceStore } from './store.ts';
import { checkEngineDesignation, isAiIdentityMarker, normalizeKey } from './classification.ts';
import { computeIntegrityTag, computeOutputHash, isHashLike, isIntegrityTagLike } from './provenanceIntegrity.ts';

export const PROVENANCE_SCHEMA_VERSION = 'ai-governance.provenance.v1';
export const MAX_PROVENANCE_SKEW_MS = 5 * 60 * 1000;

/** Data classifications a governed advisory task may operate on. */
export const DATA_CLASSIFICATIONS: readonly string[] = Object.freeze([
  'SYNTHETIC',
  'PARTNER_PROVIDED',
  'TENANT_SCOPED',
  'PUBLIC',
]);

export type ProvenanceDesignation = 'AI_ADVISORY';

/** Keys that must NEVER appear on a provenance envelope (private material). */
const FORBIDDEN_ENVELOPE_KEYS = new Set([
  'prompt', 'systemprompt', 'userprompt', 'apikey', 'modelkey', 'modelprovider',
  'token', 'accesstoken', 'credential', 'credentials', 'signingkey', 'secret',
  'secretvalue', 'chainofthought', 'cot', 'password', 'privatekey', 'model',
  'modelname', 'provider', 'reasoning', 'rawreasoning',
]);

export interface ProvenanceEnvelopeInput {
  readonly engineId: string;
  readonly taskType: string;
  readonly timestamp: number;
  readonly sourceReferences: readonly string[];
  readonly confidence?: number;
  readonly humanReviewRequired: boolean;
  readonly reviewingHumanId?: string;
  readonly reviewTimestamp?: number;
  readonly policyVersion?: string;
  readonly requestCorrelationId: string;
  readonly orgRef?: string | null;
  readonly dataClassification: string;
  readonly externalDataPresent: boolean;
  readonly protectedActionRequested: boolean;
  readonly decisionReasonCode: string;
}

export interface ProvenanceEnvelope {
  readonly provenanceId: string;
  readonly schemaVersion: string;
  readonly engineId: string;
  readonly engineVersion: string;
  readonly taskType: string;
  readonly designation: ProvenanceDesignation;
  readonly timestamp: number;
  readonly sourceReferences: readonly string[];
  readonly confidence?: number;
  readonly humanReviewRequired: boolean;
  readonly reviewingHumanId?: string;
  readonly reviewTimestamp?: number;
  readonly outputHash: string;
  readonly policyVersion: string;
  readonly auditId: string;
  readonly requestCorrelationId: string;
  readonly orgRef: string | null;
  readonly dataClassification: string;
  readonly externalDataPresent: boolean;
  readonly protectedActionRequested: boolean;
  readonly protectedActionAllowed: false;
  readonly decisionReasonCode: string;
  readonly integrityTag: string;
}

export interface CreateProvenanceParams {
  store: GovernanceStore;
  /** the exact governed output bytes — hashed into outputHash. */
  governedOutput: string;
  input: ProvenanceEnvelopeInput;
}

export interface ProvenanceVerification {
  readonly ok: boolean;
  readonly reasonCode?: string;
  readonly envelope?: ProvenanceEnvelope;
}

export interface VerifyProvenanceParams {
  store: GovernanceStore;
  envelope: ProvenanceEnvelope | null | undefined | unknown;
  expectedPolicyVersion?: string;
  /** exact governed output bytes — when provided they must hash to outputHash. */
  governedOutput?: string;
}

function fail(code: string): never {
  throw new Error(code);
}

/**
 * Fixed-order bound metadata values — the HMAC covers ALL of them. Absent
 * optional fields bind as null, so a field cannot be silently dropped or
 * reordered without breaking the tag.
 */
export function boundEnvelopeValues(e: {
  provenanceId: string;
  schemaVersion: string;
  engineId: string;
  engineVersion: string;
  taskType: string;
  designation: string;
  timestamp: number;
  sourceReferences: readonly string[];
  confidence?: number | null;
  humanReviewRequired: boolean;
  reviewingHumanId?: string | null;
  reviewTimestamp?: number | null;
  outputHash: string;
  policyVersion: string;
  auditId: string;
  requestCorrelationId: string;
  orgRef: string | null;
  dataClassification: string;
  externalDataPresent: boolean;
  protectedActionRequested: boolean;
  protectedActionAllowed: boolean;
  decisionReasonCode: string;
}): readonly unknown[] {
  return [
    e.provenanceId,
    e.schemaVersion,
    e.engineId,
    e.engineVersion,
    e.taskType,
    e.designation,
    e.timestamp,
    e.sourceReferences,
    e.confidence ?? null,
    e.humanReviewRequired,
    e.reviewingHumanId ?? null,
    e.reviewTimestamp ?? null,
    e.outputHash,
    e.policyVersion,
    e.auditId,
    e.requestCorrelationId,
    e.orgRef ?? null,
    e.dataClassification,
    e.externalDataPresent,
    e.protectedActionRequested,
    e.protectedActionAllowed,
    e.decisionReasonCode,
  ];
}

/**
 * Create a provenance envelope — or fail closed with a precise throw. The
 * envelope is frozen, durable in the store, and audited (metadata only).
 */
export function createProvenanceEnvelope(params: CreateProvenanceParams): ProvenanceEnvelope {
  const { store, governedOutput, input } = params;
  if (input === null || typeof input !== 'object') return fail('PROVENANCE_INPUT_INVALID');
  const raw = input as unknown as Record<string, unknown>;

  // Private material may never ride along on the envelope.
  for (const key of Object.keys(raw)) {
    if (FORBIDDEN_ENVELOPE_KEYS.has(normalizeKey(key))) {
      return fail(`PROVENANCE_FORBIDDEN_FIELD_${normalizeKey(key).toUpperCase()}`);
    }
  }

  const engineId = raw.engineId;
  if (typeof engineId !== 'string' || !engineId) return fail('PROVENANCE_INPUT_INVALID');
  const taskType = raw.taskType;
  if (typeof taskType !== 'string' || !taskType) return fail('PROVENANCE_INPUT_INVALID');
  const timestamp = raw.timestamp;
  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
    return fail('PROVENANCE_INPUT_INVALID');
  }
  // Freshness: an envelope may not be minted far outside the clock window.
  if (Math.abs(timestamp - store.clock.now()) > MAX_PROVENANCE_SKEW_MS) {
    return fail('PROVENANCE_TIMESTAMP_OUT_OF_RANGE');
  }
  const sourceReferences = raw.sourceReferences;
  if (!Array.isArray(sourceReferences) || sourceReferences.length === 0 ||
      !(sourceReferences as unknown[]).every((s) => typeof s === 'string' && s.length > 0)) {
    return fail('PROVENANCE_INPUT_INVALID');
  }
  const humanReviewRequired = raw.humanReviewRequired;
  if (typeof humanReviewRequired !== 'boolean') return fail('PROVENANCE_INPUT_INVALID');
  const externalDataPresent = raw.externalDataPresent;
  if (typeof externalDataPresent !== 'boolean') return fail('PROVENANCE_INPUT_INVALID');
  const protectedActionRequested = raw.protectedActionRequested;
  if (typeof protectedActionRequested !== 'boolean') return fail('PROVENANCE_INPUT_INVALID');
  const dataClassification = raw.dataClassification;
  if (typeof dataClassification !== 'string' || !DATA_CLASSIFICATIONS.includes(dataClassification)) {
    return fail('PROVENANCE_DATA_CLASSIFICATION_INVALID');
  }
  const decisionReasonCode = raw.decisionReasonCode;
  if (typeof decisionReasonCode !== 'string' || !decisionReasonCode) {
    return fail('PROVENANCE_INPUT_INVALID');
  }
  const requestCorrelationId = raw.requestCorrelationId;
  if (typeof requestCorrelationId !== 'string' || !requestCorrelationId) {
    return fail('PROVENANCE_INPUT_INVALID');
  }

  let orgRef: string | null = null;
  if (typeof raw.orgRef === 'string') {
    if (!raw.orgRef) return fail('PROVENANCE_INPUT_INVALID');
    orgRef = raw.orgRef;
  } else if (raw.orgRef !== undefined && raw.orgRef !== null) {
    return fail('PROVENANCE_INPUT_INVALID');
  }

  const confidence = raw.confidence;
  if (confidence !== undefined &&
      (typeof confidence !== 'number' || !Number.isFinite(confidence) ||
       (confidence as number) < 0 || (confidence as number) > 1)) {
    return fail('PROVENANCE_CONFIDENCE_INVALID');
  }

  // Reviewer linkage: only when human review is required, and never an
  // AI/system identity standing in as the human reviewer.
  const reviewingHumanId = raw.reviewingHumanId;
  const reviewTimestamp = raw.reviewTimestamp;
  if (humanReviewRequired === false &&
      (reviewingHumanId !== undefined || reviewTimestamp !== undefined)) {
    return fail('PROVENANCE_REVIEWER_FIELDS_UNEXPECTED');
  }
  if (humanReviewRequired === true) {
    if (typeof reviewingHumanId !== 'string' || !reviewingHumanId.trim()) {
      return fail('PROVENANCE_INPUT_INVALID');
    }
    if (isAiIdentityMarker(reviewingHumanId)) return fail('PROVENANCE_REVIEWER_MUST_BE_HUMAN');
    if (typeof reviewTimestamp !== 'number' || !Number.isFinite(reviewTimestamp)) {
      return fail('PROVENANCE_INPUT_INVALID');
    }
  }

  // Advisory output can never carry a protected-action allowance.
  if (raw.protectedActionAllowed !== undefined && raw.protectedActionAllowed !== false) {
    return fail('PROTECTED_ACTION_NOT_ALLOWED_FOR_ADVISORY');
  }

  // Registry + classification pairing (fail closed, precise codes).
  const engine = store.getEngine(engineId);
  if (engine === null) return fail('PROVENANCE_ENGINE_UNKNOWN');
  const classification = checkEngineDesignation(engine, 'AI_ADVISORY', taskType);
  if (!classification.ok) return fail(classification.reasonCode);

  const policyVersion = typeof raw.policyVersion === 'string' && raw.policyVersion
    ? raw.policyVersion
    : store.policyVersion;
  if (policyVersion !== store.policyVersion) return fail('PROVENANCE_POLICY_VERSION_STALE');

  // Hash the EXACT governed output bytes.
  const outputHash = computeOutputHash(governedOutput);
  const provenanceId = store.nextProvenanceId();
  const audit = store.recordAudit({
    kind: 'governance.provenance.created',
    subjectId: engineId,
    reasonCode: 'ADVISORY_PROVENANCE_RECORDED',
    details: {
      provenanceId,
      engineId,
      engineVersion: engine.engineVersion,
      taskType,
      designation: 'AI_ADVISORY',
      outputHash,
      policyVersion,
      dataClassification,
      humanReviewRequired,
      externalDataPresent,
      protectedActionRequested,
      protectedActionAllowed: false,
      decisionReasonCode,
      orgId: orgRef ?? 'UNKNOWN',
    },
    orgRef,
  });

  const envelopeFields = {
    provenanceId,
    schemaVersion: PROVENANCE_SCHEMA_VERSION,
    engineId,
    engineVersion: engine.engineVersion,
    taskType,
    designation: 'AI_ADVISORY' as const,
    timestamp,
    sourceReferences: Object.freeze([...(sourceReferences as string[])]),
    ...(confidence !== undefined ? { confidence: confidence as number } : {}),
    humanReviewRequired,
    ...(reviewingHumanId !== undefined ? { reviewingHumanId: reviewingHumanId as string } : {}),
    ...(reviewTimestamp !== undefined ? { reviewTimestamp: reviewTimestamp as number } : {}),
    outputHash,
    policyVersion,
    auditId: audit.auditId,
    requestCorrelationId,
    orgRef,
    dataClassification,
    externalDataPresent,
    protectedActionRequested,
    protectedActionAllowed: false as const,
    decisionReasonCode,
  };
  const integrityTag = computeIntegrityTag(boundEnvelopeValues(envelopeFields), store.integrityKey);
  const envelope: ProvenanceEnvelope = Object.freeze({ ...envelopeFields, integrityTag });
  store.putProvenanceEnvelope(envelope);
  return envelope;
}

/**
 * Verify a provenance envelope — every structural, integrity, registry,
 * classification, and policy check must pass, else fail closed with a
 * precise reason code. Metadata tamper (HMAC) and output tamper (bytes vs
 * hash) are both detected.
 */
export function verifyProvenanceEnvelope(params: VerifyProvenanceParams): ProvenanceVerification {
  const { store, expectedPolicyVersion } = params;
  const e = params.envelope as Record<string, unknown> | null | undefined;
  if (e === null || e === undefined || typeof e !== 'object') {
    return { ok: false, reasonCode: 'PROVENANCE_MISSING' };
  }
  const bad = (reasonCode: string): ProvenanceVerification => ({ ok: false, reasonCode });

  for (const key of Object.keys(e)) {
    if (FORBIDDEN_ENVELOPE_KEYS.has(normalizeKey(key))) {
      return bad(`PROVENANCE_FORBIDDEN_FIELD_${normalizeKey(key).toUpperCase()}`);
    }
  }
  const requiredStrings = [
    'provenanceId', 'schemaVersion', 'engineId', 'engineVersion', 'taskType',
    'outputHash', 'policyVersion', 'auditId', 'requestCorrelationId',
    'dataClassification', 'decisionReasonCode', 'integrityTag',
  ] as const;
  for (const key of requiredStrings) {
    if (typeof e[key] !== 'string' || !(e[key] as string).length) {
      return bad('PROVENANCE_STRUCTURE_INVALID');
    }
  }
  if (e.schemaVersion !== PROVENANCE_SCHEMA_VERSION) return bad('PROVENANCE_SCHEMA_UNSUPPORTED');
  if (typeof e.timestamp !== 'number' || !Number.isFinite(e.timestamp)) return bad('PROVENANCE_STRUCTURE_INVALID');
  if (typeof e.humanReviewRequired !== 'boolean' ||
      typeof e.externalDataPresent !== 'boolean' ||
      typeof e.protectedActionRequested !== 'boolean') {
    return bad('PROVENANCE_STRUCTURE_INVALID');
  }
  if (!Array.isArray(e.sourceReferences)) return bad('PROVENANCE_STRUCTURE_INVALID');
  if (e.designation !== 'AI_ADVISORY') return bad('DESIGNATION_NOT_ADVISORY');
  if (e.protectedActionAllowed !== false) {
    return bad('PROTECTED_ACTION_NOT_ALLOWED_FOR_ADVISORY');
  }
  if (!isHashLike(e.outputHash)) return bad('PROVENANCE_OUTPUT_HASH_INVALID');
  if (!isIntegrityTagLike(e.integrityTag)) return bad('INTEGRITY_TAG_MISSING');
  if (store.auditLog.find(e.auditId as string) === null) return bad('PROVENANCE_AUDIT_NOT_FOUND');
  if (typeof e.orgRef !== 'string' && e.orgRef !== null) return bad('PROVENANCE_STRUCTURE_INVALID');
  if (e.confidence !== undefined &&
      (typeof e.confidence !== 'number' || !Number.isFinite(e.confidence) ||
       (e.confidence as number) < 0 || (e.confidence as number) > 1)) {
    return bad('PROVENANCE_CONFIDENCE_INVALID');
  }
  if (e.humanReviewRequired === true) {
    if (typeof e.reviewingHumanId !== 'string' || !(e.reviewingHumanId as string).trim()) {
      return bad('PROVENANCE_STRUCTURE_INVALID');
    }
    if (isAiIdentityMarker(e.reviewingHumanId)) return bad('PROVENANCE_REVIEWER_MUST_BE_HUMAN');
    if (typeof e.reviewTimestamp !== 'number' || !Number.isFinite(e.reviewTimestamp)) {
      return bad('PROVENANCE_STRUCTURE_INVALID');
    }
  } else if (e.reviewingHumanId !== undefined || e.reviewTimestamp !== undefined) {
    return bad('PROVENANCE_REVIEWER_FIELDS_UNEXPECTED');
  }

  // Metadata tamper: recompute the HMAC binding over the fixed-order list.
  const recomputed = computeIntegrityTag(boundEnvelopeValues(e as unknown as Parameters<typeof boundEnvelopeValues>[0]), store.integrityKey);
  if (recomputed !== (e.integrityTag as string)) return bad('METADATA_TAMPERED');

  // Output tamper: when bytes are provided they must hash to outputHash.
  if (params.governedOutput !== undefined) {
    if (typeof params.governedOutput !== 'string') return bad('OUTPUT_BYTES_INVALID');
    if (computeOutputHash(params.governedOutput) !== e.outputHash) return bad('OUTPUT_TAMPERED');
  }

  // Registry + classification pairing.
  const engine = store.getEngine(e.engineId as string);
  if (engine === null) return bad('PROVENANCE_ENGINE_UNKNOWN');
  const classification = checkEngineDesignation(engine, 'AI_ADVISORY', e.taskType as string);
  if (!classification.ok) return bad(classification.reasonCode ?? 'PROVENANCE_CLASSIFICATION_INVALID');
  if (e.engineVersion !== engine.engineVersion) return bad('PROVENANCE_ENGINE_VERSION_MISMATCH');

  // Policy version: stale -> fail closed.
  const expected = expectedPolicyVersion ?? store.policyVersion;
  if (e.policyVersion !== expected) return bad('PROVENANCE_POLICY_VERSION_STALE');

  return { ok: true, envelope: e as unknown as ProvenanceEnvelope };
}
