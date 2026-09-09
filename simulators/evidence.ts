// Stop Point 8 — contract-test evidence: metadata-only records + the
// Stop Point 10 certification mapping.
//
// Evidence is METADATA ONLY by construction: identifiers, contract codes,
// counts, booleans, and bounded strings. The builder structurally rejects
// any key outside the allowlist and any non-scalar or oversized value —
// payload content, secrets, and free-form detail can never enter evidence.
// `containsSensitiveMaterial` powers the harness-wide no-leak sweep over
// every surfaced surface (audit, telemetry, envelopes, evidence itself).
//
// The certification mapping produces the row shape the Stop Point 10
// PASS/FAIL/NOT-TESTED report generator consumes: { testId, category,
// requirement, result, reasonCode }.

import type { EvidenceSurface, FailureModeCategory } from './behaviors.ts';

// ---------------------------------------------------------------------------
// Evidence record
// ---------------------------------------------------------------------------

export type CertificationResult = 'PASS' | 'FAIL' | 'NOT-TESTED';

export interface ScenarioEvidence {
  /** `${simulatorId}:${modeId}` (control scenarios use `:control`). */
  readonly scenarioId: string;
  readonly simulatorId: string;
  readonly modeId: string;
  readonly category: FailureModeCategory | 'CONTROL';
  readonly surface: EvidenceSurface;
  /** Contract code the scenario must observe. */
  readonly expectedCode: string;
  /** Contract code actually observed (null when nothing was observed). */
  readonly observedCode: string | null;
  /** True when every declared contract point held (fail-closed discipline). */
  readonly passed: boolean;
  readonly failClosed: boolean;
  /** Retry plan the SDK computed for the failure (CLEAN_RETRY / AMBIGUOUS_RECONCILE / TERMINAL / EXHAUSTED). */
  readonly retryPlan: string | null;
  /** Underlying receipt reason when the failure was a receipt rejection. */
  readonly receiptReason: string | null;
  /** Delivery attempts recorded for the scenario's webhook phase. */
  readonly attempts: number;
  /** Transport invocations (receiver endpoint calls included). */
  readonly transportCalls: number;
  readonly deadLettered: boolean;
  /** Circuit-breaker states after each platform call (circuit scenarios only). */
  readonly circuitStates: readonly string[];
  /** Platform response codes in call order. */
  readonly operationCodes: readonly string[];
  /** Event types emitted, in order (types only — never envelope content). */
  readonly eventsEmitted: readonly string[];
  /** Final span status when a span was driven to a terminal state. */
  readonly spanStatus: string | null;
  /** Final span reconciliation status when reconciliation ran. */
  readonly reconciliationStatus: string | null;
  /** Names of the contract checks that held (short identifiers only). */
  readonly checks: readonly string[];
}

/** Keys allowed in an evidence record — identifiers and codes only. */
const SAFE_EVIDENCE_KEYS = new Set([
  'scenarioId', 'simulatorId', 'modeId', 'category', 'surface', 'expectedCode',
  'observedCode', 'passed', 'failClosed', 'retryPlan', 'receiptReason',
  'attempts', 'transportCalls', 'deadLettered', 'circuitStates',
  'operationCodes', 'eventsEmitted', 'spanStatus', 'reconciliationStatus',
  'checks',
]);

const EVIDENCE_STRING_MAX = 128;
const EVIDENCE_LIST_ITEM_MAX = 64;
const EVIDENCE_LIST_MAX = 32;

export interface ScenarioEvidenceInput {
  scenarioId: string;
  simulatorId: string;
  modeId: string;
  category: FailureModeCategory | 'CONTROL';
  surface: EvidenceSurface;
  expectedCode: string;
  observedCode: string | null;
  passed: boolean;
  failClosed: boolean;
  retryPlan?: string | null;
  receiptReason?: string | null;
  attempts?: number;
  transportCalls?: number;
  deadLettered?: boolean;
  circuitStates?: readonly string[];
  operationCodes?: readonly string[];
  eventsEmitted?: readonly string[];
  spanStatus?: string | null;
  reconciliationStatus?: string | null;
  checks?: readonly string[];
}

function evidenceString<T extends string>(value: T, key: string): T {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`EVIDENCE_FIELD_INVALID_${key.toUpperCase()}`);
  }
  if (value.length > EVIDENCE_STRING_MAX) {
    throw new Error(`EVIDENCE_FIELD_TOO_LONG_${key.toUpperCase()}`);
  }
  return value;
}

function evidenceStringList(value: unknown, key: string): string[] {
  if (!Array.isArray(value)) throw new Error(`EVIDENCE_FIELD_INVALID_${key.toUpperCase()}`);
  if (value.length > EVIDENCE_LIST_MAX) throw new Error(`EVIDENCE_LIST_TOO_LONG_${key.toUpperCase()}`);
  return value.map((item) => {
    if (typeof item !== 'string' || !item.trim() || item.length > EVIDENCE_LIST_ITEM_MAX) {
      throw new Error(`EVIDENCE_LIST_ITEM_INVALID_${key.toUpperCase()}`);
    }
    return item;
  });
}

/**
 * Build one metadata-only evidence record. Fails closed structurally:
 * unknown keys, non-scalar values, oversized strings, and non-list arrays
 * all throw — evidence can never carry payload content or free-form detail.
 */
export function buildScenarioEvidence(input: ScenarioEvidenceInput): ScenarioEvidence {
  if (!input || typeof input !== 'object') throw new Error('EVIDENCE_INPUT_INVALID');
  for (const key of Object.keys(input)) {
    if (!SAFE_EVIDENCE_KEYS.has(key)) {
      throw new Error(`EVIDENCE_KEY_UNSAFE_${key.toUpperCase()}`);
    }
  }
  const record: ScenarioEvidence = {
    scenarioId: evidenceString(input.scenarioId, 'scenarioId'),
    simulatorId: evidenceString(input.simulatorId, 'simulatorId'),
    modeId: evidenceString(input.modeId, 'modeId'),
    category: evidenceString(input.category, 'category'),
    surface: evidenceString(input.surface, 'surface'),
    expectedCode: evidenceString(input.expectedCode, 'expectedCode'),
    observedCode: input.observedCode === null || input.observedCode === undefined
      ? null
      : evidenceString(input.observedCode, 'observedCode'),
    passed: typeof input.passed === 'boolean' ? input.passed : (() => { throw new Error('EVIDENCE_FIELD_INVALID_PASSED'); })(),
    failClosed: typeof input.failClosed === 'boolean' ? input.failClosed : (() => { throw new Error('EVIDENCE_FIELD_INVALID_FAILCLOSED'); })(),
    retryPlan: input.retryPlan === null || input.retryPlan === undefined ? null : evidenceString(input.retryPlan, 'retryPlan'),
    receiptReason: input.receiptReason === null || input.receiptReason === undefined ? null : evidenceString(input.receiptReason, 'receiptReason'),
    attempts: typeof input.attempts === 'number' && Number.isInteger(input.attempts) && input.attempts >= 0
      ? input.attempts
      : 0,
    transportCalls: typeof input.transportCalls === 'number' && Number.isInteger(input.transportCalls) && input.transportCalls >= 0
      ? input.transportCalls
      : 0,
    deadLettered: input.deadLettered === true,
    circuitStates: Object.freeze(evidenceStringList(input.circuitStates ?? [], 'circuitStates')),
    operationCodes: Object.freeze(evidenceStringList(input.operationCodes ?? [], 'operationCodes')),
    eventsEmitted: Object.freeze(evidenceStringList(input.eventsEmitted ?? [], 'eventsEmitted')),
    spanStatus: input.spanStatus === null || input.spanStatus === undefined ? null : evidenceString(input.spanStatus, 'spanStatus'),
    reconciliationStatus: input.reconciliationStatus === null || input.reconciliationStatus === undefined
      ? null
      : evidenceString(input.reconciliationStatus, 'reconciliationStatus'),
    checks: Object.freeze(evidenceStringList(input.checks ?? [], 'checks')),
  };
  return Object.freeze(record);
}

// ---------------------------------------------------------------------------
// Sensitive-material detection (the no-leak sweep)
// ---------------------------------------------------------------------------

/**
 * True when any forbidden value (payload text or secret material) appears
 * as a substring of the serialized surface. Only values of meaningful
 * length participate — short tokens would produce false positives.
 */
export function containsSensitiveMaterial(text: string, forbidden: readonly string[]): boolean {
  if (typeof text !== 'string') return false;
  for (const value of forbidden) {
    if (typeof value === 'string' && value.length >= 8 && text.includes(value)) {
      return true;
    }
  }
  return false;
}

/**
 * Fail-closed metadata-only assertion for one serialized surface. Throws
 * with the SURFACE LABEL only — never the detected material itself.
 */
export function assertMetadataOnly(
  serializedSurface: string,
  forbidden: readonly string[],
  surfaceLabel: string,
): void {
  if (containsSensitiveMaterial(serializedSurface, forbidden)) {
    throw new Error(`EVIDENCE_SENSITIVE_MATERIAL_DETECTED_${surfaceLabel.toUpperCase()}`);
  }
}

// ---------------------------------------------------------------------------
// Stop Point 10 certification mapping (PASS / FAIL / NOT-TESTED rows)
// ---------------------------------------------------------------------------

export interface CertificationRow {
  /** Stable test identifier (the scenarioId). */
  readonly testId: string;
  /** Failure-mode category (or CONTROL for the well-behaved baseline). */
  readonly category: string;
  /** What the row certifies (the failure mode's contract description). */
  readonly requirement: string;
  readonly result: CertificationResult;
  /** Contract code observed (the reason a FAIL row failed, or the passing code). */
  readonly reasonCode: string | null;
}

const CERTIFICATION_REQUIREMENT_MAX = 256;

/** Map one scenario's evidence to its certification row. */
export function certificationRowFor(evidence: ScenarioEvidence): CertificationRow {
  const requirement = evidence.modeId === 'control'
    ? 'well-behaved simulator completes the full SP7 chain (sign -> verify -> receipt -> webhook -> receiver)'
    : `${evidence.modeId} (${evidence.category})`;
  return Object.freeze({
    testId: evidence.scenarioId,
    category: evidence.category,
    requirement: requirement.length > CERTIFICATION_REQUIREMENT_MAX
      ? requirement.slice(0, CERTIFICATION_REQUIREMENT_MAX)
      : requirement,
    result: evidence.passed ? 'PASS' : 'FAIL',
    reasonCode: evidence.passed ? evidence.expectedCode : (evidence.observedCode ?? 'NOT_TESTED'),
  });
}

/** A NOT-TESTED row: a case the harness recognizes but did not execute. */
export function notTestedRow(testId: string, category: string, reasonCode: string): CertificationRow {
  return Object.freeze({
    testId,
    category,
    requirement: 'not executed by this harness run',
    result: 'NOT-TESTED',
    reasonCode,
  });
}
