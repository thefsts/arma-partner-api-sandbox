// Stop Point 7 — integration observability: telemetry sink.
//
// The observability contract tracks integration traffic WITHOUT sensitive
// payloads: request/transfer ID, partner, organization reference, operation,
// start/completion, latency, success/failure, retry count, error category,
// reconciliation status. NEVER sensitive payload content. Forbidden keys
// (prompt/secret/token/content/output/payload...) are structurally rejected,
// and registered secret values can never appear in any value.

import { normalizeKey } from '../../ai-governance/classification.ts';

export type TelemetrySpanStatus = 'RUNNING' | 'SUCCESS' | 'FAILED' | 'AMBIGUOUS';

export interface TelemetrySpan {
  readonly spanId: string;
  /** Request/transfer ID being tracked (metadata only). */
  readonly requestId: string;
  readonly partnerId: string;
  readonly orgRef: string | null;
  /** Operation name, e.g. 'activation.create'. */
  readonly operation: string;
  readonly startedAt: number;
  readonly completedAt: number | null;
  readonly latencyMs: number | null;
  readonly status: TelemetrySpanStatus;
  readonly success: boolean | null;
  /** Coarse error category (AUTHENTICATION/DOWNSTREAM/TRANSPORT/...). */
  readonly errorClass: string | null;
  readonly retryCount: number;
  readonly reconciliationStatus: 'NONE' | 'PENDING' | 'RESOLVED' | 'REQUIRED_UNRESOLVED';
  readonly safeMetadata: Readonly<Record<string, string | number | boolean | null>>;
}

const SAFE_SPAN_METADATA_KEYS = new Set([
  'requestId', 'receiptId', 'eventId', 'deliveryId', 'partnerId', 'orgRef',
  'capability', 'entitlement', 'operation', 'entityRef', 'errorClass',
  'errorCode', 'attempt', 'maxAttempts', 'apiVersion', 'status', 'outcome',
  'reconciliationStatus', 'stream', 'auditId', 'provenanceId',
]);
const SPAN_METADATA_STRING_MAX = 256;

/** Key normalization shared with the SP6 classification discipline. */
const FORBIDDEN_METADATA_KEYS = new Set([
  'prompt', 'systemprompt', 'apikey', 'modelkey', 'token', 'credential',
  'credentials', 'signingkey', 'secret', 'secretvalue', 'password',
  'privatekey', 'authorization', 'signature',
]);

const FORBIDDEN_CONTENT_KEYS = new Set([
  'output', 'content', 'payload', 'result', 'message', 'body', 'text', 'data',
]);

export interface TelemetrySinkOptions {
  /** Injected clock (ms since epoch). */
  readonly now?: () => number;
  /** Secret values that must never appear in any metadata value. */
  readonly secretValues?: readonly string[];
}

export class InMemoryTelemetrySink {
  private readonly now: () => number;
  private readonly secretValues: readonly string[];
  private readonly spans = new Map<string, TelemetrySpan>();

  constructor(options: TelemetrySinkOptions = {}) {
    this.now = options.now ?? Date.now;
    this.secretValues = (options.secretValues ?? []).filter(
      (s) => typeof s === 'string' && s.length >= 8,
    ) as readonly string[];
  }

  /** Begin a span. Metadata is allowlisted at entry; forbidden keys throw. */
  startSpan(input: {
    requestId: string;
    partnerId: string;
    operation: string;
    orgRef?: string | null;
    metadata?: Record<string, unknown>;
  }): TelemetrySpan {
    if (!input || typeof input !== 'object') throw new Error('TELEMETRY_SPAN_INPUT_INVALID');
    if (typeof input.requestId !== 'string' || !input.requestId.trim()) throw new Error('TELEMETRY_REQUEST_ID_REQUIRED');
    if (typeof input.partnerId !== 'string' || !input.partnerId.trim()) throw new Error('TELEMETRY_PARTNER_REQUIRED');
    if (typeof input.operation !== 'string' || !input.operation.trim()) throw new Error('TELEMETRY_OPERATION_REQUIRED');
    if (input.orgRef !== undefined && input.orgRef !== null && (typeof input.orgRef !== 'string' || !input.orgRef.trim())) {
      throw new Error('TELEMETRY_SPAN_INPUT_INVALID');
    }

    const safeMetadata = this.sanitizeMetadata(input.metadata);
    const span: TelemetrySpan = {
      spanId: `span-${randomSpanId()}`,
      requestId: input.requestId,
      partnerId: input.partnerId,
      orgRef: input.orgRef ?? null,
      operation: input.operation,
      startedAt: this.now(),
      completedAt: null,
      latencyMs: null,
      status: 'RUNNING',
      success: null,
      errorClass: null,
      retryCount: 0,
      reconciliationStatus: 'NONE',
      safeMetadata: Object.freeze(safeMetadata),
    };
    this.spans.set(span.spanId, span);
    return span;
  }

  /** Mark a span SUCCESS or FAILED (terminal). */
  completeSpan(spanId: string, input: {
    success: boolean;
    errorClass?: string | null;
    retryCount?: number;
    reconciliationStatus?: TelemetrySpan['reconciliationStatus'];
    metadata?: Record<string, unknown>;
  }): TelemetrySpan {
    const span = this.requireSpan(spanId);
    if (span.status !== 'RUNNING') throw new Error('TELEMETRY_SPAN_ALREADY_COMPLETED');
    if (typeof input?.success !== 'boolean') throw new Error('TELEMETRY_SPAN_INPUT_INVALID');
    const retryCount = input.retryCount ?? span.retryCount;
    if (!Number.isInteger(retryCount) || retryCount < 0) throw new Error('TELEMETRY_RETRY_COUNT_INVALID');
    const reconciliationStatus = input.reconciliationStatus ?? span.reconciliationStatus;
    if (!RECONCILIATION_STATUSES.has(reconciliationStatus)) throw new Error('TELEMETRY_RECONCILIATION_STATUS_INVALID');
    const errorClass = input.errorClass ?? null;
    if (errorClass !== null && (typeof errorClass !== 'string' || !errorClass.trim())) {
      throw new Error('TELEMETRY_SPAN_INPUT_INVALID');
    }
    const completedAt = this.now();
    const mergedMetadata = { ...span.safeMetadata, ...this.sanitizeMetadata(input.metadata) };
    const updated: TelemetrySpan = Object.freeze({
      ...span,
      completedAt,
      latencyMs: completedAt - span.startedAt,
      status: input.success ? 'SUCCESS' : 'FAILED',
      success: input.success,
      errorClass,
      retryCount,
      reconciliationStatus,
      safeMetadata: Object.freeze(mergedMetadata),
    });
    this.spans.set(spanId, updated);
    return updated;
  }

  /** Mark a running span AMBIGUOUS (outcome unknown -> reconciliation). */
  markAmbiguous(spanId: string, input?: {
    errorClass?: string | null;
    retryCount?: number;
    reconciliationStatus?: TelemetrySpan['reconciliationStatus'];
    metadata?: Record<string, unknown>;
  }): TelemetrySpan {
    const span = this.requireSpan(spanId);
    if (span.status !== 'RUNNING') throw new Error('TELEMETRY_SPAN_ALREADY_COMPLETED');
    const reconciliationStatus = input?.reconciliationStatus ?? 'PENDING';
    if (!RECONCILIATION_STATUSES.has(reconciliationStatus)) throw new Error('TELEMETRY_RECONCILIATION_STATUS_INVALID');
    const retryCount = input?.retryCount ?? span.retryCount;
    if (!Number.isInteger(retryCount) || retryCount < 0) throw new Error('TELEMETRY_RETRY_COUNT_INVALID');
    const errorClass = input?.errorClass ?? null;
    const completedAt = this.now();
    const mergedMetadata = { ...span.safeMetadata, ...this.sanitizeMetadata(input?.metadata) };
    const updated: TelemetrySpan = Object.freeze({
      ...span,
      completedAt,
      latencyMs: completedAt - span.startedAt,
      status: 'AMBIGUOUS',
      success: null,
      errorClass,
      retryCount,
      reconciliationStatus,
      safeMetadata: Object.freeze(mergedMetadata),
    });
    this.spans.set(spanId, updated);
    return updated;
  }

  /** Update reconciliation status on a completed/ambiguous span. */
  updateReconciliation(spanId: string, status: TelemetrySpan['reconciliationStatus']): TelemetrySpan {
    const span = this.requireSpan(spanId);
    if (!RECONCILIATION_STATUSES.has(status)) throw new Error('TELEMETRY_RECONCILIATION_STATUS_INVALID');
    const updated: TelemetrySpan = Object.freeze({ ...span, reconciliationStatus: status });
    this.spans.set(spanId, updated);
    return updated;
  }

  getSpan(spanId: string): TelemetrySpan | null {
    return this.spans.get(spanId) ?? null;
  }

  findByRequestId(requestId: string): TelemetrySpan[] {
    return [...this.spans.values()].filter((s) => s.requestId === requestId);
  }

  list(): readonly TelemetrySpan[] {
    return [...this.spans.values()];
  }

  private requireSpan(spanId: string): TelemetrySpan {
    const span = this.spans.get(spanId);
    if (!span) throw new Error('TELEMETRY_SPAN_UNKNOWN');
    return span;
  }

  private sanitizeMetadata(metadata: Record<string, unknown> | undefined): Record<string, string | number | boolean | null> {
    const out: Record<string, string | number | boolean | null> = {};
    for (const [rawKey, value] of Object.entries(metadata ?? {})) {
      const key = rawKey.trim();
      const norm = normalizeKey(key);
      if (FORBIDDEN_METADATA_KEYS.has(norm) || FORBIDDEN_CONTENT_KEYS.has(norm)) {
        throw new Error(`TELEMETRY_METADATA_KEY_FORBIDDEN_${norm.toUpperCase()}`);
      }
      if (!SAFE_SPAN_METADATA_KEYS.has(key)) {
        throw new Error(`TELEMETRY_METADATA_KEY_UNSAFE_${norm.toUpperCase()}`);
      }
      if (value === null) { out[key] = null; continue; }
      if (typeof value === 'number') {
        if (!Number.isFinite(value)) throw new Error('TELEMETRY_METADATA_VALUE_INVALID');
        out[key] = value;
        continue;
      }
      if (typeof value === 'boolean') { out[key] = value; continue; }
      if (typeof value === 'string') {
        if (value.length > SPAN_METADATA_STRING_MAX) throw new Error('TELEMETRY_METADATA_VALUE_TOO_LONG');
        for (const secret of this.secretValues) {
          if (value.includes(secret)) throw new Error('TELEMETRY_SECRET_MATERIAL_DETECTED');
        }
        out[key] = value;
        continue;
      }
      throw new Error('TELEMETRY_METADATA_VALUE_INVALID');
    }
    return out;
  }
}

const RECONCILIATION_STATUSES = new Set(['NONE', 'PENDING', 'RESOLVED', 'REQUIRED_UNRESOLVED']);

function randomSpanId(): string {
  return Math.random().toString(16).slice(2, 10) + Date.now().toString(16);
}
