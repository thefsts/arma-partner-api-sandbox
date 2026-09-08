// Stop Point 7 — shared SDK: integration audit trail.
//
// Wraps the SP6 ai-governance AuditLog (append-only, metadata-only, secret
// detection) for integration-side events: request verification outcomes,
// receipt verification outcomes, webhook deliveries, reconciliation. All
// entries carry the SP6 discipline: material/content keys throw at record
// time; mutation is refused AND audited. Provenance references bind an
// integration entry to a governed provenance envelope via metadata only
// (provenanceId + outputHash) — never envelope contents.

import { AuditLog } from '../../ai-governance/audit.ts';
import { normalizeKey } from '../../ai-governance/classification.ts';

export { AuditLog };

/** Integration audit detail keys that are allowed (metadata only). */
const SAFE_INTEGRATION_KEYS = new Set([
  'requestId', 'partnerId', 'orgRef', 'capability', 'entityRef', 'receiptId',
  'eventId', 'sequence', 'attempt', 'maxAttempts', 'reasonCode', 'errorCode',
  'requestHash', 'payloadHash', 'nonce', 'timestamp', 'signatureValid',
  'receiptValid', 'duplicate', 'replayed', 'circuitState', 'retryCount',
  'errorClass', 'latencyMs', 'status', 'outcome', 'provenanceId', 'outputHash',
  'reconciliationStatus', 'stream', 'deliveryId', 'sdkVersion',
]);

const SAFE_DETAIL_STRING_MAX = 256;

export interface IntegrationAuditEntry {
  /** Event kind, e.g. 'integration.request.verified'. */
  readonly kind: string;
  /** Subject identifier (requestId, eventId, partnerId...). */
  readonly subjectId: string;
  /** Machine-readable reason code. */
  readonly reasonCode: string;
  /** Metadata-only details — allowlisted keys, scalar values, bounded strings. */
  readonly details?: Record<string, string | number | boolean | null>;
  /** Organization reference when known. */
  readonly orgRef?: string | null;
  /** Provenance reference — binds to a governed provenance envelope by ID only. */
  readonly provenance?: { provenanceId: string; outputHash: string };
}

export class IntegrationAuditTrail {
  private readonly log: AuditLog;

  constructor(log: AuditLog) {
    if (!(log instanceof AuditLog)) throw new Error('AUDIT_LOG_REQUIRED');
    this.log = log;
  }

  /** Append one integration audit record. Throws structurally on unsafe keys/values. */
  record(entry: IntegrationAuditEntry): void {
    if (entry === null || typeof entry !== 'object') throw new Error('AUDIT_ENTRY_INVALID');
    if (typeof entry.kind !== 'string' || !entry.kind.trim()) throw new Error('AUDIT_ENTRY_INVALID');
    if (typeof entry.subjectId !== 'string' || !entry.subjectId.trim()) throw new Error('AUDIT_ENTRY_INVALID');
    if (typeof entry.reasonCode !== 'string' || !entry.reasonCode.trim()) throw new Error('AUDIT_ENTRY_INVALID');

    const details: Record<string, string | number | boolean | null> = {};
    const source = entry.details ?? {};
    for (const [rawKey, value] of Object.entries(source)) {
      const key = rawKey.trim();
      const norm = normalizeKey(key);
      if (!SAFE_INTEGRATION_KEYS.has(key) && !SAFE_INTEGRATION_KEYS.has(norm)) {
        throw new Error(`AUDIT_DETAIL_KEY_UNSAFE_${norm.toUpperCase()}`);
      }
      if (value === null) { details[key] = null; continue; }
      if (typeof value === 'number') {
        if (!Number.isFinite(value)) throw new Error('AUDIT_DETAIL_VALUE_INVALID');
        details[key] = value;
        continue;
      }
      if (typeof value === 'boolean') { details[key] = value; continue; }
      if (typeof value === 'string') {
        if (value.length > SAFE_DETAIL_STRING_MAX) throw new Error('AUDIT_DETAIL_VALUE_TOO_LONG');
        details[key] = value;
        continue;
      }
      throw new Error('AUDIT_DETAIL_VALUE_INVALID');
    }
    if (entry.provenance !== undefined) {
      const p = entry.provenance;
      if (p === null || typeof p !== 'object'
        || typeof p.provenanceId !== 'string' || !p.provenanceId.trim()
        || typeof p.outputHash !== 'string' || !/^[0-9a-f]{64}$/.test(p.outputHash)) {
        throw new Error('AUDIT_PROVENANCE_REF_INVALID');
      }
      details.provenanceId = p.provenanceId.slice(0, SAFE_DETAIL_STRING_MAX);
      details.outputHash = p.outputHash;
    }

    this.log.recordAudit({
      kind: entry.kind,
      subjectId: entry.subjectId,
      reasonCode: entry.reasonCode,
      details,
      orgRef: entry.orgRef ?? null,
    });
  }

  /** Snapshot of the underlying append-only log. */
  list(): ReturnType<AuditLog['list']> {
    return this.log.list();
  }

  find(auditId: string): ReturnType<AuditLog['find']> {
    return this.log.find(auditId);
  }

  /** Mutation is ALWAYS refused and the refusal is itself audited (SP6 semantics). */
  attemptMutation(auditId: string, patch: unknown): { ok: false; reasonCode: string } {
    return this.log.attemptMutation(auditId, patch);
  }
}
