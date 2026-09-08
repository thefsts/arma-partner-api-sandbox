// Stop Point 6 — append-only governance audit log.
//
// Audit records are METADATA ONLY: identifiers, reason codes, hashes, and
// booleans. Material keys (prompts, keys, tokens, credentials, CoT) and
// content keys (output/content/payload/result/message) throw at record
// time, by construction. Registered secret values can never appear in any
// detail value. Mutation is refused AND audited — append-only.

import { normalizeKey } from './classification.ts';

export interface GovernanceClock {
  now(): number;
}

export interface GovernanceAuditRecord {
  readonly auditId: string;
  readonly kind: string;
  readonly subjectId: string;
  readonly reasonCode: string;
  readonly details: Readonly<Record<string, string | number | boolean | null>>;
  readonly orgRef: string | null;
  readonly at: number;
}

export interface RecordAuditEntry {
  kind: string;
  subjectId: string;
  reasonCode: string;
  details?: Record<string, string | number | boolean | null>;
  orgRef?: string | null;
}

export interface AuditLogOptions {
  clock: GovernanceClock;
  secretValues?: readonly unknown[];
}

/** Keys that would carry private material — forbidden in audit details. */
const FORBIDDEN_MATERIAL_KEYS = new Set([
  'prompt', 'systemprompt', 'apikey', 'modelkey', 'modelprovider', 'token',
  'credential', 'credentials', 'signingkey', 'secret', 'secretvalue',
  'chainofthought', 'password', 'privatekey', 'model',
]);

/** Keys that would carry governed content — audit is metadata-only. */
const FORBIDDEN_CONTENT_KEYS = new Set([
  'output', 'content', 'payload', 'result', 'message', 'body', 'text',
]);

export type AttemptMutationResult = { ok: false; reasonCode: string };

export class AuditLog {
  private readonly clock: GovernanceClock;
  private readonly secretValues: readonly string[];
  private readonly records: GovernanceAuditRecord[] = [];
  private seq = 0;

  constructor(options: AuditLogOptions) {
    if (!options || typeof options.clock?.now !== 'function') throw new Error('AUDIT_CLOCK_REQUIRED');
    this.clock = options.clock;
    this.secretValues = (options.secretValues ?? []).filter(
      (s) => typeof s === 'string' && s.length >= 8,
    ) as readonly string[];
  }

  /** Append one metadata-only record. Throws on material/content keys or
   *  any detail value containing a registered secret. */
  recordAudit(entry: RecordAuditEntry): GovernanceAuditRecord {
    if (entry === null || typeof entry !== 'object') throw new Error('AUDIT_ENTRY_INVALID');
    if (typeof entry.kind !== 'string' || !entry.kind.trim()) throw new Error('AUDIT_ENTRY_INVALID');
    if (typeof entry.subjectId !== 'string' || !entry.subjectId.trim()) throw new Error('AUDIT_ENTRY_INVALID');
    if (typeof entry.reasonCode !== 'string' || !entry.reasonCode.trim()) throw new Error('AUDIT_ENTRY_INVALID');
    const details = entry.details ?? {};
    for (const [key, value] of Object.entries(details)) {
      const norm = normalizeKey(key);
      if (FORBIDDEN_MATERIAL_KEYS.has(norm)) {
        throw new Error(`AUDIT_MATERIAL_DETAIL_KEY_${norm.toUpperCase()}`);
      }
      if (FORBIDDEN_CONTENT_KEYS.has(norm)) {
        throw new Error(`AUDIT_CONTENT_DETAIL_KEY_${norm.toUpperCase()}`);
      }
      if (typeof value === 'string') {
        for (const secret of this.secretValues) {
          if (secret.length > 0 && value.includes(secret)) {
            throw new Error('AUDIT_SECRET_MATERIAL_DETECTED');
          }
        }
      }
    }
    const record: GovernanceAuditRecord = Object.freeze({
      auditId: this.nextAuditId(),
      kind: entry.kind,
      subjectId: entry.subjectId,
      reasonCode: entry.reasonCode,
      details: Object.freeze({ ...details }),
      orgRef: entry.orgRef ?? null,
      at: this.clock.now(),
    });
    this.records.push(record);
    return record;
  }

  /** Snapshot of the append-only log (records themselves are frozen). */
  list(): readonly GovernanceAuditRecord[] {
    return [...this.records];
  }

  find(auditId: string): GovernanceAuditRecord | null {
    return this.records.find((r) => r.auditId === auditId) ?? null;
  }

  /**
   * Mutation is ALWAYS refused and the refusal is audited. Audit history is
   * append-only by construction; corrections are NEW records, never edits.
   */
  attemptMutation(auditId: string, patch: unknown): AttemptMutationResult {
    const attempted = typeof auditId === 'string' && auditId ? auditId : 'UNKNOWN';
    const patchKeys = patch !== null && typeof patch === 'object'
      ? Object.keys(patch as Record<string, unknown>).join(',')
      : '';
    this.recordAudit({
      kind: 'governance.audit.mutation_denied',
      subjectId: attempted,
      reasonCode: 'AUDIT_MUTATION_REFUSED',
      details: { attemptedAuditId: attempted, refused: true, patchKeys },
    });
    return { ok: false, reasonCode: 'AUDIT_MUTATION_REFUSED' };
  }

  private nextAuditId(): string {
    this.seq += 1;
    return `AUD-${String(this.seq).padStart(6, '0')}`;
  }
}
