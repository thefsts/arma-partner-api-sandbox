// Stop Point 6 — the governance store: engine registry, provenance /
// deterministic envelope stores, human-review records, and the append-only
// audit log. Synthetic sandbox integrity key ONLY — production deployments
// inject their own key; nothing private ships in this public repo.

import { AuditLog } from './audit.ts';
import type { GovernanceAuditRecord, RecordAuditEntry, GovernanceClock } from './audit.ts';
import type { EngineRegistration, RegisteredEngine } from './classification.ts';
import { validateEngineRegistration } from './classification.ts';
import type { ProvenanceEnvelope } from './provenance.ts';
import type { DeterministicResultEnvelope } from './deterministicRules.ts';
import type { HumanReviewRecord } from './humanReview.ts';

/** SYNTHETIC sandbox material — explicitly not a production key. */
export const SYNTHETIC_INTEGRITY_KEY = 'SYNTHETIC-sandbox-integrity-key-SP6-NOT-PRODUCTION';

export interface GovernanceStoreOptions {
  clock?: GovernanceClock;
  policyVersion?: string;
  integrityKey?: string;
}

export class GovernanceStore {
  readonly clock: GovernanceClock;
  readonly policyVersion: string;
  readonly integrityKey: string;
  readonly auditLog: AuditLog;

  private readonly engines = new Map<string, RegisteredEngine>();
  private readonly provenance = new Map<string, ProvenanceEnvelope>();
  private readonly deterministic = new Map<string, DeterministicResultEnvelope>();
  private readonly reviews = new Map<string, HumanReviewRecord>();
  private provenanceSeq = 0;
  private deterministicSeq = 0;
  private reviewSeq = 0;

  constructor(options?: GovernanceStoreOptions) {
    const opts = options ?? {};
    if (opts.policyVersion !== undefined &&
        (typeof opts.policyVersion !== 'string' || !opts.policyVersion.trim())) {
      throw new Error('STORE_POLICY_VERSION_INVALID');
    }
    if (opts.integrityKey !== undefined &&
        (typeof opts.integrityKey !== 'string' || opts.integrityKey.length < 8)) {
      throw new Error('STORE_INTEGRITY_KEY_INVALID');
    }
    this.clock = opts.clock ?? { now: () => Date.now() };
    this.policyVersion = opts.policyVersion ?? 'ai-governance.policy.v1';
    const integrityKey = opts.integrityKey ?? SYNTHETIC_INTEGRITY_KEY;
    this.integrityKey = integrityKey;
    this.auditLog = new AuditLog({ clock: this.clock, secretValues: [integrityKey] });
  }

  recordAudit(entry: RecordAuditEntry): GovernanceAuditRecord {
    return this.auditLog.recordAudit(entry);
  }

  listAudit(): readonly GovernanceAuditRecord[] {
    return this.auditLog.list();
  }

  /** Register an engine — pinned to its one legal designation, frozen,
   *  audited. Throws on re-registration (fail closed, no silent rebind). */
  registerEngine(reg: EngineRegistration): RegisteredEngine {
    validateEngineRegistration(reg);
    if (this.engines.has(reg.engineId)) throw new Error('ENGINE_ALREADY_REGISTERED');
    const engine: RegisteredEngine = Object.freeze({
      engineId: reg.engineId,
      engineClass: reg.engineClass,
      engineVersion: reg.engineVersion,
      designation: reg.designation,
      advisoryOnly: reg.advisoryOnly,
      registeredAt: this.clock.now(),
    });
    this.engines.set(engine.engineId, engine);
    this.recordAudit({
      kind: 'governance.engine.registered',
      subjectId: engine.engineId,
      reasonCode: 'ENGINE_REGISTERED',
      details: {
        engineClass: engine.engineClass,
        engineVersion: engine.engineVersion,
        designation: engine.designation,
        advisoryOnly: engine.advisoryOnly,
      },
      orgRef: null,
    });
    return engine;
  }

  getEngine(engineId: string): RegisteredEngine | null {
    return this.engines.get(engineId) ?? null;
  }

  listEngines(): readonly RegisteredEngine[] {
    return [...this.engines.values()];
  }

  nextProvenanceId(): string {
    this.provenanceSeq += 1;
    return `PROV-${String(this.provenanceSeq).padStart(6, '0')}`;
  }

  putProvenanceEnvelope(envelope: ProvenanceEnvelope): void {
    if (this.provenance.has(envelope.provenanceId)) {
      throw new Error('STORE_PROVENANCE_ID_COLLISION');
    }
    this.provenance.set(envelope.provenanceId, envelope);
  }

  getProvenanceEnvelope(provenanceId: string): ProvenanceEnvelope | null {
    return this.provenance.get(provenanceId) ?? null;
  }

  nextDeterministicId(): string {
    this.deterministicSeq += 1;
    return `DET-${String(this.deterministicSeq).padStart(6, '0')}`;
  }

  putDeterministicEnvelope(envelope: DeterministicResultEnvelope): void {
    if (this.deterministic.has(envelope.resultId)) {
      throw new Error('STORE_DETERMINISTIC_ID_COLLISION');
    }
    this.deterministic.set(envelope.resultId, envelope);
  }

  getDeterministicEnvelope(resultId: string): DeterministicResultEnvelope | null {
    return this.deterministic.get(resultId) ?? null;
  }

  nextReviewId(): string {
    this.reviewSeq += 1;
    return `REV-${String(this.reviewSeq).padStart(6, '0')}`;
  }

  putReview(review: HumanReviewRecord): void {
    if (this.reviews.has(review.reviewId)) throw new Error('STORE_REVIEW_ID_COLLISION');
    this.reviews.set(review.reviewId, review);
  }

  getReview(reviewId: string): HumanReviewRecord | null {
    return this.reviews.get(reviewId) ?? null;
  }
}
