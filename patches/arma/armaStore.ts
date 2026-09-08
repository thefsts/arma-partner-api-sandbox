// ARMA-side durable store (Stop Point 5, sandbox reference).
//
// In-memory implementation of the transferSchema.ts table shapes with the
// same transactional discipline as the SP4 reference store: runTransaction
// snapshots the whole store and restores it on throw (all-or-nothing
// mutation). The private-repo port swaps this for Convex mutations; the
// activation service only touches these accessors, so the port is
// persistence-only.
//
// SECURITY: no method on this store accepts or returns a credential secret;
// ArmaPartnerConfig carries keyId REFERENCES only (see transferSchema.ts).

import type {
  ArmaPartnerConfig, ArmaOrgMapping, ArmaEntitlementRef, ArmaCapabilityRef,
  ArmaBinding, ArmaActivationRecord, ArmaIdempotencyRecord, ArmaReceiptRecord,
  ArmaRetryRecord, ArmaReconciliationRecord, ArmaAuditEventRecord,
} from './transferSchema.ts';

export class ArmaStore {
  readonly partnerConfig = new Map<string, ArmaPartnerConfig>();
  readonly orgMappings = new Map<string, ArmaOrgMapping>();
  readonly entitlementRefs = new Map<string, ArmaEntitlementRef>();
  readonly capabilityRefs = new Map<string, ArmaCapabilityRef>();
  readonly bindings = new Map<string, ArmaBinding>();
  readonly activations = new Map<string, ArmaActivationRecord>();
  readonly idempotency = new Map<string, ArmaIdempotencyRecord>();
  readonly receipts = new Map<string, ArmaReceiptRecord>();
  readonly retries = new Map<string, ArmaRetryRecord>();
  readonly reconciliations = new Map<string, ArmaReconciliationRecord>();
  readonly audit: ArmaAuditEventRecord[] = [];
  private auditSequence = 0;
  private txDepth = 0;

  // --- Partner config (singleton 'default') ---
  getPartnerConfig(configId = 'default'): ArmaPartnerConfig | null {
    return this.partnerConfig.get(configId) ?? null;
  }
  putPartnerConfig(config: ArmaPartnerConfig): void {
    this.partnerConfig.set(config.configId, config);
  }

  // --- Org mappings ---
  getOrgMappingByArmaOrg(armaOrgId: string): ArmaOrgMapping | null {
    for (const m of this.orgMappings.values()) if (m.armaOrgId === armaOrgId) return m;
    return null;
  }
  getOrgMapping(mappingId: string): ArmaOrgMapping | null {
    return this.orgMappings.get(mappingId) ?? null;
  }
  putOrgMapping(mapping: ArmaOrgMapping): void {
    this.orgMappings.set(mapping.mappingId, mapping);
  }

  // --- Entitlement / capability reference caches ---
  getEntitlementRef(patchesOrgId: string, capability: string): ArmaEntitlementRef | null {
    return this.entitlementRefs.get(`${patchesOrgId}::${capability}`) ?? null;
  }
  putEntitlementRef(ref: ArmaEntitlementRef): void {
    this.entitlementRefs.set(ref.refId, ref);
  }
  getCapabilityRef(capability: string): ArmaCapabilityRef | null {
    return this.capabilityRefs.get(capability) ?? null;
  }
  putCapabilityRef(ref: ArmaCapabilityRef): void {
    this.capabilityRefs.set(ref.capability, ref);
  }

  // --- Bindings ---
  getBinding(bindingId: string): ArmaBinding | null {
    return this.bindings.get(bindingId) ?? null;
  }
  putBinding(binding: ArmaBinding): void {
    this.bindings.set(binding.bindingId, binding);
  }
  findActiveActivationForBinding(bindingId: string, capability: string): ArmaActivationRecord | null {
    for (const a of this.activations.values()) {
      if (a.bindingId === bindingId && a.capability === capability &&
          (a.status === 'ACTIVE' || a.status === 'ACTIVATION_SENT' || a.status === 'RECEIPT_VERIFIED' || a.status === 'RECONCILIATION_REQUIRED' || a.status === 'PENDING' || a.status === 'READY_TO_ACTIVATE')) {
        return a;
      }
    }
    return null;
  }
  findActivationByIdempotencyKey(idempotencyKey: string): ArmaActivationRecord | null {
    for (const a of this.activations.values()) if (a.idempotencyKey === idempotencyKey) return a;
    return null;
  }

  // --- Activations ---
  getActivation(activationId: string): ArmaActivationRecord | null {
    return this.activations.get(activationId) ?? null;
  }
  putActivation(record: ArmaActivationRecord): void {
    this.activations.set(record.activationId, record);
  }
  listActivations(): ArmaActivationRecord[] {
    return [...this.activations.values()];
  }

  // --- Idempotency ---
  getIdempotency(idempotencyKey: string): ArmaIdempotencyRecord | null {
    return this.idempotency.get(idempotencyKey) ?? null;
  }
  putIdempotency(record: ArmaIdempotencyRecord): void {
    this.idempotency.set(record.id, record);
  }

  // --- Receipts (verified only) ---
  putReceipt(record: ArmaReceiptRecord): void {
    this.receipts.set(record.receiptId, record);
  }
  getReceipt(receiptId: string): ArmaReceiptRecord | null {
    return this.receipts.get(receiptId) ?? null;
  }

  // --- Retry state ---
  putRetry(record: ArmaRetryRecord): void {
    this.retries.set(record.retryId, record);
  }
  listRetries(activationId: string): ArmaRetryRecord[] {
    const out: ArmaRetryRecord[] = [];
    for (const r of this.retries.values()) if (r.activationId === activationId) out.push(r);
    return out.sort((a, b) => a.attempt - b.attempt);
  }

  // --- Reconciliation ---
  putReconciliation(record: ArmaReconciliationRecord): void {
    this.reconciliations.set(record.reconciliationId, record);
  }
  listReconciliations(activationId: string): ArmaReconciliationRecord[] {
    const out: ArmaReconciliationRecord[] = [];
    for (const r of this.reconciliations.values()) if (r.activationId === activationId) out.push(r);
    return out.sort((a, b) => a.statusQueryAttempt - b.statusQueryAttempt);
  }
  nextReconciliationAttempt(activationId: string): number {
    return this.listReconciliations(activationId).length + 1;
  }

  // --- Audit (append-only, allowlisted detail only) ---
  appendAuditEvent(event: Omit<ArmaAuditEventRecord, 'sequence'>): ArmaAuditEventRecord {
    const record: ArmaAuditEventRecord = { sequence: ++this.auditSequence, ...event };
    this.audit.push(record);
    return record;
  }

  // --- Transactions (snapshot/restore, all-or-nothing) ---
  runTransaction<T>(fn: () => T): T {
    if (this.txDepth > 0) return fn();
    const snapshot = this.snapshot();
    this.txDepth = 1;
    try {
      const result = fn();
      this.txDepth = 0;
      return result;
    } catch (err) {
      this.restore(snapshot);
      this.txDepth = 0;
      throw err;
    }
  }

  private snapshot(): string {
    return JSON.stringify({
      partnerConfig: [...this.partnerConfig.entries()],
      orgMappings: [...this.orgMappings.entries()],
      entitlementRefs: [...this.entitlementRefs.entries()],
      capabilityRefs: [...this.capabilityRefs.entries()],
      bindings: [...this.bindings.entries()],
      activations: [...this.activations.entries()],
      idempotency: [...this.idempotency.entries()],
      receipts: [...this.receipts.entries()],
      retries: [...this.retries.entries()],
      reconciliations: [...this.reconciliations.entries()],
      audit: this.audit,
      auditSequence: this.auditSequence,
    });
  }

  private restore(snapshot: string): void {
    const data = JSON.parse(snapshot) as {
      partnerConfig: [string, ArmaPartnerConfig][]; orgMappings: [string, ArmaOrgMapping][];
      entitlementRefs: [string, ArmaEntitlementRef][]; capabilityRefs: [string, ArmaCapabilityRef][];
      bindings: [string, ArmaBinding][]; activations: [string, ArmaActivationRecord][];
      idempotency: [string, ArmaIdempotencyRecord][]; receipts: [string, ArmaReceiptRecord][];
      retries: [string, ArmaRetryRecord][]; reconciliations: [string, ArmaReconciliationRecord][];
      audit: ArmaAuditEventRecord[]; auditSequence: number;
    };
    this.partnerConfig.clear(); for (const [k, v] of data.partnerConfig) this.partnerConfig.set(k, v);
    this.orgMappings.clear(); for (const [k, v] of data.orgMappings) this.orgMappings.set(k, v);
    this.entitlementRefs.clear(); for (const [k, v] of data.entitlementRefs) this.entitlementRefs.set(k, v);
    this.capabilityRefs.clear(); for (const [k, v] of data.capabilityRefs) this.capabilityRefs.set(k, v);
    this.bindings.clear(); for (const [k, v] of data.bindings) this.bindings.set(k, v);
    this.activations.clear(); for (const [k, v] of data.activations) this.activations.set(k, v);
    this.idempotency.clear(); for (const [k, v] of data.idempotency) this.idempotency.set(k, v);
    this.receipts.clear(); for (const [k, v] of data.receipts) this.receipts.set(k, v);
    this.retries.clear(); for (const [k, v] of data.retries) this.retries.set(k, v);
    this.reconciliations.clear(); for (const [k, v] of data.reconciliations) this.reconciliations.set(k, v);
    this.audit.length = 0; this.audit.push(...data.audit);
    this.auditSequence = data.auditSequence;
  }
}
