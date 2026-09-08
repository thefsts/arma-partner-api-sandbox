// PATCHES Partner API v1 — synthetic reference persistence.
//
// In-memory store modeling the private PATCHES repository's durable
// persistence so the partner API contracts can be built and tested in
// this public sandbox. Interfaces are deliberately shaped for porting:
// every collection maps to a table/collection with a unique index on its
// natural key, `runTransaction` models an atomic mutation, and no PII or
// real PATCHES data is stored anywhere.
//
// PORTING NOTE (private PATCHES repo):
// - partners           -> partners table, unique index on partnerId/clientId
// - credentials        -> credentials table, unique index on clientId+keyId
// - organizations      -> organizations table, unique index on orgId
// - entitlements       -> entitlements table, unique index on (partnerId, orgId, capability)
// - bindings           -> bindings table, unique index on bindingId; lookup by (orgId, deviceId/subjectId) via secondary index
// - activations        -> activations table, unique index on activationId; lookup by bindingId via secondary index
// - idempotency        -> idempotency table, unique index on (clientId, idempotencyKey)
// - nonces             -> nonces table, unique index on (clientId, nonce) with TTL-style validity window
// - receipts           -> receipts table, unique index on receiptId
// - events             -> events table, append-only, ordered by sequence
// - audit              -> audit table, append-only, ordered by sequence
// - The acceptance path for a state-changing operation is ONE mutation
//   performing all inserts; a unique-index violation aborts the whole
//   mutation (models runTransaction rollback).
// - Remove TEST-ONLY `failPoints` when porting (keep them in the sandbox).

export interface PartnerRecord {
  partnerId: string;
  clientId: string;
  status: 'ACTIVE' | 'SUSPENDED';
}

export type CredentialKind = 'CLIENT_SECRET';

export interface CredentialRecord {
  clientId: string;
  keyId: string;
  kind: CredentialKind;
  secretHash: string; // synthetic hash material, never a plaintext secret
  status: 'ACTIVE' | 'GRACE' | 'RETIRED' | 'REVOKED';
  activatedAt: number;
  rotatedFrom?: string; // previous keyId when this key was created by rotation
  retiredAt?: number;
  revokedAt?: number;
  revokedReason?: string;
}

export interface OrganizationRecord {
  orgId: string;
  owningPartnerId: string; // the partner that operates this organization
  status: 'ACTIVE' | 'SUSPENDED';
}

export interface EntitlementRecord {
  entitlementId: string;
  partnerId: string;
  orgId: string;
  capability: string; // generic contract identifier, e.g. traffic_stop_privacy
  status: 'ACTIVE' | 'INACTIVE' | 'REVOKED';
  licensedFrom: number;
  licensedUntil: number;
}

export interface CapabilityRecord {
  capability: string;
  minApiVersion: string;
  maxApiVersion: string;
  description: string;
}

export type BindingStatus = 'ACTIVE' | 'INACTIVE';

export interface DeviceSubjectBindingRecord {
  bindingId: string;
  orgId: string;
  capability: string;
  deviceId: string; // opaque synthetic identifier
  subjectRef: string; // opaque synthetic identifier; no PII
  status: BindingStatus;
  boundAt: number;
}

export type ActivationStatus = 'ACTIVE' | 'DEACTIVATED' | 'REVOKED';

export interface ActivationRecord {
  activationId: string;
  orgId: string;
  capability: string;
  bindingId: string;
  partnerId: string;
  status: ActivationStatus;
  activatedAt: number;
  deactivatedAt?: number;
  revokedAt?: number;
  lastRequestId?: string;
  idempotencyKey?: string;
  activatedViaIdempotencyKey?: string;
  payloadHash: string; // hash of the canonical request payload, NOT payload content
}

export interface IdempotencyRecord {
  clientId: string;
  idempotencyKey: string;
  requestHash: string;
  outcome: 'SUCCESS' | 'CONFLICT';
  activationId?: string;
  requestId?: string;
  at: number;
}

export interface NonceRecord {
  clientId: string;
  nonce: string;
  firstSeenAt: number;
  firstSeenRequestId?: string;
}

export interface ReceiptRecord {
  receiptId: string;
  requestId: string;
  clientId: string;
  operation: string; // e.g. activation.create
  outcome: string; // e.g. SUCCESS / CONFLICT / REJECTED
  activationId?: string;
  orgId?: string;
  capability?: string;
  payloadHash?: string;
  at: number;
}

export interface PartnerEventRecord {
  eventId: string;
  orgId: string;
  capability: string;
  activationId?: string;
  type: string; // e.g. activation.created, activation.deactivated, activation.revoked
  at: number;
  payloadDigest?: string; // digest reference, never event content
}

export type AuditActorKind = 'PARTNER' | 'SYSTEM';
export type AuditOutcome = 'SUCCESS' | 'REJECTED' | 'FAILED' | 'QUARANTINED' | 'CONFLICT';

export interface AuditEventRecord {
  sequence: number;
  at: number;
  actorKind: AuditActorKind;
  clientId: string;
  requestId: string;
  operation: string;
  outcome: AuditOutcome;
  detail?: Record<string, unknown>;
}

export interface StoreFailPoints {
  persistActivation?: boolean;
  persistReceipt?: boolean;
  auditWrite?: boolean;
  eventWrite?: boolean;
}

// Allowlisted audit detail keys: payload content structurally cannot reach
// the audit trail. Same discipline as the Law Shield store.
export const SAFE_DETAIL_KEYS = new Set([
  'code', 'reason', 'requestId', 'receiptId', 'activationId', 'bindingId',
  'partnerId', 'clientId', 'orgId', 'capability', 'keyId', 'credentialStatus',
  'status', 'outcome', 'operation', 'idempotencyKey', 'nonce', 'requestHash',
  'payloadHash', 'eventId', 'apiVersion', 'version', 'limit', 'windowMs',
  'retryAfterMs', 'rotatedFrom', 'graceUntil', 'errorCode', 'errorCodes',
  'downstreamStatus', 'bindingStatus', 'entitlementStatus', 'firstSeenAt',
  'firstSeenRequestId', 'existingActivationId', 'existingRequestHash',
  'eventCount', 'eventType', 'at',
]);

const SAFE_DETAIL_STRING_MAX = 256;
const SAFE_DETAIL_DEPTH = 3;

function sanitizeDetail(value: unknown, depth: number): unknown {
  if (typeof value === 'string') {
    return value.length <= SAFE_DETAIL_STRING_MAX ? value : null;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    if (depth >= SAFE_DETAIL_DEPTH) return null;
    const out: unknown[] = [];
    for (const item of value) {
      const clean = sanitizeDetail(item, depth + 1);
      if (clean !== null) out.push(clean);
    }
    return out;
  }
  if (value !== null && typeof value === 'object') {
    if (depth >= SAFE_DETAIL_DEPTH) return null;
    const out: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      if (!SAFE_DETAIL_KEYS.has(key)) continue; // not allowlisted -> dropped, never logged
      const clean = sanitizeDetail(inner, depth + 1);
      if (clean !== null) out[key] = clean;
    }
    return out;
  }
  return null;
}

export class SyntheticPartnerStore {
  readonly partners = new Map<string, PartnerRecord>(); // key: clientId
  readonly credentials = new Map<string, CredentialRecord>(); // key: clientId::keyId
  readonly organizations = new Map<string, OrganizationRecord>(); // key: orgId
  readonly entitlements = new Map<string, EntitlementRecord>(); // key: partnerId::orgId::capability
  readonly capabilities = new Map<string, CapabilityRecord>(); // key: capability
  readonly bindings = new Map<string, DeviceSubjectBindingRecord>(); // key: bindingId
  readonly activations = new Map<string, ActivationRecord>(); // key: activationId
  readonly idempotency = new Map<string, IdempotencyRecord>(); // key: clientId::idempotencyKey
  readonly nonces = new Map<string, NonceRecord>(); // key: clientId::nonce
  readonly receipts = new Map<string, ReceiptRecord>(); // key: receiptId
  readonly events: PartnerEventRecord[] = [];
  readonly audit: AuditEventRecord[] = [];
  failPoints: StoreFailPoints = {};
  auditSequence = 0; // internal counter; module-level snapshot/restore accesses it directly
  private txDepth = 0;

  // --- Transaction model (TEST-ONLY fail points included) ---

  runTransaction<T>(fn: () => T): T {
    if (this.txDepth > 0) return fn(); // nested calls join the outer transaction
    const snapshot = serializeStore(this);
    this.txDepth = 1;
    try {
      const result = fn();
      this.txDepth = 0;
      return result;
    } catch (err) {
      restoreStore(this, snapshot);
      this.txDepth = 0;
      throw err;
    }
  }

  private _fail(name: keyof StoreFailPoints): void {
    if (this.failPoints[name]) throw new Error(`FAILPOINT_${name}`);
  }

  // --- Partners / credentials / orgs ---

  addPartner(partner: PartnerRecord): void {
    this.partners.set(partner.clientId, partner);
  }

  getPartnerByClientId(clientId: string): PartnerRecord | null {
    return this.partners.get(clientId) ?? null;
  }

  putCredential(cred: CredentialRecord): void {
    this.credentials.set(credentialKey(cred.clientId, cred.keyId), cred);
  }

  getCredential(clientId: string, keyId: string): CredentialRecord | null {
    return this.credentials.get(credentialKey(clientId, keyId)) ?? null;
  }

  activeCredentialFor(clientId: string): CredentialRecord | null {
    let found: CredentialRecord | null = null;
    for (const cred of this.credentials.values()) {
      if (cred.clientId !== clientId) continue;
      if (cred.status === 'ACTIVE') return cred;
      if (cred.status === 'GRACE' && !found) found = cred;
    }
    return found;
  }

  listCredentialsFor(clientId: string): CredentialRecord[] {
    const out: CredentialRecord[] = [];
    for (const cred of this.credentials.values()) {
      if (cred.clientId === clientId) out.push(cred);
    }
    return out.sort((a, b) => a.keyId.localeCompare(b.keyId));
  }

  addOrganization(org: OrganizationRecord): void {
    this.organizations.set(org.orgId, org);
  }

  getOrganization(orgId: string): OrganizationRecord | null {
    return this.organizations.get(orgId) ?? null;
  }

  // --- Entitlements / capabilities ---

  putEntitlement(ent: EntitlementRecord): void {
    this.entitlements.set(entitlementKey(ent.partnerId, ent.orgId, ent.capability), ent);
  }

  getEntitlement(partnerId: string, orgId: string, capability: string): EntitlementRecord | null {
    return this.entitlements.get(entitlementKey(partnerId, orgId, capability)) ?? null;
  }

  listEntitlementsForOrg(partnerId: string, orgId: string): EntitlementRecord[] {
    const out: EntitlementRecord[] = [];
    for (const ent of this.entitlements.values()) {
      if (ent.partnerId === partnerId && ent.orgId === orgId) out.push(ent);
    }
    return out.sort((a, b) => a.capability.localeCompare(b.capability));
  }

  putCapability(cap: CapabilityRecord): void {
    this.capabilities.set(cap.capability, cap);
  }

  getCapability(capability: string): CapabilityRecord | null {
    return this.capabilities.get(capability) ?? null;
  }

  listCapabilities(): CapabilityRecord[] {
    return [...this.capabilities.values()].sort((a, b) => a.capability.localeCompare(b.capability));
  }

  // --- Bindings (opaque device/subject) ---

  putBinding(binding: DeviceSubjectBindingRecord): void {
    this.bindings.set(binding.bindingId, binding);
  }

  getBinding(bindingId: string): DeviceSubjectBindingRecord | null {
    return this.bindings.get(bindingId) ?? null;
  }

  findBindingByDevice(orgId: string, deviceId: string): DeviceSubjectBindingRecord | null {
    for (const b of this.bindings.values()) {
      if (b.orgId === orgId && b.deviceId === deviceId) return b;
    }
    return null;
  }

  // --- Activations ---

  putActivation(activation: ActivationRecord): void {
    this._fail('persistActivation');
    this.activations.set(activation.activationId, activation);
  }

  getActivation(activationId: string): ActivationRecord | null {
    return this.activations.get(activationId) ?? null;
  }

  // --- Idempotency ---

  putIdempotency(record: IdempotencyRecord): void {
    this.idempotency.set(idempotencyKey(record.clientId, record.idempotencyKey), record);
  }

  getIdempotency(clientId: string, key: string): IdempotencyRecord | null {
    return this.idempotency.get(idempotencyKey(clientId, key)) ?? null;
  }

  // --- Nonces (replay guard) ---

  registerNonce(clientId: string, nonce: string, at: number, requestId?: string): NonceRecord | null {
    const key = nonceKey(clientId, nonce);
    const existing = this.nonces.get(key);
    if (existing) return existing; // replay: caller treats null-return as "fresh" signal
    const record: NonceRecord = { clientId, nonce, firstSeenAt: at, firstSeenRequestId: requestId };
    this.nonces.set(key, record);
    return null;
  }

  pruneNoncesBefore(at: number): void {
    for (const [key, rec] of this.nonces) {
      if (rec.firstSeenAt < at) this.nonces.delete(key);
    }
  }

  getNonceRecord(clientId: string, nonce: string): NonceRecord | null {
    return this.nonces.get(nonceKey(clientId, nonce)) ?? null;
  }

  nonceCount(): number {
    return this.nonces.size;
  }

  // --- Receipts / events / audit ---

  putReceipt(receipt: ReceiptRecord): void {
    this._fail('persistReceipt');
    this.receipts.set(receipt.receiptId, receipt);
  }

  getReceipt(receiptId: string): ReceiptRecord | null {
    return this.receipts.get(receiptId) ?? null;
  }

  appendEvent(event: PartnerEventRecord): void {
    this._fail('eventWrite');
    this.events.push(event);
  }

  appendAudit(event: Omit<AuditEventRecord, 'sequence'>): void {
    this._fail('auditWrite');
    const sanitized = sanitizeDetail(event.detail, 0);
    const record: AuditEventRecord = {
      sequence: ++this.auditSequence,
      at: event.at,
      actorKind: event.actorKind,
      clientId: event.clientId,
      requestId: event.requestId,
      operation: event.operation,
      outcome: event.outcome,
    };
    if (sanitized !== null && typeof sanitized === 'object' && !Array.isArray(sanitized)) {
      record.detail = sanitized as Record<string, unknown>;
    }
    this.audit.push(record);
  }

  getAuditEvents({ clientId, requestId }: { clientId?: string; requestId?: string }): AuditEventRecord[] {
    return this.audit.filter((e) => {
      if (clientId !== undefined && e.clientId !== clientId) return false;
      if (requestId !== undefined && e.requestId !== requestId) return false;
      return true;
    });
  }

  // --- Counts for tests ---

  activationCount(): number { return this.activations.size; }
  receiptCount(): number { return this.receipts.size; }
  eventCount(): number { return this.events.length; }
  auditCount(): number { return this.audit.length; }
  bindingCount(): number { return this.bindings.size; }
}

function credentialKey(clientId: string, keyId: string): string { return `${clientId}::${keyId}`; }
function entitlementKey(partnerId: string, orgId: string, capability: string): string { return `${partnerId}::${orgId}::${capability}`; }
function idempotencyKey(clientId: string, key: string): string { return `${clientId}::${key}`; }
function nonceKey(clientId: string, nonce: string): string { return `${clientId}::${nonce}`; }

// Snapshot/restore via deep clone — models a rolled-back mutation. The
// private repo achieves the same by aborting the mutation before commit.
function serializeStore(store: SyntheticPartnerStore): SyntheticPartnerStore {
  return {
    partners: cloneMap(store.partners),
    credentials: cloneMap(store.credentials),
    organizations: cloneMap(store.organizations),
    entitlements: cloneMap(store.entitlements),
    capabilities: cloneMap(store.capabilities),
    bindings: cloneMap(store.bindings),
    activations: cloneMap(store.activations),
    idempotency: cloneMap(store.idempotency),
    nonces: cloneMap(store.nonces),
    receipts: cloneMap(store.receipts),
    events: structuredClone(store.events),
    audit: structuredClone(store.audit),
    failPoints: { ...store.failPoints },
    auditSequence: store.auditSequence,
  } as unknown as SyntheticPartnerStore;
}

function restoreStore(target: SyntheticPartnerStore, snapshot: SyntheticPartnerStore): void {
  target.partners.clear(); for (const [k, v] of snapshot.partners) target.partners.set(k, v);
  target.credentials.clear(); for (const [k, v] of snapshot.credentials) target.credentials.set(k, v);
  target.organizations.clear(); for (const [k, v] of snapshot.organizations) target.organizations.set(k, v);
  target.entitlements.clear(); for (const [k, v] of snapshot.entitlements) target.entitlements.set(k, v);
  target.capabilities.clear(); for (const [k, v] of snapshot.capabilities) target.capabilities.set(k, v);
  target.bindings.clear(); for (const [k, v] of snapshot.bindings) target.bindings.set(k, v);
  target.activations.clear(); for (const [k, v] of snapshot.activations) target.activations.set(k, v);
  target.idempotency.clear(); for (const [k, v] of snapshot.idempotency) target.idempotency.set(k, v);
  target.nonces.clear(); for (const [k, v] of snapshot.nonces) target.nonces.set(k, v);
  target.receipts.clear(); for (const [k, v] of snapshot.receipts) target.receipts.set(k, v);
  target.events.length = 0; for (const e of snapshot.events) target.events.push(e);
  target.audit.length = 0; for (const a of snapshot.audit) target.audit.push(a);
  target.failPoints = { ...snapshot.failPoints };
  target.auditSequence = snapshot.auditSequence;
}

function cloneMap<V>(map: Map<string, V>): Map<string, V> {
  const out = new Map<string, V>();
  for (const [k, v] of map) out.set(k, structuredClone(v));
  return out;
}
