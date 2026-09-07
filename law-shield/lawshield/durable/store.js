// Durable Law Shield processor — synthetic persistence (sandbox only).
// ---------------------------------------------------------------------------
// This is the Law Shield-side durable state for the arma-lawshield.v1 lane:
// the authoritative nonce replay registry, the idempotency registry, durable
// transfer records (accepted / rejected / quarantined), receipt records, and
// the append-only audit trail. The processor (processor.js) commits ALL of
// these together inside ONE transaction via runTransaction() — nonce,
// idempotency, transfer, receipt, and audit can never partially diverge
// (a persistence or audit failure rolls back everything; fail closed).
//
// SYNTHETIC / PUBLIC SANDBOX ONLY: in-memory, no production data, no network.
//
// PORTING NOTE (private repo → Convex):
//   * Every collection below maps 1:1 to a Convex table:
//       orgMappings       → lawshieldOrgMappings     (unique index on armaOrgId)
//       caseMappings      → lawshieldCaseMappings    (unique index on [armaOrgId, incidentId])
//       authorizers       → lawshieldDisclosureAuthorizers (unique index on userId)
//       nonces            → lawshieldNonceRegistry   (UNIQUE(schemaVersion, nonce) — the
//                             authoritative multi-instance replay guard; insert inside the
//                             same transaction as acceptance so concurrent duplicate inserts
//                             fail the transaction and fail closed)
//       idempotency       → lawshieldIdempotencyRegistry (UNIQUE(schemaVersion, idempotencyKey),
//                             first-writer-wins inside the acceptance transaction)
//       transfers         → lawshieldTransfers       (unique transferId; index on idempotencyKey)
//       receipts          → lawshieldReceipts        (unique receiptId + transferId)
//       audit             → lawshieldAuditEvents     (append-only; no update/delete actions)
//   * runTransaction(fn) here (snapshot + rollback, synchronous fn) ports to a
//     single Convex mutation (or transaction) that inserts the nonce, binds the
//     idempotency key, upserts the transfer, writes the receipt, and appends
//     the audit events atomically. Convex serializes mutations per document,
//     which provides the same all-or-nothing guarantee this sandbox fakes.
//   * failPoints is a TEST-ONLY injection surface (see processor tests 12/13).
//     Production must never set fail points; the Convex port simply omits them.
//   * appendAudit sanitizes detail through a strict allowlist so payload
//     content can NEVER be written to the audit trail (structural guarantee,
//     not a convention). Keep the identical allowlist in the Convex port.
import { MAX_CLOCK_SKEW_MS } from '../_integrationSecurity.js';

// Authoritative replay window: a nonce is remembered for twice the clock-skew
// tolerance (the gateway's signature freshness check already bounds staleness
// to MAX_CLOCK_SKEW_MS; the registry must cover the full acceptance window).
export const NONCE_VALIDITY_WINDOW_MS = 2 * MAX_CLOCK_SKEW_MS;

// Audit detail keys that may EVER be written: identifiers, hashes, codes,
// field NAMES and counts only. Anything else is silently dropped — payload
// content is structurally unable to reach the audit log.
export const SAFE_DETAIL_KEYS = new Set([
  'code', 'receiptId', 'payloadHash', 'schemaVersion', 'idempotencyKey', 'transferId',
  'recordType', 'recordId', 'incidentId', 'lawShieldCaseId', 'armaOrgId', 'lawShieldOrgId',
  'minimumNecessaryFields', 'redactedFields', 'violationPaths', 'fieldNames', 'nonce',
  'status', 'outcome', 'result', 'gatewayStatus', 'processorStatus', 'eventCount',
  'eventTypes', 'duplicateDelivery', 'quarantined', 'source', 'at', 'windowMs',
  'firstSeenTransferId', 'existingTransferId', 'authorizedBy', 'processingResult',
]);
const SAFE_DETAIL_STRING_MAX = 256;
const SAFE_DETAIL_ARRAY_MAX = 32;
const SAFE_DETAIL_ARRAY_ITEM_MAX = 128;

function sanitizeDetail(value, depth = 0) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.length > SAFE_DETAIL_STRING_MAX ? value.slice(0, SAFE_DETAIL_STRING_MAX) : value;
  if (depth >= 2) return null; // flat metadata only
  if (Array.isArray(value)) {
    const out = value.slice(0, SAFE_DETAIL_ARRAY_MAX).map((v) => (
      typeof v === 'string' ? (v.length > SAFE_DETAIL_ARRAY_ITEM_MAX ? v.slice(0, SAFE_DETAIL_ARRAY_ITEM_MAX) : v) : null
    ));
    return out;
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [key, inner] of Object.entries(value)) {
      if (!SAFE_DETAIL_KEYS.has(key)) continue; // not allowlisted → dropped, never logged
      const clean = sanitizeDetail(inner, depth + 1);
      if (clean !== null) out[key] = clean;
    }
    return out;
  }
  return null;
}

// Snapshot / restore for all-or-nothing transactions (sandbox stand-in for a
// real database transaction; Convex provides this natively per mutation).
function snapshotState(store) {
  return structuredClone({
    orgMappings: store.orgMappings, caseMappings: store.caseMappings, authorizers: store.authorizers,
    nonces: store.nonces, idempotency: store.idempotency, transfers: store.transfers,
    transfersByIdempotency: store.transfersByIdempotency, receipts: store.receipts,
    audit: store.audit, auditSequence: store.auditSequence,
  });
}
function restoreState(store, snapshot) {
  store.orgMappings = snapshot.orgMappings; store.caseMappings = snapshot.caseMappings;
  store.authorizers = snapshot.authorizers; store.nonces = snapshot.nonces;
  store.idempotency = snapshot.idempotency; store.transfers = snapshot.transfers;
  store.transfersByIdempotency = snapshot.transfersByIdempotency; store.receipts = snapshot.receipts;
  store.audit = snapshot.audit; store.auditSequence = snapshot.auditSequence;
}

export class SyntheticDurableLawShieldStore {
  // failPoints: TEST-ONLY injection surface. Truthy value at a named point
  // (e.g. store.failPoints.persistTransfer = true) makes that write FAIL,
  // which rolls back the whole transaction (fail closed, never silent).
  constructor({ failPoints = {} } = {}) {
    this.orgMappings = new Map();          // armaOrgId -> { armaOrgId, lawShieldOrgId, active, ... }
    this.caseMappings = new Map();         // `${armaOrgId}::${incidentId}` -> { ..., lawShieldOrgId, lawShieldCaseId, active }
    this.authorizers = new Map();          // userId -> { userId, armaOrgId, active } (synthetic disclosure authorizers)
    this.nonces = new Map();               // `${schemaVersion}::${nonce}` -> { schemaVersion, nonce, transferId, seenAt, windowMs }
    this.idempotency = new Map();          // `${schemaVersion}::${idempotencyKey}` -> binding
    this.transfers = new Map();            // transferId -> durable transfer record (NO payload content)
    this.transfersByIdempotency = new Map(); // `${schemaVersion}::${idempotencyKey}` -> transferId
    this.receipts = new Map();             // receiptId -> receipt record (created once, deterministic)
    this.audit = [];                       // append-only audit events (sanitized detail only)
    this.auditSequence = 0;
    this.failPoints = failPoints;
    this._txDepth = 0;
  }

  // All-or-nothing transaction. `fn` is synchronous; if it throws, EVERY
  // mutation made inside (nonce, idempotency, transfer, receipt, audit) is
  // rolled back — the processor then fails closed with a structured error.
  runTransaction(fn) {
    const snapshot = snapshotState(this);
    this._txDepth += 1;
    try {
      const result = fn();
      this._txDepth -= 1;
      return result;
    } catch (error) {
      this._txDepth -= 1;
      restoreState(this, snapshot);
      throw error;
    }
  }
  isInTransaction() { return this._txDepth > 0; }

  _triggerFailPoint(name) {
    const hook = this.failPoints?.[name];
    if (!hook) return;
    if (typeof hook === 'function') hook(name); // optional test side-effect (logging)
    const error = new Error(`FAILPOINT_${name}`);
    error.failPoint = name;
    throw error; // deterministic: presence of the fail point = the write fails
  }

  // --- org mappings (explicit ARMA org <-> Law Shield org; active required) ---
  upsertOrgMapping({ armaOrgId, lawShieldOrgId, createdByUserId }) {
    const existing = this.orgMappings.get(armaOrgId);
    const record = {
      armaOrgId, lawShieldOrgId, active: true,
      createdByUserId, createdAt: existing?.createdAt ?? Date.now(),
      updatedByUserId: createdByUserId, updatedAt: Date.now(),
    };
    this.orgMappings.set(armaOrgId, record);
    return record;
  }
  getOrgMapping(armaOrgId) { return this.orgMappings.get(armaOrgId) ?? null; }
  deactivateOrgMapping(armaOrgId) { const m = this.orgMappings.get(armaOrgId); if (m) { m.active = false; m.updatedAt = Date.now(); } }

  // --- case mappings (explicit incident <-> Law Shield case; active required) ---
  upsertCaseMapping({ armaOrgId, incidentId, lawShieldOrgId, lawShieldCaseId, createdByUserId }) {
    const key = `${armaOrgId}::${incidentId}`;
    const existing = this.caseMappings.get(key);
    const record = {
      armaOrgId, incidentId, lawShieldOrgId, lawShieldCaseId, active: true,
      createdByUserId, createdAt: existing?.createdAt ?? Date.now(),
      updatedByUserId: createdByUserId, updatedAt: Date.now(),
    };
    this.caseMappings.set(key, record);
    return record;
  }
  getCaseMapping(armaOrgId, incidentId) { return this.caseMappings.get(`${armaOrgId}::${incidentId}`) ?? null; }
  deactivateCaseMapping(armaOrgId, incidentId) { const m = this.caseMappings.get(`${armaOrgId}::${incidentId}`); if (m) { m.active = false; m.updatedAt = Date.now(); } }

  // --- synthetic disclosure authorizers (processor-side mirror of the ARMA
  // human-only authorizer role; defense in depth — the authoritative gate
  // lives on the ARMA side, the processor re-checks known authorizers) ---
  upsertAuthorizer({ userId, armaOrgId }) {
    const record = { userId, armaOrgId, active: true, createdAt: Date.now(), updatedAt: Date.now() };
    this.authorizers.set(userId, record);
    return record;
  }
  getAuthorizer(userId) { return this.authorizers.get(userId) ?? null; }
  deactivateAuthorizer(userId) { const a = this.authorizers.get(userId); if (a) { a.active = false; a.updatedAt = Date.now(); } }

  // --- authoritative nonce replay registry ---
  // Duplicate nonce within the validity window FAILS CLOSED (REPLAYED_NONCE).
  // The registration MUST run inside the same transaction as the acceptance
  // decision: that is what makes this registry authoritative (a crash between
  // "nonce seen" and "transfer accepted" is impossible — both commit or
  // neither does).
  registerNonce({ schemaVersion, nonce, transferId, at = Date.now(), windowMs = NONCE_VALIDITY_WINDOW_MS }) {
    if (!schemaVersion || typeof schemaVersion !== 'string') throw new Error('INVALID_NONCE_REGISTRY_INPUT');
    if (!nonce || typeof nonce !== 'string') throw new Error('INVALID_NONCE');
    if (!/^[A-Za-z0-9_-]{20,128}$/.test(nonce)) throw new Error('INVALID_NONCE'); // same format rule as the gateway
    const key = `${schemaVersion}::${nonce}`;
    // prune expired nonces (window elapsed → no longer replay-relevant)
    for (const [k, rec] of this.nonces) { if (at - rec.seenAt > (rec.windowMs ?? windowMs)) this.nonces.delete(k); }
    const existing = this.nonces.get(key);
    if (existing) {
      const error = new Error('REPLAYED_NONCE');
      error.firstSeenTransferId = existing.transferId ?? null;
      error.firstSeenAt = existing.seenAt;
      throw error;
    }
    const record = { schemaVersion, nonce, transferId: transferId ?? null, seenAt: at, windowMs };
    this.nonces.set(key, record);
    return record;
  }
  getNonceRecord({ schemaVersion, nonce }) { return this.nonces.get(`${schemaVersion}::${nonce}`) ?? null; }
  nonceCount() { return this.nonces.size; }

  // --- durable idempotency registry ---
  // resolve: null = first use; binding = EXACT duplicate (same transferId AND
  // payloadHash) → caller replays the stored deterministic result; anything
  // else with the same key = integrity conflict → FAIL CLOSED.
  resolveIdempotencyKey({ schemaVersion, idempotencyKey, transferId, payloadHash }) {
    const key = `${schemaVersion}::${idempotencyKey}`;
    const binding = this.idempotency.get(key);
    if (!binding) return null;
    if (binding.transferId !== transferId || binding.payloadHash !== payloadHash) {
      const error = new Error('IDEMPOTENCY_KEY_CONFLICT');
      error.existingTransferId = binding.transferId;
      error.existingPayloadHash = binding.payloadHash;
      error.outcome = binding.outcome;
      throw error;
    }
    return binding;
  }
  bindIdempotencyKey({ schemaVersion, idempotencyKey, transferId, payloadHash, outcome, receiptId = null, acceptedAt = null, errorCode = null }) {
    const key = `${schemaVersion}::${idempotencyKey}`;
    const existing = this.idempotency.get(key);
    if (existing) return existing; // first binding wins — never overwritten
    const binding = {
      schemaVersion, idempotencyKey, transferId, payloadHash,
      outcome, receiptId, acceptedAt, errorCode, boundAt: Date.now(),
    };
    this.idempotency.set(key, binding);
    this.transfersByIdempotency.set(key, transferId);
    return binding;
  }
  getIdempotencyBinding({ schemaVersion, idempotencyKey }) { return this.idempotency.get(`${schemaVersion}::${idempotencyKey}`) ?? null; }

  // --- durable transfer records (status: ACCEPTED | REJECTED | QUARANTINED).
  // NO payload content is ever stored — payloadHash only. The payload itself
  // never needs to persist on the processor side: the record IS the protocol
  // decision, and content retention would create an unnecessary PHI surface.
  createDurableTransfer({
    transferId, idempotencyKey, schemaVersion, armaOrgId, lawShieldOrgId,
    incidentId = null, lawShieldCaseId = null, recordType, recordId, authorizedBy,
    payloadHash, status, receiptId = null, acceptedAt = null, rejectedAt = null,
    quarantinedAt = null, lastErrorCode = null, minimumNecessaryFields = [],
  }) {
    this._triggerFailPoint('persistTransfer'); // TEST-ONLY injection point
    const existing = this.transfers.get(transferId);
    if (existing) {
      if (existing.payloadHash === payloadHash && existing.status === status) return existing; // idempotent re-create
      const error = new Error('TRANSFER_ALREADY_PROCESSED');
      error.existingStatus = existing.status;
      throw error;
    }
    const now = Date.now();
    const record = {
      transferId, idempotencyKey, schemaVersion, armaOrgId, lawShieldOrgId,
      incidentId, lawShieldCaseId, recordType, recordId, authorizedBy,
      payloadHash, status, receiptId, acceptedAt, rejectedAt, quarantinedAt,
      lastErrorCode, minimumNecessaryFields: [...minimumNecessaryFields],
      createdAt: now, updatedAt: now,
    };
    this.transfers.set(transferId, record);
    return record;
  }
  getDurableTransfer(transferId) { return this.transfers.get(transferId) ?? null; }
  getDurableTransferByIdempotencyKey({ schemaVersion, idempotencyKey }) {
    const transferId = this.transfersByIdempotency.get(`${schemaVersion}::${idempotencyKey}`);
    return transferId ? this.transfers.get(transferId) ?? null : null;
  }
  transferCount() { return this.transfers.size; }

  // --- receipt records (created ONCE per accepted transfer; duplicates return
  // the stored record so re-delivery is byte-for-byte deterministic) ---
  createReceiptRecord({ receiptId, transferId, idempotencyKey, payloadHash, acceptedAt, processingResult = 'PERSISTED' }) {
    this._triggerFailPoint('persistReceipt'); // TEST-ONLY injection point
    const existing = this.receipts.get(receiptId);
    if (existing) return existing; // generated once — never a second receipt
    const record = {
      receiptId, transferId, idempotencyKey, accepted: true, acceptedAt,
      processingResult, payloadHash, createdAt: Date.now(),
    };
    this.receipts.set(receiptId, record);
    return record;
  }
  getReceiptRecord(receiptId) { return this.receipts.get(receiptId) ?? null; }
  receiptCount() { return this.receipts.size; }

  // --- append-only audit (actor/source classification + outcome; sanitized
  // detail only; no update/delete APIs exist by design) ---
  appendAudit({ transferId = null, idempotencyKey = null, armaOrgId = null, lawShieldOrgId = null, eventType, actorType, source, outcome = null, detail = null }) {
    this._triggerFailPoint('auditWrite'); // TEST-ONLY injection point
    const event = {
      auditSequence: ++this.auditSequence,
      transferId, idempotencyKey, armaOrgId, lawShieldOrgId,
      eventType, actorType, source, outcome,
      detail: sanitizeDetail(detail),
      createdAt: Date.now(),
    };
    this.audit.push(event);
    return event;
  }
  getAuditEvents({ transferId = null } = {}) {
    return transferId ? this.audit.filter((e) => e.transferId === transferId) : [...this.audit];
  }
}

// Synthetic processor-side directory seeds (sandbox stand-ins for the ARMA
// org/case/authorizer directory replicated to Law Shield). Synthetic only.
export function seedSyntheticProcessorDirectory(store) {
  store.upsertOrgMapping({ armaOrgId: 'org-arma-1', lawShieldOrgId: 'ls-org-1', createdByUserId: 'user-commander-1' });
  store.upsertOrgMapping({ armaOrgId: 'org-arma-2', lawShieldOrgId: 'ls-org-2', createdByUserId: 'user-commander-2' });
  store.upsertCaseMapping({ armaOrgId: 'org-arma-1', incidentId: 'INC-1001', lawShieldOrgId: 'ls-org-1', lawShieldCaseId: 'LS-CASE-1', createdByUserId: 'user-commander-1' });
  store.upsertCaseMapping({ armaOrgId: 'org-arma-2', incidentId: 'INC-2001', lawShieldOrgId: 'ls-org-2', lawShieldCaseId: 'LS-CASE-2', createdByUserId: 'user-commander-2' });
  store.upsertAuthorizer({ userId: 'user-commander-1', armaOrgId: 'org-arma-1' });
  store.upsertAuthorizer({ userId: 'user-commander-2', armaOrgId: 'org-arma-2' });
  store.upsertAuthorizer({ userId: 'user-77', armaOrgId: 'org-arma-1' }); // synthetic fixture authorizer
  return store;
}
