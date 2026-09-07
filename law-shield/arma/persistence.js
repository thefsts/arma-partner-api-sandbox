// ARMA-side synthetic persistence for the Law Shield transfer lane (sandbox only).
// Mirrors the table shapes in law-shield/arma/lawShieldTransferSchema.ts so the
// private ARMA repository can swap in real Convex without changing service logic.
// Everything here is in-memory and synthetic; no production data or connections.
export class SyntheticLawShieldStore {
  constructor() {
    this.orgMappings = new Map();        // key: armaOrgId -> { lawShieldOrgId, active, createdBy, createdAt, ... }
    this.caseMappings = new Map();       // key: `${armaOrgId}::${incidentId}` -> { lawShieldOrgId, lawShieldCaseId, active, ... }
    this.authorizations = new Map();     // key: transferId -> { ...policyDecision, minimumNecessaryFields, redactedFields }
    this.transfers = new Map();          // key: transferId -> outbound transfer record
    this.transfersByIdempotency = new Map(); // idempotencyKey -> transferId
    this.reconciliation = new Map();     // key: transferId -> reconciliation record
    this.audit = [];                     // append-only audit events
    this.sequence = 0;
  }

  // --- org mappings ---
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
  deactivateOrgMapping(armaOrgId) { const m = this.orgMappings.get(armaOrgId); if (m) m.active = false; }

  // --- case mappings ---
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

  // --- durable authorizations (human-only; guard enforced before storing) ---
  recordAuthorization({ transferId, armaOrgId, authorizedByUserId, authorizationReason, purposeOfDisclosure, phiCategories, minimumNecessaryFields, redactedFields, policyDecision, auditReference }) {
    const record = {
      transferId, armaOrgId, authorizedByUserId, authorizationReason,
      purposeOfDisclosure: purposeOfDisclosure ?? null,
      phiCategories: [...(phiCategories ?? [])],
      minimumNecessaryFields: [...(minimumNecessaryFields ?? [])],
      redactedFields: [...(redactedFields ?? [])],
      policyDecision, auditReference: auditReference ?? null, createdAt: Date.now(),
    };
    this.authorizations.set(transferId, record);
    return record;
  }
  getAuthorization(transferId) { return this.authorizations.get(transferId) ?? null; }

  // --- outbound transfers ---
  createTransfer({ transferId, idempotencyKey, armaOrgId, lawShieldOrgId, incidentId, lawShieldCaseId, recordType, recordId, payloadEnvelope, authorizedByUserId, authorizationReason, redactionProof = null }) {
    if (this.transfersByIdempotency.has(idempotencyKey)) {
      const existingId = this.transfersByIdempotency.get(idempotencyKey);
      const existing = this.transfers.get(existingId);
      const err = new Error('DUPLICATE_IDEMPOTENCY_KEY');
      err.existingTransferId = existingId;
      err.existingStatus = existing?.status;
      throw err;
    }
    const sequence = ++this.sequence;
    const record = {
      transferId, idempotencyKey, armaOrgId, lawShieldOrgId, incidentId,
      lawShieldCaseId: lawShieldCaseId ?? null, recordType, recordId,
      eventSequence: sequence, previousEventHash: null,
      payloadHash: null, // computed by transferService once payload finalized
      status: 'DRAFT', protocolVersion: 'arma-lawshield.v1',
      createdAt: Date.now(), approvedAt: null, sentAt: null, acceptedAt: null, rejectedAt: null,
      receiptId: null, receiptHash: null, lastErrorCode: null,
      retryCount: 0, nextRetryAt: null,
      payloadEnvelope: JSON.parse(JSON.stringify(payloadEnvelope)),
      redactionProof: redactionProof ? { minimumNecessaryFields: [...redactionProof.minimumNecessaryFields], redactedFields: [...redactionProof.redactedFields], phiCategories: [...(redactionProof.phiCategories ?? [])] } : null,
      authorizedByUserId: authorizedByUserId ?? null,
      authorizationReason: authorizationReason ?? null,
      updatedAt: Date.now(),
    };
    this.transfers.set(transferId, record);
    this.transfersByIdempotency.set(idempotencyKey, transferId);
    return record;
  }
  getTransfer(transferId) { return this.transfers.get(transferId) ?? null; }
  getTransferByIdempotencyKey(key) { const id = this.transfersByIdempotency.get(key); return id ? this.transfers.get(id) ?? null : null; }
  updateTransfer(transferId, patch) {
    const record = this.transfers.get(transferId);
    if (!record) throw new Error('TRANSFER_NOT_FOUND');
    Object.assign(record, patch, { updatedAt: Date.now() });
    return record;
  }

  // --- reconciliation ---
  openReconciliation({ transferId, expectedPayloadHash, expectedDestination, currentArmaState, discrepancyCode, reportedLawShieldState }) {
    const record = {
      transferId, expectedPayloadHash, expectedDestination,
      currentArmaState, reportedLawShieldState: reportedLawShieldState ?? null,
      discrepancyCode: discrepancyCode ?? null, lawShieldReceiptId: null, receiptHash: null,
      retryCount: 0, lastCheckedAt: Date.now(),
      resolutionStatus: 'OPEN', authorizedResolverUserId: null, resolutionNote: null, updatedAt: Date.now(),
    };
    this.reconciliation.set(transferId, record);
    return record;
  }
  getReconciliation(transferId) { return this.reconciliation.get(transferId) ?? null; }
  resolveReconciliation(transferId, { authorizedResolverUserId, resolutionNote, resolutionStatus = 'RESOLVED' }) {
    const record = this.reconciliation.get(transferId);
    if (!record) throw new Error('RECONCILIATION_NOT_FOUND');
    if (record.resolutionStatus === 'RESOLVED') throw new Error('RECONCILIATION_ALREADY_RESOLVED');
    Object.assign(record, { authorizedResolverUserId, resolutionNote, resolutionStatus, updatedAt: Date.now() });
    return record;
  }

  // --- audit (append-only; actorType HUMAN/SYSTEM/TRANSPORT; never store payload content) ---
  appendAudit({ transferId, armaOrgId, eventType, actorType, actorUserId, detail }) {
    const event = {
      transferId: transferId ?? null, armaOrgId: armaOrgId ?? null,
      eventType, actorType, actorUserId: actorUserId ?? null,
      detail: detail ?? null, createdAt: Date.now(),
    };
    this.audit.push(event);
    return event;
  }
  getAudit(transferId) { return this.audit.filter((e) => e.transferId === transferId); }
}

// Synthetic directory of authenticated ARMA users/orgs/roles (sandbox stand-in for
// Clerk-authenticated identity + ARMA RBAC). NEVER trust these values from partner input.
export class SyntheticIdentityDirectory {
  constructor() {
    this.users = new Map(); // userId -> { orgId, roles: Set, actorType }
  }
  addUser({ userId, orgId, roles = [], actorType = 'HUMAN' }) {
    this.users.set(userId, { userId, orgId, roles: new Set(roles), actorType });
    return this.users.get(userId);
  }
  getUser(userId) { return this.users.get(userId) ?? null; }
  isHuman(userId) { return this.users.get(userId)?.actorType === 'HUMAN'; }
  hasRole(userId, role) { return this.users.get(userId)?.roles.has(role) ?? false; }
  belongsToOrg(userId, orgId) { return this.users.get(userId)?.orgId === orgId; }
}

// Synthetic users used across the ARMA-side test suite (documented, synthetic-only).
export function seedSyntheticIdentities(directory) {
  directory.addUser({ userId: 'user-commander-1', orgId: 'org-arma-1', roles: ['ORG_COMMANDER', 'LAW_SHIELD_DISCLOSURE_AUTHORIZER'] });
  directory.addUser({ userId: 'user-officer-1', orgId: 'org-arma-1', roles: ['OFFICER'] });
  directory.addUser({ userId: 'user-commander-2', orgId: 'org-arma-2', roles: ['ORG_COMMANDER', 'LAW_SHIELD_DISCLOSURE_AUTHORIZER'] });
  directory.addUser({ userId: 'ai-engine-joy', orgId: 'org-arma-1', roles: [], actorType: 'AI' });
  directory.addUser({ userId: 'ai-engine-rose', orgId: 'org-arma-1', roles: [], actorType: 'AI' });
  return directory;
}
