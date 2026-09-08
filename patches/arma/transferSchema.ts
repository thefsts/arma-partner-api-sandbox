// ARMA -> PATCHES transfer schema (Stop Point 5, sandbox reference).
//
// Convex-shaped schema for the ARMA side of the partner integration: what
// ARMA persists locally about its OUTBOUND partner operations. This is the
// durable backing store for the activation service state machine.
//
// DESIGN RULES (owner spec):
// - Opaque identifiers only; no PII (no emails, names, device serials,
//   subject references beyond opaque ids already used by PATCHES bindings).
// - NO credential secrets ANYWHERE. Credential rows reference keyId ONLY;
//   the secret lives in the platform KMS/secret store, never in Convex.
// - Audit/event rows are append-only; the client's redactForAudit output is
//   the only payload shape ever written.
// - Every table maps 1:1 to a Convex table (name + index definitions).
//
// PORTING NOTE (private PATCHES repo): convert each table below to a Convex
// table definition (defineTable({...}).index(...)); the field shapes are
// already Convex-compatible (id: v.string() etc. except where noted). The
// synthetic in-memory store used by the sandbox tests (patches/arma/armaStore.ts)
// implements the same accessors so the activation service is portable
// without touching persistence code.

// --- Table shapes (Convex table = { field: validator } + indexes) ---

export const ARMA_PARTNER_CONFIG_TABLE = 'arma_partner_config';
export interface ArmaPartnerConfig {
  configId: string;              // 'default' — singleton row
  clientId: string;              // PATCHES partner clientId (arma-client in the sandbox)
  activeKeyId: string;           // current signing keyId
  graceKeyIds: string[];         // still-valid keys during rotation overlap
  retiredKeyIds: string[];       // kept for audit reference only (never signs)
  receiptVerificationKeyRef: string; // reference to KMS-held receipt verification key
  baseUrl: string;               // PATCHES Partner API base URL
  outboundEnabled: boolean;      // local outbound kill switch (row-level)
  updatedAt: number;
}

export const ARMA_ORG_MAPPING_TABLE = 'arma_org_mapping';
export interface ArmaOrgMapping {
  mappingId: string;             // `${armaOrgId}::${patchesOrgId}`
  armaOrgId: string;             // opaque local org identifier
  patchesOrgId: string;          // PATCHES tenant orgId (ORG-ARMA-ALPHA etc.)
  status: 'ACTIVE' | 'PAUSED';
  createdAt: number;
}

export const ARMA_ENTITLEMENT_REF_TABLE = 'arma_entitlement_ref';
export interface ArmaEntitlementRef {
  refId: string;                 // `${patchesOrgId}::${capability}`
  patchesOrgId: string;
  capability: string;            // generic contract identifier (traffic_stop_privacy, ...)
  entitled: boolean;             // local preflight cache of PATCHES entitlement state
  lastCheckedAt: number;
  licensedUntil?: number;        // epoch ms, for preflight staleness checks
}

export const ARMA_CAPABILITY_REF_TABLE = 'arma_capability_ref';
export interface ArmaCapabilityRef {
  capability: string;            // primary key
  minApiVersion: string;
  maxApiVersion: string;
  description: string;
  syncedAt: number;              // last capabilities.list sync
}

export const ARMA_BINDING_TABLE = 'arma_bindings';
export interface ArmaBinding {
  bindingId: string;             // opaque PATCHES binding id (BIND-ALPHA-TSP etc.)
  patchesOrgId: string;
  capability: string;
  deviceId: string;              // opaque synthetic device identifier (no PII)
  subjectRef: string;            // opaque synthetic subject reference (no PII)
  status: 'ACTIVE' | 'INACTIVE';
  boundAt: number;
}

export const ARMA_ACTIVATION_TABLE = 'arma_activations';
export type ArmaActivationStatus =
  | 'PENDING' | 'READY_TO_ACTIVATE' | 'ACTIVATION_SENT' | 'RECEIPT_VERIFIED'
  | 'ACTIVE' | 'RECONCILIATION_REQUIRED' | 'DEACTIVATED' | 'REVOKED'
  | 'REJECTED' | 'QUARANTINED';
export interface ArmaActivationRecord {
  activationId: string;          // ARMA-local id: ARMA-ACT-<uuid>
  patchesActivationId?: string;  // ACT-<requestId> once known
  lastIntentRequestHint?: string; // ACT-<first create requestId> — stable identity for reconciliation before verification
  lastRequestId?: string;        // most recent outbound request id for this activation
  idempotencyKey: string;        // stable across retries/reconciliation (owner amendment)
  armaOrgId: string;
  patchesOrgId: string;
  capability: string;
  bindingId: string;             // opaque binding id (no PII)
  status: ArmaActivationStatus;
  lastAttemptAt?: number;
  firstVerifiedAt?: number;
  activatedAt?: number;          // PATCHES receipt 'at' when ACTIVE
  deactivatedAt?: number;
  revokedAt?: number;
  rejectedCode?: string;         // terminal classification error code
  quarantineReason?: string;     // why manual intervention is required
  createdAt: number;
  updatedAt: number;
}

export const ARMA_IDEMPOTENCY_TABLE = 'arma_idempotency';
export interface ArmaIdempotencyRecord {
  id: string;                    // `${idempotencyKey}` (globally unique per client)
  idempotencyKey: string;
  intentHash: string;            // sha256 of canonical activation intent
  patchesActivationId?: string;
  status: 'OPEN' | 'COLLAPSED' | 'CONFLICT';
  lastOutcome?: 'SUCCESS' | 'RECONCILE' | 'TERMINAL';
  createdAt: number;
  updatedAt: number;
}

export const ARMA_RECEIPT_TABLE = 'arma_receipts';
export interface ArmaReceiptRecord {
  receiptId: string;             // PATCHES receipt id (RCP-ACT-...)
  patchesActivationId?: string;
  requestId: string;             // client request id this receipt answers
  operation: string;             // activation.create / activation.deactivate / activation.revoke
  outcome: string;               // SUCCESS (only verified receipts are stored)
  clientId: string;
  verifiedAt: number;
  contentSha256: string;         // sha256 of the raw response bytes (evidence pointer)
  rawReceiptJson: string;        // sanitized receipt JSON (schema fields only — no secrets possible by contract)
}

export const ARMA_RETRY_TABLE = 'arma_retry_state';
export interface ArmaRetryRecord {
  retryId: string;               // `${activationId}::${operation}::${attempt}`
  activationId: string;          // ARMA-local activation id
  operation: OperationRef;
  attempt: number;
  attemptRecordJson: string;     // JSON.stringify(AttemptRecord) — secret-free by construction
  createdAt: number;
}
export type OperationRef = 'activation.create' | 'activation.status' | 'activation.deactivate' | 'activation.revoke';

export const ARMA_RECONCILIATION_TABLE = 'arma_reconciliation';
export interface ArmaReconciliationRecord {
  reconciliationId: string;      // `${activationId}::${n}`
  activationId: string;
  reason: string;                // ambiguous-failure reason (TIMEOUT, RESPONSE_LOST, ...)
  status: 'OPEN' | 'RESOLVED_ACTIVE' | 'RESOLVED_NOT_FOUND' | 'RESOLVED_TERMINAL' | 'BLOCKED';
  patchesActivationId?: string;  // identity used for the status query (identity hint or verified)
  statusQueryAttempt: number;
  resolution?: 'ACTIVE' | 'NOT_FOUND' | 'TERMINAL' | 'ACCESS_DENIED' | 'PENDING';
  resolutionDetail?: string;
  openedAt: number;
  resolvedAt?: number;
}

export const ARMA_AUDIT_TABLE = 'arma_audit_events';
export interface ArmaAuditEventRecord {
  sequence: number;              // append-only ordering
  at: number;
  actorKind: 'SYSTEM' | 'OPERATOR';
  activationId?: string;
  idempotencyKey?: string;
  operation: string;             // state-machine transitions + lifecycle ops
  outcome: 'SUCCESS' | 'REJECTED' | 'FAILED' | 'QUARANTINED' | 'CONFLICT' | 'BLOCKED';
  detail?: ArmaSafeDetail;       // allowlisted fields only
}
export interface ArmaSafeDetail {
  code?: string; requestId?: string; receiptId?: string; activationId?: string;
  bindingId?: string; capability?: string; orgId?: string; status?: string;
  failureClass?: string; failureReason?: string; errorCode?: string;
  idempotencyKey?: string; keyId?: string; nonce?: string; timestamp?: number;
  retryAfterMs?: number; attempt?: number; phase?: string; duplicate?: boolean;
  outcome?: string; operation?: string; reason?: string; resolution?: string;
  patchesActivationId?: string; quarantineReason?: string; httpStatus?: number;
}

export const ARMA_TABLES = [
  ARMA_PARTNER_CONFIG_TABLE, ARMA_ORG_MAPPING_TABLE, ARMA_ENTITLEMENT_REF_TABLE,
  ARMA_CAPABILITY_REF_TABLE, ARMA_BINDING_TABLE, ARMA_ACTIVATION_TABLE,
  ARMA_IDEMPOTENCY_TABLE, ARMA_RECEIPT_TABLE, ARMA_RETRY_TABLE,
  ARMA_RECONCILIATION_TABLE, ARMA_AUDIT_TABLE,
] as const;

// The ARMA-side tables never contain PII or secrets; a structural statement
// encoded here for the porting note and enforced by the store's serializers.
export const ARMA_NO_PII_NO_SECRET_FIELDS = 'ARMA tables hold only opaque ids, status, hashes, timestamps, and allowlisted audit detail; credential secrets live exclusively in the platform KMS/secret store (keyId references only).';

// Convex-shaped table descriptor (reference for the private repo port):
//   arma_partner_config:  (configId) + [clientId]
//   arma_org_mapping:     (mappingId) + [armaOrgId], [patchesOrgId]
//   arma_entitlement_ref: (refId) + [patchesOrgId], [patchesOrgId+capability]
//   arma_capability_ref:  (capability)
//   arma_bindings:        (bindingId) + [patchesOrgId], [patchesOrgId+capability]
//   arma_activations:     (activationId) + [idempotencyKey], [bindingId], [status], [armaOrgId]
//   arma_idempotency:     (id) + [idempotencyKey]
//   arma_receipts:        (receiptId) + [patchesActivationId], [requestId]
//   arma_retry_state:     (retryId) + [activationId], [activationId+operation]
//   arma_reconciliation:  (reconciliationId) + [activationId], [status]
//   arma_audit_events:    (sequence) + [activationId], [operation], [at]
