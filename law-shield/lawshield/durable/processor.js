// Durable Law Shield processor for protocol arma-lawshield.v1 (Stop Point 3).
// ---------------------------------------------------------------------------
// This is the REAL processor behind the gateway (replacing the Stop Point 2
// test stub). The gateway has ALREADY verified the inbound request end-to-end
// (signature, nonce format, freshness, payload hash, envelope validity) before
// forwarding. The processor receives:
//   POST <processorUrl>
//     authorization: Bearer <token>            (service-to-service auth)
//     x-verified-arma-nonce                    (gateway-verified nonce)
//     x-verified-arma-content-sha256           (gateway-verified body hash)
//     x-integration-schema-version             (must match accepted value)
//     x-integration-transfer-id                (must match envelope)
//     body: the ORIGINAL raw envelope bytes
//
// The processor re-validates EVERYTHING defense-in-depth (never trusts the
// gateway blindly): Bearer auth, schema version, transfer-id header match,
// envelope re-validation with the CANONICAL validator, payload-hash recompute,
// AI-authorization denial, org/case mapping, minimum-necessary disclosure
// policy, then commits nonce registration + idempotency binding + transfer
// persistence + receipt creation + audit appends inside ONE transaction.
//
// Outcome model (deterministic, gateway-compatible):
//   ACCEPTED   → 200 { accepted:true, receiptId, transferId, acceptedAt, processingResult, payloadHash }
//   duplicate  → 200 SAME receipt (byte-identical fields; duplicate-safe)
//   REJECTED   → 200 { accepted:false, error:<CODE>, transferId, idempotencyKey }
//                    (gateway maps non-accepted to 502 PROCESSOR_REJECTED_TRANSFER + error passthrough)
//   kill switch / transport-level → 503 { accepted:false, error:'PROCESSOR_DISABLED' }
//
// Processor-owned error codes (added to the KNOWN set in gateway docs; never
// raw messages):
//   REPLAYED_NONCE, IDEMPOTENCY_KEY_CONFLICT, TRANSFER_ALREADY_PROCESSED,
//   ORG_MAPPING_MISSING, ORG_MAPPING_INACTIVE, ORG_MAPPING_MISMATCH,
//   CASE_MAPPING_MISSING, CASE_MAPPING_INACTIVE, CASE_MAPPING_MISMATCH,
//   AUTHORIZER_UNKNOWN, AUTHORIZER_INACTIVE, AUTHORIZER_ORG_MISMATCH,
//   MINIMUM_NECESSARY_VIOLATION, ALWAYS_REDACTED_FIELD_PRESENT,
//   PROCESSOR_AUTH_FAILED, PROCESSOR_NOT_CONFIGURED, PROCESSOR_DISABLED,
//   INVALID_JSON, PAYLOAD_TOO_LARGE, FAILPOINT_* (test-only injection)
//
// SYNTHETIC / PUBLIC SANDBOX ONLY — synthetic persistence, no production data.
//
// PORTING NOTE (private repo → Convex):
//   * The HTTP shape of this file ports to a Convex action (httpAction) that
//     wraps a single mutation carrying the entire decision transaction: nonce
//     insert (unique index) + idempotency insert (unique index) + transfer
//     upsert + receipt insert + audit inserts. Convex's serializable
//     transactions give the same all-or-nothing guarantee as runTransaction.
//   * processTransferRequest() is deliberately a pure function of (store,
//     request) — no ambient state — so the Convex mutation can call the same
//     decision logic. Keep it pure when porting.
//   * The kill switch reads LAW_SHIELD_PROCESSOR_DISABLED (env) — port to a
//     config table read; fail closed exactly like here.
import crypto from 'node:crypto';
import {
  INTEGRATION_SCHEMA_VERSION, MAX_BODY_BYTES, validateEnvelope, sha256Hex,
} from '../_integrationSecurity.js';
import { MINIMUM_NECESSARY_POLICY, ALWAYS_REDACTED } from '../../arma/redaction.js';
import { SyntheticDurableLawShieldStore, NONCE_VALIDITY_WINDOW_MS, seedSyntheticProcessorDirectory } from './store.js';

const PROCESSOR_DISABLED_DEFAULT = 'false';

export function processorDisabled() {
  return String(process.env.LAW_SHIELD_PROCESSOR_DISABLED ?? PROCESSOR_DISABLED_DEFAULT).toLowerCase() === 'true';
}

function processorToken() { return process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN ?? null; }

function timingSafeEqualString(expected, actual) {
  if (typeof expected !== 'string' || typeof actual !== 'string' || expected.length !== actual.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual)); } catch { return false; }
}

function sendJson(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

async function readRawBody(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error('PAYLOAD_TOO_LARGE');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// Minimum-necessary disclosure policy enforcement (processor-side defense in
// depth). The ARMA side redacts before sending; the processor REFUSES any
// payload that did not already arrive redacted: no ALWAYS_REDACTED field may
// be present anywhere, and every data-bearing key must be in the record
// type's allow-list. The REAL wire contract (verified in
// arma/transferService.js) is a FLAT redacted payload: the redactor output
// (payloadEnvelope.data) IS the envelope payload — no wrapper. The processor
// therefore treats 'data' (and other unlisted keys) as non-minimum-necessary
// violations and fails closed. Returns { minimumNecessaryFields } or throws
// structured codes. Field NAMES are collected for audit — never content.
export function enforceDisclosurePolicy({ recordType, payload }) {
  const policy = MINIMUM_NECESSARY_POLICY[recordType];
  if (!policy) throw new Error('RECORD_TYPE_NOT_ALLOWED');
  const allowed = new Set(policy.fields);
  const always = new Set(ALWAYS_REDACTED.map((f) => f.toLowerCase()));
  const minimumNecessaryFields = [];
  const violationPaths = [];

  const checkEntry = (entry, pathPrefix) => {
    for (const [key, value] of Object.entries(entry)) {
      const path = pathPrefix ? `${pathPrefix}.${key}` : key;
      if (always.has(key.toLowerCase())) { violationPaths.push(`${path} (always-redacted)`); continue; }
      if (!allowed.has(key)) { violationPaths.push(`${path} (not in minimum-necessary allow-list)`); continue; }
      minimumNecessaryFields.push(path);
      if (value && typeof value === 'object' && !Array.isArray(value)) checkEntry(value, path);
      else if (Array.isArray(value)) {
        for (const item of value) {
          if (item && typeof item === 'object' && !Array.isArray(item)) checkEntry(item, path);
        }
      }
    }
  };
  checkEntry(payload, '');
  if (violationPaths.length > 0) {
    const alwaysViolation = violationPaths.find((p) => p.includes('always-redacted'));
    const error = new Error(alwaysViolation ? 'ALWAYS_REDACTED_FIELD_PRESENT' : 'MINIMUM_NECESSARY_VIOLATION');
    error.violationPaths = violationPaths;
    throw error;
  }
  return { minimumNecessaryFields };
}

// Authorizer check (processor-side mirror of the ARMA human-only gate).
// The ARMA directory is authoritative for human identity; the processor keeps
// a replicated synthetic authorizer directory and fails closed on unknown /
// inactive / wrong-org authorizers. AI actors were already denied by
// validateEnvelope (defense in depth both sides).
export function checkProcessorAuthorizer(store, envelope) {
  const authorizer = store.getAuthorizer(envelope.authorizedBy);
  if (!authorizer) throw structured('AUTHORIZER_UNKNOWN', { authorizedBy: envelope.authorizedBy });
  if (!authorizer.active) throw structured('AUTHORIZER_INACTIVE', { authorizedBy: envelope.authorizedBy });
  if (authorizer.armaOrgId !== envelope.armaOrgId) throw structured('AUTHORIZER_ORG_MISMATCH', { authorizedBy: envelope.authorizedBy });
  return authorizer;
}

// Mapping checks: explicit ARMA org↔Law Shield org mapping, active required;
// incident-scoped transfers require an active case mapping to the SAME
// Law Shield org (cross-tenant block — identical rule to the ARMA side).
export function checkProcessorMappings(store, envelope) {
  const orgMapping = store.getOrgMapping(envelope.armaOrgId);
  if (!orgMapping) throw structured('ORG_MAPPING_MISSING', { armaOrgId: envelope.armaOrgId });
  if (!orgMapping.active) throw structured('ORG_MAPPING_INACTIVE', { armaOrgId: envelope.armaOrgId });
  if (orgMapping.lawShieldOrgId !== envelope.lawShieldOrgId) {
    throw structured('ORG_MAPPING_MISMATCH', {
      armaOrgId: envelope.armaOrgId, expected: orgMapping.lawShieldOrgId, actual: envelope.lawShieldOrgId,
    });
  }
  const caseId = envelope.mapping?.lawShieldCaseId ?? null;
  if (envelope.incidentId) {
    const caseMapping = store.getCaseMapping(envelope.armaOrgId, envelope.incidentId);
    if (!caseMapping) throw structured('CASE_MAPPING_MISSING', { incidentId: envelope.incidentId });
    if (!caseMapping.active) throw structured('CASE_MAPPING_INACTIVE', { incidentId: envelope.incidentId });
    if (caseMapping.lawShieldOrgId !== envelope.lawShieldOrgId) {
      throw structured('CASE_MAPPING_MISMATCH', {
        incidentId: envelope.incidentId, expected: caseMapping.lawShieldOrgId, actual: envelope.lawShieldOrgId,
      });
    }
    if (caseId && caseMapping.lawShieldCaseId !== caseId) {
      throw structured('CASE_MAPPING_MISMATCH', {
        incidentId: envelope.incidentId, expected: caseMapping.lawShieldCaseId, actual: caseId,
      });
    }
  }
  return { orgMapping, caseMapping: envelope.incidentId ? store.getCaseMapping(envelope.armaOrgId, envelope.incidentId) : null };
}

function structured(code, detail) {
  const error = new Error(code);
  error.detail = detail ?? null;
  return error;
}

// ---------------------------------------------------------------------------
// processTransferRequest — THE decision function (pure: (store, request) →
// result; no ambient state). The HTTP wrapper and the future Convex mutation
// both call this. Every durable write happens inside exactly ONE
// runTransaction so nonce / idempotency / transfer / receipt / audit can
// never partially diverge (item 6: transaction-safe processing).
// ---------------------------------------------------------------------------
const NONCE_PATTERN = /^[A-Za-z0-9_-]{20,128}$/;

function result(kind, httpStatus, body, meta = {}) {
  return { kind, httpStatus, body, meta };
}

function receiptWireShape(receiptRecord) {
  return {
    accepted: true,
    receiptId: receiptRecord.receiptId,
    transferId: receiptRecord.transferId,
    acceptedAt: receiptRecord.acceptedAt,
    processingResult: receiptRecord.processingResult,
    payloadHash: receiptRecord.payloadHash,
  };
}

function rejectedWireShape({ error, transferId = null, idempotencyKey = null, quarantined = false, violationPaths = null }) {
  const body = { accepted: false, error, transferId, idempotencyKey };
  if (quarantined) body.quarantined = true;
  if (violationPaths) body.violationPaths = violationPaths; // field NAMES only, never content
  return body;
}

// Read gateway-forwarded verification headers (set by the gateway AFTER it
// verified the ARMA signature). The processor re-checks each one itself.
function readForwardedHeaders(headers) {
  const source = headers && typeof headers === 'object' ? headers : {}; // missing/malformed → empty → fail closed
  const h = (name) => {
    const value = source[name.toLowerCase()] ?? source[name] ?? null;
    return typeof value === 'string' ? value : (Array.isArray(value) ? String(value[0] ?? '') : null);
  };
  return {
    nonce: h('x-verified-arma-nonce'),
    contentSha256: h('x-verified-arma-content-sha256'),
    schemaVersion: h('x-integration-schema-version'),
    transferId: h('x-integration-transfer-id'),
  };
}

export function processTransferRequest({ store, rawBody, headers, now = Date.now() }) {
  if (processorDisabled()) throw new Error('PROCESSOR_DISABLED');
  if (typeof rawBody !== 'string' || rawBody.length === 0) return result('ERROR', 400, rejectedWireShape({ error: 'INVALID_JSON' }));
  const forwarded = readForwardedHeaders(headers);
  if (!forwarded.nonce || !NONCE_PATTERN.test(forwarded.nonce)) return result('ERROR', 400, rejectedWireShape({ error: 'INVALID_NONCE' }));
  if (!forwarded.contentSha256 || !/^[a-f0-9]{64}$/i.test(forwarded.contentSha256)) return result('ERROR', 400, rejectedWireShape({ error: 'INVALID_CONTENT_HASH' }));
  if (forwarded.schemaVersion !== INTEGRATION_SCHEMA_VERSION) return result('ERROR', 422, rejectedWireShape({ error: 'SCHEMA_VERSION_UNSUPPORTED' }));

  let envelope;
  try { envelope = JSON.parse(rawBody); } catch { return result('ERROR', 400, rejectedWireShape({ error: 'INVALID_JSON' })); }

  // Canonical re-validation (defense in depth — the gateway already ran this):
  // required fields, system route, record type, AI-authorizer denial, mapping
  // shape, timestamps, expiry, payload-hash recompute, injection screening.
  try { validateEnvelope(envelope); } catch (error) {
    bestEffortAudit(store, {
      transferId: typeof envelope?.transferId === 'string' ? envelope.transferId : null,
      idempotencyKey: typeof envelope?.idempotencyKey === 'string' ? envelope.idempotencyKey : null,
      eventType: 'TRANSFER_ENVELOPE_REJECTED', outcome: 'REJECTED',
      detail: { code: error instanceof Error ? error.message : 'INVALID_ENVELOPE', schemaVersion: forwarded.schemaVersion },
    });
    return result('REJECTED', 200, rejectedWireShape({
      error: error instanceof Error ? error.message : 'INVALID_ENVELOPE',
      transferId: typeof envelope?.transferId === 'string' ? envelope.transferId : null,
      idempotencyKey: typeof envelope?.idempotencyKey === 'string' ? envelope.idempotencyKey : null,
    }));
  }

  // Header/envelope consistency: the forwarded transfer id must match the envelope.
  if (forwarded.transferId && forwarded.transferId !== envelope.transferId) {
    return result('ERROR', 400, rejectedWireShape({ error: 'PROCESSOR_TRANSFER_ID_MISMATCH', transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey }));
  }
  // Body-hash consistency: the forwarded content hash must equal the raw bytes received.
  if (sha256Hex(rawBody) !== forwarded.contentSha256) {
    return result('ERROR', 400, rejectedWireShape({ error: 'PROCESSOR_CONTENT_HASH_MISMATCH', transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey }));
  }
  // Validity window enforcement (item 1): a request whose send time is older
  // than the registry window is stale for durable processing.
  if (Math.abs(now - envelope.sentAt) > NONCE_VALIDITY_WINDOW_MS) {
    return result('REJECTED', 200, rejectedWireShape({ error: 'STALE_OR_FUTURE_REQUEST', transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey }));
  }

  // --- Authoritative nonce registry (pre-check; registration commits inside
  // the transaction). An already-seen nonce fails closed — never re-processes.
  const nonceRecord = store.getNonceRecord({ schemaVersion: envelope.schemaVersion, nonce: forwarded.nonce });
  if (nonceRecord) {
    store.runTransaction(() => {
      store.appendAudit({
        transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
        armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
        eventType: 'NONCE_REPLAY_REJECTED', actorType: 'GATEWAY', source: 'GATEWAY_FORWARD',
        outcome: 'REJECTED',
        detail: { code: 'REPLAYED_NONCE', nonce: forwarded.nonce, firstSeenTransferId: nonceRecord.transferId },
      });
    });
    return result('REJECTED', 200, rejectedWireShape({ error: 'REPLAYED_NONCE', transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey }));
  }

  // --- Idempotency registry resolution (pre-check read; binding commits
  // inside the transaction). Same key + exact same transfer & payload → the
  // SAME deterministic receipt; same key + different content → integrity
  // conflict, quarantined, fail closed.
  let binding = null;
  try {
    binding = store.resolveIdempotencyKey({
      schemaVersion: envelope.schemaVersion, idempotencyKey: envelope.idempotencyKey,
      transferId: envelope.transferId, payloadHash: envelope.payloadHash,
    });
  } catch (conflict) {
    return quarantineIntegrityConflict(store, envelope, forwarded, conflict);
  }
  if (binding) {
    // Exact duplicate delivery (fresh nonce, same idempotent content): collapse
    // to the stored deterministic result. NO second disclosure can be created.
    if (binding.outcome === 'ACCEPTED') {
      const receiptRecord = store.getReceiptRecord(binding.receiptId);
      if (!receiptRecord) {
        // Registry/receipt divergence is an integrity anomaly: fail closed.
        return quarantineIntegrityConflict(store, envelope, forwarded, new Error('IDEMPOTENCY_RECEIPT_DIVERGENCE'));
      }
      store.runTransaction(() => {
        store.registerNonce({ schemaVersion: envelope.schemaVersion, nonce: forwarded.nonce, transferId: envelope.transferId, at: now });
        store.appendAudit({
          transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
          armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
          eventType: 'DUPLICATE_DELIVERY_COLLAPSED', actorType: 'GATEWAY', source: 'GATEWAY_FORWARD',
          outcome: 'ACCEPTED',
          detail: { code: 'DUPLICATE_COLLAPSED_TO_STORED_RECEIPT', receiptId: binding.receiptId, duplicateDelivery: true, payloadHash: binding.payloadHash },
        });
      });
      return result('DUPLICATE', 200, receiptWireShape(receiptRecord), { duplicate: true, receiptId: binding.receiptId });
    }
    // Deterministic replay of a prior non-accepted outcome.
    store.runTransaction(() => {
      store.registerNonce({ schemaVersion: envelope.schemaVersion, nonce: forwarded.nonce, transferId: envelope.transferId, at: now });
      store.appendAudit({
        transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
        armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
        eventType: 'DUPLICATE_DELIVERY_COLLAPSED', actorType: 'GATEWAY', source: 'GATEWAY_FORWARD',
        outcome: binding.outcome,
        detail: { code: 'DUPLICATE_COLLAPSED_TO_STORED_OUTCOME', result: binding.outcome, duplicateDelivery: true },
      });
    });
    return result('DUPLICATE', 200, rejectedWireShape({ error: binding.errorCode, transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey }), { duplicate: true });
  }

  // --- First delivery of this idempotency key: business checks, then ONE
  // all-or-nothing transaction. Any check failure is recorded durably
  // (rejected or quarantined) with the nonce registration + audit.
  let businessError = null;
  let policyProof = null;
  try {
    checkProcessorAuthorizer(store, envelope);
    checkProcessorMappings(store, envelope);
    policyProof = enforceDisclosurePolicy({ recordType: envelope.recordType, payload: envelope.payload });
  } catch (error) {
    businessError = error;
  }

  if (businessError) {
    const code = businessError instanceof Error ? businessError.message : 'PROCESSOR_REJECTED_TRANSFER';
    const quarantined = code === 'MINIMUM_NECESSARY_VIOLATION' || code === 'ALWAYS_REDACTED_FIELD_PRESENT' || code === 'IDEMPOTENCY_KEY_CONFLICT';
    try {
      store.runTransaction(() => {
        store.registerNonce({ schemaVersion: envelope.schemaVersion, nonce: forwarded.nonce, transferId: envelope.transferId, at: now });
        store.createDurableTransfer({
          transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey, schemaVersion: envelope.schemaVersion,
          armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
          incidentId: envelope.incidentId ?? null, lawShieldCaseId: envelope.mapping?.lawShieldCaseId ?? null,
          recordType: envelope.recordType, recordId: envelope.recordId, authorizedBy: envelope.authorizedBy,
          payloadHash: envelope.payloadHash, status: quarantined ? 'QUARANTINED' : 'REJECTED',
          quarantinedAt: quarantined ? now : null, rejectedAt: quarantined ? null : now,
          lastErrorCode: code,
          minimumNecessaryFields: policyProof?.minimumNecessaryFields ?? [],
        });
        store.bindIdempotencyKey({
          schemaVersion: envelope.schemaVersion, idempotencyKey: envelope.idempotencyKey,
          transferId: envelope.transferId, payloadHash: envelope.payloadHash,
          outcome: quarantined ? 'QUARANTINED' : 'REJECTED', errorCode: code,
        });
        store.appendAudit({
          transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
          armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
          eventType: quarantined ? 'TRANSFER_QUARANTINED' : 'TRANSFER_REJECTED',
          actorType: 'PROCESSOR', source: 'PROCESSOR_DECISION',
          outcome: quarantined ? 'QUARANTINED' : 'REJECTED',
          detail: { code, violationPaths: businessError.violationPaths ?? null, recordType: envelope.recordType, recordId: envelope.recordId },
        });
      });
    } catch (txError) {
      return persistenceFailure(store, envelope, forwarded, txError);
    }
    return result(quarantined ? 'QUARANTINED' : 'REJECTED', 200, rejectedWireShape({
      error: code, transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
      quarantined, violationPaths: businessError.violationPaths ?? null,
    }), { quarantined });
  }

  // --- ACCEPTANCE: nonce + transfer + receipt + idempotency + audit in ONE
  // transaction. A failure at ANY write rolls back EVERYTHING (fail closed).
  const receiptId = 'RCP-' + envelope.transferId;
  try {
    const created = store.runTransaction(() => {
      store.registerNonce({ schemaVersion: envelope.schemaVersion, nonce: forwarded.nonce, transferId: envelope.transferId, at: now });
      store.createDurableTransfer({
        transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey, schemaVersion: envelope.schemaVersion,
        armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
        incidentId: envelope.incidentId ?? null, lawShieldCaseId: envelope.mapping?.lawShieldCaseId ?? null,
        recordType: envelope.recordType, recordId: envelope.recordId, authorizedBy: envelope.authorizedBy,
        payloadHash: envelope.payloadHash, status: 'ACCEPTED', receiptId, acceptedAt: now,
        minimumNecessaryFields: policyProof.minimumNecessaryFields,
      });
      store.createReceiptRecord({
        receiptId, transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
        payloadHash: envelope.payloadHash, acceptedAt: now, processingResult: 'PERSISTED',
      });
      store.bindIdempotencyKey({
        schemaVersion: envelope.schemaVersion, idempotencyKey: envelope.idempotencyKey,
        transferId: envelope.transferId, payloadHash: envelope.payloadHash,
        outcome: 'ACCEPTED', receiptId, acceptedAt: now,
      });
      store.appendAudit({
        transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
        armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
        eventType: 'TRANSFER_ACCEPTED', actorType: 'PROCESSOR', source: 'PROCESSOR_DECISION',
        outcome: 'ACCEPTED',
        detail: { code: 'ACCEPTED', receiptId, payloadHash: envelope.payloadHash, processingResult: 'PERSISTED', minimumNecessaryFields: policyProof.minimumNecessaryFields },
      });
      return true;
    });
    if (!created) return persistenceFailure(store, envelope, forwarded, new Error('TRANSACTION_DID_NOT_COMMIT'));
    const receiptRecord = store.getReceiptRecord(receiptId);
    return result('ACCEPTED', 200, receiptWireShape(receiptRecord), { receiptId });
  } catch (txError) {
    return persistenceFailure(store, envelope, forwarded, txError);
  }
}

// Integrity conflict (same idempotency key, different transfer/payload): the
// attempt is quarantined for human review — never accepted, never collapsed.
// If the transferId already exists with a DIFFERENT payloadHash (same id
// reused for different content), the attempt is still quarantined and the
// ORIGINAL record is left untouched — no overwrite, no second disclosure.
function quarantineIntegrityConflict(store, envelope, forwarded, conflict) {
  const code = conflict instanceof Error ? conflict.message : 'IDEMPOTENCY_KEY_CONFLICT';
  const existing = conflict?.existingTransferId ?? null;
  const payloadConflictKey = `CONFLICT-${envelope.transferId}`;
  try {
    store.runTransaction(() => {
      store.registerNonce({ schemaVersion: envelope.schemaVersion, nonce: forwarded.nonce, transferId: envelope.transferId, at: Date.now() });
      const prior = store.getDurableTransfer(envelope.transferId);
      if (prior && prior.payloadHash !== envelope.payloadHash) {
        // Same transferId re-delivered with different content: audit the
        // conflict; the prior durable record stays authoritative.
        store.appendAudit({
          transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey,
          armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
          eventType: 'TRANSFER_QUARANTINED', actorType: 'PROCESSOR', source: 'PROCESSOR_DECISION',
          outcome: 'QUARANTINED',
          detail: { code: 'TRANSFER_CONTENT_CONFLICT', existingTransferId: prior.transferId, payloadHash: envelope.payloadHash },
        });
        return;
      }
      store.createDurableTransfer({
        transferId: payloadConflictKey, idempotencyKey: envelope.idempotencyKey, schemaVersion: envelope.schemaVersion,
        armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
        incidentId: envelope.incidentId ?? null, lawShieldCaseId: envelope.mapping?.lawShieldCaseId ?? null,
        recordType: envelope.recordType, recordId: envelope.recordId, authorizedBy: envelope.authorizedBy,
        payloadHash: envelope.payloadHash, status: 'QUARANTINED', quarantinedAt: Date.now(),
        lastErrorCode: code,
      });
      store.appendAudit({
        transferId: payloadConflictKey, idempotencyKey: envelope.idempotencyKey,
        armaOrgId: envelope.armaOrgId, lawShieldOrgId: envelope.lawShieldOrgId,
        eventType: 'TRANSFER_QUARANTINED', actorType: 'PROCESSOR', source: 'PROCESSOR_DECISION',
        outcome: 'QUARANTINED',
        detail: { code, existingTransferId: existing, payloadHash: envelope.payloadHash },
      });
    });
  } catch (txError) {
    return persistenceFailure(store, envelope, forwarded, txError);
  }
  return result('QUARANTINED', 200, rejectedWireShape({
    error: code, transferId: envelope.transferId, idempotencyKey: envelope.idempotencyKey, quarantined: true,
  }), { quarantined: true });
}

// Transaction failure (incl. TEST-ONLY fail points): everything rolled back,
// nothing accepted, nothing silently persisted. Best-effort failure audit in
// a SEPARATE transaction (never masks the error response).
function persistenceFailure(store, envelope, forwarded, txError) {
  const rawCode = txError instanceof Error ? txError.message : String(txError ?? '');
  const code = /^FAILPOINT_/.test(rawCode) ? 'PROCESSOR_PERSISTENCE_FAILED' : (KNOWN_PROCESSOR_FAILURES.has(rawCode) ? rawCode : 'PROCESSOR_PERSISTENCE_FAILED');
  try {
    store.runTransaction(() => {
      store.appendAudit({
        transferId: envelope?.transferId ?? null, idempotencyKey: envelope?.idempotencyKey ?? null,
        armaOrgId: envelope?.armaOrgId ?? null, lawShieldOrgId: envelope?.lawShieldOrgId ?? null,
        eventType: 'PROCESSOR_TRANSACTION_FAILED', actorType: 'PROCESSOR', source: 'PROCESSOR_DECISION',
        outcome: 'FAILED',
        detail: { code, nonce: forwarded?.nonce ?? null, payloadHash: envelope?.payloadHash ?? null },
      });
    });
  } catch { /* audit unavailable — the failure response itself is the record; NEVER accept silently */ }
  return result('ERROR', 500, rejectedWireShape({ error: code, transferId: envelope?.transferId ?? null, idempotencyKey: envelope?.idempotencyKey ?? null }));
}

const KNOWN_PROCESSOR_FAILURES = new Set(['TRANSFER_ALREADY_PROCESSED', 'IDEMPOTENCY_RECEIPT_DIVERGENCE']);

// Best-effort audit for pre-envelope-validation failures (nothing durable can
// be trusted yet — identifiers only if well-formed strings, never content).
function bestEffortAudit(store, partial) {
  try {
    store.runTransaction(() => {
      store.appendAudit({
        transferId: partial.transferId, idempotencyKey: partial.idempotencyKey,
        eventType: partial.eventType, actorType: 'GATEWAY', source: 'GATEWAY_FORWARD',
        outcome: partial.outcome, detail: partial.detail,
      });
    });
  } catch { /* never mask the rejection with an audit failure */ }
}

// ---------------------------------------------------------------------------
// Status / reconciliation inquiry (item 10). The ARMA side queries ACTUAL
// durable upstream state after an ambiguous outcome (accepted-but-response-
// lost, timeout, receipt mismatch) instead of guessing. Lookup by transferId
// and/or idempotencyKey. Authenticated the same way as /process (Bearer).
// Quarantined state is exposed for human review; the ARMA-side resolution
// flow (human RESOLVED/QUARANTINED) then proceeds on the ARMA side, and the
// processor accepts the outcome via the duplicate-collapse path (the same
// idempotencyKey must be reused so no second disclosure is created).
// ---------------------------------------------------------------------------
export function buildStatusResponse({ store, transferId = null, idempotencyKey = null, schemaVersion = INTEGRATION_SCHEMA_VERSION }) {
  const scrub = (record) => {
    if (!record) return null;
    const { minimumNecessaryFields, ...rest } = record;
    return { ...rest, minimumNecessaryFieldCount: minimumNecessaryFields?.length ?? 0 };
  };
  const transfer = transferId
    ? store.getDurableTransfer(transferId)
    : store.getDurableTransferByIdempotencyKey({ schemaVersion, idempotencyKey });
  if (!transfer) return { status: 404, body: { found: false, transferId: transferId ?? null, idempotencyKey: idempotencyKey ?? null, error: 'TRANSFER_NOT_FOUND' } };
  const binding = store.getIdempotencyBinding({ schemaVersion, idempotencyKey: transfer.idempotencyKey });
  const receipt = transfer.receiptId ? store.getReceiptRecord(transfer.receiptId) : null;
  const audit = store.getAuditEvents({ transferId: transfer.transferId }).map((e) => ({
    auditSequence: e.auditSequence, eventType: e.eventType, actorType: e.actorType, source: e.source, outcome: e.outcome, createdAt: e.createdAt,
  }));
  return {
    status: 200,
    body: {
      found: true,
      transferId: transfer.transferId,
      idempotencyKey: transfer.idempotencyKey,
      schemaVersion: transfer.schemaVersion,
      status: transfer.status,
      receiptId: transfer.receiptId,
      acceptedAt: transfer.acceptedAt ?? null,
      quarantinedAt: transfer.quarantinedAt ?? null,
      rejectedAt: transfer.rejectedAt ?? null,
      lastErrorCode: transfer.lastErrorCode ?? null,
      payloadHash: transfer.payloadHash,
      armaOrgId: transfer.armaOrgId,
      lawShieldOrgId: transfer.lawShieldOrgId,
      incidentId: transfer.incidentId ?? null,
      lawShieldCaseId: transfer.lawShieldCaseId ?? null,
      recordType: transfer.recordType,
      recordId: transfer.recordId,
      idempotency: binding ? { outcome: binding.outcome, receiptId: binding.receiptId, acceptedAt: binding.acceptedAt, errorCode: binding.errorCode } : null,
      receipt: receipt ? { receiptId: receipt.receiptId, acceptedAt: receipt.acceptedAt, processingResult: receipt.processingResult, payloadHash: receipt.payloadHash } : null,
      auditEvents: audit,
      auditEventCount: audit.length,
    },
  };
}

// ---------------------------------------------------------------------------
// HTTP handler (sandbox stand-in for a Convex httpAction). The gateway POSTs
// /process; ARMA reconciliation queries GET /status?transferId=... or
// ?idempotencyKey=... Both require the Bearer token (fail closed without it).
// ---------------------------------------------------------------------------
export function createDurableProcessorServer({ store = new SyntheticDurableLawShieldStore(), token = null, now = Date.now } = {}) {
  const bearer = () => token ?? processorToken();
  const authorized = (req) => {
    const expected = bearer();
    if (!expected) return false; // unconfigured token → fail closed
    const provided = String(req.headers.authorization ?? '');
    const prefix = 'Bearer ';
    if (!provided.startsWith(prefix)) return false;
    return timingSafeEqualString(expected, provided.slice(prefix.length));
  };

  return async function durableProcessorHandler(req, res) {
    // Kill switch FIRST — nothing (not even status) is served while disabled.
    if (processorDisabled()) {
      return sendJson(res, 503, { accepted: false, error: 'PROCESSOR_DISABLED' });
    }
    if (req.method === 'POST' && (req.url === '/process' || req.url === '/')) {
      if (!authorized(req)) return sendJson(res, 401, { accepted: false, error: 'PROCESSOR_AUTH_FAILED' });
      let rawBody;
      try { rawBody = await readRawBody(req); } catch (error) {
        return sendJson(res, error?.message === 'PAYLOAD_TOO_LARGE' ? 413 : 400, { accepted: false, error: error?.message ?? 'INVALID_JSON' });
      }
      let outcome;
      try {
        outcome = processTransferRequest({ store, rawBody, headers: req.headers, now: now() });
      } catch (error) {
        // processTransferRequest is expected to return structured outcomes; a
        // throw here is a processor-fault condition: fail closed 503, generic
        // code, never echo raw messages.
        return sendJson(res, 503, { accepted: false, error: 'PROCESSOR_UNAVAILABLE', transferId: null, idempotencyKey: null });
      }
      return sendJson(res, outcome.httpStatus, outcome.body);
    }
    if (req.method === 'GET' && (req.url === '/status' || req.url.startsWith('/status?'))) {
      if (!authorized(req)) return sendJson(res, 401, { accepted: false, error: 'PROCESSOR_AUTH_FAILED' });
      const url = new URL(req.url, 'http://processor.internal');
      const transferId = url.searchParams.get('transferId');
      const idempotencyKey = url.searchParams.get('idempotencyKey');
      const schemaVersion = url.searchParams.get('schemaVersion') ?? INTEGRATION_SCHEMA_VERSION;
      if (!transferId && !idempotencyKey) {
        return sendJson(res, 400, { accepted: false, error: 'STATUS_LOOKUP_CRITERIA_REQUIRED' });
      }
      if (schemaVersion !== INTEGRATION_SCHEMA_VERSION) {
        return sendJson(res, 422, { accepted: false, error: 'SCHEMA_VERSION_UNSUPPORTED' });
      }
      const { status, body } = buildStatusResponse({ store, transferId, idempotencyKey, schemaVersion });
      return sendJson(res, status, body);
    }
    return sendJson(res, 404, { accepted: false, error: 'NOT_FOUND' });
  };
}

export { SyntheticDurableLawShieldStore, seedSyntheticProcessorDirectory, NONCE_VALIDITY_WINDOW_MS };
