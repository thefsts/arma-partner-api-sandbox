// ARMA-side transfer envelope builder for protocol arma-lawshield.v1.
// PARITY RULE: this builder must produce envelopes the Law Shield gateway
// (lawshield/_integrationSecurity.js validateEnvelope) accepts verbatim. To
// guarantee that, the builder imports the canonical validator and runs it
// locally BEFORE anything leaves ARMA — fail inside ARMA, never on the wire.
// The builder is deliberately the only place ARMA constructs outbound payloads.
import {
  INTEGRATION_SCHEMA_VERSION,
  ALLOWED_RECORD_TYPES,
  validateEnvelope,
  sha256Hex,
  assertPayloadSafe,
} from '../lawshield/_integrationSecurity.js';

// Payload hash MUST match the gateway's rule exactly: sha256 over
// JSON.stringify(payload) — key order matters downstream, so callers must
// treat the payload object as immutable after this point.
export function buildPayloadHash(payload) {
  return sha256Hex(JSON.stringify(payload));
}

function finiteNumberOrThrow(value, code) {
  if (!Number.isFinite(value)) throw new Error(code);
  return value;
}

// Build a protocol envelope from ARMA-side inputs. Throws structured Error
// codes identical to the gateway's so local failures are self-explanatory.
// Required inputs: transferId, idempotencyKey, armaOrgId, lawShieldOrgId,
// recordType, recordId, authorizedBy (HUMAN userId, enforced by the
// authorizationGuard BEFORE this builder runs; re-checked defensively),
// authorizationReason, mapping source, payload (already redacted).
export function buildEnvelope({
  transferId,
  idempotencyKey,
  armaOrgId,
  lawShieldOrgId,
  recordType,
  recordId,
  authorizedBy,
  authorizationReason,
  incidentId = null,
  lawShieldCaseId = null,
  disclosurePurpose = null,
  payload,
  createdAt,
  sentAt,
  expiresAt,
}) {
  for (const [name, value] of [
    ['transferId', transferId], ['idempotencyKey', idempotencyKey],
    ['armaOrgId', armaOrgId], ['lawShieldOrgId', lawShieldOrgId],
    ['recordType', recordType], ['recordId', recordId],
    ['authorizedBy', authorizedBy], ['authorizationReason', authorizationReason],
  ]) {
    if (typeof value !== 'string' || !value.trim()) throw new Error(`INVALID_FIELD_${name}`);
  }
  if (!ALLOWED_RECORD_TYPES.has(recordType)) throw new Error('RECORD_TYPE_NOT_ALLOWED');
  // Defense in depth: the authorizationGuard is the authoritative human-only
  // gate, but the builder refuses to construct an envelope that would be
  // rejected at the perimeter anyway (identical rule, identical error code).
  if (authorizedBy.startsWith('AI:') || ['AI', 'JOY', 'ROSE'].includes(authorizedBy)) {
    throw new Error('AI_CANNOT_AUTHORIZE_TRANSFER');
  }
  const created = finiteNumberOrThrow(createdAt, 'INVALID_TIMESTAMPS');
  const sent = finiteNumberOrThrow(sentAt ?? createdAt, 'INVALID_TIMESTAMPS');
  const expires = finiteNumberOrThrow(expiresAt, 'INVALID_TIMESTAMPS');
  if (expires <= Date.now()) throw new Error('TRANSFER_EXPIRED');
  if (sent < created) throw new Error('INVALID_TIME_ORDER');
  if (payload === undefined || payload === null) throw new Error('PAYLOAD_REQUIRED');

  // Local prompt-injection / executable-instruction screen (same rules as the
  // gateway) — reject inside ARMA so offensive content never crosses the wire.
  assertPayloadSafe(payload);

  const mapping = { armaOrgId, lawShieldOrgId };
  if (lawShieldCaseId) mapping.lawShieldCaseId = lawShieldCaseId;

  const envelope = {
    schemaVersion: INTEGRATION_SCHEMA_VERSION,
    transferId,
    idempotencyKey,
    sourceSystem: 'ARMA_360',
    destinationSystem: 'LAW_SHIELD',
    armaOrgId,
    lawShieldOrgId,
    recordType,
    recordId,
    authorizedBy,
    authorizationReason,
    mapping,
  };
  if (incidentId) envelope.incidentId = incidentId;
  if (disclosurePurpose) envelope.disclosurePurpose = disclosurePurpose;
  envelope.createdAt = created;
  envelope.sentAt = sent;
  envelope.expiresAt = expires;
  envelope.payload = payload;
  envelope.payloadHash = buildPayloadHash(payload);

  // Full local validation with the CANONICAL gateway validator: if this
  // throws, ARMA never sends anything (fail before leaving ARMA).
  validateEnvelope(envelope);
  return envelope;
}

export { INTEGRATION_SCHEMA_VERSION, ALLOWED_RECORD_TYPES };
