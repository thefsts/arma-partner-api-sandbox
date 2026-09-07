// ARMA-side Law Shield receipt verification over RAW received bytes.
// NEVER re-serialize before hashing/signing verification — a re-serialized
// object can differ from the wire bytes (key order), silently invalidating the
// signature. This mirrors the gateway's raw-byte discipline on the ARMA side.
import crypto from 'node:crypto';
import { INTEGRATION_SCHEMA_VERSION, sha256Hex } from '../lawshield/_integrationSecurity.js';

function timingSafeEqualHex(expected, actual) {
  if (!expected || !actual || expected.length !== actual.length) return false;
  if (!/^[a-f0-9]+$/i.test(expected) || !/^[a-f0-9]+$/i.test(actual)) return false;
  try { return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex')); }
  catch { return false; }
}

// Verify an inbound Law Shield receipt. All inputs EXACTLY as received.
// `expected` = the transfer context ARMA actually sent (for field consistency).
export function verifyReceipt({ rawBody, headers, secret, expected }) {
  const h = (name) => headers[name.toLowerCase()] ?? headers[name] ?? null;
  const bodyHash = h('X-LawShield-Content-SHA256');
  const signature = h('X-LawShield-Signature');
  const schemaVersion = h('X-LawShield-Schema-Version');
  const receiptId = h('X-LawShield-Receipt-Id');
  if (!bodyHash || !signature || !schemaVersion || !receiptId) throw new Error('RECEIPT_HEADERS_MISSING');
  if (schemaVersion !== INTEGRATION_SCHEMA_VERSION) throw new Error('SCHEMA_VERSION_UNSUPPORTED');
  if (typeof rawBody !== 'string' || rawBody.length === 0) throw new Error('RECEIPT_EMPTY_BODY');
  if (!secret) throw new Error('ARMA_RECEIPT_VERIFIER_NOT_CONFIGURED');

  // 1) Hash + signature over RAW bytes exactly as received.
  const calculatedHash = sha256Hex(rawBody);
  if (!timingSafeEqualHex(calculatedHash, bodyHash)) throw new Error('RECEIPT_BODY_HASH_MISMATCH');
  const expectedSignature = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  if (!timingSafeEqualHex(expectedSignature, signature)) throw new Error('RECEIPT_INVALID_SIGNATURE');

  // 2) Parse only after cryptographic verification passed.
  let receipt; try { receipt = JSON.parse(rawBody); } catch { throw new Error('RECEIPT_INVALID_JSON'); }
  if (receipt.receiptId !== receiptId) throw new Error('RECEIPT_ID_MISMATCH');

  // 3) Field consistency with what ARMA actually sent.
  if (!receipt.transferId) throw new Error('RECEIPT_TRANSFER_ID_MISSING');
  if (expected?.transferId && receipt.transferId !== expected.transferId) throw new Error('RECEIPT_TRANSFER_ID_MISMATCH');
  if (expected?.idempotencyKey && receipt.idempotencyKey !== expected.idempotencyKey) throw new Error('RECEIPT_IDEMPOTENCY_MISMATCH');
  if (expected?.armaOrgId && receipt.armaOrgId !== expected.armaOrgId) throw new Error('RECEIPT_ORG_MISMATCH');
  if (expected?.lawShieldOrgId && receipt.lawShieldOrgId !== expected.lawShieldOrgId) throw new Error('RECEIPT_ORG_MISMATCH');
  if (receipt.status !== 'ACCEPTED') throw new Error('RECEIPT_STATUS_NOT_ACCEPTED');
  if (receipt.accepted !== true) throw new Error('RECEIPT_ACCEPTED_NOT_TRUE');
  if (expected?.payloadHash && receipt.receivedPayloadHash !== expected.payloadHash) throw new Error('RECEIPT_PAYLOAD_HASH_MISMATCH');
  if (expected?.recordType && receipt.recordType !== expected.recordType) throw new Error('RECEIPT_RECORD_TYPE_MISMATCH');
  if (expected?.recordId && receipt.recordId !== expected.recordId) throw new Error('RECEIPT_RECORD_ID_MISMATCH');
  if (!Number.isFinite(receipt.acceptedAt)) throw new Error('RECEIPT_ACCEPTED_AT_INVALID');

  return {
    receipt, bodyHash, signature, receiptId, schemaVersion,
    verifiedAt: Date.now(),
    // D1: both contract fields present on every verified receipt.
    contract: { status: receipt.status, accepted: receipt.accepted },
  };
}

// Classify a gateway failure response for ARMA-side state transitions.
// Returns { code, retryable, ambiguous, cleanRetryable, reconciliationRequired }.
//   ambiguous        = the processor was involved and the outcome is UNKNOWN;
//                      blind retry could duplicate an accepted disclosure —
//                      route to RECONCILIATION_REQUIRED instead of retry.
//   cleanRetryable   = failure occurred BEFORE processor involvement
//                      (connection-level) → safe to retry with a fresh nonce.
//   reconciliationRequired = gateway explicitly flagged the mismatch path (D2).
export function classifyGatewayFailure({ status, body }) {
  const code = body?.error ?? (status === 502 ? 'PROCESSOR_UNKNOWN' : 'GATEWAY_UNKNOWN');
  const retryable = body?.retryable === true;
  const reconciliationRequired = body?.reconciliationRequired === true;
  const ambiguousCodes = new Set(['PROCESSOR_RECEIPT_MISMATCH', 'PROCESSOR_TIMEOUT']);
  const cleanRetryableCodes = new Set(['PROCESSOR_UNAVAILABLE']);
  return {
    code, retryable, reconciliationRequired,
    ambiguous: ambiguousCodes.has(code),
    cleanRetryable: cleanRetryableCodes.has(code),
  };
}
