// PATCHES Partner API v1 — signed receipts for state-changing operations.
//
// RECEIPT CONTRACT: every state-changing response body is a receipt and is
// signed over its RAW response bytes:
//   X-PATCHES-Receipt-Id:    <receiptId>
//   X-PATCHES-Content-SHA256: sha256(raw response bytes)
//   X-PATCHES-Signature:     hex(HMAC-SHA256(receiptSecret, raw bytes))
// This mirrors the arma-lawshield.v1 raw-byte receipt pattern: the partner
// verifies the signature over the exact bytes it received, so any in-flight
// mutation (truncation, field swap, status flip) breaks verification.
//
// PORTING NOTE (private PATCHES repo): the receipt secret lives in the
// platform's secret store (KMS boundary); signing happens at the response
// boundary, never inside business logic. Receipts persist durable state so
// a partner can re-verify an old receipt without replaying the operation.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const RECEIPT_SCHEMA_VERSION = 'patches-partner-v1';

export interface ReceiptBody {
  schemaVersion: string; // 'patches-partner-v1'
  receiptId: string;
  requestId: string;
  clientId: string;
  operation: string; // e.g. 'activation.create', 'activation.deactivate', 'activation.revoke'
  outcome: string; // 'SUCCESS' | 'CONFLICT' | 'REJECTED'
  at: number;
  activationId?: string;
  orgId?: string;
  capability?: string;
  payloadHash?: string;
  result?: unknown; // operation-specific result payload (already sanitized)
}

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

export function signReceiptBytes(rawBytes: Buffer, secret: string): { contentSha256: string; signature: string } {
  const contentSha256 = createHash('sha256').update(rawBytes).digest('hex');
  const signature = createHmac('sha256', secret).update(rawBytes).digest('hex');
  return { contentSha256, signature };
}

export interface VerifyReceiptInput {
  rawBody: Buffer;
  headers: Record<string, string | string[] | undefined>;
  secret: string;
  expected?: {
    receiptId?: string;
    requestId?: string;
    clientId?: string;
    operation?: string;
    outcome?: string;
    activationId?: string;
  };
}

export interface ReceiptVerification {
  verified: boolean;
  reason?: 'RECEIPT_MISSING_HEADERS' | 'RECEIPT_INVALID_SIGNATURE' | 'RECEIPT_CONTENT_HASH_MISMATCH' | 'RECEIPT_BODY_MALFORMED' | 'RECEIPT_FIELD_MISMATCH';
  receipt?: ReceiptBody;
}

// Verifies a receipt over RAW bytes — the partner-side check. `expected`
// fields bind the receipt to the exact operation it claims to prove.
export function verifyReceipt(input: VerifyReceiptInput): ReceiptVerification {
  const h = (name: string): string | undefined => {
    const raw = input.headers[name.toLowerCase()];
    if (Array.isArray(raw)) return raw[0];
    return raw;
  };
  const receiptIdHeader = h('x-patches-receipt-id');
  const contentHashHeader = h('x-patches-content-sha256');
  const signatureHeader = h('x-patches-signature');
  if (!receiptIdHeader || !contentHashHeader || !signatureHeader) {
    return { verified: false, reason: 'RECEIPT_MISSING_HEADERS' };
  }

  const { contentSha256, signature } = signReceiptBytes(input.rawBody, input.secret);
  if (contentHashHeader !== contentSha256) {
    return { verified: false, reason: 'RECEIPT_CONTENT_HASH_MISMATCH' };
  }
  if (signatureHeader.length !== 64 || !timingSafeEqualHex(signature, signatureHeader)) {
    return { verified: false, reason: 'RECEIPT_INVALID_SIGNATURE' };
  }

  let receipt: ReceiptBody;
  try {
    receipt = JSON.parse(input.rawBody.toString('utf8')) as ReceiptBody;
  } catch {
    return { verified: false, reason: 'RECEIPT_BODY_MALFORMED' };
  }
  if (receipt.receiptId !== receiptIdHeader) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }
  if (receipt.schemaVersion !== RECEIPT_SCHEMA_VERSION) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }

  if (input.expected) {
    const e = input.expected;
    const mismatch =
      (e.receiptId !== undefined && receipt.receiptId !== e.receiptId) ||
      (e.requestId !== undefined && receipt.requestId !== e.requestId) ||
      (e.clientId !== undefined && receipt.clientId !== e.clientId) ||
      (e.operation !== undefined && receipt.operation !== e.operation) ||
      (e.outcome !== undefined && receipt.outcome !== e.outcome) ||
      (e.activationId !== undefined && receipt.activationId !== e.activationId);
    if (mismatch) return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }

  return { verified: true, receipt };
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}
