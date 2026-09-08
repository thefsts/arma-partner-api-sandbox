// Stop Point 7 — shared partner SDK: signed receipts, byte-exact.
//
// Every state-changing partner operation returns a receipt signed over its
// RAW response bytes — the same discipline both existing surfaces already
// enforce (arma-lawshield.v1 raw-byte receipt; patches-partner-v1 receipt
// headers). The verifier NEVER re-serializes: hash and signature are
// computed over the exact received bytes, then the body is parsed and bound
// to the expected operation context. Any in-flight mutation (truncation,
// field swap, status flip) breaks verification.
//
// PORTING NOTE (private repos): receipt secrets live in the platform secret
// store (KMS boundary), injected by the caller. Receipts persist durable
// state so partners can re-verify old receipts without replaying operations.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { sha256Hex } from './canonical.ts';

export { sha256Hex };

export const RECEIPT_SCHEMA_VERSION = 'shared-partner-v1';

export interface ReceiptBody {
  schemaVersion: string; // 'shared-partner-v1'
  receiptId: string;
  requestId: string;
  partnerId: string;
  operation: string; // e.g. 'activation.create', 'transfer.send'
  outcome: 'SUCCESS' | 'CONFLICT' | 'REJECTED';
  at: number;
  entityRef?: string; // operation-specific opaque entity reference
  payloadHash?: string; // hash of the request payload, never the payload
  result?: unknown; // sanitized operation result view
}


export function signReceiptBytes(
  rawBytes: Buffer,
  secret: string,
): { contentSha256: string; signature: string } {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('RECEIPT_SECRET_REQUIRED');
  }
  const contentSha256 = createHash('sha256').update(rawBytes).digest('hex');
  const signature = createHmac('sha256', secret).update(rawBytes).digest('hex');
  return { contentSha256, signature };
}

export interface VerifyReceiptInput {
  rawBody: Buffer | string;
  headers: Record<string, string | string[] | undefined>;
  secret: string;
  expected?: {
    receiptId?: string;
    requestId?: string;
    partnerId?: string;
    operation?: string;
    outcome?: string;
    entityRef?: string;
  };
  headerNames?: Partial<typeof DEFAULT_RECEIPT_HEADERS>;
}

export type ReceiptFailureCode =
  | 'RECEIPT_MISSING_HEADERS'
  | 'RECEIPT_INVALID_SIGNATURE'
  | 'RECEIPT_CONTENT_HASH_MISMATCH'
  | 'RECEIPT_BODY_MALFORMED'
  | 'RECEIPT_FIELD_MISMATCH';

export interface ReceiptVerification {
  verified: boolean;
  reason?: ReceiptFailureCode;
  receipt?: ReceiptBody;
}

// Default header names for the shared surface. Law Shield uses
// x-lawshield-* and PATCHES uses x-patches-*; the shared SDK keeps these
// neutral names and accepts per-surface override via input.headerNames.
export const DEFAULT_RECEIPT_HEADERS = {
  receiptId: 'x-shared-receipt-id',
  contentSha256: 'x-shared-content-sha256',
  signature: 'x-shared-signature',
} as const;

function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

/** Verify a receipt over RAW bytes. `expected` binds the receipt to the
 *  exact operation it claims to prove. Fails closed on every defect. */
export function verifyReceipt(input: VerifyReceiptInput): ReceiptVerification {
  const headerNames = { ...DEFAULT_RECEIPT_HEADERS, ...(input.headerNames ?? {}) };
  const h = (name: string): string | undefined => {
    const raw = input.headers[name.toLowerCase()];
    if (Array.isArray(raw)) return raw[0];
    return raw;
  };
  const receiptIdHeader = h(headerNames.receiptId);
  const contentHashHeader = h(headerNames.contentSha256);
  const signatureHeader = h(headerNames.signature);
  if (!receiptIdHeader || !contentHashHeader || !signatureHeader) {
    return { verified: false, reason: 'RECEIPT_MISSING_HEADERS' };
  }

  const raw = typeof input.rawBody === 'string' ? Buffer.from(input.rawBody, 'utf8') : input.rawBody;
  if (raw.length === 0) return { verified: false, reason: 'RECEIPT_BODY_MALFORMED' };

  const { contentSha256, signature } = signReceiptBytes(raw, input.secret);
  if (contentHashHeader !== contentSha256) {
    return { verified: false, reason: 'RECEIPT_CONTENT_HASH_MISMATCH' };
  }
  if (!timingSafeEqualHex(signature, signatureHeader)) {
    return { verified: false, reason: 'RECEIPT_INVALID_SIGNATURE' };
  }

  let receipt: ReceiptBody;
  try {
    receipt = JSON.parse(raw.toString('utf8')) as ReceiptBody;
  } catch {
    return { verified: false, reason: 'RECEIPT_BODY_MALFORMED' };
  }
  if (receipt.receiptId !== receiptIdHeader) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }
  if (receipt.schemaVersion !== RECEIPT_SCHEMA_VERSION) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }
  if (typeof receipt.requestId !== 'string' || !receipt.requestId) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }
  if (typeof receipt.partnerId !== 'string' || !receipt.partnerId) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }
  if (typeof receipt.operation !== 'string' || !receipt.operation) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }
  if (typeof receipt.outcome !== 'string' || !receipt.outcome) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }
  if (!Number.isFinite(receipt.at)) {
    return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }

  if (input.expected) {
    const e = input.expected;
    const mismatch =
      (e.receiptId !== undefined && receipt.receiptId !== e.receiptId) ||
      (e.requestId !== undefined && receipt.requestId !== e.requestId) ||
      (e.partnerId !== undefined && receipt.partnerId !== e.partnerId) ||
      (e.operation !== undefined && receipt.operation !== e.operation) ||
      (e.outcome !== undefined && receipt.outcome !== e.outcome) ||
      (e.entityRef !== undefined && receipt.entityRef !== e.entityRef);
    if (mismatch) return { verified: false, reason: 'RECEIPT_FIELD_MISMATCH' };
  }

  return { verified: true, receipt };
}
