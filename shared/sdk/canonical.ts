// Stop Point 7 — shared partner SDK: canonical request signing.
//
// One signing primitive for every partner integration surface (Law Shield
// gateway requests, PATCHES partner API requests, webhook deliveries). The
// canonical string is the proven five-field form:
//   `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`
// The signature binds the caller to method + exact path + time + nonce +
// byte-exact body hash, so any in-flight mutation (path rewrite, body edit,
// timestamp shift) breaks verification. Verification is timing-safe and
// fails closed on every unknown or malformed input.
//
// PORTING NOTE (private repos): this module is the shared replacement for
// the per-surface signers (law-shield/arma/signer.js, patches/lib/security.ts
// canonical helpers). Each surface keeps its own header names; only the
// canonical+HMAC primitive is shared. Secrets always come from the caller's
// injected resolver — never stored here.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000; // ±5 minutes, both surfaces
export const NONCE_MIN_LENGTH = 20;
export const NONCE_MAX_LENGTH = 128;
export const NONCE_PATTERN = /^[A-Za-z0-9_-]{20,128}$/;
export const TIMESTAMP_PATTERN = /^\d{1,16}$/;
export const HEX_SHA256_PATTERN = /^[0-9a-f]{64}$/;

export type SignatureFailureCode =
  | 'SIGNATURE_INPUT_INVALID'
  | 'SIGNATURE_NONCE_INVALID'
  | 'SIGNATURE_TIMESTAMP_INVALID'
  | 'SIGNATURE_BODY_HASH_INVALID'
  | 'SIGNATURE_SIGNATURE_MISMATCH'
  | 'SIGNATURE_CLOCK_SKEW_EXCEEDED';

export interface CanonicalRequest {
  method: string;
  path: string;
  timestamp: string | number;
  nonce: string;
  bodyHash: string;
}

/** The canonical string: exact field order, newline separated. */
export function canonicalRequestString(req: CanonicalRequest): string {
  return `${String(req.method).toUpperCase()}\n${req.path}\n${String(req.timestamp)}\n${req.nonce}\n${req.bodyHash}`;
}

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Body hash over the EXACT raw bytes; empty body hashes the empty string. */
export function bodyHashFor(rawBody: Buffer | string): string {
  const raw = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : rawBody;
  return sha256Hex(raw.length === 0 ? '' : raw);
}

export function computeRequestSignature(secret: string, canonical: string): string {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('SIGNER_SECRET_REQUIRED');
  }
  return createHmac('sha256', secret).update(canonical).digest('hex');
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

export interface SignedRequest {
  canonical: string;
  bodyHash: string;
  signature: string;
}

/** Sign a canonical request. Fails closed on malformed inputs. */
export function signCanonicalRequest(secret: string, req: CanonicalRequest): SignedRequest {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('SIGNER_SECRET_REQUIRED');
  }
  if (typeof req.method !== 'string' || !req.method) throw new Error('SIGNATURE_INPUT_INVALID');
  if (typeof req.path !== 'string' || !req.path) throw new Error('SIGNATURE_INPUT_INVALID');
  if (!NONCE_PATTERN.test(req.nonce)) throw new Error('SIGNATURE_NONCE_INVALID');
  if (!TIMESTAMP_PATTERN.test(String(req.timestamp))) throw new Error('SIGNATURE_TIMESTAMP_INVALID');
  if (!HEX_SHA256_PATTERN.test(req.bodyHash)) throw new Error('SIGNATURE_BODY_HASH_INVALID');
  const canonical = canonicalRequestString(req);
  const signature = computeRequestSignature(secret, canonical);
  return { canonical, bodyHash: req.bodyHash, signature };
}

export interface VerifySignatureInput {
  secret: string;
  method: string;
  path: string;
  timestamp: string;
  nonce: string;
  bodyHash: string;
  providedSignature: string;
  now?: number;
  maxClockSkewMs?: number;
}

export type SignatureVerification =
  | { ok: true; signature: string }
  | { ok: false; code: SignatureFailureCode; detail?: Record<string, unknown> };

/** Verify a signed canonical request against a secret. Timing-safe compare,
 *  clock-skew window, and fail-closed structural checks. */
export function verifyCanonicalRequestSignature(input: VerifySignatureInput): SignatureVerification {
  const now = input.now ?? Date.now();
  const skewLimit = input.maxClockSkewMs ?? MAX_CLOCK_SKEW_MS;
  if (
    typeof input.method !== 'string' || !input.method ||
    typeof input.path !== 'string' || !input.path ||
    typeof input.nonce !== 'string'
  ) {
    return { ok: false, code: 'SIGNATURE_INPUT_INVALID' };
  }
  if (!TIMESTAMP_PATTERN.test(String(input.timestamp))) {
    return { ok: false, code: 'SIGNATURE_TIMESTAMP_INVALID' };
  }
  const ts = Number(input.timestamp);
  if (Math.abs(now - ts) > skewLimit) {
    return {
      ok: false,
      code: 'SIGNATURE_CLOCK_SKEW_EXCEEDED',
      detail: { skewMs: Math.abs(now - ts), limitMs: skewLimit },
    };
  }
  if (!NONCE_PATTERN.test(input.nonce)) {
    return { ok: false, code: 'SIGNATURE_NONCE_INVALID' };
  }
  if (typeof input.bodyHash !== 'string' || !HEX_SHA256_PATTERN.test(input.bodyHash)) {
    return { ok: false, code: 'SIGNATURE_BODY_HASH_INVALID' };
  }
  if (typeof input.secret !== 'string' || input.secret.length === 0) {
    return { ok: false, code: 'SIGNATURE_INPUT_INVALID' };
  }
  const canonical = canonicalRequestString(input);
  const expected = computeRequestSignature(input.secret, canonical);
  if (typeof input.providedSignature !== 'string' || !HEX_SHA256_PATTERN.test(input.providedSignature)) {
    return { ok: false, code: 'SIGNATURE_SIGNATURE_MISMATCH' };
  }
  if (!timingSafeEqualHex(expected, input.providedSignature)) {
    return { ok: false, code: 'SIGNATURE_SIGNATURE_MISMATCH' };
  }
  return { ok: true, signature: input.providedSignature };
}
