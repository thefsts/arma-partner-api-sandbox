// Stop Point 6 — integrity primitives for provenance + deterministic
// envelopes. Hash the EXACT governed output bytes; bind envelope metadata
// with an HMAC over a fixed-order value list; compare timing-safe; fail
// closed on any mismatch or tamper. Synthetic test keys only — never
// production material.

import { createHash, createHmac, timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';

/** sha256 hex over the EXACT utf-8 bytes of the governed output. */
export function computeOutputHash(output: string): string {
  if (typeof output !== 'string') throw new Error('OUTPUT_BYTES_REQUIRED');
  return createHash('sha256').update(Buffer.from(output, 'utf8')).digest('hex');
}

/** True only for a lowercase 64-char hex digest. */
export function isHashLike(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

/**
 * Canonical HMAC tag over a fixed-order list of bound values. The list is
 * JSON-serialized (arrays serialize deterministically), so field order and
 * separators cannot collide. Optional/absent fields bind as null.
 */
export function computeIntegrityTag(boundValues: readonly unknown[], integrityKey: string): string {
  if (typeof integrityKey !== 'string' || integrityKey.length < 8) {
    throw new Error('INTEGRITY_KEY_REQUIRED');
  }
  const canonical = JSON.stringify(boundValues);
  return createHmac('sha256', integrityKey).update(canonical, 'utf8').digest('hex');
}

/** Timing-safe hex comparison (same defensive shape as the partner lanes). */
export function timingSafeEqualHex(expected: string, actual: string): boolean {
  if (!expected || !actual || expected.length !== actual.length) return false;
  if (!/^[a-f0-9]+$/i.test(expected) || !/^[a-f0-9]+$/i.test(actual)) return false;
  try {
    return nodeTimingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex'));
  } catch {
    return false;
  }
}

/** A well-formed integrity tag is a lowercase 64-char hex digest. */
export function isIntegrityTagLike(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}
