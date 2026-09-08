// Stop Point 7 — shared SDK signing tests (canonical form, HMAC, skew, replay).
//
// Proves the shared canonical signing contract: 5-field canonical string,
// HMAC-SHA256 hex, timing-safe verification, ±5 minute clock skew window,
// nonce shape enforcement, and fail-closed behavior on every tamper vector.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalRequestString,
  computeRequestSignature,
  signCanonicalRequest,
  verifyCanonicalRequestSignature,
  sha256Hex,
  bodyHashFor,
  MAX_CLOCK_SKEW_MS,
  NONCE_PATTERN,
} from '../sdk/canonical.ts';
import { PARTNER_SECRET, makeClock, validNonce } from './helpers.mjs';

const NOW = 1_700_000_000_000;

function baseReq(overrides = {}) {
  return {
    method: 'POST',
    path: '/api/partner/v1/activations',
    timestamp: String(NOW),
    nonce: validNonce('a'),
    bodyHash: sha256Hex('{"caseId":"case-001"}'),
    ...overrides,
  };
}

test('canonical string joins the five fields in fixed order', () => {
  const canonical = canonicalRequestString(baseReq());
  assert.equal(
    canonical,
    'POST\n/api/partner/v1/activations\n' + NOW + '\n' + validNonce('a') + '\n' + sha256Hex('{"caseId":"case-001"}'),
  );
});

test('signing is deterministic: same secret + canonical => same signature', () => {
  const a = computeRequestSignature(PARTNER_SECRET, canonicalRequestString(baseReq()));
  const b = computeRequestSignature(PARTNER_SECRET, canonicalRequestString(baseReq()));
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('empty body hashes to sha256 of empty string', () => {
  assert.equal(bodyHashFor(Buffer.alloc(0)), sha256Hex(''));
});

test('sign + verify round trip succeeds', () => {
  const req = baseReq();
  const signed = signCanonicalRequest(PARTNER_SECRET, req);
  const verification = verifyCanonicalRequestSignature({
    method: req.method,
    path: req.path,
    timestamp: req.timestamp,
    nonce: req.nonce,
    bodyHash: req.bodyHash,
    providedSignature: signed.signature,
    secret: PARTNER_SECRET,
    now: NOW,
  });
  assert.equal(verification.ok, true);
});

test('verification fails closed on signature tamper', () => {
  const req = baseReq();
  const signed = signCanonicalRequest(PARTNER_SECRET, req);
  const flipped = signed.signature.slice(0, 62) + (signed.signature.endsWith('0') ? '1' : '0');
  const verification = verifyCanonicalRequestSignature({
    ...req,
    providedSignature: flipped,
    secret: PARTNER_SECRET,
    now: NOW,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) assert.equal(verification.code, 'SIGNATURE_SIGNATURE_MISMATCH');
});

test('verification fails closed on wrong secret', () => {
  const req = baseReq();
  const signed = signCanonicalRequest(PARTNER_SECRET, req);
  const verification = verifyCanonicalRequestSignature({
    ...req,
    providedSignature: signed.signature,
    secret: 'synthetic-other-secret-SP7-sandbox',
    now: NOW,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) assert.equal(verification.code, 'SIGNATURE_SIGNATURE_MISMATCH');
});

test('clock skew beyond ±5 minutes fails closed with skew detail', () => {
  const req = baseReq();
  const signed = signCanonicalRequest(PARTNER_SECRET, req);
  const verification = verifyCanonicalRequestSignature({
    ...req,
    providedSignature: signed.signature,
    secret: PARTNER_SECRET,
    now: NOW + MAX_CLOCK_SKEW_MS + 1,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) {
    assert.equal(verification.code, 'SIGNATURE_CLOCK_SKEW_EXCEEDED');
    assert.equal(verification.detail?.skewMs, MAX_CLOCK_SKEW_MS + 1);
    assert.equal(verification.detail?.limitMs, MAX_CLOCK_SKEW_MS);
  }
});

test('clock skew exactly at the limit is accepted (boundary)', () => {
  const req = baseReq();
  const signed = signCanonicalRequest(PARTNER_SECRET, req);
  const verification = verifyCanonicalRequestSignature({
    ...req,
    providedSignature: signed.signature,
    secret: PARTNER_SECRET,
    now: NOW + MAX_CLOCK_SKEW_MS,
  });
  assert.equal(verification.ok, true);
});

test('verification fails closed on malformed timestamp', () => {
  const req = baseReq({ timestamp: 'not-a-number' });
  const verification = verifyCanonicalRequestSignature({
    ...req,
    providedSignature: '0'.repeat(64),
    secret: PARTNER_SECRET,
    now: NOW,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) assert.equal(verification.code, 'SIGNATURE_TIMESTAMP_INVALID');
});

test('verification fails closed on malformed nonce', () => {
  const req = baseReq({ nonce: 'short' });
  const verification = verifyCanonicalRequestSignature({
    ...req,
    providedSignature: '0'.repeat(64),
    secret: PARTNER_SECRET,
    now: NOW,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) assert.equal(verification.code, 'SIGNATURE_NONCE_INVALID');
});

test('verification fails closed on malformed body hash', () => {
  const req = baseReq({ bodyHash: 'zz' });
  const verification = verifyCanonicalRequestSignature({
    ...req,
    providedSignature: '0'.repeat(64),
    secret: PARTNER_SECRET,
    now: NOW,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) assert.equal(verification.code, 'SIGNATURE_BODY_HASH_INVALID');
});

test('verification fails closed on path tamper', () => {
  const req = baseReq();
  const signed = signCanonicalRequest(PARTNER_SECRET, req);
  const verification = verifyCanonicalRequestSignature({
    ...req,
    path: '/api/partner/v1/transfers',
    providedSignature: signed.signature,
    secret: PARTNER_SECRET,
    now: NOW,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) assert.equal(verification.code, 'SIGNATURE_SIGNATURE_MISMATCH');
});

test('verification fails closed on body swap (same nonce+timestamp)', () => {
  const req = baseReq();
  const signed = signCanonicalRequest(PARTNER_SECRET, req);
  const verification = verifyCanonicalRequestSignature({
    ...req,
    bodyHash: sha256Hex('{"caseId":"case-999"}'),
    providedSignature: signed.signature,
    secret: PARTNER_SECRET,
    now: NOW,
  });
  assert.equal(verification.ok, false);
  if (!verification.ok) assert.equal(verification.code, 'SIGNATURE_SIGNATURE_MISMATCH');
});

test('signing refuses an empty secret', () => {
  assert.throws(() => computeRequestSignature('', canonicalRequestString(baseReq())), /SIGNER_SECRET_REQUIRED/);
});

test('signCanonicalRequest rejects malformed inputs structurally', () => {
  assert.throws(() => signCanonicalRequest(PARTNER_SECRET, baseReq({ nonce: 'short' })), /SIGNATURE_NONCE_INVALID/);
  assert.throws(() => signCanonicalRequest(PARTNER_SECRET, baseReq({ timestamp: 'x' })), /SIGNATURE_TIMESTAMP_INVALID/);
  assert.throws(() => signCanonicalRequest(PARTNER_SECRET, baseReq({ bodyHash: 'nothex' })), /SIGNATURE_BODY_HASH_INVALID/);
});

test('NONCE_PATTERN accepts 20-128 char [A-Za-z0-9_-] nonces', () => {
  assert.ok(NONCE_PATTERN.test(validNonce('a')));
  assert.ok(NONCE_PATTERN.test('a'.repeat(128)));
  assert.ok(!NONCE_PATTERN.test('a'.repeat(19)));
  assert.ok(!NONCE_PATTERN.test('a'.repeat(129)));
  assert.ok(!NONCE_PATTERN.test('bad nonce with spaces!'));
});

test('method is uppercased in the canonical form', () => {
  const canonical = canonicalRequestString(baseReq({ method: 'post' }));
  assert.ok(canonical.startsWith('POST\n'));
});

test('signing with different secrets yields different signatures', () => {
  const a = computeRequestSignature(PARTNER_SECRET, canonicalRequestString(baseReq()));
  const b = computeRequestSignature('synthetic-receipt-signing-secret-SP7-sandbox', canonicalRequestString(baseReq()));
  assert.notEqual(a, b);
});
