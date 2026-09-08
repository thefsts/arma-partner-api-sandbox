// Stop Point 7 — shared SDK receipt tests (byte-exact sign/verify + binding).
//
// Proves the shared receipt contract: signature over EXACT raw bytes,
// content-hash binding, expected-field binding to the operation, and
// fail-closed on every tamper vector (truncation, field swap, header strip).

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RECEIPT_SCHEMA_VERSION,
  signReceiptBytes,
  verifyReceipt,
  DEFAULT_RECEIPT_HEADERS,
} from '../sdk/receipts.ts';
import { RECEIPT_SECRET } from './helpers.mjs';

const NOW = 1_700_000_000_000;

function receiptBody(overrides = {}) {
  return {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    receiptId: 'rcpt-000000001',
    requestId: 'req-0123456789abcdef',
    partnerId: 'partner-sandbox-1',
    operation: 'activation.create',
    outcome: 'SUCCESS',
    at: NOW,
    entityRef: 'entity-activation-001',
    payloadHash: 'a'.repeat(64),
    ...overrides,
  };
}

function signedReceipt(bodyOverrides = {}) {
  const body = receiptBody(bodyOverrides);
  const raw = Buffer.from(JSON.stringify(body), 'utf8');
  const { contentSha256, signature } = signReceiptBytes(raw, RECEIPT_SECRET);
  const headers = {
    [DEFAULT_RECEIPT_HEADERS.receiptId]: body.receiptId,
    [DEFAULT_RECEIPT_HEADERS.contentSha256]: contentSha256,
    [DEFAULT_RECEIPT_HEADERS.signature]: signature,
  };
  return { raw, headers, body };
}

test('sign + verify round trip succeeds with expected binding', () => {
  const { raw, headers } = signedReceipt();
  const v = verifyReceipt({
    rawBody: raw,
    headers,
    secret: RECEIPT_SECRET,
    expected: { requestId: 'req-0123456789abcdef', operation: 'activation.create', outcome: 'SUCCESS' },
  });
  assert.equal(v.verified, true);
  assert.ok(v.receipt);
});

test('verify fails closed when headers are missing', () => {
  const { raw } = signedReceipt();
  const v = verifyReceipt({ rawBody: raw, headers: {}, secret: RECEIPT_SECRET });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_MISSING_HEADERS');
});

test('verify fails closed on content-hash mismatch (truncated body)', () => {
  const { raw, headers } = signedReceipt();
  const truncated = raw.subarray(0, raw.length - 5);
  const v = verifyReceipt({ rawBody: truncated, headers, secret: RECEIPT_SECRET });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_CONTENT_HASH_MISMATCH');
});

test('verify fails closed on signature tamper', () => {
  const { raw, headers } = signedReceipt();
  const v = verifyReceipt({
    rawBody: raw,
    headers: { ...headers, [DEFAULT_RECEIPT_HEADERS.signature]: '0'.repeat(64) },
    secret: RECEIPT_SECRET,
  });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_INVALID_SIGNATURE');
});

test('verify fails closed on wrong secret', () => {
  const { raw, headers } = signedReceipt();
  const v = verifyReceipt({ rawBody: raw, headers, secret: 'synthetic-other-secret-SP7-sandbox' });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_INVALID_SIGNATURE');
});

test('verify fails closed on body-field swap (signature still valid)', () => {
  // Bind to a DIFFERENT operation than the receipt proves — the
  // expected-field binding must catch this even with a valid signature.
  const { raw, headers } = signedReceipt();
  const v = verifyReceipt({
    rawBody: raw,
    headers,
    secret: RECEIPT_SECRET,
    expected: { operation: 'transfer.send' },
  });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_FIELD_MISMATCH');
});

test('verify fails closed on partner mismatch binding', () => {
  const { raw, headers } = signedReceipt();
  const v = verifyReceipt({
    rawBody: raw,
    headers,
    secret: RECEIPT_SECRET,
    expected: { partnerId: 'partner-sandbox-999' },
  });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_FIELD_MISMATCH');
});

test('verify fails closed on empty raw bytes', () => {
  const { headers } = signedReceipt();
  const v = verifyReceipt({ rawBody: Buffer.alloc(0), headers, secret: RECEIPT_SECRET });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_BODY_MALFORMED');
});

test('verify fails closed on malformed JSON body with valid headers', () => {
  const raw = Buffer.from('not-json-at-all', 'utf8');
  const { contentSha256, signature } = signReceiptBytes(raw, RECEIPT_SECRET);
  const headers = {
    [DEFAULT_RECEIPT_HEADERS.receiptId]: 'rcpt-000000001',
    [DEFAULT_RECEIPT_HEADERS.contentSha256]: contentSha256,
    [DEFAULT_RECEIPT_HEADERS.signature]: signature,
  };
  const v = verifyReceipt({ rawBody: raw, headers, secret: RECEIPT_SECRET });
  assert.equal(v.verified, false);
  if (!v.verified) assert.equal(v.reason, 'RECEIPT_BODY_MALFORMED');
});

test('signReceiptBytes refuses an empty secret', () => {
  assert.throws(() => signReceiptBytes(Buffer.from('x'), ''), /RECEIPT_SECRET_REQUIRED/);
});

test('signature covers the exact bytes: one byte difference breaks it', () => {
  const a = signReceiptBytes(Buffer.from('{"a":1}'), RECEIPT_SECRET);
  const b = signReceiptBytes(Buffer.from('{"a":2}'), RECEIPT_SECRET);
  assert.notEqual(a.signature, b.signature);
  assert.notEqual(a.contentSha256, b.contentSha256);
});
