// Stop Point 7 — shared SDK correlation + version tests.
//
// Proves the request/correlation ID contract (echo-valid-or-generate, child
// derivation with depth bounds) and exact-match API version negotiation
// that fails closed on unknown/malformed versions.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateRequestId,
  resolveRequestId,
  deriveChildRequestId,
  REQUEST_ID_HEADER,
  CORRELATION_ID_HEADER,
  CHILD_ID_MAX_DEPTH,
} from '../sdk/correlation.ts';
import {
  negotiateApiVersion,
  SUPPORTED_SDK_API_VERSIONS,
  isWellFormedVersion,
  isSupportedSdkVersion,
  compareVersions,
} from '../sdk/versions.ts';
import { makeClock } from './helpers.mjs';

const NOW = 1_700_000_000_000;

// --- Correlation ---

test('generateRequestId produces the req-<uuid> shape', () => {
  const id = generateRequestId();
  assert.match(id, /^req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
});

test('resolveRequestId echoes a valid caller-supplied ID', () => {
  const r = resolveRequestId({ headerValue: 'caller-id-0001', at: NOW });
  assert.deepEqual(r, { requestId: 'caller-id-0001', echoed: true, generated: false });
});

test('resolveRequestId generates when the header is absent', () => {
  const r = resolveRequestId({ headerValue: undefined, at: NOW });
  assert.equal(r.echoed, false);
  assert.equal(r.generated, true);
  assert.match(r.requestId, /^req-/);
});

test('resolveRequestId generates when the header is malformed (fail-safe, not fail-closed)', () => {
  const r = resolveRequestId({ headerValue: 'bad id!', at: NOW });
  assert.equal(r.echoed, false);
  assert.equal(r.generated, true);
});

test('resolveRequestId takes the first value from a multi-valued header', () => {
  const r = resolveRequestId({ headerValue: ['first-id-0001', 'second-id-0002'], at: NOW });
  assert.deepEqual(r, { requestId: 'first-id-0001', echoed: true, generated: false });
});

test('deriveChildRequestId appends the suffix with > separator', () => {
  assert.equal(deriveChildRequestId('parent-id-0001', 'adapter'), 'parent-id-0001>adapter');
});

test('deriveChildRequestId fails closed on a malformed suffix', () => {
  assert.throws(() => deriveChildRequestId('parent-id-0001', ''), /CORRELATION_SUFFIX_INVALID/);
  assert.throws(() => deriveChildRequestId('parent-id-0001', 'x'.repeat(33)), /CORRELATION_DEPTH_EXCEEDED|CORRELATION_SUFFIX_INVALID/);
  assert.throws(() => deriveChildRequestId('parent-id-0001', 'bad suffix!'), /CORRELATION_SUFFIX_INVALID/);
});

test('deriveChildRequestId fails closed past the depth bound', () => {
  let id = 'root-id-0001';
  // 1 root part + (CHILD_ID_MAX_DEPTH - 1) suffixes = CHILD_ID_MAX_DEPTH parts;
  // the next derivation must refuse (parent already at the bound).
  for (let i = 0; i < CHILD_ID_MAX_DEPTH - 1; i++) {
    id = deriveChildRequestId(id, `lvl${i}`);
  }
  assert.throws(() => deriveChildRequestId(id, 'one-too-many'), /CORRELATION_DEPTH_EXCEEDED/);
});

test('deriveChildRequestId fails closed on a malformed parent', () => {
  assert.throws(() => deriveChildRequestId('', 'adapter'), /CORRELATION_PARENT_INVALID/);
});

test('correlation headers use the x-request-id / x-correlation-id names', () => {
  assert.equal(REQUEST_ID_HEADER, 'x-request-id');
  assert.equal(CORRELATION_ID_HEADER, 'x-correlation-id');
});

// --- Versions ---

test('negotiateApiVersion accepts an exact supported version', () => {
  const r = negotiateApiVersion({ provided: 'v1' });
  assert.deepEqual(r, { ok: true, version: 'v1', supported: ['v1'] });
});

test('negotiateApiVersion fails closed when the version is missing', () => {
  const r = negotiateApiVersion({ provided: undefined });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.failure.code, 'VERSION_MISSING');
});

test('negotiateApiVersion fails closed on a malformed version', () => {
  const r = negotiateApiVersion({ provided: 'version-1' });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.failure.code, 'VERSION_MALFORMED');
});

test('negotiateApiVersion fails closed on an unknown version (never silent downgrade)', () => {
  const r = negotiateApiVersion({ provided: 'v9' });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.failure.code, 'VERSION_UNKNOWN');
});

test('negotiateApiVersion honors the capability window', () => {
  const inWindow = negotiateApiVersion({ provided: 'v1', capabilityMin: 'v1', capabilityMax: 'v2' });
  assert.equal(inWindow.ok, true);
  const outOfWindow = negotiateApiVersion({ provided: 'v1', capabilityMin: 'v2', capabilityMax: 'v2' });
  assert.equal(outOfWindow.ok, false);
  if (!outOfWindow.ok) assert.equal(outOfWindow.failure.code, 'VERSION_OUT_OF_CAPABILITY_WINDOW');
});

test('SUPPORTED_SDK_API_VERSIONS is exactly v1 today', () => {
  assert.deepEqual([...SUPPORTED_SDK_API_VERSIONS], ['v1']);
});

test('isWellFormedVersion and isSupportedSdkVersion classify correctly', () => {
  assert.equal(isWellFormedVersion('v1'), true);
  assert.equal(isWellFormedVersion('1'), false);
  assert.equal(isWellFormedVersion(1), false);
  assert.equal(isSupportedSdkVersion('v1'), true);
  assert.equal(isSupportedSdkVersion('v2'), false);
});

test('compareVersions is numeric, not lexicographic (v2 < v10)', () => {
  assert.equal(compareVersions('v1', 'v2'), -1);
  assert.equal(compareVersions('v10', 'v2'), 1);
  assert.equal(compareVersions('v3', 'v3'), 0);
});
