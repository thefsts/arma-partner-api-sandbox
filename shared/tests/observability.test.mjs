// Stop Point 7 — integration observability contract tests.
//
// Proves the metadata-only telemetry contract: allowlisted safe-metadata
// keys only, scalar bounded values, registered secrets structurally
// excluded, span lifecycle (RUNNING -> SUCCESS/FAILED/AMBIGUOUS), retry
// counts, reconciliation status, and lookup by request ID.

import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryTelemetrySink } from '../observability/telemetry.ts';
import { makeClock, PARTNER_SECRET } from './helpers.mjs';

const { clock, now, advance } = makeClock(1_700_000_000_000);

function makeSink(secretValues = []) {
  return new InMemoryTelemetrySink({ now, secretValues });
}

const SPAN_INPUT = {
  requestId: 'req-observability-0001',
  partnerId: 'partner-sandbox-1',
  operation: 'activation.create',
  orgRef: 'org-sandbox-1',
};

// --- Span lifecycle ---

test('startSpan creates a RUNNING span with the full metadata-only shape', () => {
  const sink = makeSink();
  const span = sink.startSpan({ ...SPAN_INPUT, metadata: { entityRef: 'entity-activation-001', attempt: 1 } });
  assert.match(span.spanId, /^span-/);
  assert.equal(span.requestId, 'req-observability-0001');
  assert.equal(span.partnerId, 'partner-sandbox-1');
  assert.equal(span.orgRef, 'org-sandbox-1');
  assert.equal(span.operation, 'activation.create');
  assert.equal(span.startedAt, now());
  assert.equal(span.completedAt, null);
  assert.equal(span.latencyMs, null);
  assert.equal(span.status, 'RUNNING');
  assert.equal(span.success, null);
  assert.equal(span.errorClass, null);
  assert.equal(span.retryCount, 0);
  assert.equal(span.reconciliationStatus, 'NONE');
  assert.deepEqual({ ...span.safeMetadata }, { entityRef: 'entity-activation-001', attempt: 1 });
  assert.equal(Object.isFrozen(span.safeMetadata), true);
});

test('startSpan fails closed on malformed input', () => {
  const sink = makeSink();
  assert.throws(() => sink.startSpan(null), /TELEMETRY_SPAN_INPUT_INVALID/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, requestId: '' }), /TELEMETRY_REQUEST_ID_REQUIRED/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, partnerId: ' ' }), /TELEMETRY_PARTNER_REQUIRED/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, operation: '' }), /TELEMETRY_OPERATION_REQUIRED/);
});

test('completeSpan marks SUCCESS with latency from the injected clock', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  advance(1_500);
  const done = sink.completeSpan(span.spanId, { success: true });
  assert.equal(done.status, 'SUCCESS');
  assert.equal(done.success, true);
  assert.equal(done.completedAt, now());
  assert.equal(done.latencyMs, 1_500);
  assert.equal(done.reconciliationStatus, 'NONE');
});

test('completeSpan marks FAILED with errorClass and retryCount', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  advance(200);
  const done = sink.completeSpan(span.spanId, { success: false, errorClass: 'TRANSPORT', retryCount: 2 });
  assert.equal(done.status, 'FAILED');
  assert.equal(done.success, false);
  assert.equal(done.errorClass, 'TRANSPORT');
  assert.equal(done.retryCount, 2);
  assert.equal(done.latencyMs, 200);
});

test('completeSpan merges completion metadata into safeMetadata', () => {
  const sink = makeSink();
  const span = sink.startSpan({ ...SPAN_INPUT, metadata: { entityRef: 'entity-activation-001' } });
  const done = sink.completeSpan(span.spanId, { success: true, metadata: { receiptId: 'rcpt-000000001', outcome: 'SUCCESS' } });
  assert.deepEqual({ ...done.safeMetadata }, { entityRef: 'entity-activation-001', receiptId: 'rcpt-000000001', outcome: 'SUCCESS' });
});

test('a completed span cannot be completed or re-marked again', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  sink.completeSpan(span.spanId, { success: true });
  assert.throws(() => sink.completeSpan(span.spanId, { success: true }), /TELEMETRY_SPAN_ALREADY_COMPLETED/);
  assert.throws(() => sink.markAmbiguous(span.spanId), /TELEMETRY_SPAN_ALREADY_COMPLETED/);
});

test('completeSpan fails closed on malformed completion input', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  assert.throws(() => sink.completeSpan(span.spanId, null), /TELEMETRY_SPAN_INPUT_INVALID/);
  assert.throws(() => sink.completeSpan(span.spanId, {}), /TELEMETRY_SPAN_INPUT_INVALID/);
  assert.throws(() => sink.completeSpan(span.spanId, { success: true, retryCount: -1 }), /TELEMETRY_RETRY_COUNT_INVALID/);
  assert.throws(() => sink.completeSpan(span.spanId, { success: true, retryCount: 1.5 }), /TELEMETRY_RETRY_COUNT_INVALID/);
  assert.throws(() => sink.completeSpan(span.spanId, { success: true, reconciliationStatus: 'SOMEHOW' }), /TELEMETRY_RECONCILIATION_STATUS_INVALID/);
  assert.throws(() => sink.completeSpan(span.spanId, { success: true, errorClass: ' ' }), /TELEMETRY_SPAN_INPUT_INVALID/);
});

test('unknown span operations fail closed', () => {
  const sink = makeSink();
  assert.throws(() => sink.completeSpan('span-ghost', { success: true }), /TELEMETRY_SPAN_UNKNOWN/);
  assert.throws(() => sink.markAmbiguous('span-ghost'), /TELEMETRY_SPAN_UNKNOWN/);
  assert.throws(() => sink.updateReconciliation('span-ghost', 'RESOLVED'), /TELEMETRY_SPAN_UNKNOWN/);
});

// --- Ambiguity + reconciliation ---

test('markAmbiguous flags an unknown outcome for reconciliation', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  advance(50);
  const amb = sink.markAmbiguous(span.spanId, { errorClass: 'TRANSPORT', retryCount: 3 });
  assert.equal(amb.status, 'AMBIGUOUS');
  assert.equal(amb.success, null);
  assert.equal(amb.errorClass, 'TRANSPORT');
  assert.equal(amb.retryCount, 3);
  assert.equal(amb.reconciliationStatus, 'PENDING');
  assert.equal(amb.latencyMs, 50);
});

test('reconciliation status can be updated to RESOLVED / REQUIRED_UNRESOLVED', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  sink.markAmbiguous(span.spanId);
  const resolved = sink.updateReconciliation(span.spanId, 'RESOLVED');
  assert.equal(resolved.reconciliationStatus, 'RESOLVED');
  assert.equal(resolved.status, 'AMBIGUOUS');
  const stillOpen = sink.startSpan(SPAN_INPUT);
  sink.markAmbiguous(stillOpen.spanId);
  const required = sink.updateReconciliation(stillOpen.spanId, 'REQUIRED_UNRESOLVED');
  assert.equal(required.reconciliationStatus, 'REQUIRED_UNRESOLVED');
});

test('updateReconciliation rejects an invalid status', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  assert.throws(() => sink.updateReconciliation(span.spanId, 'DONE_MAYBE'), /TELEMETRY_RECONCILIATION_STATUS_INVALID/);
});

// --- Safe metadata discipline ---

test('forbidden metadata keys throw structurally (material + content)', () => {
  const sink = makeSink();
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { signature: 'leak' } }), /TELEMETRY_METADATA_KEY_FORBIDDEN_/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { payload: 'leak' } }), /TELEMETRY_METADATA_KEY_FORBIDDEN_/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { prompt: 'leak' } }), /TELEMETRY_METADATA_KEY_FORBIDDEN_/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { apiKey: 'leak' } }), /TELEMETRY_METADATA_KEY_FORBIDDEN_/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { content: 'leak' } }), /TELEMETRY_METADATA_KEY_FORBIDDEN_/);
});

test('non-allowlisted keys throw as unsafe', () => {
  const sink = makeSink();
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { arbitraryKey: 'x' } }), /TELEMETRY_METADATA_KEY_UNSAFE_/);
});

test('non-scalar and unbounded metadata values throw', () => {
  const sink = makeSink();
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { entityRef: { nested: true } } }), /TELEMETRY_METADATA_VALUE_INVALID/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { entityRef: ['x'] } }), /TELEMETRY_METADATA_VALUE_INVALID/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { entityRef: 'x'.repeat(300) } }), /TELEMETRY_METADATA_VALUE_TOO_LONG/);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { attempt: Infinity } }), /TELEMETRY_METADATA_VALUE_INVALID/);
});

test('registered secret material can never appear in metadata values', () => {
  const sink = makeSink([PARTNER_SECRET]);
  assert.throws(() => sink.startSpan({ ...SPAN_INPUT, metadata: { entityRef: `leaked-${PARTNER_SECRET}` } }), /TELEMETRY_SECRET_MATERIAL_DETECTED/);
});

test('null metadata values are preserved (explicit absence)', () => {
  const sink = makeSink();
  const span = sink.startSpan({ ...SPAN_INPUT, metadata: { entityRef: null } });
  assert.equal(span.safeMetadata.entityRef, null);
});

// --- Lookup ---

test('getSpan / findByRequestId / list retrieve spans', () => {
  const sink = makeSink();
  const a = sink.startSpan({ ...SPAN_INPUT, requestId: 'req-lookup-0001' });
  const b = sink.startSpan({ ...SPAN_INPUT, requestId: 'req-lookup-0001' });
  sink.startSpan({ ...SPAN_INPUT, requestId: 'req-lookup-0002' });
  assert.ok(sink.getSpan(a.spanId));
  assert.equal(sink.getSpan('span-ghost'), null);
  assert.equal(sink.findByRequestId('req-lookup-0001').length, 2);
  assert.equal(sink.findByRequestId('req-lookup-0002').length, 1);
  assert.equal(sink.list().length, 3);
  assert.equal(sink.findByRequestId('req-lookup-0001')[0].spanId, a.spanId);
  assert.equal(sink.findByRequestId('req-lookup-0001')[1].spanId, b.spanId);
});

test('completed spans are frozen', () => {
  const sink = makeSink();
  const span = sink.startSpan(SPAN_INPUT);
  const done = sink.completeSpan(span.spanId, { success: true });
  assert.equal(Object.isFrozen(done), true);
});
