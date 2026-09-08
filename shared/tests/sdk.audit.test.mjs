// Stop Point 7 — shared SDK integration audit trail tests.
//
// Proves the integration audit contract: metadata-only allowlisted detail
// keys, bounded scalar values, provenance bound by ID + outputHash only,
// append-only semantics inherited from the SP6 governance AuditLog, and
// mutation always refused AND audited.

import test from 'node:test';
import assert from 'node:assert/strict';
import { IntegrationAuditTrail, AuditLog } from '../sdk/audit.ts';
import { makeClock } from './helpers.mjs';

const { clock, now, advance } = makeClock(1_700_000_000_000);

function makeTrail(secretValues = []) {
  const log = new AuditLog({ clock, secretValues });
  const trail = new IntegrationAuditTrail(log);
  return { log, trail };
}

// --- Construction ---

test('IntegrationAuditTrail requires a real AuditLog (fail closed)', () => {
  assert.throws(() => new IntegrationAuditTrail({}), /AUDIT_LOG_REQUIRED/);
  assert.throws(() => new IntegrationAuditTrail(null), /AUDIT_LOG_REQUIRED/);
});

// --- Recording ---

test('record appends a metadata-only entry and the log lists it', () => {
  const { trail } = makeTrail();
  trail.record({
    kind: 'integration.request.verified',
    subjectId: 'req-verified-0001',
    reasonCode: 'SIGNATURE_VALID',
    details: { partnerId: 'partner-sandbox-1', signatureValid: true, latencyMs: 42 },
    orgRef: 'org-sandbox-1',
  });
  const entries = trail.list();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].kind, 'integration.request.verified');
  assert.equal(entries[0].subjectId, 'req-verified-0001');
  assert.equal(entries[0].reasonCode, 'SIGNATURE_VALID');
  assert.equal(entries[0].details.signatureValid, true);
  assert.equal(entries[0].details.latencyMs, 42);
  assert.equal(entries[0].orgRef, 'org-sandbox-1');
});

test('record rejects malformed entries (fail closed)', () => {
  const { trail } = makeTrail();
  assert.throws(() => trail.record(null), /AUDIT_ENTRY_INVALID/);
  assert.throws(() => trail.record({}), /AUDIT_ENTRY_INVALID/);
  assert.throws(() => trail.record({ kind: '', subjectId: 's', reasonCode: 'R' }), /AUDIT_ENTRY_INVALID/);
  assert.throws(() => trail.record({ kind: 'k', subjectId: '', reasonCode: 'R' }), /AUDIT_ENTRY_INVALID/);
  assert.throws(() => trail.record({ kind: 'k', subjectId: 's', reasonCode: '   ' }), /AUDIT_ENTRY_INVALID/);
});

// --- Detail allowlist discipline ---

test('unsafe detail keys throw structurally at record time', () => {
  const { trail } = makeTrail();
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    details: { prompt: 'never-here' },
  }), /AUDIT_DETAIL_KEY_UNSAFE/);
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    details: { output: 'never-here' },
  }), /AUDIT_DETAIL_KEY_UNSAFE/);
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    details: { apiKey: 'never-here' },
  }), /AUDIT_DETAIL_KEY_UNSAFE/);
});

test('non-scalar and unbounded detail values throw', () => {
  const { trail } = makeTrail();
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    details: { requestId: { nested: true } },
  }), /AUDIT_DETAIL_VALUE_INVALID/);
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    details: { requestId: ['array'] },
  }), /AUDIT_DETAIL_VALUE_INVALID/);
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    details: { requestId: 'x'.repeat(300) },
  }), /AUDIT_DETAIL_VALUE_TOO_LONG/);
});

test('null detail values are preserved (explicit absence)', () => {
  const { trail } = makeTrail();
  trail.record({ kind: 'k', subjectId: 's', reasonCode: 'R', details: { entityRef: null } });
  assert.equal(trail.list()[0].details.entityRef, null);
});

test('registered secret material can never appear in a detail value', () => {
  const { trail } = makeTrail(['synthetic-partner-signing-secret-SP7-sandbox']);
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    details: { requestId: 'leaked-synthetic-partner-signing-secret-SP7-sandbox' },
  }), /AUDIT_SECRET_MATERIAL_DETECTED/);
});

// --- Provenance binding ---

test('provenance binds by metadata only: provenanceId + 64-hex outputHash', () => {
  const { trail } = makeTrail();
  trail.record({
    kind: 'integration.provenance.bound',
    subjectId: 'req-prov-0001',
    reasonCode: 'PROVENANCE_BOUND',
    provenance: { provenanceId: 'prov-0001', outputHash: 'a'.repeat(64) },
  });
  const rec = trail.list()[0];
  assert.equal(rec.details.provenanceId, 'prov-0001');
  assert.equal(rec.details.outputHash, 'a'.repeat(64));
});

test('malformed provenance references fail closed', () => {
  const { trail } = makeTrail();
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    provenance: { provenanceId: '', outputHash: 'a'.repeat(64) },
  }), /AUDIT_PROVENANCE_REF_INVALID/);
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    provenance: { provenanceId: 'p', outputHash: 'not-hex' },
  }), /AUDIT_PROVENANCE_REF_INVALID/);
  assert.throws(() => trail.record({
    kind: 'k', subjectId: 's', reasonCode: 'R',
    provenance: { provenanceId: 'p' },
  }), /AUDIT_PROVENANCE_REF_INVALID/);
});

// --- Append-only semantics ---

test('mutation is refused AND audited', () => {
  const { trail } = makeTrail();
  trail.record({ kind: 'k', subjectId: 's', reasonCode: 'R' });
  const before = trail.list().length;
  const auditId = trail.list()[0].auditId;
  const result = trail.attemptMutation(auditId, { reasonCode: 'TAMPERED' });
  assert.equal(result.ok, false);
  assert.equal(typeof result.reasonCode, 'string');
  // The refusal itself is appended to the log.
  const after = trail.list();
  assert.equal(after.length, before + 1);
  assert.equal(after[0].reasonCode, 'R'); // original untouched
});

test('find retrieves an appended record by auditId', () => {
  const { trail } = makeTrail();
  trail.record({ kind: 'k', subjectId: 'subject-find-0001', reasonCode: 'R' });
  const auditId = trail.list()[0].auditId;
  const rec = trail.find(auditId);
  assert.ok(rec);
  assert.equal(rec.subjectId, 'subject-find-0001');
  assert.equal(trail.find('AUD-000000'), null);
});

test('audit timestamps come from the injected clock and sequence ids are AUD-XXXXXX', () => {
  const { trail } = makeTrail();
  trail.record({ kind: 'k', subjectId: 's1', reasonCode: 'R' });
  advance(1_500);
  trail.record({ kind: 'k', subjectId: 's2', reasonCode: 'R' });
  const entries = trail.list();
  assert.match(entries[0].auditId, /^AUD-[0-9]{6}$/);
  assert.match(entries[1].auditId, /^AUD-[0-9]{6}$/);
  assert.equal(entries[1].at - entries[0].at, 1_500);
  assert.equal(entries[0].at, now() - 1_500);
});

test('records are frozen (no in-place tampering)', () => {
  const { trail } = makeTrail();
  trail.record({ kind: 'k', subjectId: 's', reasonCode: 'R' });
  const rec = trail.list()[0];
  assert.equal(Object.isFrozen(rec), true);
});
