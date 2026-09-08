// Stop Point 6 — provenance envelope + integrity tests.
//
// Hash exact governed output bytes; verify outputHash; bind metadata to the
// envelope with HMAC; fail closed on mismatch/tamper; detect missing
// provenance, classification mismatch, stale policy version, forbidden
// private-material fields, and preserve source references verbatim.

import test from 'node:test';
import assert from 'node:assert/strict';
import { GovernanceStore, SYNTHETIC_INTEGRITY_KEY } from '../store.ts';
import {
  createProvenanceEnvelope, verifyProvenanceEnvelope, boundEnvelopeValues,
} from '../provenance.ts';
import { computeOutputHash, computeIntegrityTag } from '../provenanceIntegrity.ts';
import { AI_MAY_TASK_TYPES } from '../classification.ts';
import { ACTIVE_POLICY_VERSION } from '../protectedActions.ts';
import {
  makeClock, makeStore, makeGovernedStore, provenanceInput, CLEAN_ADVISORY_OUTPUT,
  ADVISORY_ENGINE, RULE_ENGINE, HUMAN_ENGINE, ORG,
} from './helpers.mjs';

const SKEW = 5 * 60 * 1000;

test('provenance: valid advisory envelope creates, audits, and verifies', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const now = t.now();
  const envelope = createProvenanceEnvelope({
    store,
    governedOutput: CLEAN_ADVISORY_OUTPUT,
    input: provenanceInput(now),
  });
  assert.equal(envelope.designation, 'AI_ADVISORY');
  // The outputHash is over the EXACT governed output bytes.
  assert.equal(envelope.outputHash, computeOutputHash(CLEAN_ADVISORY_OUTPUT));
  assert.match(envelope.integrityTag, /^[a-f0-9]{64}$/);
  assert.equal(envelope.schemaVersion, 'ai-governance.provenance.v1');
  assert.equal(envelope.policyVersion, ACTIVE_POLICY_VERSION);
  // Advisory output can never carry a protected-action allowance.
  assert.equal(envelope.protectedActionAllowed, false);
  assert.ok(Object.isFrozen(envelope));
  // Creation is audited — identifiers + hash only, no content.
  const audit = store.auditLog.find(envelope.auditId);
  assert.ok(audit);
  assert.equal(audit.kind, 'governance.provenance.created');
  assert.equal(audit.reasonCode, 'ADVISORY_PROVENANCE_RECORDED');
  assert.equal(audit.details.provenanceId, envelope.provenanceId);
  assert.equal(audit.details.outputHash, envelope.outputHash);
  // The envelope is durable in the store.
  assert.deepEqual(store.getProvenanceEnvelope(envelope.provenanceId), envelope);
  // Verify passes, with and without the governed output bytes.
  assert.equal(verifyProvenanceEnvelope({ store, envelope }).ok, true);
  const withBytes = verifyProvenanceEnvelope({ store, envelope, governedOutput: CLEAN_ADVISORY_OUTPUT });
  assert.equal(withBytes.ok, true);
  assert.equal(withBytes.envelope.provenanceId, envelope.provenanceId);
});

test('provenance: every AI_MAY task type creates a valid advisory envelope', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  for (const taskType of AI_MAY_TASK_TYPES) {
    const envelope = createProvenanceEnvelope({
      store,
      governedOutput: CLEAN_ADVISORY_OUTPUT,
      input: provenanceInput(t.now(), { taskType }),
    });
    assert.equal(envelope.taskType, taskType, taskType);
    assert.equal(verifyProvenanceEnvelope({ store, envelope }).ok, true, taskType);
  }
});

test('provenance: missing provenance / structural failures fail closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // Missing envelope.
  assert.equal(verifyProvenanceEnvelope({ store, envelope: null }).reasonCode, 'PROVENANCE_MISSING');
  assert.equal(verifyProvenanceEnvelope({ store, envelope: undefined }).reasonCode, 'PROVENANCE_MISSING');
  assert.equal(verifyProvenanceEnvelope({ store, envelope: 'nope' }).reasonCode, 'PROVENANCE_MISSING');
  // Wrong schema version.
  const good = createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) });
  assert.equal(
    verifyProvenanceEnvelope({ store, envelope: { ...good, schemaVersion: 'ai-governance.provenance.v9' } }).reasonCode,
    'PROVENANCE_SCHEMA_UNSUPPORTED',
  );
  // Structure broken (missing required field).
  const { outputHash, ...stripped } = good;
  assert.equal(verifyProvenanceEnvelope({ store, envelope: stripped }).reasonCode, 'PROVENANCE_STRUCTURE_INVALID');
  // Output hash not hash-like.
  assert.equal(
    verifyProvenanceEnvelope({ store, envelope: { ...good, outputHash: 'not-a-hash' } }).reasonCode,
    'PROVENANCE_OUTPUT_HASH_INVALID',
  );
  // Integrity tag malformed (well-formed structure, non-hex tag).
  assert.equal(
    verifyProvenanceEnvelope({ store, envelope: { ...good, integrityTag: 'not-a-tag' } }).reasonCode,
    'INTEGRITY_TAG_MISSING',
  );
});

test('provenance: OUTPUT tamper — bytes changed after the fact fail closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const envelope = createProvenanceEnvelope({
    store,
    governedOutput: CLEAN_ADVISORY_OUTPUT,
    input: provenanceInput(t.now()),
  });
  // Same bytes verify.
  assert.equal(verifyProvenanceEnvelope({ store, envelope, governedOutput: CLEAN_ADVISORY_OUTPUT }).ok, true);
  // Bytes changed after the fact -> OUTPUT_TAMPERED.
  const tampered = verifyProvenanceEnvelope({
    store,
    envelope,
    governedOutput: CLEAN_ADVISORY_OUTPUT + ' (edited)',
  });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.reasonCode, 'OUTPUT_TAMPERED');
  // Non-string governed output fails closed structurally.
  assert.equal(
    verifyProvenanceEnvelope({ store, envelope, governedOutput: null }).reasonCode,
    'OUTPUT_BYTES_INVALID',
  );
});

test('provenance: METADATA tamper — any bound field edited fails closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const good = createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) });
  // Editing any HMAC-bound field breaks the tag -> METADATA_TAMPERED.
  const variants = [
    { ...good, engineVersion: 'v9.9.9' },
    { ...good, taskType: 'summarize' },
    { ...good, decisionReasonCode: 'SOMETHING_ELSE' },
    { ...good, confidence: 0.11 },
    { ...good, reviewingHumanId: 'human.someone-else-2' },
    { ...good, dataClassification: 'PUBLIC' },
    { ...good, orgRef: 'org-sandbox-2' },
    { ...good, sourceReferences: ['partner-feed:item-999'] },
    { ...good, requestCorrelationId: 'corr-9999' },
    { ...good, protectedActionRequested: false },
  ];
  for (const variant of variants) {
    const result = verifyProvenanceEnvelope({ store, envelope: variant });
    assert.equal(result.ok, false, JSON.stringify({ ...variant, integrityTag: undefined }));
    assert.equal(result.reasonCode, 'METADATA_TAMPERED');
  }
});

test('provenance: classification mismatch — AI output claiming the deterministic lane fails closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // Create path: an advisory engine may not produce deterministic-lane tasks.
  assert.throws(
    () => createProvenanceEnvelope({
      store,
      governedOutput: 'x',
      input: provenanceInput(t.now(), { taskType: 'policy_evaluation' }),
    }),
    /AI_TASK_TYPE_NOT_ALLOWED/,
  );
  // Verify path: an envelope claiming the deterministic designation.
  const good = createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) });
  const mislabeled = verifyProvenanceEnvelope({ store, envelope: { ...good, designation: 'DETERMINISTIC_RULE' } });
  assert.equal(mislabeled.ok, false);
  assert.equal(mislabeled.reasonCode, 'DESIGNATION_NOT_ADVISORY');
});

test('provenance: stale policy version fails closed (create and verify)', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // Create path.
  assert.throws(
    () => createProvenanceEnvelope({
      store,
      governedOutput: 'x',
      input: provenanceInput(t.now(), { policyVersion: 'ai-governance.policy.v0' }),
    }),
    /PROVENANCE_POLICY_VERSION_STALE/,
  );
  // Verify path: expected policy version mismatch.
  const good = createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) });
  const stale = verifyProvenanceEnvelope({
    store,
    envelope: good,
    expectedPolicyVersion: 'ai-governance.policy.v0',
  });
  assert.equal(stale.ok, false);
  assert.equal(stale.reasonCode, 'PROVENANCE_POLICY_VERSION_STALE');
});

test('provenance: unknown engine / version mismatch fail closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  assert.throws(
    () => createProvenanceEnvelope({
      store,
      governedOutput: 'x',
      input: provenanceInput(t.now(), { engineId: 'ghost-engine-1' }),
    }),
    /PROVENANCE_ENGINE_UNKNOWN/,
  );
  const good = createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) });
  // Edit engineVersion WITHOUT re-signing -> the tamper is detected first.
  assert.equal(
    verifyProvenanceEnvelope({ store, envelope: { ...good, engineVersion: 'v9.9.9' } }).reasonCode,
    'METADATA_TAMPERED',
  );
  // Re-sign the tampered envelope (sandbox key) to reach the registry check:
  // the version no longer matches the registered engine.
  const edited = { ...good, engineVersion: 'v9.9.9' };
  edited.integrityTag = computeIntegrityTag(boundEnvelopeValues(edited), SYNTHETIC_INTEGRITY_KEY);
  assert.equal(
    verifyProvenanceEnvelope({ store, envelope: edited }).reasonCode,
    'PROVENANCE_ENGINE_VERSION_MISMATCH',
  );
  // Engine dropped from registry after issuance: a store that never
  // registered the advisory engine fails closed on the engine lookup.
  const t2 = makeClock();
  const store2 = new GovernanceStore({ clock: t2.clock });
  store2.registerEngine({ ...ADVISORY_ENGINE });
  const env2 = createProvenanceEnvelope({ store: store2, governedOutput: 'x', input: provenanceInput(t2.now()) });
  const store3 = new GovernanceStore({ clock: makeClock().clock });
  // Two non-advisory engines: the audit id of env2 resolves (same audit
  // sequence) but the advisory engine is unknown in this registry.
  store3.registerEngine({ ...RULE_ENGINE });
  store3.registerEngine({ ...HUMAN_ENGINE });
  assert.equal(verifyProvenanceEnvelope({ store: store3, envelope: env2 }).reasonCode, 'PROVENANCE_ENGINE_UNKNOWN');
});

test('provenance: forbidden private-material fields fail closed at create AND verify', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // Create path: private material may never ride on the envelope.
  for (const [key, value] of [
    ['prompt', 'you are a helpful assistant'],
    ['systemPrompt', 'private system prompt text'],
    ['chainOfThought', 'step by step private reasoning'],
    ['modelProvider', 'some-private-provider'],
    ['apiKey', 'sk-0000'],
    ['signingKey', 'key-material'],
  ]) {
    assert.throws(
      () => createProvenanceEnvelope({
        store,
        governedOutput: 'x',
        input: provenanceInput(t.now(), { [key]: value }),
      }),
      /PROVENANCE_FORBIDDEN_FIELD_/,
      key,
    );
  }
  // Verify path: smuggled private-material key on the envelope.
  const good = createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) });
  const smuggled = verifyProvenanceEnvelope({ store, envelope: { ...good, modelProvider: 'x' } });
  assert.equal(smuggled.ok, false);
  assert.equal(smuggled.reasonCode, 'PROVENANCE_FORBIDDEN_FIELD_MODELPROVIDER');
});

test('provenance: reviewer identity on the envelope must be human (never AI/system identity)', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // AI/system identities can never stand in as the human reviewer.
  for (const reviewingHumanId of ['ai-assistant-1', 'system-reviewer', 'agent-007', 'bot-operator']) {
    assert.throws(
      () => createProvenanceEnvelope({
        store,
        governedOutput: 'x',
        input: provenanceInput(t.now(), { reviewingHumanId }),
      }),
      /PROVENANCE_REVIEWER_MUST_BE_HUMAN/,
      reviewingHumanId,
    );
  }
  // Reviewer fields are only allowed when human review is required.
  assert.throws(
    () => createProvenanceEnvelope({
      store,
      governedOutput: 'x',
      input: provenanceInput(t.now(), {
        humanReviewRequired: false,
        reviewingHumanId: 'human.reviewer-1',
        reviewTimestamp: t.now(),
      }),
    }),
    /PROVENANCE_REVIEWER_FIELDS_UNEXPECTED/,
  );
  // When review is required the reviewer linkage must be complete.
  assert.throws(
    () => createProvenanceEnvelope({
      store,
      governedOutput: 'x',
      input: provenanceInput(t.now(), { reviewingHumanId: undefined, reviewTimestamp: undefined }),
    }),
    /PROVENANCE_INPUT_INVALID/,
  );
});

test('provenance: freshness — timestamps outside the skew window fail closed', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  // Stale (too old).
  assert.throws(
    () => createProvenanceEnvelope({
      store,
      governedOutput: 'x',
      input: provenanceInput(t.now() - SKEW - 1),
    }),
    /PROVENANCE_TIMESTAMP_OUT_OF_RANGE/,
  );
  // From the future.
  assert.throws(
    () => createProvenanceEnvelope({
      store,
      governedOutput: 'x',
      input: provenanceInput(t.now() + SKEW + 1),
    }),
    /PROVENANCE_TIMESTAMP_OUT_OF_RANGE/,
  );
  // Exactly at the boundary passes (<= skew).
  const boundary = createProvenanceEnvelope({
    store,
    governedOutput: 'x',
    input: provenanceInput(t.now() - SKEW),
  });
  assert.equal(verifyProvenanceEnvelope({ store, envelope: boundary }).ok, true);
});

test('provenance: source references are preserved verbatim (frozen, exact)', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const input = provenanceInput(t.now(), {
    sourceReferences: ['partner-feed:item-001', 'partner-feed:item-002', 'audit:CASE-42'],
  });
  const envelope = createProvenanceEnvelope({ store, governedOutput: 'x', input });
  // Preserved exactly, in order, frozen.
  assert.deepEqual(envelope.sourceReferences, ['partner-feed:item-001', 'partner-feed:item-002', 'audit:CASE-42']);
  assert.ok(Object.isFrozen(envelope.sourceReferences));
  // Editing the references on the envelope breaks the binding.
  const edited = verifyProvenanceEnvelope({
    store,
    envelope: { ...envelope, sourceReferences: ['partner-feed:item-001'] },
  });
  assert.equal(edited.reasonCode, 'METADATA_TAMPERED');
});

test('provenance: no envelope duplication — store rejects provenance id collisions', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const first = createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) });
  const second = createProvenanceEnvelope({ store, governedOutput: 'y', input: provenanceInput(t.now()) });
  assert.notEqual(first.provenanceId, second.provenanceId);
  // Attempting to re-file an existing provenance id fails closed.
  assert.throws(() => store.putProvenanceEnvelope(first), /STORE_PROVENANCE_ID_COLLISION/);
});
