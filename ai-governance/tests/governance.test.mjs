// Stop Point 6 — governance vocabulary, registry, audit, and store tests.
//
// The five designations and four engine classes are the exact vocabulary;
// engine registration is structural fail closed; the audit log is
// metadata-only and append-only by construction; the protected-action
// registry lists exactly the ten owner-specified actions; the store ships
// synthetic sandbox material only.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DESIGNATIONS, ENGINE_CLASSES, AI_MAY_TASK_TYPES, DETERMINISTIC_TASK_TYPES,
  EXTERNAL_DATA_DESIGNATION, checkEngineDesignation,
} from '../classification.ts';
import { GovernanceStore, SYNTHETIC_INTEGRITY_KEY } from '../store.ts';
import { AuditLog } from '../audit.ts';
import {
  PROTECTED_ACTION_KINDS, PROTECTED_ACTION_POLICIES, ACTIVE_POLICY_VERSION,
} from '../protectedActions.ts';
import { createProvenanceEnvelope } from '../provenance.ts';
import { guardAiOutput } from '../aiOutputGuard.ts';
import {
  makeClock, makeStore, makeGovernedStore, provenanceInput, CLEAN_ADVISORY_OUTPUT,
  ADVISORY_ENGINE, RULE_ENGINE, HUMAN_ENGINE, SYSTEM_ENGINE, ORG,
} from './helpers.mjs';

test('governance: the five designations and four engine classes are the exact vocabulary', () => {
  assert.deepEqual(DESIGNATIONS, [
    'AI_ADVISORY',
    'DETERMINISTIC_RULE',
    'HUMAN_AUTHORIZATION',
    'SYSTEM_AUTOMATION',
    'EXTERNAL_PARTNER_DATA',
  ]);
  assert.deepEqual(ENGINE_CLASSES, [
    'GENERATIVE_AI',
    'DETERMINISTIC_RULE_ENGINE',
    'HUMAN_OPERATOR_CONSOLE',
    'SYSTEM_AUTOMATION_ENGINE',
  ]);
  assert.deepEqual(AI_MAY_TASK_TYPES, [
    'analyze', 'summarize', 'classify', 'recommend',
    'identify_issues', 'flag_for_review', 'advise',
  ]);
  assert.deepEqual(DETERMINISTIC_TASK_TYPES, ['policy_evaluation']);
  // External partner data is DATA — a designation, never an engine lane.
  assert.equal(EXTERNAL_DATA_DESIGNATION, 'EXTERNAL_PARTNER_DATA');
  assert.ok(DESIGNATIONS.includes(EXTERNAL_DATA_DESIGNATION));
  assert.ok(!ENGINE_CLASSES.includes('EXTERNAL_PARTNER_DATA_ENGINE'));
});

test('governance: AI engine registration is pinned advisory-only, structural fail closed', () => {
  const t = makeClock();
  const store = makeStore(t);
  // A generative AI engine that is not advisory-only cannot register.
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE, advisoryOnly: false }), /AI_ENGINE_MUST_BE_ADVISORY_ONLY/);
  // A generative AI engine on any other designation cannot register.
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE, designation: 'DETERMINISTIC_RULE' }), /DESIGNATION_ENGINE_CLASS_MISMATCH/);
  // A deterministic engine can never claim advisory.
  assert.throws(() => store.registerEngine({ ...RULE_ENGINE, advisoryOnly: true }), /DETERMINISTIC_ENGINE_CANNOT_BE_ADVISORY/);
  // No engine may claim the external-data designation as its own lane.
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE, designation: 'EXTERNAL_PARTNER_DATA' }), /ENGINE_CANNOT_REGISTER_EXTERNAL_DATA/);
  assert.throws(() => store.registerEngine({ ...RULE_ENGINE, designation: 'EXTERNAL_PARTNER_DATA' }), /ENGINE_CANNOT_REGISTER_EXTERNAL_DATA/);
  // Structural failures.
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE, engineClass: 'MAGIC_ENGINE' }), /ENGINE_CLASS_UNKNOWN/);
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE, engineId: 'x' }), /ENGINE_ID_INVALID/);
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE, engineVersion: '' }), /ENGINE_VERSION_INVALID/);
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE, advisoryOnly: 'yes' }), /ENGINE_ADVISORY_ONLY_FLAG_INVALID/);
  assert.throws(() => store.registerEngine(null), /ENGINE_REGISTRATION_INVALID/);
});

test('governance: all four engine classes register cleanly on their one legal lane', () => {
  const t = makeClock();
  const store = makeStore(t);
  const before = store.listAudit().length;
  for (const fixture of [ADVISORY_ENGINE, RULE_ENGINE, HUMAN_ENGINE, SYSTEM_ENGINE]) {
    const engine = store.registerEngine({ ...fixture });
    assert.equal(engine.engineId, fixture.engineId);
    assert.equal(engine.designation, fixture.designation);
    assert.equal(engine.advisoryOnly, fixture.advisoryOnly);
    assert.equal(engine.registeredAt, t.now());
    assert.ok(Object.isFrozen(engine));
    // getEngine returns the same registration; the registry is durable.
    assert.deepEqual(store.getEngine(fixture.engineId), engine);
  }
  // Re-registration fails closed — no silent rebinding of an engine identity.
  assert.throws(() => store.registerEngine({ ...ADVISORY_ENGINE }), /ENGINE_ALREADY_REGISTERED/);
  // Every registration is audited.
  const registrations = store.listAudit().filter((r) => r.kind === 'governance.engine.registered');
  assert.equal(registrations.length, 4);
  assert.equal(store.listAudit().length, before + 4);
  for (const record of registrations) {
    assert.equal(record.reasonCode, 'ENGINE_REGISTERED');
    assert.ok(record.details.designation);
  }
});

test('governance: designation checks pass on the legal lane and fail closed on every mismatch', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const advisory = store.getEngine(ADVISORY_ENGINE.engineId);
  const rule = store.getEngine(RULE_ENGINE.engineId);
  const human = store.getEngine(HUMAN_ENGINE.engineId);
  const system = store.getEngine(SYSTEM_ENGINE.engineId);

  // The one legal lane per engine class.
  assert.deepEqual(checkEngineDesignation(advisory, 'AI_ADVISORY', 'analyze'), { ok: true, designation: 'AI_ADVISORY' });
  assert.deepEqual(checkEngineDesignation(rule, 'DETERMINISTIC_RULE', 'policy_evaluation'), { ok: true, designation: 'DETERMINISTIC_RULE' });
  assert.deepEqual(checkEngineDesignation(human, 'HUMAN_AUTHORIZATION', 'operator_decision'), { ok: true, designation: 'HUMAN_AUTHORIZATION' });
  assert.deepEqual(checkEngineDesignation(system, 'SYSTEM_AUTOMATION', 'batch_job'), { ok: true, designation: 'SYSTEM_AUTOMATION' });

  // AI claiming the deterministic lane, and vice versa.
  assert.equal(checkEngineDesignation(advisory, 'DETERMINISTIC_RULE', 'analyze').reasonCode, 'AI_OUTPUT_MISLABELED_DETERMINISTIC');
  assert.equal(checkEngineDesignation(rule, 'AI_ADVISORY', 'analyze').reasonCode, 'DETERMINISTIC_OUTPUT_MISLABELED_AI');
  // No engine may claim external data as its output designation.
  assert.equal(checkEngineDesignation(advisory, 'EXTERNAL_PARTNER_DATA', 'analyze').reasonCode, 'ENGINE_CANNOT_CLAIM_EXTERNAL_DATA');
  assert.equal(checkEngineDesignation(rule, 'EXTERNAL_PARTNER_DATA', 'policy_evaluation').reasonCode, 'ENGINE_CANNOT_CLAIM_EXTERNAL_DATA');
  // Cross-lane designation mismatches.
  assert.equal(checkEngineDesignation(advisory, 'HUMAN_AUTHORIZATION', 'analyze').reasonCode, 'DESIGNATION_ENGINE_CLASS_MISMATCH');
  assert.equal(checkEngineDesignation(human, 'AI_ADVISORY', 'analyze').reasonCode, 'DESIGNATION_ENGINE_CLASS_MISMATCH');
  assert.equal(checkEngineDesignation(system, 'DETERMINISTIC_RULE', 'batch_job').reasonCode, 'DESIGNATION_ENGINE_CLASS_MISMATCH');
  // Task-type boundaries.
  assert.equal(checkEngineDesignation(advisory, 'AI_ADVISORY', 'policy_evaluation').reasonCode, 'AI_TASK_TYPE_NOT_ALLOWED');
  assert.equal(checkEngineDesignation(advisory, 'AI_ADVISORY', 'deploy_to_production').reasonCode, 'TASK_TYPE_INVALID');
  assert.equal(checkEngineDesignation(rule, 'DETERMINISTIC_RULE', 'analyze').reasonCode, 'DETERMINISTIC_TASK_TYPE_NOT_ALLOWED');
  assert.equal(checkEngineDesignation(rule, 'DETERMINISTIC_RULE', 'nonsense').reasonCode, 'TASK_TYPE_INVALID');
  // Defense in depth: an advisory-flagged engine that somehow lost its
  // advisoryOnly pin still fails closed.
  const unpinned = { ...advisory, advisoryOnly: false };
  assert.equal(checkEngineDesignation(unpinned, 'AI_ADVISORY', 'analyze').reasonCode, 'AI_ENGINE_NOT_ADVISORY_ONLY');
});

test('governance: every AI_MAY task type passes the advisory lane; non-AI_MAY fails', () => {
  const t = makeClock();
  const store = makeGovernedStore(t);
  const advisory = store.getEngine(ADVISORY_ENGINE.engineId);
  for (const taskType of AI_MAY_TASK_TYPES) {
    assert.deepEqual(checkEngineDesignation(advisory, 'AI_ADVISORY', taskType), { ok: true, designation: 'AI_ADVISORY' }, taskType);
    // End to end through the AI output guard on the same lane.
    const guarded = guardAiOutput(store, {
      engineId: ADVISORY_ENGINE.engineId,
      orgRef: ORG,
      output: CLEAN_ADVISORY_OUTPUT,
      taskType,
    });
    assert.equal(guarded.ok, true, taskType);
    assert.equal(guarded.reasonCode, 'AI_ADVISORY_OUTPUT_ALLOWED', taskType);
  }
  // Anything outside AI_MAY is not an approved AI task in v1.
  assert.throws(
    () => guardAiOutput(store, {
      engineId: ADVISORY_ENGINE.engineId,
      orgRef: ORG,
      output: CLEAN_ADVISORY_OUTPUT,
      taskType: 'policy_evaluation',
    }),
    /AI_TASK_TYPE_NOT_ALLOWED/,
  );
  assert.throws(
    () => guardAiOutput(store, {
      engineId: ADVISORY_ENGINE.engineId,
      orgRef: ORG,
      output: CLEAN_ADVISORY_OUTPUT,
      taskType: 'authorize_disclosures',
    }),
    /TASK_TYPE_INVALID/,
  );
});

test('governance: protected-action registry lists exactly the owner-specified ten actions', () => {
  const actions = Object.values(PROTECTED_ACTION_POLICIES);
  assert.equal(actions.length, PROTECTED_ACTION_KINDS.length);
  assert.equal(actions.length, 10);
  assert.deepEqual(
    actions.map((a) => a.action).sort(),
    [
      'ADMIN_GRANT', 'AUDIT_MUTATION', 'ENTITLEMENT_OVERRIDE', 'EVIDENCE_DESTRUCTION',
      'LAW_SHIELD_DISCLOSURE', 'PARTNER_CREDENTIAL_CHANGE', 'PROTECTED_PARTNER_ACTIVATION_OVERRIDE',
      'RBAC_CHANGE', 'SECURITY_POLICY_OVERRIDE', 'TENANT_OWNERSHIP_CHANGE',
    ].sort(),
  );
  for (const spec of actions) {
    assert.equal(spec.requiredPolicyVersion, ACTIVE_POLICY_VERSION, spec.action);
    assert.equal(spec.humanReviewRequired, true, spec.action);
    assert.equal(spec.aiProhibited, true, spec.action);
    assert.equal(spec.auditRequired, true, spec.action);
    assert.equal(spec.failClosedResult, 'DENIED', spec.action);
    // AI is never an allowed actor class on any protected action.
    assert.equal(spec.allowedActorClasses.includes('AI'), false, spec.action);
  }
});

test('governance: audit records are metadata-only by construction (secrets/keys/prompt keys throw)', () => {
  const t = makeClock();
  const store = makeStore(t);
  const good = store.recordAudit({ kind: 'governance.test.probe', subjectId: 'subject-1', reasonCode: 'PROBE', details: { count: 1, flag: true, ref: 'partner-feed:item-001' } });
  assert.ok(good.auditId.startsWith('AUD-'));
  // Material keys throw at record time — regardless of value.
  for (const key of ['prompt', 'systemPrompt', 'apiKey', 'modelKey', 'modelProvider', 'token', 'credential', 'credentials', 'signingKey', 'secret', 'chainOfThought', 'password', 'privateKey', 'model']) {
    assert.throws(
      () => store.recordAudit({ kind: 'k', subjectId: 's', reasonCode: 'r', details: { [key]: 'anything' } }),
      new RegExp(`AUDIT_MATERIAL_DETAIL_KEY_`),
      key,
    );
  }
  // Content keys throw — audit carries identifiers and hashes only.
  for (const key of ['output', 'content', 'payload', 'result', 'message', 'body', 'text']) {
    assert.throws(
      () => store.recordAudit({ kind: 'k', subjectId: 's', reasonCode: 'r', details: { [key]: 'anything' } }),
      /AUDIT_CONTENT_DETAIL_KEY_/,
      key,
    );
  }
  // Registered secret VALUES can never appear in any detail value.
  assert.throws(
    () => store.recordAudit({
      kind: 'k', subjectId: 's', reasonCode: 'r',
      details: { note: `leaked ${SYNTHETIC_INTEGRITY_KEY} in a note` },
    }),
    /AUDIT_SECRET_MATERIAL_DETECTED/,
  );
});

test('governance: audit is append-only — mutation attempts are refused AND audited', () => {
  const t = makeClock();
  const store = makeStore(t);
  const original = store.recordAudit({ kind: 'governance.test.probe', subjectId: 'subject-1', reasonCode: 'PROBE', details: { count: 1 } });
  const before = store.listAudit().length;
  const result = store.auditLog.attemptMutation(original.auditId, { reasonCode: 'REDACTED' });
  assert.equal(result.ok, false);
  assert.equal(result.reasonCode, 'AUDIT_MUTATION_REFUSED');
  // The refusal itself is a NEW audit record; history only grows.
  assert.equal(store.listAudit().length, before + 1);
  const refusal = store.listAudit().find((r) => r.kind === 'governance.audit.mutation_denied');
  assert.ok(refusal);
  assert.equal(refusal.subjectId, original.auditId);
  // The original record is untouched — deep-equal, frozen.
  assert.deepEqual(store.auditLog.find(original.auditId), original);
});

test('governance: governance store policy version and synthetic key are sandbox material only', () => {
  const t = makeClock();
  const store = new GovernanceStore({ clock: t.clock });
  assert.equal(store.policyVersion, 'ai-governance.policy.v1');
  assert.equal(store.policyVersion, ACTIVE_POLICY_VERSION);
  // The shipped key is explicitly synthetic sandbox material, never a secret.
  assert.equal(store.integrityKey, SYNTHETIC_INTEGRITY_KEY);
  assert.ok(SYNTHETIC_INTEGRITY_KEY.startsWith('SYNTHETIC-'));
  assert.ok(SYNTHETIC_INTEGRITY_KEY.includes('NOT-PRODUCTION'));
  // Production deployments inject their own key material.
  const custom = new GovernanceStore({ clock: t.clock, integrityKey: 'production-operator-key-material-0' });
  assert.equal(custom.integrityKey, 'production-operator-key-material-0');
  assert.notEqual(custom.integrityKey, SYNTHETIC_INTEGRITY_KEY);
  // Structural failures on store construction.
  assert.throws(() => new GovernanceStore({ clock: t.clock, policyVersion: '' }), /STORE_POLICY_VERSION_INVALID/);
  assert.throws(() => new GovernanceStore({ clock: t.clock, integrityKey: 'short' }), /STORE_INTEGRITY_KEY_INVALID/);
  // An audit log without a clock is refused — timestamps are mandatory.
  assert.throws(() => new AuditLog({ clock: null }), /AUDIT_CLOCK_REQUIRED/);
});

test('governance: unknown engine on the advisory path fails closed (PROVENANCE_ENGINE_UNKNOWN)', () => {
  const t = makeClock();
  const store = makeStore(t);
  // Nothing is registered in this store — the advisory path fails closed.
  assert.equal(store.getEngine('ghost-engine-1'), null);
  assert.throws(
    () => createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now(), { engineId: 'ghost-engine-1' }) }),
    /PROVENANCE_ENGINE_UNKNOWN/,
  );
  // Even the fixture advisory engine is unknown until registered.
  assert.throws(
    () => createProvenanceEnvelope({ store, governedOutput: 'x', input: provenanceInput(t.now()) }),
    /PROVENANCE_ENGINE_UNKNOWN/,
  );
  // The AI output guard fails closed on unregistered engines too.
  assert.throws(
    () => guardAiOutput(store, { engineId: ADVISORY_ENGINE.engineId, orgRef: ORG, output: CLEAN_ADVISORY_OUTPUT, taskType: 'analyze' }),
    /AI_OUTPUT_ENGINE_ID_INVALID/,
  );
});
