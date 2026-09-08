// Stop Point 7 — partner registry contract tests.
//
// Proves the single source of truth: org -> partner -> entitlement ->
// capability -> status -> API version window, with every unknown, suspended,
// revoked, expired, or malformed element failing closed with a typed code —
// partner logic is never hardcoded.

import test from 'node:test';
import assert from 'node:assert/strict';
import { PartnerRegistry } from '../registry/partnerRegistry.ts';
import {
  PARTNER_ID, ORG_ID, OTHER_ORG_ID, CAPABILITY, ENTITLEMENT,
  partnerRecordFixture, orgRecordFixture, makeClock,
} from './helpers.mjs';

const { clock, now, advance } = makeClock(1_700_000_000_000);

function makeRegistry(overrides = {}) {
  const registry = new PartnerRegistry({ now });
  registry.registerPartner(partnerRecordFixture(overrides.partner));
  registry.registerOrg(orgRecordFixture(overrides.org));
  return registry;
}

const resolveInput = (overrides = {}) => ({
  partnerId: PARTNER_ID, orgId: ORG_ID, entitlement: ENTITLEMENT, capability: CAPABILITY, ...overrides,
});

// --- Happy path ---

test('resolve succeeds for the synthetic sandbox chain', () => {
  const registry = makeRegistry();
  const r = registry.resolve(resolveInput());
  assert.deepEqual(r, {
    ok: true,
    partnerId: PARTNER_ID,
    orgId: ORG_ID,
    entitlement: ENTITLEMENT,
    capability: CAPABILITY,
    apiVersionWindow: { min: 'v1', max: 'v2' },
  });
});

// --- Partner-level failures ---

test('an unknown or malformed partner id fails closed', () => {
  const registry = makeRegistry();
  assert.deepEqual(registry.resolve(resolveInput({ partnerId: 'partner-ghost-99' })), { ok: false, code: 'PARTNER_UNKNOWN' });
  assert.deepEqual(registry.resolve(resolveInput({ partnerId: '' })), { ok: false, code: 'PARTNER_UNKNOWN' });
  assert.deepEqual(registry.resolve(resolveInput({ partnerId: 'x' })), { ok: false, code: 'PARTNER_UNKNOWN' }); // too short
  assert.deepEqual(registry.resolve(null), { ok: false, code: 'PARTNER_UNKNOWN' });
});

test('a suspended or revoked partner fails closed', () => {
  const suspended = makeRegistry({ partner: { status: 'SUSPENDED' } });
  assert.equal(suspended.resolve(resolveInput()).code, 'PARTNER_SUSPENDED');
  const revoked = makeRegistry({ partner: { status: 'REVOKED' } });
  assert.equal(revoked.resolve(resolveInput()).code, 'PARTNER_REVOKED');
});

// --- Org-level failures ---

test('an unknown or suspended org fails closed', () => {
  const registry = makeRegistry();
  assert.equal(registry.resolve(resolveInput({ orgId: 'org-ghost-99' })).code, 'ORG_UNKNOWN');
  assert.equal(registry.resolve(resolveInput({ orgId: '' })).code, 'ORG_UNKNOWN');
  const suspendedOrg = makeRegistry({ org: { status: 'SUSPENDED' } });
  assert.equal(suspendedOrg.resolve(resolveInput()).code, 'ORG_SUSPENDED');
});

test('an org not bound to the partner fails closed', () => {
  const registry = makeRegistry();
  const other = orgRecordFixture({ orgId: OTHER_ORG_ID, partnerBindings: [] });
  registry.registerOrg(other);
  assert.equal(registry.resolve(resolveInput({ orgId: OTHER_ORG_ID })).code, 'ORG_NOT_BOUND_TO_PARTNER');
});

test('an inactive binding fails closed', () => {
  const registry = makeRegistry();
  registry.registerOrg(orgRecordFixture({
    partnerBindings: [{ partnerId: PARTNER_ID, status: 'INACTIVE', entitlements: [ENTITLEMENT] }],
  }));
  assert.equal(registry.resolve(resolveInput()).code, 'BINDING_INACTIVE');
});

test('a binding without the entitlement fails closed (BINDING_UNKNOWN)', () => {
  const registry = makeRegistry();
  registry.registerOrg(orgRecordFixture({
    partnerBindings: [{ partnerId: PARTNER_ID, status: 'ACTIVE', entitlements: [] }],
  }));
  assert.equal(registry.resolve(resolveInput()).code, 'BINDING_UNKNOWN');
});

// --- Entitlement failures ---

test('entitlement missing on the partner fails closed', () => {
  const registry = makeRegistry({ partner: { entitlements: [] } });
  assert.equal(registry.resolve(resolveInput()).code, 'ENTITLEMENT_MISSING');
});

test('an inactive, revoked, or expired entitlement fails closed', () => {
  for (const status of ['INACTIVE', 'REVOKED', 'EXPIRED']) {
    const registry = makeRegistry({ partner: { entitlements: [{ entitlement: ENTITLEMENT, status, capabilities: [{ capability: CAPABILITY, minApiVersion: 'v1', maxApiVersion: 'v2' }] }] } });
    assert.equal(registry.resolve(resolveInput()).code, `ENTITLEMENT_${status}`, status);
  }
});

test('validUntil expiry is enforced against the injected clock', () => {
  const registry = makeRegistry({ partner: { entitlements: [{ entitlement: ENTITLEMENT, status: 'ACTIVE', validUntil: now() + 10_000, capabilities: [{ capability: CAPABILITY, minApiVersion: 'v1', maxApiVersion: 'v2' }] }] } });
  assert.equal(registry.resolve(resolveInput()).ok, true); // still valid
  advance(10_000);
  assert.equal(registry.resolve(resolveInput()).code, 'ENTITLEMENT_EXPIRED'); // now >= validUntil
});

test('validUntil at the exact boundary is expired (>= is expired)', () => {
  const registry = makeRegistry({ partner: { entitlements: [{ entitlement: ENTITLEMENT, status: 'ACTIVE', validUntil: now(), capabilities: [{ capability: CAPABILITY, minApiVersion: 'v1', maxApiVersion: 'v2' }] }] } });
  assert.equal(registry.resolve(resolveInput()).code, 'ENTITLEMENT_EXPIRED');
});

// --- Capability failures ---

test('an unknown capability fails closed', () => {
  const registry = makeRegistry();
  assert.equal(registry.resolve(resolveInput({ capability: 'capability-ghost' })).code, 'CAPABILITY_UNKNOWN');
});

test('a capability with a malformed version window fails closed at resolve time', () => {
  // Registering a malformed window throws at REGISTER time; but a window
  // with min > max is structurally valid yet unusable — resolve refuses it.
  const registry = new PartnerRegistry({ now });
  registry.registerPartner(partnerRecordFixture({
    entitlements: [{
      entitlement: ENTITLEMENT, status: 'ACTIVE',
      capabilities: [{ capability: CAPABILITY, minApiVersion: 'v3', maxApiVersion: 'v1' }],
    }],
  }));
  registry.registerOrg(orgRecordFixture());
  assert.equal(registry.resolve(resolveInput()).code, 'CAPABILITY_VERSION_UNSUPPORTED');
});

// --- Registration validation (fail closed at register time) ---

test('registerPartner rejects malformed records with typed codes', () => {
  const registry = new PartnerRegistry({ now });
  assert.throws(() => registry.registerPartner(null), /REGISTRY_PARTNER_RECORD_INVALID/);
  assert.throws(() => registry.registerPartner({ ...partnerRecordFixture(), partnerId: 'x' }), /REGISTRY_PARTNER_ID_INVALID/);
  assert.throws(() => registry.registerPartner({ ...partnerRecordFixture(), status: 'PAUSED' }), /REGISTRY_PARTNER_STATUS_INVALID/);
  assert.throws(() => registry.registerPartner({ ...partnerRecordFixture(), entitlements: 'no' }), /REGISTRY_PARTNER_RECORD_INVALID/);
  assert.throws(() => registry.registerPartner({
    ...partnerRecordFixture(),
    entitlements: [{ entitlement: 'e', status: 'ACTIVE', capabilities: [] }],
  }), /REGISTRY_ENTITLEMENT_INVALID/);
  assert.throws(() => registry.registerPartner({
    ...partnerRecordFixture(),
    entitlements: [{ entitlement: ENTITLEMENT, status: 'WEIRD', capabilities: [] }],
  }), /REGISTRY_ENTITLEMENT_STATUS_INVALID/);
  assert.throws(() => registry.registerPartner({
    ...partnerRecordFixture(),
    entitlements: [{ entitlement: ENTITLEMENT, status: 'ACTIVE', capabilities: [{ capability: CAPABILITY, minApiVersion: 'x1', maxApiVersion: 'v2' }] }],
  }), /REGISTRY_CAPABILITY_VERSION_INVALID/);
});

test('registerOrg rejects malformed records with typed codes', () => {
  const registry = new PartnerRegistry({ now });
  assert.throws(() => registry.registerOrg(null), /REGISTRY_ORG_RECORD_INVALID/);
  assert.throws(() => registry.registerOrg({ ...orgRecordFixture(), orgId: 'o' }), /REGISTRY_ORG_ID_INVALID/);
  assert.throws(() => registry.registerOrg({ ...orgRecordFixture(), status: 'PAUSED' }), /REGISTRY_ORG_STATUS_INVALID/);
  assert.throws(() => registry.registerOrg({ ...orgRecordFixture(), partnerBindings: 'no' }), /REGISTRY_ORG_RECORD_INVALID/);
  assert.throws(() => registry.registerOrg({
    ...orgRecordFixture(),
    partnerBindings: [{ partnerId: 'p', status: 'ACTIVE', entitlements: [ENTITLEMENT] }],
  }), /REGISTRY_BINDING_INVALID/);
  assert.throws(() => registry.registerOrg({
    ...orgRecordFixture(),
    partnerBindings: [{ partnerId: PARTNER_ID, status: 'WEIRD', entitlements: [ENTITLEMENT] }],
  }), /REGISTRY_BINDING_STATUS_INVALID/);
});

test('getPartner / getOrg return null for unknown ids', () => {
  const registry = makeRegistry();
  assert.ok(registry.getPartner(PARTNER_ID));
  assert.equal(registry.getPartner('partner-ghost-99'), null);
  assert.ok(registry.getOrg(ORG_ID));
  assert.equal(registry.getOrg('org-ghost-99'), null);
});

test('replacing a record updates resolution (no hardcoded logic)', () => {
  const registry = makeRegistry();
  assert.equal(registry.resolve(resolveInput()).ok, true);
  registry.registerPartner(partnerRecordFixture({ status: 'SUSPENDED' }));
  assert.equal(registry.resolve(resolveInput()).code, 'PARTNER_SUSPENDED');
  registry.registerPartner(partnerRecordFixture()); // restored
  assert.equal(registry.resolve(resolveInput()).ok, true);
});
