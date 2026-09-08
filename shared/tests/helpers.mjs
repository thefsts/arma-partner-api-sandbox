// Stop Point 7 — shared test fixtures for the partner integration platform.
//
// Synthetic sandbox material only: a fake clock, a synthetic partner with
// entitlements/capabilities, an org bound to it, deterministic signing
// secrets, and receipt/webhook fixtures. No private partner identifiers,
// prompts, or keys — this is the public integration-facing contract.

import { PartnerRegistry } from '../registry/partnerRegistry.ts';
import { AuditLog } from '../../ai-governance/audit.ts';
import { IntegrationAuditTrail } from '../sdk/audit.ts';

export const PARTNER_ID = 'partner-sandbox-1';
export const ORG_ID = 'org-sandbox-1';
export const OTHER_ORG_ID = 'org-sandbox-2';
export const CAPABILITY = 'traffic_stop_privacy';
export const ENTITLEMENT = 'partner-privacy-basic';

/** Synthetic signing secret (sandbox only — never a real credential). */
export const PARTNER_SECRET = 'synthetic-partner-signing-secret-SP7-sandbox';
/** Synthetic receipt/webhook secret (sandbox only — never a real credential). */
export const RECEIPT_SECRET = 'synthetic-receipt-signing-secret-SP7-sandbox';
/** Synthetic webhook signing secret (sandbox only — never a real credential). */
export const WEBHOOK_SECRET = 'synthetic-webhook-signing-secret-SP7-sandbox';

/** Deterministic fake clock — every test timestamp comes from here. */
export function makeClock(startMs = 1_700_000_000_000) {
  let t = startMs;
  return {
    clock: { now: () => t },
    now: () => t,
    advance(ms) { t += ms; return t; },
  };
}

/** A synthetic partner record for the shared registry. */
export function partnerRecordFixture(overrides = {}) {
  return Object.freeze({
    partnerId: PARTNER_ID,
    status: 'ACTIVE',
    entitlements: [
      {
        entitlement: ENTITLEMENT,
        status: 'ACTIVE',
        capabilities: [
          { capability: CAPABILITY, minApiVersion: 'v1', maxApiVersion: 'v2' },
        ],
      },
    ],
    ...overrides,
  });
}

/** A synthetic org bound to the partner. */
export function orgRecordFixture(overrides = {}) {
  return Object.freeze({
    orgId: ORG_ID,
    status: 'ACTIVE',
    partnerBindings: [
      { partnerId: PARTNER_ID, status: 'ACTIVE', entitlements: [ENTITLEMENT] },
    ],
    ...overrides,
  });
}

/** A registry with the synthetic partner + org registered. */
export function makeRegistry(clockFixture, overrides = {}) {
  const registry = new PartnerRegistry({ now: clockFixture?.now ?? (() => 1_700_000_000_000) });
  registry.registerPartner(partnerRecordFixture(overrides.partner));
  registry.registerOrg(orgRecordFixture(overrides.org));
  return registry;
}

/** An SP6 AuditLog + SP7 IntegrationAuditTrail fixture. */
export function makeAuditTrail(clockFixture, secretValues = []) {
  const log = new AuditLog({ clock: clockFixture.clock, secretValues });
  return { log, trail: null };
}

/** Deterministic nonce source for signing tests. */
export function makeNonceSource(prefix = 'nonce', start = 0) {
  let n = start;
  return () => `${prefix}${String(n++).padStart(6, '0')}`;
}

/** A well-formed valid nonce (meets NONCE_PATTERN, >= 20 chars). */
export function validNonce(seed = 'test') {
  return `nonce-${seed}-0123456789abcdefg`; // 24+ chars, [A-Za-z0-9_-]
}
