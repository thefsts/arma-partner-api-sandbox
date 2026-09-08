// PATCHES Partner API v1 — required test matrix (27 scenarios).
//
// Every scenario boots a REAL HTTP server on an ephemeral port and drives it
// over the wire with contract-signed requests. Synthetic data only.

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootServer, signedRequest, unsignedRequest, makeClock, seedStore, RECEIPT_SECRET, resolveClientSecret, injectSecret } from './helpers.mjs';
import { verifyReceipt } from '../lib/receipts.ts';
import { rotateCredential, revokeCredential, sha256Hex, computeRequestSignature, canonicalRequestString, bodyHashFor, MAX_CLOCK_SKEW_MS, NONCE_VALIDITY_WINDOW_MS } from '../lib/security.ts';
import { MAX_BODY_BYTES, RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_PER_SEC } from '../lib/server.ts';
import { TokenBucketRateLimiter } from '../lib/rateLimit.ts';

const HEALTH = '/api/partner/v1/health';
const ACTIVATIONS = '/api/partner/v1/activations';
const CAPS = '/api/partner/v1/capabilities';
const ENTS = (orgId) => `/api/partner/v1/entitlements?orgId=${encodeURIComponent(orgId)}`;
const EVENTS = (orgId) => `/api/partner/v1/events?orgId=${encodeURIComponent(orgId)}`;
const AUDIT = (orgId) => `/api/partner/v1/audit?orgId=${encodeURIComponent(orgId)}`;
const STATUS = (id) => `/api/partner/v1/activations/${id}`;
const DEACTIVATE = (id) => `/api/partner/v1/activations/${id}/deactivate`;
const REVOKE = (id) => `/api/partner/v1/activations/${id}/revoke`;

function okBody(orgId = 'ORG-ARMA-ALPHA', capability = 'traffic_stop_privacy', bindingId = 'BIND-ALPHA-TSP', idempotencyKey = 'idem-key-001') {
  return { orgId, capability, bindingId, idempotencyKey };
}

async function setup(options = {}) {
  const clock = makeClock();
  const h = await bootServer(clock, options).start();
  return { clock, ...h };
}

async function activate(h, body, extra = {}) {
  return signedRequest(h.url, { method: 'POST', path: ACTIVATIONS, body, clock: h.clock, ...extra });
}

// ---------- 1. valid partner success ----------
test('scenario 1: valid partner success (activation + receipt + audit + event)', async () => {
  const h = await setup();
  try {
    const r = await activate(h, okBody());
    assert.equal(r.status, 200);
    assert.equal(r.json.operation, 'activation.create');
    assert.equal(r.json.outcome, 'SUCCESS');
    assert.equal(r.json.duplicate, undefined);
    const activationId = r.json.activationId;
    assert.ok(activationId, 'activationId present');
    // Receipt headers present and signed over the raw response bytes
    const receiptHeaders = {
      'x-patches-receipt-id': r.headers.get('x-patches-receipt-id'),
      'x-patches-content-sha256': r.headers.get('x-patches-content-sha256'),
      'x-patches-signature': r.headers.get('x-patches-signature'),
    };
    assert.ok(receiptHeaders['x-patches-receipt-id']);
    const raw = Buffer.from(r.text, 'utf8');
    const verification = verifyReceipt({ rawBody: raw, headers: receiptHeaders, secret: RECEIPT_SECRET, expected: { clientId: 'arma-client', operation: 'activation.create', outcome: 'SUCCESS', activationId } });
    assert.equal(verification.verified, true, `receipt verified: ${verification.reason}`);
    assert.equal(verification.receipt.receiptId, receiptHeaders['x-patches-receipt-id']);
    // Store state: activation ACTIVE, receipt persisted, event appended, audit appended
    assert.equal(h.store.getActivation(activationId).status, 'ACTIVE');
    assert.equal(h.store.getReceipt(verification.receipt.receiptId).operation, 'activation.create');
    assert.equal(h.store.eventCount() >= 1, true);
    const audits = h.store.getAuditEvents({ requestId: r.requestId });
    assert.equal(audits.length >= 1, true);
    assert.equal(audits.some((a) => a.operation === 'activation.create' && a.outcome === 'SUCCESS'), true);
    // Status route confirms the live state
    const st = await signedRequest(h.url, { path: STATUS(activationId), clock: h.clock });
    assert.equal(st.status, 200);
    assert.equal(st.json.activation.status, 'ACTIVE');
  } finally {
    await h.close();
  }
});

// ---------- 2. missing credential ----------
test('scenario 2: missing credential (no Authorization header)', async () => {
  const h = await setup();
  try {
    const r = await unsignedRequest(h.url, { method: 'POST', path: ACTIVATIONS, body: okBody() });
    assert.equal(r.status, 401);
    assert.equal(r.json.error, 'AUTH_MISSING');
    assert.equal(r.json.errorClass, 'AUTHENTICATION');
    assert.ok(r.json.requestId, 'structured error carries requestId');
  } finally {
    await h.close();
  }
});

// ---------- 3. invalid credential ----------
test('scenario 3: invalid credential (bad signature)', async () => {
  const h = await setup();
  try {
    const r = await activate(h, okBody(), { signature: 'f'.repeat(64) });
    assert.equal(r.status, 401);
    assert.equal(r.json.error, 'SIGNATURE_INVALID');
  } finally {
    await h.close();
  }
});

// ---------- 4. revoked credential ----------
test('scenario 4: revoked credential is denied immediately', async () => {
  const h = await setup();
  try {
    revokeCredential({ store: h.store, clientId: 'arma-client', keyId: 'arma-key-1', reason: 'synthetic-test-revocation', now: h.clock.now });
    const r = await activate(h, okBody());
    assert.equal(r.status, 401);
    assert.equal(r.json.error, 'CREDENTIAL_REVOKED');
  } finally {
    await h.close();
  }
});

// ---------- 5. credential rotation ----------
test('scenario 5: credential rotation behavior (new key ACTIVE, old key GRACE then expired)', async () => {
  const h = await setup();
  try {
    // New key becomes ACTIVE; old key enters GRACE until retiredAt.
    injectSecret('arma-client', 'arma-key-2', 'synthetic-secret-ARMA-2');
    rotateCredential({ store: h.store, clientId: 'arma-client', newKeyId: 'arma-key-2', newSecretHash: 'synthetic-hash-2', graceMs: 10 * 60 * 1000, now: h.clock.now });
    const withNew = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-ALPHA-TSP', 'idem-rot-1'), { keyId: 'arma-key-2', secret: 'synthetic-secret-ARMA-2' });
    assert.equal(withNew.status, 200, JSON.stringify(withNew.json));
    // Old key still works during grace...
    const withOld = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-ALPHA-TSP', 'idem-rot-2'), { keyId: 'arma-key-1', secret: 'synthetic-secret-ARMA-1' });
    assert.equal(withOld.status, 200);
    // ...but after the grace window expires the old key is dead.
    h.clock.advance(10 * 60 * 1000 + 1000);
    const withOldLate = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-ALPHA-TSP', 'idem-rot-3'), { keyId: 'arma-key-1', secret: 'synthetic-secret-ARMA-1' });
    assert.equal(withOldLate.status, 401);
    assert.equal(withOldLate.json.error, 'CREDENTIAL_EXPIRED');
    // And the new key keeps working.
    const withNew2 = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-ALPHA-TSP', 'idem-rot-4'), { keyId: 'arma-key-2', secret: 'synthetic-secret-ARMA-2' });
    assert.equal(withNew2.status, 200);
  } finally {
    await h.close();
  }
});

// ---------- 6. suspended partner ----------
test('scenario 6: suspended partner is denied', async () => {
  const h = await setup({ lumenSuspended: true });
  try {
    const r = await activate(h, okBody('ORG-LUMEN-GAMMA', 'traffic_stop_privacy', 'BIND-LUMEN-CROSS', 'idem-lum-1'), { clientId: 'lumen-client', keyId: 'lumen-key-1', secret: 'synthetic-secret-LUMEN-1' });
    assert.equal(r.status, 401);
    assert.equal(r.json.error, 'PARTNER_SUSPENDED');
  } finally {
    await h.close();
  }
});

// ---------- 7. wrong tenant/org ----------
test("scenario 7: wrong tenant/org — partner cannot touch another partner's org", async () => {
  const h = await setup();
  try {
    // ARMA partner attempts an activation referencing LUMEN's org.
    const r = await activate(h, okBody('ORG-LUMEN-GAMMA', 'traffic_stop_privacy', 'BIND-LUMEN-CROSS', 'idem-cross-1'));
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'ORG_NOT_BOUND_TO_PARTNER');
    // And cannot even LIST the other tenant's entitlements/events/audit.
    const ents = await signedRequest(h.url, { path: ENTS('ORG-LUMEN-GAMMA'), clock: h.clock });
    assert.equal(ents.status, 403);
    assert.equal(ents.json.error, 'ORG_NOT_BOUND_TO_PARTNER');
    const events = await signedRequest(h.url, { path: EVENTS('ORG-LUMEN-GAMMA'), clock: h.clock });
    assert.equal(events.status, 403);
    assert.equal(events.json.error, 'ORG_NOT_BOUND_TO_PARTNER');
    const audit = await signedRequest(h.url, { path: AUDIT('ORG-LUMEN-GAMMA'), clock: h.clock });
    assert.equal(audit.status, 403);
    assert.equal(audit.json.error, 'ORG_NOT_BOUND_TO_PARTNER');
  } finally {
    await h.close();
  }
});

// ---------- 8. missing entitlement ----------
test('scenario 8: missing entitlement', async () => {
  const h = await setup();
  try {
    // ORG-ARMA-BETA is licensed for home_privacy (ENT-002) but has no
    // telemetry_privacy entitlement at all — a genuinely missing row.
    const r = await activate(h, okBody('ORG-ARMA-BETA', 'telemetry_privacy', 'BIND-BETA-HP', 'idem-ent-1'));
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'ENTITLEMENT_MISSING');
  } finally {
    await h.close();
  }
});

// ---------- 8b. inactive entitlement ----------
test('scenario 8b: inactive entitlement is denied', async () => {
  const h = await setup();
  try {
    // ENT-003: ORG-ARMA-ALPHA home_privacy INACTIVE.
    const r = await activate(h, okBody('ORG-ARMA-ALPHA', 'home_privacy', 'BIND-ALPHA-HP-INACTIVE', 'idem-ent-inact'));
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'ENTITLEMENT_INACTIVE');
  } finally {
    await h.close();
  }
});

// ---------- 9. revoked entitlement ----------
test('scenario 9: revoked entitlement is denied', async () => {
  const h = await setup();
  try {
    // ENT-004: ORG-ARMA-BETA traffic_stop_privacy REVOKED. The binding
    // BIND-BETA-HP is home_privacy — the entitlement check fires first
    // because the policy pipeline checks entitlement BEFORE binding.
    const r = await activate(h, okBody('ORG-ARMA-BETA', 'traffic_stop_privacy', 'BIND-BETA-HP', 'idem-ent-rev'));
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'ENTITLEMENT_REVOKED');
  } finally {
    await h.close();
  }
});

// ---------- 9b. expired (license window) entitlement ----------
test('scenario 9b: expired license window is denied', async () => {
  const h = await setup();
  try {
    // ENT-005 (ORG-ARMA-DELTA): licensedFrom in the FUTURE (not yet
    // licensed -> expired branch).
    const r = await activate(h, okBody('ORG-ARMA-DELTA', 'traffic_stop_privacy', 'BIND-DELTA-TSP', 'idem-ent-fut'));
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'ENTITLEMENT_EXPIRED');
  } finally {
    await h.close();
  }
});

// ---------- 10. unsupported capability ----------
test('scenario 10: unsupported capability is rejected', async () => {
  const h = await setup();
  try {
    // ENT-007 licenses telemetry_privacy for ALPHA, but the capability is
    // deliberately NOT registered in the capability directory -> the
    // entitlement check passes and CAPABILITY_UNKNOWN fires.
    const r = await activate(h, okBody('ORG-ARMA-ALPHA', 'telemetry_privacy', 'BIND-ALPHA-TSP', 'idem-cap-bad'));
    assert.equal(r.status, 403);
    assert.equal(r.json.error, 'CAPABILITY_UNKNOWN');
    // Pipeline precedence: an entirely bogus capability name fails at the
    // entitlement step first (org -> entitlement -> capability -> binding).
    const bogus = await activate(h, okBody('ORG-ARMA-ALPHA', 'this_is_not_a_capability', 'BIND-ALPHA-TSP', 'idem-cap-bogus'));
    assert.equal(bogus.status, 403);
    assert.equal(bogus.json.error, 'ENTITLEMENT_MISSING');
  } finally {
    await h.close();
  }
});

// ---------- 10b. capability list (capability discovery) ----------
test('scenario 10b: capability discovery lists generic capabilities only', async () => {
  const h = await setup();
  try {
    const r = await signedRequest(h.url, { path: CAPS, clock: h.clock });
    assert.equal(r.status, 200);
    const caps = r.json.capabilities.map((c) => c.capability).sort();
    assert.deepEqual(caps, ['home_privacy', 'traffic_stop_privacy']);
  } finally {
    await h.close();
  }
});

// ---------- 11. duplicate activation, same idempotency key ----------
test('scenario 11: duplicate activation with the same idempotency key collapses', async () => {
  const h = await setup();
  try {
    const first = await activate(h, okBody(...okIdem('idem-dup-1')));
    assert.equal(first.status, 200);
    const firstId = first.json.activationId;
    // Same key + SAME payload -> duplicate collapse: 200 + duplicate:true
    // + the ORIGINAL activation, not a new one.
    const second = await activate(h, okBody(...okIdem('idem-dup-1')));
    assert.equal(second.status, 200);
    assert.equal(second.json.duplicate, true);
    assert.equal(second.json.activationId, firstId);
    assert.equal(h.store.activationCount(), 1);
    // The receipt still verifies over raw bytes.
    const v = verifyReceipt({ rawBody: Buffer.from(second.text, 'utf8'), headers: pickReceiptHeaders(second), secret: RECEIPT_SECRET, expected: { clientId: 'arma-client', operation: 'activation.create' } });
    assert.equal(v.verified, true);
  } finally {
    await h.close();
  }
});

// ---------- 12. idempotency conflict, different payload ----------
test('scenario 12: same idempotency key + different payload -> 409 CONFLICT', async () => {
  const h = await setup();
  try {
    const first = await activate(h, okBody(...okIdem('idem-conf-1')));
    assert.equal(first.status, 200);
    // Same key, DIFFERENT payload (different binding) -> 409.
    const second = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-UNKNOWN-404', 'idem-conf-1'));
    assert.equal(second.status, 409);
    assert.equal(second.json.error, 'IDEMPOTENCY_KEY_CONFLICT');
    assert.equal(second.json.existingActivationId, first.json.activationId);
    assert.equal(h.store.activationCount(), 1);
  } finally {
    await h.close();
  }
});

// ---------- 13. deactivation ----------
test('scenario 13: deactivation (lifecycle, idempotent by status)', async () => {
  const h = await setup();
  try {
    const act = await activate(h, okBody(...okIdem('idem-deact-1')));
    const id = act.json.activationId;
    const off = await signedRequest(h.url, { method: 'POST', path: DEACTIVATE(id), body: { orgId: 'ORG-ARMA-ALPHA' }, clock: h.clock });
    assert.equal(off.status, 200);
    assert.equal(off.json.operation, 'activation.deactivate');
    assert.equal(off.json.result.status, 'DEACTIVATED');
    // Second deactivate: no-op success (idempotent by status).
    const off2 = await signedRequest(h.url, { method: 'POST', path: DEACTIVATE(id), body: { orgId: 'ORG-ARMA-ALPHA' }, clock: h.clock });
    assert.equal(off2.status, 200);
    assert.equal(off2.json.result.status, 'DEACTIVATED');
    // Store + audit reflect the transition.
    assert.equal(h.store.getActivation(id).status, 'DEACTIVATED');
    const events = await signedRequest(h.url, { path: EVENTS('ORG-ARMA-ALPHA'), clock: h.clock });
    assert.equal(events.json.events.some((e) => e.type === 'activation.deactivated'), true);
  } finally {
    await h.close();
  }
});

// ---------- 14. revocation ----------
test('scenario 14: revocation (REVOKED terminal; no reactivate/deactivate)', async () => {
  const h = await setup();
  try {
    const act = await activate(h, okBody(...okIdem('idem-rev-1')));
    const id = act.json.activationId;
    const rev = await signedRequest(h.url, { method: 'POST', path: REVOKE(id), body: { orgId: 'ORG-ARMA-ALPHA' }, clock: h.clock });
    assert.equal(rev.status, 200);
    assert.equal(rev.json.operation, 'activation.revoke');
    assert.equal(rev.json.result.status, 'REVOKED');
    // Revoking again: no-op success.
    const rev2 = await signedRequest(h.url, { method: 'POST', path: REVOKE(id), body: { orgId: 'ORG-ARMA-ALPHA' }, clock: h.clock });
    assert.equal(rev2.status, 200);
    assert.equal(rev2.json.result.status, 'REVOKED');
    // But deactivating a REVOKED activation -> 409 (terminal state).
    const deact = await signedRequest(h.url, { method: 'POST', path: DEACTIVATE(id), body: { orgId: 'ORG-ARMA-ALPHA' }, clock: h.clock });
    assert.equal(deact.status, 409);
    assert.equal(deact.json.error, 'ACTIVATION_REVOKED');
    // Status route shows REVOKED.
    const st = await signedRequest(h.url, { path: STATUS(id), clock: h.clock });
    assert.equal(st.json.activation.status, 'REVOKED');
  } finally {
    await h.close();
  }
});

// ---------- 15. invalid device/subject binding ----------
test('scenario 15: invalid device/subject binding', async () => {
  const h = await setup();
  try {
    // Unknown binding on a fully valid entitlement path.
    const unknown = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-DOES-NOT-EXIST', 'idem-bind-1'));
    assert.equal(unknown.status, 403);
    assert.equal(unknown.json.error, 'BINDING_UNKNOWN');
    // Inactive binding on a VALID entitlement path (ALPHA traffic_stop_privacy).
    const inactive = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-ALPHA-TSP-INACTIVE', 'idem-bind-2'));
    assert.equal(inactive.status, 403);
    assert.equal(inactive.json.error, 'BINDING_INACTIVE');
    // Cross-org binding: BETA holds a valid home_privacy entitlement
    // (ENT-002), but BIND-LUMEN-CROSS belongs to LUMEN's org.
    const cross = await activate(h, okBody('ORG-ARMA-BETA', 'home_privacy', 'BIND-LUMEN-CROSS', 'idem-bind-3'));
    assert.equal(cross.status, 403);
    assert.equal(cross.json.error, 'BINDING_ORG_MISMATCH');
    // Capability mismatch: valid traffic_stop_privacy path (ENT-001), but
    // BIND-CAP-MISMATCH is a home_privacy binding in the ALPHA org.
    const mismatch = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-CAP-MISMATCH', 'idem-bind-4'));
    assert.equal(mismatch.status, 403);
    assert.equal(mismatch.json.error, 'BINDING_CAPABILITY_MISMATCH');
  } finally {
    await h.close();
  }
});

function okIdem(idemKey) {
  return ['ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-ALPHA-TSP', idemKey];
}

function pickReceiptHeaders(r) {
  return {
    'x-patches-receipt-id': r.headers.get('x-patches-receipt-id') ?? undefined,
    'x-patches-content-sha256': r.headers.get('x-patches-content-sha256') ?? undefined,
    'x-patches-signature': r.headers.get('x-patches-signature') ?? undefined,
  };
}

// ---------- 16. replayed request ----------
test('scenario 16: replayed request (same nonce) is rejected with NONCE_REPLAYED', async () => {
  const h = await setup();
  try {
    const first = await activate(h, okBody(...okIdem('idem-replay-1')));
    assert.equal(first.status, 200);
    const replayedNonce = first.nonce;
    // Exact replay: same nonce + same body + same timestamp.
    const replay = await activate(h, okBody(...okIdem('idem-replay-1')), { nonce: replayedNonce, timestamp: first.timestamp });
    assert.equal(replay.status, 409);
    assert.equal(replay.json.error, 'NONCE_REPLAYED');
    // Replay is refused even if the attacker changes the idempotency key.
    const replay2 = await activate(h, okBody(...okIdem('idem-replay-2')), { nonce: replayedNonce, timestamp: first.timestamp });
    assert.equal(replay2.status, 409);
    assert.equal(replay2.json.error, 'NONCE_REPLAYED');
  } finally {
    await h.close();
  }
});

// ---------- 17. stale request ----------
test('scenario 17: stale request (timestamp outside the clock-skew window) is rejected', async () => {
  const h = await setup();
  try {
    const r = await activate(h, okBody(...okIdem('idem-stale-1')), { timestamp: h.clock.now() - MAX_CLOCK_SKEW_MS - 1000 });
    assert.equal(r.status, 401);
    assert.equal(r.json.error, 'TIMESTAMP_OUT_OF_WINDOW');
  } finally {
    await h.close();
  }
});

// ---------- 18. tampered request ----------
test('scenario 18: tampered request (valid signature over different body) is rejected', async () => {
  const h = await setup();
  try {
    // Sign the ORIGINAL body, then send a DIFFERENT one (signature/body
    // mismatch: the bodyHash in the canonical string no longer matches).
    const r = await activate(h, okBody('ORG-ARMA-ALPHA', 'traffic_stop_privacy', 'BIND-UNKNOWN-404', 'idem-tamper-1'), {
      // precomputed signature for a different (valid-looking) payload
      signature: computeRequestSignature('synthetic-secret-ARMA-1', canonicalRequestString('POST', ACTIVATIONS, String(h.clock.now()), 'nonce-tamper-0000000000', bodyHashFor(Buffer.from(JSON.stringify(okBody(...okIdem('idem-tamper-1'))), 'utf8')))),
    });
    assert.equal(r.status, 401);
    assert.equal(r.json.error, 'SIGNATURE_INVALID');
  } finally {
    await h.close();
  }
});

// ---------- 19. unsupported API version ----------
test('scenario 19: unsupported API version is rejected', async () => {
  const h = await setup();
  try {
    const r = await signedRequest(h.url, { method: 'POST', path: '/api/partner/v2/activations', body: okBody(...okIdem('idem-ver-1')), clock: h.clock });
    assert.equal(r.status, 400);
    assert.equal(r.json.error, 'UNSUPPORTED_API_VERSION');
  } finally {
    await h.close();
  }
});

// ---------- 20. malformed payload ----------
test('scenario 20: malformed payload is rejected', async () => {
  const h = await setup();
  try {
    const r = await activate(h, okBody(...okIdem('idem-mal-1')), { bodyRaw: 'not-json{{' });
    assert.equal(r.status, 400);
    assert.equal(r.json.error, 'MALFORMED_PAYLOAD');
  } finally {
    await h.close();
  }
});

// ---------- 21. payload too large ----------
test('scenario 21: payload over the limit is rejected with 413', async () => {
  const h = await setup();
  try {
    const big = { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'idem-big-1', padding: 'x'.repeat(MAX_BODY_BYTES) };
    const r = await activate(h, big);
    assert.equal(r.status, 413);
    assert.equal(r.json.error, 'PAYLOAD_TOO_LARGE');
    assert.equal(r.json.limitBytes, MAX_BODY_BYTES);
  } finally {
    await h.close();
  }
});

// ---------- 22. rate limit ----------
test('scenario 22: rate limit reference behavior (429 + retry-after)', async () => {
  const h = await setup({ rateLimiter: new TokenBucketRateLimiter({ capacity: 2, refillPerSecond: 0.001, now: makeClock().now }) });
  try {
    const r1 = await activate(h, okBody(...okIdem('idem-rl-1')));
    assert.equal(r1.status, 200);
    const r2 = await activate(h, okBody(...okIdem('idem-rl-2')));
    assert.equal(r2.status, 200);
    const r3 = await activate(h, okBody(...okIdem('idem-rl-3')));
    assert.equal(r3.status, 429);
    assert.equal(r3.json.error, 'RATE_LIMITED');
    assert.ok(Number(r3.headers.get('retry-after')) >= 1, 'retry-after present');
    // Rate limiting is scoped to the clientId: the OTHER partner still works.
    // ENT-008: LUMEN holds a valid home_privacy entitlement on ORG-LUMEN-GAMMA.
    const other = await activate(h, okBody('ORG-LUMEN-GAMMA', 'home_privacy', 'BIND-LUMEN-CROSS', 'idem-rl-lum'), { clientId: 'lumen-client', keyId: 'lumen-key-1', secret: 'synthetic-secret-LUMEN-1' });
    assert.equal(other.status, 200, JSON.stringify(other.json));
  } finally {
    await h.close();
  }
});

// ---------- 23. downstream failure (fail-closed) ----------
test('scenario 23: downstream protection service failure fails the activation CLOSED', async () => {
  const h = await setup({ protectionService: { enqueueActivation: async () => ({ ok: false, downstreamStatus: 'SYNTHETIC_DOWNSTREAM_DOWN' }) } });
  try {
    const before = h.store.activationCount();
    const r = await activate(h, okBody(...okIdem('idem-down-1')));
    assert.equal(r.status, 503);
    assert.equal(r.json.error, 'DOWNSTREAM_UNAVAILABLE');
    // FAIL-CLOSED: nothing persisted, no receipt, no event.
    assert.equal(h.store.activationCount(), before);
    assert.ok(!r.headers.get('x-patches-receipt-id'));
    const events = await signedRequest(h.url, { path: EVENTS('ORG-ARMA-ALPHA'), clock: h.clock });
    assert.equal(events.json.events.some((e) => e.activationId === undefined || e.type === 'activation.created'), false);
  } finally {
    await h.close();
  }
});

// ---------- 24. receipt integrity ----------
test('scenario 24: receipt integrity (signature over raw response bytes)', async () => {
  const h = await setup();
  try {
    const r = await activate(h, okBody(...okIdem('idem-rcpt-1')));
    assert.equal(r.status, 200);
    const v = verifyReceipt({ rawBody: Buffer.from(r.text, 'utf8'), headers: pickReceiptHeaders(r), secret: RECEIPT_SECRET });
    assert.equal(v.verified, true, v.reason);
    // Tampering with the body invalidates the receipt.
    const tampered = Buffer.from(r.text.replace('"SUCCESS"', '"SUCCESS "'), 'utf8');
    const vBad = verifyReceipt({ rawBody: tampered, headers: pickReceiptHeaders(r), secret: RECEIPT_SECRET });
    assert.equal(vBad.verified, false);
    assert.equal(vBad.reason, 'RECEIPT_CONTENT_HASH_MISMATCH');
    // A wrong secret fails the signature check.
    const vWrongSecret = verifyReceipt({ rawBody: Buffer.from(r.text, 'utf8'), headers: pickReceiptHeaders(r), secret: 'wrong-secret' });
    assert.equal(vWrongSecret.verified, false);
    assert.equal(vWrongSecret.reason, 'RECEIPT_INVALID_SIGNATURE');
  } finally {
    await h.close();
  }
});

// ---------- 25. receipt mismatch (expected-field binding) ----------
test('scenario 25: receipt mismatch is detected via expected-field binding', async () => {
  const h = await setup();
  try {
    const r = await activate(h, okBody(...okIdem('idem-rcpt-2')));
    assert.equal(r.status, 200);
    // Expecting a DIFFERENT activationId -> FIELD_MISMATCH.
    const v = verifyReceipt({ rawBody: Buffer.from(r.text, 'utf8'), headers: pickReceiptHeaders(r), secret: RECEIPT_SECRET, expected: { activationId: 'ACT-NOT-THIS-ONE' } });
    assert.equal(v.verified, false);
    assert.equal(v.reason, 'RECEIPT_FIELD_MISMATCH');
    // Missing receipt headers -> RECEIPT_MISSING_HEADERS.
    const vNone = verifyReceipt({ rawBody: Buffer.from(r.text, 'utf8'), headers: {}, secret: RECEIPT_SECRET });
    assert.equal(vNone.verified, false);
    assert.equal(vNone.reason, 'RECEIPT_MISSING_HEADERS');
  } finally {
    await h.close();
  }
});

// ---------- 26. audit creation ----------
test('scenario 26: audit creation (append-only, sanitization, tenant-scoped read)', async () => {
  const h = await setup();
  try {
    const r = await activate(h, okBody(...okIdem('idem-aud-1')));
    assert.equal(r.status, 200);
    const audits = h.store.getAuditEvents({ requestId: r.requestId });
    assert.ok(audits.length >= 1);
    const created = audits.find((a) => a.operation === 'activation.create');
    assert.ok(created);
    // Sequence numbers are strictly increasing (append-only ordering).
    const all = h.store.audit;
    const seqs = all.map((a) => a.sequence);
    for (let i = 1; i < seqs.length; i++) assert.equal(seqs[i] > seqs[i - 1], true);
    // Tenant-scoped audit read: only this partner's own orgs.
    const read = await signedRequest(h.url, { path: AUDIT('ORG-ARMA-ALPHA'), clock: h.clock });
    assert.equal(read.status, 200);
    assert.ok(read.json.audit.length >= 1);
    assert.equal(read.json.audit.some((a) => a.operation === 'activation.create'), true);
    // Sanitization: audit detail is allowlisted; payload content must NOT appear.
    const rawJson = JSON.stringify(all);
    assert.equal(rawJson.includes('SUBJ-'), false, 'no subject refs in audit');
    assert.equal(rawJson.includes('DEV-OPAQUE'), false, 'no device refs in audit');
  } finally {
    await h.close();
  }
});

// ---------- 27. health/readiness ----------
test('scenario 27: health/readiness is live (reflects kill switch, no caching semantics)', async () => {
  const h = await setup();
  try {
    const r = await unsignedRequest(h.url, { path: HEALTH });
    assert.equal(r.status, 200);
    assert.equal(r.json.status, 'available');
    assert.equal(r.json.directDatabaseAccess, false);
    assert.equal(r.json.requiresScopedAuthentication, true);
    assert.equal(r.json.version, 'v1');
    assert.ok(r.json.capabilities.includes('traffic_stop_privacy'));
    assert.equal(r.headers.get('cache-control'), 'no-store');
    assert.equal(r.headers.get('x-api-version'), 'v1');
    // Kill switch flips health AND blocks all routes.
    process.env.PATCHES_PARTNER_API_DISABLED = 'true';
    try {
      const dead = await unsignedRequest(h.url, { path: HEALTH });
      assert.equal(dead.status, 503);
      assert.equal(dead.json.status, 'disabled');
      const blocked = await activate(h, okBody(...okIdem('idem-kill-1')));
      assert.equal(blocked.status, 503);
      assert.equal(blocked.json.error, 'PARTNER_API_DISABLED');
    } finally {
      process.env.PATCHES_PARTNER_API_DISABLED = 'false';
    }
  } finally {
    await h.close();
  }
});
