// PATCHES Partner API v1 — test harness.
//
// Boots the REAL reference HTTP server (node:http) on an ephemeral port,
// signs requests exactly per the partner contract:
//   Authorization: PATCHES-Partner <clientId>:<keyId>
//   X-PATCHES-Timestamp: epoch ms
//   X-PATCHES-Nonce: [A-Za-z0-9_-]{20,128}
//   X-PATCHES-Signature: hex HMAC-SHA256 over
//     `${METHOD}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`
//   bodyHash = sha256hex(raw body bytes; empty body hashes "")
// and seeds a synthetic partner directory (2 partners / 3 orgs for tenant
// isolation tests + every negative credential/entitlement/binding state).
// Synthetic data only: opaque identifiers, no PII, no real secrets.

import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { SyntheticPartnerStore } from '../lib/store.ts';
import { canonicalRequestString, computeRequestSignature, bodyHashFor } from '../lib/security.ts';
import { createPartnerApiServer } from '../lib/server.ts';
import { TokenBucketRateLimiter } from '../lib/rateLimit.ts';

export const RECEIPT_SECRET = 'synthetic-receipt-secret-for-tests-only';

// Synthetic secrets (TEST-ONLY; never production material).
const PARTNER_SECRETS = {
  'arma-client': { 'arma-key-1': 'synthetic-secret-ARMA-1' },
  'lumen-client': { 'lumen-key-1': 'synthetic-secret-LUMEN-1' },
};

export function resolveClientSecret(clientId, keyId) {
  const keys = PARTNER_SECRETS[clientId];
  return keys ? (keys[keyId] ?? null) : null;
}

// Injectable synthetic clock.
export function makeClock(startMs) {
  let now = startMs ?? Date.UTC(2026, 0, 15, 12, 0, 0);
  return {
    now: () => now,
    advance: (ms) => { now += ms; return now; },
    set: (ms) => { now = ms; return now; },
  };
}

// --- Synthetic directory seeding ---
// IDs are opaque and synthetic; no PII, no real orgs, no PATCHES private
// logic. ENT-003 INACTIVE, ENT-004 REVOKED, ENT-005 future-licensed, and
// ENT-006 expired cover the negative entitlement branches.
export function seedStore(clock, options = {}) {
  const store = new SyntheticPartnerStore();
  const at = clock.now();
  const DAY = 86_400_000;

  // Partners
  store.addPartner({ partnerId: 'PARTNER-ARMA', clientId: 'arma-client', status: 'ACTIVE' });
  store.addPartner({ partnerId: 'PARTNER-LUMEN', clientId: 'lumen-client', status: options.lumenSuspended ? 'SUSPENDED' : 'ACTIVE' });

  // Credentials (ACTIVE)
  store.putCredential({ clientId: 'arma-client', keyId: 'arma-key-1', kind: 'CLIENT_SECRET', status: 'ACTIVE', activatedAt: at - 1000, secretHash: 'synthetic-hash' });
  store.putCredential({ clientId: 'lumen-client', keyId: 'lumen-key-1', kind: 'CLIENT_SECRET', status: 'ACTIVE', activatedAt: at - 1000, secretHash: 'synthetic-hash' });

  // Organizations — tenant boundary via owningPartnerId
  store.addOrganization({ orgId: 'ORG-ARMA-ALPHA', owningPartnerId: 'PARTNER-ARMA', status: 'ACTIVE' });
  store.addOrganization({ orgId: 'ORG-ARMA-BETA', owningPartnerId: 'PARTNER-ARMA', status: 'ACTIVE' });
  store.addOrganization({ orgId: 'ORG-LUMEN-GAMMA', owningPartnerId: 'PARTNER-LUMEN', status: 'ACTIVE' });
  store.addOrganization({ orgId: 'ORG-ARMA-DELTA', owningPartnerId: 'PARTNER-ARMA', status: 'ACTIVE' });

  // Capabilities (generic contract identifiers only)
  store.putCapability({ capability: 'traffic_stop_privacy', minApiVersion: 'v1', maxApiVersion: 'v1', description: 'Traffic-stop privacy capability (generic contract)' });
  store.putCapability({ capability: 'home_privacy', minApiVersion: 'v1', maxApiVersion: 'v1', description: 'Home privacy capability (generic contract)' });

  // Entitlements — valid + negative states.
  //   ENT-003 INACTIVE, ENT-004 REVOKED, ENT-005 future-licensed, ENT-006
  //   expired cover the negative entitlement branches. ENT-007 licenses a
  //   capability deliberately NOT registered in the capability directory
  //   (exercises CAPABILITY_UNKNOWN downstream of a valid entitlement).
  //   ENT-008 gives LUMEN a valid home_privacy entitlement so cross-partner
  //   scoping tests can reach a genuine 200.
  store.putEntitlement({ entitlementId: 'ENT-001', partnerId: 'PARTNER-ARMA', orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', status: 'ACTIVE', licensedFrom: at - DAY, licensedUntil: at + 365 * DAY });
  store.putEntitlement({ entitlementId: 'ENT-002', partnerId: 'PARTNER-ARMA', orgId: 'ORG-ARMA-BETA', capability: 'home_privacy', status: 'ACTIVE', licensedFrom: at - DAY, licensedUntil: at + 365 * DAY });
  store.putEntitlement({ entitlementId: 'ENT-003', partnerId: 'PARTNER-ARMA', orgId: 'ORG-ARMA-ALPHA', capability: 'home_privacy', status: 'INACTIVE', licensedFrom: at - DAY, licensedUntil: at + 365 * DAY });
  store.putEntitlement({ entitlementId: 'ENT-004', partnerId: 'PARTNER-ARMA', orgId: 'ORG-ARMA-BETA', capability: 'traffic_stop_privacy', status: 'REVOKED', licensedFrom: at - DAY, licensedUntil: at + 365 * DAY });
  store.putEntitlement({ entitlementId: 'ENT-005', partnerId: 'PARTNER-ARMA', orgId: 'ORG-ARMA-DELTA', capability: 'traffic_stop_privacy', status: 'ACTIVE', licensedFrom: at + DAY, licensedUntil: at + 2 * 365 * DAY });
  store.putEntitlement({ entitlementId: 'ENT-006', partnerId: 'PARTNER-LUMEN', orgId: 'ORG-LUMEN-GAMMA', capability: 'traffic_stop_privacy', status: 'ACTIVE', licensedFrom: at - DAY, licensedUntil: at - 1000 });
  store.putEntitlement({ entitlementId: 'ENT-007', partnerId: 'PARTNER-ARMA', orgId: 'ORG-ARMA-ALPHA', capability: 'telemetry_privacy', status: 'ACTIVE', licensedFrom: at - DAY, licensedUntil: at + 365 * DAY });
  store.putEntitlement({ entitlementId: 'ENT-008', partnerId: 'PARTNER-LUMEN', orgId: 'ORG-LUMEN-GAMMA', capability: 'home_privacy', status: 'ACTIVE', licensedFrom: at - DAY, licensedUntil: at + 365 * DAY });

  // Bindings — opaque synthetic identifiers, no PII
  store.putBinding({ bindingId: 'BIND-ALPHA-TSP', orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-001', subjectRef: 'SUBJ-OPAQUE-001', status: 'ACTIVE', boundAt: at - 3600_000 });
  // INACTIVE binding on a VALID entitlement path (ALPHA traffic_stop_privacy):
  // exercises BINDING_INACTIVE without tripping the earlier pipeline stages.
  store.putBinding({ bindingId: 'BIND-ALPHA-TSP-INACTIVE', orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-020', subjectRef: 'SUBJ-OPAQUE-020', status: 'INACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-BETA-HP', orgId: 'ORG-ARMA-BETA', capability: 'home_privacy', deviceId: 'DEV-OPAQUE-002', subjectRef: 'SUBJ-OPAQUE-002', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-ALPHA-HP-INACTIVE', orgId: 'ORG-ARMA-ALPHA', capability: 'home_privacy', deviceId: 'DEV-OPAQUE-015', subjectRef: 'SUBJ-OPAQUE-015', status: 'INACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-CAP-MISMATCH', orgId: 'ORG-ARMA-ALPHA', capability: 'home_privacy', deviceId: 'DEV-OPAQUE-016', subjectRef: 'SUBJ-OPAQUE-016', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-LUMEN-CROSS', orgId: 'ORG-LUMEN-GAMMA', capability: 'home_privacy', deviceId: 'DEV-OPAQUE-017', subjectRef: 'SUBJ-OPAQUE-017', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-UNKNOWN-404', orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-018', subjectRef: 'SUBJ-OPAQUE-018', status: 'ACTIVE', boundAt: at - 3600_000 });
  store.putBinding({ bindingId: 'BIND-DELTA-TSP', orgId: 'ORG-ARMA-DELTA', capability: 'traffic_stop_privacy', deviceId: 'DEV-OPAQUE-019', subjectRef: 'SUBJ-OPAQUE-019', status: 'ACTIVE', boundAt: at - 3600_000 });

  return store;
}

// --- Server boot + request signer ---

export function bootServer(clock, options = {}) {
  const store = options.store ?? seedStore(clock, options);
  const rateLimiter = options.rateLimiter ?? new TokenBucketRateLimiter({ capacity: 30, refillPerSecond: 10, now: clock.now });
  const protectionService = options.protectionService ?? { enqueueActivation: async () => ({ ok: true, downstreamStatus: 'SYNTHETIC_OK' }) };
  const handler = createPartnerApiServer({
    store,
    resolveClientSecret,
    receiptSecret: RECEIPT_SECRET,
    protectionService,
    now: clock.now,
    rateLimiter,
  });
  const server = createServer(handler);
  const started = new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    store,
    rateLimiter,
    handler,
    server,
    async start() {
      await started;
      return this;
    },
    get url() {
      const addr = server.address();
      return `http://127.0.0.1:${addr.port}`;
    },
    async close() {
      // fetch (undici) keeps keep-alive sockets open; server.close() alone
      // would wait for them forever. Force-close connections, then stop.
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

// Signs + sends a request per the partner contract. `path` must include the
// version segment (e.g. /api/partner/v1/activations).
export async function signedRequest(base, { method = 'GET', path, body, bodyRaw, clientId = 'arma-client', keyId = 'arma-key-1', secret, timestamp, nonce, signature, headers = {}, clock }) {
  // bodyRaw: send EXACT bytes (for malformed-payload tests); the signature
  // is still computed over whatever bytes are actually sent.
  const rawBody = bodyRaw !== undefined ? Buffer.from(bodyRaw, 'utf8') : (body === undefined ? null : Buffer.from(JSON.stringify(body), 'utf8'));
  // The client signs with the SAME clock the server verifies against
  // (injected synthetic clock in tests; Date.now in production).
  const ts = timestamp ?? (clock ? clock.now() : Date.now());
  const nc = nonce ?? `nonce-${randomUUID()}`;
  const pathOnly = path.split('?')[0];
  const bodyHash = bodyHashFor(rawBody ?? Buffer.alloc(0));
  const canonical = canonicalRequestString(method, pathOnly, String(ts), nc, bodyHash);
  const sig = signature ?? computeRequestSignature(secret ?? secretFor(clientId, keyId), canonical);
  const url = `${base}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      authorization: `PATCHES-Partner ${clientId}:${keyId}`,
      'x-patches-timestamp': String(ts),
      'x-patches-nonce': nc,
      'x-patches-signature': sig,
      ...(rawBody ? { 'content-type': 'application/json', 'content-length': String(rawBody.length) } : {}),
      ...headers,
    },
    body: rawBody ?? undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* keep raw */ }
  return { status: res.status, headers: res.headers, json, text, requestId: json?.requestId ?? null, nonce: nc, timestamp: ts, bodyHash };
}

function secretFor(clientId, keyId) {
  const secret = resolveClientSecret(clientId, keyId);
  if (secret === null) throw new Error(`no synthetic secret for ${clientId}:${keyId}`);
  return secret;
}

export async function unsignedRequest(base, { method = 'GET', path, body, headers = {} }) {
  const rawBody = body === undefined ? null : Buffer.from(JSON.stringify(body), 'utf8');
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { ...(rawBody ? { 'content-type': 'application/json' } : {}), ...headers },
    body: rawBody ?? undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* keep raw */ }
  return { status: res.status, headers: res.headers, json, text };
}

// Injects a synthetic secret for a rotated key (tests only). The production
// counterpart is the KMS-backed secret resolver in the private repo.
export function injectSecret(clientId, keyId, secret) {
  if (!PARTNER_SECRETS[clientId]) PARTNER_SECRETS[clientId] = {};
  PARTNER_SECRETS[clientId][keyId] = secret;
}
