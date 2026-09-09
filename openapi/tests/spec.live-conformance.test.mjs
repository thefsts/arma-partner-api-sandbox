// OpenAPI live conformance lane (Stop Point 9).
//
// Boots the REAL reference servers (the same modules CI boots for the
// existing matrices — createPartnerApiServer for PATCHES, the real durable
// processor + real gateway for Law Shield) and drives EVERY documented
// operation end-to-end over real HTTP, then asserts each response's status,
// documented headers, and body conform to the OpenAPI schemas.
//
// This is the "validated against the live reference server in CI" lane from
// the approved SP9 proposal: if the implementation and the contract drift
// apart, this lane fails. Synthetic data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { loadSpec, resolveRef, validateAgainstSchema } from './helpers.mjs';

// Reuse the REAL test harness from the PATCHES lane (server boot + signer).
const {
  bootServer, signedRequest, unsignedRequest, makeClock, RECEIPT_SECRET,
} = await import('../../patches/tests/helpers.mjs');

// Reuse the REAL law-shield harness (gateway/processor boot + signer).
const {
  applyTestEnv, buildEnvelope, get: lsGet, post: lsPost, resetGatewayState,
  sha256Hex, startGateway, startReadiness, SCHEMA_VERSION, GATEWAY_SECRET,
  PROCESSOR_TOKEN,
} = await import('../../law-shield/tests/helpers/servers.mjs');
const { SyntheticDurableLawShieldStore, seedSyntheticProcessorDirectory } = await import('../../law-shield/lawshield/durable/store.js');
const { createDurableProcessorServer } = await import('../../law-shield/lawshield/durable/processor.js');
// The REAL redactor — the durable processor enforces the disclosure policy on
// the FLAT minimum-necessary redacted payload (redactor output IS the envelope
// payload, no wrapper). Verified against processor.durable.test.mjs.
const { redactPayload } = await import('../../law-shield/arma/redaction.js');

const patchesSpec = loadSpec('../patches-partner-v1.yaml');
const lawshieldSpec = loadSpec('../../law-shield/openapi/arma-lawshield-v1.yaml');

// Flat minimum-necessary redacted CASE_REFERRAL payload (mirrors the REAL
// harness contract in processor.durable.test.mjs's validRedactedPayload —
// ssn/officerNotes in the raw input prove the redactor strips them).
function redactedCasePayload(overrides = {}) {
  const { payload } = redactPayload('CASE_REFERRAL', {
    caseNumber: 'CASE-100',
    incidentId: 'INC-1001',
    incidentDate: '2026-01-05',
    incidentType: 'SYNTHETIC_INCIDENT',
    summary: 'Synthetic referral for legal review',
    legalNeeds: ['LEGAL_REVIEW'],
    incidentLocation: 'Synthetic Location 1',
    ssn: '000-00-0000',
    officerNotes: 'never leaves ARMA',
  });
  return { ...payload, ...overrides };
}

// ---------------------------------------------------------------------------
// Conformance helpers
// ---------------------------------------------------------------------------
function operation(doc, path, method) {
  const op = doc.paths?.[path]?.[method];
  if (!op) throw new Error(`no ${method.toUpperCase()} ${path} in spec`);
  return op;
}

function responseSpec(doc, path, method, status) {
  const op = operation(doc, path, method);
  const code = String(status);
  let r = op.responses[code];
  if (!r && op.responses.default) r = op.responses.default;
  if (r && r.$ref) r = resolveRef(doc, r.$ref);
  if (!r) throw new Error(`no response ${code} documented for ${method.toUpperCase()} ${path}`);
  return r;
}

function bodySchema(doc, path, method, status) {
  const r = responseSpec(doc, path, method, status);
  return r.content?.['application/json']?.schema ?? null;
}

function checkHeaders(doc, path, method, status, headers, notes = []) {
  const r = responseSpec(doc, path, method, status);
  const docHeaders = r.headers ?? {};
  // Header access that works for both fetch Headers objects (.get) and the
  // plain lowercased-key objects the law-shield harness client returns.
  const getHeader = (name) => {
    if (typeof headers.get === 'function') return headers.get(name);
    return headers[name] ?? headers[name.toLowerCase()] ?? null;
  };
  for (const [name, spec] of Object.entries(docHeaders)) {
    const h = spec.$ref ? resolveRef(doc, spec.$ref) : spec;
    if (!h) throw new Error(`unresolvable header ref for ${name}`);
    const actual = getHeader(name);
    if (actual === null || actual === undefined) {
      notes.push(`missing documented header ${name} on ${method.toUpperCase()} ${path} ${status}`);
      continue;
    }
    if (h.schema) {
      const errs = [];
      validateAgainstSchema(doc, h.schema, actual, errs, `header ${name}`);
      for (const e of errs) notes.push(`header ${name}: ${e}`);
    }
  }
}

function checkBody(doc, path, method, status, body, notes = []) {
  const schema = bodySchema(doc, path, method, status);
  if (!schema) { notes.push(`no schema documented for ${method.toUpperCase()} ${path} ${status}`); return; }
  const errs = [];
  validateAgainstSchema(doc, schema, body, errs, `${method.toUpperCase()} ${path} ${status} body`);
  for (const e of errs) notes.push(e);
}

function assertConformance(notes) {
  assert.deepEqual(notes, [], 'wire response does not conform to the OpenAPI contract');
}

// ---------------------------------------------------------------------------
// PATCHES Partner API v1 — live conformance
// ---------------------------------------------------------------------------
test('live conformance: PATCHES — health, discovery, activation lifecycle, events, audit, receipts, error shapes', async () => {
  const clock = makeClock();
  const srv = await bootServer(clock, {}).start();
  const notes = [];
  try {
    // ---- GET /health (documented as unauthenticated, 200) ----
    {
      const res = await unsignedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/health' });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/health', 'get', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/health', 'get', 200, res.json, notes);
    }

    // ---- GET /capabilities ----
    {
      const res = await signedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/capabilities', clock });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/capabilities', 'get', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/capabilities', 'get', 200, res.json, notes);
    }

    // ---- GET /entitlements?orgId=ORG-ARMA-ALPHA ----
    {
      const res = await signedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/entitlements?orgId=ORG-ARMA-ALPHA', clock });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/entitlements', 'get', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/entitlements', 'get', 200, res.json, notes);
    }

    // ---- POST /activations (fresh) — receipt + headers ----
    let activationId = null;
    {
      const res = await signedRequest(srv.url, {
        method: 'POST', path: '/api/partner/v1/activations', clock,
        body: { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'IDK-CONF-001' },
      });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/activations', 'post', 200, res.headers, notes);
      // receipt headers (documented on the 200 response)
      const r = responseSpec(patchesSpec, '/api/partner/v1/activations', 'post', 200);
      for (const name of Object.keys(r.headers ?? {})) {
        if (name === 'x-patches-receipt-id' || name === 'x-patches-content-sha256' || name === 'x-patches-signature') {
          const actual = res.headers.get(name);
          if (actual === null) notes.push(`200 receipt missing header ${name}`);
        }
      }
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 200, res.json, notes);
      activationId = res.json?.activation?.activationId ?? res.json?.activationId ?? null;
      assert.ok(activationId, 'activation id missing from receipt body');
    }

    // ---- POST /activations duplicate (same idempotency key + same request) ----
    {
      const res = await signedRequest(srv.url, {
        method: 'POST', path: '/api/partner/v1/activations', clock,
        body: { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'IDK-CONF-001' },
      });
      assert.equal(res.status, 200);
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 200, res.json, notes);
      assert.equal(res.json.duplicate, true, 'duplicate flag must be true');
    }

    // ---- POST /activations idempotency conflict (same key, different body) ----
    {
      const res = await signedRequest(srv.url, {
        method: 'POST', path: '/api/partner/v1/activations', clock,
        body: { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: 'IDK-CONF-001', note: 'different request hash' },
      });
      assert.equal(res.status, 409);
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 409, res.json, notes);
    }

    // ---- GET /activations/{id} ----
    {
      const res = await signedRequest(srv.url, { method: 'GET', path: `/api/partner/v1/activations/${activationId}`, clock });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/activations/{activationId}', 'get', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/activations/{activationId}', 'get', 200, res.json, notes);
    }

    // ---- GET /activations/{unknown-id} -> 404 with requestId (GET family) ----
    {
      const res = await signedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/activations/ACT-DOES-NOT-EXIST', clock });
      assert.equal(res.status, 404);
      checkBody(patchesSpec, '/api/partner/v1/activations/{activationId}', 'get', 404, res.json, notes);
    }

    // ---- POST /activations/{id}/deactivate ----
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: `/api/partner/v1/activations/${activationId}/deactivate`, clock, body: {} });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/activations/{activationId}/deactivate', 'post', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/activations/{activationId}/deactivate', 'post', 200, res.json, notes);
    }

    // ---- POST /activations/{id}/deactivate again (idempotent by status) ----
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: `/api/partner/v1/activations/${activationId}/deactivate`, clock, body: {} });
      assert.equal(res.status, 200);
      checkBody(patchesSpec, '/api/partner/v1/activations/{activationId}/deactivate', 'post', 200, res.json, notes);
    }

    // ---- POST /activations/{id}/revoke ----
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: `/api/partner/v1/activations/${activationId}/revoke`, clock, body: {} });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/activations/{activationId}/revoke', 'post', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/activations/{activationId}/revoke', 'post', 200, res.json, notes);
    }

    // ---- POST deactivate on a REVOKED activation -> 409 ACTIVATION_REVOKED ----
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: `/api/partner/v1/activations/${activationId}/deactivate`, clock, body: {} });
      assert.equal(res.status, 409);
      checkBody(patchesSpec, '/api/partner/v1/activations/{activationId}/deactivate', 'post', 409, res.json, notes);
    }

    // ---- GET /events?orgId= ----
    {
      const res = await signedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/events?orgId=ORG-ARMA-ALPHA', clock });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/events', 'get', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/events', 'get', 200, res.json, notes);
    }

    // ---- GET /audit?orgId= ----
    {
      const res = await signedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/audit?orgId=ORG-ARMA-ALPHA', clock });
      assert.equal(res.status, 200);
      checkHeaders(patchesSpec, '/api/partner/v1/audit', 'get', 200, res.headers, notes);
      checkBody(patchesSpec, '/api/partner/v1/audit', 'get', 200, res.json, notes);
    }

    // ---- Auth failure family (401) — unsigned request ----
    {
      const res = await unsignedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/capabilities' });
      assert.equal(res.status, 401);
      checkBody(patchesSpec, '/api/partner/v1/capabilities', 'get', 401, res.json, notes);
      assert.ok(res.json.requestId, 'auth failure must carry requestId');
    }

    // ---- Rate limiting (429) — drain the token bucket ----
    {
      const clock2 = makeClock();
      const srv2 = await bootServer(clock2, {}).start();
      try {
        let last = null;
        for (let i = 0; i < 40; i++) {
          last = await signedRequest(srv2.url, { method: 'GET', path: '/api/partner/v1/capabilities', clock: clock2 });
          if (last.status === 429) break;
        }
        assert.equal(last.status, 429, 'rate limiter must engage within 40 requests (capacity 30)');
        checkBody(patchesSpec, '/api/partner/v1/capabilities', 'get', 429, last.json, notes);
        const retryAfter = last.headers.get('retry-after');
        assert.ok(retryAfter && Number(retryAfter) >= 1, 'retry-after header must be present (seconds, min 1)');
      } finally {
        await srv2.close();
      }
    }

    // ---- Unsupported version -> 400 UNSUPPORTED_API_VERSION ----
    // Documented as the cross-cutting version policy in info.description PROSE
    // (not a per-path response schema): any /api/partner/vN path with an
    // unsupported N fails closed with the same body everywhere.
    {
      const res = await unsignedRequest(srv.url, { method: 'GET', path: '/api/partner/v2/capabilities' });
      assert.equal(res.status, 400);
      assert.equal(res.json.error, 'UNSUPPORTED_API_VERSION');
      assert.equal(res.json.errorClass, 'VERSION');
      assert.deepEqual(res.json.supported, ['v1']);
      assert.ok(res.json.requestId, 'version failure must carry requestId');
    }

    // ---- Unknown route -> 404 NOT_FOUND (no 405 anywhere) ----
    {
      const res = await unsignedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/unknown-route' });
      assert.equal(res.status, 404);
      assert.equal(res.json.error, 'NOT_FOUND');
      assert.ok(res.json.requestId, 'NOT_FOUND must carry requestId');
    }

    // ---- Kill switch -> 503 single-key PARTNER_API_DISABLED, no x-request-id ----
    {
      process.env.PATCHES_PARTNER_API_DISABLED = 'true';
      try {
        const res = await unsignedRequest(srv.url, { method: 'GET', path: '/api/partner/v1/capabilities' });
        assert.equal(res.status, 503);
        assert.equal(res.json.error, 'PARTNER_API_DISABLED');
        assert.deepEqual(Object.keys(res.json), ['error'], 'kill-switch body must be the single documented key');
        assert.equal(res.headers.get('x-request-id'), null, 'kill-switch 503 carries no x-request-id');
      } finally {
        delete process.env.PATCHES_PARTNER_API_DISABLED;
      }
    }

    assertConformance(notes);
  } finally {
    await srv.close();
  }
});

test('live conformance: PATCHES — create-activation policy failures (403 family) and input errors (400/413) match the spec', async () => {
  const clock = makeClock();
  const srv = await bootServer(clock, {}).start();
  const notes = [];
  let n = 0;
  const idk = () => `IDK-CONF-POLICY-${++n}`;
  try {
    // 403 ORG_UNKNOWN (org does not exist)
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, body: { orgId: 'ORG-NOPE', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: idk() } });
      assert.equal(res.status, 403);
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 403, res.json, notes);
    }
    // 403 ENTITLEMENT_MISSING (org exists, no entitlement at all)
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, body: { orgId: 'ORG-ARMA-BETA', capability: 'home_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: idk() } });
      // ORG-ARMA-BETA + home_privacy: entitlement ENT-002 exists (BETA/home) -> need a binding mismatch instead. Use ORG-ARMA-DELTA with home_privacy (no entitlement).
      if (res.status === 200) { /* handled below */ }
    }
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, body: { orgId: 'ORG-ARMA-DELTA', capability: 'home_privacy', bindingId: 'BIND-DELTA-TSP', idempotencyKey: idk() } });
      assert.equal(res.status, 403);
      assert.equal(res.json.error, 'ENTITLEMENT_MISSING');
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 403, res.json, notes);
    }
    // 403 CAPABILITY_UNKNOWN (valid entitlement, unregistered capability)
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, body: { orgId: 'ORG-ARMA-ALPHA', capability: 'telemetry_privacy', bindingId: 'BIND-ALPHA-TSP', idempotencyKey: idk() } });
      assert.equal(res.status, 403);
      assert.equal(res.json.error, 'CAPABILITY_UNKNOWN');
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 403, res.json, notes);
    }
    // 403 BINDING_INACTIVE
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, body: { orgId: 'ORG-ARMA-ALPHA', capability: 'traffic_stop_privacy', bindingId: 'BIND-ALPHA-TSP-INACTIVE', idempotencyKey: idk() } });
      assert.equal(res.status, 403);
      assert.equal(res.json.error, 'BINDING_INACTIVE');
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 403, res.json, notes);
    }
    // 400 ACTIVATION_INPUT_MISSING (missing fields) — oneOf family
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, body: { orgId: 'ORG-ARMA-ALPHA' } });
      assert.equal(res.status, 400);
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 400, res.json, notes);
    }
    // 400 MALFORMED_PAYLOAD (body not a JSON object)
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, bodyRaw: '"just a string"' });
      assert.equal(res.status, 400);
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 400, res.json, notes);
    }
    // 413 PAYLOAD_TOO_LARGE
    {
      const res = await signedRequest(srv.url, { method: 'POST', path: '/api/partner/v1/activations', clock, bodyRaw: '{"orgId":"' + 'A'.repeat(300000) + '"}' });
      assert.equal(res.status, 413);
      checkBody(patchesSpec, '/api/partner/v1/activations', 'post', 413, res.json, notes);
      assert.equal(res.json.limitBytes, 262144);
    }
    assertConformance(notes);
  } finally {
    await srv.close();
  }
});

// ---------------------------------------------------------------------------
// Law Shield — live conformance (real gateway + real durable processor)
// ---------------------------------------------------------------------------
test('live conformance: Law Shield — transfer submission, receipt, readiness, processor process + status match the spec', async () => {
  const notes = [];
  await resetGatewayState();
  const envCleanups = [];

  // Boot the REAL durable processor (flat redacted payloads required — the
  // disclosure policy is enforced processor-side).
  const store = seedSyntheticProcessorDirectory(new SyntheticDurableLawShieldStore());
  const processorServer = createServer(createDurableProcessorServer({ store, token: PROCESSOR_TOKEN }));
  await new Promise((r) => processorServer.listen(0, '127.0.0.1', r));
  processorServer.unref(); // a skipped/failed teardown must never pin the event loop (SP10 red-gate cascade fix)
  const processorPort = processorServer.address().port;

  // Gateway env: signing + receipt secrets + the real processor.
  envCleanups.push(applyTestEnv({
    LAW_SHIELD_INTEGRATION_PROCESSOR_URL: `http://127.0.0.1:${processorPort}/process`,
    LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN: PROCESSOR_TOKEN,
  }));
  const gw = await startGateway();
  // Readiness is a SEPARATE platform-mounted handler (own server), reading the
  // same env: gateway + receipt secrets + processor configured => ready:true.
  const readiness = await startReadiness();

  // Flat redacted CASE_REFERRAL payload in a signed envelope. buildEnvelope
  // defaults are overridden so payload + payloadHash carry the REDACTOR output.
  const makeEnvelope = (n) => {
    const payload = redactedCasePayload();
    return buildEnvelope({
      transferId: `TRX-CONF-${n}`, idempotencyKey: `IDK-CONF-${n}`,
      payload, payloadHash: sha256Hex(JSON.stringify(payload)),
    });
  };

  try {
    // ---- POST /api/lawshield/arma — happy path 200 + signed receipt ----
    let envelope = makeEnvelope(1);
    let rawBody = JSON.stringify(envelope);
    let signed = signLawshield(rawBody);
    {
      const res = await lsPost(gw.port, '/api/lawshield/arma', signed, rawBody);
      assert.equal(res.status, 200);
      checkHeaders(lawshieldSpec, '/api/lawshield/arma', 'post', 200, res.headers, notes);
      checkBody(lawshieldSpec, '/api/lawshield/arma', 'post', 200, res.body, notes);
      assert.equal(res.body.accepted, true, 'receipt must be accepted');
      assert.equal(res.body.receiptId, `RCP-TRX-CONF-1`);
      // receipt signature headers (documented on the 200 response)
      for (const name of ['x-lawshield-content-sha256', 'x-lawshield-signature', 'x-lawshield-receipt-id']) {
        const actual = res.headers[name] ?? res.headers[name.toLowerCase()] ?? null;
        if (actual === null) notes.push(`receipt header ${name} missing`);
      }
    }

    // ---- replay the same signed request -> 409 REPLAYED_NONCE (real transferId) ----
    {
      const res = await lsPost(gw.port, '/api/lawshield/arma', signed, rawBody);
      assert.equal(res.status, 409);
      assert.equal(res.body.error, 'REPLAYED_NONCE');
      assert.equal(res.body.transferId, 'TRX-CONF-1');
      checkBody(lawshieldSpec, '/api/lawshield/arma', 'post', 409, res.body, notes);
    }

    // ---- fresh transfer, missing security headers -> 401 MISSING_SECURITY_HEADERS ----
    {
      envelope = makeEnvelope(2);
      rawBody = JSON.stringify(envelope);
      const res = await lsPost(gw.port, '/api/lawshield/arma', { 'content-type': 'application/json' }, rawBody);
      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'MISSING_SECURITY_HEADERS');
      checkBody(lawshieldSpec, '/api/lawshield/arma', 'post', 401, res.body, notes);
    }

    // ---- fresh transfer, invalid signature -> 401 INVALID_SIGNATURE ----
    {
      envelope = makeEnvelope(3);
      rawBody = JSON.stringify(envelope);
      const bad = { ...signLawshield(rawBody), 'x-arma-signature': '0'.repeat(64) };
      const res = await lsPost(gw.port, '/api/lawshield/arma', bad, rawBody);
      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'INVALID_SIGNATURE');
      checkBody(lawshieldSpec, '/api/lawshield/arma', 'post', 401, res.body, notes);
    }

    // ---- fresh transfer, tampered body (hash mismatch) -> 401 BODY_HASH_MISMATCH ----
    {
      envelope = makeEnvelope(4);
      const signedForEnvelope = signLawshield(JSON.stringify(envelope));
      const res = await lsPost(gw.port, '/api/lawshield/arma', signedForEnvelope, JSON.stringify({ ...envelope, sentAt: envelope.sentAt + 5 }));
      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'BODY_HASH_MISMATCH');
      checkBody(lawshieldSpec, '/api/lawshield/arma', 'post', 401, res.body, notes);
    }

    // ---- GET /api/lawshield/integration-readiness (separate handler) -> 200 ready ----
    {
      const res = await lsGet(readiness.port, '/api/lawshield/integration-readiness');
      assert.equal(res.status, 200);
      checkHeaders(lawshieldSpec, '/api/lawshield/integration-readiness', 'get', 200, res.headers, notes);
      checkBody(lawshieldSpec, '/api/lawshield/integration-readiness', 'get', 200, res.body, notes);
      assert.equal(res.body.ready, true, 'readiness must be ready with processor configured');
    }

    // ---- POST /process (processor, Bearer auth) — 200 receipt shape ----
    {
      envelope = makeEnvelope(5);
      rawBody = JSON.stringify(envelope);
      const headers = {
        'content-type': 'application/json',
        authorization: `Bearer ${PROCESSOR_TOKEN}`,
        'x-verified-arma-nonce': makeNonce(),
        'x-verified-arma-content-sha256': sha256Hex(rawBody),
        'x-integration-schema-version': envelope.schemaVersion,
        'x-integration-transfer-id': envelope.transferId,
      };
      const res = await lsPost(processorPort, '/process', headers, rawBody);
      assert.equal(res.status, 200);
      checkBody(lawshieldSpec, '/process', 'post', 200, res.body, notes);
      assert.equal(res.body.accepted, true);
      assert.equal(res.body.receiptId, 'RCP-TRX-CONF-5');
    }

    // ---- GET /status?transferId=... (processor, Bearer auth) -> 200 StatusResponse ----
    {
      const res = await lsGetAuth(processorPort, '/status?transferId=TRX-CONF-5');
      assert.equal(res.status, 200);
      checkBody(lawshieldSpec, '/status', 'get', 200, res.body, notes);
      assert.equal(res.body.found, true);
      assert.equal(res.body.transferId, 'TRX-CONF-5');
      assert.equal(res.body.status, 'ACCEPTED');
      assert.ok(Array.isArray(res.body.auditEvents) && res.body.auditEvents.length >= 1, 'accepted transfer must have audit events');
    }

    // ---- GET /status without criteria -> 400 STATUS_LOOKUP_CRITERIA_REQUIRED ----
    {
      const res = await lsGetAuth(processorPort, '/status');
      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'STATUS_LOOKUP_CRITERIA_REQUIRED');
      checkBody(lawshieldSpec, '/status', 'get', 400, res.body, notes);
    }

    // ---- POST /process unauthorized -> 401 PROCESSOR_AUTH_FAILED ----
    {
      envelope = makeEnvelope(6);
      rawBody = JSON.stringify(envelope);
      const headers = {
        'content-type': 'application/json',
        authorization: 'Bearer wrong-token',
        'x-verified-arma-nonce': makeNonce(),
        'x-verified-arma-content-sha256': sha256Hex(rawBody),
        'x-integration-schema-version': envelope.schemaVersion,
        'x-integration-transfer-id': envelope.transferId,
      };
      const res = await lsPost(processorPort, '/process', headers, rawBody);
      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'PROCESSOR_AUTH_FAILED');
      checkBody(lawshieldSpec, '/process', 'post', 401, res.body, notes);
    }

    // ---- gateway method check -> 405 METHOD_NOT_ALLOWED ----
    {
      const res = await lsGet(gw.port, '/api/lawshield/arma');
      assert.equal(res.status, 405);
      assert.equal(res.body.error, 'METHOD_NOT_ALLOWED');
      checkBody(lawshieldSpec, '/api/lawshield/arma', 'post', 405, res.body, notes);
    }

    assertConformance(notes);
  } finally {
    for (const c of envCleanups) c();
    await new Promise((r) => processorServer.close(r));
    await gw.close();
    await readiness.close();
  }
});

// Law Shield signing helper (mirrors the harness signer but with fresh nonce).
function signLawshield(body) {
  const timestamp = String(Date.now());
  const nonce = makeNonce();
  const bodyHash = sha256Hex(body);
  const crypto = globalThis.crypto ?? null;
  const sig = hmacHex(GATEWAY_SECRET, `${SCHEMA_VERSION}\n${timestamp}\n${nonce}\n${bodyHash}`);
  return {
    'content-type': 'application/json',
    'x-arma-schema-version': SCHEMA_VERSION,
    'x-arma-timestamp': timestamp,
    'x-arma-nonce': nonce,
    'x-arma-content-sha256': bodyHash,
    'x-arma-signature': sig,
  };
}

function makeNonce() {
  return cryptoRandomBytes(24).toString('base64url');
}

// Bearer-authenticated GET against the processor (its /status route requires
// auth BEFORE the criteria check — fail closed).
async function lsGetAuth(port, path) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'GET',
    headers: { authorization: `Bearer ${PROCESSOR_TOKEN}` },
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, headers: Object.fromEntries(res.headers), body: json, raw: text };
}

import { createHmac as nodeCreateHmac, randomBytes as cryptoRandomBytes } from 'node:crypto';
function hmacHex(secret, value) {
  return nodeCreateHmac('sha256', secret).update(value).digest('hex');
}
