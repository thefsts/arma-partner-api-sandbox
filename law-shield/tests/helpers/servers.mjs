// Shared synthetic test infrastructure for the Law Shield lane.
// All identifiers, secrets, and records are synthetic. No production values.
import { createServer } from 'node:http';
import crypto from 'node:crypto';

export const GATEWAY_SECRET = 'synthetic-arma-to-lawshield-test-secret';
export const RECEIPT_SECRET = 'synthetic-lawshield-to-arma-test-secret';
export const PROCESSOR_TOKEN = 'synthetic-processor-bearer-token';

export function sha256Hex(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

export function hmacHex(secret, value) { return crypto.createHmac('sha256', secret).update(value).digest('hex'); }

export const SCHEMA_VERSION = 'arma-lawshield.v1';

// --- Synthetic envelope factory (parity with validateEnvelope requirements) ---
export function buildEnvelope(overrides = {}) {
  const now = Date.now();
  const payload = {
    recordType: 'CASE_REFERRAL',
    recordId: 'rec-0001',
    incidentId: 'INC-1001',
    data: { summary: 'Synthetic incident summary for sandbox verification.', location: 'Synthetic Location 1' },
  };
  const envelope = {
    schemaVersion: SCHEMA_VERSION,
    transferId: 'TRX-0001',
    idempotencyKey: 'IDK-0001',
    sourceSystem: 'ARMA_360',
    destinationSystem: 'LAW_SHIELD',
    armaOrgId: 'org-arma-1',
    lawShieldOrgId: 'ls-org-1',
    recordType: 'CASE_REFERRAL',
    recordId: 'rec-0001',
    authorizedBy: 'user-77',
    authorizationReason: 'Owner-approved synthetic test disclosure',
    mapping: { armaOrgId: 'org-arma-1', lawShieldOrgId: 'ls-org-1', lawShieldCaseId: 'LS-CASE-1' },
    incidentId: 'INC-1001',
    createdAt: now - 1000,
    sentAt: now,
    expiresAt: now + 3600_000,
    payload,
    payloadHash: sha256Hex(JSON.stringify(payload)),
  };
  return Object.assign(envelope, overrides);
}

export function signRequest({ body, secret = GATEWAY_SECRET, timestamp = String(Date.now()), nonce = crypto.randomBytes(24).toString('base64url'), schemaVersion = SCHEMA_VERSION }) {
  const bodyHash = sha256Hex(body);
  const signature = hmacHex(secret, `${schemaVersion}\n${timestamp}\n${nonce}\n${bodyHash}`);
  return {
    'content-type': 'application/json',
    'x-arma-schema-version': schemaVersion,
    'x-arma-timestamp': timestamp,
    'x-arma-nonce': nonce,
    'x-arma-content-sha256': bodyHash,
    'x-arma-signature': signature,
  };
}

// --- Minimal HTTP client against a live server ---
export async function post(port, path, headers, body) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers, body });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, headers: Object.fromEntries(res.headers), body: json, raw: text };
}

export async function get(port, path) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'GET' });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, headers: Object.fromEntries(res.headers), body: json, raw: text };
}

// --- Real gateway server wrapping the production handler module ---
export async function startGateway({ port = 0 } = {}) {
  const mod = await import(`file://${process.cwd()}/law-shield/lawshield/arma-integration.js`);
  const server = createServer(mod.default);
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  return { server, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

export async function startReadiness({ port = 0 } = {}) {
  const mod = await import(`file://${process.cwd()}/law-shield/lawshield/integration-readiness.js`);
  const server = createServer(mod.default);
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  return { server, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

// --- Synthetic durable processor stub (Stop Point 3 will replace with the real one) ---
// Modes:
//   'healthy'      normal durable behavior: idempotent, returns receipt
//   'reject'       returns ORG_NOT_AUTHORIZED accepted:false
//   'unavailable'  returns 503 PROCESSOR_UNAVAILABLE
//   'mismatch'     returns receipt with WRONG transferId (D2 path)
//   'hang'         never responds (D3 timeout path)
//   'nonjson'      returns HTML (malformed processor response)
//   'garbage-receipt' returns accepted:true but receiptId of a DIFFERENT transfer
export async function startProcessor({ port = 0, mode = 'healthy', accepted = {}, events = [] } = {}) {
  const seen = new Map(); // idempotencyKey -> receipt (duplicate-safe processing)
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      events.push({ url: req.url, method: req.method, auth: req.headers.authorization ?? null, transferId: safeJson(body)?.transferId ?? null, idempotencyKey: safeJson(body)?.idempotencyKey ?? null, nonce: req.headers['x-verified-arma-nonce'] ?? null });
      if (req.headers.authorization !== `Bearer ${PROCESSOR_TOKEN}`) { res.writeHead(401, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: 'PROCESSOR_AUTH_FAILED', accepted: false })); }
      let envelope; try { envelope = JSON.parse(body); } catch { res.writeHead(400, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: 'INVALID_JSON', accepted: false })); }
      if (mode === 'hang') return; // never respond -> gateway timeout
      if (mode === 'nonjson') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html>not json</html>'); }
      if (mode === 'unavailable') { res.writeHead(503, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: 'PROCESSOR_UNAVAILABLE', accepted: false })); }
      if (mode === 'reject') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: 'ORG_NOT_AUTHORIZED', accepted: false })); }
      if (mode === 'mismatch') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ accepted: true, receiptId: 'RCP-mismatch', transferId: 'TRX-DIFFERENT', payloadHash: envelope.payloadHash })); }
      if (mode === 'garbage-receipt') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ accepted: true, receiptId: 'RCP-OTHER-TRANSFER' })); }
      // healthy: durable, idempotent processing
      const prior = seen.get(envelope.idempotencyKey);
      if (prior) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(prior)); }
      const receipt = { accepted: true, receiptId: 'RCP-' + envelope.transferId, transferId: envelope.transferId, acceptedAt: Date.now(), processingResult: 'PERSISTED', payloadHash: envelope.payloadHash };
      seen.set(envelope.idempotencyKey, receipt);
      accepted[envelope.transferId] = receipt;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(receipt));
    });
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  return { server, port: server.address().port, close: () => new Promise((r) => server.close(r)), seen };
}

function safeJson(text) { try { return JSON.parse(text); } catch { return {}; } }

// --- Environment lifecycle for tests ---
export function applyTestEnv(overrides = {}) {
  const saved = {};
  const defaults = {
    ARMA_TO_LAW_SHIELD_HMAC_SECRET: GATEWAY_SECRET,
    LAW_SHIELD_TO_ARMA_HMAC_SECRET: RECEIPT_SECRET,
    LAW_SHIELD_ARMA_INTEGRATION_DISABLED: 'false',
    LAW_SHIELD_GATEWAY_REPLAY_GUARD: 'enabled',
  };
  const all = { ...defaults, ...overrides };
  for (const [k, v] of Object.entries(all)) { saved[k] = process.env[k]; process.env[k] = v; }
  return () => { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } };
}

// Reset gateway-level module state (nonce replay map) between tests.
export async function resetGatewayState() {
  const sec = await import(`file://${process.cwd()}/law-shield/lawshield/_integrationSecurity.js`);
  sec.replayGuard.reset();
}
