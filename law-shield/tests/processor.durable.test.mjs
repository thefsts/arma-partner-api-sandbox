// Stop Point 3 — Durable Law Shield processor tests: the 21 mandatory cases.
// Every test drives the REAL durable processor (durable/store.js +
// durable/processor.js) — the same pure decision function a Convex mutation
// would call — over real HTTP where a server is needed, with fail-point
// injection for the transaction-safety cases. Payloads use the REAL wire
// contract: a FLAT minimum-necessary redacted payload exactly as
// arma/redaction.js produces it (payloadEnvelope.data IS the envelope
// payload — no wrapper). Synthetic data only; no production values.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { SyntheticDurableLawShieldStore, seedSyntheticProcessorDirectory } from '../lawshield/durable/store.js';
import { processTransferRequest, createDurableProcessorServer } from '../lawshield/durable/processor.js';
import { redactPayload } from '../arma/redaction.js';
import { SyntheticLawShieldStore, SyntheticIdentityDirectory, seedSyntheticIdentities } from '../arma/persistence.js';
import { ArmaLawShieldTransferService } from '../arma/transferService.js';
import { verifyReceipt } from '../arma/receiptVerifier.js';
import { buildEnvelope as buildArmaEnvelope } from '../arma/envelope.js';
import {
  startGateway, applyTestEnv, resetGatewayState, signRequest, post, buildEnvelope,
  sha256Hex, GATEWAY_SECRET, RECEIPT_SECRET, PROCESSOR_TOKEN, SCHEMA_VERSION,
} from './helpers/servers.mjs';

const REASON = 'Commander approved synthetic referral for legal review';

// REAL-contract payload: the redactor output for CASE_REFERRAL. The raw input
// deliberately contains always-redacted fields (ssn, officerNotes) to prove
// the payload that reaches the processor is already minimum-necessary.
function validRedactedPayload(overrides = {}) {
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

function rawCaseInput(overrides = {}) {
  return {
    caseNumber: 'CASE-100',
    incidentId: 'INC-1001',
    incidentDate: '2026-01-05',
    incidentType: 'SYNTHETIC_INCIDENT',
    summary: 'Synthetic referral for legal review',
    legalNeeds: ['LEGAL_REVIEW'],
    incidentLocation: 'Synthetic Location 1',
    ssn: '000-00-0000',
    officerNotes: 'never leaves ARMA',
    ...overrides,
  };
}

// Build a processor-bound request exactly as the gateway forwards one:
// verified-nonce + content-hash + schema + transfer-id headers over the
// ORIGINAL raw body bytes, Bearer-authenticated. A fresh nonce is generated
// per call (that is the retry / duplicate-delivery semantics the gateway uses).
function makeForwarded({ payload = null, overrides = {}, headerOverrides = {} } = {}) {
  const p = payload ?? validRedactedPayload();
  const envelope = buildEnvelope({ ...overrides, payload: p, payloadHash: sha256Hex(JSON.stringify(p)) });
  const rawBody = JSON.stringify(envelope);
  const signed = signRequest({ body: rawBody });
  const headers = {
    'content-type': 'application/json',
    authorization: `Bearer ${PROCESSOR_TOKEN}`,
    'x-verified-arma-nonce': signed['x-arma-nonce'],
    'x-verified-arma-content-sha256': sha256Hex(rawBody),
    'x-integration-schema-version': envelope.schemaVersion,
    'x-integration-transfer-id': envelope.transferId,
    ...headerOverrides,
  };
  return { envelope, rawBody, headers, nonce: signed['x-arma-nonce'] };
}

// Boot the real durable processor over HTTP + the real gateway pointed at it.
async function bootDurable({ env = {} } = {}) {
  await resetGatewayState();
  const store = seedSyntheticProcessorDirectory(new SyntheticDurableLawShieldStore());
  const server = createServer(createDurableProcessorServer({ store, token: PROCESSOR_TOKEN }));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const restore = applyTestEnv({
    LAW_SHIELD_INTEGRATION_PROCESSOR_URL: `http://127.0.0.1:${port}/process`,
    LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN: PROCESSOR_TOKEN,
    ...env,
  });
  const gw = await startGateway();
  return { store, server, port, gw, restore, close: () => { restore(); server.close(); gw.close(); } };
}

// Full synthetic stack: ARMA transferService -> real gateway -> real durable
// processor (timeout / reconciliation / duplicate-safety cases).
async function bootFull(env = {}) {
  await resetGatewayState();
  const processorStore = seedSyntheticProcessorDirectory(new SyntheticDurableLawShieldStore());
  const processorServer = createServer(createDurableProcessorServer({ store: processorStore, token: PROCESSOR_TOKEN }));
  await new Promise((r) => processorServer.listen(0, '127.0.0.1', r));
  const processorPort = processorServer.address().port;
  const restore = applyTestEnv({
    LAW_SHIELD_INTEGRATION_PROCESSOR_URL: `http://127.0.0.1:${processorPort}/process`,
    LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN: PROCESSOR_TOKEN,
    ...env,
  });
  const gw = await startGateway();
  const store = new SyntheticLawShieldStore();
  const directory = seedSyntheticIdentities(new SyntheticIdentityDirectory());
  store.upsertOrgMapping({ armaOrgId: 'org-arma-1', lawShieldOrgId: 'ls-org-1', createdByUserId: 'user-commander-1' });
  store.upsertCaseMapping({ armaOrgId: 'org-arma-1', incidentId: 'INC-1001', lawShieldOrgId: 'ls-org-1', lawShieldCaseId: 'LS-CASE-1', createdByUserId: 'user-commander-1' });
  const service = new ArmaLawShieldTransferService({
    store, directory,
    config: { gatewayUrl: `http://127.0.0.1:${gw.port}/api/lawshield/arma`, signingSecret: GATEWAY_SECRET, receiptSecret: RECEIPT_SECRET },
  });
  return {
    service, store, directory, gw, processorStore, processorServer, processorPort, restore,
    close: () => { restore(); gw.close(); processorServer.close(); },
  };
}

// ARMA-side lifecycle up to READY_TO_SEND (human authorization included).
function drive(h, { recordId = 'CASE-100', caseNumber = 'CASE-100' } = {}) {
  const draft = h.service.createDraft({
    actor: { userId: 'user-commander-1' }, armaOrgId: 'org-arma-1', incidentId: 'INC-1001',
    recordType: 'CASE_REFERRAL', recordId, rawPayload: rawCaseInput({ caseNumber }), lawShieldOrgId: 'ls-org-1',
  });
  h.service.authorize({ actor: { userId: 'user-commander-1' }, transferId: draft.transfer.transferId, authorizationReason: REASON });
  h.service.ready({ transferId: draft.transfer.transferId });
  return draft;
}

async function deliver(h, req) { return post(h.port, '/process', req.headers, req.rawBody); }

async function statusInquiry(port, params) {
  const url = `http://127.0.0.1:${port}/status?` + new URLSearchParams({ schemaVersion: SCHEMA_VERSION, ...params });
  const res = await fetch(url, { headers: { authorization: `Bearer ${PROCESSOR_TOKEN}` } });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, body: json };
}

// Rebuild the exact envelope ARMA's send() would send for a stored transfer
// (same transferId / idempotencyKey / redacted payload) — redelivery semantics.
function rebuildEnvelopeBody(t) {
  const envelope = buildArmaEnvelope({
    transferId: t.transferId, idempotencyKey: t.idempotencyKey,
    armaOrgId: t.armaOrgId, lawShieldOrgId: t.lawShieldOrgId,
    recordType: t.recordType, recordId: t.recordId,
    authorizedBy: t.authorizedByUserId, authorizationReason: t.authorizationReason,
    incidentId: t.incidentId, lawShieldCaseId: t.lawShieldCaseId,
    payload: t.payloadEnvelope.data,
    createdAt: t.createdAt, sentAt: Date.now(), expiresAt: Date.now() + 15 * 60 * 1000,
  });
  return JSON.stringify(envelope);
}

// ---------------------------------------------------------------------------
// Mandatory tests 1-4: authoritative acceptance, replay registry, idempotency
// registry (same-payload collapse, different-payload conflict).
// ---------------------------------------------------------------------------

// 1. First valid transfer is accepted (durable record, receipt, audit).
test('1. first valid transfer is accepted by the durable processor', async () => {
  const h = await bootDurable();
  const req = makeForwarded({ overrides: { transferId: 'TRX-SP3-001', idempotencyKey: 'IDK-SP3-001' } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, true);
  assert.equal(res.body.transferId, 'TRX-SP3-001');
  assert.equal(res.body.receiptId, 'RCP-TRX-SP3-001');
  assert.equal(res.body.processingResult, 'PERSISTED');
  assert.equal(res.body.payloadHash, req.envelope.payloadHash);
  // Durable state: transfer record, receipt record, nonce registered, audit.
  const transfer = h.store.getDurableTransfer('TRX-SP3-001');
  assert.equal(transfer.status, 'ACCEPTED');
  assert.equal(transfer.payloadHash, req.envelope.payloadHash);
  assert.ok(transfer.acceptedAt > 0);
  assert.ok(h.store.getReceiptRecord('RCP-TRX-SP3-001'));
  assert.ok(h.store.getNonceRecord({ schemaVersion: SCHEMA_VERSION, nonce: req.nonce }));
  const events = h.store.getAuditEvents({ transferId: 'TRX-SP3-001' });
  assert.ok(events.some((e) => e.eventType === 'TRANSFER_ACCEPTED' && e.outcome === 'ACCEPTED'));
  // No payload content may be persisted on the processor side (hash only).
  assert.equal('payload' in transfer, false);
  assert.equal(JSON.stringify(transfer).includes('Synthetic referral for legal review'), false);
  h.close();
});

// 2. Exact replayed nonce is denied (fails closed) — even before idempotency.
test('2. exact replayed nonce is denied by the authoritative replay registry', async () => {
  const h = await bootDurable();
  const req = makeForwarded({ overrides: { transferId: 'TRX-SP3-002', idempotencyKey: 'IDK-SP3-002' } });
  const first = await deliver(h, req);
  assert.equal(first.status, 200);
  assert.equal(first.body.accepted, true);
  // Byte-for-byte replay of the same signed request: same nonce, same body.
  const replay = await deliver(h, req);
  assert.equal(replay.status, 200);
  assert.equal(replay.body.accepted, false);
  assert.equal(replay.body.error, 'REPLAYED_NONCE');
  // The replay attempt was audited; the original record is untouched.
  const events = h.store.getAuditEvents({ transferId: 'TRX-SP3-002' });
  assert.ok(events.some((e) => e.eventType === 'NONCE_REPLAY_REJECTED'));
  assert.equal(h.store.getDurableTransfer('TRX-SP3-002').status, 'ACCEPTED');
  assert.equal(h.store.receiptCount(), 1);
  h.close();
});

// 3. Duplicate idempotency key + SAME payload -> deterministic duplicate-safe
//    result: the stored receipt is returned, no second disclosure is created.
test('3. duplicate idempotency (same payload) collapses to the deterministic stored receipt', async () => {
  const h = await bootDurable();
  const req1 = makeForwarded({ overrides: { transferId: 'TRX-SP3-003', idempotencyKey: 'IDK-SP3-003' } });
  const first = await deliver(h, req1);
  assert.equal(first.body.accepted, true);
  // Duplicate delivery: FRESH nonce (a retry after a lost response), same
  // transferId + idempotencyKey + payload bytes.
  const req2 = makeForwarded({ overrides: { transferId: 'TRX-SP3-003', idempotencyKey: 'IDK-SP3-003' } });
  assert.notEqual(req2.nonce, req1.nonce); // genuinely fresh nonce
  const dup = await deliver(h, req2);
  assert.equal(dup.status, 200);
  assert.equal(dup.body.accepted, true);
  assert.equal(dup.body.receiptId, first.body.receiptId);
  assert.equal(dup.body.acceptedAt, first.body.acceptedAt); // deterministic: stored receipt, not a new one
  assert.equal(dup.body.transferId, 'TRX-SP3-003');
  // Exactly ONE receipt, ONE accepted transfer, ONE disclosure.
  assert.equal(h.store.receiptCount(), 1);
  assert.equal(h.store.transferCount(), 1);
  const events = h.store.getAuditEvents({ transferId: 'TRX-SP3-003' });
  assert.ok(events.some((e) => e.eventType === 'DUPLICATE_DELIVERY_COLLAPSED' && e.detail?.duplicateDelivery === true));
  h.close();
});

// 4. Duplicate idempotency key + DIFFERENT payload -> integrity conflict,
//    denied (quarantined for human review), never accepted, never collapsed.
test('4. duplicate idempotency (different payload) is an integrity conflict and is denied', async () => {
  const h = await bootDurable();
  const req1 = makeForwarded({ overrides: { transferId: 'TRX-SP3-004', idempotencyKey: 'IDK-SP3-004' } });
  const first = await deliver(h, req1);
  assert.equal(first.body.accepted, true);
  // Same idempotency key, DIFFERENT content: a changed summary alters the
  // payload hash. The registry must treat this as tampering/ambiguity.
  const req2 = makeForwarded({
    payload: validRedactedPayload({ summary: 'Altered synthetic content under the same key' }),
    overrides: { transferId: 'TRX-SP3-004', idempotencyKey: 'IDK-SP3-004' },
  });
  const conflict = await deliver(h, req2);
  assert.equal(conflict.status, 200);
  assert.equal(conflict.body.accepted, false);
  assert.equal(conflict.body.error, 'IDEMPOTENCY_KEY_CONFLICT');
  assert.equal(conflict.body.quarantined, true);
  // The original accepted record is untouched and remains authoritative; the
  // content conflict (same transferId, altered content) was AUDITED without
  // overwriting the durable record or creating a second disclosure.
  assert.equal(h.store.getDurableTransfer('TRX-SP3-004').status, 'ACCEPTED');
  const events = h.store.getAuditEvents({ transferId: 'TRX-SP3-004' });
  assert.ok(events.some((e) => e.detail?.code === 'TRANSFER_CONTENT_CONFLICT'));
  // (b) a DIFFERENT transferId reusing the same idempotency key: quarantined
  //     durably under a conflict-scoped record for human review.
  const req3 = makeForwarded({
    payload: validRedactedPayload({ summary: 'Different transfer reusing the same idempotency key' }),
    overrides: { transferId: 'TRX-SP3-004B', idempotencyKey: 'IDK-SP3-004' },
  });
  const conflictB = await deliver(h, req3);
  assert.equal(conflictB.status, 200);
  assert.equal(conflictB.body.accepted, false);
  assert.equal(conflictB.body.error, 'IDEMPOTENCY_KEY_CONFLICT');
  assert.equal(conflictB.body.quarantined, true);
  const quarantined = h.store.getDurableTransfer('CONFLICT-TRX-SP3-004B');
  assert.equal(quarantined.status, 'QUARANTINED');
  assert.equal(quarantined.lastErrorCode, 'IDEMPOTENCY_KEY_CONFLICT');
  // Still exactly one receipt — the conflicting deliveries created none.
  assert.equal(h.store.receiptCount(), 1);
  h.close();
});

// ---------------------------------------------------------------------------
// Mandatory tests 5-8: explicit org/case mapping discipline at the processor.
// ---------------------------------------------------------------------------

// 5. Cross-org mapping (ARMA org mapped to a different Law Shield org) denied.
test('5. cross-org mapping is denied by the durable processor', async () => {
  const h = await bootDurable();
  // org-arma-1 is mapped to ls-org-1; the envelope claims ls-org-2.
  const req = makeForwarded({ overrides: {
    transferId: 'TRX-SP3-005', idempotencyKey: 'IDK-SP3-005', lawShieldOrgId: 'ls-org-2',
    mapping: { armaOrgId: 'org-arma-1', lawShieldOrgId: 'ls-org-2', lawShieldCaseId: 'LS-CASE-1' },
  } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'ORG_MAPPING_MISMATCH');
  const transfer = h.store.getDurableTransfer('TRX-SP3-005');
  assert.equal(transfer.status, 'REJECTED');
  assert.equal(transfer.lastErrorCode, 'ORG_MAPPING_MISMATCH');
  assert.equal(h.store.receiptCount(), 0);
  h.close();
});

// 6. Inactive org mapping denied (explicit mapping exists but is deactivated).
test('6. inactive org mapping is denied', async () => {
  const h = await bootDurable();
  h.store.deactivateOrgMapping('org-arma-1');
  const req = makeForwarded({ overrides: { transferId: 'TRX-SP3-006', idempotencyKey: 'IDK-SP3-006' } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'ORG_MAPPING_INACTIVE');
  assert.equal(h.store.getDurableTransfer('TRX-SP3-006').status, 'REJECTED');
  h.close();
});

// 7. Missing case mapping denied (incident-scoped transfer, no mapping).
test('7. missing case mapping is denied', async () => {
  const h = await bootDurable();
  // INC-9001 has no case mapping in the processor directory.
  const p = validRedactedPayload({ incidentId: 'INC-9001' });
  const req = makeForwarded({ payload: p, overrides: {
    transferId: 'TRX-SP3-007', idempotencyKey: 'IDK-SP3-007', incidentId: 'INC-9001',
    mapping: { armaOrgId: 'org-arma-1', lawShieldOrgId: 'ls-org-1', lawShieldCaseId: 'LS-CASE-1' },
  } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'CASE_MAPPING_MISSING');
  assert.equal(h.store.getDurableTransfer('TRX-SP3-007').status, 'REJECTED');
  h.close();
});

// 8. Wrong case mapping denied (case mapping points to a different Law Shield
//    org / case than the envelope claims).
test('8. wrong case mapping is denied', async () => {
  const h = await bootDurable();
  // Envelope claims LS-CASE-2 for org-arma-1::INC-1001, but the directory
  // maps that incident to LS-CASE-1 — case mapping mismatch.
  const req = makeForwarded({ overrides: {
    transferId: 'TRX-SP3-008', idempotencyKey: 'IDK-SP3-008',
    mapping: { armaOrgId: 'org-arma-1', lawShieldOrgId: 'ls-org-1', lawShieldCaseId: 'LS-CASE-2' },
  } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'CASE_MAPPING_MISMATCH');
  assert.equal(h.store.getDurableTransfer('TRX-SP3-008').status, 'REJECTED');
  h.close();
});

// ---------------------------------------------------------------------------
// Mandatory tests 9-11: human-only authorization + minimum-necessary policy.
// ---------------------------------------------------------------------------

// 9. Unauthorized human authorizer denied at the processor (unknown to the
//    processor's replicated authorizer directory).
test('9. unauthorized human authorizer is denied by the durable processor', async () => {
  const h = await bootDurable();
  const req = makeForwarded({ overrides: {
    transferId: 'TRX-SP3-009', idempotencyKey: 'IDK-SP3-009', authorizedBy: 'user-not-an-authorizer-9',
  } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'AUTHORIZER_UNKNOWN');
  assert.equal(h.store.getDurableTransfer('TRX-SP3-009').status, 'REJECTED');
  h.close();
});

// 9b. Known authorizer but WRONG ORG is also denied (defense in depth).
test('9b. authorizer from the wrong org is denied', async () => {
  const h = await bootDurable();
  const req = makeForwarded({ overrides: {
    transferId: 'TRX-SP3-009B', idempotencyKey: 'IDK-SP3-009B', authorizedBy: 'user-commander-2',
  } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'AUTHORIZER_ORG_MISMATCH');
  h.close();
});

// 10. AI authorization denied — the canonical validateEnvelope rule fires at
//     the processor exactly as at the gateway (defense in depth, both sides).
test('10. AI authorization is denied by the durable processor', async () => {
  const h = await bootDurable();
  const req = makeForwarded({ overrides: {
    transferId: 'TRX-SP3-010', idempotencyKey: 'IDK-SP3-010', authorizedBy: 'AI:JOY',
  } });
  const res = await deliver(h, req);
  assert.equal(res.status, 200);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'AI_CANNOT_AUTHORIZE_TRANSFER');
  // Envelope-rejected attempts are still audited (identifier-only detail).
  const events = h.store.getAuditEvents({ transferId: 'TRX-SP3-010' });
  assert.ok(events.some((e) => e.eventType === 'TRANSFER_ENVELOPE_REJECTED'));
  h.close();
});

// 11. Minimum-necessary policy violation denied (quarantined): a payload that
//     carries an always-redacted field or a non-allow-listed field is refused.
test('11. minimum-necessary policy violation is denied and quarantined', async () => {
  const h = await bootDurable();
  // (a) ALWAYS_REDACTED field smuggled into the payload.
  const smuggled = { ...validRedactedPayload(), ssn: '000-00-0000' };
  const reqA = makeForwarded({ payload: smuggled, overrides: { transferId: 'TRX-SP3-011A', idempotencyKey: 'IDK-SP3-011A' } });
  const resA = await deliver(h, reqA);
  assert.equal(resA.status, 200);
  assert.equal(resA.body.accepted, false);
  assert.equal(resA.body.error, 'ALWAYS_REDACTED_FIELD_PRESENT');
  assert.equal(resA.body.quarantined, true);
  assert.ok(resA.body.violationPaths.some((p) => p.includes('ssn')));
  // (b) Non-allow-listed field (the stub-era 'data' wrapper shape).
  const wrapper = { data: { summary: 'wrapped shape is not minimum-necessary' } };
  const reqB = makeForwarded({ payload: wrapper, overrides: { transferId: 'TRX-SP3-011B', idempotencyKey: 'IDK-SP3-011B' } });
  const resB = await deliver(h, reqB);
  assert.equal(resB.body.accepted, false);
  assert.equal(resB.body.error, 'MINIMUM_NECESSARY_VIOLATION');
  assert.equal(resB.body.quarantined, true);
  // Both quarantine records exist with field NAMES only in the audit trail.
  assert.equal(h.store.getDurableTransfer('TRX-SP3-011A').status, 'QUARANTINED');
  assert.equal(h.store.getDurableTransfer('TRX-SP3-011B').status, 'QUARANTINED');
  const auditText = JSON.stringify(h.store.getAuditEvents());
  assert.equal(auditText.includes('000-00-0000'), false); // content never in audit
  assert.equal(h.store.receiptCount(), 0);
  h.close();
});

// ---------------------------------------------------------------------------
// Mandatory tests 12-13: transaction safety — a failure at ANY durable write
// rolls back EVERYTHING (nonce + transfer + receipt + idempotency + audit all
// commit together or none does). failPoints are the TEST-ONLY injection
// surface for exactly these cases; production never sets them.
// ---------------------------------------------------------------------------

// 12. Processor persistence failure (transfer write fails) rolls the whole
//     transaction back and fails closed — nothing is accepted or persisted.
test('12. persistence failure rolls back the transaction and fails closed', async () => {
  const h = await bootDurable();
  const before = {
    transfers: h.store.transferCount(), receipts: h.store.receiptCount(),
    nonces: h.store.nonceCount(), audit: h.store.audit.length,
  };
  // Inject: the durable transfer write fails mid-transaction.
  h.store.failPoints.persistTransfer = true;
  const req = makeForwarded({ overrides: { transferId: 'TRX-SP3-012', idempotencyKey: 'IDK-SP3-012' } });
  const res = await deliver(h, req);
  assert.equal(res.status, 500);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'PROCESSOR_PERSISTENCE_FAILED');
  h.store.failPoints.persistTransfer = false;
  // ROLLBACK PROOF: no transfer, no receipt, no nonce, no binding — the only
  // durable trace is the failure audit event itself.
  assert.equal(h.store.getDurableTransfer('TRX-SP3-012'), null);
  assert.equal(h.store.getIdempotencyBinding({ schemaVersion: SCHEMA_VERSION, idempotencyKey: 'IDK-SP3-012' }), null);
  assert.equal(h.store.getNonceRecord({ schemaVersion: SCHEMA_VERSION, nonce: req.nonce }), null);
  assert.equal(h.store.transferCount(), before.transfers);
  assert.equal(h.store.receiptCount(), before.receipts);
  assert.equal(h.store.nonceCount(), before.nonces);
  const failureEvents = h.store.getAuditEvents({ transferId: 'TRX-SP3-012' });
  assert.ok(failureEvents.some((e) => e.eventType === 'PROCESSOR_TRANSACTION_FAILED' && e.outcome === 'FAILED'));
  // Fail closed: the same delivery can be retried cleanly afterwards.
  const retry = makeForwarded({ overrides: { transferId: 'TRX-SP3-012', idempotencyKey: 'IDK-SP3-012' } });
  const retryRes = await deliver(h, retry);
  assert.equal(retryRes.status, 200);
  assert.equal(retryRes.body.accepted, true);
  assert.equal(retryRes.body.receiptId, 'RCP-TRX-SP3-012');
  h.close();
});

// 13. Audit-write failure does NOT create silent acceptance: if the audit
//     write fails inside the acceptance transaction, the acceptance itself
//     rolls back — the processor refuses to accept without a durable audit.
test('13. audit write failure does not create silent acceptance', async () => {
  const h = await bootDurable();
  const before = { transfers: h.store.transferCount(), receipts: h.store.receiptCount() };
  // Inject: the audit append fails inside the acceptance transaction.
  h.store.failPoints.auditWrite = true;
  const req = makeForwarded({ overrides: { transferId: 'TRX-SP3-013', idempotencyKey: 'IDK-SP3-013' } });
  const res = await deliver(h, req);
  assert.equal(res.status, 500);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'PROCESSOR_PERSISTENCE_FAILED');
  h.store.failPoints.auditWrite = false;
  // NOTHING was accepted: no transfer, no receipt, no idempotency binding.
  assert.equal(h.store.getDurableTransfer('TRX-SP3-013'), null);
  assert.equal(h.store.getIdempotencyBinding({ schemaVersion: SCHEMA_VERSION, idempotencyKey: 'IDK-SP3-013' }), null);
  assert.equal(h.store.receiptCount(), before.receipts);
  assert.equal(h.store.transferCount(), before.transfers);
  // And the receipt-write fail point behaves the same way (all-or-nothing).
  h.store.failPoints.persistReceipt = true;
  const reqB = makeForwarded({ overrides: { transferId: 'TRX-SP3-013B', idempotencyKey: 'IDK-SP3-013B' } });
  const resB = await deliver(h, reqB);
  h.store.failPoints.persistReceipt = false;
  assert.equal(resB.status, 500);
  assert.equal(resB.body.accepted, false);
  assert.equal(h.store.getDurableTransfer('TRX-SP3-013B'), null);
  assert.equal(h.store.receiptCount(), before.receipts);
  h.close();
});

// ---------------------------------------------------------------------------
// Mandatory tests 14-16: ambiguity reconciliation, duplicate delivery safety,
// deterministic receipts. These run the FULL synthetic stack: ARMA
// transferService -> real gateway -> real durable processor.
// ---------------------------------------------------------------------------

// 14. Timeout after durable acceptance reconciles correctly: the ARMA side
//     times out (response lost), opens reconciliation, queries the processor's
//     status endpoint, and finds the ACCEPTED durable record + receipt — no
//     second disclosure is created by the recovery re-delivery.
test('14. timeout after durable acceptance reconciles to the accepted state (no duplicate disclosure)', async () => {
  const h = await bootFull();
  const draft = drive(h, { recordId: 'CASE-114', caseNumber: 'CASE-114' });
  const tid = draft.transfer.transferId;

  // Interpose: swallow the gateway's success response so ARMA sees a timeout
  // AFTER the processor durably accepted (accepted-but-response-lost).
  const realFetch = h.service.fetchImpl;
  h.service.fetchImpl = async (url, init) => {
    const response = await realFetch(url, init);
    await response.text(); // let the gateway + processor finish durably
    throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
  };
  const r = await h.service.send({ transferId: tid });
  h.service.fetchImpl = realFetch;
  assert.equal(r.outcome, 'RECONCILIATION_REQUIRED');
  assert.equal(h.store.getTransfer(tid).status, 'RECONCILIATION_REQUIRED');
  assert.equal(h.store.getTransfer(tid).lastErrorCode, 'PROCESSOR_TIMEOUT');

  // The processor HAS durably accepted (the response was lost, not the write).
  const status = await statusInquiry(h.processorPort, { transferId: tid });
  assert.equal(status.status, 200);
  assert.equal(status.body.found, true);
  assert.equal(status.body.status, 'ACCEPTED');
  assert.equal(status.body.receiptId, 'RCP-' + tid);
  assert.equal(status.body.idempotency.outcome, 'ACCEPTED');
  assert.ok(status.body.auditEventCount >= 1);

  // Recovery: re-deliver the SAME transfer (same idempotencyKey, fresh nonce).
  // The idempotency registry collapses it to the stored receipt — the ARMA
  // side can reconcile safely: still exactly ONE accepted disclosure.
  const t = h.store.getTransfer(tid);
  const rawBody = rebuildEnvelopeBody(t);
  const signed = signRequest({ body: rawBody });
  const res = await post(h.gw.port, '/api/lawshield/arma', signed, rawBody);
  assert.equal(res.status, 200);
  assert.equal(res.body.receiptId, 'RCP-' + tid);
  assert.equal(res.body.accepted, true);
  assert.equal(h.processorStore.transferCount(), 1);
  assert.equal(h.processorStore.receiptCount(), 1);
  // Durable ARMA-side resolution by an authorized human.
  const resolved = h.service.resolveReconciliation({ userId: 'user-commander-1' }, {
    transferId: tid, resolutionNote: 'Status endpoint confirmed accepted upstream; receipt on record',
  });
  assert.equal(resolved.resolutionStatus, 'RESOLVED');
  h.close();
});

// 15. Duplicate delivery does not duplicate the disclosure: the same transfer
//     re-delivered over the full stack creates exactly one accepted record
//     and one receipt, on both the processor and the ARMA side.
test('15. duplicate delivery never duplicates the disclosure', async () => {
  const h = await bootFull();
  const draft = drive(h, { recordId: 'CASE-115', caseNumber: 'CASE-115' });
  const tid = draft.transfer.transferId;
  const first = await h.service.send({ transferId: tid });
  assert.equal(first.outcome, 'ACCEPTED');

  // Re-deliver the identical signed request twice more (fresh nonce each
  // time is impossible for byte-identical replays; the gateway replay guard
  // catches those first — so use fresh nonces with the same content, the
  // duplicate-delivery semantic after a lost response).
  const t = h.store.getTransfer(tid);
  const rawBody = rebuildEnvelopeBody(t);
  for (let i = 0; i < 2; i++) {
    const signed = signRequest({ body: rawBody });
    const res = await post(h.gw.port, '/api/lawshield/arma', signed, rawBody);
    assert.equal(res.status, 200);
    assert.equal(res.body.accepted, true);
    assert.equal(res.body.receiptId, 'RCP-' + tid);
    assert.equal(res.body.transferId, tid);
  }
  // Exactly one disclosure on the processor side, one receipt, ever.
  assert.equal(h.processorStore.transferCount(), 1);
  assert.equal(h.processorStore.receiptCount(), 1);
  const events = h.processorStore.getAuditEvents({ transferId: tid });
  assert.equal(events.filter((e) => e.eventType === 'TRANSFER_ACCEPTED').length, 1);
  assert.ok(events.filter((e) => e.eventType === 'DUPLICATE_DELIVERY_COLLAPSED').length >= 2);
  h.close();
});

// 16. Receipt generated ONCE and deterministic: duplicate delivery returns
//     byte-identical receipt fields (receiptId, acceptedAt, processingResult).
test('16. receipt is generated once and is deterministic on duplicate delivery', async () => {
  const h = await bootDurable();
  const req1 = makeForwarded({ overrides: { transferId: 'TRX-SP3-016', idempotencyKey: 'IDK-SP3-016' } });
  const first = await deliver(h, req1);
  assert.ok(first.body.receiptId);
  // Two more duplicate deliveries: all receipt fields identical.
  const dupBodies = [];
  for (let i = 0; i < 2; i++) {
    const dup = makeForwarded({ overrides: { transferId: 'TRX-SP3-016', idempotencyKey: 'IDK-SP3-016' } });
    const res = await deliver(h, dup);
    assert.equal(res.body.accepted, true);
    dupBodies.push(res.body);
  }
  for (const body of dupBodies) {
    assert.equal(body.receiptId, first.body.receiptId);
    assert.equal(body.acceptedAt, first.body.acceptedAt);
    assert.equal(body.processingResult, first.body.processingResult);
    assert.equal(body.payloadHash, first.body.payloadHash);
  }
  assert.equal(h.store.receiptCount(), 1); // one receipt record, ever
  h.close();
});

// ---------------------------------------------------------------------------
// Mandatory tests 17-18: signed receipt raw-byte discipline end-to-end.
// ---------------------------------------------------------------------------

// 17. Receipt signature verifies against the RAW response bytes: the gateway
//     signs the receipt body it produced, ARMA's verifier confirms signature +
//     body hash + every bound field over the exact bytes received.
test('17. receipt signature verifies against raw bytes (full stack)', async () => {
  const h = await bootFull();
  const draft = drive(h, { recordId: 'CASE-117', caseNumber: 'CASE-117' });
  const tid = draft.transfer.transferId;
  const t = h.store.getTransfer(tid);
  // Send at the raw-envelope level so the RAW gateway response bytes are kept.
  const rawBody = rebuildEnvelopeBody(t);
  const signed = signRequest({ body: rawBody });
  const res = await post(h.gw.port, '/api/lawshield/arma', signed, rawBody);
  assert.equal(res.status, 200);
  // Verify EXACTLY as ARMA's verifier does: raw text + header map + expected.
  const verified = verifyReceipt({
    rawBody: res.raw, // raw bytes as received — never re-serialized
    headers: res.headers,
    secret: RECEIPT_SECRET,
    expected: {
      transferId: t.transferId, idempotencyKey: t.idempotencyKey,
      armaOrgId: t.armaOrgId, lawShieldOrgId: t.lawShieldOrgId,
      payloadHash: JSON.parse(rawBody).payloadHash, recordType: t.recordType, recordId: t.recordId,
    },
  });
  assert.equal(verified.receiptId, 'RCP-' + tid);
  assert.equal(verified.receipt.status, 'ACCEPTED');
  assert.equal(verified.receipt.accepted, true);
  assert.equal(verified.receipt.receivedPayloadHash, JSON.parse(rawBody).payloadHash);
  assert.equal(verified.receipt.processingResult, 'PERSISTED');
  h.close();
});

// 18. Tampered receipt fails closed: corrupt the receipt between gateway and
//     ARMA and the verifier rejects it (invalid signature / hash) — the
//     transfer never becomes ACCEPTED on the ARMA side; it opens reconciliation.
test('18. tampered receipt fails closed to reconciliation', async () => {
  const h = await bootFull();
  const draft = drive(h, { recordId: 'CASE-118', caseNumber: 'CASE-118' });
  const tid = draft.transfer.transferId;
  const realFetch = h.service.fetchImpl;
  h.service.fetchImpl = async (url, init) => {
    const response = await realFetch(url, init);
    const rawBody = await response.text();
    // Corrupt the signature header (one hex digit swapped) — same discipline
    // as the ARMA-side suite, now against the REAL durable processor.
    return {
      status: response.status,
      headers: new Headers(Object.fromEntries([...response.headers.entries()].map(([k, v]) => [k, k.toLowerCase() === 'x-lawshield-signature' ? v.replace(/./, 'f') : v]))),
      text: async () => rawBody,
    };
  };
  const r = await h.service.send({ transferId: tid });
  h.service.fetchImpl = realFetch;
  assert.equal(r.outcome, 'RECONCILIATION_REQUIRED');
  assert.match(r.transfer.lastErrorCode, /RECEIPT_INVALID_SIGNATURE|RECEIPT_BODY_HASH_MISMATCH/);
  assert.notEqual(r.transfer.status, 'ACCEPTED');
  assert.equal(h.store.getReconciliation(tid).resolutionStatus, 'OPEN');
  // The processor's durable truth is still intact and queryable.
  const status = await statusInquiry(h.processorPort, { transferId: tid });
  assert.equal(status.body.status, 'ACCEPTED');
  h.close();
});

// ---------------------------------------------------------------------------
// Mandatory tests 19-20: reconciliation resolution + quarantine path.
// ---------------------------------------------------------------------------

// 19. Reconciliation can resolve an ACCEPTED ambiguous outcome: an ambiguous
//     failure (tampered receipt bytes on a 200) opens reconciliation; the
//     status inquiry reveals the true upstream state (ACCEPTED with receipt);
//     an authorized human resolves it on the ARMA side — never AI, never auto.
test('19. reconciliation resolves an accepted ambiguous outcome via status inquiry + human resolver', async () => {
  const h = await bootFull();
  const draft = drive(h, { recordId: 'CASE-119', caseNumber: 'CASE-119' });
  const tid = draft.transfer.transferId;
  // Ambiguity: mutate the receipt BODY bytes (not just the signature) so
  // verification fails on the 200 path.
  const realFetch = h.service.fetchImpl;
  h.service.fetchImpl = async (url, init) => {
    const response = await realFetch(url, init);
    const rawBody = await response.text();
    return { status: response.status, headers: response.headers, text: async () => rawBody.slice(0, -2) };
  };
  const r = await h.service.send({ transferId: tid });
  h.service.fetchImpl = realFetch;
  assert.equal(r.outcome, 'RECONCILIATION_REQUIRED');
  const recon = h.store.getReconciliation(tid);
  assert.equal(recon.resolutionStatus, 'OPEN');
  assert.match(recon.discrepancyCode, /RECEIPT_/);

  // Resolution workflow: (1) query ACTUAL durable upstream state.
  const status = await statusInquiry(h.processorPort, { transferId: tid });
  assert.equal(status.body.status, 'ACCEPTED');
  assert.equal(status.body.receiptId, 'RCP-' + tid);
  assert.ok(status.body.auditEventCount >= 1);
  assert.ok(status.body.auditEvents.some((e) => e.eventType === 'TRANSFER_ACCEPTED'));
  // (2) AI can NEVER resolve; (3) wrong-org human cannot; (4) authorized
  // human in the transfer org resolves with a substantive note.
  assert.throws(() => h.service.resolveReconciliation({ userId: 'ai-engine-joy' }, { transferId: tid, resolutionNote: 'AI attempts resolution of the discrepancy' }), /AI_CANNOT_RESOLVE_RECONCILIATION|ACTOR_NOT_AUTHENTICATED/);
  assert.throws(() => h.service.resolveReconciliation({ userId: 'user-commander-2' }, { transferId: tid, resolutionNote: 'Cross-org resolver attempts resolution here' }), /ACTOR_NOT_IN_TRANSFER_ORG/);
  const resolved = h.service.resolveReconciliation({ userId: 'user-commander-1' }, {
    transferId: tid, resolutionNote: 'Status inquiry confirmed upstream accepted; receipt RCP record verified',
  });
  assert.equal(resolved.resolutionStatus, 'RESOLVED');
  assert.equal(resolved.authorizedResolverUserId, 'user-commander-1');
  // The upstream disclosure is still exactly one — reconciliation never
  // created a second one.
  assert.equal(h.processorStore.transferCount(), 1);
  assert.equal(h.processorStore.receiptCount(), 1);
  h.close();
});

// 20. Quarantine path works end-to-end: a policy-violating payload is
//     quarantined durably, exposed through the status endpoint for human
//     review, and never accepted or receipted.
test('20. quarantine path works: durable record, status exposure, no receipt', async () => {
  const h = await bootDurable();
  const smuggled = { ...validRedactedPayload(), ssn: '000-00-0000' };
  const req = makeForwarded({ payload: smuggled, overrides: { transferId: 'TRX-SP3-020', idempotencyKey: 'IDK-SP3-020' } });
  const res = await deliver(h, req);
  assert.equal(res.body.accepted, false);
  assert.equal(res.body.error, 'ALWAYS_REDACTED_FIELD_PRESENT');
  assert.equal(res.body.quarantined, true);
  // Durable quarantine record + audit event with field NAMES only.
  const transfer = h.store.getDurableTransfer('TRX-SP3-020');
  assert.equal(transfer.status, 'QUARANTINED');
  assert.ok(transfer.quarantinedAt > 0);
  const events = h.store.getAuditEvents({ transferId: 'TRX-SP3-020' });
  assert.ok(events.some((e) => e.eventType === 'TRANSFER_QUARANTINED'));
  assert.equal(JSON.stringify(events).includes('000-00-0000'), false);
  // Status endpoint exposes the quarantine for human review (by idempotencyKey).
  const status = await statusInquiry(h.port, { idempotencyKey: 'IDK-SP3-020' });
  assert.equal(status.status, 200);
  assert.equal(status.body.found, true);
  assert.equal(status.body.status, 'QUARANTINED');
  assert.equal(status.body.lastErrorCode, 'ALWAYS_REDACTED_FIELD_PRESENT');
  assert.equal(status.body.receiptId, null);
  assert.equal(h.store.receiptCount(), 0);
  // A duplicate delivery of the quarantined transfer collapses to the SAME
  // quarantine outcome (deterministic, no re-processing).
  const dup = makeForwarded({ payload: smuggled, overrides: { transferId: 'TRX-SP3-020', idempotencyKey: 'IDK-SP3-020' } });
  const dupRes = await deliver(h, dup);
  assert.equal(dupRes.body.accepted, false);
  assert.equal(dupRes.body.error, 'ALWAYS_REDACTED_FIELD_PRESENT');
  assert.equal(h.store.transferCount(), 1);
  h.close();
});

// ---------------------------------------------------------------------------
// Mandatory test 21: kill switch.
// ---------------------------------------------------------------------------

// 21. Processor kill switch fails closed: with LAW_SHIELD_PROCESSOR_DISABLED
//     the processor refuses /process AND /status (nothing is served while
//     disabled), the gateway surfaces the failure to ARMA, and no durable
//     state is created. Recovery after re-enabling is clean.
test('21. processor kill switch fails closed (process + status + gateway path)', async () => {
  const h = await bootDurable({ env: { LAW_SHIELD_PROCESSOR_DISABLED: 'true' } });
  const req = makeForwarded({ overrides: { transferId: 'TRX-SP3-021', idempotencyKey: 'IDK-SP3-021' } });
  // Direct processor POST: refused while disabled.
  const direct = await deliver(h, req);
  assert.equal(direct.status, 503);
  assert.equal(direct.body.error, 'PROCESSOR_DISABLED');
  // Direct processor STATUS: refused while disabled (kill switch is first).
  const status = await statusInquiry(h.port, { transferId: 'TRX-SP3-021' });
  assert.equal(status.status, 503);
  assert.equal(status.body.error, 'PROCESSOR_DISABLED');
  // Through the real gateway: the failure propagates to the ARMA caller.
  const signed = signRequest({ body: req.rawBody });
  const gatewayRes = await post(h.gw.port, '/api/lawshield/arma', signed, req.rawBody);
  assert.equal(gatewayRes.status, 502);
  assert.equal(gatewayRes.body.error, 'PROCESSOR_DISABLED');
  assert.equal(gatewayRes.body.accepted, false);
  // Nothing was persisted while disabled.
  assert.equal(h.store.transferCount(), 0);
  assert.equal(h.store.receiptCount(), 0);
  h.close();
  // Recovery: with the kill switch released the same content is accepted.
  const h2 = await bootDurable();
  const req2 = makeForwarded({ overrides: { transferId: 'TRX-SP3-021R', idempotencyKey: 'IDK-SP3-021R' } });
  const res2 = await deliver(h2, req2);
  assert.equal(res2.status, 200);
  assert.equal(res2.body.accepted, true);
  h2.close();
});
