// Stop Point 3 — FULL synthetic end-to-end chain test.
// ARMA transferService (human-only authorization, minimum-necessary redaction)
// -> signed request (fresh nonce) -> REAL gateway (signature + envelope
// verification) -> REAL durable processor (authoritative nonce replay
// registry, idempotency registry, org/case mapping + disclosure-policy
// checks, transactional persistence, receipt) -> signed receipt -> ARMA
// raw-byte receipt verification -> ACCEPTED -> replay/duplicate discipline +
// status/reconciliation verification + audit verification on both sides.
// Synthetic data only; no production values; no real network leaves loopback.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { SyntheticDurableLawShieldStore, seedSyntheticProcessorDirectory } from '../lawshield/durable/store.js';
import { createDurableProcessorServer } from '../lawshield/durable/processor.js';
import { SyntheticLawShieldStore, SyntheticIdentityDirectory, seedSyntheticIdentities } from '../arma/persistence.js';
import { ArmaLawShieldTransferService } from '../arma/transferService.js';
import { verifyReceipt } from '../arma/receiptVerifier.js';
import { buildEnvelope as buildArmaEnvelope } from '../arma/envelope.js';
import {
  startGateway, applyTestEnv, resetGatewayState, signRequest, post,
  GATEWAY_SECRET, RECEIPT_SECRET, PROCESSOR_TOKEN, SCHEMA_VERSION,
} from './helpers/servers.mjs';

const REASON = 'Commander approved synthetic referral for legal review';

async function bootE2E() {
  await resetGatewayState();
  // REAL durable Law Shield processor (authoritative registries).
  const processorStore = seedSyntheticProcessorDirectory(new SyntheticDurableLawShieldStore());
  const processorServer = createServer(createDurableProcessorServer({ store: processorStore, token: PROCESSOR_TOKEN }));
  await new Promise((r) => processorServer.listen(0, '127.0.0.1', r));
  const processorPort = processorServer.address().port;
  const restore = applyTestEnv({
    LAW_SHIELD_INTEGRATION_PROCESSOR_URL: `http://127.0.0.1:${processorPort}/process`,
    LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN: PROCESSOR_TOKEN,
  });
  // REAL gateway wrapped around the production handler module.
  const gw = await startGateway();
  // REAL ARMA-side store + directory + transfer service.
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

// The synthetic case input, deliberately containing always-redacted fields to
// prove the minimum-necessary redaction hop of the chain.
const RAW_CASE = {
  caseNumber: 'CASE-200',
  incidentId: 'INC-1001',
  incidentDate: '2026-02-05',
  incidentType: 'SYNTHETIC_INCIDENT',
  summary: 'Synthetic incident referral requiring legal review by Law Shield',
  legalNeeds: ['LEGAL_REVIEW', 'RECORDS_REQUEST'],
  incidentLocation: 'Synthetic Location 2',
  requestingOrgId: 'org-arma-1',
  ssn: '000-00-0000',
  officerNotes: 'Internal ARMA notes must never leave the system boundary',
};

// Rebuild the exact wire envelope ARMA sent for a stored transfer (used for
// replay / duplicate-delivery hops against the real gateway + processor).
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

async function statusInquiry(port, params) {
  const url = `http://127.0.0.1:${port}/status?` + new URLSearchParams({ schemaVersion: SCHEMA_VERSION, ...params });
  const res = await fetch(url, { headers: { authorization: `Bearer ${PROCESSOR_TOKEN}` } });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, body: json };
}

// ---------------------------------------------------------------------------
// THE full synthetic E2E chain. Every hop is asserted in order:
//   1. ARMA draft creation (minimum-necessary redaction proof)
//   2. Human-only authorization (durable authorization record)
//   3. Ready (mapping resolution -> lawShieldCaseId LS-CASE-1)
//   4. Send -> real gateway -> real durable processor (acceptance)
//   5. Signed receipt returned; ARMA verifies over RAW bytes -> ACCEPTED
//   6. Replay + duplicate-delivery discipline (no second disclosure)
//   7. Status/reconciliation inquiry exposes the durable truth
//   8. Audit verification on BOTH sides (no payload content anywhere)
// ---------------------------------------------------------------------------
test('full synthetic E2E: ARMA -> gateway -> durable processor -> receipt -> ACCEPTED -> verification', async () => {
  const h = await bootE2E();

  // --- Hop 1: ARMA draft + minimum-necessary redaction -----------------------
  const draft = h.service.createDraft({
    actor: { userId: 'user-commander-1' }, armaOrgId: 'org-arma-1', incidentId: 'INC-1001',
    recordType: 'CASE_REFERRAL', recordId: 'CASE-200', rawPayload: RAW_CASE, lawShieldOrgId: 'ls-org-1',
  });
  const tid = draft.transfer.transferId;
  assert.equal(draft.transfer.status, 'DRAFT');
  // Redaction proof: always-redacted fields removed BEFORE anything leaves.
  assert.ok(draft.redactedFields.includes('ssn'));
  assert.ok(draft.redactedFields.includes('officerNotes'));
  assert.equal('ssn' in draft.payload, false);
  assert.equal('officerNotes' in draft.payload, false);
  assert.ok(draft.payload.summary.includes('legal review'));

  // --- Hop 2: human-only authorization ---------------------------------------
  // AI can never authorize at this gate.
  assert.throws(() => h.service.authorize({ actor: { userId: 'ai-engine-joy' }, transferId: tid, authorizationReason: 'AI attempts authorization' }), /TRANSFER_NOT_FOUND|INVALID_STATE_TRANSITION|AI/);
  const authorized = h.service.authorize({ actor: { userId: 'user-commander-1' }, transferId: tid, authorizationReason: REASON });
  assert.equal(authorized.transfer.status, 'AUTHORIZED');
  const authRecord = h.store.getAuthorization(tid);
  assert.equal(authRecord.policyDecision, 'APPROVED');
  assert.equal(authRecord.authorizedByUserId, 'user-commander-1');
  assert.ok(authRecord.minimumNecessaryFields.length > 0);
  assert.ok(authRecord.redactedFields.includes('ssn')); // redaction proof preserved

  // --- Hop 3: ready (mapping resolution) --------------------------------------
  const ready = h.service.ready({ transferId: tid });
  assert.equal(ready.transfer.status, 'READY_TO_SEND');
  assert.equal(ready.transfer.lawShieldOrgId, 'ls-org-1');
  assert.equal(ready.transfer.lawShieldCaseId, 'LS-CASE-1'); // explicit case mapping

  // --- Hop 4: send -> real gateway -> real durable processor ------------------
  const sent = await h.service.send({ transferId: tid });
  assert.equal(sent.outcome, 'ACCEPTED');
  assert.equal(sent.transfer.status, 'ACCEPTED');
  assert.ok(sent.transfer.receiptId);
  // Durable processor state: ACCEPTED with receipt, nonce registered.
  const processorTransfer = h.processorStore.getDurableTransfer(tid);
  assert.equal(processorTransfer.status, 'ACCEPTED');
  assert.equal(processorTransfer.receiptId, 'RCP-' + tid);
  assert.equal(processorTransfer.lawShieldCaseId, 'LS-CASE-1');
  assert.equal(processorTransfer.armaOrgId, 'org-arma-1');
  assert.ok(h.processorStore.getIdempotencyBinding({ schemaVersion: SCHEMA_VERSION, idempotencyKey: h.store.getTransfer(tid).idempotencyKey }).outcome === 'ACCEPTED');
  // No payload content persisted processor-side (hash only).
  assert.equal(JSON.stringify(processorTransfer).includes('legal review'), false);

  // --- Hop 5: signed receipt verified over RAW bytes --------------------------
  // Re-verify independently: fetch a fresh receipt copy from the gateway path
  // (duplicate delivery with fresh nonce) and run ARMA's verifier on it.
  const t = h.store.getTransfer(tid);
  const rawBody = rebuildEnvelopeBody(t);
  const signed = signRequest({ body: rawBody });
  const receiptRes = await post(h.gw.port, '/api/lawshield/arma', signed, rawBody);
  assert.equal(receiptRes.status, 200);
  const verified = verifyReceipt({
    rawBody: receiptRes.raw,
    headers: receiptRes.headers,
    secret: RECEIPT_SECRET,
    expected: {
      transferId: t.transferId, idempotencyKey: t.idempotencyKey,
      armaOrgId: t.armaOrgId, lawShieldOrgId: t.lawShieldOrgId,
      payloadHash: JSON.parse(rawBody).payloadHash, recordType: t.recordType, recordId: t.recordId,
    },
  });
  assert.equal(verified.receiptId, 'RCP-' + tid);
  assert.equal(verified.receipt.accepted, true);
  assert.equal(verified.receipt.status, 'ACCEPTED');
  assert.equal(verified.receipt.receivedPayloadHash, JSON.parse(rawBody).payloadHash);

  // --- Hop 6: replay + duplicate-delivery discipline ---------------------------
  // (a) Byte-identical replay: gateway replay guard + processor nonce registry.
  const replayRes = await post(h.gw.port, '/api/lawshield/arma', signed, rawBody);
  assert.equal(replayRes.status, 409);
  assert.equal(replayRes.body.error, 'REPLAYED_NONCE');
  // (b) Duplicate delivery with a FRESH nonce (same content): collapsed to the
  //     SAME receipt by the idempotency registry — no second disclosure.
  const signed2 = signRequest({ body: rawBody });
  const dupRes = await post(h.gw.port, '/api/lawshield/arma', signed2, rawBody);
  assert.equal(dupRes.status, 200);
  assert.equal(dupRes.body.receiptId, 'RCP-' + tid);
  assert.equal(dupRes.body.acceptedAt, receiptRes.body.acceptedAt); // deterministic stored receipt
  assert.equal(h.processorStore.transferCount(), 1);
  assert.equal(h.processorStore.receiptCount(), 1);

  // --- Hop 7: status / reconciliation inquiry ---------------------------------
  const byTransfer = await statusInquiry(h.processorPort, { transferId: tid });
  assert.equal(byTransfer.status, 200);
  assert.equal(byTransfer.body.found, true);
  assert.equal(byTransfer.body.status, 'ACCEPTED');
  assert.equal(byTransfer.body.receiptId, 'RCP-' + tid);
  assert.equal(byTransfer.body.lawShieldCaseId, 'LS-CASE-1');
  assert.equal(byTransfer.body.idempotency.outcome, 'ACCEPTED');
  const idk = h.store.getTransfer(tid).idempotencyKey;
  const byIdempotency = await statusInquiry(h.processorPort, { idempotencyKey: idk });
  assert.equal(byIdempotency.body.transferId, tid);
  assert.equal(byIdempotency.body.status, 'ACCEPTED');
  // 404 for unknown transfer — never a guess.
  const unknown = await statusInquiry(h.processorPort, { transferId: 'TRX-UNKNOWN-E2E' });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.body.error, 'TRANSFER_NOT_FOUND');

  // --- Hop 8: audit verification on BOTH sides --------------------------------
  // Processor side: append-only events, no payload content anywhere.
  const processorEvents = h.processorStore.getAuditEvents({ transferId: tid });
  assert.ok(processorEvents.some((e) => e.eventType === 'TRANSFER_ACCEPTED'));
  assert.ok(processorEvents.some((e) => e.eventType === 'DUPLICATE_DELIVERY_COLLAPSED'));
  const processorAuditText = JSON.stringify(processorEvents);
  assert.equal(processorAuditText.includes('legal review'), false);
  assert.equal(processorAuditText.includes('000-00-0000'), false);
  // Status endpoint audit scrub: event types + outcome only, no detail.
  assert.equal(byTransfer.body.auditEvents.every((e) => e.detail === undefined), true);
  // ARMA side: full lifecycle event chain is present and hash-chained.
  const armaEvents = h.store.getAudit(tid);
  const armaEventTypes = armaEvents.map((e) => e.eventType);
  for (const expected of ['TRANSFER_DRAFT_CREATED', 'TRANSFER_AUTHORIZED', 'TRANSFER_READY_TO_SEND', 'TRANSFER_SENT', 'TRANSFER_RECEIPT_VERIFIED', 'TRANSFER_ACCEPTED']) {
    assert.ok(armaEventTypes.includes(expected), `ARMA audit missing ${expected}`);
  }
  const armaAuditText = JSON.stringify(armaEvents);
  assert.equal(armaAuditText.includes('000-00-0000'), false); // synthetic SSN never in audit
  assert.equal(armaAuditText.includes('never leave the system boundary'), false);

  h.close();
});
