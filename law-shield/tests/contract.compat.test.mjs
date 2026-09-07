// D1 contract compatibility tests (approved additive clarification).
// Proves: (a) receipts now carry accepted:true, (b) status:"ACCEPTED" is
// preserved verbatim for existing v1 consumers, (c) every original v1 receipt
// field is present with the same meaning, (d) the addition breaks nothing the
// original contract guaranteed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildEnvelope, signRequest, GATEWAY_SECRET, RECEIPT_SECRET, PROCESSOR_TOKEN, startGateway, startProcessor, applyTestEnv, resetGatewayState, post } from './helpers/servers.mjs';

// The ORIGINAL v1 receipt field list (from the sandbox baseline commit fd56c14,
// law-shield/lawshield/arma-integration.js) — the compatibility contract that
// must never regress:
const ORIGINAL_V1_RECEIPT_FIELDS = [
  'schemaVersion', 'receiptId', 'transferId', 'idempotencyKey', 'status',
  'acceptedAt', 'armaOrgId', 'lawShieldOrgId', 'incidentId', 'lawShieldCaseId',
  'recordType', 'recordId', 'receivedPayloadHash', 'processingResult',
];

async function happyReceipt() {
  await resetGatewayState();
  const processor = await startProcessor({ mode: 'healthy' });
  const restore = applyTestEnv({
    LAW_SHIELD_INTEGRATION_PROCESSOR_URL: `http://127.0.0.1:${processor.port}/process`,
    LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN: PROCESSOR_TOKEN,
  });
  const gw = await startGateway();
  const body = JSON.stringify(buildEnvelope());
  const res = await post(gw.port, '/api/lawshield/arma', signRequest({ body }), body);
  return { res, restore: () => { restore(); gw.close(); processor.close(); } };
}

test('D1 compat: v1 receipt fields all present; accepted:true added; status:"ACCEPTED" preserved', async () => {
  const { res, restore } = await happyReceipt();
  try {
    assert.equal(res.status, 200);
    const receipt = res.body;
    // (a) the NEW field is present and true
    assert.equal(receipt.accepted, true, 'accepted:true must be present (D1 addition)');
    // (b) the v1 status field is preserved EXACTLY
    assert.equal(receipt.status, 'ACCEPTED', 'status:"ACCEPTED" preserved for v1 consumers');
    // (c) every original v1 field present (no field removed or renamed)
    for (const field of ORIGINAL_V1_RECEIPT_FIELDS) {
      assert.ok(field in receipt, `original v1 field missing: ${field}`);
    }
    // (d) field values still mean the same thing
    assert.equal(receipt.schemaVersion, 'arma-lawshield.v1');
    assert.equal(receipt.sourceSystem ?? receipt.armaOrgId !== undefined, true);
    assert.ok(receipt.receiptId.startsWith('RCP-'));
    assert.ok(Number.isFinite(receipt.acceptedAt));
    assert.equal(receipt.processingResult, 'PERSISTED');
  } finally { restore(); }
});

test('D1 compat: both fields agree (accepted:true iff status:"ACCEPTED")', async () => {
  const { res, restore } = await happyReceipt();
  try {
    const receipt = res.body;
    assert.equal(receipt.accepted === true && receipt.status === 'ACCEPTED', true, 'fields must agree');
  } finally { restore(); }
});

test('D1 compat: signature covers the full receipt body including the new field', async () => {
  const { res, restore } = await happyReceipt();
  try {
    // The gateway signs its serialized receipt; the signature header must
    // verify over the RAW response bytes (which include accepted:true).
    const raw = res.raw;
    const crypto = await import('node:crypto');
    const expectedSig = crypto.createHmac('sha256', RECEIPT_SECRET).update(raw).digest('hex');
    assert.equal(res.headers['x-lawshield-signature'], expectedSig);
    assert.equal(res.headers['x-lawshield-content-sha256'], crypto.createHash('sha256').update(raw).digest('hex'));
  } finally { restore(); }
});

test('D1 compat: error responses still carry accepted:false and never accepted:true', async () => {
  await resetGatewayState();
  const processor = await startProcessor({ mode: 'reject' });
  const restore = applyTestEnv({
    LAW_SHIELD_INTEGRATION_PROCESSOR_URL: `http://127.0.0.1:${processor.port}/process`,
    LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN: PROCESSOR_TOKEN,
  });
  const gw = await startGateway();
  try {
    const body = JSON.stringify(buildEnvelope());
    const res = await post(gw.port, '/api/lawshield/arma', signRequest({ body }), body);
    assert.equal(res.status, 502);
    assert.equal(res.body.accepted, false);
    assert.equal(res.body.error, 'ORG_NOT_AUTHORIZED');
    // error responses never carry status:"ACCEPTED"
    assert.notEqual(res.body.status, 'ACCEPTED');
  } finally { restore(); gw.close(); processor.close(); }
});
