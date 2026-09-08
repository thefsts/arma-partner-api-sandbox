// Stop Point 7 e2e.synthetic.test.mjs — synthetic full-chain integration test.
//
// Exercises the ENTIRE shared partner integration platform in one flow, the
// way a real sandbox integration would:
//   registry resolve -> version negotiate -> SDK sign request -> server-side
//   verify + replay guard -> idempotency resolve/record -> platform receipt
//   -> client verify receipt -> webhook event -> signed delivery (+ retry/DLQ)
//   -> receiver-side webhook verify (guard) -> telemetry span -> audit trail.
//
// Also verifies the fail-closed discipline on unknowns (partner, capability,
// nonce replay, event replay, signature) and the metadata-only discipline
// (no payload content in any audit/telemetry/webhook surface).
//
// Synthetic sandbox material ONLY — no private identifiers, prompts, or keys.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  PARTNER_ID, ORG_ID, CAPABILITY, ENTITLEMENT,
  PARTNER_SECRET, RECEIPT_SECRET, WEBHOOK_SECRET,
  makeClock, partnerRecordFixture, orgRecordFixture, validNonce,
} from './helpers.mjs';
import { PartnerRegistry } from '../registry/partnerRegistry.ts';
import { PartnerSdkClient } from '../sdk/client.ts';
import { SUPPORTED_SDK_API_VERSIONS } from '../sdk/versions.ts';
import { negotiateApiVersion } from '../sdk/versions.ts';
import {
  signReceiptBytes, RECEIPT_SCHEMA_VERSION, DEFAULT_RECEIPT_HEADERS,
} from '../sdk/receipts.ts';
import { IdempotencyRegistry, ReplayGuard } from '../sdk/idempotency.ts';
import {
  buildWebhookEnvelope, signWebhookEnvelope, verifyWebhook, WebhookEventGuard,
  WEBHOOK_EVENT_TYPES, WEBHOOK_HEADERS,
} from '../webhooks/events.ts';
import { WebhookDeliveryService } from '../webhooks/delivery.ts';
import { InMemoryTelemetrySink } from '../observability/telemetry.ts';
import { IntegrationAuditTrail } from '../sdk/audit.ts';
import { AuditLog } from '../../ai-governance/audit.ts';

const { clock, now, advance } = makeClock();

/** Build a synthetic platform: registry, idempotency, replay guard, telemetry, audit. */
function makePlatform() {
  const registry = new PartnerRegistry({ now });
  registry.registerPartner(partnerRecordFixture());
  registry.registerOrg(orgRecordFixture());
  const idempotency = new IdempotencyRegistry({ now });
  const replay = new ReplayGuard({ now });
  const telemetry = new InMemoryTelemetrySink({ now, secretValues: [PARTNER_SECRET, RECEIPT_SECRET, WEBHOOK_SECRET] });
  const auditLog = new AuditLog({ clock, secretValues: [PARTNER_SECRET, RECEIPT_SECRET, WEBHOOK_SECRET] });
  const trail = new IntegrationAuditTrail(auditLog);
  return { registry, idempotency, replay, telemetry, trail };
}

/** A synthetic partner SDK client. */
function makeSdk() {
  return new PartnerSdkClient({
    partnerId: PARTNER_ID,
    secret: PARTNER_SECRET,
    receiptSecret: RECEIPT_SECRET,
    now,
  });
}

/** The platform's receipt response for a successful operation (raw bytes + headers). */
function platformReceiptResponse(receipt) {
  const rawBody = Buffer.from(JSON.stringify(receipt), 'utf8');
  const { contentSha256, signature } = signReceiptBytes(rawBody, RECEIPT_SECRET);
  return {
    rawBody,
    headers: {
      [DEFAULT_RECEIPT_HEADERS.receiptId]: receipt.receiptId,
      [DEFAULT_RECEIPT_HEADERS.contentSha256]: contentSha256,
      [DEFAULT_RECEIPT_HEADERS.signature]: signature,
      'x-request-id': receipt.requestId,
    },
  };
}

const PAYLOAD = JSON.stringify({ request: 'synthetic-partner-activation-request' });

// ---------------------------------------------------------------------------
// THE HAPPY PATH — one operation through the entire platform
// ---------------------------------------------------------------------------
test('e2e: full synthetic chain — resolve, negotiate, sign, verify, idempotency, receipt, webhook, delivery, telemetry, audit', () => {
  const platform = makePlatform();
  const sdk = makeSdk();

  // 1) Registry resolves the full authorization chain.
  const resolution = platform.registry.resolve({
    partnerId: PARTNER_ID, orgId: ORG_ID, entitlement: ENTITLEMENT, capability: CAPABILITY,
  });
  assert.equal(resolution.ok, true);
  assert.deepEqual(resolution.apiVersionWindow, { min: 'v1', max: 'v2' });

  // 2) Version negotiation inside the capability window.
  const negotiated = negotiateApiVersion({
    provided: 'v1',
    capabilityMin: resolution.apiVersionWindow.min,
    capabilityMax: resolution.apiVersionWindow.max,
  });
  assert.equal(negotiated.ok, true);
  assert.equal(negotiated.version, 'v1');

  // 3) SDK builds a signed request with full correlation headers.
  const built = sdk.buildRequest({
    method: 'POST',
    path: '/shared/v1/protected-operations',
    body: PAYLOAD,
  });
  assert.equal(built.method, 'POST');
  assert.match(built.headers['x-shared-signature'], /^[0-9a-f]{64}$/);
  assert.match(built.headers['x-request-id'], /^req-/);
  assert.ok(built.nonce.length >= 20);

  // 4) Platform verifies the signature (server-side view of the same SDK).
  const serverVerification = sdk.verifySignature({
    method: built.method,
    path: built.path,
    timestamp: String(built.timestamp),
    nonce: built.nonce,
    bodyHash: built.bodyHash,
    providedSignature: built.headers['x-shared-signature'],
    now: now(),
  });
  assert.equal(serverVerification.ok, true);

  // 5) Replay guard burns the nonce; a replayed presentation fails closed.
  const replay1 = platform.replay.check(PARTNER_ID, built.nonce, built.requestId);
  assert.deepEqual(replay1, { ok: true });
  const replay2 = platform.replay.check(PARTNER_ID, built.nonce, built.requestId);
  assert.equal(replay2.ok, false);
  assert.equal(replay2.code, 'REPLAYED');

  // 6) Idempotency: FRESH first, DUPLICATE collapse on retry with same hash.
  const idemKey = 'e2e-op-0001-key';
  const requestHash = built.bodyHash; // platform-side request identity
  const first = platform.idempotency.resolve(PARTNER_ID, idemKey, requestHash);
  assert.equal(first.kind, 'FRESH');

  // 7) Platform executes and returns a receipt-signed response.
  const receipt = {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    receiptId: 'rct-e2e-0001',
    requestId: built.requestId,
    partnerId: PARTNER_ID,
    operation: 'activation.create',
    outcome: 'SUCCESS',
    at: now(),
    entityRef: 'entity-sandbox-0001',
    payloadHash: built.bodyHash,
  };
  const response = platformReceiptResponse(receipt);

  // 8) Client verifies the receipt over raw bytes — binding the exact request.
  const processed = sdk.processResponse({
    status: 201,
    rawBody: response.rawBody,
    headers: response.headers,
    expected: {
      requestId: built.requestId,
      partnerId: PARTNER_ID,
      operation: 'activation.create',
      outcome: 'SUCCESS',
      entityRef: 'entity-sandbox-0001',
    },
  });
  assert.equal(processed.ok, true);
  assert.equal(processed.receipt.receiptId, 'rct-e2e-0001');
  assert.equal(processed.requestId, built.requestId);

  // 9) Platform records the idempotency outcome (same transaction discipline).
  platform.idempotency.record(PARTNER_ID, idemKey, requestHash, {
    outcome: 'SUCCESS', status: 201, bodyDigest: built.bodyHash, receiptId: receipt.receiptId, at: now(),
  });
  const duplicate = platform.idempotency.resolve(PARTNER_ID, idemKey, requestHash);
  assert.equal(duplicate.kind, 'DUPLICATE');
  assert.equal(duplicate.existing.receiptId, 'rct-e2e-0001');

  // 10) Platform emits a metadata-only webhook event for the state change.
  const envelope = buildWebhookEnvelope({
    eventType: 'resource.status.changed',
    stream: PARTNER_ID,
    sequence: 1,
    at: now(),
    partnerId: PARTNER_ID,
    orgRef: ORG_ID,
    requestId: built.requestId,
    data: {
      capability: CAPABILITY,
      entityRef: 'entity-sandbox-0001',
      status: 'ACTIVE',
      previousStatus: 'PENDING',
      requestId: built.requestId,
      receiptId: receipt.receiptId,
    },
  });
  assert.match(envelope.eventId, /^evt-[0-9a-f-]{36}$/);

  // 11) Delivery: signed attempts until the transport acknowledges.
  const transportCalls = [];
  let transportFailuresLeft = 2;
  const delivery = new WebhookDeliveryService({
    now,
    transport: (d) => {
      transportCalls.push(d);
      if (transportFailuresLeft > 0) {
        transportFailuresLeft -= 1;
        return { ok: false, code: 'TRANSPORT_ERROR' };
      }
      return { ok: true };
    },
  });
  const delivered = delivery.deliver({
    envelope,
    secret: WEBHOOK_SECRET,
    target: { targetId: 'target-partner-endpoint-1' },
  });
  assert.equal(delivered.outcome, 'DELIVERED');
  assert.equal(delivered.deadLettered, false);
  assert.equal(delivered.attempts.length, 3);
  assert.equal(transportCalls.length, 3);
  // Every attempt carried a verifiable signed request over raw bytes.
  for (const call of transportCalls) {
    const verified = verifyWebhook({
      rawBody: call.rawBody,
      headers: call.headers,
      secret: WEBHOOK_SECRET,
      now: now(),
    });
    assert.equal(verified.ok, true, 'each delivery attempt must be verifiable');
  }
  // Every attempt used a fresh nonce (no nonce reuse across attempts).
  const nonces = transportCalls.map((c) => c.headers[WEBHOOK_HEADERS.nonce]);
  assert.equal(new Set(nonces).size, nonces.length);

  // 12) Receiver-side verification with the event guard (nonce + event id + sequence).
  const guard = new WebhookEventGuard({ now });
  const receiver = verifyWebhook({
    rawBody: transportCalls[2].rawBody,
    headers: transportCalls[2].headers,
    secret: WEBHOOK_SECRET,
    now: now(),
    guard,
  });
  assert.equal(receiver.ok, true);
  assert.equal(receiver.envelope.eventId, envelope.eventId);
  // Presenting the same event again fails closed (replay).
  const replayedEvent = verifyWebhook({
    rawBody: transportCalls[2].rawBody,
    headers: transportCalls[2].headers,
    secret: WEBHOOK_SECRET,
    now: now(),
    guard,
  });
  assert.equal(replayedEvent.ok, false);

  // 13) Telemetry span — metadata only, ends SUCCESS with reconciliation NONE.
  const span = platform.telemetry.startSpan({
    requestId: built.requestId,
    partnerId: PARTNER_ID,
    operation: 'activation.create',
    orgRef: ORG_ID,
    metadata: {
      capability: CAPABILITY,
      receiptId: receipt.receiptId,
      eventId: envelope.eventId,
      deliveryId: delivered.deliveryId,
      apiVersion: 'v1',
    },
  });
  advance(37);
  const completed = platform.telemetry.completeSpan(span.spanId, {
    success: true,
    retryCount: 0,
    metadata: { status: 'SUCCESS', outcome: 'SUCCESS' },
  });
  assert.equal(completed.status, 'SUCCESS');
  assert.equal(completed.latencyMs, 37);
  assert.equal(completed.reconciliationStatus, 'NONE');
  assert.equal(completed.safeMetadata.capability, CAPABILITY);
  assert.equal(completed.safeMetadata.eventId, envelope.eventId);

  // 14) Audit trail — append-only, metadata-only record of the integration.
  platform.trail.record({
    kind: 'integration.request.verified',
    subjectId: built.requestId,
    reasonCode: 'REQUEST_VERIFIED',
    details: {
      requestId: built.requestId,
      partnerId: PARTNER_ID,
      capability: CAPABILITY,
      entityRef: 'entity-sandbox-0001',
      receiptId: receipt.receiptId,
      signatureValid: true,
      eventId: envelope.eventId,
      sequence: envelope.sequence,
    },
    orgRef: ORG_ID,
  });
  const auditEntries = platform.trail.list();
  assert.equal(auditEntries.length, 1);
  assert.equal(auditEntries[0].reasonCode, 'REQUEST_VERIFIED');
  assert.equal(auditEntries[0].details.signatureValid, true);

  // 15) NO-LEAK DISCIPLINE: no surface contains payload content or secrets.
  const auditBlob = JSON.stringify(auditEntries);
  assert.ok(!auditBlob.includes(PAYLOAD), 'audit must not contain request payload');
  assert.ok(!auditBlob.includes(PARTNER_SECRET), 'audit must not contain secrets');
  assert.ok(!auditBlob.includes(WEBHOOK_SECRET), 'audit must not contain secrets');
  const telemetryBlob = JSON.stringify(platform.telemetry.list());
  assert.ok(!telemetryBlob.includes(PAYLOAD), 'telemetry must not contain request payload');
  assert.ok(!telemetryBlob.includes(PARTNER_SECRET), 'telemetry must not contain secrets');
  const eventBlob = JSON.stringify(envelope);
  assert.ok(!eventBlob.includes(PAYLOAD), 'webhook event data must be metadata only');
  assert.ok(!eventBlob.includes(PARTNER_SECRET), 'webhook event data must not contain secrets');
});

// ---------------------------------------------------------------------------
// FAIL-CLOSED DISCIPLINE
// ---------------------------------------------------------------------------
test('e2e: unknown partner fails closed at the registry before anything else runs', () => {
  const platform = makePlatform();
  const sdk = makeSdk();

  const resolution = platform.registry.resolve({
    partnerId: 'partner-unknown-9999', orgId: ORG_ID, entitlement: ENTITLEMENT, capability: CAPABILITY,
  });
  assert.equal(resolution.ok, false);
  assert.equal(resolution.code, 'PARTNER_UNKNOWN');

  // The fail-closed surface answers with a structured, versioned error —
  // never a stack trace, never payload content.
  const built = sdk.buildRequest({ method: 'POST', path: '/shared/v1/protected-operations', body: PAYLOAD });
  const processed = sdk.processResponse({
    status: 403,
    rawBody: Buffer.from(JSON.stringify({
      error: 'PARTNER_UNKNOWN',
      errorClass: 'AUTHENTICATION',
      requestId: built.requestId,
    })),
    headers: { 'x-request-id': built.requestId },
  });
  assert.equal(processed.ok, false);
  assert.equal(processed.error.code, 'PARTNER_UNKNOWN');
  const body = processed.error.toResponse();
  assert.equal(body.error, 'PARTNER_UNKNOWN');
  assert.equal(body.errorClass, 'AUTHENTICATION');
  // No retry for an authorization failure — the plan is TERMINAL.
  const plan = sdk.planRetry('PARTNER_UNKNOWN', 0);
  assert.equal(plan.kind, 'TERMINAL');
});

test('e2e: unknown capability fails closed with a typed code (no hardcoded partner logic)', () => {
  const platform = makePlatform();
  const resolution = platform.registry.resolve({
    partnerId: PARTNER_ID, orgId: ORG_ID, entitlement: ENTITLEMENT, capability: 'capability-never-registered',
  });
  assert.equal(resolution.ok, false);
  assert.equal(resolution.code, 'CAPABILITY_UNKNOWN');
});

test('e2e: 2xx without a valid receipt fails closed — success is only trusted when proven', () => {
  const platform = makePlatform();
  const sdk = makeSdk();
  const built = sdk.buildRequest({ method: 'POST', path: '/shared/v1/protected-operations', body: PAYLOAD });

  // A 200 whose "receipt" bytes are unsigned/foreign.
  const unsigned = Buffer.from(JSON.stringify({
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    receiptId: 'rct-forged-0001',
    requestId: built.requestId,
    partnerId: PARTNER_ID,
    operation: 'activation.create',
    outcome: 'SUCCESS',
    at: now(),
  }));
  const processed = sdk.processResponse({
    status: 200,
    rawBody: unsigned,
    headers: {
      'x-shared-receipt-id': 'rct-forged-0001',
      'x-shared-content-sha256': '0'.repeat(64),
      'x-shared-signature': 'f'.repeat(64),
      'x-request-id': built.requestId,
    },
    expected: { requestId: built.requestId, operation: 'activation.create' },
  });
  assert.equal(processed.ok, false);
  assert.equal(processed.error.code, 'RECEIPT_VERIFICATION_FAILED');
  // Ambiguous class: never blindly retried — reconciliation, not re-send.
  const plan = sdk.planRetry('RECEIPT_VERIFICATION_FAILED', 0);
  assert.equal(plan.kind, 'AMBIGUOUS_RECONCILE');
});

test('e2e: tampered request signature fails closed server-side', () => {
  const sdk = makeSdk();
  const built = sdk.buildRequest({ method: 'POST', path: '/shared/v1/protected-operations', body: PAYLOAD });
  const tampered = sdk.verifySignature({
    method: built.method,
    path: '/shared/v1/different-path', // path substituted after signing
    timestamp: String(built.timestamp),
    nonce: built.nonce,
    bodyHash: built.bodyHash,
    providedSignature: built.headers['x-shared-signature'],
    now: now(),
  });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.code, 'SIGNATURE_SIGNATURE_MISMATCH');
});

test('e2e: exhausted webhook delivery dead-letters with metadata-only attempt history', () => {
  const envelope = buildWebhookEnvelope({
    eventType: 'processing.failed',
    stream: PARTNER_ID,
    sequence: 2,
    at: now(),
    partnerId: PARTNER_ID,
    orgRef: ORG_ID,
    data: { errorCode: 'DOWNSTREAM_UNAVAILABLE', reasonCode: 'DOWNSTREAM_UNAVAILABLE' },
  });
  let calls = 0;
  const delivery = new WebhookDeliveryService({
    now,
    transport: () => { calls += 1; return { ok: false, code: 'TRANSPORT_ERROR' }; },
  });
  const result = delivery.deliver({
    envelope, secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-endpoint-1' },
  });
  assert.equal(result.outcome, 'RETRY_EXHAUSTED');
  assert.equal(result.deadLettered, true);
  assert.equal(result.attempts.length, 5);
  assert.equal(calls, 5);
  for (const a of result.attempts) {
    assert.equal(a.outcome, 'FAILED');
    assert.equal(a.reasonCode, 'TRANSPORT_ERROR');
  }
  // Attempt history carries numbers and codes only — never payload content.
  const blob = JSON.stringify(result.attempts);
  assert.ok(!blob.includes(PAYLOAD));
});

test('e2e: ambiguous webhook delivery dead-letters immediately — never blind re-send', () => {
  const envelope = buildWebhookEnvelope({
    eventType: 'processing.completed',
    stream: PARTNER_ID,
    sequence: 3,
    at: now(),
    partnerId: PARTNER_ID,
    data: { status: 'COMPLETED', outcome: 'SUCCESS' },
  });
  let calls = 0;
  const delivery = new WebhookDeliveryService({
    now,
    transport: () => { calls += 1; return { ok: false, code: 'TRANSPORT_ERROR', ambiguous: true }; },
  });
  const result = delivery.deliver({
    envelope, secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-endpoint-1' },
  });
  assert.equal(result.outcome, 'DEAD_LETTERED_AMBIGUOUS');
  assert.equal(result.deadLettered, true);
  assert.equal(calls, 1, 'ambiguous outcomes must not be retried blindly');
});

test('e2e: ambiguous outcome is tracked as AMBIGUOUS telemetry pending reconciliation', () => {
  const platform = makePlatform();
  const sdk = makeSdk();

  const span = platform.telemetry.startSpan({
    requestId: 'req-e2e-ambiguous-0001',
    partnerId: PARTNER_ID,
    operation: 'transfer.send',
    orgRef: ORG_ID,
    metadata: { capability: CAPABILITY, errorCode: 'TRANSPORT_ERROR' },
  });
  const marked = platform.telemetry.markAmbiguous(span.spanId, {
    errorClass: 'TRANSPORT',
    retryCount: 3,
    metadata: { attempt: 3, maxAttempts: 5, status: 'AMBIGUOUS' },
  });
  assert.equal(marked.status, 'AMBIGUOUS');
  assert.equal(marked.success, null);
  assert.equal(marked.reconciliationStatus, 'PENDING');
  assert.equal(marked.retryCount, 3);

  // Reconciliation later resolves it.
  const resolved = platform.telemetry.updateReconciliation(span.spanId, 'RESOLVED');
  assert.equal(resolved.reconciliationStatus, 'RESOLVED');

  // A reconciliation.required event announces the need — metadata only.
  const envelope = buildWebhookEnvelope({
    eventType: 'reconciliation.required',
    stream: PARTNER_ID,
    sequence: 4,
    at: now(),
    partnerId: PARTNER_ID,
    data: {
      requestId: 'req-e2e-ambiguous-0001',
      reasonCode: 'TRANSPORT_ERROR',
      reconciliationStatus: 'PENDING',
      attempt: 3,
    },
  });
  assert.equal(envelope.eventType, 'reconciliation.required');
  const blob = JSON.stringify(envelope);
  assert.ok(!blob.includes(PAYLOAD));
  assert.ok(!blob.includes(PARTNER_SECRET));
});

test('e2e: webhook event with an unknown type is refused at build time (fail closed)', () => {
  assert.throws(
    () => buildWebhookEnvelope({
      eventType: 'partner.private.event', // not in the shared vocabulary
      stream: PARTNER_ID, sequence: 1, at: now(), partnerId: PARTNER_ID,
    }),
    /WEBHOOK_EVENT_TYPE_UNKNOWN/,
  );
});

test('e2e: SDK version negotiation fails closed outside the capability window', () => {
  const out = negotiateApiVersion({ provided: 'v1', capabilityMin: 'v2', capabilityMax: 'v3' });
  assert.equal(out.ok, false);
  assert.equal(out.failure.code, 'VERSION_OUT_OF_CAPABILITY_WINDOW');
  assert.deepEqual(out.supported, [...SUPPORTED_SDK_API_VERSIONS]);
});

test('e2e: duplicate delivery collapses without re-invoking the transport', () => {
  const envelope = buildWebhookEnvelope({
    eventType: 'entitlement.changed',
    stream: PARTNER_ID,
    sequence: 5,
    at: now(),
    partnerId: PARTNER_ID,
    data: { entitlement: ENTITLEMENT, status: 'ACTIVE' },
  });
  let calls = 0;
  const delivery = new WebhookDeliveryService({
    now,
    transport: () => { calls += 1; return { ok: true }; },
  });
  const input = { envelope, secret: WEBHOOK_SECRET, target: { targetId: 'target-partner-endpoint-1' } };
  const first = delivery.deliver(input);
  assert.equal(first.outcome, 'DELIVERED');
  const second = delivery.deliver(input);
  assert.equal(second.outcome, 'DELIVERED_DUPLICATE');
  assert.equal(second.deadLettered, false);
  assert.equal(second.attempts.length, 0);
  assert.equal(calls, 1, 'duplicate collapse must never re-invoke the transport');
});
