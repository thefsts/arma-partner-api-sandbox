// ARMA-side Law Shield outbound transfer service (sandbox).
// State machine: DRAFT -> PENDING_AUTHORIZATION -> AUTHORIZED -> READY_TO_SEND
//   -> SENT -> RECEIPT_VERIFIED -> ACCEPTED
//   with REJECTED / QUARANTINED / RECONCILIATION_REQUIRED branches.
// Rules enforced here (all non-negotiable):
//   * Human-only authorization (authorizationGuard); AI can NEVER authorize.
//   * Idempotency: same idempotencyKey never creates two accepted disclosures.
//   * Clean-retryable failures auto-retry with fresh nonce; ambiguous outcomes
//     (receipt mismatch / timeout after send) open RECONCILIATION_REQUIRED —
//     never a blind re-send (an accepted disclosure must never be duplicated).
//   * Event hash chain on every state transition.
//   * ARMA-side kill switch (ARMA_LAW_SHIELD_OUTBOUND_DISABLED) mirrors the
//     Law Shield gateway kill switch (LAW_SHIELD_ARMA_INTEGRATION_DISABLED).
//   * Receipt verification over raw bytes (receiptVerifier).
//   * Minimum-necessary redaction before envelope construction (redaction.js).
//   * No direct DB access either direction: durable state via store only.
import crypto from 'node:crypto';
import { buildEnvelope } from './envelope.js';
import { signRequest } from './signer.js';
import { verifyReceipt, classifyGatewayFailure } from './receiptVerifier.js';
import { checkDisclosureAuthorization, recordApprovedAuthorization } from './authorizationGuard.js';
import { redactPayload } from './redaction.js';
import { computeBackoff, canAutoRetry } from './retryPolicy.js';
import { openReconciliation, resolveReconciliation } from './reconciliation.js';

function outboundDisabled() {
  return String(process.env.ARMA_LAW_SHIELD_OUTBOUND_DISABLED ?? 'false').toLowerCase() === 'true';
}

function chainEvent(previousHash, eventType, transferId, payloadHash, at) {
  return crypto.createHash('sha256')
    .update(`${previousHash ?? 'GENESIS'}|${transferId}|${eventType}|${payloadHash ?? ''}|${at}`)
    .digest('hex');
}

function safeJson(text) { try { return JSON.parse(text); } catch { return {}; } }

export class ArmaLawShieldTransferService {
  constructor({ store, directory, config = {} } = {}) {
    if (!store) throw new Error('STORE_REQUIRED');
    if (!directory) throw new Error('DIRECTORY_REQUIRED');
    this.store = store;
    this.directory = directory;
    this.gatewayUrl = config.gatewayUrl ?? process.env.ARMA_LAW_SHIELD_GATEWAY_URL ?? null;
    this.signingSecret = config.signingSecret ?? process.env.ARMA_TO_LAW_SHIELD_HMAC_SECRET ?? null;
    this.receiptSecret = config.receiptSecret ?? process.env.LAW_SHIELD_TO_ARMA_HMAC_SECRET ?? null;
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.now = config.now ?? (() => Date.now());
    this.sleep = config.sleep ?? (async () => {});
  }

  createDraft({ actor, armaOrgId, incidentId = null, recordType, recordId, rawPayload, idempotencyKey, transferId, lawShieldOrgId = null, disclosurePurpose = null }) {
    if (outboundDisabled()) throw new Error('ARMA_OUTBOUND_DISABLED');
    const actorUser = this.directory.getUser(actor?.userId);
    if (!actor?.userId || !actorUser) throw new Error('ACTOR_NOT_AUTHENTICATED');
    if (actorUser.actorType !== 'HUMAN') throw new Error('AI_CANNOT_AUTHORIZE_TRANSFER');
    const { payload, minimumNecessaryFields, redactedFields } = redactPayload(recordType, rawPayload);
    const idempotency = idempotencyKey ?? 'IDY-' + crypto.randomUUID();
    const tid = transferId ?? 'TRX-' + crypto.randomUUID();
    const record = this.store.createTransfer({
      transferId: tid, idempotencyKey: idempotency,
      armaOrgId, lawShieldOrgId, incidentId, lawShieldCaseId: null,
      recordType, recordId,
      payloadEnvelope: {
        recordType, recordId, incidentId: incidentId ?? '',
        disclosurePurpose: disclosurePurpose ?? undefined, data: payload,
      },
      authorizedByUserId: null, authorizationReason: null,
      redactionProof: { minimumNecessaryFields, redactedFields },
    });
    this.store.appendAudit({
      transferId: tid, armaOrgId, eventType: 'TRANSFER_DRAFT_CREATED',
      actorType: 'HUMAN', actorUserId: actor.userId,
      detail: { recordType, recordId, minimumNecessaryFields, redactedFields },
    });
    return { transfer: record, minimumNecessaryFields, redactedFields, payload };
  }

  authorize({ actor, transferId, authorizationReason, purposeOfDisclosure = null, phiCategories = [] }) {
    if (outboundDisabled()) throw new Error('ARMA_OUTBOUND_DISABLED');
    const t = this.store.getTransfer(transferId);
    if (!t) throw new Error('TRANSFER_NOT_FOUND');
    if (!['DRAFT', 'PENDING_AUTHORIZATION'].includes(t.status)) throw new Error('INVALID_STATE_TRANSITION');
    const proof = t.redactionProof ?? { minimumNecessaryFields: Object.keys(t.payloadEnvelope?.data ?? {}), redactedFields: [], phiCategories: [] };
    const { decision, policyFields } = checkDisclosureAuthorization(this.store, this.directory, actor, {
      transferId, armaOrgId: t.armaOrgId, incidentId: t.incidentId,
      lawShieldOrgId: t.lawShieldOrgId, recordType: t.recordType, recordId: t.recordId,
      authorizationReason, purposeOfDisclosure, phiCategories,
      minimumNecessaryFields: proof.minimumNecessaryFields,
      redactedFields: proof.redactedFields,
    });
    const authorization = recordApprovedAuthorization(this.store, {
      transferId, armaOrgId: t.armaOrgId, authorizedByUserId: actor.userId,
      authorizationReason, purposeOfDisclosure,
      phiCategories: policyFields.phiCategories,
      minimumNecessaryFields: proof.minimumNecessaryFields,
      redactedFields: proof.redactedFields,
      auditReference: 'AUD-' + transferId,
    });
    const at = this.now();
    this.store.updateTransfer(transferId, {
      status: 'AUTHORIZED', approvedAt: at, authorizedByUserId: actor.userId,
      authorizationReason,
      eventSequence: t.eventSequence + 1,
      previousEventHash: chainEvent(t.previousEventHash, 'TRANSFER_AUTHORIZED', transferId, t.payloadHash, at),
    });
    this.store.appendAudit({
      transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_AUTHORIZED',
      actorType: 'HUMAN', actorUserId: actor.userId,
      detail: { policyDecision: 'APPROVED', phiCategories },
    });
    return { transfer: this.store.getTransfer(transferId), authorization };
  }

  ready({ transferId, lawShieldOrgId = null, lawShieldCaseId = null }) {
    if (outboundDisabled()) throw new Error('ARMA_OUTBOUND_DISABLED');
    const t = this.store.getTransfer(transferId);
    if (!t) throw new Error('TRANSFER_NOT_FOUND');
    if (t.status !== 'AUTHORIZED') throw new Error('INVALID_STATE_TRANSITION');
    const destination = lawShieldOrgId ?? t.lawShieldOrgId;
    if (!destination) throw new Error('LAW_SHIELD_ORG_REQUIRED');
    const orgMapping = this.store.getOrgMapping(t.armaOrgId);
    if (!orgMapping || !orgMapping.active) throw new Error('ORG_MAPPING_MISSING');
    if (orgMapping.lawShieldOrgId !== destination) throw new Error('ORG_MAPPING_MISMATCH');
    let caseMapping = null;
    if (t.incidentId) {
      caseMapping = this.store.getCaseMapping(t.armaOrgId, t.incidentId);
      if (!caseMapping || !caseMapping.active) throw new Error('CASE_MAPPING_REQUIRED');
      if (caseMapping.lawShieldOrgId !== destination) throw new Error('CASE_MAPPING_TENANT_MISMATCH');
    }
    const caseId = caseMapping ? caseMapping.lawShieldCaseId : (lawShieldCaseId ?? t.lawShieldCaseId ?? null);
    if (t.incidentId && !caseId) throw new Error('CASE_MAPPING_REQUIRED');
    const at = this.now();
    this.store.updateTransfer(transferId, {
      lawShieldOrgId: destination, lawShieldCaseId: caseId,
      status: 'READY_TO_SEND',
      eventSequence: t.eventSequence + 1,
      previousEventHash: chainEvent(t.previousEventHash, 'TRANSFER_READY_TO_SEND', transferId, t.payloadHash, at),
    });
    this.store.appendAudit({
      transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_READY_TO_SEND',
      actorType: 'SYSTEM', actorUserId: null,
      detail: { lawShieldOrgId: destination, lawShieldCaseId: caseId },
    });
    return { transfer: this.store.getTransfer(transferId) };
  }

  // Single send attempt. NEVER throws for gateway/perimeter rejections: it
  // records the correct durable outcome instead. Transfers leave ARMA only
  // here — envelope built from the redacted payload, signed with a fresh nonce,
  // receipt verified over the RAW response bytes.
  async send({ transferId }) {
    if (outboundDisabled()) throw new Error('ARMA_OUTBOUND_DISABLED');
    const t = this.store.getTransfer(transferId);
    if (!t) throw new Error('TRANSFER_NOT_FOUND');
    if (t.status !== 'READY_TO_SEND') throw new Error('INVALID_STATE_TRANSITION');
    if (!this.gatewayUrl) throw new Error('GATEWAY_URL_NOT_CONFIGURED');
    if (!this.signingSecret) throw new Error('ARMA_SIGNER_NOT_CONFIGURED');
    if (!this.receiptSecret) throw new Error('ARMA_RECEIPT_VERIFIER_NOT_CONFIGURED');

    const at = this.now();
    const envelope = buildEnvelope({
      transferId: t.transferId,
      idempotencyKey: t.idempotencyKey,
      armaOrgId: t.armaOrgId,
      lawShieldOrgId: t.lawShieldOrgId,
      recordType: t.recordType,
      recordId: t.recordId,
      authorizedBy: t.authorizedByUserId,
      authorizationReason: t.authorizationReason,
      incidentId: t.incidentId ?? null,
      lawShieldCaseId: t.lawShieldCaseId ?? null,
      disclosurePurpose: t.payloadEnvelope?.disclosurePurpose ?? null,
      payload: t.payloadEnvelope.data,
      createdAt: t.createdAt,
      sentAt: at,
      expiresAt: at + 15 * 60 * 1000,
    });
    const body = JSON.stringify(envelope);
    const signed = signRequest({ body, secret: this.signingSecret });
    this.store.updateTransfer(transferId, {
      status: 'SENT', sentAt: at, payloadHash: envelope.payloadHash,
      eventSequence: t.eventSequence + 1,
      previousEventHash: chainEvent(t.previousEventHash, 'TRANSFER_SENT', transferId, envelope.payloadHash, at),
    });
    this.store.appendAudit({
      transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_SENT',
      actorType: 'TRANSPORT', actorUserId: null,
      detail: { payloadHash: envelope.payloadHash },
    });

    let response, rawBody;
    try {
      response = await this.fetchImpl(this.gatewayUrl, { method: 'POST', headers: signed.headers, body });
      rawBody = await response.text();
    } catch (transportError) {
      // Outbound transport failure BEFORE any receipt: connection-level.
      // Timeout is ambiguous (request may have reached the processor); a plain
      // connect failure is clean-retryable. Neither re-sends automatically.
      const signature = String(transportError?.name ?? '') + String(transportError?.message ?? '');
      const code = /timeout|abort/i.test(signature) ? 'PROCESSOR_TIMEOUT' : 'PROCESSOR_UNAVAILABLE';
      return this.recordTransportFailure(t, code, at);
    }

    if (response.status === 200) {
      // Normalize fetch Headers to a plain map (receiptVerifier does raw map
      // access; Node's Headers instance does not support bracket access).
      const headerMap = {};
      if (typeof response.headers?.entries === 'function') {
        for (const [k, v] of response.headers.entries()) headerMap[k] = v;
      } else if (response.headers && typeof response.headers === 'object') {
        Object.assign(headerMap, response.headers);
      }
      // A 200 with a receipt that FAILS verification is AMBIGUOUS: the gateway
      // believes it succeeded (the processor may have persisted). Never retry
      // blind; open reconciliation and fail closed.
      let verified;
      try {
        verified = verifyReceipt({ rawBody, headers: headerMap, secret: this.receiptSecret, expected: {
          transferId: t.transferId, idempotencyKey: t.idempotencyKey,
          armaOrgId: t.armaOrgId, lawShieldOrgId: t.lawShieldOrgId,
          payloadHash: envelope.payloadHash, recordType: t.recordType, recordId: t.recordId,
        } });
      } catch (receiptError) {
        this.store.updateTransfer(t.transferId, { status: 'RECONCILIATION_REQUIRED', lastErrorCode: receiptError instanceof Error ? receiptError.message : 'RECEIPT_VERIFICATION_FAILED', retryCount: t.retryCount + 1 });
        openReconciliation(this.store, {
          transferId: t.transferId, expectedPayloadHash: envelope.payloadHash,
          expectedDestination: t.lawShieldOrgId, currentArmaState: 'SENT',
          discrepancyCode: receiptError instanceof Error ? receiptError.message : 'RECEIPT_VERIFICATION_FAILED',
          reportedLawShieldState: 'GATEWAY_200_RECEIPT_VERIFICATION_FAILED',
        });
        this.store.appendAudit({
          transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_RECONCILIATION_OPENED',
          actorType: 'TRANSPORT', actorUserId: null,
          detail: { code: receiptError instanceof Error ? receiptError.message : 'RECEIPT_VERIFICATION_FAILED', gatewayStatus: 200 },
        });
        return { transfer: this.store.getTransfer(t.transferId), outcome: 'RECONCILIATION_REQUIRED' };
      }
      const at2 = this.now();
      this.store.updateTransfer(transferId, {
        status: 'RECEIPT_VERIFIED', receiptId: verified.receiptId, receiptHash: verified.bodyHash,
        eventSequence: t.eventSequence + 2,
        previousEventHash: chainEvent(chainEvent(t.previousEventHash, 'TRANSFER_RECEIPT_VERIFIED', transferId, envelope.payloadHash, at2), 'TRANSFER_ACCEPTED', transferId, envelope.payloadHash, at2),
      });
      this.store.appendAudit({
        transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_RECEIPT_VERIFIED',
        actorType: 'TRANSPORT', actorUserId: null,
        detail: { receiptId: verified.receiptId, receiptHash: verified.bodyHash, status: verified.contract.status, accepted: verified.contract.accepted },
      });
      this.store.appendAudit({
        transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_ACCEPTED',
        actorType: 'SYSTEM', actorUserId: null, detail: null,
      });
      const accepted = this.store.updateTransfer(transferId, { status: 'ACCEPTED', acceptedAt: at2 });
      return { transfer: accepted, receipt: verified.receipt, outcome: 'ACCEPTED' };
    }

    return this.recordGatewayFailure(t, { status: response.status, body: safeJson(rawBody) }, at, envelope.payloadHash);
  }

  // Outbound transport failure (fetch threw). Timeout after send is AMBIGUOUS
  // (processor may have persisted) -> RECONCILIATION_REQUIRED, never auto-retry.
  // Connect-level failure is clean-retryable with a fresh nonce after backoff.
  recordTransportFailure(t, code, at) {
    if (code === 'PROCESSOR_TIMEOUT') {
      this.store.updateTransfer(t.transferId, { status: 'RECONCILIATION_REQUIRED', lastErrorCode: code, retryCount: t.retryCount + 1 });
      openReconciliation(this.store, {
        transferId: t.transferId, expectedPayloadHash: t.payloadHash,
        expectedDestination: t.lawShieldOrgId, currentArmaState: 'SENT',
        discrepancyCode: code, reportedLawShieldState: null,
      });
      this.store.appendAudit({
        transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_RECONCILIATION_OPENED',
        actorType: 'TRANSPORT', actorUserId: null, detail: { code, stage: 'outbound' },
      });
      return { transfer: this.store.getTransfer(t.transferId), outcome: 'RECONCILIATION_REQUIRED' };
    }
    // PROCESSOR_UNAVAILABLE (clean): schedule retry, stay READY_TO_SEND-family.
    const backoff = computeBackoff({ retryCount: t.retryCount });
    if (!backoff.allowed) {
      this.store.updateTransfer(t.transferId, { status: 'REJECTED', rejectedAt: this.now(), lastErrorCode: 'MAX_RETRIES_EXCEEDED' });
      this.store.appendAudit({ transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_REJECTED', actorType: 'SYSTEM', actorUserId: null, detail: { code: 'MAX_RETRIES_EXCEEDED' } });
      return { transfer: this.store.getTransfer(t.transferId), outcome: 'REJECTED' };
    }
    this.store.updateTransfer(t.transferId, { status: 'READY_TO_SEND', lastErrorCode: code, nextRetryAt: this.now() + backoff.delayMs, retryCount: t.retryCount + 1 });
    this.store.appendAudit({
      transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_RETRY_SCHEDULED',
      actorType: 'TRANSPORT', actorUserId: null, detail: { code, delayMs: backoff.delayMs, retryCount: t.retryCount + 1 },
    });
    return { transfer: this.store.getTransfer(t.transferId), outcome: 'RETRY_SCHEDULED' };
  }

  // Gateway responded with a structured error. Classification decides the
  // durable outcome: ambiguous -> reconciliation; clean-retryable -> scheduled
  // retry; anything else is a terminal perimeter rejection (never left ARMA).
  recordGatewayFailure(t, { status, body }, at, payloadHash) {
    const classification = classifyGatewayFailure({ status, body });
    if (classification.ambiguous) {
      this.store.updateTransfer(t.transferId, { status: 'RECONCILIATION_REQUIRED', lastErrorCode: classification.code, retryCount: t.retryCount + 1 });
      openReconciliation(this.store, {
        transferId: t.transferId, expectedPayloadHash: payloadHash ?? t.payloadHash,
        expectedDestination: t.lawShieldOrgId, currentArmaState: 'SENT',
        discrepancyCode: classification.code, reportedLawShieldState: null,
      });
      this.store.appendAudit({
        transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_RECONCILIATION_OPENED',
        actorType: 'TRANSPORT', actorUserId: null, detail: { code: classification.code, gatewayStatus: status },
      });
      return { transfer: this.store.getTransfer(t.transferId), outcome: 'RECONCILIATION_REQUIRED' };
    }
    if (canAutoRetry(classification)) {
      const backoff = computeBackoff({ retryCount: t.retryCount });
      if (!backoff.allowed) {
        this.store.updateTransfer(t.transferId, { status: 'REJECTED', rejectedAt: this.now(), lastErrorCode: 'MAX_RETRIES_EXCEEDED' });
        this.store.appendAudit({ transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_REJECTED', actorType: 'SYSTEM', actorUserId: null, detail: { code: 'MAX_RETRIES_EXCEEDED' } });
        return { transfer: this.store.getTransfer(t.transferId), outcome: 'REJECTED' };
      }
      this.store.updateTransfer(t.transferId, { status: 'READY_TO_SEND', lastErrorCode: classification.code, nextRetryAt: this.now() + backoff.delayMs, retryCount: t.retryCount + 1 });
      this.store.appendAudit({
        transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_RETRY_SCHEDULED',
        actorType: 'TRANSPORT', actorUserId: null, detail: { code: classification.code, delayMs: backoff.delayMs, retryCount: t.retryCount + 1 },
      });
      return { transfer: this.store.getTransfer(t.transferId), outcome: 'RETRY_SCHEDULED' };
    }
    // Terminal perimeter rejection: the transfer never left ARMA.
    this.store.updateTransfer(t.transferId, { status: 'REJECTED', rejectedAt: this.now(), lastErrorCode: classification.code });
    this.store.appendAudit({
      transferId: t.transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_REJECTED',
      actorType: 'SYSTEM', actorUserId: null, detail: { code: classification.code, gatewayStatus: status },
    });
    return { transfer: this.store.getTransfer(t.transferId), outcome: 'REJECTED' };
  }

  // Human-only rejection of a transfer not yet accepted.
  reject({ transferId, actor, reason = 'HUMAN_REJECTED' }) {
    const t = this.store.getTransfer(transferId);
    if (!t) throw new Error('TRANSFER_NOT_FOUND');
    const actorUser = this.directory.getUser(actor?.userId);
    if (!actor?.userId || !actorUser) throw new Error('ACTOR_NOT_AUTHENTICATED');
    if (actorUser.actorType !== 'HUMAN') throw new Error('AI_CANNOT_AUTHORIZE_TRANSFER');
    if (!['DRAFT', 'PENDING_AUTHORIZATION', 'AUTHORIZED', 'READY_TO_SEND', 'RECONCILIATION_REQUIRED'].includes(t.status)) throw new Error('INVALID_STATE_TRANSITION');
    const at = this.now();
    this.store.updateTransfer(transferId, {
      status: 'REJECTED', rejectedAt: at, lastErrorCode: reason,
      eventSequence: t.eventSequence + 1,
      previousEventHash: chainEvent(t.previousEventHash, 'TRANSFER_REJECTED', transferId, t.payloadHash, at),
    });
    this.store.appendAudit({ transferId, armaOrgId: t.armaOrgId, eventType: 'TRANSFER_REJECTED', actorType: 'HUMAN', actorUserId: actor.userId, detail: { reason } });
    return { transfer: this.store.getTransfer(transferId) };
  }

  // Resolve an open reconciliation (authorized human resolver only).
  resolveReconciliation(actor, { transferId, resolutionNote, resolutionStatus = 'RESOLVED' }) {
    return resolveReconciliation(this.store, this.directory, actor, { transferId, resolutionNote, resolutionStatus });
  }
}
