// ARMA -> PATCHES activation service (Stop Point 5, sandbox adapter).
//
// The DURABLE half of the adapter: a state machine over ARMA-local
// activation intents that drives the PatchesPartnerClient (outbound half)
// and persists every transition + audit event in the ArmaStore (which
// implements the transferSchema.ts Convex-shaped tables).
//
// STATE MACHINE (owner spec):
//   PENDING -> READY_TO_ACTIVATE -> ACTIVATION_SENT -> RECEIPT_VERIFIED -> ACTIVE
//   plus RECONCILIATION_REQUIRED, DEACTIVATED, REVOKED, REJECTED, QUARANTINED
//
// OWNER AMENDMENT (binding) — retry vs reconciliation:
// - CLEAN_RETRYABLE outcomes are retried INSIDE the client (bounded) and
//   never surface as a state change other than attempt records; if retries
//   exhaust, the activation goes QUARANTINED with reason RETRIES_EXHAUSTED
//   (never blind re-send: the operator decides).
// - AMBIGUOUS outcomes transition the activation to RECONCILIATION_REQUIRED
//   and open a reconciliation record. NO re-send of the activation create
//   happens until reconciliation resolves. Resolution queries PATCHES
//   status via the stable identity (activationIdentityHint ACT-<requestId>
//   from the FIRST create attempt, or the verified patchesActivationId).
//   - status says ACTIVE (and belongs to this binding) -> RECEIPT_VERIFIED
//     -> ACTIVE (status sync; the original receipt may be lost, but the
//     status route + binding identity prove the activation exists).
//   - status says NOT_FOUND (404) repeatedly (after a bounded number of
//     attempts) -> the create provably never persisted -> a FRESH create
//     attempt with the SAME idempotency key is permitted (server-side
//     idempotency still collapses any residual race).
//   - status ACCESS_DENIED (403) -> wrong-org reconciliation resolver
//     denied -> QUARANTINED for manual intervention.
//   - status query itself fails ambiguously -> stay RECONCILIATION_REQUIRED.
// - TERMINAL outcomes transition to REJECTED (terminal classification
//   reason recorded) — except lifecycle operations which map to their own
//   states (DEACTIVATED/REVOKED) and auth/credential failures which go
//   QUARANTINED for operator attention (credential rotation is an ops
//   action, not an automatic retry).
//
// SECURITY: the service never sees or stores credential secrets (the
// CredentialSource resolves them inside the client); audit events carry
// allowlisted detail only; binding/org references are opaque ids.

import { randomUUID, createHash } from 'node:crypto';
import type { ArmaStore } from './armaStore.ts';
import type { OperationOutcome, AttemptRecord, FailureClass } from './patchesPartnerClient.ts';
import { redactForAudit } from './patchesPartnerClient.ts';
import type { ArmaActivationRecord, ArmaActivationStatus, ArmaSafeDetail } from './transferSchema.ts';

export { ARMA_OUTBOUND_KILL_SWITCH_ENV } from './patchesPartnerClient.ts';

export interface ActivationIntent {
  armaOrgId: string;             // opaque local org id (mapped to patchesOrgId)
  capability: string;            // generic contract capability name
  bindingId: string;             // opaque PATCHES binding id
  idempotencyKey?: string;       // stable key when the caller supplies one
}

export interface ActivationServiceOptions {
  store: ArmaStore;
  client: {  // the PatchesPartnerClient surface the service uses (injectable)
    activate(input: { orgId: string; capability: string; bindingId: string; idempotencyKey: string }): Promise<OperationOutcome>;
    getActivationStatus(activationId: string): Promise<OperationOutcome>;
    deactivateActivation(activationId: string): Promise<OperationOutcome>;
    revokeActivation(activationId: string): Promise<OperationOutcome>;
  };
  now?: () => number;
  reconciliationStatusAttempts?: number; // bounded status queries before NOT_FOUND -> fresh create
  outboundDisabled?: () => boolean;      // service-level kill switch (row + env handled by client)
  secretsForRedaction?: () => string[];  // live secrets for the redactForAudit defense-in-depth scan
}

export const DEFAULT_RECONCILIATION_STATUS_ATTEMPTS = 3;

export type ActivateResultKind =
  | 'ACTIVATED'            // terminal success: ACTIVE
  | 'DUPLICATE'            // server collapsed a duplicate delivery (still ACTIVE)
  | 'RECONCILIATION_REQUIRED'
  | 'REJECTED'
  | 'QUARANTINED';

export interface ActivateResult {
  kind: ActivateResultKind;
  activationId: string;             // ARMA-local
  patchesActivationId: string | null;
  status: ArmaActivationStatus;
  failureClass: FailureClass | null;
  failureReason: string | null;
  errorCode: string | null;
  duplicate: boolean;
  attempts: number;
  auditRedaction?: Record<string, unknown>; // secret-free outcome projection for audit
}

export interface ReconciliationResult {
  status: 'RESOLVED_ACTIVE' | 'RESOLVED_NOT_FOUND' | 'RESOLVED_TERMINAL' | 'BLOCKED' | 'PENDING';
  activationStatus: ArmaActivationStatus;
  patchesActivationId: string | null;
  detail: string;
}

export class ArmaActivationService {
  private readonly store: ArmaStore;
  private readonly client: ActivationServiceOptions['client'];
  private readonly now: () => number;
  private readonly reconciliationStatusAttempts: number;
  private readonly outboundDisabled: () => boolean;
  private readonly secretsForRedaction: () => string[];

  constructor(options: ActivationServiceOptions) {
    this.store = options.store;
    this.client = options.client;
    this.now = options.now ?? Date.now;
    this.reconciliationStatusAttempts = options.reconciliationStatusAttempts ?? DEFAULT_RECONCILIATION_STATUS_ATTEMPTS;
    this.outboundDisabled = options.outboundDisabled ?? (() => false);
    this.secretsForRedaction = options.secretsForRedaction ?? (() => []);
  }

  // ================= Activation lifecycle =================

  /**
   * Begin (or resume) an activation. Idempotent per (bindingId, capability)
   * intent: an existing non-terminal activation for the same binding+capability
   * is returned as-is (no duplicate activation — owner spec).
   */
  async activate(intent: ActivationIntent): Promise<ActivateResult> {
    if (this.outboundDisabled()) {
      return this.quarantineNew(intent, 'ARMA_OUTBOUND_DISABLED', 'ARMA_OUTBOUND_DISABLED');
    }

    const mapping = this.store.getOrgMappingByArmaOrg(intent.armaOrgId);
    if (!mapping) {
      return this.rejectNew(intent, 'ORG_MAPPING_MISSING', 'ORG_MAPPING_MISSING');
    }
    if (mapping.status === 'PAUSED') {
      return this.rejectNew(intent, 'ORG_MAPPING_PAUSED', 'ORG_MAPPING_PAUSED');
    }
    const patchesOrgId = mapping.patchesOrgId;

    // Duplicate-intent collapse: same binding + capability already tracked.
    const existing = this.store.findActiveActivationForBinding(intent.bindingId, intent.capability);
    if (existing) {
      if (existing.status === 'ACTIVE' || existing.status === 'RECEIPT_VERIFIED' || existing.status === 'ACTIVATION_SENT' || existing.status === 'RECONCILIATION_REQUIRED') {
        return {
          kind: 'DUPLICATE', activationId: existing.activationId,
          patchesActivationId: existing.patchesActivationId ?? null,
          status: existing.status, failureClass: null, failureReason: null,
          errorCode: null, duplicate: true, attempts: 0,
        };
      }
      // PENDING/READY_TO_ACTIVATE entries for the same intent resume below
      // via their idempotency key (stable intent => stable key). A key
      // MISMATCH still collapses: the in-flight intent owns the binding and
      // PATCHES does not dedupe by binding — a parallel send could
      // double-activate server-side.
      if (intent.idempotencyKey !== undefined && intent.idempotencyKey !== existing.idempotencyKey) {
        return {
          kind: 'DUPLICATE', activationId: existing.activationId,
          patchesActivationId: existing.patchesActivationId ?? null,
          status: existing.status, failureClass: null, failureReason: null,
          errorCode: 'INTENT_KEY_MISMATCH', duplicate: true, attempts: 0,
        };
      }
    }

    const idempotencyKey = intent.idempotencyKey ?? this.stableIdempotencyKey(intent, patchesOrgId);
    const priorByIdem = this.store.findActivationByIdempotencyKey(idempotencyKey);
    if (priorByIdem) {
      // Resume a tracked intent rather than creating a parallel one.
      if (priorByIdem.status === 'REJECTED' || priorByIdem.status === 'QUARANTINED' ||
          priorByIdem.status === 'REVOKED' || priorByIdem.status === 'DEACTIVATED') {
        // Terminal local states: report the prior outcome without re-sending.
        return {
          kind: priorByIdem.status === 'REJECTED' ? 'REJECTED' : 'QUARANTINED',
          activationId: priorByIdem.activationId,
          patchesActivationId: priorByIdem.patchesActivationId ?? null,
          status: priorByIdem.status,
          failureClass: null, failureReason: null,
          errorCode: priorByIdem.rejectedCode ?? null,
          duplicate: true, attempts: 0,
        };
      }
      return this.resumeAndSend(priorByIdem);
    }

    // Preflight: entitlement + capability reference (owner spec). Fail
    // closed before any outbound call when the local reference says no.
    const entRef = this.store.getEntitlementRef(patchesOrgId, intent.capability);
    if (entRef && !entRef.entitled) {
      return this.rejectNew(intent, 'ENTITLEMENT_NOT_ENTITLED', 'ENTITLEMENT_NOT_ENTITLED');
    }
    const capRef = this.store.getCapabilityRef(intent.capability);
    if (capRef && (capRef.minApiVersion !== 'v1' || capRef.maxApiVersion !== 'v1')) {
      return this.rejectNew(intent, 'CAPABILITY_VERSION_UNSUPPORTED', 'CAPABILITY_VERSION_UNSUPPORTED');
    }

    // Fresh intent: PENDING -> READY_TO_ACTIVATE in one transaction with
    // idempotency row + audit.
    const activationId = `ARMA-ACT-${randomUUID()}`;
    const now = this.now();
    this.store.runTransaction(() => {
      this.store.putActivation({
        activationId, idempotencyKey, armaOrgId: intent.armaOrgId, patchesOrgId,
        capability: intent.capability, bindingId: intent.bindingId,
        status: 'PENDING', createdAt: now, updatedAt: now,
      });
      this.store.putIdempotency({
        id: idempotencyKey, idempotencyKey,
        intentHash: this.intentHash(intent, patchesOrgId),
        status: 'OPEN', createdAt: now, updatedAt: now,
      });
      this.audit(activationId, idempotencyKey, 'activation.intent.created', 'SUCCESS', {
        code: 'INTENT_CREATED', orgId: patchesOrgId, capability: intent.capability, bindingId: intent.bindingId,
      });
    });

    return this.sendCreate(this.store.getActivation(activationId)!);
  }

  /** Resume an interrupted tracked intent (PENDING/READY/SENT/RECONCILIATION). */
  async resume(activationId: string): Promise<ActivateResult> {
    const record = this.store.getActivation(activationId);
    if (!record) throw new Error(`activation unknown: ${activationId}`);
    if (record.status === 'REJECTED' || record.status === 'QUARANTINED' || record.status === 'REVOKED' || record.status === 'DEACTIVATED') {
      return {
        kind: record.status === 'REJECTED' ? 'REJECTED' : 'QUARANTINED',
        activationId, patchesActivationId: record.patchesActivationId ?? null, status: record.status,
        failureClass: null, failureReason: null, errorCode: record.rejectedCode ?? null, duplicate: true, attempts: 0,
      };
    }
    if (record.status === 'RECONCILIATION_REQUIRED') {
      const r = await this.reconcile(activationId);
      const kind: ActivateResultKind = r.status === 'RESOLVED_ACTIVE' ? 'ACTIVATED'
        : r.status === 'RESOLVED_NOT_FOUND' ? 'ACTIVATED'
        : 'QUARANTINED';
      return {
        kind, activationId, patchesActivationId: r.patchesActivationId,
        status: r.activationStatus, failureClass: null, failureReason: null,
        errorCode: null, duplicate: false, attempts: 0,
      };
    }
    if (record.status === 'ACTIVATION_SENT') {
      // A send may have reached PATCHES before the interruption: NEVER
      // re-send blind (owner amendment). Mark the unknown-outcome state
      // durably, then reconcile via the stable identity; without an identity
      // hint this is manual-intervention territory.
      this.transition(activationId, 'RECONCILIATION_REQUIRED', 'RESUME_AFTER_SEND', { code: 'RESUME_AFTER_SEND' });
      if (record.lastIntentRequestHint) {
        const r = await this.reconcile(activationId);
        const kind: ActivateResultKind = r.status === 'RESOLVED_ACTIVE' || r.status === 'RESOLVED_NOT_FOUND' ? 'ACTIVATED' : 'QUARANTINED';
        return {
          kind, activationId, patchesActivationId: r.patchesActivationId,
          status: r.activationStatus, failureClass: null, failureReason: null,
          errorCode: null, duplicate: false, attempts: 0,
        };
      }
      const q = this.transition(activationId, 'QUARANTINED', 'NO_IDENTITY_AFTER_SEND', { code: 'NO_IDENTITY_AFTER_SEND' });
      return {
        kind: 'QUARANTINED', activationId, patchesActivationId: null,
        status: q.status, failureClass: null, failureReason: 'NO_IDENTITY_AFTER_SEND',
        errorCode: 'NO_IDENTITY_AFTER_SEND', duplicate: false, attempts: 0,
      };
    }
    // PENDING / READY_TO_ACTIVATE: nothing was ever sent; safe to send now.
    return this.resumeAndSend(record);
  }

  // ================= Status query / synchronization =================

  /**
   * Synchronize local state with PATCHES status (owner spec: status
   * synchronization). Requires a known patchesActivationId (or the identity
   * hint recorded during send).
   */
  async syncStatus(activationId: string): Promise<{ status: ArmaActivationStatus; patchesActivationId: string | null; changed: boolean; errorCode: string | null }> {
    const record = this.store.getActivation(activationId);
    if (!record) throw new Error(`activation unknown: ${activationId}`);
    const patchesId = record.patchesActivationId ?? record.lastIntentRequestHint ?? null;
    if (!patchesId) return { status: record.status, patchesActivationId: null, changed: false, errorCode: 'NO_PATCHES_IDENTITY' };
    const outcome = await this.client.getActivationStatus(patchesId);
    const body = outcome.body as { activation?: { status?: string; activationId?: string; bindingId?: string; capability?: string; orgId?: string; activatedAt?: number; deactivatedAt?: number; revokedAt?: number } } | null;
    const activation = body?.activation ?? null;
    if (outcome.ok && activation) {
      // Status route data is authoritative but must match our binding
      // identity before it can move local state (fail closed on mismatch).
      if (activation.bindingId !== record.bindingId || activation.capability !== record.capability || activation.orgId !== record.patchesOrgId) {
        this.transition(activationId, 'QUARANTINED', 'STATUS_IDENTITY_MISMATCH', { code: 'STATUS_IDENTITY_MISMATCH' });
        return { status: 'QUARANTINED', patchesActivationId: patchesId, changed: true, errorCode: 'STATUS_IDENTITY_MISMATCH' };
      }
      const serverStatus = activation.status;
      let next: ArmaActivationStatus | null = null;
      if (serverStatus === 'ACTIVE') {
        next = record.status === 'ACTIVE' ? null : 'ACTIVE';
        if (next) {
          this.store.runTransaction(() => {
            const r = this.store.getActivation(activationId)!;
            this.store.putActivation({ ...r, patchesActivationId: activation.activationId ?? patchesId, status: 'ACTIVE', activatedAt: activation.activatedAt ?? r.activatedAt ?? this.now(), updatedAt: this.now() });
            this.audit(activationId, r.idempotencyKey, 'activation.status.sync', 'SUCCESS', { code: 'STATUS_SYNCED_ACTIVE', patchesActivationId: patchesId, status: 'ACTIVE' });
          });
        }
      } else if (serverStatus === 'DEACTIVATED') {
        next = 'DEACTIVATED';
        this.transition(activationId, 'DEACTIVATED', 'STATUS_SYNCED_DEACTIVATED', { code: 'STATUS_SYNCED_DEACTIVATED', patchesActivationId: patchesId });
      } else if (serverStatus === 'REVOKED') {
        next = 'REVOKED';
        this.transition(activationId, 'REVOKED', 'STATUS_SYNCED_REVOKED', { code: 'STATUS_SYNCED_REVOKED', patchesActivationId: patchesId });
      }
      return { status: next ?? record.status, patchesActivationId: patchesId, changed: next !== null, errorCode: null };
    }
    return { status: record.status, patchesActivationId: patchesId, changed: false, errorCode: outcome.errorCode };
  }

  // ================= Deactivation / revocation =================

  async deactivate(activationId: string): Promise<{ ok: boolean; status: ArmaActivationStatus; errorCode: string | null; outcome?: OperationOutcome }> {
    return this.lifecycleChange(activationId, 'deactivate');
  }

  async revoke(activationId: string): Promise<{ ok: boolean; status: ArmaActivationStatus; errorCode: string | null; outcome?: OperationOutcome }> {
    return this.lifecycleChange(activationId, 'revoke');
  }

  private async lifecycleChange(activationId: string, action: 'deactivate' | 'revoke'): Promise<{ ok: boolean; status: ArmaActivationStatus; errorCode: string | null; outcome?: OperationOutcome }> {
    const record = this.store.getActivation(activationId);
    if (!record) throw new Error(`activation unknown: ${activationId}`);
    if (action === 'deactivate' && record.status === 'DEACTIVATED') {
      return { ok: true, status: 'DEACTIVATED', errorCode: null };
    }
    if (action === 'revoke' && record.status === 'REVOKED') {
      return { ok: true, status: 'REVOKED', errorCode: null };
    }
    if (!record.patchesActivationId) {
      // No server identity: local lifecycle cannot proceed; only revoke can
      // finalize locally (terminal guard so the intent cannot silently
      // reactivate later).
      if (action === 'revoke') {
        this.transition(activationId, 'REVOKED', 'REVOKED_LOCAL_ONLY', { code: 'REVOKED_LOCAL_ONLY' });
        return { ok: true, status: 'REVOKED', errorCode: 'REVOKED_LOCAL_ONLY' };
      }
      return { ok: false, status: record.status, errorCode: 'NO_PATCHES_IDENTITY' };
    }
    const outcome = action === 'deactivate'
      ? await this.client.deactivateActivation(record.patchesActivationId)
      : await this.client.revokeActivation(record.patchesActivationId);
    this.recordAttempt(activationId, action === 'deactivate' ? 'activation.deactivate' : 'activation.revoke', outcome.attempts, outcome.lastRequestId ?? undefined);
    if (outcome.ok && outcome.receiptVerified) {
      const status = action === 'deactivate' ? 'DEACTIVATED' : 'REVOKED';
      this.store.runTransaction(() => {
        const r = this.store.getActivation(activationId)!;
        this.store.putActivation({ ...r, status, deactivatedAt: action === 'deactivate' ? this.now() : r.deactivatedAt, revokedAt: action === 'revoke' ? this.now() : r.revokedAt, updatedAt: this.now() });
        if (outcome.receipt) {
          this.store.putReceipt(this.toReceiptRecord(outcome));
        }
        this.audit(activationId, r.idempotencyKey, `activation.${action}`, 'SUCCESS', { code: `ACTIVATION_${status.toUpperCase()}`, patchesActivationId: record.patchesActivationId });
      });
      return { ok: true, status, errorCode: null, outcome };
    }
    // Ambiguous lifecycle failure: reconcile rather than assume.
    if (outcome.failureClass === 'AMBIGUOUS') {
      this.transition(activationId, 'RECONCILIATION_REQUIRED', outcome.failureReason ?? 'AMBIGUOUS', { code: 'LIFECYCLE_AMBIGUOUS', failureClass: 'AMBIGUOUS', failureReason: outcome.failureReason ?? undefined, patchesActivationId: record.patchesActivationId });
      return { ok: false, status: 'RECONCILIATION_REQUIRED', errorCode: outcome.errorCode, outcome };
    }
    // Terminal or exhausted: the local state is NOT moved on an
    // unverifiable lifecycle outcome; the server status stays authoritative
    // (syncStatus()/reconcile() are the paths that re-align local state).
    return { ok: false, status: record.status, errorCode: outcome.errorCode ?? 'LIFECYCLE_FAILED', outcome };
  }

  // ================= Reconciliation (owner amendment core) =================

  /**
   * Reconcile a RECONCILIATION_REQUIRED activation: query PATCHES status via
   * the stable identity, resolve to ACTIVE / fresh-create / terminal /
   * blocked. NEVER blind re-send of the original create.
   */
  async reconcile(activationId: string): Promise<ReconciliationResult> {
    const record = this.store.getActivation(activationId);
    if (!record) throw new Error(`activation unknown: ${activationId}`);
    if (record.status !== 'RECONCILIATION_REQUIRED' && record.status !== 'ACTIVATION_SENT') {
      return { status: 'PENDING', activationStatus: record.status, patchesActivationId: record.patchesActivationId ?? null, detail: 'not in reconciliation' };
    }

    const identity = record.patchesActivationId ?? record.lastIntentRequestHint ?? null;
    if (!identity) {
      this.transition(activationId, 'QUARANTINED', 'NO_PATCHES_IDENTITY', { code: 'NO_PATCHES_IDENTITY' });
      return { status: 'BLOCKED', activationStatus: 'QUARANTINED', patchesActivationId: null, detail: 'no stable identity to query' };
    }

    const attemptNo = this.store.nextReconciliationAttempt(activationId);
    const reconId = `${activationId}::${attemptNo}`;
    const openedAt = this.now();

    const outcome = await this.client.getActivationStatus(identity);
    const body = outcome.body as { activation?: { activationId?: string; status?: string; bindingId?: string; capability?: string; orgId?: string } } | null;
    const activation = body?.activation ?? null;

    // Wrong-org resolver denial: a 403 on the status query proves the
    // identity is not ours to read -> manual intervention, never a re-send.
    if (outcome.httpStatus === 403) {
      this.store.runTransaction(() => {
        this.store.putReconciliation({
          reconciliationId: reconId, activationId, reason: record.quarantineReason ?? 'RECONCILIATION',
          status: 'BLOCKED', patchesActivationId: identity, statusQueryAttempt: attemptNo,
          resolution: 'ACCESS_DENIED', resolutionDetail: outcome.errorCode ?? '403',
          openedAt, resolvedAt: this.now(),
        });
        this.transition(activationId, 'QUARANTINED', 'RECONCILIATION_ACCESS_DENIED', { code: 'RECONCILIATION_ACCESS_DENIED', errorCode: outcome.errorCode ?? undefined, patchesActivationId: identity });
      });
      return { status: 'RESOLVED_TERMINAL', activationStatus: 'QUARANTINED', patchesActivationId: identity, detail: 'status query access denied' };
    }

    if (outcome.ok && activation && activation.status === 'ACTIVE') {
      // Identity check: the status payload must match our binding identity.
      if (activation.bindingId !== record.bindingId || activation.capability !== record.capability || activation.orgId !== record.patchesOrgId) {
        this.store.runTransaction(() => {
          this.store.putReconciliation({
            reconciliationId: reconId, activationId, reason: record.quarantineReason ?? 'RECONCILIATION',
            status: 'BLOCKED', patchesActivationId: identity, statusQueryAttempt: attemptNo,
            resolution: 'TERMINAL', resolutionDetail: 'STATUS_IDENTITY_MISMATCH',
            openedAt, resolvedAt: this.now(),
          });
          this.transition(activationId, 'QUARANTINED', 'STATUS_IDENTITY_MISMATCH', { code: 'STATUS_IDENTITY_MISMATCH', patchesActivationId: identity });
        });
        return { status: 'RESOLVED_TERMINAL', activationStatus: 'QUARANTINED', patchesActivationId: identity, detail: 'status payload identity mismatch' };
      }
      // Resolved ACTIVE: the activation exists server-side; record it.
      this.store.runTransaction(() => {
        this.store.putReconciliation({
          reconciliationId: reconId, activationId, reason: record.quarantineReason ?? 'RECONCILIATION',
          status: 'RESOLVED_ACTIVE', patchesActivationId: identity, statusQueryAttempt: attemptNo,
          resolution: 'ACTIVE', resolutionDetail: 'status ACTIVE',
          openedAt, resolvedAt: this.now(),
        });
        const r = this.store.getActivation(activationId)!;
        this.store.putActivation({ ...r, patchesActivationId: activation.activationId ?? identity, status: 'ACTIVE', activatedAt: this.now(), updatedAt: this.now() });
        this.audit(activationId, r.idempotencyKey, 'activation.reconciled.active', 'SUCCESS', { code: 'RECONCILIATION_RESOLVED_ACTIVE', patchesActivationId: identity, status: 'ACTIVE' });
      });
      return { status: 'RESOLVED_ACTIVE', activationStatus: 'ACTIVE', patchesActivationId: identity, detail: 'server status ACTIVE' };
    }

    if (outcome.httpStatus === 404) {
      // NOT_FOUND: after bounded attempts, a fresh create with the SAME
      // idempotency key is permitted (never a blind duplicate: the 404
      // proves the original never persisted).
      this.store.runTransaction(() => {
        this.store.putReconciliation({
          reconciliationId: reconId, activationId, reason: record.quarantineReason ?? 'RECONCILIATION',
          status: attemptNo >= this.reconciliationStatusAttempts ? 'RESOLVED_NOT_FOUND' : 'OPEN',
          patchesActivationId: identity, statusQueryAttempt: attemptNo,
          resolution: attemptNo >= this.reconciliationStatusAttempts ? 'NOT_FOUND' : 'PENDING',
          resolutionDetail: `404 attempt ${attemptNo}/${this.reconciliationStatusAttempts}`,
          openedAt, resolvedAt: attemptNo >= this.reconciliationStatusAttempts ? this.now() : undefined,
        });
      });
      if (attemptNo >= this.reconciliationStatusAttempts) {
        const fresh = await this.sendCreate(this.store.getActivation(activationId)!);
        return {
          status: fresh.status === 'ACTIVE' ? 'RESOLVED_NOT_FOUND' : fresh.status === 'RECONCILIATION_REQUIRED' ? 'BLOCKED' : 'RESOLVED_TERMINAL',
          activationStatus: fresh.status,
          patchesActivationId: fresh.patchesActivationId,
          detail: `404 confirmed; fresh create with same idempotency key -> ${fresh.status}`,
        };
      }
      return { status: 'PENDING', activationStatus: 'RECONCILIATION_REQUIRED', patchesActivationId: identity, detail: `404; retry status query (${attemptNo}/${this.reconciliationStatusAttempts})` };
    }

    // Status query itself failed ambiguously: stay in reconciliation.
    this.store.runTransaction(() => {
      this.store.putReconciliation({
        reconciliationId: reconId, activationId, reason: record.quarantineReason ?? 'RECONCILIATION',
        status: 'OPEN', patchesActivationId: identity, statusQueryAttempt: attemptNo,
        resolution: 'PENDING', resolutionDetail: `status query failed: ${outcome.errorCode ?? outcome.failureReason ?? 'unknown'}`,
        openedAt,
      });
    });
    return { status: 'PENDING', activationStatus: 'RECONCILIATION_REQUIRED', patchesActivationId: identity, detail: `status query failed: ${outcome.errorCode ?? outcome.failureReason ?? 'unknown'}` };
  }

  // ================= Internal: send + classification wiring =================

  private async resumeAndSend(record: ArmaActivationRecord): Promise<ActivateResult> {
    return this.sendCreate(record);
  }

  private async sendCreate(record0: ArmaActivationRecord): Promise<ActivateResult> {
    // READY_TO_ACTIVATE (preflight done at intent creation or resume) ...
    const record = this.transition(record0.activationId, 'READY_TO_ACTIVATE', undefined, { code: 'READY_TO_ACTIVATE' });
    // ... then ACTIVATION_SENT is persisted BEFORE the outbound call: if the
    // process dies mid-send, the durable record proves a send MAY have
    // reached PATCHES, and resume() reconciles instead of re-sending.
    this.transition(record0.activationId, 'ACTIVATION_SENT', undefined, { code: 'ACTIVATION_SENT' });

    const outcome = await this.client.activate({
      orgId: record.patchesOrgId, capability: record.capability,
      bindingId: record.bindingId, idempotencyKey: record.idempotencyKey,
    });

    // Record attempts (retry evidence) + the identity hint from the FIRST
    // create attempt (stable identity for reconciliation).
    this.recordAttempt(record.activationId, 'activation.create', outcome.attempts, outcome.lastRequestId ?? undefined, outcome.attempts[0]?.requestId);

    if (outcome.ok && outcome.receiptVerified) {
      // RECEIPT_VERIFIED -> ACTIVE.
      const receipt = outcome.receipt!;
      this.store.runTransaction(() => {
        const r = this.store.getActivation(record.activationId)!;
        this.store.putActivation({ ...r, status: 'RECEIPT_VERIFIED', patchesActivationId: receipt.activationId ?? r.patchesActivationId, firstVerifiedAt: this.now(), updatedAt: this.now() });
        this.store.putReceipt(this.toReceiptRecord(outcome));
        this.audit(record.activationId, r.idempotencyKey, 'activation.receipt.verified', 'SUCCESS', { code: 'RECEIPT_VERIFIED', receiptId: receipt.receiptId, patchesActivationId: receipt.activationId ?? undefined, duplicate: outcome.duplicate });
        this.store.putActivation({ ...this.store.getActivation(record.activationId)!, status: 'ACTIVE', activatedAt: receipt.at, updatedAt: this.now() });
        const idem = this.store.getIdempotency(r.idempotencyKey);
        if (idem) this.store.putIdempotency({ ...idem, status: 'COLLAPSED', lastOutcome: 'SUCCESS', patchesActivationId: receipt.activationId, updatedAt: this.now() });
      });
      return {
        kind: outcome.duplicate ? 'DUPLICATE' : 'ACTIVATED',
        activationId: record.activationId,
        patchesActivationId: receipt.activationId ?? null,
        status: 'ACTIVE', failureClass: null, failureReason: null,
        errorCode: null, duplicate: outcome.duplicate, attempts: outcome.attempts.length,
      };
    }

    // Failure classification wiring (owner amendment).
    const failureClass = outcome.failureClass;
    const reason = outcome.failureReason;
    if (failureClass === 'AMBIGUOUS') {
      // Never blind re-send: RECONCILIATION_REQUIRED.
      this.transition(record.activationId, 'RECONCILIATION_REQUIRED', reason ?? 'AMBIGUOUS', {
        code: 'AMBIGUOUS_OUTCOME', failureClass: 'AMBIGUOUS', failureReason: reason ?? undefined,
        errorCode: outcome.errorCode ?? undefined, patchesActivationId: outcome.activationIdentityHint ?? undefined,
      });
      return {
        kind: 'RECONCILIATION_REQUIRED', activationId: record.activationId,
        patchesActivationId: outcome.activationIdentityHint ?? null,
        status: 'RECONCILIATION_REQUIRED', failureClass, failureReason: reason,
        errorCode: outcome.errorCode, duplicate: false, attempts: outcome.attempts.length,
      };
    }
    if (failureClass === 'TERMINAL') {
      // Credential/auth failures need operator action (rotation is ops);
      // other terminal codes are clean rejections.
      const authLike = (outcome.errorCode ?? '').startsWith('AUTH_') || AUTH_LIKE_CODES.has(outcome.errorCode ?? '');
      if (authLike) {
        this.transition(record.activationId, 'QUARANTINED', reason ?? 'TERMINAL', {
          code: 'CREDENTIAL_TERMINAL', failureClass: 'TERMINAL', failureReason: reason ?? undefined,
          errorCode: outcome.errorCode ?? undefined,
        });
        return {
          kind: 'QUARANTINED', activationId: record.activationId, patchesActivationId: null,
          status: 'QUARANTINED', failureClass, failureReason: reason,
          errorCode: outcome.errorCode, duplicate: false, attempts: outcome.attempts.length,
        };
      }
      this.transition(record.activationId, 'REJECTED', reason ?? 'TERMINAL', {
        code: 'INTENT_REJECTED', failureClass: 'TERMINAL', failureReason: reason ?? undefined,
        errorCode: outcome.errorCode ?? undefined,
      });
      return {
        kind: 'REJECTED', activationId: record.activationId, patchesActivationId: null,
        status: 'REJECTED', failureClass, failureReason: reason,
        errorCode: outcome.errorCode, duplicate: false, attempts: outcome.attempts.length,
      };
    }
    // CLEAN_RETRYABLE exhausted (bounded): operator decides; never blind re-send.
    this.transition(record.activationId, 'QUARANTINED', 'RETRIES_EXHAUSTED', {
      code: 'RETRIES_EXHAUSTED', failureClass: 'CLEAN_RETRYABLE', failureReason: reason ?? undefined,
      errorCode: outcome.errorCode ?? undefined,
    });
    return {
      kind: 'QUARANTINED', activationId: record.activationId, patchesActivationId: null,
      status: 'QUARANTINED', failureClass, failureReason: reason,
      errorCode: outcome.errorCode, duplicate: false, attempts: outcome.attempts.length,
    };
  }

  // ================= Internal helpers =================

  private stableIdempotencyKey(intent: ActivationIntent, patchesOrgId: string): string {
    // Stable per (org, capability, binding) intent: a retried or resumed
    // intent reuses the SAME key so PATCHES idempotency collapses it.
    return `arma-${this.intentHash(intent, patchesOrgId)}`;
    // Note: hash inputs are opaque ids only; no PII.
  }

  private intentHash(intent: ActivationIntent, patchesOrgId: string): string {
    return createHash('sha256').update(JSON.stringify({
      orgId: patchesOrgId, capability: intent.capability, bindingId: intent.bindingId,
    })).digest('hex');
  }

  private transition(activationId: string, to: ArmaActivationStatus, quarantineReason?: string, detail?: ArmaSafeDetail): ArmaActivationRecord {
    const record = this.store.getActivation(activationId);
    if (!record) throw new Error(`activation unknown: ${activationId}`);
    const now = this.now();
    const updated: ArmaActivationRecord = {
      ...record, status: to, updatedAt: now,
      ...(quarantineReason !== undefined ? { quarantineReason } : {}),
      ...(to === 'REJECTED' && detail?.errorCode ? { rejectedCode: detail.errorCode } : {}),
    };
    this.store.runTransaction(() => {
      this.store.putActivation(updated);
      this.audit(activationId, updated.idempotencyKey, `activation.state.${to.toLowerCase()}`, 'SUCCESS', detail);
    });
    return updated;
  }

  private recordAttempt(activationId: string, operation: 'activation.create' | 'activation.deactivate' | 'activation.revoke' | 'activation.status', attempts: AttemptRecord[], lastRequestId?: string, firstCreateRequestId?: string): void {
    const record = this.store.getActivation(activationId);
    if (!record) return;
    this.store.runTransaction(() => {
      for (const a of attempts) {
        this.store.putRetry({
          retryId: `${activationId}::${operation}::${a.attempt}`,
          activationId, operation, attempt: a.attempt,
          attemptRecordJson: JSON.stringify(a), createdAt: this.now(),
        });
      }
      const identityHint = firstCreateRequestId !== undefined ? `ACT-${firstCreateRequestId}` : undefined;
      this.store.putActivation({
        ...record, lastAttemptAt: this.now(),
        ...(identityHint !== undefined ? { lastIntentRequestHint: identityHint } : {}),
        ...(lastRequestId !== undefined ? { lastRequestId } : {}),
      });
    });
  }

  private toReceiptRecord(outcome: OperationOutcome): import('./transferSchema.ts').ArmaReceiptRecord {
    const receipt = outcome.receipt!;
    return {
      receiptId: receipt.receiptId,
      patchesActivationId: receipt.activationId ?? undefined,
      requestId: receipt.requestId,
      operation: receipt.operation,
      outcome: receipt.outcome,
      clientId: receipt.clientId,
      verifiedAt: this.now(),
      contentSha256: outcome.rawBody ? createHash('sha256').update(outcome.rawBody).digest('hex') : '',
      rawReceiptJson: JSON.stringify({
        schemaVersion: 'patches-partner-v1', receiptId: receipt.receiptId,
        requestId: receipt.requestId, clientId: receipt.clientId,
        operation: receipt.operation, outcome: receipt.outcome, at: receipt.at,
        activationId: receipt.activationId ?? null, orgId: receipt.orgId ?? null,
        capability: receipt.capability ?? null, payloadHash: receipt.payloadHash ?? null,
      }),
    };
  }

  private rejectNew(intent: ActivationIntent, code: string, reason: string): ActivateResult {
    // No activation record is created for a rejected-at-the-gate intent; the
    // audit trail records the rejection (operator can fix mapping/preflight
    // and retry the intent).
    this.store.runTransaction(() => {
      this.audit(`intent-${this.intentHash(intent, this.mappingFor(intent) ?? 'unmapped')}`, undefined, 'activation.intent.rejected', 'REJECTED', { code, capability: intent.capability, bindingId: intent.bindingId, orgId: intent.armaOrgId });
    });
    return {
      kind: 'REJECTED', activationId: `intent-${this.intentHash(intent, this.mappingFor(intent) ?? 'unmapped')}`,
      patchesActivationId: null, status: 'REJECTED', failureClass: 'TERMINAL', failureReason: reason,
      errorCode: code, duplicate: false, attempts: 0,
    };
  }

  private quarantineNew(intent: ActivationIntent, code: string, reason: string): ActivateResult {
    const mapping = this.mappingFor(intent);
    const activationId = `ARMA-ACT-${randomUUID()}`;
    const idempotencyKey = intent.idempotencyKey ?? `arma-${this.intentHash(intent, mapping ?? 'unmapped')}`;
    const now = this.now();
    this.store.runTransaction(() => {
      this.store.putActivation({
        activationId, idempotencyKey, armaOrgId: intent.armaOrgId,
        patchesOrgId: mapping ?? 'unmapped', capability: intent.capability,
        bindingId: intent.bindingId, status: 'QUARANTINED', quarantineReason: reason,
        createdAt: now, updatedAt: now,
      });
      this.audit(activationId, idempotencyKey, 'activation.intent.quarantined', 'QUARANTINED', { code, quarantineReason: reason });
    });
    return {
      kind: 'QUARANTINED', activationId, patchesActivationId: null, status: 'QUARANTINED',
      failureClass: 'TERMINAL', failureReason: reason, errorCode: code, duplicate: false, attempts: 0,
    };
  }

  private mappingFor(intent: ActivationIntent): string | null {
    const m = this.store.getOrgMappingByArmaOrg(intent.armaOrgId);
    return m ? m.patchesOrgId : null;
  }

  private audit(activationId: string, idempotencyKey: string | undefined, operation: string, outcome: 'SUCCESS' | 'REJECTED' | 'FAILED' | 'QUARANTINED' | 'CONFLICT' | 'BLOCKED', detail?: ArmaSafeDetail): void {
    this.store.appendAuditEvent({
      at: this.now(), actorKind: 'SYSTEM', activationId, idempotencyKey,
      operation, outcome, detail,
    });
  }
}

// SP4 auth failure codes that mean the CREDENTIAL is bad (operator must
// rotate/fix), as distinct from other terminal denials.
const AUTH_LIKE_CODES = new Set([
  'AUTH_MISSING', 'AUTH_MALFORMED', 'PARTNER_UNKNOWN', 'PARTNER_SUSPENDED',
  'CREDENTIAL_UNKNOWN', 'CREDENTIAL_REVOKED', 'CREDENTIAL_EXPIRED',
  'TIMESTAMP_OUT_OF_WINDOW', 'NONCE_INVALID', 'NONCE_REPLAYED',
  'SIGNATURE_INVALID', 'SECRET_UNAVAILABLE',
]);

export function redactOutcomeForAudit(outcome: OperationOutcome, secrets: string[]): Record<string, unknown> {
  return redactForAudit(outcome, secrets);
}
