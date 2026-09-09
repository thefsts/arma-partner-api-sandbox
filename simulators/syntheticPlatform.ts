// Stop Point 8 — the in-process synthetic CONTRACT PLATFORM (server engine).
//
// The platform is assembled ONLY from the shared Stop Point 7 modules —
// registry, signature verification, replay guard, idempotency, receipts,
// webhook events, delivery, circuit breaker, telemetry, and audit. It never
// re-implements any of them. Behavior is driven entirely by the
// ScenarioConfig record: the world (registry data), the platform fault plan
// (kill switch, receipt faults, downstream behavior, circuit plan, event
// emission), and the delivery script.
//
// The contract the platform enforces on EVERY protected request:
//   1. Kill switch   — refuse all protected work BEFORE any processing.
//   2. Signature     — verify the canonical form + HMAC, timing-safe, ±5 min.
//   3. Replay        — burn the nonce on first use; replays fail closed.
//   4. Authorization — resolve org -> binding -> entitlement -> capability.
//   5. Idempotency   — same key + same bytes = DUPLICATE: re-deliver the
//                      recorded outcome (a SUCCESS re-delivery, never an
//                      error, never a re-execution). Same key + different
//                      bytes = CONFLICT (fail closed). The first accepted
//                      operation RECORDS its outcome in the same transaction
//                      (the SP7 resolve-does-not-write discipline).
//   6. Receipt       — every 2xx carries a verifiable receipt; a faulted
//                      receipt (OMIT/FORGED/TAMPERED/WRONG_OPERATION) still
//                      returns 2xx — the CLIENT SDK must fail it closed.
//   7. Events        — emitted only for ACCEPTED requests, metadata-only
//                      webhook envelopes (closed vocabulary).
//   8. Delivery      — every emitted event is delivered in order; the
//                      receiver (the partner simulator's webhook endpoint)
//                      verifies each accepted delivery through ONE guard —
//                      per-attempt nonces, event-ID dedupe, strict
//                      per-stream sequence. Ordering gaps fail closed.
//   9. Reconciliation — ambiguous deliveries mark the span AMBIGUOUS/PENDING;
//                      the scenario's reconcile action (RESOLVE / ESCALATE)
//                      drives updateReconciliation + a reconciliation event.
//
// Every surfaced view is identifiers, codes, counts, and booleans only —
// never payload content.

import { createHash } from 'node:crypto';

import { PartnerRegistry } from '../shared/registry/partnerRegistry.ts';
import { verifyCanonicalRequestSignature } from '../shared/sdk/canonical.ts';
import { IdempotencyRegistry, ReplayGuard } from '../shared/sdk/idempotency.ts';
import {
  signReceiptBytes,
  RECEIPT_SCHEMA_VERSION,
  DEFAULT_RECEIPT_HEADERS,
} from '../shared/sdk/receipts.ts';
import { StructuredError } from '../shared/sdk/errors.ts';
import { CircuitBreaker } from '../shared/sdk/retries.ts';
import {
  buildWebhookEnvelope,
  isKnownWebhookEventType,
  verifyWebhook,
  WebhookEventGuard,
} from '../shared/webhooks/events.ts';
import type { WebhookEnvelope } from '../shared/webhooks/events.ts';
import { WebhookDeliveryService } from '../shared/webhooks/delivery.ts';
import type { DeliveryResult } from '../shared/webhooks/delivery.ts';
import { InMemoryTelemetrySink } from '../shared/observability/telemetry.ts';
import { IntegrationAuditTrail } from '../shared/sdk/audit.ts';
import { AuditLog } from '../ai-governance/audit.ts';
import {
  SYNTHETIC_SIMULATOR_SECRETS,
  SIM_CLAIM_HEADERS,
} from './behaviors.ts';
import type {
  PlatformFaultPlan,
  PlatformResponse,
  PresentableRequest,
  ScenarioConfig,
  TransportScriptStep,
} from './behaviors.ts';

export interface SyntheticPlatformOptions {
  /** The scenario world + fault plans, as pure data. */
  readonly scenario: ScenarioConfig;
  /** Injected deterministic clock. */
  readonly clock: () => number;
}

/** Platform-side view of one protected request (codes + booleans only). */
export interface PlatformDecisionView {
  readonly stage: string;
  readonly accepted: boolean;
  readonly code: string | null;
  readonly httpStatus: number;
}

/** A single emitted-event record (identifiers + type + sequence only). */
export interface EmittedEventView {
  readonly eventId: string;
  readonly eventType: string;
  readonly stream: string;
  readonly sequence: number;
}

/** Receiver-side verification outcome for a captured delivery. */
export interface ReceiverView {
  readonly verified: boolean;
  readonly code: string | null;
  readonly rePresentedCode: string | null;
}

/** Full delivery phase view (codes + counts + booleans only). */
export interface DeliveryPhaseView {
  readonly deliveryOutcome: string | null;
  readonly deliveryAttemptCount: number;
  readonly deadLettered: boolean;
  readonly receiver: ReceiverView;
  readonly deliveredTwiceOutcome: string | null;
  /** Receiver verification codes for each ACCEPTED delivery, in order. */
  readonly receiverCodes: readonly string[];
  /** Outcomes of the reconciliation-event deliveries (RESOLVE/ESCALATE only). */
  readonly reconciliationOutcomes: readonly string[];
}

/** Full scenario-run view (identifiers + codes + counts + booleans only). */
export interface PlatformRunView {
  readonly requestId: string | null;
  readonly decision: PlatformDecisionView;
  readonly circuitStates: readonly string[];
  readonly eventsEmitted: readonly string[];
  readonly emittedEvents: readonly EmittedEventView[];
  readonly delivery: DeliveryPhaseView | null;
  readonly spanStatus: string | null;
  readonly spanReconciliationStatus: string | null;
  readonly auditKinds: readonly string[];
  readonly auditReasonCodes: readonly string[];
}

const SDK_PARTNER_HEADER = 'x-shared-partner-id';
const SDK_TIMESTAMP_HEADER = 'x-shared-timestamp';
const SDK_SIGNATURE_HEADER = 'x-shared-signature';
const SDK_BODY_HASH_HEADER = 'x-shared-body-sha256';
const REQUEST_ID_HEADER = 'x-request-id';
/** Typed webhook failure codes surfaced from event-build failures. */
const WEBHOOK_FAILURE_CODE_PATTERN = /^WEBHOOK_[A-Z0-9_]+$/;

let receiptCounter = 0;
let entityCounter = 0;

function sha256Of(raw: Buffer): string {
  return createHash('sha256').update(raw).digest('hex');
}

function structuredFailureBody(
  code: string,
  status: number,
  requestId: string | null,
  errorCode: string,
): PlatformResponse {
  const error = new StructuredError({
    code,
    status,
    requestId: requestId ?? undefined,
    context: { errorCode },
  });
  return {
    status,
    rawBody: Buffer.from(JSON.stringify(error.toResponse()), 'utf8'),
    headers: { [REQUEST_ID_HEADER]: requestId ?? '' },
  };
}

/** The recorded operation outcome re-delivery store entry. */
interface StoredOutcomeResponse {
  readonly status: number;
  readonly rawBody: Buffer;
  readonly headers: Readonly<Record<string, string>>;
}

export class SyntheticPlatform {
  readonly registry: PartnerRegistry;
  readonly idempotency: IdempotencyRegistry;
  readonly replay: ReplayGuard;
  readonly telemetry: InMemoryTelemetrySink;
  readonly trail: IntegrationAuditTrail;
  readonly audit: AuditLog;
  readonly circuit: CircuitBreaker | null;

  private readonly scenario: ScenarioConfig;
  private readonly clock: () => number;
  private readonly circuitStates: string[] = [];
  private readonly events: WebhookEnvelope[] = [];
  private readonly capturedDeliveries: {
    deliveryId: string;
    eventId: string;
    targetId: string;
    rawBody: Buffer;
    headers: Readonly<Record<string, string>>;
    accepted: boolean;
  }[] = [];
  private readonly storedOutcomeResponses = new Map<string, StoredOutcomeResponse>();
  private eventSequence = 0;
  private downstreamFailureCount = 0;
  private lastDeliveryResult: DeliveryResult | null = null;
  private spanStatus: string | null = null;
  private spanReconciliationStatus: string | null = null;
  private lastDecision: PlatformDecisionView | null = null;
  /** The last GENUINELY accepted operation decision (never a duplicate). */
  private lastAcceptedDecision: PlatformDecisionView | null = null;
  private lastRequestId: string | null = null;
  private lastSpanId: string | null = null;

  constructor(options: SyntheticPlatformOptions) {
    if (!options || typeof options !== 'object') throw new Error('PLATFORM_OPTIONS_REQUIRED');
    if (!options.scenario) throw new Error('PLATFORM_SCENARIO_REQUIRED');
    if (typeof options.clock !== 'function') throw new Error('PLATFORM_CLOCK_REQUIRED');
    this.scenario = options.scenario;
    this.clock = options.clock;

    const secretValues = [
      SYNTHETIC_SIMULATOR_SECRETS.signing,
      SYNTHETIC_SIMULATOR_SECRETS.receipt,
      SYNTHETIC_SIMULATOR_SECRETS.webhook,
    ];
    this.registry = new PartnerRegistry({ now: this.clock });
    this.idempotency = new IdempotencyRegistry({ now: this.clock });
    this.replay = new ReplayGuard({ now: this.clock });
    this.telemetry = new InMemoryTelemetrySink({ now: this.clock, secretValues });
    this.audit = new AuditLog({ clock: { now: this.clock }, secretValues });
    this.trail = new IntegrationAuditTrail(this.audit);
    this.circuit = this.scenario.platformFaults.circuit
      ? new CircuitBreaker({
          failureThreshold: this.scenario.platformFaults.circuit.failureThreshold,
          resetTimeoutMs: this.scenario.platformFaults.circuit.resetTimeoutMs,
          now: this.clock,
        })
      : null;
  }

  /**
   * Assemble the scenario world: register the scenario's partner/org records
   * (world faults may omit a record — the registry then fails closed).
   */
  assembleWorld(): void {
    if (this.scenario.worldFaults?.omitPartnerRecord !== true) {
      this.registry.registerPartner(this.scenario.partnerRecord);
    }
    if (this.scenario.worldFaults?.omitOrgRecord !== true) {
      this.registry.registerOrg(this.scenario.orgRecord);
    }
  }

  /**
   * Receive ONE presented request and run the full contract chain. Returns
   * the raw response (status + body + headers) for the simulator SDK to
   * process. Deterministic: same world + same request = same response.
   */
  receive(request: PresentableRequest): PlatformResponse {
    const headers = request.headers as Readonly<Record<string, string>>;
    this.lastRequestId = request.requestId ?? null;

    // 1) KILL SWITCH — refuse ALL protected work before any processing.
    if (this.scenario.platformFaults.killSwitch === true) {
      this.auditRecord('integration.kill-switch.engaged', request.requestId, 'KILL_SWITCH_ENGAGED', {
        partnerId: headers[SDK_PARTNER_HEADER] ?? null,
      });
      this.lastDecision = {
        stage: 'KILL_SWITCH',
        accepted: false,
        code: 'PLATFORM_KILL_SWITCH',
        httpStatus: 503,
      };
      return structuredFailureBody('PLATFORM_KILL_SWITCH', 503, request.requestId, 'KILL_SWITCH_ENGAGED');
    }

    // 2) SIGNATURE — canonical form + HMAC, timing-safe, ±5 min skew window.
    const signatureFailure = this.verifySignatureStage(request);
    if (signatureFailure !== null) {
      this.auditRecord('integration.request.rejected.signature', request.requestId, signatureFailure, {
        partnerId: headers[SDK_PARTNER_HEADER] ?? null,
      });
      this.lastDecision = {
        stage: 'SIGNATURE',
        accepted: false,
        code: signatureFailure,
        httpStatus: 401,
      };
      return structuredFailureBody(signatureFailure, 401, request.requestId, signatureFailure);
    }

    // 3) REPLAY — burn the nonce on first use; replays fail closed.
    const partnerId = headers[SDK_PARTNER_HEADER] ?? '';
    const replayCheck = this.replay.check(partnerId, request.nonce, request.requestId);
    if (!replayCheck.ok) {
      this.auditRecord('integration.request.replayed', request.requestId, 'REPLAY_DETECTED', {
        partnerId,
      });
      this.lastDecision = {
        stage: 'REPLAY',
        accepted: false,
        code: 'REQUEST_REPLAYED',
        httpStatus: 409,
      };
      return structuredFailureBody('REQUEST_REPLAYED', 409, request.requestId, 'REPLAY_DETECTED');
    }

    // 4) AUTHORIZATION — org -> binding -> entitlement -> capability chain.
    const orgId = headers[SIM_CLAIM_HEADERS.orgId] ?? '';
    const entitlement = headers[SIM_CLAIM_HEADERS.entitlement] ?? '';
    const capability = headers[SIM_CLAIM_HEADERS.capability] ?? '';
    const resolution = this.registry.resolve({ partnerId, orgId, entitlement, capability });
    if (!resolution.ok) {
      this.auditRecord('integration.authorization.failed', request.requestId, resolution.code, {
        partnerId,
        orgRef: orgId,
      });
      this.lastDecision = {
        stage: 'AUTHORIZATION',
        accepted: false,
        code: resolution.code,
        httpStatus: 403,
      };
      return structuredFailureBody(resolution.code, 403, request.requestId, resolution.code);
    }

    // 5) IDEMPOTENCY — the SP7 module contract. resolve() never writes; the
    // first accepted operation records its outcome in the same transaction
    // (below). A DUPLICATE (same key + same bytes) re-delivers the recorded
    // outcome — a SUCCESS re-delivery, never an error. A CONFLICT (same key
    // + different bytes) is refused.
    const idempotencyKey = headers[SIM_CLAIM_HEADERS.idempotencyKey] ?? '';
    const operation = headers[SIM_CLAIM_HEADERS.operation] ?? '';
    const requestHash = sha256Of(request.rawBody);
    const idem = this.idempotency.resolve(partnerId, idempotencyKey, requestHash);
    if (idem.kind === 'CONFLICT') {
      this.auditRecord('integration.idempotency.conflict', request.requestId, 'IDEMPOTENCY_KEY_CONFLICT', {
        partnerId,
      });
      this.lastDecision = {
        stage: 'IDEMPOTENCY',
        accepted: false,
        code: 'IDEMPOTENCY_KEY_CONFLICT',
        httpStatus: 409,
      };
      return structuredFailureBody('IDEMPOTENCY_KEY_CONFLICT', 409, request.requestId, 'IDEMPOTENCY_KEY_CONFLICT');
    }
    if (idem.kind === 'DUPLICATE') {
      const stored = this.storedOutcomeResponses.get(`${partnerId}::${idempotencyKey}`) ?? null;
      this.auditRecord('integration.request.duplicate', request.requestId, 'IDEMPOTENCY_DUPLICATE', {
        partnerId,
      });
      this.lastDecision = {
        stage: 'IDEMPOTENCY_DUPLICATE',
        accepted: true,
        code: 'IDEMPOTENCY_DUPLICATE_COLLAPSED',
        httpStatus: stored?.status ?? 200,
      };
      if (stored !== null) {
        // Re-deliver the RECORDED outcome bytes — the duplicate collapse
        // contract: same response, never a re-execution.
        return { status: stored.status, rawBody: stored.rawBody, headers: stored.headers };
      }
      // No stored body (should not happen when the first outcome was
      // recorded) — fail closed rather than fabricate an outcome.
      return structuredFailureBody('IDEMPOTENCY_KEY_CONFLICT', 409, request.requestId, 'IDEMPOTENCY_RECORD_MISSING');
    }

    // 6) OPERATION — downstream execution behind the circuit breaker.
    // Availability failures (DOWNSTREAM_UNAVAILABLE / CIRCUIT_OPEN) are
    // PRE-TERMINAL by the shared retry model: the SDK classifies them
    // CLEAN-RETRYABLE (safe to blindly re-send). The platform therefore
    // records NO idempotency outcome for them — a same-key clean retry
    // re-executes and may succeed. Only a COMPLETED operation records
    // (SUCCESS, below) — the resolve-does-not-write discipline.
    const downstreamFailure = this.executeDownstream();
    if (downstreamFailure !== null) {
      this.auditRecord('integration.operation.failed', request.requestId, downstreamFailure, {
        partnerId,
        circuitState: this.circuit?.getState() ?? null,
      });
      const failureResponse = structuredFailureBody(
        downstreamFailure,
        503,
        request.requestId,
        downstreamFailure,
      );
      this.lastDecision = {
        stage: 'OPERATION',
        accepted: false,
        code: downstreamFailure,
        httpStatus: 503,
      };
      return failureResponse;
    }

    // 7) RECEIPT — a 2xx carrying a (possibly faulted) verifiable receipt.
    const receiptResponse = this.receiptResponseFor(request, operation, partnerId);
    this.auditRecord('integration.operation.completed', request.requestId, 'OPERATION_COMPLETED', {
      partnerId,
      orgRef: orgId,
      capability,
      requestHash,
    });
    // Record the SUCCESS outcome in the SAME transaction (SP7 discipline).
    this.idempotency.record(partnerId, idempotencyKey, requestHash, {
      outcome: 'SUCCESS',
      status: receiptResponse.status,
      bodyDigest: sha256Of(receiptResponse.rawBody),
      receiptId: String(receiptResponse.headers[DEFAULT_RECEIPT_HEADERS.receiptId] ?? ''),
      at: this.clock(),
    });
    this.storedOutcomeResponses.set(`${partnerId}::${idempotencyKey}`, receiptResponse);
    this.lastDecision = {
      stage: 'ACCEPTED',
      accepted: true,
      code: null,
      httpStatus: receiptResponse.status,
    };
    this.lastAcceptedDecision = this.lastDecision;
    return receiptResponse;
  }

  /**
   * Post-operation webhook phase: emit events + drive the shared delivery
   * service per the scripted transport, then verify receiver-side (the
   * partner simulator's webhook endpoint) with verifyWebhook through ONE
   * guard. Events are emitted ONLY for accepted requests. Reconciliation
   * events + telemetry reconciliation run for ambiguous deliveries when the
   * scenario configures a reconcile action.
   */
  emitAndDeliver(requestId: string | null): {
    events: readonly EmittedEventView[];
    delivery: DeliveryPhaseView;
    receiver: ReceiverView;
  } {
    // The event phase is gated on the last ACCEPTED operation decision — a
    // duplicate re-delivery (IDEMPOTENCY_DUPLICATE_COLLAPSED) is NOT a new
    // operation, so it must never open the event gate a second time.
    const decision = this.lastAcceptedDecision ?? this.lastDecision;
    const accepted = decision !== null && decision.accepted === true;
    const deliveryPlan = this.scenario.delivery;

    if (!accepted) {
      // Rejected requests emit NOTHING — the event phase is gated on
      // acceptance, and the span is terminal FAILED (never SUCCESS).
      this.recordSpanForScenario(null, false, false, null);
      const deliveryView: DeliveryPhaseView = {
        deliveryOutcome: null,
        deliveryAttemptCount: 0,
        deadLettered: false,
        receiver: { verified: false, code: null, rePresentedCode: null },
        deliveredTwiceOutcome: null,
        receiverCodes: [],
        reconciliationOutcomes: [],
      };
      return { events: [], delivery: deliveryView, receiver: deliveryView.receiver };
    }

    const emitted = this.emitEvents(requestId);
    const receiverCodes: string[] = [];
    const reconciliationOutcomes: string[] = [];

    let deliveryOutcome: string | null = null;
    let deliveryAttemptCount = 0;
    let deadLettered = false;
    let deliveredTwiceOutcome: string | null = null;
    // Mutable working record; frozen into the readonly ReceiverView at the
    // end of the phase (readonly fields are never assigned after freeze).
    let receiverVerified = false;
    let receiverCode: string | null = null;
    let receiverRePresentedCode: string | null = null;

    if (emitted.length > 0 && deliveryPlan.transportScript.length > 0 && this.events.length > 0) {
      let stepIndex = 0;
      const script: readonly TransportScriptStep[] = deliveryPlan.transportScript;
      // ONE receiver guard for the whole phase: every accepted delivery is
      // verified IN ORDER — per-attempt nonces, event-ID dedupe, strict
      // per-stream sequence. Ordering gaps fail closed here.
      const guard = new WebhookEventGuard({ now: this.clock });
      const deliveryService = new WebhookDeliveryService({
        now: this.clock,
        transport: (d) => {
          const step = script[Math.min(stepIndex, script.length - 1)];
          stepIndex += 1;
          const acceptedByTransport = step.ok === true;
          this.capturedDeliveries.push({ ...d, accepted: acceptedByTransport });
          if (acceptedByTransport) return { ok: true };
          return { ok: false, code: step.code, ambiguous: step.ambiguous === true };
        },
      });

      // Deliver EVERY emitted event, in order.
      let totalAttempts = 0;
      let anyDelivered = false;
      let anyDeadLettered = false;
      let lastOutcome: string | null = null;
      for (const envelope of this.events) {
        const result = deliveryService.deliver({
          envelope,
          secret: SYNTHETIC_SIMULATOR_SECRETS.webhook,
          target: { targetId: `target-${this.scenario.identity.partnerId}` },
        });
        this.lastDeliveryResult = result;
        lastOutcome = result.outcome;
        totalAttempts += result.attempts.length;
        if (result.outcome === 'DELIVERED') anyDelivered = true;
        if (result.deadLettered) anyDeadLettered = true;
      }
      deliveryOutcome = lastOutcome;
      deliveryAttemptCount = totalAttempts;
      deadLettered = anyDeadLettered;
      void anyDelivered;

      // Receiver-side verification: every ACCEPTED delivery, in order,
      // through the ONE guard (the partner simulator's webhook endpoint).
      const acceptedDeliveries = this.capturedDeliveries.filter((c) => c.accepted);
      for (const captured of acceptedDeliveries) {
        const verification = verifyWebhook({
          rawBody: captured.rawBody,
          headers: { ...captured.headers },
          secret: SYNTHETIC_SIMULATOR_SECRETS.webhook,
          now: this.clock(),
          guard,
        });
        receiverCodes.push(verification.ok ? 'OK' : verification.code);
      }
      receiverVerified = receiverCodes.length > 0 && receiverCodes.every((c) => c === 'OK');
      receiverCode = receiverCodes.length > 0 && receiverCodes[receiverCodes.length - 1] !== 'OK'
        ? receiverCodes[receiverCodes.length - 1]
        : null;

      const lastAccepted = acceptedDeliveries[acceptedDeliveries.length - 1] ?? null;
      if (lastAccepted !== null) {
        if (deliveryPlan.receiverFaults?.rePresentSameDelivery === true) {
          // Re-present the SAME signed delivery — nonce + event ID are
          // already burned: WEBHOOK_NONCE_REPLAYED.
          const second = verifyWebhook({
            rawBody: lastAccepted.rawBody,
            headers: { ...lastAccepted.headers },
            secret: SYNTHETIC_SIMULATOR_SECRETS.webhook,
            now: this.clock(),
            guard,
          });
          receiverRePresentedCode = second.ok ? 'OK' : second.code;
        }
        if (deliveryPlan.receiverFaults?.tamperBody === true) {
          // Present the delivery with a tampered body — the signature /
          // body-hash binding fails closed: WEBHOOK_SIGNATURE_INVALID.
          const tamperedBody = Buffer.from(`${lastAccepted.rawBody.toString('utf8')} `);
          const tampered = verifyWebhook({
            rawBody: tamperedBody,
            headers: { ...lastAccepted.headers },
            secret: SYNTHETIC_SIMULATOR_SECRETS.webhook,
            now: this.clock(),
            guard,
          });
          receiverCode = tampered.ok ? 'OK' : tampered.code;
          receiverCodes.push(tampered.ok ? 'OK' : String(tampered.code));
        }
      }

      if (deliveryPlan.deliverTwice === true && this.events.length > 0) {
        const second = deliveryService.deliver({
          envelope: this.events[0],
          secret: SYNTHETIC_SIMULATOR_SECRETS.webhook,
          target: { targetId: `target-${this.scenario.identity.partnerId}` },
        });
        deliveredTwiceOutcome = second.outcome;
      }

      // Reconciliation: ambiguous deliveries route to reconciliation —
      // never a blind re-send. The scenario's reconcile action drives the
      // telemetry status + a reconciliation event (delivered like any other).
      const ambiguous = deadLettered
        || (deliveryOutcome !== null && deliveryOutcome !== 'DELIVERED' && deliveryOutcome !== 'DELIVERED_DUPLICATE');
      if (ambiguous && this.scenario.reconcile !== undefined) {
        const eventType = this.scenario.reconcile === 'RESOLVE' ? 'reconciliation.completed' : 'reconciliation.required';
        const reconcileEvent = this.emitSingleEvent(requestId, eventType);
        if (reconcileEvent !== null) {
          const result = deliveryService.deliver({
            envelope: reconcileEvent,
            secret: SYNTHETIC_SIMULATOR_SECRETS.webhook,
            target: { targetId: `target-${this.scenario.identity.partnerId}` },
          });
          reconciliationOutcomes.push(result.outcome);
          if (result.outcome === 'DELIVERED') {
            const captured = this.capturedDeliveries[this.capturedDeliveries.length - 1];
            if (captured?.accepted === true) {
              const verification = verifyWebhook({
                rawBody: captured.rawBody,
                headers: { ...captured.headers },
                secret: SYNTHETIC_SIMULATOR_SECRETS.webhook,
                now: this.clock(),
                guard,
              });
              receiverCodes.push(verification.ok ? 'OK' : verification.code);
            }
          }
        }
        if (this.scenario.reconcile === 'RESOLVE') {
          this.auditRecord('integration.reconciliation.resolved', requestId ?? 'unknown-request', 'RECONCILIATION_RESOLVED', {
            partnerId: this.scenario.identity.partnerId,
          });
        } else {
          this.auditRecord('integration.reconciliation.escalated', requestId ?? 'unknown-request', 'RECONCILIATION_ESCALATED', {
            partnerId: this.scenario.identity.partnerId,
          });
        }
      }
    }

    const receiver: ReceiverView = Object.freeze({
      verified: receiverVerified,
      code: receiverCode,
      rePresentedCode: receiverRePresentedCode,
    });
    const deliveryView: DeliveryPhaseView = {
      deliveryOutcome,
      deliveryAttemptCount,
      deadLettered,
      receiver,
      deliveredTwiceOutcome,
      receiverCodes,
      reconciliationOutcomes,
    };
    this.recordSpanForScenario(deliveryOutcome, deadLettered, true, reconciliationOutcomes.length > 0 ? this.scenario.reconcile ?? null : null);
    return { events: emitted, delivery: deliveryView, receiver };
  }

  /** Circuit states observed after each downstream-facing call (codes only). */
  get circuitStateViews(): readonly string[] {
    return this.circuitStates;
  }

  /** Final span status + reconciliation status (codes only). */
  get spanViews(): { status: string | null; reconciliationStatus: string | null } {
    return { status: this.spanStatus, reconciliationStatus: this.spanReconciliationStatus };
  }

  /** The decision view of the LAST received request (codes + booleans only). */
  get decisionView(): PlatformDecisionView | null {
    return this.lastDecision;
  }

  /** All captured transport deliveries (raw bytes + headers for verification). */
  get deliveries(): readonly {
    deliveryId: string;
    eventId: string;
    targetId: string;
    rawBody: Buffer;
    headers: Readonly<Record<string, string>>;
    accepted: boolean;
  }[] {
    return this.capturedDeliveries;
  }

  /** Telemetry span count (test visibility, count only). */
  get spanCount(): number {
    return this.telemetry.list().length;
  }

  /** Audit entries as kind + reasonCode lists (no content). */
  get auditViews(): { kinds: readonly string[]; reasonCodes: readonly string[] } {
    const entries = this.trail.list();
    const kinds: string[] = [];
    const reasonCodes: string[] = [];
    for (const e of entries) {
      kinds.push(e.kind);
      reasonCodes.push(e.reasonCode);
    }
    return { kinds, reasonCodes };
  }

  // --- internals -----------------------------------------------------------

  private verifySignatureStage(request: PresentableRequest): string | null {
    const headers = request.headers as Readonly<Record<string, string>>;
    const bodyHashHeader = headers[SDK_BODY_HASH_HEADER] ?? '';
    const actualBodyHash = sha256Of(request.rawBody);

    // Body-hash binding first: the presented body must hash to the header.
    if (bodyHashHeader !== actualBodyHash) {
      return 'SIGNATURE_BODY_HASH_INVALID';
    }

    const verification = verifyCanonicalRequestSignature({
      secret: SYNTHETIC_SIMULATOR_SECRETS.signing,
      method: request.method,
      path: request.path,
      timestamp: headers[SDK_TIMESTAMP_HEADER] ?? '',
      nonce: request.nonce,
      bodyHash: bodyHashHeader,
      providedSignature: headers[SDK_SIGNATURE_HEADER] ?? '',
      now: this.clock(),
    });
    if (!verification.ok) {
      return verification.code;
    }
    return null;
  }

  private executeDownstream(): string | null {
    const downstream = this.scenario.platformFaults.downstream ?? 'HEALTHY';
    const circuitPlan = this.scenario.platformFaults.circuit;

    // Circuit-breaker gate (fail closed while OPEN / HALF_OPEN non-canary).
    if (this.circuit !== null) {
      const decision = this.circuit.check();
      this.circuitStates.push(decision.state);
      if (!decision.allowed) {
        this.recordCircuitState();
        return 'CIRCUIT_OPEN';
      }
    }

    // Downstream behavior per the plan (deterministic failure counters).
    const failsThenHealthy = downstream === 'FAILS_ONCE_THEN_HEALTHY';
    const scriptedFailures = circuitPlan?.downstreamFailures ?? 0;
    const mustFail =
      downstream === 'UNAVAILABLE' ||
      (failsThenHealthy && this.downstreamFailureCount < 1) ||
      (circuitPlan !== null && this.downstreamFailureCount < scriptedFailures);
    if (mustFail) {
      this.downstreamFailureCount += 1;
      this.circuit?.recordFailure();
      this.recordCircuitState();
      return 'DOWNSTREAM_UNAVAILABLE';
    }

    // Success path: record success on the breaker and proceed.
    this.circuit?.recordSuccess();
    this.recordCircuitState();
    return null;
  }

  private recordCircuitState(): void {
    if (this.circuit !== null) {
      this.circuitStates.push(this.circuit.getState());
    }
  }

  private receiptResponseFor(
    request: PresentableRequest,
    operation: string,
    partnerId: string,
  ): PlatformResponse {
    receiptCounter += 1;
    entityCounter += 1;
    const receiptId = `rct-sim-${String(receiptCounter).padStart(4, '0')}`;
    const entityRef = `entity-sim-${String(entityCounter).padStart(4, '0')}`;
    const fault = this.scenario.platformFaults.receiptFault ?? 'NONE';
    const requestHash = sha256Of(request.rawBody);

    if (fault === 'OMIT') {
      // 2xx with NO receipt headers at all — the client must fail closed.
      const receipt = this.receiptBody(receiptId, request.requestId, partnerId, operation, requestHash, entityRef);
      const rawBody = Buffer.from(JSON.stringify(receipt), 'utf8');
      return { status: 200, rawBody, headers: { [REQUEST_ID_HEADER]: request.requestId } };
    }

    if (fault === 'WRONG_OPERATION') {
      // A valid receipt proving the WRONG operation (binding violation).
      const wrong = this.receiptBody(receiptId, request.requestId, partnerId, 'sim.other-operation', requestHash, entityRef);
      const wrongRaw = Buffer.from(JSON.stringify(wrong), 'utf8');
      const wrongSigned = signReceiptBytes(wrongRaw, SYNTHETIC_SIMULATOR_SECRETS.receipt);
      return {
        status: 200,
        rawBody: wrongRaw,
        headers: {
          [REQUEST_ID_HEADER]: request.requestId,
          [DEFAULT_RECEIPT_HEADERS.receiptId]: receiptId,
          [DEFAULT_RECEIPT_HEADERS.contentSha256]: wrongSigned.contentSha256,
          [DEFAULT_RECEIPT_HEADERS.signature]: wrongSigned.signature,
        },
      };
    }

    const receipt = this.receiptBody(receiptId, request.requestId, partnerId, operation, requestHash, entityRef);
    const rawBody = Buffer.from(JSON.stringify(receipt), 'utf8');
    const signed = signReceiptBytes(rawBody, SYNTHETIC_SIMULATOR_SECRETS.receipt);
    const headers: Record<string, string> = {
      [REQUEST_ID_HEADER]: request.requestId,
      [DEFAULT_RECEIPT_HEADERS.receiptId]: receiptId,
      [DEFAULT_RECEIPT_HEADERS.contentSha256]: signed.contentSha256,
    };

    if (fault === 'FORGED') {
      // A receipt signed with the WRONG secret (a forged signer).
      const forged = signReceiptBytes(rawBody, SYNTHETIC_SIMULATOR_SECRETS.webhook);
      headers[DEFAULT_RECEIPT_HEADERS.signature] = forged.signature;
    } else if (fault === 'TAMPERED') {
      // A valid signature over the body, but a MISMATCHED content-hash header.
      headers[DEFAULT_RECEIPT_HEADERS.contentSha256] = flipFirstHexDigit(signed.contentSha256);
      headers[DEFAULT_RECEIPT_HEADERS.signature] = signed.signature;
    } else {
      headers[DEFAULT_RECEIPT_HEADERS.signature] = signed.signature;
    }

    return { status: 200, rawBody, headers };
  }

  private receiptBody(
    receiptId: string,
    requestId: string,
    partnerId: string,
    operation: string,
    requestHash: string,
    entityRef: string,
  ): Record<string, string | number> {
    return {
      schemaVersion: RECEIPT_SCHEMA_VERSION,
      receiptId,
      requestId,
      partnerId,
      operation,
      outcome: 'SUCCESS',
      at: this.clock(),
      entityRef,
      payloadHash: requestHash,
    };
  }

  private emitEvents(requestId: string | null): EmittedEventView[] {
    const faultPlan = this.scenario.platformFaults;
    const eventType = faultPlan.eventType ?? 'processing.completed';
    const count = faultPlan.emitEventCount ?? 2;
    const views: EmittedEventView[] = [];
    const stream = `${this.scenario.identity.partnerId}::${this.scenario.identity.orgId}`;
    let buildFailures = 0;

    for (let i = 0; i < count; i += 1) {
      const sequence = this.eventSequence + i + 1;
      const effectiveSequence = i === 1 && faultPlan.secondEventSequenceOffset !== undefined
        ? sequence + faultPlan.secondEventSequenceOffset
        : sequence;
      try {
        const envelope = buildWebhookEnvelope({
          eventType: isKnownWebhookEventType(eventType) ? eventType : (eventType as never),
          stream,
          sequence: effectiveSequence,
          at: this.clock(),
          partnerId: this.scenario.identity.partnerId,
          orgRef: this.scenario.identity.orgId,
          requestId,
          data: {
            operation: this.scenario.request.operation,
            outcome: 'SUCCESS',
            capability: this.scenario.request.capability,
          },
        });
        this.events.push(envelope);
        views.push({
          eventId: envelope.eventId,
          eventType: envelope.eventType,
          stream: envelope.stream,
          sequence: envelope.sequence,
        });
      } catch (err) {
        // Out-of-vocabulary event types / bad sequences fail closed at BUILD
        // time; surface the typed code, never message content beyond the code.
        if (err instanceof Error) {
          buildFailures += 1;
          const typedCode = WEBHOOK_FAILURE_CODE_PATTERN.test(err.message)
            ? err.message
            : 'WEBHOOK_BUILD_FAILED';
          views.push({
            eventId: `evt-build-failed-${buildFailures}`,
            eventType: typedCode,
            stream,
            sequence: effectiveSequence,
          });
          continue;
        }
        throw err;
      }
    }
    this.eventSequence += count;
    return views;
  }

  /** Emit ONE event of a given type (reconciliation events). */
  private emitSingleEvent(requestId: string | null, eventType: string): WebhookEnvelope | null {
    const stream = `${this.scenario.identity.partnerId}::${this.scenario.identity.orgId}`;
    const sequence = this.eventSequence + 1;
    try {
      const envelope = buildWebhookEnvelope({
        eventType: isKnownWebhookEventType(eventType) ? eventType : (eventType as never),
        stream,
        sequence,
        at: this.clock(),
        partnerId: this.scenario.identity.partnerId,
        orgRef: this.scenario.identity.orgId,
        requestId,
        data: {
          operation: this.scenario.request.operation,
          outcome: 'SUCCESS',
          capability: this.scenario.request.capability,
        },
      });
      this.events.push(envelope);
      this.eventSequence += 1;
      return envelope;
    } catch {
      // Out-of-vocabulary types fail closed at build time — no event, no throw.
      return null;
    }
  }

  /**
   * Record the scenario span. Rejected requests are terminal FAILED; an
   * accepted request with an ambiguous delivery is AMBIGUOUS/PENDING (or
   * RESOLVED / REQUIRED_UNRESOLVED after a reconcile action); anything else
   * with a clean delivery is SUCCESS.
   */
  private recordSpanForScenario(
    deliveryOutcome: string | null,
    deadLettered: boolean,
    accepted: boolean,
    reconcileAction: 'RESOLVE' | 'ESCALATE' | null,
  ): void {
    const requestId = this.lastRequestId ?? 'unknown-request';
    const span = this.telemetry.startSpan({
      requestId,
      partnerId: this.scenario.identity.partnerId,
      operation: this.scenario.request.operation,
      orgRef: this.scenario.identity.orgId,
      metadata: {
        capability: this.scenario.request.capability,
        outcome: deliveryOutcome ?? (accepted ? 'NOT_DELIVERED' : 'REJECTED'),
      },
    });
    this.lastSpanId = span.spanId;

    if (!accepted) {
      // A rejected request NEVER records SUCCESS — terminal FAILED.
      this.telemetry.completeSpan(span.spanId, {
        success: false,
        errorClass: 'AUTHENTICATION',
        retryCount: 0,
        reconciliationStatus: 'NONE',
      });
      this.spanStatus = 'FAILED';
      this.spanReconciliationStatus = 'NONE';
      return;
    }

    const ambiguous = deadLettered || (deliveryOutcome !== null && deliveryOutcome !== 'DELIVERED' && deliveryOutcome !== 'DELIVERED_DUPLICATE');
    if (ambiguous) {
      this.telemetry.markAmbiguous(span.spanId, {
        errorClass: 'DOWNSTREAM',
        reconciliationStatus: 'PENDING',
      });
      this.spanStatus = 'AMBIGUOUS';
      this.spanReconciliationStatus = 'PENDING';
      if (reconcileAction === 'RESOLVE') {
        this.telemetry.updateReconciliation(span.spanId, 'RESOLVED');
        this.spanReconciliationStatus = 'RESOLVED';
      } else if (reconcileAction === 'ESCALATE') {
        this.telemetry.updateReconciliation(span.spanId, 'REQUIRED_UNRESOLVED');
        this.spanReconciliationStatus = 'REQUIRED_UNRESOLVED';
      }
      return;
    }

    this.telemetry.completeSpan(span.spanId, { success: true, retryCount: 0 });
    this.spanStatus = 'SUCCESS';
    this.spanReconciliationStatus = 'NONE';
  }

  private auditRecord(
    kind: string,
    subjectId: string,
    reasonCode: string,
    details?: Record<string, string | number | boolean | null>,
  ): void {
    this.trail.record({
      kind,
      subjectId: subjectId || 'unknown-request',
      reasonCode,
      details,
      orgRef: null,
    });
  }
}

function flipFirstHexDigit(hash: string): string {
  if (typeof hash !== 'string' || hash.length === 0) return hash;
  const first = hash.slice(0, 1);
  const flipped = first === '0' ? '1' : '0';
  return `${flipped}${hash.slice(1)}`;
}
