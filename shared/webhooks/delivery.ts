// Stop Point 7 — secure webhook delivery.
//
// Delivers signed webhook envelopes to partner endpoints with the D3
// retry-vs-reconcile discipline: transport-level failures retry on the
// proven schedule; ambiguous outcomes (timeout after send, receipt/signature
// rejection by the partner) NEVER blindly re-send — they go to
// reconciliation via dead-letter. Duplicate events (same eventId already
// delivered to the same stream) collapse to the recorded outcome instead of
// being re-delivered. Every attempt is signed with a fresh nonce.

import { randomUUID } from 'node:crypto';
import {
  buildWebhookEnvelope,
  signWebhookEnvelope,
} from './events.ts';
import type { WebhookEnvelope } from './events.ts';
import { RETRY_SCHEDULE_MS, RetryPolicy } from '../sdk/retries.ts';
import { NONCE_PATTERN } from '../sdk/canonical.ts';

export type DeliveryOutcomeCode =
  | 'DELIVERED'
  | 'DELIVERED_DUPLICATE'
  | 'RETRY_EXHAUSTED'
  | 'DEAD_LETTERED_AMBIGUOUS'
  | 'DELIVERY_ENDPOINT_INVALID';

export interface DeliveryAttemptRecord {
  readonly attempt: number;
  readonly at: number;
  readonly outcome: 'SUCCEEDED' | 'FAILED' | 'AMBIGUOUS';
  /** Clean-retryable transport failure code (metadata only). */
  readonly reasonCode: string | null;
}

export interface DeliveryResult {
  readonly deliveryId: string;
  readonly eventId: string;
  readonly outcome: DeliveryOutcomeCode;
  readonly attempts: readonly DeliveryAttemptRecord[];
  readonly deadLettered: boolean;
  /** Partner the event was addressed to (never a payload). */
  readonly partnerId: string;
  readonly stream: string;
}

/** What the transport reports for a single attempt. */
export interface TransportResult {
  /** true only for a definitive success acknowledgement. */
  ok: boolean;
  /** Transport-level failure code, e.g. 'TRANSPORT_ERROR'. Metadata only. */
  code?: string;
  /** AMBIGUOUS: sent but outcome unknown (e.g. timeout after send). Never retried blindly. */
  ambiguous?: boolean;
}

export interface DeliveryTarget {
  /** Partner endpoint reference (opaque identifier, never a secret). */
  readonly targetId: string;
}

export interface DeliveryServiceOptions {
  /** Injected clock (ms since epoch). */
  readonly now?: () => number;
  /** Transport sink — delivers the signed request; simulated in tests. */
  readonly transport: (delivery: {
    deliveryId: string;
    eventId: string;
    targetId: string;
    rawBody: Buffer;
    headers: Readonly<Record<string, string>>;
  }) => TransportResult;
  /** Max delivery attempts (default schedule length: 5). */
  readonly maxAttempts?: number;
  /** Backoff schedule (default the proven [1s, 5s, 30s, 2m, 10m]). */
  readonly scheduleMs?: readonly number[];
}

export interface DeliverInput {
  /** Event to deliver — built/validated upstream (metadata-only data). */
  readonly envelope: WebhookEnvelope;
  /** Partner webhook signing secret. */
  readonly secret: string;
  readonly target: DeliveryTarget;
}

export class WebhookDeliveryService {
  private readonly now: () => number;
  private readonly transport: DeliveryServiceOptions['transport'];
  private readonly policy = new RetryPolicy();
  private readonly maxAttempts: number;
  private readonly schedule: readonly number[];
  /** eventId -> last delivery outcome (duplicate collapse). */
  private readonly delivered = new Map<string, { outcome: DeliveryOutcomeCode; at: number; attempts: number }>();
  /** Dead-letter queue: events that could NOT be definitively delivered. */
  private readonly deadLetters: {
    deliveryId: string;
    eventId: string;
    stream: string;
    partnerId: string;
    reasonCode: string;
    at: number;
    attempts: number;
  }[] = [];

  constructor(options: DeliveryServiceOptions) {
    if (!options || typeof options !== 'object' || typeof options.transport !== 'function') {
      throw new Error('DELIVERY_TRANSPORT_REQUIRED');
    }
    this.transport = options.transport;
    this.now = options.now ?? Date.now;
    this.schedule = options.scheduleMs ?? RETRY_SCHEDULE_MS;
    this.maxAttempts = options.maxAttempts ?? this.schedule.length;
    if (!Number.isInteger(this.maxAttempts) || this.maxAttempts < 1) {
      throw new Error('DELIVERY_MAX_ATTEMPTS_INVALID');
    }
  }

  /**
   * Deliver one event: duplicate collapse first (same eventId already
   * definitively delivered -> DELIVERED_DUPLICATE), then per-attempt
   * signing + transport. Clean-retryable failures advance the schedule;
   * ambiguous outcomes dead-letter immediately (never blind re-send);
   * exhaustion dead-letters. Returns the full attempt history (metadata only).
   */
  deliver(input: DeliverInput): DeliveryResult {
    if (!input || typeof input !== 'object' || !input.envelope) {
      throw new Error('DELIVERY_INPUT_INVALID');
    }
    if (typeof input.secret !== 'string' || input.secret.length === 0) {
      throw new Error('DELIVERY_SECRET_REQUIRED');
    }
    if (!input.target || typeof input.target.targetId !== 'string' || !input.target.targetId.trim()) {
      return this.refused(input, 'DELIVERY_ENDPOINT_INVALID');
    }

    const prior = this.delivered.get(input.envelope.eventId);
    if (prior && (prior.outcome === 'DELIVERED')) {
      return {
        deliveryId: `dlv-${randomUUID()}`,
        eventId: input.envelope.eventId,
        outcome: 'DELIVERED_DUPLICATE',
        attempts: [],
        deadLettered: false,
        partnerId: input.envelope.partnerId,
        stream: input.envelope.stream,
      };
    }

    const deliveryId = `dlv-${randomUUID()}`;
    const attempts: DeliveryAttemptRecord[] = [];
    let attempt = 0;
    let finalOutcome: DeliveryOutcomeCode = 'DELIVERED';
    let deadLettered = false;

    while (attempt < this.maxAttempts) {
      attempt += 1;
      const nonce = randomUUID().replace(/-/g, '') + randomUUID().slice(0, 8).replace(/-/g, '');
      if (!NONCE_PATTERN.test(nonce)) throw new Error('WEBHOOK_NONCE_INVALID');
      const signed = signWebhookEnvelope(input.envelope, input.secret, nonce);
      const result = this.transport({
        deliveryId,
        eventId: input.envelope.eventId,
        targetId: input.target.targetId,
        rawBody: signed.rawBody,
        headers: signed.headers,
      });
      if (result && result.ok === true) {
        attempts.push({ attempt, at: this.now(), outcome: 'SUCCEEDED', reasonCode: null });
        finalOutcome = 'DELIVERED';
        this.delivered.set(input.envelope.eventId, { outcome: 'DELIVERED', at: this.now(), attempts: attempt });
        return {
          deliveryId, eventId: input.envelope.eventId, outcome: finalOutcome,
          attempts: Object.freeze([...attempts]), deadLettered: false,
          partnerId: input.envelope.partnerId, stream: input.envelope.stream,
        };
      }
      const code = result?.code ?? 'TRANSPORT_ERROR';
      const classification = this.policy.classify(code);
      if (result?.ambiguous === true || classification.ambiguous) {
        attempts.push({ attempt, at: this.now(), outcome: 'AMBIGUOUS', reasonCode: code });
        finalOutcome = 'DEAD_LETTERED_AMBIGUOUS';
        deadLettered = true;
        break;
      }
      if (!classification.cleanRetryable) {
        attempts.push({ attempt, at: this.now(), outcome: 'FAILED', reasonCode: code });
        finalOutcome = 'DEAD_LETTERED_AMBIGUOUS';
        deadLettered = true;
        break;
      }
      // Clean-retryable: record the attempt and advance the schedule. In this
      // synchronous sandbox the next attempt proceeds immediately (the
      // schedule's proven delay values live in sdk/retries.ts for async drivers).
      attempts.push({ attempt, at: this.now(), outcome: 'FAILED', reasonCode: code });
      if (attempt >= this.maxAttempts) {
        finalOutcome = 'RETRY_EXHAUSTED';
        deadLettered = true;
        break;
      }
      const backoff = this.policy.computeBackoff(attempt - 1);
      if (!backoff.allowed) {
        finalOutcome = 'RETRY_EXHAUSTED';
        deadLettered = true;
        break;
      }
    }

    if (deadLettered) {
      this.deadLetters.push({
        deliveryId,
        eventId: input.envelope.eventId,
        stream: input.envelope.stream,
        partnerId: input.envelope.partnerId,
        reasonCode: finalOutcome === 'RETRY_EXHAUSTED' ? 'RETRY_EXHAUSTED' : 'AMBIGUOUS_OUTCOME',
        at: this.now(),
        attempts: attempt,
      });
    }

    return {
      deliveryId, eventId: input.envelope.eventId, outcome: finalOutcome,
      attempts: Object.freeze([...attempts]), deadLettered,
      partnerId: input.envelope.partnerId, stream: input.envelope.stream,
    };
  }

  /** Dead-letter queue snapshot (metadata only). */
  listDeadLetters(): readonly DeliveryResult['eventId'][] {
    return this.deadLetters.map((d) => d.eventId);
  }

  deadLetterCount(): number {
    return this.deadLetters.length;
  }

  private refused(input: DeliverInput, code: DeliveryOutcomeCode): DeliveryResult {
    return {
      deliveryId: `dlv-${randomUUID()}`,
      eventId: input.envelope?.eventId ?? 'UNKNOWN',
      outcome: code,
      attempts: [],
      deadLettered: false,
      partnerId: input.envelope?.partnerId ?? 'UNKNOWN',
      stream: input.envelope?.stream ?? 'UNKNOWN',
    };
  }
}
