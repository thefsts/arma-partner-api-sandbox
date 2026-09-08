// Stop Point 7 — secure webhook/event framework: envelopes.
//
// Outbound events to partners are signed envelopes with a fixed canonical
// form, per-attempt HMAC signatures, event IDs for idempotent consumption,
// strict per-stream sequence ordering, and nonce replay prevention on the
// receiving side. Event data is METADATA ONLY (allowlisted keys, scalar
// values, bounded strings) — sensitive payload content can never enter an
// envelope by construction.

import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { MAX_CLOCK_SKEW_MS, NONCE_PATTERN } from '../sdk/canonical.ts';

export const WEBHOOK_SCHEMA_VERSION = 'shared-webhook-v1';

export const WEBHOOK_EVENT_TYPES = Object.freeze([
  'resource.status.changed',
  'processing.completed',
  'processing.failed',
  'entitlement.changed',
  'entitlement.revoked',
  'reconciliation.required',
  'reconciliation.completed',
] as const);
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export function isKnownWebhookEventType(t: unknown): t is WebhookEventType {
  return typeof t === 'string' && (WEBHOOK_EVENT_TYPES as readonly string[]).includes(t);
}

/** Event data is metadata only — these keys, scalar values, bounded strings. */
const SAFE_EVENT_DATA_KEYS = new Set([
  'requestId', 'receiptId', 'entityRef', 'capability', 'entitlement',
  'operation', 'outcome', 'status', 'previousStatus', 'reasonCode',
  'errorCode', 'errorClass', 'attempt', 'maxAttempts', 'reconciliationStatus',
  'retries', 'deliveryId', 'auditId', 'sdkVersion', 'apiVersion',
]);
const EVENT_DATA_STRING_MAX = 256;

export const EVENT_ID_PATTERN = /^evt-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function generateEventId(): string {
  return `evt-${randomUUID()}`;
}

const STREAM_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;

export interface WebhookEnvelope {
  readonly schemaVersion: string;
  readonly eventId: string;
  readonly eventType: WebhookEventType;
  /** Ordering stream — typically the partner (or partner::org) pair. */
  readonly stream: string;
  /** Strict sequence: first event in a stream starts at any N >= 1, every
   *  following event must be exactly last + 1. */
  readonly sequence: number;
  readonly at: number;
  readonly partnerId: string;
  readonly orgRef: string | null;
  readonly requestId: string | null;
  /** Metadata-only event data (allowlisted keys, scalar values). */
  readonly data: Readonly<Record<string, string | number | boolean | null>>;
}

export interface BuildEnvelopeInput {
  readonly eventType: WebhookEventType;
  readonly stream: string;
  readonly sequence: number;
  readonly at: number;
  readonly partnerId: string;
  readonly orgRef?: string | null;
  readonly requestId?: string | null;
  readonly data?: Record<string, unknown>;
}

export type EnvelopeFailureCode =
  | 'WEBHOOK_EVENT_TYPE_UNKNOWN'
  | 'WEBHOOK_EVENT_MALFORMED'
  | 'WEBHOOK_STREAM_INVALID'
  | 'WEBHOOK_SEQUENCE_INVALID'
  | 'WEBHOOK_DATA_KEY_UNSAFE'
  | 'WEBHOOK_DATA_VALUE_INVALID'
  | 'WEBHOOK_PARTNER_INVALID'
  | 'WEBHOOK_TIMESTAMP_INVALID';

function isPositiveInt(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= Number.MAX_SAFE_INTEGER;
}

function sanitizeData(data: Record<string, unknown> | undefined): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(data ?? {})) {
    if (!SAFE_EVENT_DATA_KEYS.has(key)) {
      throw new Error(`WEBHOOK_DATA_KEY_UNSAFE`);
    }
    if (value === null) { out[key] = null; continue; }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new Error('WEBHOOK_DATA_VALUE_INVALID');
      out[key] = value;
      continue;
    }
    if (typeof value === 'boolean') { out[key] = value; continue; }
    if (typeof value === 'string') {
      if (value.length > EVENT_DATA_STRING_MAX) throw new Error('WEBHOOK_DATA_VALUE_INVALID');
      out[key] = value;
      continue;
    }
    throw new Error('WEBHOOK_DATA_VALUE_INVALID');
  }
  return out;
}

/** Build a validated metadata-only event envelope. Fails closed on any defect. */
export function buildWebhookEnvelope(input: BuildEnvelopeInput): WebhookEnvelope {
  if (!input || typeof input !== 'object') throw new Error('WEBHOOK_EVENT_MALFORMED');
  if (!isKnownWebhookEventType(input.eventType)) throw new Error('WEBHOOK_EVENT_TYPE_UNKNOWN');
  if (typeof input.stream !== 'string' || !STREAM_PATTERN.test(input.stream)) throw new Error('WEBHOOK_STREAM_INVALID');
  if (!isPositiveInt(input.sequence)) throw new Error('WEBHOOK_SEQUENCE_INVALID');
  if (typeof input.at !== 'number' || !Number.isFinite(input.at)) throw new Error('WEBHOOK_TIMESTAMP_INVALID');
  if (typeof input.partnerId !== 'string' || !STREAM_PATTERN.test(input.partnerId)) throw new Error('WEBHOOK_PARTNER_INVALID');
  const data = sanitizeData(input.data);
  const envelope: WebhookEnvelope = Object.freeze({
    schemaVersion: WEBHOOK_SCHEMA_VERSION,
    eventId: generateEventId(),
    eventType: input.eventType,
    stream: input.stream,
    sequence: input.sequence,
    at: input.at,
    partnerId: input.partnerId,
    orgRef: input.orgRef ?? null,
    requestId: input.requestId ?? null,
    data: Object.freeze(data),
  });
  return envelope;
}

/** Validate an already-built envelope (received side). Fails closed. */
export function validateWebhookEnvelope(env: unknown): { ok: true; envelope: WebhookEnvelope } | { ok: false; code: EnvelopeFailureCode } {
  if (!env || typeof env !== 'object') return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  const e = env as Record<string, unknown>;
  if (e.schemaVersion !== WEBHOOK_SCHEMA_VERSION) return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  if (typeof e.eventId !== 'string' || !EVENT_ID_PATTERN.test(e.eventId)) return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  if (!isKnownWebhookEventType(e.eventType)) return { ok: false, code: 'WEBHOOK_EVENT_TYPE_UNKNOWN' };
  if (typeof e.stream !== 'string' || !STREAM_PATTERN.test(e.stream)) return { ok: false, code: 'WEBHOOK_STREAM_INVALID' };
  if (!isPositiveInt(e.sequence)) return { ok: false, code: 'WEBHOOK_SEQUENCE_INVALID' };
  if (typeof e.at !== 'number' || !Number.isFinite(e.at)) return { ok: false, code: 'WEBHOOK_TIMESTAMP_INVALID' };
  if (typeof e.partnerId !== 'string' || !STREAM_PATTERN.test(e.partnerId)) return { ok: false, code: 'WEBHOOK_PARTNER_INVALID' };
  if (e.orgRef !== null && (typeof e.orgRef !== 'string' || !STREAM_PATTERN.test(e.orgRef))) return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  if (e.requestId !== null && (typeof e.requestId !== 'string' || !e.requestId.trim())) return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  if (!e.data || typeof e.data !== 'object' || Array.isArray(e.data)) return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  for (const [key, value] of Object.entries(e.data as Record<string, unknown>)) {
    if (!SAFE_EVENT_DATA_KEYS.has(key)) return { ok: false, code: 'WEBHOOK_DATA_KEY_UNSAFE' };
    if (value === null) continue;
    if (typeof value === 'number') { if (!Number.isFinite(value)) return { ok: false, code: 'WEBHOOK_DATA_VALUE_INVALID' }; continue; }
    if (typeof value === 'boolean') continue;
    if (typeof value === 'string') { if (value.length > EVENT_DATA_STRING_MAX) return { ok: false, code: 'WEBHOOK_DATA_VALUE_INVALID' }; continue; }
    return { ok: false, code: 'WEBHOOK_DATA_VALUE_INVALID' };
  }
  return {
    ok: true,
    envelope: Object.freeze({
      schemaVersion: WEBHOOK_SCHEMA_VERSION,
      eventId: e.eventId,
      eventType: e.eventType as WebhookEventType,
      stream: e.stream,
      sequence: e.sequence,
      at: e.at,
      partnerId: e.partnerId,
      orgRef: (e.orgRef as string | null) ?? null,
      requestId: (e.requestId as string | null) ?? null,
      data: Object.freeze({ ...(e.data as Record<string, string | number | boolean | null>) }),
    }),
  };
}

// --- Canonical form + signing ---

/**
 * Fixed-order canonical webhook string. The HMAC covers the schema version,
 * event identity, type, stream, sequence, timestamp, and the exact body
 * hash — nothing can be swapped without breaking the signature.
 */
export function canonicalWebhookString(input: {
  schemaVersion: string;
  eventId: string;
  eventType: string;
  stream: string;
  sequence: number;
  at: number;
  bodyHash: string;
}): string {
  return [
    input.schemaVersion,
    input.eventId,
    input.eventType,
    input.stream,
    String(input.sequence),
    String(input.at),
    input.bodyHash,
  ].join('\n');
}

export const WEBHOOK_HEADERS = {
  eventId: 'x-shared-webhook-event-id',
  signature: 'x-shared-webhook-signature',
  timestamp: 'x-shared-webhook-timestamp',
  nonce: 'x-shared-webhook-nonce',
  bodySha256: 'x-shared-webhook-body-sha256',
  schemaVersion: 'x-shared-webhook-schema-version',
} as const;

export interface SignedWebhook {
  readonly envelope: WebhookEnvelope;
  /** Exact serialized bytes — the signature covers EXACTLY these bytes. */
  readonly rawBody: Buffer;
  readonly headers: Readonly<Record<string, string>>;
}

/** Serialize + sign an envelope. The nonce makes each ATTEMPT unique. */
export function signWebhookEnvelope(envelope: WebhookEnvelope, secret: string, nonce: string): SignedWebhook {
  if (typeof secret !== 'string' || secret.length === 0) throw new Error('WEBHOOK_SECRET_REQUIRED');
  if (typeof nonce !== 'string' || !NONCE_PATTERN.test(nonce)) throw new Error('WEBHOOK_NONCE_INVALID');
  const rawBody = Buffer.from(JSON.stringify(envelope), 'utf8');
  const bodyHash = createHashSha256Hex(rawBody);
  const canonical = canonicalWebhookString({
    schemaVersion: envelope.schemaVersion,
    eventId: envelope.eventId,
    eventType: envelope.eventType,
    stream: envelope.stream,
    sequence: envelope.sequence,
    at: envelope.at,
    bodyHash,
  });
  const signature = createHmac('sha256', secret).update(canonical, 'utf8').digest('hex');
  const headers: Record<string, string> = Object.freeze({
    [WEBHOOK_HEADERS.eventId]: envelope.eventId,
    [WEBHOOK_HEADERS.signature]: signature,
    [WEBHOOK_HEADERS.timestamp]: String(envelope.at),
    [WEBHOOK_HEADERS.nonce]: nonce,
    [WEBHOOK_HEADERS.bodySha256]: bodyHash,
    [WEBHOOK_HEADERS.schemaVersion]: envelope.schemaVersion,
  });
  return { envelope, rawBody, headers };
}

export type WebhookFailureCode =
  | 'WEBHOOK_MISSING_HEADERS'
  | 'WEBHOOK_TIMESTAMP_INVALID'
  | 'WEBHOOK_SIGNATURE_INVALID'
  | 'WEBHOOK_NONCE_REPLAYED'
  | 'WEBHOOK_BODY_MALFORMED'
  | 'WEBHOOK_EVENT_TYPE_UNKNOWN'
  | 'WEBHOOK_EVENT_MALFORMED'
  | 'WEBHOOK_ORDERING_GAP'
  | 'WEBHOOK_STREAM_INVALID'
  | 'WEBHOOK_SEQUENCE_INVALID'
  | 'WEBHOOK_DATA_KEY_UNSAFE'
  | 'WEBHOOK_DATA_VALUE_INVALID'
  | 'WEBHOOK_PARTNER_INVALID';

export interface VerifyWebhookInput {
  readonly rawBody: Buffer | string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly secret: string;
  readonly now?: number;
  readonly guard?: WebhookEventGuard;
  readonly headerNames?: Partial<typeof WEBHOOK_HEADERS>;
}

export type WebhookVerification =
  | { ok: true; envelope: WebhookEnvelope }
  | { ok: false; code: WebhookFailureCode; detail?: Record<string, string | number | boolean | null> };

function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

/**
 * Verify a received webhook over RAW bytes: header presence -> schema/timestamp
 * skew -> nonce replay -> body hash -> HMAC -> envelope validation -> event-ID
 * replay -> per-stream sequence ordering. Fails closed on every defect.
 */
export function verifyWebhook(input: VerifyWebhookInput): WebhookVerification {
  if (!input || typeof input !== 'object') return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  const headerNames = { ...WEBHOOK_HEADERS, ...(input.headerNames ?? {}) };
  const h = (name: string): string | undefined => {
    const raw = input.headers[name.toLowerCase()];
    return Array.isArray(raw) ? raw[0] : raw;
  };
  const eventIdHeader = h(headerNames.eventId);
  const signatureHeader = h(headerNames.signature);
  const timestampHeader = h(headerNames.timestamp);
  const nonceHeader = h(headerNames.nonce);
  const bodyHashHeader = h(headerNames.bodySha256);
  const schemaVersionHeader = h(headerNames.schemaVersion);
  if (!eventIdHeader || !signatureHeader || !timestampHeader || !nonceHeader || !bodyHashHeader || !schemaVersionHeader) {
    return { ok: false, code: 'WEBHOOK_MISSING_HEADERS' };
  }
  if (schemaVersionHeader !== WEBHOOK_SCHEMA_VERSION) return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };

  const at = Number(timestampHeader);
  const now = input.now ?? Date.now();
  if (!Number.isFinite(at) || Math.abs(now - at) > MAX_CLOCK_SKEW_MS) {
    return { ok: false, code: 'WEBHOOK_TIMESTAMP_INVALID', detail: { skewMs: Math.abs(now - at), limitMs: MAX_CLOCK_SKEW_MS } };
  }

  if (typeof input.secret !== 'string' || input.secret.length === 0) {
    return { ok: false, code: 'WEBHOOK_SIGNATURE_INVALID' };
  }

  const raw = typeof input.rawBody === 'string' ? Buffer.from(input.rawBody, 'utf8') : input.rawBody;
  if (raw.length === 0) return { ok: false, code: 'WEBHOOK_BODY_MALFORMED' };
  const bodyHash = createHashSha256Hex(raw);
  if (bodyHash !== bodyHashHeader) return { ok: false, code: 'WEBHOOK_SIGNATURE_INVALID' };

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    return { ok: false, code: 'WEBHOOK_BODY_MALFORMED' };
  }
  const validated = validateWebhookEnvelope(parsed);
  if (!validated.ok) return { ok: false, code: validated.code };
  const envelope = validated.envelope;

  if (envelope.eventId !== eventIdHeader || envelope.at !== at) {
    return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
  }

  const canonical = canonicalWebhookString({
    schemaVersion: envelope.schemaVersion,
    eventId: envelope.eventId,
    eventType: envelope.eventType,
    stream: envelope.stream,
    sequence: envelope.sequence,
    at: envelope.at,
    bodyHash,
  });
  const expected = createHmac('sha256', input.secret).update(canonical, 'utf8').digest('hex');
  if (!timingSafeEqualHex(expected, signatureHeader)) {
    return { ok: false, code: 'WEBHOOK_SIGNATURE_INVALID' };
  }

  if (input.guard) {
    const replay = input.guard.check({
      eventId: envelope.eventId,
      stream: envelope.stream,
      sequence: envelope.sequence,
      nonce: nonceHeader,
      at: now,
    });
    if (!replay.ok) return { ok: false, code: replay.code, detail: replay.detail };
  }

  return { ok: true, envelope };
}

// --- Replay + ordering guard ---

export interface WebhookGuardCheckInput {
  readonly eventId: string;
  readonly stream: string;
  readonly sequence: number;
  readonly nonce: string;
  readonly at: number;
}

export type WebhookGuardResult =
  | { ok: true }
  | { ok: false; code: 'WEBHOOK_NONCE_REPLAYED' | 'WEBHOOK_ORDERING_GAP' | 'WEBHOOK_EVENT_MALFORMED'; detail?: Record<string, string | number | boolean | null> };

const NONCE_WINDOW_MS = 10 * 60 * 1000; // 2x MAX_CLOCK_SKEW_MS

/**
 * Receiver-side guard: per-nonce replay registry (any prior use burns the
 * nonce within the window) + per-stream strict sequence ordering (first
 * event in a stream may start at any sequence >= 1; every subsequent event
 * must be exactly last + 1 — gaps fail closed with the expected sequence).
 */
export class WebhookEventGuard {
  private readonly seenNonces = new Map<string, number>(); // nonce -> firstSeenAt
  private readonly seenEventIds = new Set<string>();
  private readonly streamSequence = new Map<string, number>(); // stream -> last sequence
  private readonly clock: () => number;

  constructor(options?: { now?: () => number }) {
    this.clock = options?.now ?? Date.now;
  }

  /** Check AND consume: a passing event's nonce, event ID, and sequence are
   *  recorded atomically — a second presentation of the same event fails. */
  check(input: WebhookGuardCheckInput): WebhookGuardResult {
    if (!input || typeof input !== 'object') return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
    if (typeof input.nonce !== 'string' || !NONCE_PATTERN.test(input.nonce)) {
      return { ok: false, code: 'WEBHOOK_EVENT_MALFORMED' };
    }
    const now = input.at ?? this.clock();
    this.prune(now);

    if (this.seenNonces.has(input.nonce)) {
      return { ok: false, code: 'WEBHOOK_NONCE_REPLAYED', detail: { nonce: input.nonce.slice(0, 16) } };
    }
    if (this.seenEventIds.has(input.eventId)) {
      return { ok: false, code: 'WEBHOOK_NONCE_REPLAYED', detail: { eventIdSeen: input.eventId } };
    }

    const last = this.streamSequence.get(input.stream);
    if (last !== undefined && input.sequence !== last + 1) {
      return {
        ok: false,
        code: 'WEBHOOK_ORDERING_GAP',
        detail: { sequence: input.sequence, expectedSequence: last + 1 },
      };
    }

    this.seenNonces.set(input.nonce, now);
    this.seenEventIds.add(input.eventId);
    this.streamSequence.set(input.stream, input.sequence);
    return { ok: true };
  }

  /** Drop expired nonces outside the replay window. */
  prune(now?: number): number {
    const at = now ?? this.clock();
    let remaining = 0;
    for (const [nonce, seenAt] of this.seenNonces) {
      if (at - seenAt > NONCE_WINDOW_MS) this.seenNonces.delete(nonce);
      else remaining += 1;
    }
    return remaining;
  }

  /** TEST-ONLY: seed a stream's last sequence (simulating prior history). */
  seedStream(stream: string, lastSequence: number): void {
    this.streamSequence.set(stream, lastSequence);
  }

  /** TEST-ONLY: inspect state. */
  lastSequenceFor(stream: string): number | undefined {
    return this.streamSequence.get(stream);
  }
}

function createHashSha256Hex(input: Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}
