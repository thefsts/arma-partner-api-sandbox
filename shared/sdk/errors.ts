// Stop Point 7 — shared partner SDK: structured errors.
//
// Every partner-facing failure is a StructuredError: a stable machine code,
// an error CLASS (coarse routing vocabulary), an HTTP status, a retryable
// flag, and SAFE CONTEXT (allowlisted keys only — payload content, secrets,
// and free-form detail structurally cannot reach a partner-visible body).
// The safe-context allowlist is the same discipline as the PATCHES server's
// auth-failure response shaping and the SP6 audit detail allowlist.

export const ERROR_CLASSES = [
  'AUTHENTICATION',
  'AUTHORIZATION',
  'VERSION',
  'INPUT',
  'NOT_FOUND',
  'STATE',
  'IDEMPOTENCY',
  'REPLAY',
  'RATE_LIMIT',
  'DOWNSTREAM',
  'PERSISTENCE',
  'TRANSPORT',
  'UNAVAILABLE',
] as const;
export type ErrorClass = (typeof ERROR_CLASSES)[number];

export type SdkErrorCode =
  // authentication / authorization
  | 'AUTH_MISSING' | 'AUTH_MALFORMED' | 'PARTNER_UNKNOWN' | 'PARTNER_SUSPENDED'
  | 'ORG_UNKNOWN' | 'ORG_SUSPENDED' | 'ORG_NOT_BOUND_TO_PARTNER'
  | 'ENTITLEMENT_MISSING' | 'ENTITLEMENT_INACTIVE' | 'ENTITLEMENT_REVOKED' | 'ENTITLEMENT_EXPIRED'
  | 'CAPABILITY_UNKNOWN' | 'CAPABILITY_VERSION_UNSUPPORTED'
  | 'CREDENTIAL_UNKNOWN' | 'CREDENTIAL_REVOKED' | 'CREDENTIAL_EXPIRED'
  // version
  | 'VERSION_MISSING' | 'VERSION_MALFORMED' | 'VERSION_UNKNOWN' | 'VERSION_OUT_OF_CAPABILITY_WINDOW'
  // input
  | 'INPUT_MISSING' | 'INPUT_MALFORMED' | 'PAYLOAD_TOO_LARGE'
  // state
  | 'ENTITY_UNKNOWN' | 'ENTITY_STATE_CONFLICT'
  // idempotency / replay
  | 'IDEMPOTENCY_KEY_INVALID' | 'IDEMPOTENCY_KEY_CONFLICT' | 'REPLAY_DETECTED'
  // rate limit / downstream / persistence / transport
  | 'RATE_LIMITED' | 'DOWNSTREAM_UNAVAILABLE' | 'PERSISTENCE_FAILED' | 'TRANSPORT_ERROR'
  // circuit / availability
  | 'CIRCUIT_OPEN' | 'UNAVAILABLE'
  // webhook-specific
  | 'WEBHOOK_SIGNATURE_INVALID' | 'WEBHOOK_TIMESTAMP_INVALID' | 'WEBHOOK_NONCE_REPLAYED'
  | 'WEBHOOK_EVENT_TYPE_UNKNOWN' | 'WEBHOOK_EVENT_MALFORMED' | 'WEBHOOK_ORDERING_GAP'
  | 'WEBHOOK_DELIVERY_FAILED' | 'WEBHOOK_DEAD_LETTERED'
  | 'RECEIPT_VERIFICATION_FAILED' | 'PARTNER_REQUEST_FAILED';

/** Safe partner-visible context keys — identifiers and diagnostics only. */
export const SAFE_CONTEXT_KEYS = new Set([
  'requestId', 'receiptId', 'partnerId', 'clientId', 'orgId', 'capability',
  'entityRef', 'keyId', 'idempotencyKey', 'nonce', 'requestHash', 'payloadHash',
  'errorCode', 'retryAfterMs', 'limitBytes', 'skewMs', 'limitMs', 'graceUntil',
  'supported', 'provided', 'min', 'max', 'apiVersion', 'eventId', 'sequence',
  'expectedSequence', 'at', 'firstSeenAt', 'firstSeenRequestId', 'eventIdSeen',
  'sequenceNumber', 'errorClass', 'eventType', 'stream', 'attempt', 'maxAttempts',
]);

const SAFE_CONTEXT_STRING_MAX = 256;

/** Map an error code to its coarse class. */
export function errorClassForCode(code: string): ErrorClass {
  switch (code) {
    case 'AUTH_MISSING': case 'AUTH_MALFORMED': case 'PARTNER_UNKNOWN': case 'PARTNER_SUSPENDED':
    case 'CREDENTIAL_UNKNOWN': case 'CREDENTIAL_REVOKED': case 'CREDENTIAL_EXPIRED':
      return 'AUTHENTICATION';
    case 'ORG_UNKNOWN': case 'ORG_SUSPENDED': case 'ORG_NOT_BOUND_TO_PARTNER':
    case 'ENTITLEMENT_MISSING': case 'ENTITLEMENT_INACTIVE': case 'ENTITLEMENT_REVOKED': case 'ENTITLEMENT_EXPIRED':
    case 'CAPABILITY_UNKNOWN': case 'CAPABILITY_VERSION_UNSUPPORTED':
      return 'AUTHORIZATION';
    case 'VERSION_MISSING': case 'VERSION_MALFORMED': case 'VERSION_UNKNOWN': case 'VERSION_OUT_OF_CAPABILITY_WINDOW':
      return 'VERSION';
    case 'INPUT_MISSING': case 'INPUT_MALFORMED': case 'PAYLOAD_TOO_LARGE':
      return 'INPUT';
    case 'ENTITY_UNKNOWN': return 'NOT_FOUND';
    case 'ENTITY_STATE_CONFLICT': return 'STATE';
    case 'IDEMPOTENCY_KEY_INVALID': case 'IDEMPOTENCY_KEY_CONFLICT': return 'IDEMPOTENCY';
    case 'REPLAY_DETECTED': return 'REPLAY';
    case 'RATE_LIMITED': return 'RATE_LIMIT';
    case 'DOWNSTREAM_UNAVAILABLE': return 'DOWNSTREAM';
    case 'PERSISTENCE_FAILED': return 'PERSISTENCE';
    case 'CIRCUIT_OPEN': return 'UNAVAILABLE';
    case 'TRANSPORT_ERROR': case 'UNAVAILABLE': return 'TRANSPORT';
    case 'RECEIPT_VERIFICATION_FAILED': return 'TRANSPORT';
    case 'PARTNER_REQUEST_FAILED': return 'DOWNSTREAM';
    case 'WEBHOOK_SIGNATURE_INVALID': case 'WEBHOOK_TIMESTAMP_INVALID':
    case 'WEBHOOK_NONCE_REPLAYED': case 'WEBHOOK_EVENT_TYPE_UNKNOWN': case 'WEBHOOK_EVENT_MALFORMED':
    case 'WEBHOOK_ORDERING_GAP': case 'WEBHOOK_DELIVERY_FAILED': case 'WEBHOOK_DEAD_LETTERED':
      return 'TRANSPORT';
    default: return 'INPUT';
  }
}

/** Which failures are safe to retry automatically? CLEAN RETRYABLE ONLY:
 *  transport-level failures that occurred before processing. Ambiguous
 *  outcomes route to reconciliation instead (retry-vs-reconcile). */
export const RETRYABLE_CODES = new Set<string>([
  'TRANSPORT_ERROR', 'DOWNSTREAM_UNAVAILABLE', 'UNAVAILABLE',
]);

export const AMBIGUOUS_CODES = new Set<string>([
  'CIRCUIT_OPEN', 'WEBHOOK_DELIVERY_FAILED', 'RECEIPT_VERIFICATION_FAILED',
]);

export const TERMINAL_CODES = new Set<string>([
  'AUTH_MISSING', 'AUTH_MALFORMED', 'PARTNER_UNKNOWN', 'PARTNER_SUSPENDED',
  'ORG_UNKNOWN', 'ORG_SUSPENDED', 'ORG_NOT_BOUND_TO_PARTNER',
  'ENTITLEMENT_MISSING', 'ENTITLEMENT_INACTIVE', 'ENTITLEMENT_REVOKED', 'ENTITLEMENT_EXPIRED',
  'CAPABILITY_UNKNOWN', 'CAPABILITY_VERSION_UNSUPPORTED',
  'CREDENTIAL_UNKNOWN', 'CREDENTIAL_REVOKED', 'CREDENTIAL_EXPIRED',
  'VERSION_MISSING', 'VERSION_MALFORMED', 'VERSION_UNKNOWN', 'VERSION_OUT_OF_CAPABILITY_WINDOW',
  'INPUT_MISSING', 'INPUT_MALFORMED', 'PAYLOAD_TOO_LARGE',
  'ENTITY_UNKNOWN', 'ENTITY_STATE_CONFLICT',
  'IDEMPOTENCY_KEY_INVALID', 'IDEMPOTENCY_KEY_CONFLICT', 'REPLAY_DETECTED',
  'WEBHOOK_SIGNATURE_INVALID', 'WEBHOOK_TIMESTAMP_INVALID',
  'WEBHOOK_NONCE_REPLAYED', 'WEBHOOK_EVENT_TYPE_UNKNOWN', 'WEBHOOK_EVENT_MALFORMED',
  'WEBHOOK_ORDERING_GAP', 'WEBHOOK_DEAD_LETTERED',
]);

export function isRetryableCode(code: string): boolean {
  return RETRYABLE_CODES.has(code);
}

export function isAmbiguousCode(code: string): boolean {
  return AMBIGUOUS_CODES.has(code);
}

export function isTerminalCode(code: string): boolean {
  return TERMINAL_CODES.has(code);
}

export interface StructuredErrorInit {
  code: SdkErrorCode | string;
  status?: number;
  retryable?: boolean;
  context?: Record<string, unknown>;
  requestId?: string;
}

export interface SafeContextEntry {
  key: string;
  value: string | number | boolean | null;
}

function sanitizeContextValue(value: unknown, key: string): string | number | boolean | null {
  if (typeof value === 'string') {
    return value.length <= SAFE_CONTEXT_STRING_MAX ? value : null;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (value === null || value === undefined) return null;
  return null; // objects/arrays never reach partner-visible context
}

/** Build the safe partner-visible context: allowlisted keys only, scalar
 *  values only, bounded string length. Returns a NEW object (no aliasing). */
export function safeContextFor(context: Record<string, unknown> | undefined): Record<string, string | number | boolean | null> {
  if (!context || typeof context !== 'object') return {};
  const out: Record<string, string | number | boolean | null> = {}
  for (const [key, value] of Object.entries(context)) {
    if (!SAFE_CONTEXT_KEYS.has(key)) continue;
    const clean = sanitizeContextValue(value, key);
    if (clean !== null) out[key] = clean;
  }
  return out;
}

/**
 * The shared structured error. `toResponse()` produces the partner-visible
 * body: { error, errorClass, requestId?, ...safeContext }. Payload content,
 * secrets, and non-allowlisted keys structurally cannot appear.
 */
export class StructuredError extends Error {
  readonly code: string;
  readonly errorClass: ErrorClass;
  readonly status: number;
  readonly retryable: boolean;
  readonly safeContext: Record<string, string | number | boolean | null>;
  readonly requestId: string | null;

  constructor(init: StructuredErrorInit) {
    super(init.code);
    this.name = 'StructuredError';
    this.code = init.code;
    this.errorClass = errorClassForCode(init.code);
    this.status = init.status ?? defaultStatusForCode(init.code);
    this.retryable = init.retryable ?? isRetryableCode(init.code);
    this.safeContext = safeContextFor(init.context);
    this.requestId = init.requestId ?? null;
  }

  toResponse(): Record<string, unknown> {
    const body: Record<string, unknown> = {
      error: this.code,
      errorClass: this.errorClass,
    };
    if (this.requestId) body.requestId = this.requestId;
    return { ...body, ...this.safeContext };
  }
}

function defaultStatusForCode(code: string): number {
  const cls = errorClassForCode(code);
  switch (cls) {
    case 'AUTHENTICATION': return 401;
    case 'AUTHORIZATION': return 403;
    case 'VERSION': return 400;
    case 'INPUT': return 400;
    case 'NOT_FOUND': return 404;
    case 'STATE': return 409;
    case 'IDEMPOTENCY': return 409;
    case 'REPLAY': return 409;
    case 'RATE_LIMIT': return 429;
    case 'DOWNSTREAM': return 503;
    case 'PERSISTENCE': return 500;
    case 'UNAVAILABLE': return 503;
    case 'TRANSPORT': return 502;
    default: return 400;
  }
}
