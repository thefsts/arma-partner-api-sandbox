// ARMA-side retry policy for Law Shield transfers (D3 approval requirement).
// Backoff schedule is injectable (clock + sleep) so tests prove retry
// behavior deterministically without real time. KEY RULE from the approved
// D3 fix: retries are only legal for CLEAN retryable failures. AMBIGUOUS
// outcomes (receipt mismatch, timeout after send) never blindly re-send —
// they transition to RECONCILIATION_REQUIRED (an accepted disclosure must
// never be duplicated). Each retry uses a FRESH nonce/timestamp/signature.

export const RETRY_SCHEDULE_MS = [1_000, 5_000, 30_000, 120_000, 600_000]; // 5 attempts max
export const MAX_RETRY_ATTEMPTS = RETRY_SCHEDULE_MS.length;

// Default clock/sleep (injectable for tests).
export function defaultSleeper() {
  return { now: () => Date.now(), sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) };
}

// Compute the next retry state for a transfer.
// Returns { allowed, delayMs, nextAttempt } or { allowed:false, reason }.
export function computeBackoff({ retryCount, clock = defaultSleeper() } = {}) {
  const attempts = Number(retryCount ?? 0);
  if (attempts >= MAX_RETRY_ATTEMPTS) {
    return { allowed: false, reason: 'MAX_RETRIES_EXCEEDED', attempts };
  }
  const delayMs = RETRY_SCHEDULE_MS[attempts];
  return { allowed: true, delayMs, nextAttempt: attempts + 1, retryAt: clock.now() + delayMs };
}

// Decide whether a classified failure may be retried automatically.
// CLEAN retryable only (see receiptVerifier.classifyGatewayFailure).
export function canAutoRetry(classification) {
  if (!classification) return false;
  if (!classification.cleanRetryable) return false;
  return classification.retryable === true || classification.cleanRetryable === true;
}

// Compute delay and schedule WITHOUT sleeping (used by transferService to set
// nextRetryAt on the durable record; the scheduler loop performs the sleep).
export function scheduleRetry({ retryCount, clock = defaultSleeper() } = {}) {
  const backoff = computeBackoff({ retryCount, clock });
  if (!backoff.allowed) return backoff;
  return { ...backoff, sleepMs: backoff.delayMs };
}

export const RETRYABLE_CODES = new Set(['PROCESSOR_UNAVAILABLE', 'INTEGRATION_PROCESSOR_NOT_CONFIGURED']);
export const AMBIGUOUS_CODES = new Set(['PROCESSOR_RECEIPT_MISMATCH', 'PROCESSOR_TIMEOUT']);
export const TERMINAL_CODES = new Set([
  'INVALID_SIGNATURE', 'BODY_HASH_MISMATCH', 'PAYLOAD_HASH_MISMATCH', 'MISSING_SECURITY_HEADERS',
  'AI_CANNOT_AUTHORIZE_TRANSFER', 'AI_OR_EXECUTABLE_INSTRUCTION_BLOCKED', 'TRANSFER_EXPIRED',
  'REPLAYED_NONCE', 'STALE_OR_FUTURE_REQUEST', 'SCHEMA_VERSION_UNSUPPORTED', 'RECORD_TYPE_NOT_ALLOWED',
  'ORG_MAPPING_MISMATCH', 'CASE_MAPPING_REQUIRED', 'INVALID_SYSTEM_ROUTE', 'PROCESSOR_REJECTED_TRANSFER',
  'ORG_NOT_AUTHORIZED', 'PROCESSOR_NON_JSON_RESPONSE',
]);
