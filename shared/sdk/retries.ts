// Stop Point 7 — shared partner SDK: retries + circuit breaker.
//
// Backoff generalizes the proven Law Shield D3 discipline: CLEAN-RETRYABLE
// ONLY. Ambiguous outcomes never blindly re-send (an accepted disclosure
// must never be duplicated) — they route to reconciliation. The schedule is
// injectable-clock so tests prove behavior deterministically.
//
// The CircuitBreaker is the fail-closed availability model: CLOSED (normal)
// -> OPEN (fail closed, refuse work) -> HALF_OPEN (probe with a canary
// request; success closes, failure re-opens). While OPEN, every call is
// refused — the partner is never allowed to hammer a failing dependency.

export const RETRY_SCHEDULE_MS = [1_000, 5_000, 30_000, 120_000, 600_000] as const; // 5 attempts max
export const MAX_RETRY_ATTEMPTS = RETRY_SCHEDULE_MS.length;

export type RetryDecision =
  | { allowed: true; delayMs: number; nextAttempt: number; retryAt: number }
  | { allowed: false; reason: 'MAX_RETRIES_EXCEEDED'; attempts: number };

export interface RetryPolicyOptions {
  scheduleMs?: readonly number[];
  now?: () => number;
}

export class RetryPolicy {
  private readonly schedule: readonly number[];
  private readonly now: () => number;

  constructor(options: RetryPolicyOptions = {}) {
    this.schedule = options.scheduleMs ?? RETRY_SCHEDULE_MS;
    this.now = options.now ?? Date.now;
  }

  /** Compute the next retry for a CLEAN-RETRYABLE failure. */
  computeBackoff(retryCount: number): RetryDecision {
    const attempts = Number(retryCount ?? 0);
    if (attempts >= this.schedule.length) {
      return { allowed: false, reason: 'MAX_RETRIES_EXCEEDED', attempts };
    }
    const delayMs = this.schedule[attempts];
    return { allowed: true, delayMs, nextAttempt: attempts + 1, retryAt: this.now() + delayMs };
  }

  /** Is a failure clean-retryable (pre-processing transport failure)? */
  canAutoRetry(failure: { retryable?: boolean; cleanRetryable?: boolean; ambiguous?: boolean }): boolean {
    if (failure.cleanRetryable === true) return true;
    if (failure.ambiguous === true) return false;
    if (failure.retryable === false) return false;
    return failure.retryable === true;
  }

  classify(code: string): { retryable: boolean; ambiguous: boolean; cleanRetryable: boolean } {
    const cleanRetryable = CLEAN_RETRYABLE_CODES.has(code);
    const ambiguous = AMBIGUOUS_RETRY_CODES.has(code);
    return {
      retryable: cleanRetryable || ambiguous,
      ambiguous,
      cleanRetryable,
    };
  }
}

export const CLEAN_RETRYABLE_CODES = new Set<string>([
  'TRANSPORT_ERROR', 'DOWNSTREAM_UNAVAILABLE', 'UNAVAILABLE',
]);
export const AMBIGUOUS_RETRY_CODES = new Set<string>([
  'CIRCUIT_OPEN', 'WEBHOOK_DELIVERY_FAILED', 'PERSISTENCE_FAILED',
  'RECEIPT_VERIFICATION_FAILED',
]);

// --- Circuit breaker ---

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  failureThreshold: number; // consecutive failures before OPEN
  resetTimeoutMs?: number; // time in OPEN before a canary probe
  now?: () => number;
}

export interface CircuitDecision {
  allowed: boolean;
  state: CircuitState;
  reason?: 'CIRCUIT_OPEN';
  probe?: boolean; // true when this call is the canary while HALF_OPEN
}

export class CircuitBreaker {
  private state: CircuitState = 'CLOSED';
  private consecutiveFailures = 0;
  private lastFailureAt: number | null = null;
  private readonly threshold: number;
  private readonly resetTimeoutMs: number;
  private readonly now: () => number;

  constructor(options: CircuitBreakerOptions) {
    if (!options || typeof options.failureThreshold !== 'number' || options.failureThreshold < 1) {
      throw new Error('CIRCUIT_OPTIONS_INVALID');
    }
    this.resetTimeoutMs = options.resetTimeoutMs ?? 30_000;
    this.threshold = options.failureThreshold;
    this.now = options.now ?? Date.now;
  }

  /** May work proceed? While OPEN, refuse (fail closed) until the reset
   *  timeout elapses, then allow ONE canary probe (HALF_OPEN). */
  check(): CircuitDecision {
    const now = this.now();
    if (this.state === 'CLOSED') {
      return { allowed: true, state: 'CLOSED' };
    }
    if (this.state === 'OPEN') {
      if (this.lastFailureAt !== null && now - this.lastFailureAt >= this.resetTimeoutMs) {
        this.state = 'HALF_OPEN';
        return { allowed: true, state: 'HALF_OPEN', probe: true, reason: 'CIRCUIT_OPEN' };
      }
      return { allowed: false, state: 'OPEN', reason: 'CIRCUIT_OPEN' };
    }
    // HALF_OPEN: only the canary may proceed; ordinary calls fail closed
    return { allowed: false, state: 'HALF_OPEN', reason: 'CIRCUIT_OPEN' };
  }

  /** Record a success: any state -> CLOSED, counters reset. */
  recordSuccess(): void {
    this.state = 'CLOSED';
    this.consecutiveFailures = 0;
    this.lastFailureAt = null;
  }

  /** Record a failure: CLOSED -> (threshold) -> OPEN; HALF_OPEN failure
   *  re-opens immediately. */
  recordFailure(): void {
    this.consecutiveFailures += 1;
    this.lastFailureAt = this.now();
    if (this.state === 'HALF_OPEN' || this.consecutiveFailures >= this.threshold) {
      this.state = 'OPEN';
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  getConsecutiveFailures(): number {
    return this.consecutiveFailures;
  }

  /** TEST-ONLY: force a state for direct assertions. */
  forceState(state: CircuitState): void {
    this.state = state;
  }
}
