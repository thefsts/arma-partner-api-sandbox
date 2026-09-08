// Stop Point 7 — shared partner SDK: idempotency + replay protection.
//
// Two coupled registries modeled on the proven PATCHES store discipline:
//  - IdempotencyRegistry: (scope, idempotencyKey) -> recorded outcome.
//    FRESH / DUPLICATE (same request hash -> collapse to the recorded
//    outcome; a duplicate delivery is a SUCCESS re-delivery, not an error)
//    / CONFLICT (same key, different request hash -> refuse).
//  - ReplayGuard: per-scope nonce registry with a bounded validity window
//    and pruning, so a captured request cannot be replayed later.
//
// Both are in-memory synthetic persistence shaped for porting: each map
// entry models a durable unique-index row (see PORTING NOTE below).
//
// PORTING NOTE (private repos): idempotency -> unique index on
// (scope, idempotencyKey); nonces -> unique index on (scope, nonce) with
// TTL-style validity window; resolve() inside one transaction with the
// operation outcome so a partial write can never poison the registry.

export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;
export const DEFAULT_IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000; // 24h

export type IdempotencyOutcomeKind = 'FRESH' | 'DUPLICATE' | 'CONFLICT';

export interface IdempotencyRecordedOutcome {
  outcome: 'SUCCESS' | 'CONFLICT' | 'REJECTED';
  status: number;
  bodyDigest: string; // hash of the response body, never the body itself
  receiptId?: string;
  at: number;
}

export interface IdempotencyResolveResult {
  kind: IdempotencyOutcomeKind;
  existing?: IdempotencyRecordedOutcome;
}

export class IdempotencyRegistry {
  private readonly records = new Map<string, { requestHash: string; outcome: IdempotencyRecordedOutcome; expiresAt: number }>();
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(options: { ttlMs?: number; now?: () => number } = {}) {
    this.ttlMs = options.ttlMs ?? DEFAULT_IDEMPOTENCY_TTL_MS;
    this.now = options.now ?? Date.now;
  }

  /** Resolve an idempotency key. Does NOT write — the caller records the
   *  outcome in the same transaction as the operation (fail-closed). */
  resolve(scope: string, idempotencyKey: string, requestHash: string): IdempotencyResolveResult {
    if (!this.isValidKey(idempotencyKey)) return { kind: 'CONFLICT' };
    const key = compositeKey(scope, idempotencyKey);
    const existing = this.records.get(key);
    if (!existing || this.now() > existing.expiresAt) {
      return { kind: 'FRESH' };
    }
    if (existing.requestHash !== requestHash) return { kind: 'CONFLICT' };
    return { kind: 'DUPLICATE', existing: existing.outcome };
  }

  /** Record the outcome for an idempotency key — call inside the operation
   *  transaction. Recording a key twice for DIFFERENT request hashes is a
   *  bug in the caller and throws (fail-closed). */
  record(scope: string, idempotencyKey: string, requestHash: string, outcome: IdempotencyRecordedOutcome): void {
    if (!this.isValidKey(idempotencyKey)) throw new Error('IDEMPOTENCY_KEY_INVALID');
    const key = compositeKey(scope, idempotencyKey);
    const existing = this.records.get(key);
    if (existing && existing.requestHash !== requestHash) {
      throw new Error('IDEMPOTENCY_RECORD_CONFLICT');
    }
    this.records.set(key, { requestHash, outcome, expiresAt: this.now() + this.ttlMs });
  }

  lookup(scope: string, idempotencyKey: string): IdempotencyRecordedOutcome | null {
    const rec = this.records.get(compositeKey(scope, idempotencyKey));
    if (!rec) return null;
    if (this.now() > rec.expiresAt) return null;
    return rec.outcome;
  }

  size(): number {
    return this.records.size;
  }

  private isValidKey(key: string): boolean {
    return typeof key === 'string' && IDEMPOTENCY_KEY_PATTERN.test(key);
  }
}

// --- Replay protection (nonce registry) ---

export const REPLAY_WINDOW_MS = 10 * 60 * 1000; // 2x MAX_CLOCK_SKEW_MS

export interface ReplayGuardOptions {
  windowMs?: number;
  now?: () => number;
}

export class ReplayGuard {
  private readonly nonces = new Map<string, { firstSeenAt: number; firstSeenRequestId?: string }>();
  private readonly windowMs: number;
  private readonly now: () => number;

  constructor(options: ReplayGuardOptions = {}) {
    this.windowMs = options.windowMs ?? REPLAY_WINDOW_MS;
    this.now = options.now ?? Date.now;
  }

  /** Check + consume a nonce atomically. Fails closed with REPLAYED when
   *  the nonce was already seen inside the validity window (any prior use
   *  burns it). Nonces older than the window have expired and are treated
   *  as unseen (pruning is best-effort bounded-memory housekeeping). */
  check(scope: string, nonce: string, requestId?: string): { ok: true } | { ok: false; code: 'REPLAYED'; firstSeenAt: number; firstSeenRequestId?: string } {
    const now = this.now();
    const key = compositeKey(scope, nonce);
    const existing = this.nonces.get(key);
    if (existing && now - existing.firstSeenAt <= this.windowMs) {
      return { ok: false, code: 'REPLAYED', firstSeenAt: existing.firstSeenAt, firstSeenRequestId: existing.firstSeenRequestId };
    }
    if (existing) this.nonces.delete(key); // expired outside the window
    this.nonces.set(key, { firstSeenAt: now, firstSeenRequestId: requestId });
    return { ok: true };
  }

  /** Prune nonces older than the window (bounded memory). Returns the
   *  number of REMAINING entries (pruning is best-effort housekeeping). */
  prune(): number {
    const cutoff = this.now() - this.windowMs;
    for (const [key, rec] of this.nonces) {
      if (rec.firstSeenAt < cutoff) this.nonces.delete(key);
    }
    return this.nonces.size;
  }

  size(): number {
    return this.nonces.size;
  }

  /** TEST-ONLY: inject a first-seen record directly. */
  seed(scope: string, nonce: string, firstSeenAt: number, requestId?: string): void {
    this.nonces.set(compositeKey(scope, nonce), { firstSeenAt, firstSeenRequestId: requestId });
  }

  /** TEST-ONLY: direct map access for assertions. */
  entries(): ReadonlyMap<string, { firstSeenAt: number; firstSeenRequestId?: string }> {
    return this.nonces;
  }
}

function compositeKey(scope: string, part: string): string {
  if (typeof scope !== 'string' || !scope || typeof part !== 'string') {
    throw new Error('IDEMPOTENCY_SCOPE_INVALID');
  }
  return `${scope}::${part}`;
}
