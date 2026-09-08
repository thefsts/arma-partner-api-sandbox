// PATCHES Partner API v1 — reference rate-limiting behavior.
//
// Reference token bucket per clientId, in-memory: capacity tokens refill
// continuously. This models the reference behavior the private repo
// implements with real infrastructure (per-partner quotas, burst headroom,
// 429 with Retry-After). It is deliberately simple and injectable-clock
// friendly for tests; it is NOT a production rate limiter.

export interface RateLimiterOptions {
  capacity: number; // burst size
  refillPerSecond: number; // sustained rate
  now?: () => number;
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterMs?: number;
}

export class TokenBucketRateLimiter {
  private readonly capacity: number;
  private readonly refillPerSecond: number;
  private readonly now: () => number;
  private buckets = new Map<string, { tokens: number; lastRefillAt: number }>();

  constructor(options: RateLimiterOptions) {
    this.capacity = options.capacity;
    this.refillPerSecond = options.refillPerSecond;
    this.now = options.now ?? Date.now;
  }

  check(clientId: string): RateLimitDecision {
    const now = this.now();
    const bucket = this.buckets.get(clientId) ?? { tokens: this.capacity, lastRefillAt: now };
    const elapsedSec = Math.max(0, (now - bucket.lastRefillAt) / 1000);
    const tokens = Math.min(this.capacity, bucket.tokens + elapsedSec * this.refillPerSecond);
    if (tokens < 1) {
      const retryAfterMs = Math.ceil(((1 - tokens) / this.refillPerSecond) * 1000);
      this.buckets.set(clientId, { tokens, lastRefillAt: now });
      return { allowed: false, remaining: Math.floor(tokens), retryAfterMs };
    }
    const used = tokens - 1;
    this.buckets.set(clientId, { tokens: used, lastRefillAt: now });
    return { allowed: true, remaining: Math.floor(used) };
  }

  reset(clientId?: string): void {
    if (clientId === undefined) this.buckets.clear();
    else this.buckets.delete(clientId);
  }
}
