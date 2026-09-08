// Stop Point 7 — shared SDK: composed partner client façade.
//
// Composes the shared primitives into one call flow:
//   buildRequest    — canonical form + HMAC signature + correlation header
//   processResponse — raw-byte receipt verification + structured error parse
//   planRetry       — clean-retryable-only classification + backoff + circuit
//
// The client never sees or carries partner payload content beyond the
// caller-provided raw bytes; failures are typed codes, never payloads.

import { randomUUID } from 'node:crypto';
import {
  canonicalRequestString,
  bodyHashFor,
  signCanonicalRequest,
  verifyCanonicalRequestSignature,
} from './canonical.ts';
import type { CanonicalRequest } from './canonical.ts';
import { verifyReceipt } from './receipts.ts';
import type { ReceiptBody, ReceiptVerification } from './receipts.ts';
import { StructuredError } from './errors.ts';
import { RetryPolicy } from './retries.ts';
import { REQUEST_ID_HEADER, generateRequestId, resolveRequestId } from './correlation.ts';
import { SUPPORTED_SDK_API_VERSIONS } from './versions.ts';

export const SDK_HEADER_PREFIX = 'x-shared';
export const SDK_TIMESTAMP_HEADER = 'x-shared-timestamp';
export const SDK_NONCE_HEADER = 'x-shared-nonce';
export const SDK_SIGNATURE_HEADER = 'x-shared-signature';
export const SDK_BODY_HASH_HEADER = 'x-shared-body-sha256';
export const SDK_API_VERSION_HEADER = 'x-shared-api-version';
export const SDK_PARTNER_HEADER = 'x-shared-partner-id';

export interface PartnerSdkClientOptions {
  /** Calling partner identifier (verified against the registry by the server). */
  readonly partnerId: string;
  /** Partner signing secret — used to sign outgoing requests. */
  readonly secret: string;
  /** Secret the receiving platform uses to sign response receipts.
   *  Defaults to `secret` (single-secret sandboxes); production surfaces
   *  inject the platform receipt secret from the secret store instead. */
  readonly receiptSecret?: string;
  /** Injected clock for deterministic signing timestamps (default Date.now). */
  readonly now?: () => number;
  /** Injected nonce source (default crypto random 32 chars). */
  readonly nonceSource?: () => string;
}

export interface BuildRequestInput {
  readonly method: string;
  readonly path: string;
  /** Raw request body bytes — signed EXACTLY as provided, never re-serialized. */
  readonly body?: string | Buffer;
  /** Caller-provided request id; generated when absent. */
  readonly requestId?: string;
  /** Caller-provided nonce; generated when absent. */
  readonly nonce?: string;
}

export interface BuiltRequest {
  readonly method: string;
  readonly path: string;
  readonly rawBody: Buffer;
  readonly requestId: string;
  readonly nonce: string;
  readonly timestamp: number;
  readonly bodyHash: string;
  readonly canonical: string;
  /** Headers to attach to the outgoing request. */
  readonly headers: Readonly<Record<string, string>>;
}

export type ProcessedResponse =
  | { ok: true; status: number; requestId: string | null; receipt: ReceiptBody; rawBody: Buffer }
  | { ok: false; status: number; requestId: string | null; error: StructuredError; rawBody: Buffer };

export interface ProcessResponseInput {
  readonly status: number;
  readonly rawBody: Buffer | string;
  readonly headers: Record<string, string | string[] | undefined>;
  /** Binding: the receipt must prove exactly this operation. */
  readonly expected?: {
    requestId?: string;
    partnerId?: string;
    operation?: string;
    outcome?: string;
    entityRef?: string;
  };
}

export type RetryPlan =
  | {
      kind: 'CLEAN_RETRY';
      classification: { retryable: boolean; ambiguous: boolean; cleanRetryable: boolean };
      backoff: { allowed: true; delayMs: number; nextAttempt: number; retryAt: number };
    }
  | { kind: 'AMBIGUOUS_RECONCILE'; classification: { retryable: boolean; ambiguous: boolean; cleanRetryable: boolean } }
  | { kind: 'TERMINAL'; classification: { retryable: boolean; ambiguous: boolean; cleanRetryable: boolean } }
  | { kind: 'EXHAUSTED'; classification: { retryable: boolean; ambiguous: boolean; cleanRetryable: boolean }; attempts: number };

function defaultNonce(): string {
  return randomUUID().replace(/-/g, '');
}

export class PartnerSdkClient {
  readonly partnerId: string;
  private readonly secret: string;
  private readonly receiptSecret: string;
  private readonly now: () => number;
  private readonly nonceSource: () => string;
  private readonly retryPolicy = new RetryPolicy();

  constructor(options: PartnerSdkClientOptions) {
    if (!options || typeof options !== 'object') throw new Error('SDK_CLIENT_OPTIONS_REQUIRED');
    if (typeof options.partnerId !== 'string' || !options.partnerId.trim()) throw new Error('SDK_PARTNER_ID_REQUIRED');
    if (typeof options.secret !== 'string' || options.secret.length === 0) throw new Error('SDK_SECRET_REQUIRED');
    if (options.receiptSecret !== undefined && (typeof options.receiptSecret !== 'string' || options.receiptSecret.length === 0)) {
      throw new Error('SDK_RECEIPT_SECRET_INVALID');
    }
    this.partnerId = options.partnerId;
    this.secret = options.secret;
    this.receiptSecret = options.receiptSecret ?? options.secret;
    this.now = options.now ?? Date.now;
    this.nonceSource = options.nonceSource ?? defaultNonce;
  }

  /** Build a signed outgoing request: canonical form, HMAC, correlation header. */
  buildRequest(input: BuildRequestInput): BuiltRequest {
    if (!input || typeof input !== 'object') throw new Error('SDK_BUILD_INPUT_INVALID');
    if (typeof input.method !== 'string' || !input.method.trim()) throw new Error('SDK_METHOD_INVALID');
    if (typeof input.path !== 'string' || !input.path.startsWith('/')) throw new Error('SDK_PATH_INVALID');

    const rawBody = input.body === undefined || input.body === null
      ? Buffer.alloc(0)
      : (typeof input.body === 'string' ? Buffer.from(input.body, 'utf8') : Buffer.from(input.body));
    const requestId = input.requestId !== undefined && input.requestId !== null
      ? resolveRequestId({ headerValue: input.requestId, at: this.now() }).requestId
      : generateRequestId();
    const nonce = input.nonce ?? this.nonceSource();
    const timestamp = this.now();
    const bodyHash = bodyHashFor(rawBody);

    const canonicalReq: CanonicalRequest = {
      method: input.method.toUpperCase(),
      path: input.path,
      timestamp: String(timestamp),
      nonce,
      bodyHash,
    };
    const canonical = canonicalRequestString(canonicalReq);
    const signed = signCanonicalRequest(this.secret, canonicalReq);

    const headers: Record<string, string> = {
      [SDK_TIMESTAMP_HEADER]: String(timestamp),
      [SDK_NONCE_HEADER]: nonce,
      [SDK_SIGNATURE_HEADER]: signed.signature,
      [SDK_BODY_HASH_HEADER]: bodyHash,
      [SDK_PARTNER_HEADER]: this.partnerId,
      [SDK_API_VERSION_HEADER]: SUPPORTED_SDK_API_VERSIONS[SUPPORTED_SDK_API_VERSIONS.length - 1],
      [REQUEST_ID_HEADER]: requestId,
    };
    return {
      method: canonicalReq.method,
      path: input.path,
      rawBody,
      requestId,
      nonce,
      timestamp,
      bodyHash,
      canonical,
      headers: Object.freeze(headers),
    };
  }

  /**
   * Process an incoming response: verify the receipt over RAW bytes with the
   * expected binding; any 4xx/5xx parses as a structured error. A 2xx with an
   * unverifiable receipt FAILS CLOSED (ok:false) — a success is only trusted
   * when its receipt proves it.
   */
  processResponse(input: ProcessResponseInput): ProcessedResponse {
    if (!input || typeof input !== 'object') throw new Error('SDK_PROCESS_INPUT_INVALID');
    const rawBody = typeof input.rawBody === 'string' ? Buffer.from(input.rawBody, 'utf8') : Buffer.from(input.rawBody);
    const requestId = typeof input.headers[REQUEST_ID_HEADER] === 'string'
      ? (input.headers[REQUEST_ID_HEADER] as string)
      : null;

    if (input.status >= 200 && input.status < 300) {
      const verification: ReceiptVerification = verifyReceipt({
        rawBody,
        headers: input.headers,
        secret: this.receiptSecret,
        expected: { ...input.expected, partnerId: input.expected?.partnerId ?? this.partnerId },
      });
      if (!verification.verified || !verification.receipt) {
        return {
          ok: false,
          status: input.status,
          requestId,
          error: new StructuredError({
            code: 'RECEIPT_VERIFICATION_FAILED',
            status: 502,
            context: { errorCode: verification.reason, requestId: requestId ?? undefined },
            requestId: requestId ?? undefined,
          }),
          rawBody,
        };
      }
      return { ok: true, status: input.status, requestId, receipt: verification.receipt, rawBody };
    }

    // Non-2xx: parse the structured error body; fall back to a typed code.
    let parsed: { error?: unknown; requestId?: unknown } = {};
    try {
      parsed = rawBody.length ? JSON.parse(rawBody.toString('utf8')) as typeof parsed : {};
    } catch {
      parsed = {};
    }
    const code = typeof parsed.error === 'string' && parsed.error.trim() ? parsed.error : 'PARTNER_REQUEST_FAILED';
    const error = new StructuredError({
      code,
      status: input.status,
      requestId: typeof parsed.requestId === 'string' ? parsed.requestId : (requestId ?? undefined),
    });
    return { ok: false, status: input.status, requestId, error, rawBody };
  }

  /**
   * Plan the response to a failure: CLEAN_RETRYABLE only auto-retries;
   * AMBIGUOUS outcomes route to reconciliation (never blind re-send);
   * TERMINAL fails immediately. Backoff only while attempts remain.
   */
  planRetry(failureCode: string, attempts: number): RetryPlan {
    const classification = this.retryPolicy.classify(failureCode);
    if (!classification.retryable) return { kind: 'TERMINAL', classification };
    if (classification.ambiguous) return { kind: 'AMBIGUOUS_RECONCILE', classification };
    const backoff = this.retryPolicy.computeBackoff(attempts);
    if (!backoff.allowed) return { kind: 'EXHAUSTED', classification, attempts: backoff.attempts };
    return { kind: 'CLEAN_RETRY', classification, backoff };
  }

  /** Verify a partner signature over a request the server received. */
  verifySignature(input: {
    method: string;
    path: string;
    timestamp: string;
    nonce: string;
    bodyHash: string;
    providedSignature: string;
    now?: number;
  }): ReturnType<typeof verifyCanonicalRequestSignature> {
    return verifyCanonicalRequestSignature({
      method: input.method,
      path: input.path,
      timestamp: input.timestamp,
      nonce: input.nonce,
      bodyHash: input.bodyHash,
      providedSignature: input.providedSignature,
      secret: this.secret,
      now: input.now ?? this.now(),
    });
  }

  /** Expose the shared retry policy classification for callers. */
  classifyFailure(code: string): { retryable: boolean; ambiguous: boolean; cleanRetryable: boolean } {
    return this.retryPolicy.classify(code);
  }
}

