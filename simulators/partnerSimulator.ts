// Stop Point 8 — the in-process synthetic PARTNER simulator (client engine).
//
// A simulator is CONFIGURATION, not code: this engine reads a
// ScenarioConfig's request plan + client fault plan and drives the SHARED
// Stop Point 7 SDK (PartnerSdkClient) exactly as a real partner integration
// would. It never re-implements signing, verification, receipt processing,
// or retry classification — it builds on the SDK.
//
// Faults are record fields the engine applies MECHANICALLY to the SDK-built
// request (data in, presented request out — no partner-specific branching):
//   tamperSignature                    — corrupt the signature header after signing
//   wrongSigningSecret                 — sign with a secret the platform does not know
//   timestampOffsetMs                  — sign at now + offset (skew fault when > ±5 min)
//   nonceOverride                      — present a nonce that violates the nonce pattern
//   tamperPath                         — mutate the path after signing (canonical mismatch)
//   replayPresentation                 — present the SAME signed request twice
//   idempotencyConflictPresentation    — same idempotency key, DIFFERENT payload
//
// The simulator exposes ONLY identifiers, codes, counts, and booleans on
// every surfaced surface — never payload content.

import {
  PartnerSdkClient,
  SDK_SIGNATURE_HEADER,
  SDK_TIMESTAMP_HEADER,
  SDK_NONCE_HEADER,
} from '../shared/sdk/client.ts';
import {
  canonicalRequestString,
  computeRequestSignature,
} from '../shared/sdk/canonical.ts';
import {
  SYNTHETIC_SIMULATOR_SECRETS,
  SIM_CLAIM_HEADERS,
} from './behaviors.ts';
import type {
  PlatformResponse,
  PresentableRequest,
  ScenarioRequestPlan,
  SimulatorIdentity,
  PartnerFaultPlan,
} from './behaviors.ts';
import type { BuiltRequest, ProcessedResponse, RetryPlan } from '../shared/sdk/client.ts';
import type { StructuredError } from '../shared/sdk/errors.ts';

export interface PartnerSimulatorOptions {
  readonly identity: SimulatorIdentity;
  /** Request-signing secret (defaults to the synthetic sandbox secret). */
  readonly secret?: string;
  /** Response-receipt secret (defaults to the synthetic sandbox receipt secret). */
  readonly receiptSecret?: string;
  /** Injected deterministic clock. */
  readonly clock: () => number;
  /** Deterministic nonce source (a FRESH nonce per signed request). */
  readonly nonceSource?: () => string;
}

/** A processed outcome view: codes + booleans only (no payload content). */
export interface ProcessedResponseView {
  readonly ok: boolean;
  readonly status: number;
  readonly requestId: string | null;
  readonly receiptOperation: string | null;
  readonly receiptOutcome: string | null;
  readonly errorCode: string | null;
  readonly receiptFailure: string | null;
}

/** The result of one simulator execution (identifiers + codes + counts only). */
export interface SimulatedRequestOutcome {
  readonly requestId: string;
  readonly nonce: string;
  readonly idempotencyKey: string;
  readonly presented: PresentableRequest;
  readonly processed: ProcessedResponseView;
  /** Second presentation result (replay / idempotency-conflict faults). */
  readonly secondPresentation: ProcessedResponseView | null;
  /** Retry plan the SDK computed for the first failure (kind only). */
  readonly retryPlan: string | null;
  /** Transport invocations observed by this simulator (counts only). */
  readonly transportCalls: number;
}

function processedViewFor(processed: ProcessedResponse): ProcessedResponseView {
  return {
    ok: processed.ok,
    status: processed.status,
    requestId: processed.requestId,
    receiptOperation: processed.ok ? (processed.receipt.operation ?? null) : null,
    receiptOutcome: processed.ok ? (processed.receipt.outcome ?? null) : null,
    errorCode: processed.ok ? null : (processed.error.code ?? null),
    receiptFailure: processed.ok
      ? null
      : receiptFailureCodeFor(processed.error),
  };
}

/**
 * The SDK fails CLOSED on an unverifiable 2xx receipt: the receipt reason
 * rides in the structured error's safe context under `errorCode`. Only a
 * string value is surfaced (numbers/booleans from other contexts are
 * dropped — a typed code or null, never unvalidated content).
 */
function receiptFailureCodeFor(error: StructuredError): string | null {
  const candidate = error.safeContext?.errorCode;
  return typeof candidate === 'string' && candidate.length > 0 ? candidate : null;
}

export class PartnerSimulator {
  readonly identity: SimulatorIdentity;
  /** Transport invocations observed so far (count only, never content). */
  private readonly transportCallCount: number[] = [];
  private readonly sdk: PartnerSdkClient;
  private readonly nonceSource: () => string;
  private readonly clock: () => number;

  constructor(options: PartnerSimulatorOptions) {
    if (!options || typeof options !== 'object') throw new Error('SIMULATOR_OPTIONS_REQUIRED');
    if (!options.identity) throw new Error('SIMULATOR_IDENTITY_REQUIRED');
    if (typeof options.clock !== 'function') throw new Error('SIMULATOR_CLOCK_REQUIRED');
    this.identity = options.identity;
    this.clock = options.clock;
    this.nonceSource = options.nonceSource ?? (() => `simnonce${randomNonceSuffix()}`);
    this.sdk = new PartnerSdkClient({
      partnerId: options.identity.partnerId,
      secret: options.secret ?? SYNTHETIC_SIMULATOR_SECRETS.signing,
      receiptSecret: options.receiptSecret ?? SYNTHETIC_SIMULATOR_SECRETS.receipt,
      now: options.clock,
      nonceSource: this.nonceSource,
    });
  }

  /**
   * Execute one scenario request: build the SIGNED request through the
   * shared SDK, apply the fault plan mechanically, present to the platform,
   * and process the response through the SDK (receipt-verified 2xx or
   * structured failure). A second presentation runs for the replay /
   * idempotency-conflict faults.
   */
  execute(
    plan: ScenarioRequestPlan,
    faults: PartnerFaultPlan,
    platform: {
      receive(request: PresentableRequest): PlatformResponse;
    },
  ): SimulatedRequestOutcome {
    if (!plan || typeof plan !== 'object') throw new Error('SIMULATOR_PLAN_REQUIRED');
    if (!platform || typeof platform.receive !== 'function') throw new Error('SIMULATOR_PLATFORM_REQUIRED');

    // 1) Build the SIGNED request through the shared SDK.
    const built = this.sdk.buildRequest({
      method: plan.method,
      path: plan.path,
      body: plan.payload,
    });

    // 2) Apply the client fault plan MECHANICALLY (record in, request out).
    const presented = this.applyFaults(built, plan, faults);

    // 3) Present to the platform; process the response through the SDK.
    const response = platform.receive(presented);
    this.recordTransportCall();
    const processed = this.sdk.processResponse({
      status: response.status,
      rawBody: response.rawBody,
      headers: { ...response.headers },
      expected: {
        requestId: built.requestId,
        partnerId: this.identity.partnerId,
        operation: plan.operation,
      },
    });

    // 4) Optional second presentation (replay / duplicate / conflict faults).
    let secondPresentation: ProcessedResponseView | null = null;
    if (faults.replayPresentation === true) {
      // Replay: the SAME signed bytes presented twice. The platform's replay
      // guard must burn the nonce on first use and fail closed the second.
      const response2 = platform.receive(presented);
      this.recordTransportCall();
      const processed2 = this.sdk.processResponse({
        status: response2.status,
        rawBody: response2.rawBody,
        headers: { ...response2.headers },
        expected: {
          requestId: built.requestId,
          partnerId: this.identity.partnerId,
          operation: plan.operation,
        },
      });
      secondPresentation = processedViewFor(processed2);
    } else if (faults.duplicatePresentation === true) {
      // Duplicate: a FRESH signed request (new nonce + timestamp, same SDK
      // path) carrying the SAME payload bytes under the SAME idempotency
      // key. The platform must collapse to the recorded SUCCESS outcome —
      // a re-delivery, not an error and not a re-execution.
      const built2 = this.sdk.buildRequest({
        method: plan.method,
        path: plan.path,
        body: plan.payload,
      });
      const duplicateHeaders: Record<string, string> = {
        ...built2.headers,
        [SIM_CLAIM_HEADERS.orgId]: plan.orgId,
        [SIM_CLAIM_HEADERS.entitlement]: plan.entitlement,
        [SIM_CLAIM_HEADERS.capability]: plan.capability,
        [SIM_CLAIM_HEADERS.operation]: plan.operation,
        [SIM_CLAIM_HEADERS.idempotencyKey]: plan.idempotencyKey,
      };
      const duplicatePresented: PresentableRequest = Object.freeze({
        method: built2.method,
        path: built2.path,
        rawBody: built2.rawBody,
        headers: Object.freeze(duplicateHeaders),
        requestId: built2.requestId,
        nonce: built2.nonce,
      });
      const response2 = platform.receive(duplicatePresented);
      this.recordTransportCall();
      // The duplicate re-delivery contract: the platform returns the
      // ORIGINAL recorded receipt (bound to the FIRST request). Verifying
      // against the original binding proves the outcome was re-delivered,
      // not re-executed.
      const processed2 = this.sdk.processResponse({
        status: response2.status,
        rawBody: response2.rawBody,
        headers: { ...response2.headers },
        expected: {
          requestId: built.requestId,
          partnerId: this.identity.partnerId,
          operation: plan.operation,
        },
      });
      secondPresentation = processedViewFor(processed2);
    } else if (faults.idempotencyConflictPresentation === true) {
      // Idempotency conflict: same idempotency key, DIFFERENT request bytes —
      // a fresh SDK build with fresh nonce/timestamp signs different content
      // under the SAME idempotency claim header.
      const conflictPayload = `${plan.payload.slice(0, Math.max(0, plan.payload.length - 1))}X`;
      const built2 = this.sdk.buildRequest({
        method: plan.method,
        path: plan.path,
        body: conflictPayload,
      });
      const conflictHeaders: Record<string, string> = {
        ...built2.headers,
        [SIM_CLAIM_HEADERS.orgId]: plan.orgId,
        [SIM_CLAIM_HEADERS.entitlement]: plan.entitlement,
        [SIM_CLAIM_HEADERS.capability]: plan.capability,
        [SIM_CLAIM_HEADERS.operation]: plan.operation,
        [SIM_CLAIM_HEADERS.idempotencyKey]: plan.idempotencyKey,
      };
      const conflictPresented: PresentableRequest = Object.freeze({
        method: built2.method,
        path: built2.path,
        rawBody: built2.rawBody,
        headers: Object.freeze(conflictHeaders),
        requestId: built2.requestId,
        nonce: built2.nonce,
      });
      const response2 = platform.receive(conflictPresented);
      this.recordTransportCall();
      const processed2 = this.sdk.processResponse({
        status: response2.status,
        rawBody: response2.rawBody,
        headers: { ...response2.headers },
        expected: {
          requestId: built2.requestId,
          partnerId: this.identity.partnerId,
          operation: plan.operation,
        },
      });
      secondPresentation = processedViewFor(processed2);
    }

    // 5) SDK retry classification for the first presentation's failure.
    const retryPlan: string | null = processed.ok
      ? null
      : this.sdk.planRetry(processed.error.code, 1).kind;

    return Object.freeze({
      requestId: built.requestId,
      nonce: presented.nonce,
      idempotencyKey: plan.idempotencyKey,
      presented,
      processed: processedViewFor(processed),
      secondPresentation,
      retryPlan,
      transportCalls: this.transportCallCount.length,
    });
  }

  /** Retry plan (kind only) the SDK computes for an observed failure code. */
  planRetryFor(failureCode: string, attempts: number): string {
    return this.sdk.planRetry(failureCode, attempts).kind;
  }

  /** Full SDK retry plan for an observed failure code (test visibility). */
  planRetryDetailFor(failureCode: string, attempts: number): RetryPlan {
    return this.sdk.planRetry(failureCode, attempts);
  }

  /** Build a signed request through the SDK without presenting it (wiring tests). */
  buildSignedRequest(plan: ScenarioRequestPlan): BuiltRequest {
    return this.sdk.buildRequest({
      method: plan.method,
      path: plan.path,
      body: plan.payload,
    });
  }

  /**
   * Apply the fault plan to an SDK-built request — MECHANICALLY, from the
   * record fields. No branch in this file ever checks a specific partner,
   * entitlement, or capability: the same code path runs every simulator.
   */
  private applyFaults(
    built: BuiltRequest,
    plan: ScenarioRequestPlan,
    faults: PartnerFaultPlan,
  ): PresentableRequest {
    const headers: Record<string, string> = { ...built.headers };
    let path = built.path;
    let nonce = built.nonce;
    let rawBody = built.rawBody;

    // timestampOffsetMs: re-sign the canonical form at a skewed timestamp.
    // The signature stays internally consistent — the DEFECT is the clock
    // skew, caught by the platform's skew window (SIGNATURE_CLOCK_SKEW_EXCEEDED).
    if (faults.timestampOffsetMs !== undefined && faults.timestampOffsetMs !== 0) {
      const skewedTimestamp = String(built.timestamp + faults.timestampOffsetMs);
      const skewedCanonical = canonicalRequestString({
        method: built.method,
        path: built.path,
        timestamp: skewedTimestamp,
        nonce: built.nonce,
        bodyHash: built.bodyHash,
      });
      headers[SDK_TIMESTAMP_HEADER] = skewedTimestamp;
      headers[SDK_SIGNATURE_HEADER] = computeRequestSignature(
        this.signingSecret(),
        skewedCanonical,
      );
    }

    // wrongSigningSecret: a fully well-formed canonical request signed with
    // a secret the platform does NOT know — SIGNATURE_SIGNATURE_MISMATCH.
    if (faults.wrongSigningSecret !== undefined) {
      const wrongCanonical = canonicalRequestString({
        method: built.method,
        path: built.path,
        timestamp: String(built.timestamp),
        nonce: built.nonce,
        bodyHash: built.bodyHash,
      });
      headers[SDK_SIGNATURE_HEADER] = computeRequestSignature(
        faults.wrongSigningSecret,
        wrongCanonical,
      );
    }

    // nonceOverride: present a nonce that violates the nonce pattern.
    if (faults.nonceOverride !== undefined) {
      headers[SDK_NONCE_HEADER] = faults.nonceOverride;
      // The canonical binds the ORIGINAL nonce: an override corrupts the
      // signature binding (SIGNATURE_SIGNATURE_MISMATCH) and, when the
      // override itself violates the pattern, SIGNATURE_NONCE_INVALID.
      nonce = faults.nonceOverride;
    }

    // tamperPath: mutate the path after signing — the canonical no longer
    // matches the presented request (SIGNATURE_SIGNATURE_MISMATCH).
    if (faults.tamperPath === true) {
      path = `${built.path}?tampered=1`;
    }

    // tamperBody: mutate the raw body after signing — the presented bytes no
    // longer hash to the x-shared-body-sha256 header. The platform verifies
    // the body-hash binding FIRST, so this fails closed with
    // SIGNATURE_BODY_HASH_INVALID (before any HMAC compare).
    if (faults.tamperBody === true) {
      rawBody = Buffer.from(`${built.rawBody.toString('utf8')} `, 'utf8');
    }

    // tamperSignature: corrupt the signature header after signing — the
    // platform's timing-safe compare fails closed (SIGNATURE_SIGNATURE_MISMATCH).
    if (faults.tamperSignature === true) {
      headers[SDK_SIGNATURE_HEADER] = flipLastHexDigit(headers[SDK_SIGNATURE_HEADER]);
    }

    // Claim headers complete the sandbox convention (registry inputs).
    headers[SIM_CLAIM_HEADERS.orgId] = plan.orgId;
    headers[SIM_CLAIM_HEADERS.entitlement] = plan.entitlement;
    headers[SIM_CLAIM_HEADERS.capability] = plan.capability;
    headers[SIM_CLAIM_HEADERS.operation] = plan.operation;
    headers[SIM_CLAIM_HEADERS.idempotencyKey] = plan.idempotencyKey;

    return Object.freeze({
      method: built.method,
      path,
      rawBody,
      headers: Object.freeze(headers),
      requestId: built.requestId,
      nonce,
    });
  }

  private signingSecret(): string {
    return SYNTHETIC_SIMULATOR_SECRETS.signing;
  }

  private recordTransportCall(): void {
    this.transportCallCount.push(1);
  }
}

// --- deterministic nonce suffix (fresh per call, no Math.random) -----------

const NONCE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
let nonceCounter = 0;

function randomNonceSuffix(): string {
  nonceCounter += 1;
  // Deterministic counter-based suffix padded into the nonce alphabet.
  let n = nonceCounter;
  let out = '';
  while (out.length < 16) {
    out += NONCE_ALPHABET[n % NONCE_ALPHABET.length];
    n = Math.floor(n / NONCE_ALPHABET.length);
    if (n === 0) n = nonceCounter * 31 + 7; // keep folding for entropy-like spread
  }
  return `${out}${nonceCounter.toString(36)}`;
}

/** Corrupt the last hex digit of a signature (0<->1) — deterministic tamper. */
export function flipLastHexDigit(signature: string): string {
  if (typeof signature !== 'string' || signature.length === 0) return signature;
  const last = signature.slice(-1);
  const flipped = last === '0' ? '1' : '0';
  return `${signature.slice(0, -1)}${flipped}`;
}
