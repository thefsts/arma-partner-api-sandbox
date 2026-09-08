// ARMA -> PATCHES partner client (Stop Point 5, sandbox adapter).
//
// This is the OUTBOUND half of the ARMA adapter: it speaks the PATCHES
// Partner API v1 wire contract EXACTLY as the SP4 reference server defines
// it (see docs/SP5-CONTRACT-SURFACES.md), reusing the shared contract
// primitives from ../lib/security.ts and ../lib/receipts.ts so the
// canonical signing string, body hash, and receipt verification can never
// drift between the reference server and the adapter.
//
// OWNER AMENDMENT (binding) — retry vs reconciliation. Every failure is
// classified into exactly one of:
//   CLEAN_RETRYABLE — provably NOT processed by PATCHES (connection refused
//     before delivery; authenticated 429 rejected pre-processing; kill-switch
//     503 checked before auth; DOWNSTREAM_UNAVAILABLE checked before the
//     persistence transaction; PARTNER_PERSISTENCE_FAILED which rolls back
//     the whole transaction). Safe to re-send with a FRESH nonce+signature
//     and the SAME idempotency key (server-side idempotency collapses any
//     residual duplicate anyway).
//   AMBIGUOUS — processing state unknown (timeout after the request may have
//     reached PATCHES; connection drop mid-response; response/receipt lost
//     after server-side processing; receipt integrity mismatch on a 2xx that
//     may reflect a real activation; unprovable 5xx). NEVER blindly
//     re-sent: surfaced to the activation service, which transitions to
//     RECONCILIATION_REQUIRED and queries PATCHES status via the stable
//     idempotency/activation identity.
//   TERMINAL — the operation cannot succeed as attempted (invalid/revoked/
//     expired credentials; tenant, entitlement, capability, or binding
//     denial; input/version errors; state conflicts; replay/stale requests;
//     local outbound kill switch). No retry; surfaced for operator review.
//
// Fail-closed default: anything that cannot be PROVEN non-processed and
// cannot be PROVEN terminal is classified AMBIGUOUS (reconcile, never
// re-send blind).
//
// SECURITY INVARIANTS:
// - The client credential secret is used for signing only; it never appears
//   in AttemptRecord, OperationOutcome, or any serialized payload (see
//   redactForAudit, which additionally scans serialized output for live
//   secret material as defense in depth).
// - Every attempt uses a FRESH timestamp and FRESH single-use nonce; a
//   retried attempt is a NEW HTTP request with a NEW request id, signed
//   from scratch against the credential source's CURRENT key (so key
//   rotation is picked up between attempts).
//
// PORTING NOTE (private PATCHES repo): the shared primitives
// (canonicalRequestString, computeRequestSignature, bodyHashFor,
// verifyReceipt, RECEIPT_SCHEMA_VERSION) are the platform's published
// partner-contract primitives — import them from the private repo's
// contract package rather than this sandbox's ../lib. baseUrl, the
// CredentialSource (KMS-backed), and the receipt verification key are
// injected; nothing here is sandbox-specific beyond the defaults.

import { randomBytes, randomUUID } from 'node:crypto';
import { canonicalRequestString, computeRequestSignature, bodyHashFor } from '../lib/security.ts';
import { verifyReceipt, type ReceiptBody, type ReceiptVerification } from '../lib/receipts.ts';

export const PATCHES_API_PATH_PREFIX = '/api/partner';
export const ARMA_API_VERSION = 'v1';
export const ARMA_OUTBOUND_KILL_SWITCH_ENV = 'ARMA_PATCHES_OUTBOUND_DISABLED';

export const DEFAULT_TIMEOUT_MS = 5_000;
export const DEFAULT_MAX_ATTEMPTS = 3; // bounded: 1 initial attempt + 2 retries
export const DEFAULT_BACKOFF_BASE_MS = 100;
export const DEFAULT_RETRY_AFTER_CAP_MS = 30_000;

// --- Failure classification (owner amendment) ---

export type FailureClass = 'CLEAN_RETRYABLE' | 'AMBIGUOUS' | 'TERMINAL';

// SP4 auth failure codes (security.ts): every one is a credential/config
// problem on the adapter side or a replay — none are retried blindly.
const AUTH_FAILURE_CODES = new Set([
  'AUTH_MISSING', 'AUTH_MALFORMED', 'PARTNER_UNKNOWN', 'PARTNER_SUSPENDED',
  'CREDENTIAL_UNKNOWN', 'CREDENTIAL_REVOKED', 'CREDENTIAL_EXPIRED',
  'TIMESTAMP_OUT_OF_WINDOW', 'NONCE_INVALID', 'NONCE_REPLAYED',
  'SIGNATURE_INVALID', 'SECRET_UNAVAILABLE',
]);

// Connection failures that occur BEFORE the request is delivered to PATCHES.
const PRE_DELIVERY_CODES = new Set([
  'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
]);

export interface FailureEvidence {
  transportError?: unknown;              // raw fetch / body-read error (never serialized)
  httpStatus?: number | null;
  errorCode?: string | null;             // SP4 structured error code from the response body
  receiptExpected: boolean;
  receiptVerification?: ReceiptVerification | null;
  responseComplete?: boolean;            // false when the response body could not be fully read
  serverApiVersion?: string | null;      // x-api-version on the response
}

export interface FailureClassification {
  failureClass: FailureClass;
  failureReason: string | null;
}

function errorChain(err: unknown, depth = 0): { name: string; code?: string; message: string } {
  const e = (err ?? {}) as { name?: string; code?: string; message?: string; cause?: unknown };
  const name = typeof e.name === 'string' ? e.name : 'Error';
  if (typeof e.code === 'string') return { name, code: e.code, message: String(e.message ?? '') };
  if (e.name === 'AbortError' || e.code === 'ABORT_ERR' || e.code === 'UND_ERR_ABORTED') {
    return { name: 'AbortError', code: 'ABORT_ERR', message: String(e.message ?? '') };
  }
  if (e.cause !== undefined && e.cause !== null && depth < 5) return errorChain(e.cause, depth + 1);
  return { name, message: String(e.message ?? '') };
}

/**
 * Pure classification of a failed (or unverifiable) attempt, per the owner's
 * binding amendment. Exported for direct unit testing.
 */
export function classifyFailure(evidence: FailureEvidence): FailureClassification {
  // 1) Transport-level failures.
  if (evidence.transportError !== undefined) {
    const chain = errorChain(evidence.transportError);
    if (chain.name === 'AbortError' || chain.code === 'ABORT_ERR' || chain.code === 'UND_ERR_ABORTED') {
      // Our own timeout fired: the request may already have reached PATCHES
      // and been processed. NEVER blind re-send.
      return { failureClass: 'AMBIGUOUS', failureReason: 'TIMEOUT' };
    }
    if (chain.code !== undefined && PRE_DELIVERY_CODES.has(chain.code)) {
      // The OS never delivered the request bytes (refused/unroutable/unresolvable).
      return { failureClass: 'CLEAN_RETRYABLE', failureReason: `CONN_${chain.code}` };
    }
    // Reset/drop/truncation at any point after send, or an unrecognized
    // transport failure: processing state unknown.
    return { failureClass: 'AMBIGUOUS', failureReason: chain.code ? `DROP_${chain.code}` : 'CONNECTION_DROP' };
  }

  const complete = evidence.responseComplete !== false;

  // 2) Response incompletely read (connection dropped mid-body): the server
  // may have fully processed and persisted; the receipt is lost.
  if (!complete) {
    return { failureClass: 'AMBIGUOUS', failureReason: 'RESPONSE_LOST' };
  }

  const status = evidence.httpStatus ?? undefined; // normalize null -> undefined
  const errorCode = evidence.errorCode ?? null;

  // 3) Receipt verification failure on a 2xx receipt-bearing response: the
  // response claims success but its integrity cannot be proven — processing
  // may already have occurred. Reconcile; never trust, never blind re-send.
  if (evidence.receiptExpected && status !== undefined && status >= 200 && status < 300) {
    const verification = evidence.receiptVerification ?? null;
    if (verification === null || !verification.verified) {
      return { failureClass: 'AMBIGUOUS', failureReason: verification?.reason ?? 'RECEIPT_UNVERIFIED' };
    }
    if (evidence.serverApiVersion != null && evidence.serverApiVersion !== ARMA_API_VERSION) {
      return { failureClass: 'AMBIGUOUS', failureReason: 'SERVER_VERSION_MISMATCH' };
    }
  }

  if (status === undefined) {
    return { failureClass: 'AMBIGUOUS', failureReason: 'UNKNOWN_OUTCOME' };
  }

  // 4) HTTP status table (SP4 contract semantics).
  if (status === 429) {
    // Authenticated partner rejected BEFORE any route processing (the rate
    // limiter runs after auth, before route logic). Bounded retry honoring
    // Retry-After.
    return { failureClass: 'CLEAN_RETRYABLE', failureReason: 'RATE_LIMITED' };
  }
  if (status === 503 && errorCode === 'PARTNER_API_DISABLED') {
    // PATCHES kill switch is evaluated FIRST, before auth and processing:
    // a response carrying this code proves nothing was processed.
    return { failureClass: 'CLEAN_RETRYABLE', failureReason: 'PATCHES_API_DISABLED' };
  }
  if (status === 503 && errorCode === 'DOWNSTREAM_UNAVAILABLE') {
    // SP4 contract: the downstream check runs BEFORE the persistence
    // transaction and fails closed with zero partial state — a 503 with
    // this code proves the activation was not persisted.
    return { failureClass: 'CLEAN_RETRYABLE', failureReason: 'DOWNSTREAM_UNAVAILABLE' };
  }
  if (status === 500 && errorCode === 'PARTNER_PERSISTENCE_FAILED') {
    // SP4 contract: the acceptance path is ONE transaction that rolls back
    // atomically on failure (and the nonce is not registered) — this code
    // proves nothing was persisted.
    return { failureClass: 'CLEAN_RETRYABLE', failureReason: 'PERSISTENCE_ROLLED_BACK' };
  }
  if (status === 200 && !evidence.receiptExpected) {
    if (evidence.serverApiVersion != null && evidence.serverApiVersion !== ARMA_API_VERSION) {
      return { failureClass: 'TERMINAL', failureReason: 'SERVER_VERSION_MISMATCH' };
    }
    // Non-receipt 2xx (GET routes): fine — callers treat this as ok.
    return { failureClass: 'TERMINAL', failureReason: 'UNEXPECTED_2XX' };
  }
  if (AUTH_FAILURE_CODES.has(errorCode ?? '')) {
    return { failureClass: 'TERMINAL', failureReason: `AUTH_${errorCode}` };
  }
  if (status === 400 || status === 403 || status === 404 || status === 409 || status === 413) {
    // Input errors, tenant/entitlement/capability/binding denials, state
    // conflicts (idempotency conflict, revoked activation), unknown
    // activation/route: none can succeed by re-sending the same intent.
    return { failureClass: 'TERMINAL', failureReason: errorCode ?? `HTTP_${status}` };
  }
  // Anything else (unrecognized 5xx, empty error body, non-JSON body):
  // cannot prove non-processing, cannot prove terminal -> reconcile.
  return { failureClass: 'AMBIGUOUS', failureReason: errorCode ? `UNPROVABLE_${errorCode}` : 'UNPROVABLE_5XX' };
}

// --- Credentials ---

export interface PartnerCredential {
  clientId: string;
  keyId: string;
  secret: string; // signing material only; NEVER serialized (see redactForAudit)
}

/**
 * Credential source: called FRESH on every attempt, so rotating the
 * underlying key between attempts is picked up without re-signing stale
 * material. The production implementation resolves the current key from
 * the platform KMS/secret store; the sandbox uses static or test-injected
 * sources.
 */
export interface CredentialSource {
  current(): PartnerCredential;
}

export function staticCredentialSource(credential: PartnerCredential): CredentialSource {
  return { current: () => ({ ...credential }) };
}

// --- Operation plumbing ---

export type OperationName =
  | 'activation.create' | 'activation.status' | 'activation.deactivate'
  | 'activation.revoke' | 'capabilities.list' | 'entitlements.list';

export interface AttemptRecord {
  attempt: number;            // 1-based
  requestId: string;          // x-request-id generated for THIS HTTP attempt
  keyId: string;              // key used to sign (never the secret)
  timestamp: number;          // epoch ms sent in X-PATCHES-Timestamp
  nonce: string;              // fresh single-use nonce for THIS attempt
  method: string;
  path: string;               // signed path (query excluded)
  bodyHash: string;           // sha256 of the raw body bytes ("" when empty)
  phase: 'BLOCKED' | 'TRANSPORT_ERROR' | 'HTTP_RESPONSE' | 'VERIFIED';
  httpStatus?: number;
  errorCode?: string | null;
  failureClass?: FailureClass;
  failureReason?: string;
  receiptId?: string | null;
  duplicate?: boolean;
  sleepBeforeNextMs?: number; // backoff/retry-after the client honored after this attempt
}

export interface OperationOutcome {
  ok: boolean;
  operation: OperationName;
  failureClass: FailureClass | null;  // null iff ok
  failureReason: string | null;
  retriesExhausted: boolean;          // true when CLEAN_RETRYABLE but attempts ran out
  attempts: AttemptRecord[];
  httpStatus: number | null;
  errorCode: string | null;
  body: unknown;                      // parsed JSON of the last response (no secrets by contract)
  rawBody: Buffer | null;             // raw response bytes (receipt evidence)
  receipt: ReceiptBody | null;        // VERIFIED receipt (iff receipt route verified)
  receiptVerified: boolean;
  retryAfterMs: number | null;
  lastRequestId: string | null;
  activationIdentityHint: string | null; // ACT-<first attempt requestId> for activation.create
  duplicate: boolean;                    // server collapsed a duplicate delivery
}

export interface PatchesPartnerClientOptions {
  baseUrl: string;                       // e.g. http://127.0.0.3:8787 (no trailing slash)
  credentials: CredentialSource;
  receiptVerificationKey: string;        // platform-published receipt verification key
  now?: () => number;                    // injectable clock (production: Date.now)
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxAttempts?: number;
  backoffBaseMs?: number;
  retryAfterCapMs?: number;
  sleep?: (ms: number) => Promise<void>; // injectable for deterministic tests
  outboundDisabled?: () => boolean;      // ARMA-local outbound kill switch (default: env)
  onAttempt?: (attempt: AttemptRecord) => void; // audit hook (records are secret-free)
}

function defaultOutboundDisabled(): boolean {
  return String(process.env[ARMA_OUTBOUND_KILL_SWITCH_ENV] ?? 'false').toLowerCase() === 'true';
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class PatchesPartnerClient {
  private readonly baseUrl: string;
  private readonly credentials: CredentialSource;
  private readonly receiptVerificationKey: string;
  private readonly now: () => number;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxAttempts: number;
  private readonly backoffBaseMs: number;
  private readonly retryAfterCapMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly outboundDisabled: () => boolean;
  private readonly onAttempt?: (attempt: AttemptRecord) => void;

  constructor(options: PatchesPartnerClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.credentials = options.credentials;
    this.receiptVerificationKey = options.receiptVerificationKey;
    this.now = options.now ?? Date.now;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxAttempts = Math.max(1, options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
    this.backoffBaseMs = options.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS;
    this.retryAfterCapMs = options.retryAfterCapMs ?? DEFAULT_RETRY_AFTER_CAP_MS;
    this.sleep = options.sleep ?? defaultSleep;
    this.outboundDisabled = options.outboundDisabled ?? defaultOutboundDisabled;
    this.onAttempt = options.onAttempt;
  }

  // --- Public operation surface ---

  /** POST /activations — idempotent activation create. */
  async activate(input: { orgId: string; capability: string; bindingId: string; idempotencyKey: string }): Promise<OperationOutcome> {
    // Fixed key order => stable serialization => stable payloadHash across
    // attempts (required for server-side idempotency duplicate collapse).
    const body = { orgId: input.orgId, capability: input.capability, bindingId: input.bindingId, idempotencyKey: input.idempotencyKey };
    return this.send('activation.create', 'POST', '/activations', body, { receiptExpected: true });
  }

  /** GET /activations/:activationId — status (reconciliation + sync). */
  async getActivationStatus(activationId: string): Promise<OperationOutcome> {
    return this.send('activation.status', 'GET', `/activations/${encodeURIComponent(activationId)}`, undefined, { receiptExpected: false });
  }

  /** POST /activations/:id/deactivate — idempotent-by-status on the server. */
  async deactivateActivation(activationId: string): Promise<OperationOutcome> {
    // SP4 contract: all POST routes parse a JSON body (even when the route
    // logic ignores it) — send `{}` so the request is a valid JSON POST.
    return this.send('activation.deactivate', 'POST', `/activations/${encodeURIComponent(activationId)}/deactivate`, {}, { receiptExpected: true });
  }

  /** POST /activations/:id/revoke — terminal revocation. */
  async revokeActivation(activationId: string): Promise<OperationOutcome> {
    return this.send('activation.revoke', 'POST', `/activations/${encodeURIComponent(activationId)}/revoke`, {}, { receiptExpected: true });
  }

  /** GET /capabilities — capability discovery (adapter preflight). */
  async listCapabilities(): Promise<OperationOutcome> {
    return this.send('capabilities.list', 'GET', '/capabilities', undefined, { receiptExpected: false });
  }

  /** GET /entitlements?orgId=... — tenant-scoped entitlement lookup (preflight). */
  async listEntitlements(orgId: string): Promise<OperationOutcome> {
    return this.send('entitlements.list', 'GET', `/entitlements?orgId=${encodeURIComponent(orgId)}`, undefined, { receiptExpected: false });
  }

  // --- Core send loop (bounded retry for CLEAN_RETRYABLE only) ---

  private async send(
    operation: OperationName,
    method: 'GET' | 'POST',
    pathWithQuery: string,
    body: Record<string, unknown> | undefined,
    opts: { receiptExpected: boolean },
  ): Promise<OperationOutcome> {
    const rawBody = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), 'utf8');
    // The SP4 server verifies the signature over the FULL request pathname
    // (`/api/partner/v1/...` — server.ts passes `url.pathname` to auth), and
    // the query string is never signed. The URL is built from the same
    // prefix, so the signed path and the served path are identical bytes.
    const signedPath = `${PATCHES_API_PATH_PREFIX}/${ARMA_API_VERSION}${pathWithQuery.split('?')[0]}`;
    const url = `${this.baseUrl}${PATCHES_API_PATH_PREFIX}/${ARMA_API_VERSION}${pathWithQuery}`;

    const attempts: AttemptRecord[] = [];
    let lastOutcome: {
      ok: boolean; failureClass: FailureClass | null; failureReason: string | null;
      httpStatus: number | null; errorCode: string | null; parsed: unknown;
      raw: Buffer | null; receipt: ReceiptBody | null; receiptVerified: boolean;
      retryAfterMs: number | null; duplicate: boolean;
    } | null = null;

    for (let attemptNo = 1; attemptNo <= this.maxAttempts; attemptNo++) {
      // 0) ARMA-local outbound kill switch: refuse to send anything.
      if (this.outboundDisabled()) {
        const blocked: AttemptRecord = {
          attempt: attemptNo, requestId: `req-${randomUUID()}`, keyId: '(blocked)',
          timestamp: this.now(), nonce: '(blocked)', method, path: signedPath,
          bodyHash: bodyHashFor(rawBody), phase: 'BLOCKED',
          failureClass: 'TERMINAL', failureReason: 'ARMA_OUTBOUND_DISABLED',
        };
        attempts.push(blocked);
        this.onAttempt?.(blocked);
        return this.buildOutcome(operation, attempts, {
          ok: false, failureClass: 'TERMINAL', failureReason: 'ARMA_OUTBOUND_DISABLED',
          httpStatus: null, errorCode: 'ARMA_OUTBOUND_DISABLED', parsed: null,
          raw: null, receipt: null, receiptVerified: false, retryAfterMs: null, duplicate: false,
        }, false);
      }

      // 1) Fresh credentials per attempt (rotation is picked up here).
      const credential = this.credentials.current();
      if (
        typeof credential.clientId !== 'string' || credential.clientId === '' ||
        typeof credential.keyId !== 'string' || credential.keyId === '' ||
        typeof credential.secret !== 'string' || credential.secret === ''
      ) {
        const bad: AttemptRecord = {
          attempt: attemptNo, requestId: `req-${randomUUID()}`, keyId: String((credential as { keyId?: unknown })?.keyId ?? '(invalid)'),
          timestamp: this.now(), nonce: '(not-sent)', method, path: signedPath,
          bodyHash: bodyHashFor(rawBody), phase: 'BLOCKED',
          failureClass: 'TERMINAL', failureReason: 'CREDENTIAL_SOURCE_INVALID',
        };
        attempts.push(bad);
        this.onAttempt?.(bad);
        return this.buildOutcome(operation, attempts, {
          ok: false, failureClass: 'TERMINAL', failureReason: 'CREDENTIAL_SOURCE_INVALID',
          httpStatus: null, errorCode: 'CREDENTIAL_SOURCE_INVALID', parsed: null,
          raw: null, receipt: null, receiptVerified: false, retryAfterMs: null, duplicate: false,
        }, false);
      }

      // 2) Fresh request id, timestamp, nonce, signature per attempt.
      const requestId = `req-${randomUUID()}`;
      const timestamp = this.now();
      const nonce = randomBytes(24).toString('base64url'); // 32 chars, [A-Za-z0-9_-]
      const bodyHash = bodyHashFor(rawBody);
      const canonical = canonicalRequestString(method, signedPath, String(timestamp), nonce, bodyHash);
      const signature = computeRequestSignature(credential.secret, canonical);

      const record: AttemptRecord = {
        attempt: attemptNo, requestId, keyId: credential.keyId, timestamp,
        nonce, method, path: signedPath, bodyHash, phase: 'HTTP_RESPONSE',
      };

      // 3) Send with a hard timeout.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      let responseComplete = true;
      let httpStatus: number | null = null;
      let serverApiVersion: string | null = null;
      let headers: Record<string, string> = {};
      let raw: Buffer | null = null;
      let transportError: unknown;
      try {
        const res = await this.fetchImpl(url, {
          method,
          signal: controller.signal,
          headers: {
            authorization: `PATCHES-Partner ${credential.clientId}:${credential.keyId}`,
            'x-patches-timestamp': String(timestamp),
            'x-patches-nonce': nonce,
            'x-patches-signature': signature,
            'x-request-id': requestId,
            'x-api-version': ARMA_API_VERSION,
            accept: 'application/json',
            ...(rawBody.length > 0 ? { 'content-type': 'application/json' } : {}),
          },
          body: rawBody.length > 0 ? rawBody : undefined,
        });
        httpStatus = res.status;
        const versionHeader = res.headers.get('x-api-version');
        serverApiVersion = versionHeader === null ? null : versionHeader;
        headers = {};
        res.headers.forEach((value, name) => { headers[name.toLowerCase()] = value; });
        try {
          raw = Buffer.from(await res.arrayBuffer());
        } catch (readErr) {
          // Connection dropped while reading the response body: the server
          // may have fully processed the operation; the receipt is lost.
          transportError = readErr;
          responseComplete = false;
        }
      } catch (err) {
        transportError = err;
        responseComplete = false;
      } finally {
        clearTimeout(timer);
      }

      // 4) Parse + receipt-verify (over the exact RAW response bytes).
      let parsed: unknown = null;
      if (raw !== null && raw.length > 0) {
        try { parsed = JSON.parse(raw.toString('utf8')); } catch { parsed = null; }
      }
      const errorCode = typeof (parsed as { error?: unknown } | null)?.error === 'string'
        ? (parsed as { error: string }).error
        : null;

      let receiptVerification: ReceiptVerification | null = null;
      if (opts.receiptExpected && httpStatus !== null && httpStatus >= 200 && httpStatus < 300 && raw !== null) {
        receiptVerification = verifyReceipt({
          rawBody: raw,
          headers,
          secret: this.receiptVerificationKey,
          expected: {
            requestId,
            clientId: credential.clientId,
            operation,
            outcome: 'SUCCESS',
          },
        });
      }

      // 5) Classify per the owner's amendment.
      let classification: FailureClassification;
      let ok = false;
      let receipt: ReceiptBody | null = null;
      if (transportError !== undefined || responseComplete === false) {
        classification = classifyFailure({ transportError: transportError ?? new Error('response-incomplete'), receiptExpected: opts.receiptExpected });
        record.phase = 'TRANSPORT_ERROR';
      } else if (
        opts.receiptExpected && httpStatus !== null && httpStatus >= 200 && httpStatus < 300
      ) {
        if (receiptVerification?.verified === true) {
          classification = { failureClass: 'TERMINAL', failureReason: null }; // unused when ok
          ok = true;
          receipt = receiptVerification.receipt ?? null;
          record.phase = 'VERIFIED';
          record.receiptId = receipt?.receiptId ?? null;
          record.duplicate = (parsed as { duplicate?: unknown } | null)?.duplicate === true;
        } else {
          classification = classifyFailure({
            httpStatus, errorCode, receiptExpected: opts.receiptExpected,
            receiptVerification, responseComplete, serverApiVersion,
          });
        }
      } else if (httpStatus !== null && httpStatus >= 200 && httpStatus < 300 && parsed !== null) {
        // Non-receipt 2xx (GET routes) with a parseable body.
        const versionClass = serverApiVersion !== null && serverApiVersion !== ARMA_API_VERSION
          ? { failureClass: 'TERMINAL' as FailureClass, failureReason: 'SERVER_VERSION_MISMATCH' }
          : null;
        if (versionClass) {
          classification = versionClass;
        } else {
          classification = { failureClass: 'TERMINAL', failureReason: null };
          ok = true;
          record.phase = 'VERIFIED';
        }
      } else {
        classification = classifyFailure({
          httpStatus, errorCode, receiptExpected: opts.receiptExpected,
          receiptVerification, responseComplete, serverApiVersion,
        });
      }

      record.httpStatus = httpStatus ?? undefined;
      record.errorCode = errorCode;
      record.failureClass = ok ? undefined : classification.failureClass;
      record.failureReason = ok ? undefined : classification.failureReason ?? undefined;
      attempts.push(record);
      this.onAttempt?.(record);

      const retryAfterMs = httpStatus === 429
        ? this.resolveRetryAfterMs(parsed, headers)
        : null;

      lastOutcome = {
        ok, failureClass: ok ? null : classification.failureClass,
        failureReason: ok ? null : classification.failureReason,
        httpStatus, errorCode, parsed, raw, receipt,
        receiptVerified: receipt !== null, retryAfterMs,
        duplicate: record.duplicate ?? false,
      };

      if (ok) {
        return this.buildOutcome(operation, attempts, lastOutcome, false);
      }

      // 6) Bounded retry ONLY for CLEAN_RETRYABLE (provably not processed).
      if (classification.failureClass === 'CLEAN_RETRYABLE' && attemptNo < this.maxAttempts) {
        const sleepMs = retryAfterMs !== null
          ? Math.min(retryAfterMs, this.retryAfterCapMs)
          : this.backoffBaseMs * Math.pow(2, attemptNo - 1);
        record.sleepBeforeNextMs = sleepMs;
        await this.sleep(sleepMs);
        continue; // fresh nonce + signature + (possibly rotated) key
      }

      const exhausted = classification.failureClass === 'CLEAN_RETRYABLE' && attemptNo >= this.maxAttempts;
      return this.buildOutcome(operation, attempts, lastOutcome, exhausted);
    }

    // Unreachable: the loop always returns.
    throw new Error('PatchesPartnerClient.send: unreachable');
  }

  private resolveRetryAfterMs(parsed: unknown, headers: Record<string, string>): number | null {
    const fromBody = (parsed as { retryAfterMs?: unknown } | null)?.retryAfterMs;
    if (typeof fromBody === 'number' && Number.isFinite(fromBody) && fromBody >= 0) return fromBody;
    const headerSeconds = Number(headers['retry-after']);
    if (Number.isFinite(headerSeconds) && headerSeconds >= 0) return headerSeconds * 1000;
    return null;
  }

  private buildOutcome(
    operation: OperationName,
    attempts: AttemptRecord[],
    last: {
      ok: boolean; failureClass: FailureClass | null; failureReason: string | null;
      httpStatus: number | null; errorCode: string | null; parsed: unknown;
      raw: Buffer | null; receipt: ReceiptBody | null; receiptVerified: boolean;
      retryAfterMs: number | null; duplicate: boolean;
    },
    retriesExhausted: boolean,
  ): OperationOutcome {
    const firstCreateRequestId = operation === 'activation.create' ? attempts[0]?.requestId ?? null : null;
    return {
      ok: last.ok,
      operation,
      failureClass: last.failureClass,
      failureReason: last.failureReason,
      retriesExhausted,
      attempts,
      httpStatus: last.httpStatus,
      errorCode: last.errorCode,
      body: last.parsed,
      rawBody: last.raw,
      receipt: last.receipt,
      receiptVerified: last.receiptVerified,
      retryAfterMs: last.retryAfterMs,
      lastRequestId: attempts.length > 0 ? attempts[attempts.length - 1].requestId : null,
      activationIdentityHint: firstCreateRequestId !== null ? `ACT-${firstCreateRequestId}` : null,
      duplicate: last.duplicate,
    };
  }
}

// --- Audit-safe serialization ---

/**
 * Audit-safe projection of an outcome: drops raw bytes and parsed bodies
 * (they are evidence, not audit material) and keeps only classification +
 * attempt metadata. As defense in depth, the serialized form is scanned for
 * the live credential secrets; if any secret appears the projection fails
 * closed by throwing (a bug this loud must never be silently papered over).
 */
export function redactForAudit(outcome: OperationOutcome, secrets: string[]): Record<string, unknown> {
  const projected: Record<string, unknown> = {
    operation: outcome.operation,
    ok: outcome.ok,
    failureClass: outcome.failureClass,
    failureReason: outcome.failureReason,
    retriesExhausted: outcome.retriesExhausted,
    httpStatus: outcome.httpStatus,
    errorCode: outcome.errorCode,
    receiptVerified: outcome.receiptVerified,
    receiptId: outcome.receipt?.receiptId ?? null,
    activationId: outcome.receipt?.activationId ?? null,
    duplicate: outcome.duplicate,
    attemptCount: outcome.attempts.length,
    attempts: outcome.attempts.map((a) => ({
      attempt: a.attempt, requestId: a.requestId, keyId: a.keyId,
      nonce: a.nonce, timestamp: a.timestamp, method: a.method, path: a.path,
      bodyHash: a.bodyHash, phase: a.phase, httpStatus: a.httpStatus ?? null,
      errorCode: a.errorCode ?? null, failureClass: a.failureClass ?? null,
      failureReason: a.failureReason ?? null,
    })),
  };
  const serialized = JSON.stringify(projected);
  for (const secret of secrets) {
    if (secret !== '' && serialized.includes(secret)) {
      throw new Error('redactForAudit: credential secret material detected in audit projection');
    }
  }
  return projected;
}
