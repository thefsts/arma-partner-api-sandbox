// PATCHES Partner API v1 — reference server. Real Node HTTP handler
// wrapping the partner contracts: scoped partner authentication, tenant
// authorization, entitlements, capabilities, activation lifecycle with
// idempotency, opaque bindings, events, signed receipts, audit, replay
// protection, request IDs, structured errors, payload limits, reference
// rate limiting, and fail-closed downstream behavior.
//
// ROUTES (all under /api/partner/v1):
//   GET  /health                     live readiness (no cache semantics)
//   GET  /capabilities               capability discovery
//   GET  /entitlements?orgId=...     entitlement lookup (tenant-scoped)
//   POST /activations                activation (idempotent)
//   GET  /activations/:activationId  current status
//   POST /activations/:id/deactivate deactivate
//   POST /activations/:id/revoke     revoke
//   GET  /events?orgId=...           events/notifications contract
//   GET  /audit?orgId=...            audit trail (scrubbed)
//
// Every response carries x-request-id (echoes caller's or generates) and
// every error is structured: { error, requestId, ...context }.
//
// PORTING NOTE (private PATCHES repo): this handler maps 1:1 to the
// platform's HTTP layer (Next.js route handlers or equivalent): kill
// switch first, then auth, then rate limit, then route logic; the
// downstream protection service is an injectable boundary (see
// ProtectionService below) — the private repo injects its real services;
// this sandbox uses synthetic fail-points only.

import { createHash, randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { SyntheticPartnerStore, AuditEventRecord } from './store.ts';
import { verifyPartnerAuth, bodyHashFor, MAX_CLOCK_SKEW_MS, type ApiVersion, type AuthFailure } from './security.ts';
import { authorizeOrg, checkEntitlement, checkCapability, checkBinding, isSupportedApiVersion, MAX_API_VERSION, MIN_API_VERSION, KNOWN_CAPABILITIES } from './policy.ts';
import { TokenBucketRateLimiter } from './rateLimit.ts';
import { signReceiptBytes, RECEIPT_SCHEMA_VERSION } from './receipts.ts';

export const PARTNER_API_PATH_PREFIX = '/api/partner';
export const SUPPORTED_API_VERSION = 'v1';
export const MAX_BODY_BYTES = 256 * 1024; // 256 KiB reference payload limit
export const RATE_LIMIT_CAPACITY = 30;
export const RATE_LIMIT_REFILL_PER_SEC = 10;

export function partnerApiDisabled(): boolean {
  return String(process.env.PATCHES_PARTNER_API_DISABLED ?? 'false').toLowerCase() === 'true';
}

// --- Downstream protection service boundary (synthetic) ---
// The private repo injects its real licensed protection services here.
// The sandbox models the CONTRACT only: enqueueActivation is called after
// all validation; a downstream failure fails the operation closed — the
// activation is NOT persisted as ACTIVE (fail-closed downstream behavior).
export interface ProtectionService {
  enqueueActivation(input: { activationId: string; capability: string; orgId: string; bindingId: string }): Promise<{ ok: boolean; downstreamStatus?: string }>;
}

export interface PartnerApiServerOptions {
  store: SyntheticPartnerStore;
  resolveClientSecret: (clientId: string, keyId: string) => string | null;
  receiptSecret: string;
  protectionService?: ProtectionService;
  now?: () => number;
  rateLimiter?: TokenBucketRateLimiter;
}

type HeaderBag = Record<string, string | string[] | undefined>;

function sendJson(res: ServerResponse, status: number, body: unknown, headers: HeaderBag = {}): void {
  const raw = Buffer.from(JSON.stringify(body), 'utf8');
  const h = res.getHeaderNames();
  for (const name of h) res.removeHeader(name);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.setHeader('content-length', String(raw.length));
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-api-version', SUPPORTED_API_VERSION);
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined) res.setHeader(name, value);
  }
  res.end(raw);
}

async function readRawBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      const err = new Error('PAYLOAD_TOO_LARGE') as Error & { statusCode?: number };
      err.statusCode = 413;
      throw err;
  }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

// --- Health: live readiness, never force-static cached ---
function healthPayload(store: SyntheticPartnerStore, now: number): Record<string, unknown> {
  return {
    service: 'PATCHES Partner API',
    version: 'v1',
    status: partnerApiDisabled() ? 'unavailable' : 'available',
    directDatabaseAccess: false,
    requiresScopedAuthentication: true,
    capabilities: store.listCapabilities().map((c) => c.capability),
    supportedApiVersions: [MIN_API_VERSION],
    at: now,
  };
}

// Store-free live-health payload for standalone route modules (e.g. the
// platform-mounted /api/partner/v1/health route): capability discovery
// baseline comes from the KNOWN_CAPABILITIES contract, not a store.
export const PARTNER_API_DISABLED_ENV = 'PATCHES_PARTNER_API_DISABLED';
export function healthPayloadFor(now: number): Record<string, unknown> {
  return {
    service: 'PATCHES Partner API',
    version: 'v1',
    status: partnerApiDisabled() ? 'unavailable' : 'available',
    directDatabaseAccess: false,
    requiresScopedAuthentication: true,
    capabilities: KNOWN_CAPABILITIES,
    supportedApiVersions: [MIN_API_VERSION],
    at: now,
  };
}

// --- Audit helper ---
function audit(store: SyntheticPartnerStore, event: Omit<AuditEventRecord, 'sequence'>): void {
  store.appendAudit(event);
}

function authFailureToResponse(failure: AuthFailure): { status: number; body: Record<string, unknown> } {
  const { code, detail } = failure;
  const body: Record<string, unknown> = { error: code, errorClass: 'AUTHENTICATION' };
  // Safe context (no secrets) surfaced to the partner for diagnostics.
  const safe = ['clientId', 'keyId', 'nonce', 'firstSeenAt', 'firstSeenRequestId', 'graceUntil', 'skewMs'];
  if (detail) {
    for (const key of safe) {
      if (detail[key] !== undefined) body[key] = detail[key];
    }
  }
  return { status: failure.status, body };
}

// --- Idempotency resolution ---
export interface IdempotencyResolveOutcome {
  kind: 'FRESH' | 'DUPLICATE' | 'CONFLICT';
  existing?: IdempotencyRecordView;
}

export interface IdempotencyRecordView {
  clientId: string;
  idempotencyKey: string;
  requestHash: string;
  outcome: string;
  activationId?: string;
  requestId?: string;
  at: number;
}

// The activation pipeline: validate -> idempotency resolve -> downstream ->
// transaction. Everything after idempotency resolution happens inside ONE
// store transaction so partial divergence is impossible.
async function processActivation(
  opts: PartnerApiServerOptions,
  auth: { clientId: string; partnerId: string },
  body: Record<string, unknown>,
  requestId: string,
  now: number,
): Promise<{ status: number; body: Record<string, unknown>; receipt?: ReceiptPayload; registerNonce: boolean }> {
  const store = opts.store;
  const { orgId, capability, bindingId, idempotencyKey } = readActivationInput(body);
  if (!orgId || !capability || !bindingId || !idempotencyKey) {
    return { status: 400, body: { error: 'ACTIVATION_INPUT_MISSING', fields: missingFieldsFor(body) }, registerNonce: false };
  }
  const apiVersion = SUPPORTED_API_VERSION;
  const requestHash = hashObject(body);

  // Policy pipeline: partner -> org -> entitlement -> capability -> binding
  const orgAuth = authorizeOrg(store, auth.partnerId, orgId);
  if (!orgAuth.ok) {
    return { status: 403, body: { error: orgAuth.failure!.code, errorClass: 'AUTHORIZATION' }, registerNonce: true };
  }
  const ent = checkEntitlement(store, auth.partnerId, orgId, capability, now);
  if (!ent.ok) {
    return { status: 403, body: { error: ent.failure!.code, errorClass: 'AUTHORIZATION' }, registerNonce: true };
  }
  const cap = checkCapability(store, capability, apiVersion);
  if (!cap.ok) {
    return { status: 403, body: { error: cap.failure!.code, errorClass: 'AUTHORIZATION' }, registerNonce: true };
  }
  const binding = checkBinding(store, bindingId, orgId, capability);
  if (!binding.ok) {
    return { status: 403, body: { error: binding.failure!.code, errorClass: 'AUTHORIZATION' }, registerNonce: true };
  }

  // Idempotency resolve
  const idem = resolveIdempotency(store, auth.clientId, idempotencyKey, requestHash, now, requestId);
  if (idem.kind === 'CONFLICT') {
    audit(store, { at: now, actorKind: 'PARTNER', clientId: auth.clientId, requestId, operation: 'activation.create', outcome: 'CONFLICT', detail: { code: 'IDEMPOTENCY_CONFLICT', idempotencyKey, existingRequestHash: idem.existing?.requestHash, existingActivationId: idem.existing?.activationId } });
    return {
      status: 409,
      body: { error: 'IDEMPOTENCY_KEY_CONFLICT', errorClass: 'IDEMPOTENCY', existingActivationId: idem.existing?.activationId ?? null },
      registerNonce: true,
    };
  }
  if (idem.kind === 'DUPLICATE') {
    const existing = idem.existing!;
    const dupReceiptId = `RCP-DUP-${requestId}`;
    audit(store, { at: now, actorKind: 'PARTNER', detail: { code: 'DUPLICATE_DELIVERY_COLLAPSED', idempotencyKey, existingActivationId: existing.activationId, existingRequestHash: existing.requestHash }, clientId: auth.clientId, requestId, operation: 'activation.create', outcome: 'CONFLICT' });
    const activation = existing.activationId ? store.getActivation(existing.activationId) : null;
    return {
      status: 200,
      body: receiptBody('activation.create', 'SUCCESS', requestId, auth.clientId, now, dupReceiptId, {
        activationId: existing.activationId ?? null,
        orgId, capability, payloadHash: requestHash,
        result: activationView(activation),
        duplicate: true,
      }),
      receipt: { receiptId: dupReceiptId },
      registerNonce: true,
    };
  }

  // FRESH: downstream check (fail-closed) then one transaction
  const activationId = `ACT-${requestId}`;
  const receiptId = `RCP-ACT-${requestId}`;
  const downstream = await awaitDownstream(opts, { activationId, capability, orgId, bindingId });
  if (!downstream.ok) {
    audit(store, { at: now, actorKind: 'PARTNER', clientId: auth.clientId, requestId, operation: 'activation.create', outcome: 'FAILED', detail: { code: 'DOWNSTREAM_UNAVAILABLE', downstreamStatus: downstream.downstreamStatus ?? 'UNKNOWN' } });
    return { status: 503, body: { error: 'DOWNSTREAM_UNAVAILABLE', errorClass: 'DOWNSTREAM' }, registerNonce: true };
  }

  try {
    store.runTransaction(() => {
      store.putActivation({ activationId, orgId, capability, bindingId, partnerId: auth.partnerId, status: 'ACTIVE', activatedAt: now, lastRequestId: requestId, idempotencyKey, activatedViaIdempotencyKey: idempotencyKey, payloadHash: requestHash });
      store.putReceipt({ receiptId, requestId, clientId: auth.clientId, operation: 'activation.create', outcome: 'SUCCESS', activationId, orgId, capability, payloadHash: requestHash, at: now });
      store.putIdempotency({ clientId: auth.clientId, idempotencyKey, requestHash, outcome: 'SUCCESS', activationId, requestId, at: now });
      store.appendEvent({ eventId: `EVT-${requestId}`, orgId, capability, activationId, type: 'activation.created', at: now, payloadDigest: requestHash });
      audit(store, { at: now, actorKind: 'PARTNER', clientId: auth.clientId, requestId, operation: 'activation.create', outcome: 'SUCCESS', detail: { code: 'ACTIVATION_CREATED', activationId, orgId, capability, bindingId } });
    });
  } catch (err) {
    return persistenceFailureResponse(store, auth.clientId, requestId, now, err);
  }
  return {
    status: 200,
    body: receiptBody('activation.create', 'SUCCESS', requestId, auth.clientId, now, receiptId, { activationId, orgId, capability, payloadHash: requestHash, result: activationView(store.getActivation(activationId)) }),
    receipt: { receiptId },
    registerNonce: true,
  };
}

// Deactivate/revoke pipeline: same policy pipeline; deactivate/revoke are
// idempotent by status (a second deactivate on DEACTIVATED is a no-op
// success) and a REVOKED activation cannot be reactivated or deactivated.
function processActivationStateChange(
  opts: PartnerApiServerOptions,
  auth: { clientId: string; partnerId: string },
  action: 'deactivate' | 'revoke',
  activationId: string,
  requestId: string,
  now: number,
): { status: number; body: Record<string, unknown>; receipt?: { receiptId: string }; registerNonce: boolean } {
  const store = opts.store;
  const activation = store.getActivation(activationId);
  if (!activation) {
    return { status: 404, body: { error: 'ACTIVATION_UNKNOWN', errorClass: 'NOT_FOUND' }, registerNonce: true };
  }
  const orgAuth = authorizeOrg(store, auth.partnerId, activation.orgId);
  if (!orgAuth.ok) {
    return { status: 403, body: { error: orgAuth.failure!.code, errorClass: 'AUTHORIZATION' }, registerNonce: true };
  }
  const entitlement = checkEntitlement(store, auth.partnerId, activation.orgId, activation.capability, now);
  if (!entitlement.ok) {
    return { status: 403, body: { error: entitlement.failure!.code, errorClass: 'AUTHORIZATION' }, registerNonce: true };
  }
  if (action === 'revoke' && activation.status === 'REVOKED') {
    return { status: 200, body: receiptBody('activation.revoke', 'SUCCESS', requestId, auth.clientId, now, `RCP-${action.toUpperCase()}-${requestId}`, { activationId, orgId: activation.orgId, capability: activation.capability, result: activationView(activation) }), receipt: { receiptId: `RCP-${action.toUpperCase()}-${requestId}` }, registerNonce: true };
  }
  if (action === 'deactivate' && activation.status === 'DEACTIVATED') {
    return { status: 200, body: receiptBody('activation.deactivate', 'SUCCESS', requestId, auth.clientId, now, `RCP-${action.toUpperCase()}-${requestId}`, { activationId, orgId: activation.orgId, capability: activation.capability, result: activationView(activation) }), receipt: { receiptId: `RCP-${action.toUpperCase()}-${requestId}` }, registerNonce: true };
  }
  if (activation.status === 'REVOKED') {
    return { status: 409, body: { error: 'ACTIVATION_REVOKED', errorClass: 'STATE' }, registerNonce: true };
  }

  const newStatus = action === 'revoke' ? 'REVOKED' : 'DEACTIVATED';
  const receiptId = `RCP-${action.toUpperCase()}-${requestId}`;
  try {
    store.runTransaction(() => {
      store.putActivation({ ...activation, status: newStatus, deactivatedAt: action === 'deactivate' ? now : activation.deactivatedAt, revokedAt: action === 'revoke' ? now : activation.revokedAt, lastRequestId: requestId });
      store.putReceipt({ receiptId, requestId, clientId: auth.clientId, operation: `activation.${action}`, outcome: 'SUCCESS', activationId, orgId: activation.orgId, capability: activation.capability, at: now });
      store.appendEvent({ eventId: `EVT-${requestId}`, orgId: activation.orgId, capability: activation.capability, activationId, type: `activation.${action === 'revoke' ? 'revoked' : 'deactivated'}`, at: now, payloadDigest: activation.payloadHash });
      audit(store, { at: now, actorKind: 'PARTNER', clientId: auth.clientId, requestId, operation: `activation.${action}`, outcome: 'SUCCESS', detail: { code: `ACTIVATION_${newStatus}`, activationId, orgId: activation.orgId, capability: activation.capability } });
    });
  } catch (err) {
    return persistenceFailureResponse(store, auth.clientId, requestId, now, err);
  }
  return {
    status: 200,
    body: receiptBody(`activation.${action}`, 'SUCCESS', requestId, auth.clientId, now, receiptId, { activationId, orgId: activation.orgId, capability: activation.capability, result: activationView(store.getActivation(activationId)) }),
    receipt: { receiptId },
    registerNonce: true,
  };
}

function persistenceFailureResponse(store: SyntheticPartnerStore, clientId: string, requestId: string, now: number, err: unknown): { status: number; body: Record<string, unknown>; registerNonce: boolean } {
  const isFailPoint = err instanceof Error && err.message.startsWith('FAILPOINT_');
  store.runTransaction(() => {
    audit(store, { at: now, actorKind: 'SYSTEM', clientId, requestId, operation: 'activation.create', outcome: 'FAILED', detail: { code: 'PARTNER_TRANSACTION_FAILED' } });
  });
  return { status: 500, body: { error: 'PARTNER_PERSISTENCE_FAILED', errorClass: 'PERSISTENCE' }, registerNonce: false };
}

function resolveIdempotency(store: SyntheticPartnerStore, clientId: string, idempotencyKey: string, requestHash: string, now: number, requestId: string): IdempotencyResolveOutcome {
  const existing = store.getIdempotency(clientId, idempotencyKey);
  if (!existing) return { kind: 'FRESH' };
  if (existing.requestHash === requestHash) return { kind: 'DUPLICATE', existing: toView(existing) };
  return { kind: 'CONFLICT', existing: toView(existing) };
}

function toView(record: import('./store.ts').IdempotencyRecord): IdempotencyRecordView {
  return { clientId: record.clientId, idempotencyKey: record.idempotencyKey, requestHash: record.requestHash, outcome: record.outcome, activationId: record.activationId, requestId: record.requestId, at: record.at };
}

function readActivationInput(body: Record<string, unknown>): { orgId?: string; capability?: string; bindingId?: string; idempotencyKey?: string } {
  const orgId = typeof body.orgId === 'string' ? body.orgId : undefined;
  const capability = typeof body.capability === 'string' ? body.capability : undefined;
  const bindingId = typeof body.bindingId === 'string' ? body.bindingId : undefined;
  const idempotencyKey = typeof body.idempotencyKey === 'string' ? body.idempotencyKey : undefined;
  return { orgId, capability, bindingId, idempotencyKey };
}

function missingFieldsFor(body: Record<string, unknown>): string[] {
  const missing: string[] = [];
  if (typeof body.orgId !== 'string') missing.push('orgId');
  if (typeof body.capability !== 'string') missing.push('capability');
  if (typeof body.bindingId !== 'string') missing.push('bindingId');
  if (typeof body.idempotencyKey !== 'string') missing.push('idempotencyKey');
  return missing;
}

function hashObject(obj: Record<string, unknown>): string {
  return createHash('sha256').update(JSON.stringify(obj)).digest('hex');
}

function activationView(activation: import('./store.ts').ActivationRecord | null): Record<string, unknown> | null {
  if (!activation) return null;
  return { activationId: activation.activationId, orgId: activation.orgId, capability: activation.capability, bindingId: activation.bindingId, status: activation.status, activatedAt: activation.activatedAt, deactivatedAt: activation.deactivatedAt ?? null, revokedAt: activation.revokedAt ?? null };
}

function receiptBody(operation: string, outcome: string, requestId: string, clientId: string, now: number, receiptId: string, extra: Record<string, unknown>): Record<string, unknown> {
  // receiptId is passed in (and echoed in the signed headers) so the body
  // and the x-patches-receipt-id header always name the SAME receipt.
  return { schemaVersion: RECEIPT_SCHEMA_VERSION, receiptId, requestId, clientId, operation, outcome, at: now, ...extra };
}

async function awaitDownstream(opts: PartnerApiServerOptions, input: { activationId: string; capability: string; orgId: string; bindingId: string }): Promise<{ ok: boolean; downstreamStatus?: string }> {
  const svc = opts.protectionService;
  if (!svc) return { ok: true, downstreamStatus: 'SYNTHETIC_NO_DOWNSTREAM' }; // no downstream configured -> sandbox default: allow
  try {
    const result = await svc.enqueueActivation(input);
    return { ok: result.ok, downstreamStatus: result.downstreamStatus ?? (result.ok ? 'SYNTHETIC_OK' : 'SYNTHETIC_FAILED') };
  } catch {
    return { ok: false, downstreamStatus: 'DOWNSTREAM_THREW' };
  }
}

interface ReceiptPayload { receiptId: string; }

// --- The HTTP handler ---

export function createPartnerApiServer(opts: PartnerApiServerOptions) {
  const rateLimiter = opts.rateLimiter ?? new TokenBucketRateLimiter({ capacity: RATE_LIMIT_CAPACITY, refillPerSecond: RATE_LIMIT_REFILL_PER_SEC, now: opts.now });
  const nowFn = opts.now ?? Date.now;

  return async function partnerApiHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://partner.api.internal');
    const pathname = url.pathname; // e.g. /api/partner/v1/health

    // Kill switch FIRST — nothing is served while disabled. Health stays
    // LIVE (a cached or silent health probe would be a lie): it reports the
    // disabled state itself, mirroring the platform-mounted route module.
    // Every other route fails closed.
    if (partnerApiDisabled()) {
      if (req.method === 'GET' && pathname === `${PARTNER_API_PATH_PREFIX}/v1/health`) {
        return sendJson(res, 503, {
          service: 'PATCHES Partner API',
          version: 'v1',
          status: 'disabled',
          directDatabaseAccess: false,
          requiresScopedAuthentication: true,
          at: nowFn(),
        });
      }
      return sendJson(res, 503, { error: 'PARTNER_API_DISABLED' });
    }

    // Request ID: echo the caller's or generate one (correlation across services).
    const reqHeader = (name: string): string | undefined => {
      const raw = req.headers[name.toLowerCase()];
      if (Array.isArray(raw)) return raw[0];
      return raw;
    };
    const requestId = reqHeader('x-request-id') ?? `req-${randomUUID()}`;
    const baseHeaders: HeaderBag = { 'x-request-id': requestId };

    // --- Unauthenticated routes ---
    if (req.method === 'GET' && pathname === `${PARTNER_API_PATH_PREFIX}/v1/health`) {
      return sendJson(res, 200, healthPayload(opts.store, nowFn()), baseHeaders);
    }

    // --- Version compatibility (route-scoped) ---
    // /api/partner/v2/... etc. -> 400 UNSUPPORTED_API_VERSION (fail closed,
    // never silently serve a different contract).
    const versionMatch = /^\/api\/partner\/(v[0-9]+)(\/.*)?$/.exec(pathname);
    if (versionMatch) {
      const version = versionMatch[1];
      const rest = versionMatch[2] ?? '/';
      if (!isSupportedApiVersion(version)) {
        return sendJson(res, 400, { error: 'UNSUPPORTED_API_VERSION', errorClass: 'VERSION', supported: [MIN_API_VERSION], requestId }, baseHeaders);
      }
      // version is v1: fall through to route matching below
      const route = matchV1Route(req.method ?? 'GET', rest);
      return await handleV1Route(route, req, res, url, requestId, baseHeaders);
    }

    return sendJson(res, 404, { error: 'NOT_FOUND', requestId }, baseHeaders);
  };

  async function handleV1Route(route: V1Route | null, req: IncomingMessage, res: ServerResponse, url: URL, requestId: string, baseHeaders: HeaderBag): Promise<void> {
    if (!route) {
      return sendJson(res, 404, { error: 'NOT_FOUND', requestId }, baseHeaders);
    }
    // All v1 routes except health require scoped partner authentication.
    const rawBody = route.method === 'POST' ? await readBodyWithLimit(req, res, requestId, baseHeaders) : Buffer.alloc(0);
    if (rawBody === null) return; // error response already sent

    const authResult = verifyPartnerAuth({
      store: opts.store,
      resolveClientSecret: opts.resolveClientSecret,
      method: route.method,
      path: url.pathname, // verify over the exact full path the client signed
      headers: req.headers,
      rawBody,
      now: nowFn,
    });
    if (!authResult.ok) {
      const { status, body } = authFailureToResponse(authResult.failure);
      audit(opts.store, { at: nowFn(), actorKind: 'PARTNER', clientId: 'unknown', requestId, operation: routeLabel(route), outcome: 'REJECTED', detail: { code: authResult.failure.code } });
      return sendJson(res, status, { ...body, requestId }, baseHeaders);
    }
    const auth = authResult.auth;

    // Rate limit per clientId AFTER authentication (so only authenticated
    // partners consume quota — anonymous floods cannot starve partners).
    const decision = rateLimiter.check(auth.clientId);
    if (!decision.allowed) {
      audit(opts.store, { at: nowFn(), actorKind: 'PARTNER', clientId: auth.clientId, requestId, operation: routeLabel(route), outcome: 'REJECTED', detail: { code: 'RATE_LIMITED', retryAfterMs: decision.retryAfterMs } });
      const headers: HeaderBag = { ...baseHeaders };
      if (decision.retryAfterMs !== undefined) headers['retry-after'] = String(Math.max(1, Math.ceil(decision.retryAfterMs / 1000)));
      return sendJson(res, 429, { error: 'RATE_LIMITED', errorClass: 'RATE_LIMIT', retryAfterMs: decision.retryAfterMs, requestId }, headers);
    }

    const now = nowFn();

    // --- GET routes ---
    if (route.kind === 'capabilities') {
      const caps = opts.store.listCapabilities();
      return sendJson(res, 200, { requestId, capabilities: caps.map((c) => ({ capability: c.capability, minApiVersion: c.minApiVersion, maxApiVersion: c.maxApiVersion, description: c.description })) }, baseHeaders);
    }
    if (route.kind === 'entitlements') {
      const orgId = url.searchParams.get('orgId');
      if (!orgId) return sendJson(res, 400, { error: 'ORG_ID_REQUIRED', errorClass: 'INPUT', requestId }, baseHeaders);
      const orgAuth = authorizeOrg(opts.store, auth.partner.partnerId, orgId);
      if (!orgAuth.ok) return sendJson(res, 403, { error: orgAuth.failure!.code, errorClass: 'AUTHORIZATION', requestId }, baseHeaders);
      const ents = opts.store.listEntitlementsForOrg(auth.partner.partnerId, orgId);
      audit(opts.store, { at: now, actorKind: 'PARTNER', clientId: auth.clientId, requestId, operation: 'entitlements.list', outcome: 'SUCCESS', detail: { code: 'ENTITLEMENTS_LISTED', orgId, eventCount: ents.length } });
      return sendJson(res, 200, { requestId, orgId, entitlements: ents.map((e) => ({ entitlementId: e.entitlementId, capability: e.capability, status: e.status, licensedFrom: e.licensedFrom, licensedUntil: e.licensedUntil })) }, baseHeaders);
    }
    if (route.kind === 'activation-status') {
      const activation = opts.store.getActivation(route.activationId);
      if (!activation) return sendJson(res, 404, { error: 'ACTIVATION_UNKNOWN', errorClass: 'NOT_FOUND', requestId }, baseHeaders);
      const orgAuth = authorizeOrg(opts.store, auth.partner.partnerId, activation.orgId);
      if (!orgAuth.ok) return sendJson(res, 403, { error: orgAuth.failure!.code, errorClass: 'AUTHORIZATION', requestId }, baseHeaders);
      return sendJson(res, 200, { requestId, activation: activationView(activation) }, baseHeaders);
    }
    if (route.kind === 'events') {
      const orgId = url.searchParams.get('orgId');
      if (!orgId) return sendJson(res, 400, { error: 'ORG_ID_REQUIRED', errorClass: 'INPUT', requestId }, baseHeaders);
      const orgAuth = authorizeOrg(opts.store, auth.partner.partnerId, orgId);
      if (!orgAuth.ok) return sendJson(res, 403, { error: orgAuth.failure!.code, errorClass: 'AUTHORIZATION', requestId }, baseHeaders);
      const events = opts.store.events.filter((e) => e.orgId === orgId);
      return sendJson(res, 200, { requestId, orgId, events: events.map((e) => ({ eventId: e.eventId, capability: e.capability, activationId: e.activationId, type: e.type, at: e.at })) }, baseHeaders);
    }
    if (route.kind === 'audit') {
      const orgId = url.searchParams.get('orgId');
      if (!orgId) return sendJson(res, 400, { error: 'ORG_ID_REQUIRED', errorClass: 'INPUT', requestId }, baseHeaders);
      const orgAuth = authorizeOrg(opts.store, auth.partner.partnerId, orgId);
      if (!orgAuth.ok) return sendJson(res, 403, { error: orgAuth.failure!.code, errorClass: 'AUTHORIZATION', requestId }, baseHeaders);
      // Tenant filter: a partner only ever sees audit events for its own orgs.
      const org = opts.store.getOrganization(orgId);
      const clientIds = [...opts.store.partners.values()].filter((p) => p.partnerId === org!.owningPartnerId).map((p) => p.clientId);
      const events = opts.store.audit.filter((a) => clientIds.includes(a.clientId));
      return sendJson(res, 200, { requestId, orgId, audit: events.map((a) => ({ sequence: a.sequence, at: a.at, actorKind: a.actorKind, clientId: a.clientId, requestId: a.requestId, operation: a.operation, outcome: a.outcome })) }, baseHeaders);
    }

    // --- POST routes (state-changing: receipts signed over raw bytes) ---
    let json: Record<string, unknown>;
    try {
      const parsed = JSON.parse(rawBody.toString('utf8'));
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('MALFORMED');
      json = parsed as Record<string, unknown>;
    } catch {
      return sendJson(res, 400, { error: 'MALFORMED_PAYLOAD', errorClass: 'INPUT', requestId }, baseHeaders);
    }

    if (route.kind === 'activation-create') {
      const outcome = await processActivation(opts, { clientId: auth.clientId, partnerId: auth.partner.partnerId }, json, requestId, now);
      if (outcome.registerNonce) {
        registerNonceTransactional(opts.store, auth.clientId, auth.nonce, now, requestId);
      }
      const headers: HeaderBag = { ...baseHeaders };
      if (outcome.receipt) {
        const raw = Buffer.from(JSON.stringify(outcome.body), 'utf8');
        const { contentSha256, signature } = signReceiptBytes(raw, opts.receiptSecret);
        headers['x-patches-receipt-id'] = outcome.receipt.receiptId;
        headers['x-patches-content-sha256'] = contentSha256;
        headers['x-patches-signature'] = signature;
      }
      return sendJson(res, outcome.status, outcome.body, headers);
    }
    if (route.kind === 'activation-deactivate' || route.kind === 'activation-revoke') {
      const action = route.kind === 'activation-revoke' ? 'revoke' : 'deactivate';
      const outcome = processActivationStateChange(opts, { clientId: auth.clientId, partnerId: auth.partner.partnerId }, action, route.activationId, requestId, now);
      if (outcome.registerNonce) {
        registerNonceTransactional(opts.store, auth.clientId, auth.nonce, now, requestId);
      }
      const headers: HeaderBag = { ...baseHeaders };
      if (outcome.receipt) {
        const raw = Buffer.from(JSON.stringify(outcome.body), 'utf8');
        const { contentSha256, signature } = signReceiptBytes(raw, opts.receiptSecret);
        headers['x-patches-receipt-id'] = outcome.receipt.receiptId;
        headers['x-patches-content-sha256'] = contentSha256;
        headers['x-patches-signature'] = signature;
      }
      return sendJson(res, outcome.status, outcome.body, headers);
    }

    return sendJson(res, 404, { error: 'NOT_FOUND', requestId }, baseHeaders);
  }

  // Hoisted function declaration (not a const arrow): this factory returns the
  // handler below, so any code after that `return` never executes. A function
  // declaration initializes during hoisting and is therefore safe to call from
  // the auth-failure and rate-limit audit paths.
  function routeLabel(route: V1Route): string {
    // Operation labels used in the audit trail (generic, contract-level).
    switch (route.kind) {
      case 'capabilities': return 'capabilities.list';
      case 'entitlements': return 'entitlements.list';
      case 'activation-create': return 'activation.create';
      case 'activation-status': return 'activation.status';
      case 'activation-deactivate': return 'activation.deactivate';
      case 'activation-revoke': return 'activation.revoke';
      case 'events': return 'events.list';
      case 'audit': return 'audit.list';
    }
  }

  function matchV1Route(method: string, rest: string): V1Route | null {
    if (method === 'GET' && rest === '/capabilities') return { kind: 'capabilities', method };
    if (method === 'GET' && rest === '/entitlements') return { kind: 'entitlements', method };
    if (method === 'POST' && rest === '/activations') return { kind: 'activation-create', method };
    let m = /^\/activations\/([A-Za-z0-9_-]{1,128})$/.exec(rest);
    if (method === 'GET' && m) return { kind: 'activation-status', method, activationId: m[1] };
    m = /^\/activations\/([A-Za-z0-9_-]{1,128})\/(deactivate|revoke)$/.exec(rest);
    if (method === 'POST' && m) return { kind: m[2] === 'revoke' ? 'activation-revoke' : 'activation-deactivate', method, activationId: m[1] };
    if (method === 'GET' && rest === '/events') return { kind: 'events', method };
    if (method === 'GET' && rest === '/audit') return { kind: 'audit', method };
    return null;
  }

  async function readBodyWithLimit(req: IncomingMessage, res: ServerResponse, requestId: string, baseHeaders: HeaderBag): Promise<Buffer | null> {
    try {
      return await readRawBody(req);
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 400;
      const body: Record<string, unknown> = status === 413
        ? { error: 'PAYLOAD_TOO_LARGE', errorClass: 'INPUT', limitBytes: MAX_BODY_BYTES, requestId }
        : { error: 'INVALID_BODY', errorClass: 'INPUT', requestId };
      sendJson(res, status, body, baseHeaders);
      return null;
    }
  }
}

function registerNonceTransactional(store: SyntheticPartnerStore, clientId: string, nonce: string, now: number, requestId: string): void {
  store.runTransaction(() => {
    store.registerNonce(clientId, nonce, now, requestId);
  });
}

type V1Route =
  | { kind: 'capabilities' | 'entitlements' | 'activation-create' | 'events' | 'audit'; method: string }
  | { kind: 'activation-status' | 'activation-deactivate' | 'activation-revoke'; method: string; activationId: string; path?: string };
