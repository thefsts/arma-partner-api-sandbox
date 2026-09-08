// PATCHES Partner API v1 — scoped partner authentication + request
// integrity + replay protection + credential lifecycle (rotation/revocation).
//
// AUTH CONTRACT (partner -> PATCHES):
//   Authorization: PATCHES-Partner <clientId>:<keyId>
//   X-PATCHES-Timestamp:  <epoch ms>
//   X-PATCHES-Nonce:      <opaque nonce, [A-Za-z0-9_-]{20,128}>
//   X-PATCHES-Signature:  hex(HMAC-SHA256(secret, canonical))
//   canonical = `${method}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`
// where bodyHash = sha256hex(rawBodyBytes) ('' hashes to sha256 of empty
// string for bodyless GETs, which keeps the signature bound to the method).
//
// The authenticated partner identity is the ONLY source of truth for
// authorization: orgId/deviceId/subjectId from a request body are never
// trusted until validated against the partner's bound organizations
// (see policy.ts).
//
// ROTATION STRATEGY (library-level; ops-driven, not a partner endpoint):
//   rotateCredential(): new key becomes ACTIVE; the previous ACTIVE key
//   moves to GRACE with retiredAt = now + graceMs; after retiredAt the
//   grace key is treated as expired (CREDENTIAL_EXPIRED) and may be
//   flipped to RETIRED. A REVOKED key is denied immediately, no grace.
//
// PORTING NOTE (private PATCHES repo): resolveClientSecret is the KMS /
// secret-store boundary. The private repo injects its real secret store;
// this sandbox resolves synthetic secrets from the seed directory. Never
// store plaintext secrets in durable persistence.

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { CredentialRecord, PartnerRecord, SyntheticPartnerStore } from './store.ts';

export const SUPPORTED_API_VERSIONS = ['v1'] as const;
export type ApiVersion = (typeof SUPPORTED_API_VERSIONS)[number];

export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000; // ±5 minutes
export const NONCE_VALIDITY_WINDOW_MS = 2 * MAX_CLOCK_SKEW_MS; // 10 minutes
export const NONCE_PATTERN = /^[A-Za-z0-9_-]{20,128}$/;

export interface AuthFailure {
  code:
    | 'AUTH_MISSING'
    | 'AUTH_MALFORMED'
    | 'PARTNER_UNKNOWN'
    | 'PARTNER_SUSPENDED'
    | 'CREDENTIAL_UNKNOWN'
    | 'CREDENTIAL_REVOKED'
    | 'CREDENTIAL_EXPIRED'
    | 'TIMESTAMP_OUT_OF_WINDOW'
    | 'NONCE_INVALID'
    | 'NONCE_REPLAYED'
    | 'SIGNATURE_INVALID'
    | 'SECRET_UNAVAILABLE';
  status: 401 | 409;
  detail?: Record<string, unknown>;
}

export interface AuthSuccess {
  clientId: string;
  keyId: string;
  partner: PartnerRecord;
  credential: CredentialRecord;
  nonce: string;
}

export type SecretResolver = (clientId: string, keyId: string) => string | null;

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

export function canonicalRequestString(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  bodyHash: string,
): string {
  return `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;
}

export function computeRequestSignature(secret: string, canonical: string): string {
  return createHmac('sha256', secret).update(canonical).digest('hex');
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

export function bodyHashFor(rawBody: Buffer): string {
  return sha256Hex(rawBody.length === 0 ? '' : rawBody);
}

export interface VerifyAuthInput {
  store: SyntheticPartnerStore;
  resolveClientSecret: SecretResolver;
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  now?: () => number;
}

// Full authentication pipeline. Does NOT consume the nonce: the caller
// registers it in the same transaction as the operation outcome (see
// server.ts), so an unauthenticated request cannot burn a partner's
// nonces and a fully processed request can never be replayed.
export function verifyPartnerAuth(input: VerifyAuthInput): { ok: true; auth: AuthSuccess } | { ok: false; failure: AuthFailure } {
  const now = (input.now ?? Date.now)();
  const h = (name: string): string | undefined => {
    const raw = input.headers[name.toLowerCase()];
    if (Array.isArray(raw)) return raw[0];
    return raw;
  };

  const authorization = h('authorization');
  if (!authorization) {
    return { ok: false, failure: { code: 'AUTH_MISSING', status: 401 } };
  }
  const match = /^PATCHES-Partner ([A-Za-z0-9_-]{1,128}):([A-Za-z0-9_-]{1,128})$/.exec(authorization);
  if (!match) {
    return { ok: false, failure: { code: 'AUTH_MALFORMED', status: 401 } };
  }
  const clientId = match[1];
  const keyId = match[2];

  const partner = input.store.getPartnerByClientId(clientId);
  if (!partner) return { ok: false, failure: { code: 'PARTNER_UNKNOWN', status: 401 } };
  if (partner.status === 'SUSPENDED') {
    return { ok: false, failure: { code: 'PARTNER_SUSPENDED', status: 401, detail: { clientId } } };
  }

  const credential = input.store.getCredential(clientId, keyId);
  if (!credential) {
    return { ok: false, failure: { code: 'CREDENTIAL_UNKNOWN', status: 401, detail: { keyId } } };
  }
  if (credential.status === 'REVOKED') {
    return { ok: false, failure: { code: 'CREDENTIAL_REVOKED', status: 401, detail: { keyId } } };
  }
  if (credential.status === 'RETIRED') {
    return { ok: false, failure: { code: 'CREDENTIAL_EXPIRED', status: 401, detail: { keyId } } };
  }
  if (credential.status === 'GRACE' && credential.retiredAt !== undefined && credential.retiredAt <= now) {
    return { ok: false, failure: { code: 'CREDENTIAL_EXPIRED', status: 401, detail: { keyId, graceUntil: credential.retiredAt } } };
  }

  const timestamp = h('x-patches-timestamp');
  if (!timestamp || !/^\d{1,16}$/.test(timestamp)) {
    return { ok: false, failure: { code: 'TIMESTAMP_OUT_OF_WINDOW', status: 401 } };
  }
  const ts = Number(timestamp);
  if (Math.abs(now - ts) > MAX_CLOCK_SKEW_MS) {
    return { ok: false, failure: { code: 'TIMESTAMP_OUT_OF_WINDOW', status: 401, detail: { skewMs: Math.abs(now - ts) } } };
  }

  const nonce = h('x-patches-nonce');
  if (!nonce || !NONCE_PATTERN.test(nonce)) {
    return { ok: false, failure: { code: 'NONCE_INVALID', status: 401 } };
  }
  const existing = input.store.getNonceRecord(clientId, nonce);
  if (existing && now - existing.firstSeenAt <= NONCE_VALIDITY_WINDOW_MS) {
    return {
      ok: false,
      failure: {
        code: 'NONCE_REPLAYED',
        status: 409,
        detail: { nonce, firstSeenAt: existing.firstSeenAt, firstSeenRequestId: existing.firstSeenRequestId },
      },
    };
  }
  input.store.pruneNoncesBefore(now - NONCE_VALIDITY_WINDOW_MS);

  const secret = input.resolveClientSecret(clientId, keyId);
  if (secret === null) {
    return { ok: false, failure: { code: 'SECRET_UNAVAILABLE', status: 401, detail: { keyId } } };
  }

  const bodyHash = bodyHashFor(input.rawBody);
  const canonical = canonicalRequestString(input.method, input.path, timestamp, nonce, bodyHash);
  const expected = computeRequestSignature(secret, canonical);
  const provided = h('x-patches-signature');
  if (!provided || !/^[0-9a-f]{64}$/.test(provided) || !timingSafeEqualHex(expected, provided)) {
    return { ok: false, failure: { code: 'SIGNATURE_INVALID', status: 401 } };
  }

  return {
    ok: true,
    auth: { clientId, keyId, partner, credential, nonce },
  };
}

// --- Credential lifecycle (ops-level library functions) ---

export interface RotateCredentialInput {
  store: SyntheticPartnerStore;
  clientId: string;
  newKeyId: string;
  newSecretHash: string;
  graceMs?: number; // default 10 minutes
  now?: () => number;
}

export function rotateCredential(input: RotateCredentialInput): CredentialRecord {
  const now = (input.now ?? Date.now)();
  const graceMs = input.graceMs ?? 10 * 60 * 1000;
  return input.store.runTransaction(() => {
    const previous = input.store.activeCredentialFor(input.clientId);
    if (previous && previous.status === 'ACTIVE') {
      input.store.putCredential({ ...previous, status: 'GRACE', retiredAt: now + graceMs });
    }
    const created: CredentialRecord = {
      clientId: input.clientId,
      keyId: input.newKeyId,
      kind: 'CLIENT_SECRET',
      secretHash: input.newSecretHash,
      status: 'ACTIVE',
      activatedAt: now,
      rotatedFrom: previous?.keyId,
    };
    input.store.putCredential(created);
    return created;
  });
}

export function revokeCredential(input: {
  store: SyntheticPartnerStore;
  clientId: string;
  keyId: string;
  reason: string;
  now?: () => number;
}): CredentialRecord | null {
  const now = (input.now ?? Date.now)();
  const cred = input.store.getCredential(input.clientId, input.keyId);
  if (!cred) return null;
  const revoked: CredentialRecord = { ...cred, status: 'REVOKED', revokedAt: now, revokedReason: input.reason };
  input.store.putCredential(revoked);
  return revoked;
}
