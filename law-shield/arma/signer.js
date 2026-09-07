// ARMA-side request signer for protocol arma-lawshield.v1.
// Produces the exact header set the Law Shield gateway verifies:
//   x-arma-timestamp / x-arma-nonce / x-arma-signature / x-arma-content-sha256 / x-arma-schema-version
// Canonical string: `${schemaVersion}\n${timestamp}\n${nonce}\n${bodyHash}`
// The signer signs the EXACT bytes that will go on the wire (never a
// re-serialized object), mirroring the gateway's raw-byte verification.
import crypto from 'node:crypto';
import { INTEGRATION_SCHEMA_VERSION, sha256Hex } from '../lawshield/_integrationSecurity.js';

const NONCE_MIN = 20, NONCE_MAX = 128;

export function generateNonce() {
  return crypto.randomBytes(24).toString('base64url'); // 32 chars, [A-Za-z0-9_-]
}

function timingSafeEqualHex(expected, actual) {
  if (!expected || !actual || expected.length !== actual.length) return false;
  if (!/^[a-f0-9]+$/i.test(expected) || !/^[a-f0-9]+$/i.test(actual)) return false;
  try { return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex')); }
  catch { return false; }
}
export { timingSafeEqualHex };

// Sign an outbound request. `body` MUST be the exact byte string being sent.
// Receipt VERIFICATION lives in receiptVerifier.js (single source of truth —
// this module signs only, mirroring the gateway's separation of concerns).
export function signRequest({ body, secret, timestamp = String(Date.now()), nonce = generateNonce(), schemaVersion = INTEGRATION_SCHEMA_VERSION }) {
  if (!secret) throw new Error('ARMA_SIGNER_NOT_CONFIGURED');
  if (typeof body !== 'string' || body.length === 0) throw new Error('ARMA_SIGNER_INVALID_BODY');
  const bodyHash = sha256Hex(body);
  const canonical = `${schemaVersion}\n${timestamp}\n${nonce}\n${bodyHash}`;
  const signature = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  if (nonce.length < NONCE_MIN || nonce.length > NONCE_MAX || !/^[A-Za-z0-9_-]+$/.test(nonce)) throw new Error('INVALID_NONCE');
  return {
    headers: {
      'content-type': 'application/json',
      'x-arma-timestamp': timestamp,
      'x-arma-nonce': nonce,
      'x-arma-signature': signature,
      'x-arma-content-sha256': bodyHash,
      'x-arma-schema-version': schemaVersion,
    },
    body, bodyHash, nonce, timestamp, signature, canonical,
  };
}
