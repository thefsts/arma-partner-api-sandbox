import crypto from 'node:crypto';

export const INTEGRATION_SCHEMA_VERSION = 'arma-lawshield.v1';
export const MAX_BODY_BYTES = 1024 * 1024;
export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

export const ALLOWED_RECORD_TYPES = new Set([
  'CASE_REFERRAL','INCIDENT_METADATA','EVIDENCE_MANIFEST','EVIDENCE_PACKAGE_REFERENCE',
  'CHAIN_OF_CUSTODY_UPDATE','TRANSFER_STATUS','CASE_STATUS_UPDATE',
]);

const FORBIDDEN_INSTRUCTION_KEYS = new Set([
  'systemprompt','developerprompt','toolcall','toolcalls','execute','shellcommand','command',
  'functioncall','functioncalls','authorizationoverride','policyoverride',
]);
const FORBIDDEN_INSTRUCTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,/ignore\s+(all\s+)?prior\s+instructions/i,
  /reveal\s+(the\s+)?system\s+prompt/i,/bypass\s+(security|authorization|policy|access)/i,
  /disable\s+(audit|logging|security|authorization)/i,
  /grant\s+(admin|administrator|root|elevated)\s+access/i,
  /execute\s+(this\s+)?(tool|command|shell|function)/i,
];

function timingSafeEqualHex(expected, actual) {
  if (!expected || !actual || expected.length !== actual.length) return false;
  if (!/^[a-f0-9]+$/i.test(expected) || !/^[a-f0-9]+$/i.test(actual)) return false;
  try { return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex')); }
  catch { return false; }
}
export function sha256Hex(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

// Shared payload-safety check (additive export, Stop Point 2). Lets the ARMA-side
// envelope builder apply the EXACT perimeter rules locally (fail before leaving ARMA)
// instead of duplicating the forbidden-key/pattern lists. No behavior change to the
// gateway; assertNoExecutableOrAiInstructions remains the single source of truth.
export function assertPayloadSafe(payload) { assertNoExecutableOrAiInstructions(payload); }
export function integrationDisabled() { return String(process.env.LAW_SHIELD_ARMA_INTEGRATION_DISABLED ?? 'false').toLowerCase() === 'true'; }

function assertNoExecutableOrAiInstructions(value, depth = 0) {
  if (depth > 20) throw new Error('PAYLOAD_STRUCTURE_TOO_DEEP');
  if (value == null) return;
  if (typeof value === 'string') {
    if (FORBIDDEN_INSTRUCTION_PATTERNS.some((pattern) => pattern.test(value))) throw new Error('AI_OR_EXECUTABLE_INSTRUCTION_BLOCKED');
    return;
  }
  if (Array.isArray(value)) return value.forEach((item) => assertNoExecutableOrAiInstructions(item, depth + 1));
  if (typeof value === 'object') for (const [key, child] of Object.entries(value)) {
    const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase();
    if (FORBIDDEN_INSTRUCTION_KEYS.has(normalized)) throw new Error('AI_OR_EXECUTABLE_INSTRUCTION_BLOCKED');
    assertNoExecutableOrAiInstructions(child, depth + 1);
  }
}

export function verifyIntegrationRequest({ rawBody, headers }) {
  if (integrationDisabled()) throw new Error('INTEGRATION_DISABLED');
  const secret = process.env.ARMA_TO_LAW_SHIELD_HMAC_SECRET;
  if (!secret) throw new Error('INTEGRATION_NOT_CONFIGURED');
  if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) throw new Error('PAYLOAD_TOO_LARGE');
  const timestamp=headers['x-arma-timestamp'], nonce=headers['x-arma-nonce'], signature=headers['x-arma-signature'];
  const bodyHash=headers['x-arma-content-sha256'], schemaVersion=headers['x-arma-schema-version'];
  if (!timestamp || !nonce || !signature || !bodyHash || !schemaVersion) throw new Error('MISSING_SECURITY_HEADERS');
  if (schemaVersion !== INTEGRATION_SCHEMA_VERSION) throw new Error('SCHEMA_VERSION_UNSUPPORTED');
  if (!/^[A-Za-z0-9_-]{20,128}$/.test(nonce)) throw new Error('INVALID_NONCE');
  const requestTime=Number(timestamp);
  if (!Number.isFinite(requestTime) || Math.abs(Date.now()-requestTime)>MAX_CLOCK_SKEW_MS) throw new Error('STALE_OR_FUTURE_REQUEST');
  const calculatedBodyHash=sha256Hex(rawBody);
  if (!timingSafeEqualHex(calculatedBodyHash, bodyHash)) throw new Error('BODY_HASH_MISMATCH');
  const canonical=`${schemaVersion}\n${timestamp}\n${nonce}\n${bodyHash}`;
  const expectedSignature=crypto.createHmac('sha256',secret).update(canonical).digest('hex');
  if (!timingSafeEqualHex(expectedSignature,signature)) throw new Error('INVALID_SIGNATURE');
  let envelope; try { envelope=JSON.parse(rawBody); } catch { throw new Error('INVALID_JSON'); }
  validateEnvelope(envelope); return { envelope, bodyHash, nonce, requestTime };
}

export function validateEnvelope(envelope) {
  const requiredStrings=['schemaVersion','transferId','idempotencyKey','sourceSystem','destinationSystem','armaOrgId','lawShieldOrgId','recordType','recordId','authorizedBy','authorizationReason'];
  for (const key of requiredStrings) if (typeof envelope?.[key] !== 'string' || !envelope[key].trim()) throw new Error(`INVALID_FIELD_${key}`);
  if (envelope.schemaVersion!==INTEGRATION_SCHEMA_VERSION) throw new Error('SCHEMA_VERSION_UNSUPPORTED');
  if (envelope.sourceSystem!=='ARMA_360' || envelope.destinationSystem!=='LAW_SHIELD') throw new Error('INVALID_SYSTEM_ROUTE');
  if (!ALLOWED_RECORD_TYPES.has(envelope.recordType)) throw new Error('RECORD_TYPE_NOT_ALLOWED');
  if (envelope.authorizedBy.startsWith('AI:') || ['AI','JOY','ROSE'].includes(envelope.authorizedBy) || envelope.authorizationMode==='AI') throw new Error('AI_CANNOT_AUTHORIZE_TRANSFER');
  if (!envelope.mapping || typeof envelope.mapping!=='object') throw new Error('MAPPING_REQUIRED');
  if (envelope.mapping.armaOrgId!==envelope.armaOrgId || envelope.mapping.lawShieldOrgId!==envelope.lawShieldOrgId) throw new Error('ORG_MAPPING_MISMATCH');
  if (envelope.incidentId && !envelope.mapping.lawShieldCaseId) throw new Error('CASE_MAPPING_REQUIRED');
  if (![envelope.createdAt,envelope.sentAt,envelope.expiresAt].every(Number.isFinite)) throw new Error('INVALID_TIMESTAMPS');
  if (envelope.expiresAt<=Date.now()) throw new Error('TRANSFER_EXPIRED');
  if (envelope.sentAt<envelope.createdAt) throw new Error('INVALID_TIME_ORDER');
  if (envelope.payload===undefined) throw new Error('PAYLOAD_REQUIRED');
  const payloadHash=sha256Hex(JSON.stringify(envelope.payload));
  if (!envelope.payloadHash || !timingSafeEqualHex(payloadHash,envelope.payloadHash)) throw new Error('PAYLOAD_HASH_MISMATCH');
  assertNoExecutableOrAiInstructions(envelope.payload);
}

export function signReceipt(receipt) {
  const secret=process.env.LAW_SHIELD_TO_ARMA_HMAC_SECRET;
  if (!secret) throw new Error('RECEIPT_SIGNING_NOT_CONFIGURED');
  const body=JSON.stringify(receipt);
  return { body, bodyHash:sha256Hex(body), signature:crypto.createHmac('sha256',secret).update(body).digest('hex') };
}

export function getIntegrationReadiness() {
  return { schemaVersion:INTEGRATION_SCHEMA_VERSION, gatewayConfigured:Boolean(process.env.ARMA_TO_LAW_SHIELD_HMAC_SECRET), receiptSigningConfigured:Boolean(process.env.LAW_SHIELD_TO_ARMA_HMAC_SECRET), processorConfigured:Boolean(process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_URL && process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN), killSwitchActive:integrationDisabled(), maxBodyBytes:MAX_BODY_BYTES, maxClockSkewMs:MAX_CLOCK_SKEW_MS, allowedRecordTypes:[...ALLOWED_RECORD_TYPES] };
}

// ---------------------------------------------------------------------------
// First-layer nonce replay guard (sandbox addition, Stop Point 2).
// The authoritative replay registry lives in the durable processor (Stop Point 3).
// This guard protects the gateway itself against duplicate delivery of an
// already-accepted nonce within the freshness window. Single-instance in-memory:
// PORTING NOTE — multi-instance deployments must relocate this check to shared
// storage (alongside the processor nonce registry) before production.
// Disable via LAW_SHIELD_GATEWAY_REPLAY_GUARD=disabled (default enabled).
// ---------------------------------------------------------------------------
const replaySeen=new Map();
export const replayGuard={
  enabled(){return String(process.env.LAW_SHIELD_GATEWAY_REPLAY_GUARD??'enabled').toLowerCase()!=='disabled';},
  remember(nonce){
    if(!this.enabled())return;
    const now=Date.now();
    for(const [seenNonce,at] of replaySeen){if(now-at>2*MAX_CLOCK_SKEW_MS)replaySeen.delete(seenNonce);}
    if(replaySeen.has(nonce))throw new Error('REPLAYED_NONCE');
    replaySeen.set(nonce,now);
  },
  reset(){replaySeen.clear();},
};
