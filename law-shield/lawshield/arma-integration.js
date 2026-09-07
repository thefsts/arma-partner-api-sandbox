import { verifyIntegrationRequest, signReceipt, replayGuard } from './_integrationSecurity.js';

const PROCESSOR_TIMEOUT_DEFAULT_MS = 10_000;

// Transport-level failure classification (D3/D4 + unknown transport faults).
// Raw runtime messages are NEVER exposed to callers; ARMA sees structured codes only.
// Node 24 fetch shapes (verified): TimeoutError(code 23) from AbortSignal.timeout,
// AbortError(code 20) from manual abort, TypeError('fetch failed', cause ECONNREFUSED)
// for unreachable endpoints.
function processorTimeoutMs(){
  const configured=Number(process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_TIMEOUT_MS);
  return Number.isFinite(configured)&&configured>0?configured:PROCESSOR_TIMEOUT_DEFAULT_MS;
}
function classifyTransportError(error){
  const name=error?.name, code=error?.code, causeCode=error?.cause?.code, message=String(error?.message??'');
  if(name==='TimeoutError'||name==='AbortError'||code===23||code===20||causeCode===23||causeCode===20||/timeout|aborted/i.test(message)) return {code:'PROCESSOR_TIMEOUT',status:502,retryable:true};
  return {code:'PROCESSOR_UNAVAILABLE',status:502,retryable:true};
}

// Every error code the security perimeter can raise, plus gateway-generated codes.
// Anything else becomes a generic 500 INTEGRATION_REJECTED (raw messages never echoed).
const KNOWN_ERROR_CODES = new Set([
  'PAYLOAD_TOO_LARGE', 'INTEGRATION_DISABLED', 'INTEGRATION_NOT_CONFIGURED', 'RECEIPT_SIGNING_NOT_CONFIGURED',
  'INTEGRATION_PROCESSOR_NOT_CONFIGURED', 'RECORD_TYPE_NOT_ALLOWED', 'SCHEMA_VERSION_UNSUPPORTED',
  'TRANSFER_EXPIRED', 'STALE_OR_FUTURE_REQUEST', 'REPLAYED_NONCE', 'INVALID_NONCE', 'INVALID_JSON',
  'INVALID_TIMESTAMPS', 'INVALID_TIME_ORDER', 'PROCESSOR_RECEIPT_MISMATCH', 'PROCESSOR_TIMEOUT',
  'PROCESSOR_UNAVAILABLE', 'MISSING_SECURITY_HEADERS', 'INVALID_SIGNATURE', 'BODY_HASH_MISMATCH',
  'PAYLOAD_HASH_MISMATCH', 'AI_CANNOT_AUTHORIZE_TRANSFER', 'AI_OR_EXECUTABLE_INSTRUCTION_BLOCKED',
  'MAPPING_REQUIRED', 'ORG_MAPPING_MISMATCH', 'CASE_MAPPING_REQUIRED', 'INVALID_SYSTEM_ROUTE',
  'PAYLOAD_REQUIRED', 'PAYLOAD_STRUCTURE_TOO_DEEP', 'INTEGRATION_REJECTED',
]);

function sendJson(res,status,body,extraHeaders={}) { res.statusCode=status; res.setHeader('Content-Type','application/json'); res.setHeader('Cache-Control','no-store'); res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Referrer-Policy','no-referrer'); res.setHeader('X-Frame-Options','DENY'); for(const [k,v] of Object.entries(extraHeaders)) res.setHeader(k,v); res.end(JSON.stringify(body)); }
async function readRawBody(req){const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>1024*1024)throw new Error('PAYLOAD_TOO_LARGE');chunks.push(chunk);}return Buffer.concat(chunks).toString('utf8');}
function statusForError(code){
  if(code==='PAYLOAD_TOO_LARGE')return 413;
  if(['INTEGRATION_DISABLED','INTEGRATION_NOT_CONFIGURED','RECEIPT_SIGNING_NOT_CONFIGURED','INTEGRATION_PROCESSOR_NOT_CONFIGURED'].includes(code))return 503;
  if(['RECORD_TYPE_NOT_ALLOWED','SCHEMA_VERSION_UNSUPPORTED'].includes(code))return 422;
  if(['TRANSFER_EXPIRED','STALE_OR_FUTURE_REQUEST','REPLAYED_NONCE'].includes(code))return 409;
  if(code.startsWith('INVALID_FIELD_')||['INVALID_JSON','INVALID_TIMESTAMPS','INVALID_TIME_ORDER','INVALID_NONCE'].includes(code))return 400;
  if(['PROCESSOR_RECEIPT_MISMATCH','PROCESSOR_TIMEOUT','PROCESSOR_UNAVAILABLE'].includes(code))return 502; // D2/D3/D4
  return 401;
}

export default async function handler(req,res){
  if(req.method!=='POST'){res.setHeader('Allow','POST');return sendJson(res,405,{error:'METHOD_NOT_ALLOWED',accepted:false});}
  if(!String(req.headers['content-type']??'').toLowerCase().startsWith('application/json'))return sendJson(res,415,{error:'CONTENT_TYPE_NOT_ALLOWED',accepted:false});
  let transferIdHint=null;
  try{
    const rawBody=await readRawBody(req); const verified=verifyIntegrationRequest({rawBody,headers:req.headers});
    transferIdHint=verified.envelope.transferId;
    // First-layer replay guard (G1, approved at Stop Point 1 review). The authoritative
    // registry lives in the durable processor (Stop Point 3); this protects the gateway
    // against duplicate delivery of an already-seen nonce within the freshness window.
    // PORTING NOTE: single-instance in-memory map; multi-instance deployments must move
    // this check to shared storage with the processor registry (see Stop Point 2 report).
    replayGuard.remember(verified.nonce);
    const processorUrl=process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_URL, processorToken=process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN;
    if(!processorUrl||!processorToken)return sendJson(res,503,{error:'INTEGRATION_PROCESSOR_NOT_CONFIGURED',transferId:transferIdHint,accepted:false});
    let upstream;
    try{
      upstream=await fetch(processorUrl,{method:'POST',headers:{'content-type':'application/json','authorization':`Bearer ${processorToken}`,'x-verified-arma-nonce':verified.nonce,'x-verified-arma-content-sha256':verified.bodyHash,'x-integration-schema-version':verified.envelope.schemaVersion,'x-integration-transfer-id':verified.envelope.transferId},body:rawBody,signal:AbortSignal.timeout(processorTimeoutMs())});
    }catch(transportError){
      const classified=classifyTransportError(transportError); // D3/D4: structured, no raw leak
      return sendJson(res,classified.status,{error:classified.code,transferId:transferIdHint,accepted:false,retryable:classified.retryable});
    }
    const resultText=await upstream.text();let result;try{result=JSON.parse(resultText);}catch{result={error:'PROCESSOR_NON_JSON_RESPONSE'};}
    if(!upstream.ok||result?.accepted!==true||!result?.receiptId)return sendJson(res,502,{error:result?.error||'PROCESSOR_REJECTED_TRANSFER',transferId:transferIdHint,accepted:false,processorStatus:upstream.status});
    if((result.transferId&&result.transferId!==verified.envelope.transferId)||(result.payloadHash&&result.payloadHash!==verified.envelope.payloadHash)){
      // D2: downstream integrity / ambiguous-processing condition. Never 401.
      // Fail closed. Ambiguous outcome => ARMA-side RECONCILIATION_REQUIRED (retry must
      // never blindly re-send: an accepted disclosure must never be duplicated).
      return sendJson(res,502,{error:'PROCESSOR_RECEIPT_MISMATCH',transferId:transferIdHint,accepted:false,reconciliationRequired:true});
    }
    // D1 (approved additive contract clarification): success receipts carry accepted:true.
    // status:"ACCEPTED" preserved for existing v1 consumers — compatibility covered by
    // law-shield/tests/contract.compat.test.mjs.
    const receipt={schemaVersion:verified.envelope.schemaVersion,receiptId:result.receiptId,transferId:verified.envelope.transferId,idempotencyKey:verified.envelope.idempotencyKey,status:'ACCEPTED',accepted:true,acceptedAt:Number.isFinite(result.acceptedAt)?result.acceptedAt:Date.now(),armaOrgId:verified.envelope.armaOrgId,lawShieldOrgId:verified.envelope.lawShieldOrgId,incidentId:verified.envelope.incidentId??null,lawShieldCaseId:verified.envelope.mapping.lawShieldCaseId??null,recordType:verified.envelope.recordType,recordId:verified.envelope.recordId,receivedPayloadHash:verified.envelope.payloadHash,processingResult:result.processingResult??'PERSISTED'};
    const signed=signReceipt(receipt);return sendJson(res,200,receipt,{'X-LawShield-Content-SHA256':signed.bodyHash,'X-LawShield-Signature':signed.signature,'X-LawShield-Schema-Version':receipt.schemaVersion,'X-LawShield-Receipt-Id':receipt.receiptId});
  }catch(error){
    const raw=error instanceof Error?error.message:String(error);
    const code=KNOWN_ERROR_CODES.has(raw)?raw:'INTEGRATION_REJECTED'; // D3/D4 discipline: never echo raw runtime messages
    const status=code==='INTEGRATION_REJECTED'&&!KNOWN_ERROR_CODES.has(raw)?500:statusForError(code);
    return sendJson(res,status,{error:code,transferId:transferIdHint,accepted:false});
  }
}
