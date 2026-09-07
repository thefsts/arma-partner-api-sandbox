import { verifyIntegrationRequest, signReceipt } from './_integrationSecurity.js';

function sendJson(res,status,body,extraHeaders={}) { res.statusCode=status; res.setHeader('Content-Type','application/json'); res.setHeader('Cache-Control','no-store'); res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Referrer-Policy','no-referrer'); res.setHeader('X-Frame-Options','DENY'); for(const [k,v] of Object.entries(extraHeaders)) res.setHeader(k,v); res.end(JSON.stringify(body)); }
async function readRawBody(req){const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>1024*1024)throw new Error('PAYLOAD_TOO_LARGE');chunks.push(chunk);}return Buffer.concat(chunks).toString('utf8');}
function statusForError(code){if(code==='PAYLOAD_TOO_LARGE')return 413;if(['INTEGRATION_DISABLED','INTEGRATION_NOT_CONFIGURED','RECEIPT_SIGNING_NOT_CONFIGURED'].includes(code))return 503;if(['RECORD_TYPE_NOT_ALLOWED','SCHEMA_VERSION_UNSUPPORTED'].includes(code))return 422;if(['TRANSFER_EXPIRED','STALE_OR_FUTURE_REQUEST'].includes(code))return 409;if(code.startsWith('INVALID_FIELD_')||['INVALID_JSON','INVALID_TIMESTAMPS','INVALID_TIME_ORDER'].includes(code))return 400;return 401;}

export default async function handler(req,res){
  if(req.method!=='POST'){res.setHeader('Allow','POST');return sendJson(res,405,{error:'METHOD_NOT_ALLOWED',accepted:false});}
  if(!String(req.headers['content-type']??'').toLowerCase().startsWith('application/json'))return sendJson(res,415,{error:'CONTENT_TYPE_NOT_ALLOWED',accepted:false});
  try{
    const rawBody=await readRawBody(req); const verified=verifyIntegrationRequest({rawBody,headers:req.headers});
    const processorUrl=process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_URL, processorToken=process.env.LAW_SHIELD_INTEGRATION_PROCESSOR_TOKEN;
    if(!processorUrl||!processorToken)return sendJson(res,503,{error:'INTEGRATION_PROCESSOR_NOT_CONFIGURED',transferId:verified.envelope.transferId,accepted:false});
    const upstream=await fetch(processorUrl,{method:'POST',headers:{'content-type':'application/json','authorization':`Bearer ${processorToken}`,'x-verified-arma-nonce':verified.nonce,'x-verified-arma-content-sha256':verified.bodyHash,'x-integration-schema-version':verified.envelope.schemaVersion,'x-integration-transfer-id':verified.envelope.transferId},body:rawBody,signal:AbortSignal.timeout(10_000)});
    const resultText=await upstream.text();let result;try{result=JSON.parse(resultText);}catch{result={error:'PROCESSOR_NON_JSON_RESPONSE'};}
    if(!upstream.ok||result?.accepted!==true||!result?.receiptId)return sendJson(res,502,{error:result?.error||'PROCESSOR_REJECTED_TRANSFER',transferId:verified.envelope.transferId,accepted:false,processorStatus:upstream.status});
    if((result.transferId&&result.transferId!==verified.envelope.transferId)||(result.payloadHash&&result.payloadHash!==verified.envelope.payloadHash))throw new Error('PROCESSOR_RECEIPT_MISMATCH');
    const receipt={schemaVersion:verified.envelope.schemaVersion,receiptId:result.receiptId,transferId:verified.envelope.transferId,idempotencyKey:verified.envelope.idempotencyKey,status:'ACCEPTED',acceptedAt:Number.isFinite(result.acceptedAt)?result.acceptedAt:Date.now(),armaOrgId:verified.envelope.armaOrgId,lawShieldOrgId:verified.envelope.lawShieldOrgId,incidentId:verified.envelope.incidentId??null,lawShieldCaseId:verified.envelope.mapping.lawShieldCaseId??null,recordType:verified.envelope.recordType,recordId:verified.envelope.recordId,receivedPayloadHash:verified.envelope.payloadHash,processingResult:result.processingResult??'PERSISTED'};
    const signed=signReceipt(receipt);return sendJson(res,200,receipt,{'X-LawShield-Content-SHA256':signed.bodyHash,'X-LawShield-Signature':signed.signature,'X-LawShield-Schema-Version':receipt.schemaVersion,'X-LawShield-Receipt-Id':receipt.receiptId});
  }catch(error){const code=error instanceof Error?error.message:'INTEGRATION_REJECTED';return sendJson(res,statusForError(code),{error:code,accepted:false});}
}
