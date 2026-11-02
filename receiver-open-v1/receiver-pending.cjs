'use strict';
const {need}=require('../ephemeral-attempt-v1/scope.cjs'),{requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs'),{canonical,digest}=require('../source-open-v1/protocol.cjs');
// One authenticated client request; bounded SELECT-only server polling, no action retry.
module.exports=function({pool,verifyPayload,wait=ms=>new Promise(r=>setTimeout(r,ms)),monotonic=()=>performance.now()}){
 need(typeof verifyPayload==='function','PENDING_INDEPENDENT_PAYLOAD_REQUIRED');
 return async function pending({id,auth,body}){need(body&&Object.keys(body).length===0,'PENDING_BODY');const start=monotonic();
 while(true){const c=await pool.connect();let result;try{await c.query('BEGIN');await c.query("SET LOCAL statement_timeout='2s'");await c.query("SET LOCAL lock_timeout='1s'");const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1',[id])).rows[0];need(row,'PENDING_UNKNOWN');const h=row.document;need(h.id===id&&h.projectId===row.project_id&&h.enabled===true&&h.receiverMode==='open-ui-turn'&&h.receiverEmail===auth.email&&h.receiverSession===auth.sessionId&&h.receiverDevice===auth.deviceId&&h.reviewDigest===auth.reviewDigest,'PENDING_BINDING');
 await requireActive(c,auth,h.projectId,h.centralPath,require('../source-open-v1/controlled-cycle.cjs').enrollmentRole(h,'receiver'));const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(Number.isSafeInteger(h.expiresAt)&&now<h.expiresAt,'PENDING_EXPIRED');
 need(['armed','receiver-ready','native-attempted','pending'].includes(h.state),'PENDING_STOPPED');if(h.state==='pending'){need(typeof h.wire==='string'&&Buffer.byteLength(h.wire)<=1048576,'PENDING_WIRE');const envelope=JSON.parse(h.wire);need(canonical(envelope)===h.wire&&digest(envelope)===h.digest&&envelope.OperationId===h.operationId,'PENDING_DIGEST');result={operationId:h.operationId,wire:h.wire,digest:h.digest,generation:h.generation,sourceSession:h.sourceSession,receiverPins:h.receiverPins,reviewDigest:h.reviewDigest,expiresAt:h.expiresAt,contentProof:await verifyPayload(c,h)};}
 await c.query('COMMIT');}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 const elapsed=monotonic()-start;need(elapsed>=0&&elapsed<7000,'PENDING_DEADLINE_NO_RETRY');if(result)return result;await wait(200);
 }
 };
};

