'use strict';
const proof=require('./ephemeral-attempt-v1/device-proof.cjs'),{need}=require('./ephemeral-attempt-v1/scope.cjs');
const protocol=require('./scoped-api-v11/direct/protocol.cjs');
// Intake and drain have separate per-model PostgreSQL locks. Slow processing
// cannot reorder committed arrivals or keep later requests only in RAM.
module.exports=function({pool,store}){
 async function enqueue(auth,body,assembled=false,reserving=false){
  need(assembled||Buffer.byteLength(proof.canonical(body))<=1048576,'STREAM_TRANSPORT_BOUND');
  protocol.validateStream(body?.patch);need(body.patch.SourceSession===auth.sessionId,'STREAM_SOURCE_EPOCH');
  const digest=proof.hash(body),c=await pool.connect();try{await c.query('BEGIN');
   await c.query('SELECT pg_advisory_xact_lock(194811, $1)',[auth.fileId]);
   const session=(await c.query('SELECT s.session_id FROM bimchat_direct_ownership.model_stream_sessions s JOIN bimchat_direct_ownership.model_stream_participants p USING(participant_id) JOIN bimchat_direct_ownership.model_streams m ON m.file_id=p.file_id JOIN project_members pm ON pm.project_id=m.project_id AND pm.user_email=p.email WHERE s.session_id=$1 AND p.file_id=$2 AND p.email=$3 AND p.device_id=$4 AND s.key_digest=$5 AND s.revoked=false AND s.expires_at>clock_timestamp()',[auth.sessionId,auth.fileId,auth.email,auth.deviceId,auth.keyDigest])).rows[0];need(session,'STREAM_SESSION');
   const old=(await c.query('SELECT * FROM bimchat_direct_ownership.model_stream_inbox WHERE operation_id=$1',[body.patch.OperationId])).rows[0];
   if(old){need(old.file_id===auth.fileId&&old.digest===digest&&old.source_auth.email===auth.email&&old.source_auth.deviceId===auth.deviceId,'STREAM_OPERATION_ID_REUSED');if(!reserving&&old.payload_ready===false)await c.query('UPDATE bimchat_direct_ownership.model_stream_inbox SET payload_ready=true WHERE arrival=$1 AND payload_ready=false',[old.arrival]);await c.query('COMMIT');return {queued:true,arrival:String(old.arrival),operationId:old.operation_id,duplicate:true};}
   const source={fileId:auth.fileId,email:auth.email,deviceId:auth.deviceId,sessionId:auth.sessionId,keyDigest:auth.keyDigest}; // public identity only; never JWT/private key
   const row=(await c.query('INSERT INTO bimchat_direct_ownership.model_stream_inbox(file_id,operation_id,digest,source_auth,payload,payload_ready) VALUES($1,$2,$3,$4,$5,$6) RETURNING arrival',[auth.fileId,body.patch.OperationId,digest,JSON.stringify(source),JSON.stringify(body),!reserving])).rows[0];
   await c.query('COMMIT');return {queued:true,arrival:String(row.arrival),operationId:body.patch.OperationId,duplicate:false};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async function drain(fileId){const c=await pool.connect();let locked=false;try{
  locked=(await c.query('SELECT pg_try_advisory_lock(194812,$1) locked',[fileId])).rows[0].locked;if(!locked)return;
  for(;;){const row=(await c.query("SELECT * FROM bimchat_direct_ownership.model_stream_inbox WHERE file_id=$1 AND state='queued' ORDER BY arrival LIMIT 1",[fileId])).rows[0];if(!row)return;
   if(row.payload_ready===false)return; // Never overtake an earlier accepted upload.
   let result;
   // Recover a committed operation whose receipt update was interrupted. Never
   // infer failure or repeat it merely because the old temporary key expired.
   const committed=(await c.query('SELECT file_id,sequence,digest FROM bimchat_direct_ownership.model_stream_operations WHERE operation_id=$1',[row.operation_id])).rows[0];
   if(committed){need(committed.file_id===fileId&&committed.digest===row.digest,'STREAM_INBOX_COMMIT_MISMATCH');result={accepted:true,sequence:Number(committed.sequence),duplicate:true};}
   else try{result=await store.submit(row.source_auth,row.payload);}catch(e){
    if(!e||typeof e.message!=='string'||!/^(STREAM|USERS)_[A-Z_]+$/.test(e.message))throw e;
    result={accepted:false,reason:e.message};
   }
   await c.query("UPDATE bimchat_direct_ownership.model_stream_inbox SET state=$2,result=$3 WHERE arrival=$1 AND state='queued'",[row.arrival,result.accepted?'accepted':'rejected',JSON.stringify(result)]);
  }
 }finally{try{if(locked)await c.query('SELECT pg_advisory_unlock(194812,$1)',[fileId]);}finally{c.release();}}}
 async function status(auth,operationId){const c=await pool.connect();try{const row=(await c.query('SELECT file_id,source_auth,arrival,state,result FROM bimchat_direct_ownership.model_stream_inbox WHERE operation_id=$1',[operationId])).rows[0];need(row&&row.file_id===auth.fileId&&row.source_auth.email===auth.email&&row.source_auth.deviceId===auth.deviceId,'STREAM_OPERATION_SCOPE');return {operationId,arrival:String(row.arrival),state:row.state,result:row.result};}finally{c.release();}}
 return {enqueue,reserve:(auth,body)=>enqueue(auth,body,true,true),drain,status};
};
