'use strict';
// Actual product repository: no listener, credentials, schema changes or IO on import.
// Caller authenticates JWT + temporary-key proof before invoking these methods.
const proof=require('./ephemeral-attempt-v1/device-proof.cjs');
const policy=require('./product-model-stream-policy.cjs');
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
module.exports=function({pool,sessionLifetimeMs}){
 const tables=require('./product-stream-users.cjs')({pool}),stream=policy.stream(tables);
 async function transaction(auth,work){
  need(auth&&Number.isSafeInteger(auth.fileId)&&auth.fileId>0&&typeof auth.email==='string'&&typeof auth.sessionId==='string','STREAM_AUTH');
  const c=await pool.connect();try{await c.query('BEGIN');
   // This lock assigns durable accepted order across API processes. No in-memory FIFO.
   const h=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1 FOR UPDATE',[auth.fileId])).rows[0];need(h,'STREAM_BASELINE_NOT_READY');
   need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[h.project_id,auth.email])).rowCount===1,'STREAM_MEMBERSHIP');
   const s=(await c.query('SELECT s.key_digest,p.* FROM bimchat_direct_ownership.model_stream_sessions s JOIN bimchat_direct_ownership.model_stream_participants p USING(participant_id) WHERE s.session_id=$1 AND p.file_id=$2 AND p.email=$3 AND s.revoked=false AND s.expires_at>clock_timestamp() FOR UPDATE OF s,p',[auth.sessionId,auth.fileId,auth.email])).rows[0];
   need(s&&s.key_digest===auth.keyDigest,'STREAM_SESSION');
   need(s.epoch===h.epoch&&Number.isSafeInteger(Number(s.applied_sequence))&&Number(s.applied_sequence)>=0&&Number(s.applied_sequence)<=Number(h.sequence),'STREAM_CURSOR');
   const result=await work(c,h,s);await c.query('COMMIT');return result;
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async function submit(auth,body){return transaction(auth,async(c,h,s)=>{
  const digest=proof.hash(body),p=body&&body.patch;need(p&&body.epoch===h.epoch,'STREAM_SOURCE_EPOCH');
  const old=(await c.query('SELECT file_id,sequence,source_participant,digest FROM bimchat_direct_ownership.model_stream_operations WHERE operation_id=$1',[p.OperationId])).rows[0];
  // A renewed key may query an identical completed submission from its own
  // participant. It may not introduce new data signed for an old session.
  if(old){need(old.file_id===auth.fileId&&old.source_participant===s.participant_id&&old.digest===digest,'STREAM_OPERATION_ID_REUSED');return {accepted:true,sequence:Number(old.sequence),duplicate:true};}
  need(p.SourceSession===auth.sessionId,'STREAM_SOURCE_EPOCH');
  need(Number(s.applied_sequence)===Number(h.sequence),'STREAM_CATCHUP_REQUIRED');
  need(p.PreviousSequence===Number(h.sequence)&&p.Sequence===Number(h.sequence)+1,'STREAM_BASE_REVISION_CHANGED');
  const next=await stream.next(c,auth.fileId,h.head,body);need(await stream.compatible(c,auth.fileId,s.local_pins,{files:p.Files.map(f=>({name:f.Name,length:f.PreLength,sha256:f.PreHash})),users:body.usersBefore}),'STREAM_SOURCE_BASELINE');
  const sequence=Number(h.sequence)+1;need(Number.isSafeInteger(sequence),'STREAM_SEQUENCE_BOUND');
  await c.query('INSERT INTO bimchat_direct_ownership.model_stream_operations(file_id,sequence,operation_id,source_session,digest,payload,source_participant,result_pins) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[auth.fileId,sequence,p.OperationId,auth.sessionId,digest,JSON.stringify(body),s.participant_id,JSON.stringify(next)]);
  await c.query('UPDATE bimchat_direct_ownership.model_streams SET sequence=$2,head=$3 WHERE file_id=$1',[auth.fileId,sequence,JSON.stringify(next)]);
  const local={files:p.Files.map(f=>({name:f.Name,length:f.PostLength,sha256:f.PostHash})),users:body.usersAfter};
  await c.query('UPDATE bimchat_direct_ownership.model_stream_participants SET applied_sequence=$2,local_pins=$3 WHERE participant_id=$1',[s.participant_id,sequence,JSON.stringify(local)]);
  // No receiver is required. This source already performed the native change.
  return {accepted:true,sequence,duplicate:false};
 });}
 async function pending(auth){return transaction(auth,async(c,h,s)=>{
  // A complete published baseline supersedes earlier deltas for catch-up. Keep
  // history, but avoid requiring an offline PC to install obsolete centrals.
  const latest=(await c.query("SELECT sequence,operation_id,digest,payload FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND sequence>$2 AND payload->>'kind'='sync-baseline' ORDER BY sequence DESC LIMIT 1",[auth.fileId,s.applied_sequence])).rows;
  const rows=latest.length?latest:(await c.query('SELECT sequence,operation_id,digest,payload FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND sequence>$2 ORDER BY sequence LIMIT 1',[auth.fileId,s.applied_sequence])).rows;
  if(latest.length){rows[0]={...rows[0],catchup_from:Number(s.applied_sequence),catchup_pins:s.local_pins};}
  return {epoch:h.epoch,headSequence:Number(h.sequence),appliedSequence:Number(s.applied_sequence),operation:rows[0]||null};
 });}
 async function acknowledge(auth,body){return transaction(auth,async(c,h,s)=>{
  need(body&&Object.keys(body).sort().join(',')==='digest,operationId,pins,sequence','STREAM_RECEIPT_FIELDS');policy.pins(body.pins);
  const op=(await c.query('SELECT sequence,digest,payload FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND operation_id=$2',[auth.fileId,body.operationId])).rows[0];
  need(op&&Number(op.sequence)===body.sequence&&op.digest===body.digest,'STREAM_RECEIPT_OPERATION');
  const old=(await c.query('SELECT receipt FROM bimchat_direct_ownership.model_stream_receipts WHERE participant_id=$1 AND operation_id=$2',[s.participant_id,body.operationId])).rows[0];
  if(old){need(proof.canonical(old.receipt)===proof.canonical(body),'STREAM_RECEIPT_REUSED');return {acknowledged:true,duplicate:true};}
  need(body.sequence===Number(s.applied_sequence)+1||(op.payload.kind==='sync-baseline'&&body.sequence>Number(s.applied_sequence)),'STREAM_RECEIPT_ORDER');
  const p=op.payload.patch,expected=op.payload.kind==='sync-baseline'?op.payload.afterPins:{files:p.Files.map(f=>({name:f.Name,length:f.PostLength,sha256:f.PostHash})),users:op.payload.usersAfter};
  await stream.receipt(c,auth.fileId,s.local_pins,body.pins,expected);
  await c.query('INSERT INTO bimchat_direct_ownership.model_stream_receipts(participant_id,operation_id,receipt) VALUES($1,$2,$3)',[s.participant_id,body.operationId,JSON.stringify(body)]);
  await c.query('UPDATE bimchat_direct_ownership.model_stream_participants SET applied_sequence=$2,local_pins=$3 WHERE participant_id=$1',[s.participant_id,body.sequence,JSON.stringify(body.pins)]);
  return {acknowledged:true,duplicate:false};
 });}
 // JWT, approved build binding and possession of this public key must be
 // verified by the HTTP adapter before calling join. No Revit/peer presence.
 async function join(auth,body){
  const crypto=require('node:crypto');
  need(auth&&Number.isSafeInteger(auth.fileId)&&auth.fileId>0&&typeof auth.email==='string'&&/^[a-f0-9-]{36}$/i.test(auth.deviceId)&&/^[a-f0-9-]{36}$/i.test(auth.sessionId),'STREAM_JOIN_AUTH');
  need(Number.isSafeInteger(sessionLifetimeMs)&&sessionLifetimeMs>0,'STREAM_KEY_LIFETIME_CONFIG');
  need(body&&Object.keys(body).sort().join(',')==='epoch,lastAppliedSequence,pins,publicJwk','STREAM_JOIN_FIELDS');policy.pins(body.pins);
  need(body.publicJwk&&body.publicJwk.kty==='RSA'&&!['d','p','q','dp','dq','qi','oth'].some(k=>k in body.publicJwk),'STREAM_PUBLIC_KEY_ONLY');
  const key=crypto.createPublicKey({key:body.publicJwk,format:'jwk'});
  need(key.asymmetricKeyType==='rsa'&&key.asymmetricKeyDetails.modulusLength>=3072,'STREAM_KEY_SIZE');
  const digest=policy.sha(key.export({type:'spki',format:'der'}));need(digest===auth.keyDigest,'STREAM_KEY_PIN');
  const c=await pool.connect();try{await c.query('BEGIN');
   const h=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1 FOR UPDATE',[auth.fileId])).rows[0];need(h,'STREAM_BASELINE_NOT_READY');
   need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[h.project_id,auth.email])).rowCount===1,'STREAM_MEMBERSHIP');
   need(body.epoch===h.epoch,'STREAM_JOIN_EPOCH');
   const previous=(await c.query('SELECT * FROM bimchat_direct_ownership.model_stream_participants WHERE file_id=$1 AND email=$2 AND device_id=$3 FOR UPDATE',[auth.fileId,auth.email,auth.deviceId])).rows[0];
   let sequence=body.lastAppliedSequence;
   if(previous){
    // Renewing a key never discards or fabricates this participant's cursor.
    need(previous.epoch===h.epoch&&(sequence===null||sequence===Number(previous.applied_sequence)),'STREAM_JOIN_CURSOR');
    need(await stream.compatible(c,auth.fileId,previous.local_pins,body.pins),'STREAM_JOIN_LOCAL_STATE');
    await stream.append(c,auth.fileId,previous.local_pins.users,body.pins.users);sequence=Number(previous.applied_sequence);
   }else{
    const matches=[];
    if(sequence===null||sequence===0)matches.push({sequence:0,result_pins:h.baseline});
    if(sequence===null||sequence===Number(h.sequence))matches.unshift({sequence:Number(h.sequence),result_pins:h.head});
    if(sequence!==0&&sequence!==Number(h.sequence)){
     need(sequence===null||(Number.isSafeInteger(sequence)&&sequence>0&&sequence<=Number(h.sequence)),'STREAM_JOIN_CURSOR');
     const rows=(await c.query("SELECT sequence,result_pins FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND ($2::bigint IS NULL OR sequence=$2) AND (result_pins->'files')-0=($3::jsonb->'files')-0 ORDER BY sequence DESC",[auth.fileId,sequence,JSON.stringify(body.pins)])).rows;matches.push(...rows);
    }
    let match;for(const row of matches.sort((a,b)=>Number(b.sequence)-Number(a.sequence))){try{if(await stream.compatible(c,auth.fileId,row.result_pins,body.pins)){match=row;break;}}catch(e){if(!/^(USERS_|STREAM_)/.test(e.message))throw e;}}
    need(match,'STREAM_JOIN_BASELINE_MISMATCH');sequence=Number(match.sequence);
   }
   const participant=previous?previous.participant_id:crypto.randomUUID();
   const existing=(await c.query('SELECT participant_id,key_digest,revoked,expires_at FROM bimchat_direct_ownership.model_stream_sessions WHERE session_id=$1 FOR UPDATE',[auth.sessionId])).rows[0];
   if(existing){need(existing.participant_id===participant&&existing.key_digest===digest&&!existing.revoked,'STREAM_JOIN_SESSION_REUSED');await c.query('COMMIT');return {participantId:participant,epoch:h.epoch,appliedSequence:sequence,headSequence:Number(h.sequence),expiresAt:+new Date(existing.expires_at),duplicate:true};}
   if(!previous)await c.query('INSERT INTO bimchat_direct_ownership.model_stream_participants(participant_id,file_id,email,device_id,epoch,applied_sequence,local_pins) VALUES($1,$2,$3,$4,$5,$6,$7)',[participant,auth.fileId,auth.email,auth.deviceId,h.epoch,sequence,JSON.stringify(body.pins)]);
   else await c.query('UPDATE bimchat_direct_ownership.model_stream_participants SET local_pins=$2 WHERE participant_id=$1',[participant,JSON.stringify(body.pins)]);
   const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now),expires=now+sessionLifetimeMs;need(Number.isSafeInteger(expires),'STREAM_KEY_LIFETIME_CONFIG');
   // Only this participant's prior key is retired, never another user's session.
   await c.query('UPDATE bimchat_direct_ownership.model_stream_sessions SET revoked=true WHERE participant_id=$1 AND revoked=false',[participant]);
   await c.query('INSERT INTO bimchat_direct_ownership.model_stream_sessions(session_id,participant_id,public_key,key_digest,expires_at) VALUES($1,$2,$3,$4,$5)',[auth.sessionId,participant,JSON.stringify(body.publicJwk),digest,new Date(expires)]);
   await c.query('COMMIT');return {participantId:participant,epoch:h.epoch,appliedSequence:sequence,headSequence:Number(h.sequence),expiresAt:expires,duplicate:false};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 return {join,submit,pending,acknowledge};
};
