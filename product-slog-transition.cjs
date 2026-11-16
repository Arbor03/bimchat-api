'use strict';
// Explicit offline transition only. Not mounted as an endpoint; importing this
// module performs no IO. Both PCs must be quiesced and the exact review approved.
const crypto=require('node:crypto'),proof=require('./ephemeral-attempt-v1/device-proof.cjs');
const scope=require('./scoped-api-v11/scope.cjs'),{need}=scope;
const legacy=require('./product-model-stream-policy.cjs'),logPolicy=require('./product-slog-policy.cjs');
const equal=(a,b)=>proof.canonical(a)===proof.canonical(b);
function five(p){const result={files:p.files.slice(0,5),users:p.users};legacy.pins(result);return result;}
function validate(review,digest){
 need(review&&review.offlineSplitApproved===true&&proof.hash(review)===digest,'STREAM_SLOG_TRANSITION_REVIEW');
 need(Number.isSafeInteger(review.fileId)&&review.fileId>0&&Number.isSafeInteger(review.projectId)&&review.projectId>0&&Number.isSafeInteger(review.sequence)&&review.sequence>=0,'STREAM_SLOG_TRANSITION_SCOPE');
 logPolicy.uuid(review.epoch);need(typeof review.centralPath==='string'&&/\.rvt$/i.test(review.centralPath),'STREAM_SLOG_TRANSITION_MODEL');
 const model=review.centralPath.replace(/\\/g,'/').split('/').pop(),native=require('./product-native-stream-policy.cjs')(null,model);native.pins(review.head);
 need(Array.isArray(review.participants)&&review.participants.length>0,'STREAM_SLOG_TRANSITION_PARTICIPANTS');const ids=new Set();
 for(const p of review.participants){logPolicy.uuid(p.id);need(!ids.has(p.id),'STREAM_SLOG_TRANSITION_PARTICIPANTS');ids.add(p.id);native.pins(p.pins);need(p.pins.files.slice(1).every((f,i)=>equal(f,review.head.files[i+1])),'STREAM_SLOG_TRANSITION_DIVERGED');}
 const acceptedPin={length:review.head.files[5].length,sha256:review.head.files[5].sha256};let pin=acceptedPin;
 if(review.logSeed!==undefined){
  const seed=review.logSeed;need(seed&&Object.keys(seed).sort().join(',')==='appendOnly,pin,sourceParticipantId'&&seed.appendOnly===true&&ids.has(seed.sourceParticipantId),'STREAM_SLOG_TRANSITION_SEED');
  logPolicy.pin(seed.pin);need(seed.pin.length>acceptedPin.length,'STREAM_SLOG_TRANSITION_APPEND');pin=seed.pin;
 }
 return {model,pin,acceptedPin};
}
async function prepare({pool,review,approvedDigest,openLog}){
 const {pin,acceptedPin}=validate(review,approvedDigest);review=JSON.parse(proof.canonical(review));need(typeof openLog==='function','STREAM_SLOG_TRANSITION_SOURCE');
 const c=await pool.connect();try{
  await c.query('BEGIN');await c.query("SET LOCAL lock_timeout='3s'");await c.query("SET LOCAL statement_timeout='30s'");
  await scope.lock(c,review.projectId);await c.query('SELECT pg_advisory_xact_lock(194811,$1)',[review.fileId]);
  const h=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1 FOR UPDATE',[review.fileId])).rows[0];
  need(h&&h.project_id===review.projectId&&h.epoch===review.epoch&&Number(h.sequence)===review.sequence&&h.native_gate_enabled===true,'STREAM_SLOG_TRANSITION_HEAD');
  const catalog=(await c.query('SELECT project_id,relative_path FROM cloud_files WHERE id=$1',[review.fileId])).rows[0];need(catalog&&catalog.project_id===review.projectId&&scope.equal(catalog.relative_path,review.centralPath),'STREAM_SLOG_TRANSITION_MODEL');
  const old=(await c.query('SELECT * FROM bimchat_direct_ownership.slog_transitions WHERE file_id=$1',[review.fileId])).rows[0];
  if(old){need(old.review_digest===approvedDigest&&equal(h.head,five(review.head)),'STREAM_SLOG_TRANSITION_CHANGED');const log=(await c.query('SELECT * FROM bimchat_direct_ownership.slog_streams WHERE file_id=$1',[review.fileId])).rows[0];need(log&&log.epoch===review.epoch&&Number(log.ownership_start_sequence)===review.sequence&&equal(log.baseline,pin),'STREAM_SLOG_TRANSITION_CHANGED');await c.query('COMMIT');return {prepared:true,duplicate:true};}
  need(equal(h.head,review.head),'STREAM_SLOG_TRANSITION_PREIMAGE');
  need(!(await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[review.fileId])).rowCount,'STREAM_SLOG_TRANSITION_SYNC');
  need(!(await c.query("SELECT 1 FROM bimchat_direct_ownership.model_stream_inbox WHERE file_id=$1 AND state='queued' LIMIT 1",[review.fileId])).rowCount,'STREAM_SLOG_TRANSITION_QUEUE');
  need(!(await c.query("SELECT 1 FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND state<>'completed' LIMIT 1",[review.fileId])).rowCount,'STREAM_SLOG_TRANSITION_ADMISSION');
  need(!(await c.query('SELECT 1 FROM bimchat_direct_ownership.model_stream_sessions s JOIN bimchat_direct_ownership.model_stream_participants p USING(participant_id) WHERE p.file_id=$1 AND s.revoked=false AND s.expires_at>clock_timestamp() LIMIT 1',[review.fileId])).rowCount,'STREAM_SLOG_TRANSITION_SESSION');
  const participants=(await c.query('SELECT * FROM bimchat_direct_ownership.model_stream_participants WHERE file_id=$1 FOR UPDATE',[review.fileId])).rows;
  need(participants.length===review.participants.length,'STREAM_SLOG_TRANSITION_PARTICIPANTS');
  const users=require('./product-stream-users.cjs')({pool});
  for(const p of participants){const wanted=review.participants.find(x=>x.id===p.participant_id);need(wanted&&p.epoch===review.epoch&&Number(p.applied_sequence)===review.sequence&&equal(p.local_pins,wanted.pins),'STREAM_SLOG_TRANSITION_PARTICIPANT');await users.merge(c,review.fileId,h.head.users,p.local_pins.users);}
  await c.query('INSERT INTO bimchat_direct_ownership.slog_streams(file_id,epoch,ownership_start_sequence,baseline,head) VALUES($1,$2,$3,$4,$4)',[review.fileId,review.epoch,review.sequence,pin]);
  const source=await openLog();need(source&&source[Symbol.asyncIterator]&&typeof source.destroy==='function','STREAM_SLOG_TRANSITION_SOURCE');let length=0,offset=0,pending=Buffer.alloc(0),prefixRemaining=acceptedPin.length;const hash=crypto.createHash('sha256'),prefix=crypto.createHash('sha256');
  try{for await(const raw of source){need(Buffer.isBuffer(raw),'STREAM_SLOG_TRANSITION_BYTES');length+=raw.length;need(length<=pin.length,'STREAM_SLOG_TRANSITION_BYTES');hash.update(raw);const count=Math.min(prefixRemaining,raw.length);prefix.update(raw.subarray(0,count));prefixRemaining-=count;let block=Buffer.concat([pending,raw]);while(block.length>=262144){await c.query('INSERT INTO bimchat_direct_ownership.slog_extents(file_id,sequence,byte_offset,bytes) VALUES($1,0,$2,$3)',[review.fileId,offset,block.subarray(0,262144)]);offset+=262144;block=block.subarray(262144);}pending=Buffer.from(block);}
   if(pending.length)await c.query('INSERT INTO bimchat_direct_ownership.slog_extents(file_id,sequence,byte_offset,bytes) VALUES($1,0,$2,$3)',[review.fileId,offset,pending]);
  }finally{source.destroy();}
  need(length===pin.length&&hash.digest('hex').toUpperCase()===pin.sha256,'STREAM_SLOG_TRANSITION_HASH');
  need(prefixRemaining===0&&prefix.digest('hex').toUpperCase()===acceptedPin.sha256,'STREAM_SLOG_TRANSITION_PREFIX');
  for(const p of participants){await c.query('INSERT INTO bimchat_direct_ownership.slog_participants(participant_id,file_id,applied_sequence,pin) VALUES($1,$2,0,$3)',[p.participant_id,review.fileId,pin]);await c.query('UPDATE bimchat_direct_ownership.model_stream_participants SET local_pins=$2 WHERE participant_id=$1',[p.participant_id,five(p.local_pins)]);}
  // No accepted operation, receipt, epoch or ownership sequence is removed/reset.
  await c.query('UPDATE bimchat_direct_ownership.model_streams SET head=$2,baseline=$3 WHERE file_id=$1',[review.fileId,five(h.head),five(h.baseline)]);
  await c.query('UPDATE bimchat_direct_ownership.model_stream_sessions SET revoked=true WHERE participant_id IN (SELECT participant_id FROM bimchat_direct_ownership.model_stream_participants WHERE file_id=$1)',[review.fileId]);
  await c.query('INSERT INTO bimchat_direct_ownership.slog_transitions(file_id,review_digest,review) VALUES($1,$2,$3)',[review.fileId,approvedDigest,review]);
  await c.query('COMMIT');return {prepared:true,duplicate:false,epoch:review.epoch,ownershipSequence:review.sequence,logSequence:0,splitLog:{ownershipSequence:review.sequence,logPin:pin}};
 }catch(error){await c.query('ROLLBACK');throw error;}finally{c.release();}
}
module.exports={validate,five,prepare};
