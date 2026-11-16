'use strict';
// Independent durable log order. No ownership-row lock, ownership cursor update,
// lease timeout, text merge, path argument or import-time IO.
const crypto=require('node:crypto'),p=require('./product-slog-policy.cjs');
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
const channel='bimchat_slog_changed';
module.exports=function({pool,sessionLifetimeMs}){
 need(Number.isSafeInteger(sessionLifetimeMs)&&sessionLifetimeMs>0,'STREAM_SLOG_LIFETIME');
 const one=async(c,q,v)=>(await c.query(q,v)).rows[0];
 async function head(c,a){const h=await one(c,'SELECT l.*,m.project_id FROM bimchat_direct_ownership.slog_streams l JOIN bimchat_direct_ownership.model_streams m USING(file_id) WHERE l.file_id=$1 AND l.epoch=m.epoch FOR UPDATE OF l',[a.fileId]);need(h,'STREAM_SLOG_NOT_PREPARED');p.pin(h.head);return h;}
 async function member(c,h,a){need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[h.project_id,a.email])).rowCount===1,'STREAM_MEMBERSHIP');}
 async function transaction(a,work){const c=await pool.connect();try{await c.query('BEGIN');const h=await head(c,a);await member(c,h,a);
  const s=await one(c,`SELECT lp.*,rp.email,rp.device_id FROM bimchat_direct_ownership.slog_sessions ss
   JOIN bimchat_direct_ownership.slog_participants lp USING(participant_id)
   JOIN bimchat_direct_ownership.model_stream_participants rp USING(participant_id)
   WHERE ss.session_id=$1 AND lp.file_id=$2 AND rp.email=$3 AND ss.key_digest=$4
   AND ss.revoked=false AND ss.expires_at>clock_timestamp() FOR UPDATE OF lp`,[a.sessionId,a.fileId,a.email,a.keyDigest]);
  need(s&&s.device_id===a.deviceId,'STREAM_SLOG_SESSION');need(Number(s.applied_sequence)<=Number(h.sequence),'STREAM_SLOG_CURSOR');
  const result=await work(c,h,s);await c.query('COMMIT');return result;
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
 const notify=(c,h)=>c.query('SELECT pg_notify($1,$2)',[channel,String(h.file_id)]);
 function owner(r,h,s){need(r&&r.file_id===h.file_id&&r.epoch===h.epoch&&r.participant_id===s.participant_id,'STREAM_SLOG_OWNER');return r;}
 const turn=async(c,h,s,id)=>owner(await one(c,'SELECT * FROM bimchat_direct_ownership.slog_admissions WHERE request_id=$1',[p.uuid(id)]),h,s);
 const view=(r,h)=>({requestId:r.request_id,epoch:h.epoch,state:r.state,generation:r.generation==null?null:String(r.generation),baseSequence:r.base_sequence==null?null:Number(r.base_sequence),headSequence:Number(h.sequence)});
 async function join(a,b){
  const recover=b.recoverUnadmitted===true;
  p.fields(b,Object.hasOwn(b,'recoverUnadmitted')?['epoch','pin','publicJwk','recoverUnadmitted']:['epoch','pin','publicJwk']);
  if(Object.hasOwn(b,'recoverUnadmitted'))need(typeof b.recoverUnadmitted==='boolean','STREAM_SLOG_RECOVERY_FLAG');
  p.pin(b.pin);p.uuid(a.sessionId);p.uuid(a.deviceId);
  need(b.publicJwk&&b.publicJwk.kty==='RSA'&&!['d','p','q','dp','dq','qi','oth'].some(k=>k in b.publicJwk),'STREAM_PUBLIC_KEY_ONLY');
  const key=crypto.createPublicKey({key:b.publicJwk,format:'jwk'});need(key.asymmetricKeyDetails.modulusLength>=3072&&crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex').toUpperCase()===a.keyDigest,'STREAM_KEY_PIN');
  const c=await pool.connect();try{await c.query('BEGIN');const h=await head(c,a);await member(c,h,a);need(b.epoch===h.epoch,'STREAM_SLOG_EPOCH');
   const root=await one(c,'SELECT participant_id FROM bimchat_direct_ownership.model_stream_participants WHERE file_id=$1 AND email=$2 AND device_id=$3 AND epoch=$4',[a.fileId,a.email,a.deviceId,h.epoch]);need(root,'STREAM_SLOG_OWNERSHIP_JOIN_REQUIRED');
   let participant=await one(c,'SELECT * FROM bimchat_direct_ownership.slog_participants WHERE participant_id=$1 FOR UPDATE',[root.participant_id]);
   if(participant)need(p.equal(participant.pin,b.pin),'STREAM_SLOG_LOCAL_STATE');
   else{
    let seq=p.equal(h.head,b.pin)?Number(h.sequence):p.equal(h.baseline,b.pin)?0:null;
    if(seq===null){const old=await one(c,'SELECT sequence FROM bimchat_direct_ownership.slog_operations WHERE file_id=$1 AND after_pin=$2 ORDER BY sequence DESC LIMIT 1',[a.fileId,b.pin]);seq=old?Number(old.sequence):null;}
    need(seq!==null,'STREAM_SLOG_BASELINE_MISMATCH');participant={participant_id:root.participant_id,applied_sequence:seq,pin:b.pin};
    await c.query('INSERT INTO bimchat_direct_ownership.slog_participants(participant_id,file_id,applied_sequence,pin) VALUES($1,$2,$3,$4)',[root.participant_id,a.fileId,seq,b.pin]);
   }
   const old=await one(c,'SELECT * FROM bimchat_direct_ownership.slog_sessions WHERE session_id=$1',[a.sessionId]);
   let expires;
   if(old){need(old.participant_id===root.participant_id&&old.key_digest===a.keyDigest&&!old.revoked,'STREAM_SLOG_SESSION_REUSED');expires=+new Date(old.expires_at);}
   else{expires=+new Date((await one(c,'SELECT clock_timestamp() now')).now)+sessionLifetimeMs;
    await c.query('UPDATE bimchat_direct_ownership.slog_sessions SET revoked=true WHERE participant_id=$1 AND revoked=false',[root.participant_id]);
    await c.query('INSERT INTO bimchat_direct_ownership.slog_sessions(session_id,participant_id,public_key,key_digest,expires_at) VALUES($1,$2,$3,$4,$5)',[a.sessionId,root.participant_id,b.publicJwk,a.keyDigest,new Date(expires)]);
   }
   let recoveredRequestId=null;
   if(recover){
    // Startup only, after fencing every prior session under the same log-row
    // lock used by ready(). An unadmitted turn cannot have reached native Allow.
    // Ordinary key renewal must never retire an in-flight request.
    const pending=await one(c,"SELECT * FROM bimchat_direct_ownership.slog_admissions WHERE file_id=$1 AND participant_id=$2 AND state<>'completed'",[h.file_id,root.participant_id]);
    if(pending){
     need(!old,'STREAM_SLOG_RECOVERY_SESSION');
     need(['waiting','reserved'].includes(pending.state),'STREAM_SLOG_RECOVERY_ADMITTED');
     need(!await one(c,'SELECT request_id FROM bimchat_direct_ownership.slog_uploads WHERE request_id=$1',[pending.request_id])&&!await one(c,'SELECT request_id FROM bimchat_direct_ownership.slog_operations WHERE request_id=$1',[pending.request_id]),'STREAM_SLOG_RECOVERY_ARTIFACTS');
     await c.query("UPDATE bimchat_direct_ownership.slog_admissions SET state='completed',changed=false WHERE request_id=$1",[pending.request_id]);
     recoveredRequestId=pending.request_id;await notify(c,h);
    }
   }
   await c.query('COMMIT');return {epoch:h.epoch,appliedSequence:Number(participant.applied_sequence),headSequence:Number(h.sequence),expiresAt:expires,...(recover?{startupRecovery:true,recoveredRequestId}:{})};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async function request(a,b){p.fields(b,['requestId']);p.uuid(b.requestId);return transaction(a,async(c,h,s)=>{
  let r=await one(c,'SELECT * FROM bimchat_direct_ownership.slog_admissions WHERE request_id=$1',[b.requestId]);
  if(r)owner(r,h,s);else{
   need(!await one(c,"SELECT request_id FROM bimchat_direct_ownership.slog_admissions WHERE file_id=$1 AND participant_id=$2 AND state<>'completed'",[h.file_id,s.participant_id]),'STREAM_SLOG_OUTSTANDING');
   r=await one(c,"INSERT INTO bimchat_direct_ownership.slog_admissions(request_id,file_id,epoch,participant_id,state) VALUES($1,$2,$3,$4,'waiting') RETURNING *",[b.requestId,h.file_id,h.epoch,s.participant_id]);
  }
  if(r.state==='waiting'){
   const active=await one(c,"SELECT request_id FROM bimchat_direct_ownership.slog_admissions WHERE file_id=$1 AND state IN ('reserved','admitted')",[h.file_id]);
   const first=await one(c,"SELECT request_id FROM bimchat_direct_ownership.slog_admissions WHERE file_id=$1 AND state='waiting' ORDER BY arrival LIMIT 1",[h.file_id]);
   if(!active&&first?.request_id===r.request_id){const g=await one(c,'UPDATE bimchat_direct_ownership.slog_streams SET generation=generation+1 WHERE file_id=$1 RETURNING generation',[h.file_id]);r=await one(c,"UPDATE bimchat_direct_ownership.slog_admissions SET state='reserved',generation=$2,base_sequence=$3 WHERE request_id=$1 RETURNING *",[r.request_id,g.generation,h.sequence]);}
  }return view(r,h);
 });}
 async function ready(a,b){p.fields(b,['requestId','generation']);p.generation(b.generation);return transaction(a,async(c,h,s)=>{
  const r=await turn(c,h,s,b.requestId);need(['reserved','admitted'].includes(r.state)&&String(r.generation)===b.generation,'STREAM_SLOG_GENERATION');
  need(Number(r.base_sequence)===Number(h.sequence)&&Number(s.applied_sequence)===Number(h.sequence)&&p.equal(s.pin,h.head),'STREAM_SLOG_CATCHUP_REQUIRED');
  await c.query("UPDATE bimchat_direct_ownership.slog_admissions SET state='admitted' WHERE request_id=$1",[r.request_id]);return view({...r,state:'admitted'},h);
 });}
 async function begin(a,b){p.descriptor(b);return transaction(a,async(c,h,s)=>{
  const r=await turn(c,h,s,b.requestId);need(String(r.generation)===b.generation,'STREAM_SLOG_GENERATION');
  const old=await one(c,'SELECT * FROM bimchat_direct_ownership.slog_uploads WHERE request_id=$1',[r.request_id]);
  if(old){need(old.digest===p.digest(b),'STREAM_SLOG_REUSED');return {prepared:true};}
  need(r.state==='admitted'&&Number(r.base_sequence)===Number(h.sequence)&&Number(s.applied_sequence)===Number(h.sequence)&&p.equal(b.before,h.head)&&p.equal(s.pin,h.head),'STREAM_SLOG_PREIMAGE');
  await c.query('INSERT INTO bimchat_direct_ownership.slog_uploads(request_id,document,digest) VALUES($1,$2,$3)',[r.request_id,b,p.digest(b)]);return {prepared:true};
 });}
 async function put(a,b){p.fields(b,['requestId','index','bytes']);return transaction(a,async(c,h,s)=>{
  const r=await turn(c,h,s,b.requestId),u=await one(c,'SELECT document FROM bimchat_direct_ownership.slog_uploads WHERE request_id=$1',[r.request_id]);need(u,'STREAM_SLOG_UPLOAD');
  const bytes=p.chunk(b,u.document.after.length-u.document.before.length);
  await c.query('INSERT INTO bimchat_direct_ownership.slog_upload_chunks(request_id,part,bytes) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[r.request_id,b.index,bytes]);
  need((await one(c,'SELECT bytes FROM bimchat_direct_ownership.slog_upload_chunks WHERE request_id=$1 AND part=$2',[r.request_id,b.index])).bytes.equals(bytes),'STREAM_SLOG_CHUNK_CHANGED');return {stored:true,index:b.index};
 });}
 async function committedHash(c,file,sequence,expected,hash){
  let offset=0;
  while(offset<expected.length){const rows=(await c.query('SELECT byte_offset,bytes FROM bimchat_direct_ownership.slog_extents WHERE file_id=$1 AND sequence<=$2 AND byte_offset>=$3 ORDER BY byte_offset LIMIT 32',[file,sequence,offset])).rows;need(rows.length,'STREAM_SLOG_INCOMPLETE');
   for(const row of rows){need(Number(row.byte_offset)===offset&&row.bytes.length>0&&offset+row.bytes.length<=expected.length,'STREAM_SLOG_EXTENT');hash.update(row.bytes);offset+=row.bytes.length;}
  }need(hash.copy().digest('hex').toUpperCase()===expected.sha256,'STREAM_SLOG_PREIMAGE');
 }
 async function commit(a,b){p.fields(b,['requestId']);return transaction(a,async(c,h,s)=>{
  const r=await turn(c,h,s,b.requestId),old=await one(c,'SELECT * FROM bimchat_direct_ownership.slog_operations WHERE request_id=$1',[r.request_id]);
  if(old)return {accepted:true,sequence:Number(old.sequence),pin:old.after_pin};
  const u=await one(c,'SELECT document FROM bimchat_direct_ownership.slog_uploads WHERE request_id=$1',[r.request_id]);need(u,'STREAM_SLOG_UPLOAD');const doc=u.document;p.descriptor(doc);
  need(r.state==='admitted'&&Number(r.base_sequence)===Number(h.sequence)&&Number(s.applied_sequence)===Number(h.sequence)&&p.equal(h.head,doc.before),'STREAM_SLOG_PREIMAGE');
  const full=crypto.createHash('sha256'),tail=crypto.createHash('sha256');await committedHash(c,h.file_id,Number(h.sequence),h.head,full);
  const length=doc.after.length-doc.before.length,sequence=Number(h.sequence)+1;need(Number.isSafeInteger(sequence),'STREAM_SEQUENCE_BOUND');
  for(let index=0,at=0;at<length;index++){
   const row=await one(c,'SELECT bytes FROM bimchat_direct_ownership.slog_upload_chunks WHERE request_id=$1 AND part=$2',[r.request_id,index]);need(row&&row.bytes.length===Math.min(p.block,length-at),'STREAM_SLOG_INCOMPLETE');
   tail.update(row.bytes);full.update(row.bytes);await c.query('INSERT INTO bimchat_direct_ownership.slog_extents(file_id,sequence,byte_offset,bytes) VALUES($1,$2,$3,$4)',[h.file_id,sequence,doc.before.length+at,row.bytes]);at+=row.bytes.length;
  }
  need(tail.digest('hex').toUpperCase()===doc.appendHash&&full.digest('hex').toUpperCase()===doc.after.sha256,'STREAM_SLOG_HASH');
  await c.query('INSERT INTO bimchat_direct_ownership.slog_operations(file_id,sequence,request_id,source_participant,before_pin,after_pin,append_hash) VALUES($1,$2,$3,$4,$5,$6,$7)',[h.file_id,sequence,r.request_id,s.participant_id,doc.before,doc.after,doc.appendHash]);
  await c.query('UPDATE bimchat_direct_ownership.slog_streams SET sequence=$2,head=$3 WHERE file_id=$1',[h.file_id,sequence,doc.after]);
  await c.query('UPDATE bimchat_direct_ownership.slog_participants SET applied_sequence=$2,pin=$3 WHERE participant_id=$1',[s.participant_id,sequence,doc.after]);await notify(c,h);
  return {accepted:true,sequence,pin:doc.after};
 });}
 async function complete(a,b){p.fields(b,['requestId','generation','changed']);p.generation(b.generation);need(typeof b.changed==='boolean','STREAM_SLOG_CHANGED');return transaction(a,async(c,h,s)=>{
  const r=await turn(c,h,s,b.requestId);need(String(r.generation)===b.generation,'STREAM_SLOG_GENERATION');
  if(r.state==='completed'){need(r.changed===b.changed,'STREAM_SLOG_REUSED');return view(r,h);}need(r.state==='admitted','STREAM_SLOG_STATE');
  const op=await one(c,'SELECT * FROM bimchat_direct_ownership.slog_operations WHERE request_id=$1',[r.request_id]);
  need(Number(s.applied_sequence)===Number(h.sequence)&&(b.changed?op&&Number(op.sequence)===Number(r.base_sequence)+1&&Number(op.sequence)===Number(h.sequence):!op&&Number(h.sequence)===Number(r.base_sequence)),'STREAM_SLOG_NOT_PUBLISHED');
  await c.query("UPDATE bimchat_direct_ownership.slog_admissions SET state='completed',changed=$2 WHERE request_id=$1",[r.request_id,b.changed]);await notify(c,h);return view({...r,state:'completed'},h);
 });}
 async function pending(a,b){p.fields(b,[]);return transaction(a,async(c,h,s)=>({epoch:h.epoch,headSequence:Number(h.sequence),appliedSequence:Number(s.applied_sequence),pin:s.pin,operation:await one(c,'SELECT * FROM bimchat_direct_ownership.slog_operations WHERE file_id=$1 AND sequence=$2',[h.file_id,Number(s.applied_sequence)+1])||null}));}
 async function image(c,h,sequence){
  need(Number.isSafeInteger(sequence)&&sequence>=0&&sequence<=Number(h.sequence),'STREAM_SLOG_RANGE');
  if(sequence===0)return {pin:h.baseline,operationId:null};
  const op=await one(c,'SELECT after_pin,request_id FROM bimchat_direct_ownership.slog_operations WHERE file_id=$1 AND sequence=$2',[h.file_id,sequence]);
  need(op,'STREAM_SLOG_RANGE');p.pin(op.after_pin);return {pin:op.after_pin,operationId:op.request_id};
 }
 async function catchupBoundary(c,h,s,sequence){
  const active=await one(c,"SELECT state,base_sequence FROM bimchat_direct_ownership.slog_admissions WHERE file_id=$1 AND participant_id=$2 AND state IN ('reserved','admitted')",[h.file_id,s.participant_id]);
  need(!active||active.state!=='admitted','STREAM_SLOG_CATCHUP_ADMITTED');
  need(!active||sequence<=Number(active.base_sequence),'STREAM_SLOG_CATCHUP_BOUNDARY');
 }
 // A fixed immutable target, not a mutable latest-file URL. History is retained.
 async function catchup(a,b){p.fields(b,['targetSequence']);return transaction(a,async(c,h,s)=>{
  const sequence=b.targetSequence===null?Number(h.sequence):b.targetSequence;
  need(Number.isSafeInteger(sequence)&&sequence>=Number(s.applied_sequence),'STREAM_SLOG_CATCHUP_ORDER');
  await catchupBoundary(c,h,s,sequence);const target=await image(c,h,sequence);
  need(target.pin.length>=s.pin.length,'STREAM_SLOG_APPEND_ONLY');
  return {epoch:h.epoch,appliedSequence:Number(s.applied_sequence),pin:s.pin,headSequence:Number(h.sequence),targetSequence:sequence,targetPin:target.pin,operationId:target.operationId};
 });}
 async function catchupAck(a,b){p.fields(b,['fromSequence','fromPin','sequence','pin','operationId']);p.pin(b.fromPin);p.pin(b.pin);return transaction(a,async(c,h,s)=>{
  need(Number.isSafeInteger(b.fromSequence)&&b.fromSequence>=0&&Number.isSafeInteger(b.sequence)&&b.sequence>b.fromSequence,'STREAM_SLOG_CATCHUP_ORDER');
  const before=await image(c,h,b.fromSequence),target=await image(c,h,b.sequence);
  need(p.equal(before.pin,b.fromPin)&&p.equal(target.pin,b.pin)&&target.operationId===b.operationId&&target.pin.length>=before.pin.length,'STREAM_SLOG_CATCHUP_RECEIPT');
  // Lost responses may repeat only the same immutable result; never regress.
  if(Number(s.applied_sequence)===b.sequence){need(p.equal(s.pin,b.pin),'STREAM_SLOG_RECEIPT_REUSED');return {acknowledged:true,sequence:b.sequence};}
  need(Number(s.applied_sequence)===b.fromSequence&&p.equal(s.pin,b.fromPin),'STREAM_SLOG_CATCHUP_CURSOR');
  await catchupBoundary(c,h,s,b.sequence);
  await c.query('UPDATE bimchat_direct_ownership.slog_participants SET applied_sequence=$2,pin=$3 WHERE participant_id=$1',[s.participant_id,b.sequence,b.pin]);
  return {acknowledged:true,sequence:b.sequence};
 });}
 async function get(a,b){p.fields(b,['sequence','offset']);need(Number.isSafeInteger(b.sequence)&&b.sequence>=0&&Number.isSafeInteger(b.offset)&&b.offset>=0,'STREAM_SLOG_RANGE');return transaction(a,async(c,h)=>{
  need(b.sequence<=Number(h.sequence),'STREAM_SLOG_RANGE');const pin=b.sequence===0?h.baseline:(await one(c,'SELECT after_pin FROM bimchat_direct_ownership.slog_operations WHERE file_id=$1 AND sequence=$2',[h.file_id,b.sequence]))?.after_pin;p.pin(pin);need(b.offset<pin.length,'STREAM_SLOG_RANGE');
  const output=Buffer.alloc(Math.min(p.block,pin.length-b.offset));let at=0;
  // One bounded range query, even when this range contains thousands of tiny appends.
  const extents=(await c.query('SELECT byte_offset,bytes FROM bimchat_direct_ownership.slog_extents WHERE file_id=$1 AND sequence<=$2 AND byte_offset<$4 AND byte_offset+octet_length(bytes)>$3 ORDER BY byte_offset',[h.file_id,b.sequence,b.offset,b.offset+output.length])).rows;
  for(const row of extents){const pos=b.offset+at,start=Number(row.byte_offset);need(start<=pos&&(at===0||start===pos),'STREAM_SLOG_EXTENT');
   const skip=pos-start,n=Math.min(row.bytes.length-skip,output.length-at);need(n>0,'STREAM_SLOG_EXTENT');row.bytes.copy(output,at,skip,skip+n);at+=n;
  }need(at===output.length,'STREAM_SLOG_INCOMPLETE');return {epoch:h.epoch,sequence:b.sequence,offset:b.offset,pin,bytes:output.toString('base64')};
 });}
 async function acknowledge(a,b){p.fields(b,['sequence','pin']);p.pin(b.pin);return transaction(a,async(c,h,s)=>{
  if(b.sequence===Number(s.applied_sequence)){need(p.equal(s.pin,b.pin),'STREAM_SLOG_RECEIPT_REUSED');return {acknowledged:true};}
  need(b.sequence===Number(s.applied_sequence)+1,'STREAM_SLOG_RECEIPT_ORDER');const op=await one(c,'SELECT * FROM bimchat_direct_ownership.slog_operations WHERE file_id=$1 AND sequence=$2',[h.file_id,b.sequence]);need(op&&p.equal(op.before_pin,s.pin)&&p.equal(op.after_pin,b.pin),'STREAM_SLOG_RECEIPT');
  await c.query('UPDATE bimchat_direct_ownership.slog_participants SET applied_sequence=$2,pin=$3 WHERE participant_id=$1',[s.participant_id,b.sequence,b.pin]);return {acknowledged:true};
 });}
 async function resume(a){const c=await pool.connect();try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const h=await one(c,'SELECT l.*,m.project_id FROM bimchat_direct_ownership.slog_streams l JOIN bimchat_direct_ownership.model_streams m USING(file_id) WHERE l.file_id=$1 AND l.epoch=m.epoch',[a.fileId]);need(h,'STREAM_SLOG_NOT_PREPARED');await member(c,h,a);
  const old=await one(c,'SELECT lp.applied_sequence,lp.pin FROM bimchat_direct_ownership.slog_participants lp JOIN bimchat_direct_ownership.model_stream_participants rp USING(participant_id) WHERE lp.file_id=$1 AND rp.email=$2 AND rp.device_id=$3',[a.fileId,a.email,a.deviceId]);
  return old?{existing:true,epoch:h.epoch,sequence:Number(old.applied_sequence),pin:old.pin}:{existing:false,epoch:h.epoch};
 }finally{try{await c.query('ROLLBACK');}finally{c.release();}}}
 return {join,resume,request,ready,begin,put,commit,complete,pending,get,acknowledge,catchup,'catchup-ack':catchupAck};
};
module.exports.channel=channel;
