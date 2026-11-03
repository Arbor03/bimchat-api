'use strict';
const crypto=require('node:crypto'),scope=require('./scoped-api-v11/scope.cjs'),content=require('./scoped-api-v11/content-pins.cjs');
const policy=require('./product-model-stream-policy.cjs'),proof=require('./ephemeral-attempt-v1/device-proof.cjs'),{need}=scope;
const names=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];
function inventory(review,rows){
 const selected=rows.filter(f=>f.project_id===review.projectId&&scope.group(review.centralPath,f.relative_path));scope.unique(selected.map(f=>f.relative_path));
 need(selected.some(f=>f.id===review.fileId&&scope.equal(f.relative_path,review.centralPath)),'STREAM_BASELINE_MODEL');
 for(const name of names)need(selected.filter(f=>scope.equal(f.relative_path,review.centralPath.replace(/\.rvt$/i,'')+'_backup/'+name)).length===1,'STREAM_BASELINE_INCOMPLETE');
 return selected;
}
async function verifiedSnapshot(c,review,r2,rows,cacheBase=false){
 const selected=inventory(review,rows),manifest=[];let users;
 for(const f of selected){const pin=await content.load(c,f.b2_key);need(pin.size===Number(f.file_size),'STREAM_BASELINE_CATALOG_SIZE');
  // Conditional GET validates actual content, never ETag-as-hash assumptions.
  const isUsers=scope.equal(f.relative_path,review.centralPath.replace(/\.rvt$/i,'')+'_backup/users.dat');
  const ownershipName=names.find(name=>scope.equal(f.relative_path,review.centralPath.replace(/\.rvt$/i,'')+'_backup/'+name));
  let bytes;if(cacheBase&&ownershipName){const base=require('./product-stream-base.cjs');need(typeof r2.withVerifiedStream==='function','STREAM_BASELINE_STREAM_REQUIRED');await r2.withVerifiedStream(pin,input=>base.capture(c,review.fileId,ownershipName,pin,input));if(isUsers){users={length:pin.size,sha256:pin.sha256};await require('./product-stream-users.cjs')({}).importStream(c,review.fileId,users,base.read(c,review.fileId,ownershipName,pin.size));}}
  else if(isUsers&&typeof r2.withVerifiedStream==='function'){users={length:pin.size,sha256:pin.sha256};await r2.withVerifiedStream(pin,input=>require('./product-stream-users.cjs')({}).importStream(c,review.fileId,users,input));}
  else if(typeof r2.verify==='function'&&!isUsers){const actual=await r2.verify(pin);need(actual.size===pin.size&&actual.sha256===pin.sha256,'STREAM_BASELINE_R2_CONTENT');}
  else{bytes=await r2.readVerified(pin);need(bytes.length===pin.size&&policy.sha(bytes)===pin.sha256,'STREAM_BASELINE_R2_CONTENT');}
  manifest.push({fileId:f.id,path:f.relative_path,version:f.current_version,...pin});
  if(isUsers&&bytes)users=bytes.toString('base64');
 }
 const pins={files:names.map(name=>{const f=manifest.find(x=>scope.equal(x.path,review.centralPath.replace(/\.rvt$/i,'')+'_backup/'+name));return {name,length:f.size,sha256:f.sha256};}),users};policy.pins(pins);return {manifest,pins};
}
// Called inside the normal completed-Sync publication transaction after its
// writer fence and authenticated publisher have been checked. Sequence continues;
// offline participants keep their existing cursor and receive a baseline event.
async function advance(c,{review,source,publicationId,snapshot}){
 policy.pins(snapshot.pins);need(Array.isArray(snapshot.manifest)&&snapshot.manifest.length>=6,'STREAM_BASELINE_MANIFEST');
 scope.unique(snapshot.manifest.map(f=>f.path));for(const f of snapshot.manifest)content.validate(f);
 need(snapshot.manifest.some(f=>f.fileId===review.fileId&&scope.equal(f.path,review.centralPath)),'STREAM_BASELINE_MODEL');
 for(const pin of snapshot.pins.files){const file=snapshot.manifest.find(f=>scope.equal(f.path,review.centralPath.replace(/\.rvt$/i,'')+'_backup/'+pin.name));need(file&&file.sha256===pin.sha256&&file.size===pin.length,'STREAM_BASELINE_MANIFEST_CONTENT');}
 // Serialize the empty-inbox decision with actual intake on every API process.
 // Otherwise an arrival could commit between this check and baseline commit.
 await c.query('SELECT pg_advisory_xact_lock(194811, $1)',[review.fileId]);
 const h=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1 FOR UPDATE',[review.fileId])).rows[0];need(h&&h.project_id===review.projectId,'STREAM_BASELINE_MODEL');
 const prior=(await c.query('SELECT file_id,sequence,pins,manifest FROM bimchat_direct_ownership.model_stream_baselines WHERE publication_id=$1',[publicationId])).rows[0];
 if(prior){need(prior.file_id===review.fileId&&proof.canonical(prior.pins)===proof.canonical(snapshot.pins)&&proof.canonical(prior.manifest)===proof.canonical(snapshot.manifest),'STREAM_PUBLICATION_REUSED');return {sequence:Number(prior.sequence),duplicate:true};}
 need(!(await c.query("SELECT 1 FROM bimchat_direct_ownership.model_stream_inbox WHERE file_id=$1 AND state='queued' LIMIT 1",[review.fileId])).rowCount,'STREAM_PUBLICATION_QUEUE_PENDING');
 const p=(await c.query('SELECT p.* FROM bimchat_direct_ownership.model_stream_participants p JOIN bimchat_direct_ownership.model_stream_sessions s USING(participant_id) WHERE s.session_id=$1 AND p.file_id=$2 AND p.email=$3 AND s.key_digest=$4 AND s.revoked=false AND s.expires_at>clock_timestamp() FOR UPDATE OF p,s',[source.sessionId,review.fileId,source.email,source.keyDigest])).rows[0];
 need(p&&p.epoch===h.epoch&&Number(p.applied_sequence)===Number(h.sequence),'STREAM_PUBLICATION_SOURCE');
 need(policy.equivalent(source.pins,snapshot.pins),'STREAM_PUBLICATION_LOCAL_CONTENT');
 require('./product-user-table.cjs').appendOnly(policy.userBytes(h.head.users),policy.userBytes(snapshot.pins.users));
 const sequence=Number(h.sequence)+1;need(Number.isSafeInteger(sequence),'STREAM_SEQUENCE_BOUND');
 const payload={kind:'sync-baseline',epoch:h.epoch,publicationId,beforePins:h.head,afterPins:snapshot.pins,manifest:snapshot.manifest};
 await c.query('INSERT INTO bimchat_direct_ownership.model_stream_operations(file_id,sequence,operation_id,source_session,source_participant,digest,payload,result_pins) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[review.fileId,sequence,publicationId,source.sessionId,p.participant_id,proof.hash(payload),JSON.stringify(payload),JSON.stringify(snapshot.pins)]);
 await c.query('INSERT INTO bimchat_direct_ownership.model_stream_baselines(file_id,sequence,publication_id,manifest,pins,previous_head) VALUES($1,$2,$3,$4,$5,$6)',[review.fileId,sequence,publicationId,JSON.stringify(snapshot.manifest),JSON.stringify(snapshot.pins),JSON.stringify(h)]);
 await c.query('UPDATE bimchat_direct_ownership.model_streams SET sequence=$2,head=$3 WHERE file_id=$1',[review.fileId,sequence,JSON.stringify(snapshot.pins)]);
 await c.query('UPDATE bimchat_direct_ownership.model_stream_participants SET applied_sequence=$2,local_pins=$3 WHERE participant_id=$1',[p.participant_id,sequence,JSON.stringify(source.pins)]);
 return {sequence,duplicate:false};
}
module.exports=function({pool,r2,review,writerInventoryDigest}){
 const drain=require('./receiver-open-v1/evidence-adapters.cjs').writerDrain({reviewedInventoryDigest:writerInventoryDigest});
 // Readback of one immutable publication, including after a lost response or
 // normal lock release. Absence is not permission to replay a pending mutation.
 async function status(source,body){const c=await pool.connect();try{
  const row=(await c.query('SELECT o.sequence,o.payload,o.source_participant FROM bimchat_direct_ownership.model_stream_operations o WHERE o.file_id=$1 AND o.operation_id=$2',[review.fileId,body.publicationId])).rows[0];
  if(!row)return {committed:false};
  const participant=(await c.query('SELECT p.participant_id FROM bimchat_direct_ownership.model_stream_participants p JOIN bimchat_direct_ownership.model_stream_sessions s USING(participant_id) WHERE s.session_id=$1 AND p.file_id=$2 AND p.email=$3 AND s.key_digest=$4 AND s.revoked=false AND s.expires_at>clock_timestamp()',[source.sessionId,review.fileId,source.email,source.keyDigest])).rows[0];
  need(participant&&row.source_participant===participant.participant_id&&row.payload.kind==='sync-baseline','STREAM_PUBLICATION_SOURCE');
  const central=row.payload.manifest.find(f=>f.fileId===review.fileId);
  need(proof.canonical(row.payload.afterPins)===proof.canonical(body.pins)&&central&&central.size===body.central?.size&&central.sha256===body.central?.sha256,'STREAM_PUBLICATION_REUSED');
  return {committed:true,sequence:Number(row.sequence),duplicate:true};
 }finally{c.release();}}
 async function initial(){
  need(review.participantMode==='independent'&&review.initialBaselineApproved===true&&r2&&typeof r2.seal==='function'&&typeof r2.readVerified==='function','STREAM_INITIAL_APPROVAL');
  const c=await pool.connect();let id;try{
   await c.query('BEGIN');await scope.lock(c,review.projectId);
   const existing=(await c.query('SELECT epoch,sequence FROM bimchat_direct_ownership.model_streams WHERE file_id=$1',[review.fileId])).rows[0];if(existing){await c.query('COMMIT');return {ready:true,existing:true};}
   need(!(await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[review.fileId])).rowCount,'STREAM_INITIAL_SYNC_ACTIVE');await drain(c,review);
   const scopes=await scope.scopes(c,review.projectId);need(!scopes.some(s=>scope.overlap(s.central_path,review.centralPath)),'STREAM_INITIAL_EXISTING_SCOPE');
   const rows=(await c.query('SELECT id,project_id,relative_path,b2_key,current_version,file_size FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[review.projectId])).rows;inventory(review,rows);
   id=crypto.randomUUID();await c.query("INSERT INTO bimchat_direct_ownership.scopes(id,project_id,file_id,central_path,logical_central_path,state) VALUES($1,$2,$3,$4,$5,'draining')",[id,review.projectId,review.fileId,review.centralPath,review.logicalCentralPath]);await c.query('COMMIT');
   await c.query('BEGIN');await scope.lock(c,review.projectId);await drain(c,review);
   const current=inventory(review,(await c.query('SELECT id,project_id,relative_path,b2_key,current_version,file_size FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[review.projectId])).rows);
   for(const f of current){const cap={project_id:review.projectId,relative_path:f.relative_path,object_key:f.b2_key};const pin=await r2.seal(cap,content.reservation(pool,cap));need(pin.contentVerified&&pin.size===Number(f.file_size),'STREAM_INITIAL_CONTENT');await content.insert(c,pin);await content.complete(c,pin);
    need((await c.query('UPDATE cloud_files SET b2_key=$1 WHERE id=$2 AND b2_key=$3 AND current_version=$4 RETURNING id',[pin.key,f.id,f.b2_key,f.current_version])).rowCount===1,'STREAM_INITIAL_CATALOG_RACE');f.b2_key=pin.key;
   }
   const snapshot=await verifiedSnapshot(c,review,r2,current,true),epoch=crypto.randomUUID();
   await c.query('INSERT INTO bimchat_direct_ownership.model_streams(project_id,file_id,epoch,baseline,head) VALUES($1,$2,$3,$4,$4)',[review.projectId,review.fileId,epoch,JSON.stringify(snapshot.pins)]);
   await c.query('INSERT INTO bimchat_direct_ownership.model_stream_baselines(file_id,sequence,publication_id,manifest,pins) VALUES($1,0,$2,$3,$4)',[review.fileId,crypto.randomUUID(),JSON.stringify(snapshot.manifest),JSON.stringify(snapshot.pins)]);
   need((await c.query("UPDATE bimchat_direct_ownership.scopes SET state='released' WHERE id=$1 AND state='draining' RETURNING id",[id])).rowCount===1,'STREAM_INITIAL_SCOPE_CHANGED');
   await c.query('COMMIT');return {ready:true,existing:false};
  }catch(e){try{await c.query('ROLLBACK');}catch{}throw e;}finally{c.release();}
 }
 async function sync(source,body){const c=await pool.connect();let transaction=false;try{
  need(body&&/^[a-f0-9-]{36}$/i.test(body.publicationId),'STREAM_SYNC_PUBLICATION');
  const lock=(await c.query('SELECT locked_by FROM file_locks WHERE cloud_file_id=$1',[review.fileId])).rows[0];need(lock&&lock.locked_by===source.email,'STREAM_SYNC_LOCK_OWNER');
  const rows=(await c.query('SELECT id,project_id,relative_path,b2_key,current_version,file_size FROM cloud_files WHERE project_id=$1 ORDER BY id',[review.projectId])).rows;
  // R2 reads do not hold the project transaction lock. Recheck the exact scoped
  // catalog and owner before the short commit so network latency cannot fence it.
  const snapshot=await verifiedSnapshot(c,review,r2,rows),central=snapshot.manifest.find(f=>f.fileId===review.fileId);
  need(body.central&&body.central.sha256===central.sha256&&body.central.size===central.size,'STREAM_SYNC_CENTRAL_CONTENT');
  await c.query('BEGIN');transaction=true;await scope.lock(c,review.projectId);
  need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[review.projectId,source.email])).rowCount===1,'STREAM_MEMBERSHIP');
  const currentLock=(await c.query('SELECT locked_by FROM file_locks WHERE cloud_file_id=$1 FOR UPDATE',[review.fileId])).rows[0];need(currentLock&&currentLock.locked_by===source.email,'STREAM_SYNC_LOCK_OWNER');
  const current=(await c.query('SELECT id,project_id,relative_path,b2_key,current_version,file_size FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[review.projectId])).rows;
  need(proof.canonical(inventory(review,current))===proof.canonical(inventory(review,rows)),'STREAM_SYNC_CATALOG_CHANGED');
  const result=await advance(c,{review,source:{...source,pins:body.pins},publicationId:body.publicationId,snapshot});await c.query('COMMIT');return result;
 }catch(e){if(transaction)await c.query('ROLLBACK');throw e;}finally{c.release();}}
 // Only initial provisioning is wired by the independent product. Historical
 // Sync-baseline methods are not exposed as routes or called by normal Sync.
 return {initial,sync,status,verifiedSnapshot:(c,rows)=>verifiedSnapshot(c,review,r2,rows),advance:(c,input)=>advance(c,{review,...input})};
};
module.exports.inventory=inventory;module.exports.verifiedSnapshot=verifiedSnapshot;module.exports.advance=advance;
