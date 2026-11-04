'use strict';
const proof=require('./ephemeral-attempt-v1/device-proof.cjs'),{need}=require('./ephemeral-attempt-v1/scope.cjs');
// Normal product HTTP adapter. Explicit composition only; no import-time IO.
module.exports=function({pool,review,approvedDigest,baseline,r2}){
 need(review&&proof.hash(review)===approvedDigest&&review.participantMode==='independent'&&Number.isSafeInteger(review.sessionLifetimeMs)&&review.sessionLifetimeMs>0,'STREAM_REVIEW');
 const config=JSON.parse(proof.canonical(review));
 const store=require('./product-model-stream.cjs')({pool,sessionLifetimeMs:config.sessionLifetimeMs});
 const queue=require('./product-model-stream-queue.cjs')({pool,store});
 const chunks=require('./product-stream-chunks.cjs')({pool});
 const images=require('./product-stream-images.cjs')({pool});
 const deltas=require('./product-stream-deltas.cjs')({pool,r2});
 const users=require('./product-stream-users.cjs')({pool});
 let provisioning='idle';
 function provision(){if(provisioning!=='idle'||!baseline)return;provisioning='running';baseline.initial().then(()=>{provisioning='ready';},e=>{if(e?.message==='STREAM_INITIAL_SYNC_ACTIVE'){provisioning='idle';return;}provisioning='uncertain';console.warn(JSON.stringify({event:'ownership-stream-baseline-interrupted'}));});}
 function wake(){queue.drain(config.fileId).catch(()=>{console.warn(JSON.stringify({event:'ownership-stream-drain-interrupted'}));});}
 function member(email){const p=config.participants?.find(p=>p.email===email);need(p,'STREAM_ACCOUNT');return p;}
 async function catalog(c,email){
  member(email);need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[config.projectId,email])).rowCount===1,'STREAM_MEMBERSHIP');
  const row=(await c.query('SELECT project_id,relative_path FROM cloud_files WHERE id=$1',[config.fileId])).rows[0];
  const normalized=p=>String(p).replace(/\\/g,'/').toLowerCase();
  need(row&&row.project_id===config.projectId&&normalized(row.relative_path)===normalized(config.centralPath),'STREAM_MODEL_BINDING');
 }
 async function plan(email){const c=await pool.connect();try{await catalog(c,email);const row=(await c.query('SELECT epoch,sequence FROM bimchat_direct_ownership.model_streams WHERE file_id=$1',[config.fileId])).rows[0];const me=member(email);
  if(!row)provision();
  return {mode:'independent',reviewDigest:approvedDigest,sessionLifetimeMs:config.sessionLifetimeMs,projectId:config.projectId,fileId:config.fileId,logicalCentralPath:config.logicalCentralPath,agentBuild:me.agentBuild,addinBuild:me.addinBuild,baselineReady:!!row,baselineState:row?'ready':provisioning,...(row?{epoch:row.epoch,headSequence:Number(row.sequence)}:{})};
 }finally{c.release();}}
 async function authenticate(req,joining){
  const receivedAt=Date.now(),email=req.user?.email,b=req.body;member(email);
  need(b&&b.fileId===config.fileId&&Buffer.byteLength(proof.canonical(b))<=1200000,'STREAM_BODY');
  const encoded=req.headers['x-bimchat-proof'];need(typeof encoded==='string'&&encoded.length<=12000,'DEVICE_PROOF_HEADER');
  const signed=JSON.parse(Buffer.from(encoded,'base64').toString('utf8'));let participant;
  const c=await pool.connect();try{await catalog(c,email);
   if(joining){
    const initial=b.bootstrap||b;need(Object.keys(initial).sort().join(',')===(b.bootstrap?'addinBuild,agentBuild,logicalCentralPath,profile':'addinBuild,agentBuild,fileId,logicalCentralPath,profile,state'),'STREAM_JOIN_BODY');
    const me=member(email),p=initial.profile;
    need(initial.agentBuild===me.agentBuild&&initial.addinBuild===me.addinBuild&&initial.logicalCentralPath===config.logicalCentralPath,'STREAM_BUILD_MODEL');
    need(p&&Object.keys(p).sort().join(',')==='device,keyDigest,publicJwk,session'&&p.publicJwk&&!['d','p','q','dp','dq','qi','oth'].some(k=>k in p.publicJwk),'STREAM_JOIN_PROFILE');
    participant={email,sessionId:p.session,deviceId:p.device,publicJwk:p.publicJwk,publicKeyDigest:p.keyDigest};
   }else{
    const row=(await c.query('SELECT s.public_key,s.key_digest,p.device_id FROM bimchat_direct_ownership.model_stream_sessions s JOIN bimchat_direct_ownership.model_stream_participants p USING(participant_id) WHERE s.session_id=$1 AND p.file_id=$2 AND p.email=$3 AND s.revoked=false AND s.expires_at>clock_timestamp()',[signed.payload?.session,config.fileId,email])).rows[0];need(row,'STREAM_SESSION');
    participant={email,sessionId:signed.payload.session,deviceId:row.device_id,publicJwk:row.public_key,publicKeyDigest:row.key_digest};
   }
   const auth=proof.verify(signed,{email,method:'POST',path:req.originalUrl,body:b},participant,approvedDigest,receivedAt);
   need((await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[signed.payload.nonce,approvedDigest,email,auth.sessionId])).rowCount===1,'DEVICE_PROOF_REPLAY');
   return {...auth,fileId:config.fileId,keyDigest:participant.publicKeyDigest};
  }finally{c.release();}
 }
 async function handle(req,action){const auth=await authenticate(req,action==='join'||((action.startsWith('users-')||action==='resume')&&!!req.body?.bootstrap));const b=req.body;
  if(action==='resume'){need(b.bootstrap&&Object.keys(b).sort().join(',')===(b.name?'bootstrap,epoch,fileId,index,name,pinsDigest,sequence':'bootstrap,fileId'),'STREAM_RESUME_BODY');return deltas.resume(auth,b);}
  if(action==='users-known'){const c=await pool.connect();try{try{await users.known(c,auth.fileId,b.reference);return {known:true};}catch(e){if(e.message==='USERS_UNVERIFIED')return {known:false};throw e;}}finally{c.release();}}
  if(action==='users-put'){need(typeof b.bytes==='string'&&b.bytes.length<=349528,'USERS_CHUNK');const bytes=Buffer.from(b.bytes,'base64');need(bytes.toString('base64')===b.bytes,'USERS_ENCODING');return users.upload(auth.fileId,b.reference,b.index,bytes);}
  if(action==='users-seal')return users.finish(auth.fileId,b.reference);
  if(action==='users-get')return {index:b.index,bytes:(await users.get(auth.fileId,b.reference,b.index)).toString('base64')};
  if(action==='image-begin'){need(b.operation?.patch?.Schema===2&&b.operation?.patch?.Model===config.centralPath.replace(/\\/g,'/').split('/').pop(),'STREAM_MODEL_BINDING');const arrival=await queue.reserve(auth,b.operation);const image=await images.begin(auth,b.operation);return {...image,arrival:arrival.arrival};}
  if(action==='delta-begin'){need(b.operation?.patch?.Schema===3&&b.operation.patch.Model===config.centralPath.replace(/\\/g,'/').split('/').pop(),'STREAM_MODEL_BINDING');const arrival=await queue.reserve(auth,b.operation);return {...await deltas.begin(auth,b.operation),arrival:arrival.arrival};}
  if(action==='delta-put')return deltas.put(auth,b);
  if(action==='delta-get')return deltas.get(auth,b);
  if(action==='delta-submit'){const operation=await deltas.verified(auth,b.operationId);const result=await queue.enqueue(auth,operation,true);wake();return result;}
  if(action==='image-put')return images.put(auth,b);
  if(action==='image-get')return images.get(auth,b);
  if(action==='image-submit'){const operation=await images.verified(auth,b.operationId);const result=await queue.enqueue(auth,operation,true);wake();return result;}
  if(action==='chunk-put')return chunks.put(auth,b);
  if(action==='operation-chunk')return chunks.get(auth,b);
  if(action==='submit-chunked'){const operation=await chunks.assemble(auth,b);need(![2,3].includes(operation?.patch?.Schema)&&operation?.patch?.Model===config.centralPath.replace(/\\/g,'/').split('/').pop(),'STREAM_MODEL_BINDING');const result=await queue.enqueue(auth,operation,true);wake();return result;}
  if(action==='join'){need(b.state&&Object.keys(b.state).sort().join(',')==='epoch,lastAppliedSequence,pins','STREAM_JOIN_STATE');return store.join(auth,{...b.state,publicJwk:b.profile.publicJwk});}
  if(action==='sync-baseline'||action==='sync-status'){need(baseline&&Object.keys(b).sort().join(',')==='central,fileId,pins,publicationId'&&/^[a-f0-9-]{36}$/i.test(b.publicationId),'STREAM_SYNC_BODY');return action==='sync-status'?baseline.status(auth,b):baseline.sync(auth,b);}
  if(action==='baseline-file'){
   need(r2&&Object.keys(b).sort().join(',')==='fileId,name,operationId'&&['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'].includes(b.name),'STREAM_BASELINE_FILE');
   const c=await pool.connect();let payload;try{payload=(await c.query('SELECT payload FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND operation_id=$2',[config.fileId,b.operationId])).rows[0]?.payload;}finally{c.release();}
   need(payload?.kind==='sync-baseline','STREAM_BASELINE_OPERATION');const relative=config.centralPath.replace(/\.rvt$/i,'')+'_backup/'+b.name;
   const pin=payload.manifest.find(f=>require('./scoped-api-v11/scope.cjs').equal(f.path,relative));need(pin&&pin.size<=8388608,'STREAM_BASELINE_PIN');
   const bytes=await r2.readVerified(pin);return {operationId:b.operationId,name:b.name,sha256:pin.sha256,size:pin.size,bytes:bytes.toString('base64')};
  }
  need(Object.keys(b).sort().join(',')===(action==='pending'?'fileId':action==='status'?'fileId,operationId':'fileId,operation'),'STREAM_ACTION_BODY');
  if(action==='submit'){need(![2,3].includes(b.operation?.patch?.Schema)&&b.operation?.patch?.Model===config.centralPath.replace(/\\/g,'/').split('/').pop(),'STREAM_MODEL_BINDING');const result=await queue.enqueue(auth,b.operation);wake();return result;}
  if(action==='status'){wake();return queue.status(auth,b.operationId);}
  if(action==='acknowledge')return store.acknowledge(auth,b.operation);
  wake();const result=await store.pending(auth);result.operation=await chunks.pending(auth,result.operation);return result;
 }
 function mount(app,jwt){
  app.get('/drive/ownership/stream/plan',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await plan(req.user.email));}catch{res.status(409).json({code:'STREAM_PLAN_UNAVAILABLE'});}});
  // Normal Sync never replaces the agent's ownership state. The earlier
  // Sync-baseline/status work is retained as history, not mounted in this mode.
  for(const action of ['resume','delta-begin','delta-put','delta-get','delta-submit','users-known','users-put','users-seal','users-get','join','submit','submit-chunked','chunk-put','operation-chunk','image-begin','image-put','image-get','image-submit','status','pending','acknowledge','baseline-file'])app.post('/drive/ownership/stream/'+action,jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await handle(req,action));}catch(e){
   const reason=typeof e.message==='string'&&/^(STREAM|USERS|DEVICE_PROOF)_[A-Z_]+$/.test(e.message)?e.message:'STREAM_REQUEST_FAILED';
   res.status(409).json({code:reason});
  }});
 }
 return {mount,plan,handle};
};
