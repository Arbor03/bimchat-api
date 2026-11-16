'use strict';
const proof=require('./ephemeral-attempt-v1/device-proof.cjs'),{need}=require('./ephemeral-attempt-v1/scope.cjs');
// Normal product HTTP adapter. Explicit composition only; no import-time IO.
module.exports=function({pool,review,approvedDigest,baseline,r2}){
 need(review&&proof.hash(review)===approvedDigest&&review.participantMode==='independent'&&Number.isSafeInteger(review.sessionLifetimeMs)&&review.sessionLifetimeMs>0,'STREAM_REVIEW');
 const config=JSON.parse(proof.canonical(review));
 need(config.nativeStreamSchema===undefined||[3,4,5].includes(config.nativeStreamSchema),'STREAM_NATIVE_SCHEMA');
 const splitLog=config.nativeStreamSchema===5;
 if(splitLog){need(config.splitLog&&Object.keys(config.splitLog).sort().join(',')==='logPin,ownershipSequence'&&Number.isSafeInteger(config.splitLog.ownershipSequence)&&config.splitLog.ownershipSequence>=0,'STREAM_SLOG_REVIEW');require('./product-slog-policy.cjs').pin(config.splitLog.logPin);}
 const nativeModel=config.nativeStreamSchema===4?config.centralPath.replace(/\\/g,'/').split('/').pop():null;
 if(nativeModel!==null)require('./scoped-api-v11/direct/protocol.cjs').nativeNames(nativeModel);
 const nativeBaseline=splitLog?null:config.nativeBaseline||null;
 need(!nativeBaseline||nativeModel!==null,'STREAM_NATIVE_ENROLLMENT');
 if(nativeBaseline)require('./product-native-enrollment.cjs').validate(nativeBaseline,nativeModel);
 const store=require('./product-model-stream.cjs')({pool,sessionLifetimeMs:config.sessionLifetimeMs,nativeModel,nativeBaseline,minimumSequence:splitLog?config.splitLog.ownershipSequence:0});
 const queue=require('./product-model-stream-queue.cjs')({pool,store,nativeModel});
 const chunks=require('./product-stream-chunks.cjs')({pool});
 const images=require('./product-stream-images.cjs')({pool});
 const deltas=require('./product-stream-deltas.cjs')({pool,r2,nativeModel,nativeBaseline,splitLog:splitLog?{sequence:config.splitLog.ownershipSequence,model:config.centralPath.replace(/\\/g,'/').split('/').pop()}:null});
 const deltaWire=require('./product-delta-stream.cjs');
 const deltaStream=deltaWire({deltas,queue,pool,schema:nativeModel===null?3:4,validateModel:operation=>{need(operation?.patch?.Schema===(nativeModel===null?3:4)&&operation.patch.Model===config.centralPath.replace(/\\/g,'/').split('/').pop(),'STREAM_MODEL_BINDING');if(nativeModel===null)require('./scoped-api-v11/direct/protocol.cjs').validateStream(operation.patch);else require('./scoped-api-v11/direct/protocol.cjs').validateNativeStream(operation.patch,nativeModel);},wake});
 const users=require('./product-stream-users.cjs')({pool});
 const notifications=require('./product-stream-notifications.cjs')({pool});
 const slog=splitLog?require('./product-slog-stream.cjs')({pool,sessionLifetimeMs:config.sessionLifetimeMs}):null;
 const slogNotifications=splitLog?require('./product-slog-notifications.cjs')({pool}):null;
 let provisioning='idle';
 async function requireNativeBaseline(c,row){
  if(splitLog){
   if(row===undefined)row=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1',[config.fileId])).rows[0];
   const log=(await c.query('SELECT * FROM bimchat_direct_ownership.slog_streams WHERE file_id=$1',[config.fileId])).rows[0];
   need(row&&row.native_gate_enabled===true&&row.head.files.length===5&&log&&log.epoch===row.epoch&&Number(log.ownership_start_sequence)===config.splitLog.ownershipSequence&&Number(row.sequence)>=config.splitLog.ownershipSequence&&require('./product-slog-policy.cjs').equal(log.baseline,config.splitLog.logPin),'STREAM_SLOG_NOT_PREPARED');return;
  }
  if(nativeModel===null)return;
  if(row===undefined)row=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1',[config.fileId])).rows[0];
  need(row&&row.native_gate_enabled===true,'STREAM_NATIVE_BASELINE_REQUIRED');
  require('./product-native-enrollment.cjs').head(nativeBaseline,row,nativeModel);
 }
 function provision(){if(provisioning!=='idle'||!baseline)return;provisioning='running';baseline.initial().then(()=>{provisioning='ready';},e=>{if(e?.message==='STREAM_INITIAL_SYNC_ACTIVE'){provisioning='idle';return;}provisioning='uncertain';console.warn(JSON.stringify({event:'ownership-stream-baseline-interrupted'}));});}
 function wake(){queue.drain(config.fileId).catch(()=>{console.warn(JSON.stringify({event:'ownership-stream-drain-interrupted'}));});}
 function member(email){const p=config.participants?.find(p=>p.email===email);need(p,'STREAM_ACCOUNT');return p;}
 async function catalog(c,email){
  member(email);need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[config.projectId,email])).rowCount===1,'STREAM_MEMBERSHIP');
  const row=(await c.query('SELECT project_id,relative_path FROM cloud_files WHERE id=$1',[config.fileId])).rows[0];
  const normalized=p=>String(p).replace(/\\/g,'/').toLowerCase();
  need(row&&row.project_id===config.projectId&&normalized(row.relative_path)===normalized(config.centralPath),'STREAM_MODEL_BINDING');
 }
 async function plan(email){const c=await pool.connect();try{await catalog(c,email);const row=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1',[config.fileId])).rows[0];const me=member(email);
  await requireNativeBaseline(c,row||null);
  if(!row)provision();
  return {mode:'independent',deltaStreamVersion:1,nativeStreamSchema:splitLog?5:nativeModel===null?3:4,nativeAdmission:row?.native_gate_enabled===true,reviewDigest:approvedDigest,sessionLifetimeMs:config.sessionLifetimeMs,projectId:config.projectId,fileId:config.fileId,logicalCentralPath:config.logicalCentralPath,agentBuild:me.agentBuild,addinBuild:me.addinBuild,baselineReady:!!row,baselineState:row?'ready':provisioning,...(row?{epoch:row.epoch,headSequence:Number(row.sequence)}:{})};
 }finally{c.release();}}
 async function authenticate(req,joining,logLane=false){
  const receivedAt=Date.now(),email=req.user?.email,b=req.body;member(email);
  need(b&&b.fileId===config.fileId&&Buffer.byteLength(proof.canonical(b))<=1200000,'STREAM_BODY');
  const encoded=req.headers['x-bimchat-proof'];need(typeof encoded==='string'&&encoded.length<=12000,'DEVICE_PROOF_HEADER');
  const signed=JSON.parse(Buffer.from(encoded,'base64').toString('utf8'));let participant;
  const c=await pool.connect();try{await catalog(c,email);await requireNativeBaseline(c);
   if(joining){
    const initial=b.bootstrap||b;need(Object.keys(initial).sort().join(',')===(b.bootstrap?'addinBuild,agentBuild,logicalCentralPath,profile':'addinBuild,agentBuild,fileId,logicalCentralPath,profile,state'),'STREAM_JOIN_BODY');
    const me=member(email),p=initial.profile;
    need(initial.agentBuild===me.agentBuild&&initial.addinBuild===me.addinBuild&&initial.logicalCentralPath===config.logicalCentralPath,'STREAM_BUILD_MODEL');
    need(p&&Object.keys(p).sort().join(',')==='device,keyDigest,publicJwk,session'&&p.publicJwk&&!['d','p','q','dp','dq','qi','oth'].some(k=>k in p.publicJwk),'STREAM_JOIN_PROFILE');
    participant={email,sessionId:p.session,deviceId:p.device,publicJwk:p.publicJwk,publicKeyDigest:p.keyDigest};
   }else{
    const table=logLane?'slog_sessions':'model_stream_sessions';
    const row=(await c.query('SELECT s.public_key,s.key_digest,p.device_id FROM bimchat_direct_ownership.'+table+' s JOIN bimchat_direct_ownership.model_stream_participants p USING(participant_id) WHERE s.session_id=$1 AND p.file_id=$2 AND p.email=$3 AND s.revoked=false AND s.expires_at>clock_timestamp()',[signed.payload?.session,config.fileId,email])).rows[0];need(row,logLane?'STREAM_SLOG_SESSION':'STREAM_SESSION');
    participant={email,sessionId:signed.payload.session,deviceId:row.device_id,publicJwk:row.public_key,publicKeyDigest:row.key_digest};
   }
   const auth=proof.verify(signed,{email,method:'POST',path:req.originalUrl,body:b},participant,approvedDigest,receivedAt);
   need((await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[signed.payload.nonce,approvedDigest,email,auth.sessionId])).rowCount===1,'DEVICE_PROOF_REPLAY');
   return {...auth,fileId:config.fileId,keyDigest:participant.publicKeyDigest};
  }finally{c.release();}
 }
 async function handle(req,action){const logLane=action.startsWith('slog-');need(!logLane||splitLog,'STREAM_SLOG_DISABLED');const auth=await authenticate(req,action==='join'||((action.startsWith('users-')||action==='resume'||action==='slog-join'||action==='slog-resume')&&!!req.body?.bootstrap),logLane);const b=req.body;
  if(logLane){
   const name=action.slice(5);if(name==='wait')return slogNotifications.wait(auth,b,req.ownershipAbortSignal);
   if(name==='join'){
    const recovery=Object.hasOwn(b,'recoverUnadmitted');
    need(Object.keys(b).sort().join(',')===(recovery?'bootstrap,epoch,fileId,pin,recoverUnadmitted':'bootstrap,epoch,fileId,pin'),'STREAM_SLOG_FIELDS');
    return slog.join(auth,{epoch:b.epoch,pin:b.pin,publicJwk:b.bootstrap.profile.publicJwk,...(recovery?{recoverUnadmitted:b.recoverUnadmitted}:{})});
   }
   if(name==='resume'){need(Object.keys(b).sort().join(',')==='bootstrap,fileId','STREAM_SLOG_FIELDS');return slog.resume(auth);}
   need(['request','ready','begin','put','commit','complete','pending','get','acknowledge','catchup','catchup-ack'].includes(name),'STREAM_SLOG_ACTION');const body={...b};delete body.fileId;return slog[name](auth,body);
  }
  if(action==='wait')return notifications.wait(auth,b,req.ownershipAbortSignal);
  if(action==='native-request'||action==='native-ready'||action==='native-complete'){
   const body={...b};delete body.fileId;
   return action==='native-request'?store.nativeRequest(auth,body):action==='native-ready'?store.nativeReady(auth,body):store.nativeComplete(auth,body);
  }
  if(action==='resume'){need(b.bootstrap&&Object.keys(b).sort().join(',')===(b.name?'bootstrap,epoch,fileId,index,name,pinsDigest,sequence':'bootstrap,fileId'),'STREAM_RESUME_BODY');return deltas.resume(auth,b);}
  if(action==='users-known'){const c=await pool.connect();try{try{await users.known(c,auth.fileId,b.reference);return {known:true};}catch(e){if(e.message==='USERS_UNVERIFIED')return {known:false};throw e;}}finally{c.release();}}
  if(action==='users-put'){need(typeof b.bytes==='string'&&b.bytes.length<=349528,'USERS_CHUNK');const bytes=Buffer.from(b.bytes,'base64');need(bytes.toString('base64')===b.bytes,'USERS_ENCODING');return users.upload(auth.fileId,b.reference,b.index,bytes);}
  if(action==='users-seal')return users.finish(auth.fileId,b.reference);
  if(action==='users-get')return {index:b.index,bytes:(await users.get(auth.fileId,b.reference,b.index)).toString('base64')};
  if(action==='image-begin'){need(b.operation?.patch?.Schema===2&&b.operation?.patch?.Model===config.centralPath.replace(/\\/g,'/').split('/').pop(),'STREAM_MODEL_BINDING');const arrival=await queue.reserve(auth,b.operation);const image=await images.begin(auth,b.operation);return {...image,arrival:arrival.arrival};}
  if(action==='delta-begin'){need(b.operation?.patch?.Schema===(nativeModel===null?3:4)&&b.operation.patch.Model===config.centralPath.replace(/\\/g,'/').split('/').pop(),'STREAM_MODEL_BINDING');const arrival=await queue.reserve(auth,b.operation);return {...await deltas.begin(auth,b.operation),arrival:arrival.arrival};}
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
  for(const action of ['delta-upload-stream','delta-download-stream'])app.post('/drive/ownership/stream/'+action,jwt,async(req,res)=>{
   const abort=new AbortController();const closed=()=>abort.abort();res.on('close',closed);req.ownershipAbortSignal=abort.signal;
   // Inactivity timeout, not a whole-transfer size/time limit. Proxy timeouts
   // must also permit streaming when this candidate is deployed.
   req.setTimeout(30000,()=>req.destroy(Error('STREAM_TRANSFER_IDLE')));
   res.setTimeout(30000,()=>res.destroy(Error('STREAM_TRANSFER_IDLE')));
   try{res.set('Cache-Control','no-store');
    if(action==='delta-upload-stream'){
     need(req.headers['content-type']===deltaWire.TYPE,'STREAM_CONTENT_TYPE');
     const reader=new deltaWire.Reader(req);req.body=await reader.header();const auth=await authenticate(req,false);
     res.json(await deltaStream.upload(auth,req.body,reader));
    }else{
     const auth=await authenticate(req,false);
     res.type(deltaWire.TYPE);
     await require('node:stream/promises').pipeline(require('node:stream').Readable.from(deltaStream.download(auth,req.body)),res);
    }
   }catch(e){const code=/^(STREAM|USERS|DEVICE_PROOF)_[A-Z_]+$/.test(e.message)?e.message:'STREAM_REQUEST_FAILED';if(res.headersSent)res.destroy();else if(!res.destroyed)res.status(409).json({code});}
   finally{req.setTimeout(0);res.setTimeout(0);res.removeListener('close',closed);}
  });
  app.get('/drive/ownership/stream/plan',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await plan(req.user.email));}catch{res.status(409).json({code:'STREAM_PLAN_UNAVAILABLE'});}});
  // Normal Sync never replaces the agent's ownership state. The earlier
  // Sync-baseline/status work is retained as history, not mounted in this mode.
  for(const action of ['wait','native-request','native-ready','native-complete','resume','delta-begin','delta-put','delta-get','delta-submit','users-known','users-put','users-seal','users-get','join','submit','submit-chunked','chunk-put','operation-chunk','image-begin','image-put','image-get','image-submit','status','pending','acknowledge','baseline-file',...(splitLog?['slog-join','slog-resume','slog-request','slog-ready','slog-begin','slog-put','slog-commit','slog-complete','slog-pending','slog-get','slog-acknowledge','slog-catchup','slog-catchup-ack','slog-wait']:[])])app.post('/drive/ownership/stream/'+action,jwt,async(req,res)=>{const abort=new AbortController();const closed=()=>abort.abort();res.on('close',closed);req.ownershipAbortSignal=abort.signal;try{res.set('Cache-Control','no-store');res.json(await handle(req,action));}catch(e){
   const reason=typeof e.message==='string'&&/^(STREAM|USERS|DEVICE_PROOF)_[A-Z_]+$/.test(e.message)?e.message:'STREAM_REQUEST_FAILED';
   if(!res.destroyed)res.status(409).json({code:reason});
  }finally{res.removeListener('close',closed);}});
 }
 return {mount,plan,handle};
};
