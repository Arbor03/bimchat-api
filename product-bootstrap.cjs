'use strict';
const crypto=require('node:crypto'),scope=require('./ephemeral-attempt-v1/scope.cjs'),proof=require('./ephemeral-attempt-v1/device-proof.cjs');const {need}=scope;
// Automatic enrollment under an explicit preapproved plan. Initial provisioning
// verifies and seals the scoped baseline before activation; never creates keys.
const rejectionCodes=new Set(["BEGIN","BOOTSTRAP_ACCOUNT","BOOTSTRAP_ACTIVATION_STOPPED","BOOTSTRAP_ACTIVE_BINDING","BOOTSTRAP_BODY","BOOTSTRAP_CENTRAL_CHANGED_DURING_SEAL","BOOTSTRAP_CHANGED_DURING_SEAL","BOOTSTRAP_CONFIRM_FRESH","BOOTSTRAP_CONFIRM_ONCE","BOOTSTRAP_EXPIRED","BOOTSTRAP_IDENTITY","BOOTSTRAP_KEY_SIZE","BOOTSTRAP_MEMBERSHIP","BOOTSTRAP_NATIVE_MAPPING","BOOTSTRAP_NATIVE_ONCE","BOOTSTRAP_NOT_CONFIGURED","BOOTSTRAP_OFFER_ONCE","BOOTSTRAP_PEER","BOOTSTRAP_PLAN_PARTICIPANT","BOOTSTRAP_PLAN_SCOPE","BOOTSTRAP_PROFILE_CHANGED","BOOTSTRAP_PROFILE_FIELDS","BOOTSTRAP_PROOF","BOOTSTRAP_PUBLIC_ONLY","BOOTSTRAP_REPLAY","BOOTSTRAP_REVIEW","BOOTSTRAP_SCOPE_BUILD","BOOTSTRAP_STAGE","BOOTSTRAP_UNKNOWN","COMMIT","CONNECTION_READY_BINDING","CONNECTION_READY_BODY","DEVICE_NOT_REVIEWED","DEVICE_PROOF_FIELDS","DEVICE_PROOF_FRESH","DEVICE_PROOF_HEADER","DEVICE_PROOF_IDENTITY","DEVICE_PROOF_KEY","DEVICE_PROOF_KEY_PIN","DEVICE_PROOF_REPLAY","DEVICE_PROOF_REQUEST","DEVICE_PROOF_SIGNATURE","DEVICE_REVIEW_PIN","DEVICE_SESSION","INITIAL_PROVISIONER_REQUIRED","OWNERSHIP_BOOTSTRAP_STOP_NO_RETRY","OWNERSHIP_BOOTSTRAP_UNAVAILABLE","OWNERSHIP_CONNECTION_RECONCILIATION_REQUIRED","OWNERSHIP_NOT_READY","POST","ROLLBACK","RSA"]);
function rejectionReason(e){return e&&rejectionCodes.has(e.message)?e.message:'INTERNAL_VALIDATION_FAILURE';}
module.exports=function({pool,review,approvedDigest,provisionInitialBaseline}){
 const id=review.bootstrapAttemptId;
 const activationJobs=new Map();
 function startActivation(confirmed=false){
  need(activationJobs.get(id)!=='running'&&typeof provisionInitialBaseline==='function','INITIAL_PROVISIONER_REQUIRED');activationJobs.set(id,'running');
  // R2 work can exceed an HTTP timeout. Accepted proposals return immediately;
  // Drive polls this existing status route. A crash leaves durable pending/drain
  // evidence and never causes an automatic retry on a later GET.
  (async()=>{try{if(!confirmed)await provisionInitialBaseline(id);const c=await pool.connect();let renewed;try{renewed=(await c.query('SELECT document FROM bimchat_direct_ownership.attempts WHERE id=$1',[id])).rows[0].document.renewalPrevious;}finally{c.release();}if(confirmed||renewed)await require('./product-bootstrap-enrollment.cjs').activateAutomatic(pool,id);activationJobs.set(id,'succeeded');}
   catch{const c=await pool.connect();try{await c.query('BEGIN');await scope.lock(c,review.projectId);const row=(await c.query('SELECT document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[id])).rows[0];if(row&&row.document.state==='bootstrap'){const h=row.document;h.bootstrapActivation='failed';await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);}await c.query('COMMIT');}catch{try{await c.query('ROLLBACK');}catch{}}finally{c.release();}}
   finally{if(activationJobs.get(id)==='running')activationJobs.set(id,'failed');}})().catch(()=>{activationJobs.set(id,'failed');});
 }
 async function load(c,email,write){need(typeof id==='string'&&/^[a-f0-9-]{36}$/.test(id),'BOOTSTRAP_NOT_CONFIGURED');
  const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1'+(write?' FOR UPDATE':''),[id])).rows[0];need(row&&row.document.id===id&&row.document.projectId===row.project_id,'BOOTSTRAP_UNKNOWN');const h=structuredClone(row.document);
  need(h.bootstrapPlanDigest===approvedDigest&&h.ordinaryUserChanges===true&&h.automaticEnrollmentApproved===true&&h.transportMode==='background-prepared'&&review.automaticEnrollmentApproved===true&&review.transportMode==='background-prepared','BOOTSTRAP_REVIEW');
  need(review.projectId===h.projectId&&review.centralPath===h.centralPath&&review.logicalCentralPath===h.logicalCentralPath&&review.sourceEmail===(h.ordinaryEnrollmentSourceEmail||h.sourceEmail)&&Array.isArray(review.participants)&&review.participants.length===2,'BOOTSTRAP_PLAN_SCOPE');
  for(const r of ['source','receiver']){const participant=review.participants.find(x=>x.email===h[r+'Email']);need(participant&&participant.agentBuild===h[r+'Build']&&participant.addinBuild===h[r+'AddinBuild'],'BOOTSTRAP_PLAN_PARTICIPANT');}
  const role=email===h.sourceEmail?'source':email===h.receiverEmail?'receiver':null;need(role,'BOOTSTRAP_ACCOUNT');
  need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[row.project_id,email])).rowCount===1,'BOOTSTRAP_MEMBERSHIP');
  const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(require('./product-session-lifetime.cjs').continuous(h)||now<h.bootstrapExpiresAt,'BOOTSTRAP_EXPIRED');return{h,role,now};
 }
 async function ready(req){
  const b=req.body;need(b&&Object.keys(b).sort().join(',')==='addinBuild,logicalCentralPath,pid,startedTicks'&&Number.isSafeInteger(b.pid)&&b.pid>0&&typeof b.startedTicks==='string'&&/^[0-9]{17,19}$/.test(b.startedTicks),'CONNECTION_READY_BODY');
  const c=await pool.connect();try{await c.query('BEGIN');await scope.lock(c,review.projectId);const {h,role,now}=await load(c,req.user.email,true);
   need(require('./product-session-lifetime.cjs').continuous(h)&&h.state==='bootstrap'&&!h.enabled&&b.logicalCentralPath===h.logicalCentralPath&&b.addinBuild===h[role+'AddinBuild'],'CONNECTION_READY_BINDING');
   // Presence is only a scheduling hint. It grants no enrollment or write access;
   // the signed native capture still verifies process, model and file identities.
   h.connectionReadiness=h.connectionReadiness||{};h.connectionReadiness[req.user.email]={...b,at:now};
   await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[h.id,JSON.stringify(h)]);await c.query('COMMIT');return {ready:true};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async function get(email){const c=await pool.connect();try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const {h,role,now}=await load(c,email,false);const proposal=h.bootstrapProposals&&Object.values(h.bootstrapProposals).find(x=>x.profile.email===email);
  const active=h.state==='armed'&&h.enabled===true&&h.ordinaryUserChanges===true;
  if(active)need(proposal&&proposal.stage==='native'&&proposal.profile.session===h[role+'Session']&&proposal.profile.device===h[role+'Device']&&proposal.profile.keyDigest===h[role+'PublicKeyDigest'],'BOOTSTRAP_ACTIVE_BINDING');
  const out={attempt:id,role,email,generation:h.generation,renewedFrom:h.renewalPrevious?h.renewalPrevious.reviewDigest:null,renewalPins:h.renewalBaselinePins?h.renewalBaselinePins[email]:null,automaticEnrollmentApproved:true,transportMode:h.transportMode,projectId:h.projectId,fileId:h.fileId,logicalCentralPath:h.logicalCentralPath,elementUniqueId:h.elementUniqueId||null,agentBuild:h[role+'Build'],addinBuild:h[role+'AddinBuild'],planDigest:approvedDigest,lifecycle:h.lifecycle||null,bootstrapExpiresAt:require('./product-session-lifetime.cjs').enrollmentLimit(h,now),checkedAt:now,proposal:proposal||null,paired:!!(h.bootstrapProposals&&h.bootstrapProposals.source&&h.bootstrapProposals.source.stage==='native'&&h.bootstrapProposals.receiver&&h.bootstrapProposals.receiver.stage==='native'),active};
  out.participantsReady=['source','receiver'].every(r=>{const p=h.connectionReadiness?.[h[r+'Email']];return p&&p.at<=now&&now-p.at<15000;});
  out.localReadiness=h.connectionReadiness?.[email]||null;
  if(out.paired&&!active){out.pairDigest=proof.hash(h.bootstrapProposals);try{need(h.bootstrapActivation==='pending'&&['running','succeeded'].includes(activationJobs.get(id)),'BOOTSTRAP_ACTIVATION_STOPPED');require('./product-bootstrap-enrollment.cjs').prepare(h,out.pairDigest,now);out.pairReady=true;}catch{out.pairReady=false;}out.approverEmail=review.approverEmail;out.accounts=[h.sourceEmail,h.receiverEmail];}
  if(active)out.runtime={reviewDigest:h.reviewDigest,expiresAt:h.expiresAt,session:h[role+'Session'],device:h[role+'Device'],keyDigest:h[role+'PublicKeyDigest']};
  out.baselineNeedsConfirmation=!active&&!h.renewalPrevious&&h.initialProvisioning?.state==='sealed'&&!(h.bootstrapConfirmations&&h.bootstrapConfirmations[role]);
  await c.query('COMMIT');return out;
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
 async function propose(req){need(req.user&&req.body&&Buffer.byteLength(proof.canonical(req.body))<=65536,'BOOTSTRAP_BODY');const body=JSON.parse(proof.canonical(req.body));need(['offer','native','confirm'].includes(body.stage),'BOOTSTRAP_STAGE');const p=body.profile;
  need(p&&p.publicJwk&&p.publicJwk.kty==='RSA'&&!['d','p','q','dp','dq','qi'].some(k=>k in p.publicJwk),'BOOTSTRAP_PUBLIC_ONLY');const key=crypto.createPublicKey({key:p.publicJwk,format:'jwk'});need(key.asymmetricKeyDetails.modulusLength>=3072,'BOOTSTRAP_KEY_SIZE');
  const digest=crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex').toUpperCase();need(p.keyDigest===digest&&/^[a-f0-9-]{36}$/.test(p.session)&&/^[a-f0-9-]{36}$/.test(p.device),'BOOTSTRAP_IDENTITY');
  const raw=req.headers['x-bimchat-proof'];need(typeof raw==='string'&&raw.length<=12000,'BOOTSTRAP_PROOF');const signed=JSON.parse(Buffer.from(raw,'base64').toString('utf8'));
  const c=await pool.connect();try{await c.query('BEGIN');const first=await load(c,req.user.email,false);await scope.lock(c,first.h.projectId);const {h,role,now}=await load(c,req.user.email,true);
   need(Object.keys(p).sort().join(',')===['attempt','expiresAt','email','session','device','logicalCentralPath','drive','revit','addinBuild','publicJwk','keyDigest'].concat(body.stage!=='offer'?['native']:[]).sort().join(','),'BOOTSTRAP_PROFILE_FIELDS');
   need(h.state==='bootstrap'&&h.enabled===false&&p.attempt===id&&p.email===req.user.email&&p.logicalCentralPath===h.logicalCentralPath&&p.drive.sha256===h[role+'Build']&&p.addinBuild===h[role+'AddinBuild']&&Number.isSafeInteger(p.expiresAt)&&p.expiresAt>now&&p.expiresAt<=require('./product-session-lifetime.cjs').enrollmentLimit(h,now),'BOOTSTRAP_SCOPE_BUILD');
   for(const peer of [p.drive,p.revit])need(Object.keys(peer).sort().join(',')==='path,pid,sha256,started,startedTicks'&&Number.isSafeInteger(peer.pid)&&peer.pid>0&&typeof peer.path==='string'&&peer.path.length<=4096&&/^[A-Za-z]:\\/.test(peer.path)&&/^[A-F0-9]{64}$/.test(peer.sha256)&&typeof peer.startedTicks==='string'&&/^[0-9]{17,19}$/.test(peer.startedTicks)&&typeof peer.started==='string'&&Number.isFinite(Date.parse(peer.started)),'BOOTSTRAP_PEER');
   proof.verify(signed,{email:req.user.email,method:'POST',path:'/drive/ownership/session-proposal',body},{email:req.user.email,sessionId:p.session,deviceId:p.device,publicJwk:p.publicJwk,publicKeyDigest:digest},approvedDigest,now);
   h.bootstrapProposals=h.bootstrapProposals||{};const prior=h.bootstrapProposals[role];
   if(body.stage==='offer')need(!prior,'BOOTSTRAP_OFFER_ONCE');
   else{need(prior&&prior.stage===(body.stage==='confirm'?'native':'offer'),'BOOTSTRAP_NATIVE_ONCE');const old=structuredClone(p),previous=structuredClone(prior.profile);delete old.native;delete previous.native;need(proof.canonical(old)===proof.canonical(previous),'BOOTSTRAP_PROFILE_CHANGED');
    need(p.native&&Object.keys(p.native).sort().join(',')==='baseline,capturedAt,mapping,pins'&&p.native.mapping&&Object.keys(p.native.mapping).sort().join(',')==='CentralLogical,CentralPhysical,DocumentPhysical,ElementId,ElementUniqueId,GroupMember,IdentityKind,OwnershipPhysical,ProjectId,RevitUser'&&p.native.mapping.IdentityKind==='project-information'&&p.native.pins&&p.native.mapping.CentralLogical===h.logicalCentralPath&&p.native.mapping.ProjectId===h.projectId&&typeof p.native.mapping.ElementUniqueId==='string'&&p.native.mapping.ElementUniqueId.length<=128&&(!h.elementUniqueId||p.native.mapping.ElementUniqueId===h.elementUniqueId),'BOOTSTRAP_NATIVE_MAPPING');require('./source-open-v1/source-policy.cjs').pins(p.native.pins);
    if(body.stage==='confirm'){
     need(!h.renewalPrevious&&h.initialProvisioning?.state==='sealed'&&!(h.bootstrapConfirmations&&h.bootstrapConfirmations[role]),'BOOTSTRAP_CONFIRM_ONCE');
     for(const field of ['mapping','pins'])need(proof.canonical(p.native[field])===proof.canonical(prior.profile.native[field]),'BOOTSTRAP_CHANGED_DURING_SEAL');
     need(proof.canonical(p.native.baseline.central)===proof.canonical(prior.profile.native.baseline.central),'BOOTSTRAP_CENTRAL_CHANGED_DURING_SEAL');
     need(Number.isSafeInteger(p.native.capturedAt)&&p.native.capturedAt<=now&&now-p.native.capturedAt<=10000&&p.native.baseline.checkedAt>=p.native.capturedAt&&p.native.baseline.checkedAt<=now&&p.native.baseline.writerMode==='idle-snapshot'&&p.native.baseline.nativeUiHeld===false,'BOOTSTRAP_CONFIRM_FRESH');
     h.bootstrapConfirmations=h.bootstrapConfirmations||{};h.bootstrapConfirmations[role]=true;
    }
   }
   need((await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[signed.payload.nonce,approvedDigest,req.user.email,p.session])).rowCount===1,'BOOTSTRAP_REPLAY');
   h.bootstrapProposals[role]={stage:body.stage==='confirm'?'native':body.stage,proofStage:body.stage,profile:p,signed,receivedAt:now};
   const paired=body.stage==='native'&&h.bootstrapProposals.source&&h.bootstrapProposals.source.stage==='native'&&h.bootstrapProposals.receiver&&h.bootstrapProposals.receiver.stage==='native';const confirmed=body.stage==='confirm'&&h.bootstrapConfirmations.source&&h.bootstrapConfirmations.receiver;if(paired||confirmed){need(typeof provisionInitialBaseline==='function','INITIAL_PROVISIONER_REQUIRED');h.bootstrapActivation='pending';}
   await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);await c.query('COMMIT');if(paired||confirmed)startActivation(!!confirmed);return{accepted:true,stage:body.stage,active:false};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 function mount(app,jwt){app.post('/drive/ownership/native-ready',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await ready(req));}catch{res.status(423).json({code:'OWNERSHIP_NOT_READY'});}});app.post('/drive/ownership/connect',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await require('./product-session-registration.cjs')(pool,review,approvedDigest,req.user.email,req.body));}catch{res.status(423).json({code:'OWNERSHIP_CONNECTION_RECONCILIATION_REQUIRED'});}});app.get('/drive/ownership/session',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await get(req.user.email));}catch{res.status(423).json({code:'OWNERSHIP_BOOTSTRAP_UNAVAILABLE'});}});app.post('/drive/ownership/session-proposal',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await propose(req));}catch(e){const reason=rejectionReason(e);console.warn(JSON.stringify({event:'ownership-proposal-rejected',reason}));res.status(423).json({code:'OWNERSHIP_BOOTSTRAP_STOP_NO_RETRY',reason});}});}
 return{get,propose,mount};
};
