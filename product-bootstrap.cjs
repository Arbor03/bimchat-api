'use strict';
const crypto=require('node:crypto'),scope=require('./ephemeral-attempt-v1/scope.cjs'),proof=require('./ephemeral-attempt-v1/device-proof.cjs');const {need}=scope;
// Automatic public enrollment under an explicit preapproved server plan. No key creation or storage sealing.
module.exports=function({pool,review,approvedDigest}){
 const id=review.bootstrapAttemptId;
 async function load(c,email,write){need(typeof id==='string'&&/^[a-f0-9-]{36}$/.test(id),'BOOTSTRAP_NOT_CONFIGURED');
  const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1'+(write?' FOR UPDATE':''),[id])).rows[0];need(row&&row.document.id===id&&row.document.projectId===row.project_id,'BOOTSTRAP_UNKNOWN');const h=structuredClone(row.document);
  need(h.bootstrapPlanDigest===approvedDigest&&h.ordinaryUserChanges===true&&h.automaticEnrollmentApproved===true&&h.transportMode==='background-prepared'&&review.automaticEnrollmentApproved===true&&review.transportMode==='background-prepared','BOOTSTRAP_REVIEW');
  need(review.projectId===h.projectId&&review.centralPath===h.centralPath&&review.logicalCentralPath===h.logicalCentralPath&&review.sourceEmail===(h.ordinaryEnrollmentSourceEmail||h.sourceEmail)&&Array.isArray(review.participants)&&review.participants.length===2,'BOOTSTRAP_PLAN_SCOPE');
  for(const r of ['source','receiver']){const participant=review.participants.find(x=>x.email===h[r+'Email']);need(participant&&participant.agentBuild===h[r+'Build']&&participant.addinBuild===h[r+'AddinBuild'],'BOOTSTRAP_PLAN_PARTICIPANT');}
  const role=email===h.sourceEmail?'source':email===h.receiverEmail?'receiver':null;need(role,'BOOTSTRAP_ACCOUNT');
  need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[row.project_id,email])).rowCount===1,'BOOTSTRAP_MEMBERSHIP');
  const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(now<h.bootstrapExpiresAt,'BOOTSTRAP_EXPIRED');return{h,role,now};
 }
 async function get(email){const c=await pool.connect();try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const {h,role,now}=await load(c,email,false);const proposal=h.bootstrapProposals&&Object.values(h.bootstrapProposals).find(x=>x.profile.email===email);
  const active=h.state==='armed'&&h.enabled===true&&h.ordinaryUserChanges===true;
  if(active)need(proposal&&proposal.stage==='native'&&proposal.profile.session===h[role+'Session']&&proposal.profile.device===h[role+'Device']&&proposal.profile.keyDigest===h[role+'PublicKeyDigest'],'BOOTSTRAP_ACTIVE_BINDING');
  const out={attempt:id,role,email,generation:h.generation,renewedFrom:h.renewalPrevious?h.renewalPrevious.reviewDigest:null,renewalPins:h.renewalBaselinePins?h.renewalBaselinePins[email]:null,automaticEnrollmentApproved:true,transportMode:h.transportMode,projectId:h.projectId,fileId:h.fileId,logicalCentralPath:h.logicalCentralPath,elementUniqueId:h.elementUniqueId||null,agentBuild:h[role+'Build'],addinBuild:h[role+'AddinBuild'],planDigest:approvedDigest,bootstrapExpiresAt:h.bootstrapExpiresAt,checkedAt:now,proposal:proposal||null,paired:!!(h.bootstrapProposals&&h.bootstrapProposals.source&&h.bootstrapProposals.source.stage==='native'&&h.bootstrapProposals.receiver&&h.bootstrapProposals.receiver.stage==='native'),active};
  if(out.paired&&!active){out.pairDigest=proof.hash(h.bootstrapProposals);try{require('./product-bootstrap-enrollment.cjs').prepare(h,out.pairDigest,now);out.pairReady=true;}catch{out.pairReady=false;}out.approverEmail=review.approverEmail;out.accounts=[h.sourceEmail,h.receiverEmail];}
  if(active)out.runtime={reviewDigest:h.reviewDigest,expiresAt:h.expiresAt,session:h[role+'Session'],device:h[role+'Device'],keyDigest:h[role+'PublicKeyDigest']};
  await c.query('COMMIT');return out;
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
 async function propose(req){need(req.user&&req.body&&Buffer.byteLength(proof.canonical(req.body))<=65536,'BOOTSTRAP_BODY');const body=JSON.parse(proof.canonical(req.body));need(body.stage==='offer'||body.stage==='native','BOOTSTRAP_STAGE');const p=body.profile;
  need(p&&p.publicJwk&&p.publicJwk.kty==='RSA'&&!['d','p','q','dp','dq','qi'].some(k=>k in p.publicJwk),'BOOTSTRAP_PUBLIC_ONLY');const key=crypto.createPublicKey({key:p.publicJwk,format:'jwk'});need(key.asymmetricKeyDetails.modulusLength>=3072,'BOOTSTRAP_KEY_SIZE');
  const digest=crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex').toUpperCase();need(p.keyDigest===digest&&/^[a-f0-9-]{36}$/.test(p.session)&&/^[a-f0-9-]{36}$/.test(p.device),'BOOTSTRAP_IDENTITY');
  const raw=req.headers['x-bimchat-proof'];need(typeof raw==='string'&&raw.length<=12000,'BOOTSTRAP_PROOF');const signed=JSON.parse(Buffer.from(raw,'base64').toString('utf8'));
  const c=await pool.connect();try{await c.query('BEGIN');const first=await load(c,req.user.email,false);await scope.lock(c,first.h.projectId);const {h,role,now}=await load(c,req.user.email,true);
   need(Object.keys(p).sort().join(',')===['attempt','expiresAt','email','session','device','logicalCentralPath','drive','revit','addinBuild','publicJwk','keyDigest'].concat(body.stage==='native'?['native']:[]).sort().join(','),'BOOTSTRAP_PROFILE_FIELDS');
   need(h.state==='bootstrap'&&h.enabled===false&&p.attempt===id&&p.email===req.user.email&&p.logicalCentralPath===h.logicalCentralPath&&p.drive.sha256===h[role+'Build']&&p.addinBuild===h[role+'AddinBuild']&&Number.isSafeInteger(p.expiresAt)&&p.expiresAt>now&&p.expiresAt<=Math.min(h.bootstrapExpiresAt,now+600000),'BOOTSTRAP_SCOPE_BUILD');
   for(const peer of [p.drive,p.revit])need(Object.keys(peer).sort().join(',')==='path,pid,sha256,started,startedTicks'&&Number.isSafeInteger(peer.pid)&&peer.pid>0&&typeof peer.path==='string'&&peer.path.length<=4096&&/^[A-Za-z]:\\/.test(peer.path)&&/^[A-F0-9]{64}$/.test(peer.sha256)&&typeof peer.startedTicks==='string'&&/^[0-9]{17,19}$/.test(peer.startedTicks)&&typeof peer.started==='string'&&Number.isFinite(Date.parse(peer.started)),'BOOTSTRAP_PEER');
   proof.verify(signed,{email:req.user.email,method:'POST',path:'/drive/ownership/session-proposal',body},{email:req.user.email,sessionId:p.session,deviceId:p.device,publicJwk:p.publicJwk,publicKeyDigest:digest},approvedDigest,now);
   h.bootstrapProposals=h.bootstrapProposals||{};const prior=h.bootstrapProposals[role];
   if(body.stage==='offer')need(!prior,'BOOTSTRAP_OFFER_ONCE');
   else{need(prior&&prior.stage==='offer','BOOTSTRAP_NATIVE_ONCE');const old=structuredClone(p);delete old.native;need(proof.canonical(old)===proof.canonical(prior.profile),'BOOTSTRAP_PROFILE_CHANGED');
    need(p.native&&Object.keys(p.native).sort().join(',')==='mapping,pins'&&p.native.mapping&&Object.keys(p.native.mapping).sort().join(',')==='CentralLogical,CentralPhysical,DocumentPhysical,ElementId,ElementUniqueId,GroupMember,OwnershipPhysical,ProjectId,RevitUser'&&p.native.pins&&p.native.mapping.CentralLogical===h.logicalCentralPath&&p.native.mapping.ProjectId===h.projectId&&typeof p.native.mapping.ElementUniqueId==='string'&&p.native.mapping.ElementUniqueId.length<=128&&(!h.elementUniqueId||p.native.mapping.ElementUniqueId===h.elementUniqueId),'BOOTSTRAP_NATIVE_MAPPING');require('./source-open-v1/source-policy.cjs').pins(p.native.pins);
   }
   need((await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[signed.payload.nonce,approvedDigest,req.user.email,p.session])).rowCount===1,'BOOTSTRAP_REPLAY');
   h.bootstrapProposals[role]={stage:body.stage,profile:p,signed,receivedAt:now};
   await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);await c.query('COMMIT');const paired=body.stage==='native'&&h.bootstrapProposals.source&&h.bootstrapProposals.source.stage==='native'&&h.bootstrapProposals.receiver&&h.bootstrapProposals.receiver.stage==='native';if(paired)await require('./product-bootstrap-enrollment.cjs').activateAutomatic(pool,id);return{accepted:true,stage:body.stage,active:!!paired};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 function mount(app,jwt){app.get('/drive/ownership/session',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await get(req.user.email));}catch{res.status(423).json({code:'OWNERSHIP_BOOTSTRAP_UNAVAILABLE'});}});app.post('/drive/ownership/session-proposal',jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await propose(req));}catch{res.status(423).json({code:'OWNERSHIP_BOOTSTRAP_STOP_NO_RETRY'});}});}
 return{get,propose,mount};
};
