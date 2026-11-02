'use strict';
const pathEqual=require('./scoped-api-v11/scope.cjs').equal;
const scope=require('./ephemeral-attempt-v1/scope.cjs'),proof=require('./ephemeral-attempt-v1/device-proof.cjs'),policy=require('./source-open-v1/source-policy.cjs'),cycle=require('./source-open-v1/controlled-cycle.cjs');const {need}=scope;
// Operator-only, deliberately NOT mounted. Caller approves the exact pair digest
// after reviewing both normal-product proposals and the already sealed baseline.
function prepare(head,pairDigest,now){
 const h=structuredClone(head),pair=h.bootstrapProposals;
 need(h.state==='bootstrap'&&h.enabled===false&&(h.ordinaryUserChanges===true?h.automaticEnrollmentApproved===true&&h.transportMode==='background-prepared'&&!h.cycle:h.controlledCycleApproved===true&&h.disposableModelRelinquishApproved===true)&&pair&&proof.hash(pair)===pairDigest,'BOOTSTRAP_PAIR_REVIEW');
 const participants=[];
 for(const role of ['source','receiver']){const proposal=pair[role],p=proposal&&proposal.profile;need(proposal&&proposal.stage==='native'&&p.email===h[role+'Email']&&p.attempt===h.id&&p.drive.sha256===h[role+'Build']&&p.addinBuild===h[role+'AddinBuild'],'BOOTSTRAP_PAIR_BINDING');
  proof.verify(proposal.signed,{email:p.email,method:'POST',path:'/drive/ownership/session-proposal',body:{stage:proposal.proofStage||'native',profile:p}},{email:p.email,sessionId:p.session,deviceId:p.device,publicJwk:p.publicJwk,publicKeyDigest:p.keyDigest},h.bootstrapPlanDigest,proposal.receivedAt);
  need(p.expiresAt>now+90000&&p.expiresAt<=require('./product-session-lifetime.cjs').enrollmentLimit(h,now),'BOOTSTRAP_KEY_WINDOW');const m=p.native.mapping;
  if(h.renewalPrevious){need(h.renewalEvidenceDigest&&h.renewalBaselinePins&&proof.canonical(p.native.pins)===proof.canonical(h.renewalBaselinePins[p.email]),'BOOTSTRAP_RENEWAL_PREIMAGE_CHANGED');need(p.session!==h.renewalPrevious.sourceSession&&p.session!==h.renewalPrevious.receiverSession,'BOOTSTRAP_RENEWAL_SESSION_REUSED');}
  need(m.CentralLogical===h.logicalCentralPath&&m.ProjectId===h.projectId&&!m.GroupMember&&typeof m.ElementUniqueId==='string','BOOTSTRAP_MODEL_BINDING');policy.pins(p.native.pins);
  if(h.ordinaryUserChanges===true)need(m.IdentityKind==='project-information','BOOTSTRAP_MODEL_IDENTITY_KIND');
  h[role+'Session']=p.session;h[role+'Device']=p.device;h[role+'AgentPublicKey']=p.publicJwk;h[role+'PublicKeyDigest']=p.keyDigest;
  h[role+'Pins']=p.native.pins;h[role+'MappingHash']=proof.hash(m);h[role+'RevitUser']=m.RevitUser;
  h[role+'AgentPid']=p.drive.pid;h[role+'AgentStarted']=p.drive.started;h[role+'RevitPid']=p.revit.pid;h[role+'RevitStarted']=p.revit.started;
  participants.push({email:p.email,sessionId:p.session,deviceId:p.device,publicJwk:p.publicJwk,publicKeyDigest:p.keyDigest,agentBuild:p.drive.sha256,addinBuild:p.addinBuild,mappingHash:h[role+'MappingHash']});
 }
 const a=pair.source.profile,b=pair.receiver.profile;
 need(a.native.mapping.ElementUniqueId===b.native.mapping.ElementUniqueId&&a.native.mapping.RevitUser!==b.native.mapping.RevitUser&&a.email!==b.email&&a.session!==b.session&&a.device!==b.device,'BOOTSTRAP_DISTINCT_PAIR');
 policy.baselineMatch(h.sourcePins,h.receiverPins);h.elementUniqueId=a.native.mapping.ElementUniqueId;h.preBundle=policy.pins(h.sourcePins);
 h.pairedReview={bootstrapPlanDigest:h.bootstrapPlanDigest,pairDigest,projectId:h.projectId,centralPath:h.centralPath,logicalCentralPath:h.logicalCentralPath,elementUniqueId:h.elementUniqueId,sourceEmail:h.sourceEmail,participants};
 h.reviewDigest=proof.hash(h.pairedReview);h.expiresAt=Math.min(a.expiresAt,b.expiresAt,require('./product-session-lifetime.cjs').enrollmentLimit(h,now));h.generation=require('node:crypto').randomUUID();
 h.receiverMode='open-ui-turn';if(h.ordinaryUserChanges===true){h.nativeAction='observe-user-change';h.observedHistory=[];h.ordinaryEnrollmentSourceEmail=h.sourceEmail;}else{h.nativeAction='checkout';h.cycle={kind:cycle.kind,leg:0,history:[]};}h.state='armed';h.enabled=true;h.revision++;policy.validateReviewed(h);return h;
}
async function activate(pool,id,approvedPairDigest,authorization){const c=await pool.connect();try{await c.query('BEGIN');const first=(await c.query('SELECT project_id FROM bimchat_direct_ownership.attempts WHERE id=$1',[id])).rows[0];need(first,'BOOTSTRAP_UNKNOWN');await scope.lock(c,first.project_id);
 const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[id])).rows[0];need(row&&row.project_id===first.project_id,'BOOTSTRAP_SCOPE_CHANGED');const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);if(authorization&&authorization.automatic===true){need(row.document.ordinaryUserChanges===true&&row.document.automaticEnrollmentApproved===true,'AUTOMATIC_ENROLLMENT_NOT_APPROVED');approvedPairDigest=proof.hash(row.document.bootstrapProposals);}
 const h=prepare(row.document,approvedPairDigest,now);
 if(h.initialProvisioning&&!h.renewalPrevious){need(h.initialProvisioning.state==='sealed'&&h.bootstrapConfirmations?.source===true&&h.bootstrapConfirmations?.receiver===true,'BOOTSTRAP_FRESH_CONFIRMATIONS_REQUIRED');for(const r of ['source','receiver'])need(h.bootstrapProposals[r].proofStage==='confirm'&&now-h.bootstrapProposals[r].profile.native.capturedAt<=30000,'BOOTSTRAP_CONFIRMATION_EXPIRED');}
 if(authorization&&authorization.automatic!==true){const a=authorization,p=h.bootstrapProposals.source.profile;need(a.email===h.sourceEmail&&a.approverEmail===h.sourceEmail&&a.planDigest===h.bootstrapPlanDigest&&Object.keys(a.body).join(',')==='pairDigest'&&a.body.pairDigest===approvedPairDigest,'BOOTSTRAP_ACTIVATION_APPROVER');
  proof.verify(a.signed,{email:a.email,method:'POST',path:'/drive/ownership/bootstrap-activate',body:a.body},{email:p.email,sessionId:p.session,deviceId:p.device,publicJwk:p.publicJwk,publicKeyDigest:p.keyDigest},h.bootstrapPlanDigest,now);
  need((await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[a.signed.payload.nonce,h.bootstrapPlanDigest,a.email,p.session])).rowCount===1,'BOOTSTRAP_ACTIVATION_REPLAY');
 }
 const fenced=(await c.query('SELECT * FROM bimchat_direct_ownership.scopes WHERE id=$1 FOR UPDATE',[id])).rows[0];need(fenced&&fenced.state==='fenced'&&fenced.project_id===h.projectId&&fenced.file_id===h.fileId&&fenced.central_path===h.centralPath,'BOOTSTRAP_SCOPE_NOT_READY');
 const baseline=await require('./scoped-api-v11/baseline-r2.cjs').verify(c,id,h.baselinePublicationId);need(baseline.manifest_digest===h.baselineManifestDigest,'BOOTSTRAP_BASELINE_REVIEW');
 for(const f of h.sourcePins.files){const path=h.centralPath.replace(/\.rvt$/i,'')+'_backup/'+f.name,rows=baseline.manifest.filter(x=>pathEqual(x.path,path));need(rows.length===1&&rows[0].sha256===f.sha256&&rows[0].size===f.length,'BOOTSTRAP_BASELINE_CONTENT');}
 const work=(await c.query("SELECT relative_path FROM bimchat_direct_ownership.storage_work WHERE project_id=$1 AND state IN ('started','uncertain')",[h.projectId])).rows;need(!work.some(x=>x.relative_path==null||scope.group(h.centralPath,x.relative_path)),'BOOTSTRAP_STORAGE_BUSY');
 need((await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[h.fileId])).rowCount===0,'BOOTSTRAP_SYNC_BUSY');
 for(const role of ['source','receiver']){need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[h.projectId,h[role+'Email']])).rowCount===1,'BOOTSTRAP_MEMBER');
  // Never replace another existing or uncertain device/session record.
  need((await c.query("INSERT INTO isolated_revit_sessions(email,session_id,device_id,state) VALUES($1,$2,$3,'active') ON CONFLICT DO NOTHING RETURNING email",[h[role+'Email'],h[role+'Session'],h[role+'Device']])).rowCount===1,'BOOTSTRAP_EXISTING_SESSION_REQUIRES_REVIEW');
  await c.query("INSERT INTO bimchat_direct_ownership.publication_enrollments(review_digest,email,session_id,device_id,project_id,central_path,role,public_key_digest,state,not_before,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',to_timestamp($9/1000.0),to_timestamp($10/1000.0))",[h.reviewDigest,h[role+'Email'],h[role+'Session'],h[role+'Device'],h.projectId,h.centralPath,role,h[role+'PublicKeyDigest'],now,h.expiresAt]);
 }
 if(h.ordinaryUserChanges===true){h.ordinaryIdle=true;need((await c.query("UPDATE bimchat_direct_ownership.scopes SET state='released' WHERE id=$1 AND state='fenced' RETURNING id",[h.id])).rowCount===1,'AUTOMATIC_IDLE_SCOPE_CHANGED');}
 await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);await c.query('INSERT INTO bimchat_direct_ownership.events(attempt_id,revision,event) VALUES($1,$2,$3)',[id,h.revision,'operator-approved-product-bootstrap']);
 const end=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(end<h.expiresAt,'BOOTSTRAP_COMMIT_EXPIRED');await c.query('COMMIT');return{id,reviewDigest:h.reviewDigest,expiresAt:h.expiresAt,state:h.state};
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
// Call only after BOTH authenticated/pinned native proposals are committed.
// Active keys and accounts are still verified by prepare; this creates no key.
async function activateAutomatic(pool,id){return activate(pool,id,null,{automatic:true});}
module.exports={prepare,activate,activateAutomatic};
