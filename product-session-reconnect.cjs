'use strict';
const {need}=require('./ephemeral-attempt-v1/scope.cjs'),scope=require('./scoped-api-v11/scope.cjs');
// Called inside the model/account-checked connection transaction and project
// advisory lock. Expiry alone never authorizes resetting an in-flight operation.
module.exports=async function reconnect(c,original,email){
 const h=structuredClone(original),now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);
 need(require('./product-session-lifetime.cjs').continuous(h),'RECONNECT_MODE');
 const proposals=Object.values(h.bootstrapProposals||{}),mine=proposals.find(p=>p.profile.email===email);
 if(h.state==='bootstrap'&&!mine&&!h.initialProvisioning&&!h.bootstrapActivation)return {waiting:false,changed:false};
 if(h.state==='bootstrap'&&!mine&&h.renewalPrevious&&!h.bootstrapActivation)return {waiting:false,changed:false};
 if(h.state==='armed'&&Number.isSafeInteger(h.expiresAt)&&now<h.expiresAt)return {waiting:true,changed:false};
 if(h.state==='bootstrap'&&proposals.some(p=>Number.isSafeInteger(p.profile.expiresAt)&&now<p.profile.expiresAt))return {waiting:!!mine,changed:false};
 need(h.state==='bootstrap'||(h.state==='armed'&&h.enabled===true&&h.ordinaryIdle===true&&Number.isSafeInteger(h.expiresAt)&&now>=h.expiresAt),'RECONNECT_NOT_IDLE');
 need(!h.ordinaryClaim&&!h.receiverPreparedGeneration&&!h.renewalProposals&&!h.postSyncRequired&&!h.postSyncReconcile&&!h.postSyncNeedsReconciliation,'RECONNECT_PENDING_OPERATION');
 need(!h.initialProvisioning||h.initialProvisioning.state==='sealed','RECONNECT_UNCERTAIN_PROVISIONING');
 need(h.bootstrapActivation!=='failed'&&h.bootstrapActivation!=='pending','RECONNECT_UNCERTAIN_ACTIVATION');
 const s=(await c.query('SELECT * FROM bimchat_direct_ownership.scopes WHERE id=$1 FOR UPDATE',[h.id])).rows[0];
 const sealed=!!h.baselinePublicationId;
 if(sealed){need(s&&s.project_id===h.projectId&&s.file_id===h.fileId&&s.central_path===h.centralPath&&s.state===(h.state==='armed'?'released':'fenced'),'RECONNECT_SCOPE');await require('./scoped-api-v11/baseline-r2.cjs').verify(c,h.id,h.baselinePublicationId);}
 else need(!s&&!h.initialProvisioning,'RECONNECT_SCOPE_UNRESOLVED');
 need((await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[h.fileId])).rowCount===0,'RECONNECT_SYNC_BUSY');
 const work=(await c.query("SELECT relative_path FROM bimchat_direct_ownership.storage_work WHERE project_id=$1 AND state IN ('started','uncertain')",[h.projectId])).rows;
 need(!work.some(w=>w.relative_path==null||scope.group(h.centralPath,w.relative_path)),'RECONNECT_STORAGE_UNCERTAIN');
 const previous={reviewDigest:h.reviewDigest||h.bootstrapPlanDigest,sourceEmail:h.sourceEmail,receiverEmail:h.receiverEmail},baselinePins={};
 for(const email of [h.sourceEmail,h.receiverEmail].sort())await c.query('SELECT pg_advisory_xact_lock(193722,hashtext($1))',[email]);
 for(const role of ['source','receiver']){
  const p=h.bootstrapProposals?.[role]?.profile,session=h[role+'Session']||p?.session,device=h[role+'Device']||p?.device;
  if(sealed){need(session&&device,'RECONNECT_PRIOR_BINDING');previous[role+'Session']=session;previous[role+'Device']=device;baselinePins[h[role+'Email']]=h[role+'Pins']||p?.native?.pins;need(baselinePins[h[role+'Email']],'RECONNECT_PRIOR_PINS');}
  if(!session)continue;
  need((await c.query('SELECT 1 FROM file_locks WHERE session_id=$1 LIMIT 1',[session])).rowCount===0,'RECONNECT_LEGACY_LOCK');
  need((await c.query("SELECT 1 FROM isolated_publications WHERE owner_session_id=$1 AND (state IS NULL OR state NOT IN ('published','unverified')) LIMIT 1",[session])).rowCount===0,'RECONNECT_LEGACY_PUBLICATION');
  need((await c.query("SELECT 1 FROM bimchat_direct_ownership.model_publications WHERE session_id=$1 AND state<>'released'",[session])).rowCount===0,'RECONNECT_PUBLICATION');
  need((await c.query("SELECT 1 FROM bimchat_direct_ownership.attempts WHERE id<>$1 AND (document->>'sourceSession'=$2 OR document->>'receiverSession'=$2) AND document->>'state' NOT IN ('released','disabled')",[h.id,session])).rowCount===0,'RECONNECT_SHARED_ATTEMPT');
  const enrollments=(await c.query("SELECT * FROM bimchat_direct_ownership.publication_enrollments WHERE session_id=$1 AND state='active' FOR UPDATE",[session])).rows;
  const live=h.state==='armed';need(enrollments.length===(live?1:0),'RECONNECT_ENROLLMENT_COUNT');
  if(live){const e=enrollments[0];need(e.email===h[role+'Email']&&e.device_id===device&&e.project_id===h.projectId&&e.central_path===h.centralPath&&e.review_digest===h.reviewDigest&&Number.isFinite(+new Date(e.expires_at))&&+new Date(e.expires_at)<=now,'RECONNECT_ENROLLMENT_BINDING');
   need((await c.query("UPDATE bimchat_direct_ownership.publication_enrollments SET state='revoked',not_before=NULL,expires_at=NULL WHERE review_digest=$1 AND email=$2 AND session_id=$3 AND device_id=$4 AND state='active' RETURNING email",[h.reviewDigest,h[role+'Email'],session,device])).rowCount===1,'RECONNECT_ENROLLMENT_RACE');
   need((await c.query("DELETE FROM isolated_revit_sessions WHERE email=$1 AND session_id=$2 AND device_id=$3 AND state='active' RETURNING email",[h[role+'Email'],session,device])).rowCount===1,'RECONNECT_SESSION_RACE');
  }else need((await c.query('SELECT 1 FROM isolated_revit_sessions WHERE session_id=$1',[session])).rowCount===0,'RECONNECT_UNEXPECTED_SESSION');
 }
 await c.query('INSERT INTO bimchat_direct_ownership.baseline_history(scope_id,publication_id,baseline,evidence) VALUES($1,$2,$3,$4)',[h.id,h.generation,JSON.stringify({kind:'connection-retirement',baselinePublicationId:h.baselinePublicationId||null}),JSON.stringify({head:h,at:now,reason:'expired-idle-runtime'})]);
 await c.query("UPDATE bimchat_direct_ownership.normal_upload_receipts SET state='revoked' WHERE scope_id=$1 AND state='issued'",[h.id]);
 if(sealed&&h.state==='armed')need((await c.query("UPDATE bimchat_direct_ownership.scopes SET state='fenced' WHERE id=$1 AND state='released' RETURNING id",[h.id])).rowCount===1,'RECONNECT_SCOPE_RACE');
 if(h.ordinaryEnrollmentSourceEmail&&h.sourceEmail!==h.ordinaryEnrollmentSourceEmail)for(const suffix of ['Email','Build','AddinBuild'])[h['source'+suffix],h['receiver'+suffix]]=[h['receiver'+suffix],h['source'+suffix]];
 for(const k of ['bootstrapProposals','bootstrapConfirmations','bootstrapActivation','connectionReadiness','pairedReview','reviewDigest','expiresAt','ordinaryEnrollmentSourceEmail','ordinaryIdle','observedHistory','sourceFenceProof','operationId','digest','postBundle','wire','observedSourcePins','sourceObservation','receiverApplyExpiresAt','receiverReceipt','cycleCheckpoints','preparedSourceGrant','receiverAttestedAt','nativeVerificationStartedAt','nativeVerificationExpiresAt','nativeVerification','verificationOutcome','quiescence','syncRelease'])delete h[k];
 for(const role of ['source','receiver'])for(const suffix of ['Session','Device','AgentPublicKey','PublicKeyDigest','MappingHash','RevitUser','AgentPid','AgentStarted','RevitPid','RevitStarted','Pins'])delete h[role+suffix];
 h.generation=require('node:crypto').randomUUID();h.state='bootstrap';h.enabled=false;h.revision++;h.bootstrapExpiresAt=null;
 if(sealed){h.renewalPrevious=previous;h.renewalBaselinePins=baselinePins;h.renewalEvidenceDigest=require('./ephemeral-attempt-v1/device-proof.cjs').hash({previous,baselinePins,at:now});}
 await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[h.id,JSON.stringify(h)]);
 return {waiting:false,changed:true};
};
