'use strict';
const scope=require('../ephemeral-attempt-v1/scope.cjs');
const {need}=scope,{bindReceiver}=require('./receiver-auth.cjs');
const {requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs');
// Existing attempts/document + events tables. No migration/startup/mount/provisioning.
// New review fields are mandatory; old closed-only attempts fail closed.
module.exports=function({pool,verifyOpenReceiver,verifyAppliedReceipt}){
 need(pool&&typeof verifyOpenReceiver==='function'&&typeof verifyAppliedReceipt==='function','RECEIVER_TRUSTED_ADAPTERS');
 async function act(id,auth,body,event){
  need(typeof id==='string'&&/^[a-f0-9-]{36}$/i.test(id)&&auth&&body&&typeof body==='object','RECEIVER_REQUEST');
  const c=await pool.connect();try{await c.query('BEGIN');
   const initial=(await c.query('SELECT project_id FROM bimchat_direct_ownership.attempts WHERE id=$1',[id])).rows[0];need(initial,'RECEIVER_ATTEMPT_UNKNOWN');
   await scope.lock(c,initial.project_id);
   const stored=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[id])).rows[0];need(stored&&stored.project_id===initial.project_id,'RECEIVER_SCOPE_CHANGED');
   const h=JSON.parse(JSON.stringify(stored.document));
   need(h.id===id&&h.projectId===stored.project_id&&h.reviewDigest===auth.reviewDigest&&h.receiverEmail===auth.email&&h.receiverSession===auth.sessionId&&h.receiverDevice===auth.deviceId,'RECEIVER_BOUND_ATTEMPT');
   need(h.enabled===true&&h.receiverMode==='open-ui-turn'&&typeof h.centralPath==='string'&&typeof h.logicalCentralPath==='string'&&typeof h.elementUniqueId==='string'&&h.receiverPins&&typeof h.receiverPins.rootIdentity==='string','RECEIVER_OPEN_REVIEW_REQUIRED');
   need(Number.isSafeInteger(h.revision)&&h.revision>=0&&h.revision<2147483647,'RECEIVER_REVISION');
   await requireActive(c,auth,h.projectId,h.centralPath,require('../source-open-v1/controlled-cycle.cjs').enrollmentRole(h,'receiver'));
   need(body.operationId===h.operationId&&body.digest===h.digest,'RECEIVER_OPERATION_DIGEST');
   let result;
   if(event==='apply-begin'){
    need(h.state==='pending','RECEIVER_BEGIN_ONCE');
    // Adapter checks fresh independent native/process/build/model/idle evidence;
    // a receiver-supplied idle boolean is never sufficient.
    const nativeLease=await verifyOpenReceiver(c,h,body,auth);need(nativeLease&&Number.isSafeInteger(nativeLease.expiresAt),'RECEIVER_NATIVE_EVIDENCE');
    const grant=await bindReceiver(c,auth,{enrollment_role:require('../source-open-v1/controlled-cycle.cjs').enrollmentRole(h,'receiver'),state:h.state,review_digest:h.reviewDigest,receiver_email:h.receiverEmail,receiver_session:h.receiverSession,receiver_device:h.receiverDevice,project_id:h.projectId,central_path:h.centralPath,id:h.operationId,logical_central_path:h.logicalCentralPath,element_unique_id:h.elementUniqueId,receiver_root_identity:h.receiverPins.rootIdentity});
    const time=(await c.query('SELECT clock_timestamp() now')).rows[0].now;const now=+new Date(time);
    need(Number.isSafeInteger(h.expiresAt)&&h.expiresAt>now,'RECEIVER_ATTEMPT_EXPIRED');grant.expiresAt=Math.min(grant.expiresAt,h.expiresAt,nativeLease.expiresAt);if(h.ordinaryUserChanges===true&&h.transportMode!=='background-prepared'){need(h.sourceObservation&&Number.isSafeInteger(h.sourceObservation.holdExpiresAt),'USER_CHANGE_SOURCE_HOLD');grant.expiresAt=Math.min(grant.expiresAt,h.sourceObservation.holdExpiresAt);}need(grant.expiresAt>now,'RECEIVER_NATIVE_LEASE_EXPIRED');
    h.state='apply-attempted';h.receiverApplyExpiresAt=grant.expiresAt;result={...grant,state:h.state,generation:h.generation,digest:h.digest};
   }else if(event==='applied'){
    need(h.state==='apply-attempted','RECEIVER_ACK_STATE');
    const time=(await c.query('SELECT clock_timestamp() now')).rows[0].now;
    need(Number.isFinite(h.receiverApplyExpiresAt)&&+new Date(time)<h.receiverApplyExpiresAt,'RECEIVER_APPLY_EXPIRED');
    need(await verifyAppliedReceipt(c,h,body,auth)===true,'RECEIVER_RECEIPT');h.receiverReceipt=JSON.parse(JSON.stringify(body.receipt));if(h.ordinaryUserChanges===true){need(h.nativeAction==='observe-user-change'&&!h.cycle,'USER_CHANGE_MODE');h.state='recovery';h.enabled=false;result={state:h.state,operationId:h.operationId,fenced:true,baselineCheckpointRequired:true};}else if(h.cycle&&require('../source-open-v1/controlled-cycle.cjs').leg(h)===1){need(h.nativeAction==='relinquish','CYCLE_RELEASE_ACTION');h.state='recovery';h.enabled=false;result={state:h.state,operationId:h.operationId,fenced:true,cycleCheckpointRequired:true};}else{h.state='native-verification-required';result={state:h.state,operationId:h.operationId,fenced:true};}
   }else{need(event==='stop'&&h.state!=='released','RECEIVER_STOP_STATE');h.state='recovery';h.enabled=false;result={state:h.state,fenced:true};}
   // Recheck after potentially slow native/storage evidence work. No late commit.
   await requireActive(c,auth,h.projectId,h.centralPath,require('../source-open-v1/controlled-cycle.cjs').enrollmentRole(h,'receiver'));
   if(event!=='stop'){
    const finalClock=(await c.query('SELECT clock_timestamp() now')).rows[0].now;
    const finalNow=+new Date(finalClock);
    need(Number.isFinite(finalNow)&&finalNow<h.expiresAt&&finalNow<h.receiverApplyExpiresAt,'RECEIVER_COMMIT_EXPIRED');
   }
   h.revision++;await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);
   await c.query('INSERT INTO bimchat_direct_ownership.events(attempt_id,revision,event) VALUES($1,$2,$3)',[id,h.revision,event]);await c.query('COMMIT');return result;
  }catch(e){try{await c.query('ROLLBACK');}catch{}throw e;}finally{c.release();}
 }
 return {begin:({id,body,auth})=>act(id,auth,body,'apply-begin'),applied:({id,body,auth})=>act(id,auth,body,'applied'),stop:({id,body,auth})=>act(id,auth,body,'stop')};
};

