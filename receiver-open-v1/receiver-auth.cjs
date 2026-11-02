'use strict';
const {requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs');
const {lock,need}=require('../ephemeral-attempt-v1/scope.cjs');
// Called INSIDE the existing apply-begin transaction after JWT and request-signature
// verification. Never converts a source publication grant into receiver authority.
async function bindReceiver(c,auth,operation){
 need(operation&&operation.state==='pending'&&operation.review_digest===auth.reviewDigest,'RECEIVER_OPERATION_STATE');
 need(operation.receiver_email===auth.email&&operation.receiver_session===auth.sessionId&&operation.receiver_device===auth.deviceId,'RECEIVER_OPERATION_IDENTITY');
 await lock(c,operation.project_id);
 const enrollment=await requireActive(c,auth,operation.project_id,operation.central_path,operation.enrollment_role||'receiver');
 const clock=(await c.query('SELECT clock_timestamp() now')).rows[0].now;
 const now=clock instanceof Date?clock.getTime():Date.parse(clock),end=enrollment.expires_at instanceof Date?enrollment.expires_at.getTime():Date.parse(enrollment.expires_at);
 need(Number.isFinite(now)&&Number.isFinite(end)&&end>now,'RECEIVER_EXPIRED');
 return {operationId:operation.id,reviewDigest:auth.reviewDigest,receiverSession:auth.sessionId,receiverDevice:auth.deviceId,logicalCentralPath:operation.logical_central_path,elementUniqueId:operation.element_unique_id,receiverRootIdentity:operation.receiver_root_identity,expiresAt:Math.min(end,now+30000)};
}
module.exports={bindReceiver};
