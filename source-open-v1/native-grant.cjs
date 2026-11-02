'use strict';
const crypto=require('node:crypto'),evidence=require('./open-evidence.cjs'),{canonical}=require('./protocol.cjs');
const {need}=require('../ephemeral-attempt-v1/scope.cjs'),{requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs');
// Called by reviewed source transaction/host adapters while their scope lock is held.
// Mapping comes from enrolled local review, not an HTTP body or discovery fallback.
async function prepare(c,h,auth,mapping,operationId){
 need(h&&h.enabled===true&&h.state==='receiver-ready'&&auth.email===h.sourceEmail&&auth.sessionId===h.sourceSession&&auth.deviceId===h.sourceDevice&&auth.reviewDigest===h.reviewDigest&&auth.publicKeyDigest===h.sourcePublicKeyDigest,'SOURCE_GRANT_PRINCIPAL');
 need(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(operationId),'SOURCE_GRANT_OPERATION');
 need(!h.nativeAction||h.nativeAction==='checkout'||(h.nativeAction==='relinquish'&&h.disposableModelRelinquishApproved===true),'SOURCE_NATIVE_ACTION_REVIEW');const local=JSON.parse(canonical(mapping));need(crypto.createHash('sha256').update(canonical(local)).digest('hex').toUpperCase()===h.sourceMappingHash,'SOURCE_GRANT_MAPPING');
 need(local.CentralLogical===h.logicalCentralPath&&local.ElementUniqueId===h.elementUniqueId&&local.RevitUser===h.sourceRevitUser&&typeof local.CentralPhysical==='string'&&typeof local.DocumentPhysical==='string','SOURCE_GRANT_NATIVE_BINDING');
 await requireActive(c,auth,h.projectId,h.centralPath,require('./controlled-cycle.cjs').enrollmentRole(h,'source'));const lease=await evidence.readVerified(c,h);
 const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);evidence.openReady(h,{receiverOpenLease:lease},now);
 const end=Math.min(h.expiresAt,lease.expiresAt,lease.timestamp+10000);need(Number.isSafeInteger(end)&&end>now,'SOURCE_GRANT_EXPIRED');
 return {Operation:operationId,Phase:h.nativeAction==='relinquish'?'source-relinquish':'source-checkout',CentralPhysical:local.CentralPhysical,CentralLogical:local.CentralLogical,DocumentPhysical:local.DocumentPhysical,ElementUniqueId:local.ElementUniqueId,RevitUser:local.RevitUser,Generation:h.generation,SourceSession:h.sourceSession,SourceRootIdentity:h.sourcePins.rootIdentity,ReceiverRootIdentity:h.receiverPins.rootIdentity,ExpiresUtc:new Date(end).toISOString(),ReceiverMode:'open-ui-turn',ReceiverHoldExpiresUtc:new Date(lease.expiresAt).toISOString(),ReceiverObservationDigest:crypto.createHash('sha256').update(canonical(lease)).digest('hex').toUpperCase(),ReceiverMappedModelVerified:false};
}
// Return only AFTER native-begin transition committed; caller must not release sticky fences.
async function acknowledgement(c,h,auth,grant){
 need(h.state==='native-attempted'&&h.operationId===grant.Operation&&h.generation===grant.Generation&&h.sourceSession===grant.SourceSession&&auth.email===h.sourceEmail&&auth.sessionId===h.sourceSession&&auth.deviceId===h.sourceDevice&&auth.reviewDigest===h.reviewDigest&&auth.publicKeyDigest===h.sourcePublicKeyDigest,'SOURCE_ACK_CONTEXT');
 await requireActive(c,auth,h.projectId,h.centralPath,require('./controlled-cycle.cjs').enrollmentRole(h,'source'));const lease=await evidence.readVerified(c,h);
 const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);evidence.openReady(h,{receiverOpenLease:lease},now);
 const digest=crypto.createHash('sha256').update(canonical(lease)).digest('hex').toUpperCase();need(grant.ReceiverMode==='open-ui-turn'&&digest===grant.ReceiverObservationDigest&&Date.parse(grant.ReceiverHoldExpiresUtc)===lease.expiresAt&&Number.isFinite(Date.parse(grant.ExpiresUtc))&&now<Date.parse(grant.ExpiresUtc)&&Date.parse(grant.ExpiresUtc)<=Math.min(h.expiresAt,lease.expiresAt,lease.timestamp+10000),'SOURCE_ACK_HOLD');
 return {recorded:true,operationId:h.operationId,receiverMode:'open-ui-turn',receiverObservationDigest:digest,receiverHoldExpiresAt:lease.expiresAt};
}
module.exports={prepare,acknowledgement};

