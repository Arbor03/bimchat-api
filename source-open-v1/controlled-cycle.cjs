'use strict';
const crypto=require('node:crypto'),{need}=require('../ephemeral-attempt-v1/scope.cjs');
const protocol=require('./protocol.cjs'),{pins}=require('./source-policy.cjs');
const kind='borrow-relinquish-reverse-v1';
const identityFields=['Email','Session','Device','AgentPublicKey','PublicKeyDigest','Build','MappingHash','RevitUser','AgentPid','AgentStarted','RevitPid','RevitStarted','AddinBuild'];
function leg(h){if(!h.cycle)return -1;need(h.cycle.kind===kind&&h.controlledCycleApproved===true&&h.disposableModelRelinquishApproved===true&&Number.isInteger(h.cycle.leg)&&h.cycle.leg>=0&&h.cycle.leg<=2&&Array.isArray(h.cycle.history)&&h.cycle.history.length===(h.state==='cycle-complete-fenced'?3:h.cycle.leg),'CYCLE_REVIEW');return h.cycle.leg;}
function enrollmentRole(h,role){need(role==='source'||role==='receiver','CYCLE_ROLE');if(h.ordinaryUserChanges===true&&h.ordinaryEnrollmentSourceEmail){need(!h.cycle&&[h.sourceEmail,h.receiverEmail].includes(h.ordinaryEnrollmentSourceEmail),'USER_ENROLLMENT_BINDING');return h[role+'Email']===h.ordinaryEnrollmentSourceEmail?'source':'receiver';}return leg(h)===2?(role==='source'?'receiver':'source'):role;}
function validatePostPins(h,role,current){
 const old=h[role+'Pins'],e=JSON.parse(h.wire);need(protocol.canonical(e)===h.wire&&protocol.validate(e)===h.digest,'CYCLE_WIRE');
 pins(current);need(current.rootIdentity===old.rootIdentity,'CYCLE_ROOT_CHANGED');
 current.files.forEach((f,i)=>{const p=old.files[i],t=e.Files[i];need(f.name===p.name&&f.name===t.Name&&f.identity===p.identity&&f.length===t.PostLength&&f.sha256===t.PostHash,'CYCLE_POSTIMAGE_CHANGED');});
 need(current.files[0].sha256===old.files[0].sha256&&current.files[0].length===old.files[0].length,'CYCLE_USERS_CHANGED');
 return current;
}
// Caller must authenticate BOTH fresh native/UI-held checkpoints in the locked
// transaction. No IO, unlock, activation, key generation or baseline guessing here.
function advance(head,source,receiver,now){
 const n=leg(head);need(n>=0&&head.enabled===false&&head.state==='recovery'&&now<head.expiresAt,'CYCLE_NOT_READY');
 need(head.receiverReceipt&&head.receiverReceipt.journalComplete===true,'CYCLE_APPLY_RECEIPT_REQUIRED');
 if(n!==1)need(head.nativeVerification&&head.nativeVerification.returnedTarget===false&&head.nativeVerification.unexpectedReturnedElements===false,'CYCLE_BLOCK_NOT_DEMONSTRATED');
 else need(head.nativeAction==='relinquish'&&!head.nativeVerificationStartedAt,'CYCLE_RELEASE_MUST_NOT_CHECKOUT');
 validatePostPins(head,'source',source);validatePostPins(head,'receiver',receiver);need(pins(source)===pins(receiver),'CYCLE_BASELINES_DIVERGED');
 const h=structuredClone(head);h.cycle.history.push({generation:h.generation,operationId:h.operationId,digest:h.digest,wire:h.wire,nativeAction:h.nativeAction||'checkout',receiverReceipt:h.receiverReceipt,nativeVerification:h.nativeVerification||null,sourcePins:source,receiverPins:receiver});
 if(n===2){h.state='cycle-complete-fenced';h.enabled=false;h.revision++;return h;}
 h.sourcePins=structuredClone(source);h.receiverPins=structuredClone(receiver);
 if(n===1){for(const suffix of identityFields){const x=h['source'+suffix];h['source'+suffix]=h['receiver'+suffix];h['receiver'+suffix]=x;}[h.sourcePins,h.receiverPins]=[h.receiverPins,h.sourcePins];}
 h.cycle.leg=n+1;h.preBundle=pins(h.sourcePins);h.generation=crypto.randomUUID();h.nativeAction=n===0?'relinquish':'checkout';
 for(const key of ['preparedSourceGrant','receiverAttestedAt','sourceFenceProof','operationId','digest','postBundle','wire','receiverApplyExpiresAt','receiverReceipt','nativeVerificationStartedAt','nativeVerificationExpiresAt','nativeVerification','verificationOutcome','quiescence','cycleCheckpoints'])delete h[key];
 h.state='armed';h.enabled=true;h.revision++;return h;
}
function advanceObserved(head,source,receiver,now,nextSourceEmail){
 need(head.ordinaryUserChanges===true&&head.nativeAction==='observe-user-change'&&!head.cycle&&head.state==='recovery'&&head.enabled===false&&now<head.expiresAt,'USER_BASELINE_NOT_READY');
 need(head.receiverReceipt&&head.receiverReceipt.journalComplete===true&&!head.nativeVerificationStartedAt,'USER_BASELINE_RECEIPT');
 validatePostPins(head,'source',source);validatePostPins(head,'receiver',receiver);need(pins(source)===pins(receiver),'USER_BASELINE_DIVERGED');
 need(nextSourceEmail===head.sourceEmail||nextSourceEmail===head.receiverEmail,'USER_NEXT_SOURCE_REQUIRED');
 const h=structuredClone(head);h.observedHistory=h.observedHistory||[];need(Array.isArray(h.observedHistory)&&h.observedHistory.length<32,'USER_BASELINE_HISTORY_BOUND');
 h.ordinaryEnrollmentSourceEmail=h.ordinaryEnrollmentSourceEmail||h.sourceEmail;
 h.observedHistory.push({generation:h.generation,operationId:h.operationId,digest:h.digest,wire:h.wire,receiverReceipt:h.receiverReceipt,sourcePins:source,receiverPins:receiver});
 h.sourcePins=structuredClone(source);h.receiverPins=structuredClone(receiver);
 if(nextSourceEmail===h.receiverEmail){for(const suffix of identityFields){const x=h['source'+suffix];h['source'+suffix]=h['receiver'+suffix];h['receiver'+suffix]=x;}[h.sourcePins,h.receiverPins]=[h.receiverPins,h.sourcePins];}
 h.preBundle=pins(h.sourcePins);h.generation=crypto.randomUUID();
 for(const k of ['sourceFenceProof','operationId','digest','postBundle','wire','observedSourcePins','sourceObservation','receiverApplyExpiresAt','receiverReceipt','cycleCheckpoints','ordinaryClaim','receiverPreparedGeneration'])delete h[k];
 h.state='armed';h.enabled=true;h.revision++;return h;
}
function claimObserved(head,email){
 need(head.ordinaryUserChanges===true&&head.transportMode==='background-prepared'&&!head.cycle&&head.enabled===true&&head.state==='armed'&&!head.ordinaryClaim&&!head.receiverPreparedGeneration&&!head.renewalProposals,'USER_CLAIM_BUSY');
 need(email===head.sourceEmail||email===head.receiverEmail,'USER_CLAIM_PARTICIPANT');const h=structuredClone(head);h.ordinaryEnrollmentSourceEmail=h.ordinaryEnrollmentSourceEmail||h.sourceEmail;
 if(email===h.receiverEmail){for(const suffix of identityFields){const x=h['source'+suffix];h['source'+suffix]=h['receiver'+suffix];h['receiver'+suffix]=x;}[h.sourcePins,h.receiverPins]=[h.receiverPins,h.sourcePins];}
 h.ordinaryClaim={email,generation:h.generation};h.ordinaryIdle=false;h.revision++;return h;
}
module.exports={kind,leg,enrollmentRole,validatePostPins,advance,advanceObserved,claimObserved};
