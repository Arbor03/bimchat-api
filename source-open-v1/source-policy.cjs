'use strict';
// Pure model-specific policy. No IO, listener, provisioning, fixtures or credential access.
const crypto=require('node:crypto');
const protocol=require('./protocol.cjs');
const {openReady}=require('./open-evidence.cjs');
const names=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];
const uuid=s=>typeof s==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(s);
const hash=s=>typeof s==='string'&&/^[A-F0-9]{64}$/.test(s);
function need(ok,code){if(!ok)throw Object.assign(Error(code),{status:409});}
function exact(v,keys){need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join('|')===keys.slice().sort().join('|'),'DIRECT_FIELDS');}
function pins(p){exact(p,['rootIdentity','files']);need(typeof p.rootIdentity==='string'&&/^[A-F0-9]{8}:[A-F0-9]{16}$/.test(p.rootIdentity),'DIRECT_ROOT_PIN');need(Array.isArray(p.files)&&p.files.length===5,'DIRECT_FIVE_FILES');
 p.files.forEach((f,i)=>{exact(f,['name','identity','length','sha256']);need(f.name===names[i]&&typeof f.identity==='string'&&/^[A-F0-9]{8}:[A-F0-9]{16}$/.test(f.identity)&&Number.isSafeInteger(f.length)&&f.length>=0&&f.length<=8388608&&hash(f.sha256),'DIRECT_FILE_PIN');});
 return crypto.createHash('sha256').update(p.files.map(f=>f.name+':'+f.length+':'+f.sha256).join('\n')).digest('hex').toUpperCase();
}
function baselineMatch(a,b){need(pins(a)===pins(b),'DIRECT_BASELINE_DIVERGENT');}
function nativeAction(h){const action=h.nativeAction||'checkout';need(action==='checkout'||(action==='relinquish'&&h.disposableModelRelinquishApproved===true)||(action==='observe-user-change'&&h.ordinaryUserChanges===true&&!h.cycle),'DIRECT_NATIVE_ACTION');return action;}
function validateReviewed(h){nativeAction(h);need(h&&h.projectId===4&&Number.isSafeInteger(h.fileId)&&h.fileId>0&&uuid(h.id)&&uuid(h.generation)&&uuid(h.sourceSession)&&uuid(h.receiverSession)&&h.sourceSession!==h.receiverSession,'DIRECT_CONTEXT');require('../ephemeral-attempt-v1/scope.cjs').path(h.model);need(/\.rvt$/i.test(h.model)&&typeof h.elementUniqueId==='string'&&h.elementUniqueId.length>0&&h.elementUniqueId.length<=128,'DIRECT_MODEL_ELEMENT');need(typeof h.sourceRevitUser==='string'&&h.sourceRevitUser.length>0&&h.sourceRevitUser.length<=256&&typeof h.receiverRevitUser==='string'&&h.receiverRevitUser.length>0&&h.receiverRevitUser.length<=256&&h.sourceRevitUser!==h.receiverRevitUser,'DIRECT_NATIVE_USERS');need(Number.isSafeInteger(h.expiresAt)&&h.expiresAt>0&&Number.isInteger(h.revision)&&h.revision>=0&&h.revision<2147483647&&typeof h.enabled==='boolean'&&['disabled','armed','receiver-ready','native-attempted','pending','apply-attempted','native-verification-required','native-verification-attempted','completed-blocked','recovery','released'].includes(h.state),'DIRECT_STATE');baselineMatch(h.sourcePins,h.receiverPins);need(h.preBundle===pins(h.sourcePins),'DIRECT_BASELINE');}
function participant(h,p,role){need(p&&p.role===role&&p.sessionId===h[role+'Session']&&p.generation===h.generation,'DIRECT_PARTICIPANT');}
function transition(head,event,body,principal,runtime,now){need(['receiver-ready','native-begin','native-observed'].includes(event),'OPEN_SOURCE_EVENT_ONLY');validateReviewed(head);openReady(head,runtime,now);need(Number.isSafeInteger(now)&&runtime&&runtime.participantsVerified===true&&runtime.reciprocalFencesHeld===true,'DIRECT_RUNTIME_INTEGRATION_REQUIRED');
 const h=structuredClone(head);need(h.enabled===true&&now<h.expiresAt,'DIRECT_DISABLED_OR_EXPIRED');
 if(event==='receiver-ready'){participant(h,principal,'receiver');exact(body,['pins']);need(h.state==='armed'&&openReady(h,runtime,now),'DIRECT_RECEIVER_HOLD_REQUIRED');need(protocol.canonical(body.pins)===protocol.canonical(h.receiverPins),'DIRECT_RECEIVER_CHANGED');h.state='receiver-ready';h.receiverAttestedAt=now;}
 else if(event==='native-begin'){participant(h,principal,'source');exact(body,['pins','elementUniqueId','operationId']);need(h.state==='receiver-ready'&&openReady(h,runtime,now)&&now>=h.receiverAttestedAt&&now-h.receiverAttestedAt<=10000,'DIRECT_RECEIVER_STALE');need(protocol.canonical(body.pins)===protocol.canonical(h.sourcePins)&&body.elementUniqueId===h.elementUniqueId&&uuid(body.operationId),'DIRECT_SOURCE_CHANGED');h.operationId=body.operationId;h.state='native-attempted';}
 else if(event==='native-observed'){participant(h,principal,'source');exact(body,['wire','native']);need(h.state==='native-attempted'&&typeof body.wire==='string'&&Buffer.byteLength(body.wire)<=1048576,'DIRECT_NATIVE_STATE');const e=JSON.parse(body.wire);need(protocol.canonical(e)===body.wire,'DIRECT_CANONICAL');const digest=protocol.validate(e);exact(body.native,['action','elementUniqueId','returnedRequestedElement','unexpectedReturnedElements']);need(body.native.action===nativeAction(h),'DIRECT_NATIVE_ACTION');need(body.native.elementUniqueId===h.elementUniqueId&&body.native.returnedRequestedElement===true&&body.native.unexpectedReturnedElements===false,'DIRECT_NATIVE_BOUNDARY');need(e.OperationId===h.operationId&&e.Generation===h.generation&&e.SourceSession===h.sourceSession&&e.Model===h.model&&e.PreBundle===h.preBundle&&e.PreviousSequence===0&&e.Sequence===1,'DIRECT_ENVELOPE_CONTEXT');
  for(let i=0;i<5;i++){const f=e.Files[i],p=h.sourcePins.files[i];need(f.PreHash===p.sha256&&f.PreLength===p.length&&f.SourceIdentity===p.identity,'DIRECT_SOURCE_PREIMAGE');}
  const users=e.Files[0];need(users.PreHash===users.PostHash&&users.PreLength===users.PostLength&&users.Append.length===0&&users.Overwrites.length===0,'DIRECT_USER_MAP_CHANGED');
  h.state='pending';h.digest=digest;h.postBundle=e.PostBundle;h.wire=body.wire;
 }
 else need(false,'DIRECT_UNKNOWN_EVENT');
 h.revision=head.revision+1;return h;
}
function assertOtherMutationAllowed(head){need(!head||head.state==='released','DIRECT_MODEL_FENCED');}
// The user has already edited in Revit. This does not manufacture a checkout
// result or grant permission for a native action. Both UI holds are needed only
// for transporting this measured delta; any changed receiver preimage refuses it.
function observedUserChange(head,body,principal,runtime,now){
 validateReviewed(head);need(nativeAction(head)==='observe-user-change'&&head.state==='armed'&&head.enabled&&now<head.expiresAt,'USER_CHANGE_MODE');
 if(head.transportMode==='background-prepared')need(head.ordinaryClaim&&head.ordinaryClaim.email===head.sourceEmail&&head.ordinaryClaim.generation===head.generation,'USER_CHANGE_CLAIM_REQUIRED');participant(head,principal,'source');openReady(head,runtime,now);need(runtime.participantsVerified===true&&runtime.reciprocalFencesHeld===true,'DIRECT_RUNTIME_INTEGRATION_REQUIRED');
 exact(body,['wire','postPins','native']);const n=body.native;exact(n,['action','elementUniqueId','nativeUiHeld','timestamp','holdExpiresAt']);
 need(n.action==='observe-user-change'&&n.elementUniqueId===head.elementUniqueId&&(head.transportMode==='background-prepared'?n.nativeUiHeld===false:n.nativeUiHeld===true)&&Number.isSafeInteger(n.timestamp)&&Number.isSafeInteger(n.holdExpiresAt)&&n.timestamp<=now&&now-n.timestamp<=10000&&now<n.holdExpiresAt&&n.holdExpiresAt<=n.timestamp+30000,'USER_CHANGE_NATIVE_HOLD');
 need(typeof body.wire==='string'&&Buffer.byteLength(body.wire)<=1048576,'USER_CHANGE_WIRE');const e=JSON.parse(body.wire);need(protocol.canonical(e)===body.wire,'DIRECT_CANONICAL');const digest=protocol.validate(e);
 need(e.Generation===head.generation&&e.SourceSession===head.sourceSession&&e.Model===head.model&&e.PreBundle===head.preBundle&&e.PreviousSequence===0&&e.Sequence===1,'DIRECT_ENVELOPE_CONTEXT');
 pins(body.postPins);need(body.postPins.rootIdentity===head.sourcePins.rootIdentity,'USER_CHANGE_ROOT');
 for(let i=0;i<5;i++){const f=e.Files[i],before=head.sourcePins.files[i],after=body.postPins.files[i];need(f.SourceIdentity===before.identity&&f.PreHash===before.sha256&&f.PreLength===before.length&&after.identity===before.identity&&after.sha256===f.PostHash&&after.length===f.PostLength,'USER_CHANGE_SOURCE_PINS');}
 const u=e.Files[0];need(u.PreHash===u.PostHash&&u.PreLength===u.PostLength&&u.Append.length===0&&u.Overwrites.length===0,'DIRECT_USER_MAP_CHANGED');
 require('./post-sync-reconciliation.cjs').requirePostimage(head,body.postPins);
 const h=structuredClone(head);h.operationId=e.OperationId;h.state='pending';h.digest=digest;h.postBundle=e.PostBundle;h.wire=body.wire;h.observedSourcePins=structuredClone(body.postPins);h.sourceObservation=structuredClone(n);h.revision++;return h;
}
module.exports={nativeAction,pins,baselineMatch,validateReviewed,transition,observedUserChange,assertOtherMutationAllowed};




