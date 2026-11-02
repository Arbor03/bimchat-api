'use strict';
const crypto=require('node:crypto'),{canonical}=require('./protocol.cjs');
const {requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs');
const trusted=new WeakSet();
function freeze(v){if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}const need=(v,c)=>{if(!v)throw Error(c);};
function validate(p,h,now){
 const background=h.ordinaryUserChanges===true&&h.transportMode==='background-prepared';need(p&&p.schema===(background?3:2)&&h.receiverMode==='open-ui-turn'&&p.role==='receiver','OPEN_REVIEW_MODE');
 for(const [field,expected] of Object.entries({attempt:h.id,generation:h.generation,reviewDigest:h.reviewDigest,session:h.receiverSession,device:h.receiverDevice,logicalCentralPath:h.logicalCentralPath,elementUniqueId:h.elementUniqueId,rootIdentity:h.receiverPins.rootIdentity,build:h.receiverBuild,mappingHash:h.receiverMappingHash}))need(typeof expected==='string'&&expected.length>0&&p[field]===expected,'OPEN_EVIDENCE_BINDING');
 need(Number.isSafeInteger(p.timestamp)&&Number.isSafeInteger(p.expiresAt)&&Number.isSafeInteger(now)&&now>=p.timestamp&&now-p.timestamp<=10000&&p.expiresAt>now&&p.expiresAt-p.timestamp<=30000,'OPEN_EVIDENCE_EXPIRED');
 need(p.revitVersion==='2024'&&Number.isSafeInteger(p.revitPid)&&p.revitPid>0&&typeof p.revitStarted==='string'&&p.revitStarted.length>0&&p.revitOpen===true&&(background?p.nativeUiHeld===false&&p.preparationOnly===true:p.nativeUiHeld===true)&&p.transferIdle===true&&p.fence===h.id,'OPEN_NATIVE_HOLD_REQUIRED');
 need(canonical(p.preimages)===canonical(h.receiverPins)&&p.allFiveExclusiveReadObserved===true,'OPEN_BASELINE_OR_HANDLES');
 return true;
}
function verifyEnvelope(h,signed,now){
 need(signed&&signed.payload&&typeof signed.signature==='string'&&signed.signature.length<=1368&&Buffer.byteLength(canonical(signed))<=65536,'OPEN_ENVELOPE_BOUND');
 const p=signed.payload;validate(p,h,now);
 const jwk=h.receiverAgentPublicKey;need(jwk&&jwk.kty==='RSA'&&!['d','p','q','dp','dq','qi'].some(k=>k in jwk),'OPEN_PUBLIC_KEY_ONLY');
 const key=crypto.createPublicKey({key:jwk,format:'jwk'});need(key.asymmetricKeyDetails.modulusLength>=3072,'OPEN_KEY_SIZE');
 const fingerprint=crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex').toUpperCase();need(fingerprint===h.receiverPublicKeyDigest,'OPEN_KEY_PIN');
 const sig=Buffer.from(signed.signature||'','base64');need(sig.toString('base64')===signed.signature&&crypto.verify('RSA-SHA256',Buffer.from(canonical(p)),key,sig),'OPEN_SIGNATURE');
 return {payload:p,fingerprint};
}
async function readVerified(c,h){
 const rows=(await c.query('SELECT payload,signature FROM bimchat_direct_ownership.observations WHERE attempt_id=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1',[h.id,'receiver'])).rows;need(rows.length===1,'OPEN_EVIDENCE_MISSING');
 const row=rows[0],p=row.payload,clock=(await c.query('SELECT clock_timestamp() now')).rows[0].now;const now=+new Date(clock);validate(p,h,now);
 const {fingerprint}=verifyEnvelope(h,row,now);
 await requireActive(c,{email:h.receiverEmail,sessionId:h.receiverSession,deviceId:h.receiverDevice,reviewDigest:h.reviewDigest,publicKeyDigest:fingerprint},h.projectId,h.centralPath,require('./controlled-cycle.cjs').enrollmentRole(h,'receiver'));
 const lease=JSON.parse(canonical(p));trusted.add(lease);freeze(lease);return lease;
}
function openReady(h,runtime,now){const lease=runtime&&runtime.receiverOpenLease;need(lease&&trusted.has(lease),'OPEN_VERIFIED_LEASE_REQUIRED');validate(lease,h,now);return true;}
module.exports={validate,verifyEnvelope,readVerified,openReady};


