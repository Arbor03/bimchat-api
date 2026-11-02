'use strict';
const {need}=require('../ephemeral-attempt-v1/scope.cjs'),{canonical,validate}=require('../source-open-v1/protocol.cjs');
// Requires verified receiver request proof and enrollment. Postimage receipt is NOT ownership proof.
function verify(h,body,now){const p=body&&body.receipt;need(p&&p.schema===1&&p.phase==='native-verification-required'&&p.journalComplete===true,'RECEIPT_PHASE');
 for(const [k,v] of Object.entries({operationId:h.operationId,digest:h.digest,reviewDigest:h.reviewDigest,session:h.receiverSession,device:h.receiverDevice,logicalCentral:h.logicalCentralPath,elementUniqueId:h.elementUniqueId,rootIdentity:h.receiverPins.rootIdentity}))need(p[k]===v,'RECEIPT_BINDING');
 need(Number.isSafeInteger(now)&&Number.isSafeInteger(p.timestamp)&&p.timestamp<=now&&now-p.timestamp<=10000&&now<h.receiverApplyExpiresAt,'RECEIPT_EXPIRED');
 const e=JSON.parse(h.wire);need(canonical(e)===h.wire&&validate(e)===h.digest,'RECEIPT_SOURCE_WIRE');need(p.pins&&p.pins.rootIdentity===h.receiverPins.rootIdentity&&Array.isArray(p.pins.files)&&p.pins.files.length===5,'RECEIPT_PINS');
 for(let i=0;i<5;i++){const f=p.pins.files[i],old=h.receiverPins.files[i],next=e.Files[i];need(f.name===old.name&&f.name===next.Name&&f.identity===old.identity&&f.length===next.PostLength&&f.sha256===next.PostHash,'RECEIPT_POSTIMAGE');}
 return true;
}
module.exports={verify};
