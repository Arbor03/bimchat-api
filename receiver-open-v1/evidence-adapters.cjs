'use strict';
const crypto=require('node:crypto');
const need=(ok,code)=>{if(!ok)throw Error(code);};
const digest=x=>crypto.createHash('sha256').update(x).digest('hex').toUpperCase();
const scope=require('../ephemeral-attempt-v1/scope.cjs');
// API/background writer inventory must first be independently reviewed and frozen.
// This adapter checks actual recorded work/capabilities; an empty table cannot prove
// that an uninstrumented writer does not exist. That deployment prerequisite is explicit.
function writerDrain({reviewedInventoryDigest}){
 need(/^[A-F0-9]{64}$/.test(reviewedInventoryDigest),'INVENTORY_REQUIRED');
 return async(c,review)=>{
  need(review.writerInventoryDigest===reviewedInventoryDigest,'INVENTORY_CHANGED');
  await scope.lock(c,review.projectId);
  const work=(await c.query("SELECT relative_path FROM bimchat_direct_ownership.storage_work WHERE project_id=$1 AND state IN ('started','uncertain')",[review.projectId])).rows;
  need(!work.some(w=>!w.relative_path||scope.group(review.centralPath,w.relative_path.replace(/\\/g,'/'))),'DRAIN_WORK_UNRESOLVED');
  const caps=(await c.query("SELECT relative_path FROM bimchat_direct_ownership.upload_capabilities WHERE project_id=$1 AND (expires_at>clock_timestamp() OR state='verified')",[review.projectId])).rows;
  need(!caps.some(w=>!w.relative_path||scope.group(review.centralPath,w.relative_path.replace(/\\/g,'/'))),'DRAIN_CAPABILITY_UNRESOLVED');
  return true;
 };
}
// Inputs are separate: enrolled operation/manifest from SQL, local file observations
// from the receiver, object contents from conditional R2 GET. Never trust ETag as hash.
async function verifyReceiverPayload({r2,operation,local,now}){
 need(r2&&typeof r2.readVerified==='function'&&operation&&local&&typeof now==='function','RECEIVER_CONTEXT');
 operation=JSON.parse(JSON.stringify(operation));local=JSON.parse(JSON.stringify(local));
 const start=now();need(Number.isFinite(start)&&Number.isFinite(operation.expiresAt)&&operation.state==='pending'&&operation.expiresAt>start&&operation.expiresAt-start<=30000,'RECEIVER_GRANT');
 const checkTime=()=>{const t=now();need(Number.isFinite(t)&&t>=start&&t<operation.expiresAt,'RECEIVER_EXPIRED');};
 for(const name of ['reviewDigest','operationId','generation','receiverSession','receiverDevice','logicalCentralPath','elementUniqueId'])need(typeof operation[name]==='string'&&operation[name].length>0&&local[name]===operation[name],'RECEIVER_BINDING');
 need(operation.rootIdentity===local.rootIdentity&&Array.isArray(operation.files)&&operation.files.length===5&&Array.isArray(local.files)&&local.files.length===5,'RECEIVER_BASELINE');
 const names=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];const result=[];
 for(let i=0;i<5;i++){
  const file=operation.files[i],observed=local.files[i];need(file.name===names[i]&&observed.name===names[i]&&observed.identity===file.receiverIdentity&&observed.sha256===file.preHash&&observed.size===file.preSize,'RECEIVER_PREIMAGE');
  need(file.pin&&file.pin.provider==='r2'&&file.pin.sha256===file.postHash&&file.pin.size>=file.preSize&&file.pin.size<=8388608,'RECEIVER_OBJECT_PIN');
  checkTime();const body=await r2.readVerified(file.pin);checkTime();need(Buffer.isBuffer(body)&&body.length===file.pin.size&&digest(body)===file.postHash,'RECEIVER_R2_CONTENT');
  if(i===0)need(file.postHash===file.preHash&&file.pin.size===file.preSize,'RECEIVER_USERS_CHANGED');
  result.push({name:file.name,bytes:Buffer.from(body)});
 }
 checkTime();return result; // No write/ack; local writer independently reopens and checks exact preimages.
}
module.exports={writerDrain,verifyReceiverPayload};

