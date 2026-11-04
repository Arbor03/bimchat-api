'use strict';
const crypto=require('node:crypto'),co=require('./scoped-api-v11/coordinator.cjs'),scope=require('./scoped-api-v11/scope.cjs'),routes=require('./scoped-api-v11/install-handlers.cjs');
const {need}=scope;
module.exports=function({rawPool,r2,selected,catalog,finalize}){
 const policy={type:'upload',legacyUpload:true};
 const guarded=(req,fn)=>co.guarded(rawPool,c=>routes.resolve(c,req,policy),fn);
 function bound(r,s,req){const b=req.body;need(r&&r.scope_id===s.id&&r.project_id===s.project_id&&r.relative_path===b.relativePath&&r.email===req.user.email&&Number(r.expected_size)===b.fileSize,'UPLOAD_RECEIPT_BINDING');}
 function priorMatches(prior,r){need(prior?prior.id===r.prior_file_id&&prior.current_version===r.prior_version&&prior.b2_key===r.prior_key:r.prior_file_id===null,'UPLOAD_RECEIPT_CATALOG_CHANGED');}
 async function reserve(receipt,owner,p){
  return co.transaction(rawPool,async c=>{
   const changed=await c.query("UPDATE bimchat_direct_ownership.normal_upload_seal_jobs SET state='sealing',destination_key=$3,source_etag=$4,expected_sha256=$5,expected_size=$6,updated_at=clock_timestamp() WHERE receipt_id=$1 AND owner_id=$2 AND state='claimed' RETURNING receipt_id",[receipt.id,owner,p.key,p.sourceEtag,p.sha256,p.size]);need(changed.rowCount===1,'UPLOAD_SEAL_OWNER_CHANGED');
   need(Number(receipt.expected_size)===p.size,'UPLOAD_RECEIPT_CONTENT');
   await c.query("INSERT INTO bimchat_direct_ownership.storage_work(id,project_id,relative_path,kind,state,object_key,expected_sha256,expected_size) VALUES($1,$2,$3,'r2-seal','started',$4,$5,$6)",[crypto.randomUUID(),receipt.project_id,receipt.relative_path,p.key,p.sha256,p.size]);return true;
  });
 }
 async function work(req,r,owner){
  try{
   // No project transaction or SQL connection is retained across either network await.
   const progress=phase=>co.transaction(rawPool,async c=>{need(['source-head','source-read','sealed-put','sealed-verify'].includes(phase),'UPLOAD_SEAL_PHASE');need((await c.query("UPDATE bimchat_direct_ownership.normal_upload_seal_jobs SET network_phase=$3,updated_at=clock_timestamp() WHERE receipt_id=$1 AND owner_id=$2 AND state IN ('claimed','sealing') RETURNING receipt_id",[r.id,owner,phase])).rowCount===1,'UPLOAD_SEAL_OWNER_CHANGED');});
   const pin=await r2.seal({object_key:r.upload_key,project_id:r.project_id,relative_path:r.relative_path,progress},p=>reserve(r,owner,p));
   need(pin.contentVerified===true&&pin.size===Number(r.expected_size),'UPLOAD_RECEIPT_CONTENT');
   await co.transaction(rawPool,async c=>{need((await c.query("UPDATE bimchat_direct_ownership.normal_upload_seal_jobs SET state='verified',verified_pin=$3::jsonb,updated_at=clock_timestamp() WHERE receipt_id=$1 AND owner_id=$2 AND state='sealing' AND destination_key=$4 AND expected_sha256=$5 AND expected_size=$6 RETURNING receipt_id",[r.id,owner,JSON.stringify(pin),pin.key,pin.sha256,pin.size])).rowCount===1,'UPLOAD_SEAL_OWNER_CHANGED');});
   await guarded(req,async c=>{
    const s=await selected(c,req);need(s,'UPLOAD_RECEIPT_SCOPE_REQUIRED');
    const fresh=(await c.query('SELECT * FROM bimchat_direct_ownership.normal_upload_receipts WHERE id=$1 FOR UPDATE',[r.id])).rows[0];bound(fresh,s,req);need(fresh.state==='issued','UPLOAD_RECEIPT_STATE_CHANGED');
    const job=(await c.query('SELECT * FROM bimchat_direct_ownership.normal_upload_seal_jobs WHERE receipt_id=$1 FOR UPDATE',[r.id])).rows[0];need(job&&job.owner_id===owner&&job.state==='verified','UPLOAD_SEAL_OWNER_CHANGED');
    const prior=await catalog(c,s.project_id,req.body.relativePath);priorMatches(prior,fresh);
    const result=await finalize(c,req,s,fresh,prior,pin);
    need((await c.query("UPDATE bimchat_direct_ownership.normal_upload_seal_jobs SET state='completed',result=$3::jsonb,updated_at=clock_timestamp() WHERE receipt_id=$1 AND owner_id=$2 AND state='verified' RETURNING receipt_id",[r.id,owner,JSON.stringify(result)])).rowCount===1,'UPLOAD_SEAL_OWNER_CHANGED');
   });
  }catch(e){
   // Includes uncertain PUT, DB commit ambiguity, or changed catalog. Never repeat PUT.
   try{await co.transaction(rawPool,async c=>{await c.query("UPDATE bimchat_direct_ownership.normal_upload_seal_jobs SET state='uncertain',updated_at=clock_timestamp() WHERE receipt_id=$1 AND owner_id=$2 AND state IN ('claimed','sealing','verified')",[r.id,owner]);});}catch{}
   console.warn(JSON.stringify({event:'normal-upload-seal-unresolved',receiptId:r.id,stage:'seal-or-finalize',category:/^UPLOAD_[A-Z_]+$/.test(e.message||'')?e.message:'UNCLASSIFIED'}));
  }
 }
 async function confirm(input){
  // Keep only the already-authenticated identity and immutable request values, no token.
  const b=input.body||{};const req={user:{email:input.user?.email},body:{projectId:b.projectId,relativePath:b.relativePath,fileName:b.fileName,fileSize:b.fileSize,b2Key:b.b2Key,confirmProtocol:b.confirmProtocol}};
  need(req.body.confirmProtocol===2,'UPLOAD_CONFIRM_PROTOCOL_REQUIRED');
  const outcome=await guarded(req,async c=>{
   const s=await selected(c,req);need(s,'UPLOAD_RECEIPT_SCOPE_REQUIRED');
   need(req.body.fileName===scope.path(req.body.relativePath).replaceAll('\\','/').split('/').pop(),'UPLOAD_RECEIPT_FILENAME');
   const r=(await c.query('SELECT *,clock_timestamp() server_now FROM bimchat_direct_ownership.normal_upload_receipts WHERE upload_key=$1 FOR UPDATE',[req.body.b2Key])).rows[0];bound(r,s,req);
   const j=(await c.query('SELECT * FROM bimchat_direct_ownership.normal_upload_seal_jobs WHERE receipt_id=$1 FOR UPDATE',[r.id])).rows[0];
   // Old receipts may already have an R2 operation. Never infer permission to restart it.
   need(j,'UPLOAD_SEAL_LEGACY_RECONCILIATION_REQUIRED');
   if(j.state==='completed'){need(r.state==='consumed'&&j.result?.success===true,'UPLOAD_SEAL_RESULT_INVALID');return {status:200,body:{...j.result,publicationState:'committed'}};}
   need(r.state==='issued','UPLOAD_RECEIPT_STATE_CHANGED');
   if(j.state==='uncertain')return {status:409,body:{success:false,publicationState:'uncertain',receiptId:r.id}};
   if(j.state!=='ready')return {status:202,body:{success:false,publicationState:'pending',receiptId:r.id}};
   need(+new Date(r.server_now)<+new Date(r.expires_at),'UPLOAD_RECEIPT_EXPIRED');
   const prior=await catalog(c,s.project_id,req.body.relativePath);priorMatches(prior,r);
   const owner=crypto.randomUUID();need((await c.query("UPDATE bimchat_direct_ownership.normal_upload_seal_jobs SET state='claimed',owner_id=$2,updated_at=clock_timestamp() WHERE receipt_id=$1 AND state='ready' RETURNING receipt_id",[r.id,owner])).rowCount===1,'UPLOAD_SEAL_OWNER_CHANGED');
   return {status:202,body:{success:false,publicationState:'pending',receiptId:r.id},start:{r,owner}};
  });
  if(outcome.start){const {r,owner}=outcome.start;setImmediate(()=>{void work(req,r,owner);});delete outcome.start;}
  return outcome;
 }
 return {confirm};
};
