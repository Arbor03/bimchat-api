'use strict';
const scope=require('./scoped-api-v11/scope.cjs'),co=require('./scoped-api-v11/coordinator.cjs');
const {need}=scope;
function manifest(body){
 need(Number.isSafeInteger(body.projectId)&&body.projectId>0&&/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(body.batchId||''),'BATCH_CONTEXT');
 const central=scope.path(body.centralPath);need(/\.rvt$/i.test(central),'BATCH_CENTRAL');
 need(Array.isArray(body.files)&&body.files.length>0&&body.files.length<=10000,'BATCH_FILES');
 const files=body.files.map(f=>{const path=scope.path(f.path);need(scope.group(central,path)&&Number.isSafeInteger(f.size)&&f.size>=0&&/^[A-F0-9]{64}$/.test(f.sha256||''),'BATCH_FILE');return {path,size:f.size,sha256:f.sha256};});
 scope.unique(files.map(f=>f.path));need(files.some(f=>scope.equal(f.path,central)),'BATCH_MAIN_REQUIRED');
 return files.sort((a,b)=>scope.key(a.path).localeCompare(scope.key(b.path),'en'));
}
async function stage(c,r,pin){
 const b=(await c.query('SELECT * FROM bimchat_direct_ownership.sync_batches WHERE id=$1 FOR UPDATE',[r.sync_batch_id])).rows[0];
 need(b&&b.state==='collecting'&&b.email===r.email&&b.project_id===r.project_id,'BATCH_BINDING');
 const f=b.manifest.find(x=>scope.equal(x.path,r.relative_path));need(f&&f.size===pin.size&&f.sha256===pin.sha256,'BATCH_CONTENT_MISMATCH');
 need((await c.query('UPDATE bimchat_direct_ownership.sync_batch_items SET sealed_pin=$3::jsonb WHERE batch_id=$1 AND receipt_id=$2 RETURNING path_key',[b.id,r.id,JSON.stringify(pin)])).rowCount===1,'BATCH_RECEIPT_CHANGED');
 return {success:true,publicationState:'staged',batchId:b.id};
}
module.exports=function({rawPool,uploads}){
 async function context(c,req){
  const project=req.body.projectId;need(Number.isSafeInteger(project)&&project>0&&typeof req.user?.email==='string','BATCH_CONTEXT');
  await scope.lock(c,project);
  need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[project,req.user.email])).rowCount===1,'BATCH_MEMBERSHIP');
 }
 async function load(c,req){await context(c,req);const b=(await c.query('SELECT * FROM bimchat_direct_ownership.sync_batches WHERE id=$1 FOR UPDATE',[req.body.batchId])).rows[0];need(b&&b.project_id===req.body.projectId&&b.email===req.user.email,'BATCH_BINDING');return b;}
 const fileReq=(req,f)=>({user:req.user,body:{projectId:req.body.projectId,relativePath:f.path,fileName:f.path.replace(/\\/g,'/').split('/').pop(),fileSize:f.size}});
 async function describe(c,b,state,clientVersion){
  const result={success:true,state};
  if(state!=='collecting'||clientVersion!==1)return result;
  const row=(await c.query(
   "SELECT p.sha256 FROM bimchat_direct_ownership.sync_batch_items i JOIN bimchat_direct_ownership.sealed_objects p ON p.object_key=(i.prior_pin->>'key') WHERE i.batch_id=$1 AND i.path_key=$2",
   [b.batchId,scope.key(b.centralPath)])).rows[0];
  if(row)result.rvtBaseSha256=row.sha256;
  return result;
 }
 async function begin(req){const files=manifest(req.body);return co.transaction(rawPool,async c=>{
  await context(c,req);
  const old=(await c.query('SELECT * FROM bimchat_direct_ownership.sync_batches WHERE id=$1 FOR UPDATE',[req.body.batchId])).rows[0];
  if(old){need(old.email===req.user.email&&old.project_id===req.body.projectId&&old.central_path===req.body.centralPath&&JSON.stringify(manifest({...req.body,files:old.manifest}))===JSON.stringify(files),'BATCH_ID_REUSE');return describe(c,req.body,old.state,req.body.rvtDeltaVersion);}
  for(const f of files){await scope.ordinary(c,req.body.projectId,f.path);const s=await uploads.selected(c,fileReq(req,f));need(s&&scope.equal(s.central_path,req.body.centralPath),'BATCH_ENROLLED_MODEL_REQUIRED');}
  await c.query("INSERT INTO bimchat_direct_ownership.sync_batches(id,project_id,central_path,email,manifest,state) VALUES($1,$2,$3,$4,$5::jsonb,'collecting')",[req.body.batchId,req.body.projectId,req.body.centralPath,req.user.email,JSON.stringify(files)]);
  for(const f of files){const prior=await uploads.catalog(c,req.body.projectId,f.path);await c.query('INSERT INTO bimchat_direct_ownership.sync_batch_items(batch_id,path_key,prior_pin) VALUES($1,$2,$3::jsonb)',[req.body.batchId,scope.key(f.path),JSON.stringify(prior?{id:prior.id,version:prior.current_version,key:prior.b2_key}:null)]);}
  return describe(c,req.body,'collecting',req.body.rvtDeltaVersion);
 });}
 async function issue(req){return co.transaction(rawPool,async c=>{
  const b=await load(c,req);need(b.state==='collecting','BATCH_ALREADY_COMMITTED');const f=b.manifest.find(x=>scope.equal(x.path,req.body.path));need(f,'BATCH_FILE_UNKNOWN');
  const item=(await c.query('SELECT * FROM bimchat_direct_ownership.sync_batch_items WHERE batch_id=$1 AND path_key=$2 FOR UPDATE',[b.id,scope.key(f.path)])).rows[0];
  if(item.sealed_pin)return {success:true,staged:true};
  const prior=await uploads.catalog(c,b.project_id,f.path),base=item.prior_pin;
  need(prior?base&&prior.id===base.id&&prior.current_version===base.version&&prior.b2_key===base.key:base===null,'BATCH_CATALOG_CHANGED');
  // An existing attempt is reconciled, never PUT again to an ambiguous key.
  if(item.receipt_id&&req.body.replaceAttempt!==true){const r=(await c.query('SELECT * FROM bimchat_direct_ownership.normal_upload_receipts WHERE id=$1',[item.receipt_id])).rows[0];return {success:true,b2Key:r.upload_key,reconcile:true};}
  // Replacement uses a NEW object key and receipt. Any late old seal fails the
  // receipt-id CAS in stage(); it cannot publish or replace this attempt.
  const input=fileReq(req,f);await scope.ordinary(c,b.project_id,f.path);let delta=false;
  if(scope.equal(f.path,b.central_path)&&prior&&/^[A-F0-9]{64}$/.test(req.body.rvtBaseSha256||'')&&Number.isSafeInteger(req.body.deltaBytes)&&req.body.deltaBytes>0&&req.body.deltaBytes<f.size){
   const pin=(await c.query('SELECT sha256 FROM bimchat_direct_ownership.sealed_objects WHERE object_key=$1',[prior.b2_key])).rows[0];
   delta=!!pin&&pin.sha256===req.body.rvtBaseSha256;
  }
  const result=await uploads.issue(c,input,delta);need(result,'BATCH_UPLOAD_REQUIRED');
  const r=(await c.query('UPDATE bimchat_direct_ownership.normal_upload_receipts SET sync_batch_id=$2 WHERE upload_key=$1 RETURNING id',[result.b2Key,b.id])).rows[0];need(r,'BATCH_RECEIPT_REQUIRED');
  await c.query('UPDATE bimchat_direct_ownership.sync_batch_items SET receipt_id=$3 WHERE batch_id=$1 AND path_key=$2',[b.id,scope.key(f.path),r.id]);return {...result,rvtDelta:delta};
 });}
 async function commit(req){return co.transaction(rawPool,async c=>{
  const b=await load(c,req);if(b.state==='committed')return b.result;
  const items=(await c.query('SELECT * FROM bimchat_direct_ownership.sync_batch_items WHERE batch_id=$1 ORDER BY path_key FOR UPDATE',[b.id])).rows;
  need(items.length===b.manifest.length&&items.every(x=>x.receipt_id&&x.sealed_pin),'BATCH_NOT_READY');const results=[];
  // All old catalogue versions remain visible until this single transaction commits.
  for(const f of b.manifest){const item=items.find(x=>x.path_key===scope.key(f.path)),input=fileReq(req,f);await scope.ordinary(c,b.project_id,f.path);const s=await uploads.selected(c,input);need(s&&scope.equal(s.central_path,b.central_path),'BATCH_SCOPE_CHANGED');
   const r=(await c.query('SELECT * FROM bimchat_direct_ownership.normal_upload_receipts WHERE id=$1 FOR UPDATE',[item.receipt_id])).rows[0];need(r&&r.sync_batch_id===b.id&&r.email===b.email&&r.state==='issued','BATCH_RECEIPT_CHANGED');
   const prior=await uploads.catalog(c,b.project_id,f.path);need(prior?prior.id===r.prior_file_id&&prior.current_version===r.prior_version&&prior.b2_key===r.prior_key:r.prior_file_id===null,'BATCH_CATALOG_CHANGED');
   results.push(await uploads.finalize(c,input,s,r,prior,item.sealed_pin,true));
  }
  const result={success:true,state:'committed',batchId:b.id,files:results};await c.query("UPDATE bimchat_direct_ownership.sync_batches SET state='committed',result=$2::jsonb WHERE id=$1",[b.id,JSON.stringify(result)]);
  await require('./product-catalog-notifications.cjs').publish(c);return result;
 });}
 function mount(app,jwt){for(const [name,fn]of Object.entries({begin,issue,commit}))app.post('/drive/sync-batches/'+name,jwt,async(req,res)=>{try{res.json(await fn(req));}catch(e){res.status(e.status||409).json({success:false,error:/^BATCH_|^UPLOAD_|^OWNERSHIP_|^MODEL_/.test(e.message)?e.message:'BATCH_UNAVAILABLE'});}});}
 return {begin,issue,commit,mount};
};
module.exports.manifest=manifest;module.exports.stage=stage;
