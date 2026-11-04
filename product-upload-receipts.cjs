'use strict';
// Runs INSIDE the normal handler's existing project-locked SQL transaction.
// The existing request/response shape is retained. Old fixed-key confirmations
// fail closed only for enrolled model scopes. No HTTP request supplies authority.
const crypto=require('node:crypto'),scope=require('./scoped-api-v11/scope.cjs'),pins=require('./scoped-api-v11/content-pins.cjs');
const {need}=scope;
module.exports=function({rawPool,r2,signUpload}){
 async function selected(c,req){
  const project=Number(req.body.projectId),path=scope.path(req.body.relativePath);need(Number.isSafeInteger(project)&&project>0&&req.user&&typeof req.user.email==='string','UPLOAD_RECEIPT_CONTEXT');
  const matches=(await scope.scopes(c,project)).filter(s=>scope.group(s.central_path,path));need(matches.length<=1,'UPLOAD_RECEIPT_AMBIGUOUS_SCOPE');
  if(!matches.length){need(!String(req.body.b2Key||'').startsWith('direct-upload/'),'UPLOAD_RECEIPT_SCOPE_REQUIRED');return null;}
  const s=matches[0];need(['released','staged'].includes(s.state),'UPLOAD_RECEIPT_FENCED');
  const ownership=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'].some(name=>scope.equal(path,s.central_path.replace(/\.rvt$/i,'')+'_backup/'+name));
  if(ownership){
   const exists=(await c.query("SELECT to_regclass('bimchat_direct_ownership.model_streams') present")).rows[0]?.present;
   if(exists)need(!(await c.query('SELECT 1 FROM bimchat_direct_ownership.model_streams WHERE project_id=$1 AND file_id=$2',[s.project_id,s.file_id])).rowCount,'OWNERSHIP_AGENT_ONLY');
  }
  need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[project,req.user.email])).rowCount===1,'UPLOAD_RECEIPT_MEMBERSHIP');
  need(Number.isSafeInteger(req.body.fileSize)&&req.body.fileSize>=0&&req.body.fileSize<=64*1024*1024,'UPLOAD_RECEIPT_SIZE');return s;
 }
 async function catalog(c,project,path){const rows=(await c.query('SELECT id,current_version,b2_key FROM cloud_files WHERE project_id=$1 AND lower(replace(relative_path,chr(92),chr(47)))=$2 FOR UPDATE',[project,scope.key(path)])).rows;need(rows.length<=1,'UPLOAD_RECEIPT_CATALOG_AMBIGUOUS');return rows[0]||null;}
 async function issue(c,req){const s=await selected(c,req);if(!s)return null;const b=req.body,prior=await catalog(c,s.project_id,b.relativePath),id=crypto.randomUUID(),key='direct-upload/'+s.project_id+'/'+id;
  await c.query("INSERT INTO bimchat_direct_ownership.normal_upload_receipts(id,scope_id,project_id,relative_path,email,upload_key,expected_size,prior_file_id,prior_version,prior_key,expires_at,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()+interval '1 hour','issued')",[id,s.id,s.project_id,b.relativePath,req.user.email,key,b.fileSize,prior&&prior.id,prior&&prior.current_version,prior&&prior.b2_key]);
  await c.query("INSERT INTO bimchat_direct_ownership.normal_upload_seal_jobs(receipt_id,owner_id,state) VALUES($1,$2,'ready')",[id,crypto.randomUUID()]);
  // Response is buffered by handler-bridge until the receipt transaction commits.
  return {success:true,uploadUrl:await signUpload(key),b2Key:key,expiresIn:3600};
 }
 async function confirm(c,req){const s=await selected(c,req);if(!s)return null;throw Object.assign(Error('UPLOAD_CONFIRM_PROTOCOL_REQUIRED'),{status:409});}
 async function finalize(c,req,s,r,prior,sealed){
  const b=req.body;
  need(sealed.contentVerified===true&&sealed.size===Number(r.expected_size)&&sealed.key!==r.upload_key,'UPLOAD_RECEIPT_CONTENT');pins.validate(sealed);
  await pins.insert(c,sealed);await pins.complete(c,sealed);
  let fileId,version;
  if(prior){
   await c.query('INSERT INTO file_versions (cloud_file_id,version,b2_key,file_size,uploaded_by,comment) SELECT id,current_version,b2_key,file_size,uploaded_by,NULL FROM cloud_files WHERE id=$1',[prior.id]);
   const updated=await c.query('UPDATE cloud_files SET b2_key=$1,file_size=$2,current_version=current_version+1,uploaded_by=$3,last_modified=NOW() WHERE id=$4 AND current_version=$5 AND b2_key=$6 RETURNING id,current_version',[sealed.key,sealed.size,req.user.email,prior.id,prior.current_version,prior.b2_key]);need(updated.rowCount===1,'UPLOAD_RECEIPT_CATALOG_RACE');fileId=updated.rows[0].id;version=updated.rows[0].current_version;
  }else{const added=await c.query('INSERT INTO cloud_files(project_id,file_name,relative_path,b2_key,file_size,uploaded_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,current_version',[s.project_id,b.fileName,b.relativePath,sealed.key,sealed.size,req.user.email]);need(added.rowCount===1,'UPLOAD_RECEIPT_CATALOG_INSERT');fileId=added.rows[0].id;version=added.rows[0].current_version;}
  need((await c.query("UPDATE bimchat_direct_ownership.normal_upload_receipts SET state='consumed',sealed_key=$2 WHERE id=$1 AND state='issued' RETURNING id",[r.id,sealed.key])).rowCount===1,'UPLOAD_RECEIPT_COMMIT_EXPIRED');
  return {success:true,fileId,version,message:'Uploaded'};
 }
 const managed=require('./product-upload-seal-jobs.cjs')({rawPool,r2,selected,catalog,finalize});
 return {issue,confirm,confirmManaged:managed.confirm};
};
