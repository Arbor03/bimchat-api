'use strict';
const {need,path,group,key,equal}=require('./ephemeral-attempt-v1/scope.cjs');
const names=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];
// Preparation only: bind existing normal-Drive catalog rows to independently
// reviewed local observations. This grants no authority and performs no I/O.
// The existing R2 sealing/drain transaction must subsequently verify the bytes.
module.exports=function({projectId,fileId,centralPath,sourcePins,receiverPins,catalog}){
 path(centralPath);need(/\.rvt$/i.test(centralPath)&&Number.isSafeInteger(projectId)&&projectId>0&&Number.isSafeInteger(fileId)&&fileId>0,'PRODUCT_BASELINE_MODEL');
 need(sourcePins&&receiverPins&&Array.isArray(sourcePins.files)&&sourcePins.files.length===5&&Array.isArray(receiverPins.files)&&receiverPins.files.length===5&&Array.isArray(catalog),'PRODUCT_BASELINE_OBSERVATIONS');
 const selected=catalog.filter(f=>f.project_id===projectId&&group(centralPath,f.relative_path));
 const central=selected.filter(f=>f.id===fileId&&equal(f.relative_path,centralPath));need(central.length===1,'PRODUCT_BASELINE_CATALOG_IDENTITY');
 const seenPaths=new Set(),seenIds=new Set();
 for(const f of selected){need(!seenPaths.has(key(f.relative_path))&&!seenIds.has(f.id)&&typeof f.b2_key==='string'&&f.b2_key.length>0&&Number.isSafeInteger(f.current_version)&&f.current_version>0,'PRODUCT_BASELINE_CATALOG_AMBIGUOUS');seenPaths.add(key(f.relative_path));seenIds.add(f.id);}
 const ownership=[];
 for(let i=0;i<5;i++){
  const a=sourcePins.files[i],b=receiverPins.files[i];need(a.name===names[i]&&b.name===names[i]&&/^[A-F0-9]{64}$/.test(a.sha256)&&Number.isSafeInteger(a.length)&&a.length>=0&&a.length<=8388608,'PRODUCT_BASELINE_LOCAL_PIN');
  need(a.sha256===b.sha256&&a.length===b.length,i===0?'PRODUCT_USERS_DIVERGED_PRESERVE_BOTH':'PRODUCT_BASELINE_OWNERSHIP_DIVERGED');
  const relative=centralPath.replace(/\.rvt$/i,'')+'_backup/'+names[i];const rows=selected.filter(f=>equal(f.relative_path,relative));
  need(rows.length===1&&Number(rows[0].file_size)===a.length,'PRODUCT_BASELINE_FILE_NOT_PUBLISHED');
  const f=rows[0];ownership.push({id:f.id,path:f.relative_path,oldKey:f.b2_key,version:f.current_version,sha256:a.sha256,size:a.length});
 }
 return {projectId,fileId,centralPath,centralVersion:central[0].current_version,
  inventory:selected.map(f=>({id:f.id,path:f.relative_path,oldKey:f.b2_key,version:f.current_version})),ownership,
  readyToActivate:false,required:'Verify full inventory bytes in R2 under writer drain; bind signed local observations before sealing.'};
};
