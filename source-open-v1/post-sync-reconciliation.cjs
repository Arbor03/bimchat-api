'use strict';
const pathEqual=require('../scoped-api-v11/scope.cjs').equal;
const {need,group}=require('../ephemeral-attempt-v1/scope.cjs'),proof=require('../ephemeral-attempt-v1/device-proof.cjs'),pins=require('../scoped-api-v11/content-pins.cjs');
async function admit(c,h,email){
 need(!h.postSyncReconcile&&h.ordinaryIdle===true,'POST_SYNC_RECONCILIATION_ONCE');
 const rows=(await c.query('SELECT id,relative_path,b2_key,file_size,uploaded_by FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[h.projectId])).rows.filter(f=>group(h.centralPath,f.relative_path));
 require('../scoped-api-v11/scope.cjs').unique(rows.map(f=>f.relative_path));need(rows.length>0&&rows.length<=512,'POST_SYNC_INVENTORY');const central=rows.filter(f=>f.id===h.fileId&&pathEqual(f.relative_path,h.centralPath));need(central.length===1&&central[0].uploaded_by===email,'POST_SYNC_PUBLISHER');
 const manifest=[];for(const f of rows){const p=await pins.load(c,f.b2_key);need(p.size===Number(f.file_size),'POST_SYNC_CATALOG_SIZE');manifest.push({path:f.relative_path,...p});}
 for(const f of h.sourcePins.files){const found=manifest.filter(p=>pathEqual(p.path,h.centralPath.replace(/\.rvt$/i,'')+'_backup/'+f.name));need(found.length===1&&found[0].size>=f.length,'POST_SYNC_NO_TRUNCATION');if(f.name==='users.dat')need(found[0].size===f.length&&found[0].sha256===f.sha256,'POST_SYNC_USERS_DIVERGED_PRESERVE_BOTH');}
 return {kind:'sealed-post-sync',manifest,digest:proof.hash(manifest),publisher:email};
}
function requirePostimage(h,post){if(!h.postSyncReconcile)return;need(h.postSyncReconcile.publisher===h.sourceEmail,'POST_SYNC_SOURCE_BINDING');for(const f of post.files){const p=h.postSyncReconcile.manifest.filter(x=>pathEqual(x.path,h.centralPath.replace(/\.rvt$/i,'')+'_backup/'+f.name));need(p.length===1&&p[0].sha256===f.sha256&&p[0].size===f.length,'POST_SYNC_PUBLISHED_POSTIMAGE_REQUIRED');}}
module.exports={admit,requirePostimage};
