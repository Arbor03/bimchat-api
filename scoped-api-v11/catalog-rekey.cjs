"use strict";
const scope=require('./scope.cjs'),{need}=scope;
// Caller holds scope lane in a transaction plus a previously COMMITTED storage_work
// reservation. SQL rollback does not undo created objects: retain reservation/evidence.
// This covers cloud_files only; isolated publication manifests must also be reconciled
// before drain.arm may accept allWritersGuarded/oldWritableKeysDetached proof.
async function rekey(c,s,reviewedFiles,seal){need(s.state==='draining'&&typeof seal==='function','REKEY_DRAIN_REQUIRED');const files=(await c.query('SELECT id,relative_path,b2_key FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[s.project_id])).rows.filter(f=>scope.group(s.central_path,f.relative_path));need(Array.isArray(reviewedFiles)&&files.length>0&&files.length===reviewedFiles.length,'REKEY_REVIEW_INVENTORY');scope.unique(files.map(f=>f.relative_path));const proof=[];
 for(const f of files){const expected=reviewedFiles.filter(x=>x.id===f.id&&x.path===f.relative_path&&x.oldKey===f.b2_key);need(expected.length===1&&/^[A-F0-9]{64}$/.test(expected[0].sha256),'REKEY_REVIEW_BINDING');const out=await seal({object_key:f.b2_key,project_id:s.project_id,relative_path:f.relative_path});need(out.contentVerified===true&&out.provider==='r2'&&out.sha256===expected[0].sha256&&out.key.startsWith('direct-sealed/'+s.project_id+'/')&&out.key!==f.b2_key&&out.etag,'REKEY_CONTENT_CHANGED');await require('./content-pins.cjs').insert(c,out);await require('./content-pins.cjs').complete(c,out);await c.query('UPDATE cloud_files SET b2_key=$1 WHERE id=$2 AND b2_key=$3',[out.key,f.id,f.b2_key]);proof.push({path:f.relative_path,oldKey:f.b2_key,newKey:out.key,sha256:out.sha256,provider:out.provider,etag:out.etag,size:out.size,contentVerified:out.contentVerified});}
 return proof;
}
module.exports={rekey,pinForDownload:require('./content-pins.cjs').load};
