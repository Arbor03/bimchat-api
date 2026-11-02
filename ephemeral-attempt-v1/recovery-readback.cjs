'use strict';
const {need}=require('./scope.cjs');
async function read(pool,email,field,value){need(['id','review_digest'].includes(field)&&typeof email==='string','READBACK_CONTEXT');const c=await pool.connect();try{
 await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const row=(await c.query(`SELECT p.id,p.project_id,p.central_path,p.state,p.review_digest,p.manifest_digest,p.post_sync_manifest_digest,p.created_at,p.updated_at,clock_timestamp() checked_at FROM bimchat_direct_ownership.model_publications p WHERE p.${field}=$1 AND p.email=$2 AND EXISTS(SELECT 1 FROM project_members m WHERE m.project_id=p.project_id AND m.user_email=$2)`,[value,email])).rows[0];
 if(!row){await c.query('COMMIT');return {found:false,readyToSync:false};}
 const files=(await c.query("SELECT count(*)::int total,count(*) FILTER(WHERE state='planned')::int planned,count(*) FILTER(WHERE state='issued')::int issued,count(*) FILTER(WHERE state='sealed')::int sealed FROM bimchat_direct_ownership.model_publication_files WHERE publication_id=$1",[row.id])).rows[0];
 const baseline=(await c.query('SELECT count(*)::int total FROM bimchat_direct_ownership.model_publication_baseline WHERE publication_id=$1',[row.id])).rows[0].total;
 const work=(await c.query("SELECT relative_path,state FROM bimchat_direct_ownership.storage_work WHERE project_id=$1 AND state IN ('started','uncertain')",[row.project_id])).rows.filter(w=>require('./scope.cjs').group(row.central_path,w.relative_path.replace(/\\/g,'/')));
 await c.query('COMMIT');return {found:true,operationId:row.id,state:row.state,checkedAt:row.checked_at,files,baselineFiles:baseline,unresolvedStorage:work.length,manifestDigest:row.manifest_digest,postSyncDigest:row.post_sync_manifest_digest,recoveryRequired:row.state!=='released'||work.length>0,readyToSync:false};
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
function mount(app,jwt,pool){const route=field=>async(req,res)=>{try{const result=await read(pool,req.user&&req.user.email,field,field==='id'?req.params.id:req.params.digest);res.set('Cache-Control','no-store');res.json(result);}catch{res.status(503).json({code:'PUBLICATION_READBACK_UNAVAILABLE'});}};
 app.get('/drive/model-publications/:id/status',jwt,route('id'));
 app.get('/drive/model-publications/review/:digest/status',jwt,route('review_digest'));
}
module.exports={read,mount};
