'use strict';
const {need,group}=require('./ephemeral-attempt-v1/scope.cjs');
// Read-only recovery inspection uses the normal account JWT, including after the
// ephemeral signing enrollment expired. It cannot release, reactivate or retry.
async function read(pool,id,email){
 need(/^[a-f0-9-]{36}$/i.test(id)&&typeof email==='string','RECOVERY_CONTEXT');
 const c=await pool.connect();try{
  await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1',[id])).rows[0];
  need(row&&row.document.id===id&&row.document.projectId===row.project_id,'RECOVERY_UNKNOWN');const h=row.document;
  need(email===h.sourceEmail||email===h.receiverEmail,'RECOVERY_PARTICIPANT');
  need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[row.project_id,email])).rowCount===1,'RECOVERY_MEMBER');
  const s=(await c.query('SELECT state FROM bimchat_direct_ownership.scopes WHERE id=$1',[id])).rows[0];
  const work=(await c.query("SELECT relative_path FROM bimchat_direct_ownership.storage_work WHERE project_id=$1 AND state IN ('started','uncertain')",[row.project_id])).rows;
  const now=(await c.query('SELECT clock_timestamp() now')).rows[0].now;
  const result={id,projectId:row.project_id,state:h.state,enabled:h.enabled,expiresAt:h.expiresAt,
   scopeState:s?s.state:'missing',unresolvedStorage:work.filter(w=>w.relative_path==null||group(h.centralPath,w.relative_path)).length,
   operationId:h.operationId||null,digest:h.digest||null,revision:h.revision,reviewDigest:h.reviewDigest,checkedAt:now,readyToSync:false,
   instruction:'Preserve local evidence and fence; reconcile before release.'};
  // Server release is not permission to delete a local marker blindly. The
  // Drive must still match its exact attempt, account, generation and file pins.
  if(h.ordinaryUserChanges===true&&h.state==='released'&&h.enabled===false&&s&&s.state==='released'&&h.syncRelease&&h.syncRelease.reason==='normal-sync'&&result.unresolvedStorage===0){
   const role=email===h.sourceEmail?'source':'receiver';
   result.serverReleaseConfirmed=true;result.release={generation:h.syncRelease.generation,logicalCentralPath:h.logicalCentralPath,session:h[role+'Session'],device:h[role+'Device'],pins:h.syncRelease[role+'Pins']};
   result.instruction='Server ownership enrollment released for normal Sync; verify exact local pins before archiving the local hold. A new baseline is required afterward.';
  }
  await c.query('COMMIT');return result;
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}
function mount(app,jwt,pool){app.get('/drive/open-attempts/:id/recovery-status',jwt,async(req,res)=>{
 try{res.set('Cache-Control','no-store');res.json(await read(pool,req.params.id,req.user&&req.user.email));}
 catch{res.status(423).json({code:'OWNERSHIP_RECOVERY_READBACK_UNAVAILABLE'});}
});}
module.exports={read,mount};
