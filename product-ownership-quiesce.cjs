'use strict';
const scope=require('./ephemeral-attempt-v1/scope.cjs');
const {need}=scope;
// Account-authenticated attenuation only. Works after ephemeral key expiry, but
// never grants write access, releases a scope, or asserts that a write stopped.
async function quiesce(pool,id,email,body){
 need(typeof id==='string'&&/^[a-f0-9-]{36}$/i.test(id)&&typeof email==='string','QUIESCE_CONTEXT');
 need(body&&Object.keys(body).sort().join(',')==='expectedRevision,reviewDigest'&&Number.isSafeInteger(body.expectedRevision)&&/^[A-F0-9]{64}$/.test(body.reviewDigest),'QUIESCE_REVIEW');
 const c=await pool.connect();try{
  await c.query('BEGIN');
  const first=(await c.query('SELECT project_id FROM bimchat_direct_ownership.attempts WHERE id=$1',[id])).rows[0];need(first,'QUIESCE_UNKNOWN');
  await scope.lock(c,first.project_id);
  const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[id])).rows[0];
  need(row&&row.project_id===first.project_id&&row.document.id===id&&row.document.projectId===row.project_id,'QUIESCE_SCOPE');
  const h=structuredClone(row.document);
  need(email===h.sourceEmail||email===h.receiverEmail,'QUIESCE_PARTICIPANT');
  need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[row.project_id,email])).rowCount===1,'QUIESCE_MEMBER');
  need(h.reviewDigest===body.reviewDigest&&h.revision===body.expectedRevision&&h.revision<2147483647&&h.state!=='released','QUIESCE_STALE_OR_RELEASED');
  const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(Number.isSafeInteger(now),'QUIESCE_CLOCK');
  // An already issued native/apply grant may still be executing. Preserve its
  // deadline and every receipt; never turn this stop into evidence of idleness.
  if(!h.quiescence)h.quiescence={at:now,by:email,previousState:h.state,previousRevision:h.revision};
  h.enabled=false;h.state='recovery';h.revision++;
  await c.query("UPDATE bimchat_direct_ownership.publication_enrollments SET state='revoked',not_before=NULL,expires_at=NULL WHERE review_digest=$1 AND project_id=$2 AND central_path=$3 AND ((email=$4 AND session_id=$5 AND device_id=$6) OR (email=$7 AND session_id=$8 AND device_id=$9)) AND state='active'",[h.reviewDigest,h.projectId,h.centralPath,h.sourceEmail,h.sourceSession,h.sourceDevice,h.receiverEmail,h.receiverSession,h.receiverDevice]);
  await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);
  await c.query('INSERT INTO bimchat_direct_ownership.events(attempt_id,revision,event) VALUES($1,$2,$3)',[id,h.revision,'ownership-quiesce-preserve-fences']);
  await c.query('COMMIT');
  return {id,revision:h.revision,state:h.state,enabled:false,fenced:true,readyToSync:false,requiresFreshReconciliation:true};
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}
function mount(app,jwt,pool){app.post('/drive/open-attempts/:id/quiesce',jwt,async(req,res)=>{
 try{res.set('Cache-Control','no-store');res.json(await quiesce(pool,req.params.id,req.user&&req.user.email,req.body));}
 catch{res.status(423).json({code:'OWNERSHIP_QUIESCE_REFUSED_READBACK_REQUIRED'});}
});}
module.exports={quiesce,mount};
