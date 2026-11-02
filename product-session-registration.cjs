'use strict';
const scope=require('./scoped-api-v11/scope.cjs'),proof=require('./ephemeral-attempt-v1/device-proof.cjs');
const {need}=scope;
// Normal authenticated Drive connection. This creates only model coordination
// metadata, not an enrollment, key, storage write, or permission to apply bytes.
module.exports=async function connect(pool,review,digest,email,body){
 need(review.automaticEnrollmentApproved===true&&review.initialBaselineApproved===true&&review.transportMode==='background-prepared','CONNECT_NOT_CONFIGURED');
 need(body&&Object.keys(body).sort().join(',')==='addinBuild,agentBuild,logicalCentralPath'&&body.logicalCentralPath===review.logicalCentralPath,'CONNECT_MODEL');
 const me=review.participants?.find(p=>p.email===email);
 need(me&&body.agentBuild===me.agentBuild&&body.addinBuild===me.addinBuild,'CONNECT_BUILD_ACCOUNT');
 need(review.participants.length===2&&new Set(review.participants.map(p=>p.email)).size===2,'CONNECT_PARTICIPANTS');
 const source=review.participants.find(p=>p.email===review.sourceEmail),receiver=review.participants.find(p=>p.email!==review.sourceEmail);
 need(source&&receiver&&/^[a-f0-9-]{36}$/.test(review.bootstrapAttemptId),'CONNECT_CONFIGURATION');
 const c=await pool.connect();try{await c.query('BEGIN');await scope.lock(c,review.projectId);
  for(const p of review.participants)need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[review.projectId,p.email])).rowCount===1,'CONNECT_MEMBERSHIP');
  const prior=(await c.query('SELECT document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[review.bootstrapAttemptId])).rows[0];
  if(prior){const h=prior.document;need(h.lifecycle==='drive'&&h.bootstrapPlanDigest===digest&&h.projectId===review.projectId&&h.fileId===review.fileId&&['bootstrap','armed'].includes(h.state)&&h.bootstrapActivation!=='failed','CONNECT_RECONCILIATION_REQUIRED');await c.query('COMMIT');return {connected:true,created:false};}
  need((await c.query('SELECT 1 FROM bimchat_direct_ownership.attempts WHERE project_id=$1 AND file_id=$2',[review.projectId,review.fileId])).rowCount===0,'CONNECT_EXISTING_STATE');
  const scopes=(await c.query('SELECT central_path FROM bimchat_direct_ownership.scopes WHERE project_id=$1',[review.projectId])).rows;need(!scopes.some(s=>scope.equal(s.central_path,review.centralPath)),'CONNECT_EXISTING_SCOPE');
  const rows=(await c.query('SELECT id,relative_path,b2_key,current_version FROM cloud_files WHERE project_id=$1 ORDER BY id FOR SHARE',[review.projectId])).rows.filter(f=>scope.group(review.centralPath,f.relative_path));
  const catalog=rows.map(f=>({id:f.id,path:f.relative_path,oldKey:f.b2_key,version:f.current_version}));
  need(rows.some(f=>f.id===review.fileId&&scope.equal(f.relative_path,review.centralPath))&&proof.canonical(catalog)===proof.canonical(review.initialCatalog),'CONNECT_CATALOG_CHANGED');
  need((await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[review.fileId])).rowCount===0,'CONNECT_SYNC_BUSY');
  const h={id:review.bootstrapAttemptId,generation:require('node:crypto').randomUUID(),projectId:review.projectId,fileId:review.fileId,model:review.centralPath,centralPath:review.centralPath,logicalCentralPath:review.logicalCentralPath,state:'bootstrap',enabled:false,revision:0,lifecycle:'drive',bootstrapExpiresAt:null,bootstrapPlanDigest:digest,ordinaryUserChanges:true,automaticEnrollmentApproved:true,transportMode:review.transportMode,sourceEmail:source.email,receiverEmail:receiver.email,sourceBuild:source.agentBuild,receiverBuild:receiver.agentBuild,sourceAddinBuild:source.addinBuild,receiverAddinBuild:receiver.addinBuild,writerInventoryDigest:review.writerInventoryDigest};
  await c.query('INSERT INTO bimchat_direct_ownership.attempts(id,project_id,file_id,document) VALUES($1,$2,$3,$4)',[h.id,h.projectId,h.fileId,JSON.stringify(h)]);
  await c.query('COMMIT');return {connected:true,created:true};
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
};
