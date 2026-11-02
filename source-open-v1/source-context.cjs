'use strict';
const {need}=require('../ephemeral-attempt-v1/scope.cjs'),{requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs');
const baseline=require('../scoped-api-v11/baseline-r2.cjs'),{writerDrain}=require('../receiver-open-v1/evidence-adapters.cjs');
module.exports=function({reviewedInventoryDigest}){
 const verifySourceNativeFence=require('./source-fence-evidence.cjs').verifyStored;
 need(typeof verifySourceNativeFence==='function','SOURCE_NATIVE_VERIFIER_REQUIRED');const drain=writerDrain({reviewedInventoryDigest});
 return async(c,h,auth)=>{
  const s=(await c.query('SELECT * FROM bimchat_direct_ownership.scopes WHERE id=$1 FOR UPDATE',[h.id])).rows[0];need(s&&s.state==='fenced'&&s.project_id===h.projectId&&s.file_id===h.fileId&&s.central_path===h.centralPath&&s.logical_central_path===h.logicalCentralPath,'SOURCE_MODEL_FENCE');
  for(const role of ['source','receiver'])await requireActive(c,{email:h[role+'Email'],sessionId:h[role+'Session'],deviceId:h[role+'Device'],reviewDigest:h.reviewDigest,publicKeyDigest:h[role+'PublicKeyDigest']},h.projectId,h.centralPath,require('./controlled-cycle.cjs').enrollmentRole(h,role));
  const publication=(await c.query('SELECT state,published_id FROM isolated_publications WHERE project_id=$1 AND central_path=$2 FOR UPDATE',[h.projectId,h.centralPath])).rows[0];need(publication&&publication.state==='published'&&publication.published_id===h.baselinePublicationId,'SOURCE_BASELINE_PUBLICATION');await baseline.verifyForHead(c,h);await drain(c,h);
  need(!(await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1 LIMIT 1',[h.fileId])).rowCount,'SOURCE_SYNC_LOCK');
  // Requires independently verified, session/build/process-bound SOURCE fence observation;
  // never substitute an HTTP boolean, old receiver capability screenshot or empty work tables.
  need(await verifySourceNativeFence(c,h,auth)===true,'SOURCE_NATIVE_FENCE_UNVERIFIED');return true;
 };
};

