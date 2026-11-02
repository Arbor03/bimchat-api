'use strict';
const {need}=require('./scope.cjs'),{hash}=require('./device-proof.cjs'),manifest=require('./publication-manifest.cjs');
// Request principal proof already authenticates the exact capture body. This check
// binds it to the reviewed capture implementation, native model, session and operation.
function reviewer(review,approvedDigest){need(hash(review)===approvedDigest,'POST_SYNC_REVIEW_PIN');const r=JSON.parse(JSON.stringify(review));return (row,auth,capture)=>{
 const source=r.participants.find(p=>p.email===r.sourceEmail&&p.email===auth.email&&p.sessionId===auth.sessionId&&p.deviceId===auth.deviceId);
 need(source&&capture&&capture.operationId===row.id&&capture.syncSucceeded===true,'POST_SYNC_OPERATION');
 need(capture.build===source.agentBuild&&capture.mappingHash===source.mappingDigest&&capture.logicalCentralPath===r.logicalCentralPath&&capture.rootIdentity===source.rootIdentity,'POST_SYNC_BINDING');
 need(typeof capture.centralIdentity==='string'&&capture.centralIdentity.length>0,'POST_SYNC_CENTRAL_ID');
 need(Number.isSafeInteger(capture.capturedAt)&&Date.now()>=capture.capturedAt&&Date.now()-capture.capturedAt<=600000,'POST_SYNC_FRESH');
 manifest.validate(row.central_path,capture.files);return capture.files;
};}
async function attest(c,row,files){
 need(row.state==='writing'&&!row.post_sync_attested_at,'POST_SYNC_ONCE');
 const baseline=(await c.query('SELECT * FROM bimchat_direct_ownership.model_publication_files WHERE publication_id=$1 FOR UPDATE',[row.id])).rows;
 need(baseline.length>1&&baseline.every(f=>f.state==='planned'),'POST_SYNC_BEFORE_UPLOAD');
 for(const f of baseline)await c.query('INSERT INTO bimchat_direct_ownership.model_publication_baseline(publication_id,relative_path,sha256,byte_length) VALUES($1,$2,$3,$4)',[row.id,f.relative_path,f.expected_sha256,f.expected_size]);
 // Original evidence is retained above in the same transaction before replacing the plan.
 await c.query('DELETE FROM bimchat_direct_ownership.model_publication_files WHERE publication_id=$1',[row.id]);
 await manifest.plan(c,row.id,row.central_path,files);
 const digest=hash(files);await c.query('UPDATE bimchat_direct_ownership.model_publications SET post_sync_manifest_digest=$2,post_sync_attested_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1',[row.id,digest]);
 return {attested:true,manifestDigest:digest};
}
module.exports={reviewer,attest};
