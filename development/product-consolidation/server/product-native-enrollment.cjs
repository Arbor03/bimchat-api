'use strict';
// Explicit, reviewed offline enrollment. Not an HTTP route or automatic recovery.
// The reviewed record is retained with deployment configuration for reconstruction.
const proof=require('./ephemeral-attempt-v1/device-proof.cjs');
const legacy=require('./product-model-stream-policy.cjs');
const scope=require('./scoped-api-v11/scope.cjs'),{need}=scope;
const content=require('./scoped-api-v11/content-pins.cjs');
function validate(e,model){
 need(e&&Object.keys(e).sort().join(',')==='epoch,log,pins,sequence'&&/^[a-f0-9-]{36}$/i.test(e.epoch)&&Number.isSafeInteger(e.sequence)&&e.sequence>=0,'STREAM_NATIVE_ENROLLMENT');
 require('./product-native-stream-policy.cjs')(null,model).pins(e.pins);content.validate(e.log);
 const log=e.pins.files[5];need(log.length===e.log.size&&log.sha256===e.log.sha256,'STREAM_NATIVE_ENROLLMENT_LOG');return e;
}
function five(p){const value={files:p.files.slice(0,5),users:p.users};legacy.pins(value);return value;}
function equal(a,b){return proof.canonical(a)===proof.canonical(b);}
function pending(e,p){
 if(p.local_pins?.files?.length!==5)return false;
 need(e&&p.epoch===e.epoch&&Number(p.applied_sequence)===e.sequence&&equal(p.local_pins,five(e.pins)),'STREAM_NATIVE_ENROLLMENT_CURSOR');return true;
}
function joined(e,previous,actual){need(pending(e,previous)&&equal(actual,e.pins),'STREAM_NATIVE_ENROLLMENT_LOCAL_STATE');}
function head(e,h,model){
 const native=require('./product-native-stream-policy.cjs')(null,model);native.pins(h.head);
 if(e){validate(e,model);need(h.epoch===e.epoch&&Number(h.sequence)>=e.sequence,'STREAM_NATIVE_ENROLLMENT_EPOCH');if(Number(h.sequence)===e.sequence)need(equal(h.head,e.pins),'STREAM_NATIVE_ENROLLMENT_PREIMAGE');legacy.pins(h.baseline);}
 else native.pins(h.baseline);
}
async function prepare({pool,r2,review,approvedDigest}){
 // No live call is made by importing this module. Actual use requires a separate
 // operator-approved outage: all Revit/Drive writers stopped and sessions expired.
 need(review&&review.offlineEnrollmentApproved===true&&proof.hash(review)===approvedDigest,'STREAM_NATIVE_ENROLLMENT_REVIEW');
 review=JSON.parse(proof.canonical(review));
 const model=review.centralPath.replace(/\\/g,'/').split('/').pop(),e=validate(review.nativeBaseline,model);
 need(Number.isSafeInteger(review.fileId)&&review.fileId>0&&r2&&typeof r2.withVerifiedStream==='function','STREAM_NATIVE_ENROLLMENT_CONTEXT');
 const c=await pool.connect();try{
  await c.query('BEGIN');await scope.lock(c,review.projectId);
  await c.query('SELECT pg_advisory_xact_lock(194811, $1)',[review.fileId]);
  const h=(await c.query('SELECT * FROM bimchat_direct_ownership.model_streams WHERE file_id=$1 FOR UPDATE',[review.fileId])).rows[0];
  need(h&&h.project_id===review.projectId&&h.epoch===e.epoch&&Number(h.sequence)===e.sequence&&h.native_gate_enabled===false,'STREAM_NATIVE_ENROLLMENT_HEAD');
  const catalog=(await c.query('SELECT project_id,relative_path FROM cloud_files WHERE id=$1',[review.fileId])).rows[0];need(catalog&&catalog.project_id===review.projectId&&scope.equal(catalog.relative_path,review.centralPath),'STREAM_NATIVE_ENROLLMENT_MODEL');
  legacy.pins(h.baseline);legacy.pins(h.head);need(equal(h.head,five(e.pins)),'STREAM_NATIVE_ENROLLMENT_PREIMAGE');
  const history=(await c.query("SELECT COUNT(*) AS total, MIN(sequence) AS first, MAX(sequence) AS last, BOOL_AND(COALESCE(payload->'patch'->>'Schema'='3',false)) AS delta_only FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1",[review.fileId])).rows[0];
  need(history&&Number(history.total)===e.sequence&&(e.sequence===0||(Number(history.first)===1&&Number(history.last)===e.sequence&&history.delta_only===true)),'STREAM_NATIVE_ENROLLMENT_HISTORY');
  need(!(await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[review.fileId])).rowCount,'STREAM_NATIVE_ENROLLMENT_SYNC');
  need(!(await c.query("SELECT 1 FROM bimchat_direct_ownership.model_stream_inbox WHERE file_id=$1 AND state='queued' LIMIT 1",[review.fileId])).rowCount,'STREAM_NATIVE_ENROLLMENT_QUEUE');
  need(!(await c.query("SELECT 1 FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND state<>'completed' LIMIT 1",[review.fileId])).rowCount,'STREAM_NATIVE_ENROLLMENT_ADMISSION');
  need(!(await c.query('SELECT 1 FROM bimchat_direct_ownership.model_stream_sessions s JOIN bimchat_direct_ownership.model_stream_participants p USING(participant_id) WHERE p.file_id=$1 AND s.revoked=false AND s.expires_at>clock_timestamp() LIMIT 1',[review.fileId])).rowCount,'STREAM_NATIVE_ENROLLMENT_SESSION');
  const participants=(await c.query('SELECT epoch,applied_sequence,local_pins FROM bimchat_direct_ownership.model_stream_participants WHERE file_id=$1 FOR UPDATE',[review.fileId])).rows;
  for(const p of participants)need(pending(e,p),'STREAM_NATIVE_ENROLLMENT_PARTICIPANT');
  const pin=await content.load(c,e.log.key);need(equal(pin,e.log),'STREAM_NATIVE_ENROLLMENT_SEALED_LOG');
  await r2.withVerifiedStream(pin,input=>require('./product-stream-base.cjs').capture(c,review.fileId,e.pins.files[5].name,pin,input));
  await c.query('UPDATE bimchat_direct_ownership.model_streams SET head=$2 WHERE file_id=$1',[review.fileId,JSON.stringify(e.pins)]);
  // Epoch, accepted sequence, five-file initial base/history, participant cursors
  // and receipts remain unchanged. Only actual six-file Join upgrades a participant.
  await c.query('COMMIT');return {prepared:true,epoch:e.epoch,sequence:e.sequence,nativeGateEnabled:false};
 }catch(error){await c.query('ROLLBACK');throw error;}finally{c.release();}
}
module.exports={validate,five,equal,pending,joined,head,prepare};
