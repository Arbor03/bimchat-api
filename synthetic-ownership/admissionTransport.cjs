'use strict';
// No imports of application config, no pool creation, listener or auto-migration.
const crypto=require('node:crypto');
const diag=require('./diagnostic.cjs');
const scratch=require('./scratchEvidence.cjs');
const need=(ok)=>{if(!ok)throw Object.assign(Error('OBSERVATION_REFUSED_RECONCILE'),{status:409});};
function exact(o,keys){need(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===keys.slice().sort().join('|'));}
function create({pool,canonical,validate,windowGate,expectedDatabase,verifyTarget}){
 need(pool&&canonical&&validate&&windowGate&&typeof windowGate.verifyAndHold==='function'&&typeof expectedDatabase==='string'&&expectedDatabase.length>0&&typeof verifyTarget==='function');
 // windowGate is mandatory. Must hold main-DB session/membership/Sync protection until
 // disposable commit; deny absent integration. Client flags are never accepted as proof.
 async function transaction(req,fn){diag.stage(req,"pool-connect");const c=await pool.connect();let hold;try{
  diag.stage(req,'transaction-begin');await c.query('BEGIN');await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='3s'");
  diag.stage(req,'database-target');const t=(await c.query('SELECT current_database() db,host(inet_server_addr()) host,inet_server_port() port')).rows[0];need(t.db===expectedDatabase);await verifyTarget(c,t);
  diag.stage(req,"authenticated-context");need(req.user&&req.user.email&&req.headers['x-bimchat-session']);
  diag.stage(req,'experiment-lock');const e=(await c.query('SELECT * FROM observation_experiments WHERE id=$1 FOR UPDATE',[req.params.experiment])).rows[0];need(e&&e.enabled);
  diag.stage(req,"window-gate");hold=await windowGate.verifyAndHold({client:c,experiment:e,authenticatedUser:req.user,session:req.headers['x-bimchat-session']});
  need(hold&&['source','receiver'].includes(hold.role)&&hold.sessionsActive&&hold.membershipsValid&&hold.syncBlocked&&hold.exclusive&&hold.receiverIdle&&hold.scratchIdentity===e.destination_root_identity&&typeof hold.release==='function');
  const result=await fn(c,e,hold.role);diag.stage(req,'commit');await c.query('COMMIT');diag.stage(req,'committed');return result;
 }catch(err){await c.query('ROLLBACK');throw err;}finally{try{if(hold)await hold.release();}finally{c.release();}}}
 const validWindow=e=>need(e.admission_id&&e.expires_at&&new Date(e.expires_at)>new Date());
 function evidence(e){return {ExperimentId:e.id,Model:e.model,Generation:e.generation,SourceSession:e.source_session,ReceiverSession:e.receiver_session,AdmissionId:e.admission_id,PreBundle:e.pre_bundle,SourceRootIdentity:e.source_root_identity,DestinationRootIdentity:e.destination_root_identity,Sequence:Number(e.sequence),IssuedUtc:new Date().toISOString(),ExpiresUtc:new Date(e.expires_at).toISOString(),ScratchDestination:true,ExclusiveWindow:true,SyncBlocked:true,ReceiverIdle:true};}
 async function admit(req){return transaction(req,async(c,e,role)=>{
  need(role==='source'&&e.state==='ready'&&!e.admission_id&&!e.pending_operation);
  const att=(await c.query('SELECT * FROM observation_scratch_attestations WHERE experiment_id=$1 ORDER BY created_at DESC LIMIT 1 FOR SHARE',[e.id])).rows[0];
  need(att&&att.receiver_session===e.receiver_session&&Date.now()-new Date(att.created_at).getTime()<=120000);
  const id=crypto.randomUUID();const expires=new Date(Date.now()+120000);
  await c.query("UPDATE observation_experiments SET admission_id=$2,expires_at=$3,state='observing' WHERE id=$1",[e.id,id,expires]);
  return evidence({...e,admission_id:id,expires_at:expires});
 });}
 async function preflight(req){return transaction(req,async(c,e)=>{need(['observing','pending'].includes(e.state));validWindow(e);return evidence(e);});}
 function parse(wire){need(typeof wire==='string'&&Buffer.byteLength(wire)<=1048576);const p=JSON.parse(wire);need(canonical(p)===wire); // also rejects duplicate keys/noncanonical numeric spelling
  exact(p,['Schema','Model','Generation','SourceSession','OperationId','PreBundle','PostBundle','PreviousSequence','Sequence','Files']);
  need(Array.isArray(p.Files));for(const f of p.Files){exact(f,['Name','PreHash','PostHash','SourceIdentity','PreLength','PostLength','Overwrites','Append']);need(Array.isArray(f.Overwrites));for(const s of f.Overwrites)exact(s,['Offset','Before','After']);}
  const digest=validate(p);const users=p.Files.find(f=>f.Name==='users.dat');need(users&&users.PreHash===users.PostHash&&users.PreLength===users.PostLength&&users.Overwrites.length===0&&users.Append.length===0);return {p,digest};
 }
 async function submit(req){return transaction(req,async(c,e,role)=>{
  need(role==='source'&&e.state==='observing'&&!e.pending_operation);validWindow(e);need(req.params.admission===e.admission_id);
  const {p,digest}=parse(req.body);need(p.Model===e.model&&p.Generation===e.generation&&p.SourceSession===e.source_session&&p.PreBundle===e.pre_bundle&&p.PreviousSequence===Number(e.sequence));
  // Existing ID is refused, not silently replayed. Status GET is reconciliation path.
  await c.query("INSERT INTO observation_transactions(operation_id,experiment_id,admission_id,digest,wire,state) VALUES($1,$2,$3,$4,$5,'pending')",[p.OperationId,e.id,e.admission_id,digest,req.body]);
  await c.query("UPDATE observation_experiments SET state='pending',pending_operation=$2 WHERE id=$1",[e.id,p.OperationId]);return {operationId:p.OperationId,digest,state:'pending'};
 });}
 async function status(req){return transaction(req,async(c,e)=>{
  const t=(await c.query('SELECT operation_id,digest,wire,state,ack FROM observation_transactions WHERE experiment_id=$1 AND operation_id=$2',[e.id,req.params.operation])).rows[0];need(t);return {operationId:t.operation_id,digest:t.digest,wire:t.wire,state:t.state,ack:t.ack};
 });}
 async function coordination(req){return transaction(req,(c,e)=>require('./coordinationState.cjs')(c,e));}
 async function provision(req){return transaction(req,async(c,e,role)=>{
  diag.stage(req,'attestation-role-state');need(role==='receiver'&&['ready','observing'].includes(e.state)&&!e.pending_operation);if(e.state==='observing')validWindow(e);
  scratch.provisioning(req.body,e,canonical,label=>diag.stage(req,label));const receipt=crypto.randomUUID(),digest=scratch.sha(req.body);
  // Records attestation only: never creates remote files or learns pins from the caller.
  diag.stage(req,'attestation-insert');await c.query('INSERT INTO observation_scratch_attestations(experiment_id,receiver_session,receipt_id,canonical_receipt,digest) VALUES($1,$2,$3,$4,$5)',[e.id,e.receiver_session,receipt,req.body,digest]);
  return {receiptId:receipt,digest,accepted:true};
 });}
 async function baseline(req){return transaction(req,async(c,e)=>{
  need(['ready','observing'].includes(e.state)&&!e.pending_operation);
  const r=(await c.query('SELECT * FROM observation_scratch_attestations WHERE experiment_id=$1 ORDER BY created_at DESC LIMIT 1 FOR SHARE',[e.id])).rows[0];
  need(r&&r.receiver_session===e.receiver_session);scratch.provisioning(r.canonical_receipt,e,canonical);
  return {receipt:r.canonical_receipt,receiptId:r.receipt_id,digest:r.digest};
 });}
 async function ack(req){return transaction(req,async(c,e,role)=>{
  need(role==='receiver');
  const t=(await c.query('SELECT * FROM observation_transactions WHERE experiment_id=$1 AND operation_id=$2 FOR UPDATE',[e.id,req.params.operation])).rows[0];need(t);
  const parsed=parse(t.wire);need(parsed.digest===t.digest);
  const a=scratch.completion(req.body,e,t,parsed.p,canonical);
  if(t.state==='acknowledged'){need(canonical(t.ack)===canonical(a));return {state:'acknowledged',duplicate:true};}
  validWindow(e);need(e.state==='pending'&&e.pending_operation===t.operation_id&&t.state==='pending'&&t.admission_id===e.admission_id);
  await c.query("UPDATE observation_transactions SET state='acknowledged',ack=$2,acknowledged_at=now() WHERE operation_id=$1",[t.operation_id,JSON.stringify(a)]);
  // Single observation only; NEVER rearm automatically or clear the main DB barrier.
  await c.query("UPDATE observation_experiments SET state='completed-blocked',pending_operation=NULL,sequence=$2 WHERE id=$1",[e.id,parsed.p.Sequence]);
  return {state:'acknowledged',operationId:t.operation_id,digest:t.digest};
 });}
 function mount(app,auth,textBody){need(typeof auth==='function'&&typeof textBody==='function');const wrap=fn=>async(req,res)=>{try{res.json(await fn(req));}catch(err){res.status(err.status||503).json({error:'OBSERVATION_STOP_RECONCILE'});}};
  app.get('/isolated-observation/experiments/:experiment/coordination',auth,wrap(coordination));
  app.use('/isolated-observation/experiments/:experiment/scratch-attestation',diag.middleware);const base='/isolated-observation/experiments/:experiment';app.post(base+'/scratch-attestation',auth,textBody,wrap(provision));app.get(base+'/scratch-baseline',auth,wrap(baseline));app.post(base+'/admit',auth,wrap(admit));app.get(base+'/preflight',auth,wrap(preflight));app.post(base+'/admissions/:admission/proposals',auth,textBody,wrap(submit));app.get(base+'/transactions/:operation',auth,wrap(status));app.post(base+'/transactions/:operation/ack',auth,textBody,wrap(ack));
 }
 // Receiver attestation is authenticated evidence, not hardware proof of remote disk state.
 // Concrete local completion exporter and one-ACK client still require review/testing.
 return {mount,admit,preflight,submit,status,provision,baseline,ack,coordination};
}
module.exports={create};
