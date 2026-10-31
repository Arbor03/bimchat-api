'use strict';
// Use ONLY within admissionTransport's authenticated, locked transaction.
module.exports=async function readState(c,e){
 const need=b=>{if(!b)throw Object.assign(Error('COORDINATION_REFUSED'),{status:409});};
 let state,operation=null,digest=null;
 if(e.state==='ready'){
  const a=(await c.query('SELECT created_at FROM observation_scratch_attestations WHERE experiment_id=$1 ORDER BY created_at DESC LIMIT 1',[e.id])).rows[0];
  if(!a)state='awaiting-attestation';else{const age=Date.now()-new Date(a.created_at).getTime();need(Number.isFinite(age)&&age>=0&&age<=10000);state='ready-for-source';}
 }else if(e.state==='observing'){need(e.expires_at&&new Date(e.expires_at)>new Date());state='observing';}
 else if(e.state==='pending'){
  need(e.expires_at&&new Date(e.expires_at)>new Date());const t=(await c.query("SELECT operation_id,digest FROM observation_transactions WHERE experiment_id=$1 AND operation_id=$2 AND state='pending'",[e.id,e.pending_operation])).rows[0];need(t);state='pending';operation=t.operation_id;digest=t.digest;
 }else if(e.state==='completed-blocked'){
  const rows=(await c.query("SELECT operation_id,digest FROM observation_transactions WHERE experiment_id=$1 AND state='acknowledged'",[e.id])).rows;need(rows.length===1);state='completed-blocked';operation=rows[0].operation_id;digest=rows[0].digest;
 }else need(false);
 return {Experiment:e.id,Generation:e.generation,State:state,Operation:operation,Digest:digest,CheckedUtc:new Date().toISOString()};
};
