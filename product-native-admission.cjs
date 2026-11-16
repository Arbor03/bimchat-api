'use strict';
// Called inside model-stream.transaction, with the model row locked FOR UPDATE.
// No timers, external IO, or lease-expiry takeover. Experimental mode is opt-in.
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
const uuid=x=>typeof x==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(x);
const generation=x=>typeof x==='string'&&/^[1-9][0-9]*$/.test(x);
function fields(b,names){need(b&&Object.keys(b).sort().join(',')===names.slice().sort().join(','),'STREAM_NATIVE_FIELDS');}
function enabled(h){need(h.native_gate_enabled===true,'STREAM_NATIVE_DISABLED');}
function owner(r,h,s){need(r&&r.file_id===h.file_id&&r.participant_id===s.participant_id&&r.epoch===h.epoch,'STREAM_NATIVE_OWNER');}
function view(r,h){return {requestId:r.request_id,epoch:r.epoch,state:r.state,generation:r.generation==null?null:String(r.generation),baseSequence:r.base_sequence==null?null:Number(r.base_sequence),headSequence:Number(h.sequence)};}
async function request(c,h,s,b){
 enabled(h);fields(b,['requestId']);need(uuid(b.requestId),'STREAM_NATIVE_REQUEST');
 let r=(await c.query('SELECT * FROM bimchat_direct_ownership.native_admissions WHERE request_id=$1',[b.requestId])).rows[0];
 if(r)owner(r,h,s);
 else {
  const other=(await c.query("SELECT request_id FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND participant_id=$2 AND state<>'completed'",[h.file_id,s.participant_id])).rows[0];
  need(!other,'STREAM_NATIVE_OUTSTANDING');
  r=(await c.query("INSERT INTO bimchat_direct_ownership.native_admissions(request_id,file_id,epoch,participant_id,state) VALUES($1,$2,$3,$4,'waiting') RETURNING *",[b.requestId,h.file_id,h.epoch,s.participant_id])).rows[0];
 }
 if(r.state==='waiting'){
  const active=(await c.query("SELECT request_id FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND state IN ('reserved','admitted')",[h.file_id])).rows[0];
  const first=(await c.query("SELECT request_id FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND state='waiting' ORDER BY arrival LIMIT 1",[h.file_id])).rows[0];
  if(!active&&first?.request_id===r.request_id){
   // Admission and publication share the model row lock; no grant races across API workers.
   const g=(await c.query('UPDATE bimchat_direct_ownership.model_streams SET native_generation=native_generation+1 WHERE file_id=$1 RETURNING native_generation',[h.file_id])).rows[0];
   r=(await c.query("UPDATE bimchat_direct_ownership.native_admissions SET state='reserved',generation=$2,base_sequence=$3 WHERE request_id=$1 RETURNING *",[r.request_id,g.native_generation,h.sequence])).rows[0];
  }
 }
 return view(r,h);
}
async function ready(c,h,s,b){
 enabled(h);fields(b,['requestId','generation']);need(uuid(b.requestId)&&generation(b.generation),'STREAM_NATIVE_REQUEST');
 const r=(await c.query('SELECT * FROM bimchat_direct_ownership.native_admissions WHERE request_id=$1',[b.requestId])).rows[0];owner(r,h,s);
 need(String(r.generation)===b.generation&&['reserved','admitted'].includes(r.state),'STREAM_NATIVE_GENERATION');
 need(Number(s.applied_sequence)===Number(h.sequence)&&Number(r.base_sequence)===Number(h.sequence),'STREAM_CATCHUP_REQUIRED');
 if(r.state==='reserved')await c.query("UPDATE bimchat_direct_ownership.native_admissions SET state='admitted' WHERE request_id=$1",[r.request_id]);
 return view({...r,state:'admitted'},h);
}
async function requirePublication(c,h,s,operationId){
 if(h.native_gate_enabled!==true)return;
 const r=(await c.query("SELECT * FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND state='admitted'",[h.file_id])).rows[0];owner(r,h,s);
 need(r.request_id===operationId&&Number(r.base_sequence)===Number(h.sequence),'STREAM_NATIVE_PUBLICATION');
}
async function complete(c,h,s,b){
 enabled(h);fields(b,['requestId','generation','changed']);need(uuid(b.requestId)&&generation(b.generation)&&typeof b.changed==='boolean','STREAM_NATIVE_REQUEST');
 const r=(await c.query('SELECT * FROM bimchat_direct_ownership.native_admissions WHERE request_id=$1',[b.requestId])).rows[0];owner(r,h,s);
 need(String(r.generation)===b.generation,'STREAM_NATIVE_GENERATION');
 if(r.state==='completed'){need(r.changed===b.changed,'STREAM_NATIVE_REUSED');return view(r,h);}
 need(r.state==='admitted','STREAM_NATIVE_STATE');
 const op=(await c.query('SELECT sequence,source_participant FROM bimchat_direct_ownership.model_stream_operations WHERE file_id=$1 AND operation_id=$2',[h.file_id,r.request_id])).rows[0];
 if(b.changed)need(op&&op.source_participant===s.participant_id&&Number(op.sequence)===Number(r.base_sequence)+1&&Number(h.sequence)===Number(op.sequence)&&Number(s.applied_sequence)===Number(op.sequence),'STREAM_NATIVE_NOT_PUBLISHED');
 else need(!op&&Number(h.sequence)===Number(r.base_sequence)&&Number(s.applied_sequence)===Number(h.sequence),'STREAM_NATIVE_CHANGED');
 // Trusted agent reports native quiescence before this call. Never release on elapsed time.
 await c.query("UPDATE bimchat_direct_ownership.native_admissions SET state='completed',changed=$2 WHERE request_id=$1",[r.request_id,b.changed]);
 await require('./product-stream-notifications.cjs').publish(c,h.file_id);
 return view({...r,state:'completed'},h);
}
module.exports={request,ready,complete,requirePublication};
