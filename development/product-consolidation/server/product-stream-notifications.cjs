'use strict';
// Notifications are hints. LISTEN precedes the durable read, closing the subscribe/read race.
// No schema change and no polling query while idle. pg_notify is delivered only on commit.
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
const channel='bimchat_ownership_changed';
async function publish(c,fileId){await c.query('SELECT pg_notify($1,$2)',[channel,String(fileId)]);}
module.exports=function({pool,timeoutMs=20000,maxWaiters=Math.max(1,(pool.options?.max||10)-6)}){
 let active=0;
 async function wait(auth,body,signal){
  const operation=body.operationId,request=body.requestId;
  need(!(operation&&request)&&Object.keys(body).sort().join(',')===(operation?'epoch,fileId,operationId,sequence':request?'epoch,fileId,requestId,sequence':'epoch,fileId,sequence')&&typeof body.epoch==='string'&&Number.isSafeInteger(body.sequence)&&body.sequence>=0,'STREAM_WAIT_BODY');
  need(!(operation||request)||/^[a-f0-9-]{36}$/i.test(operation||request),'STREAM_WAIT_BODY');
  need(active<maxWaiters,'STREAM_WAIT_CAPACITY');active++;
  let c,timer,resolveWake,rejectWake,dirty=false,destroy=false;
  const wake=()=>{dirty=true;if(resolveWake)resolveWake();};
  const error=()=>{destroy=true;if(rejectWake)rejectWake(new Error('STREAM_WAIT_CONNECTION'));};
  const abort=()=>{if(rejectWake)rejectWake(new Error('STREAM_WAIT_CANCELLED'));};
  const notification=n=>{if(n.channel===channel&&n.payload===String(auth.fileId))wake();};
  const deadline=Date.now()+timeoutMs;
  try{
   c=await pool.connect();c.on('notification',notification);c.on('error',error);
   await c.query('LISTEN '+channel);
   for(;;){
    need(!signal?.aborted,'STREAM_WAIT_CANCELLED');need(!destroy,'STREAM_WAIT_CONNECTION');dirty=false;
    const r=(await c.query(`SELECT m.epoch,m.sequence,p.participant_id FROM bimchat_direct_ownership.model_streams m
     JOIN bimchat_direct_ownership.model_stream_participants p ON p.file_id=m.file_id
     JOIN bimchat_direct_ownership.model_stream_sessions s USING(participant_id)
     JOIN project_members pm ON pm.project_id=m.project_id AND pm.user_email=p.email
     WHERE m.file_id=$1 AND p.email=$2 AND s.session_id=$3 AND s.key_digest=$4
     AND s.revoked=false AND s.expires_at>clock_timestamp()`,[auth.fileId,auth.email,auth.sessionId,auth.keyDigest])).rows[0];
    need(r&&r.epoch===body.epoch,'STREAM_WAIT_SESSION');
    let changed=Number(r.sequence)!==body.sequence;
    if(operation){
     const op=(await c.query('SELECT file_id,source_auth,state FROM bimchat_direct_ownership.model_stream_inbox WHERE operation_id=$1',[operation])).rows[0];
     need(op&&op.file_id===auth.fileId&&op.source_auth.email===auth.email&&op.source_auth.deviceId===auth.deviceId,'STREAM_OPERATION_SCOPE');
     changed=op.state!=='queued';
    }
    if(request){
     const turn=(await c.query('SELECT file_id,participant_id,epoch,state FROM bimchat_direct_ownership.native_admissions WHERE request_id=$1',[request])).rows[0];
     need(turn&&turn.file_id===auth.fileId&&turn.participant_id===r.participant_id&&turn.epoch===r.epoch,'STREAM_NATIVE_OWNER');
     const active=(await c.query("SELECT request_id FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND state IN ('reserved','admitted')",[auth.fileId])).rows[0];
     const first=(await c.query("SELECT request_id FROM bimchat_direct_ownership.native_admissions WHERE file_id=$1 AND state='waiting' ORDER BY arrival LIMIT 1",[auth.fileId])).rows[0];
     changed=turn.state!=='waiting'||(!active&&first?.request_id===request);
    }
    if(changed||Date.now()>=deadline)return {epoch:r.epoch,headSequence:Number(r.sequence),changed};
    if(dirty)continue;
    await new Promise((resolve,reject)=>{
     resolveWake=resolve;rejectWake=reject;timer=setTimeout(resolve,Math.max(0,deadline-Date.now()));
     signal?.addEventListener('abort',abort,{once:true});
     if(dirty)resolve();else if(signal?.aborted)abort();else if(destroy)error();
    }).finally(()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);resolveWake=null;rejectWake=null;});
   }
  }finally{
   active--;if(c){try{if(!destroy)await c.query('UNLISTEN '+channel);}catch{destroy=true;}
    c.removeListener('notification',notification);c.removeListener('error',error);c.release(destroy);}
  }
 }
 return {wait};
};
module.exports.publish=publish;
