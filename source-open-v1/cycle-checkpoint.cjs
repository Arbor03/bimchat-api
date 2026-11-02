'use strict';
const scope=require('../ephemeral-attempt-v1/scope.cjs'),proof=require('../ephemeral-attempt-v1/device-proof.cjs');
const {requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs'),cycle=require('./controlled-cycle.cjs');const {need}=scope;
module.exports=function({pool}){
 async function accept(req){
  const match=req&&req.method==='POST'&&/^\/drive\/open-attempts\/([a-f0-9-]{36})\/(cycle-checkpoint|baseline-checkpoint|normal-sync-checkpoint)$/.exec(req.originalUrl);need(match&&req.user,'CYCLE_REQUEST');
  need(req.body&&Buffer.byteLength(proof.canonical(req.body))<=65536,'CYCLE_BODY_BOUND');const body=JSON.parse(proof.canonical(req.body));
  const raw=req.headers['x-bimchat-proof'];need(typeof raw==='string'&&raw.length<=12000,'CYCLE_PROOF');const signed=JSON.parse(Buffer.from(raw,'base64').toString('utf8'));
  const c=await pool.connect();try{await c.query('BEGIN');const first=(await c.query('SELECT project_id FROM bimchat_direct_ownership.attempts WHERE id=$1',[match[1]])).rows[0];need(first,'CYCLE_UNKNOWN');await scope.lock(c,first.project_id);
   const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[match[1]])).rows[0];need(row&&row.project_id===first.project_id,'CYCLE_SCOPE');let h=structuredClone(row.document);
   const syncRelease=match[2]==='normal-sync-checkpoint',ordinary=match[2]!=='cycle-checkpoint';need(ordinary?h.ordinaryUserChanges===true&&!h.cycle:h.ordinaryUserChanges!==true,'CHECKPOINT_MODE');
   const role=req.user.email===h.sourceEmail?'source':req.user.email===h.receiverEmail?'receiver':null;need(role&&h.id===match[1]&&h.projectId===row.project_id&&(ordinary||cycle.leg(h)>=0)&&h.state==='recovery'&&h.enabled===false,'CYCLE_PARTICIPANT_STATE');
   let now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);
   const auth=proof.verify(signed,{email:req.user.email,method:'POST',path:req.originalUrl,body},{email:h[role+'Email'],sessionId:h[role+'Session'],deviceId:h[role+'Device'],publicJwk:h[role+'AgentPublicKey'],publicKeyDigest:h[role+'PublicKeyDigest']},h.reviewDigest,now);auth.reviewDigest=h.reviewDigest;auth.publicKeyDigest=h[role+'PublicKeyDigest'];
   await requireActive(c,auth,h.projectId,h.centralPath,cycle.enrollmentRole(h,role));
   if(ordinary)need(syncRelease?body.nextSourceEmail===h.sourceEmail:body.nextSourceEmail===h.sourceEmail||body.nextSourceEmail===h.receiverEmail,'USER_NEXT_SOURCE_REQUIRED');
   need(body.revision===h.revision&&body.generation===h.generation&&body.operationId===h.operationId&&body.digest===h.digest,'CYCLE_STALE');
   const background=ordinary&&h.transportMode==='background-prepared';const p=body.native;need(p&&(background?p.nativeUiHeld===false:p.nativeUiHeld===true)&&p.transferIdle===true&&p.fence===h.id&&p.logicalCentralPath===h.logicalCentralPath&&p.elementUniqueId===h.elementUniqueId&&p.revitPid===h[role+'RevitPid']&&p.revitStarted===h[role+'RevitStarted']&&p.agentPid===h[role+'AgentPid']&&p.agentStarted===h[role+'AgentStarted']&&p.addinBuild===h[role+'AddinBuild']&&p.agentBuild===h[role+'Build']&&p.mappingHash===h[role+'MappingHash'],'CYCLE_NATIVE_BINDING');
   const live=(p,t)=>Number.isSafeInteger(p.timestamp)&&Number.isSafeInteger(p.holdExpiresAt)&&p.timestamp<=t&&t-p.timestamp<=10000&&t<p.holdExpiresAt&&p.holdExpiresAt<=p.timestamp+30000;
   need(live(p,now)&&now<h.expiresAt,'CYCLE_CHECKPOINT_EXPIRED');cycle.validatePostPins(h,role,body.pins);
   h.cycleCheckpoints=h.cycleCheckpoints||{};need(!h.cycleCheckpoints[role],'CYCLE_CHECKPOINT_ONCE');
   need((await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[signed.payload.nonce,h.reviewDigest,auth.email,auth.sessionId])).rowCount===1,'CYCLE_REPLAY');
   h.cycleCheckpoints[role]={body,signed,action:match[2]};let advanced=false;
   if(h.cycleCheckpoints.source&&h.cycleCheckpoints.receiver){now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);for(const r of ['source','receiver']){const cp=h.cycleCheckpoints[r];need(cp.body.generation===h.generation&&cp.body.revision===h.revision&&live(cp.body.native,now),'CYCLE_PEER_CHECKPOINT_STALE');await requireActive(c,{email:h[r+'Email'],sessionId:h[r+'Session'],deviceId:h[r+'Device'],reviewDigest:h.reviewDigest,publicKeyDigest:h[r+'PublicKeyDigest']},h.projectId,h.centralPath,cycle.enrollmentRole(h,r));}
    const fenced=(await c.query('SELECT state,project_id,file_id,central_path FROM bimchat_direct_ownership.scopes WHERE id=$1 FOR UPDATE',[h.id])).rows[0];need(fenced&&fenced.state==='fenced'&&fenced.project_id===h.projectId&&fenced.file_id===h.fileId&&fenced.central_path===h.centralPath,'CYCLE_SCOPE_NOT_FENCED');
    const work=(await c.query("SELECT relative_path FROM bimchat_direct_ownership.storage_work WHERE project_id=$1 AND state IN ('started','uncertain')",[h.projectId])).rows;need(!work.some(x=>x.relative_path==null||scope.group(h.centralPath,x.relative_path)),'CYCLE_STORAGE_NOT_IDLE');
    need((await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1 LIMIT 1',[h.fileId])).rowCount===0,'CYCLE_SYNC_NOT_IDLE');
    const evidence=h.cycleCheckpoints;need(evidence.source.action===match[2]&&evidence.receiver.action===match[2],'CHECKPOINT_ACTION_DISAGREEMENT');if(ordinary)need(evidence.source.body.nextSourceEmail===evidence.receiver.body.nextSourceEmail,'USER_NEXT_SOURCE_DISAGREEMENT');h=(ordinary?cycle.advanceObserved:cycle.advance)(h,evidence.source.body.pins,evidence.receiver.body.pins,now,body.nextSourceEmail);const history=ordinary?h.observedHistory:h.cycle.history;history[history.length-1].checkpoints=evidence;advanced=true;
    if(ordinary&&h.lifecycle==='drive'){
     const checkpoint=history[history.length-1];
     await c.query('INSERT INTO bimchat_direct_ownership.baseline_history(scope_id,publication_id,baseline,evidence) VALUES($1,$2,$3,$4)',[h.id,checkpoint.operationId,JSON.stringify({kind:'ownership-checkpoint',generation:checkpoint.generation,sourcePins:checkpoint.sourcePins,receiverPins:checkpoint.receiverPins}),JSON.stringify({reviewDigest:h.reviewDigest,checkpoint})]);
    }
    if(ordinary&&!syncRelease){h.ordinaryIdle=true;need((await c.query("UPDATE bimchat_direct_ownership.scopes SET state='released' WHERE id=$1 AND state='fenced' RETURNING id",[h.id])).rowCount===1,'ORDINARY_IDLE_SCOPE_CHANGED');}
    if(syncRelease){
     h.enabled=false;h.state='released';h.syncRelease={generation:h.generation,at:now,reason:'normal-sync',sourcePins:h.sourcePins,receiverPins:h.receiverPins};
     need((await c.query("UPDATE bimchat_direct_ownership.scopes SET state='released' WHERE id=$1 AND state='fenced' RETURNING id",[h.id])).rowCount===1,'SYNC_RELEASE_SCOPE_CHANGED');
     await c.query("UPDATE bimchat_direct_ownership.publication_enrollments SET state='revoked',not_before=NULL,expires_at=NULL WHERE review_digest=$1 AND project_id=$2 AND central_path=$3 AND ((email=$4 AND session_id=$5 AND device_id=$6) OR (email=$7 AND session_id=$8 AND device_id=$9)) AND state='active'",[h.reviewDigest,h.projectId,h.centralPath,h.sourceEmail,h.sourceSession,h.sourceDevice,h.receiverEmail,h.receiverSession,h.receiverDevice]);
    }
   }
   await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[h.id,JSON.stringify(h)]);
   if(advanced)await c.query('INSERT INTO bimchat_direct_ownership.events(attempt_id,revision,event) VALUES($1,$2,$3)',[h.id,h.revision,syncRelease?'ordinary-normal-sync-release':ordinary?'ordinary-baseline-checkpoint':'controlled-cycle-checkpoint']);
   const end=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(end<h.expiresAt&&live(p,end),'CYCLE_COMMIT_EXPIRED');
   if(advanced)for(const cp of Object.values((ordinary?h.observedHistory:h.cycle.history).slice(-1)[0].checkpoints))need(live(cp.body.native,end),'CYCLE_PEER_COMMIT_EXPIRED');
   await c.query('COMMIT');return {accepted:true,advanced,generation:h.generation,revision:h.revision,state:h.state,fenced:true};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 function mount(app,jwt){for(const action of ['cycle-checkpoint','baseline-checkpoint','normal-sync-checkpoint'])app.post('/drive/open-attempts/:id/'+action,jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await accept(req));}catch{res.status(423).json({code:'CYCLE_CHECKPOINT_STOP_NO_RETRY'});}});}
 return{accept,mount};
};
