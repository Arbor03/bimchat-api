'use strict';
const scope=require('./scoped-api-v11/scope.cjs'),proof=require('./ephemeral-attempt-v1/device-proof.cjs'),pins=require('./scoped-api-v11/content-pins.cjs'),{requireActive}=require('./ephemeral-attempt-v1/ephemeral-authorization.cjs'),cycle=require('./source-open-v1/controlled-cycle.cjs');
const {need}=scope;
module.exports=function({pool}){
 async function inventory(c,h){
  const catalog=(await c.query('SELECT id,project_id,relative_path,b2_key,current_version,file_size FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[h.projectId])).rows.filter(f=>scope.group(h.centralPath,f.relative_path)).map(f=>({...f,file_size:Number(f.file_size)}));
  scope.unique(catalog.map(f=>f.relative_path));need(catalog.length>0&&catalog.length<=512,'RENEWAL_INVENTORY_BOUND');const manifest=[];
  for(const f of catalog){const p=await pins.load(c,f.b2_key);need(p.size===f.file_size,'RENEWAL_CATALOG_SIZE');manifest.push({path:f.relative_path,...p});}
  return {catalog,manifest,catalogDigest:proof.hash(catalog)};
 }
 async function authenticate(c,h,role,signed,action,body,now){
  const auth=proof.verify(signed,{email:h[role+'Email'],method:'POST',path:'/drive/open-attempts/'+h.id+'/'+action,body},{email:h[role+'Email'],sessionId:h[role+'Session'],deviceId:h[role+'Device'],publicJwk:h[role+'AgentPublicKey'],publicKeyDigest:h[role+'PublicKeyDigest']},h.reviewDigest,now);auth.reviewDigest=h.reviewDigest;auth.publicKeyDigest=h[role+'PublicKeyDigest'];await requireActive(c,auth,h.projectId,h.centralPath,cycle.enrollmentRole(h,role));
 }
 async function accept(req){
  const m=req&&req.method==='POST'&&/^\/drive\/open-attempts\/([a-f0-9-]{36})\/(renewal-context|renew-after-sync)$/.exec(req.originalUrl);need(m&&req.user&&req.body&&Buffer.byteLength(proof.canonical(req.body))<=65536,'RENEWAL_REQUEST');
  const raw=req.headers['x-bimchat-proof'];need(typeof raw==='string'&&raw.length<=12000,'RENEWAL_PROOF');const signed=JSON.parse(Buffer.from(raw,'base64').toString('utf8'));
  const c=await pool.connect();try{await c.query('BEGIN');const first=(await c.query('SELECT project_id FROM bimchat_direct_ownership.attempts WHERE id=$1',[m[1]])).rows[0];need(first,'RENEWAL_UNKNOWN');await scope.lock(c,first.project_id);
   const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[m[1]])).rows[0],h=row&&structuredClone(row.document);need(h&&h.id===m[1]&&h.projectId===first.project_id&&h.ordinaryUserChanges===true&&h.transportMode==='background-prepared'&&h.ordinaryIdle===true&&h.state==='armed'&&h.enabled&&!h.ordinaryClaim&&!h.receiverPreparedGeneration,'RENEWAL_IDLE_REQUIRED');
   const role=req.user.email===h.sourceEmail?'source':req.user.email===h.receiverEmail?'receiver':null;need(role,'RENEWAL_PARTICIPANT');
   // Same lock namespace/order as legacy revitSessions.tx. Acquire BEFORE
   // requireActive takes session-row share locks, avoiding a lock-upgrade cycle.
   if(m[2]==='renew-after-sync')for(const email of [h.sourceEmail,h.receiverEmail].sort())await c.query('SELECT pg_advisory_xact_lock(193722,hashtext($1))',[email]);
   let now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);await authenticate(c,h,role,signed,m[2],req.body,now);
   need((await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[signed.payload.nonce,h.reviewDigest,req.user.email,h[role+'Session']])).rowCount===1,'RENEWAL_REPLAY');
   const s=(await c.query('SELECT * FROM bimchat_direct_ownership.scopes WHERE id=$1 FOR UPDATE',[h.id])).rows[0];need(s&&s.state==='released'&&s.project_id===h.projectId&&s.file_id===h.fileId&&s.central_path===h.centralPath,'RENEWAL_SCOPE');
   need((await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[h.fileId])).rowCount===0,'RENEWAL_SYNC_ACTIVE');const work=(await c.query("SELECT relative_path FROM bimchat_direct_ownership.storage_work WHERE project_id=$1 AND state IN ('started','uncertain')",[h.projectId])).rows;need(!work.some(x=>x.relative_path==null||scope.group(h.centralPath,x.relative_path)),'RENEWAL_STORAGE_UNCERTAIN');
   const current=await inventory(c,h);
   if(m[2]==='renewal-context'){need(Object.keys(req.body).length===0,'RENEWAL_CONTEXT_BODY');await c.query('COMMIT');return {...current,generation:h.generation,revision:h.revision,checkedAt:now};}
   const b=req.body;need(b.attempt===h.id&&b.generation===h.generation&&b.revision===h.revision&&b.email===req.user.email&&b.session===h[role+'Session']&&b.device===h[role+'Device']&&b.catalogDigest===current.catalogDigest&&b.mappingHash===h[role+'MappingHash']&&b.logicalCentralPath===h.logicalCentralPath&&b.elementUniqueId===h.elementUniqueId&&b.transferIdle===true&&b.nativeUiHeld===false,'RENEWAL_PROPOSAL_BINDING');
   need(Number.isSafeInteger(b.timestamp)&&b.timestamp<=now&&now-b.timestamp<=10000&&Number.isSafeInteger(b.expiresAt)&&now<b.expiresAt&&b.expiresAt<=b.timestamp+30000,'RENEWAL_PROPOSAL_EXPIRED');require('./source-open-v1/source-policy.cjs').pins(b.pins);
   h.renewalProposals=h.renewalProposals||{};need(!h.renewalProposals[role],'RENEWAL_PROPOSAL_ONCE');h.renewalProposals[role]={body:structuredClone(req.body),signed};
   if(!h.renewalProposals.source||!h.renewalProposals.receiver){await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[h.id,JSON.stringify(h)]);await c.query('COMMIT');return {accepted:true,renewed:false};}
   now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);
   for(const r of ['source','receiver'])await authenticate(c,h,r,h.renewalProposals[r].signed,'renew-after-sync',h.renewalProposals[r].body,now);
   const publicationId=require('node:crypto').randomUUID(),next=require('./product-post-sync-renewal.cjs').prepare(h,{...current,source:h.renewalProposals.source.body,receiver:h.renewalProposals.receiver.body,publicationId,now,bootstrapExpiresAt:h.bootstrapExpiresAt});delete next.head.renewalProposals;
   const previous=(await c.query('SELECT * FROM bimchat_direct_ownership.baselines WHERE scope_id=$1 FOR UPDATE',[h.id])).rows[0];need(previous&&previous.publication_id===h.baselinePublicationId&&previous.manifest_digest===h.baselineManifestDigest,'RENEWAL_PREVIOUS_BASELINE');
   await c.query('INSERT INTO bimchat_direct_ownership.baseline_history(scope_id,publication_id,baseline,evidence) VALUES($1,$2,$3,$4)',[h.id,previous.publication_id,JSON.stringify(previous),JSON.stringify(next.archive)]);
   // Temporary upload destinations may still receive late PUTs, but their
   // revoked receipts can never republish those bytes into this catalog.
   await c.query("UPDATE bimchat_direct_ownership.normal_upload_receipts SET state='revoked' WHERE scope_id=$1 AND state='issued'",[h.id]);
   for(const r of ['source','receiver']){
    need((await c.query("SELECT 1 FROM isolated_revit_sessions WHERE email=$1 AND session_id=$2 AND device_id=$3 AND state='active' FOR UPDATE",[h[r+'Email'],h[r+'Session'],h[r+'Device']])).rowCount===1,'RENEWAL_SESSION_CHANGED');
    // The shared registry is per account, not per model. Never retire it while
    // ANY legacy Sync/publication still owns that session, including other projects.
    need((await c.query('SELECT 1 FROM file_locks WHERE session_id=$1 LIMIT 1',[h[r+'Session']])).rowCount===0,'RENEWAL_LEGACY_SESSION_LOCK');
    need((await c.query("SELECT 1 FROM isolated_publications WHERE owner_session_id=$1 AND (state IS NULL OR state NOT IN ('published','unverified')) LIMIT 1",[h[r+'Session']])).rowCount===0,'RENEWAL_LEGACY_PUBLICATION');
    need((await c.query("SELECT 1 FROM bimchat_direct_ownership.publication_enrollments WHERE session_id=$1 AND device_id=$2 AND email=$3 AND state='active' AND (review_digest<>$4 OR project_id<>$5 OR central_path<>$6)",[h[r+'Session'],h[r+'Device'],h[r+'Email'],h.reviewDigest,h.projectId,h.centralPath])).rowCount===0,'RENEWAL_SHARED_ENROLLMENT');
    need((await c.query("SELECT 1 FROM bimchat_direct_ownership.model_publications WHERE session_id=$1 AND device_id=$2 AND email=$3 AND state<>'released'",[h[r+'Session'],h[r+'Device'],h[r+'Email']])).rowCount===0,'RENEWAL_SHARED_PUBLICATION');
    need((await c.query("SELECT 1 FROM bimchat_direct_ownership.attempts WHERE id<>$1 AND (document->>'sourceSession'=$2 OR document->>'receiverSession'=$2) AND document->>'state' NOT IN ('released','disabled')",[h.id,h[r+'Session']])).rowCount===0,'RENEWAL_SHARED_ATTEMPT');
    need((await c.query("UPDATE bimchat_direct_ownership.publication_enrollments SET state='revoked',not_before=NULL,expires_at=NULL WHERE review_digest=$1 AND email=$2 AND session_id=$3 AND device_id=$4 AND state='active' RETURNING email",[h.reviewDigest,h[r+'Email'],h[r+'Session'],h[r+'Device']])).rowCount===1,'RENEWAL_ENROLLMENT_CHANGED');
    need((await c.query("DELETE FROM isolated_revit_sessions WHERE email=$1 AND session_id=$2 AND device_id=$3 AND state='active' RETURNING email",[h[r+'Email'],h[r+'Session'],h[r+'Device']])).rowCount===1,'RENEWAL_SESSION_CHANGED');
   }
   const manifest=current.manifest.map(p=>({path:p.path,key:p.key,provider:p.provider,etag:p.etag,size:p.size,sha256:p.sha256})).sort((a,b)=>a.path.localeCompare(b.path,'en'));
   await c.query('UPDATE bimchat_direct_ownership.baselines SET publication_id=$2,manifest=$3,manifest_digest=$4 WHERE scope_id=$1',[h.id,publicationId,JSON.stringify(manifest),next.head.baselineManifestDigest]);
   need((await c.query("UPDATE isolated_publications SET published_id=$3,published_paths=$4 WHERE project_id=$1 AND central_path=$2 AND state='published' RETURNING project_id",[h.projectId,h.centralPath,publicationId,JSON.stringify(manifest.map(p=>p.path))])).rowCount===1,'RENEWAL_PUBLICATION_CHANGED');
   need((await c.query("UPDATE bimchat_direct_ownership.scopes SET state='fenced' WHERE id=$1 AND state='released' RETURNING id",[h.id])).rowCount===1,'RENEWAL_SCOPE_CHANGED');
   await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[h.id,JSON.stringify(next.head)]);await c.query('INSERT INTO bimchat_direct_ownership.events(attempt_id,revision,event) VALUES($1,$2,$3)',[h.id,next.head.revision,'paired-post-sync-renewal']);
   const end=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(end<h.expiresAt&&['source','receiver'].every(r=>end<h.renewalProposals[r].body.expiresAt),'RENEWAL_COMMIT_EXPIRED');await c.query('COMMIT');return{accepted:true,renewed:true,attempt:h.id};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 function mount(app,jwt){for(const action of ['renewal-context','renew-after-sync'])app.post('/drive/open-attempts/:id/'+action,jwt,async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await accept(req));}catch{res.status(423).json({code:'OWNERSHIP_RENEWAL_STOP_NO_RETRY'});}});}
 return {accept,mount};
};
