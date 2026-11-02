'use strict';
// Automatic initial provisioning after two authenticated native proposals. A
// committed drain precedes R2 writes; failure never releases it or retries PUTs.
const crypto=require('node:crypto'),scope=require('./scoped-api-v11/scope.cjs'),proof=require('./ephemeral-attempt-v1/device-proof.cjs');
const {need}=scope,pins=require('./scoped-api-v11/content-pins.cjs');
const enrollment=require('./product-bootstrap-enrollment.cjs');
function evidence(h,review,now){
 need(proof.hash(review)===h.bootstrapPlanDigest&&review.initialBaselineApproved===true&&review.bootstrapAttemptId===h.id&&review.projectId===h.projectId&&review.centralPath===h.centralPath&&review.logicalCentralPath===h.logicalCentralPath,'INITIAL_BASELINE_APPROVAL');
 const prepared=enrollment.prepare(h,proof.hash(h.bootstrapProposals),now);
 for(const role of ['source','receiver']){
  const p=h.bootstrapProposals[role],n=p.profile.native,b=n.baseline;
  need(Number.isSafeInteger(n.capturedAt)&&n.capturedAt<=p.receivedAt&&now-n.capturedAt<=30000,'INITIAL_NATIVE_STALE');
  need(b&&b.writerMode==='idle-snapshot'&&b.nativeUiHeld===false&&Number.isSafeInteger(b.checkedAt)&&b.checkedAt>=n.capturedAt&&b.checkedAt<=p.receivedAt&&now-b.checkedAt<=30000,'INITIAL_WRITER_EVIDENCE');
  need(b.central&&/^[A-F0-9]{8}:[A-F0-9]{16}$/.test(b.central.identity)&&/^[A-F0-9]{64}$/.test(b.central.sha256)&&Number.isSafeInteger(b.central.size)&&b.central.size>0&&b.central.size<=64*1024*1024,'INITIAL_CENTRAL_PIN');
 }
 const a=h.bootstrapProposals.source.profile.native.baseline.central,b=h.bootstrapProposals.receiver.profile.native.baseline.central;
 need(a.sha256===b.sha256&&a.size===b.size,'INITIAL_CENTRALS_DIVERGE');return prepared;
}
function catalogBinding(h,review,catalog,prepared){
 const bound=require('./product-baseline-binding.cjs')({projectId:h.projectId,fileId:h.fileId,centralPath:h.centralPath,sourcePins:prepared.sourcePins,receiverPins:prepared.receiverPins,catalog});
 need(Array.isArray(review.initialCatalog)&&proof.hash(bound.inventory)===proof.hash(review.initialCatalog),'INITIAL_CATALOG_CHANGED');
 const central=catalog.find(f=>f.id===h.fileId),pin=h.bootstrapProposals.source.profile.native.baseline.central;
 need(Number(central.file_size)===pin.size,'INITIAL_CENTRAL_CATALOG_SIZE');
 return {bound,expected:new Map([[h.fileId,pin],...bound.ownership.map(f=>[f.id,{sha256:f.sha256,size:f.size}])])};
}
module.exports=function({pool,r2,review,writerInventoryDigest}){
 const drain=require('./receiver-open-v1/evidence-adapters.cjs').writerDrain({reviewedInventoryDigest:writerInventoryDigest});
 async function load(c,id){const row=(await c.query('SELECT document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[id])).rows[0];need(row,'INITIAL_ATTEMPT_UNKNOWN');return structuredClone(row.document);}
 async function now(c){return +new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);}
 async function writers(c,h){await drain(c,{...h,writerInventoryDigest});need(!(await c.query('SELECT 1 FROM file_locks WHERE cloud_file_id=$1',[h.fileId])).rowCount,'INITIAL_SYNC_BUSY');
  const publications=(await c.query('SELECT central_path,state FROM isolated_publications WHERE project_id=$1 FOR UPDATE',[h.projectId])).rows;
  need(!publications.some(p=>scope.overlap(h.centralPath,p.central_path)&&p.central_path!==h.centralPath),'INITIAL_PUBLICATION_ALIAS');
  need(!publications.some(p=>scope.overlap(h.centralPath,p.central_path)&&!['published','unverified'].includes(p.state)),'INITIAL_PUBLICATION_BUSY');
 }
 return async function provision(id){
  need(id===review.bootstrapAttemptId&&r2&&typeof r2.seal==='function','INITIAL_CONTEXT');
  const c=await pool.connect();try{
   await c.query('BEGIN');await scope.lock(c,review.projectId);let h=await load(c,id);
   // Renewal already installed a baseline; it must never be resealed here.
   if(h.renewalPrevious){await require('./scoped-api-v11/baseline-r2.cjs').verify(c,id,h.baselinePublicationId);await c.query('COMMIT');return;}
   evidence(h,review,await now(c));need(!h.initialProvisioning&&!h.baselinePublicationId,'INITIAL_ONCE_NO_RETRY');await writers(c,h);
   const catalog=(await c.query('SELECT id,project_id,relative_path,b2_key,current_version,file_size FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[h.projectId])).rows;
   catalogBinding(h,review,catalog,evidence(h,review,await now(c)));
   const others=await scope.scopes(c,h.projectId);need(!others.some(s=>scope.overlap(s.central_path,h.centralPath)),'INITIAL_EXISTING_SCOPE');
   await c.query("INSERT INTO bimchat_direct_ownership.scopes(id,project_id,file_id,central_path,logical_central_path,state) VALUES($1,$2,$3,$4,$5,'draining')",[id,h.projectId,h.fileId,h.centralPath,h.logicalCentralPath]);
   h.initialProvisioning={state:'started',pairDigest:proof.hash(h.bootstrapProposals)};
   await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);await c.query('COMMIT');
   // All ordinary API/worker writers now see the durable scope drain. Late PUTs
   // to legacy keys cannot affect separately sealed destinations.
   await c.query('BEGIN');await scope.lock(c,review.projectId);h=await load(c,id);
   need(h.initialProvisioning.state==='started'&&h.initialProvisioning.pairDigest===proof.hash(h.bootstrapProposals),'INITIAL_PAIR_CHANGED');
   const prepared=evidence(h,review,await now(c));await writers(c,h);
   const current=(await c.query('SELECT id,project_id,relative_path,b2_key,current_version,file_size FROM cloud_files WHERE project_id=$1 ORDER BY id FOR UPDATE',[h.projectId])).rows;
   const {bound,expected}=catalogBinding(h,review,current,prepared),manifest=[];
   for(const f of bound.inventory){
    const cap={project_id:h.projectId,relative_path:f.path,object_key:f.oldKey},expectedPin=expected.get(f.id);
    // Native snapshots authorize the starting content, not a live UI hold.
    // Bound each R2 call separately and preserve time for fresh confirmation.
    const deadline=Math.min(Date.now()+30000,h.bootstrapExpiresAt-120000,...['source','receiver'].map(role=>h.bootstrapProposals[role].profile.expiresAt-120000));
    const sealed=await r2.seal({...cap,expected:expectedPin,deadline},pins.reservation(pool,cap));
    need(sealed.contentVerified===true&&(!expectedPin||(sealed.sha256===expectedPin.sha256&&sealed.size===expectedPin.size)),'INITIAL_R2_CONTENT');
    const catalogRow=current.find(x=>x.id===f.id);need(sealed.size===Number(catalogRow.file_size),'INITIAL_R2_CATALOG_SIZE');
    await pins.insert(c,sealed);await pins.complete(c,sealed);
    need((await c.query('UPDATE cloud_files SET b2_key=$1 WHERE id=$2 AND b2_key=$3 AND current_version=$4 RETURNING id',[sealed.key,f.id,f.oldKey,f.version])).rowCount===1,'INITIAL_CATALOG_RACE');
    manifest.push({path:f.path,key:sealed.key,provider:sealed.provider,etag:sealed.etag,size:sealed.size,sha256:sealed.sha256});
   }
   manifest.sort((a,b)=>a.path.localeCompare(b.path,'en'));enrollment.prepare(h,proof.hash(h.bootstrapProposals),await now(c));
   const previous=(await c.query('SELECT * FROM isolated_publications WHERE project_id=$1 AND central_path=$2 FOR UPDATE',[h.projectId,h.centralPath])).rows[0];
   h.baselinePublicationId=crypto.randomUUID();h.baselineManifestDigest=proof.hash(manifest);h.initialProvisioning.state='sealed';
   await c.query('INSERT INTO bimchat_direct_ownership.baselines(scope_id,publication_id,manifest,manifest_digest,previous_publication) VALUES($1,$2,$3,$4,$5)',[id,h.baselinePublicationId,JSON.stringify(manifest),h.baselineManifestDigest,previous?JSON.stringify(previous):null]);
   await c.query("INSERT INTO isolated_publications(project_id,central_path,state,published_id,published_paths) VALUES($1,$2,'published',$3,$4) ON CONFLICT(project_id,central_path) DO UPDATE SET state='published',published_id=EXCLUDED.published_id,published_paths=EXCLUDED.published_paths",[h.projectId,h.centralPath,h.baselinePublicationId,JSON.stringify(manifest.map(f=>f.path))]);
   need((await c.query("UPDATE bimchat_direct_ownership.scopes SET state='fenced' WHERE id=$1 AND state='draining' RETURNING id",[id])).rowCount===1,'INITIAL_DRAIN_CHANGED');
   await c.query('UPDATE bimchat_direct_ownership.attempts SET document=$2 WHERE id=$1',[id,JSON.stringify(h)]);await c.query('COMMIT');
  }catch(e){try{await c.query('ROLLBACK');}catch{}throw e;}finally{c.release();}
 };
};
module.exports.evidence=evidence;module.exports.catalogBinding=catalogBinding;
