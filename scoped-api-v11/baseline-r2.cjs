'use strict';
const crypto=require('node:crypto'),scope=require('./scope.cjs'),pins=require('./content-pins.cjs');
const {need}=scope;
// Reviewed operator-only operation. Reuses existing real model objects: no generated
// fixture, client-supplied object bytes, public route or automatic activation.
module.exports=async function baseline({pool,scopeId,publicationId,reviewedFiles,sealer,verifyWritersAndLocalBaseline}){
 need(typeof verifyWritersAndLocalBaseline==='function'&&sealer&&typeof sealer.seal==='function','BASELINE_VERIFIERS_REQUIRED');
 need(/^[a-f0-9-]{36}$/i.test(publicationId),'BASELINE_ID');
 const c=await pool.connect();try{await c.query('BEGIN');const s=await scope.attempt(c,scopeId,true);need(s.state==='draining','BASELINE_DRAIN_REQUIRED');
  need(!(await c.query('SELECT 1 FROM bimchat_direct_ownership.baselines WHERE scope_id=$1',[scopeId])).rowCount,'BASELINE_ONCE');
  const old=(await c.query('SELECT * FROM isolated_publications WHERE project_id=$1 AND central_path=$2 FOR UPDATE',[s.project_id,s.central_path])).rows[0];
  need(!old||['unverified','published'].includes(old.state),'BASELINE_EXISTING_PUBLICATION_BUSY');
  // Must verify both signed closed-PC observations and the real guarded writer
  // inventory against this exact inventory. Caller cannot substitute an HTTP bool.
  need(await verifyWritersAndLocalBaseline(c,s,reviewedFiles)===true,'BASELINE_REVIEW_UNVERIFIED');
  const proof=await require('./catalog-rekey.cjs').rekey(c,s,reviewedFiles,cap=>sealer.seal(cap,pins.reservation(pool,cap)));
  need(proof.some(f=>scope.equal(f.path,s.central_path)),'BASELINE_CENTRAL_REQUIRED');
  const manifest=proof.map(f=>({path:f.path,key:f.newKey,provider:f.provider,etag:f.etag,size:f.size,sha256:f.sha256})).sort((a,b)=>a.path.localeCompare(b.path,'en'));
  const digest=crypto.createHash('sha256').update(require('./direct/protocol.cjs').canonical(manifest)).digest('hex').toUpperCase();
  await c.query('INSERT INTO bimchat_direct_ownership.baselines(scope_id,publication_id,manifest,manifest_digest,previous_publication) VALUES($1,$2,$3,$4,$5)',[scopeId,publicationId,JSON.stringify(manifest),digest,old?JSON.stringify(old):null]);
  await c.query("INSERT INTO isolated_publications(project_id,central_path,state,published_id,published_paths) VALUES($1,$2,'published',$3,$4) ON CONFLICT(project_id,central_path) DO UPDATE SET state='published',published_id=EXCLUDED.published_id,published_paths=EXCLUDED.published_paths",[s.project_id,s.central_path,publicationId,JSON.stringify(manifest.map(f=>f.path))]);
  await c.query('COMMIT');return {scopeId,publicationId,manifestDigest:digest,files:manifest.length,state:'draining',activationAllowed:false};
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
};
async function verify(c,scopeId,publicationId,reconciliation){
 const row=(await c.query('SELECT manifest,manifest_digest FROM bimchat_direct_ownership.baselines WHERE scope_id=$1 AND publication_id=$2',[scopeId,publicationId])).rows[0];need(row&&Array.isArray(row.manifest)&&row.manifest.length,'R2_BASELINE_MISSING');
 const digest=crypto.createHash('sha256').update(require('./direct/protocol.cjs').canonical(row.manifest)).digest('hex').toUpperCase();need(digest===row.manifest_digest,'R2_BASELINE_DIGEST');
 for(const f of row.manifest){const pin=await pins.load(c,f.key);need(pin.sha256===f.sha256&&pin.etag===f.etag&&pin.size===f.size,'R2_BASELINE_PIN_CHANGED');}
 const s=(await c.query('SELECT project_id,central_path FROM bimchat_direct_ownership.scopes WHERE id=$1',[scopeId])).rows[0];need(s,'R2_BASELINE_SCOPE');
 const files=(await c.query('SELECT relative_path,b2_key FROM cloud_files WHERE project_id=$1',[s.project_id])).rows.filter(f=>scope.group(s.central_path,f.relative_path));
 scope.unique(files.map(f=>f.relative_path));scope.unique(row.manifest.map(f=>f.path));const catalogManifest=reconciliation?reconciliation.manifest:row.manifest;
 if(reconciliation){need(reconciliation.kind==='sealed-post-sync'&&Array.isArray(catalogManifest)&&require('../ephemeral-attempt-v1/device-proof.cjs').hash(catalogManifest)===reconciliation.digest,'R2_RECONCILIATION_BINDING');for(const f of catalogManifest){const p=await pins.load(c,f.key);need(p.sha256===f.sha256&&p.etag===f.etag&&p.size===f.size,'R2_RECONCILIATION_PIN');}}
 need(files.length===catalogManifest.length&&files.every(f=>catalogManifest.filter(p=>p.path===f.relative_path&&p.key===f.b2_key).length===1),'R2_BASELINE_CATALOG_CHANGED');
 return row;
}
module.exports.verify=(c,scopeId,publicationId)=>verify(c,scopeId,publicationId,null);
// Only a server-created claim can attach this sealed post-Sync manifest. The
// original baseline/history remains the byte-delta preimage; no baseline reset.
module.exports.verifyForHead=(c,h)=>verify(c,h.id,h.baselinePublicationId,h.postSyncReconcile||null);
