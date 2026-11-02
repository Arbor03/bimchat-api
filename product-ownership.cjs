'use strict';
// Called by the normal API host explicitly. Disabled mode is a no-op and has no
// database/storage side effects. No migration, enrollment or activation here.
const proof = require('./ephemeral-attempt-v1/device-proof.cjs');
const {need} = require('./ephemeral-attempt-v1/scope.cjs');
const mounted = new WeakSet();
module.exports = async function compose({enabled=false,app,jwt,pool,r2Client,r2Commands,bucket,review,approvedDigest,writerInventoryDigest}) {
  if (!enabled) return Object.freeze({enabled:false});
  need(app && typeof app.post==='function' && typeof app.get==='function' && typeof jwt==='function' && pool && typeof pool.connect==='function','PRODUCT_OWNERSHIP_HOST');
  need(!mounted.has(app),'PRODUCT_OWNERSHIP_ONCE');
  need(review && proof.hash(review)===approvedDigest && review.writerInventoryDigest===writerInventoryDigest && /^[A-F0-9]{64}$/.test(writerInventoryDigest),'PRODUCT_OWNERSHIP_REVIEW');
  need(r2Client && r2Client.config && typeof r2Client.config.maxAttempts==='function' && await r2Client.config.maxAttempts()===1 && bucket==='bimchat-files','PRODUCT_OWNERSHIP_R2');
  const snapshot=JSON.parse(proof.canonical(review));
  const r2=require('./ephemeral-attempt-v1/r2-content.cjs')({client:r2Client,bucket,...r2Commands});
  const source=require('./source-open-v1/source-transactions.cjs')({pool,
    verifySourceAndStorage:require('./source-open-v1/source-context.cjs')({reviewedInventoryDigest:writerInventoryDigest})});
  const ingest=require('./source-open-v1/observation-ingest.cjs')({pool});
  const status=require('./source-open-v1/attempt-status.cjs')({pool});
  // Construct receiver routes on an inert registration collector first. A bad
  // review or missing dependency cannot leave half an ownership API mounted.
  const registrations=[];
  const collector={post(...args){registrations.push(['post',args]);},get(...args){registrations.push(['get',args]);}};
  source.mount(collector,jwt); ingest.mount(collector,jwt); status.mount(collector,jwt);
  const receiver=require('./receiver-open-v1/receiver-compose.cjs')({app:collector,jwt,pool,review:snapshot,approvedDigest,r2});
  require('./ephemeral-attempt-v1/recovery-readback.cjs').mount(collector,jwt,pool);
  require('./product-recovery-status.cjs').mount(collector,jwt,pool);
  require('./product-ownership-quiesce.cjs').mount(collector,jwt,pool);
  require('./source-open-v1/cycle-checkpoint.cjs')({pool}).mount(collector,jwt);
  require('./source-open-v1/ordinary-claim.cjs')({pool}).mount(collector,jwt);
  const provisionInitialBaseline=require('./product-initial-baseline.cjs')({pool,r2,review:snapshot,writerInventoryDigest});
  require('./product-bootstrap.cjs')({pool,review:snapshot,approvedDigest,provisionInitialBaseline}).mount(collector,jwt);
  require('./product-renewal.cjs')({pool}).mount(collector,jwt);
  mounted.add(app); // If the real host registration throws, discard that host.
  for(const [method,args] of registrations) app[method](...args);
  return Object.freeze({enabled:true,routeCount:registrations.length,source,receiver,status});
};
