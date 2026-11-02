'use strict';
const {need}=require('../ephemeral-attempt-v1/scope.cjs');
const proof=require('../ephemeral-attempt-v1/device-proof.cjs');
const {requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs');
function allowed(req){return req.method==='POST'&&/^\/drive\/receiver-operations\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\/(pending|apply-begin|applied|verify-begin|verified|stop)$/.test(req.originalUrl);}
function resolver({pool,review,approvedDigest}){
 need(pool&&proof.hash(review)===approvedDigest&&Array.isArray(review.participants)&&review.participants.length===2,'RECEIVER_REVIEW');
 const snapshot=JSON.parse(proof.canonical(review));
 return async req=>{
  need(allowed(req)&&req.user&&typeof req.user.email==='string','RECEIVER_ROUTE_OR_JWT');
  const encoded=req.headers['x-bimchat-proof'];need(typeof encoded==='string'&&encoded.length<=12000,'RECEIVER_PROOF_HEADER');
  const envelope=JSON.parse(Buffer.from(encoded,'base64').toString('utf8'));
  need(envelope&&envelope.payload,'RECEIVER_ROLE');
  const c=await pool.connect();try{await c.query('BEGIN');
   const row=(await c.query('SELECT document FROM bimchat_direct_ownership.attempts WHERE id=$1',[req.params.id])).rows[0];const h=row&&row.document;need(h,'RECEIVER_UNKNOWN');
   let selected=snapshot,digest=approvedDigest;
   if(h.bootstrapPlanDigest){need(h.bootstrapPlanDigest===approvedDigest&&h.pairedReview&&h.pairedReview.bootstrapPlanDigest===approvedDigest&&proof.hash(h.pairedReview)===h.reviewDigest&&h.pairedReview.projectId===h.projectId&&h.pairedReview.centralPath===h.centralPath,'RECEIVER_PAIRED_REVIEW');selected=h.pairedReview;digest=h.reviewDigest;}
   const p=selected.participants.find(p=>p.email===req.user.email&&p.deviceId===envelope.payload.device);need(p,'RECEIVER_PARTICIPANT');
   const auth=proof.verify(envelope,{email:req.user.email,method:req.method,path:req.originalUrl,body:req.body},p,digest);auth.reviewDigest=digest;auth.publicKeyDigest=p.publicKeyDigest;
   need(h.reviewDigest===digest&&h.receiverEmail===auth.email&&h.receiverSession===auth.sessionId&&h.receiverDevice===auth.deviceId,'RECEIVER_CURRENT_ROLE');await requireActive(c,auth,h.projectId,h.centralPath,require('../source-open-v1/controlled-cycle.cjs').enrollmentRole(h,'receiver'));
   const used=await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[envelope.payload.nonce,digest,auth.email,auth.sessionId]);need(used.rowCount===1,'RECEIVER_REPLAY');await c.query('COMMIT');return auth;
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 };
}
function mount(app,jwt,resolve,operations){need(app&&typeof jwt==='function'&&typeof resolve==='function'&&operations&&['pending','begin','applied','verifyBegin','verified','stop'].every(k=>typeof operations[k]==='function'),'RECEIVER_ROUTE_ADAPTERS');
 for(const [route,method] of [['pending','pending'],['apply-begin','begin'],['applied','applied'],['verify-begin','verifyBegin'],['verified','verified'],['stop','stop']])app.post('/drive/receiver-operations/:id/'+route,jwt,async(req,res)=>{try{const auth=await resolve(req);need(auth&&req.user&&auth.email===req.user.email,'RECEIVER_PRINCIPAL');res.set('Cache-Control','no-store');res.json(await operations[method]({id:req.params.id,body:req.body,auth}));}catch{res.status(423).json({code:'RECEIVER_STOP_PRESERVE_FENCE_NO_RETRY'});}});
}
module.exports={allowed,resolver,mount}; // Explicit mounting only, no startup or credentials.


