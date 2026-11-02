'use strict';
const scope=require('../ephemeral-attempt-v1/scope.cjs'),proof=require('../ephemeral-attempt-v1/device-proof.cjs');
const {requireActive}=require('../ephemeral-attempt-v1/ephemeral-authorization.cjs');
const evidence=require('./open-evidence.cjs');const {need}=scope;
const route=/^\/drive\/open-observations\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/;
// Full request authentication and one-time evidence insert in the SAME transaction.
// No startup/migration/listener/key generation. JWT middleware required at explicit mount.
module.exports=function({pool}){
 need(pool&&typeof pool.connect==='function','OPEN_INGEST_POOL');
 async function accept(req){
  const match=req&&req.method==='POST'&&typeof req.originalUrl==='string'&&req.originalUrl.match(route);
  need(match&&req.user&&typeof req.user.email==='string','OPEN_INGEST_ROUTE_JWT');
  need(req.body&&Buffer.byteLength(proof.canonical(req.body))<=65536,'OPEN_INGEST_BOUND');
  const signed=JSON.parse(proof.canonical(req.body));
  const header=req.headers&&req.headers['x-bimchat-proof'];need(typeof header==='string'&&header.length<=12000,'OPEN_INGEST_PROOF');
  const envelope=JSON.parse(Buffer.from(header,'base64').toString('utf8'));const id=match[1];
  const c=await pool.connect();try{await c.query('BEGIN');
   const first=(await c.query('SELECT project_id FROM bimchat_direct_ownership.attempts WHERE id=$1',[id])).rows[0];need(first,'OPEN_INGEST_UNKNOWN');await scope.lock(c,first.project_id);
   const row=(await c.query('SELECT project_id,document FROM bimchat_direct_ownership.attempts WHERE id=$1 FOR UPDATE',[id])).rows[0];need(row&&row.project_id===first.project_id,'OPEN_INGEST_SCOPE');const h=row.document;
   need(h.id===id&&h.projectId===row.project_id&&h.enabled===true&&h.state==='armed'&&h.receiverEmail!==h.sourceEmail&&req.user.email===h.receiverEmail,'OPEN_INGEST_STATE_PRINCIPAL');
   if(h.ordinaryUserChanges===true)need(h.ordinaryClaim&&h.ordinaryClaim.generation===h.generation,'USER_CHANGE_NOT_CLAIMED');
   const now=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);need(Number.isSafeInteger(h.expiresAt)&&now<h.expiresAt,'OPEN_INGEST_EXPIRED');
   const auth=proof.verify(envelope,{email:req.user.email,method:req.method,path:req.originalUrl,body:signed},{email:h.receiverEmail,sessionId:h.receiverSession,deviceId:h.receiverDevice,publicJwk:h.receiverAgentPublicKey,publicKeyDigest:h.receiverPublicKeyDigest},h.reviewDigest,now);
   auth.reviewDigest=h.reviewDigest;auth.publicKeyDigest=h.receiverPublicKeyDigest;
   await requireActive(c,auth,h.projectId,h.centralPath,require('./controlled-cycle.cjs').enrollmentRole(h,'receiver'));
   const checked=evidence.verifyEnvelope(h,signed,now);need(checked.fingerprint===auth.publicKeyDigest&&signed.payload.expiresAt<=h.expiresAt,'OPEN_INGEST_LEASE_BOUND');
   const sequence=require('./controlled-cycle.cjs').leg(h)+1;const expectedSequence=h.ordinaryUserChanges===true?(h.observedHistory||[]).length+1:h.cycle?sequence:1;const prior=(await c.query('SELECT sequence FROM bimchat_direct_ownership.observations WHERE attempt_id=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1',[id,'receiver'])).rows;need((prior.length?prior[0].sequence:0)===expectedSequence-1,'OPEN_INGEST_ALREADY_OBSERVED');
   const used=await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[envelope.payload.nonce,h.reviewDigest,auth.email,auth.sessionId]);need(used.rowCount===1,'OPEN_INGEST_REPLAY');
   await c.query('INSERT INTO bimchat_direct_ownership.observations(attempt_id,role,sequence,payload,signature) VALUES($1,$2,$3,$4,$5)',[id,'receiver',expectedSequence,JSON.stringify(signed.payload),signed.signature]);
   if(h.ordinaryUserChanges===true){h.receiverPreparedGeneration=h.generation;await c.query('UPDATE bimchat_direct_ownership.attempts SET document= WHERE id=',[h.id,JSON.stringify(h)]);}
   // DB time checked again after all evidence/authorization work. Roll back late inserts.
   await requireActive(c,auth,h.projectId,h.centralPath,require('./controlled-cycle.cjs').enrollmentRole(h,'receiver'));const end=+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now);evidence.validate(signed.payload,h,end);need(end<h.expiresAt,'OPEN_INGEST_LATE');
   await c.query('COMMIT');return {accepted:true,generation:h.generation,sequence:expectedSequence,expiresAt:signed.payload.expiresAt};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 function mount(app,jwt){need(app&&typeof jwt==='function','OPEN_INGEST_JWT_REQUIRED');app.post('/drive/open-observations/:id',jwt,async(req,res)=>{try{const result=await accept(req);res.set('Cache-Control','no-store');res.json(result);}catch{res.status(423).json({code:'OPEN_OBSERVATION_STOP_NO_RETRY'});}});}
 return {accept,mount};
};
