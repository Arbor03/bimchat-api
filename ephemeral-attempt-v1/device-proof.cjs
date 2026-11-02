'use strict';
const crypto=require('node:crypto'),{need}=require('./scope.cjs');
function canonical(v){if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';if(v&&typeof v==='object')return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';return JSON.stringify(v);}
const hash=v=>crypto.createHash('sha256').update(canonical(v)).digest('hex').toUpperCase();
function verify(proof,request,participant,reviewDigest,now=Date.now()){
 const p=proof&&proof.payload;
 need(p&&Object.keys(p).sort().join('|')===['schema','email','session','device','method','path','bodyHash','nonce','at','reviewDigest'].sort().join('|'),'DEVICE_PROOF_FIELDS');
 need(p.schema===1&&p.email===request.email&&p.email===participant.email&&p.session===participant.sessionId&&p.device===participant.deviceId,'DEVICE_PROOF_IDENTITY');
 need(p.method===request.method&&p.path===request.path&&p.bodyHash===hash(request.body)&&p.reviewDigest===reviewDigest,'DEVICE_PROOF_REQUEST');
 need(Number.isSafeInteger(p.at)&&now>=p.at&&now-p.at<=10000&&/^[a-f0-9-]{36}$/i.test(p.nonce),'DEVICE_PROOF_FRESH');
 const key=crypto.createPublicKey({key:participant.publicJwk,format:'jwk'});
 need(!participant.publicJwk.d&&key.asymmetricKeyType==='rsa'&&key.asymmetricKeyDetails.modulusLength>=3072,'DEVICE_PROOF_KEY');
 need(crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex').toUpperCase()===participant.publicKeyDigest,'DEVICE_PROOF_KEY_PIN');
 const signature=Buffer.from(proof.signature||'','base64');need(signature.toString('base64')===proof.signature&&crypto.verify('RSA-SHA256',Buffer.from(canonical(p)),key,signature),'DEVICE_PROOF_SIGNATURE');
 return {email:p.email,sessionId:p.session,deviceId:p.device};
}
function resolver({pool,review,approvedDigest}){
 need(hash(review)===approvedDigest&&Array.isArray(review.participants),'DEVICE_REVIEW_PIN');
 // Freeze an independent snapshot; operator's later object mutation cannot alter trust.
 const snapshot=JSON.parse(canonical(review));
 return async req=>{
  const encoded=req.headers['x-bimchat-proof'];need(typeof encoded==='string'&&encoded.length<=12000,'DEVICE_PROOF_HEADER');
  const proof=JSON.parse(Buffer.from(encoded,'base64').toString('utf8'));const participant=snapshot.participants.find(p=>p.email===req.user.email&&p.deviceId===proof.payload.device);
  need(participant,'DEVICE_NOT_REVIEWED');
  const auth=verify(proof,{email:req.user.email,method:req.method,path:req.originalUrl,body:req.body},participant,approvedDigest);
  auth.reviewDigest=approvedDigest;auth.publicKeyDigest=participant.publicKeyDigest;
  const c=await pool.connect();try{await c.query('BEGIN');
   need((await c.query("SELECT 1 FROM isolated_revit_sessions WHERE email=$1 AND session_id=$2 AND device_id=$3 AND state='active' FOR SHARE",[auth.email,auth.sessionId,auth.deviceId])).rowCount===1,'DEVICE_SESSION');
   await require('./ephemeral-authorization.cjs').requireActive(c,auth,snapshot.projectId,snapshot.centralPath);
   const used=await c.query('INSERT INTO bimchat_direct_ownership.publication_request_nonces(nonce,review_digest,email,session_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING nonce',[proof.payload.nonce,approvedDigest,auth.email,auth.sessionId]);need(used.rowCount===1,'DEVICE_PROOF_REPLAY');
   await c.query('COMMIT');return auth;
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 };
}
module.exports={canonical,hash,verify,resolver};
