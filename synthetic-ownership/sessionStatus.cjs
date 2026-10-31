'use strict';
// Read-only adapter. Provider MUST verify expiry, exact user/session/experiment/generation,
// enabled synthetic experiment, project membership, and reviewed source/receiver assignment.
// Never manufacture active=true from a valid JWT alone. No provider default.
module.exports=function mountSessionStatus(app,authenticate,readVerifiedBinding){
 if(typeof authenticate!=='function'||typeof readVerifiedBinding!=='function')throw Error('VERIFIED_BINDING_PROVIDER_REQUIRED');
 app.get('/isolated-observation/experiments/:experiment/session',authenticate,async(req,res)=>{
  try{
   const sid=req.headers['x-bimchat-session'];const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
   if(!req.user||typeof req.user.email!=='string'||!uuid.test(sid||'')||!uuid.test(req.params.experiment))return res.status(403).json({error:'TEST_BINDING_REFUSED'});
   const b=await readVerifiedBinding({email:req.user.email,sessionId:sid,experimentId:req.params.experiment});
   if(!b||b.active!==true||b.email!==req.user.email||b.sessionId!==sid||b.experimentId!==req.params.experiment||!uuid.test(b.generation)||!['source','receiver'].includes(b.role))return res.status(403).json({error:'TEST_BINDING_REFUSED'});
   res.set('Cache-Control','no-store');return res.json({active:true,email:b.email,sessionId:b.sessionId,generation:b.generation,role:b.role});
  }catch{return res.status(503).json({error:'TEST_BINDING_UNAVAILABLE'});}
 });
};
