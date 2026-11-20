'use strict';
const crypto=require('node:crypto');
const fail=code=>Object.assign(new Error(code),{code});
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');

function createClient({url,key,fetchImpl=fetch,timeoutMs=360000}) {
 let target;try{target=new URL(url);}catch{throw fail('AI_WORKER_URL_INVALID');}
 if(target.username||target.password||target.search||target.hash||target.pathname!=='/'||
    !(target.protocol==='https:'||(target.protocol==='http:'&&['127.0.0.1','[::1]'].includes(target.hostname))))throw fail('AI_WORKER_URL_INVALID');
 if(typeof key!=='string'||Buffer.byteLength(key)<32)throw fail('AI_WORKER_KEY_REQUIRED');
 return async function request(method,path,body,principal) {
  const bytes=Buffer.from(body===undefined?'':JSON.stringify(body));
  if(bytes.length>8*1024*1024)throw fail('AI_BODY_TOO_LARGE');
  const issued=String(Math.floor(Date.now()/1000)),nonce=crypto.randomUUID();
  const claims=Buffer.from(JSON.stringify({...principal,audience:'bimlink-ai-worker'})).toString('base64url');
  const message=['v1',method,path,issued,nonce,hash(bytes),claims].join('\n');
  const signature=crypto.createHmac('sha256',key).update(message).digest('hex');
  let response;
  try {
   response=await fetchImpl(new URL(path,target),{method,redirect:'error',signal:AbortSignal.timeout(timeoutMs),
    headers:{'Content-Type':'application/json','X-BIMLink-Issued':issued,'X-BIMLink-Nonce':nonce,'X-BIMLink-Claims':claims,'X-BIMLink-Signature':signature},
    ...(method==='GET'?{}:{body:bytes})});
   const reader=response.body.getReader();let length=0,chunks=[];
   try {for(;;){const {value,done}=await reader.read();if(done)break;length+=value.length;if(length>8*1024*1024)throw fail('AI_WORKER_RESPONSE_TOO_LARGE');chunks.push(Buffer.from(value));}}
   finally {await reader.cancel();}
   const responseBytes=Buffer.concat(chunks);
   const proof=crypto.createHmac('sha256',key).update(['v1',nonce,signature,String(response.status),hash(responseBytes)].join('\n')).digest('hex');
   const supplied=response.headers.get('X-BIMLink-Response-Signature')||'';
   if(!/^[0-9a-f]{64}$/.test(supplied)||!crypto.timingSafeEqual(Buffer.from(proof,'hex'),Buffer.from(supplied,'hex')))throw fail('AI_WORKER_RESPONSE_UNAUTHENTICATED');
   const data=JSON.parse(responseBytes.toString('utf8'));
   if(!data||typeof data!=='object'||Array.isArray(data))throw fail('AI_WORKER_RESPONSE_INVALID');
   return {status:response.status,data};
  } catch {throw fail('AI_WORKER_UNAVAILABLE');}
 };
}
module.exports={createClient};
