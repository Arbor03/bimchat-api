'use strict';
const fs=require('node:fs'),fsp=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {Readable,Transform}=require('node:stream'),{pipeline}=require('node:stream/promises');
const need=(ok,code)=>{if(!ok)throw Error(code);};
// Independent product adapter. No import-time IO, fixed whole-object ceiling,
// buffering of whole R2 objects, credentials discovery, or uncertain PUT retry.
module.exports=function({client,bucket,HeadObjectCommand,GetObjectCommand,PutObjectCommand,temporaryRoot=os.tmpdir()}){
 async function consume(key,etag,destination){
  const response=await client.send(new GetObjectCommand({Bucket:bucket,Key:key,IfMatch:etag}));
  let length=0;const sha=crypto.createHash('sha256');
  try{need(response.ETag===etag&&Number.isSafeInteger(response.ContentLength)&&response.ContentLength>=0,'R2_ETAG_OR_SIZE');
   const meter=new Transform({transform(chunk,encoding,done){length+=chunk.length;if(!Number.isSafeInteger(length)||length>response.ContentLength)return done(Error('R2_LENGTH_CHANGED'));sha.update(chunk);done(null,chunk);}});
   if(destination)await pipeline(Readable.from(response.Body),meter,fs.createWriteStream(destination,{flags:'wx',mode:0o600}));
   else for await(const chunk of response.Body){length+=chunk.length;need(Number.isSafeInteger(length)&&length<=response.ContentLength,'R2_LENGTH_CHANGED');sha.update(chunk);}
   need(length===response.ContentLength,'R2_INCOMPLETE_BODY');return {size:length,sha256:sha.digest('hex').toUpperCase()};
  }finally{if(response.Body&&typeof response.Body.destroy==='function')response.Body.destroy();}
 }
 async function verify(pin){need(pin&&pin.provider==='r2'&&typeof pin.key==='string'&&typeof pin.etag==='string','R2_CONTENT_PIN_REQUIRED');const actual=await consume(pin.key,pin.etag);need(actual.size===pin.size&&actual.sha256===pin.sha256,'R2_CONTENT_CHANGED');return actual;}
 async function readVerified(pin){
  // Compatibility for small callers only; initial model verification calls
  // verify() and never this collecting interface except the user-name table.
  const folder=await fsp.mkdtemp(path.join(temporaryRoot,'bimchat-r2-read-')),file=path.join(folder,'content');
  try{const actual=await consume(pin.key,pin.etag,file);need(actual.size===pin.size&&actual.sha256===pin.sha256,'R2_CONTENT_CHANGED');return await fsp.readFile(file);}finally{await fsp.rm(file,{force:true});await fsp.rmdir(folder);}
 }
 async function seal(cap,reserve){need(cap&&Number.isSafeInteger(cap.project_id)&&cap.project_id>0&&typeof cap.object_key==='string'&&typeof reserve==='function','R2_SEAL_CONTEXT');
  const folder=await fsp.mkdtemp(path.join(temporaryRoot,'bimchat-r2-seal-')),file=path.join(folder,'content');let body;
  try{const head=await client.send(new HeadObjectCommand({Bucket:bucket,Key:cap.object_key}));const actual=await consume(cap.object_key,head.ETag,file);
   if(cap.expected)need(actual.size===cap.expected.size&&actual.sha256===cap.expected.sha256,'R2_EXPECTED_CONTENT_CHANGED');
   const key='direct-sealed/'+cap.project_id+'/'+crypto.randomUUID(),record={provider:'r2',key,...actual,sourceKey:cap.object_key,sourceEtag:head.ETag};
   need(await reserve(Object.freeze({...record}))===true,'R2_DURABLE_RESERVATION_REQUIRED');
   body=fs.createReadStream(file,{highWaterMark:65536});const result=await client.send(new PutObjectCommand({Bucket:bucket,Key:key,Body:body,ContentLength:actual.size,ContentType:'application/octet-stream',CacheControl:'no-store',IfNoneMatch:'*'}));
   const pin={...record,etag:result.ETag};await verify(pin);return {...pin,contentVerified:true,immutable:false};
  }finally{if(body){body.destroy();await new Promise(resolve=>{if(body.closed)return resolve();body.once('close',resolve);});}await fsp.rm(file,{force:true});await fsp.rmdir(folder);}
 }
 async function withVerifiedStream(pin,work){
  const folder=await fsp.mkdtemp(path.join(temporaryRoot,'bimchat-r2-users-')),file=path.join(folder,'content');let input;
  try{const actual=await consume(pin.key,pin.etag,file);need(actual.size===pin.size&&actual.sha256===pin.sha256,'R2_CONTENT_CHANGED');input=fs.createReadStream(file,{highWaterMark:65536});return await work(input);}
  finally{if(input){input.destroy();if(!input.closed)await new Promise(resolve=>input.once('close',resolve));}await fsp.rm(file,{force:true});await fsp.rmdir(folder);}
 }
 return {seal,verify,readVerified,withVerifiedStream};
};
