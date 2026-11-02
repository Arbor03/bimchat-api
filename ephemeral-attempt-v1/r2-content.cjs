'use strict';
const crypto = require('node:crypto');
function need(value, code) { if (!value) throw new Error(code); }
const hash = body => crypto.createHash('sha256').update(body).digest('hex').toUpperCase();
// No credentials/environment discovery. Caller supplies an SDK client configured with
// maxAttempts:1. Uncertain PUT results must be reconciled, never automatically retried.
module.exports = function ({client,bucket,HeadObjectCommand,GetObjectCommand,PutObjectCommand,maxBytes=64*1024*1024}) {
  need(client && bucket && HeadObjectCommand && GetObjectCommand && PutObjectCommand,'R2_ADAPTER_REQUIRED');
  need(Number.isSafeInteger(maxBytes) && maxBytes>0,'R2_SIZE_LIMIT');
  async function read(key,etag,signal) {
    need(typeof key==='string' && key.length>0 && typeof etag==='string' && etag.length>0,'R2_READ_PIN_REQUIRED');
    const o=await client.send(new GetObjectCommand({Bucket:bucket,Key:key,IfMatch:etag}),signal?{abortSignal:signal}:undefined);
    try {
      need(o.ETag===etag && Number.isSafeInteger(o.ContentLength) && o.ContentLength>=0 && o.ContentLength<=maxBytes,'R2_ETAG_OR_SIZE');
      const chunks=[]; let size=0;
      for await (const chunk of o.Body) {need(!signal||!signal.aborted,'R2_DEADLINE');size+=chunk.length; need(size<=maxBytes,'R2_SIZE_BOUND'); chunks.push(Buffer.from(chunk));}
      need(size===o.ContentLength,'R2_INCOMPLETE_BODY'); return Buffer.concat(chunks);
    } finally { if (o.Body && typeof o.Body.destroy==='function') o.Body.destroy(); }
  }
  async function readVerified(pin,signal) {
    need(pin && pin.provider==='r2' && /^[A-F0-9]{64}$/.test(pin.sha256) && Number.isSafeInteger(pin.size) && pin.size>=0,'R2_CONTENT_PIN_REQUIRED');
    const body=await read(pin.key,pin.etag,signal);
    need(body.length===pin.size && hash(body)===pin.sha256,'R2_CONTENT_CHANGED'); return body;
  }
  // Reservation MUST durably record destination before network PUT. This leaves an
  // auditable orphan on SQL failure. No cleanup/delete or retry is performed here.
  async function seal(cap,reserve) {
    need(cap && Number.isSafeInteger(cap.project_id) && cap.project_id>0 && typeof cap.object_key==='string' && cap.object_key.length>0 && typeof reserve==='function','R2_SEAL_CONTEXT');
    let timer,controller;
    if(cap.deadline!==undefined){need(Number.isSafeInteger(cap.deadline)&&cap.deadline>Date.now()&&cap.deadline-Date.now()<=30000,'R2_DEADLINE');controller=new AbortController();timer=setTimeout(()=>controller.abort(),Math.max(1,cap.deadline-Date.now()));}
    const signal=controller&&controller.signal,check=()=>need(!signal||(!signal.aborted&&Date.now()<cap.deadline),'R2_DEADLINE');
    try{
    check();const head=await client.send(new HeadObjectCommand({Bucket:bucket,Key:cap.object_key}),signal?{abortSignal:signal}:undefined);
    const body=await read(cap.object_key,head.ETag,signal);check();
    // Reject mismatched initial native/catalog content before reserving or PUT.
    if(cap.expected)need(cap.expected.sha256===hash(body)&&cap.expected.size===body.length,'R2_EXPECTED_CONTENT_CHANGED');
    const key='direct-sealed/'+cap.project_id+'/'+crypto.randomUUID();
    const record={provider:'r2',key,sha256:hash(body),size:body.length,sourceKey:cap.object_key,sourceEtag:head.ETag};
    need(await reserve(Object.freeze({...record}))===true,'R2_DURABLE_RESERVATION_REQUIRED');
    check();const put=await client.send(new PutObjectCommand({Bucket:bucket,Key:key,Body:body,ContentLength:body.length,ContentType:'application/octet-stream',CacheControl:'no-store',IfNoneMatch:'*'}),signal?{abortSignal:signal}:undefined);
    const pin={...record,etag:put.ETag};
    await readVerified(pin,signal);check();
    // ETag is a conditional validator, NOT a version ID or SHA-256. This result
    // intentionally cannot satisfy v9's immutable/version contract.
    return {...pin,contentVerified:true,immutable:false};
    }finally{if(timer)clearTimeout(timer);}
  }
  return {seal,readVerified};
};
