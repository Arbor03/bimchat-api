'use strict';
const crypto=require('node:crypto'),{need}=require('./ephemeral-attempt-v1/scope.cjs');
const block=262144;
function reference(r){need(r&&Object.keys(r).sort().join(',')==='length,sha256'&&Number.isSafeInteger(r.length)&&r.length>0&&/^[A-F0-9]{64}$/.test(r.sha256),'USERS_REFERENCE');return r;}
module.exports=function({pool}){
 async function withClient(work){const c=await pool.connect();try{return await work(c);}finally{c.release();}}
 async function put(c,file,r,index,bytes){reference(r);need(Number.isSafeInteger(index)&&index>=0&&index<Math.ceil(r.length/block)&&Buffer.isBuffer(bytes)&&bytes.length===Math.min(block,r.length-index*block),'USERS_CHUNK');
  await c.query('INSERT INTO bimchat_direct_ownership.stream_user_tables(file_id,sha256,byte_length) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[file,r.sha256,r.length]);
  need((await c.query('SELECT byte_length FROM bimchat_direct_ownership.stream_user_tables WHERE file_id=$1 AND sha256=$2',[file,r.sha256])).rows[0]?.byte_length==r.length,'USERS_REFERENCE');
  await c.query('INSERT INTO bimchat_direct_ownership.stream_user_chunks(file_id,sha256,chunk_index,bytes) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[file,r.sha256,index,bytes]);
  const old=(await c.query('SELECT bytes FROM bimchat_direct_ownership.stream_user_chunks WHERE file_id=$1 AND sha256=$2 AND chunk_index=$3',[file,r.sha256,index])).rows[0];need(old?.bytes.equals(bytes),'USERS_CHUNK_CHANGED');return {stored:true,index};
 }
 async function known(c,file,r){reference(r);const row=(await c.query('SELECT byte_length,verified FROM bimchat_direct_ownership.stream_user_tables WHERE file_id=$1 AND sha256=$2',[file,r.sha256])).rows[0];need(row?.verified&&Number(row.byte_length)===r.length,'USERS_UNVERIFIED');return r;}
 async function chunk(c,file,r,index){const row=(await c.query('SELECT bytes FROM bimchat_direct_ownership.stream_user_chunks WHERE file_id=$1 AND sha256=$2 AND chunk_index=$3',[file,r.sha256,index])).rows[0];need(row&&row.bytes.length===Math.min(block,r.length-index*block),'USERS_INCOMPLETE');return row.bytes;}
 async function seal(c,file,r){reference(r);const row=(await c.query('SELECT byte_length,verified FROM bimchat_direct_ownership.stream_user_tables WHERE file_id=$1 AND sha256=$2 FOR UPDATE',[file,r.sha256])).rows[0];need(row&&Number(row.byte_length)===r.length,'USERS_REFERENCE');if(row.verified)return {verified:true};
  const hash=crypto.createHash('sha256');let remaining=0,name=[],terminated=false,ordinal=0;
  for(let index=0;index<Math.ceil(r.length/block);index++){const bytes=await chunk(c,file,r,index);hash.update(bytes);
   for(let offset=0;offset<bytes.length;offset++){
    const byte=bytes[offset];need(!terminated,'USERS_TRAILING_DATA');
    if(remaining===0){if(byte===0){terminated=true;continue;}remaining=byte*2;name=[];}
    else{name.push(byte);if(--remaining===0){const value=Buffer.from(name);for(let at=0;at<value.length;at+=2){const code=value.readUInt16LE(at);need(code>=32&&(code<0xD800||code>0xDFFF),'USERS_INVALID_OR_DUPLICATE');}
     await c.query('INSERT INTO bimchat_direct_ownership.stream_user_names(file_id,sha256,ordinal,name) VALUES($1,$2,$3,$4)',[file,r.sha256,ordinal++,value]);}}
   }
  }
  need(terminated&&remaining===0,'USERS_TERMINATOR');need(hash.digest('hex').toUpperCase()===r.sha256,'USERS_HASH');await c.query('UPDATE bimchat_direct_ownership.stream_user_tables SET verified=true WHERE file_id=$1 AND sha256=$2',[file,r.sha256]);return {verified:true};
 }
 async function prefix(c,file,a,b){await known(c,file,a);await known(c,file,b);if(a.length>b.length)return false;let remaining=a.length-1;for(let index=0;remaining>0;index++){const x=await chunk(c,file,a,index),y=await chunk(c,file,b,index),count=Math.min(block,remaining);if(!x.subarray(0,count).equals(y.subarray(0,count)))return false;remaining-=count;}return true;}
 async function merge(c,file,a,b){if(await prefix(c,file,a,b))return b;if(await prefix(c,file,b,a))return a;throw Error('USERS_INDEX_CONFLICT');}
 async function transaction(work){return withClient(async c=>{try{await c.query('BEGIN');const result=await work(c);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK');throw e;}});}
 return {reference,known,prefix,merge,put,seal,chunk,
  upload:(file,r,index,bytes)=>withClient(c=>put(c,file,r,index,bytes)),
  finish:(file,r)=>transaction(c=>seal(c,file,r)),
  get:(file,r,index)=>withClient(async c=>{await known(c,file,r);need(Number.isSafeInteger(index)&&index>=0&&index<Math.ceil(r.length/block),'USERS_CHUNK');return chunk(c,file,r,index);}),
  importStream:async(c,file,r,source)=>{let pending=Buffer.alloc(0),index=0;for await(const raw of source){let offset=0;while(offset<raw.length){const count=Math.min(block-pending.length,raw.length-offset);pending=Buffer.concat([pending,raw.subarray(offset,offset+count)]);offset+=count;if(pending.length===block){await put(c,file,r,index++,pending);pending=Buffer.alloc(0);}}}if(pending.length)await put(c,file,r,index,pending);return seal(c,file,r);}
 };
};
module.exports.reference=reference;
