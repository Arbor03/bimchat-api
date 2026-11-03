'use strict';
// Streaming wire format shared with OwnershipByteDelta.Write: each record is
// LE uint64 offset, uint32 before length, uint32 after length, before, after.
// A record is at most 64 KiB of changed bytes; the operation has no size cap.
// Output is PRIVATE staging, never a live model or authoritative committed object.
const crypto=require('node:crypto');
const block=65536;
function need(ok,code){if(!ok)throw Error(code);}
async function exact(file,size,position){const bytes=Buffer.alloc(size);let at=0;while(at<size){const r=await file.read(bytes,at,size-at,position+at);need(r.bytesRead>0,'STREAM_DELTA_TRUNCATED');at+=r.bytesRead;}return bytes;}
async function write(file,bytes,position){let at=0;while(at<bytes.length){const r=await file.write(bytes,at,bytes.length-at,position+at);need(r.bytesWritten>0,'STREAM_DELTA_WRITE');at+=r.bytesWritten;}}
async function hash(file,length){const sha=crypto.createHash('sha256');for(let at=0;at<length;at+=block)sha.update(await exact(file,Math.min(block,length-at),at));return sha.digest('hex').toUpperCase();}
async function apply({before,delta,output,preLength,postLength,preHash,postHash,records}){
 need([preLength,postLength,records].every(n=>Number.isSafeInteger(n)&&n>=0),'STREAM_DELTA_METADATA');
 need(/^[0-9A-F]{64}$/.test(preHash)&&/^[0-9A-F]{64}$/.test(postHash),'STREAM_DELTA_METADATA');
 const a=await before.stat(),b=await delta.stat(),c=await output.stat();
 need(c.size===0&&!(a.dev===c.dev&&a.ino===c.ino)&&!(b.dev===c.dev&&b.ino===c.ino),'STREAM_DELTA_PRIVATE_OUTPUT');
 need(a.size===preLength&&await hash(before,preLength)===preHash,'STREAM_DELTA_PREIMAGE');
 for(let at=0;at<Math.min(preLength,postLength);at+=block)await write(output,await exact(before,Math.min(block,Math.min(preLength,postLength)-at),at),at);
 let wire=0,end=0,appendEnd=preLength,changed=0;
 for(let index=0;index<records;index++){
  const header=await exact(delta,16,wire);wire+=16;
  const wide=header.readBigUInt64LE(0);need(wide<=BigInt(Number.MAX_SAFE_INTEGER),'STREAM_DELTA_OFFSET');
  const offset=Number(wide),oldLength=header.readUInt32LE(8),newLength=header.readUInt32LE(12);
  need(newLength>0&&newLength<=block&&offset>=end&&offset<=postLength-newLength&&oldLength===Math.min(newLength,Math.max(0,preLength-offset)),'STREAM_DELTA_RANGE');
  // Growth may not introduce unspecified holes; only contiguous append data.
  if(offset+newLength>preLength){need(Math.max(offset,preLength)===appendEnd,'STREAM_DELTA_APPEND_GAP');appendEnd=offset+newLength;}
  const old=await exact(delta,oldLength,wire);wire+=oldLength;
  const next=await exact(delta,newLength,wire);wire+=newLength;
  if(oldLength)need(old.equals(await exact(before,oldLength,offset)),'STREAM_DELTA_RANGE_PREIMAGE');
  for(let i=0;i<oldLength;i++)need(old[i]!==next[i],'STREAM_DELTA_UNCHANGED_BYTE');
  await write(output,next,offset);end=offset+newLength;changed+=newLength;
 }
 need(wire===b.size&&appendEnd===Math.max(preLength,postLength),'STREAM_DELTA_LENGTH');
 await output.truncate(postLength);await output.sync();
 need(await hash(output,postLength)===postHash,'STREAM_DELTA_POSTIMAGE');
 return {records,changedBytes:changed,wireBytes:wire,length:postLength,sha256:postHash};
}
module.exports={apply,hash};
