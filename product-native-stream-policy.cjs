'use strict';
const protocol=require('./scoped-api-v11/direct/protocol.cjs');
const {reference}=require('./product-stream-users.cjs');
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
// Opt-in composition for a model with an established six-file baseline. Never
// infers a missing log baseline from a receiver's current local file.
module.exports=function(tables,model){
 const names=protocol.nativeNames(model);
 function pins(p){
  need(p&&Object.keys(p).sort().join(',')==='files,users'&&Array.isArray(p.files)&&p.files.length===6,'STREAM_NATIVE_PINS');
  p.files.forEach((f,i)=>need(f&&Object.keys(f).sort().join(',')==='length,name,sha256'&&f.name===names[i]&&Number.isSafeInteger(f.length)&&f.length>=0&&/^[A-F0-9]{64}$/.test(f.sha256),'STREAM_NATIVE_PIN'));
  reference(p.users);need(p.files[0].length===p.users.length&&p.files[0].sha256===p.users.sha256,'STREAM_USERS_PIN');return p;
 }
 async function valid(c,file,p){pins(p);await tables.known(c,file,p.users);return p;}
 async function append(c,file,a,b){need(await tables.prefix(c,file,a,b),'USERS_INDEX_CHANGED');}
 async function compatible(c,file,a,b){
  await valid(c,file,a);await valid(c,file,b);
  return a.files.slice(1).every((f,i)=>f.length===b.files[i+1].length&&f.sha256===b.files[i+1].sha256)&&!!await tables.merge(c,file,a.users,b.users);
 }
 async function next(c,file,head,body){
  await valid(c,file,head);
  need(body&&Object.keys(body).sort().join(',')==='epoch,patch,usersAfter,usersBefore','STREAM_OPERATION_FIELDS');
  const p=body.patch;protocol.validateNativeStream(p,model);need(p.Generation===body.epoch,'STREAM_EPOCH');
  const a=reference(body.usersBefore),b=reference(body.usersAfter);await append(c,file,a,b);
  need(p.Files[0].PreHash===a.sha256&&p.Files[0].PostHash===b.sha256&&p.Files[0].PreLength===a.length&&p.Files[0].PostLength===b.length,'STREAM_USERS_PATCH');
  await tables.merge(c,file,head.users,a);
  for(let i=1;i<6;i++)need(head.files[i].length===p.Files[i].PreLength&&head.files[i].sha256===p.Files[i].PreHash,'STREAM_PREIMAGE_DIVERGED');
  const merged=await tables.merge(c,file,head.users,b);
  return {files:p.Files.map((f,i)=>({name:names[i],length:i===0?merged.length:f.PostLength,sha256:i===0?merged.sha256:f.PostHash})),users:merged};
 }
 async function receipt(c,file,previous,actual,expected){
  await valid(c,file,previous);await valid(c,file,actual);await valid(c,file,expected);
  need(actual.files.slice(1).every((f,i)=>f.length===expected.files[i+1].length&&f.sha256===expected.files[i+1].sha256),'STREAM_RECEIPT_POSTIMAGE');
  const merged=await tables.merge(c,file,previous.users,expected.users);
  need(merged.length===actual.users.length&&merged.sha256===actual.users.sha256,'STREAM_RECEIPT_USERS');return actual;
 }
 return {pins,valid,compatible,append,next,receipt};
};
