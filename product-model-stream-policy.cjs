'use strict';
const crypto=require('node:crypto');
const protocol=require('./scoped-api-v11/direct/protocol.cjs');
const users=require('./product-user-table.cjs');
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
const names=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];
const sha=b=>crypto.createHash('sha256').update(b).digest('hex').toUpperCase();
function userBytes(text){need(typeof text==='string','USERS_BYTES_REQUIRED');const b=Buffer.from(text,'base64');need(b.toString('base64')===text,'USERS_ENCODING');users.decode(b);return b;}
function pins(value){
 need(value&&Object.keys(value).sort().join(',')==='files,users'&&Array.isArray(value.files)&&value.files.length===5,'STREAM_PINS');
 value.files.forEach((f,i)=>need(f&&Object.keys(f).sort().join(',')==='length,name,sha256'&&f.name===names[i]&&Number.isSafeInteger(f.length)&&f.length>=0&&/^[A-F0-9]{64}$/.test(f.sha256),'STREAM_PIN'));
 if(typeof value.users==='object'){const r=require('./product-stream-users.cjs').reference(value.users);need(value.files[0].length===r.length&&value.files[0].sha256===r.sha256,'STREAM_USERS_PIN');return value;}
 const u=userBytes(value.users);need(value.files[0].length===u.length&&value.files[0].sha256===sha(u),'STREAM_USERS_PIN');return value;
}
function equivalent(a,b){pins(a);pins(b);return a.files.slice(1).every((f,i)=>f.length===b.files[i+1].length&&f.sha256===b.files[i+1].sha256)&&users.reconcile(userBytes(a.users),userBytes(b.users))!=null;}
function advance(head,body){
 pins(head);need(body&&Object.keys(body).sort().join(',')==='epoch,patch,usersAfter,usersBefore','STREAM_OPERATION_FIELDS');
 const p=body.patch;protocol.validateStream(p);need(p.Generation===body.epoch,'STREAM_EPOCH');
 const before=userBytes(body.usersBefore),after=userBytes(body.usersAfter);users.appendOnly(before,after);
 need(p.Files[0].PreHash===sha(before)&&p.Files[0].PostHash===sha(after)&&p.Files[0].PreLength===before.length&&p.Files[0].PostLength===after.length,'STREAM_USERS_PATCH');
 // Check the users patch itself, not just the advertised digest.
 if(p.Schema!==2){const derived=Buffer.concat([before,Buffer.from(p.Files[0].Append)]);
 for(const span of p.Files[0].Overwrites){need(before.subarray(span.Offset,span.Offset+span.Before.length).equals(Buffer.from(span.Before)),'STREAM_USERS_PREIMAGE');Buffer.from(span.After).copy(derived,span.Offset);}
 need(derived.equals(after),'STREAM_USERS_POSTIMAGE');}
 users.reconcile(userBytes(head.users),before);
 for(let i=1;i<5;i++)need(head.files[i].length===p.Files[i].PreLength&&head.files[i].sha256===p.Files[i].PreHash,'STREAM_PREIMAGE_DIVERGED');
 const merged=users.reconcile(userBytes(head.users),after);
 return {files:p.Files.map((f,i)=>({name:names[i],length:i===0?merged.length:f.PostLength,sha256:i===0?sha(merged):f.PostHash})),users:merged.toString('base64')};
}
function receiptPins(previous,actual,expected){
 pins(previous);pins(actual);pins(expected);
 need(actual.files.slice(1).every((f,i)=>f.length===expected.files[i+1].length&&f.sha256===expected.files[i+1].sha256),'STREAM_RECEIPT_POSTIMAGE');
 // Prefix compatibility alone is insufficient: a receiver must retain its own
 // users AND include all incoming users, never acknowledge a shorter table.
 const merged=users.reconcile(userBytes(previous.users),userBytes(expected.users));
 need(merged.equals(userBytes(actual.users)),'STREAM_RECEIPT_USERS');
 return actual;
}
module.exports={pins,equivalent,advance,receiptPins,sha,userBytes};
// Reference-aware policy: caller's transaction and model scope are retained.
// The legacy schema-1 path is kept for old recorded operations only.
module.exports.stream=function(tables){
 async function valid(c,file,p){pins(p);if(typeof p.users==='object')await tables.known(c,file,p.users);return p;}
 async function compatible(c,file,a,b){if(typeof a.users!=='object'&&typeof b.users!=='object')return equivalent(a,b);await valid(c,file,a);await valid(c,file,b);return a.files.slice(1).every((f,i)=>f.length===b.files[i+1].length&&f.sha256===b.files[i+1].sha256)&&!!await tables.merge(c,file,a.users,b.users);}
 async function append(c,file,a,b){if(typeof a==='string'&&typeof b==='string')return users.appendOnly(userBytes(a),userBytes(b));need(await tables.prefix(c,file,a,b),'USERS_INDEX_CHANGED');}
 async function next(c,file,head,body){if(typeof body.usersBefore==='string')return advance(head,body);await valid(c,file,head);need(Object.keys(body).sort().join(',')==='epoch,patch,usersAfter,usersBefore','STREAM_OPERATION_FIELDS');const p=body.patch;protocol.validateStream(p);need((p.Schema===2||p.Schema===3)&&p.Generation===body.epoch,'STREAM_EPOCH');const a=body.usersBefore,b=body.usersAfter;await append(c,file,a,b);need(p.Files[0].PreHash===a.sha256&&p.Files[0].PostHash===b.sha256&&p.Files[0].PreLength===a.length&&p.Files[0].PostLength===b.length,'STREAM_USERS_PATCH');await tables.merge(c,file,head.users,a);for(let i=1;i<5;i++)need(head.files[i].length===p.Files[i].PreLength&&head.files[i].sha256===p.Files[i].PreHash,'STREAM_PREIMAGE_DIVERGED');const merged=await tables.merge(c,file,head.users,b);return {files:p.Files.map((f,i)=>({name:names[i],length:i===0?merged.length:f.PostLength,sha256:i===0?merged.sha256:f.PostHash})),users:merged};}
 async function receipt(c,file,previous,actual,expected){if(typeof actual.users==='string')return receiptPins(previous,actual,expected);await valid(c,file,previous);await valid(c,file,actual);await valid(c,file,expected);need(actual.files.slice(1).every((f,i)=>f.length===expected.files[i+1].length&&f.sha256===expected.files[i+1].sha256),'STREAM_RECEIPT_POSTIMAGE');const merged=await tables.merge(c,file,previous.users,expected.users);need(merged.length===actual.users.length&&merged.sha256===actual.users.sha256,'STREAM_RECEIPT_USERS');return actual;}
 return {valid,compatible,append,next,receipt};
};
