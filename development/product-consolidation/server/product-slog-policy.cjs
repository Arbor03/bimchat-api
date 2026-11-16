'use strict';
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
const proof=require('./ephemeral-attempt-v1/device-proof.cjs');
const block=262144;
function pin(p){need(p&&Object.keys(p).sort().join(',')==='length,sha256'&&Number.isSafeInteger(p.length)&&p.length>=0&&/^[A-F0-9]{64}$/.test(p.sha256),'STREAM_SLOG_PIN');return p;}
function equal(a,b){pin(a);pin(b);return a.length===b.length&&a.sha256===b.sha256;}
function uuid(x){need(typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(x),'STREAM_SLOG_ID');return x;}
function generation(x){need(typeof x==='string'&&/^[1-9][0-9]*$/.test(x),'STREAM_SLOG_GENERATION');return x;}
function descriptor(b){
 need(b&&Object.keys(b).sort().join(',')==='after,appendHash,before,generation,requestId','STREAM_SLOG_UPLOAD');uuid(b.requestId);generation(b.generation);pin(b.before);pin(b.after);
 need(b.after.length>b.before.length&&/^[A-F0-9]{64}$/.test(b.appendHash),'STREAM_SLOG_APPEND_ONLY');return b;
}
function chunk(b,length){
 need(Number.isSafeInteger(b.index)&&b.index>=0&&b.index<Math.ceil(length/block)&&typeof b.bytes==='string'&&b.bytes.length<=349528,'STREAM_SLOG_CHUNK');
 const bytes=Buffer.from(b.bytes,'base64');need(bytes.toString('base64')===b.bytes&&bytes.length===Math.min(block,length-b.index*block),'STREAM_SLOG_CHUNK');return bytes;
}
function fields(b,names){need(b&&Object.keys(b).sort().join(',')===names.slice().sort().join(','),'STREAM_SLOG_FIELDS');}
module.exports={block,pin,equal,uuid,generation,descriptor,chunk,fields,digest:proof.hash};
