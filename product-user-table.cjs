'use strict';
// Only the counted UTF-16 layout actually observed in the manual trials.
// Never rewrite or infer ownership indices when two tables disagree.
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
function decode(value){
 need(Buffer.isBuffer(value)&&value.length>0,'USERS_FORMAT_BOUND');
 const names=[];let at=0;
 while(at<value.length){const count=value[at++];if(count===0){need(at===value.length,'USERS_TRAILING_DATA');return names;}
  need(at+count*2<value.length,'USERS_TRUNCATED');const name=value.subarray(at,at+count*2).toString('utf16le');
  need(name.length===count&&!/[\u0000-\u001f\ud800-\udfff]/.test(name)&&!names.includes(name),'USERS_INVALID_OR_DUPLICATE');names.push(name);at+=count*2;
 }
 need(false,'USERS_TERMINATOR');
}
function prefix(a,b){return a.length<=b.length&&a.every((v,i)=>v===b[i]);}
function reconcile(local,incoming){
 const a=decode(local),b=decode(incoming);
 if(prefix(a,b))return Buffer.from(incoming);
 if(prefix(b,a))return Buffer.from(local); // preserve independently appended users and their indices
 need(false,'USERS_INDEX_CONFLICT');
}
function appendOnly(before,after){need(prefix(decode(before),decode(after)),'USERS_INDEX_CHANGED');}
module.exports={decode,reconcile,appendOnly};
