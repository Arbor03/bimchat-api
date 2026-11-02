"use strict";
// Resolve only after successful worker exit, not merely after its success message.
// Timeout/error leaves the caller's committed storage reservation uncertain.
function run(create,{timeoutMs=300000}={}){return new Promise((resolve,reject)=>{let w,result,finished=false;const done=(error)=>{if(finished)return;finished=true;clearTimeout(timer);error?reject(error):resolve(result);};const timer=setTimeout(()=>{if(w)Promise.resolve(w.terminate()).catch(()=>{});done(Error('WORKER_TIMEOUT_UNCERTAIN'));},timeoutMs);try{w=create();w.on('message',m=>{if(result){done(Error('WORKER_MULTIPLE_RESULTS'));return;}result=m;});w.once('error',()=>done(Error('WORKER_ERROR_UNCERTAIN')));w.once('exit',code=>{if(code!==0||!result||result.ok!==true||typeof result.fragKey!=='string'||!result.fragKey)done(Error('WORKER_EXIT_UNCERTAIN'));else done();});}catch(e){done(Error('WORKER_START_FAILED'));}});}
module.exports={run};
