'use strict';
// STAGED ONLY. Never log request/response bodies, headers, exception text or identifiers.
const stages=new Set(['request-entered','pool-connect','transaction-begin','database-target','authenticated-context','experiment-lock','window-gate','attestation-role-state','receipt-parse','reviewed-pins','receipt-pins','observed-freshness','stable-freshness','capture-span','attestation-insert','commit','committed']);
const state=new WeakMap();
for(const label of ['isolation-guard','route-dispatch','authentication','body-parser'])stages.add(label);
function stage(req,label){if(state.has(req)&&stages.has(label))state.set(req,label);}
function middleware(req,res,next){if(state.has(req)){next();return;}state.set(req,'request-entered');const start=process.hrtime.bigint();let emitted=false;
 function emit(outcome){if(emitted)return;emitted=true;const status=Number.isInteger(res.statusCode)&&res.statusCode>=100&&res.statusCode<=599?res.statusCode:0;
  console.log(JSON.stringify({kind:'ATTESTATION_DIAGNOSTIC',utc:new Date().toISOString(),stage:state.get(req)||'request-entered',status,outcome,elapsedMs:Math.min(3600000,Number((process.hrtime.bigint()-start)/1000000n))}));state.delete(req);}
 res.once('finish',()=>emit('finished'));res.once('close',()=>emit('closed'));next();
}
module.exports={stage,middleware};
