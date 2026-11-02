"use strict";
const {AsyncLocalStorage}=require('node:async_hooks'),co=require('./coordinator.cjs'),scope=require('./scope.cjs');
// For existing JSON async handlers. Carries pool.query through the same transaction.
module.exports=function(raw){const context=new AsyncLocalStorage();const pool=new Proxy(raw,{get(target,key){const state=context.getStore(),c=state&&state.client;if(c&&(key==='query'||key==='connect'))scope.need(state.active,'SCOPED_HANDLER_ALREADY_FINISHED');if(key==='query'&&c)return c.query.bind(c);if(key==='connect'&&c)return ()=>{throw Error('SCOPED_NESTED_TRANSACTION_UNSUPPORTED');};const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value;}});
 function wrap(handler,resolve,{external=false,kind='storage',list=false}={}){return async(req,res)=>{let payload,status=200,sent=false;const buffered={status(n){status=n;return this;},json(p){scope.need(!sent,'SCOPED_DOUBLE_RESPONSE');sent=true;payload=p;return this;}};
 try{const run=async(c,m)=>{const state={client:c,active:true};try{return await context.run(state,async()=>{await handler(req,buffered);scope.need(sent&&status<400,'SCOPED_HANDLER_FAILED');if(list){const rows=await scope.scopes(c,m.project);scope.need(Array.isArray(payload),'SCOPED_LIST_SHAPE');payload=payload.filter(f=>!rows.some(s=>scope.blocked(s,m.project,f.relative_path)));}});}finally{state.active=false;}};
 const resolver=c=>resolve(c,req);if(list)await co.transaction(raw,async c=>{const m=await resolver(c);await scope.lock(c,m.project);await run(c,m);});else if(external)await co.external(raw,resolver,kind,run);else await co.guarded(raw,resolver,run);
 return res.status(status).json(payload);
 }catch(e){return res.status(e.status||423).json({code:'SCOPED_OPERATION_STOPPED'});}};}
 return {pool,wrap};
};
