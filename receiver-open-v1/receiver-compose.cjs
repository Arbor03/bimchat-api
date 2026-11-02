'use strict';
// Explicit application wiring. Import has no effects. Caller must provide actual
// independent native/storage evidence verifiers; no default true-returning adapters.
module.exports=function({app,jwt,pool,review,approvedDigest,r2}){
 const routes=require('./receiver-signed-routes.cjs'); const verifyOpenReceiver=(c,h)=>require('../source-open-v1/open-evidence.cjs').readVerified(c,h); const verifyAppliedReceipt=async(c,h,body)=>require('./receiver-receipt.cjs').verify(h,body,+new Date((await c.query('SELECT clock_timestamp() now')).rows[0].now));
 const operations=require('./receiver-transactions.cjs')({pool,verifyOpenReceiver,verifyAppliedReceipt,r2});
 operations.pending=require('./receiver-pending.cjs')({pool,verifyPayload:require('./receiver-content-proof.cjs')({r2})});
 Object.assign(operations,require('./native-verification.cjs')({pool}));
 const resolve=routes.resolver({pool,review,approvedDigest});
 routes.mount(app,jwt,resolve,operations);
 return Object.freeze({operations});
};




