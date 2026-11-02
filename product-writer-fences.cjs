'use strict';
// Install before the normal API registers routes. The returned pool must replace
// the normal route handlers' pool so guard and mutation share one transaction.
// Import/disabled mode does not query or migrate a database.
const installed=new WeakSet();
module.exports=function({enabled=false,app,rawPool}){
 if(!enabled)return rawPool;
 if(!app||!rawPool||installed.has(app))throw Error('PRODUCT_WRITER_FENCES_HOST');
 const bridge=require('./scoped-api-v11/handler-bridge.cjs')(rawPool);
 require('./scoped-api-v11/install-handlers.cjs').install(app,bridge);
 installed.add(app);return bridge.pool;
};
