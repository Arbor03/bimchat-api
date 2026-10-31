'use strict';
// Dependency-injected integration seam only. No listener, migration, secrets or DB connection.
// No permissive default: real context/target providers must be reviewed against deployment.
module.exports=function mountReviewed({app,authenticateExistingToken,textParser,pool,canonical,validate,windowGate,expectedDatabase,verifyTarget,readVerifiedBinding,review}){
 if(!review||review.mode!=='synthetic-only'||review.deploymentPinned!==true||review.realModelsReachable!==false||typeof verifyTarget!=='function'||typeof readVerifiedBinding!=='function'||typeof authenticateExistingToken!=='function'||typeof textParser!=='function')throw Error('ONLINE_INTEGRATION_NOT_REVIEWED');
 const api=require('./admissionTransport.cjs').create({pool,canonical,validate,windowGate,expectedDatabase,verifyTarget});
 api.mount(app,authenticateExistingToken,textParser);
 require('./sessionStatus.cjs')(app,authenticateExistingToken,readVerifiedBinding);
 return api;
};
