'use strict';
// Called only by an explicitly reviewed deploy. No auto-migration/seeding/account creation.
module.exports=function install({app,express,pool,authenticateToken,expectedDatabase,environmentId}){
 const providers=require('./providers.cjs').create({pool,expectedDatabase,environmentId});
 const protocol=require('./protocol.cjs');
 const api=require('./admissionTransport.cjs').create({pool,canonical:protocol.canonical,validate:protocol.validate,expectedDatabase,...providers});
 app.use('/isolated-observation',require('./diagnostic.cjs').middleware);
 api.mount(app,authenticateToken,express.text({type:'text/plain',limit:'1mb'}));
 require('./sessionStatus.cjs')(app,authenticateToken,providers.readVerifiedBinding);
 return api;
};
