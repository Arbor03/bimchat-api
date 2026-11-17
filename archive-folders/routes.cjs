'use strict';
module.exports=function mountArchive({app,pool,auth,enabled=false,ownershipEnabled=false}){
  if(!enabled)return;
  if(!ownershipEnabled)throw Error('ARCHIVE_REQUIRES_CATALOG_WRITER_FENCES');
  const service=require('./service.cjs')({pool});
  const route=fn=>async(req,res)=>{try{res.set('Cache-Control','no-store');res.json(await fn(req));}catch(error){const status=error.status||503;res.status(status).json({code:error.status?error.code:'ARCHIVE_UNAVAILABLE'});}};
  const prefix='/archive/projects/:projectId/folders';
  app.get(prefix,auth,route(req=>service.list(req.params.projectId,req.user.email)));
  app.post(prefix,auth,route(req=>service.create(req.params.projectId,req.user.email,req.body)));
  app.patch(prefix+'/:folderId',auth,route(req=>service.rename(req.params.projectId,req.user.email,req.params.folderId,req.body)));
  app.delete(prefix+'/:folderId',auth,route(req=>service.remove(req.params.projectId,req.user.email,req.params.folderId,req.body)));
  app.put(prefix+'/:folderId/access',auth,route(req=>service.access(req.params.projectId,req.user.email,req.params.folderId,req.body)));
  app.put(prefix+'/:folderId/sync-preferences',auth,route(req=>service.preferences(req.params.projectId,req.user.email,req.params.folderId,req.body)));
  app.post('/archive/devices/register',auth,route(req=>service.register(req.user.email,req.body)));
  app.post('/archive/drive/projects/:projectId/plan',auth,route(req=>service.plan(req.params.projectId,req)));
  app.post('/archive/drive/projects/:projectId/acknowledge',auth,route(req=>service.acknowledge(req.params.projectId,req)));
};
