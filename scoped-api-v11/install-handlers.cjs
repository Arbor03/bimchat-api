"use strict";
const scope=require('./scope.cjs');
// Explicit catalog of existing routes. Unknown future routes require coverage review.
function policy(method,url){
 if(method==='get'&&url==='/drive/files/:projectId')return {type:'list',list:true};
 if(method==='post'&&['/drive/files/upload-url','/drive/files/confirm-upload'].includes(url))return {type:'upload',legacyUpload:true};
 if(/^\/drive\/files\/:fileId(?:\/|$)/.test(url))return {type:'cloud',external:method==='delete',kind:'cloud-delete'};
 if(method!=='get'&&/^\/projects\/:id(?:\/|$)/.test(url))return {type:'project',external:method==='delete'&&url==='/projects/:id',kind:'project-delete'};
 if(method!=='get'&&/^\/folders\/:id$/.test(url))return {type:'folder'};
 if(method!=='get'&&/^\/revit-files\/:id(?:\/|$)/.test(url))return {type:'revit'};
 if(method==='post'&&/^\/web-export\/:fileId\//.test(url))return {type:'export',external:true,kind:'fragment-conversion'};
 return null;
}
async function resolve(c,req,p){let project,path=null;
 if(p.type==='upload'){project=Number(req.body.projectId);path=scope.path(req.body.relativePath);}
 else if(p.type==='list')project=Number(req.params.projectId);
 else if(p.type==='project')project=Number(req.params.id);
 else {const table=p.type==='cloud'?'cloud_files':p.type==='folder'?'project_folders':'revit_files';const id=req.params.fileId||req.params.id;const r=(await c.query('SELECT project_id'+(p.type==='cloud'?',relative_path':'')+' FROM '+table+' WHERE id=$1',[id])).rows[0];scope.need(r,'SCOPED_RESOURCE_NOT_FOUND');project=r.project_id;if(p.type==='cloud')path=scope.path(r.relative_path);}
 scope.need(Number.isSafeInteger(project)&&project>0,'SCOPED_PROJECT');scope.need(req.user&&typeof req.user.email==='string','SCOPED_AUTH');scope.need((await c.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2 FOR SHARE',[project,req.user.email])).rowCount===1,'SCOPED_MEMBER');
 if(p.legacyUpload){const rows=await scope.scopes(c,project);scope.need(!rows.some(s=>scope.blocked(s,project,path)),'SCOPED_CAPABILITY_ROUTE_REQUIRED');}
 if(p.kind==='cloud-delete'||p.kind==='project-delete'){
  const sealed=(await c.query(`SELECT 1 FROM cloud_files cf WHERE cf.project_id=$1
    AND ($2::text IS NULL OR cf.relative_path=$2)
    AND (cf.b2_key LIKE 'direct-sealed/%' OR EXISTS(SELECT 1 FROM file_versions fv WHERE fv.cloud_file_id=cf.id AND fv.b2_key LIKE 'direct-sealed/%')) LIMIT 1`,[project,path])).rowCount;
  scope.need(sealed===0,'SEALED_DELETE_REQUIRES_REVIEWED_RETENTION');
 }
 return {project,path};
}
function install(app,bridge){for(const method of ['get','post','put','patch','delete']){const original=app[method].bind(app);app[method]=function(url,...handlers){const p=policy(method,url);if(p&&handlers.length){const last=handlers.pop();handlers.push(bridge.wrap(last,(c,req)=>resolve(c,req,p),p));}return original(url,...handlers);};}}
module.exports={install,policy,resolve};
