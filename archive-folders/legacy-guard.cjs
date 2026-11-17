'use strict';
const {effective,member,check,deviceAuth}=require('./service.cjs');
const {pathKey}=require('./sync-policy.cjs');
const below=(root,path)=>path===root||path.startsWith(root+'/');
async function state(c,project){return (await c.query('SELECT folders,retired_paths FROM bimchat_archive.projects WHERE project_id=$1',[project])).rows[0]||{folders:[],retired_paths:[]};}
async function authorize(c,req,policy,mapping){
  if(process.env.BIMCHAT_ARCHIVE_FOLDERS!=='1'||!['cloud','upload'].includes(policy.type))return;
  const role=await member(c,mapping.project,req.user.email),s=await state(c,mapping.project),key=pathKey(mapping.path);
  check(!s.retired_paths.some(old=>below(old,key)),'FOLDER_RETIRED',409);
  const permission=effective(s.folders,key,req.user.email,role);
  check(permission!=='none'&&(req.method==='GET'||permission==='edit'),'FOLDER_ACCESS_DENIED',403);
  if(policy.type==='upload'){
    const display=req.body.relativePath.replace(/\\/g,'/');
    check(req.body.fileName===display.split('/').pop(),'INVALID_FILE_NAME',400);
    if(req.body.b2Key&&!req.body.b2Key.startsWith('direct-upload/'))check(req.body.b2Key===`project-${mapping.project}/${req.body.relativePath.replace(/^\/+/, '')}`,'INVALID_STORAGE_KEY',403);
    const alias=(await c.query("SELECT relative_path FROM cloud_files WHERE project_id=$1 AND lower(replace(relative_path,chr(92),'/'))=$2",[mapping.project,key])).rows;
    check(alias.every(f=>f.relative_path===req.body.relativePath),'FOLDER_PATH_ALIAS');
    // A model/support tree cannot be introduced under document-specific ACLs:
    // existing native Ownership endpoints keep their existing project-level authorization.
    const model=/\.(rvt|rfa|ifc|ifczip|nwd|nwc|dwg|dgn|3dm|skp|pln|pla|rte|rft|frag)$/i.test(key)||key.split('/').some(p=>p.endsWith('_backup'));
    if(model)check(!s.folders.some(f=>below(pathKey(f.path),key)&&(f.restricted||f.grants?.length)),'MODEL_FOLDER_ACCESS_REQUIRES_COORDINATION');
    if(req.get('X-BIMChat-Device')){
      const d=await deviceAuth(c,req,false),pref=(await c.query('SELECT preferences FROM bimchat_archive.device_projects WHERE device_id=$1 AND project_id=$2',[d.id,mapping.project])).rows[0];
      if(!model&&pref){
        const catalog=(await c.query('SELECT relative_path FROM cloud_files WHERE project_id=$1',[mapping.project])).rows;
        const mandatory=s.folders.some(f=>f.kind==='model'&&below(pathKey(f.path),key))||catalog.some(f=>{const p=pathKey(f.relative_path),directory=p.includes('/')?p.slice(0,p.lastIndexOf('/')):'';return directory&&/\.(rvt|rfa|ifc|ifczip|nwd|nwc|dwg|dgn|3dm|skp|pln|pla|rte|rft|frag)$/.test(p)&&below(directory,key);});
        if(!mandatory){let chosen=null;for(const p of pref.preferences){const folder=s.folders.find(f=>f.id===String(p.folderId));if(folder&&below(pathKey(folder.path),key)&&(!chosen||folder.path.length>chosen.length))chosen={mode:p.mode,length:folder.path.length};}check(chosen?.mode!=='online-only','FOLDER_ONLINE_ONLY',409);}
      }
    }
  }
}
async function filter(c,project,email,files){
  if(process.env.BIMCHAT_ARCHIVE_FOLDERS!=='1')return files;
  const role=await member(c,project,email),s=await state(c,project);
  return files.filter(file=>effective(s.folders,pathKey(file.relative_path),email,role)!=='none');
}
module.exports={authorize,filter};
