'use strict';
const crypto = require('node:crypto');
const { compile, pathKey } = require('./sync-policy.cjs');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const parent = path => path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
const below = (root, path) => root === '' || path === root || path.startsWith(root + '/');
const writesEnabled = () => process.env.BIMCHAT_ARCHIVE_WRITES === '1';
const requireWrites = () => check(writesEnabled(), 'DRIVE_ROLLOUT_REQUIRED', 503);
const idValue = value => { const id = Number(value); check(Number.isSafeInteger(id) && id > 0, 'INVALID_PROJECT', 400); return id; };
function check(ok, code, status = 409) { if (!ok) throw Object.assign(new Error(code), { code, status }); }
function nameValue(value) { check(typeof value === 'string' && value.length <= 120 && value === value.trim() && !/[\\/]/.test(value), 'INVALID_FOLDER_NAME', 400); try { pathKey(value); } catch { check(false, 'INVALID_FOLDER_NAME', 400); } return value.normalize('NFC'); }
function effective(folders, path, email, role) {
  if (role === 'BIM Manager') return 'edit';
  let access = 'edit'; // Preserve the existing project-member default unless explicitly restricted.
  for (const folder of folders.filter(f => below(pathKey(f.path), path)).sort((a,b)=>a.path.length-b.path.length)) {
    if (folder.restricted) access = 'none';
    const grant = folder.grants?.find(g => g.email === email);
    if (grant) access = grant.access;
  }
  return access;
}
async function member(c, project, email) {
  const row = (await c.query('SELECT role FROM project_members WHERE project_id=$1 AND user_email=$2', [project,email])).rows[0];
  check(row, 'FOLDER_ACCESS_DENIED', 403); return row.role;
}
async function snapshot(c, project, email, importPaths = true) {
  const role = await member(c, project, email);
  await c.query('INSERT INTO bimchat_archive.projects(project_id) VALUES($1) ON CONFLICT DO NOTHING', [project]);
  const state = (await c.query('SELECT * FROM bimchat_archive.projects WHERE project_id=$1 FOR UPDATE', [project])).rows[0];
  const files = (await c.query('SELECT id,relative_path,file_name,current_version,file_size,last_modified FROM cloud_files WHERE project_id=$1 ORDER BY id', [project])).rows;
  const folders = state.folders;
  let changed = false;
  const linkedFolders=(await c.query('SELECT id,parent_id,name FROM project_folders WHERE project_id=$1',[project])).rows;
  for(const linked of linkedFolders){
    let names=[nameValue(linked.name)],node=linked,seen=new Set([linked.id]);
    while(node.parent_id){node=linkedFolders.find(f=>f.id===node.parent_id);check(node&&!seen.has(node.id),'INVALID_MODEL_FOLDER_TREE');seen.add(node.id);names.unshift(nameValue(node.name));}
    const display=names.join('/'),existing=folders.find(f=>pathKey(f.path)===pathKey(display));
    if(existing){if(existing.kind!=='model'){existing.kind='model';changed=true;}}
    else {folders.push({id:crypto.randomUUID(),path:display,name:linked.name,kind:'model',grants:[],restricted:false});changed=true;}
  }
  if (importPaths) for (const file of files) {
    const display = file.relative_path.replace(/\\/g,'/').normalize('NFC'); pathKey(display);
    for (let path = parent(display); path; path = parent(path)) {
      if (!folders.some(f => pathKey(f.path) === pathKey(path))) {
        check(!state.retired_paths.some(old => below(old,pathKey(path))), 'RETIRED_PATH_CONFLICT');
        folders.push({id:crypto.randomUUID(),path,name:path.split('/').pop(),grants:[],restricted:false}); changed = true;
      }
    }
  }
  if (changed) { state.revision++; await c.query('UPDATE bimchat_archive.projects SET folders=$2,revision=$3 WHERE project_id=$1',[project,JSON.stringify(folders),state.revision]); }
  const policy = compile({folders,files,complete:true});
  return {project,email,role,state,folders,files,policy};
}
async function locked(pool, project, email, body) {
  project = idValue(project); const c = await pool.connect();
  try {
    await c.query('BEGIN'); await c.query("SET LOCAL lock_timeout='3s'");
    // Same lock as the existing catalog/Ownership writer fence, including upload confirmation.
    await c.query('SELECT pg_advisory_xact_lock(193729,$1)',[project]);
    const result = await body(c, await snapshot(c,project,email));
    await c.query('COMMIT'); return result;
  } catch(error) { await c.query('ROLLBACK').catch(()=>{}); throw error; } finally { c.release(); }
}
function folderFrom(s,id,version,manager = true) {
  check(!manager || s.role === 'BIM Manager','FOLDER_ACCESS_DENIED',403);
  check(Number.isSafeInteger(version) && version === s.state.revision,'FOLDER_CHANGED');
  const folder=s.folders.find(f=>f.id===id); check(folder,'FOLDER_NOT_FOUND',404); return folder;
}
function protectedFolder(s,folder) {
  const key=pathKey(folder.path);
  return s.policy.folderPolicy(folder.id)!=='optional' || s.folders.some(f=>below(key,pathKey(f.path))&&s.policy.folderPolicy(f.id)!=='optional');
}
async function save(c,s,action,folderId) {
  s.state.revision++;
  await c.query('UPDATE bimchat_archive.projects SET revision=$2,folders=$3,retired_paths=$4 WHERE project_id=$1',[s.project,s.state.revision,JSON.stringify(s.folders),JSON.stringify(s.state.retired_paths)]);
  await c.query('INSERT INTO bimchat_archive.audit(project_id,actor_email,action,folder_id,revision) VALUES($1,$2,$3,$4,$5)',[s.project,s.email,action,folderId,s.state.revision]);
  await c.query("SELECT pg_notify('bimchat_catalog_changed','changed')");
}
function visibleFolders(s) {
  return s.folders.filter(f=>effective(s.folders,pathKey(f.path),s.email,s.role)!=='none' || s.folders.some(child=>below(pathKey(f.path),pathKey(child.path))&&effective(s.folders,pathKey(child.path),s.email,s.role)!=='none'));
}
function planToken(s, preference) {
  return hash(JSON.stringify({email:s.email,role:s.role,revision:s.state.revision,files:s.files.map(f=>[f.id,f.relative_path,f.current_version,f.file_size,f.last_modified]),preferences:preference.preferences,preferenceRevision:preference.revision}));
}
async function deviceAuth(c, req, touch = true) {
  const id=req.get('X-BIMChat-Device'),secret=req.get('X-BIMChat-Device-Key');
  check(typeof id==='string'&&/^[a-f0-9-]{36}$/i.test(id)&&typeof secret==='string'&&secret.length===64,'DEVICE_ACCESS_DENIED',403);
  const d=(await c.query('SELECT * FROM bimchat_archive.devices WHERE id=$1 AND user_email=$2 AND NOT revoked',[id,req.user.email])).rows[0];
  check(d&&d.secret_hash===hash(secret),'DEVICE_ACCESS_DENIED',403);
  if(touch)await c.query('UPDATE bimchat_archive.devices SET last_seen=now() WHERE id=$1',[id]); return d;
}
module.exports=function archiveService({pool}) {
  async function list(project,email) { return locked(pool,project,email,async(c,s)=>{
    const members=(await c.query('SELECT user_email AS email,role FROM project_members WHERE project_id=$1 ORDER BY user_email',[s.project])).rows;
    const devices=(await c.query(`SELECT d.id,d.name,d.protocol,d.last_seen,dp.revision,dp.preferences,dp.applied_token,dp.status FROM bimchat_archive.devices d JOIN bimchat_archive.device_projects dp ON dp.device_id=d.id AND dp.project_id=$1 WHERE d.user_email=$2 AND NOT d.revoked ORDER BY d.name`,[s.project,email])).rows;
    const ready=writesEnabled();
    return {rootCapabilities:{create:ready&&s.role==='BIM Manager',reason:ready?undefined:'Drive update is being activated.'},members:s.role==='BIM Manager'?members:[],folders:visibleFolders(s).map(folder=>{
      const protectedFlag=protectedFolder(s,folder),ownAccess=effective(s.folders,pathKey(folder.path),email,s.role);
      return {...folder,grants:s.role==='BIM Manager'?folder.grants:[],version:s.state.revision,protected:protectedFlag,syncPolicy:s.policy.folderPolicy(folder.id),capabilities:{create:ready&&s.role==='BIM Manager'&&!protectedFlag,rename:ready&&s.role==='BIM Manager'&&!protectedFlag,delete:ready&&s.role==='BIM Manager'&&!protectedFlag,share:ready&&s.role==='BIM Manager'&&!protectedFlag,availability:ready&&ownAccess!=='none',reason:ready?undefined:'Drive update is being activated.'},devices:devices.map(d=>{
        const token=planToken(s,d),prefs=d.preferences||[];
        const local=prefs.map(p=>({...p,folder:s.folders.find(f=>f.id===String(p.folderId))})).filter(p=>p.folder&&below(pathKey(p.folder.path),pathKey(folder.path))).sort((a,b)=>b.folder.path.length-a.folder.path.length)[0];
        return {id:d.id,name:d.name,protocol:d.protocol,revision:d.revision,mode:s.policy.folderPolicy(folder.id)==='always-local'?'local':local?.mode||'local',inherited:!!local&&local.folder.id!==folder.id,status:Date.now()-new Date(d.last_seen).getTime()>120000?'offline':d.status==='conflict'?'conflict':d.status==='applied'&&d.applied_token===token?'applied':'pending'};
      })};})};
  }); }
  async function create(project,email,input) {return locked(pool,project,email,async(c,s)=>{
    requireWrites();
    check(s.role==='BIM Manager','FOLDER_ACCESS_DENIED',403);
    const name=nameValue(input.name),parentKey=pathKey(input.parentPath||'',true);
    const p=parentKey?s.folders.find(f=>pathKey(f.path)===parentKey):null;
    check(!parentKey||p,'FOLDER_NOT_FOUND',404); if(p){folderFrom(s,p.id,input.version);check(!protectedFolder(s,p),'FOLDER_PROTECTED');}
    const path=p?p.path+'/'+name:name; pathKey(path);
    check(!s.folders.some(f=>pathKey(f.path)===pathKey(path)),'FOLDER_CONFLICT');
    check(!s.state.retired_paths.some(old=>below(old,pathKey(path))),'FOLDER_RETIRED');
    check(!path.toLowerCase().split('/').some(part=>part.endsWith('_backup')),'FOLDER_PROTECTED');
    const folder={id:crypto.randomUUID(),path,name,grants:[],restricted:false};s.folders.push(folder);await save(c,s,'create',folder.id);return {path,id:folder.id};
  });}
  async function rename(project,email,id,input){return locked(pool,project,email,async(c,s)=>{
    requireWrites();
    const folder=folderFrom(s,id,input.version);check(!protectedFolder(s,folder),'FOLDER_PROTECTED');
    const name=nameValue(input.name),old=folder.path,oldKey=pathKey(old),next=parent(old)?parent(old)+'/'+name:name,newKey=pathKey(next);
    check(newKey!==oldKey,'FOLDER_CONFLICT');check(!name.toLowerCase().endsWith('_backup'),'FOLDER_PROTECTED');
    check(!s.folders.some(f=>!below(oldKey,pathKey(f.path))&&below(newKey,pathKey(f.path)))&&!s.state.retired_paths.some(p=>below(p,newKey)),'FOLDER_CONFLICT');
    // Real model/support content is excluded above; live ordinary file locks must also be clear.
    const locks=(await c.query('SELECT cf.relative_path FROM cloud_files cf JOIN file_locks fl ON fl.cloud_file_id=cf.id WHERE cf.project_id=$1',[s.project])).rows;
    check(!locks.some(f=>below(oldKey,pathKey(f.relative_path))),'FOLDER_SYNC_REQUIRED');
    for(const file of s.files.filter(f=>below(oldKey,pathKey(f.relative_path)))) await c.query('UPDATE cloud_files SET relative_path=$2 WHERE id=$1',[file.id,next+file.relative_path.replace(/\\/g,'/').slice(old.length)]);
    for(const f of s.folders.filter(f=>below(oldKey,pathKey(f.path)))){f.path=next+f.path.slice(old.length);f.name=f.path.split('/').pop();}
    s.state.retired_paths.push(oldKey);await save(c,s,'rename',id);return {path:next};
  });}
  async function remove(project,email,id,input){return locked(pool,project,email,async(c,s)=>{
    requireWrites();
    const folder=folderFrom(s,id,input.version),key=pathKey(folder.path);check(!protectedFolder(s,folder),'FOLDER_PROTECTED');
    check(!s.files.some(f=>below(key,pathKey(f.relative_path)))&&!s.folders.some(f=>f.id!==id&&below(key,pathKey(f.path))),'FOLDER_NOT_EMPTY');
    s.folders.splice(s.folders.indexOf(folder),1);s.state.retired_paths.push(key);await save(c,s,'delete',id);return {deleted:true,path:parent(folder.path)};
  });}
  async function access(project,email,id,input){return locked(pool,project,email,async(c,s)=>{
    requireWrites();
    const folder=folderFrom(s,id,input.version);check(!protectedFolder(s,folder),'FOLDER_PROTECTED');
    check(Array.isArray(input.grants)&&input.grants.length<=1000&&typeof input.restricted==='boolean','INVALID_GRANTS',400);
    const members=(await c.query('SELECT user_email,role FROM project_members WHERE project_id=$1',[s.project])).rows;
    const seen=new Set();for(const g of input.grants){check(typeof g.email==='string'&&!seen.has(g.email)&&['view','edit'].includes(g.access)&&members.some(m=>m.user_email===g.email&&m.role!=='BIM Manager'),'INVALID_GRANTS',400);seen.add(g.email);}
    folder.grants=input.grants.map(g=>({email:g.email,access:g.access}));folder.restricted=input.restricted;await save(c,s,'access',id);return {path:folder.path};
  });}
  async function preferences(project,email,id,input){return locked(pool,project,email,async(c,s)=>{
    requireWrites();
    const folder=folderFrom(s,id,input.folderVersion,false);check(effective(s.folders,pathKey(folder.path),email,s.role)!=='none','FOLDER_ACCESS_DENIED',403);
    check(Array.isArray(input.devices)&&input.devices.length>0&&input.devices.length<=50&&new Set(input.devices.map(d=>d.deviceId)).size===input.devices.length,'INVALID_DEVICES',400);
    for(const selected of input.devices){
      check(['local','online-only'].includes(selected.mode),'INVALID_MODE',400);check(selected.mode!=='online-only'||s.policy.folderPolicy(id)!=='always-local','MODEL_MUST_STAY_LOCAL');
      const device=(await c.query(`SELECT dp.* FROM bimchat_archive.device_projects dp JOIN bimchat_archive.devices d ON d.id=dp.device_id WHERE dp.project_id=$1 AND dp.device_id=$2 AND d.user_email=$3 AND NOT d.revoked FOR UPDATE OF dp`,[s.project,selected.deviceId,email])).rows[0];
      check(device,'DEVICE_ACCESS_DENIED',403);check(device.revision===selected.expectedRevision,'PREFERENCE_CHANGED');
      const prefs=device.preferences.filter(p=>String(p.folderId)!==id);prefs.push({folderId:id,mode:selected.mode});
      await c.query("UPDATE bimchat_archive.device_projects SET preferences=$3,revision=revision+1,status='pending' WHERE project_id=$1 AND device_id=$2",[s.project,selected.deviceId,JSON.stringify(prefs)]);
    }
    await c.query("SELECT pg_notify('bimchat_catalog_changed','changed')");return {path:folder.path,status:'pending'};
  });}
  async function register(email,input){
    check(typeof input.id==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(input.id)&&typeof input.name==='string'&&input.name.trim()&&input.name.length<=120&&input.protocol===1,'INVALID_DEVICE',400);
    const secret=crypto.randomBytes(32).toString('hex');
    const result=await pool.query('INSERT INTO bimchat_archive.devices(id,user_email,secret_hash,name,protocol) VALUES($1,$2,$3,$4,1) ON CONFLICT DO NOTHING RETURNING id',[input.id,email,hash(secret),input.name]);
    check(result.rowCount===1,'DEVICE_ALREADY_REGISTERED');return {id:input.id,secret};
  }
  async function plan(project,req){return locked(pool,project,req.user.email,async(c,s)=>{
    const device=await deviceAuth(c,req);await c.query('INSERT INTO bimchat_archive.device_projects(device_id,project_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[device.id,s.project]);
    const pref=(await c.query('SELECT * FROM bimchat_archive.device_projects WHERE device_id=$1 AND project_id=$2',[device.id,s.project])).rows[0],token=planToken(s,pref);
    await c.query('UPDATE bimchat_archive.device_projects SET offered_token=$3 WHERE device_id=$1 AND project_id=$2',[device.id,s.project,token]);
    const folders=visibleFolders(s).map(f=>({...f,grants:undefined,restricted:undefined,access:effective(s.folders,pathKey(f.path),s.email,s.role),syncPolicy:s.policy.folderPolicy(f.id)}));
    return {protocol:1,complete:true,token,folders,retiredPaths:s.state.retired_paths,preferences:pref.preferences,files:s.files.filter(f=>effective(s.folders,pathKey(f.relative_path),s.email,s.role)!=='none').map(f=>({id:f.id,path:f.relative_path,version:f.current_version,size:f.file_size,mode:s.policy.decision(f.relative_path,pref.preferences).mode,required:s.policy.decision(f.relative_path,pref.preferences).reason==='model-required',canWrite:effective(s.folders,pathKey(f.relative_path),s.email,s.role)==='edit'}))};
  });}
  async function acknowledge(project,req){return locked(pool,project,req.user.email,async(c,s)=>{
    const device=await deviceAuth(c,req),pref=(await c.query('SELECT * FROM bimchat_archive.device_projects WHERE device_id=$1 AND project_id=$2 FOR UPDATE',[device.id,s.project])).rows[0];
    check(pref&&req.body.token===pref.offered_token&&req.body.token===planToken(s,pref),'PLAN_CHANGED');check(['applied','conflict'].includes(req.body.status),'INVALID_STATUS',400);
    await c.query('UPDATE bimchat_archive.device_projects SET applied_token=$3,status=$4,applied_at=now() WHERE device_id=$1 AND project_id=$2',[device.id,s.project,req.body.token,req.body.status]);return {status:req.body.status};
  });}
  return {list,create,rename,remove,access,preferences,register,plan,acknowledge};
};
module.exports.effective=effective;
module.exports.snapshot=snapshot;
module.exports.member=member;
module.exports.check=check;
module.exports.hash=hash;
module.exports.deviceAuth=deviceAuth;
