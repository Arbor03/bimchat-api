'use strict';
const {createHash,randomUUID,timingSafeEqual}=require('node:crypto');
const {createClient}=require('./worker-client.cjs');
const projectAccess=require('./project-access.cjs');

const ID=/^[1-9][0-9]{0,9}$/;
const ROUTE_PART=/^[A-Za-z0-9_-]{1,256}$/;
const INTERNAL_PATH='/internal/assistant/v1/dispatch';
const PREFIX='/ai/v1/projects/:projectId';
const TENANT='bimchat-assistant-test';
const TOKEN=/^[A-Za-z0-9_-]{43}$/;
const PILOT_PROJECT='BIM Link AI Pilot';
const PILOT_FILE='Pilot-A.rvt';
const LEGACY_WRITES=['revit_level_modify'];
const DOCUMENTATION_WRITES=['revit_view_create','revit_sheet_create','revit_viewport_place','revit_text_note_create'];

function mount({app,authenticateToken,pool,env=process.env,workerRequest}){
 if(env.BIMLINK_ASSISTANT_TEST!=='1')return false;
 if(typeof authenticateToken!=='function'||typeof pool?.query!=='function')throw Error('AI_TEST_GATEWAY_HOST_REQUIRED');
 const projects=JSON.parse(env.BIMLINK_ASSISTANT_TEST_PROJECTS_JSON||'[]');
 if(!Array.isArray(projects)||!projects.length||projects.some(id=>typeof id!=='string'||!ID.test(id)))
  throw Error('AI_TEST_PROJECT_SCOPE_REQUIRED');
 const production=env.RAILWAY_ENVIRONMENT_NAME==='production';
 const pilotFile=env.BIMLINK_ASSISTANT_PILOT_FILE_ID;
 if(production&&(!env.RAILWAY_SERVICE_ID||!env.RAILWAY_ENVIRONMENT_ID||
    env.RAILWAY_SERVICE_ID!==env.BIMLINK_ASSISTANT_GATEWAY_SERVICE_ID||
    env.RAILWAY_ENVIRONMENT_ID!==env.BIMLINK_ASSISTANT_GATEWAY_ENVIRONMENT_ID||
    projects.length!==1||typeof pilotFile!=='string'||!ID.test(pilotFile)))
  throw Error('AI_PILOT_GATEWAY_SCOPE_REQUIRED');
 const devices=JSON.parse(env.BIMLINK_ASSISTANT_TEST_DEVICES_JSON||'[]');
 if(!Array.isArray(devices)||devices.some(row=>!row||!projects.includes(row.projectId)||
    !ID.test(row.subject)||!ID.test(row.fileId)||typeof row.deviceId!=='string'||!row.deviceId||
    typeof row.allowWrite!=='boolean'||
    !/^[0-9a-f]{64}$/.test(row.tokenSha256)))throw Error('AI_TEST_DEVICE_CONFIGURATION_INVALID');
 if(production&&devices.some(row=>row.fileId!==pilotFile))throw Error('AI_PILOT_FILE_SCOPE_REQUIRED');
 const pilotFiles=new Map([[pilotFile,{name:PILOT_FILE,writeTools:LEGACY_WRITES}]]);
 const documentation=production&&env.BIMLINK_ASSISTANT_DOCUMENTATION_FILE_JSON
  ?JSON.parse(env.BIMLINK_ASSISTANT_DOCUMENTATION_FILE_JSON):null;
 if(documentation){
  const {fileId,fileName,subject,deviceId}=documentation;
  const existing=devices.find(row=>row.fileId===pilotFile&&row.subject===subject&&row.deviceId===deviceId&&row.allowWrite);
  if(typeof fileId!=='string'||!ID.test(fileId)||fileId===pilotFile||typeof fileName!=='string'||
     fileName.length>255||!/^.+\.rvt$/iu.test(fileName)||fileName.toLowerCase()===PILOT_FILE.toLowerCase()||!existing)
   throw Error('AI_PILOT_DOCUMENTATION_BINDING_INVALID');
  pilotFiles.set(fileId,{name:fileName,writeTools:DOCUMENTATION_WRITES});
  devices.push({...existing,fileId});
 }
 const request=workerRequest||createClient({url:env.BIMLINK_ASSISTANT_WORKER_URL,
  key:env.BIMLINK_ASSISTANT_GATEWAY_KEY,timeoutMs:15000});

 app.use(PREFIX,(req,res,next)=>{
  const trace=randomUUID();
  res.set('Cache-Control','no-store').set('X-Request-Id',trace);
  res.locals.assistantError=(status,code,message,retryable=false)=>
   res.status(status).json({error:{code,message,retryable,requestId:trace}});
  // Reuse the host's actual BIMChat JWT verification and normalize its two error responses.
  authenticateToken(req,{status:code=>({json:()=>res.locals.assistantError(
   401,'unauthenticated',code===401?'Sign in to BIMChat TEST.':'The BIMChat TEST login expired or is invalid.')})},next);
 },async(req,res)=>{
  const fail=res.locals.assistantError;
  const project=req.params.projectId;
  const route=req.path.split('/').filter(Boolean);
  if(!projects.includes(project))return fail(404,'not_found','The TEST AI project was not found.');
  if(!['GET','POST','PUT'].includes(req.method)||!route.length||route.some(part=>!ROUTE_PART.test(part)))
   return fail(404,'not_found','The AI route was not found.');
  if(!Number.isSafeInteger(req.user?.id)||typeof req.user.email!=='string')
   return fail(401,'unauthenticated','Sign in to BIMChat TEST.');
  const body=req.method==='GET'?req.query:req.body;
  if(body===null||typeof body!=='object'||Array.isArray(body))
   return fail(400,'invalid_request','Send a JSON object.');
  if(req.method==='GET'&&Object.entries(body).some(([key,value])=>
    !['cursor','sessionId'].includes(key)||typeof value!=='string'||!ROUTE_PART.test(value)))
   return fail(400,'invalid_request','Invalid query parameters.');
  const grant=req.get('X-BIMLink-Session-Grant')??null;
  if(grant!==null&&!TOKEN.test(grant))
   return fail(401,'invalid_session_grant','Register the current Revit session again.');

  try{
   if(!await projectAccess(pool,project,req.user.id,req.user.email))
    return fail(403,'forbidden','The account is not authorized for this project.');
   const registration=req.method==='POST'&&route.length===1&&route[0]==='revit-sessions';
   if(registration){
    const device=devices.find(row=>row.projectId===project&&row.subject===String(req.user.id)&&
     row.fileId===String(body.fileId)&&row.deviceId===body.deviceId);
    const proof=req.get('X-BIMLink-Device-Token');
    if(!device||!TOKEN.test(proof||'')||!timingSafeEqual(
     createHash('sha256').update(proof).digest(),Buffer.from(device.tokenSha256,'hex')))
     return fail(403,'device_not_enrolled','This device is not enrolled for this TEST model.');
   }
   const linked=production
    ?await pool.query(`SELECT f.id,f.file_name FROM revit_files f JOIN projects p ON p.id=f.project_id
       JOIN unnest($2::integer[],$4::text[]) AS approved(id,file_name)
         ON approved.id=f.id AND approved.file_name=lower(f.file_name)
       WHERE p.id=$1 AND p.name=$3`,
       [Number(project),Array.from(pilotFiles.keys(),Number),PILOT_PROJECT,
        Array.from(pilotFiles.values(),file=>file.name.toLowerCase())])
    :await pool.query('SELECT id,file_name FROM revit_files WHERE project_id=$1',[Number(project)]);
   // Only the HMAC-authenticated gateway supplies the live account/file/device grants.
   const accountDevices=devices.filter(device=>device.projectId===project&&device.subject===String(req.user.id));
   const files=Object.fromEntries(linked.rows.map(row=>[String(row.id),{
    name:String(row.file_name).slice(0,255),devices:Object.fromEntries(accountDevices
     .filter(device=>device.fileId===String(row.id)).map(device=>[device.deviceId,device.allowWrite])),
    ...(production?{writeTools:pilotFiles.get(String(row.id)).writeTools}:{})
   }]));
   if(production&&(!Object.keys(files).length||(registration&&!Object.hasOwn(files,String(body.fileId)))))
    return fail(403,'pilot_file_unavailable','The authorized pilot file is unavailable.');
   const upstream=await request('POST',INTERNAL_PATH,{method:req.method,route,body,files,grant},
    {subject:String(req.user.id),tenant:TENANT,project,permissions:['assistant.read']});
   if(![200,201,202,400,401,403,404,409,413,429,503].includes(upstream.status)||!upstream.data?.body)
    return fail(503,'assistant_unavailable','The TEST AI worker is not available.',true);
   if(upstream.data.sessionGrant&&req.method==='POST'&&req.path==='/revit-sessions'&&upstream.status===201)
    res.set('X-BIMLink-Session-Grant',upstream.data.sessionGrant);
   if(upstream.status>=400){
    const error=upstream.data.body.error;
    return fail(upstream.status,error.code,error.message,error.retryable);
   }
   return res.status(upstream.status).json(upstream.data.body);
  }catch{
   return fail(503,'assistant_unavailable','The TEST authorization service or AI worker is not available.',true);
  }
 });
 return true;
}
module.exports={mount};
