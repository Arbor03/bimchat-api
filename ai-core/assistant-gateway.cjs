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

const validId=value=>typeof value==='string'&&ID.test(value)&&Number(value)<=2147483647;
const validIdentity=row=>row&&validId(row.projectId)&&validId(row.subject)&&
 typeof row.deviceId==='string'&&row.deviceId.length>0&&row.deviceId.length<=256;

function deviceAccess(env){
 const enrolled=JSON.parse(env.BIMLINK_ASSISTANT_TEST_DEVICES_JSON||'[]');
 if(!Array.isArray(enrolled)||enrolled.some(row=>!validIdentity(row)||
    !(row.fileId===null||validId(row.fileId))||typeof row.allowWrite!=='boolean'||
    typeof row.tokenSha256!=='string'||!/^[0-9a-f]{64}$/.test(row.tokenSha256)))
  throw Error('AI_TEST_DEVICE_CONFIGURATION_INVALID');
 const explicit=JSON.parse(env.BIMLINK_ASSISTANT_DEVICE_FILE_GRANTS_JSON||'[]');
 if(!Array.isArray(explicit))throw Error('AI_TEST_FILE_GRANTS_INVALID');
 const devices=[...enrolled];
 for(const link of explicit){
  if(!validIdentity(link)||!validId(link.fileId)||
     !(link.credentialFileId===null||validId(link.credentialFileId))||typeof link.allowWrite!=='boolean')
   throw Error('AI_TEST_FILE_GRANTS_INVALID');
  const credential=enrolled.find(row=>row.projectId===link.projectId&&row.subject===link.subject&&
   row.deviceId===link.deviceId&&row.fileId===link.credentialFileId);
  if(!credential||link.allowWrite&&!credential.allowWrite)throw Error('AI_TEST_FILE_GRANTS_INVALID');
  devices.push({...credential,fileId:link.fileId,allowWrite:link.allowWrite});
 }
 const keys=devices.map(row=>JSON.stringify([row.projectId,row.subject,row.deviceId,row.fileId]));
 if(keys.length!==new Set(keys).size)throw Error('AI_TEST_DEVICE_CONFIGURATION_INVALID');
 return devices;
}

function mount({app,authenticateToken,pool,env=process.env,workerRequest}){
 if(env.BIMLINK_ASSISTANT_TEST!=='1')return false;
 if(typeof authenticateToken!=='function'||typeof pool?.query!=='function')throw Error('AI_TEST_GATEWAY_HOST_REQUIRED');
 const production=env.RAILWAY_ENVIRONMENT_NAME==='production';
 if(production&&(!env.RAILWAY_SERVICE_ID||!env.RAILWAY_ENVIRONMENT_ID||
    env.RAILWAY_SERVICE_ID!==env.BIMLINK_ASSISTANT_GATEWAY_SERVICE_ID||
    env.RAILWAY_ENVIRONMENT_ID!==env.BIMLINK_ASSISTANT_GATEWAY_ENVIRONMENT_ID))
  throw Error('AI_PILOT_GATEWAY_SCOPE_REQUIRED');
 const devices=deviceAccess(env);
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
  if(!validId(project)||!devices.some(device=>device.projectId===project))
   return fail(404,'not_found','The AI project was not found.');
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
   const accountDevices=devices.filter(device=>device.projectId===project&&device.subject===String(req.user.id));
   if(!accountDevices.length)return fail(403,'device_not_enrolled','The account has no enrolled Revit device for this project.');
   // An explicit file entry takes precedence over a project-wide device entry.
   function grantsFor(fileId){
    return new Map([...accountDevices.filter(device=>device.fileId===null),
     ...accountDevices.filter(device=>device.fileId===fileId)].map(device=>[device.deviceId,device]));
   }
   const registration=req.method==='POST'&&route.length===1&&route[0]==='revit-sessions';
   if(registration){
    const device=grantsFor(String(body.fileId)).get(body.deviceId);
    const proof=req.get('X-BIMLink-Device-Token');
    if(!device||!TOKEN.test(proof||'')||!timingSafeEqual(
     createHash('sha256').update(proof).digest(),Buffer.from(device.tokenSha256,'hex')))
     return fail(403,'device_not_enrolled','This device is not enrolled for this TEST model.');
   }
   const fileIds=accountDevices.some(device=>device.fileId===null)
    ?null:[...new Set(accountDevices.map(device=>Number(device.fileId)))];
   const linked=await pool.query(
    'SELECT id,file_name FROM revit_files WHERE project_id=$1 AND ($2::integer[] IS NULL OR id=ANY($2::integer[]))',
    [Number(project),fileIds]);
   // Only the HMAC-authenticated gateway supplies the live account/file/device grants.
   const files=Object.fromEntries(linked.rows.map(row=>[String(row.id),{
    name:String(row.file_name).slice(0,255),devices:Object.fromEntries(
     Array.from(grantsFor(String(row.id)).values(),device=>[device.deviceId,device.allowWrite]))
   }]));
   if(!Object.keys(files).length||(registration&&!Object.hasOwn(files,String(body.fileId))))
    return fail(403,'file_unavailable','The authorized Revit file is unavailable.');
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
