'use strict';
const crypto=require('node:crypto');
const channel='bimchat_catalog_changed';
// Invoke inside the transaction that makes a sealed file visible. NOTIFY is delivered on COMMIT.
async function publish(c){await c.query('SELECT pg_notify($1,$2)',[channel,'changed']);}
module.exports=function({pool,timeoutMs=20000}){
 let listener=null,connecting=null;const subscribers=new Set();
 function signal(error){for(const fn of [...subscribers])fn(error);}
 async function listen(){
  if(listener)return;if(connecting)return connecting;
  connecting=(async()=>{const c=await pool.connect();let failed=false;
   const error=()=>{if(failed)return;failed=true;if(listener===c)listener=null;signal(Error('CATALOG_NOTIFICATION_CONNECTION'));c.release(true);};
   c.on('error',error);c.on('end',error);c.on('notification',n=>{if(n.channel===channel)signal();});
   try{await c.query('LISTEN '+channel);if(failed)throw Error('CATALOG_NOTIFICATION_CONNECTION');listener=c;}
   catch(e){error();throw e;}
  })();try{await connecting;}finally{connecting=null;}
 }
 async function cursor(email){
  // Only metadata already visible to this account, never object keys or signed URLs.
  // Single statement snapshot includes deletions, renames and membership/folder changes.
  const result=await pool.query(`WITH visible AS (
   SELECT DISTINCT p.id,p.name FROM projects p LEFT JOIN users u ON u.id=p.created_by
   LEFT JOIN project_members pm ON pm.project_id=p.id AND pm.user_email=$1
   WHERE pm.user_email=$1 OR u.email=$1)
   SELECT COALESCE((SELECT jsonb_agg(v ORDER BY v.id) FROM visible v),'[]'::jsonb) AS projects,
   COALESCE((SELECT jsonb_agg(x ORDER BY x.id) FROM (SELECT f.id,f.project_id,f.parent_id,f.name FROM project_folders f JOIN visible v ON v.id=f.project_id) x),'[]'::jsonb) AS folders,
   COALESCE((SELECT jsonb_agg(x ORDER BY x.id) FROM (SELECT f.id,f.project_id,f.relative_path,f.current_version,l.locked_by FROM cloud_files f JOIN visible v ON v.id=f.project_id LEFT JOIN file_locks l ON l.cloud_file_id=f.id) x),'[]'::jsonb) AS files`,[email]);
  return crypto.createHash('sha256').update(JSON.stringify(result.rows[0])).digest('hex');
 }
 async function wait(email,after,abort){
  if(typeof email!=='string'||!email||!(after==null||/^[a-f0-9]{64}$/.test(after)))throw Error('CATALOG_NOTIFICATION_REQUEST');
  await listen();let dirty=false,failure=null,resolveWake,rejectWake,timer;
  const deadline=Date.now()+timeoutMs;
  const changed=e=>{dirty=true;if(e)failure=e;if(e&&rejectWake)rejectWake(e);else if(resolveWake)resolveWake();};
  const cancelled=()=>changed(Error('CATALOG_NOTIFICATION_CANCELLED'));
  subscribers.add(changed);abort?.addEventListener('abort',cancelled,{once:true});
  try{
   let current;
   for(;;){
    if(abort?.aborted)throw Error('CATALOG_NOTIFICATION_CANCELLED');if(failure)throw failure;
    dirty=false;current=await cursor(email);
    if(current!==after)return {cursor:current,changed:true};
    if(dirty)continue;
    if(Date.now()>=deadline)return {cursor:current,changed:false};
    await new Promise((resolve,reject)=>{resolveWake=resolve;rejectWake=reject;timer=setTimeout(resolve,Math.max(0,deadline-Date.now()));if(failure)reject(failure);else if(dirty)resolve();})
     .finally(()=>{clearTimeout(timer);resolveWake=null;rejectWake=null;});
    // Timeout renews the transport; it is not a request to rescan the Drive folder.
    if(!dirty&&Date.now()>=deadline)return {cursor:current,changed:false};
   }
  }finally{clearTimeout(timer);subscribers.delete(changed);abort?.removeEventListener('abort',cancelled);}
 }
 function mount(app,jwt){
  app.post('/drive/catalog/wait',jwt,async(req,res)=>{const abort=new AbortController();const close=()=>abort.abort();res.on('close',close);
   try{if(!req.body||Object.keys(req.body).join(',')!=='cursor')throw Error('CATALOG_NOTIFICATION_REQUEST');res.set('Cache-Control','no-store');res.json(await wait(req.user.email,req.body.cursor,abort.signal));}
   catch(e){if(!res.destroyed)res.status(503).json({code:'CATALOG_NOTIFICATION_UNAVAILABLE'});}finally{res.removeListener('close',close);}
  });
 }
 // Runs before routes; successful publication/structure responses are hints only.
 // The asynchronous seal worker additionally calls publish within its commit transaction.
 function middleware(req,res,next){
  const path=req.path||'',mutation=['POST','PUT','PATCH','DELETE'].includes(req.method);
  if(mutation&&(/^\/projects(?:\/|$)/.test(path)||/^\/drive\/files(?:\/|$)/.test(path))&&!path.endsWith('/upload-url')&&!path.endsWith('/heartbeat'))res.once('finish',()=>{
   if(req.user?.email&&!res.locals?.catalogDeferred&&res.statusCode>=200&&res.statusCode<300&&res.statusCode!==202)publish(pool).catch(()=>{signal(Error('CATALOG_NOTIFICATION_CONNECTION'));});
  });next();
 }
 return {wait,mount,middleware};
};
module.exports.publish=publish;
