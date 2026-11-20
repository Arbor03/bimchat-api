'use strict';
const {randomUUID}=require('node:crypto');
const priorities=['Low','Normal','High'],statuses=['Open','InProgress','Closed'];
function need(ok,message,status=400){if(!ok)throw Object.assign(new Error(message),{status});}
function planning(b){
 if(b.priority!==undefined)need(priorities.includes(b.priority),'Invalid priority');
 if(b.dueDate!=null&&b.dueDate!==''){
  need(typeof b.dueDate==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(b.dueDate),'Invalid due date');
  const d=new Date(b.dueDate+'T00:00:00Z');
  need(Number.isFinite(d.getTime())&&d.toISOString().slice(0,10)===b.dueDate,'Invalid due date');
 }
}
const scopedConversations=`SELECT c.* FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id
 WHERE c.project_id=$1 AND lower(cm.user_email)=lower($2)
 AND (c.level='project' OR (c.level='folder' AND c.folder_id=$3) OR (c.level='model' AND c.file_id=$4))`;
async function snapshot(db,model,email){
 const args=[model.project_id,email,model.folder_id,model.id];
 const members=(await db.query('SELECT pm.user_email AS email,u.full_name AS name FROM project_members pm LEFT JOIN users u ON u.email=pm.user_email WHERE pm.project_id=$1',[model.project_id])).rows;
 const chats=(await db.query(`WITH visible AS (${scopedConversations}) SELECT v.id,v.name,v.type,v.level AS scope,
 ARRAY(SELECT user_email FROM conversation_members WHERE conversation_id=v.id) AS members
 FROM visible v ORDER BY v.created_at DESC`,args)).rows;
 const messages=await readMessages(db,args);
 const tasks=(await db.query(`SELECT t.id,t.description,t.assignee,t.status,t.element_id,t.element_name,t.priority,to_char(t.due_date,'YYYY-MM-DD') AS due_date,
 (SELECT json_agg(json_build_object('author',c.author,'text',c.text,'time',c.created_at) ORDER BY c.created_at,c.id) FROM comments c WHERE c.task_id=t.id) AS comments
 FROM tasks t WHERE t.file_id=$1 ORDER BY t.created_at DESC,t.id`,[model.id])).rows;
 return {model,members,chats,messages,tasks};
}
async function readMessages(db,args,before){
 const bound=before?' AND v.id=$5 AND (created_at,id)<(SELECT created_at,id FROM messages WHERE id=$6 AND conversation_id=v.id)':'';
 return (await db.query(`WITH visible AS (${scopedConversations}) SELECT v.id AS conversation_id,m.id,m.sender,m.message,m.created_at,
 CASE WHEN m.file_id=$4 OR (m.file_id IS NULL AND v.file_id=$4) THEN m.element_id END AS element_id,m.element_name,
 (SELECT json_agg(json_build_object('id',a.id,'name',a.file_name)) FROM attachments a WHERE a.message_id=m.id) AS attachments
 FROM visible v CROSS JOIN LATERAL (SELECT * FROM messages WHERE conversation_id=v.id ${bound} ORDER BY created_at DESC,id DESC LIMIT 200) m
 ORDER BY m.created_at,m.id`,args)).rows;
}
async function command(db,m,email,b){
 const memberParams=[m.project_id,email,m.folder_id,m.id];
 const op=b.op;
 if(op==='history')return {messages:await readMessages(db,[...memberParams,b.conversation,b.before],true)};
 if(op==='taskCreate'){
  planning(b);
  need(typeof b.description==='string'&&b.description.trim()&&b.description.length<=16000,'Description required');
  need((await db.query('SELECT 1 FROM project_members WHERE project_id=$1 AND user_email=$2',[m.project_id,b.assignee])).rowCount,'Invalid assignee');
  let element=Number(b.elementId)||-1,name=b.elementName||'';
  if(b.sourceId){
   const src=(await db.query(`WITH v AS (${scopedConversations}) SELECT msg.element_id,msg.element_name,msg.file_id,v.file_id AS scope_file
    FROM messages msg JOIN v ON v.id=msg.conversation_id WHERE msg.id=$5`,[...memberParams,b.sourceId])).rows[0];
   need(src,'Message unavailable',404);
   element=(src.file_id===m.id||(!src.file_id&&src.scope_file===m.id))?src.element_id:-1;name=element>0?src.element_name:'';
  }
  const id=randomUUID();
  await db.query(`INSERT INTO tasks(id,project_name,file_id,description,assignee,created_by,priority,due_date,element_id,element_name,status,source_message_id)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'Open',$11)`,[id,m.project_name,m.id,b.description.trim(),b.assignee,email,b.priority||'Normal',b.dueDate||null,element||-1,name,b.sourceId||null]);
  await db.query('INSERT INTO notifications(id,type,message,created_by,task_id,project_name) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),'NewTask',email+' created a task: '+b.description.trim(),email,id,m.project_name]);
  return {id};
 }
 need(['taskChange','taskDelete','comment'].includes(op),'Unknown command');
 const current=(await db.query('SELECT id FROM tasks WHERE id=$1 AND file_id=$2 FOR UPDATE',[b.id,m.id])).rows[0];
 need(current,'Task unavailable',404);
 if(op==='taskChange'){
  planning(b);
  const fields=[],args=[b.id,m.id];
  for(const [key,column] of [['priority','priority'],['dueDate','due_date'],['status','status']]){
   if(!Object.hasOwn(b,key))continue;
   if(key==='status')need(statuses.includes(b[key]),'Invalid status');
   args.push(b[key]||null);fields.push(column+'=$'+args.length);
  }
  need(fields.length,'No changes');await db.query('UPDATE tasks SET '+fields.join(',')+' WHERE id=$1 AND file_id=$2',args);
 }else if(op==='taskDelete'){
  await db.query('DELETE FROM tasks WHERE id=$1 AND file_id=$2',[b.id,m.id]);
 }else{
  need(typeof b.text==='string'&&b.text.trim()&&b.text.length<=16000,'Comment required');
  await db.query('INSERT INTO comments(id,task_id,author,text) VALUES($1,$2,$3,$4)',[randomUUID(),b.id,email,b.text.trim()]);
 }
 return {id:b.id};
}
module.exports=function mount(app,pool,auth){
 app.get('/attachments/:id/content',auth,async(req,res)=>{
  try{
   const {rows}=await pool.query(`SELECT a.file_url FROM attachments a JOIN messages m ON m.id=a.message_id
    JOIN conversations c ON c.id=m.conversation_id
    JOIN conversation_members cm ON cm.conversation_id=c.id AND lower(cm.user_email)=lower($2)
    JOIN project_members pm ON pm.project_id=c.project_id AND lower(pm.user_email)=lower($2)
    WHERE a.id=$1`,[req.params.id,req.user.email]);
   if(!rows.length)return res.sendStatus(404);
   const url=new URL(rows[0].file_url);
   if(url.protocol!=='https:'||url.host!=='res.cloudinary.com'||url.username||url.password||!process.env.CLOUDINARY_CLOUD_NAME||!url.pathname.startsWith('/'+process.env.CLOUDINARY_CLOUD_NAME+'/'))return res.sendStatus(404);
   const remote=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(20000)});
   if(!remote.ok)return res.sendStatus(502);
   const chunks=[];let bytes=0;
   for await(const chunk of remote.body){bytes+=chunk.length;if(bytes>10*1024*1024)return res.sendStatus(413);chunks.push(chunk);}
   res.set({'Cache-Control':'no-store','Content-Type':'application/octet-stream','X-Content-Type-Options':'nosniff'}).send(Buffer.concat(chunks));
  }catch{res.sendStatus(502);}
 });
 async function handle(req,res){
  let db;
  try{
   const file=Number(req.params.fileId),email=req.user.email;
   need(Number.isSafeInteger(file)&&file>0,'Invalid model');
   db=await pool.connect();await db.query(req.method==='GET'?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');
   const model=(await db.query(`SELECT f.id,f.project_id,f.folder_id,f.file_name,p.name AS project_name,d.name AS folder_name FROM revit_files f
    JOIN projects p ON p.id=f.project_id JOIN project_members pm ON pm.project_id=p.id LEFT JOIN project_folders d ON d.id=f.folder_id
    WHERE f.id=$1 AND lower(pm.user_email)=lower($2)`,[file,email])).rows[0];
   need(model,'Model unavailable',404);
   const result=req.method==='GET'?await snapshot(db,model,email):await command(db,model,email,req.body);
   await db.query('COMMIT');res.set('Cache-Control','no-store').json(result);
  }catch(e){if(db)await db.query('ROLLBACK').catch(()=>{});res.status(e.status||500).json({error:e.status?e.message:'Panel request failed'});}
  finally{if(db)db.release();}
 }
 app.get('/revit-panel/:fileId',auth,handle);app.post('/revit-panel/:fileId',auth,handle);
};
module.exports.planning=planning;
