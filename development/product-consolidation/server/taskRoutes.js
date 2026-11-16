'use strict';
const crypto=require('node:crypto');
const access=require('./chatAccess');
const has=(b,k)=>Object.prototype.hasOwnProperty.call(b,k);
const statuses=['Open','InProgress','Closed'];
function body(req) {
    if(!req.body || typeof req.body!=='object' || Array.isArray(req.body)) access.reject(400,'A JSON object is required');
    return req.body;
}
function status(value) { if(!statuses.includes(value)) access.reject(400,'Invalid task status'); return value; }
function text(value,name,nullable=false) {
    if(nullable && value===null) return value;
    if(typeof value!=='string') access.reject(400,name+' must be a string');
    return value;
}
async function assignee(db,p,value) {
    text(value,'assignee',true);
    if(value) await access.members(db,p.id,[value]);
    return value;
}
function mayEdit(context,email) {
    const t=context.task, same=v=>typeof v==='string'&&v.toLowerCase()===email.toLowerCase();
    if(context.project.member_role!=='BIM Manager'&&!same(t.created_by)&&!same(t.assignee))
        access.reject(403,'Only the project BIM Manager, task creator or assignee can edit this task');
}
async function visible(db,rows,email) {
    const result=[];
    for(const row of rows) {
        try { await access.task(db,row.id,email); result.push(row); }
        catch(e) { if(![403,404,409].includes(e.status)) throw e; }
    }
    return result;
}
module.exports=function registerTaskRoutes(app,pool,auth) {
    const route=(method,path,fn)=>app[method](path,auth,access.route(pool,fn));
    route('get','/tasks/:projectName',async(db,req)=>{
        await access.namedProject(db,req.params.projectName,req.user.email,req.query.fileId);
        const values=[req.params.projectName]; let filter='';
        if(req.query.fileId==='project') filter=' AND file_id IS NULL';
        else if(req.query.fileId) { values.push(req.query.fileId); filter=' AND file_id=$2'; }
        return visible(db,(await db.query('SELECT * FROM tasks WHERE project_name=$1'+filter+' ORDER BY created_at ASC',values)).rows,req.user.email);
    });
    route('post','/tasks',async(db,req)=>{
        const b=body(req), p=await access.namedProject(db,b.project_name,req.user.email,b.file_id);
        const description=text(b.description,'description');
        if(!description.trim()) access.reject(400,'description is required');
        const assigned=await assignee(db,p,b.assignee??null), state=status(b.status??'Open');
        if(b.file_id==='project') access.reject(400,'Use null for a project task file');
        const id=b.id==null?crypto.randomUUID():text(b.id,'id');
        if(!id.trim()) access.reject(400,'id is required');
        const task=(await db.query(`INSERT INTO tasks(id,project_name,description,assignee,created_by,element_id,element_name,view_name,status,file_id)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
            [id,p.name,description,assigned,req.user.email,b.element_id??-1,b.element_name??'',b.view_name??'',state,b.file_id??null])).rows[0];
        await db.query('INSERT INTO notifications(id,type,message,created_by,task_id,project_name) VALUES($1,$2,$3,$4,$5,$6)',
            [crypto.randomUUID(),'NewTask',req.user.email+' created new task: '+description,req.user.email,id,p.name]);
        return {success:true,id,task};
    });
    route('put','/tasks/:id',async(db,req)=>{
        const b=body(req), allowed=['status','assignee','viewName','view_name'];
        if(!Object.keys(b).length||Object.keys(b).some(k=>!allowed.includes(k))||has(b,'viewName')&&has(b,'view_name'))
            access.reject(400,'Invalid task fields');
        const context=await access.taskContext(db,req.params.id,req.user.email,true);
        mayEdit(context,req.user.email);
        const update={};
        if(has(b,'status')) update.status=status(b.status);
        if(has(b,'assignee')) update.assignee=await assignee(db,context.project,b.assignee);
        for(const key of ['viewName','view_name']) if(has(b,key)) update.view_name=text(b[key],key,true);
        const fields=Object.keys(update), values=Object.values(update); values.push(req.params.id);
        const result=await db.query('UPDATE tasks SET '+fields.map((k,i)=>k+'=$'+(i+1)).join(', ')+' WHERE id=$'+values.length+' RETURNING *',values);
        if(!result.rows.length) access.reject(404,'Task not found');
        return {success:true,task:result.rows[0]};
    });
    route('delete','/tasks/:id',async(db,req)=>{
        const context=await access.taskContext(db,req.params.id,req.user.email,true); mayEdit(context,req.user.email);
        // External attachment cleanup needs a separate durable storage job. Never orphan objects silently.
        const attached=await db.query('SELECT 1 FROM attachments WHERE task_id=$1 OR comment_id IN (SELECT id FROM comments WHERE task_id=$1) LIMIT 1',[req.params.id]);
        if(attached.rows.length) access.reject(409,'Remove task and comment attachments before deleting this task');
        await db.query('DELETE FROM notifications WHERE task_id=$1',[req.params.id]);
        await db.query('DELETE FROM tasks WHERE id=$1',[req.params.id]); return {success:true};
    });
    route('get','/comments/:taskId',async(db,req)=>{
        await access.task(db,req.params.taskId,req.user.email);
        return (await db.query('SELECT * FROM comments WHERE task_id=$1 ORDER BY created_at ASC',[req.params.taskId])).rows;
    });
    route('post','/comments',async(db,req)=>{
        const b=body(req),t=await access.task(db,b.task_id,req.user.email),value=text(b.text,'text');
        if(!value.trim()) access.reject(400,'text is required');
        const id=b.id==null?crypto.randomUUID():text(b.id,'id');
        await db.query('INSERT INTO comments(id,task_id,author,text) VALUES($1,$2,$3,$4)',[id,t.id,req.user.email,value]);
        await db.query('INSERT INTO notifications(id,type,message,created_by,task_id,project_name) VALUES($1,$2,$3,$4,$5,$6)',
            [crypto.randomUUID(),'NewComment',req.user.email+' commented: '+value,req.user.email,t.id,t.project_name]);
        return {success:true};
    });
    route('get','/notifications/:projectName',async(db,req)=>{
        await access.namedProject(db,req.params.projectName,req.user.email);
        const rows=(await db.query('SELECT * FROM notifications WHERE project_name=$1 AND created_by!=$2 AND is_read=FALSE ORDER BY created_at DESC',[req.params.projectName,req.user.email])).rows;
        const result=[];
        for(const row of rows) {
            if(!row.task_id) continue;
            try { await access.task(db,row.task_id,req.user.email); result.push(row); }
            catch(e) { if(![403,404,409].includes(e.status)) throw e; }
        }
        return result;
    });
    route('put','/notifications/read/:projectName',async(db,req)=>{
        await access.namedProject(db,req.params.projectName,req.user.email);
        const rows=(await db.query('SELECT id,task_id FROM notifications WHERE project_name=$1 AND created_by!=$2 AND is_read=FALSE',[req.params.projectName,req.user.email])).rows;
        for(const row of rows) {
            if(!row.task_id) continue;
            try { await access.task(db,row.task_id,req.user.email); }
            catch(e) { if([403,404,409].includes(e.status)) continue; throw e; }
            await db.query('UPDATE notifications SET is_read=TRUE WHERE id=$1',[row.id]);
        }
        return {success:true};
    });
};
