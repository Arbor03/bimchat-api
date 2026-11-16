'use strict';
function reject(status, message) { const e = new Error(message); e.status = status; throw e; }
async function project(db, id, email) {
    const r = await db.query('SELECT p.*,pm.role AS member_role FROM projects p JOIN project_members pm ON pm.project_id=p.id WHERE p.id=$1 AND pm.user_email=$2 FOR SHARE OF p,pm',[id,email]);
    if (!r.rows.length) reject(403,'Not a member of this project');
    return r.rows[0];
}
async function namedProject(db, name, email, fileId) {
    let r;
    if (fileId != null && fileId !== 'project') {
        if (!/^\d+$/.test(String(fileId))) reject(400,'Invalid file ID');
        r = await db.query('SELECT p.id FROM projects p JOIN revit_files rf ON rf.project_id=p.id WHERE p.name=$1 AND rf.id=$2',[name,fileId]);
    } else r = await db.query('SELECT id FROM projects WHERE name=$1',[name]);
    if (r.rows.length !== 1) reject(409,'Project cannot be identified uniquely');
    return project(db,r.rows[0].id,email);
}
async function conversation(db,id,email) {
    const r = await db.query(
        `SELECT c.*,p.name AS project_name FROM conversations c
         JOIN projects p ON p.id=c.project_id
         JOIN project_members pm ON pm.project_id=c.project_id AND pm.user_email=$2
         JOIN conversation_members cm ON cm.conversation_id=c.id AND cm.user_email=$2
         WHERE c.id=$1 FOR SHARE OF c,pm,cm`,[id,email]);
    if (!r.rows.length) reject(403,'Current project and conversation membership required');
    return r.rows[0];
}
async function members(db,projectId,emails) {
    const r = await db.query('SELECT user_email FROM project_members WHERE project_id=$1 AND user_email=ANY($2::text[]) FOR SHARE',[projectId,emails]);
    if (new Set(r.rows.map(x=>x.user_email)).size !== new Set(emails).size)
        reject(403,'Every conversation member must be a current project member');
}
async function message(db,id,email) {
    const r = await db.query('SELECT * FROM messages WHERE id=$1 FOR SHARE',[id]);
    if (!r.rows.length) reject(404,'Message not found');
    const m = r.rows[0];
    if (m.conversation_id != null) await conversation(db,m.conversation_id,email);
    else {
        await namedProject(db,m.project_name,email,m.file_id);
        if (m.receiver && m.sender !== email && m.receiver !== email) reject(403,'Private message access denied');
    }
    return m;
}
async function taskContext(db,id,email,write=false) {
    const r = await db.query('SELECT * FROM tasks WHERE id=$1 '+(write?'FOR UPDATE':'FOR SHARE'),[id]);
    if (!r.rows.length) reject(404,'Task not found');
    const t=r.rows[0];
    let p;
    if (t.source_message_id) {
        const m=await message(db,t.source_message_id,email);
        if(m.conversation_id != null) {
            const c=await conversation(db,m.conversation_id,email);
            p=await project(db,c.project_id,email);
        } else p=await namedProject(db,m.project_name,email,m.file_id);
        if(t.project_name!==p.name) reject(409,'Task project mismatch');
        if(t.file_id != null && !(await db.query('SELECT 1 FROM revit_files WHERE id=$1 AND project_id=$2',[t.file_id,p.id])).rows.length)
            reject(409,'Task file does not belong to source project');
    } else p=await namedProject(db,t.project_name,email,t.file_id);
    return {task:t,project:p};
}
async function task(db,id,email) { return (await taskContext(db,id,email)).task; }
async function parent(db,record,email) {
    const count=[record.message_id,record.task_id,record.comment_id].filter(Boolean).length;
    if (count !== 1) reject(400,'Exactly one attachment parent is required');
    if (record.message_id) return message(db,record.message_id,email);
    if (record.task_id) return task(db,record.task_id,email);
    const r=await db.query('SELECT task_id FROM comments WHERE id=$1',[record.comment_id]);
    if (!r.rows.length) reject(404,'Comment not found');
    return task(db,r.rows[0].task_id,email);
}
function route(pool,action) {
    return async (req,res) => {
        let db;
        try {
            db=await pool.connect(); await db.query('BEGIN');
            const value=await action(db,req);
            await db.query('COMMIT');
            if (value && value.bytes) {
                res.set('Cache-Control','no-store');
                res.set('X-Content-Type-Options','nosniff');
                res.type('application/octet-stream');
                res.attachment(value.name); return res.send(value.bytes);
            }
            res.set('Cache-Control','no-store');
            return res.status(value?.httpStatus || 200).json(value?.json ?? value);
        } catch(e) {
            if(db) await db.query('ROLLBACK').catch(()=>{});
            return res.status(e.status || 500).json({error:e.status ? e.message : 'Request failed'});
        } finally { if(db) db.release(); }
    };
}
module.exports={reject,project,namedProject,conversation,members,message,task,taskContext,parent,route};
