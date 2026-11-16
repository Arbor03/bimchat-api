'use strict';
const crypto=require('node:crypto');
const access=require('./chatAccess');
module.exports=function registerChatRoutes(app,pool,auth) {
    const get=(url,fn)=>app.get(url,auth,access.route(pool,fn));
    const post=(url,fn)=>app.post(url,auth,access.route(pool,fn));
    const del=(url,fn)=>app.delete(url,auth,access.route(pool,fn));
    async function fileInProject(db,fileId,projectId) {
        if(fileId == null) return;
        if(!(await db.query('SELECT 1 FROM revit_files WHERE id=$1 AND project_id=$2',[fileId,projectId])).rows.length)
            access.reject(400,'File not in this project');
    }
    async function legacy(db,req,isPrivate) {
        await access.namedProject(db,req.params.projectName,req.user.email,req.query.fileId);
        const values=[req.params.projectName], filters=['project_name=$1','conversation_id IS NULL'];
        if(isPrivate) {
            values.push(req.user.email,req.params.otherUser);
            filters.push('((sender=$2 AND receiver=$3) OR (sender=$3 AND receiver=$2))');
        } else filters.push('receiver IS NULL');
        if(req.query.fileId==='project') filters.push('file_id IS NULL');
        else if(req.query.fileId) {values.push(req.query.fileId); filters.push('file_id=$'+values.length);}
        return (await db.query('SELECT * FROM messages WHERE '+filters.join(' AND ')+' ORDER BY created_at ASC LIMIT 100',values)).rows;
    }
    get('/messages/group/:projectName',(db,req)=>legacy(db,req,false));
    get('/messages/private/:projectName/:otherUser',(db,req)=>legacy(db,req,true));
    post('/messages',async(db,req)=>{
        const b=req.body;
        if(b.conversation_id != null) access.reject(400,'Use the conversation messages endpoint');
        const p=await access.namedProject(db,b.project_name,req.user.email,b.file_id);
        if(b.receiver) await access.members(db,p.id,[b.receiver]);
        if(typeof b.message!=='string'||!b.message.trim()) access.reject(400,'message is required');
        await db.query('INSERT INTO messages(id,project_name,sender,receiver,message,element_id,element_name,file_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
            [b.id || crypto.randomUUID(),p.name,req.user.email,b.receiver || null,b.message,b.element_id || -1,b.element_name || null,b.file_id || null]);
        return {success:true};
    });
    get('/users/:projectName',async(db,req)=>{
        const p=await access.namedProject(db,req.params.projectName,req.user.email);
        return (await db.query('SELECT u.email,u.full_name,u.role FROM users u JOIN project_members pm ON pm.user_email=u.email WHERE pm.project_id=$1 ORDER BY u.full_name',[p.id])).rows;
    });
    post('/conversations',async(db,req)=>{
        const b=req.body, me=req.user.email;
        const p=await access.project(db,b.project_id,me);
        if(b.members != null && (!Array.isArray(b.members)||b.members.some(x=>typeof x!=='string'||!x.trim())))
            access.reject(400,'members must be an array of email addresses');
        const emails=[...new Set([me,...(b.members || []).map(x=>x.trim().toLowerCase())])];
        await access.members(db,p.id,emails);
        const type=b.type==='dm'?'dm':'group';
        const level=['project','folder','model'].includes(b.level)?b.level:'project';
        let folder=null,file=null;
        if(level==='folder') {
            if(!(await db.query('SELECT 1 FROM project_folders WHERE id=$1 AND project_id=$2',[b.folder_id,p.id])).rows.length) access.reject(400,'Folder not in this project');
            folder=b.folder_id;
        }
        if(level==='model') {
            if(!b.file_id) access.reject(400,'file_id is required');
            await fileInProject(db,b.file_id,p.id); file=b.file_id;
        }
        if(type==='dm') {
            if(emails.length!==2) access.reject(400,'A DM needs exactly one other member');
            const found=await db.query(`SELECT c.* FROM conversations c
                WHERE c.project_id=$1 AND c.type='dm' AND c.level=$2
                AND c.folder_id IS NOT DISTINCT FROM $3::integer AND c.file_id IS NOT DISTINCT FROM $4::integer
                AND (SELECT count(*) FROM conversation_members cm WHERE cm.conversation_id=c.id)=2
                AND (SELECT count(*) FROM conversation_members cm WHERE cm.conversation_id=c.id AND cm.user_email=ANY($5::text[]))=2 LIMIT 1`,
                [p.id,level,folder,file,emails]);
            if(found.rows.length) return {success:true,conversation_id:found.rows[0].id,existed:true};
        } else if(typeof b.name!=='string'||!b.name.trim()) access.reject(400,'Group name is required');
        const c=(await db.query('INSERT INTO conversations(project_id,type,name,level,folder_id,file_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
            [p.id,type,type==='group'?b.name.trim():null,level,folder,file,me])).rows[0];
        for(const email of emails) await db.query('INSERT INTO conversation_members(conversation_id,user_email) VALUES($1,$2)',[c.id,email]);
        return {success:true,conversation_id:c.id,conversation:c};
    });
    get('/conversations',async(db,req)=>{
        await access.project(db,req.query.project_id,req.user.email);
        return (await db.query(`SELECT c.*,
            (SELECT array_agg(cm2.user_email) FROM conversation_members cm2
             JOIN project_members pm ON pm.project_id=c.project_id AND pm.user_email=cm2.user_email
             WHERE cm2.conversation_id=c.id) AS members,
            (SELECT max(created_at) FROM messages WHERE conversation_id=c.id) AS last_message_at
            FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id AND cm.user_email=$1
            WHERE c.project_id=$2 ORDER BY last_message_at DESC NULLS LAST,c.created_at DESC`,[req.user.email,req.query.project_id])).rows;
    });
    get('/conversations/:id/messages',async(db,req)=>{
        await access.conversation(db,req.params.id,req.user.email);
        return (await db.query('SELECT * FROM messages WHERE conversation_id=$1 ORDER BY created_at ASC LIMIT 200',[req.params.id])).rows;
    });
    post('/conversations/:id/messages',async(db,req)=>{
        const c=await access.conversation(db,req.params.id,req.user.email),b=req.body;
        if(typeof b.message!=='string'||!b.message.trim()) access.reject(400,'message is required');
        const file=b.file_id ?? c.file_id;
        await fileInProject(db,file,c.project_id);
        if(c.file_id && file!==c.file_id) access.reject(400,'File does not match conversation');
        const id=crypto.randomUUID();
        await db.query('INSERT INTO messages(id,project_name,sender,receiver,message,element_id,element_name,file_id,conversation_id) VALUES($1,$2,$3,NULL,$4,$5,$6,$7,$8)',
            [id,c.project_name,req.user.email,b.message,b.element_id || -1,b.element_name || null,file,c.id]);
        return {success:true,id};
    });
    post('/conversations/:id/members',async(db,req)=>{
        const c=await access.conversation(db,req.params.id,req.user.email);
        if(c.type==='dm') access.reject(400,'DM participants cannot be added');
        if(typeof req.body.user_email!=='string'||!req.body.user_email.trim()) access.reject(400,'user_email is required');
        const email=req.body.user_email.trim().toLowerCase();
        await access.members(db,c.project_id,[email]);
        await db.query('INSERT INTO conversation_members(conversation_id,user_email) VALUES($1,$2) ON CONFLICT DO NOTHING',[c.id,email]);
        return {success:true};
    });
    del('/conversations/:id/members/:email',async(db,req)=>{
        const c=await access.conversation(db,req.params.id,req.user.email), target=req.params.email.toLowerCase();
        if(target!==req.user.email && c.created_by!==req.user.email) access.reject(403,'Only the creator can remove other members');
        await db.query('DELETE FROM conversation_members WHERE conversation_id=$1 AND user_email=$2',[c.id,target]);
        return {success:true};
    });
    post('/tasks/from-message',async(db,req)=>{
        const b=req.body,m=await access.message(db,b.message_id,req.user.email),id=crypto.randomUUID();
        if(b.status!=null&&!['Open','InProgress','Closed'].includes(b.status)) access.reject(400,'Invalid task status');
        if(b.assignee!=null&&typeof b.assignee!=='string') access.reject(400,'Invalid assignee');
        let p;
        if(m.conversation_id!=null) {
            const c=await access.conversation(db,m.conversation_id,req.user.email);
            p=await access.project(db,c.project_id,req.user.email);
        } else p=await access.namedProject(db,m.project_name,req.user.email,m.file_id);
        if(b.assignee) await access.members(db,p.id,[b.assignee]);
        await db.query('INSERT INTO tasks(id,project_name,description,assignee,created_by,element_id,element_name,view_name,status,file_id,source_message_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
            [id,m.project_name,m.message,b.assignee || null,req.user.email,m.element_id || -1,m.element_name || '', '',b.status || 'Open',m.file_id,b.message_id]);
        await db.query('INSERT INTO notifications(id,type,message,created_by,task_id,project_name) VALUES($1,$2,$3,$4,$5,$6)',
            [crypto.randomUUID(),'NewTask',req.user.email+' created a task from a message',req.user.email,id,m.project_name]);
        return {success:true,id};
    });
};
