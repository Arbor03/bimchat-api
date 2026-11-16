'use strict';
// Isolated PostgreSQL + real HTTP/JWT. No .env, production startup, email or cloud storage.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const crypto=require('node:crypto'),express=require('express'),jwt=require('jsonwebtoken'),{Pool}=require('pg');
const base=path.resolve(__dirname,'../server'),source=fs.readFileSync(path.join(base,'index.js'),'utf8');
const database='product_test_'+crypto.randomBytes(6).toString('hex');
const config={host:'127.0.0.1',port:55439,user:'product_test',password:'IsolatedProductTest-2026',ssl:false,connectionTimeoutMillis:3000};
const admin=new Pool({...config,database:'postgres'});
let pool,server,created=false,checks=0;
const key='isolated-product-test-jwt-not-production';
async function main(){
    await admin.query('CREATE DATABASE '+database+' TEMPLATE template0'); created=true;
    pool=new Pool({...config,database});
    const errors=[];
    const init=source.slice(source.indexOf('async function initDB()'),source.indexOf('function authenticateToken('));
    await vm.runInNewContext(init+';initDB()', {pool,console:{log(){},error(...args){errors.push(args.map(String).join(' '));}}});
    assert.deepEqual(errors,[],'real candidate schema initialization');
    const authSource=source.slice(source.indexOf('function authenticateToken('),source.indexOf('// Optional synthetic-only'));
    const auth=vm.runInNewContext(authSource+';authenticateToken',{jwt,process:{env:{JWT_SECRET:key}}});
    const app=express(); app.use(express.json());
    // Keep the deployed writer-fence wrapper enabled while mounting the new routes.
    const fenced=require(path.join(base,'product-writer-fences.cjs'))({enabled:true,app,rawPool:pool});
    require(path.join(base,'collaborationRoutes'))(app,fenced,auth,require(path.join(base,'attachmentStorage')).createAttachmentStorage(true));
    assert.equal((source.match(/require\('\.\/collaborationRoutes'\)/g)||[]).length,1);
    assert.ok(!/app\.(get|post|put|delete)\('\/(tasks|comments|messages|conversations|attachments|notifications|users)\b/.test(source),'no legacy routes shadow secure handlers');
    server=app.listen(0,'127.0.0.1'); await new Promise(resolve=>server.once('listening',resolve));
    const origin='http://127.0.0.1:'+server.address().port;
    const tokens=Object.fromEntries(['manager','creator','assignee','member','outsider'].map(n=>[n,jwt.sign({email:n+'@example.invalid'},key,{expiresIn:'5m'})]));
    const send=async(method,url,body,who='manager')=>{
        const response=await fetch(origin+url,{method,headers:{'Content-Type':'application/json',...(who?{Authorization:'Bearer '+(tokens[who]||who)}:{})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(5000)});
        return {status:response.status,body:await response.json()};
    };
    const check=async(name,fn)=>{await fn();checks++;console.log('PASS '+name);};
    const expect=async(method,url,body,who,code)=>{const r=await send(method,url,body,who);assert.equal(r.status,code,JSON.stringify(r));return r.body;};
    for(const n of Object.keys(tokens)) await pool.query('INSERT INTO users(email,password_hash,full_name) VALUES($1,$2,$3)',[n+'@example.invalid','not-a-real-password',n]);
    for(const n of ['Alpha','Beta']) await pool.query('INSERT INTO projects(name) VALUES($1)',[n]);
    for(const n of ['manager','creator','assignee','member']) await pool.query('INSERT INTO project_members(project_id,user_email,role) VALUES(1,$1,$2)',[n+'@example.invalid',n==='manager'?'BIM Manager':'Specialist']);
    await pool.query("INSERT INTO project_members(project_id,user_email,role) VALUES(2,'outsider@example.invalid','BIM Manager')");
    await pool.query("INSERT INTO revit_files(project_id,file_name) VALUES(1,'alpha.rvt'),(2,'beta.rvt')");
    const task=async(id='task-one')=>(await pool.query('SELECT * FROM tasks WHERE id=$1',[id])).rows[0];
    await check('JWT required and invalid JWT rejected',async()=>{
        await expect('GET','/tasks/Alpha',undefined,null,401);await expect('GET','/tasks/Alpha',undefined,'invalid',403);
    });
    await check('create ignores forged author and returns stored task',async()=>{
        const r=await expect('POST','/tasks',{id:'task-one',project_name:'Alpha',description:'Wall',created_by:'outsider@example.invalid',assignee:'assignee@example.invalid',view_name:'Level 1',file_id:1},'creator',200);
        assert.equal(r.task.created_by,'creator@example.invalid');assert.equal(r.id,'task-one');
    });
    await check('outsider denied list/create/update/delete/comments/users/notifications',async()=>{
        for(const [method,url,b] of [['GET','/tasks/Alpha'],['POST','/tasks',{project_name:'Alpha',description:'attack'}],['PUT','/tasks/task-one',{status:'Closed'}],['DELETE','/tasks/task-one'],['GET','/comments/task-one'],['POST','/comments',{task_id:'task-one',text:'attack'}],['GET','/users/Alpha'],['GET','/notifications/Alpha'],['PUT','/notifications/read/Alpha']]) await expect(method,url,b,'outsider',403);
    });
    for(const who of ['manager','creator','assignee']) await check(who+' status-only preserves view and assignee',async()=>{
        const before=await task(); const r=await expect('PUT','/tasks/task-one',{status:before.status==='Open'?'Closed':'Open'},who,200);
        assert.equal(r.task.view_name,before.view_name);assert.equal(r.task.assignee,before.assignee);assert.equal((await task()).status,r.task.status);
    });
    await check('unrelated member cannot edit or delete',async()=>{
        await expect('PUT','/tasks/task-one',{status:'Closed'},'member',403);await expect('DELETE','/tasks/task-one',undefined,'member',403);
    });
    await check('invalid partial updates and missing task do not change data',async()=>{
        const before=await task();
        for(const body of [{},{status:'bad'},{status:null},{viewName:'a',view_name:'b'},{created_by:'intruder'},{assignee:22}]) await expect('PUT','/tasks/task-one',body,'manager',400);
        await expect('PUT','/tasks/missing',{status:'Closed'},'manager',404);assert.deepEqual(await task(),before);
    });
    await check('null and empty string clear fields explicitly; legacy viewName supported',async()=>{
        for(const value of [null,'']) {const r=await expect('PUT','/tasks/task-one',{view_name:value,assignee:value},'manager',200);assert.equal(r.task.view_name,value);assert.equal(r.task.assignee,value);}
        const r=await expect('PUT','/tasks/task-one',{viewName:'Restored',assignee:'assignee@example.invalid'},'manager',200);assert.equal(r.task.view_name,'Restored');
    });
    await check('cross-project file and assignee rejected',async()=>{
        await expect('POST','/tasks',{project_name:'Alpha',description:'bad',file_id:2},'manager',409);
        await expect('PUT','/tasks/task-one',{assignee:'outsider@example.invalid'},'manager',403);
    });
    await check('comments use authenticated author and actual task project',async()=>{
        await expect('POST','/comments',{id:'comment-one',task_id:'task-one',text:'Test',author:'outsider@example.invalid',project_name:'Beta'},'member',200);
        const rows=await expect('GET','/comments/task-one',undefined,'manager',200);assert.equal(rows[0].author,'member@example.invalid');
        assert.equal((await pool.query("SELECT project_name FROM notifications WHERE type='NewComment'")).rows[0].project_name,'Alpha');
    });
    await check('user list contains only current project members',async()=>{
        const rows=await expect('GET','/users/Alpha',undefined,'manager',200);assert.equal(rows.length,4);assert.ok(!rows.some(r=>r.email==='outsider@example.invalid'));
    });
    let dm,msg,privateTask;
    await check('private conversation creation and message send',async()=>{
        dm=(await expect('POST','/conversations',{project_id:1,type:'dm',members:['assignee@example.invalid']},'manager',200)).conversation_id;
        msg=(await expect('POST',`/conversations/${dm}/messages`,{message:'Private wall issue'},'manager',200)).id;
        privateTask=(await expect('POST','/tasks/from-message',{message_id:msg,assignee:'assignee@example.invalid'},'manager',200)).id;
        await expect('POST','/tasks/from-message',{message_id:msg,assignee:'outsider@example.invalid'},'manager',403);
    });
    await check('DM cannot leak through legacy messages, tasks, comments or notifications',async()=>{
        const tasks=await expect('GET','/tasks/Alpha',undefined,'member',200);assert.ok(!tasks.some(t=>t.id===privateTask));
        assert.deepEqual(await expect('GET','/messages/group/Alpha',undefined,'member',200),[]);
        await expect('GET',`/conversations/${dm}/messages`,undefined,'member',403);
        await expect('GET',`/comments/${privateTask}`,undefined,'member',403);
        await expect('PUT',`/tasks/${privateTask}`,{status:'Closed'},'member',403);
        const notices=await expect('GET','/notifications/Alpha',undefined,'member',200);assert.ok(!notices.some(n=>n.task_id===privateTask));
        await expect('PUT','/notifications/read/Alpha',undefined,'member',200);
        assert.equal((await pool.query('SELECT is_read FROM notifications WHERE task_id=$1',[privateTask])).rows[0].is_read,false);
    });
    let attachment;
    const upload=async(parent,who)=>{
        const form=new FormData();for(const [k,v] of Object.entries(parent))form.append(k,v);
        form.append('file',new Blob(['private bytes'],{type:'application/pdf'}),'private.pdf');
        const r=await fetch(origin+'/attachments/upload',{method:'POST',headers:{Authorization:'Bearer '+tokens[who]},body:form,signal:AbortSignal.timeout(5000)});
        return {status:r.status,body:await r.json()};
    };
    await check('private attachment authorization covers upload metadata and content',async()=>{
        let r=await upload({task_id:privateTask},'assignee');assert.equal(r.status,201,JSON.stringify(r));attachment=r.body.attachment;
        assert.ok(!attachment.cloudinary_public_id);assert.equal(attachment.file_url,origin+'/attachments/'+attachment.id+'/content');
        assert.equal((await upload({task_id:privateTask},'member')).status,403);
        await expect('GET','/attachments/'+attachment.id,undefined,'member',403);
        await expect('GET','/attachments/task/'+privateTask,undefined,'member',403);
        await expect('GET','/attachments/'+attachment.id+'/content',undefined,'member',403);
        const content=await fetch(attachment.file_url,{headers:{Authorization:'Bearer '+tokens.assignee}});assert.equal(content.status,200);assert.equal(await content.text(),'private bytes');assert.equal(content.headers.get('cache-control'),'no-store');
    });
    await check('revoked member with still-valid JWT loses every private access path',async()=>{
        await pool.query("DELETE FROM project_members WHERE project_id=1 AND user_email='assignee@example.invalid'");
        for(const url of ['/tasks/Alpha','/comments/'+privateTask,'/attachments/'+attachment.id,'/attachments/'+attachment.id+'/content',`/conversations/${dm}/messages`]) await expect('GET',url,undefined,'assignee',403);
        await expect('PUT','/tasks/task-one',{status:'Closed'},'assignee',403);
        await expect('DELETE','/attachments/'+attachment.id,undefined,'assignee',403);
        assert.equal((await upload({task_id:privateTask},'assignee')).status,403);
        await expect('GET',`/conversations/${dm}/messages`,undefined,'manager',200);
    });
    await check('failed notification write rolls back task creation',async()=>{
        await pool.query("CREATE FUNCTION fail_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$");
        await pool.query('CREATE TRIGGER fail_notice BEFORE INSERT ON notifications FOR EACH ROW EXECUTE FUNCTION fail_notice()');
        await expect('POST','/tasks',{id:'rollback-task',project_name:'Alpha',description:'rollback'},'creator',500);
        assert.equal(await task('rollback-task'),undefined);await pool.query('DROP TRIGGER fail_notice ON notifications');
    });
    await check('task delete blocks orphaned attachments; authorized empty task deletes',async()=>{
        await expect('DELETE','/tasks/'+privateTask,undefined,'manager',409);
        await expect('DELETE','/tasks/task-one',undefined,'creator',200);assert.equal(await task(),undefined);
        await expect('DELETE','/tasks/task-one',undefined,'creator',404);
    });
    await check('duplicate project names fail closed while conversation identity stays valid',async()=>{
        await pool.query("UPDATE projects SET name='Alpha' WHERE id=2");
        await expect('GET','/tasks/Alpha',undefined,'manager',409);
        await expect('GET',`/conversations/${dm}/messages`,undefined,'manager',200);
        await expect('PUT','/tasks/'+privateTask,{status:'Closed'},'manager',200);
    });
    console.log(JSON.stringify({passed:checks,database,storage:'in-memory',productionTouched:false}));
}
main().catch(e=>{console.error(e);process.exitCode=1;}).finally(async()=>{
    if(server) await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});
    if(pool) await pool.end();
    if(created && /^product_test_[a-f0-9]{12}$/.test(database)) await admin.query('DROP DATABASE '+database);
    await admin.end();
});
