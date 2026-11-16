'use strict';
// Local UI test service. Synthetic records only; no database, credentials or production requests.
const http=require('node:http');
const user={email:'reviewer@example.test',full_name:'Alex Morgan',role:'BIM Manager'};
const folders=[{id:1,name:'Architecture',parent_id:null},{id:2,name:'Structure',parent_id:null},{id:3,name:'MEP',parent_id:null},{id:4,name:'Building A',parent_id:1}];
const files=Array.from({length:20},(_,i)=>({id:100+i,file_name:`Building ${String.fromCharCode(65+i%4)} — ${['Architecture','Structure','MEP'][i%3]} ${Math.floor(i/4)+1}.rvt`,folder_id:i%3+1,linked_by:'Alex Morgan',linked_at:'2026-11-15T10:00:00Z',frag_status:i===19?'pending':'ready'}));
const project={id:9001,name:'Park Residences · UI test',description:'Synthetic project for checking the new web interface.',status:'Active',created_at:'2026-11-01T10:00:00Z',deadline:'2027-03-01',members:[{...user,user_email:user.email},{user_email:'engineer@example.test',full_name:'Sam Taylor',role:'Structural'}],files};
const tasks=[{id:'ui-task-1',description:'Review ground floor circulation',assignee:'Alex Morgan',created_by:'Sam Taylor',status:'Open',created_at:'2026-11-15T10:00:00Z'},{id:'ui-task-2',description:'Coordinate the stair opening',assignee:'Sam Taylor',created_by:'Alex Morgan',status:'InProgress',created_at:'2026-11-14T10:00:00Z'},{id:'ui-task-3',description:'Confirm the entrance detail',assignee:'Alex Morgan',created_by:'Sam Taylor',status:'Closed',created_at:'2026-11-13T10:00:00Z'}];
const archive=[['01 Models/Architecture/Building A.rvt',14000000],['01 Models/Structure/Building A.ifc',4300000],['02 Drawings/Ground floor.pdf',480000],['02 Drawings/Sections.pdf',390000],['03 Reports/Design report.pdf',240000],['04 Surveys/Site survey.dwg',2000000],['Readme.txt',245]].map(([relative_path,file_size],i)=>({id:200+i,relative_path,file_size,file_name:relative_path.split('/').pop(),current_version:3,updated_at:'2026-11-15T14:30:00Z'}));
const conversations=[{id:'ui-conv-1',type:'group',level:'project',name:'Project coordination',members:[user.email,'engineer@example.test']},{id:'ui-conv-2',type:'group',level:'model',file_id:100,name:'Building A review',members:[user.email,'engineer@example.test']}];
const messages=[{id:'ui-msg-1',sender:'engineer@example.test',sender_email:'engineer@example.test',author:'Sam Taylor',content:'Please review the ground floor circulation before our next coordination meeting.',message:'Please review the ground floor circulation before our next coordination meeting.',created_at:'2026-11-15T14:30:00Z'}];
const token=[Buffer.from(JSON.stringify({alg:'none',typ:'JWT'})).toString('base64url'),Buffer.from(JSON.stringify(user)).toString('base64url'),'ui-fixture-only'].join('.');
const server=http.createServer(async(req,res)=>{
 res.setHeader('Access-Control-Allow-Origin','http://127.0.0.1:5187');res.setHeader('Access-Control-Allow-Headers','Authorization, Content-Type');res.setHeader('Access-Control-Allow-Methods','GET, POST, PUT, DELETE, OPTIONS');res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
 const send=(data,status=200)=>{res.statusCode=status;res.end(JSON.stringify(data));};
 if(req.method==='OPTIONS')return send({});
 const url=new URL(req.url,'http://127.0.0.1:5517'),p=url.pathname;
 console.log(JSON.stringify({method:req.method,path:p,fixture:true}));
 if(p==='/auth/login')return send({token});
 if(p==='/auth/verify')return send({user});
 if(!req.headers.authorization)return send({error:'UI fixture sign-in required'},401);
 if(p==='/projects'&&req.method==='GET')return send([{...project,member_count:2,task_count:3,my_role:'BIM Manager'},{id:9002,name:'Community Hall · UI test',status:'Active',member_count:1,task_count:0,my_role:'BIM Manager'}]);
 if(p==='/projects/9001')return send(project);
 if(p==='/projects/9002')return send({...project,id:9002,name:'Community Hall · UI test',files:[]});
 if(p.endsWith('/folders')&&req.method==='GET')return send(p.includes('9002')?[]:folders);
 if(p.endsWith('/folders')&&req.method==='POST'){let body='';for await(const c of req)body+=c;const input=JSON.parse(body);const folder={id:folders.length+1,name:input.name,parent_id:input.parent_id};folders.push(folder);return send(folder,201);}
 if(p.startsWith('/tasks/'))return send(p.includes('Community')?[]:tasks);
 if(p.startsWith('/users/'))return send([user]);
 if(p==='/conversations')return send(conversations);
 if(p.endsWith('/messages'))return send(messages);
 if(p.startsWith('/attachments/'))return send([]);
 if(p==='/drive/files/9001')return send(archive);
 if(p==='/drive/files/9002')return send([]);
 if(p.endsWith('/versions'))return send([{id:1,version:3,file_size:480000,uploaded_at:'2026-11-15T14:30:00Z'},{id:2,version:2,file_size:450000,uploaded_at:'2026-11-12T09:00:00Z'}]);
 if(p.endsWith('/download-url'))return send({error:'Downloads are disabled in the local UI fixture'},409);
 return send({error:'Not available in the local UI fixture'},404);
});
server.listen(5517,'127.0.0.1',()=>console.log('UI fixture API ready at http://127.0.0.1:5517 (synthetic data only)'));
