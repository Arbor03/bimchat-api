'use strict';
const fs=require('node:fs'),path=require('node:path');
const root=path.join(__dirname,'web/src/pages');
let dashboard=fs.readFileSync(path.join(root,'Dashboard.jsx'),'utf8');
const start=dashboard.indexOf('                                {attachmentsMap[m.id]?.map(att => (');
const end=dashboard.indexOf('                                ))}',start);
if(start<0||end<0)throw Error('Dashboard attachment markup changed');
dashboard="import ProtectedAttachment from '../components/ProtectedAttachment'\n"+dashboard.slice(0,start)+`                                {attachmentsMap[m.id]?.map(att => (
                                  <ProtectedAttachment key={att.id} attachment={att} api={API} token={token} />
                                ))}`+dashboard.slice(end+'                                ))}'.length);
fs.writeFileSync(path.join(root,'Dashboard.jsx'),dashboard);
let viewer=fs.readFileSync(path.join(root,'Viewer.jsx'),'utf8');
const vs=viewer.indexOf('                        {(attByMsg[m.id] || []).map(att => (');
const ve=viewer.indexOf('                        ))}',vs);
if(vs<0||ve<0)throw Error('Viewer attachment markup changed');
viewer="import ProtectedAttachment from '../components/ProtectedAttachment'\n"+viewer.slice(0,vs)+`                        {(attByMsg[m.id] || []).map(att => (
                          <ProtectedAttachment key={att.id} attachment={att} api={API} token={token} />
                        ))}`+viewer.slice(ve+'                        ))}'.length);
const helper=viewer.indexOf('  const isImageAtt = (att) =>'),next=viewer.indexOf('  const loadMissingAttachments',helper);
if(helper<0||next<0)throw Error('Viewer image helper changed');
viewer=viewer.slice(0,helper)+viewer.slice(next);
fs.writeFileSync(path.join(root,'Viewer.jsx'),viewer);
