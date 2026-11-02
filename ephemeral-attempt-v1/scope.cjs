"use strict";
const need=(b,c)=>{if(!b)throw Object.assign(Error(c),{status:423});};
// Validate Windows or URL relative separators, but retain the exact stored spelling.
function path(p){need(typeof p==='string'&&p.length<=512,'SCOPE_PATH');const n=p.replace(/\\/g,'/');need(!n.startsWith('/')&&!n.includes(':')&&!/[\x00-\x1f]/.test(n)&&n.split('/').every(x=>x&&x!=='.'&&x!=='..'),'SCOPE_PATH');return p;}
function key(p){return path(p).replace(/\\/g,'/').toLowerCase();}
function equal(a,b){return key(a)===key(b);}
function unique(paths){need(new Set(paths.map(key)).size===paths.length,'SCOPE_PATH_ALIAS');return paths;}
function logical(p){need(typeof p==='string'&&/^[A-Za-z]:\\/.test(p)&&/\.rvt$/i.test(p),'LOGICAL_CENTRAL');path(p.slice(3).replace(/\\/g,'/'));return p;}
function group(central,candidate){const c=key(central),p=key(candidate);return p===c||p.startsWith(c.replace(/\.rvt$/i,'')+'_backup/');}
function overlap(a,b){return group(a,b)||group(b,a);}
function blocked(scope,project,relative){return scope.project_id===project&&!['staged','released'].includes(scope.state)&&(relative==null||group(scope.central_path,relative));}
async function lock(c,project){need(Number.isSafeInteger(project)&&project>0,'SCOPE_PROJECT');await c.query("SET LOCAL lock_timeout='3s'");await c.query('SELECT pg_advisory_xact_lock(193729,$1)',[project]);}
async function scopes(c,project){return (await c.query('SELECT * FROM bimchat_direct_ownership.scopes WHERE project_id=$1 ORDER BY id',[project])).rows;}
async function ordinary(c,project,relative){await lock(c,project);await require('./publication.cjs').blocked(c,project,relative);const rows=await scopes(c,project);need(!rows.some(s=>blocked(s,project,relative)),'MODEL_SCOPE_FENCED');}
async function attempt(c,id,allowUnarmed=false){const initial=(await c.query('SELECT * FROM bimchat_direct_ownership.scopes WHERE id=$1',[id])).rows[0];need(initial,'MODEL_SCOPE_UNKNOWN');await lock(c,initial.project_id);const fresh=(await c.query('SELECT * FROM bimchat_direct_ownership.scopes WHERE id=$1 FOR UPDATE',[id])).rows[0];need(fresh&&fresh.project_id===initial.project_id,'MODEL_SCOPE_CHANGED');if(!allowUnarmed)need(fresh.state==='fenced','MODEL_SCOPE_NOT_ARMED');return fresh;}
module.exports={need,path,key,equal,unique,logical,group,overlap,blocked,lock,scopes,ordinary,attempt};
