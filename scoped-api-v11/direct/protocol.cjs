'use strict';
// Staged module: no import-time IO, migrations, listener, credentials or activation.
const crypto=require('node:crypto');
const names=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];
const hash=/^[A-F0-9]{64}$/;const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const fail=(status,message)=>Object.assign(new Error(message),{status});
function need(ok,message,status=409){if(!ok)throw fail(status,message);}
function canonical(v){if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';if(v&&typeof v==='object')return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';return JSON.stringify(v);}
function digest(v){return crypto.createHash('sha256').update(canonical(v)).digest('hex');}
function bytes(v,stream=false){need(Array.isArray(v)&&v.length<=(stream?Number.MAX_SAFE_INTEGER:65536)&&v.every(x=>Number.isInteger(x)&&x>=0&&x<=255),'Invalid bounded bytes',400);return v.length;}
function validate(p,stream=false){
 if(stream&&(p?.Schema===2||p?.Schema===3)){
  const result=validateImage(p);
  if(p.Schema===3)for(const f of p.Files)need(Number.isSafeInteger(f.DeltaLength)&&f.DeltaLength>=0&&Number.isSafeInteger(f.DeltaRecords)&&f.DeltaRecords>=0&&hash.test(f.DeltaHash),'STREAM_DELTA_METADATA');
  return result;
 }
 need(p&&(stream||Buffer.byteLength(JSON.stringify(p))<=1048576),'Envelope limit',400);
 need(p.Schema===1&&typeof p.Model==='string'&&/^[^\\/:\x00-\x1f]{1,180}\.rvt$/i.test(p.Model),'Invalid model/schema',400);
 need(uuid.test(p.Generation)&&uuid.test(p.OperationId)&&uuid.test(p.SourceSession),'Invalid context IDs',400);
 need(Number.isSafeInteger(p.PreviousSequence)&&p.PreviousSequence>=0&&Number.isSafeInteger(p.Sequence)&&p.Sequence===p.PreviousSequence+1,'Invalid sequence',400);
 need(hash.test(p.PreBundle)&&hash.test(p.PostBundle)&&p.PreBundle!==p.PostBundle,'Invalid bundle hashes',400);
 need(Array.isArray(p.Files)&&p.Files.length===5,'Five files required',400);let changed=0,ranges=0;
 p.Files.forEach((f,i)=>{need(f&&f.Name===names[i]&&hash.test(f.PreHash)&&hash.test(f.PostHash),'File order/hash',400);
 need(Number.isSafeInteger(f.PreLength)&&f.PreLength>=0&&(stream||f.PreLength<=8388608)&&Number.isSafeInteger(f.PostLength)&&f.PostLength>=0&&(stream||f.PostLength>=f.PreLength)&&(stream||f.PostLength<=8388608),'File bounds',400);
 need(bytes(f.Append,stream)===Math.max(0,f.PostLength-f.PreLength)&&Array.isArray(f.Overwrites)&&(stream||f.Overwrites.length<=256),'Append/range bounds',400);changed+=Math.abs(f.PostLength-f.PreLength);let end=0;
 for(const c of f.Overwrites){need(c&&Number.isInteger(c.Offset)&&c.Offset>=end,'Overlap/offset',400);let n=bytes(c.Before,stream);need(n>0&&bytes(c.After,stream)===n&&c.Offset+n<=Math.min(f.PreLength,f.PostLength),'Overwrite bounds',400);end=c.Offset+n;changed+=n;ranges++;}
 });need(stream||(changed<=65536&&ranges<=256),'Transaction bounds',400);
 for(const side of ['Pre','Post']){const actual=crypto.createHash('sha256').update(p.Files.map(f=>f.Name+':'+f[side+'Length']+':'+f[side+'Hash']).join('\n')).digest('hex').toUpperCase();need(actual===p[side+'Bundle'],'Bundle manifest mismatch',400);}
 return digest(p);
}
function validateImage(p){
 need(p&&typeof p.Model==='string'&&/^[^\\/:\x00-\x1f]{1,180}\.rvt$/i.test(p.Model),'STREAM_IMAGE_MODEL');
 need(uuid.test(p.Generation)&&uuid.test(p.OperationId)&&uuid.test(p.SourceSession),'STREAM_IMAGE_CONTEXT');
 need(Number.isSafeInteger(p.PreviousSequence)&&p.PreviousSequence>=0&&p.Sequence===p.PreviousSequence+1,'STREAM_IMAGE_SEQUENCE');
 need(Array.isArray(p.Files)&&p.Files.length===5,'STREAM_IMAGE_FILES');
 p.Files.forEach((f,i)=>need(f&&f.Name===names[i]&&Number.isSafeInteger(f.PreLength)&&f.PreLength>=0&&Number.isSafeInteger(f.PostLength)&&f.PostLength>=0&&hash.test(f.PreHash)&&hash.test(f.PostHash),'STREAM_IMAGE_PIN'));
 for(const side of ['Pre','Post'])need(crypto.createHash('sha256').update(p.Files.map(f=>f.Name+':'+f[side+'Length']+':'+f[side+'Hash']).join('\n')).digest('hex').toUpperCase()===p[side+'Bundle'],'STREAM_IMAGE_BUNDLE');
 need(p.PreBundle!==p.PostBundle,'STREAM_IMAGE_UNCHANGED');return digest(p);
}
function accept(head,p,existing,d){
 need(head.generation===p.Generation&&head.source_session===p.SourceSession,'Generation/source mismatch');
 if(existing){need(existing.digest===d&&existing.project_id===head.project_id&&existing.central_path===head.central_path,'Operation ID reused');return {duplicate:true,state:existing.state};}
 need(head.state==='ready'&&!head.pending_operation,'Pending or recovery; no next transaction',423);
 need(Number(head.sequence)===p.PreviousSequence&&head.bundle_hash===p.PreBundle,'Stale baseline');return {duplicate:false,state:'pending'};
}
function acknowledge(head,tx,sid,body){
 need(tx.receiver_session===sid&&head.receiver_session===sid,'Not designated receiver',403);
 need(body&&body.operationId===tx.operation_id&&body.digest===tx.digest,'Ack identity mismatch');
 if(tx.state==='acknowledged'){need(canonical(body)===canonical(tx.ack),'Conflicting duplicate ack');return 'duplicate';}
 need(head.state==='pending'&&head.pending_operation===tx.operation_id&&tx.state==='pending','Recovery or stale acknowledgment',423);
 need(['applied','partial','divergent','interrupted'].includes(body.result),'Invalid result',400);
 if(body.result!=='applied')return 'recovery';
 need(body.postBundle===tx.payload.PostBundle&&body.sequence===Number(tx.sequence),'Postimage/sequence acknowledgment mismatch');return 'acknowledged';
}

module.exports={canonical,digest,validate,validateStream:p=>validate(p,true)};
