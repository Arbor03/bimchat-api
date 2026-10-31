'use strict';
const crypto=require('node:crypto');const names=['users.dat','editingperms.dat','editingdeltas.dat','editingrequests.dat','worksetperms.dat'];
const need=b=>{if(!b)throw Object.assign(Error('SCRATCH_EVIDENCE_REFUSED'),{status:409});};
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
function exact(o,k){need(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join('|')===k.slice().sort().join('|'));}
function parse(raw,canonical,keys){need(typeof raw==='string'&&Buffer.byteLength(raw)<=16384);const o=JSON.parse(raw);need(canonical(o)===raw);exact(o,keys);return o;}
function manifest(files){need(Array.isArray(files)&&files.length===5);files.forEach((f,i)=>{exact(f,['name','identity','length','sha256']);need(f.name===names[i]&&typeof f.identity==='string'&&f.identity.length>0&&f.identity.length<=128&&Number.isSafeInteger(f.length)&&f.length>=0&&f.length<=8388608&&/^[A-F0-9]{64}$/.test(f.sha256));});return sha(files.map(f=>f.name+':'+f.length+':'+f.sha256).join('\n')).toUpperCase();}
function reviewed(e){const p=e.reviewed_destination;exact(p,['scratchId','rootIdentity','files']);need(p.scratchId===e.scratch_id&&p.rootIdentity===e.destination_root_identity&&manifest(p.files)===e.pre_bundle);return p;}
function provisioning(raw,e,canonical,trace=()=>{}){trace('receipt-parse');const r=parse(raw,canonical,['experimentId','scratchId','rootIdentity','files','noJournal','receiverIdle','stableFirstUtc','stableSecondUtc','observedUtc']);trace('reviewed-pins');const pins=reviewed(e);trace('receipt-pins');need(r.experimentId===e.id&&r.scratchId===pins.scratchId&&r.rootIdentity===pins.rootIdentity&&canonical(r.files)===canonical(pins.files)&&r.noJournal===true&&r.receiverIdle===true);trace('observed-freshness');fresh(r.observedUtc);trace('stable-freshness');fresh(r.stableSecondUtc);trace('capture-span');const span=Date.parse(r.stableSecondUtc)-Date.parse(r.stableFirstUtc);need(span>=300&&span<=5000&&Date.parse(r.stableSecondUtc)<=Date.parse(r.observedUtc));return r;}
function fresh(date){need(typeof date==='string');const age=Date.now()-Date.parse(date);need(Number.isFinite(age)&&age>=0&&age<=10000);}
function completion(raw,e,t,p,canonical){const a=parse(raw,canonical,['operationId','digest','result','sequence','postBundle','scratchId','rootIdentity','files','completeRecordSha256','observedUtc']);const pins=reviewed(e);
 need(a.operationId===t.operation_id&&a.digest===t.digest&&a.result==='applied'&&a.sequence===p.Sequence&&a.postBundle===p.PostBundle&&a.scratchId===pins.scratchId&&a.rootIdentity===pins.rootIdentity&&manifest(a.files)===p.PostBundle);
 a.files.forEach((f,i)=>need(f.identity===pins.files[i].identity&&f.length===p.Files[i].PostLength&&f.sha256===p.Files[i].PostHash));
 const complete=t.digest.toUpperCase()+'\n'+p.PostBundle;need(a.completeRecordSha256===sha(complete).toUpperCase());fresh(a.observedUtc);return a;
}
module.exports={provisioning,completion,sha};
