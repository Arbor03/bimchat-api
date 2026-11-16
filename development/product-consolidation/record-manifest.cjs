'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=__dirname,baseline=path.resolve(root,'../ownership-native-gate/review/slog-wire-fix-20261115/server-release');
const sha=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function files(dir,prefix='') {
    return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>{
        const rel=path.join(prefix,e.name);
        return e.isDirectory()?files(path.join(dir,e.name),rel):e.isFile()?[rel]:[];
    });
}
const changed=[],added=[],hashes={};
for(const rel of files(path.join(root,'server'))) {
    hashes['server/'+rel.replaceAll('\\','/')]=sha(path.join(root,'server',rel));
    if(!fs.existsSync(path.join(baseline,rel)))added.push(rel);
    else if(sha(path.join(baseline,rel))!==hashes['server/'+rel.replaceAll('\\','/')])changed.push(rel);
}
if(changed.length!==1||changed[0]!=='index.js')throw Error('Unexpected modification of baseline server modules: '+changed);
for(const rel of files(path.join(root,'web/src')))hashes['web/src/'+rel.replaceAll('\\','/')]=sha(path.join(root,'web/src',rel));
const manifest={utc:new Date().toISOString(),state:'local_candidate_not_deployed',baselineServer:'56ae761e-1e84-4c9a-94f2-29f8e73af130',baselineModified:changed,serverAdded:added,ownershipModulesUnchanged:true,hashes};
fs.writeFileSync(path.join(root,'source-manifest.json'),JSON.stringify(manifest,null,2));
console.log(JSON.stringify({baselineModified:changed,serverAdded:added,ownershipModulesUnchanged:true}));
