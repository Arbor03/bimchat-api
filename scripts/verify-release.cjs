'use strict';
// Publication check: compare source bytes and reviewed public pins. No network or credentials.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const read=name=>JSON.parse(fs.readFileSync(path.join(root,name),'utf8').replace(/^\uFEFF/,''));
const hash=value=>crypto.createHash('sha256').update(value).digest('hex').toUpperCase();
const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}':JSON.stringify(value);
const manifest=read('release/manifest.json'),release=read('release/production.json'),review=read('ownership-review.json');
assert.equal(manifest.files.length,103,'Unexpected reviewed runtime inventory');
for(const file of manifest.files){
 assert(!path.isAbsolute(file.path)&&!file.path.split(/[\\/]/).includes('..'),'Invalid manifest path');
 assert.equal(hash(fs.readFileSync(path.join(root,file.path))),file.sha256,'Unreviewed runtime change: '+file.path);
}
assert.equal(hash(canonical(review)),manifest.newDigest,'Review digest mismatch');
assert.equal(release.publicConfiguration.BIMCHAT_OWNERSHIP_REVIEW_DIGEST,manifest.newDigest);
assert.equal(release.publicConfiguration.BIMCHAT_OWNERSHIP_WRITER_DIGEST,review.writerInventoryDigest);
assert.equal(release.driveBuild,manifest.newBuild);
assert(review.participants.every(p=>p.agentBuild===release.driveBuild),'Client build mismatch');
if(process.argv.includes('--environment')){
 for(const [key,value] of Object.entries(release.publicConfiguration))assert.equal(process.env[key],value,'Deployment configuration mismatch: '+key);
}
console.log('Verified 103 runtime files, review digest, writer pin and client build.');
