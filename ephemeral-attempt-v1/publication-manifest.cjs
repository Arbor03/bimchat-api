'use strict';
const crypto=require('node:crypto'),scope=require('./scope.cjs'),pins=require('./content-pins.cjs'),{need}=scope;
function validate(central,files){need(Array.isArray(files)&&files.length>1&&files.length<=10000,'PUBLICATION_FULL_MANIFEST');const seen=new Set();for(const f of files){need(f&&scope.group(central,f.path)&&/^[A-F0-9]{64}$/.test(f.sha256)&&Number.isSafeInteger(f.size)&&f.size>=0&&f.size<=67108864,'PUBLICATION_MANIFEST_FILE');need(!seen.has(scope.key(f.path)),'PUBLICATION_MANIFEST_ALIAS');seen.add(scope.key(f.path));}need(seen.has(scope.key(central)),'PUBLICATION_MANIFEST_CENTRAL');return files;}
async function plan(c,id,central,files){validate(central,files);for(const f of files)await c.query("INSERT INTO bimchat_direct_ownership.model_publication_files(publication_id,relative_path,expected_sha256,expected_size,state) VALUES($1,$2,$3,$4,'planned')",[id,f.path,f.sha256,f.size]);}
function verifier(r2){need(r2&&typeof r2.readVerified==='function','PUBLICATION_VERIFY_ADAPTER');return async(c,row)=>{
 need(row.post_sync_attested_at,'PUBLICATION_POST_SYNC_REQUIRED');
 const files=(await c.query('SELECT * FROM bimchat_direct_ownership.model_publication_files WHERE publication_id=$1 ORDER BY relative_path FOR UPDATE',[row.id])).rows;
 validate(row.central_path,files.map(f=>({path:f.relative_path,sha256:f.expected_sha256,size:Number(f.expected_size)})));
 // Initial publication only: no replacement/aliasing of Project06 or another catalog model.
 const catalog=(await c.query('SELECT relative_path FROM cloud_files WHERE project_id=$1 FOR UPDATE',[row.project_id])).rows;
 need(!catalog.some(f=>scope.group(row.central_path,f.relative_path.replace(/\\/g,'/'))),'PUBLICATION_CATALOG_ALREADY_EXISTS');
 const manifest=[];
 for(const f of files){need(f.state==='sealed','PUBLICATION_INCOMPLETE');const pin=await pins.load(c,f.sealed_key);need(pin.sha256===f.expected_sha256&&pin.size===Number(f.expected_size),'PUBLICATION_PIN_CHANGED');await r2.readVerified(pin);manifest.push({path:f.relative_path,key:pin.key,sha256:pin.sha256,size:pin.size,etag:pin.etag});}
 for(const f of manifest)await c.query('INSERT INTO cloud_files(project_id,file_name,relative_path,b2_key,file_size,uploaded_by) VALUES($1,$2,$3,$4,$5,$6)',[row.project_id,f.path.slice(f.path.lastIndexOf('/')+1),f.path,f.key,f.size,row.email]);
 return {complete:true,manifestDigest:crypto.createHash('sha256').update(JSON.stringify(manifest)).digest('hex').toUpperCase()};
};}
module.exports={validate,plan,verifier};
