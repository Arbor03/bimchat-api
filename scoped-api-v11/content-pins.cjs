'use strict';
const {need}=require('./scope.cjs');
function validate(p){need(p&&p.provider==='r2'&&/^direct-sealed\/[1-9][0-9]*\/[a-f0-9-]{36}$/.test(p.key)&&typeof p.etag==='string'&&/^"[^"\r\n]+"$/.test(p.etag)&&/^[A-F0-9]{64}$/.test(p.sha256)&&Number.isSafeInteger(p.size)&&p.size>=0,'R2_PIN_INVALID');return p;}
async function insert(c,p){validate(p);await c.query('INSERT INTO bimchat_direct_ownership.sealed_objects(object_key,provider,etag,sha256,byte_length) VALUES($1,$2,$3,$4,$5)',[p.key,p.provider,p.etag,p.sha256,p.size]);}
async function load(c,key){const row=(await c.query('SELECT object_key,provider,etag,sha256,byte_length FROM bimchat_direct_ownership.sealed_objects WHERE object_key=$1',[key])).rows[0];need(row,'R2_PIN_MISSING');return validate({key:row.object_key,provider:row.provider,etag:row.etag,sha256:row.sha256,size:Number(row.byte_length)});}
// Uses raw pool, never the caller's uncommitted transaction. An unresolved row
// survives crash/rollback and blocks drain. No automatic orphan deletion.
function reservation(pool,cap){return async p=>{await pool.query("INSERT INTO bimchat_direct_ownership.storage_work(id,project_id,relative_path,kind,state,object_key,expected_sha256,expected_size) VALUES($1,$2,$3,'r2-seal','started',$4,$5,$6)",[require('node:crypto').randomUUID(),cap.project_id,cap.relative_path,p.key,p.sha256,p.size]);return true;};}
async function complete(c,p){const r=await c.query("UPDATE bimchat_direct_ownership.storage_work SET state='completed',finished_at=clock_timestamp() WHERE object_key=$1 AND kind='r2-seal' AND state='started' AND expected_sha256=$2 AND expected_size=$3 RETURNING id",[p.key,p.sha256,p.size]);need(r.rowCount===1,'R2_RESERVATION_MISMATCH');}
module.exports={validate,insert,load,reservation,complete};
