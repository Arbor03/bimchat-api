"use strict";
const crypto=require('node:crypto'),scope=require('./scope.cjs');
const {need}=scope;
// Handler adapters must return data; send the HTTP response only after this resolves.
// A disconnect is NOT proof the handler or storage request stopped.
async function transaction(pool,body){const c=await pool.connect();try{await c.query('BEGIN');const result=await body(c);await c.query('COMMIT');return result;}catch(e){try{await c.query('ROLLBACK');}catch{}throw e;}finally{c.release();}}
function same(a,b){return a.project===b.project&&a.path===b.path;}
async function guarded(pool,resolve,body){return transaction(pool,async c=>{const before=await resolve(c);await scope.ordinary(c,before.project,before.path);const after=await resolve(c);need(same(before,after),'RESOURCE_MAPPING_CHANGED');return body(c,after);});}
// Persist reservation BEFORE any external side effect. A crash leaves a blocking row.
// Failed work stays uncertain until an operator verifies storage; never infer from TTL.
async function external(pool,resolve,kind,body){const id=crypto.randomUUID();const mapping=await guarded(pool,resolve,async(c,m)=>{await c.query("INSERT INTO bimchat_direct_ownership.storage_work(id,project_id,relative_path,kind,state) VALUES($1,$2,$3,$4,'started')",[id,m.project,m.path,kind]);return m;});
 try{return await guarded(pool,resolve,async(c,m)=>{need(same(mapping,m),'RESOURCE_MAPPING_CHANGED');const result=await body(c,m);await c.query("UPDATE bimchat_direct_ownership.storage_work SET state='completed',finished_at=clock_timestamp() WHERE id=$1 AND state='started'",[id]);return result;});}
 catch(e){try{await transaction(pool,c=>c.query("UPDATE bimchat_direct_ownership.storage_work SET state='uncertain' WHERE id=$1 AND state='started'",[id]));}catch{}throw e;}}
module.exports={transaction,guarded,external,same};
