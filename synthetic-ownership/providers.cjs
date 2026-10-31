'use strict';
const need=b=>{if(!b)throw Object.assign(Error('ONLINE_SYNTHETIC_CONTEXT_REFUSED'),{status:403});};
const uuid=s=>typeof s==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
function create({pool,expectedDatabase,environmentId}){
 need(pool&&typeof expectedDatabase==='string'&&expectedDatabase.length>0&&uuid(environmentId));
 async function verifyTarget(c,t){
  need(t&&t.db===expectedDatabase);
  await c.query('SET LOCAL search_path TO bimchat_synthetic_v1,pg_catalog');
  const r=(await c.query('SELECT environment_id,synthetic_only FROM bimchat_synthetic_v1.environment WHERE singleton=true')).rows;
  need(r.length===1&&r[0].environment_id===environmentId&&r[0].synthetic_only===true);
 }
 async function bindings(c,e,lock=true){
  need(e&&e.enabled&&e.synthetic_only===true&&e.source_session!==e.receiver_session&&['ready','observing','pending','completed-blocked'].includes(e.state));
  const rows=(await c.query('SELECT session_id,email,role,generation,expires_at,revoked FROM bimchat_synthetic_v1.sessions WHERE experiment_id=$1'+(lock?' FOR SHARE':''),[e.id])).rows;
  need(rows.length===2);let result={};
  for(const role of ['source','receiver']){
   const matches=rows.filter(r=>r.role===role);need(matches.length===1);const b=matches[0];
   need(b.session_id===e[role+'_session']&&b.generation===e.generation&&!b.revoked&&new Date(b.expires_at).getTime()>Date.now());
   const m=await c.query('SELECT 1 FROM public.project_members WHERE project_id=$1 AND user_email=$2'+(lock?' FOR SHARE':''),[e.project_id,b.email]);need(m.rows.length===1);result[role]=b;
  }
  need(result.source.email!==result.receiver.email);return result;
 }
 const windowGate={async verifyAndHold({client:c,experiment:e,authenticatedUser,session}){
  // admissionTransport holds experiment FOR UPDATE through commit. Same connection,
  // no cross-DB lock cycle. This excludes synthetic operations, NOT real Revit Sync.
  const b=await bindings(c,e);const role=['source','receiver'].find(r=>b[r].email===authenticatedUser.email&&b[r].session_id===session);need(role);
  need(e.operator_confirmed_receiver_idle===true&&new Date(e.idle_expires_at).getTime()>Date.now());
  return {role,sessionsActive:true,membershipsValid:true,syncBlocked:true,exclusive:true,receiverIdle:true,scratchIdentity:e.destination_root_identity,async release(){}};
 }};
 async function readVerifiedBinding({email,sessionId,experimentId}){
  need(uuid(sessionId)&&uuid(experimentId));const c=await pool.connect();try{
   await c.query('BEGIN READ ONLY');await c.query("SET LOCAL statement_timeout='5s'");await c.query("SET LOCAL lock_timeout='3s'");
   const t=(await c.query('SELECT current_database() db')).rows[0];await verifyTarget(c,t);
   const e=(await c.query('SELECT * FROM observation_experiments WHERE id=$1',[experimentId])).rows[0];const b=await bindings(c,e,false);
   const role=['source','receiver'].find(r=>b[r].email===email&&b[r].session_id===sessionId);need(role);
   await c.query('COMMIT');return {active:true,email,sessionId,experimentId,generation:e.generation,role};
  }catch(err){await c.query('ROLLBACK');throw err;}finally{c.release();}
 }
 return {verifyTarget,windowGate,readVerifiedBinding};
}
module.exports={create};
