'use strict';
const {need}=require('./scope.cjs');
const timestamp=value=>value instanceof Date?value.getTime():Date.parse(value);
function valid(row,auth,project,central,role='source'){need(row&&row.state==='active'&&row.role===role,'ATTEMPT_NOT_AUTHORIZED');need(row.email===auth.email&&row.session_id===auth.sessionId&&row.device_id===auth.deviceId&&row.review_digest===auth.reviewDigest&&row.public_key_digest===auth.publicKeyDigest,'ATTEMPT_BINDING');need(row.project_id===project&&row.central_path===central,'ATTEMPT_MODEL');const now=timestamp(row.server_now),start=timestamp(row.not_before),end=timestamp(row.expires_at);need(Number.isFinite(now)&&Number.isFinite(start)&&Number.isFinite(end)&&now>=start&&now<end&&end-start<=1200000,'ATTEMPT_EXPIRED_OR_INVALID');return true;}
async function requireActive(c,auth,project,central,role='source'){need(auth&&/^[A-F0-9]{64}$/.test(auth.reviewDigest)&&/^[A-F0-9]{64}$/.test(auth.publicKeyDigest),'ATTEMPT_REVIEW_REQUIRED');
 const row=(await c.query("SELECT e.*,clock_timestamp() server_now FROM bimchat_direct_ownership.publication_enrollments e JOIN isolated_revit_sessions s ON s.session_id=e.session_id AND s.email=e.email AND s.device_id=e.device_id JOIN project_members m ON m.project_id=e.project_id AND m.user_email=e.email WHERE e.review_digest=$1 AND e.email=$2 AND s.state='active' FOR SHARE OF e,s,m",[auth.reviewDigest,auth.email])).rows[0];
 valid(row,auth,project,central,role);return row;
}
module.exports={valid,requireActive};

