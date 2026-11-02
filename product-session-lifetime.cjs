'use strict';
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
// Model authorization has no test countdown. Individual keys still have a
// bounded lease; only the authenticated, paired idle transition can renew it.
const leaseMs=600000;
function continuous(h){return h.lifecycle==='drive'&&h.ordinaryUserChanges===true&&h.automaticEnrollmentApproved===true&&h.transportMode==='background-prepared'&&!h.cycle;}
function enrollmentLimit(h,now){
 need(Number.isSafeInteger(now),'SESSION_CLOCK');
 if(continuous(h))return now+leaseMs;
 need(Number.isSafeInteger(h.bootstrapExpiresAt),'SESSION_DEADLINE_REQUIRED');
 return Math.min(h.bootstrapExpiresAt,now+leaseMs);
}
function nextWindow(h,now){
 need(Number.isSafeInteger(now)&&now<h.expiresAt,'RENEWAL_APPROVAL_WINDOW');
 return continuous(h)?now+leaseMs:h.bootstrapExpiresAt;
}
module.exports={continuous,enrollmentLimit,nextWindow,leaseMs};
