'use strict';
const {continuous}=require('./product-session-lifetime.cjs');
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
// Only an expired, never-activated initial enrollment can be superseded.
// Called under the existing project and attempt transaction locks, after JWT,
// membership, request signature, build and fresh proof verification.
function idle(h){return continuous(h)&&h.state==='bootstrap'&&h.enabled===false&&
 !h.initialProvisioning&&!h.bootstrapActivation&&!h.bootstrapConfirmations&&!h.sourceSession&&!h.receiverSession&&!h.renewalPrevious;
}
function available(h,role,now){const p=h.bootstrapProposals?.[role]?.profile;return idle(h)&&!!p&&Number.isSafeInteger(p.expiresAt)&&p.expiresAt<=now;}
async function replace(c,h,role,p,now){
 need(available(h,role,now),'BOOTSTRAP_REPLACEMENT_NOT_IDLE');const previous=h.bootstrapProposals[role];
 need(p.session!==previous.profile.session&&p.device!==previous.profile.device&&p.keyDigest!==previous.profile.keyDigest,'BOOTSTRAP_REPLACEMENT_KEY_REUSED');
 // Existing evidence is archived transactionally, not erased or replayed.
 h.revision++;await c.query('INSERT INTO bimchat_direct_ownership.events(attempt_id,revision,event) VALUES($1,$2,$3)',[h.id,h.revision,JSON.stringify({kind:'expired-initial-offer-superseded',role,previous})]);
}
module.exports={idle,available,replace};
