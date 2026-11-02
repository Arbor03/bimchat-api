'use strict';
const pathEqual=require('./scoped-api-v11/scope.cjs').equal;
// Internal transition, not an HTTP authority. The caller must verify both signed
// observations, seal the current catalog and retire the exact prior enrollments
// in the same locked transaction before storing this result.
const proof=require('./ephemeral-attempt-v1/device-proof.cjs');
const policy=require('./source-open-v1/source-policy.cjs');
const {need}=require('./ephemeral-attempt-v1/scope.cjs');
const bind=require('./product-baseline-binding.cjs');
function prepare(head,{source,receiver,catalog,manifest,publicationId,now,bootstrapExpiresAt}){
 need(head.ordinaryUserChanges===true&&head.transportMode==='background-prepared'&&head.automaticEnrollmentApproved===true&&!head.cycle&&head.state==='armed'&&head.enabled===true&&head.ordinaryIdle===true&&!head.ordinaryClaim&&!head.receiverPreparedGeneration,'RENEWAL_NOT_IDLE');
 need(Number.isSafeInteger(now)&&now<head.expiresAt&&Number.isSafeInteger(bootstrapExpiresAt)&&bootstrapExpiresAt>now&&bootstrapExpiresAt<=Math.min(head.bootstrapExpiresAt,now+600000),'RENEWAL_APPROVAL_WINDOW');
 need(/^[a-f0-9-]{36}$/.test(publicationId)&&publicationId!==head.baselinePublicationId,'RENEWAL_PUBLICATION_ID');
 const catalogDigest=proof.hash(catalog);
 for(const [role,observation] of [['source',source],['receiver',receiver]]){
  need(observation&&observation.attempt===head.id&&observation.generation===head.generation&&observation.revision===head.revision&&observation.email===head[role+'Email']&&observation.session===head[role+'Session']&&observation.device===head[role+'Device']&&observation.mappingHash===head[role+'MappingHash']&&observation.logicalCentralPath===head.logicalCentralPath&&observation.elementUniqueId===head.elementUniqueId&&observation.catalogDigest===catalogDigest&&observation.transferIdle===true&&observation.nativeUiHeld===false,'RENEWAL_OBSERVATION_BINDING');
  need(Number.isSafeInteger(observation.timestamp)&&observation.timestamp<=now&&now-observation.timestamp<=10000&&Number.isSafeInteger(observation.expiresAt)&&now<observation.expiresAt&&observation.expiresAt<=observation.timestamp+30000,'RENEWAL_OBSERVATION_EXPIRED');
  policy.pins(observation.pins);const previous=head[role+'Pins'];
  need(previous&&observation.pins.rootIdentity===previous.rootIdentity&&observation.pins.files.every((f,i)=>f.identity===previous.files[i].identity),'RENEWAL_OWNERSHIP_FILE_REPLACED');
 }
 // Divergence (including users.dat) is never resolved by copying one PC over the other.
 const bound=bind({projectId:head.projectId,fileId:head.fileId,centralPath:head.centralPath,sourcePins:source.pins,receiverPins:receiver.pins,catalog});
 need(Array.isArray(manifest)&&manifest.length===bound.inventory.length,'RENEWAL_MANIFEST_INVENTORY');
 const keys=new Set();
 for(const f of bound.inventory){const rows=manifest.filter(p=>p.path===f.path);need(rows.length===1,'RENEWAL_MANIFEST_PATH');const p=rows[0];require('./scoped-api-v11/content-pins.cjs').validate(p);need(p.key.startsWith('direct-sealed/'+head.projectId+'/')&&!keys.has(p.key),'RENEWAL_MANIFEST_KEY');keys.add(p.key);const ownership=bound.ownership.find(x=>x.path===f.path);if(ownership)need(p.sha256===ownership.sha256&&p.size===ownership.size,'RENEWAL_OWNERSHIP_CONTENT');}
 const central=manifest.find(p=>pathEqual(p.path,head.centralPath));
 for(const observation of [source,receiver])need(observation.central&&observation.central.fileId===head.fileId&&observation.central.version===bound.centralVersion&&observation.central.sha256===central.sha256&&observation.central.size===central.size,'RENEWAL_LOCAL_CENTRAL_NOT_DOWNLOADED');
 const h=structuredClone(head);
 // A reverse-direction operation must not change the plan's original account
 // ordering. New enrollment is always keyed by physical account, not last sender.
 if(head.ordinaryEnrollmentSourceEmail&&head.sourceEmail!==head.ordinaryEnrollmentSourceEmail){
  need(head.receiverEmail===head.ordinaryEnrollmentSourceEmail,'RENEWAL_ORIGINAL_PARTICIPANT');
  for(const suffix of ['Email','Build','AddinBuild'])[h['source'+suffix],h['receiver'+suffix]]=[h['receiver'+suffix],h['source'+suffix]];
 }
 // Preserve full old state separately. No old authority or operation state leaks
 // into the next bootstrap; no lifetime is extended and no key is manufactured.
 const archive={head:structuredClone(head),observations:{source:structuredClone(source),receiver:structuredClone(receiver)},catalogDigest,at:now};
 const previous={reviewDigest:head.reviewDigest,sourceEmail:head.sourceEmail,receiverEmail:head.receiverEmail};
 for(const role of ['source','receiver'])for(const suffix of ['Session','Device'])previous[role+suffix]=head[role+suffix];
 for(const k of ['bootstrapProposals','pairedReview','reviewDigest','expiresAt','ordinaryEnrollmentSourceEmail','ordinaryIdle','observedHistory','sourceFenceProof','operationId','digest','postBundle','wire','observedSourcePins','sourceObservation','receiverApplyExpiresAt','receiverReceipt','cycleCheckpoints','ordinaryClaim','receiverPreparedGeneration','preparedSourceGrant','receiverAttestedAt','nativeVerificationStartedAt','nativeVerificationExpiresAt','nativeVerification','verificationOutcome','quiescence','syncRelease','postSyncReconcile'])delete h[k];
 for(const role of ['source','receiver'])for(const suffix of ['Session','Device','AgentPublicKey','PublicKeyDigest','MappingHash','RevitUser','AgentPid','AgentStarted','RevitPid','RevitStarted','Pins'])delete h[role+suffix];
 h.generation=require('node:crypto').randomUUID();h.state='bootstrap';h.enabled=false;h.revision++;h.bootstrapExpiresAt=bootstrapExpiresAt;h.renewalPrevious=previous;h.renewalEvidenceDigest=proof.hash(archive);
 h.renewalBaselinePins={[source.email]:structuredClone(source.pins),[receiver.email]:structuredClone(receiver.pins)};
 const canonicalManifest=manifest.map(p=>({path:p.path,key:p.key,provider:p.provider,etag:p.etag,size:p.size,sha256:p.sha256})).sort((a,b)=>a.path.localeCompare(b.path,'en'));
 h.baselinePublicationId=publicationId;h.baselineManifestDigest=proof.hash(canonicalManifest);delete h.preBundle;
 return {head:h,archive,binding:bound};
}
module.exports={prepare};
