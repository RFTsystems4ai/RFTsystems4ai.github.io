export const RELEASE_SPEC='rftsystems4ai-signed-demo-release-1.0';
export const BUNDLE_SPEC='rftsystems4ai-demo-receipt-bundle-1.0';
export const RECEIPT_SPEC='rftsystems4ai-demo-receipt-1.0';
export const RELEASE_DOMAIN='RFTSYSTEMS4AI_DEMO_RELEASE_V1';
export const RELEASE_ID='rftsystems4ai-verification-demo-2026-08-21';
export const TRUSTED_RELEASE_KEY=Object.freeze({
  key_id:'rftsystems4ai-demo-verification-2026-08-21',
  public_key_raw_b64url:'-PqEBjaRTENge1gUWYxgo8RsXB_Ll7sDfp7DDEIHYF0',
  public_key_sha256:'30ef9e7f8bfda83e9a712f0b2e65eda31078ba4d392e48dd76dd8e6b169b12fe'
});
const enc=new TextEncoder();

export function canonicalise(value){
  if(value===null)return'null';
  if(typeof value==='string')return JSON.stringify(value);
  if(typeof value==='boolean')return value?'true':'false';
  if(typeof value==='number'){if(!Number.isFinite(value))throw new TypeError('Non-finite numbers are not canonical JSON');return JSON.stringify(value);}
  if(Array.isArray(value))return`[${value.map(canonicalise).join(',')}]`;
  if(typeof value==='object'){const keys=Object.keys(value).sort();return`{${keys.map(k=>`${JSON.stringify(k)}:${canonicalise(value[k])}`).join(',')}}`;}
  throw new TypeError(`Unsupported canonical JSON type: ${typeof value}`);
}
export async function sha256Hex(text){const d=await crypto.subtle.digest('SHA-256',enc.encode(text));return[...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join('');}
function equal(a,b){return canonicalise(a)===canonicalise(b);}
function obj(v,label){if(!v||typeof v!=='object'||Array.isArray(v))throw new Error(`${label} must be an object`);return v;}
function arr(v,label){if(!Array.isArray(v))throw new Error(`${label} must be an array`);return v;}
function str(v,label){if(typeof v!=='string'||!v.length)throw new Error(`${label} must be a non-empty string`);return v;}
function b64urlBytes(text){if(typeof text!=='string'||!/^[A-Za-z0-9_-]+$/.test(text))throw new Error('Non-canonical base64url');const padded=text.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-text.length%4)%4);const raw=atob(padded);return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function b64Bytes(text){if(typeof text!=='string')throw new Error('Invalid base64');try{return Uint8Array.from(atob(text),c=>c.charCodeAt(0));}catch{throw new Error('Invalid base64');}}

export async function verifySignedRelease(release){
  obj(release,'official_release'); const core=obj(release.release_core,'release_core'); const sig=obj(release.signature,'release signature');
  if(core.spec!==RELEASE_SPEC||core.release_id!==RELEASE_ID||core.canonicalisation!=='RFT-JCS-1')throw new Error('Unsupported or substituted RFTSystems4Ai demo release');
  if(core.issuer?.name!=='RFTSystems4Ai'||core.issuer?.legal_identity!=='RFTSystems4Ai is a trading name of Liam S Grinstead, sole trader.'||core.issuer?.copyright!=='© 2026 Liam S Grinstead. All rights reserved.')throw new Error('Release issuer identity mismatch');
  if(sig.algorithm!=='Ed25519'||sig.domain!==RELEASE_DOMAIN||sig.key_id!==TRUSTED_RELEASE_KEY.key_id||sig.public_key_sha256!==TRUSTED_RELEASE_KEY.public_key_sha256)throw new Error('Release trust-anchor metadata mismatch');
  const canonical=canonicalise(core), hash=await sha256Hex(canonical); if(hash!==sig.release_core_sha256)throw new Error('Signed release-core SHA-256 mismatch');
  const keyBytes=b64urlBytes(TRUSTED_RELEASE_KEY.public_key_raw_b64url), signature=b64urlBytes(sig.signature_b64url); if(keyBytes.length!==32||signature.length!==64)throw new Error('Invalid release key/signature length');
  const key=await crypto.subtle.importKey('raw',keyBytes,{name:'Ed25519'},false,['verify']);
  const ok=await crypto.subtle.verify({name:'Ed25519'},key,signature,enc.encode(`${RELEASE_DOMAIN}\0${canonical}`)); if(!ok)throw new Error('RFTSystems4Ai demo release signature invalid');
  return{valid:true,release_core:core,key_id:sig.key_id,release_core_sha256:hash};
}

async function verifyFlight(artifact,contract){
  obj(artifact,'Flight Recorder artefact'); arr(artifact.events,'Flight Recorder events');
  if(artifact.format!=='rftsystems4ai-browser-flight-record-v1'||artifact.events.length!==contract.seed.length)throw new Error('Flight Recorder artefact is outside the signed demo contract');
  str(artifact.session_id,'session_id'); let prev='0'.repeat(64), chainOk=true, controlled=false;
  for(let i=0;i<artifact.events.length;i++){
    const e=obj(artifact.events[i],`event ${i+1}`),[kind,basePayload]=contract.seed[i]; if(e.seq!==i+1||e.event_type!==kind||e.session_id!==artifact.session_id)throw new Error(`Flight Recorder event ${i+1} identity is outside the signed demo contract`);
    let allowed=equal(e.payload,basePayload); if(i===3){const mutated={...basePayload,value:contract.controlled_failures.event_4_memory_value};if(equal(e.payload,mutated)){allowed=true;controlled=true;}}
    if(!allowed)throw new Error(`Flight Recorder event ${i+1} payload is outside the signed demo contract`);
    const core={session_id:e.session_id,seq:e.seq,event_type:e.event_type,payload:e.payload,prev_hash:prev};const h=await sha256Hex(canonicalise(core));if(e.prev_hash!==prev||e.event_hash!==h)chainOk=false;prev=h;
  }
  if(artifact.final_anchor!==prev)chainOk=false;
  return{verdict:!controlled&&chainOk?'PASS':'FAIL',verification_scope:contract.verification_scope,chain_consistent:chainOk,controlled_failure_present:controlled};
}
async function verifyMemory(artifact,contract){
  obj(artifact,'Memory Receipt artefact');const ledger=arr(artifact.ledger,'ledger');const r=obj(artifact.receipt,'receipt');if(ledger.length!==contract.baseline_rows.length||r.format!=='rftsystems4ai-browser-memory-receipt-v1')throw new Error('Memory Receipt artefact is outside the signed demo contract');
  const q=contract.questions[r.question];if(!q||r.answer!==q.answer||r.evidence?.event_seq!==q.seq)throw new Error('Memory Receipt question/answer is outside the signed demo contract');
  let prev='0'.repeat(64),chainOk=true,controlled=false;
  for(let i=0;i<ledger.length;i++){
    const e=obj(ledger[i],`ledger event ${i+1}`),[key,base]=contract.baseline_rows[i];if(e.seq!==i+1||e.key!==key)throw new Error(`Memory ledger event ${i+1} identity is outside the signed demo contract`);
    if(e.value!==base){const isSelected=e.seq===q.seq&&e.value===contract.controlled_failures[r.question];if(!isSelected)throw new Error(`Memory ledger event ${i+1} value is outside the signed demo contract`);controlled=true;}
    const core={seq:e.seq,key:e.key,value:e.value,prev_hash:prev},h=await sha256Hex(canonicalise(core));if(e.prev_hash!==prev||e.event_hash!==h)chainOk=false;prev=h;
  }
  const event=ledger.find(e=>e.seq===q.seq),evidence={event_seq:event.seq,key:event.key,value:event.value,event_hash:event.event_hash};
  const memoryHash=await sha256Hex(canonicalise(evidence)),answerHash=await sha256Hex(r.answer),receiptCore={format:r.format,scope:r.scope,question:r.question,evidence,memory_hash:r.memory_hash,answer:r.answer,answer_hash:r.answer_hash},receiptHash=await sha256Hex(canonicalise(receiptCore));
  const bindingOk=event.event_hash===r.evidence?.event_hash&&memoryHash===r.memory_hash&&answerHash===r.answer_hash&&receiptHash===r.receipt_hash;
  return{verdict:!controlled&&chainOk&&bindingOk?'PASS':'FAIL',verification_scope:contract.verification_scope,chain_consistent:chainOk,binding_verified:bindingOk,controlled_failure_present:controlled};
}
async function verifyTimelineRun(run,seed,label,contract){
  obj(run,`run ${label}`);arr(run.events,`run ${label} events`);if(run.format!=='rftsystems4ai-browser-timeline-v1'||run.label!==label||run.events.length!==seed.length)throw new Error(`TimelineDiff run ${label} is outside the signed demo contract`);
  let prev='0'.repeat(64),chainOk=true,controlled=false;
  for(let i=0;i<run.events.length;i++){
    const e=obj(run.events[i],`run ${label} event ${i+1}`),[kind,base]=seed[i];if(e.seq!==i+1||e.kind!==kind||e.session_id!==run.session_id)throw new Error(`TimelineDiff run ${label} event ${i+1} identity is outside the signed demo contract`);
    let allowed=equal(e.payload,base);if(label===contract.controlled_failure.run&&e.seq===contract.controlled_failure.event){const mut={...base,[contract.controlled_failure.field]:contract.controlled_failure.value};if(equal(e.payload,mut)){allowed=true;controlled=true;}}
    if(!allowed)throw new Error(`TimelineDiff run ${label} event ${i+1} payload is outside the signed demo contract`);
    const core={session_id:e.session_id,seq:e.seq,kind:e.kind,payload:e.payload,prev_hash:prev},h=await sha256Hex(canonicalise(core));if(e.prev_hash!==prev||e.event_hash!==h)chainOk=false;prev=h;
  }
  if(run.final_anchor!==prev)chainOk=false;return{chainOk,controlled};
}
async function verifyTimeline(artifact,contract){
  obj(artifact,'TimelineDiff artefact');const A=obj(artifact.run_a,'run_a'),B=obj(artifact.run_b,'run_b');const a=await verifyTimelineRun(A,contract.run_a_seed,'A',contract),b=await verifyTimelineRun(B,contract.run_b_seed,'B',contract);
  let first=null,count=0;for(let i=0;i<Math.max(A.events.length,B.events.length);i++){const ae=A.events[i],be=B.events[i],same=!!ae&&!!be&&ae.kind===be.kind&&equal(ae.payload,be.payload);if(!same){count++;if(first===null)first=i+1;}}
  return{verdict:a.chainOk&&b.chainOk&&!a.controlled&&!b.controlled?'PASS':'FAIL',verification_scope:contract.verification_scope,first_divergence:first,differing_events:count,run_a_chain_consistent:a.chainOk,run_b_chain_consistent:b.chainOk,controlled_failure_present:a.controlled||b.controlled};
}
async function challengeHashes(events){let prev='0'.repeat(64),out=[];for(const e of events){const h=await sha256Hex(prev+JSON.stringify({seq:e.seq,type:e.type,payload:e.payload}));out.push(h);prev=h;}return out;}
function expectedChallenge(contract,attack){const e=structuredClone(contract.baseline_events);if(attack==='none')return e;if(attack==='modify'){e[3].payload='audit_mode = permissive';return e;}if(attack==='remove'){e.splice(2,1);return e;}if(attack==='reorder'){[e[1],e[2]]=[e[2],e[1]];return e;}if(attack==='inject'){e.splice(3,0,{seq:99,type:'INJECTED_EVENT',payload:'unrecorded action'});return e;}throw new Error('Challenge attack is outside the signed demo contract');}
async function verifyChallenge(artifact,contract){
  obj(artifact,'Challenge artefact');if(!contract.attacks.includes(artifact.attack))throw new Error('Challenge attack is outside the signed demo contract');const sealed=await challengeHashes(contract.baseline_events),root=sealed.at(-1);if(!equal(artifact.sealed_commitments,sealed)||artifact.baseline_root!==root)throw new Error('Challenge baseline does not match the signed RFTSystems4Ai release');
  const expected=expectedChallenge(contract,artifact.attack);if(!equal(artifact.current_events,expected))throw new Error('Challenge current events do not match the recognised controlled attack');const computed=await challengeHashes(artifact.current_events);let first=null;for(let i=0;i<Math.max(sealed.length,computed.length);i++){if(sealed[i]!==computed[i]){first=i+1;break;}}const pass=first===null&&computed.length===sealed.length&&computed.at(-1)===root;
  return{verdict:pass?'PASS':'FAIL',verification_scope:contract.verification_scope,attack:artifact.attack,first_failure_event:first,official_baseline_verified:true};
}
async function verifyTrustStack(artifact,contract){
  obj(artifact,'TrustStack artefact');if(artifact.format!=='rftsystems4ai-browser-truststack-decision-v1')throw new Error('Unsupported TrustStack artefact format');const state=str(artifact.packet_state,'packet_state');if(!contract.packet_states[state])throw new Error('TrustStack packet state is outside the signed demo contract');const p=obj(artifact.packet,'packet');const fresh=await sha256Hex(p.payload),hashOK=fresh===p.stored_hash;let decision='BLOCK',reason='payload commitment failed';
  if(hashOK&&!p.signature){decision='HOLD';reason='integrity only; no signature';}
  else if(hashOK&&p.signature&&p.key_id!==contract.trusted_key_id){decision='BLOCK';reason='untrusted signer key';}
  else if(hashOK&&p.signature){
    try{const keyBytes=b64Bytes(contract.trusted_public_key_b64),sigBytes=b64Bytes(p.signature);const key=await crypto.subtle.importKey('raw',keyBytes,{name:'Ed25519'},false,['verify']);const ok=await crypto.subtle.verify({name:'Ed25519'},key,sigBytes,enc.encode(p.payload));decision=ok?'ALLOW':'BLOCK';reason=ok?'trusted-key signature verified':'trusted-key signature invalid';}
    catch(error){if(error?.name==='NotSupportedError'){decision='HOLD';reason='Ed25519 unavailable in this browser';}else{decision='BLOCK';reason='malformed or unverifiable signature material';}}
  }
  if(decision!==contract.packet_states[state].decision)throw new Error('TrustStack decision does not match the signed demo release contract');
  return{verdict:decision,verification_scope:contract.verification_scope,payload_integrity:hashOK?'PASS':'FAIL',reason};
}
const VERIFIERS={'agent-flight-recorder':verifyFlight,'memory-receipt':verifyMemory,'timelinediff':verifyTimeline,'falsification-001':verifyChallenge,'truststack':verifyTrustStack};

export async function verifyDemoBundle(bundle){
  obj(bundle,'bundle');if(bundle.spec!==BUNDLE_SPEC)throw new Error('Unsupported RFTSystems4Ai demo bundle spec');const releaseResult=await verifySignedRelease(bundle.official_release);const receipt=obj(bundle.rftsystems4ai_demo_receipt,'demo receipt');if(receipt.spec!==RECEIPT_SPEC||receipt.release_id!==releaseResult.release_core.release_id||receipt.issuer!=='RFTSystems4Ai')throw new Error('Demo receipt is not bound to the authenticated release');
  const surfaceId=str(receipt.surface_id,'surface_id');if(bundle.surface_id!==surfaceId)throw new Error('Surface ID mismatch');const contract=releaseResult.release_core.contracts?.[surfaceId],verifier=VERIFIERS[surfaceId];if(!contract||!verifier)throw new Error('Surface is not covered by this signed RFTSystems4Ai release');
  const artifactHash=await sha256Hex(canonicalise(bundle.artifact));if(receipt.artifact_sha256!==artifactHash)throw new Error('Artefact SHA-256 does not match the receipt');const derived=await verifier(bundle.artifact,contract);if(receipt.reported_verdict!==derived.verdict)throw new Error('Reported verdict does not match independent verification');
  return{valid:true,release_authenticated:true,release_id:releaseResult.release_core.release_id,release_issued_at_utc:releaseResult.release_core.issued_at_utc,release_key_id:releaseResult.key_id,release_core_sha256:releaseResult.release_core_sha256,surface_id:surfaceId,surface_name:contract.surface_name,artifact_sha256:artifactHash,downloaded_at_utc:receipt.downloaded_at_utc,timestamp_basis:receipt.timestamp_basis,derived};
}
