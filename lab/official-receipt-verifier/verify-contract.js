import { verifyDemoBundle as verifyCryptographicBundle, canonicalise, sha256Hex } from './receipt-crypto.js';

const LEGAL_IDENTITY='RFTSystems4Ai is a trading name of Liam S Grinstead, sole trader.';
const COPYRIGHT='© 2026 Liam S Grinstead. All rights reserved.';
const LOCAL_TIMESTAMP_BASIS='UTC rendered from the local browser device clock for download traceability; the official release UTC is separately authenticated by the RFTSystems4Ai Ed25519 release signature.';
const NOTE_FLIGHT='This artefact is independently re-checkable against the Ed25519-signed RFTSystems4Ai demo release contract bundled with the download.';
const NOTE_MEMORY='The complete ledger and receipt are bundled so the signed-release verifier can recompute the current chain and evidence binding independently.';
const NOTE_TIMELINE='Both complete timelines are bundled so the authenticated release verifier can derive chain state and first behavioural divergence independently.';

function object(value,label){if(!value||typeof value!=='object'||Array.isArray(value))throw new Error(`${label} must be an object`);return value;}
function exactKeys(value,keys,label){object(value,label);const got=Object.keys(value).sort(),want=[...keys].sort();if(got.length!==want.length||got.some((k,i)=>k!==want[i]))throw new Error(`${label} contains missing or unauthorised fields`);}
function allowedKeys(value,required,optional,label){object(value,label);for(const key of required)if(!(key in value))throw new Error(`${label} is missing ${key}`);for(const key of Object.keys(value))if(!required.includes(key)&&!optional.includes(key))throw new Error(`${label} contains unauthorised field ${key}`);}
function exact(value,expected,label){if(canonicalise(value)!==canonicalise(expected))throw new Error(`${label} does not match the authenticated demonstration contract`);}
function validLocalUtc(value){return typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)&&Number.isFinite(Date.parse(value));}
function trustBoundary(value,label){exactKeys(value,['external_anchor_present','external_anchor_verified','signer_identity_verified'],label);if(value.external_anchor_present!==false||value.external_anchor_verified!==false||value.signer_identity_verified!==false)throw new Error(`${label} misstates the browser trust boundary`);}
function eventKeys(events,keys,label){if(!Array.isArray(events))throw new Error(`${label} must be an array`);events.forEach((e,i)=>exactKeys(e,keys,`${label} ${i+1}`));}

function validateEnvelope(bundle){
  exactKeys(bundle,['spec','surface_id','artifact','rftsystems4ai_demo_receipt','official_release'],'bundle');
  exactKeys(bundle.official_release,['release_core','signature'],'official_release');
  const receipt=object(bundle.rftsystems4ai_demo_receipt,'demo receipt');
  exactKeys(receipt,['spec','issuer','surface_id','release_id','reported_verdict','artifact_sha256','downloaded_at_utc','timestamp_basis','legal_identity','copyright'],'demo receipt');
  const signedIssuer=bundle.official_release?.release_core?.issuer;
  if(receipt.issuer!=='RFTSystems4Ai'||receipt.legal_identity!==LEGAL_IDENTITY||receipt.copyright!==COPYRIGHT)throw new Error('Demo receipt issuer/footer identity mismatch');
  if(signedIssuer?.name!=='RFTSystems4Ai'||signedIssuer?.legal_identity!==LEGAL_IDENTITY||signedIssuer?.copyright!==COPYRIGHT)throw new Error('Signed release issuer/footer identity mismatch');
  if(receipt.timestamp_basis!==LOCAL_TIMESTAMP_BASIS)throw new Error('Local timestamp trust-boundary wording mismatch');
  if(!validLocalUtc(receipt.downloaded_at_utc))throw new Error('Local download UTC is malformed');
}

function validateFlight(artifact){
  exactKeys(artifact,['format','scope','session_id','events','final_anchor','trust_boundary','verification_note'],'Flight Recorder artefact');
  if(artifact.scope!=='internal-sha256-chain-consistency-demo')throw new Error('Flight Recorder scope mismatch');
  if(artifact.verification_note!==NOTE_FLIGHT)throw new Error('Flight Recorder verification note mismatch');
  trustBoundary(artifact.trust_boundary,'Flight Recorder trust boundary');
  eventKeys(artifact.events,['session_id','seq','event_type','payload','prev_hash','event_hash'],'Flight Recorder event');
}

async function baselineMemoryReceipt(contract,question){
  const q=contract.questions?.[question];if(!q)throw new Error('Memory Receipt question is outside the signed contract');
  let prev='0'.repeat(64),selected=null;
  for(let i=0;i<contract.baseline_rows.length;i++){
    const [key,value]=contract.baseline_rows[i],payload={seq:i+1,key,value,prev_hash:prev},event_hash=await sha256Hex(canonicalise(payload));
    if(i+1===q.seq)selected={...payload,event_hash};
    prev=event_hash;
  }
  const evidence={event_seq:selected.seq,key:selected.key,value:selected.value,event_hash:selected.event_hash};
  const memory_hash=await sha256Hex(canonicalise(evidence)),answer_hash=await sha256Hex(q.answer);
  const core={format:'rftsystems4ai-browser-memory-receipt-v1',scope:'internal-sha256-evidence-binding-demo',question,evidence,memory_hash,answer:q.answer,answer_hash};
  const receipt_hash=await sha256Hex(canonicalise(core));
  return{...core,receipt_hash,trust_boundary:{external_anchor_present:false,external_anchor_verified:false,signer_identity_verified:false}};
}

async function validateMemory(artifact,contract){
  exactKeys(artifact,['ledger','receipt','verification_note'],'Memory Receipt artefact');
  if(artifact.verification_note!==NOTE_MEMORY)throw new Error('Memory Receipt verification note mismatch');
  eventKeys(artifact.ledger,['seq','key','value','prev_hash','event_hash'],'Memory ledger event');
  const receipt=object(artifact.receipt,'Memory Receipt receipt');
  exactKeys(receipt,['format','scope','question','evidence','memory_hash','answer','answer_hash','receipt_hash','trust_boundary'],'Memory Receipt receipt');
  exactKeys(receipt.evidence,['event_seq','key','value','event_hash'],'Memory Receipt evidence');
  if(receipt.scope!=='internal-sha256-evidence-binding-demo')throw new Error('Memory Receipt scope mismatch');
  trustBoundary(receipt.trust_boundary,'Memory Receipt trust boundary');
  const expected=await baselineMemoryReceipt(contract,receipt.question);
  exact(receipt,expected,'Memory Receipt baseline receipt');
}

function timelineRun(run,label){
  exactKeys(run,['format','scope','session_id','label','events','final_anchor','trust_boundary'],`TimelineDiff run ${label}`);
  if(run.scope!=='internal-sha256-timeline-consistency-demo'||run.label!==label)throw new Error(`TimelineDiff run ${label} scope/label mismatch`);
  trustBoundary(run.trust_boundary,`TimelineDiff run ${label} trust boundary`);
  eventKeys(run.events,['session_id','seq','kind','payload','prev_hash','event_hash'],`TimelineDiff run ${label} event`);
}
async function timelineIntegrity(run){let prev='0'.repeat(64),first=null;for(const e of run.events){const core={session_id:e.session_id,seq:e.seq,kind:e.kind,payload:e.payload,prev_hash:prev},hash=await sha256Hex(canonicalise(core));if(first===null&&(e.prev_hash!==prev||e.event_hash!==hash))first=e.seq;prev=hash;}if(first===null&&run.final_anchor!==prev)first=run.events.length;return{status:first===null?'PASS':'FAIL',first_failure_event:first};}
function expectedTimelineDifferences(A,B){let first=null,count=0,rows=[];const n=Math.max(A.events.length,B.events.length);for(let i=0;i<n;i++){const a=A.events[i],b=B.events[i],same=!!a&&!!b&&a.kind===b.kind&&canonicalise(a.payload)===canonicalise(b.payload);if(!same){count++;if(first===null)first=i+1;rows.push({seq:i+1,run_a:a?{kind:a.kind,payload:a.payload}:null,run_b:b?{kind:b.kind,payload:b.payload}:null});}}return{first,count,rows};}
async function validateTimeline(artifact,derived){
  exactKeys(artifact,['run_a','run_b','diff','verification_note'],'TimelineDiff artefact');
  if(artifact.verification_note!==NOTE_TIMELINE)throw new Error('TimelineDiff verification note mismatch');
  timelineRun(artifact.run_a,'A');timelineRun(artifact.run_b,'B');
  const diff=object(artifact.diff,'TimelineDiff report');
  exactKeys(diff,['format','verification_scope','verification_status','run_a','run_b','run_integrity','first_divergence','differing_events','differences'],'TimelineDiff report');
  if(diff.format!=='rftsystems4ai-browser-diff-v1'||diff.verification_scope!=='behavioural-diff-with-current-internal-chain-status')throw new Error('TimelineDiff report scope mismatch');
  if(diff.run_a!==artifact.run_a.session_id||diff.run_b!==artifact.run_b.session_id)throw new Error('TimelineDiff report run binding mismatch');
  exactKeys(diff.run_integrity,['run_a','run_b'],'TimelineDiff run_integrity');
  exactKeys(diff.run_integrity.run_a,['status','first_failure_event'],'TimelineDiff run A integrity');
  exactKeys(diff.run_integrity.run_b,['status','first_failure_event'],'TimelineDiff run B integrity');
  const expected=expectedTimelineDifferences(artifact.run_a,artifact.run_b);
  if(diff.first_divergence!==expected.first||diff.differing_events!==expected.count)throw new Error('TimelineDiff summary does not match independent behavioural recomputation');
  exact(diff.differences,expected.rows,'TimelineDiff difference rows');
  if(diff.verification_status!==derived.verdict)throw new Error('TimelineDiff embedded verification status mismatch');
  const aIntegrity=await timelineIntegrity(artifact.run_a),bIntegrity=await timelineIntegrity(artifact.run_b);
  exact(diff.run_integrity.run_a,aIntegrity,'TimelineDiff run A integrity result');
  exact(diff.run_integrity.run_b,bIntegrity,'TimelineDiff run B integrity result');
  if((aIntegrity.status==='PASS')!==derived.run_a_chain_consistent||(bIntegrity.status==='PASS')!==derived.run_b_chain_consistent)throw new Error('TimelineDiff independent integrity engines disagree');
}

function validateChallenge(artifact,derived){
  exactKeys(artifact,['challenge','scope','attack','verification_status','baseline_root','sealed_commitments','current_events'],'Falsification Challenge artefact');
  if(artifact.challenge!=='RFTSystems4Ai Falsification Challenge 001'||artifact.scope!=='public browser SHA-256 event-chain integrity only')throw new Error('Falsification Challenge identity/scope mismatch');
  if(artifact.verification_status!==derived.verdict)throw new Error('Falsification Challenge embedded verdict mismatch');
  eventKeys(artifact.current_events,['seq','type','payload'],'Falsification Challenge event');
}

function validateTrustStack(artifact,derived){
  exactKeys(artifact,['format','packet_state','packet','decision'],'TrustStack artefact');
  const packet=object(artifact.packet,'TrustStack packet');
  allowedKeys(packet,['name','payload','stored_hash','key_id','signature','scope'],['presented_public_key'],'TrustStack packet');
  exactKeys(artifact.decision,['verdict','scope'],'TrustStack decision');
  if(artifact.decision.verdict!==derived.verdict)throw new Error('TrustStack embedded verdict mismatch');
  const expectations={
    signed:{name:'Signed + intact',packetScope:'signed-evidence',decisionScope:'Integrity + trusted-key signature verified',presented:false},
    legacy:{name:'Legacy + intact',packetScope:'integrity-only',decisionScope:'Integrity only · no signature',presented:false},
    tampered:{name:'Signed + altered',packetScope:'signed-evidence',decisionScope:'Payload commitment failed.',presented:false},
    substituted:{name:'Self-signed + untrusted key',packetScope:'signed-evidence',decisionScope:'Signer is not in the verifier trust store',presented:true}
  };
  const expected=expectations[artifact.packet_state];if(!expected)throw new Error('TrustStack packet state is outside the public contract');
  if(packet.name!==expected.name||packet.scope!==expected.packetScope)throw new Error('TrustStack packet label/scope mismatch');
  if(('presented_public_key'in packet)!==expected.presented)throw new Error('TrustStack presented-key field mismatch');
  if(artifact.decision.scope!==expected.decisionScope)throw new Error('TrustStack embedded decision scope mismatch');
}

export async function verifyDemoBundle(bundle){
  validateEnvelope(bundle);
  const result=await verifyCryptographicBundle(bundle);
  const artifact=object(bundle.artifact,'artefact');
  if(result.surface_id==='agent-flight-recorder')validateFlight(artifact);
  else if(result.surface_id==='memory-receipt')await validateMemory(artifact,bundle.official_release.release_core.contracts['memory-receipt']);
  else if(result.surface_id==='timelinediff')await validateTimeline(artifact,result.derived);
  else if(result.surface_id==='falsification-001')validateChallenge(artifact,result.derived);
  else if(result.surface_id==='truststack')validateTrustStack(artifact,result.derived);
  else throw new Error('Unsupported public demonstration surface');
  return result;
}
