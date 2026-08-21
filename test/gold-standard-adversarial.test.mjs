import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { verifyDemoBundle } from '../lab/official-receipt-verifier/verify-contract.js';
import { canonicalise, sha256Hex } from '../lab/official-receipt-verifier/receipt-crypto.js';
import { verifyEvolutionBundle } from '../evolution-data/verify-contract.js';
import { recomputeResult } from '../evolution-data/verify-crypto.js';

const root = path.resolve(new URL('..', import.meta.url).pathname);
const LEGAL = 'RFTSystems4Ai is a trading name of Liam S Grinstead, sole trader.';
const COPYRIGHT = '© 2026 Liam S Grinstead. All rights reserved.';
const LOCAL_BASIS = 'UTC rendered from the local browser device clock for download traceability; the official release UTC is separately authenticated by the RFTSystems4Ai Ed25519 release signature.';
const EVOLUTION_LOCAL_BASIS = 'UTC rendered from the local browser device clock for download traceability; the official Evolution Data release UTC is separately authenticated by the RFTSystems4Ai Ed25519 release signature.';
const TRUST = { external_anchor_present:false, external_anchor_verified:false, signer_identity_verified:false };

function clone(value) { return structuredClone(value); }
function loadWindow(file, key) {
  const source = fs.readFileSync(path.join(root, file), 'utf8');
  const context = { window:{} };
  vm.createContext(context);
  vm.runInContext(source, context, { filename:file });
  return clone(context.window[key]);
}

async function makeBundle(surface, artifact, verdict, release) {
  return {
    spec:'rftsystems4ai-demo-receipt-bundle-1.0',
    surface_id:surface,
    artifact,
    rftsystems4ai_demo_receipt:{
      spec:'rftsystems4ai-demo-receipt-1.0', issuer:'RFTSystems4Ai', surface_id:surface,
      release_id:release.release_core.release_id, reported_verdict:verdict,
      artifact_sha256:await sha256Hex(canonicalise(artifact)),
      downloaded_at_utc:'2026-08-21T14:30:00.000Z', timestamp_basis:LOCAL_BASIS,
      legal_identity:LEGAL, copyright:COPYRIGHT
    },
    official_release:release
  };
}

async function makeEvolutionBundle(artifact, release) {
  return {
    spec:'rftsystems4ai-evolution-demo-receipt-bundle-1.0',
    surface_id:'evolution-data-decision-field',
    artifact,
    rftsystems4ai_demo_receipt:{
      spec:'rftsystems4ai-evolution-demo-receipt-1.0', issuer:'RFTSystems4Ai',
      surface_id:'evolution-data-decision-field', release_id:release.release_core.release_id,
      reported_verdict:'PASS', artifact_sha256:await sha256Hex(canonicalise(artifact)),
      downloaded_at_utc:'2026-08-21T14:31:00.000Z', timestamp_basis:EVOLUTION_LOCAL_BASIS,
      legal_identity:LEGAL, copyright:COPYRIGHT
    },
    official_release:release
  };
}

async function makeFlight(contract) {
  const session_id='afr-gold-001';
  let prev='0'.repeat(64); const events=[];
  for (let i=0;i<contract.seed.length;i++) {
    const [event_type,payload] = contract.seed[i];
    const core={session_id,seq:i+1,event_type,payload:clone(payload),prev_hash:prev};
    const event_hash=await sha256Hex(canonicalise(core));
    events.push({...core,event_hash}); prev=event_hash;
  }
  return {format:'rftsystems4ai-browser-flight-record-v1',scope:'internal-sha256-chain-consistency-demo',session_id,events,final_anchor:prev,trust_boundary:clone(TRUST),verification_note:'This artefact is independently re-checkable against the Ed25519-signed RFTSystems4Ai demo release contract bundled with the download.'};
}

async function makeMemory(contract, question='deployment_state') {
  let prev='0'.repeat(64); const ledger=[];
  for (let i=0;i<contract.baseline_rows.length;i++) {
    const [key,value]=contract.baseline_rows[i];
    const core={seq:i+1,key,value,prev_hash:prev};
    const event_hash=await sha256Hex(canonicalise(core));
    ledger.push({...core,event_hash}); prev=event_hash;
  }
  const q=contract.questions[question], event=ledger[q.seq-1];
  const evidence={event_seq:event.seq,key:event.key,value:event.value,event_hash:event.event_hash};
  const memory_hash=await sha256Hex(canonicalise(evidence));
  const answer_hash=await sha256Hex(q.answer);
  const receiptCore={format:'rftsystems4ai-browser-memory-receipt-v1',scope:'internal-sha256-evidence-binding-demo',question,evidence,memory_hash,answer:q.answer,answer_hash};
  const receipt_hash=await sha256Hex(canonicalise(receiptCore));
  return {ledger,receipt:{...receiptCore,receipt_hash,trust_boundary:clone(TRUST)},verification_note:'The complete ledger and receipt are bundled so the signed-release verifier can recompute the current chain and evidence binding independently.'};
}

async function makeTimelineRun(seed,label) {
  const session_id=`td-${label}-gold-001`;
  let prev='0'.repeat(64); const events=[];
  for (let i=0;i<seed.length;i++) {
    const [kind,payload]=seed[i];
    const core={session_id,seq:i+1,kind,payload:clone(payload),prev_hash:prev};
    const event_hash=await sha256Hex(canonicalise(core));
    events.push({...core,event_hash}); prev=event_hash;
  }
  return {format:'rftsystems4ai-browser-timeline-v1',scope:'internal-sha256-timeline-consistency-demo',session_id,label,events,final_anchor:prev,trust_boundary:clone(TRUST)};
}

async function timelineIntegrity(run) {
  let prev='0'.repeat(64), first=null;
  for (const event of run.events) {
    const core={session_id:event.session_id,seq:event.seq,kind:event.kind,payload:event.payload,prev_hash:prev};
    const hash=await sha256Hex(canonicalise(core));
    if (first===null && (event.prev_hash!==prev || event.event_hash!==hash)) first=event.seq;
    prev=hash;
  }
  if (first===null && run.final_anchor!==prev) first=run.events.length;
  return {status:first===null?'PASS':'FAIL',first_failure_event:first};
}

function timelineDiff(A,B) {
  let first=null,count=0; const differences=[];
  for (let i=0;i<Math.max(A.events.length,B.events.length);i++) {
    const a=A.events[i], b=B.events[i];
    const same=!!a&&!!b&&a.kind===b.kind&&canonicalise(a.payload)===canonicalise(b.payload);
    if (!same) {
      count++; if (first===null) first=i+1;
      differences.push({seq:i+1,run_a:a?{kind:a.kind,payload:a.payload}:null,run_b:b?{kind:b.kind,payload:b.payload}:null});
    }
  }
  return {first,count,differences};
}

async function makeTimeline(contract, A=null, B=null) {
  A ??= await makeTimelineRun(contract.run_a_seed,'A');
  B ??= await makeTimelineRun(contract.run_b_seed,'B');
  const a=await timelineIntegrity(A), b=await timelineIntegrity(B), d=timelineDiff(A,B);
  const verification_status=a.status==='PASS'&&b.status==='PASS'?'PASS':'FAIL';
  return {run_a:A,run_b:B,diff:{format:'rftsystems4ai-browser-diff-v1',verification_scope:'behavioural-diff-with-current-internal-chain-status',verification_status,run_a:A.session_id,run_b:B.session_id,run_integrity:{run_a:a,run_b:b},first_divergence:d.first,differing_events:d.count,differences:d.differences},verification_note:'Both complete timelines are bundled so the authenticated release verifier can derive chain state and first behavioural divergence independently.'};
}

async function makeChallenge(contract, attack) {
  const baseline=clone(contract.baseline_events);
  const hashes=async events=>{let prev='0'.repeat(64);const out=[];for(const e of events){const h=await sha256Hex(prev+JSON.stringify({seq:e.seq,type:e.type,payload:e.payload}));out.push(h);prev=h;}return out;};
  const sealed=await hashes(baseline), events=clone(baseline);
  if (attack==='modify') events[3].payload='audit_mode = permissive';
  if (attack==='remove') events.splice(2,1);
  if (attack==='reorder') [events[1],events[2]]=[events[2],events[1]];
  if (attack==='inject') events.splice(3,0,{seq:99,type:'INJECTED_EVENT',payload:'unrecorded action'});
  const computed=await hashes(events); let first=null;
  for(let i=0;i<Math.max(sealed.length,computed.length);i++) if(sealed[i]!==computed[i]){first=i+1;break;}
  const verdict=first===null&&computed.length===sealed.length&&computed.at(-1)===sealed.at(-1)?'PASS':'FAIL';
  return {artifact:{challenge:'RFTSystems4Ai Falsification Challenge 001',scope:'public browser SHA-256 event-chain integrity only',attack,verification_status:verdict,baseline_root:sealed.at(-1),sealed_commitments:sealed,current_events:events},verdict};
}

const verificationRelease=loadWindow('assets/official-release.js','RFT_OFFICIAL_RELEASE');
const evolutionRelease=loadWindow('evolution-data/official-release.js','RFT_EVOLUTION_RELEASE');
const evolutionData=loadWindow('evolution-data/data.js','EVOLUTION_DEMO_DATA');

test('builder: Flight Recorder PASS and controlled FAIL are independently reproducible', async()=>{
  const contract=verificationRelease.release_core.contracts['agent-flight-recorder'];
  const passArtifact=await makeFlight(contract);
  const pass=await makeBundle('agent-flight-recorder',passArtifact,'PASS',clone(verificationRelease));
  assert.equal((await verifyDemoBundle(pass)).derived.verdict,'PASS');
  const failArtifact=clone(passArtifact); failArtifact.events[3].payload.value=contract.controlled_failures.event_4_memory_value;
  const fail=await makeBundle('agent-flight-recorder',failArtifact,'FAIL',clone(verificationRelease));
  assert.equal((await verifyDemoBundle(fail)).derived.verdict,'FAIL');
});

test('security: recomputing local hashes cannot smuggle a stronger Flight Recorder claim', async()=>{
  const contract=verificationRelease.release_core.contracts['agent-flight-recorder'];
  const scoped=await makeFlight(contract); scoped.scope='proof-of-factual-truth';
  await assert.rejects(async()=>verifyDemoBundle(await makeBundle('agent-flight-recorder',scoped,'PASS',clone(verificationRelease))),/scope mismatch/);
  const extra=await makeFlight(contract); extra.assertion='RFTSystems4Ai certifies this real-world claim';
  await assert.rejects(async()=>verifyDemoBundle(await makeBundle('agent-flight-recorder',extra,'PASS',clone(verificationRelease))),/unauthorised fields/);
});

test('memory: original binding passes and controlled post-receipt alteration remains a portable FAIL', async()=>{
  const contract=verificationRelease.release_core.contracts['memory-receipt'];
  const passArtifact=await makeMemory(contract);
  assert.equal((await verifyDemoBundle(await makeBundle('memory-receipt',passArtifact,'PASS',clone(verificationRelease)))).derived.verdict,'PASS');
  const failArtifact=clone(passArtifact); failArtifact.ledger[4].value=contract.controlled_failures.deployment_state;
  assert.equal((await verifyDemoBundle(await makeBundle('memory-receipt',failArtifact,'FAIL',clone(verificationRelease)))).derived.verdict,'FAIL');
  const forged=clone(passArtifact); forged.receipt.scope='factual-truth';
  await assert.rejects(async()=>verifyDemoBundle(await makeBundle('memory-receipt',forged,'PASS',clone(verificationRelease))),/Reported verdict|scope mismatch|baseline receipt/);
});

test('engineering: TimelineDiff embedded report must equal independent recomputation', async()=>{
  const contract=verificationRelease.release_core.contracts.timelinediff;
  const artifact=await makeTimeline(contract);
  const good=await makeBundle('timelinediff',artifact,'PASS',clone(verificationRelease));
  assert.equal((await verifyDemoBundle(good)).derived.first_divergence,4);
  const forged=clone(artifact); forged.diff.first_divergence=1;
  await assert.rejects(async()=>verifyDemoBundle(await makeBundle('timelinediff',forged,'PASS',clone(verificationRelease))),/summary does not match/);
  const B=clone(artifact.run_b); B.events[2].payload.service='orders-api';
  const failArtifact=await makeTimeline(contract,clone(artifact.run_a),B);
  assert.equal((await verifyDemoBundle(await makeBundle('timelinediff',failArtifact,'FAIL',clone(verificationRelease)))).derived.verdict,'FAIL');
  const falseMarker=clone(failArtifact); falseMarker.diff.run_integrity.run_b.first_failure_event=99;
  await assert.rejects(async()=>verifyDemoBundle(await makeBundle('timelinediff',falseMarker,'FAIL',clone(verificationRelease))),/integrity result/);
});

test('falsification: recognised mutation exports FAIL but extra semantic claims are rejected', async()=>{
  const contract=verificationRelease.release_core.contracts['falsification-001'];
  const {artifact,verdict}=await makeChallenge(contract,'modify');
  const good=await makeBundle('falsification-001',artifact,verdict,clone(verificationRelease));
  assert.equal((await verifyDemoBundle(good)).derived.verdict,'FAIL');
  const injected=clone(artifact); injected.claim='this proves external factual truth';
  await assert.rejects(async()=>verifyDemoBundle(await makeBundle('falsification-001',injected,'FAIL',clone(verificationRelease))),/unauthorised fields/);
  const flipped=clone(good); flipped.rftsystems4ai_demo_receipt.reported_verdict='PASS';
  await assert.rejects(()=>verifyDemoBundle(flipped),/Reported verdict/);
});

test('compliance: TrustStack ALLOW, HOLD and BLOCK preserve exact public semantics', async()=>{
  const signed={name:'Signed + intact',payload:'{"anchor":"8f4b-demo-anchor","claim":"synthetic agent run integrity","run_id":"demo-allow-001","scope":"signed-evidence"}',stored_hash:'f4dad503625786906ffe7934e3e83bb7bf5cafc49a9dd4cae679b3716529ec21',key_id:'demo-rft-trust-001',signature:'fJnTHFmUAC9UeLv5k92vqAnZ9Sa6FOIozCF++Zu1RqXi0+b6kbli9OFDDPiTpuwLfQ2/lNhvADDG2GaTcSQJCQ==',scope:'signed-evidence'};
  const legacyPayload='{"claim":"legacy synthetic evidence","run_id":"demo-hold-001","scope":"integrity-only"}';
  const legacy={name:'Legacy + intact',payload:legacyPayload,stored_hash:await sha256Hex(legacyPayload),key_id:'',signature:'',scope:'integrity-only'};
  const cases=[
    ['signed',signed,'ALLOW','Integrity + trusted-key signature verified'],
    ['legacy',legacy,'HOLD','Integrity only · no signature'],
    ['tampered',{...signed,name:'Signed + altered',payload:'{"anchor":"8f4b-demo-anchor","claim":"ALTERED agent run integrity","run_id":"demo-allow-001","scope":"signed-evidence"}'},'BLOCK','Payload commitment failed.']
  ];
  for (const [state,packet,verdict,scope] of cases) {
    const artifact={format:'rftsystems4ai-browser-truststack-decision-v1',packet_state:state,packet,decision:{verdict,scope}};
    assert.equal((await verifyDemoBundle(await makeBundle('truststack',artifact,verdict,clone(verificationRelease)))).derived.verdict,verdict);
  }
  const malicious={format:'rftsystems4ai-browser-truststack-decision-v1',packet_state:'legacy',packet:{...legacy,name:'Certified external evidence',scope:'factual-truth'},decision:{verdict:'HOLD',scope:'Integrity only · no signature'}};
  await assert.rejects(async()=>verifyDemoBundle(await makeBundle('truststack',malicious,'HOLD',clone(verificationRelease))),/label\/scope mismatch/);
});

test('enterprise: Evolution Data recomputation rejects altered results and receipt semantics', async()=>{
  const result=recomputeResult(evolutionData,'cost_reduction','full_family');
  const artifact={dataset:clone(evolutionData),result};
  const good=await makeEvolutionBundle(artifact,clone(evolutionRelease));
  assert.equal((await verifyEvolutionBundle(good)).verdict,'PASS');
  const changed=clone(artifact); changed.result.portfolio.strict_changes+=1;
  await assert.rejects(async()=>verifyEvolutionBundle(await makeEvolutionBundle(changed,clone(evolutionRelease))),/deterministic recomputation/);
  const extra=clone(good); extra.rftsystems4ai_demo_receipt.assertion='certified business saving';
  await assert.rejects(()=>verifyEvolutionBundle(extra),/unauthorised fields/);
  const footer=clone(good); footer.rftsystems4ai_demo_receipt.legal_identity='Different issuer';
  await assert.rejects(()=>verifyEvolutionBundle(footer),/issuer\/footer identity mismatch/);
});

test('timestamp boundary: local download UTC remains traceability metadata, separate from signed release UTC', async()=>{
  const contract=verificationRelease.release_core.contracts['agent-flight-recorder'];
  const artifact=await makeFlight(contract);
  const receipt=await makeBundle('agent-flight-recorder',artifact,'PASS',clone(verificationRelease));
  receipt.rftsystems4ai_demo_receipt.downloaded_at_utc='2026-08-21T14:45:00.000Z';
  const result=await verifyDemoBundle(receipt);
  assert.equal(result.release_issued_at_utc,verificationRelease.release_core.issued_at_utc);
  assert.equal(result.downloaded_at_utc,'2026-08-21T14:45:00.000Z');
});
