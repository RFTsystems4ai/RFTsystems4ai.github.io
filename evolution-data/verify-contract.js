import { verifyEvolutionBundle as verifyCryptographicBundle } from './verify-crypto.js';

const LEGAL_IDENTITY='RFTSystems4Ai is a trading name of Liam S Grinstead, sole trader.';
const COPYRIGHT='© 2026 Liam S Grinstead. All rights reserved.';
const LOCAL_TIMESTAMP_BASIS='UTC rendered from the local browser device clock for download traceability; the official Evolution Data release UTC is separately authenticated by the RFTSystems4Ai Ed25519 release signature.';

function object(value,label){if(!value||typeof value!=='object'||Array.isArray(value))throw new Error(`${label} must be an object`);return value;}
function exactKeys(value,keys,label){object(value,label);const got=Object.keys(value).sort(),want=[...keys].sort();if(got.length!==want.length||got.some((k,i)=>k!==want[i]))throw new Error(`${label} contains missing or unauthorised fields`);}
function validLocalUtc(value){return typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)&&Number.isFinite(Date.parse(value));}

export async function verifyEvolutionBundle(bundle){
  exactKeys(bundle,['spec','surface_id','artifact','rftsystems4ai_demo_receipt','official_release'],'Evolution Data bundle');
  exactKeys(bundle.official_release,['release_core','signature'],'Evolution Data official_release');
  exactKeys(bundle.artifact,['dataset','result'],'Evolution Data artefact');
  const receipt=object(bundle.rftsystems4ai_demo_receipt,'Evolution Data receipt');
  exactKeys(receipt,['spec','issuer','surface_id','release_id','reported_verdict','artifact_sha256','downloaded_at_utc','timestamp_basis','legal_identity','copyright'],'Evolution Data receipt');
  const signedIssuer=bundle.official_release?.release_core?.issuer;
  if(receipt.issuer!=='RFTSystems4Ai'||receipt.legal_identity!==LEGAL_IDENTITY||receipt.copyright!==COPYRIGHT)throw new Error('Evolution Data receipt issuer/footer identity mismatch');
  if(signedIssuer?.name!=='RFTSystems4Ai'||signedIssuer?.legal_identity!==LEGAL_IDENTITY||signedIssuer?.copyright!==COPYRIGHT)throw new Error('Evolution Data signed issuer/footer identity mismatch');
  if(receipt.timestamp_basis!==LOCAL_TIMESTAMP_BASIS)throw new Error('Evolution Data local timestamp trust-boundary wording mismatch');
  if(!validLocalUtc(receipt.downloaded_at_utc))throw new Error('Evolution Data local download UTC is malformed');
  return verifyCryptographicBundle(bundle);
}
