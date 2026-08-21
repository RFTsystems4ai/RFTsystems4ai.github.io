window.RFTDemoBundle=Object.freeze({
  async build(surfaceId,artifact,reportedVerdict){
    if(!window.RFT_OFFICIAL_RELEASE)throw new Error('Signed RFTSystems4Ai demo release is unavailable');
    const canonical=value=>{if(value===null)return'null';if(typeof value==='string')return JSON.stringify(value);if(typeof value==='boolean')return value?'true':'false';if(typeof value==='number')return JSON.stringify(value);if(Array.isArray(value))return`[${value.map(canonical).join(',')}]`;const keys=Object.keys(value).sort();return`{${keys.map(k=>`${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;};
    const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(artifact)));
    const artifactSha256=[...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');
    return{
      spec:'rftsystems4ai-demo-receipt-bundle-1.0',
      surface_id:surfaceId,
      artifact,
      rftsystems4ai_demo_receipt:{
        spec:'rftsystems4ai-demo-receipt-1.0',
        issuer:'RFTSystems4Ai',
        surface_id:surfaceId,
        release_id:window.RFT_OFFICIAL_RELEASE.release_core.release_id,
        reported_verdict:reportedVerdict,
        artifact_sha256:artifactSha256,
        downloaded_at_utc:new Date().toISOString(),
        timestamp_basis:'UTC rendered from the local browser device clock for download traceability; the official release UTC is separately authenticated by the RFTSystems4Ai Ed25519 release signature.',
        legal_identity:'RFTSystems4Ai is a trading name of Liam S Grinstead, sole trader.',
        copyright:'© 2026 Liam S Grinstead. All rights reserved.'
      },
      official_release:window.RFT_OFFICIAL_RELEASE
    };
  }
});
