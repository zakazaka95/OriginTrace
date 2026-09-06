# Portal submission

## Title

OriginTrace — Consensus-Sealed Software Release Provenance

## Description

OriginTrace is a reusable GenLayer primitive that seals the provenance of an exact Python package release. A requester locks a PyPI package, version and expected GitHub repository. Independent validators fetch the live PyPI release record and Integrity API provenance for every release file, then agree on VERIFIED, PROVENANCE_GAP, IDENTITY_MISMATCH or UNREADABLE. The full receipt is deterministically rebuilt by every validator and accepted only when its complete canonical payload matches, including each file digest, provenance URL/status, release status, truncation flag, publisher identity and derived count. This prevents a leader from persisting evidence different from what validators fetched. Retries are bounded and final results cannot be overwritten. VERIFIED confirms only the scoped publishing identity, never package safety. Tracked source and tamper tests document the primitive.

## Required evidence

1. GitHub Repository
2. Direct tracked `OriginTrace.py` URL as additional source evidence
3. GenLayer Explorer Contract address URL using `/address/0x...`
4. Accepted evaluation transaction as optional extra evidence

Do not rely on a Studio import link as the only source evidence.

## Bradbury deployment

- Current v1.1.0 contract: https://explorer-bradbury.genlayer.com/address/0xC977BF8Bb668fa6AC238e26B0c46109eaD5CEF18
- Deployment transaction: https://explorer-bradbury.genlayer.com/tx/0x869e35cce40c23bedd0a75aac74dc18d7f5a131fcbad3f9660503e497dbcf217
- Accepted `VERIFIED` evaluation: https://explorer-bradbury.genlayer.com/tx/0x62f428cd121818ae804c4819234a483a9798b2a938b7ed105c381839fc97e1df

Do not resubmit the rejected v1.0.5 address or the legacy v1.0.0 through v1.0.3 diagnostic deployments.
