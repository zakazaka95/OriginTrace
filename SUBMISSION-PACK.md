# Portal submission

## Title

OriginTrace — Consensus-Sealed Software Release Provenance

## Description

OriginTrace is a reusable GenLayer primitive that seals the provenance of an exact Python package release. A requester locks a PyPI package, version and expected GitHub repository. Independent validators fetch the live PyPI release record and Integrity API provenance for every release file, then agree on VERIFIED, PROVENANCE_GAP, IDENTITY_MISMATCH or UNREADABLE. Deterministic guards prevent VERIFIED when files are truncated, provenance is missing, evidence cannot be read, or an attested publisher conflicts. Receipts store the request hash, source snapshot hash, file digests, provenance URLs and observed publisher repositories. Retries are bounded and final results cannot be overwritten. VERIFIED only confirms the scoped publishing identity; it never claims the package is safe or malware-free. The repository includes tracked source and reproducible tests for matching and conflicting identities.

## Required evidence

1. GitHub Repository
2. Direct tracked `OriginTrace.py` URL as additional source evidence
3. GenLayer Explorer Contract address URL using `/address/0x...`
4. Accepted evaluation transaction as optional extra evidence

Do not rely on a Studio import link as the only source evidence.

## Bradbury deployment

- Current v1.0.5 contract: `0x49bD8511b1746AeCA391C118cC72ABa274092714`
- Explorer contract: https://explorer-bradbury.genlayer.com/address/0x49bD8511b1746AeCA391C118cC72ABa274092714
- Studio import: https://studio.genlayer.com/?import-contract=0x49bD8511b1746AeCA391C118cC72ABa274092714
- `VERIFIED` evaluation transaction: https://explorer-bradbury.genlayer.com/tx/0xaafd26b02bc7e5b11eeccaa0346fdd4cfaafa86cad90d0b2cce3eb57dbc6cfcb

Do not submit the legacy v1.0.0 through v1.0.3 diagnostic deployments.
