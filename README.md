# OriginTrace

OriginTrace is a GenLayer Intelligent Contract that creates an on-chain provenance receipt for a specific Python package release. The current source version is `1.0.5`.

A requester locks three facts: the PyPI package, the exact version, and the expected GitHub repository. Independent validators then read the live PyPI release metadata and the PyPI Integrity API for every release file. The contract records one narrow result:

- `VERIFIED`: PyPI metadata links to the expected repository, every inspected file exposes provenance, and every attested publisher repository matches.
- `PROVENANCE_GAP`: no conflicting publisher was found, but provenance or repository linkage is incomplete.
- `IDENTITY_MISMATCH`: release metadata or an attested publisher points to another repository.
- `UNREADABLE`: required evidence could not be read. Three attempts are allowed before `UNREADABLE_FINAL`.

`VERIFIED` is a provenance statement, not a malware scan and not a claim that the project is trustworthy. The receipt only describes the exact PyPI release and expected repository evaluated at the recorded time.

## Why GenLayer

The relevant evidence lives across changing public APIs and must be interpreted as one release identity. A leader proposes a normalized receipt. Validators independently refetch the same PyPI metadata and per-file provenance, reproduce the classification, and compare the decision plus the objective evidence snapshot. State changes only after consensus.

## Contract design

- Exact package, version, repository, and request hash are locked before evaluation.
- At most eight release files are inspected; truncation prevents `VERIFIED`.
- Conflicting attested publisher identities deterministically require `IDENTITY_MISMATCH`.
- Missing and temporarily unreadable evidence are distinct outcomes.
- Retries are bounded and final decisions cannot be overwritten.
- Accepted receipts include file hashes, provenance URLs, publisher repositories, and an evidence snapshot hash.

## Public methods

### Write

- `open_check(package, version, expected_repository)`
- `evaluate_release(check_id)`

### Read

- `get_check(check_id)`
- `get_recent_checks(limit)`
- `get_stats()`

## Reproducible demo

The complete Bradbury test sequence is in [STUDIO-TEST.md](./STUDIO-TEST.md). Local deterministic tests are in `test_origintrace.py`.

Run locally:

```bash
python -m unittest test_origintrace.py
```

## Authoritative sources

- [PyPI JSON API](https://docs.pypi.org/api/json/)
- [PyPI Integrity API](https://docs.pypi.org/api/integrity/)
- [PyPI attestation verification guidance](https://docs.pypi.org/attestations/consuming-attestations/)
- [GenLayer Equivalence Principle](https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle)

## Deployment

- Network: GenLayer Bradbury Testnet
- Current v1.0.5 contract: `0x49bD8511b1746AeCA391C118cC72ABa274092714`
- Explorer contract: https://explorer-bradbury.genlayer.com/address/0x49bD8511b1746AeCA391C118cC72ABa274092714
- Studio import: https://studio.genlayer.com/?import-contract=0x49bD8511b1746AeCA391C118cC72ABa274092714
- Verified evaluation: https://explorer-bradbury.genlayer.com/tx/0xaafd26b02bc7e5b11eeccaa0346fdd4cfaafa86cad90d0b2cce3eb57dbc6cfcb
- Legacy diagnostic deployment: `0x0217CA3237650072a73548194eD886923d907bC1` (do not submit)

The tracked `OriginTrace.py` file is the submitted source for the deployment.
