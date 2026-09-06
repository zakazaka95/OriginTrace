# OriginTrace

OriginTrace is a GenLayer Intelligent Contract that creates an on-chain provenance receipt for a specific Python package release. The current source version is `1.1.0`.

A requester locks three facts: the PyPI package, the exact version, and the expected GitHub repository. Independent validators then read the live PyPI release metadata and the PyPI Integrity API for every release file. The contract records one narrow result:

- `VERIFIED`: PyPI metadata links to the expected repository, every inspected file exposes provenance, and every attested publisher repository matches.
- `PROVENANCE_GAP`: no conflicting publisher was found, but provenance or repository linkage is incomplete.
- `IDENTITY_MISMATCH`: release metadata or an attested publisher points to another repository.
- `UNREADABLE`: required evidence could not be read. Three attempts are allowed before `UNREADABLE_FINAL`.

`VERIFIED` is a provenance statement, not a malware scan and not a claim that the project is trustworthy. The receipt only describes the exact PyPI release and expected repository evaluated at the recorded time.

## Why GenLayer

The relevant evidence lives across changing public APIs and must be interpreted as one release identity. A leader proposes only the classification. The complete receipt is then built deterministically from the fetched evidence. Validators independently refetch the same PyPI metadata and every per-file provenance record, rebuild the receipt, and require exact canonical equality across the entire payload before state can change.

## Contract design

- Exact package, version, repository, and request hash are locked before evaluation.
- At most eight release files are inspected; truncation prevents `VERIFIED`.
- Conflicting attested publisher identities deterministically require `IDENTITY_MISMATCH`.
- Missing and temporarily unreadable evidence are distinct outcomes.
- Retries are bounded and final decisions cannot be overwritten.
- Accepted receipts include the complete normalized evidence and derived facts, including every file hash, provenance URL/status, release status, truncation flag, publisher repository, and evidence snapshot hash.
- The validator compares the entire consequential receipt payload, so a leader cannot persist different evidence than validators fetched.

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
- Current v1.1.0 deployment: [`0xC977BF8Bb668fa6AC238e26B0c46109eaD5CEF18`](https://explorer-bradbury.genlayer.com/address/0xC977BF8Bb668fa6AC238e26B0c46109eaD5CEF18)
- Deployment transaction: [`0x869e35...cf217`](https://explorer-bradbury.genlayer.com/tx/0x869e35cce40c23bedd0a75aac74dc18d7f5a131fcbad3f9660503e497dbcf217)
- `VERIFIED` evaluation: [`0x62f428...7e1df`](https://explorer-bradbury.genlayer.com/tx/0x62f428cd121818ae804c4819234a483a9798b2a938b7ed105c381839fc97e1df)
- Rejected v1.0.5 deployment: `0x49bD8511b1746AeCA391C118cC72ABa274092714` (do not resubmit)
- Legacy diagnostic deployment: `0x0217CA3237650072a73548194eD886923d907bC1` (do not submit)

The tracked `OriginTrace.py` file is the submitted source for the deployment.
