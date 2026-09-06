# OriginTrace Studio test

Deploy `OriginTrace.py` as a new instance on Bradbury. Use Accepted state for all reads.

Version under test: `1.1.0`. Deploy a new instance; do not upgrade or reuse the rejected v1.0.5 address.

## Test A: matching provenance

Call `open_check`:

```text
package: sampleproject
version: 4.0.0
expected_repository: pypa/sampleproject
```

Expected: check `#1` is `OPEN`.

Call `evaluate_release`:

```text
check_id: 1
```

Expected final result: `VERIFIED`. The receipt should show two release files under `receipt.evidence.files`, two attested files under `receipt.facts.attested_file_count`, and publisher repository `pypa/sampleproject`.

Confirm with:

```text
get_check(1)
get_stats()
```

The transaction must be `accepted` without an execution error. Save the Explorer transaction and contract-address links.

## Test B: explicit identity mismatch

Call `open_check` again:

```text
package: sampleproject
version: 4.0.0
expected_repository: pypa/pip
```

Call `evaluate_release(2)`.

Expected final result: `IDENTITY_MISMATCH`, because the locked expected repository differs from the repository in the release metadata and Trusted Publisher provenance.

## What the demo proves

- The request is locked before web access and AI interpretation.
- Validators independently inspect live PyPI evidence.
- Validators rebuild and compare the complete canonical receipt, including every per-file digest, provenance URL/status, release status, and truncation flag.
- Matching and conflicting identities produce different final receipts.
- Only accepted contract state is treated as the result.

## Accepted Bradbury proof

- Contract: [`0xC977BF8Bb668fa6AC238e26B0c46109eaD5CEF18`](https://explorer-bradbury.genlayer.com/address/0xC977BF8Bb668fa6AC238e26B0c46109eaD5CEF18)
- Deployment: [`0x869e35...cf217`](https://explorer-bradbury.genlayer.com/tx/0x869e35cce40c23bedd0a75aac74dc18d7f5a131fcbad3f9660503e497dbcf217)
- Open check: [`0x2ec2d7...a57cd`](https://explorer-bradbury.genlayer.com/tx/0x2ec2d7af26c1737c25df9126f46a0cdd97a11b56320829348b07c1ac2bca57cd)
- `VERIFIED` evaluation: [`0x62f428...7e1df`](https://explorer-bradbury.genlayer.com/tx/0x62f428cd121818ae804c4819234a483a9798b2a938b7ed105c381839fc97e1df)
