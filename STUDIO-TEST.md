# OriginTrace Studio test

Deploy `OriginTrace.py` as a new instance on Bradbury. Use Accepted state for all reads.

Verified v1.0.5 deployment: `0x49bD8511b1746AeCA391C118cC72ABa274092714`

Accepted `VERIFIED` transaction: `0xaafd26b02bc7e5b11eeccaa0346fdd4cfaafa86cad90d0b2cce3eb57dbc6cfcb`

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

Expected final result: `VERIFIED`. The receipt should show two release files, two attested files, and publisher repository `pypa/sampleproject`.

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
- Matching and conflicting identities produce different final receipts.
- Only accepted contract state is treated as the result.
