# V1-LAB namespace export and Domain cutover

`tools/ninlil_lab_export.py` exports an offline POSIX SQLite V1-LAB namespace
as the exact ADR-0022 `NLEXP001` evidence artifact. It does not import,
rewrite, delete, or infer Domain records.

This separation is deliberate. Legacy service markers do not contain enough
durable information to reconstruct descriptor, quota-window, callback, and
effect truth without guessing. A safe cutover therefore uses a new empty
namespace.

## Preconditions

- Stop every Runtime/process using the SQLite database.
- Keep the source database and its adjacent `.ninlil-sqlite-*.lock` file on a
  local POSIX filesystem.
- Identify the exact source namespace bytes and provider configuration bytes.
- Choose an output path that does not exist. The tool never overwrites it.

The exporter acquires the same inode-keyed exclusive sidecar lock as the
POSIX provider. If the provider is still active, export fails with
`BUSY/SOURCE_PROVIDER_ACTIVE`. SQLite is opened with `mode=ro` and
`query_only=ON`; schema validation, two-pass row count/emission, and
lexicographic iteration use one READ_ONLY transaction.

## Export

```bash
python3 tools/ninlil_lab_export.py export \
  --database /absolute/path/runtime.sqlite3 \
  --namespace-hex 736974652d303031 \
  --provider-config-hex 706f7369782d7631 \
  --output /absolute/path/site-001.nlexp
```

The command prints compact JSON containing the namespace, record count,
content digest, and whole-artifact SHA-256. Record that output in the
operator reconciliation manifest.

## Independent verification

```bash
python3 tools/ninlil_lab_export.py verify \
  --artifact /absolute/path/site-001.nlexp \
  --provider-kind 1 \
  --provider-schema 1 \
  --provider-config-hex 706f7369782d7631
```

Verification is streaming and fail-closed for truncation, missing completion,
extra bytes, row order/length/reserved violations, provider mismatch, and
row/content digest mismatch.

## Explicit cutover

1. Verify the completed artifact and its manifest SHA-256.
2. Reconcile inflight work with the authoritative application/operator.
3. Configure a different namespace known to contain zero rows.
4. Bootstrap that namespace as Domain format 2.
5. Re-register services through the public API and submit required work as new
   logical work.
6. Archive or delete the LAB source only under a separate operator
   authorization.

Never point Domain Runtime at the LAB namespace, copy legacy rows into the new
namespace, or treat a successful export as proof that work was imported.
