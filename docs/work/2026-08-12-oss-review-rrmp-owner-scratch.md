# OSS review: RRMP durable scratch ownership

Date: 2026-08-12

## Scope

The RRMP durable bundle export buffer (307,200 bytes) and piece buffer
(61,440 bytes) are now part of each caller-owned RRMP workspace.  The Host
process globals and the ESP lazy heap allocation were removed.  Public API,
wire encoding, storage keys, and promotion state are unchanged.

The route-page slot staging buffer now reuses the existing owner-local
4,096-byte encode workspace instead of a function-static 4,064-byte array.
Every exit clears that staging buffer.  The SHA-256 provider still runs the
NIST empty/`abc` KAT fail-closed, but no longer stores the result in a mutable
process-global cache.  These changes keep the measured owner size unchanged.

The exact measured Host workspace is 756,688 bytes and remains below the
786,432-byte private budget.  The HIL schema and evidence arithmetic count the
two buffers once, inside that workspace; worst-case live dynamic memory is the
workspace plus the 307,456-byte target smoke store, or 1,064,144 bytes.

## Verification

- RRMP codec, storage atomicity, and Fabric two-instance tests: PASS.
- The storage atomicity fixture interrupts owner A's CAS callback with a full
  owner B commit against a separate store, then verifies both routes.  This
  makes the former process-global scratch implementation fail by coherent
  cross-owner overwrite.
- The same fixture checks every byte of both caller workspaces is zero after
  `ninlil_rrmp_owner_fini`.
- Fresh ASan/UBSan storage-atomicity execution: PASS.
- RRMP DRAM authority check and self-test: PASS (`workspace=756688`,
  `worst_case=1064144`).
- The resource gate rejects a renamed function-static scratch, a renamed
  function-static KAT cache, their column-zero file-static equivalents, route
  scratch detached from the active owner, and every mutable file-static object
  in the checked RRMP core/provider sources. The former exact `g_bound`
  exception was removed by the serial-domain closure recorded separately.
- Fresh normal and ASan/UBSan codec, storage-atomicity, and Fabric two-owner
  isolation tests: 3/3 PASS in each profile after the route/KAT changes.
- `python3 -B -m tools.ninlil_hil self-test`: PASS after schema/arithmetic
  synchronization.

## Nonclaims

This record closes the RRMP durable/route scratch and SHA KAT-cache parts of
OR-21. The initially separate serial-domain finding is closed by
`2026-08-12-oss-review-rrmp-serial-owner.md`; MFDT and R7 have their own owner
state records. No physical RF/HIL execution or ESP runtime PSRAM measurement
is claimed here.
