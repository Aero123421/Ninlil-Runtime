# MFDT V1 release policy (explicit)

**Status: Proposed / PROPOSED_SPEC_ONLY — not SPEC_ACCEPTED.**

## Default

| Surface | Default |
| --- | --- |
| Compile (`NINLIL_ENABLE_MFDT_V1_PRIVATE` / Kconfig) | **OFF** |
| Runtime admission (`private_mfdt_admission_v1`) | **OFF** |
| Public ABI / installed headers | **unchanged** (no MFDT symbols) |

## When default ON is allowed

Only when the current completion authority and reproducible release evidence
show every required software, target, and physical-HIL row as GREEN.  A
nonexistent or manually edited summary file is not release authority.

`ninlil_mfdt_v1_release_policy_allows_default_on()` returns 1 only under that
condition. Today the joined public software composition is incomplete and HIL
is **NOT_RUN**, so both independent pins are zero and the function returns
**0**.

## ApplicationData path

The intended API remains generic `ninlil_submit` with ApplicationData; there
is no separate product-specific transfer API.  The private candidate currently
selects and arms MFDT during admission, but the joined public path is not
complete: NTS3 logical/inline length separation, Runtime-owned MFDT scheduling,
instance-local Host/ESP ownership, Runtime Storage Port custody, and
public-submit → Fabric → peer apply/Receipt acceptance remain open.  The exact
audit is recorded in
`docs/work/2026-07-31-public-mfdt-runtime-integration-audit.md`.

Therefore this document does not claim that payloads above 926 bytes already
complete automatically through the public Runtime.

## Non-claims

- No fabricated HIL success.
- No silent Accepted NCL1 catalog pollution (private MFN1 `0x34..0x35` +
  MFDT `0x36..0x43` demux; the void allocation has no compatibility aliases).
- No RELEASE_SUPPORTED / SPEC_ACCEPTED promotion by this document alone.
