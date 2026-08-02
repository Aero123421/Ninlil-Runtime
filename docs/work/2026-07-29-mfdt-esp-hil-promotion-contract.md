# MFDT ESP FULL / CU promotion contract (ADR-0021 §738–740)

**Status: Contract note — not SPEC_ACCEPTED. Not HIL PASS. Not RELEASE_SUPPORTED.**

## Rule (normative for this private candidate)

ESP format-4 / media FULL often returns `NINLIL_STORAGE_COMMIT_UNKNOWN` even when
a write was issued. ADR-0021:

> ESP format-4はpower-cut HILでFULL promotionが証明されるまでreadback一致を
> successへ昇格しない。

Split:

| Layer | Allowed | Forbidden before physical HIL |
| --- | --- | --- |
| **Raw ESP adapter** (`mfdt_v1_store_esp.c`) | Read-back classify OLD / NEW / CORRUPT; report raw NEW via `ERR_CU_NEW_NOT_PROMOTED` + `ninlil_mfdt_v1_esp_last_cu_class()`; length-probe `lab_get(NULL,…)` | Claiming wire/engine external success |
| **Engine release path** (`full_commit` in engine) | Keep `S_COMMIT_UNKNOWN` / `ERR_COMMIT_UNKNOWN` when gate OFF | Promoting CU-NEW read-back to FULL OK / wire accept |
| **HIL attestation gate** | Default **OFF** (`hil_full_promotion_enabled()==0`) | Hard-coding ON in CI / release builds |

## Gate API

Portable PRODUCTION TU: `src/runtime/mfdt_v1/mfdt_v1_hil_gate.c` (always linked
with engine; not ESP-store-only — unit/host link must not depend on
`mfdt_v1_store_esp.c` for this symbol).

- `ninlil_mfdt_v1_hil_full_promotion_enabled()` — default 0
- **No public mutable setter** (removed). Host tests cannot forge ON.
- `ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation(sealed, len)` —
  reserved target-only authority; currently does not parse any seal and always
  fails closed. A future implementation needs platform-rooted signature,
  device/build/profile binding, anti-rollback, expiry/revocation, and accepted
  physical-HIL matrix verification. Magic/non-zero bytes are not evidence.
- `ninlil_mfdt_v1_esp_last_cu_class()` / `_set(int)` — raw CU latch port hook
- Physical power-cut HIL success is the intended production enablement trigger
- This document does **not** claim that HIL has been run

## CI simultaneous proof

1. **Raw NEW classification PASS** — host mock + ESP smoke: after CU+apply media,
   `lab_full_commit` → `ERR_CU_NEW_NOT_PROMOTED`, durable get == NEW, last CU class NEW
2. **Release path NOT_PROMOTED** — gate OFF; engine `full_commit` maps
   `ERR_CU_NEW_NOT_PROMOTED` → `ERR_COMMIT_UNKNOWN` (no external success)

Map symbol presence alone is **not** completion.

## Fault injection (separate)

Host `mfdt_v1_esp_store_cu_test`: OLD retry, third/corrupt fence, 64-bit txn
width, retry without duplicate rows. Not merged into feature smoke residual pass.
