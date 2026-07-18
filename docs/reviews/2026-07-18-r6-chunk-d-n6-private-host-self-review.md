# R6 Chunk D private N6 host — self-review (final independent NO-GO delta)

Date: 2026-07-18  
**Verdict: overall R6 NOT GO.** Host candidate only. Self-test PASS ≠ GO.

## Re-audit targets (new hashes — replace snapshot h=f7473a6c / c=b2220e5d)

| path | sha256 |
| --- | --- |
| `src/radio/n6_context_store.c` | `0248e0ef0780b76e1efe23d3983ae5fb81f1f29f0976ed2223edfef7ab7e3e65` |
| `src/radio/n6_context_store.h` | `2b1489df14df0bfdc582f33f455d9f69db4836ffb63fb3a6fe8a182e54408270` |
| `tests/radio/n6_context_store_test.c` | `77923a3db02efdb914cf9595e5ac1eeb8e63974271859ed0d919a637e9956187` |
| `tests/support/n6_mem_storage.c` | `949c2c4fb5fae283b526faf914b48ae3b73e2ac1f091a5608bed54aa62672c25` |

Prior reviewer snapshot `h=f7473a6c` / `c=b2220e5d` is **superseded**. Re-audit **must** use the new hashes above.

## Frozen

- docs/25 pin `08bfdec…aa224` unchanged this pass  
- docs/24 not edited in this coding pass  
- commit/push: none  

## What changed (final NO-GO delta)

### Boot §5.3.1.5 exact equality
- Context-local join (not global count)
- AL: active_count / retired / floor / full receiver_id + fingerprint recompute
- HW joined by layer+direction; orphan HW → CORRUPT; AL with activity needs HW
- active + same-layer RT conflict → CORRUPT
- role cap = pool slot_count; duplicate complete set; cross-direction conflict
- RT last_kgen vs HW high_water
- boot rollback status checked (not ignored)

### Storage
- open: `out_handle=NULL` then OK iff nonnull
- commit: **never rollback after commit** (txn consumed); CORRUPT → fence
- capacity free_entries≥4 **removed** from boot/CU open; install-only `n6_require_install_capacity`
- full namespace can still boot/recover

### CU
- get buffer zeroed; length shape check; rollback on get fail checked
- install ALL_PROPOSED → **DORMANT_DURABLE_NO_SECRET** (no secret discard into READY)
- install ALL_OLD → BOOTED
- plan max 32; DELETE classification branch

### Install
- HW kgen strictly >
- INBOUND: id == next_free (fresh AL ⇒ id==1 only); no arbitrary new context
- OUTBOUND: peer_floor ≤ id
- role cap / lane collision / AL IO+CORRUPT mapped
- capacity admission separate from open

### TX partial final tranche
- if `reserved_exclusive` near `UINT64_MAX`, grow by remaining only so last counter is MAX-1

### Pool canary
- all slots canary-init at `init`; free slots keep canaries; corrupt canary → CORRUPT fence (not NOT_FOUND)

## Measured

| check | result |
| --- | --- |
| `n6_context_store_test` | **23 / 23 PASS** |
| ctest `n6_*` | 3/3 PASS |
| leakage + CMake dual-register | OK |
| docs gate check | OK |
| ASan/UBSan in CI this pass | **not run** (clang present; no sanitizer build matrix executed here) |

## Residual (honest — keeps NOT GO)

- ASan/UBSan full matrix not executed in this session  
- Boot mutation negatives: junk seed + incomplete set path; not every single invariant field as isolated seed vector  
- TX partial tranche near MAX-1: code path present; dedicated seed vector for U=MAX-63 not added  
- Production durable session still testbuild-gated (M4/M5 absent)  
- fence/restamp/reclaim/gc FULL still M4_REQUIRED  
- CU DELETE write-set emission limited  
- ESP / HIL not claimed  

## Verdict

**Independent final-delta integrated into host candidate.**  
**Re-audit against new hashes required.**  
**Self-test PASS alone is not GO.**  
**Overall R6: NOT GO.**
