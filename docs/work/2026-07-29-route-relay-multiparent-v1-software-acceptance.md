# RRMP V1 software acceptance — 2026-07-29 (REPAIR VERIFIED; RE-REVIEW PENDING)

## Verdict (software)

**NO-GO (formal state unchanged) — all known software P1 repair families now
have source fixes and focused regression evidence, but the fresh independent
re-review and authority-state promotion have not completed.**

ADR-0019 / ADR-0020 remain **Proposed**. This document does **not** claim SPEC_ACCEPTED,
public installed ABI, or physical RF multi-node HIL PASS.

## Independent re-review repair closure

The later independent review invalidated the earlier candidate verdict even
though the existing normal and sanitizer suites were green. The known repair
families now have the following source and regression closure:

1. RRM1 stores one manifest plus bounded chunks; every Platform Storage value
   is at most 61,440 bytes, below the public 65,536-byte single-value ceiling.
   The 307,200-byte figure is logical export scratch, not one storage value.
2. Machine authority and validators use the exact physical key budgets:
   21 route keys and 22 parent keys.
3. The global QST4 used-attempt ledger survives A-B-A, cold restart and
   assignment changes; a parent-set reinstall cannot erase that authority.
4. Route and parent import strictly allow at most two canonical images per key
   and reject a third image, duplicate generation and reverse generation order.
5. Handoff authority CAS binds the complete old/new tuples, term proof,
   expected bundle witness and writer generation.
6. Authority-writer conflict sets a durable authority-global fence that blocks
   every scope, downlink and new handoff; it is not treated as scope-local.
7. Definite outer-CAS failure rehydrates exact durable OLD without applying a
   stale insertion index afterward. Focused `parent_select` and
   `forward_admit` tests place the failed attempt between two existing rows and
   verify byte-exact namespace recovery, both old attempt rows, the ACTIVE route
   and downlink eligibility.

The focused repair tests were demonstrated red before the final fix and green
after it. Until a separate fresh independent re-review confirms this closure,
all PASS tables below remain regression evidence rather than an acceptance or
promotion verdict.

## Sol FINAL blockers — closure status

| # | Blocker | Closure |
|---|---------|---------|
| 1 | Fabricated LINK_ACK in `fabric_relay_cycle` | Cycle now: admit → service → hop materialize + **outbound provider submit** only. No auto-ACK/complete. `link_ack_from_evidence` requires `auth_ok`, non-zero proof, matching `outer_tx_counter`. Complete requires `evidence.auth_link_ack`. Adversarial tests: no-provider + no-ACK → no false complete. |
| 2 | `owner_scope` = `path_policy_id`; unknown fail-open | ADR-0020 §4 `ninlil_rrmp_derive_owner_scope_id`; multi-parent admit derives + `find_scope` fail-closed. Vectors: different path_policy → different scope; unknown scope → `DRAIN_FENCED`. |
| 3 | RAM-only durability | Optional `ninlil_rrmp_owner_bind_storage` + FULL export writepoint + recover; dual-slot export now includes soft attempt fences; buffer export/import retained. |
| 4 | S6 `old_owner_seal=1` after rehydrate | Rehydrate forces `old_seal=0` when handoff ≥ OLD_RETIRED / tombstone; S6 restart test. |
| 5 | Volatile `uint64` attempt fence | Durable `attempt_id16[16]`; select fence is exact 16-byte memeq; ordinal = BE u16 @ [14..15]; export/import soft trailer restores fence; restart conflict test. |
| 6 | ADR promotion | **Not promoted** — remain Proposed. |
| 7 | ESP / strict / ASan / TESTS-OFF / HIL | Host strict all-feature private archive green under `-Wframe-larger-than=2048`. Storage ABI compile + script gates. Codec page validates in-place (no 4 KiB stack). ESP feature-ON map proof **PASS** (`rrmp_esp_idf_map_proof`). Physical HIL **NOT_RUN**. |

## Unused reclaim helpers

`reclaim_one_route_old` / `reclaim_one_parent_old` are **called** on arena alloc failure in dual begin_write (not attributes-suppressed).

## Workspace

| Item | Value |
|------|-------|
| Budget | 384 KiB (393216 B) |
| Measured | **388048 B** (owner workspace) |
| Align | 8-byte |

The owner workspace is not the complete live ESP allocation.  The checked-in
resource authority now accounts for all four simultaneously live large
buffers:

| Live allocation | Bytes | Placement |
|---|---:|---|
| owner workspace (host-conservative measured size) | 388048 | ESP PSRAM CAPS |
| namespace export scratch | 307200 | ESP PSRAM CAPS |
| bounded piece scratch | 61440 | ESP PSRAM CAPS |
| target software-FULL smoke store | 307456 | ESP PSRAM CAPS |
| **worst-case simultaneous total** | **1064144 (1039.203125 KiB)** | PSRAM |

`tools/rrmp_esp_dram_budget_gate.py` compares these values across the C source,
software manifest, HIL template and an executed Host binary.  The ESP map gate
also requires `CONFIG_SPIRAM`, `CONFIG_SPIRAM_USE_CAPS_ALLOC`, the RRMP feature
flag, all production objects, no Host simulation object, and internal RRMP BSS
within 32 KiB.  Large-buffer allocation no longer falls back to internal DRAM.
The physical-HIL runtime workspace/free-PSRAM measurements remain `null` and
all physical claims remain `NOT_RUN`.

## Production composition vs host/ESP fixtures (Sol re-audit)

| Layer | Location | Claims |
|-------|----------|--------|
| **Production TU** | `rrmp_composition.{h,c}` | **Only** `composition_bind` (requires real storage ops+handle) + `composition_recover`. No synthetic RAM store/provider, ~0 large BSS. |
| **Host lifecycle KAT** | `tests/.../rrmp_host_lifecycle_fixture.c` | Synthetic FULL store + outbound doubles. FULL writepoints, cold restart route/parent/attempt, LIVE REPLAY, ACK lost→retry→complete, fabric reject zero mutation, **parent_loss → unique SPLIT_BRAIN**. Not carrier/HIL. |
| **ESP target smoke** | `ports/esp-idf/src/rrmp_target_smoke.c` | **Explicit SPIRAM CAPS** workspace + SPIRAM software FULL store; production bind/recover; route/parent/select/cold restart/parent_loss SPLIT_BRAIN. Not RF air. Host fixture **not** linked. |

Host: `ninlil_rrmp_composition_test` **PASS**.

## Simultaneous logical-capacity envelope

`test_simultaneous_capacity_envelope` keeps the advertised maxima live in the
same owner at the same time:

- 128 ACTIVE route records;
- 64 parent scopes, including the derived scope used by all admitted routes;
- 64 forward queue entries (56 NORMAL + the reserved 8 CONTROL entries).

The test rejects scope 65 and queue entry 65 without evicting live state,
exports the combined namespace, cold-imports it, and verifies that the route,
scope, and exact `RRMPQST4` counts remain 128/64/64. The focused Host normal
and ASan+UBSan builds both pass.

## Host gates (post-repair verification)

| Gate | Result |
|------|--------|
| Strict all-feature `ninlil_runtime_private` | **PASS** (+ `-Wframe-larger-than=2048` on ESP-path TUs) |
| `tools/rrmp_storage_abi_gate.py` | **PASS** |
| `tools/rrmp_frame_stack_gate.py` | **PASS** (ceiling 2048; no page `tmp[]`) |
| Host `.su` validates (nrp1/nep1/npp1/npa1/npt1) | **32 B static** each |
| `ninlil_rrmp_{codec,sm,crash_corrupt,storage_atomicity,token_ledger,sim_lifecycle,composition}_test` | **PASS** |
| 10k exact lifecycle | **PASS** |
| ASan+UBSan RRMP suite (all seven Host executables) | **PASS** |
| ESP feature-ON map proof | **PASS** (`tools/rrmp_esp_idf_map_proof.sh`, internal RRMP BSS **3140 B**) |
| ADR-0019/0020 status | **Proposed** (unchanged) |
| Physical RF multi-node HIL | **NOT_RUN** |

## Remaining limits (honest)

1. **ADR remain Proposed** — do not treat as Accepted until independent audit + acceptance matrix match.
2. **Physical multi-node RF HIL** remains **NOT_RUN** (schema/tooling only).
3. **Production composition bind requires real storage ops** — no NULL→synthetic fallback in production TU. Host/ESP software FULL stores are fixtures (SPIRAM on ESP), not flash FULL proven (ESP flash FULL remains COMMIT_UNKNOWN / ESP_UNPROVEN).
4. **Synthetic outbound/auth_ack** exist only in host lifecycle fixture — not production carrier/provider proof. Real WiFi/Fabric/Radio workers own submit + authenticated inbound evidence.
5. **Public installed ABI** for `ninlil_route_*` / `ninlil_parent_*` still default-OFF private.
6. **ESP internal DRAM**: large workspace/store are SPIRAM CAPS, not static BSS. Host fixture BSS stays off ESP ELF.
7. Queue, opaque handle, authenticated LINK_ACK state, and LIVE evidence are
   included in the `RRMPQST4` FULL snapshot and covered by cold-restart tests.
   Physical flash power-cut HIL remains **NOT_RUN**.

## Non-claims

- SPEC_ACCEPTED / marketing “Accepted” for ADR-0019/0020
- Public installed route/parent ABI
- Physical RF multi-hop PASS
- Security audit complete
