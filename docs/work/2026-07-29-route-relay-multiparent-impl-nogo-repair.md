# RRMP NO-GO repair tranche (2026-07-29)

## Design delta (short)

Independent Sol audit: prior focused green was **semantic false-green**. This tranche
aligns implementation to Proposed ADR-0019/0020 **without** promoting Accepted.

| Gap | Was | Now |
|-----|-----|-----|
| Preamble | u16 api/size | exact u32 api_version/struct_size/reserved0/1 |
| Catalog signatures | `(runtime*, req*, out*)` | `(req*, out*)` + bound owner serial domain |
| Result | loose envelope | exact 128B field table + status matches return |
| Req layouts | ad-hoc | packed ADR layouts + `_Static_assert` |
| Precedence | early-return order | closed matrix pick (route+parent KATs) |
| Durable | snapshot without rehydrate; no parent pages | dual-slot FULL provider; NRD1/NRP1/NEP1 + NPP1; import rehydrates routes/evidence/scopes |
| CU | partial only | PARTIAL/EXTRA/THIRD sticky + recover → CORRUPT/TX=0 |
| Forward/parent/SB | sim manual events | **production core SM**; sim = driver only |
| Seams | none | `rrmp_seam` NFL1 hop view + R7 FRAG view + fabric forward once |
| ESP | Kconfig only | sources ON path + software HIL manifest; physical HIL residual honest |

**Not claimed:** SPEC_ACCEPTED, physical 2/3-hop or multi-parent RF HIL.

## Files

```
src/runtime/route_relay_v1/
  rrmp_abi.h          exact packed ABI + catalog ops
  rrmp_store.{h,c}    dual-slot transactional provider
  rrmp_core.c         owner + SM + rehydrate + precedence
  rrmp_seam.{h,c}     Fabric/NFL1/R7 composition adapters
  rrmp_sim.{h,c}      driver only
  rrmp_codec/util     wire codecs (unchanged layouts)
tools/rrmp_software_hil_manifest.json
```

## Commands / results (local)

### Spec (still Proposed)

```bash
python3 tools/route_relay_multiparent_spec_gate.py --check
# OK cases=114 donors_required=12882 sha256=eaa49094…
```

### Host strict

```bash
cmake -S . -B build-rrmp -DNINLIL_BUILD_TESTS=ON -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF
cmake --build build-rrmp --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test \
  ninlil_rrmp_private_probe -j
ctest --test-dir build-rrmp -R 'rrmp_' --output-on-failure
```

| Test | Result |
|------|--------|
| ninlil_rrmp_codec_test (static asserts + full precedence KAT) | PASS |
| ninlil_rrmp_sm_test (hop/loop, 124 LIVE RESOURCE, handoff, select, split-brain, seam) | PASS |
| ninlil_rrmp_crash_corrupt_test (export/import rehydrate, PARTIAL/EXTRA/THIRD) | PASS |
| ninlil_rrmp_sim_lifecycle_test (core driver + 1k lifecycle) | PASS |
| rrmp_private_feature_symbol_probe/archive | PASS |
| ASan/UBSan all four binaries | PASS |

### Feature OFF/ON archive

- Default `NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF`: production archive probe asserts
  `ninlil_rrmp_owner_create` absent when prod `.a` present; tests still compile private TUs ON.
- Probe archive `libninlil_rrmp_private_probe.a` always carries catalog symbols for nm proof.

### ESP

- Kconfig default OFF; optional ENDPOINT/RELAY/PARENT independent bits.
- Production ESP TUs: util/codec/store/core/seam (sim host-only).
- **esp32s3 final ELF/map/nm + on-target RAM**: recipe in
  `tools/rrmp_software_hil_manifest.json` — **not executed in this environment**
  (no ESP-IDF board campaign this session). Software HIL plugin/manifest present.

## Hardware-only residuals

1. Physical 2-hop / 3-hop RF HIL  
2. Physical multi-parent diversity on air  
3. Power-cut dual-slot HIL on real flash  
4. Board-level esp32s3 RRMP-on size/stack map campaign  

## Closing claim (corrected)

**Implementation candidate only** for Proposed ADR-0019/0020 private surface.
Not Accepted. Not production/HIL complete. Subsequent P1/P2 close is documented in
`docs/work/2026-07-29-route-relay-multiparent-p1p2-close.md` (workspace ≤256KiB,
scope-local split-brain, queue-before-LIVE, etc.).
