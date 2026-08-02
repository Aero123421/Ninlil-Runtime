# Route-relay / multi-parent private implementation tranche (2026-07-29)

## Status

- Spec authority remains **Proposed** (`claims.spec_accepted=0`).
- Independent gates: **114/114** cases, **12,882** donors (Py + Node) — unchanged by this tranche.
- Private Host implementation: **default-OFF** production-candidate under `src/runtime/route_relay_v1/`.
- **Public ABI untouched.** Feature flag `NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF` by default.
- **No physical 2-hop / multi-parent HIL claim** (hardware residual).

## What was implemented

Private modules (symbol prefixes `ninlil_rrmp_*`, `ninlil_route_*`, `ninlil_parent_*`):

| Area | Coverage |
|------|----------|
| Codecs | NRD1, NRP1, NRM1, slot/exact, NEV1, NEP1, NPS1, NPP1, NOA1, NPH1, commit digest, loop/dedup/evidence keys |
| Route ops | install_batch, activate, begin_drain, retire, query, forward_admit, forward_complete, cancel_drain, recover_cu, diagnostics |
| Hop/custody | hop budget, terminal mismatch, loop window, dedup window (no outer_rx in keys), durable-first admit |
| Evidence | LIVE/COMPLETED/EMPTY, capacity 124, complete does not free, reclaim, gen-retire GC, liveness beyond 124 |
| Queues | global 64/16320 with CONTROL/SAFETY reservation (8/2048) |
| Parent ops | set_install (NPS1), owner_prepare (full NOA1), S1–S6 handoff, retire old_owner only, multi-scope sets |
| Split-brain / loss | TX=0 on split-brain; parent_loss seals; same-attempt reselect blocked in sim |
| Durable CU | FULL snapshot/restore; PARTIAL/EXTRA/corrupt → COMMIT_UNKNOWN |
| Simulator | Deterministic multi-node virtual-link bounded transcript (endpoint+relay concurrent role) |
| ESP | Kconfig feature + independent endpoint/relay/parent role flags; production TUs (no host sim) |

Composition: Fabric / NRW1 contracts **unchanged** (no shared source edits to those modules).

## Build / test commands and results

### Spec authority (still Proposed, green)

```bash
python3 tools/route_relay_multiparent_spec_gate.py --check
# route-relay-multiparent python gate OK … cases=114 executed=114 … donors_required=12882
```

### Host strict build (feature archive default-OFF; tests force feature ON)

```bash
cmake -S . -B build-rrmp -DNINLIL_BUILD_TESTS=ON -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF
cmake --build build-rrmp --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test ninlil_runtime_private -j
ctest --test-dir build-rrmp -R 'rrmp_|route_relay_multiparent' --output-on-failure
```

**Results (local 2026-07-29):**

| Test | Result |
|------|--------|
| route_relay_multiparent_vector_oracle | PASS |
| route_relay_multiparent_python_gate (+ self-test) | PASS |
| route_relay_multiparent_node_gate (+ self-test) | PASS |
| ninlil_rrmp_codec_test | PASS |
| ninlil_rrmp_sm_test | PASS |
| ninlil_rrmp_crash_corrupt_test | PASS |
| ninlil_rrmp_sim_lifecycle_test (incl. 10k lifecycle) | PASS |
| rrmp_private_feature_symbol_probe + archive | PASS (dedicated probe archive; prod archive checked when present) |
| ASan/UBSan sm + crash + lifecycle | PASS (`ASAN_SM:0 ASAN_CRASH:0 ASAN_LIFE:0`) |

### Normal binaries

```bash
./build-rrmp/ninlil_rrmp_codec_test
./build-rrmp/ninlil_rrmp_sm_test
./build-rrmp/ninlil_rrmp_crash_corrupt_test
./build-rrmp/ninlil_rrmp_sim_lifecycle_test
# all: OK
```

### ASan + UBSan (Host)

```bash
OPENSSL_PREFIX=$(brew --prefix openssl@3)
clang -fsanitize=address,undefined -g -O1 \
  -Isrc/runtime/route_relay_v1 -I"$OPENSSL_PREFIX/include" \
  -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1 -DNINLIL_RRMP_HAVE_OPENSSL=1 \
  tests/runtime/route_relay_v1/rrmp_sm_test.c \
  src/runtime/route_relay_v1/rrmp_{util,codec,core,sim}.c \
  -L"$OPENSSL_PREFIX/lib" -lcrypto -o /tmp/rrmp_sm_asan && /tmp/rrmp_sm_asan
# ASAN_SM:0  (rrmp_sm_test OK)

# same pattern for rrmp_crash_corrupt_test and rrmp_sim_lifecycle_test
# ASAN_CRASH:0  ASAN_LIFE:0
```

### ESP component role control

Kconfig (default all OFF except endpoint role defaults y when feature on):

- `CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1`
- `CONFIG_NINLIL_RRMP_ROLE_ENDPOINT`
- `CONFIG_NINLIL_RRMP_ROLE_RELAY`
- `CONFIG_NINLIL_RRMP_ROLE_PARENT`

Roles are **independent bits** — a node may be endpoint+relay concurrently. No fixed single role enum.

Production composition sources on ESP: `rrmp_util.c`, `rrmp_codec.c`, `rrmp_core.c` (sim host-only).

## Hardware-only residuals (do not claim)

1. **Physical 2-hop RF path** — no SX1262 multi-hop HIL executed in this tranche.
2. **Physical multi-parent uplink diversity on air** — host sim only (`RRMP-2HOP-DIVERSITY` / sim transcript).
3. **Power-cut HIL on real NOR/NVS** for NRD1/NRP1/NEP1 FULL groups — host snapshot/restore campaign only.
4. **radio_hil_app multi-node field run** — Kconfig role wiring ready; no board campaign recorded.
5. **Independent acceptance / SPEC_ACCEPTED** — still Proposed until independent audit closes implementation.

## Layout map (private, not installed)

```
src/runtime/route_relay_v1/
  rrmp_types.h rrmp_util.{h,c} rrmp_codec.{h,c}
  rrmp_api.h rrmp_core.c rrmp_sim.{h,c}
tests/runtime/route_relay_v1/
  rrmp_codec_test.c rrmp_sm_test.c
  rrmp_crash_corrupt_test.c rrmp_sim_lifecycle_test.c
```

## Honest claims

- Host production-candidate **default-OFF** private implementation against ADR-0019/0020 + vector/private API catalog: **present**.
- Exhaustive oracle gates: **still Proposed, green**.
- Physical multi-hop / multi-parent HIL: **not claimed**.
