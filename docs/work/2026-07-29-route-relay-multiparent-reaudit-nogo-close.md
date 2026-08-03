# RRMP independent re-audit NO-GO close — 2026-07-29

> Historical snapshot. Current capacity evidence supersedes the workspace
> number below: **353480 B ≤ 384 KiB**, with full 128-route/64-scope restart
> tests.

## Status

- Spec/ADR: still **Proposed** (no Accepted claim).
- Host private implementation: HOST_CANDIDATE / software path only (no physical HIL).
- Feature default-OFF: `NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF`.

## Re-audit gaps closed (implementation, not mark-only)

| Gap | Close |
|-----|--------|
| Drain zero-input UBSan | `ninlil_rrmp_drain_evaluate_v1`: F=0 / attempts=0 early ineligible; cost=0 / A=0 never divides |
| Parent ABI mismatch | Distinct packed `ninlil_parent_result_v1_t` 128B (status@16, owner_scope_id@32, handoff_step@72, seal_allowed@75, dig@80) — not route-result alias |
| NPA1 / NPT1 + atomic FULL | Codec encode/validate; handoff prepare→retire writes NPA1+NPT1 dual then `parent_full_commit` (2-key FULL) |
| CU OLD | Dual classify when active gen &lt; other complete; inject helpers; recover → `COMMIT_UNKNOWN` |
| Payload / rewrap / TxPermit / LINK_ACK / 2–3hop | Queue materializes exact 96B E2E body; `hop_forward_execute` requires TxPermit, bit-identical rewrap, payload copy; `link_ack` frees slot; multi-hop host tests |
| Scope seal on split-brain / parent-loss | `scope_seal_allowed`; parent_select + hop TX blocked for sealed scope; unrelated scopes continue |
| ESP SHA silent fallback | OpenSSL (host) → mbedTLS (`ESP_PLATFORM` / `NINLIL_RRMP_HAVE_MBEDTLS`) → portable **only non-ESP**; ESP without mbedTLS fails closed |

## Workspace

- Measured: `ws_bytes=252280` (≈246 KiB) ≤ 256 KiB ESP-candidate envelope.

## Commands / results

```text
# Normal ON
cmake -S . -B build-rrmp-fix -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON
cmake --build build-rrmp-fix -j --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test \
  ninlil_runtime_private
cd build-rrmp-fix && ctest -R 'ninlil_rrmp_|rrmp_private' --output-on-failure
# → 7/7 Passed

# ASan
cmake -S . -B build-rrmp-asan \
  -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-rrmp-asan -j --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test
cd build-rrmp-asan && ctest -R 'ninlil_rrmp_' --output-on-failure
# → 4/4 Passed

# Feature OFF (prod archive must lack rrmp/route/parent catalog symbols)
cmake -S . -B build-rrmp-off -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=OFF
cmake --build build-rrmp-off -j --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test \
  ninlil_runtime_private ninlil_rrmp_private_probe ninlil_rrmp_prod_off_proxy
cd build-rrmp-off && ctest -R 'ninlil_rrmp_|rrmp_private' --output-on-failure
# → 7/7 Passed
```

## Tests added / extended

- Parent result offsetof lockstep; drain F=0 / cost=0; real multi-hop + TxPermit deny; scope seal blocks select/hop; CU OLD inject + recover fault injection; NPA1/NPT1 codec validate after handoff.

## Residuals (honest)

- No physical HIL / radio airtime evidence.
- Spec remains Proposed; no security-audit skill run in this tranche.
- Multi-hop is software host path (queue + hop_tx_view), not ESP RF.
- NPA1/NPT1 rehydrate-into-scope RAM on import is still NPS1-primary; durable pages are written FULL on handoff and validated by codec/CRC.

## Parent ABI / core lockstep (follow-up; stale green rejected)

Audit note: `rrmp_abi.h` exact parent result must not be paired with core writing
route fields (`lifecycle_state` / `evidence_or_digest32`) into parent results.

### Snapshot guarantees

| Surface | Fields written |
|---------|----------------|
| `ninlil_route_result_v1_t` | `lifecycle_state@77`, `evidence_or_digest32@80` via `route_result_set_*` only |
| `ninlil_parent_result_v1_t` | `handoff_step@72`, `seal_allowed@75`, `token_or_commit_digest32@80` via `parent_result_*` only |

`rrmp_core.c` carries `_Static_assert` lockstep on both layouts. Parent helpers are
distinct typed functions (not `typedef` alias of route result).

### Fresh build (wipe + rebuild — do not reuse prior trees)

```text
rm -rf build-rrmp-lockstep
cmake -S . -B build-rrmp-lockstep -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON
cmake --build build-rrmp-lockstep -j --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test \
  ninlil_runtime_private ninlil_rrmp_private_probe ninlil_rrmp_prod_off_proxy
cd build-rrmp-lockstep && ctest -R 'ninlil_rrmp_|rrmp_private' --output-on-failure
# → 7/7 Passed; 0 compile errors

rm -rf build-rrmp-lockstep-asan
cmake -S . -B build-rrmp-lockstep-asan \
  -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-rrmp-lockstep-asan -j --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test
cd build-rrmp-lockstep-asan && ctest -R 'ninlil_rrmp_' --output-on-failure
```

## P0: self-recursive helpers (ASan stack overflow)

Sol re-audit: `route_result_set_lifecycle` / `route_result_set_evidence` called
themselves → infinite recursion / stack overflow under ASan (trace at former
`rrmp_core.c:255`).

### Fix

- **Deleted** those wrappers (and `parent_result_set_digest`) entirely.
- Call sites use **direct non-recursive** assignment:
  - `out->lifecycle_state = …;`
  - `memcpy(out->evidence_or_digest32, …, 32u);`
  - `memcpy(out->token_or_commit_digest32, …, 32u);`

### Fresh ASan+UBSan (required)

```text
rm -rf build-rrmp-asan-p0
cmake -S . -B build-rrmp-asan-p0 \
  -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-rrmp-asan-p0 -j --target \
  ninlil_rrmp_codec_test ninlil_rrmp_sm_test \
  ninlil_rrmp_crash_corrupt_test ninlil_rrmp_sim_lifecycle_test
cd build-rrmp-asan-p0
ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
  ctest -R 'ninlil_rrmp_' --output-on-failure
# → 4/4 Passed
```

## Acceptance close (post-recursion)

| Item | Close |
|------|--------|
| Exact parent/route ABI | Distinct structs + `_Static_assert` lockstep; tests offsetof |
| Durable restart/CU | NPA1/NPT1 rehydrate on import; handoff restart test; CU OLD inject+recover |
| payload/rewrap/TxPermit/LINK_ACK | hop_execute materialize-exact rewrap; TxPermit gate; LINK_ACK frees |
| parent-loss/split-brain | scope_seal_allowed; select/hop TX fenced; other scopes continue |
| Executable 2/3-hop | `hop_once` acceptance: hop3→2→1 + dedicated 2-hop test |

```text
rm -rf build-rrmp-accept build-rrmp-accept-asan
# normal: 7/7  (4 unit + 3 symbol when probe/proxy built)
# asan:   4/4
```
