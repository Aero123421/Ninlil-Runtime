# 2026-07-29 Wi-Fi real-path authority candidate（SPEC-ONLY）

状態: **Proposed machine-verifiable candidate under independent Sol re-audit repair — not SPEC_ACCEPTED, not P0-closed**

Inventory: **79** acceptance IDs; every ID has a distinct substantive assertion;
ledger mark only after success. Donor self-test policies differ by gate (do not
conflate):

- **Python / Node**: one donor body per victim → measured `donor_rejects=79`
  (policy: one donor body per victim id, not full cross-product)
- **C11**: full victim×donor with donor≠victim → measured `donor_rejects=6162`
  (`79×78`; C11 full cross-product only)

CMake registers the Wi-Fi oracle/gates; **normal** host builds do **not** force
ASan — ASan/UBSan only when `NINLIL_ENABLE_SANITIZERS=ON`.

Sol independent re-audit NO-GO repair (2026-07-29 follow-up):
- **P0-1** association tuple full bind: old/new `profile_id`, epoch, digest, binding,
  bssid, channel, auth bound to 80-byte canonical input in generator/fixture/Python/
  Node/C; surface-only donor mutations (e.g. `old_bssid_hex`) permanently rejected
- **P0-2** independent NWD1 literal KAT hardpinned (160B fixed material, not generator
  `encode_nwd1(lab SSID)` self-ref); CRC/auth/complete recomputed from pin in Py/Node/C;
  coherent KAT drift rejected
- **P1** recursive closed schema for root + nested objects/rows (unknown key /
  `authority_override` rejected at **every** object path including all 79 acceptance
  rows); **all** normative integer leaves reject JSON bool (not sample-only
  `exact_int`); exhaustive self-test from gate stdout:
  `object_paths=117` unknown_accepted=0 and
  `integer_leaves=386` bool_accepted=0 on Python **and** Node with full parity;
  Node semantic key dups (`\n`/`\u000a`, `\u0073chema`) rejected; u64>2^53 as BigInt;
  source metadata hardpinned + existence-checked; type-preserving scalar campaign
  `scalar_leaves=1078` accepted=0 via canonical document model SHA
- **P2** docs coverage must match gate stdout (no Py/Node 6162 claim; integer leaf
  count follows gate `integer_leaves=` not stale 359); CMake normal vs ASan split
- **Still Proposed; do not claim SPEC_ACCEPTED / P0=0 until re-audit GO**

本記録は非規範。Normative候補は [ADR-0018](../adr/0018-wifi-bearer.md) と
`spec/vectors/wifi-bearer-spec-v1.json` である。

## Scope

- ADR-0018 real-path authority + **P0/P1 false-green repair**（ID→semantic contract）
- product-neutral machine vectors + independent Python / Node / C11 gates
- **CMakeLists.txt registered** (`wifi_bearer_spec_*` CTest block; normal vs sanitizer split)

## Non-claims

- `SPEC_ACCEPTED` ではない
- implementation / HIL / `RELEASE_SUPPORTED` / public API / production ではない
- **P0=0 / independent review GO を主張しない**（Sol re-audit pending）
- Fabric / Production Attachment / Domain Store / OSS release gates 非干渉

## Audit defects repaired this resume

| Defect | Repair |
| --- | --- |
| set-only inventory / donor full-row pass | Hard-coded ID→semantic contract for all **79** IDs; ledger mark only after assertion; **Python/Node donor_rejects=79** (one donor body per victim); **C11 donor_rejects=6162** (79×78 full cross-product) |
| Assoc `old_bssid_hex` unbound from canonical input | Full old/new field bind in Py/Node/C + permanent surface desync mutations |
| NWD1 KAT generator self-ref (SSID change still green) | Independent 160B KAT hardpins + recompute; lab SSID forbidden |
| Nested open schema / authority_override | Recursive closed keys for constants/pins/storage/restoration/rows/items |
| Node `\n`/`\u000a` dups + u64 Number rounding | Strict escape decode + BigInt for >2^53 |
| Metadata coherent drift | Hardpinned adr/generator/gates/vector/c_test paths + existence |
| Type-preserving scalar drift (all 1078 scalar leaves) | Canonical document model SHA + machine field pins; campaign accepted=0 |
| Doc coverage exaggeration (Py/Node as 79×78; leaves 359) | Coverage auto-generated/verified from gate stdout via evidence tool |
| 78/79 doc mix + always-on ASan | Docs **79**; CMake ASan only under `NINLIL_ENABLE_SANITIZERS` |
| WIFI-NWB1-DUPLICATE expected_sequence lie | `prior=1`, `expected=2`, `received=1` |
| COMMIT_UNKNOWN omit CORRUPT / BOTH | Full closed set + BOTH vector |
| C mark-only inventory | C executes NWB1/seq/assoc bind/KAT/resource semantics |

## Changed files

| Path | Role |
| --- | --- |
| `docs/adr/0018-wifi-bearer.md` | Proposed exact authority + contract notes |
| `docs/06-versioning-and-compatibility.md` | allocation summary (**79** IDs) |
| `docs/adr/README.md` | index note |
| `docs/reviews/README.md` | local proof pointer (not GO) |
| `docs/work/2026-07-29-wifi-real-path-authority-candidate.md` | this record |
| `docs/work/2026-07-29-wifi-bearer-spec-coverage.fragment.md` | AUTO coverage block from gate stdout |
| `docs/work/2026-07-29-wifi-bearer-spec-evidence.json` | machine evidence |
| `CMakeLists.txt` | wifi_bearer_spec CTest + normal/ASan split |
| `spec/vectors/wifi-bearer-spec-v1.json` | machine authority |
| `tools/wifi_bearer_spec_vector_gen.py` | semantic source generator |
| `tools/wifi_bearer_spec_gate.py` | independent Python semantic contract gate |
| `tools/wifi_bearer_spec_gate.mjs` | independent Node semantic contract gate |
| `tools/wifi_bearer_spec_audit_evidence.py` | evidence + docs coverage gate |
| `tests/transport/wifi_bearer_spec_vector_test.c` | independent C11 semantic gate |

## Local proof（stable snapshot; re-auditable）

Coverage numbers below are **machine-generated** by
`tools/wifi_bearer_spec_audit_evidence.py` from live gate self-test stdout.
Do not hand-edit the fragment; re-run the evidence tool after gate changes.

<!-- coverage:begin -->
<!-- AUTO-GENERATED by tools/wifi_bearer_spec_audit_evidence.py; do not hand-edit. -->
```text
vector sha256=38d8050206d8de832dfe9395f6f39b99e1119eb06fa60ee2112af2cd375b25ff
status=PROPOSED_CANDIDATE_NOT_SPEC_ACCEPTED ids=79

Donor coverage (measured from gate self-test stdout):
  Python: donor_rejects=79  policy=one donor body per victim id (not full cross-product)
  Node:   donor_rejects=79  policy=one donor body per victim id (not full cross-product)
  C11:    donor_rejects=6162  policy=full cross-product victim×donor with donor!=victim (79×78)
  note: 79×78=6162 is C11 full cross-product only; Py/Node self-tests do not claim 6162.

Exhaustive false-green surface (Py+Node self-test stdout; accepted=0):
  object_paths=117 unknown_key accepted=0
  integer_leaves=386 bool_as_int accepted=0 int_as_str accepted=0
  string_leaves=692 str_as_int accepted=0
  digest_leaves=96 digest_flip accepted=0
  scalar_leaves=1078 type-preserving value campaign accepted=0
  document model SHA pin: 38d8050206d8de832dfe9395f6f39b99e1119eb06fa60ee2112af2cd375b25ff
  DESCRIPTIVE_SCALAR_ALLOWLIST empty
```
<!-- coverage:end -->

```text
evidence: docs/work/2026-07-29-wifi-bearer-spec-evidence.json
          docs/work/2026-07-29-wifi-bearer-spec-coverage.fragment.md
          tools/wifi_bearer_spec_audit_evidence.py  # regenerates fragment + docs gate

python3 tools/wifi_bearer_spec_vector_gen.py --check
python3 tools/wifi_bearer_spec_vector_gen.py --self-test
python3 tools/wifi_bearer_spec_gate.py --check
python3 tools/wifi_bearer_spec_gate.py --self-test   # donor_rejects=79 (one per victim)
node tools/wifi_bearer_spec_gate.mjs --check
node tools/wifi_bearer_spec_gate.mjs --self-test     # donor_rejects=79 (one per victim)
python3 tools/wifi_bearer_spec_audit_evidence.py     # parses stdout; fails on doc exaggeration
# C11 (normal build; ASan only if NINLIL_ENABLE_SANITIZERS=ON)
cmake -S . -B build-wifi-normal -DNINLIL_ENABLE_SANITIZERS=OFF
ctest --test-dir build-wifi-normal -R wifi_bearer_spec  # 8/8
./build-wifi-normal/ninlil_wifi_bearer_spec_vector_test  # executed_ids=79 donor_rejects=6162 (79×78 C only)
```

## Why still NOT SPEC_ACCEPTED / P0=0 GO (priority order)

Machine-vector false-greens above are closed for `wifi-bearer-spec-v1` under the
measured coverage policies. Full ADR-0018 `SPEC_ACCEPTED` remains blocked by:

1. **Independent Sol re-audit GO** on this snapshot (external; not self-claimed)
2. **ADR SPEC_ACCEPTED gate §2–5** remaining corpora beyond real-path 79 IDs
   (NFL1/NWB1 structural already in vectors; TLS X.509/NRV1/NCM1/NWS1/NWA1/NWC1/NWP1/NWM1
   short/max/integration KAT + dual-oracle bit-exact still open for full ADR)
3. **S1–S6 / versioning / decision-log sync** with docs/34 and related ADRs
4. **Independent security review** recorded under docs/reviews/
5. **No implementation** yet (SPEC is design-only; POSIX TCP/TLS next)

## Remaining work after machine-vector SPEC candidate GO → POSIX TCP/TLS

Private, feature-gated, default OFF (no RELEASE_SUPPORTED / public API):

1. Host POSIX adapter skeleton: TCP connect/read/write, phase deadlines, event generation
2. Pinned OpenSSL 3.5.7 static link path (Host authority pin only; no system lib claim)
3. TLS1.3 exact suite/group/signature negotiation enforcement + exporter contexts (62/64)
4. NWB1 framing codec on socket stream (partial I/O, RETAINED ownership, sequence)
5. Session fence / availability epoch / liveness (keepalive exclusive, blackhole, half-open)
6. Credential provider null on Host; network profile zero; no Wi-Fi driver ownership
7. Unit/integration tests vs this vector set; ASan/UBSan; no HIL required for host unit
8. ESP path deferred until Host private path green + M4 carrier dependency explicit
