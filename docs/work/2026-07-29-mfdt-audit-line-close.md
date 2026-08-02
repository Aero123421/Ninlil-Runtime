# MFDT audit line close (2026-07-29)

Status: **Proposed / PROPOSED_SPEC_ONLY** — not SPEC_ACCEPTED, not status-promoted.

## Spec authority first

- ADR-0021 residual FULL totals **68/58 → 77/67** (and daily **136/116 → 154/134**)
  unified with §FULL ordering / budget and machine vectors.
- Expiry predicate unified: sole rule `now_ms >= reservation_not_after_ms`
  (`MF-NEG-EXPIRY-BOUNDARY-EQ` / `now_ge_not_after`). Residual `>` void.
- Authority resync: vector 93 IDs, map/source pins refreshed. Status remains
  `PROPOSED_SPEC_ONLY`.

## Implementation closes (private / default-OFF)

| Audit class | Close |
| --- | --- |
| P0 wire | OPEN mandatory-field validate; digest @202; PAGE/CHUNK BIND52; active 308+body+CRC |
| P0 NRC1 | schema/transfer/session/seq/header_crc/record_crc; 72×204 BE; 14732 value |
| P0 durable | mutation+NRC1 **one multi-key FULL**; terminal erase+NM30 one FULL; GC dual-delete FULL |
| P0 restart/CU | `restart_scan` reloads durable NM3*; CU on real old/new bytes |
| P0 exact-once | NRC1 lookup before PAGE/CHUNK mutation; CHUNK vs manifest entry; durable content |
| P0 token/handoff | `NM3-PUBLISH-V1` token; handoff FULL; upper dedupe by token |
| P0 terminal gate | COMPLETE only after R_HANDED_OFF / S_ACCEPT_RX |
| P0 bounds | resume 0/gap/>8 reject; host/ESP active max; fairness unpaid CHUNK; expiry FULL |
| P1 ESP | lab `mfdt_v1_store.c` **removed** from ESP component; fail-closed `mfdt_v1_store_esp_stub.c` |
| P1 tests | lifecycle reuses store; fault no `\|\| 1`; independent KAT; crash co-FULL all-or-nothing |
| P0 negotiation | Accepted HELLO 1/2不変; bound MFN1 0x3e/0x3f; endpoint/nonce/request/session/digest correlation; duplicate replay/cache; conflict fence |
| P0 Fabric carrier | instance-bound private Foundation carrier; exact TRANSFER_RESERVED service/digest/ID derivation; TxPermit; source/target/session/content demux; two real Fabric cores carry MFN1 plus 4096-byte split/reassembly in both directions |

## Explicit non-claims

- NCL1/NCG1 and Generic Fabric owner-plane adapters are software candidates.
  compact RF direct mapping and physical Wi-Fi HIL remain OPEN MF-O04/O05.
- No public ABI or public Service integration; private/default-OFF source-only.
- No power-cut HIL (MF-O03).
- No status promotion.

## Verify snapshot

- Host private: unit/kat/e2e/fault/lifecycle OK
- Spec gates: vector/spec/acceptance OK (93)
- Freeze noninterference OK; tests-OFF surface OK; ESP packaging OK
- ASan+UBSan: unit/kat/fault/e2e/lifecycle OK
- Actual Fabric carrier: standard Portable Runtime submit/verified Receipt E2E
  plus MFN1 negotiation and 4096-byte MFDT E2E, normal + ASan/UBSan OK
- Runtime probe library builds when `NINLIL_ENABLE_MFDT_V1_PRIVATE=ON` (not installed)
- Retry SM charge/exhaustion, session-gen reclaim, restart rehydrate, CU on durable keys, sealed KATs
