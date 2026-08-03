# MFDT 1--4 target admission and restart reconciliation 3C2c

Date: 2026-08-02
Status: **bounded 1--4 target admission/reconciliation implemented and targeted GREEN**

## Implementation contract

- Extend only the private MFDT V1 route from one exact target to the existing
  canonical exact roster of one through four targets. Repeated target Runtime IDs
  use the existing `REJECTED / TARGET_COUNT_UNSUPPORTED` result before Application
  attempt entropy, sidecar mutation, or Foundation mutation.
- Visit targets in canonical order. For each target, select one non-zero Application
  attempt in at most four entropy draws, rejecting the existing durable
  active/retained attempt index and candidates selected earlier in the same
  admission, then durably pre-arm its exact target-local transfer/ordinal/OPEN.
- Commit the complete roster and all target-local attempt/correlation fields in the
  existing single Foundation admission FULL only after every sidecar arm is `NEW`.
  Definite candidate/arm failure cleans only earlier arms; definite Foundation
  failure cleans all arms. Arm, cleanup, or Foundation `COMMIT_UNKNOWN` retains
  uncertain custody and fences for cold reconciliation.
- Reconcile one nonterminal Foundation MFDT transaction against its complete set of
  target-local sender rows before mutation. Missing, mismatched, extra, duplicate,
  receiver-side, or same-origin incompatible truth fences; wholly Foundation-absent
  fresh sender arms retain the existing bounded orphan-cleanup rule.
- Sender pre-arm validates the canonical Application envelope and configured
  non-zero session generation/cookie, and binds Host custody to the target Runtime
  without requiring a live carrier session. Existing carrier, ingress,
  maintenance, and single-peer `bind_session` checks remain unchanged.

## Representation decision

The existing NTS3 attempt history stores the four initial attempts in canonical
target order. Target zero remains the active scheduler target and the top-level
attempt mirrors target zero. The codec keeps its general "top-level equals latest
history entry" rule, with only the MFDT DesiredState multi-target admission shape
validated by the stricter existing target-local history and active-target mirror
rules instead. No durable state, kind, table, or schema is added.

## Implemented coverage

- 2-, 3-, and 4-target admission proves canonical target order, distinct
  target-local attempts, exact OPEN metadata/ordinal/transfer ID, one Foundation
  FULL after all sidecar FULLs, and zero admission wire/TxGate/callback effects.
- Duplicate target Runtime IDs with different Application-instance IDs reject
  with zero entropy and zero sidecar/Foundation mutation.
- Same-admission attempt collision retry, second-target four-draw exhaustion,
  first/second arm definite failure and `COMMIT_UNKNOWN`, Foundation definite
  failure and `COMMIT_UNKNOWN`, and cleanup definite/CU failures have bounded
  entropy, commit, retained-arm, fence, wire, TxGate, and callback canaries.
- Cold restart accepts an exact four-target Foundation/sidecar set without
  entropy or mutation and retains the same attempts/transfer IDs. Missing,
  mismatched, extra same-origin, and incompatible rows fence before mutation;
  Foundation-absent fresh orphan cleanup retains the existing bounded rule.
- Cold-restart Foundation shape validation re-derives every target-local
  transfer ID from transaction ID, target Runtime ID, and canonical ordinal.
  A Foundation target and its NM3S/NRC1 sidecar rows that agree on the same
  internally valid but noncanonical transfer ID now fence `STORAGE_CORRUPT`
  before entropy, storage mutation, wire, TxGate, or callback effects.
- Detached sender pre-arm accepts a configured but unbound owner and a target
  other than the live single-peer session while producing no wire/TxGate work.
  It still validates the complete canonical Application envelope and Host
  metadata. Carrier ingress, maintenance, and session binding remain strict.
- NTS3 round-trips canonical target-order initial attempts while target zero is
  the active top-level mirror. Reordered history, repeated target indices,
  target-local attempt mismatch, and top-level active-mirror mismatch are
  rejected by codec mutants.

## Verification

Normal and ASan/UBSan targeted runs passed:

```text
v1_runtime_capability direct                              PASS / PASS
v1_transaction_codec direct                              PASS / PASS
mfdt_v1_host_coordinator_acceptance                      PASS / PASS
ctest -R 'mfdt|multi_frame'                            41/41 / 41/41 PASS
Foundation codec/durable/restart focused set              9/9 / 9/9 PASS
MFDT-OFF v1_runtime_capability + v1_transaction_codec          PASS
strict -Wall -Wextra -Werror -Wpedantic build                  PASS
git diff --check                                               PASS
```

The focused P1 review-repair rerun additionally passed the normal and
ASan/UBSan `v1_runtime_capability` binaries and the MFDT-OFF capability binary.
As a negative control, removing only the new byte-exact canonical transfer-ID
comparison made the new mutant configure successfully (`status=OK`) with all
three sender rows active; restoring the comparison made the same case fence as
required. Leak detection is unavailable in the local Apple sanitizer runtime,
so the sanitizer run used ASan/UBSan `halt_on_error` without leak detection.

## Nonclaims

This tranche does not implement or claim multi-peer session registration, carrier
dispatch/progression for multiple peers, receiver publication, READY/Application
handoff, Application Receipt, Wi-Fi/Fabric integration, a public API, release
support, ESP32-S3 execution, or physical HIL.
