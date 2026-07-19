# ADR-0010: R6 NRW1 Compact Context-Handle Secure Radio Wire

状態: **Accepted**（independent root QA re-GO 2026-07-19 P0=P1=P2=0 complete; **Stage 9** docs freeze）  
決定日: 2026-07-17（Stage 9 追補 2026-07-18; P1(11)–(40) + re-audit repair; final re-GO 2026-07-19）  
非主張: R7 full AEAD codec 実装 / M4·M5 handshake 実装 / ESP N6 capacity / RF·USB 実機 HIL / Japan legal / production radio / crash-atomic exactly-once not claimed; compile/link ≠ HIL

## Context

独立 Stage 8 監査は NO-GO: (A) G→G+1 / fence_target / controller-durable snapshot と private-mandatory reconcile の虚偽、(B) 現行 `ninlil_pcp_issue`+Algorithm E では owner epoch を mutation 前に固定できない、(C) clock 混在と timer domain 未閉包、(D) ACK burn の semantic identity/二次 burn 不足、(E) terminal commit と issued drain の順序不足。Stage 9 はこれらを docs-only で閉じ、P1(11)–(26) で実装不能/矛盾を追加閉鎖する。

## Decision (Stage 9 accepted — final re-GO complete)

**Stage 9 docs freeze Accepted.** Independent root QA re-GO 2026-07-19 closed with **P0=0 / P1=0 / P2=0**. This is **R6 docs freeze GO**, not R7 implementation complete / M4·M5 complete / ESP N6 capacity / RF·USB 実機 HIL / Japan legal / production radio.

1. **L1/W1:** W1=codec; L1=clock/Permit/R1/edge. Closed **7 events** including `TX_RESULT` (no Permit body; W1 never calls edge). `ISSUE_GRANTED`/`TRANSMIT_EDGE` abolished.

2. **Single-sample issue:** L1→R5 adapter→R2 private coordinator. R2 samples **once**; pre-RW generic validation callback returns immutable window from R5 state under same S; R2 has no R5 header dep; registry insert after R2 OK.

3. **Activation same-S:** L1-only activate with accepted class-D snapshot copy-in; issue always re-samples. R6 0x11 requires RegulatoryProfile **schema 2** `authority_clock_epoch_id`; schema1 reserved-zero for LAB only. Schema2 loader = **R7 blocker**.

4. **N6:** exact HOP 2 / E2E 1 lanes; direction-independent allocator scope `(membership_epoch, receiver_node_id, layer_code)`; one N6AL for the **actual local side only** (no phantom pair); OUTBOUND `peer_next_floor` monotonic (no fixed 0); no retained_uncompacted; reclaim only on FULL success; N6CF 64B; N6HW scope_digest28; boot exact join via membership_epoch+alloc_side+26 B direction-free fingerprint; GC in ≤32-entry batches.

5. **CU recovery:** N≤32; normalize no-ops; ALL_OLD/ALL_PROPOSED only; inspect open/begin/get/rollback/commit; **close is void** (exactly once, no status).

6. **Adopt proof:** sole **120 B** recovery_proof (SHA-256 of 200 B LE meta); prove API; no opaque/72B dual.

7. **FRAG INTENT_BURN_CU:** copy pre ram_next/limit, proposed U, C; ALL_PROPOSED/OLD/MIXED closed; no double burn.

8. **Consume two catalogs:** R2 PCP **9/43/44/45** map to R1 HAL **16/43/44/45** (separate namespaces; 16 is HAL-only). Same-Permit retry only HAL 16+45. Uncertain 44 ⇒ CLOCK_PATH_DROP. Generic HAL 41/42 = legacy production only, not R6 target. C wiring + HAL enum extension = R7 blocker; until then NOT READY.

9. **CLOCK_FAULT:** Algorithm A A2 and all sample-observing APIs call shared helper FULL-commits F_c before return; empty→FENCED only after FULL; durable=0 without F_c is forbidden; L1 does not write meta.

10. **ESP storage:** exact formula entries_required=A+2H+E+F+T+W and bytes_required=80A+232H+116E+92F+76T+60W; current ESP max_namespaces=2 < required 3 ⇒ NOT READY; R7 port/HIL blocker.

11. **Gate honesty:** structural checks + mutations; not NLP proof; gate PASS ≠ GO / ≠ arbitrary natural-language proof.

**Relay** still MUST NOT open E2E. docs/25 untouched.

## Consequences

[30章](../30-r6-secure-radio-wire.md) **Normative / Accepted / Stage 9**. Independent root QA re-GO 2026-07-19 **P0=P1=P2=0**. **R6 docs freeze Accepted.** R7 full AEAD codec / M4·M5 handshake 実装 / ESP N6 capacity / RF·USB 実機 HIL / Japan legal / production radio は未完。docs/23、docs/29、ADR-0009 は本 ADR と同時に整合済み。R7 must re-freeze docs/24 for the new private APIs and implement the already-frozen profile_clock_epoch contract. Final status-only editorial delta independent recheck also closed **P0=P1=P2=0 GO** (status/progress/review/gate only; layout/API/constants unchanged).

## Related

[30](../30-r6-secure-radio-wire.md) · [05](../05-security-and-compliance.md) · [23](../23-usb-radio-boundary.md) · [24](../24-r2-physical-compliance-permit-authority.md) · [25](../25-u5-cell-operating-assignment.md) · [29](../29-r5-lab-only-profile-loader.md) · [27](../27-r3-airtime-calculator.md) · [ADR-0009](0009-r5-lab-only-profile-loader.md)

## Retained Normative constants (prior R6 freeze; still in force)

- **Relay** still MUST NOT open E2E; docs/25 freeze untouched
- eligible_at; Valid LINK_ACK ≠ fragment acceptance
- frag_ack_wait_ms=5000; frag_retry_interval_ms=500; frag_sender_transfer_ttl_ms=90000; frag_idle_timeout_ms=20000; FRAG_MAX_OUTER_ATTEMPTS_PER_FRAGMENT=16; frag_receiver_transfer_ttl_ms=90000; group_absolute_deadline
- `transfer_start_mono` / immutable `sender_absolute_deadline` set once at outgoing transfer admission
- `retry_not_before` includes `frag_ack_deadline`
- non-retryable issue/expiry/plan fence terminally fails that LINK group
- definite unconsumed+retryable result before TX
- FRAG sender absolute deadline or SINGLE queue/item TTL
- every terminal tombstone expiry uses checked add before atomic commit
- every-4/idle-only generation is forbidden
- tombstones and START reservations follow restart three-way cleanup
- Seal after Permit is forbidden; burn→Seal→Permit order
- positive 100ms/max8; global Permit FIFO; FRAG_ACK-before-LINK_ACK; full CONT cancels PARTIAL
- NEED_CLOSE_OLD→NEED_OPEN→READ_CLASSIFY; copy-owned recovery inputs
- exact namespace distinct from Foundation Runtime storage namespace
- 21-row timer table; 72 B tombstone; crash-atomic exactly-once not claimed
- e2e_attempt_start_mono; ACK burn limits; authority-time domain
- exported private-module drain; ninlil_r5_shutdown; no ordinary fence_after_revoke
- checked_owner_epoch; w1_last_accepted_now_ms (L1 fields)
- R7 materialization requirements frozen; artifacts pending
- Stage 9 docs freeze **Accepted** (independent re-GO 2026-07-19 P0=P1=P2=0); R7/M4/M5/ESP capacity/HIL/legal/production incomplete

## Round 4 repair (docs freeze Accepted; implementation incompletes remain)

Round 3.1 の directionful N6AL / phantom paired N6AL / old_present=0 adopt は独立監査で棄却され、**superseded（非Normative）**。Round 4 は direction-independent allocator、actual-side-only N6AL、`old_present=1` 固定120 B proof、published と trusted baseline の分離、state2 initial-untrusted fence、sample/issue の two-axis mutationを採用する。Independent root QA re-GO 2026-07-19 closed **P0=P1=P2=0** → **R6 docs freeze Accepted**. Remaining incomplete: R7 full AEAD codec / M4·M5 / ESP N6 capacity / RF·USB 実機 HIL / Japan legal / production radio. compile/link ≠ HIL.

## Round 3 repair (still not GO)

Root independent QA found false-green contradictions after round 2. Round 3 replaces older authoritative rows (docs/24 §10.10 generic 41, Algorithm A durable=0, opaque adopt marker, generic UNCONSUMED retry, vague ESP formula, prose-only N6 keys, orphan tails). Status remains **Accepted 仮 / not GO**. Implementation/header ABI for HAL 43/44/45 and F_c helper remains absent.

## Chunk D private N6 host candidate (2026-07-18)

Decision: implement **portable private** N6 under `src/radio/n6_*` only; no public ABI; docs/24+25 frozen; M4/M5/ESP fail-closed until real binders/ports exist. Codec/layouts remain docs/30 §5.3. Completion bar = host candidate + gates, **not** R7 full AEAD / ESP N6 ready / production radio.

**Current status (2026-07-19):** host candidate **fixed-hash integration GO**; R6 docs freeze **Accepted**. R7 full AEAD codec / M4·M5 binder / ESP N6 capacity / RF·USB 実機 HIL / Japan legal / production radio **未完**.

## Chunk D repair — durable production engine + authenticated local identity (2026-07-18)

Closes implementability gaps found by independent QA without changing R2/M4 public ABI or docs/24/docs/25. Host candidate fixed-hash integration GO after re-GO 2026-07-19; R7/M4/M5/ESP capacity/HIL/legal/production remain incomplete.

1. **Production compile set:** Durable install/TX/RX/boot engine and boot invariants **MUST** compile into the production private object (`n6_context_store.c` on the single canonical private source authority with codec+crypto). Production **MUST NOT** ship no-op/fake-success stubs for those paths. Fixture authority stamp and FIXTURE_ONLY install-provenance wrappers may be `NINLIL_N6_TEST_BUILD` / `NINLIL_TEST_ONLY_ARTIFACT`. **Local identity has no raw fixture bind in core.**
2. **Authenticated local identity — exact private accepted adapter ABI (docs/30 §20.4.1):**  
   - Incomplete token; claim ABI v1 **exact** `struct_size == 24` (not ≥); ops v1 **`struct_size == sizeof(ops)`** exactly. Oversized shapes rejected now; extension needs later ADR.  
   - Sole binder `ninlil_n6_bind_local_identity_accepted`. **BOUND** ⇔ storage∧crypto∧identity; bind order arbitrary.  
   - Identity bind only once while **INIT** and unbound; second/rebind/wrong state ⇒ callback 0, `INVALID_STATE`.  
   - Preflight before callback; under reentry, consume **exactly once** (token terminal); claim zero all paths; copy-own node_id16 only on OK+valid shape.  
   - `boot_scan`: missing storage/crypto ⇒ `INVALID_STATE` I/O0; missing identity ⇒ `M4_REQUIRED`+`LOCAL_IDENTITY` I/O0 (empty included); empty success ⇒ BOOTED.  
   - Fixture provider in `tests/support` TEST_ONLY; production archive free of fixture/raw-id tags. Public M4/R2 ABI unchanged.

3. **Boot joins (docs/30 §5.3.1.5):** Lane-set **assembly** identity = joined AL/NS + side + direction + cid (`nsfp, epoch, alloc_side, layer, direction, cid`). Complete lane sets only **after** exact AL join. **Context collision** under direction-independent allocator scope `(membership_epoch, full receiver_node_id[16], layer_code, context_id)` — independent of direction/alloc_side; uses full receiver ID. **Forbidden** dead check `memcmp(nsfp)==0 && alloc_side!=` (nsfp includes alloc_side). N6HW via exact `scope_digest28`. Required negative: valid opposite-side fingerprints, same receiver/cid/epoch/layer, both complete → CORRUPT.
4. **Gates:** tests-OFF production archive; ar member exact-once for `{codec,crypto,context}`; nm all symbols + strings ban fixture tokens / raw identity bind; install tree and expanded ESP exact source set; mutation self-tests for missing context object / static fixture string.

## Chunk D identity API refinement (exact adapter ABI; docs-first)

**Decision:** Adopt exact private accepted adapter ABI (docs/30 §20.4.1): incomplete token, claim v1 24 B, consume statuses, sole `bind_local_identity_accepted`, BOUND iff all three binds, identity required for empty boot, I/O0 preflight, one-shot terminal consume. Supersedes raw `local_identity_t`/`accepted_tag` and core test bind. Host candidate fixed-hash GO after re-GO; R7/production incompletes remain.

## Chunk D boot cross-direction collision fix (docs-first)

**Problem:** Boot cross-direction check that required `memcmp(nsfp)==0 && alloc_side !=` can never fire for valid records because `ns_fingerprint12` incorporates `alloc_side`.

**Decision (docs/30 §5.3.1.5):** Build complete lane sets only after exact AL join. Detect context collision under allocator scope `(membership_epoch, full receiver_node_id, layer_code, context_id)` independent of direction and alloc_side. Assembly identity retains side/direction for lane-set construction; collision compares full receiver ID after join. Required host negative: opposite-side valid fingerprints, same receiver/cid **full durable dual-install KAT → CORRUPT**. Code that still uses nsfp-equality across opposite sides is **non-conforming** until fixed. Host candidate fixed-hash GO after re-GO; R7/production incompletes remain.

## Chunk D ESP boot stack + one-shot providers (hardening tranche)

**Decision:** Multipass `boot_scan` with caller pool workspace; O(1) stack scratch; no heap/VLA; frame/su gates; one-shot storage/crypto/identity binds; fence retains identity; shutdown zeroes providers. Single CMake N6 production source variable. Host candidate fixed-hash GO after re-GO; ESP N6 capacity / HIL / production remain incomplete.

## Boot snapshot + union pool cell (architecture correction)

**Decision (supersedes “rollback each scan”):**

1. **One open + one shared RO txn** for all boot passes; per pass only `iter_open→scan→iter_close`; live txn≤1, live iter≤1; **rollback once** at common cleanup; publish BOOTED/DORMANT only after rollback OK.  
2. **Union pool cell** `union { n6_slot_t live; n6_boot_pack_t boot; }` — no strict-aliasing cast of slot bytes to an unrelated type; public pool byte size unchanged.  
3. BOUND boot entry requires empty live/leases/tickets/CU; zero cells; exit rebuilds empty live canaries; identity retained.  
4. Cleanup tree + provider-shape CORRUPT rules as docs/30 §20.4.1.  
5. **Scaled** namespace ceilings with `C = slot_count ∈ 1..128` (not fixed 1280-only model): complete active H+E ≤ C; lane rows L = 2H+E ≤ 2C; AL A ≤ 2C; RT T ≤ 2C; CF F ≤ C; HW W ≤ 2A and W ≤ 4C; total R = A+L+T+F+W ≤ 11C; logical key+value bytes ≤ 876C. Pins: C=128 → 1408 rows / 112128 B; C=8 → 88 rows / 7008 B. Exact single-snapshot **4 passes** including empty durable happy path (begin1 / open4 / close4 / rollback1); `iter_next` ≤ 4×(11C+1) (C=128 → 5636).  
6. Boot decode scratch is **per-object** (inside the N6 object under the fixed public byte constant); not process-global. Multiple independent Runtime objects do not share mutable N6 boot workspace; same-object concurrent calls remain reentry-forbidden.

Host candidate fixed-hash GO after re-GO 2026-07-19; R7 full AEAD / M4·M5 / ESP capacity / 実機 HIL / legal / production remain incomplete.

## Gate honesty

exact table/set/hash + enumerated mutations only; does not claim arbitrary natural-language contradiction detection; independent human review required; gate PASS ≠ GO; gate PASS ≠ arbitrary natural-language proof.
