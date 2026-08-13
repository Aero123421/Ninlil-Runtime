# ADR-0019: Route Authority and Relay Lifecycle

状態: **Accepted / SPEC_ACCEPTED**
状態補足: ADR-0020とjoint design acceptance（independent final review GO; P0=0 / P1=0）
提案日: 2026-07-28
改訂日: 2026-08-12（caller-owned serial domainを明示化; Normative bytes不変）
受入日: 2026-07-30
SPEC_ACCEPTED日: 2026-07-30（vector `claims.spec_accepted=1`）
RELEASE_SUPPORTED日: —（未達・非主張）

claim境界: 本ADRのAcceptedは **design authorityのSPEC_ACCEPTEDだけ** を意味する。
`claims.spec_accepted=1`、`claims.implementation=0`、`claims.hil=0`、
`claims.release_supported=0`、`claims.public_abi=0` とする。private/default-OFF
implementationとhost/ESP software evidenceは存在するが、public ABI・physical RF HIL・
SLO・legal・production mesh・`RELEASE_SUPPORTED` は未主張であり、physical HIL/RFは
`NOT_RUN`のままである。

## Context

[30章](../30-r6-secure-radio-wire.md)はNRW1のroute handle、lease/fence検査、Hop
open/rewrap、E2E envelope不変、forwarding resourceをAccepted仕様として固定している。
しかしControllerによるroute計算・発行、Cell Agentへのinstall、durable recovery、drain、
operator diagnosticsを接続するlifecycleと **exact private API** は未固定だった。

先行独立audit（NO-GO、P0=0 / P1=9）は次を指摘した。

1. public/private API境界の衝突
2. route-authority ownershipの曖昧さ
3. exact API / storage / recoveryの欠落
4. 物理的に不可能なFRAG drain式
5. loop / terminal / parent churnの未指定
6. custody / evidenceのfalse-successリスク
7. scheduler resources / fairnessの不完全さ
8. mixed-version / default-OFF / rollback mappingの不完全さ
9. vectors / gates / simulation / HILの欠落

本改訂は1〜8とsimulation transcriptを **1つの閉じたNormative authority** で固定する。
private implementationはこのauthorityへ追従する。RF HILは別trancheであり、
ACCEPTANCE節はSPEC_ACCEPTEDの充足証拠と、その先の実機gateを分離して記録する。

## Decision register

| ID | 決定 |
| --- | --- |
| D19-01 | docs/30 NRW1 byte/security/resourceを唯一の正本とし、本ADRは変更しない |
| D19-02 | route APIは **private source-only**。Runtime Platform public ABIを変更しない |
| D19-03 | Controllerが唯一のroute authority issuer。local install ownerが唯一のdurable mutation owner |
| D19-04 | management recordとmaterialized NRW1 exact recordをtype分離し、lease_epochを同値copyする |
| D19-05 | route lookup keyはdocs/30どおり `{ingress_hop_context_id_u32, route_handle_u16, route_generation_u16}` exact |
| D19-06 | lifecycle closed set `STAGED → ACTIVE → DRAINING → EXPIRED → RETIRED` |
| D19-07 | drain完了可能性はchecked-addの **物理可能** FRAG依存式で判定する |
| D19-08 | loop / hop_remaining / terminal / replay-dedup / generation staleをexact fail-closedにする |
| D19-09 | custody transport truthとApplication Receiptを分離し、custodyだけではsuccess表示しない |
| D19-10 | schedulerはbounded queue / priority fairness / backpressure / cancel-drainを持つ |
| D19-11 | default feature flag OFF。mixed-version / downgrade / rollbackをfail-closedにする |
| D19-12 | machine vectors + 独立Python/Node/C gateを機械正本とする。実装・HILは別tranche |
| D19-13 | route/evidence page encode scratch と durable bundle scratch は caller-owned owner workspace に置き、SHA provider KAT は process-global mutable cache を持たず fail-closed に実行する。serial-domain bind pointer の解消は D19-14 で固定する |
| D19-14 | RRMP private catalogのserial domainは既存caller-owned `ninlil_rrmp_owner_t` workspaceそのものとし、全catalog callが明示第1引数で渡す。process-global current-owner pointerは禁止し、別ownerの状態を参照・変更しないこと、owner単位のreentry拒否、unbind/owner-fini時の認証・workspace zeroizationを必須とする |

## Decision

### 1. Scope、owner、failure domain、依存方向

**Scope（in）**

- route management/install record
- local durable route store materialization
- ACTIVE/DRAINING lifecycleとdrain fence
- Relay outer Hop open + bit-identical E2E rewrap
- forwarding admission、queue、bounded retry
- private source-only API surface（`api_version` / `struct_size` / reserved）
- crash-safe storage keys/FULL groupsと`COMMIT_UNKNOWN` classification
- custody hop evidence chain（Application Receiptではない）
- default-OFF capability negotiationとmixed-version拒否

**Scope（out）**

- docs/30 NRW1 wire byte layoutの変更
- public Runtime Platform ABI
- Multi-parent owner handoff（[ADR-0020](0020-multi-parent.md)）
- Wi-Fi / Fabric path selection / Production Attachment
- RF HIL、SLO、field、legal、production support claim

**Owner**

| Role | 権限 | 禁止 |
| --- | --- | --- |
| **Controller route authority** | management/install recordの発行、`controller_term` / `route_revision` fence、planned removal指示 | local durable storeの直接書込み、Cell Agent queueへの直接enqueue |
| **Local route install owner**（1 nodeあたり1） | management → exact NRW1 materialization、lifecycle遷移、FULL storage mutation、queue admission fence | 独自route発行、lease延長、authority termの前進、docs/30 fieldの改変 |
| **Relay forward owner**（install owner配下の同一serial domain） | outer Hop認証後のroute lookup、E2E structural-only検査、rewrap、bounded forward TX要求 | E2E open、payload改変、TxPermit発行、authority再計算 |
| **Scheduler lane owner** | priority fairness、airtime reservation、backpressure | route truthの生成、lease更新 |

**Failure domain**

1 local Fabric storage namespace `ninlil.route.v1` と、そのnode上のroute table /
forwarding queue / per-route inflight全体。1 routeの`COMMIT_UNKNOWN`またはcorruptは
当該pageと参照routeをforward fenceし、未関連routeのACTIVEを推測で落とさない。
ただしdirectory corruptはnamespace全体をACTIVE 0にする。

**依存方向（一方向）**

```text
docs/30 NRW1 Accepted semantics
  -> Controller management/install record
  -> Local route install owner (sole durable mutation)
  -> materialized exact NRW1 route + R2 sidecar
  -> ACTIVE admit
  -> Relay outer auth + E2E structural-only
  -> Scheduler reservation + TxPermit sole authority
  -> radio TX
```

後段から前段のtruthを生成してはならない。route leaseは送信許可ではない。

### 2. Private source-only API（public ABIなし）

本ADRが固定するAPIは **private source-only** である。ヘッダはproduction treeの
`src/` 私有面にだけ置き、インストールpublic header、Platform ABI manifest、
compatibility matrixのpublic surfaceへ載せない。`api_version` / `struct_size` /
reserved規則でsource driftを検出し、安定public ABIを主張しない。

#### 2.1 Common preamble rules

すべてのprivate entry structとrequest/result structは次を先頭に持つ。

```text
offset  size  field
0       4     api_version_u32     /* exact 1 for this ADR revision */
4       4     struct_size_u32     /* exact sizeof(this struct) at compile time */
8       4     reserved0_u32       /* MUST be 0 */
12      4     reserved1_u32       /* MUST be 0 */
```

受理規則（fail-closed、status exact）:

| 条件 | status |
| --- | --- |
| `api_version != 1` | `NINLIL_ROUTE_UNSUPPORTED_API` |
| `struct_size <` 本ADR固定サイズ | `NINLIL_ROUTE_UNSUPPORTED_API` |
| `struct_size >` 固定サイズかつ末尾非zero | `NINLIL_ROUTE_CORRUPT` |
| `struct_size >` 固定サイズかつ末尾zero | 前方互換read; writeは固定サイズだけ |
| `reserved* != 0` | `NINLIL_ROUTE_CORRUPT` |
| NULL required pointer | `NINLIL_ROUTE_INVALID_ARGUMENT` |
| reentrant call into same owner | `NINLIL_ROUTE_REENTRANT` |

caller-owned buffer以外のheap成長、VLA、callback reentry、borrowed pointerの保持を禁止する。
route/evidence page encode と outer durable bundle の全scratchは、その操作を実行する
ownerのcaller-owned workspaceに含める。別ownerと共有するfunction-static scratchを禁止する。
SHA provider KATはempty/`abc`をfail-closedに検査するが、その結果をprocess-global mutable
stateへcacheしない。

RRMP private catalogのserial domainは既存のcaller-owned owner workspaceそのものであり、
`owner_bind(owner)` または `owner_bind_authorized(owner, ...)` の成功後、同じ `owner` を
各catalog callの第1引数として渡す。NULL・未初期化・別ownerを指定したcallは
`INVALID_ARGUMENT`またはrequestに対応するclosed statusかつ対象外ownerへの副作用0。
`owner_unbind(owner)` は当該ownerの認証principal/capabilityをzeroizeし、
`owner_fini(owner)` はworkspace全体をzeroizeする。process-global / thread-local の
implicit current-ownerをcatalog authorityにしてはならない。同一ownerのcatalog callback
実行中に`bind` / `bind_authorized` / `unbind` / `owner_fini`を再入してはならず、
実装は失敗またはno-opとして認証・workspaceを変更しない。

#### 2.2 Private function surface（exact names）

```text
/* all return ninlil_route_status_u32; no public export */
ninlil_route_install_batch
ninlil_route_activate
ninlil_route_begin_drain
ninlil_route_retire
ninlil_route_query
ninlil_route_forward_admit
ninlil_route_forward_complete
ninlil_route_cancel_drain
ninlil_route_recover_commit_unknown
ninlil_route_diagnostics_snapshot
```

#### 2.3 Status codes（closed set, precedence high→low）

```text
1  NINLIL_ROUTE_OK
2  NINLIL_ROUTE_INVALID_ARGUMENT
3  NINLIL_ROUTE_CORRUPT
4  NINLIL_ROUTE_UNSUPPORTED_API
5  NINLIL_ROUTE_UNSUPPORTED_SCHEMA
6  NINLIL_ROUTE_UNSUPPORTED_CAPABILITY
7  NINLIL_ROUTE_AUTHORITY_CONFLICT
8  NINLIL_ROUTE_STALE_GENERATION
9  NINLIL_ROUTE_LEASE_EXPIRED
10 NINLIL_ROUTE_CLOCK_EPOCH_MISMATCH
11 NINLIL_ROUTE_LOOP
12 NINLIL_ROUTE_TERMINAL_MISMATCH
13 NINLIL_ROUTE_HOP_EXHAUSTED
14 NINLIL_ROUTE_REPLAY
15 NINLIL_ROUTE_DRAIN_FENCED
16 NINLIL_ROUTE_NOT_ACTIVE
17 NINLIL_ROUTE_RESOURCE
18 NINLIL_ROUTE_BACKPRESSURE
19 NINLIL_ROUTE_COMMIT_UNKNOWN
20 NINLIL_ROUTE_REENTRANT
21 NINLIL_ROUTE_FEATURE_OFF
```

**Failure precedence（同一callで複数条件が成立する場合）**

```text
INVALID_ARGUMENT
  > CORRUPT
  > UNSUPPORTED_API
  > UNSUPPORTED_SCHEMA
  > FEATURE_OFF
  > UNSUPPORTED_CAPABILITY
  > AUTHORITY_CONFLICT
  > CLOCK_EPOCH_MISMATCH
  > LEASE_EXPIRED
  > STALE_GENERATION
  > NOT_ACTIVE
  > DRAIN_FENCED
  > LOOP
  > TERMINAL_MISMATCH
  > HOP_EXHAUSTED
  > REPLAY
  > RESOURCE
  > BACKPRESSURE
  > COMMIT_UNKNOWN
  > REENTRANT
  > OK
```

実装はmark-only countで成功を装ってはならない。semantic rejectionの前にCRC/digestを
recomputeしてintegrity classを先に確定する（§10）。

#### 2.4 Private C11 signatures（全10操作; private source-only）

すべて `ninlil_route_status_u32` を返す。public export / dynamic symbol を持たない。
`out` は caller-owned 固定 `ninlil_route_result_v1`（§2.5、exact 128 bytes）。
NULL `owner`/`req`/`out` は `INVALID_ARGUMENT`。同一 install-owner serial domain への reentry は
`REENTRANT`。feature_route_relay=0 は preamble通過後 `FEATURE_OFF`（precedence §2.3）。

```c
/* private; not installed public headers */
typedef uint32_t ninlil_route_status_u32;
typedef struct ninlil_rrmp_owner ninlil_rrmp_owner_t;

ninlil_route_status_u32 ninlil_route_install_batch(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_install_batch_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_activate(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_activate_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_begin_drain(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_begin_drain_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_retire(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_retire_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_query(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_query_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_forward_admit(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_admit_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_forward_complete(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_complete_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_cancel_drain(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_cancel_drain_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_recover_commit_unknown(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_recover_cu_req_v1 *req,
    ninlil_route_result_v1 *out);

ninlil_route_status_u32 ninlil_route_diagnostics_snapshot(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_diagnostics_req_v1 *req,
    ninlil_route_result_v1 *out);
```

#### 2.5 Common result layout `ninlil_route_result_v1`（exact 128 bytes）

すべての route private call が同一 result を埋める。pointer を返さない。opaque handle は u64。

```text
offset  size  field
0       4     api_version_u32 = 1
4       4     struct_size_u32 = 128
8       4     reserved0_u32 = 0
12      4     reserved1_u32 = 0
16      4     status_u32              /* same closed set as return; MUST match return */
20      4     detail_flags_u32        /* bit0=cu_classified bit1=drain_active bit2=fenced */
24      8     opaque_local_handle_u64 /* 0 if none; not a pointer */
32      4     ingress_hop_context_id_u32
36      2     route_handle_u16
38      2     route_generation_u16
40      8     next_admission_seq_u64
48      8     lease_epoch_u64
56      8     route_revision_u64
64      8     controller_term_u64
72      4     hop_remaining_out_u32   /* 0 if N/A */
76      1     cu_class_u8             /* 0 NONE 1 OLD 2 NEW 3 ABSENT 4 PARTIAL 5 EXTRA 6 THIRD */
77      1     lifecycle_state_u8      /* 0..5 empty/STAGED/ACTIVE/DRAINING/EXPIRED/RETIRED */
78      2     reserved2_u16 = 0
80      32    evidence_or_digest32    /* operation-specific; zero if unused */
112     16    reserved_tail zero
/* total 128 */
```

**Result ownership / 出力不変規則**

| 規則 | 内容 |
| --- | --- |
| R-OUT-1 | success/failure に関わらず `struct_size=128` と preamble を埋める（部分書込み禁止） |
| R-OUT-2 | `status_u32` は関数戻り値と bit-exact 同一 |
| R-OUT-3 | failure 時 `opaque_local_handle=0`、`evidence_or_digest` は zero または prior durable digest の読取専用再掲 |
| R-OUT-4 | caller は result を free しない; 次 call まで valid; callee は result を retain しない |
| R-OUT-5 | 999 および closed set 外 status は禁止 |

#### 2.6 Exact private request layouts（全10; canonical big-endian on wire/storage fields）

共通: §2.1 preamble 16 bytes を先頭に持つ。`struct_size` は下表 exact。

| op | struct | struct_size | owner |
| --- | --- | --- | --- |
| install_batch | `ninlil_route_install_batch_req_v1` | `56+256*N` (N=1..8) | install owner |
| activate | `ninlil_route_activate_req_v1` | 64 | install owner |
| begin_drain | `ninlil_route_begin_drain_req_v1` | 80 | install owner |
| retire | `ninlil_route_retire_req_v1` | 64 | install owner |
| query | `ninlil_route_query_req_v1` | 48 | any local reader |
| forward_admit | `ninlil_route_forward_admit_req_v1` | 128 | forward owner |
| forward_complete | `ninlil_route_forward_complete_req_v1` | 64 | forward owner |
| cancel_drain | `ninlil_route_cancel_drain_req_v1` | 48 | install owner |
| recover_commit_unknown | `ninlil_route_recover_cu_req_v1` | 80 | install owner |
| diagnostics_snapshot | `ninlil_route_diagnostics_req_v1` | 32 | diagnostics |

**`ninlil_route_install_batch_req_v1`**（exact; N = entry_count 1..8）

```text
struct_size = INSTALL_BATCH_HEADER_BYTES + NRM1_BYTES * N = 56 + 256 * N

+0   api preamble 16
+16  authority_id[16]
+32  controller_term_u64
+40  batch_id_u64
+48  entry_count_u16          /* 1..8 */
+50  reserved2_u16 = 0
+52  reserved3_u32 = 0
+56  entries[N]               /* each NRM1_BYTES=256 */

KAT: N=1 → 312; N=8 → 2104.
Forbidden: 48+8*N.
```

**`ninlil_route_activate_req_v1`**（struct_size=64）

```text
+0   api preamble 16
+16  ingress_hop_context_id_u32
+20  route_handle_u16
+22  route_generation_u16
+24  now_ms_u64
+32  expected_route_revision_u64   /* CAS fence; 0 = any staged */
+40  reserved2_u64 = 0
+48  reserved3_u64 = 0
+56  reserved4_u64 = 0
```

**`ninlil_route_begin_drain_req_v1`**（struct_size=80）

```text
+0   api preamble 16
+16  ingress_hop_context_id_u32
+20  route_handle_u16
+22  route_generation_u16
+24  now_ms_u64
+32  drain_deadline_ms_u64
+40  lease_deadline_ms_u64
+48  item_deadline_ms_u64
+56  reason_code_u32           /* 1 planned_removal 2 parent_loss 3 lease 4 operator */
+60  reserved2_u32 = 0
+64  reserved3_u64 = 0
+72  reserved4_u64 = 0
```

**`ninlil_route_retire_req_v1`**（struct_size=64）

```text
+0   api preamble 16
+16  ingress_hop_context_id_u32
+20  route_handle_u16
+22  route_generation_u16
+24  now_ms_u64
+32  expected_route_revision_u64
+40  force_u8                  /* 0 normal 1 only if DRAINING complete */
+41  reserved2_u8[3] = 0
+44  reserved3_u32 = 0
+48  reserved4_u64 = 0
+56  reserved5_u64 = 0
```

**`ninlil_route_query_req_v1`**（struct_size=48）

```text
+0   api preamble 16
+16  ingress_hop_context_id_u32
+20  route_handle_u16
+22  route_generation_u16
+24  query_mask_u32           /* bit0=lifecycle bit1=lease bit2=drain bit3=cu */
+28  reserved2_u32 = 0
+32  reserved3_u64 = 0
+40  reserved4_u64 = 0
```

**`ninlil_route_forward_admit_req_v1`**（struct_size=128）

```text
+0    api preamble 16
+16   ingress_hop_context_id_u32
+20   route_handle_u16
+22   route_generation_u16
+24   hop_remaining_u8
+25   flags_u8                /* bit0 = is_frag_transfer */
+26   reserved2_u16 = 0
+28   e2e_header_digest32[32]
+60   outer_rx_counter_u64
+68   admission_now_ms_u64
+76   item_deadline_ms_u64
+84   remaining_link_groups_u16
+86   remaining_attempts_u16
+88   max_airtime_ms_u32
+92   turnaround_ms_u32
+96   link_ack_wait_ms_u32
+100  scheduler_guard_ms_u32
+104  inter_group_gap_ms_u32
+108  priority_class_u8       /* 0 CONTROL 1 SAFETY 2 NORMAL 3 BULK */
+109  reserved3_u8[3] = 0
+112  caller_item_token_u64
+120  reserved4_u64 = 0
```

**`ninlil_route_forward_complete_req_v1`**（struct_size=64）

```text
+0   api preamble 16
+16  opaque_local_handle_u64  /* from prior admit result */
+24  outcome_u8               /* 1 TX_OK 2 TX_FAIL 3 CANCELLED 4 EXPIRED */
+25  reserved2_u8[3] = 0
+28  reserved3_u32 = 0
+32  airtime_used_ms_u32
+36  reserved4_u32 = 0
+40  completion_now_ms_u64
+48  reserved5_u64 = 0
+56  reserved6_u64 = 0
```

**`ninlil_route_cancel_drain_req_v1`**（struct_size=48）

```text
+0   api preamble 16
+16  ingress_hop_context_id_u32
+20  route_handle_u16
+22  route_generation_u16
+24  now_ms_u64
+32  expected_drain_fence_u64
+40  reserved2_u64 = 0
```

**`ninlil_route_recover_cu_req_v1`**（struct_size=80）

```text
+0   api preamble 16
+16  observed_group_digest32[32]  /* durable group identity */
+48  expected_class_u8            /* 0 probe 1 OLD 2 NEW 3 ABSENT 4 PARTIAL 5 EXTRA 6 THIRD */
+49  reserved2_u8[3] = 0
+52  reserved3_u32 = 0
+56  now_ms_u64
+64  reserved4_u64 = 0
+72  reserved5_u64 = 0
```

**`ninlil_route_diagnostics_req_v1`**（struct_size=32）

```text
+0   api preamble 16
+16  snapshot_mask_u32        /* bit0=counts bit1=cu bit2=queue */
+20  reserved2_u32 = 0
+24  reserved3_u64 = 0
```

#### 2.7 Per-operation ownership and 出力不変

| op | sole mutator | durable mutation | success 不変 |
| --- | --- | --- | --- |
| install_batch | install owner | FULL group write | partial entry success 禁止; N entries atomic |
| activate | install owner | STAGED→ACTIVE | lease/revision CAS mismatch → AUTHORITY_CONFLICT |
| begin_drain | install owner | ACTIVE→DRAINING + fence immutable | fence fields write-once |
| retire | install owner | →RETIRED tombstone | drain incomplete + force=0 → NOT_ACTIVE |
| query | reader | none | no side effect; no handle allocation |
| forward_admit | forward owner | NEV1 `LIVE`、copy-owned queue、ApplicationData carrier、opaque handle、retry/attempt stateを**同じplatform FULL snapshot**へ置く | same durable_evidence_key while LIVE/COMPLETED → `REPLAY`; no free slot after reclaim → `RESOURCE`; borrowed pointer保持禁止 |
| forward_complete | forward owner | authenticated LINK_ACK authority（またはdurable retry exhaustion）を検証後、NEV1 LIVE→COMPLETED、queue releaseを同じFULL snapshotへ置く | `TX_OK`はauthenticated LINK_ACKなしで必ず`AUTHORITY_CONFLICT` |
| cancel_drain | install owner | DRAINING→ACTIVE only if fence match | mismatch → AUTHORITY_CONFLICT |
| recover_commit_unknown | install owner | classification only | class PARTIAL/EXTRA/THIRD → CORRUPT + seal/forward 0 path |
| diagnostics_snapshot | reader | none | no admission; no seal |

**Hop durable RX admission（§5.1 step 2）と op 表の整合**: `forward_admit` 成功は、
NEV1、queue、carrier、handle、attempt/selected-parentを含む1つのplatform FULL snapshotの
commit pointで線形化する。FULL失敗/不明では成功を返さず、`COMMIT_UNKNOWN`時はownerを
fenceする。carrierは成功前にcopy-ownし、caller bufferをretainしない。

ABI enum: status codes §2.3、precedence §2.3 が唯一 closed set。vector `status_codes_route` /
`failure_precedence_route` は本表と deep-equal 必須（gate 独立 pin）。

### 3. Management recordとmaterialized NRW1 exact record

#### 3.1 Management/install record（canonical big-endian, 256 bytes）

Magic `NRM1`。schema 1。

```text
offset  size  field
0       4     magic "NRM1"
4       2     schema_u16 = 1
6       2     record_length_u16 = 256
8       16    authority_id
24      8     controller_term_u64          /* 1..UINT64_MAX-1 */
32      8     route_revision_u64           /* 1..UINT64_MAX-1 */
40      8     lease_epoch_u64              /* 1..UINT64_MAX-1; == NRW1 lease_epoch */
48      16    authority_clock_epoch_id
64      8     lease_expiry_ms_u64          /* 1..UINT64_MAX-1; == NRW1 expiry and R2 expiry_ms */
72      4     ingress_hop_context_id_u32   /* non-zero, non-MAX */
76      2     route_handle_u16             /* non-zero, non-MAX */
78      2     route_generation_u16         /* non-zero, non-MAX */
80      16    egress_peer_id
96      4     egress_hop_context_id_u32    /* non-zero, non-MAX */
100     2     egress_route_handle_u16      /* 0 only if terminal; else non-zero non-MAX */
102     2     egress_route_generation_u16  /* 0 only if terminal; else non-zero non-MAX */
104     16    grant_id
120     2     queue_quota_entries_u16      /* 1..64 */
122     2     reserved_a_u16 = 0
124     4     queue_quota_bytes_u32        /* 1..16320 */
128     1     max_hops_u8                  /* 1..8; ESP V1 profile default/max = 3 */
129     1     ack_policy_u8                /* 0=NO_LINK_ACK, 1=REQUEST_LINK_ACK */
130     1     terminal_flag_u8             /* 0 or 1; MUST match egress handle/gen zero-pair */
131     1     reserved_b_u8 = 0
132     16    path_policy_id               /* bit-exact NFL1 route_policy_id when present */
148     8     path_policy_revision_u64
156     32    management_body_digest       /* SHA-256 of bytes[0..156) with this field zero */
188     4     crc32c                       /* CRC32C of bytes[0..188) with this field zero */
192     64    reserved_tail                /* all zero */
```

規則:

- zeroと`UINT64_MAX`をterm/revision/epoch/expiry/context/handle/generationに許可しない
  （terminal egress handle/generationの0-pairだけ例外）。
- `terminal_flag=1` ⇔ egress handle=0 かつ generation=0。片側だけ0はCORRUPT。
- `terminal_flag=0` ⇔ 両方non-zero/非MAX。
- 別名`route_epoch`は作らない。management `lease_epoch`をmaterialized NRW1
  `lease_epoch`へ同値copyする。
- authority precedence: 同一`authority_id`内で`controller_term`、次に`route_revision`の
  unsigned numeric降順。後退はreject。同一term/revisionでcanonical digestが異なる場合は
  `AUTHORITY_CONFLICT`としてそのauthorityの全routeをfenceする。同一digest retryのみ
  idempotent。

#### 3.2 Materialized exact NRW1 route record fields（docs/30）

install ownerは1 local FULL atomic materializationで、lookup keyとmanagement valueから
次を欠落なく生成する。

```text
egress_peer_id16
egress_hop_context_id_u32
egress_route_handle_u16
egress_route_generation_u16
authority_id16
lease_epoch_u64
expiry_u64
grant_id16
queue_quota_entries_u16
queue_quota_bytes_u32
max_hops_u8
ack_policy_u8
```

`controller_term` / `route_revision`はmanagement-only fenceであり、NRW1 wire/exact fieldへ
追加しない。

#### 3.3 R2 sidecar（同一atomic unit）

```text
{ clock_epoch_id[16], expiry_ms_u64 }
```

sidecar `expiry_ms`はdocs/30 record `expiry`とexact一致。R2 accepted clock epochと一致し、
かつ`now < expiry_ms`の場合だけACTIVE/forward候補。authority ID、lease epoch、clock epoch、
expiryの不一致/後退/不明ではACTIVE 0、queue admission 0、forward 0、radio TX 0。

### 4. Lifecycle、admission sequence、drain

#### 4.1 States

```text
STAGED -> ACTIVE -> DRAINING -> EXPIRED -> RETIRED
```

| State | new admission | forward existing | radio TX | notes |
| --- | --- | --- | --- | --- |
| STAGED | 0 | 0 | 0 | materialization only |
| ACTIVE | 1 if gates pass | 1 | via TxPermit | sole steady state |
| DRAINING | 0 | bounded eligible only | via TxPermit | immutable drain fence |
| EXPIRED | 0 | 0 | 0 | lease/clock ended |
| RETIRED | 0 | 0 | 0 | tombstone retained bounded |

`now >= lease_expiry`をactivate/admitで検出した遷移もwritepointである。
route pageとplatform FULL snapshotへ`EXPIRED`を永続化できた場合だけ
`LEASE_EXPIRED`を返し、FULL失敗/unknown時はTXをfenceして
`CORRUPT` / `COMMIT_UNKNOWN`を返す。

#### 4.2 Admission sequence

各ACTIVE/DRAINING routeは`next_admission_seq_u64`（初期1）を持つ。
`next_admission_seq == UINT64_MAX`でrouteをfenceし、それ以上のadmissionを0にする。
forward queue itemはadmission時に次をcopy-ownする。

```text
admission_seq_u64
route_revision_u64
absolute_deadline_ms_u64
priority_class_u8
remaining_link_groups_u16
remaining_attempts_u16
opaque_local_handle_u64
outer_rx_counter_u64
outer_tx_counter_u64
retry_count_u16 / retry_limit_u16
link_ack_wait_ms_u32
ack_deadline_ms_u64 / retry_not_before_ms_u64
ApplicationData_len_u16 + ApplicationData bytes
attempt_id16
selected_parent_id16 + selected_parent_set_u8
expected_LINK_ACK_peer_id16
caller_principal_id16
```

#### 4.3 Drain fence（immutable on DRAINING entry）

```text
drain_fence_u64 = next_admission_seq   /* items with admission_seq < fence only */
route_revision_u64                     /* must match item */
drain_deadline_ms_u64
lease_deadline_ms_u64                  /* copy of current lease expiry */
```

許可できるのは:

1. `admission_seq < drain_fence`
2. 同一`route_revision`
3. `completion_ms <= min(item_deadline, drain_deadline, lease_deadline)`（§4.4）
4. priority fairnessとresource gate通過

新規admission、別revision、deadline超過、overflowはforward/TX 0。

#### 4.4 Physically possible drain / resource formula（FRAG依存）

profile snapshotに無い値、0、MAX、overflowはすべてforward/TX 0。

定数（requestまたはprofile; すべてu32、1..3600000）:

```text
A = max_airtime_ms_u32
T = turnaround_ms_u32
W = link_ack_wait_ms_u32
G = scheduler_guard_ms_u32
I = inter_group_gap_ms_u32
```

入力:

```text
now_ms_u64
F = remaining_link_groups_u16     /* SINGLE: 1; FRAG: remaining groups at this hop */
R = remaining_attempts_u16        /* 1..profile.max_attempts; 0/MAX forbidden */
```

**Link-group cost（1 attempt）**

```text
link_group_cost_ms = checked_add_u32(A, checked_add_u32(T, W))
```

**Work cost（全remaining groups × attempts）**

```text
per_group_ms = checked_mul_u64(R, link_group_cost_ms)
work_ms      = checked_mul_u64(F, per_group_ms)
```

**Inter-group gaps**

```text
gaps_ms = (F == 0) ? overflow
        : checked_mul_u64(F - 1, I)
```

**Completion instant**

```text
completion_ms = checked_add_u64(now_ms,
                  checked_add_u64(work_ms,
                    checked_add_u64(gaps_ms, G)))
```

**Physical feasibility gates（すべて必須）**

```text
F >= 1
F <= profile.max_link_groups_per_transfer      /* ESP V1: 13 */
R >= 1
R <= profile.max_attempts_per_group            /* ESP V1: 3 */
checked_mul_u64(F, A) <= profile.max_airtime_budget_ms_per_transfer
completion_ms <= min(item_deadline_ms, drain_deadline_ms, lease_deadline_ms)
completion_ms >= now_ms                        /* overflow/underflow reject */
```

この式は「1 fragmentを同時に無限再送する」ことを仮定しない。各remaining link groupに
対し最大R回の逐次attemptと、group間の最小gap、最終scheduler guardだけを積む。
`F * A`がprofile airtime budgetを超える要求は物理不可能としてrejectする
（以前の「全remaining groupsに同一項を無制限合算して成功扱いになり得る」曖昧さを閉じる）。

FRAG依存: RelayはE2Eを開かない。FRAG transferはdocs/30のouter FRAG pathに従い、
各remaining link groupを独立outerとしてforwardする。drain判定の`F`は
**このhopに残っているlink group数**であり、remote hopの未観測状態を推測しない。

#### 4.5 Planned removal vs sudden failure

**Planned removal order**

1. descendant assessment（diagnostics only; successを主張しない）
2. alternate path staging（STAGED; ACTIVEにしない）
3. new admission fence FULL（ACTIVE→DRAINING）
4. bounded eligible inflight drain（§4.4）
5. retirement evidence FULL（RETIRED）

**Sudden failure**

lease expiryまたはauthority fence。alternate routeなしを成功表示しない。
既存itemはdeadline/leaseで自然に0へ落ち、Application Receiptを捏造しない。

### 5. Relay hop envelope、terminal、loop、replay

#### 5.1 Ingress path（exact order）

1. outer Hop authenticate（docs/30）
2. hop durable RX admission
3. structural-only E2E header validation（docs/30 `RELAY_MUST_STRUCTURAL_E2E_HEADER`）
4. route lookup key = `(ingress_hop_context_id, route_handle, route_generation)`
5. lifecycle / lease / clock / authority gates
6. hop_remaining / terminal invariant
7. loop / replay-dedup gates
8. resource / fairness / drain gates
9. NEV1 + queue + ApplicationData + attempt/handleを1 platform FULLへadmit（copy-own）
10. rewrap bit-identical E2E bytes into new outer Hop
11. TxPermit sole authority → radio TX

いずれかの失敗でqueue admit / forward TX / LINK_ACK / deliver = 0。

#### 5.2 hop_remaining and terminal

docs/30 `ROUTE_TERMINAL_INVARIANT_REMAINING`をそのまま採用する。

```text
if hop_remaining == 1:
  require terminal_flag == 1
  require egress_route_handle == 0 AND egress_route_generation == 0
  remaining' = 0   /* not forwarded as relay; endpoint delivery path */
else:
  require terminal_flag == 0
  require egress handles non-zero/non-MAX
  remaining' = hop_remaining - 1
  require 1 <= remaining' <= record.max_hops
```

`hop_remaining == 0`のDATAはrelay forward 0。
`hop_remaining > record.max_hops`は`HOP_EXHAUSTED`。
terminal mismatchは`TERMINAL_MISMATCH`。

#### 5.3 Loop prevention

local nodeは次のbounded loop bloom（exact）を持つ。

```text
/* Semantic E2E invariant key — outer Hop counters MUST NOT participate.
   Fresh outer_rx_counter / outer rewrap MUST NOT evade LOOP. */
loop_key = SHA-256(
  "NINLIL-ROUTE-LOOP-V1" ||
  e2e_header_digest32 ||                 /* sole E2E structural identity */
  route_handle_u16_be ||
  route_generation_u16_be ||
  local_runtime_id16
)[0..15]
/* FORBIDDEN in preimage: outer_rx_counter, outer_tx_counter, hop_remaining,
   volatile queue index, radio handle, wall-clock */
```

同一`loop_key`がlocal seen-window（**normative exact `LOOP_WINDOW = 256`** entries,
FIFO）に存在すれば`LOOP`。window長はprofileで縮小不可・拡大不可（ESP V1 profileと
同一の固定定数）。seen-window自体はvolatileだが、restart時にdurable LIVE queueから
loop/dedup keyを再構築する。したがってcustody中の同一ingress tupleはrestart後も
`REPLAY`（narrow dedup precedence）となり、別ingressでlocal loop keyが一致する場合は
`LOOP`となる。durable route generation/leaseが進めばstale outerは
`STALE_GENERATION` / `LEASE_EXPIRED`で落ちる。
**durable NEV1** が同一 `e2e_header_digest32` を保持していれば restart 後の
outer rewrap も route/lease ゲートと併せて fail-closed する。

加えて、egress_peer_id == local peer_id のself-forwardを`LOOP`とする。

#### 5.3.1 Normative fixed constants（gate独立pin; vectorから学習しない）

| Constant | Exact value | Domain |
| --- | --- | --- |
| `API_VERSION` | 1 | private API |
| `SCHEMA_VERSION` | 1 | NRM1/NRP1/NRD1/NEV1 |
| `LOOP_WINDOW` | 256 | loop seen FIFO |
| `DEDUP_WINDOW` | 256 | replay dedup FIFO |
| `ROUTE_MAX` | 128 | route records |
| `PAGE_COUNT` | 16 | NRP1 pages |
| `SLOTS_PER_PAGE` | 8 | slots |
| `SLOT_BYTES` | 508 | route page slot size |
| `ROUTE_MAX` | 128 | = 16×8 |
| `NRP1_HEADER_BYTES` | 20 | NRP1 header |
| `NRP1_PAD_BYTES` | 12 | trailing pad |
| `NRP1_BYTES` | 4096 | page size; **exact** `20+8*508+12` |
| `NRM1_BYTES` | 256 | management record |
| `INSTALL_BATCH_HEADER_BYTES` | 56 | install batch fixed header |
| `DIR_BYTES` | 256 | directory |
| `EVIDENCE_BYTES` / `NEV1_BYTES` | 128 | NEV1 record |
| `NEP1_PAGE_COUNT` | 4 | evidence pages |
| `NEP1_SLOTS` | 31 | slots/page |
| `NEP1_HEADER_BYTES` | 24 | NEP1 header |
| `NEP1_PAD_BYTES` | 104 | trailing pad |
| `NEP1_BYTES` | 4096 | **exact** `24+31*128+104` |
| `EVIDENCE_CAPACITY` | 124 | = 4×31 |
| `PHYSICAL_KEY_COUNT` | 21 | = 1+16+4 |
| `QUEUE_GLOBAL_ENTRIES` | 64 | forward queue |
| `QUEUE_GLOBAL_BYTES` | 16320 | forward queue |
| `RESERVED_CONTROL_ENTRIES` | 8 | CONTROL/SAFETY reserve |
| `RESERVED_CONTROL_BYTES` | 2048 | CONTROL/SAFETY reserve |
| `MAX_HOPS_ABSOLUTE` | 8 | hop remaining ceiling |
| `MAX_HOPS_PROFILE_ESP_V1` | 3 | ESP V1 default/max |
| `MAX_LINK_GROUPS` | 13 | FRAG remaining groups |
| `MAX_ATTEMPTS` | 3 | per link-group attempts |
| `MAX_AIRTIME_BUDGET_MS` | 60000 | drain airtime gate |
| `INSTALL_BATCH_MAX` | 8 | routes/batch |
| `LOGICAL_MUTATIONS_MAX` | 9 | storage mutations/batch |
| `WIRE_PROFILE_ID` | 0x11 | NRW1 |

schema ≠ 1 のNRD1/NRP1/NRM1は、CRCをrepairしてframeが通っても
`UNSUPPORTED_SCHEMA`（または同等fail-closed）でrejectする。CRC OKはsemantic成功を
意味しない。

#### 5.4 Replay / dedup

```text
/* Semantic E2E+ingress invariant — outer wrap counters MUST NOT participate. */
dedup_key = SHA-256(
  "NINLIL-ROUTE-DEDUP-V1" ||
  e2e_header_digest32 ||
  ingress_hop_context_id_u32_be ||
  route_handle_u16_be ||
  route_generation_u16_be
)[0..15]
/* FORBIDDEN: outer_rx_counter, outer_tx_counter, admission wall-clock */
```

同一keyの再admitは`REPLAY`。windowは **normative exact `DEDUP_WINDOW = 256`**。
custody evidence（NEV1）にはfirst-admitだけを durable FULL で記録し、duplicate は
diagnostics counter にだけ積む（NEV1 二重書込 0）。

#### 5.5 Route replacement and parent churn

同一lookup keyへのreplacementは`route_revision`前進かつmanagement digest更新を要する。
旧revisionのinflightはDRAINING fenceでだけ完了でき、new revisionへのsilent mergeは0。

parent churn（[ADR-0020](0020-multi-parent.md)）がroute setを無効化する場合:

1. 影響routeを一括DRAINING fence（batch ≤ 8）
2. new parent assignmentのACTIVE後にだけnew routesをSTAGED→ACTIVE
3. same-attemptの経路reselectionは禁止（`same_attempt_reselect_calls = 0`）
4. new attempt identityでのみ新routeを使用

### 6. Custody hop evidence vs Application Receipt

| Truth | Owner | Meaning | Success display |
| --- | --- | --- | --- |
| **Hop custody evidence** | Relay forward owner | outer accepted/forwarded/acked at this hop | transport diagnostics only |
| **Route admission evidence** | install owner | item admitted under exact revision/lease | not application success |
| **Application Receipt** | upper U6 / application owner | application effect committed | sole application success |

禁止:

- hop LINK_ACKだけでApplication Receiptを合成する
- custody chainの欠落hopをsuccessに丸める
- partial forwardをend-to-end delivery成功と表示する
- evidence counterの増加だけでgateをpassさせる（mark-only禁止）

**Evidence record `NEV1`（canonical exact 128 bytes; field offset table）**

```text
offset  size  field
0       4     magic "NEV1"
4       2     schema_u16 = 1
6       2     length_u16 = 128
8       2     route_handle_u16
10      2     route_generation_u16
12      8     admission_seq_u64          /* 1..MAX-1; mono per route generation */
20      32    e2e_header_digest32        /* semantic E2E identity */
52      8     outer_rx_counter_u64       /* diagnostics only; NOT in durable key */
60      8     outer_tx_counter_u64       /* diagnostics only */
68      16    local_runtime_id16
84      1     hop_remaining_in_u8
85      1     hop_remaining_out_u8
86      1     lifecycle_u8
                /* 1 LIVE_ADMITTED 2 COMPLETED  — EMPTY is all-zero slot (no NEV1) */
87      1     reserved0_u8 = 0
88      4     result_status_u32
92      32    body_digest32 = SHA-256(bytes[0:92))
124     4     crc32c of bytes[0:124)
/* 128 */
```

**Durable evidence key**（restart-safe; outer counters excluded）:

```text
durable_evidence_key = SHA-256(
  "NINLIL-ROUTE-EVIDENCE-KEY-V1" ||
  e2e_header_digest32 ||
  route_handle_u16_be || route_generation_u16_be ||
  admission_seq_u64_be
)
/* FORBIDDEN: outer_rx/tx, queue index, wall-clock, lifecycle */
```

**Durable evidence capacity（arithmetic; sole numbers）**

```text
NEP1_PAGE_COUNT     = 4
NEP1_SLOTS          = 31
EVIDENCE_CAPACITY   = NEP1_PAGE_COUNT * NEP1_SLOTS = 124
/* occupied = count of LIVE + COMPLETED only; EMPTY free */
/* page layout exact offsets: §8.4.1 */
```

#### 6.1 First-admit / complete / free（normative lifecycle）

| Event | Durable effect | Capacity |
| --- | --- | --- |
| first-admit | write NEV1 lifecycle=**LIVE** FULL | +1 occupied |
| same key while LIVE/COMPLETED present | `REPLAY`（no write） | unchanged |
| `forward_complete` | LIVE→**COMPLETED** FULL（result_status + digests/CRC） | **unchanged**（not free） |
| status-only rewrite without lifecycle COMPLETED | forbidden as free; still occupied | unchanged |
| reclaim GC（§6.2） | COMPLETED→**EMPTY**（slot all-zero） | −1 occupied |
| route-generation retirement GC | all NEV1 with (handle, gen) → EMPTY | frees those slots |

**`forward_complete` alone is never capacity free.** Mark-only counters 禁止。

#### 6.2 Bounded GC / compaction / reuse

**Retention horizon（exact）**

```text
EVIDENCE_RETENTION_COMPLETED = 0
/* An unpinned COMPLETED record is immediately reclaim-eligible (capacity liveness).
   REPLAY while COMPLETED still present until reclaimed.
   After EMPTY, durable REPLAY for that key ends; volatile DEDUP_WINDOW may still apply.
   A COMPLETED record referenced by a QST4 TERMINAL used-attempt row is pinned:
   neither ordinary capacity GC nor route-generation retirement may erase it.
   Only QST4 v2 explicit reclaim may erase the row and its matching evidence/tombstone,
   in the same FULL transaction, after that row's reclaim_not_before_ms.
   Route generation advance/retirement is the durable stale path only for unpinned
   old-generation keys. */
```

**Reclaim algorithm**（forward_admit 前、または install owner の explicit GC; どちらも同一）:

```text
1. free = EVIDENCE_CAPACITY - count(LIVE|COMPLETED)
2. if free > 0: skip reclaim
3. reclaim candidate = deterministic first COMPLETED slot not pinned by a QST4
   TERMINAL used-attempt row
4. その1 slotをzeroし、同じadmissionが同slotをLIVEとして再利用して同一NEP1 pageをFULL
5. if still free == 0 after reclaim: also run generation retirement GC for RETIRED routes
6. if still free == 0: forward_admit → RESOURCE
```

**Generation retirement GC**（route retire / generation supersede）:

```text
for each NEV1 with route_handle H and route_generation G retired:
  slot → EMPTY FULL
/* old (e2e,H,G,seq) no longer durable-REPLAY; route lookup fails STALE_GENERATION first */
```

**Reuse**: admit places into EMPTY slot (probe skips LIVE/COMPLETED).  
**Old replay reject**: LIVE/COMPLETED match key → REPLAY; EMPTY after reclaim → not durable REPLAY.

#### 6.3 Restart / CU / liveness invariant

**Restart**
- volatile: raw loop_window / dedup_window buffers → clear後、durable LIVE queueから再構築
- durable: forward queue、opaque handle、ApplicationData、attempt/selected parent、
  retry/ACK wait、authenticated ACK authorityをbit-exact復元
- durable NEP1 LIVE/COMPLETED survive bit-exact
- EMPTY remains free
- CU classify NEP1 pages before forward（§8.7）

**Liveness（must hold）**

```text
occupied <= 124 always
after complete+reclaim, occupied may return to 0
lifetime first-admits may exceed 124 (prove with vector >124 sequence)
```

**FULL group（first-admit / complete / reclaim）**: single NEP1 page rewrite atomic
（§8.4.1 + directory evidence bitmap/generation）。partial slot publish 禁止。

#### 6.3.1 Durable queue / carrier / ACK snapshot（schema 3）

route/parent dual namespace envelope `RRMPNS1` のsoft trailerは `RRMPQST3`
（schema_u16=3）とする。pointer dumpやqueue slot indexの保存は禁止し、次の
canonical logical recordだけを保存する。

| record | exact bytes | 内容 |
| --- | ---: | --- |
| header | 48 | magic、schema、scope/queue/evidence count、declared length、CRC32C、next handle、lifetime admits、fairness streak、carrier total |
| scope aux | 64 | owner_scope_id、last_attempt_id、selected_parent、parent_lost bitmap、attempt-selected flag @56、scope seal flags @57（split-brain / parent-loss / old / new）、reserved @58..63 zero |
| LIVE evidence aux | 72 | evidence key32、opaque handle、outer TX counter、authenticated ACK peer16、ACK flag |
| queue record | 320 | route key/seq/deadline、retry/ACK timers、E2E digest+exact body、scope/attempt/selected parent/expected peer/caller principal |
| carrier | variable, queue直後 | `carrier_len` exact bytes。全queue合計は16320 bytes以下 |

header CRC32C、declared length、count、reserved zero、queue↔LIVE evidenceのbijection、
route exact materialization、handle単調性、carrier合計、retry invariantのどれかが不一致なら
import失敗、downlink TXをfenceする。旧schema 1はLIVE evidenceが1件もない場合だけ読める。
旧`RRMPQST2`（schema 2）は読み取り互換だけを持つがscope seal flagsを表現できないため、
parent scopeは再assignmentされるまでfail-closedとし、送信許可を復元してはならない。

物理submit後とLINK_ACK処理後のplatform FULLは、電波/peer側効果より遅い。そのため
`COMMIT_UNKNOWN`後のdurable imageはOLDまたはNEWのどちらでもよいが、次を満たす。

- TX OLD: 同じcopy-owned semantic carrierをat-least-once再送可。ACKを合成しない。
- TX NEW: retry counter/ACK deadline/outer counterを復元する。
- ACK OLD: queueはawait-ACKのまま。successful completeは禁止。
- ACK NEW: queueは解放済み、authenticated ACK auxからduplicate ACKと同一handle completeを
  idempotentに再開する。

#### 6.3.2 Caller authorization

`authorization_required=1`ではunauthorized `owner_bind(owner)`を禁止し、
外部authorizerが検証したprincipal/capabilityだけをexplicit serial domainへbindする。
caller自己申告のcapability/proofは
それ自体をauthorityとみなさない。closed capabilityは
`ROUTE_ADMIN / FORWARD / PARENT_ADMIN / DIAGNOSTICS / BEARER / WORKER`。
管理、read、forward、authenticated ACK、timeout workerの各APIは必要capability欠落時
`AUTHORITY_CONFLICT`で副作用0とする。

**Evidence chain digest**（diagnostics only; not sole authority; appears once）:

```text
chain' = SHA-256("NINLIL-ROUTE-EVIDENCE-V1" || chain || nev1_bytes[0:124))
```

**Rewrap**（appears once）: outer Hop は新規、E2E bytes は bit-identical（payload mutation 0）。
outer rewrap は loop/dedup/durable_evidence_key を変えない。
### 7. Scheduler resources、priority fairness、backpressure、cancel/drain

#### 7.1 Bounds（ESP V1 profile; machine profile ID `ESP_V1_CANDIDATE`は互換性のため不変）

| Resource | Bound | Exhaustion |
| --- | --- | --- |
| route records | **128** = `PAGE_COUNT * SLOTS_PER_PAGE` = 16×8 | install reject |
| forward queue entries global | 64 | `RESOURCE` or `BACKPRESSURE` |
| forward queue bytes global | 16320 | same |
| per-route queue entries | `queue_quota_entries` | same |
| per-route queue bytes | `queue_quota_bytes` | same |
| per-route inflight TX | 2 | `BACKPRESSURE` |
| global inflight TX | 8 | `BACKPRESSURE` |
| loop/dedup window | 256 each | oldest drop from window only; not route truth |
| **evidence durable capacity** | **124** LIVE+COMPLETED | `RESOURCE` only if free==0 after COMPLETED reclaim + gen GC（§6.2） |
| airtime reservation | profile budget | `RESOURCE` |
| install batch | 8 routes / ≤9 logical mutations | reject; partial success禁止 |
| **physical keys** | **21** = 1 + 16 + 4 | key table §8.2 |

CONTROL/SAFETY reserved capacity: global queueのentries 8 / bytes 2048を
CONTROL+SAFETY専用に予約する。NORMAL/BULKはこれを横取りしない。

#### 7.2 Priority fairness

dequeue order:

```text
1. priority_class ascending (CONTROL=0 ... BULK=3)
2. absolute_deadline_ms ascending
3. admission_seq ascending
4. route_handle ascending
```

同一class内でstarvationを避けるため、BULK連続dequeue上限は8。超過時は次のhigher
classがemptyの場合のみ継続できる。

#### 7.3 Backpressure and cancellation

- `BACKPRESSURE`: 一時的資源不足。itemは未admit。callerはsame attemptで再admitしてよいが、
  route reselectionは禁止。
- `RESOURCE`: profile hard ceiling。same attempt再admitも0。new attempt + policy要。
- cancel/drain: `ninlil_route_cancel_drain`はDRAINING fenceを早めない。item tokenごとの
  cancelはqueue上の未TX itemだけを外し、issued Permitがあるitemはdocs/30 drain pathへ渡す。

### 8. Durable storage layout（crash-safe）

#### 8.1 Domain

既存Runtime/control namespaceへ行単位追加しない。別物理Fabric storage domain:

| Namespace | Purpose |
| --- | --- |
| `ninlil.route.v1` | routes（本ADR） |
| `ninlil.parent.v1` | parent assignment（ADR-0020） |

ESP physical format 4を再利用する。production 2 namespaceの一方/他方として予約する。
既存Runtime namespace、`ninlil.ctl.v1`の32-key budget、同一partition wear budgetを
暗黙共有しない。

#### 8.2 Keys（namespace `ninlil.route.v1`）— exact budget 21

**Arithmetic (normative; sole formula):**

```text
PHYSICAL_KEY_COUNT = 1 + PAGE_COUNT + NEP1_PAGE_COUNT
                   = 1 + 16 + 4
                   = 21
/* former "≤17" is FORBIDDEN: 1+16 already exhausts 17 with zero NEP1 room */
```

| Key ID | Count | Name | Value max |
| --- | --- | --- | --- |
| 0 | **1** | directory `NRD1` | 256 bytes |
| 1..16 | **16** | page `NRP1` (page_index 0..15) | 4096 bytes |
| 17..20 | **4** | evidence page `NEP1` (page_index 0..3) | 4096 bytes |
| **sum** | **21** | — | — |

physical key bytes（20）:

```text
"NR" || namespace_tag_u8=1 || key_id_u8 || zero16
/* key_id 0..20 only; 21..255 reserved reject */
```

#### 8.3 Directory `NRD1`（exact 256 bytes; route + evidence bitmaps）

```text
offset  size  field
0       4     magic "NRD1"
4       2     schema_u16 = 1
6       2     length_u16 = 256
8       8     directory_generation_u64       /* 1..MAX-1 mono-inc */
16      16    authority_id[16]
32      8     controller_term_u64            /* 1..MAX-1 */
40      2     route_page_bitmap_u16          /* bits 0..15 → NRP1 present */
42      2     evidence_page_bitmap_u16       /* bits 0..3 → NEP1 present; bits 4..15 = 0 */
44      64    route_page_generation[16]_u32  /* 0 = absent; else 1..MAX-1 */
108     16    evidence_page_generation[4]_u32
124     128   reserved_mid zero
252     4     crc32c of entire 256 with this field zero
/* check: 44+64+16+128+4 = 256 */
```

規則:
- `route_page_bitmap` bit i set ⇔ `route_page_generation[i] ≠ 0`
- `evidence_page_bitmap` bit j set ⇔ `evidence_page_generation[j] ≠ 0`；j≥4 bit は 0
- schema ≠ 1 → `UNSUPPORTED_SCHEMA`（CRC repaired でも reject）

#### 8.4 Page `NRP1`（fixed exact 4096 bytes）

**Checked capacity (normative; must hold in gate KATs):**

```text
NRP1_HEADER_BYTES = 20
SLOTS_PER_PAGE    = 8
SLOT_BYTES        = 508
slots_span        = 8 * 508 = 4064
NRP1_PAD_BYTES    = 12
NRP1_BYTES        = 20 + 4064 + 12 = 4096
```

Forbidden: any pad that yields `20+8*508+pad ≠ 4096`（例: pad=52 → 4136）。

```text
offset  size  field
0       4     magic "NRP1"
4       2     schema_u16 = 1
6       2     page_index_u16           /* 0..15 */
8       4     page_generation_u32      /* non-zero non-MAX */
12      2     occupied_slot_bitmap_u16 /* bits 0..7 */
14      2     reserved0 = 0
16      4     crc32c of entire page with this field zero
20      4064  8 slots × 508 bytes
4084    12    reserved pad all zero
```

**Slot exact 508 bytes**

```text
0     1   state_u8                 /* 0 empty, 1 STAGED, 2 ACTIVE, 3 DRAINING, 4 EXPIRED, 5 RETIRED */
1     1   reserved0 = 0
2     2   reserved1 = 0
4     4   ingress_hop_context_id
8     2   route_handle
10    2   route_generation
12    256 management record NRM1
268   96  materialized exact body (docs/30 fields canonical pack)
364   24  R2 sidecar {clock_epoch_id16, expiry_ms_u64}
388   32  drain fence {drain_fence_u64, route_revision_u64, drain_deadline_ms_u64, lease_deadline_ms_u64}
420   8   next_admission_seq_u64
428   32  slot_digest
460   4   slot_crc32c
464   44  reserved_tail zero
/* 0..508 exclusive; 464+44=508 */
```

**Slot integrity preimage（normative; page CRC の前に独立検証）**

```text
slot_digest[32] = SHA-256(slot[0..428))
  /* digest field itself is NOT in the preimage: hash covers only bytes before offset 428 */
slot_crc32c_u32 = CRC32C(slot[0..460))
  /* CRC covers header+body+digest; CRC field held outside the preimage */
reserved_tail[44] at 464..508 MUST be all zero on every non-empty and empty slot
```

Occupied slot（page bitmap bit=1）は次を **page CRC より先に** fail-closed 検証する:

1. `reserved0`/`reserved1`/`reserved_tail` 全 zero
2. embedded NRM1（12..268）full framing/integrity/range/terminal invariant
3. materialize_exact(NRM1) == bytes 268..364 bit-exact
4. R2 sidecar clock_epoch_id non-all-zero; lease_expiry_ms ∈ (0, UINT64_MAX)
5. state=DRAINING のとき drain fence 4×u64 はすべて non-zero/non-MAX; 他stateは drain 領域 all zero 可
6. `next_admission_seq` ∈ (0, UINT64_MAX) for state∈{STAGED,ACTIVE,DRAINING}
7. `slot_digest` / `slot_crc32c` 上記 preimage exact match

empty slot（bitmap bit=0）は 508 bytes 全 zero。tombstone（RETIRED）と empty を state で区別する。
volatile radio handle、pointer、queue slot index は保存しない。一方、opaque semantic
handle、copy-owned queue/carrier、retry/ACK authorityは§6.3.1のcanonical recordへ保存する。
page CRC だけ通しても slot reserved/digest/CRC/NRM1 違反は **CORRUPT**（semantic success にしない）。

#### 8.4.1 Evidence page `NEP1`（exact 4096 bytes; sole layout site）

```text
NEP1_HEADER_BYTES = 24
NEV1_BYTES        = 128
NEP1_SLOTS        = 31
slots_span        = 31 * 128 = 3968
NEP1_PAD_BYTES    = 104
NEP1_BYTES        = 24 + 3968 + 104 = 4096
NEP1_PAGE_COUNT   = 4
EVIDENCE_CAPACITY = 4 * 31 = 124
```

```text
offset  size  field
0       4     magic "NEP1"
4       2     schema_u16 = 1
6       2     page_index_u16            /* 0..3 only */
8       4     page_generation_u32       /* 1..MAX-1 mono-inc */
12      4     occupied_count_u32        /* LIVE+COMPLETED only; 0..31 */
16      4     reserved0_u32 = 0
20      4     crc32c of entire page with this field zero
24      3968  31 × NEV1 slots (§6 field table)
3992    104   reserved pad zero
```

Placement:

```text
page_index = durable_evidence_key[1] % NEP1_PAGE_COUNT   /* 0..3 */
slot_index = durable_evidence_key[0] % NEP1_SLOTS        /* 0..30 */
/* linear probe within page; then next page mod 4; full → RESOURCE */
```

#### 8.5 Placement

page slotを`route_handle mod 128`だけで一意化しない。
placement:

```text
primary = (ingress_hop_context_id xor (route_handle << 16) xor route_generation) mod 128
slot_index = primary   /* 0..127 maps to page=index/8, slot=index%8 */
```

衝突時は+1 linear probe、最大128回で停止。occupied distinct keyを上書きしない。
満杯はinstall `RESOURCE`。

#### 8.6 FULL groups and batch atomicity

1 install batch:

- routes ≤ 8
- logical storage mutations ≤ 9（directory 1 + touched NRP1/NEP1 pages ≤ 8）
- 上限分割して部分成功にしない

lifecycle遷移（activate/drain/retire）も当該slotを含むpage + directory generationの
FULL groupとして書く。

first-admit `forward_admit` FULL group:

- touched NEP1 page + NRD1 evidence bitmap/generation 更新
- route NRP1 を同 batch で触る場合も mutations ≤ 9

#### 8.7 COMMIT_UNKNOWN classification

recoveryはfresh READ_ONLY snapshotだけで判定し、状態を推測しない。

| Classification | Observed | Action |
| --- | --- | --- |
| **OLD** | exact old page+directory group | keep old; forward under old if still ACTIVE/eligible; retry new mutation |
| **NEW** | exact new page+directory group | accept new; continue |
| **ABSENT** | neither old nor new after fresh install attempt | no publish; retry install |
| **PARTIAL** | subset of expected keys, missing members | CORRUPT/fence touched routes; ACTIVE 0 for those |
| **EXTRA** | expected group + unexpected key | CORRUPT/fence namespace or touched set |
| **THIRD** | value neither old nor new canonical bytes | CORRUPT/fence |

`COMMIT_UNKNOWN`中は対象route forward/TX 0。classification完了前にACTIVEへしない。

#### 8.8 Platform FULL envelope and exact rollback

`NINLIL_FEATURE_ROUTE_RELAY`のprivate実装でplatform Storageをbindした場合、NRP1/NEP1の
dual page commitは**inner construction**であり、public operationのlinearization pointではない。
route namespace、parent namespace、queue/carrier/attempt soft trailerを含む論理
`RRMPNS1` exportはPlatform Storageの単一valueではない。次のbounded bundleを同一
caller-opened authority namespaceの1つの`FULL` transactionで保存し、そのcommitだけを
outer writepointとする。

```text
manifest key  = "RRMP/M1"                 /* exact 7 bytes */
chunk keys    = "RRMP/C0".."RRMP/C4"      /* each exact 7 bytes */
manifest      = RRM1 schema 1, exact 256 bytes
chunk maximum = 61,440 bytes
chunk count   = canonical ceil(total_length / 61,440), 1..5
logical max   = 307,200 bytes
```

`RRM1` exact layout:

```text
0     4   magic "RRM1"
4     2   schema_u16 = 1
6     2   length_u16 = 256
8     8   bundle_generation_u64           /* 1..MAX-1 */
16    4   logical_total_length_u32         /* 1..307200 */
20    1   chunk_count_u8                   /* 1..5, canonical minimum */
21    3   reserved zero
24   32   SHA-256(exact logical RRMPNS1 bytes)
56  180   5 × {chunk_length_u32, chunk_sha256[32]}
236  16   reserved zero
252   4   CRC32C(full 256 bytes with this field zero)
```

unused descriptorは全zero、unused chunk keyはabsentでなければならない。各chunk lengthは
1..61,440（最終chunk以外はexact 61,440）、descriptor SHAはexact valueに一致する。
Platformへの全`put`は65,536 bytes以下でなければならない。

- 各ownerは最後にfresh readしたouter bundleを
  `(present, exact manifest bytes, logical length, logical SHA-256)`として保持する。
- standard Storage bindは、同じREAD_WRITE snapshot内でcurrent witnessをexact比較し、
  canonical chunk setをstage、unused chunkをerase、manifestを書いて1回だけFULL commitする。
  stale witnessは`AUTHORITY_CONFLICT`であり、blind overwriteしない。この保証はFoundation
  Storageのexact namespace exclusive-writer contract内に限る。
- 同snapshotで`RRMP/` prefixをiterator列挙し、認識済みmanifest/chunk以外、重複、
  non-canonical order、missing、unused-but-presentを拒否する。point `get`だけは
  closed-key-set evidenceではない。
- 複数handle/複数Controllerが同じauthority namespaceへ到達する構成は、private/default-OFF
  storage-authority **v2** piece-vector serializable CAS providerを必須とする。providerは
  manifest+canonical chunk set全体を1比較交換単位とし、同じexpected witnessに対して最大1
  callerだけを成功させる。v1 single-value callbackはbundle mutationを許可せず
  `UNSUPPORTED_API`で閉じる。public Storage ABI、wire、installed SDK ABIは変更しない。
- begin/get/put/erase/commitのdefinite failureではbundleは非commitでなければならない。
  Coreはfresh READ_ONLYでexact OLD bundleを再確認し、RAM/inner dual pages/soft stateをOLD
  から再構築する。exact OLDでなければCORRUPT + global fenceであり、部分RAMをqueryへ公開しない。
- outer `COMMIT_UNKNOWN`ではexact OLD/NEW bundle witnessを保持し、mutation、
  route/parent select、bearer send、worker、state queryをglobal fenceする。fresh readが
  exact OLDまたはexact NEWのときだけfenceを解除する。missing/extra/unknown key、
  bad manifest/chunk、PARTIAL/EXTRA/THIRDはCORRUPTのまま解除しない。

bounded arithmetic:

```text
route=82,457 + parent=86,566 + retained FULL group=36,981
+ QST4=84,696 + RRMPNS header=20 = 290,720
5*61,440 = 307,200; headroom = 16,480
```

送信providerが既にpacketを受理した後のouter writepointは§6.3.1のat-least-once規則に従う。
definite failureでRAMはexact OLDへ戻り、再送され得るbytes/attempt identityを変更しない。

### 9. Mixed-version、default-OFF、downgrade、rollback

| Topic | Rule |
| --- | --- |
| Feature flag | `NINLIL_FEATURE_ROUTE_RELAY` default **OFF** |
| Capability | critical negotiated capability。非対応peerへsilent route変換しない |
| Schema | schema≠1 → `UNSUPPORTED_SCHEMA`; forward 0 |
| API version | api_version≠1 → `UNSUPPORTED_API` |
| Wire | NRW1 `wire_profile_id=0x11`不変。byte意味変更は新profile ID |
| Downgrade | new schema pageをold binaryが読んだらfence; wipeしない; forward 0 |
| Rollback | Controllerが旧revisionを再発行するにはterm前進が必要。同一termでのrevision後退はreject |
| Rolling update | Cell Agent単位でdrain→retire→new install。mixed tableでpartial mesh successを表示しない |
| Default-OFF path | feature offならprivate APIは`FEATURE_OFF`。direct single-hop endpoint pathのみ（docs/30 route_handle=0） |

### 10. Integrity: CRC/digest repair before semantic rejection

gate/vector/実装oracleは次の順序を守る。

1. framing（magic/length）
2. CRC32C recompute（field zero → compare）
3. digest recompute
4. reserved zero checks
5. semantic field gates
6. lifecycle/authority/resource gates

mutation testは **semantic rejectの前にCRC/digestをrepair** してから、意図したsemantic
faultだけを観測する。CRC破壊のままで「semantic statusを数えた」mark-onlyは禁止。
self-comparison（入力をそのままexpectedに写す）も禁止。独立再計算のみ。

### 11. Machine vectors and simulation

Normative machine authority:

- `spec/vectors/route-relay-multiparent-spec-v1.json`
- `tools/route_relay_multiparent_spec_vector_gen.py`
- `tools/route_relay_multiparent_spec_gate.py`
- `tools/route_relay_multiparent_spec_gate.mjs`

必須executable cases（ID inventoryはvector `required_ids`が正本）:

1/2/3-hop routes、loop、duplicated relay、stale generation、parent loss mid-flight、
simultaneous parents/controllers、split-brain、lease expiry at boundary、route handoff、
old ACK/custody/evidence、retry/restart/power-cut、resource exhaustion、priority isolation、
drain、COMMIT_UNKNOWN OLD/NEW/PARTIAL/EXTRA/THIRD、storage arithmetic、bounded simulation
transcript。

本ADR単体のvector ID prefixは`RR-`。multi-parent連結IDは`MP-` / `RRMP-`。

## Compatibilityとmigration

- NRW1 `wire_profile_id=0x11`は不変。
- route store schemaはFoundation schema、N6 schema、ESP physical format 4と別domain。
- route非対応peerはcritical capability negotiationでattach拒否し、direct routeへsilent変換しない。
- rolling updateはControllerが新旧capabilityを理解した後、Cell Agent単位でdrainして行う。
- schema migration中またはowner不明時は対象routeをACTIVEにしない。
- Runtime Platform public ABIは変更しない。

## Dependencies

M1a restart-safe kernel、M3 durable storage、ADR-0017 Fabric、M7 scheduler、
NRW1 LINK/FRAG/state implementationを前提とする。Multi-parentは本ADRのroute lease、
drain、fencingへ依存する。private/default-OFF implementationは本設計authorityへ
追従するが、SPEC_ACCEPTEDだけをimplementation completeまたはrelease-supported
authorityとして扱ってはならない。

## Acceptance

### SPEC_ACCEPTED（2026-07-30充足）

ADR-0020とjointに、次の設計gateをすべて充足した。独立最終レビュー
[2026-07-29 RRMP final repair independent review](../reviews/2026-07-29-rrmp-final-repair-review.md)
は最終repairへの非関与を明記し、P0=0 / P1=0でjoint promotion可能と判定した。
promotion後のgenerator / Python / Node / C gate再実行は
[2026-07-30 RRMP SPEC_ACCEPTED promotion](../work/2026-07-30-rrmp-spec-accepted-promotion.md)
に固定する。これはRelayのimplementation complete、physical target/RF HIL、
production supportを意味しない。

1. 本ADRのprivate API（全10 C11 signature + req/result exact layouts）、status precedence、record layoutsが独立reviewでP0=P1=0
2. management/materialized/R2/drain/page/directoryのoffset/byte/CRC/digest KATがcross-language一致
3. docs/30 route field対応表に未対応・重複fieldが0
4. drain物理可能式、authority precedence、batch atomicity、COMMIT_UNKNOWN行列が独立再計算
5. ESP32-S3静的resource見積りが成立し、全exhaustion fail-closed
6. compatibility、default-OFF、rollback、unknown schemaが独立review承認
7. vector required-ID inventory完全、Python/Node gate緑、simulation transcript固定

### RELEASE_SUPPORTED（未達・非主張）

private/default-OFF implementationについて、docs/34および本ADR旧版RELEASE節の
physical HIL/soak条件は未充足である。本昇格はそれらの完了を主張しない。

## Consequences

route byte semanticsを変えず、設置・撤去・障害時のRelay lifecycleを **仕様として** 閉じられる。
代わりにController authority、durable route store、bounded forwarding queue、
topology simulator、複数実機HILが必要になる。public ABIは増やさない。

## Rejected alternatives

- Relayが受信品質だけで恒久routeを自己発行する
- expired routeでbest-effort forwardする
- E2E payloadをRelayで復号・変換する
- drainなしにroute recordを削除する
- route leaseをTxPermitとして扱う
- public Platform ABIとしてroute APIを露出する
- FRAG drainを「成功しそう」な過大式で通す
- custody evidenceをApplication Receiptと同一視する
- same-attemptでのroute reselection
- mark-only counterやself-comparisonによるgate成功

## 非主張

本ADRはAccepted / SPEC_ACCEPTEDのdesign authorityである。主張する状態bitは
`spec_accepted=1`だけであり、implementation、HIL、release support、public ABIは0。
private route/Relay implementationとhost/ESP software evidenceは存在するが、
physical RF HIL、SLO、legal、production mesh、`RELEASE_SUPPORTED`は主張しない。
vector/gate/host testの緑は実機合格を意味しない。

## Related

- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [Identity and Join](../03-identity-and-join.md)
- [ADR-0017](0017-bearer-registry-path-selection.md)
- [ADR-0020](0020-multi-parent.md)
- Machine vectors: `spec/vectors/route-relay-multiparent-spec-v1.json`
