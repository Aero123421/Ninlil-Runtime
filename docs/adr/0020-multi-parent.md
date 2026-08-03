# ADR-0020: Multi-parent Ownership, Diversity and Failover

状態: **Accepted / SPEC_ACCEPTED**
状態補足: ADR-0019とjoint design acceptance（independent final review GO; P0=0 / P1=0）
提案日: 2026-07-28
改訂日: 2026-07-30（ADR-0019とjoint SPEC_ACCEPTED; Normative bytes不変）
受入日: 2026-07-30
SPEC_ACCEPTED日: 2026-07-30（vector `claims.spec_accepted=1`）
RELEASE_SUPPORTED日: —（未達・非主張）

claim境界: 本ADRのAcceptedは **design authorityのSPEC_ACCEPTEDだけ** を意味する。
`claims.spec_accepted=1`、`claims.implementation=0`、`claims.hil=0`、
`claims.release_supported=0`、`claims.public_abi=0` とする。private/default-OFF
implementationとhost/ESP software evidenceは存在するが、public ABI・HA完成・physical
RF HIL・capacity/SLO・production support・`RELEASE_SUPPORTED` は未主張であり、
physical HIL/RFは`NOT_RUN`のままである。

## Context

複数parentは受信冗長化とcell容量分割を可能にするが、uplink重複とdownlink split brainを
同じ仕組みで扱えない。[03章](../03-identity-and-join.md)は複数parent uplink、
single downlink owner、transaction identityを維持したparent switchを定義し、
[30章](../30-r6-secure-radio-wire.md)はE2E sealerとcontext generationのHA invariantを固定する。
parent registry、assignment、failover lifecycle、**exact private API** は未固定だった。

[ADR-0019](0019-route-relay.md)のroute authority/lease/drainと一体で閉じる必要がある。
先行relay auditのP1項目に対応するmulti-parent側の欠落（ownership、storage/recovery、
split-brain、lease boundary、handoff、same-attempt reselection、custody/evidence、
resource fairness、mixed-version/default-OFF、vectors/gates）を本改訂で閉じる。

## Decision register

| ID | 決定 |
| --- | --- |
| D20-01 | Receive diversityとTransmit ownershipを分離する |
| D20-02 | downlink sealerは`owner_scope_id`ごとに最大1 |
| D20-03 | single logical authority writer + 複数fenced Controller participant |
| D20-04 | handoffは6-state machine; linearizationは`AUTHORITY_COMMITTED` CASのみ |
| D20-05 | same-attempt parent/route reselection禁止; new attemptのみ |
| D20-06 | private source-only API; public Platform ABI変更なし |
| D20-07 | storage `ninlil.parent.v1`、COMMIT_UNKNOWN OLD/NEW/PARTIAL/EXTRA/THIRD |
| D20-08 | custody/evidenceはApplication Receiptと分離 |
| D20-09 | default-OFF capability; mixed-version/downgrade fail-closed |
| D20-10 | machine vectorsをADR-0019と同一ファイルで連結固定 |

## Decision

### 1. Scope、owner、failure domain、依存方向

**Scope（in）**

- parent set revision/digest
- owner scope derivation
- downlink owner assignment fence tuple
- multi-Controller single-writer fencingとsplit-brain fail-closed
- lease expiry boundaryとcontroller handoff
- per-information（scope）routing policy snapshot
- uplink duplicate evidence（effect ownerは1）
- private source-only parent/assignment API
- durable `ninlil.parent.v1` storageとrecovery
- ADR-0019 route drainとの連結（parent loss mid-flight）

**Scope（out）**

- docs/30 / docs/03 Accepted byte semanticsの変更
- public Runtime Platform ABI
- Relay hop rewrap本体（ADR-0019）
- Production Attachment / Wi-Fi / Fabric path selection実装
- N+1 capacity SLO、RF HIL、production HA claim

**Owner**

| Role | 権限 | 禁止 |
| --- | --- | --- |
| **Logical authority writer** | assignment CAS、used-token tombstone、term/revision前進 | participant local storeの直接書込み |
| **Controller participant** | PREPARED_NEW / proof / activationのlocal FULL | 独自にcurrent ownerを宣言、shared sealer state |
| **Endpoint routing owner** | parent set観測、uplink diversity送信policy適用 | downlink seal、assignment CAS |
| **Local parent store owner**（1 node 1） | `ninlil.parent.v1` mutation sole owner | route store直書き（ADR-0019 ownerへ依頼） |

**Failure domain**

1 logical authority assignment namespace + 各participantのlocal parent store。
split-brainまたは`COMMIT_UNKNOWN`ではdownlink seal 0。未関連scopeまで連鎖停止させないが、
authority directory corruptは全downlink seal 0。

**依存方向**

```text
docs/03 + docs/30 + ADR-0017 path policy
  -> owner_scope_id derivation
  -> logical authority assignment CAS
  -> participant local FULL states
  -> Endpoint observation
  -> ADR-0019 route install/drain (for path changes)
  -> uplink diversity / downlink single seal
```

### 2. Private source-only API

public Platform ABIを変更しない。private preamble規則はADR-0019 §2.1と同一
（`api_version=1`、`struct_size`、reserved 0）。status / precedence は §2.2。
結果は固定 `ninlil_parent_result_v1`（exact 128 bytes、§2.4）。

#### 2.1 C11 private signatures（全10操作）

```c
typedef uint32_t ninlil_parent_status_u32;

ninlil_parent_status_u32 ninlil_parent_set_install(
    const ninlil_parent_set_install_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_owner_prepare(
    const ninlil_parent_owner_prepare_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_owner_fence_proof(
    const ninlil_parent_owner_fence_proof_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_authority_commit(
    const ninlil_parent_authority_commit_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_owner_activate(
    const ninlil_parent_owner_activate_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_endpoint_observe(
    const ninlil_parent_endpoint_observe_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_owner_retire(
    const ninlil_parent_owner_retire_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_query(
    const ninlil_parent_query_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_recover_commit_unknown(
    const ninlil_parent_recover_cu_req_v1 *req,
    ninlil_parent_result_v1 *out);

ninlil_parent_status_u32 ninlil_parent_diagnostics_snapshot(
    const ninlil_parent_diagnostics_req_v1 *req,
    ninlil_parent_result_v1 *out);
```

#### 2.2 Status codes（closed set） and precedence

```text
1  NINLIL_PARENT_OK
2  NINLIL_PARENT_INVALID_ARGUMENT
3  NINLIL_PARENT_CORRUPT
4  NINLIL_PARENT_UNSUPPORTED_API
5  NINLIL_PARENT_UNSUPPORTED_SCHEMA
6  NINLIL_PARENT_UNSUPPORTED_CAPABILITY
7  NINLIL_PARENT_AUTHORITY_CONFLICT
8  NINLIL_PARENT_SPLIT_BRAIN
9  NINLIL_PARENT_STALE_TERM
10 NINLIL_PARENT_STALE_REVISION
11 NINLIL_PARENT_LEASE_EXPIRED
12 NINLIL_PARENT_CLOCK_EPOCH_MISMATCH
13 NINLIL_PARENT_TOKEN_REPLAY
14 NINLIL_PARENT_SCOPE_MISMATCH
15 NINLIL_PARENT_NOT_OWNER
16 NINLIL_PARENT_NOT_ACTIVE
17 NINLIL_PARENT_SAME_ATTEMPT_RESELECT
18 NINLIL_PARENT_RESOURCE
19 NINLIL_PARENT_COMMIT_UNKNOWN
20 NINLIL_PARENT_REENTRANT
21 NINLIL_PARENT_FEATURE_OFF
```

**Failure precedence（high→low）**

```text
INVALID_ARGUMENT > CORRUPT > UNSUPPORTED_API > UNSUPPORTED_SCHEMA
 > FEATURE_OFF > UNSUPPORTED_CAPABILITY > AUTHORITY_CONFLICT > SPLIT_BRAIN
 > CLOCK_EPOCH_MISMATCH > LEASE_EXPIRED > STALE_TERM > STALE_REVISION
 > SCOPE_MISMATCH > TOKEN_REPLAY > NOT_OWNER > NOT_ACTIVE
 > SAME_ATTEMPT_RESELECT > RESOURCE > COMMIT_UNKNOWN > REENTRANT > OK
```

#### 2.3 Exact private request layouts（全10）

| op | struct | struct_size | sole mutator |
| --- | --- | --- | --- |
| set_install | `ninlil_parent_set_install_req_v1` | **240** | parent set install owner |
| owner_prepare | `ninlil_parent_owner_prepare_req_v1` | **464** | handoff participant（full NOA1 workspace） |
| owner_fence_proof | `ninlil_parent_owner_fence_proof_req_v1` | 96 | old owner / authority |
| authority_commit | `ninlil_parent_authority_commit_req_v1` | 96 | single authority writer |
| owner_activate | `ninlil_parent_owner_activate_req_v1` | 80 | new owner |
| endpoint_observe | `ninlil_parent_endpoint_observe_req_v1` | **80** | endpoint routing owner |
| owner_retire | `ninlil_parent_owner_retire_req_v1` | 80 | **old_owner**（local durable sole mutator of own store） |
| query | `ninlil_parent_query_req_v1` | 48 | reader |
| recover_commit_unknown | `ninlil_parent_recover_cu_req_v1` | 80 | local durable owner |
| diagnostics_snapshot | `ninlil_parent_diagnostics_req_v1` | 32 | diagnostics |

**`ninlil_parent_set_install_req_v1`**（struct_size=**240**）— parent IDs constructible

```text
+0    api preamble 16
+16   owner_scope_id[16]
+32   parent_set_count_u8           /* 1..8 */
+33   reserved2_u8[3] = 0
+36   path_policy_id[16]
+52   controller_term_u64
+60   assignment_epoch_u64
+68   reserved3_u64 = 0
+76   reserved4_u16 = 0
+78   reserved5_u16 = 0
+80   parent_set_digest32[32]       /* SHA-256(ordered parent_runtime_id[0..count)) */
+112  parent_runtime_id[8][16]      /* first count entries non-zero; remainder all-zero */
/* 240 */
```

**Constructibility（normative; prefix-only / digest16-only は禁止）**

- set_install は **唯一の parent-set constructor API**: 本文に full ordered IDs + digest32 を持つ。
- offline 「workspace only」claim は **不可**: 必ず本 req 経由で検証可能な byte を渡す。
- 成功時 durable write: **NPS1**（§10 / §12.4.1）FULL + directory/page generation。
- `parent_set_digest32 = SHA-256(parent_runtime_id[0] || … || parent_runtime_id[count-1])`
  （count 個のみ; trailing zero slots は preimage に含めない）

検証（fail-closed）:
- `1 ≤ count ≤ 8`
- `parent_runtime_id[i]` for i≥count は all-zero; for i<count は non-zero
- ids unique（order-preserving）; duplicate → `INVALID_ARGUMENT`
- digest mismatch → `CORRUPT`
- ID substitution / reordering without digest update → `CORRUPT`

**`ninlil_parent_owner_prepare_req_v1`**（struct_size=**464**）— S1 PREPARED_NEW; full NOA1 workspace

```text
+0    api preamble 16
+16   owner_scope_id[16]
+32   new_assignment_noa1[400]      /* full sealed NOA1; prefix64 禁止 */
+432  handoff_token_digest32[32]
/* 464 */
```

**Workspace / constructor binding（exact）**

| Surface | Role |
| --- | --- |
| set_install req 240 | parent-set constructor; writes durable **NPS1** |
| owner_prepare req 464 | assignment constructor; embeds full **NOA1[400]** in-request |
| participant-local buffer | prepare 成功後 INACTIVE に NOA1+NPS1 digests を保持（public ABI なし） |
| authority_commit | CAS は commit digest が NOA1∥NPS1∥token に bind（下式） |
| NPA1 slot | durable NOA1 + local_state + proof/receipt; NPS1 は別 key または同 namespace |

検証:
- `new_assignment_noa1` は §5 exact layout + digest/CRC/range **and** `parent_set_digest32`/`count`（§5 reserved_tail）
- `noa1.owner_scope_id == req.owner_scope_id`
- `noa1.handoff_token_digest == req.handoff_token_digest32`
- `noa1.parent_set_digest32 ==` durable NPS1 for scope（set_install 済）の digest
- `noa1.parent_set_count ==` NPS1 count
- prefix-only / missing NPS1 → `CORRUPT` / `NOT_ACTIVE`
**`ninlil_parent_owner_fence_proof_req_v1`**（struct_size=96）— S2

```text
+0   api preamble 16
+16  owner_scope_id[16]
+32  proof_digest32[32]
+64  old_assignment_revision_u64
+72  now_ms_u64
+80  reserved2_u64 = 0
+88  reserved3_u64 = 0
```

**`ninlil_parent_authority_commit_req_v1`**（struct_size=96）— S3 CAS

```text
+0   api preamble 16
+16  owner_scope_id[16]
+32  authority_commit_digest32[32]
+64  controller_term_u64
+72  assignment_revision_u64
+80  cas_expected_generation_u64
+88  reserved2_u64 = 0
```

**Commit binding（normative; digest-only hand-wave 禁止）**

```text
authority_commit_digest32 = SHA-256(
  "NINLIL-PARENT-COMMIT-V1" ||
  noa1_body_digest32 ||          /* NOA1[224:256) */
  nps1_record_digest32 ||        /* NPS1[196:228) */
  handoff_token_digest32 ||
  controller_term_u64_be ||
  assignment_revision_u64_be
)
```

- commit は prepared NOA1 と installed NPS1 の **両方** に bind する。
- NOA1.parent_set_digest ≠ NPS1.digest → reject。
- term/revision は NOA1 内 field と req が一致。
**`ninlil_parent_owner_activate_req_v1`**（struct_size=80）— S4

```text
+0   api preamble 16
+16  owner_scope_id[16]
+32  commit_receipt_digest32[32]
+64  now_ms_u64
+72  reserved2_u64 = 0
```

**`ninlil_parent_endpoint_observe_req_v1`**（struct_size=**80**）— S5

```text
+0   api preamble 16
+16  owner_scope_id[16]
+32  observed_parent_set_digest32[32]  /* full 32; digest16 禁止 */
+64  now_ms_u64
+72  reserved2_u64 = 0
/* 80 */
```

`observed_parent_set_digest32` は active NPS1.parent_set_digest32 と exact match。
**`ninlil_parent_owner_retire_req_v1`**（struct_size=80）— S6 local OLD_RETIRED

```text
+0   api preamble 16
+16  owner_scope_id[16]
+32  tombstone_digest32[32]
+64  now_ms_u64
+72  reserved2_u64 = 0
```

**Sole caller / participant-local sole-owner boundary（normative）**:
- `owner_retire` の sole mutator は **old_owner**（当該 participant の local durable
  assignment slot の sole writer）。
- **new_owner は old_owner の store を直接 mutate できない**（remote write 0）。
- new_owner / non-owner / third party の retire 呼び出し → `NOT_OWNER`。
- S6 は old_owner local transition: local_state ENDPOINT_OBSERVED 観測後 → OLD_RETIRED
  tombstone FULL（NPT1 used-token + NPA1 local_state=6）。
- prior_chain S1..S5 exact 必須（authority linearization は S3 で完了済み; S6 は
  old local cleanup）。
- old_owner_seal は retire 後 0; new_owner_seal は S4 以降 1（別 store）。

**`ninlil_parent_query_req_v1`**（struct_size=48）

```text
+0   api preamble 16
+16  owner_scope_id[16]
+32  query_mask_u32
+36  reserved2_u32 = 0
+40  reserved3_u64 = 0
```

**`ninlil_parent_recover_cu_req_v1`**（struct_size=80）

```text
+0   api preamble 16
+16  owner_scope_id[16]
+32  observed_assignment_digest32[32]
+64  expected_class_u8
+65  reserved2_u8[3] = 0
+68  reserved3_u32 = 0
+72  now_ms_u64
```

**`ninlil_parent_diagnostics_req_v1`**（struct_size=32）

```text
+0   api preamble 16
+16  snapshot_mask_u32
+20  reserved2_u32 = 0
+24  reserved3_u64 = 0
```

#### 2.4 Common result `ninlil_parent_result_v1`（exact 128 bytes）

```text
offset  size  field
0       16    api preamble (version=1, size=128, reserved0=0, reserved1=0)
16      4     status_u32              /* equals return */
20      4     detail_flags_u32        /* bit0=seal_allowed bit1=split_brain bit2=cu */
24      8     opaque_local_handle_u64
32      16    owner_scope_id
48      8     controller_term_u64
56      8     assignment_revision_u64
64      8     lease_not_after_u64
72      1     handoff_step_u8         /* 0 none 1..6 S1..S6 */
73      1     local_state_u8          /* §12.2 local_state closed set */
74      1     cu_class_u8             /* same as route CU */
75      1     seal_allowed_u8         /* 0/1 */
76      4     reserved2_u32 = 0
80      32    token_or_commit_digest32
112     16    reserved_tail zero
/* 128 */
```

**Result ownership / 出力不変**

| 規則 | 内容 |
| --- | --- |
| P-OUT-1 | 常に 128 bytes 全埋込み; 部分成功禁止 |
| P-OUT-2 | `status_u32` == return |
| P-OUT-3 | `seal_allowed=1` のときだけ downlink seal 許可; SPLIT_BRAIN/CU bad/FEATURE_OFF は 0 |
| P-OUT-4 | failure で `opaque_local_handle=0` |
| P-OUT-5 | handoff step は §7 independent machine と矛盾してはならない |

### 3. Receive diversity vs transmit ownership

1. **Receive diversity**: Endpoint uplinkはpolicyで許可された複数parentが受信できる。
2. **Transmit ownership**: downlinkをsealできるownerは`owner_scope_id`ごとに常に最大1。
3. Node全体の単一roleとしてownerを固定しない。scopeごとにcapacity splitできる。

### 4. owner_scope_id derivation（exact）

```text
owner_scope_id[16] = SHA-256(
  ASCII("NINLIL-OWNER-SCOPE-V1") ||
  endpoint_runtime_id16 ||
  direction_u8 ||
  namespace_len_u16_be || namespace ||
  service_len_u16_be || service ||
  traffic_class_u16_be ||
  path_policy_id16
)[0..15]
```

規則:

- `path_policy_id`はNFL1 `route_policy_id`とbit-exact同一。
- `endpoint_runtime_id`と`traffic_class`はADR-0017 path policy recordのclosed
  `scope_endpoint_selector`と`traffic_class`から取得する。
- selectorはoriginal APPLICATIONのsourceまたはtarget Runtime IDだけを選び、
  device/installation IDの有無から推測しない。
- reverse kindはingress triggerにFULL保存したoriginal endpoint/scopeを使い、
  反転後のtargetから再導出しない。
- local priorityやBearer metricsからtraffic classを推測しない。
- namespace/service length 1..63。direction/traffic classはclosed enum。reserved reject。
- 単純な可変長連結（length無し）は使わない。

### 5. Downlink owner assignment fence tuple（exact）

```text
owner_scope_id[16]
authority_id[16]
controller_term_u64            /* 1..MAX-1 */
assignment_epoch_u64           /* 1..MAX-1 */
assignment_revision_u64        /* 1..MAX-1 */
owner_controller_id[16]
owner_cell_id[16]
direction_u8
e2e_context_id_u32
key_generation_u64
e2e_security_id[16]
e2e_security_epoch_u64
e2e_binding_digest[32]
authority_clock_epoch_id[16]
lease_not_after_authority_ms_u64
handoff_token_digest[32]
```

`e2e_context_generation`のような曖昧合成fieldは使わない。
tupleの不明、同値競合、後退、binding/direction/scope不一致、期限切れではdownlink seal 0。

**Canonical assignment record `NOA1`（exact 400 bytes; field offset table）**

```text
offset  size  field
0       4     magic "NOA1"
4       2     schema_u16 = 1
6       2     length_u16 = 400
8       16    owner_scope_id[16]
24      16    authority_id[16]
40      8     controller_term_u64              /* 1..MAX-1 */
48      8     assignment_epoch_u64             /* 1..MAX-1 */
56      8     assignment_revision_u64          /* 1..MAX-1 */
64      16    owner_controller_id[16]
80      16    owner_cell_id[16]
96      1     direction_u8
97      3     reserved0_u8[3] = 0
100     4     e2e_context_id_u32               /* 1..MAX-1 */
104     8     key_generation_u64               /* 1..MAX-1 */
112     16    e2e_security_id[16]
128     8     e2e_security_epoch_u64           /* 1..MAX-1 */
136     32    e2e_binding_digest32
168     16    authority_clock_epoch_id[16]
184     8     lease_not_after_authority_ms_u64 /* 1..MAX-1 */
192     32    handoff_token_digest32
224     32    body_digest32 = SHA-256(bytes[0:224))
256     4     crc32c of **entire 400** with this field zero at offset 256
260     32    parent_set_digest32              /* MUST equal NPS1.parent_set_digest32 */
292     1     parent_set_count_u8              /* 1..8; MUST equal NPS1 count */
293     3     reserved1_u8[3] = 0
296     16    parent_set_id[16]                /* MUST equal NPS1.parent_set_id */
312     88    reserved_tail zero
/* 400; 260+32+1+3+16+88=400 */
```

**Parent-set durable reference（constructible; multi-scope）**

| Artifact | Holds full ordered IDs? | Scope key | Digest / id |
| --- | --- | --- | --- |
| set_install req | **yes** | owner_scope_id | digest32 + ids |
| **NPS1** in **NPP1** | **yes** | owner_scope_id @8 | parent_set_id + digest |
| NOA1 | **no**（reference） | owner_scope_id @8 | digest@260, count@292, **parent_set_id@296** |
| NPA1 slot | embeds NOA1 | via NOA1 | lookup NPS1 by (scope, parent_set_id) |

禁止: single global NPS1 key、digest16-only、prefix64-only NOA1、scope-less NPS1。### 6. Single-writer fencing、split-brain、simultaneous controllers

#### 6.1 Single logical authority writer

03章「1 site = 1 active Site Controller writer」を次へ拡張する。

- **logical authority writer**はassignment CASの唯一のlinearization owner。
- 複数Controller processがparticipantになれるが、同時に2つがcurrent writerを名乗ることは
  `SPLIT_BRAIN`。
- writer fence:

```text
authority_writer_record:
  authority_id16
  writer_controller_id16
  controller_term_u64
  writer_epoch_u64
  lease_not_after_ms_u64
  authority_clock_epoch_id16
  writer_proof_digest32
```

- 同一`authority_id`で異なる`writer_controller_id`が同じtermでactive claim → `SPLIT_BRAIN`、
  全downlink seal 0、新規handoff 0。
- term前進は旧writer lease expiry proofまたは旧writer explicit resign proofが必要。

NPH1を含むS3はprocess-local generation比較だけではCASではない。2 ownerが同じsnapshotを
復元して同時にS3を試みても、logical authorityのdurable outer tuple
`(present, exact length, SHA-256(exact RRMP/NS1 bytes))`に対するCASで最大1件だけが成功する。
Foundation Storageのstandard bindはexact namespace exclusive writerの範囲で同一RW snapshot
比較を行う。複数handle/複数Controller構成はprivate/default-OFF storage-authority providerを
bindしなければmulti-owner安全性を主張してはならない。この拡張はpublic Storage ABI、wire、
installed SDK ABIの一部ではない。

#### 6.2 Simultaneous parents

uplink diversityは同時parentsを許可する。downlinkはscopeあたり1 owner。
2 parentsが同一scopeでsealを試みた観測は`SPLIT_BRAIN` diagnosticsとし、
Endpointは両方のpayloadをapplication effectへpublishしない。

#### 6.3 Lease expiry at boundary

```text
active iff now_ms < lease_not_after_authority_ms
         AND clock_epoch matches authority accepted epoch
```

- `now == lease_not_after - 1` → active（still <）
- `now == lease_not_after` → **expired**（`LEASE_EXPIRED`）
- wall clock単独はproofにならない。authority clock epoch内のdurable観測だけがexpiry proof。

### 7. Controller / owner handoff state machine

複数PCを跨ぐ単一Storage transaction atomicは主張しない。
各矢印はparticipant local FULL。唯一のlinearization pointは
`AUTHORITY_COMMITTED`へのauthority compare-and-swap。

```text
PREPARED_NEW
  -> OLD_FENCED_PROOF
  -> AUTHORITY_COMMITTED
  -> NEW_OWNER_ACTIVATED
  -> ENDPOINT_OBSERVED
  -> OLD_RETIRED
```

| State | Local effect | Seal/TX |
| --- | --- | --- |
| PREPARED_NEW | new ownerがnew E2E context tupleとtoken digestをINACTIVE保存 | 0 |
| OLD_FENCED_PROOF | old owner fresh-seal fence FULL、またはauthorityのlease-expiry proof | old seal 0 after fence |
| AUTHORITY_COMMITTED | authority CAS: current revision + old tuple + token unused → new tuple | only authority truth |
| NEW_OWNER_ACTIVATED | new ownerがcommit receipt検証・token一回consume・ACTIVE | new only |
| ENDPOINT_OBSERVED | Endpoint/parent routingがnew assignmentを観測 | not linearization |
| OLD_RETIRED | **old_owner local** が own store で bounded receive-only後に retire/tombstone FULL（new_owner は old store を mutate しない） | old 0 |

#### 7.1 Independent closed transition machine（vectorから学習しない）

Gate/oracleは次の **hardcoded** 表だけをauthorityとする。vectorの
`handoff_machine` 欄は同値再掲であり、表を上書きできない。

| Step | edge_index | From | To | proof_present | cas_succeeded | commit_receipt_verified | token_consumed | tombstone_written | new_owner_seal | old_owner_seal | artifact |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | -1 | null | PREPARED_NEW | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NEW_TUPLE_UNUSED_TOKEN_FULL |
| S2 | 0 | PREPARED_NEW | OLD_FENCED_PROOF | 1 | 0 | 0 | 0 | 0 | 0 | 0 | PROOF_FULL |
| S3 | 1 | OLD_FENCED_PROOF | AUTHORITY_COMMITTED | 1 | 1 | 0 | 0 | 0 | 0 | 0 | AUTHORITY_CAS |
| S4 | 2 | AUTHORITY_COMMITTED | NEW_OWNER_ACTIVATED | 1 | 1 | 1 | 1 | 0 | 1 | 0 | COMMIT_RECEIPT_TOKEN_CONSUME |
| S5 | 3 | NEW_OWNER_ACTIVATED | ENDPOINT_OBSERVED | 1 | 1 | 1 | 1 | 0 | 1 | 0 | ENDPOINT_OBSERVE |
| S6 | 4 | ENDPOINT_OBSERVED | OLD_RETIRED | 1 | 1 | 1 | 1 | 1 | 1 | 0 | TOMBSTONE_RETIRE |

各stepはparent dual namespaceの該当NPA1/NPT1/NPS1 FULLだけで完了しない。
storage-bound ownerは同じ状態を含むplatform FULL snapshotまで成功して初めて`OK`を返す。
とくにS1 `PREPARED_NEW`もdurable writepointであり、platform FULL失敗/unknown時はseal/TXを
fenceし、`COMMIT_UNKNOWN`のOLD/NEWをcold recoveryで再分類する。
inner dual pageが先に更新されてもouter definite failureではfresh exact OLDから全RAM/inner
namespaceを再構築する。S6のNPA1/NPT1とsoft handoff stateもouter snapshot 1回で完了し、
outer成功後に独立した2回目のNPS1 commitを成功条件へ加えてはならない。

**S6受理条件（mandatory）**

- `step == "S6"` かつ `edge_index == 4` かつ上表の全flag exact一致
- **かつ** `prior_chain` が exact 長さ5で S1→S2→S3→S4→S5 の順
- 各 prior 要素は上表の step/edge_index/from/to/flags/artifact と bit-exact 一致
- prior 欠落・順序入替・flag改変・`edge_index=99` 等はすべてreject
- S2単独ケースで `step=S6` を名乗ってもreject（case_kindとstepの束縛）

**Allowed edges only:** edge_index 0..4 の5本。それ以外（99等）は常にreject。

**Forbidden**

- skip/reverse/reorder
- CAS without proof、receipt without CAS、token without receipt、tombstone without token
- second token consume → `TOKEN_REPLAY`
- vector-only machine（hardcoded表と不一致）

**Idempotent retries:** 同一stepのsame token/state再照会のみ。推測遷移禁止。

規則:

- old fence/expiry proofなしにauthorityはcommitしない。
- authority commit receiptなしにnew ownerはACTIVEにしない。
- 同じ`handoff_token_digest`の再利用、別scope/term/revision転用、rollbackは
  `TOKEN_REPLAY` / reject。
- timeout/retryは同じtokenとstateをidempotently再照会し、飛び越えない。
- 同一E2E sealer stateを複数独立Controllerで共有しない。

**Old sealed-unsent blobs**: burn済みcounterを戻さずdiscard。same transaction + **new attempt**
でnew contextへreprepare。fence前に物理送信済みblobだけbounded receive-only
retirement/dedupe対象。old contextで再送・新規sealせず、duplicate application effect 0。

### 7.2 Parent failure precedence（high→low, exact）

```text
INVALID_ARGUMENT
  > CORRUPT
  > UNSUPPORTED_API
  > UNSUPPORTED_SCHEMA
  > FEATURE_OFF
  > UNSUPPORTED_CAPABILITY
  > AUTHORITY_CONFLICT
  > SPLIT_BRAIN
  > CLOCK_EPOCH_MISMATCH
  > LEASE_EXPIRED
  > STALE_TERM
  > STALE_REVISION
  > SCOPE_MISMATCH
  > TOKEN_REPLAY
  > NOT_OWNER
  > NOT_ACTIVE
  > SAME_ATTEMPT_RESELECT
  > RESOURCE
  > COMMIT_UNKNOWN
  > REENTRANT
  > OK
```

Parent status codes（closed; unknown code e.g. 999 → reject）:

| Name | Code |
| --- | --- |
| OK | 1 |
| INVALID_ARGUMENT | 2 |
| CORRUPT | 3 |
| UNSUPPORTED_API | 4 |
| UNSUPPORTED_SCHEMA | 5 |
| UNSUPPORTED_CAPABILITY | 6 |
| AUTHORITY_CONFLICT | 7 |
| SPLIT_BRAIN | 8 |
| STALE_TERM | 9 |
| STALE_REVISION | 10 |
| LEASE_EXPIRED | 11 |
| CLOCK_EPOCH_MISMATCH | 12 |
| TOKEN_REPLAY | 13 |
| SCOPE_MISMATCH | 14 |
| NOT_OWNER | 15 |
| NOT_ACTIVE | 16 |
| SAME_ATTEMPT_RESELECT | 17 |
| RESOURCE | 18 |
| COMMIT_UNKNOWN | 19 |
| REENTRANT | 20 |
| FEATURE_OFF | 21 |

### 8. No same-attempt reselection

parent switch / route replacement / owner handoff後の再送は:

```text
same transaction_id + new attempt_id
```

禁止:

- same attemptのままparent/routeをreselect（`SAME_ATTEMPT_RESELECT`）
- old/new parentからのlate packetをsame attemptとしてmerge
- handoff中のattempt identity再利用

Fabric bearer selection（ADR-0017）の`same_attempt_reselect_calls = 0`規則と整合する。

#### 8.1 Selection must change the outbound side effect

selection APIがparent IDを返すだけでは不十分である。production admissionは
`attempt_id16`を必須入力としてowner scopeを導出し、そのFULL snapshotへ
`attempt_id16 + selected_parent_id16 + expected_LINK_ACK_peer_id16`をqueue/carrierと
同時保存する。hop outbound packetは保存済み`selected_parent_id16`を明示し、bearerは
そのpeer以外へ送信してはならない。LINK_ACKは同じpeer IDとexact outer TX counterの
authenticated evidenceだけを受理する。

restart後も同じqueue attemptは同じselected parentへ再送する。parent loss / assignment
revision更新後は同じattemptを別parentへ再選択せず、新attemptを作る。selected parentが
lost/sealedになった場合はTX 0とし、callerへnew attempt要求を返す。

### 9. Uplink duplicate、custody、Application Receipt

Controller dedupe key:

```text
transaction_id16 || attempt_id16 || content_digest32 ||
e2e_context_id_u32_be || key_generation_u64_be || e2e_binding_digest32
```

- first receiveだけを唯一の発生事実とみなさない。全path evidenceをbounded diagnostics保持可。
- application callback/effect ownerは`owner_scope_id + assignment_revision`で唯一。
- non-owner Controllerはevidenceをauthority/current ownerへ転送するだけでeffect publish 0。
- hop custody（ADR-0019）成功はApplication Receiptではない。

### 10. Parent set record `NPS1`（exact 256 bytes; multi-scope）

**Decision (a)**: multiple content-addressed NPS1 records（not 1 global key）。
scope ごとに異なる parent set を同時保持（resource: **64 concurrent scopes**）。

```text
offset  size  field
0       4     magic "NPS1"
4       2     schema_u16 = 1
6       2     length_u16 = 256
8       16    owner_scope_id[16]             /* scope key; non-zero */
24      16    parent_set_id[16]              /* set identity; non-zero */
40      8     parent_set_revision_u64        /* 1..MAX-1 mono-inc per scope */
48      1     parent_set_count_u8            /* 1..8 */
49      3     reserved0_u8[3] = 0
52      32    parent_set_digest32            /* SHA-256(ids[0..count)) */
84      128   parent_runtime_id[8][16]       /* ordered; i>=count all-zero */
212     32    record_digest32 = SHA-256(bytes[0:212) with this field zeroed)
244     4     crc32c of entire 256 with this field zero
248     8     reserved_tail zero
/* 256; 8+16+16+8+1+3+32+128+32+4+8=256 */
```

**Lookup（NOA1 → durable NPS1）**

```text
key = (NOA1.owner_scope_id, NOA1.parent_set_id)
require NPS1.owner_scope_id == NOA1.owner_scope_id
require NPS1.parent_set_id == NOA1.parent_set_id
require NPS1.parent_set_digest32 == NOA1.parent_set_digest32
require NPS1.parent_set_count == NOA1.parent_set_count
/* missing / mismatch → CORRUPT or NOT_ACTIVE (prepare/commit) */
```

**NPP1 page**（exact 4096; holds 16 × NPS1）:

```text
NPP1_HEADER = 16
NPS1_BYTES = 256
NPP1_SLOTS = 16
NPP1_PAGES = 4
SCOPE_PARENT_SET_CAPACITY = 4 * 16 = 64
check: 16 + 16*256 = 4112 — too big
```

Correct arithmetic:

```text
NPP1_HEADER_BYTES = 16
NPP1_SLOTS = 15
slots_span = 15 * 256 = 3840
NPP1_PAD = 4096 - 16 - 3840 = 240
NPP1_BYTES = 16 + 3840 + 240 = 4096
NPP1_PAGE_COUNT = 5
SCOPE_CAPACITY = 5 * 15 = 75 >= 64 resource bound
/* resource concurrent owner scopes = 64; storage capacity >= 64 */
```

```text
NPP1 header:
0   4  magic "NPP1"
4   2  schema = 1
6   2  page_index  /* 0..4 */
8   4  page_generation
12  4  crc32c of page with field zero
16  3840  15 × NPS1 slots (EMPTY = all-zero)
3856 240  pad zero
```

Placement: `page = hash(owner_scope_id)[0] % 5`, `slot = hash(owner_scope_id)[1] % 15`, linear probe.

規則:
- set_install(scope) 成功 ⇔ NPS1 FULL into NPP1（same scope overwrite only with revision mono-inc）
- 2 distinct scopes may hold 2 distinct parent sets concurrently
- digest mismatch / reorder / substitute → `CORRUPT`
- restart: NPP1 pages survive; both scopes restorable via NOA1→NPS1 lookup

Profile notes（非 byte layout）:
- redundancy vs capacity split は別 profile。
- ESP 1-radio は same-channel diversity または scheduled-scan を明示。
### 11. Per-information routing policy

scopeごとのpath policy snapshot:

```text
owner_scope_id
path_policy_id
path_policy_revision
selected_primary_parent_id
backup_parent_ids[]
route_policy_digest32
```

情報（namespace/service/traffic_class）ごとにowner/parent/routeが分かれ得る。
policy revision後退はreject。ADR-0019 route installはこのsnapshotを参照し、
scope外routeを勝手に流用しない。

### 12. Durable storage `ninlil.parent.v1`

ADR-0019と同じ別物理Fabric domainの第2 production namespace。

#### 12.1 Keys（exact budget 22）

| Key ID | Count | Content |
| --- | --- | --- |
| 0 | 1 | header `NPH1` |
| 1..5 | **5** | parent-set pages `NPP1`（§10; 15×NPS1 each; ≥64 scopes） |
| 6..13 | ≤8 | assignment pages `NPA1` |
| 14..21 | ≤8 | token/tombstone pages `NPT1` |
| **sum** | **≤22** | 1+5+8+8 |

各page ≤ 4096 bytes。single global NPS1 key は **FORBIDDEN**。#### 12.2 Header `NPH1`（exact 256 bytes）— full writer fence tuple

Magic `NPH1`。schema 1。parent namespace の sole authority-writer header。
§6.1 `authority_writer_record` を **bit-exact embed** し、restart 後に writer fence を
再構築可能にする（id/generation だけではない）。

```text
offset  size  field
0       4     magic "NPH1"
4       2     schema_u16 = 1
6       2     length_u16 = 256
8       16    authority_id[16]                 /* §6.1 authority_id */
24      16    writer_controller_id[16]         /* §6.1 writer_controller_id */
40      8     controller_term_u64              /* §6.1; 1..MAX-1 */
48      8     writer_epoch_u64                 /* §6.1; 1..MAX-1; mono per writer claim */
56      8     lease_not_after_ms_u64           /* §6.1; 1..MAX-1 */
64      16    authority_clock_epoch_id[16]     /* §6.1 */
80      32    writer_proof_digest32            /* §6.1; non-zero */
112     8     header_generation_u64            /* mono-inc on FULL write; 1..MAX-1 */
120     2     assignment_page_bitmap_u16       /* bits 0..7 NPA1 present */
122     2     token_page_bitmap_u16            /* bits 0..7 NPT1 present */
124     4     reserved0_u32 = 0
128     32    authority_commit_digest32        /* latest S3 CAS digest or zero */
160     32    header_digest32 = SHA-256(bytes[0:160) with this field zeroed)
192     4     crc32c of entire 256 with this field zero at offset 192
196     60    reserved_tail zero
/* 256; 160+32+4+60=256 */
```

規則:
- schema≠1 → `UNSUPPORTED_SCHEMA`（CRC repaired でも reject）
- generation 後退 / writer_epoch 後退 → `AUTHORITY_CONFLICT`
- 同一 authority_id で異なる writer_controller_id が同じ controller_term で active claim
  → `SPLIT_BRAIN`
- lease_not_after ≤ now → writer fence expired; new claim は proof 要
- reserved non-zero / proof all-zero / id all-zero → `CORRUPT`
- restart: NPH1 FULL から §6.1 fence tuple を完全再構築; incomplete header → seal 0

#### 12.3 Token/tombstone page `NPT1`（exact 4096 bytes）

```text
NPT1_HEADER_BYTES = 24
NPT1_SLOT_BYTES = 48
NPT1_SLOTS_PER_PAGE = 84
slots_span = 84 * 48 = 4032
NPT1_PAD_BYTES = 4096 - 24 - 4032 = 40
check: 24 + 4032 + 40 = 4096
```

**Page header**

```text
0       4     magic "NPT1"
4       2     schema_u16 = 1
6       2     page_index_u16           /* 0..7 */
8       4     page_generation_u32
12      4     occupied_count_u32       /* 0..84 */
16      4     reserved0_u32 = 0
20      4     crc32c of entire page with this field zero
24      4032  84 slots × 48
4056    40    reserved pad zero
```

**Slot exact 48 bytes**

```text
0       32    token_or_tombstone_digest32
32      1     kind_u8                  /* 0 EMPTY 1 TOKEN_LIVE 2 TOMBSTONE_USED */
33      1     reserved0_u8 = 0
34      2     reserved1_u16 = 0
36      8     created_ms_u64
44      4     slot_crc32c of bytes[0..44) with this field zero
/* 48 */
```

NPT1全pageは、scopeごとの「現在token欄」ではなく、parent namespace全体で共有する
**global replay ledger**である。current NPA1 assignmentは自身のtoken digestに一致する
ledger entryをexact 1件参照する。過去handoffの`TOMBSTONE_USED`はcurrent NPA1を持たなくても
よく、同じscopeの次handoffや別scopeのhandoffで上書き・再利用しない。

logical ledger capacityは`TOKEN_REPLAY_LEDGER_CAPACITY = 256`（`TOKEN_LIVE` +
`TOMBSTONE_USED`の合計）とする。entryはpage 0からpacked prefixで配置し、同一digestの
複数entry、partial page後のnon-empty page、256超過は`CORRUPT`。S1前に全pageを検索し、
既存digestはkind/scopeを問わず`TOKEN_REPLAY`、未使用digestでも既存entryが256件なら
`RESOURCE`とする。**duplicate判定はcapacity判定より先**である。

暗黙のFIFO/LRU/時刻evictionは禁止する。NPT1 token ledgerとQST4 used-attempt ledgerは
別domainである。NPT1のused tokenはS6完了と規定retention終了後のv2明示reclaimだけが
eraseできる。QST4のexact 80-byte row/reclaimは§12.7に従う。v1 mutation APIはこの遷移を
実行できず`UNSUPPORTED_API`で閉じる。

`TOKEN_LIVE` / `TOMBSTONE_USED` の再利用・別scope転用 → `TOKEN_REPLAY`。
EMPTY と TOMBSTONE を kind で区別。

#### 12.4 Assignment page / slot（exact; NOA1=400と矛盾しない）

`NOA1_BYTES = 400` が唯一の assignment record 正本である。
旧「320-byte body」は廃止する。

**Assignment page slot exact `ASSIGNMENT_SLOT_BYTES = 472`:**

```text
0     400  NOA1 record (canonical 400; includes parent_set_digest ref @260)
400   1    local_state_u8
401   3    reserved zero
404   32   proof_digest
436   32   receipt_digest
468   4    slot_crc32c of bytes[0..468) with this field zero
/* 472 total */
```

NPA1 は full parent IDs を持たない（NOA1 参照 + 別 key **NPS1** が IDs 正本）。
slot 検証時: NOA1.parent_set_digest は active NPS1 と cross-check 必須。
**NPA1 page exact 4096:**

```text
NPA1_HEADER_BYTES = 16
ASSIGNMENT_SLOTS_PER_PAGE = 8
slots_span = 8 * 472 = 3776
NPA1_PAD_BYTES = 4096 - 16 - 3776 = 304
check: 16 + 3776 + 304 = 4096

Header exact:
0       4     magic "NPA1"
4       2     schema_u16 = 1
6       2     page_index_u16
8       4     page_generation_u32
12      4     crc32c of entire page with this field zero
16      3776  8 × 472 slots
3792    304   reserved pad zero
```

local_state closed set:

```text
0 EMPTY
1 PREPARED_NEW
2 OLD_FENCED_PROOF
3 AUTHORITY_COMMITTED_OBSERVED
4 NEW_OWNER_ACTIVATED
5 ENDPOINT_OBSERVED
6 OLD_RETIRED
```

#### 12.5 Codec limits / migration / OLD-NEW-CU（normative）

| Item | Rule |
| --- | --- |
| schema | only 1; foreign schema fail-closed after CRC verify |
| page max | NPA1 ≤8, NPT1 ≤8, NPH1 =1 |
| generation | mono-inc; 0 and UINT_MAX forbidden |
| migration | NPA1/NPT1 page rewrite is FULL page atomic; no torn slot publish |
| OLD/NEW CU | observed durable group vs old/new assignment pages: OLD/NEW/ABSENT/PARTIAL/EXTRA/THIRD |
| seal | PARTIAL/EXTRA/THIRD/ABSENT under active handoff → seal_allowed=0 |
| CRC | every NPH1/NPA1/NPT1/slot_crc field zero while computing crc32c |

#### 12.6 COMMIT_UNKNOWN classification

ADR-0019 §8.7と同一class集合:

`OLD | NEW | ABSENT | PARTIAL | EXTRA | THIRD`

- PARTIAL/EXTRA/THIRD → downlink seal 0、affected scope fence
- classification完了前にNEW_OWNER_ACTIVATEDへ進まない
- used-token tombstoneはold/new context retirement完了まで保持
- platform outer witnessはOLD/NEWそれぞれのpresent flag、exact length、SHA-256を持つ。
  authority providerは`COMMIT_UNKNOWN`を返す前にwitnessをdurable化し、cold restartでも
  exact OLD/NEWだけを返す。witnessなしのmulti-owner safetyやdigest/length不一致の推測は禁止。
- unresolved outer `COMMIT_UNKNOWN`はscope-localだけでなくownerの全mutation、route/parent
  selection、bearer send、worker、state readbackをhard fenceする。復旧後にimportされた
  lease-expiry/split-brain/parent-loss fenceをouter recoveryが消してはならない。

各participantは次をdurable copy-ownする。

```text
handoff_token_digest
owner_scope_id
old exact tuple
new exact tuple
local_state
authority_commit_digest
proof_digest
```

#### 12.7 QST4 used-attempt ledger（exact 80-byte rows）

soft trailerは`RRMPQST4` schema 4だけを新規writeする。headerはexact 56 bytesで、
byte 48=authority-global fence、49=reason、50..51=attempt row count、
52..53=handoff tuple row count、54..55=zeroとし、reclaim clockには使わない。
scope/evidence/queue/carrierの既存layoutに続き、最大256件のused-attempt rowを置く。

```text
row bytes = 80
0   16  owner_scope_id16
16  16  attempt_id16
32   1  lifecycle_u8                 /* 1 LIVE, 2 TERMINAL_RETAINED */
33   1  flags_u8                     /* bit0 NEV1, bit1 handoff tombstone */
34   6  reserved zero
40  32  terminal_evidence_digest32   /* LIVEはall-zero、terminalはnon-zero */
72   8  reclaim_not_before_ms_u64     /* LIVE=0; terminal=1..MAX-1 */
```

Selectionは全256行のexact tupleを先に検索する。同一
`(owner_scope_id, attempt_id)`がLIVE/TERMINAL_RETAINEDのどちらでも
`SAME_ATTEMPT_RESELECT`。A→B→A、restart、assignment epoch前進、parent loss、
handoff後のold attemptでも同じである。暗黙eviction、oldest置換、scope reinstallによる
clearは禁止する。

LIVE→TERMINAL_RETAINEDは、queue releaseとdurable COMPLETED NEV1またはS6 used-token
tombstoneを同じouter FULLへ置き、そのexact record SHA-256をrowへcopy-ownする。
同時に当該rowだけのdeadlineを
`terminal_observed_now_ms + ATTEMPT_RETENTION_MS`へ設定する。
`ATTEMPT_RETENTION_MS = 60,000`とする。overflowは`RESOURCE`で
mutation 0。後からterminalになったrowはolder rowのdeadlineを変更しない。

private source-only v2 `ninlil_rrmp_core_attempt_reclaim_v2`だけが1行を消去できる。
callerが渡すdigest/proofをauthorityとして扱わず、fresh stateから次を全て再検証する。

1. exact rowがTERMINAL_RETAINEDでdigest non-zero;
2. digestがdurable COMPLETED NEV1またはused NPT1 tombstoneと一致;
3. 同scope/attemptを持つdurable/in-memory queueが0;
4. handoffならscope state=S6 `OLD_RETIRED`;
5. trusted nowが当該rowの`reclaim_not_before_ms`以上;
6. authority-global fenceなし。

1回のFULL commit成功後だけrowをEMPTYにする。definite failureはexact OLD、unknownは
OLD/NEW以外を永久fenceする。明示erase後だけ同attemptを再利用できる。継続する
terminal trafficの下でも、期限を迎えたolder rowがnewer rowに妨げられずreclaimできる
liveness testを必須とする。

QST4 maximum:

```text
56 + 64*64 + 124*72 + 64*320 + 16,320 + 256*80 + 64*224 = 84,696
```

#### 12.8 Private source-only handoff ABI v2 and exact authority tuple

v1の96-byte fence/commit requestはcomplete old tupleとproof kindを運べないため、
handoff mutationへ使用できず`UNSUPPORTED_API`を返す。v2はpublic/install surfaceへ
露出しない。

`owner_prepare_v2`はcurrent active assignmentを次のexact old tupleとしてcopy-ownし、
同時にnew tupleを別領域へ保存する。

この2 tupleはRAMだけに置かない。QST4のattempt rowsに続けて、handoff stateが
non-zeroの各scopeをlexical `owner_scope_id`順にexact 224-byte rowとして保存する。

```text
0    16  owner_scope_id16
16  104  exact old authority tuple
120 104  exact new authority tuple
```

最大64行。NPA1は既存layoutで満杯のため、S1..S6 restart continuityの正本はこの
appendixとする。missing/duplicate/extra/out-of-order row、new tupleとNPA1 NOA1の
不一致、writer epoch不一致はQST4全体をrejectする。

```text
present_u8
exact_noa1_length_u32
sha256(exact NOA1 bytes)[32]
assignment_revision_u64
controller_term_u64
owner_controller_id16
writer_epoch_u64
lease_not_after_ms_u64
authority_clock_epoch_id16
```

old absentは最初のbootstrapだけに許し、term advancement proofを要求しない。old presentで
new termが前進する場合のproof kindはclosed set:

```text
1 EXPLICIT_RESIGN
2 TRUSTED_EXACT_LEASE_EXPIRY
```

proof digestはdomain separator、complete old tuple、scope、handoff token、old writer、
old term/revision、proof kindをbindする。lease expiry proofはsame clock epochかつ
`trusted_now_ms >= exact old lease_not_after_ms`、explicit resignはexact prior writerの
resign digestが必要。単なるhigher termは`AUTHORITY_CONFLICT`。

`authority_commit_v2`はdurable current writer record、complete old tuple、complete new
tuple、unused token、proof digest、bundle expected witnessを比較し、commit digestを全入力へ
bindする。2 ownerが同じsnapshotから開始した場合、v2 bundle CASでexactly oneだけが成功する。
wrong old length/digest/revision/writer/term/epoch/lease、stale generation、token replayは
activation前にrejectする。

`parent_set_install`はNPS1 constructorだけである。成功してもactive NOA1、handoff state、
old/new seal、authority-global fence、used-attempt ledger、parent-loss/scope anomalyを
変更しない。

#### 12.9 Authority-global writer conflict vs scope-local parent anomaly

入力を別API/別durable bitとして分離する。

- `ninlil_rrmp_core_authority_writer_conflict_v2`: same authority+termで異なるactive writer。
  authority-global fenceをQST4 header/NPH1へFULL保存し、全scopeのselect/admit/worker/
  provider send/new handoffをcold restart後も拒否する。
- `ninlil_rrmp_core_scope_parent_anomaly_v2`: 1 scopeだけに証明されたduplicate/conflicting
  parent evidence。当該scopeだけをsealする。

authority-global fenceのclear APIは本revisionに存在しない。再provision以外では解除不能。
parent-set reinstall、higher assignment epoch、handoff、outer OLD/NEW recoveryはclearしない。

### 13. Resource bounds

| Resource | Bound | Exhaustion |
| --- | --- | --- |
| parent set entries | 8 | install reject |
| concurrent owner scopes | 64 | new scope reject |
| handoff inflight | 8 | new handoff reject |
| global token replay ledger（LIVE + used tombstone） | 256 | new handoff reject; implicit eviction禁止（GCはS6 + retention後の明示契約のみ） |
| uplink dedupe window | 512 | diagnostics drop only |
| path evidence ring | 128 | oldest diagnostic drop |

exhaustion時にownerを二重化しない。新規migrationを拒否する。

### 14. Parent loss mid-flight（ADR-0019連結）

parent loss検出時:

1. 当該parentをownerとするscopeをseal 0
2. 影響routeをADR-0019 batch drain（≤8）
3. authorityが新assignmentをCASするまでEndpointはold attemptを再送しない
4. new assignment ACTIVE後、**new attempt**でのみ再送
5. mid-flight custody evidenceは保持するがApplication Receiptは出さない
6. alternate parentなしをsuccess表示しない

### 15. Mixed-version / default-OFF / rollback

| Topic | Rule |
| --- | --- |
| Feature | `NINLIL_FEATURE_MULTI_PARENT` default **OFF** |
| Capability | critical negotiated。非対応Endpointをdiversityへsilent参加させない |
| Single-parent | parent set size 1として同じmodelを使用可 |
| Schema ≠1 | `UNSUPPORTED_SCHEMA`、seal 0 |
| Downgrade | new pageをold binaryが読んだらfence |
| Rollback | term前進なしのassignment_revision後退 reject |
| Rolling | Decision 7の6 state順を変えない。途中失敗でowner推測しない |

### 16. Integrity and gates

ADR-0019 §10と同一: CRC/digest repair before semantic rejection。
mark-only禁止。self-comparison禁止。

Machine vectorsはADR-0019と共有:

- `spec/vectors/route-relay-multiparent-spec-v1.json`
- generator / Python gate / Node gate

必須ID prefix: `MP-`（parent/owner）、`RRMP-`（連結scenario）。

## Compatibilityとmigration

- NRW1 `0x11`、E2E context semantics、route terminal invariantは変更しない。
- multi-parentはcritical negotiated capability。
- single-parent deploymentはparent set size 1。
- rolling migrationはPREPARED_NEW → … → OLD_RETIREDの順を変えない。
- Runtime Platform ABIは変更しない。

## Dependencies

ADR-0017 Fabric、NRW1 full state、ADR-0019 route authority/lease/drain、
durable E2E context install、Controller dedupeを前提とする。
authority protocolなしに複数PCをsupportしない。
ADR-0019とのjoint SPEC_ACCEPTEDはdesign authorityだけを閉じる。
private/default-OFF implementationは本ADRへ追従しているが、physical RF HILと
release gateを経るまではrelease-supported authorityにしてはならない。

## Acceptance

### SPEC_ACCEPTED（2026-07-30充足）

ADR-0019とjointに、次の設計gateをすべて充足した。独立最終レビュー
[2026-07-29 RRMP final repair independent review](../reviews/2026-07-29-rrmp-final-repair-review.md)
は最終repairへの非関与を明記し、P0=0 / P1=0でjoint promotion可能と判定した。
promotion後のgenerator / Python / Node / C gate再実行は
[2026-07-30 RRMP SPEC_ACCEPTED promotion](../work/2026-07-30-rrmp-spec-accepted-promotion.md)
に固定する。これはMulti-parentのimplementation complete、physical target/RF HIL、
production HA supportを意味しない。

1. 全10 private C11 signature + req/result layouts、owner scope、NPH1/NPT1/NPA1/NOA1 exact byte layout固定とKAT
2. private API、status precedence、reentrancy固定
3. 6-state machine、local FULL、authority CAS、COMMIT_UNKNOWN recoveryの独立model
4. single logical authority writer + 複数fenced participant、partition時safety境界
5. storage全key/value、retention、same-channel/scheduled-scan resource profile固定
6. duplicate effect ownerとdownlink sealerが全状態で最大1のmachine-checkable invariant
7. shared vector inventory完全、Python/Node gate緑

### RELEASE_SUPPORTED（未達・非主張）

docs/34および旧版RELEASE節のHIL/soak条件。本改訂は完了を主張しない。

## Consequences

複数親機を容量と冗長性の両方へ利用できる仕様境界を固定する一方、
single-owner fence、E2E context rotation、duplicate evidence、authority storageが必須。
単に同じ鍵を複数親機へ配る設計は採用しない。public ABIは増やさない。

## Rejected alternatives

- first heard parentが自動でdownlink ownerになる
- 複数Controllerが同じE2E sealer/contextを共有する
- parent切替ごとに新transactionを作る
- same attemptのままparent reselectionする
- redundancyとcapacity splitを同じSLOとして扱う
- split brain時にbest-effort downlinkを送る
- custody successをApplication Receiptと同一視する
- public Platform ABIへparent APIを露出する

## 非主張

本ADRはAccepted / SPEC_ACCEPTEDのdesign authorityである。主張する状態bitは
`spec_accepted=1`だけであり、implementation、HIL、release support、public ABIは0。
private Multi-parent implementation、split-brain fail-closed処理、durable handoffの
host/ESP software evidenceは存在するが、HA完成、physical RF HIL、capacity/SLO、
production support、`RELEASE_SUPPORTED`は主張しない。vector/gate/host testの緑は
実機合格を意味しない。

## Related

- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [Identity and Join](../03-identity-and-join.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [ADR-0017](0017-bearer-registry-path-selection.md)
- [ADR-0019](0019-route-relay.md)
- Machine vectors: `spec/vectors/route-relay-multiparent-spec-v1.json`
