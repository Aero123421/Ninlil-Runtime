# V1-LAB Durable Allowlist Profile（unit 1a 正本）

状態: unit 1a 実装正本  
対象: Ninlil V1 LAB 項目 1 — Store/再起動正当性（D3-S1..S3 検証可能集合）  
規範: [16-foundation-implementation-plan.md](../16-foundation-implementation-plan.md)、[17-foundation-domain-store.md](../17-foundation-domain-store.md) §18.12/18.13/18.14

## 1. 目的

V1-LAB durable profile は **record kind・state・operation の closed allowlist** です。Writer は allowlist 外の row/state を生成せず、recovery/publication は allowlist 外・unknown・corrupt・mixed を publication 前に拒否します（成功 evidence 0、false success 禁止）。

本書は unit 1a の正本です。SQLite 昇格/restart E2E（1b）、ESP gate（1c）は範囲外です。

## 2. Record kind allowlist（34 kinds）

| # | Kind ID | 名前 | Family | 検証 owner |
| ---: | --- | --- | --- | ---: |
| 1 | RS_BINDING | Runtime binding | 3 | S1 |
| 2 | RS_IDENTITY | Runtime identity | 4 | S1 |
| 3 | RS_COUNTER_TRANSACTION | Counter transaction | 3 | S1 |
| 4 | RS_COUNTER_ORDERED_INPUT | Counter ordered input | 3 | S1 |
| 5 | RS_COUNTER_ASSIGNED_OWNER | Counter assigned owner | 3 | S1 |
| 6 | RS_COUNTER_VISITED_OWNER | Counter visited owner | 3 | S1 |
| 7 | RS_CAPACITY_SERVICE | Capacity service | 3 | S1 |
| 8 | RS_CAPACITY_TRANSACTION | Capacity transaction | 3 | S1 |
| 9 | RS_CAPACITY_TARGET | Capacity target | 3 | S1 |
| 10 | RS_CAPACITY_OUTBOX_BYTES | Capacity outbox bytes | 3 | S1 |
| 11 | RS_CAPACITY_DELIVERY | Capacity delivery | 3 | S1 |
| 12 | RS_CAPACITY_EVENT_SPOOL_COUNT | Capacity event spool count | 3 | S1 |
| 13 | RS_CAPACITY_EVENT_SPOOL_BYTES | Capacity event spool bytes | 3 | S1 |
| 14 | RS_CAPACITY_RESULT_CACHE | Capacity result cache | 3 | S1 |
| 15 | RS_CAPACITY_EVIDENCE | Capacity evidence | 3 | S1 |
| 16 | RS_CAPACITY_INGRESS | Capacity ingress | 3 | S1 |
| 17 | RS_CAPACITY_DEFERRED_TOKEN | Capacity deferred token | 3 | S1 |
| 18 | DOM_WITNESS_HEAD_INDEX | Witness head index (0x7d) | 6 | S1 |
| 19 | DOM_CLOCK_BASELINE | Clock baseline (0x62) | 6 | S1 |
| 20 | SPINE_SERVICE_MARKER | B1 spine service register marker | marker | S1 |
| 21 | SPINE_TXN_ADMISSION | B1 spine submit admission marker | marker | S1 |
| 22 | SPINE_CANCEL_ADMISSION | B1 spine cancel admission marker | marker | S1 |
| 23 | SPINE_DELIVERY_STARTED | B1 delivery started (`DS`) | marker | S1 |
| 24 | SPINE_DELIVERY_EVIDENCE | B1 delivery evidence (`EV`) | marker | S1 |
| 25 | SPINE_DELIVERY_OUTCOME | B1 delivery outcome (`OC`) | marker | S1 |
| 26 | SPINE_EVENT_SPOOL | B1 event spool (`ES`) | marker | S1 |
| 27 | SPINE_EVENT_RESUME | B1 event resume (`ER`) | marker | S1 |
| 28 | SPINE_EVENT_DISCARD | B1 event discard (`ED`) | marker | S1 |
| 29 | SPINE_RETRY_STATE | B1 retry state (`RT`) | marker | S1 |
| 30 | SPINE_RESERVATION | B3 reservation (`RV`) | marker | S1 |
| 31 | M4_INSTALL_TOKEN | M4 install-token journal | M4 | M4 |
| 32 | C3_REPLAY_ADMISSION | C3 replay-admission journal | C3 | C3 |
| 33 | SPINE_BEARER_STATE | B1 bearer-state observation (`BS`) | marker | S1 |
| 34 | SPINE_ATTEMPT_PREPARE | B1 application-attempt prepare (`AP`) | marker | S1 |

コード正本: `src/runtime/v1_durable_allowlist.c` の `g_ninlil_v1_durable_allowlist_table[]`（`NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT = 34`）。

### 2a 追記（unit 2a / 項目 2 spine）

- kinds 20–22 は domain codec row ではなく、spine admission の bounded marker key（`NRS` / `TX` / `CN` prefix）です。
- writer 経路: `ninlil_v1_durable_storage_put()`（`runtime_v1_spine_durable.c`）。
- recovery publication gate は RS/DOM + spine marker（kinds 20–30）を success evidence 対象とする（`publication_classify_row` / Stage5 scan spine skip）。

### 2b 追記（unit 2b / 項目 2 delivery）

- kinds 23–29 は delivery / event management / retry spine の bounded marker key（`DS` / `EV` / `OC` / `ES` / `ER` / `ED` / `RT` prefix）。
- writer 経路: `runtime_v1_delivery_durable.c`、`runtime_v1_event_mgmt.c`（`ninlil_v1_durable_storage_put`）。
- Stage5 domain scanner は allowlisted spine row を lex-order でスキップ（`domain_store_scanner.c`）；restart 時に bootstrap + spine marker 共存を受理。

### 2c 追記（unit 4 / 項目 4 B3 capability）

- kind 30 `SPINE_RESERVATION` は admission 後の容量予約 marker key（`RV` prefix）。
- writer 経路: `runtime_v1_capability.c`（`ninlil_rt_v1_commit_reservation_marker`）、operation `RESERVATION_COMMIT`（14）。
- TX admission marker v2（46B: priority / payload_length / admitted_at_ms）は kind 21 value 拡張（v1 33B 後方互換 decode）。
- bearer payload 上限は表駆動（`runtime_v1_capability.c` `g_bearer_limit_table[]`；SIMULATED/U6=926B）。

### 2d 追記（M4 / C3 / bearer-state / attempt prepare）

- kind 31 `M4_INSTALL_TOKEN` は M4 install-token のCRC付き bounded journal、operation `M4_INSTALL_TOKEN_COMMIT`（15）。
- kind 32 `C3_REPLAY_ADMISSION` は C3 replay-admission のCRC付き bounded journal、operation `C3_REPLAY_ADMISSION_COMMIT`（16）。
- kind 33 `SPINE_BEARER_STATE` は bearer availability epoch の durable observation marker（`BS`）、operation `BEARER_STATE_COMMIT`（17）。
- kind 34 `SPINE_ATTEMPT_PREPARE` は送信前 attempt identity / retry budget の durable prepare snapshot（`AP`）、operation `APPLICATION_ATTEMPT_PREPARE_COMMIT`（18）。
- operation 19 `DESTROY_RECOVERY_COMMIT` は ACTIVE callback token 群を同一 FULL transaction で recovery-required に閉じる。対象 row は `SPINE_DELIVERY_EVIDENCE` と Runtime Store capacity 11 kinds。

### 2.1 D3-S1..S3 検証 owner 注記

| Owner | 範囲（V1 unit 1a） |
| --- | --- |
| **S1** | Bootstrap-17（family 3/4）、metadata-init 16 domain rows（HEAD_INDEX×15 + CLOCK_BASELINE）、exact-1 backlink / PVD（D3-S1）で検証可能な初期 profile |
| **S2** | 本 profile では writer 未生成（declared multi-count graph は V2） |
| **S3** | 本 profile では writer 未生成（BLOB lifecycle rows は V2） |
| **M4** | M4 install-token bounded journal（kind 31） |
| **C3** | C3 replay-admission bounded journal（kind 32） |

## 3. State allowlist（domain metadata のみ）

| Record kind | 許可 state | Operation 制約 |
| --- | --- | --- |
| DOM_WITNESS_HEAD_INDEX | `INDEX_STATE_BASELINE` (1) のみ | METADATA_INIT_COMMIT |
| DOM_CLOCK_BASELINE | `BASELINE_STATE_UNINITIALIZED` (1) | METADATA_INIT_COMMIT |
| DOM_CLOCK_BASELINE | `BASELINE_STATE_TRUSTED` (2) | CLOCK_TRUSTED_COMMIT |

Runtime store family 3/4 rows は state field を持たず、bootstrap plan の zero counter / capacity limits のみ（S1）。

## 4. Operation allowlist（19 operations）

| Operation | Writer 経路 | 許可 record kinds |
| --- | --- | --- |
| `BOOTSTRAP_COMMIT` | `runtime_store_orchestrator` → `storage_canonical_plan` | `RS_BINDING`, `RS_IDENTITY`, `RS_COUNTER_TRANSACTION`, `RS_COUNTER_ORDERED_INPUT`, `RS_COUNTER_ASSIGNED_OWNER`, `RS_COUNTER_VISITED_OWNER`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `METADATA_INIT_COMMIT` | `stage5_empty_metadata_commit` | `DOM_WITNESS_HEAD_INDEX`, `DOM_CLOCK_BASELINE` |
| `CLOCK_TRUSTED_COMMIT` | `stage5_clock_baseline_commit_trusted` | `DOM_CLOCK_BASELINE` |
| `SERVICE_REGISTER_COMMIT` | `runtime_v1_spine_durable.c` | `SPINE_SERVICE_MARKER` |
| `SUBMIT_ADMISSION_COMMIT` | 同上 | `SPINE_TXN_ADMISSION`, `SPINE_RESERVATION`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `CANCEL_ADMISSION_COMMIT` | 同上 | `SPINE_CANCEL_ADMISSION`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `DELIVERY_STARTED_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_DELIVERY_STARTED`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `DELIVERY_EVIDENCE_COMMIT` | 同上 | `SPINE_DELIVERY_EVIDENCE`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `DELIVERY_OUTCOME_COMMIT` | 同上 | `SPINE_DELIVERY_OUTCOME`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `EVENT_SPOOL_COMMIT` | 同上 / `runtime_v1_event_mgmt.c` | `SPINE_EVENT_SPOOL` |
| `EVENT_RESUME_COMMIT` | `runtime_v1_event_mgmt.c` | `SPINE_EVENT_RESUME`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `EVENT_DISCARD_COMMIT` | 同上 | `SPINE_EVENT_DISCARD`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `RETRY_STATE_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_RETRY_STATE` |
| `RESERVATION_COMMIT` | `runtime_v1_capability.c` | `SPINE_RESERVATION` |
| `M4_INSTALL_TOKEN_COMMIT` | M4 install-token writer | `M4_INSTALL_TOKEN` |
| `C3_REPLAY_ADMISSION_COMMIT` | C3 replay-admission writer | `C3_REPLAY_ADMISSION` |
| `BEARER_STATE_COMMIT` | `runtime_v1_bearer_wire.c` | `SPINE_BEARER_STATE` |
| `APPLICATION_ATTEMPT_PREPARE_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_ATTEMPT_PREPARE` |
| `DESTROY_RECOVERY_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_DELIVERY_EVIDENCE`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |

`METADATA_INIT_COMMIT` の `DOM_CLOCK_BASELINE` は UNINITIALIZED、`CLOCK_TRUSTED_COMMIT` は TRUSTED のみ許可する（state 制約は §3）。上表は companion row を省略しない exact matrix であり、C authority の 19 operations × 34 kinds と `tools/v1_durable_allowlist_gate.py` で完全一致を検査する。

## 5. Writer 構造 gate

- 検査: `ninlil_v1_durable_writer_gate_check()` — allowlist 外は `NINLIL_E_UNSUPPORTED`、put 0
- 経路: `runtime_store_orchestrator.c`（bootstrap）、`stage5_empty_metadata.c` `put_encoded`（domain metadata）
- 構造 gate: `tools/v1_durable_allowlist_gate.py` — gate check 必須、`put_encoded` 内の単一 `storage->put` のみ許可。record-kind enum/table、operation enum、C の 19×34 bit matrix、§4 の文書表を exact 検査し、operation omission / extra / operation-kind pair 改変を mutation self-test で RED 化する。

## 6. Recovery publication gate

`ninlil_v1_durable_recovery_publication_gate()` は publication 前に全 row を分類し、次を拒否します（`adopted=0`, `success_evidence_count=0`）:

| Reject reason | 条件 |
| --- | --- |
| COMMIT_UNKNOWN | `commit_unknown_active != 0` |
| MIXED | allowlisted row と unknown/corrupt/external が同一 scan に共存 |
| CORRUPT | `NINLIL_E_STORAGE_CORRUPT` 分類 |
| UNKNOWN | 分類不能 key（malformed / future） |
| ALLOWLIST_EXTERNAL | 将来拡張用（現行は UNKNOWN に集約） |

## 7. 実測: Stage5 recovery writer 生成集合 vs allowlist 差分

### 7.1 現行 writer が生成する record（実測）

| 経路 | 生成 record | 件数 |
| --- | --- | ---: |
| L2b1 `commit_new_bootstrap` | bootstrap-17（RS_* 17 kinds） | 17 |
| `stage5_empty_metadata_commit` | DOM_WITNESS_HEAD_INDEX (BASELINE) | 15 |
| 同上 | DOM_CLOCK_BASELINE (UNINITIALIZED) | 1 |
| `stage5_clock_baseline_commit_trusted` | DOM_CLOCK_BASELINE (TRUSTED) | 1（更新） |

### 7.2 Allowlist 外を生成する経路（現状）

| 経路 | 状態 |
| --- | --- |
| 直接 `storage->put`（gate 前） | **0**（gate 導入後） |
| canonical business domain rows（TRANSACTION, DELIVERY, BLOB, …） | **V2 deferred**（追加時は allowlist 表拡張必須） |
| D3-S4..S12 witness old/new | **未生成**（V2） |

### 7.3 差分表（catalog 全体に対する V1-LAB 除外）

Family 6 catalog（docs/17 §7）のうち V1-LAB allowlist **外**（writer 未生成・recovery で拒否）:

`10 SERVICE`, `11 SERVICE_QUOTA`, `20–27 TRANSACTION/INGRESS 系`, `30 BLOB`, `31–34 ATTEMPT/EVIDENCE/CANCEL`, `40–42 DELIVERY/RESULT/REPLY`, `50–52 EVENT/RETRY/MANAGEMENT`, `60 BEARER_STATE`, `61 RETENTION_BASIS`, `63 CLEANUP_PLAN`, `64 ATTEMPT_REUSE_FENCE`, `7e WITNESS_MANIFEST_CHUNK`, `7f WITNESS_HEADER`, family `5 INTERNAL_INVARIANT`

これらは現行 V1-LAB writer 経路からは到達不能（writer gate RED）。V2 で追加する際は本表への行追加 + gate self-test が必須です。D3 relation kind 19（canonical family-6 witness）を含む完全な witness graph も V2 deferred です（本 allowlist の record-kind ID 19 `DOM_CLOCK_BASELINE` とは別の番号空間）。

## 8. 非主張

- D3-S4..S12 scanner 網羅、D4 全域 convergence、public ABI 変更、ESP success path
