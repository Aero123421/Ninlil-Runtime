# V1-LAB Durable Allowlist Profile（unit 1a 正本）

状態: unit 1a 実装正本  
対象: Ninlil V1 LAB 項目 1 — Store/再起動正当性（D3-S1..S3 検証可能集合）  
規範: [16-foundation-implementation-plan.md](../16-foundation-implementation-plan.md)、[17-foundation-domain-store.md](../17-foundation-domain-store.md) §18.12/18.13/18.14

## 1. 目的

V1-LAB durable profile は **record kind・state・operation の closed allowlist** です。本 profile に適合する writer は allowlist 外の row/state を生成せず、recovery/publication は allowlist 外・unknown・corrupt・mixed を publication 前に拒否します（成功 evidence 0、false success 禁止）。本 gate が証明する writer seam の範囲は §5 に限定します。

本書は unit 1a の正本です。SQLite 昇格/restart E2E（1b）、ESP gate（1c）は範囲外です。

## 2. Record kind allowlist（41 kinds）

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
| 35 | DOM_IDEMPOTENCY_MAP | Idempotency map (0x24) | 6 | S1 |
| 36 | DOM_EVENT_ID_MAP | Event ID map (0x25) | 6 | S1 |
| 37 | DOM_WITNESS_HEADER | Witness header (0x7f) | 6 | S1 |
| 38 | DOM_WITNESS_MANIFEST_CHUNK | Witness manifest chunk (0x7e) | 6 | S1 |
| 39 | DOM_SERVICE | Service (0x10) | 6 | S1 |
| 40 | DOM_SERVICE_QUOTA | Service quota (0x11) | 6 | S1 |
| 41 | DOM_RESERVATION | Reservation (0x23) | 6 | S1 |

コード正本: `src/runtime/v1_durable_allowlist.c` の `g_ninlil_v1_durable_allowlist_table[]`（`NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT = 41`）。

### 2a 追記（unit 2a / 項目 2 spine）

- kinds 20–22 は domain codec row ではなく、spine admission の bounded marker key（`NRS` / `TX` / `CN` prefix）です。
- writer 経路: `ninlil_v1_durable_storage_put()`（`runtime_v1_spine_durable.c`）。
- recovery publication gate は分類・検証に成功した allowlisted row（kinds 1–41）を success evidence 対象とする（`publication_classify_row` / Stage5 scan spine skip）。

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

### 2e 追記（canonical map / witness / service rows）

- kinds 35–36 は canonical idempotency / event-ID map、kinds 37–38 は admission witness header / manifest chunk、kinds 39–41 は service / quota / reservation の family-6 row で、検証 owner はすべて S1。
- 41-kind catalog は row の分類・検証・recovery publication authority であり、operation ごとの書込み許可 authority は §4 の 19×41 matrix とする。
- catalog に存在することは、すべての production writer が `ninlil_v1_durable_storage_put()` という単一 seam を通ること、または各 kind に現行 operation が割り当て済みであることを意味しない。特に kinds 39–41 の direct Domain Store writer seam は本書・本 gate の非主張である。

### 2.1 D3-S1..S3 検証 owner 注記

| Owner | 範囲（V1 unit 1a） |
| --- | --- |
| **S1** | Bootstrap-17（family 3/4）、metadata rows、spine marker、canonical map / witness / service rows（kinds 1–30, 33–41）を分類・検証する profile |
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
| `SERVICE_REGISTER_COMMIT` | `runtime_v1_spine_durable.c` | `SPINE_SERVICE_MARKER`, `RS_CAPACITY_SERVICE` |
| `SUBMIT_ADMISSION_COMMIT` | 同上 | `SPINE_TXN_ADMISSION`, `SPINE_RESERVATION`, `SPINE_SERVICE_MARKER`, `DOM_IDEMPOTENCY_MAP`, `DOM_EVENT_ID_MAP`, `DOM_WITNESS_HEADER`, `DOM_WITNESS_MANIFEST_CHUNK`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `CANCEL_ADMISSION_COMMIT` | 同上 | `SPINE_CANCEL_ADMISSION`, `SPINE_SERVICE_MARKER`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `DELIVERY_STARTED_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_DELIVERY_STARTED`, `SPINE_SERVICE_MARKER`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `DELIVERY_EVIDENCE_COMMIT` | 同上 | `SPINE_DELIVERY_EVIDENCE`, `SPINE_SERVICE_MARKER`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `DELIVERY_OUTCOME_COMMIT` | 同上 | `SPINE_DELIVERY_OUTCOME`, `SPINE_SERVICE_MARKER`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `EVENT_SPOOL_COMMIT` | 同上 / `runtime_v1_event_mgmt.c` | `SPINE_EVENT_SPOOL` |
| `EVENT_RESUME_COMMIT` | `runtime_v1_event_mgmt.c` | `SPINE_EVENT_RESUME`, `SPINE_SERVICE_MARKER`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `EVENT_DISCARD_COMMIT` | 同上 | `SPINE_EVENT_DISCARD`, `SPINE_SERVICE_MARKER`, `RS_COUNTER_ORDERED_INPUT`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |
| `RETRY_STATE_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_RETRY_STATE` |
| `RESERVATION_COMMIT` | `runtime_v1_capability.c` | `SPINE_RESERVATION` |
| `M4_INSTALL_TOKEN_COMMIT` | M4 install-token writer | `M4_INSTALL_TOKEN` |
| `C3_REPLAY_ADMISSION_COMMIT` | C3 replay-admission writer | `C3_REPLAY_ADMISSION` |
| `BEARER_STATE_COMMIT` | `runtime_v1_bearer_wire.c` | `SPINE_BEARER_STATE` |
| `APPLICATION_ATTEMPT_PREPARE_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_ATTEMPT_PREPARE` |
| `DESTROY_RECOVERY_COMMIT` | `runtime_v1_delivery_durable.c` | `SPINE_DELIVERY_EVIDENCE`, `SPINE_SERVICE_MARKER`, `RS_CAPACITY_SERVICE`, `RS_CAPACITY_TRANSACTION`, `RS_CAPACITY_TARGET`, `RS_CAPACITY_OUTBOX_BYTES`, `RS_CAPACITY_DELIVERY`, `RS_CAPACITY_EVENT_SPOOL_COUNT`, `RS_CAPACITY_EVENT_SPOOL_BYTES`, `RS_CAPACITY_RESULT_CACHE`, `RS_CAPACITY_EVIDENCE`, `RS_CAPACITY_INGRESS`, `RS_CAPACITY_DEFERRED_TOKEN` |

`METADATA_INIT_COMMIT` の `DOM_CLOCK_BASELINE` は UNINITIALIZED、`CLOCK_TRUSTED_COMMIT` は TRUSTED のみ許可する（state 制約は §3）。上表は companion row を省略しない exact matrix であり、C authority の 19 operations × 41 kinds と `tools/v1_durable_allowlist_gate.py` で完全一致を検査する。catalog の kind が上表のどの operation にも現れない場合、その事実だけで writer authority は生じない。

## 5. Writer 構造 gate

- 検査: `ninlil_v1_durable_writer_gate_check()` — その API に渡された operation/kind pair が §4 外なら `NINLIL_E_UNSUPPORTED`、put 0。
- 構造検査対象: `runtime_store_orchestrator.c` の bootstrap gate、`stage5_empty_metadata.c` の `ninlil_v1_durable_storage_put()` wiring、および `v1_durable_allowlist.c` 内の単一 raw `storage->put`。
- `tools/v1_durable_allowlist_gate.py` は record-kind enum/table、operation enum、C の 19×41 bit matrix、§2 の 41-kind catalog、§4 の文書 matrix を exact 検査し、C authority と文書 authority の omission / extra / pair 改変を mutation self-test で RED 化する。
- **Writer seam 非主張:** この構造 gate は repository 全体の durable write call graph を証明しない。Domain Store の canonical plan / batch など別の atomic writer seam が存在し得るため、「全41 kinds の writer が `ninlil_v1_durable_storage_put()` を通る」「全 production direct put が0」とは主張しない。

## 6. Recovery publication gate

`ninlil_v1_durable_recovery_publication_gate()` は publication 前に全 row を分類し、次を拒否します（`adopted=0`, `success_evidence_count=0`）:

| Reject reason | 条件 |
| --- | --- |
| COMMIT_UNKNOWN | `commit_unknown_active != 0` |
| MIXED | allowlisted row と unknown/corrupt/external が同一 scan に共存 |
| CORRUPT | `NINLIL_E_STORAGE_CORRUPT` 分類 |
| UNKNOWN | 分類不能 key（malformed / future） |
| ALLOWLIST_EXTERNAL | 将来拡張用（現行は UNKNOWN に集約） |

## 7. 検証範囲: Stage5 writer と 41-kind authority

### 7.1 現行 writer が生成する record（実測）

| 経路 | 生成 record | 件数 |
| --- | --- | ---: |
| L2b1 `commit_new_bootstrap` | bootstrap-17（RS_* 17 kinds） | 17 |
| `stage5_empty_metadata_commit` | DOM_WITNESS_HEAD_INDEX (BASELINE) | 15 |
| 同上 | DOM_CLOCK_BASELINE (UNINITIALIZED) | 1 |
| `stage5_clock_baseline_commit_trusted` | DOM_CLOCK_BASELINE (TRUSTED) | 1（更新） |

### 7.2 構造 gate が証明する範囲

| 経路 | 状態 |
| --- | --- |
| `stage5_empty_metadata.c` の直接 `storage->put` | **0**（allowlist wrapper 経由を source gate で検査） |
| `v1_durable_allowlist.c` 内の raw `storage->put` | **exactly 1**（wrapper 実装 seam） |
| repository 全体の durable writer closure | **非主張**（§5 の writer seam 非主張） |
| 41-kind catalog / 19-operation pair authority | **exact**（C header/table/mask と本書 §2/§4 を gate で一致検査） |

### 7.3 差分表（catalog 全体に対する V1-LAB 除外）

Family 6 catalog（docs/17 §7）のうち 41-kind allowlist **外**（recovery publication で拒否）:

canonical map として採用した `24 IDEMPOTENCY_MAP` / `25 EVENT_ID_MAP` を除く `20–27 TRANSACTION/INGRESS` 系、`30 BLOB`、`31–34 ATTEMPT/EVIDENCE/CANCEL`、`40–42 DELIVERY/RESULT/REPLY`、`50–52 EVENT/RETRY/MANAGEMENT`、`60 BEARER_STATE`、`61 RETENTION_BASIS`、`63 CLEANUP_PLAN`、`64 ATTEMPT_REUSE_FENCE`、family `5 INTERNAL_INVARIANT`。`10 SERVICE`、`11 SERVICE_QUOTA`、`23 RESERVATION`、`7e WITNESS_MANIFEST_CHUNK`、`7f WITNESS_HEADER` は kinds 39–41 / 38 / 37 として allowlist 内である。

allowlist 外 row は本 recovery publication authority では拒否する。将来追加する際は §2 の行、必要な §4 pair、C authority、gate self-test を同時更新する。D3 relation kind 19（canonical family-6 witness）と、本 allowlist の record-kind ID 19 `DOM_CLOCK_BASELINE` は別の番号空間である。

## 8. 非主張

- repository 全 durable writer の単一-seam closure、各 catalog kind の現行 writer 到達可能性
- D3-S4..S12 scanner 網羅、D4 全域 convergence、public ABI 変更、ESP success path
