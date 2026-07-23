# V1-LAB Durable Allowlist Profile（unit 1a 正本）

状態: unit 1a 実装正本  
対象: Ninlil V1 LAB 項目 1 — Store/再起動正当性（D3-S1..S3 検証可能集合）  
規範: [16-foundation-implementation-plan.md](../16-foundation-implementation-plan.md)、[17-foundation-domain-store.md](../17-foundation-domain-store.md) §18.12/18.13/18.14

## 1. 目的

V1-LAB durable profile は **record kind・state・operation の closed allowlist** です。Writer は allowlist 外の row/state を生成せず、recovery/publication は allowlist 外・unknown・corrupt・mixed を publication 前に拒否します（成功 evidence 0、false success 禁止）。

本書は unit 1a の正本です。SQLite 昇格/restart E2E（1b）、ESP gate（1c）は範囲外です。

## 2. Record kind allowlist（19 kinds）

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

コード正本: `src/runtime/v1_durable_allowlist.c` の `g_ninlil_v1_durable_allowlist_table[]`（`NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT = 19`）。

### 2.1 D3-S1..S3 検証 owner 注記

| Owner | 範囲（V1 unit 1a） |
| --- | --- |
| **S1** | Bootstrap-17（family 3/4）、metadata-init 16 domain rows（HEAD_INDEX×15 + CLOCK_BASELINE）、exact-1 backlink / PVD（D3-S1）で検証可能な初期 profile |
| **S2** | 本 unit では writer 未生成（declared multi-count graph は項目 2–9 以降） |
| **S3** | 本 unit では writer 未生成（BLOB lifecycle rows は項目 2–9 以降） |

## 3. State allowlist（domain metadata のみ）

| Record kind | 許可 state | Operation 制約 |
| --- | --- | --- |
| DOM_WITNESS_HEAD_INDEX | `INDEX_STATE_BASELINE` (1) のみ | METADATA_INIT_COMMIT |
| DOM_CLOCK_BASELINE | `BASELINE_STATE_UNINITIALIZED` (1) | METADATA_INIT_COMMIT |
| DOM_CLOCK_BASELINE | `BASELINE_STATE_TRUSTED` (2) | CLOCK_TRUSTED_COMMIT |

Runtime store family 3/4 rows は state field を持たず、bootstrap plan の zero counter / capacity limits のみ（S1）。

## 4. Operation allowlist（3 operations）

| Operation | Writer 経路 | 許可 record kinds |
| --- | --- | --- |
| `BOOTSTRAP_COMMIT` | `runtime_store_orchestrator` → `storage_canonical_plan` | RS_BINDING .. RS_CAPACITY_DEFERRED_TOKEN（17 kinds） |
| `METADATA_INIT_COMMIT` | `stage5_empty_metadata_commit` | DOM_WITNESS_HEAD_INDEX, DOM_CLOCK_BASELINE（UNINITIALIZED） |
| `CLOCK_TRUSTED_COMMIT` | `stage5_clock_baseline_commit_trusted` | DOM_CLOCK_BASELINE（TRUSTED） |

## 5. Writer 構造 gate

- 検査: `ninlil_v1_durable_writer_gate_check()` — allowlist 外は `NINLIL_E_UNSUPPORTED`、put 0
- 経路: `runtime_store_orchestrator.c`（bootstrap）、`stage5_empty_metadata.c` `put_encoded`（domain metadata）
- 構造 gate: `tools/v1_durable_allowlist_gate.py` — gate check 必須、`put_encoded` 内の単一 `storage->put` のみ許可

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
| business domain rows（TRANSACTION, DELIVERY, BLOB, …） | **未接続**（項目 2–9 で追加時は allowlist 表拡張必須） |
| D3-S4..S12 witness old/new | **未生成**（V2） |

### 7.3 差分表（catalog 全体に対する V1-LAB 除外）

Family 6 catalog（docs/17 §7）のうち V1-LAB allowlist **外**（writer 未生成・recovery で拒否）:

`10 SERVICE`, `11 SERVICE_QUOTA`, `20–27 TRANSACTION/INGRESS 系`, `30 BLOB`, `31–34 ATTEMPT/EVIDENCE/CANCEL`, `40–42 DELIVERY/RESULT/REPLY`, `50–52 EVENT/RETRY/MANAGEMENT`, `60 BEARER_STATE`, `61 RETENTION_BASIS`, `63 CLEANUP_PLAN`, `64 ATTEMPT_REUSE_FENCE`, `7e WITNESS_MANIFEST_CHUNK`, `7f WITNESS_HEADER`, family `5 INTERNAL_INVARIANT`

これらは D3-S1..S3 の現行 writer 経路からは到達不能（writer gate RED）。項目 2–9 で追加する際は本表への行追加 + gate self-test が必須です。

## 8. 非主張

- D3-S4..S12 scanner 網羅、D4 全域 convergence、public ABI 変更、ESP success path
- Stage 5 complete / `storage_recovery_complete=1`（unit 1b）
- SQLite restart E2E（unit 1b）
