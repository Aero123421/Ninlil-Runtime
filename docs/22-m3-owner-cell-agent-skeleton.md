# 22. M3-slice: FreeRTOS owner-task / Cell Agent / loopback TxPermit

状態: **Normative for this experimental M3 slice only**（**M3 incomplete**）  
対象: ESP32-S3 dual-core FreeRTOS owner-task、Cell Agent skeleton、loopback TxPermit  
ESP-IDF pin: **v5.5.3**（`ports/esp-idf/ESP_IDF_VERSION`）

## 1. Experimental / 非主張

| 層 | 主張 |
| --- | --- |
| pure host model | experimental pure。runtime 代替ではない |
| target compile/link | compile evidence only。HIL PASS ではない |
| device flash+monitor | HIL。未実施なら未実施 |

**禁止:** M3 complete、production-candidate、compile=HIL、application integration、USB/NVS/radio。

## 2. Lifecycle authority（単一 mux）

1 つの `portMUX`。task: `portENTER_CRITICAL`、ISR: `portENTER_CRITICAL_ISR`。  
api_lifecycle / published / handle / inflight / claim / gate lease の **ロック外 plain R/W 禁止**。

### 2.1 Published lifecycle

STOPPED | STARTING | RUNNING | STOPPING | JOIN_ACK | **FAILED_LIVE** | **FAILED_JOINED**

| | free/retire | tx_gate set | core stats | storage reuse |
| --- | --- | --- | --- | --- |
| STOPPED / FAILED_JOINED | after shutdown | yes (lease 0) | yes | yes |
| FAILED_LIVE | **no** | **no** | **no** | **no**（core/TCB/stack 触らない） |
| RUNNING/STARTING/STOPPING | no | no | no | no |

**語彙（MUST）:** ここでの `JOIN_ACK` / `FAILED_JOINED` は **Owner Task Join**（FreeRTOS owner task の suspend→delete→reclaim 証跡）である。[03章](03-identity-and-join.md) の Network / Attachment join でも、[23章](23-usb-radio-boundary.md) の Control HELLO でもない。C 記号は本 M3 slice では変更しない。規定移行名は `TASK_JOIN_ACK` / `FAILED_TASK_JOINED`（[23章 §11](23-usb-radio-boundary.md)、[15章](15-glossary.md)）。

### 2.2 Init / mux one-shot（mux_ready）

- caller は object を **zero-init**。
- `init` は **critical に入る前**に `mux = portMUX_INITIALIZER_UNLOCKED` を代入し `mux_ready=1`。
- **live mux を memset しない**（フィールド個別 zero）。one-shot re-init 拒否。

### 2.3 Inflight + claim

admit under mux: `inflight` **checked**（`UINT32_MAX` で拒否、偽 0 禁止）。  
close → inflight0 → join evidence → delete → reclaim → STOPPED|FAILED_JOINED → retire。

### 2.4 Start barrier

create 後 mux で handle+start_gate を publish してから RUNNING。

### 2.5 StaticTask reclaim（ESP-IDF v5.5.3 根拠）

FreeRTOS-Kernel `tasks.c` `vTaskDelete`（ESP-IDF v5.5.3）:

- `xIsCurRunning == pdFALSE` のとき **同期的に `prvDeleteTCB`** を呼ぶ。
- static stack+TCB では `prvDeleteTCB` はアプリ所有 memory を free しない（TLS cleanup のみ）。
- よって **precondition: `eTaskGetState(handle) == eSuspended`**（いずれの core でも running でない）を満たしてから `vTaskDelete` すれば、**固定 delay なし**で TCB/stack 再利用可。

Normative 手順:

1. owner: will_suspend=1 → `vTaskSuspend(NULL)`
2. manager: poll `eSuspended`（bounded）
3. published=JOIN_ACK（**Owner Task Join ACK**; Site Membership / Attachment / Control HELLO ではない。曖昧 umbrella「Network Join」でもない）
4. `vTaskDelete(handle)`（同期 cleanup、pin v5.5.3）
5. handle=NULL、`tcb_generation++`、queue reset、STOPPED
6. **FAILED_LIVE** では 4–5 を行わず storage を再利用しない

**固定 tick delay による idle 待ちは禁止。** pin 変更時は上記 `vTaskDelete` 経路を再監査。  
**self-stop**（owner 自身が stop を呼ぶ）は `SELF_STOP` で拒否。

### 2.6 Timeout

→ **FAILED_LIVE**。core/stats/tx_gate/reclaim **禁止**。

## 3. ISR / task API

- `post_tick` task only / `post_tick_from_isr` ISR only  
- assignment/control task only  
- smoke: **real ISR** = `CONFIG_ESP_TIMER_SUPPORTS_ISR_DISPATCH_METHOD` + `ESP_TIMER_ISR`

## 4. Stack / memory

- `StackType_t stack[N/sizeof]`、depth **4096 bytes**  
- HWM **bytes**  
- no backend shadow mailbox  

## 5. Cell Agent + tx_gate lease（single-use identity）

- cell は owner 単一 mux に統合。独立 plain lifecycle なし。
- **bounded live lease registry**（Normative **`MAX_TX_GATE_LEASES = 4`**）を mux 内に保持。layout は **unstable concrete storage detail**（`ninlil_esp_idf/detail/tx_gate_lease_registry.h`）。**public `owner_task.h` は lease 型 + capacity 定数のみ**（main API stable surface から registry 内部型を除外）。
- 各 slot: `occupied`、`token`、`epoch`、`ops`。
- **Public lease 契約**（`ninlil_esp_idf_tx_gate_lease_t`）: 保持中のみ有効な `{token, epoch, ops}`。release は single-use consume。borrower は ops を借用し provider 退役は borrowers==0 まで禁止。
- **acquire:** free slot を探し occupied にし、`borrowers = occupied_count`（registry 件数と常時一致）。token は object lifetime 中 **wrap/reuse 禁止**（`next_token∈{0,UINT32_MAX}` で **`TOKEN_EXHAUSTED`** fail-closed、live token と衝突しない）。slot 枯渇は **`LEASE_FULL`**。
- **release:** `token + epoch + ops` が **exact match** する occupied slot を **1 回だけ** free。それ以外（二重 release / 偽造 token/epoch/ops / 既 release）は **`LEASE_STALE`** で registry と count **不変**。
- **`set_tx_gate` / `shutdown`:** borrowers==0 のみ（否則 **BUSY**）。epoch set も no-wrap（`UINT32_MAX` で拒否）。
- **ABI header staging + declared struct_size non-overlap（Normative）:**
  - owner config / cell config / tx_gate ops / loopback config / request / time sample / permit: **fixed sizeof ではなく検証済み declared `struct_size` 全域**で storage との overlap を checked uintptr helper で拒否。
  - 手順: (1) 最小 ABI header だけ local stage (2) known min + abi (3) declared range representable + storage nonoverlap (4) known prefix のみ local。
  - **Cell init post-write reread = 0:** owner 書込み前に outer/nested/ops stage+validate 完了。その後は **trusted initial publish seam**（private `static inline`、default global ELF symbol なし）が original identity pointer + validated known local proof のみ受け取り、`public set_tx_gate` / registry re-stage / caller ops dereference を行わない。stack local ops pointer は保存しない。public set path は通常呼び出し用に独立維持。
  - **Nested owner（inline layout）:** original outer 内の owner field header を先に stage。`struct_size` は **exact `sizeof(owner_task_config)`** のみ（docs/header）。outer declared 内完全包含、`tx_gate` field / outer tail との overlap 0。
  - **Failure atomicity（Normative）:** `owner_config_stage` と `cell_config_stage_nested_owner` は **全 output を stack temp へ stage/validate** し、**成功時だけ** caller outs へ commit。`reserved_zero` / nested exact-size / containment など **stage 後 semantic reject** でも `out_*` / storage / caller bytes は **byte-exact 不変**。host test が production と同じ helper を直接呼び、poison→fail→memcmp で全 failure path を証明する。
  - **standalone owner config / owner_config_stage:** `owner_task_init` は **owner専用 pure** `ninlil_esp_idf_owner_config_stage` のみ使用（generic abi_stage 直呼びではない）。forward extension（`struct_size >= sizeof` known）可；host test と production が同 helper を共有して退行検出。target smoke も extended owner config を `owner_task_init` へ実渡し。
  - **owner_config_stage 入力契約:** `owner_storage==NULL && size!=0` および `owner_storage!=NULL && size==0` は **closed reject**（意味的矛盾）。両方 absent `(NULL,0)` のみ vacuous non-overlap として許可。`out_local` 必須、`out_hdr` は optional NULL。`out_local`/`out_hdr` 同士および `owner_storage` declared range との alias/overlap は **uintptr checked** `pointer_range_logic` で拒否（pointer relational ops 禁止）。success commit 順（local→hdr）で壊れ得る output 同士 alias も reject。
  - **Private symbol visibility（非公開 API）:** `owner_config_stage` は public installed header に出さない。portable `NINLIL_ESP_IDF_INTERNAL`（GCC/Clang `visibility("hidden")`）で **GLOBAL DEFAULT export を止める**。`cell_config_stage_nested_owner` は **static inline**（ELF に global symbol なし）。official smoke ELF は `xtensa-esp32s3-elf-readelf -Ws` で private helper の **GLOBAL DEFAULT = 0**（HIDDEN または local/absent）を gate。公開 API 化しない。
  - tail-only overlap / declared overflow は fail-closed。fixed-size 引数は full object nonoverlap。
  - 失敗は **`INVALID_ARGUMENT`**（ops shape は **POISON**）。output poison なし。state 不変。
- **Pointer non-overlap helper:** `pointer_range_logic` は **uintptr_t** のみ。pointer 同士の `< > <= >=` **禁止**。containment helper あり。
- **pointer-compare sanitizer:** 専用 `-fsanitize=address,pointer-compare` + `detect_invalid_pointer_pairs=2`。Linux CI 必須。通常 ASan だけでは代用しない。
- **Target smoke 直接 backend 証拠:** 2 lease / snapshot borrowers / shutdown BUSY / stale 後不変。host pure は direct と呼ばない。
- **Smoke lifecycle 証跡:** init 前 zero は可。**shutdown 後**の retired standalone owner を **全 memset しない**（lifecycle / retired state を保持）。
- **app_main stack frame gate:** official ESP-IDF workflow が `xtensa-esp32s3-elf-objdump -d` で `app_main` の `entry a1, N` を解析し、`CONFIG_ESP_MAIN_TASK_STACK_SIZE`（v5.5.3 既定 **3584**）と比較、安全 margin（≥1024 B free）を assert。tool 欠落時は **fail**（false-green 禁止）。観測 baseline: **496 B / 3584 B**。
- **Host 境界:** FreeRTOS backend 直呼び不可。trusted seam は pure registry + instrumented proof test。**HIL 未実施。**

## 6. Loopback

deny-by-default。`logical_bytes==0` DENIED。shutdown は live>0 で fail。  
**Permit forward extension 許可。** release identity は known semantic fields のみ exact（**`struct_size` 除外**）。extension tail は読まない。

## 7. HIL

```sh
# compile only (not HIL PASS):
DOCKER_HOST=unix:///Users/dt/.colima/default/docker.sock \
  docker run --rm -v "$PWD:/project" -w /project espressif/idf:v5.5.3 \
  bash -lc '. $IDF_PATH/export.sh && idf.py -C ports/esp-idf/smoke_app set-target esp32s3 build'

# device HIL:
idf.py -C ports/esp-idf/smoke_app -p PORT flash monitor
```

## 8. Acceptance

- [x] mux init before critical; no live memset  
- [x] suspended→sync delete reclaim (v5.5.3); no fixed delay  
- [x] FAILED_LIVE no core touch  
- [x] cell single mux; gate lease  
- [x] real ISR dispatch config  
- [x] inflight checked  
- [ ] device HIL run  
