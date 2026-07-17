# 23. USB control transport and physical radio boundary freeze

状態: **Normative for U0 / physical radio boundary freeze** + **U1 implementation candidate / host tests** + **U2 A2 ESP CDC implementation candidate / host pure tests + target compile/link** + **U3 C3 control-session + C4 pump implementation candidate / host fake-stream tests** + **U3↔U4 production-private boundary candidate**（logical epoch claim / tracked TX raw-outstanding≤1 / claim 中 RX-only cold）+ **U4 NCL1 pure codec candidate / host vectors**（**U1 complete ではない** — **Required HIL Linux+macOS pending**; **U2 complete ではない** — **Required HIL ESP flash + host CDC roundtrip pending**; **U3 は host framing/session candidate のみ**; **U4 は pure codec/wire slice と U3↔U4 境界のみで HELLO session state machine 未実装**; **USB series 未完成**; **SX1262 production code 未実装**; M3 incomplete / M5 incomplete）<br>
対象: Controller↔Cell Agent USB 境界、最小 logical control envelope、physical Compliance Permit 境界、実装 slice U1–U7 / R1–R10<br>
依存決定: [ADR-0003](adr/0003-radio-usb-dependency-direction.md)（Accepted）<br>
関連: [01](01-architecture.md), [03](03-identity-and-join.md), [05](05-security-and-compliance.md), [06](06-versioning-and-compatibility.md), [07](07-testing-and-quality.md), [09](09-roadmap.md), [15](15-glossary.md), [19](19-m3-control-byte-stream-framing.md), [21](21-m3-esp-idf-durable-storage.md), [22](22-m3-owner-cell-agent-skeleton.md)

## 1. 位置付けと非主張

本章は **USB 実装と SX1262 実装の前**に固定する **U0 boundary freeze** と **physical radio boundary freeze** の正本である。

**開発者向け読み順（U0）:** (1) 本章 §1 非主張と forbidden claims、(2) [ADR-0003](adr/0003-radio-usb-dependency-direction.md) の compile 図と runtime 図、(3) 本章 §4 ownership / §5 session+half-open / §7–§8 NCL1 matrix・validation・counters・liveness、(4) 本章 §9 physical Permit 境界、(5) 本章 §10 slice と Required HIL。実装 PR は該当 U/R 行と §13 gate だけを追加で辿ればよい。

| 層 | 本章で固定するか | 状態 |
| --- | --- | --- |
| 依存方向（compile/source と runtime call/data flow を分離; ADR-0003 + 本章） | する | Accepted / Normative |
| USB ownership・queue・reconnect・backpressure・raw CDC 非 custody・POSIX UX | する | Normative |
| NCG1 上の最小 logical control envelope と PING/PONG/RESET/HELLO | する（U1–U4 実装可能） | Normative private |
| private session object と payload ownership 経路（U3/U4 直結） | する（U3: NCG1 session+pump 実装 candidate; U3↔U4: logical epoch / tracked TX / RX-only cold 境界 candidate; U4: NCL1 pure codec candidate） | Normative private + **U3 implementation candidate** + **U3↔U4 boundary candidate** + **U4 pure codec candidate**（HELLO session state machine 未実装） |
| 完全な assignment / Transport Custody / security session protocol | **しない** | 後続 freeze |
| Network Attachment / Join、relay、multi-parent topology | **しない** | 後続 freeze（§14） |
| secure compact radio wire の production bytes / version | **しない**（version **unallocated**） | 後続 Normative（R6） |
| USB / SX1262 production 実装 | U0 時点は **しない**（docs freeze） | **U1 host candidate** + **U2 A2 ESP CDC candidate** + **U3 C3/C4 host candidate** + **U3↔U4 boundary candidate** + **U4 NCL1 pure codec candidate**（いずれも complete ではない; U1/U2 Required HIL pending; U4 HELLO session state machine 未実装）。**SX1262 未実装** |

次を **主張しない**（forbidden claims）:

- M3 complete / M4 complete / M5 complete / V1 / field-ready / production radio
- USB CDC driver・CDC task・POSIX serial adapter **完成 / U1 complete / USB series 完成**（U1 host candidate を complete と主張しない）
- assignment lease 適用・custody spool・Application Receipt 完了
- control channel の AEAD / session authenticity 完了
- SX1262 HAL・MAC・LBT・airtime ledger 実装済み
- secure radio wire version の割当
- **compile success = HIL PASS** / compile success must not equal HIL の否定
- KGuard schema / policy が portable Core に含まれること
- 本章の private protocol が public C ABI であること
- assignment/custody/security protocol is complete
- Network Attachment / Join / relay / multi-parent が U0 で確定したこと

## 2. 依存方向（compile と runtime を分離）

正本は [ADR-0003](adr/0003-radio-usb-dependency-direction.md)。本章は実装レビュー用の再掲であり、**図と構成要素 ID（C0–D1）は ADR と完全一致**させる。

### 2.1 構成要素（ADR と同一集合）

| ID | 構成要素 |
| --- | --- |
| C0 | Portable logical Runtime (Core) |
| C1 | Portable byte-stream contract（abstract; 非 public） |
| C2 | NCG1 framing codec |
| C3 | NCL1 codec / control session（payload ownership あり） |
| C4 | Composition / pump（private glue） |
| A1 | POSIX controller transport adapter |
| A2 | ESP USB CDC adapter |
| L1 | Cell Agent local composition layer（[01章](01-architecture.md) の Application/Control/Data/Management の **4 planes ではない**） |
| P1 | Physical Compliance Gate / Permit |
| W1 | Secure compact radio wire / MAC codec |
| H1 | ninlil_radio_hal（sole transmit-with-permit） |
| D1 | SX1262 HAL / backend |
| K1 | KGuard integration |

### 2.2 Compile / source dependency（include/link のみ）

```text
K1 --> C0 (public API only)

C0 --> C1 abstract only
C0 -X-> A1, A2, D1, K1 schema, termios, TinyUSB, SX1262

C3 --> C2
C3 -X-> A1, A2, K1

C4 --> C1, C2, C3, A1|A2, L1
C4 -X-> K1 as Core types; -X-> D1 for USB series

A1 --> C1 + POSIX termios/poll
A2 --> C1 + esp_tinyusb
A1/A2 -X-> C0 reducers, P1 impl, D1, K1

L1 --> C4 outputs, P1 (radio path)
P1 -X-> A1, A2, K1
W1 -X-> C0 memcpy path
H1 --> P1 + D1
H1 -X-> C0, C3, A1, A2, K1
D1 -X-> C0, C3, USB, K1
```

**逆方向の compile-time / link-time / source include 依存は禁止。**

### 2.3 Runtime call / data flow（実行時のみ; include 図ではない）

**USB control:**

```text
C0/product -> C4 pump -> C3 session -> C2 NCG1 -> C1 -> A1/A2
                (bytes on wire)
A1/A2 -> C1 -> C2 -> C3 (owns payload) -> C4 -> L1 / upper private
```

**Physical RF TX（順序固定; sole edge）:**

```text
W1 immutable TX plan/bytes
  -> P1 inspect SiteAssignment/profile/ledger/live + reserve + issue Permit(exact plan)
    -> H1 transmit-with-permit (re-validate + single-use consume)
      -> D1 SX1262
```

要点:

1. **Physical Compliance Permit が physical RF TX の唯一の認可エッジ**（sole physical TX edge）。
2. Permit 発行後の bytes/PHY 変更は不可能。変更するなら新 plan → 新 permit。
3. Foundation logical TxPermit は physical RF を認可しない。
4. K1 は integration のみ。portable Core / private control 必須語彙にしない。

## 3. USB transport 選定（初期 freeze）

### 3.1 Cell Agent（ESP32-S3）

| 項目 | 規範 |
| --- | --- |
| SoC | **ESP32-S3**（既存 M3 pin と一致） |
| USB 役割 | **USB OTG Device** |
| クラス | **CDC-ACM**（control byte stream 用） |
| 実装 path | **`esp_tinyusb`**（ESP-IDF 公式 managed component）。**U0 は path 選定のみ**（exact version を U0 で固定しない）。**U2 実装で exact version と lock を固定**（下段） |
| ESP-IDF pin | **`ports/esp-idf/ESP_IDF_VERSION` = exact **v5.5.3****（U0 から継続） |
| `esp_tinyusb` exact pin（**U2**） | **`==2.1.1`**（Apache-2.0; IDF >=5.0）。`ports/esp-idf/components/ninlil/idf_component.yml` + **committed** `dependencies.lock` for each official ESP app project（`smoke_app` / `hil_app`）。**Never commit `managed_components/` or build trees**。Gate: manifest+lock の exact pin drift 禁止 |
| 代替 stack | 本 freeze では採用しない。変更は新 ADR |

規則:

1. portable Core および private NCG1/NCL1 codec は TinyUSB / ESP-IDF header を include しない。
2. USB adapter（A2）は `ports/esp-idf/` に閉じ、C1 経由で byte stream の open/read/write/close・backpressure・link 状態だけを上位へ出す。
3. CDC の raw ring は **non-custody**（§6）。durable spool と混線しない。
4. Control CDC は **唯一**の control plane byte stream。**printf / ESP_LOG / unstructured log を Control CDC へ出さない**。console は **distinct UART path**（`esp_tusb_init_console` 禁止 on control path）。
5. A2 は **fake `/dev` path を発明しない**。C1 open は adapter-neutral **endpoint token**（§3.4）。

#### 3.1.1 A2 physical link / DTR / mount（U2 Normative）

| 項目 | 規範 |
| --- | --- |
| USB 役割 | ESP32-S3 **USB OTG Device**、CDC-ACM **1** dedicated control interface |
| open | endpoint_token = empty/default または exact **`control-cdc`**。成功 → **`LINK_LISTENING`**（stack install）。**generation は進めない** |
| physical UP | **USB attached/configured AND DTR asserted**（host open）。→ **`LINK_UP`** + **`link_generation++`** + rings clear（stale bytes 横断禁止） |
| physical DOWN | **detach OR DTR deassert**。→ **`LINK_DOWN`**（generation sticky）。residual RX は drain 可; TX ring clear |
| host reconnect | adapter が open のまま DOWN→UP 可（**close 不要**）。新 generation + rings clear。A1 の「DOWN 後は explicit close 必須」とは異なる（§3.4） |
| close (V1) | **logical park only（esp_tinyusb 2.1.1）:** **s_mux 下で admit fence + `s_live` unpublish を先** → core inflight drain → **s_io 下** software FIFO best-effort clear → FREE。**`tinyusb_cdcacm_deinit` / `tinyusb_driver_uninstall` は V1 close で呼ばない**（upstream `get_acm` pre-dispatch + free の UAF を避ける）。成功 → CLOSED + storage reusable; USB service は READY のまま reopen/bind 可。失敗 → TEARDOWN_PENDING/POISONED + same-owner retry |
| open / rebind publish | core open + service ensure（install/cdc_init）中は **`s_live` を publish しない**。service READY 後 **flush-before-publish**: **s_io 取得 → old RX flush + TX clear（software FIFO only; non-recallable）→ s_mux 下で最終 validation して `s_live=self` atomic publish → release**。**`s_live` は READY+BOUND+flush 済み成功 bind のみ**（POISONED/open fail/close fail で re-publish 禁止; storage 保護は `live_storage`/`reserved_id`）。reconcile は seq protocol; **`physical_event_seq==UINT64_MAX` は reconcile fail-closed skip** |
| USB I/O mutex | firmware-lifetime **dedicated FreeRTOS mutex `s_io`**（lifecycle mutex と別; once-safe static create）。**全 TinyUSB software FIFO 操作を直列化**: CDC RX read/drain、TX queue/flush、device/line DOWN soft clear/flush、close park soft clear/flush。**s_mux を保持したまま s_io 待ち / driver FIFO API を禁止**（depth 0 で I/O）。`driver_install` / `cdc_init` / `tud_mounted` snapshot は s_io 外（callback が s_io を取る deadlock 回避） |
| USB service | **firmware lifetime persistent** once READY（ABSENT→STARTING→READY｜POISONED）。Control CDC sole-owner; 他 USB 用途への stack 譲渡は非対象。full runtime USB shutdown は V1 非対応。exact pin **`esp_tinyusb==2.1.1`**（`task_start` が event_cb 設定より前; ACM deinit は free） |
| unbound physical tracking | logical bind が無い期間も ATTACH/DETACH/DTR は **`physical_event_seq` を s_mux 下で必ず bump**。bind 後 reconcile は **seq capture → unlock → tud_mounted/connected snapshot → relock → seq 一致時のみ apply**（stale snapshot 非勝）。device event arg は NULL（s_live のみ） |
| unbound RX drop | persistent CDC では unbound（または admit fenced）中も TinyUSB RX software FIFO を **s_io 下 bounded read/drain/drop** し、次 generation の Ninlil ring に残さない。**RX callback は s_io を先に取得**してから s_mux で admit 判定（pre-dispatch も bind protocol と直列化）。bind 中は epoch/inflight fence 維持 |
| init / reinit | storage / out_stream の **half-open range overlap**（overflow-safe）を live/reserved と照合。overlap は memset 前に **BUSY**。raw magic 非読取。成功 park 後 same storage reinit + READY service へ rebind 可 |
| rings | fixed **4096** RX + **4096** TX。allocation-free。callback は raw bytes copy + bounded flags のみ |
| callback fence | **s_io first** → s_mux 下 **try_enter（epoch capture）+ inflight++** → s_mux 外・s_io 下で driver read → s_mux で epoch 一致時のみ ring 更新 → leave → s_io unlock。stale capture は除外。**s_mux を driver FIFO API / vTaskDelay / s_io wait に渡さない** |
| TX drain race | peek 時に **link_generation + callback_epoch** を ticket 化 → **s_io 下** `write_queue`/flush → re-lock 後、**同一 gen/epoch かつ still UP** のときだけ ring consume。mismatch 時は ring を触らず `tx_driver_stale_accepted` 計上（driver 受理済み bytes は非回収） |
| callback context | esp_tinyusb **2.1.1** CDC/device callbacks は **TinyUSB service task 文脈**（hard-ISR ではない）。ISR-safe ingress seam は本 backend では不要・未主張 |
| ownership | successful open が owner FreeRTOS task を確立。WRONG_OWNER は **out_accepted/out_length/out_events 変異前**。observers: wrong-owner は CLOSED/0 sentinel または out buffer **無変異**。install/teardown 失敗は **core last_error に sticky 永続**（caller out_error のみではない） |
| global reservation / logical bind | **logical bind:** FREE → CLAIMING → BOUND → PARKING → FREE｜**POISONED**（同一 owner close 再試行）。**USB service** は ABSENT→STARTING→**READY**（firmware lifetime）｜POISONED と独立。V1 成功 park は **logical unbind のみ**（`cdc_deinit`/`driver_uninstall` 非呼出）。第 2 bind は prior park success または fail-closed POISONED まで拒否。publish 検証失敗は **fence→PARKING→POISONED + live_storage/reserved_id 保持**（clear-only で BOUND/LIVE 放置禁止） |
| poll events | LINK_UP / LINK_DOWN / RX_OVERFLOW は **one-shot latch**（poll 観測で clear; 永久 hot loop 禁止）。**WRITABLE は LINK_UP のみ**。timeout は **call-entry tick を baseline とする absolute deadline**（初回 nonblocking pump 時間を含む; C1: ready work は最低1回 pump 可）。budget = **ceil(timeout_ms × configTICK_RATE_HZ / 1000)**（任意 HZ; `portTICK_PERIOD_MS` 割算禁止）。**delay 後は追加 TX drain/I/O の前に elapsed 再判定**（1 tick timeout で期限後 2 回目 I/O 禁止）。人工 640ms cap / busy-spin なし |
| reconnect residual | generation UP 時に未 drain residual RX を clear するなら **`generation_rx_discard_bytes` に計上**（silent discard 禁止） |
| TinyUSB software FIFO | `tud_cdc_n_write_clear` / `tud_cdc_n_read_flush` は **software stream FIFO のみ**。USB endpoint / hardware-in-flight / **既に wire 上に出た bytes は回収不能**。U2 が保証するのは **Ninlil 所有 ring の generation 隔離** + DOWN 時 best-effort soft clear。driver 受理済みは non-custody。**U3 framing/session generation が stale frame を end-to-end 拒否する MUST** |
| TinyUSB service task | driver stack の service task であり **C1 ownership pump ではない** |
| nonclaim | write accept ≠ custody/receipt。RX overflow ≠ physical link down。**compile ≠ HIL**。raw USB は物理送信済み bytes を recall できない。U2 Required HIL pending |

### 3.2 Site Controller（host 初期 backend）— POSIX UX 規範

| 項目 | 規範 |
| --- | --- |
| OS | **Linux** および **macOS** を初期対象 |
| デバイス指定 | **explicit device path** のみ。自動 picker UI は非対象 |
| I/O | **raw POSIX `termios` + `poll`**（canonical/echo/ICRNL 等を無効化; blocking unbounded read 禁止） |
| Windows | 未固定（後続 slice） |

#### 3.2.1 デバイス識別と path 選択

| 項目 | 規範 |
| --- | --- |
| Linux path | 典型 `/dev/ttyACM*` または udev が作る stable symlink。仕様上は **呼び出し元が渡す absolute path 1 本** |
| macOS path | **`/dev/cu.*` を選択**（`/dev/tty.*` は open 時に DCD 待ちしうるため Controller 既定にしない）。例: `/dev/cu.usbmodem*` |
| VID/PID | 接続診断・運用ドキュメント用。open 契約の必須引数ではないが、U1 は **失敗時診断** に「期待 VID/PID / serial が platform から取れるなら表示」を含める |
| serial / USB iSerial | 複数同種デバイス時の運用識別子。path 解決は Controllers の責任 |
| Linux udev / permission | open が `EACCES` のとき、実装は **permission / udev membership の診断ヒント**を structured error に含めてよい（例: dialout グループ）。仕様は root 必須としない |
| macOS 診断 | path 不在・busy・I/O error を区別。`cu.*` を使っていることを log に明示 |

#### 3.2.2 open / termios / lifecycle

| 項目 | 規範 |
| --- | --- |
| open flags | Linux/macOS: **`O_RDWR \| O_NOCTTY \| O_NONBLOCK \| O_CLOEXEC`**（platform が `O_CLOEXEC` を定義するとき atomic close-on-exec）。controlling tty にしない。`O_CLOEXEC` が compile 時に無い環境のみ open 後 `fcntl(F_SETFD, FD_CLOEXEC)` fallback; 失敗は fd を fence し structured open error（黙って継続禁止）。host CTest は modern 上でも FORCE macro の private twin library で fallback を compile/cover する（production/install 非適用） |
| exclusive open | Linux は可能なら `flock` または `TIOCEXCL` 相当で **同一 path の二重 open を拒否**。失敗は structured `BUSY`。macOS も非共有 open を目指す |
| termios raw | 入力/出力ともに raw: `ICANON`/`ECHO`/`ISIG` off、**`OPOST` off**、software flow 既定 off、8N1。固定 baud は CDC-ACM では host 側の論理値（実 CDC は USB bulk; 互換のため 115200 8N1 raw を default profile とする） |
| DTR / RTS | open 成功後に **DTR assert** を default とする（多くの USB-CDC が DTR で device 側「host present」を見る）。製品が DTR 不要でも assert は害が少ない |
| HUP / hangup | `CLOCAL` を用い、carrier drop を **即 fatal としない**実装を default とする。代わりに **read/write/poll の error と 0-byte 連続**で unplug を検出 |
| owner / concurrency | **successful open がその `link_generation` の owner process/thread を確立**する。open 後は **observer を含む全 stream API**（open/close/read/write/poll および **link / generation / stats / last_error**）が **同一 owner 専用・同時 call 禁止**。内部 lock / multi-reader atomic snapshot は持たない（cross-thread は data race / UB）。open/close/read/write/poll は adapter が `WRONG_OWNER` を返してよい（**owned stream 状態は書かない**; caller-owned `out_error` のみ）。link/generation/stats/last_error は signature 上 status を返さない observer でも **cross-thread 監視 API ではない** — 上位が owner thread で snapshot して handoff する。**明示 close（`LINK_CLOSED`）後の新しい successful open は same/different thread で新 owner を確立可能** |
| fd lifecycle | open → configure termios → poll loop → **close は owner thread のみ**。fork 後の fd 共有禁止（かつ **O_CLOEXEC** で exec 継承を避ける）。close 後の use-after-close は adapter が generation で fence |
| unplug errno | `EIO` / `ENODEV` / `ENXIO`（および poll 経路での同等）/ 0-length read after POLLHUP を **link down** に写像。session を INVALID（§5） |
| reconnect | **open は `LINK_CLOSED` かつ fd fenced からのみ**。`LINK_DOWN` は同一 owner でも open 不可（`INVALID_STATE`; 先に explicit close で residual RX を確定）。close 後の同一 path 再 open は新規 link/generation。**自動 HELLO 再交渉は session 層**（U4）。adapter は link up イベントのみ |

規則:

1. Controller transport は **1 明示 path = 1 logical link candidate**。複数 path の自動フェイルオーバは本 freeze 外。
2. path 文字列・fd・termios 状態を portable Core の public 型に載せない。
3. host 実装は `ports/posix/`（または同等 host port）に置き、KGuard host 専用ディレクトリへ埋め込まない。

### 3.3 Logging / control チャネル分離

| チャネル | 用途 | 規則 |
| --- | --- | --- |
| **Control CDC** | NCG1 frames（logical control / 将来 assignment） | 唯一の control plane byte stream。人間向け log を混在させない |
| **Log / diagnostics** | 人間向け trace、crash dump、support | **別 path**（UART console、別 USB interface、host stderr 等）。Control CDC へ unstructured text を流さない |
| **Management bulk** | 将来 firmware / large asset | Control の interactive capacity を食い潰さない（[01章](01-architecture.md) Management Plane）。本 freeze では未実装 |

MUST NOT:

- `printf` / ESP_LOG を Control CDC の raw stream に直接出して framing を壊す。
- log 行を NCG1 frame と誤認して parser に feed する（adapter 境界で分離）。

### 3.4 C1 portable open / link lifecycle（private; U1+U2 共通）

C1（`src/transport/byte_stream.h`）は **platform-type-free** の private contract。POSIX 固有の「absolute path 即 UP」だけでは A2 の非同期 attach を偽同期 open で隠せないため、**最小の private 一般化**を U2 と同一 slice で固定する（public ABI 変更なし）。

| 項目 | 規範 |
| --- | --- |
| open 引数 | **`endpoint_token`**（adapter-neutral opaque UTF-8）。filesystem path であることの portable 主張ではない |
| A1 token | **absolute device path** 必須（§3.2）。成功 open = 即 physical UP + generation++（同期） |
| A2 token | empty/default または **`control-cdc`**。**fake `/dev/...` 禁止**。成功 open = **LISTENING**（generation 不変） |
| `LINK_LISTENING` | open 受理・物理 link 未確立。A1 成功 path では使わない |
| generation | **physical link-up 遷移でのみ**進む。open 単独（A2 LISTENING）では進めない。close/down では進めない |
| A1 reopen | open は **`LINK_CLOSED` のみ**。`LINK_DOWN` は explicit close 必須（residual RX を silent drop しない） |
| A2 reconnect | open 維持のまま host 再 attach+DTR で DOWN→UP 可（新 generation）。re-open API ではない |
| owner | successful open が owner を確立（LISTENING 含む）。observers 含む全 stream API は single-owner |
| error.path[] | diagnostic endpoint token スロット（A1 path / A2 id）。portable filesystem 保証ではない |

状態機械（C1 portable）:

```text
CLOSED
  -- open(endpoint) OK --> A1: UP (gen++) | A2: LISTENING (gen unchanged)
  -- open fail --> CLOSED

LISTENING          (A2 primary)
  -- physical UP (attach+DTR) --> UP (gen++, rings clear)
  -- close --> CLOSED
  -- write --> WOULD_BLOCK (accepted=0)
  -- read  --> OK + 0 bytes when empty

UP
  -- physical loss --> DOWN (gen sticky; TX clear; residual RX drainable)
  -- RX overflow --> stay UP + latch continuity event (not link down)
  -- close --> CLOSED

DOWN
  -- A1: open forbidden until close
  -- A2: host physical UP --> UP (gen++; residual RX discarded with
         generation_rx_discard_bytes accounting; not silent)
  -- close --> CLOSED on logical park success
         (A2 V1: no stack deinit/uninstall; service stays READY)
         or TEARDOWN_PENDING/POISONED on park failure
  -- read residual RX then ERR_LINK_DOWN when empty

TEARDOWN_PENDING  (A2 internal lifecycle; not a successful CLOSED)
  -- open --> INVALID_STATE (no reopen / no rebind until park success)
  -- close (same owner) --> retry **logical park** only
         (fence if needed → inflight drain → s_io soft FIFO clear →
          unbind / FREE; never cdc_deinit / driver_uninstall)
  -- success --> CLOSED (logical owner released; storage reusable;
         USB service remains READY for a later open/bind)
  -- failure --> stay TEARDOWN_PENDING or escalate bind/service POISONED
         (first error sticky; s_live stays unpublished)
```


## 4. Ownership・session object・bounded queues

### 4.1 現行 owner 境界の限界（U3/U4 直結不能の明示）

**現状（M3 まで）および U0 時点の危険な省略:** USB/raw CDC や owner mailbox が **payload summary**（長さ・type ヒント・external pointer だけ）しか持たない設計のままでは、U3（NCG1 stream）/ U4（NCL1 session）へ **所有権の切れ目なく直結できない**。summary-only は次を満たせない:

- frame 途中の bytes を誰が所有するか
- decode 後 body の lifetime
- session fence 時の一括破棄
- backpressure 時に「summary だけ残って body が消える」不整合

したがって U3/U4 は **明示的な private session object + payload ownership 経路**（§4.2–4.3）を実装必須とする。これは portable Core 公開 API でも KGuard 語彙でもない。

### 4.2 所有境界

| 資源 | Owner | 非 Owner |
| --- | --- | --- |
| USB device / CDC interface / fd | A2 task（Cell）または A1 thread（Controller） | C0、application、K1 |
| raw CDC RX/TX rings | A1/A2 のみ | C3、C0 |
| NCG1 parser / encoder state | **C3 control session object**（private） | raw CDC ISR、application |
| NCL1 decode buffer / logical payload bytes | **C3 が所有**し、C4 handoff で L1 または private gateway へ **所有権移転**または **copy-out + C3 保持終了** | raw ring、C0 public handle |
| Logical control session_generation / session_cookie / inflight table | C3 session object | termios、TinyUSB driver |
| Owner task mailbox（docs/22） | L1 / owner task | USB raw ring を直接持たない |
| Transport Custody spool | L1（後続 slice） | raw CDC ring |
| Physical Compliance Permit registry | P1（R-series） | USB path、C0 reducer |
| SX1262 registers / SPI | H1/D1 | USB adapter、C3 |

### 4.3 Private control session object と handoff（U3/U4 必須経路）

```text
A1/A2 raw RX ring
  --C4 pump reads bytes--> C3 session
       C3: NCG1 parse window (owned)
       C3: NCL1 header+body buffer (owned until handoff)
       C3: session state machine + inflight map
  --C4 handoff--> L1 owner mailbox / private gateway
       handoff modes (実装はどちらかを選択し API で固定):
         (a) move: 所有権を受信側へ移転し C3 は参照を捨てる
         (b) copy-out: 受信側が即 copy、C3 は accept 完了で free
       summary-only ポインタの外部 lifetime 依存は禁止
```

規則:

1. C3 / C4 / A1 / A2 の型は **`include/ninlil/*` に出さない**（production-private）。
2. KGuard message enum / policy ID を C3 必須フィールドにしない。
3. C0 public Runtime は「USB から来た raw payload pointer」を直接受け取らない。将来 public 化するなら別 ADR + ownership 契約。
4. FreeRTOS owner mailbox（[22章](22-m3-owner-cell-agent-skeleton.md)）へ渡す場合も、**owned buffer または即時 copy** を使い、USB ring 上の bytes を mailbox が指さない。

#### 4.3.1 U3↔U4 production-private boundary（logical epoch / tracked TX / RX-only cold）

**実装候補（host fake-stream 検証）:** `src/transport/control_session.*` が U4 の HELLO session engine より前に必要な **production-private** 境界だけを提供する。**NCL1 pure codec は別 slice で実装候補済み**だが、**HELLO state machine / session lifecycle / logical_control / U4 complete は未実装**であり、本節はそれらを完成主張しない。

| 機構 | 規範（C3 private） |
| --- | --- |
| **logical epoch claim** | 非ゼロ単調 `epoch_id` + bind 時 stream generation。`begin`/`end` 成功条件: `STATE_BOUND`（begin）、dirty TX=0（begin）、**tracked 全解決**（`tracked_token==0` かつ phase NONE — pending も **未 consume terminal も** resolve 必須）。成功 begin 時 **RX parser cumulative commit+reset + ingress discard のみ**（TX/BOUND/gen 維持）。claim 中は legacy `submit_tx` 拒否、`tracked_submit_tx` / `take_rx` / `pump` 可。epoch wrap → `EPOCH_EXHAUSTED` fail-closed。stale epoch は **zero mutation** reject。link/gen full fence で claim 無効化 |
| **tracked TX（raw outstanding max 1）** | `tracked_submit_tx` が **object lifetime 非再利用**の非ゼロ token を発行し intent→tx_wire まで保持。token wrap → 専用 `TOKEN_EXHAUSTED` fail-closed（`TX_BUSY` と区別; host test seam で直接試験可）。`tx_resolve` が sole authority（stats delta 推測禁止）。exact resolution: `PENDING_UNACCEPTED` / `RAW_ACCEPTED_CURRENT_EPOCH` / `CANCELLED_UNACCEPTED` / `FENCED_UNACCEPTED` / `RAW_ACCEPTED_THEN_FENCED` / `INDETERMINATE_PARTIAL`。terminal は resolve まで保持。cancel は C1 未 accept の intent/wire のみ atomic 削除（後から writable でも旧 frame を送らない）。accepted 済は取消不可 |
| **raw accept linearization** | WB `accepted==0` → pending・full-frame 保持・cancel 可。full OK（`accepted == requested`）+ post-I/O ticket 一致 → `RAW_ACCEPTED_CURRENT_EPOCH`。full OK + post ticket/link mismatch → accept 事実を queue clear **前**に保存し `RAW_ACCEPTED_THEN_FENCED` + epoch invalid。preaccept down/error `accepted==0` → `FENCED_UNACCEPTED`。**`accepted>0` かつ exact full OK でない全て**（partial OK / **OK で `accepted > requested`** / WB `accepted>0` / **non-OK・CLOSED・LINK_DOWN・IO_ERROR で `accepted>0`**）→ 必ず `INDETERMINATE_PARTIAL` + fence/reopen 必須（`FENCED_UNACCEPTED` と偽らない） |
| **RX-only cold（claim 中）** | parser + ingress のみ。STATE_BOUND / stream / gen / TX intent / tx_wire / token terminal **完全維持**。claim 中の C1 `RX_OVERFLOW`（poll または **read()**）/ fatal parser continuity も内部同処理で BOUND 継続 + structured status。counter: claim RX-cold は **`logical_rx_colds` のみ**加算し **`rx_overflow_fences` は加算しない**（`handle_rx_overflow` の full fence 経路だけが `rx_overflow_fences++`）。**`logical_rx_cold` reason は tagged closed domain**（`0x52430001..` = ASCII `RC` + ordinal; status 小整数 0.. と **disjoint**）。`WOULD_BLOCK(1)` 等の status を reason に誤渡しすると **INVALID_ARGUMENT + zero mutation**（EXPLICIT として受理しない）。sticky `last_error.status` は catalog 導出のみ。**legacy 非 claim の overflow は従来どおり full fence**（§4.5） + `rx_overflow_fences++` |

**非主張:** 本境界の host green は U4 complete・Required HIL・USB series 完成・custody/Application Receipt を意味しない。

### 4.4 Bounded queue 規範（profile default; 測定前の不変規範ではない）

すべて **entry 上限と byte 上限の両方** を持つ。silent drop 禁止（[01章](01-architecture.md) Bounded resource invariant）。

**容量値の位置付け:** 下表は U-series 開始用の **bounded profile / default** である。物理法則でも最終製品 SLO でもない。**U1（host）/ U2（device）で測定し、同一 PR で default と test を更新**して確定する。docs-only U0 は default を固定するが「実機最適値確定」を主張しない。

| Queue | Default entry 上限 | Default byte 上限 | Overflow 動作 |
| --- | ---: | ---: | --- |
| CDC RX raw ring（A1/A2） | n/a（byte ring） | **4096 bytes** | §4.5 |
| CDC TX raw ring | n/a | **4096 bytes** | 送信 API `WOULD_BLOCK`。Application Receipt を出さない |
| NCG1 reassembly / parser window（C3） | 1 in-progress frame | **1050 bytes**（[19章](19-m3-control-byte-stream-framing.md) `MAX_FRAME_BYTES`） | framing 規則。heap 禁止 |
| Logical control ingress（decode 後 message; C3→C4） | **16 entries** | **合計 ≤ 8192 bytes** | 新規 accept 拒否 + structured counter。世代 fence で一括破棄 |
| Host→device write intent queue（Controller TX intent; device 向け outbound） | **16 entries** | **合計 ≤ 8192 bytes** | caller へ `WOULD_BLOCK` |
| Cell continuity-loss RESET notice slot（C3 private） | **exact 1 reserved entry** | **exact 30 NCL1 bytes**（26 header + 4 body） | 通常 TX queue と別の固定 slot。2 件目を積まず merge/drop + counter。raw TX が `WOULD_BLOCK` でも local fence は維持。pending lifecycle §5.6.1: fence once / cancel-on-HELLO（`continuity_reset_notice_cancelled`）/ FIFO / sequence consume |
| Session inflight request map | **8 entries** | n/a（ID 表） | 新規 request 拒否 `ERR_CAPACITY` |

規則:

1. queue 上限変更は本章と golden/backpressure test を同一 PR で更新する。
2. ISR / TinyUSB callback は raw ring へだけ copy し、logical decode・allocation・Core 呼び出しをしない。
3. FreeRTOS owner task mailbox と USB raw ring は別資源。相互に unbounded 待機しない。

### 4.5 USB RX overflow / backpressure（exact contract）

前提: NCG1/NCL1 は **reliable ordered byte stream** 上の framing である。**frame 途中の bytes を黙って捨てて parser を続行してはならない。**

**採用契約（Normative）: overflow 時は consume 継続による暗黙欠落を禁止し、parser/session を fence/reset する。**

| 状況 | 必須動作 |
| --- | --- |
| RX ring に空きが無く、driver/ISR が追加 bytes を保持できない | (1) structured counter `rx_overflow++` (2) **NCG1 parser を cold 相当へ reset**（window discard） (3) **control session を INVALID**（§5; generation fence; **物理 Link down ではない** — §5.2 規則1(b)） (4) **local RX-only sequence epoch cold**（§5.5.2; **local TX `next_tx_seq` は継続**） (5) **SESSION_ACTIVE 検出時**は §5.6.1 **Cell continuity-loss 通知順序**（pre-fence snapshot → atomic fence + 高優先 `RESET_SESSION` notice 最大 1）; 補助として `RESET_PARSER` / `RESET_LINK` 可 (6) 上位へ **session/parser error**（「Link down」と報告しない） (7) **有限回復**は §5.6.1（Controller 検出なら即 `next_tx_seq` HELLO、Cell 検出なら RESET_SESSION 通知 + peer HELLO の **SBR-HELLO**）。**overflow 後に回復 path を無効化してよい実装は禁止**。通知 `WOULD_BLOCK`/喪失でも **local fence は戻さない** |
| RX ring high-watermark（default: 3/4 full） | C4 は drain を優先。新規 logical accept を抑制してよい。まだ欠落していなければ session は維持可 |
| TX ring full | `WOULD_BLOCK`。busy-spin で Core を止めない |
| logical ingress full | 新規 NCL1 accept 拒否。**既に ring から読んだ bytes は C3 が所有**し、reject 後も parser 位置は framing 規則に従う（byte を「無かったこと」にしない） |

**採用理由:** CDC で hardware が常に信頼できる per-byte クレジットを提供するとは限らない。欠落を許して resync「だけ」に頼ると、ordered stream 前提の session 層（request_id / generation）が silent desync する。欠落 = session 破壊として fail-closed する方が U-series の単純堅牢性に合う。

**代替（非採用）:** 「driver bytes を消費しない（応用 flow control のみ）」— TinyUSB/host 経路で常に成立させる契約を U0 では置けないため採用しない。将来 hardware FC が保証される backend では別 ADR で緩和しうる。

## 5. Reconnect / session_generation / fencing

### 5.1 用語

| 用語 | 意味 |
| --- | --- |
| **Link up** | OS / USB stack が byte stream を open 可能と報告 |
| **Framing sync** | NCG1 parser が valid frame を少なくとも 1 つ受理可能な状態 |
| **Control session** | HELLO 交渉完了後の Controller–Cell logical session |
| **session_generation** | control session の単調世代（§5.2）。reconnect ごとに進む |
| **session_cookie** | HELLO_OK 時に Cell が **CSPRNG / approved random** で選ぶ **opaque nonzero u64**（wall clock ではない）。**NCL1 header** に載せ、HELLO_OK および全 active message で wire 検証する（§5.2 / §7.2）。プロセス再起動後の generation 再利用に対する stale-frame fence |
| **request_id** | 1 request–response 相関用 u32（§5.5） |
| **NCG1 sequence** | docs/19 NCG1 header offset 12 の u32。USB U4 control path の exact ポリシーは §5.5（docs/19 の「上位」） |
| **boot_nonce** | プロセス（または device firmware image 実行）起動時に一端が保持する opaque 値。wire 必須ではないが generation 初期化に使う |

### 5.2 session_generation 規則（authority / wrap / restart）

| 項目 | 規範 |
| --- | --- |
| 型 | wire 上 **u32 big-endian** |
| **割当 authority** | **Cell Agent（HELLO responder）のみ**。Controller は HELLO で 0 を送り、HELLO_ACK の値を採用する |
| 初期（process start） | local 変数 0 = 未確立。wire で active メッセージに 0 を載せない |
| 発行 | `HELLO_OK` の `HELLO_ACK` を送る直前に Cell が `last_issued_gen+1` を割り当て。同時に **session_cookie（u64）** を §5.2.1 で新規生成し **NCL1 header** に載せる（body に cookie を重複させない） |
| 永続性 | U4 範囲では **durable 永続を必須としない**。再起動後は必ず再 HELLO。`session_cookie` が変われば旧 peer 状態は無効 |
| 再利用防止 | 同一 process 寿命内で generation を再利用しない。wrap 前 fail-closed。再起動後 generation が偶然再利用されても **cookie が全 active NCL1 で wire 不一致** のため stale frame を拒否できる（HELLO_ACK body のみに cookie を置く設計は禁止） |
| wrap | `last_issued_gen == UINT32_MAX` のとき新規 HELLO_OK を出さず `HELLO_DENIED` または `HELLO_BUSY` + process restart 要求。**黙って 1 へ戻さない** |
| ACTIVE 遷移点 | **双方**が「自状態を `SESSION_ACTIVE` にし、peer の `session_generation` と `session_cookie` を記憶した時点」。Controller は valid `HELLO_ACK`（`HELLO_OK`）受理時。Cell は自 `HELLO_ACK`（OK）の **送信 API が accept した時点**（TX ring 満杯で送れていないならまだ ACTIVE にしない） |
| error ACK の generation / cookie | `HELLO_ACK` で `result_code != HELLO_OK` のとき **`session_generation` と `session_cookie` の wire 値はともに 0**（確立しない）。`CTRL_ERROR` は §8.7 |

#### 5.2.1 session_cookie 生成（CSPRNG 必須 / fail-closed）

| 項目 | 規範 |
| --- | --- |
| 型 / wire 位置 | **u64 BE**。**NCL1 header offset 16**（§7.2）。HELLO_ACK body には載せない（header が authority） |
| 生成 authority | **Cell Agent のみ**（HELLO_OK 発行時） |
| 乱数源 | Cell **platform CSPRNG** または **platform 承認済み cryptographic random source**（例: ESP-IDF 上で port が ready と宣言した entropy/random API）。**「entropy または単調カウンタ混合」は禁止** |
| durable counter | **U4 では代替として認めない**。durable 単調カウンタを cookie に使うには独立した耐久契約 + 別 ADR が必要 |
| nonzero | 採用値は **必ず ≠ 0**。0 は HELLO / error ACK / 未確立 CTRL_ERROR 専用（§7.4） |
| 取得不能 | CSPRNG/approved source が **unavailable・not-ready・port error**、または 0 しか得られない（最大 8 回 redraw 後も 0）とき **`HELLO_OK` を出してはならない**（fail-closed）。`HELLO_BUSY` または `HELLO_DENIED`（generation=0, cookie=0）を返してよい |
| wall clock | cookie に unix time / host clock を用いない |
| active 一致 | `SESSION_ACTIVE` 後の全 active NCL1 message は header cookie が **active session_cookie と bit-exact 一致**。不一致 → reject + `ERR_SESSION_MISMATCH` 可（stats）。state を推測更新しない |

規則（番号付き）:

1. **session を INVALID にする事象**は次の **2 種**に分離する（**RX overflow / parser fence / RESET 受理を「Link down」と呼ばない**）:
   - **(a) 物理 Link down:** unplug、open 失敗、fatal stream error、観測した link close/reopen 準備。local 端は session を **INVALID** にし、§5.5.2 どおり **自側 TX+RX 双方 sequence cold**（reopen 後）。
   - **(b) session-breaking events（物理 link は up のまま）:** RX overflow fence（§4.5）、通常 sequence gap/後退、fatal framing desync、`RESET_SESSION` / `RESET_PARSER` 受理（および §8.3 `RESET_LINK` の **session 即 INVALID**）。session を **INVALID** にするが、**物理 link を down とみなさない**。sequence は trigger 別（§5.5.2: 多くは **RX-only cold + local TX 継続**、`RESET_SESSION` は双方 sequence 継続）。
2. **新しい `session_generation` + `session_cookie` を active にする**のは HELLO 交渉が成功したときだけ。**(b) の後は物理 re-Link up を必須としない** — link が up のままなら Controller の re-HELLO（`next_tx_seq` または cold 後 seq0）と §5.5.3 / §5.6.1 で `SESSION_ACTIVE` に再到達してよい（half-open / SBR / liveness）。**(a) の後**は再 Link up 観測後に HELLO を行う。
3. 旧 `session_generation` / 旧 `session_cookie` の in-flight request / queue メッセージは **一括破棄**し、structured counter に計上する。Application Outcome へ昇格しない。
4. `session_generation == 0` および active 文脈での `session_cookie == 0` は §7.4 が明示許可する message 以外 **wire 上禁止**。
5. 受理 message の generation または cookie が active と不一致 → **reject**（stats）。state を推測更新しない。

### 5.3 Controller-only initiator（同時 HELLO 方針）

**U4 規範: Controller のみが HELLO を送ってよい（sole initiator）。Cell は HELLO を送らない。**

| 事象 | 動作 |
| --- | --- |
| Cell が HELLO を受信 | responder として処理（§8.4） |
| Controller が HELLO を受信 | **protocol error**: reject + counter。`CTRL_ERROR ERR_STATE` を送ってよい（予算内）。自 HELLO を自動取り下げない（sole initiator 維持） |
| 同時 HELLO | Controller-only のため **正規経路では起きない**。万一双方実装が破った場合は **双方 session 不成立**、link を `LINK_UP_NO_SESSION` に戻し、Controller が遅延後に単一 HELLO を再送 |
| node_fingerprint | **採用しない**（削除）。同時 HELLO タイブレークに使わない |

理由: fingerprint 同値・永続性・secret 混入のリスクを避け、role を固定した方が実装とテストが単純で堅牢。

### 5.4 Fencing

1. USB reconnect だけでは [03章](03-identity-and-join.md) の **Site Membership / Attachment**（および Device Identity 本線）を確立したとみなさない。曖昧語「Network Join」を単一成功状態として使わない（§11 / [15章](15-glossary.md)）。
2. assignment epoch / controller_term（[01章](01-architecture.md)）は **後続 logical control freeze**。U1–U4 は HELLO/liveness のみ。
3. RX overflow（§4.5）は session INVALID + parser reset + **RX-only sequence cold**（TX 継続）。回復は §5.6.1。

### 5.5 request_id / NCG1 sequence / inflight

#### 5.5.1 request_id（NCL1 logical）

| 項目 | 規範 |
| --- | --- |
| request_id 型 | u32 BE（NCL1 header）。**0 は no correlation のみ**（HELLO/PING/RESET では禁止） |
| 割当 authority | **各メッセージ送信端の local allocator**。HELLO/PING は **Controller のみ**。HELLO_ACK/PONG は **対応 request の echo**（新規割当しない）。**RESET は双方が送信可**で、送信端が local allocator から **nonzero** を取る（§8.3） |
| inflight map | **HELLO / PING のみ** request–response 相関で inflight 表へ入れる（最大 **8** / session）。超過は送出せず `ERR_CAPACITY` |
| **RESET と request_id** | RESET は **no-ack**。nonzero `request_id` を wire に載せるが **inflight map へ入れない**（ACK 待ち・timeout 経路を作らない）。診断・ログ相関用 |
| 衝突 | 同一 session で未完了の **inflight** `request_id` を再使用禁止。再使用検知時は reject。RESET 用 ID は inflight 外のため HELLO/PING と衝突しないよう allocator が一意を保証 |
| wrap | 送信側カウンタが wrap して 0 になる場合は 0 をスキップ。全 32-bit 空間が inflight で埋まる前に fail-closed（実質 max 8 で到達しない） |
| stale | 応答の `request_id` が inflight 表に無い → drop + counter（session は維持可） |
| replay | 既に完了した `request_id` の重複応答 → drop + counter |
| gap | request_id の欠番は許容（単調必須ではない）。相関は表引きのみ |

#### 5.5.2 NCG1 `sequence`（存在確認と USB U4 exact policy）

**事実:** docs/19 NCG1 header は **offset 12 / size 4 / `sequence` u32 BE** を持つ。codec は任意 u32 を透過し、**wrap / gap / replay ポリシーは上位**（docs/19 §6）。本節はその上位として **USB U4 single bootstrap/control stream** の exact 規則を固定する。他 transport や後続 multi-stream Attachment に本表を自動適用しない。

**方向別 epoch（必須）:** Controller→Cell と Cell→Controller は **独立カウンタ**。各端は **local TX epoch**（`next_tx_seq`）と **local RX epoch**（`have_rx_seq` / `last_rx_seq`）を持つ。**RX 連続性喪失は原則 local RX だけ cold**し、無関係な local TX `next_tx_seq` は継続する。link down→up と自 process/adapter restart だけが **自側 TX+RX 双方 cold**。

| 項目 | U4 規範 |
| --- | --- |
| 型 / 位置 | NCG1 header **offset 12**、`u32 BE`（docs/19 layout 正本） |
| **stream_or_cell_id（U4 USB）** | **exact `0`** = sole bootstrap/control stream。送信 MUST `0`。受信 `!= 0` → **frame reject + counter**（NCL1 を解釈しない）。**後続 Attachment / multi-stream 用 non-zero ID は U4 で未割当** — 本検査は U4 single-stream 契約のみ。multi-stream freeze が別 ID を割当てたとき、その path の規則が上書きしうる（U4 実装は non-zero を「Attachment 成功」とみなしてはならない） |
| 割当 authority | **各方向の NCG1 frame 送信側**。NCL1/session 層は sequence を書き換えない。Controller→Cell と Cell→Controller は **独立カウンタ** |
| 初期値 | **当該方向の TX sequence epoch cold** 後、送信側 `next_tx_seq = 0`。**その epoch の最初の TX frame の sequence は 0**。cold を起こす trigger は下表「sequence reset authority」に **限定**（HELLO_ACK timeout だけでは cold しない） |
| increment | adapter が frame bytes の送信を **accept** した直後に `next_tx_seq = next_tx_seq + 1`（未 accept / WOULD_BLOCK では進めない） |
| 0 扱い | sequence=`0` は **合法**（cold 後の最初の frame）。「0 = 無効 frame」ではない（docs/19 透過と整合） |
| **`UINT32_MAX` 予約 terminal（U4）** | wire 上 **`sequence == UINT32_MAX` は予約 terminal**。**送信禁止**（encode/TX accept してはならない）。**受信は §5.5.3 SBR / `BOOTSTRAP_EPOCH_RESTART` / 通常 exact0 baseline / 通常連続 `last+1` の判定より必ず前**に reject + `ncg1_reject_seq_reserved++` + **control session INVALID** + **local RX-only sequence epoch cold**（local TX 継続）。payload を NCL1 peek しない。**`last_rx_seq + 1` の u32 wrap（`UINT32_MAX`→0 等）を期待・受理してはならない** |
| 受信 baseline（通常規則） | 方向ごとに、**RX sequence epoch** 開始後に accept する **最初の frame** は **sequence exact 0** でなければ reject + counter（baseline 不成立）。成功時 `last_rx_seq = 0`、`have_rx_seq = true`。**限定例外:** §5.5.3 semantic baseline resync（2 種のみ）。いずれも **`seq != UINT32_MAX` 前提**（予約は上段で先に落とす） |
| 以降の期待 | `have_rx_seq` 後は **exact `last_rx_seq + 1`** のみ受理（**加算は wrap 禁止**: `last_rx_seq == UINT32_MAX - 1` のとき期待 next は予約 `UINT32_MAX` であり **合法連続 accept は存在しない** — peer は TX fence 済みであるべき。別 seq は gap/regress）。受理後 `last_rx_seq` を更新 |
| duplicate / replay | `have_rx_seq` かつ `seq == last_rx_seq` → **通常** reject + counter、**session は維持可**。**例外:** §5.5.3 `BOOTSTRAP_EPOCH_RESTART` 候補（valid HELLO bootstrap）なら session+RX epoch を atomic fence して seq を新 baseline として accept。**`seq == UINT32_MAX` は本段に到達しない**（予約で先 reject） |
| gap | `have_rx_seq` かつ `seq > last_rx_seq + 1`（wrap なし比較）→ **fail-closed**: 当該 frame reject + **control session INVALID** + **local RX sequence epoch cold のみ**（local TX `next_tx_seq` **継続**）+ counter。gap は bootstrap 例外の対象外（NCL1 を見て gap を accept に変えない） |
| 後退 / reorder | `have_rx_seq` かつ `seq < last_rx_seq` → **通常** gap と同じ fail-closed（USB U4 は reorder を想定しない; local RX cold + session INVALID、local TX 継続）。**例外:** §5.5.3 `BOOTSTRAP_EPOCH_RESTART`（典型: peer process restart 後の HELLO `sequence=0`） |
| wrap / TX 上限 | `next_tx_seq == UINT32_MAX` のとき **当該方向の TX を停止/fence**（**予約 terminal を wire に載せて +1 wrap 継続しない**）。session INVALID + **local TX epoch cold**（送信再開前）+ 当該 RX も cold して HELLO 再交渉または process restart。**黙って 0 へ wrap して継続しない**。合法 wire sequence の上限は **`UINT32_MAX - 1`** |
| parser reset | `RESET_PARSER`（**送信 accept 時および受信時**は各端で **local RX parser/epoch のみ cold**）、RX overflow fence（§4.5）、fatal framing desync、**通常** sequence gap/後退、**予約 `UINT32_MAX` 受信** → **local RX sequence epoch cold + session INVALID**。**各端 local TX は継続**（下表） |
| link reconnect | **物理** link down→up で **自側 TX+RX 双方 cold**。**sequence リセットだけでは `SESSION_ACTIVE` にしない** — 必ず再 HELLO（§5.2）。session-breaking のみでは物理 re-Link 不要（§5.2 規則1(b)） |
| session fence との関係 | `session_generation` / `session_cookie` は **NCL1 logical session fence**。NCG1 `sequence` は **byte-stream framing 連続性**。両者は独立。**session fence だけで双方 sequence を無条件 0 にしない**（下表）。RX overflow / 通常 sequence gap は **parser/RX cold 相当かつ session INVALID** だが **TX は無関係に cold しない** |
| docs/19 整合 | framing codec の透過性は維持。本表 = USB U4 control path の **上位ポリシー**。U3 単体は sequence/stream_id 規則のみ適用可。cookie/HELLO は U4 |

**Sequence reset authority（方向別; cold / 継続を exact 分離）:**

| trigger | local TX (`next_tx_seq`) | local RX (`have_rx_seq` / `last_rx_seq`) | session | 注 |
| --- | --- | --- | --- | --- |
| link open 成功 / link down→up | **cold → 0** | **cold → baseline 待ち** | 非 ACTIVE | **自側 TX+RX 双方 cold** |
| process / adapter **自側** restart | **cold → 0**（新 process） | **cold** | 失われる | **自側双方 cold**。peer は §5.5.3 で受けうる |
| `RESET_PARSER` **送信 accept**（自端） | **継続** | **cold → baseline 待ち**（**自端 local RX parser/epoch のみ**） | INVALID | **送信端も RX-only cold**。自端 local TX は止めない。peer の epoch は触らない |
| `RESET_PARSER` **受信**（自端） | **継続** | **cold → baseline 待ち**（**自端 local RX parser/epoch のみ**） | INVALID | **受信端も RX-only cold**。自端 local TX は止めない |
| RX overflow / fatal framing desync | **継続** | **cold → baseline 待ち** | INVALID | **RX-only cold**。無関係な local TX は止めない。**物理 Link down ではない** |
| 通常 sequence gap | **継続** | **cold → baseline 待ち** | INVALID | **RX-only cold**。bootstrap 例外なし |
| 通常 sequence 後退（bootstrap 非該当） | **継続** | **cold → baseline 待ち** | INVALID | **RX-only cold** |
| 予約 `sequence == UINT32_MAX` 受信 | **継続** | **cold → baseline 待ち** | INVALID | SBR/BOOTSTRAP/baseline **より前**に reject + `ncg1_reject_seq_reserved` |
| **同一 link / 同一 process の HELLO_ACK timeout retry** | **cold しない**。`next_tx_seq` のまま次 HELLO（初回 seq0 受理後の次は **seq1**） | 変更なし（baseline 未成立なら未成立のまま） | HELLO_SENT 継続 | **必須**。ACK 喪失で Cell `last_rx_seq=0` ACTIVE のとき seq0 再送すると duplicate reject で永久停止 |
| `RESET_SESSION` | **cold しない**（双方 sequence 継続） | **cold しない** | INVALID → `LINK_UP_NO_SESSION` | session だけ fence。Controller は `next_tx_seq` で re-HELLO |
| half-open fence（ACTIVE 中 valid HELLO を **連続 sequence** で accept） | 送信側は継続 | 当該 HELLO の seq を `last_rx_seq` に更新（epoch 継続） | 旧 session fence → `HELLO_RECEIVED` | sequence を無条件 0 にしない |
| `BOOTSTRAP_EPOCH_RESTART`（§5.5.3; have_rx_seq 済み + dup/regress + valid HELLO） | 送信側は別規則 | **RX epoch を atomic に再開始**し当該 seq を新 baseline として accept | 旧 session fence → `HELLO_RECEIVED` | peer restart 系（典型 seq0） |
| **semantic baseline resync — Cell valid HELLO**（§5.5.3; baseline 未成立） | n/a（受信側規則） | **任意 sequence を新 baseline として atomic accept** | → `HELLO_RECEIVED` | peer-continuation（高 sequence HELLO 含む） |
| **semantic baseline resync — Controller matching HELLO_ACK**（§5.5.3; baseline 未成立） | n/a | **任意 sequence を新 baseline として atomic accept** | 通常 ACK 処理へ | reverse ACK loss / high ACK |
| wrap (`next_tx_seq == UINT32_MAX`; 予約 terminal を送れない) | **当該 TX 停止/fence 後 cold** | cold | INVALID | **wire に `UINT32_MAX` を載せて wrap 継続禁止** |
| `RESET_LINK` 送信 accept / 受信 | 即 sequence cold ではない | 即 sequence cold ではない | **即 INVALID** | session は **wire 受理で即 INVALID**。sequence は **観測した link reopen** で **双方 cold**（上表 物理 link down→up）。即 wire だけでは sequence cold しない |

**Sequence epoch（cold）と gap 後の次期待値（デッドロック禁止）:**

| 項目 | 規範 |
| --- | --- |
| epoch 開始条件 | 上表で **cold** とされた trigger のみ。**HELLO_ACK timeout・`RESET_SESSION`・通常 half-open 連続 accept だけでは epoch を cold しない** |
| local 状態リセット（**RX-only cold** 時） | `have_rx_seq = false`、`last_rx_seq` 不定。**`next_tx_seq` は触らない** |
| local 状態リセット（**TX+RX 双方 cold** 時） | `next_tx_seq = 0` かつ `have_rx_seq = false` を同時 |
| **次に受理可能な RX sequence（cold 後・通常）** | epoch 内の **最初の accept 対象 frame は exact `sequence=0` のみ**。0 以外は baseline 不成立として reject + counter。**gap 直前の `last_rx_seq+1` を期待し続けてはならない**。**例外:** §5.5.3 semantic baseline resync 2 種 |
| **次に送る TX sequence（TX cold 後）** | epoch 内の **最初の TX frame は exact `sequence=0`**。その後 accept ごとに +1 |
| **同一 process の HELLO retry** | cold **しない**。`next_tx_seq` を使う。**「timeout 毎に必ず seq0」は禁止** |
| 再 HELLO とデッドロック禁止 | Controller は sole initiator。Cell は HELLO を送らない。fair-delivery 下で §5.5.3 / §5.6.1 の回復経路が閉じ、有限時間で `SESSION_ACTIVE` 再到達できなければならない。**sequence 段で無条件 discard して NCL1 HELLO/HELLO_ACK を見られない実装は禁止**（§5.5.3 / §8.1） |
| peer 未同期中 | cold 済み RX は high sequence の旧 epoch frame を **通常 reject**（stats）。valid HELLO/matching HELLO_ACK なら §5.5.3 |
| link 強制 | 連続 reject や回復不能時は `RESET_LINK` / close-reopen してよい（**必須脱出口ではない**; §5.6.1） |

#### 5.5.3 Semantic baseline resync と `BOOTSTRAP_EPOCH_RESTART`（限定例外）

**失敗列 A（ACK loss; reverse baseline）— 禁止実装が踏む穴:** Controller HELLO **seq0**、Cell HELLO_ACK **seq0** が喪失 → Controller RX は baseline 未成立のまま → re-HELLO **seq1**、Cell re-ACK **seq1** → Controller が **exact0 baseline のみ**で永久拒否。

**失敗列 B（Controller restart; high ACK）:** Controller process restart 後 HELLO seq0。Cell は half-open / bootstrap で HELLO を受け、**TX 継続 sequence（high）** で HELLO_ACK を返す → 新 Controller が high ACK を baseline≠0 で永久拒否。

**失敗列 C（片側 RX-only cold）:** Cell が C→Cell gap / RX overflow / fatal desync を検出し **local RX cold + session INVALID**（TX 継続）。Controller は high `next_tx_seq` で HELLO を送り続ける → Cell が exact0 baseline のみで永久拒否。

**規則 1 — 通常 exact0 baseline:** RX epoch cold 後、§5.5.3 例外に該当しない frame の最初の accept は **exact `sequence=0`**。**非 HELLO / 非 matching HELLO_ACK** の任意 sequence を baseline にしてはならない（`ncg1_reject_baseline++`）。

**規則 2 — semantic baseline resync（baseline 未成立時のみ; 2 種）:**

| ID | 受信 role | 前提 | 完全検証 | 動作 | counter |
| --- | --- | --- | --- | --- | --- |
| **SBR-HELLO** | **Cell** | `have_rx_seq == false` かつ session 状態が `LINK_UP_NO_SESSION` または `HELLO_RECEIVED` 相当 | framing + `stream_or_cell_id=0` + NCG1 type **`DATA`** + exact **Valid HELLO bootstrap**（§5.6） | 当該 **任意 sequence** を新 RX baseline として **atomic accept**（`last_rx_seq = seq`、`have_rx_seq = true`）→ `HELLO_RECEIVED`（peer-continuation recovery） | `hello_baseline_resync++` |
| **SBR-ACK** | **Controller** | `have_rx_seq == false` かつ `HELLO_SENT` かつ **現在唯一の HELLO inflight `request_id` が 1 件** | framing + `stream_or_cell_id=0` + NCG1 type **`DATA`** + exact valid **HELLO_ACK**（body/layout + §7.4 header 規約）かつ **`request_id` が sole inflight と bit-exact 一致** | 当該 **任意 sequence** を新 RX baseline として **atomic accept** → **通常 ACK 処理**（OK なら ACTIVE、error なら §5.6）。**error ACK も matching `request_id` なら本規則適用**（gen=0,cookie=0 の error wire を含む） | `hello_ack_baseline_resync++` |

限定 peek / 検証順（固定）:

1. NCG1 framing（magic/version/type/flags/len/**CRC**）成功。
2. `stream_or_cell_id` exact 0。
3. NCG1 type exact **`DATA`**。
4. sequence が **baseline 未成立**（`have_rx_seq == false`）である（本規則）。または規則 3 の dup/regress。
5. payload を NCL1 として **限定 peek**（通常 path の順序入替ではない; §8.1）。
6. role / state / request 一致（上表）を満たすときだけ atomic accept。満たさなければ **通常 baseline 不成立 reject**（NCL1 業務解釈なし）。

**禁止:** (1) baseline 未成立時に **任意 non-HELLO / non-matching-ACK** を resync すること。(2) `have_rx_seq == true` の gap を resync で塞ぐこと。(3) matching しない HELLO_ACK を baseline にすること。(4) sequence 段で無条件 discard し peek 不能にすること。

**規則 3 — `BOOTSTRAP_EPOCH_RESTART`（have_rx_seq 済み + dup/regress + valid HELLO; Cell）:**

1. 受信側で framing 成功・`stream_or_cell_id=0`・type **`DATA`**、かつ sequence が **duplicate または 後退**、かつ payload が exact Valid HELLO bootstrap のとき、sequence 段で **無条件最終 discard してはならない**。
2. **atomic** に: 旧 RX sequence epoch を閉じる + 旧 control session を fence（active gen/cookie 無効・inflight 破棄）。
3. 当該 frame の sequence（典型 **0**）を **新 epoch の baseline として accept**。
4. Cell は `HELLO_RECEIVED` へ; counter `hello_bootstrap_epoch_restart++` および `hello_halfopen_fence++`（session fence を伴う場合）。
5. peek が valid HELLO bootstrap **でなければ**通常 dup/regress（reject + 該当 counter; 後退/gap 系は session INVALID + **RX-only cold**）。
6. **gap** には本例外を適用しない。
7. Controller 側 TX: process restart 後は自 TX+RX cold で HELLO seq0 を送ってよい。同一 process の timeout retry で seq0 に戻してはならない。

**規則 4 — 同一 process HELLO_ACK timeout retry:** sequence epoch を **cold にしない**。`next_tx_seq` で valid HELLO を再送（初回 seq0 の次は **seq1**）。Cell が ACTIVE なら連続 sequence half-open（§5.6）。Controller RX が baseline 未成立なら re-ACK を **SBR-ACK** で受ける。

### 5.6 状態機械（control session）

**Valid HELLO bootstrap（全 role 共通定義）:** NCL1 `message_type=HELLO` かつ header `session_generation=0` かつ `session_cookie=0` かつ `request_id≠0` かつ body §8.4 かつ NCG1 type が closed matrix 上 **exact `DATA`**（§7.3）。**HELLO を active cookie / active generation 一致検査で拒否してはならない**（bootstrap は常に 0/0。§8.1 で type 判明後に §7.4 の HELLO 行を適用する）。

**送信 role matrix（必須; 逆送は reject）:**

| message | Controller TX | Cell TX | 注 |
| --- | --- | --- | --- |
| `HELLO` | **のみ** | ✗ | sole initiator |
| `HELLO_ACK` | ✗ | **のみ** | HELLO 応答 |
| `PING_BODY` | **のみ** | ✗ | liveness request |
| `PONG_BODY` | ✗ | **のみ** | PING 応答 |
| `RESET_BODY` | **双方可** | **双方可** | no-ack; §8.3 |
| `CTRL_ERROR` | **双方可** | **双方可** | §8.6–§8.7 |

```text
DISCONNECTED
  -- link open ok --> LINK_UP_NO_SESSION
       （自側 TX+RX sequence epoch cold）
  -- open fail / unplug --> DISCONNECTED
  -- any HELLO/HELLO_ACK/PING/... RX --> drop (no link); no state change

LINK_UP_NO_SESSION
  -- Controller: local send valid HELLO (seq epoch 規則) --> HELLO_SENT
  -- Cell: RX valid HELLO bootstrap
       * 通常: baseline 未成立かつ seq==0 → accept → HELLO_RECEIVED
       * SBR-HELLO: baseline 未成立かつ任意 seq + 完全検証 → atomic baseline accept
         → HELLO_RECEIVED（peer-continuation; high HELLO 含む）
  -- Controller: RX HELLO (any) --> reject + counter hello_invalid_role;
       stay LINK_UP_NO_SESSION（sole initiator 維持）
  -- Cell: RX HELLO_ACK / PING / active-only msg --> reject + counter; stay
  -- NCG1 通常 sequence gap/後退 / RX overflow / RESET_PARSER local fence
       --> **local RX-only cold** + session 非確立維持; **local TX 継続**
  -- RESET_SESSION --> session 非確立維持; sequence は双方 cold しない（§5.5.2）
  -- link loss --> DISCONNECTED（双方 cold on reopen）

HELLO_SENT          (Controller only)
  -- RX valid HELLO_ACK HELLO_OK matching inflight request_id
       + session_generation!=0 + header session_cookie!=0
       + selected_control_version ok
       * 通常: baseline 済み連続 seq、または baseline 未成立かつ seq==0
       * SBR-ACK: baseline 未成立 + matching sole inflight + 任意 seq
         → atomic baseline accept 後に通常 ACK 処理
       --> SESSION_ACTIVE (store gen+cookie as active)
  -- RX HELLO_ACK error (VERSION_MISMATCH/BUSY/DENIED; gen=0,cookie=0)
       matching request_id
       （SBR-ACK 可: baseline 未成立 + matching + 任意 seq）
       --> LINK_UP_NO_SESSION
  -- RX HELLO_ACK request_id mismatch / stale / non-matching
       --> drop + counter; **baseline にしない**; stay HELLO_SENT
  -- HELLO_ACK loss / timeout（§8.11 HELLO retry; **同一 process/link**）
       --> sequence epoch を **cold しない**
       + cancel prior HELLO inflight
       + re-send valid HELLO at **`next_tx_seq`**（初回 seq0 受理後の次は seq1）
       （同一 HELLO_SENT 継続可; RX baseline 未成立のままなら次 ACK は SBR-ACK）
       【デッドロック禁止: timeout 毎に seq0 へ戻して Cell last_rx=0 ACTIVE を
         duplicate reject で永久停止させる実装】
       【デッドロック禁止: reverse ACK seq1 を exact0 baseline だけで永久拒否】
  -- RX HELLO (Cell 起点を含む) --> reject + counter hello_invalid_role;
       stay HELLO_SENT（自 HELLO を自動取り下げない）
  -- duplicate local HELLO policy: 同時に inflight HELLO は **最大 1**。
       retry 時は旧 request_id を表から外し **新 request_id** で送る
  -- link loss --> DISCONNECTED
  -- RX overflow / 通常 seq gap・後退 / 予約 UINT32_MAX fence
       --> INVALID then LINK_UP_NO_SESSION + **RX-only cold** + **TX 継続**
       --> Controller は **直ちに** `next_tx_seq` で HELLO（§5.6.1）

HELLO_RECEIVED      (Cell only)
  -- CSPRNG ok + local TX accepts HELLO_ACK HELLO_OK
       (gen!=0, header cookie!=0) --> SESSION_ACTIVE
       （HELLO_ACK は Cell **TX 継続 sequence** を使用）
  -- CSPRNG fail-closed or non-OK HELLO_ACK TX accepted
       (gen=0,cookie=0) --> LINK_UP_NO_SESSION
  -- duplicate valid HELLO bootstrap while HELLO_RECEIVED
       （連続 sequence で accept 済み、または BOOTSTRAP_EPOCH_RESTART / SBR-HELLO）
       --> 旧 in-progress HELLO 応答を破棄（未 TX の ACK 計画を捨てる）
       + 新 HELLO を sole bootstrap として処理（stay HELLO_RECEIVED）
       + 新 request_id に対する HELLO_ACK を用意
       【cookie/gen の active 一致検査は適用しない】
  -- RX HELLO with gen!=0 or cookie!=0 --> reject + counter hello_invalid_bootstrap;
       stay HELLO_RECEIVED or LINK_UP_NO_SESSION（実装は reject のみ; 推測 ACTIVE 禁止）
  -- RX PING/PONG/RESET/CTRL_ERROR（session 未 ACTIVE）--> reject + counter; stay
  -- link loss --> DISCONNECTED
  -- 通常 seq gap/overflow --> LINK_UP_NO_SESSION + **RX-only cold** + **TX 継続**

SESSION_ACTIVE
  -- PING/PONG/RESET/CTRL_ERROR: header gen+cookie が active と bit-exact 一致のときのみ
  -- active 向け message の cookie または gen 不一致 --> reject + counter
       session_mismatch; state 維持可（§8.7 burst で fence しうる）
  -- **Cell: RX valid HELLO bootstrap（half-open recovery; §5.6.1）**
       経路 A — **連続 sequence**（`seq == last_rx_seq + 1`）:
         --> 旧 session を明示 fence（active gen/cookie 無効化、inflight 全破棄、
             logical ingress の旧世代一括破棄、structured counters）
         --> 当該 seq を last_rx 更新（sequence epoch **継続**）
         --> HELLO_RECEIVED へ; 新 gen+cookie で HELLO_ACK 応答 path へ
       経路 B — **dup/regress + BOOTSTRAP_EPOCH_RESTART**（§5.5.3; 典型 seq0）:
         --> framing+DATA+valid HELLO 確認後、旧 RX sequence epoch と session を
             **atomic fence**
         --> seq を新 baseline として accept → HELLO_RECEIVED
       【MUST NOT: active cookie 一致検査で HELLO を誤拒否し旧 session 維持】
       【MUST NOT: sequence 段で無条件 discard し NCL1 HELLO を見ない】
  -- Controller: RX HELLO --> reject + counter hello_invalid_role; stay SESSION_ACTIVE
  -- RESET_SESSION accepted (no-ack; §8.3) --> session fence --> LINK_UP_NO_SESSION
       + sequence **双方 cold しない** + local re-HELLO timer（Controller; `next_tx_seq`）
  -- RESET_PARSER / RX overflow / 通常 seq gap / 予約 UINT32_MAX 受信
       --> session INVALID + **local RX-only cold** + **local TX 継続**
       --> LINK_UP_NO_SESSION（**物理 Link down ではない**; §5.2 規則1(b)）
       --> 検出側が Controller なら **直ちに next_tx_seq HELLO**（§5.6.1）
       --> 検出側が Cell なら §5.6.1 **continuity-loss 通知順序**:
           pre-fence snapshot → atomic fence と同一 action で
           高優先 RESET_SESSION notice **最大 1**
           （header=snapshot, NCG1 seq=継続 next_tx_seq; 他の旧 session TX 禁止）
           WOULD_BLOCK/喪失でも local fence は戻さない → liveness / SBR-HELLO
  -- link loss --> DISCONNECTED（generation+cookie invalid; reopen で双方 cold）
```

#### 5.6.1 Half-open / reverse-ACK / RX-only-cold recovery（有限回復）

**問題:** Controller process restart や HELLO_ACK 喪失では、**USB 物理 link down を Cell が観測しない**ことがある。Cell だけが `SESSION_ACTIVE` のまま残り、Controller は新 HELLO bootstrap（gen=0,cookie=0）を送る。active cookie 一致検査で HELLO を拒否すると **回復不能デッドロック**になる。さらに (1) **HELLO timeout 毎に sequence を cold して seq0 を再送**すると Cell `last_rx_seq=0` ACTIVE で duplicate 永久停止、(2) reverse ACK が seq1/high なのに Controller が exact0 baseline のみ、(3) 片側が RX-only cold した後に peer の high sequence HELLO/ACK を拒否、でも永久停止する。

| シナリオ | 検出 / 送信側 | 必須回復 |
| --- | --- | --- |
| **HELLO_ACK 喪失**（link up・同一 process; Cell `last_rx_seq=0` ACTIVE を含む） | Controller: epoch **cold しない**。`next_tx_seq` で valid HELLO 再送（seq0 の次は **seq1**）。RX baseline 未成立のまま | Cell: 連続 sequence valid HELLO を **half-open** 受理 → fence → `HELLO_RECEIVED` → 新 gen+cookie ACK（**Cell TX 継続 sequence**）。Controller: re-ACK を **SBR-ACK**（任意 seq matching）で atomic baseline accept |
| **Controller process restart** かつ Cell `last_rx_seq=0` | 新 process: **TX+RX 双方 cold** → HELLO **seq0** | Cell: dup 候補を §5.5.3 で peek → valid HELLO なら **`BOOTSTRAP_EPOCH_RESTART`** → `HELLO_RECEIVED`。ACK は Cell TX 継続。Controller: **SBR-ACK** で high/0 どちらでも matching なら baseline accept。**物理 link down 不要** |
| **Controller process restart** かつ Cell `last_rx_seq` high / Cell TX high | HELLO **seq0**（後退） | 同上 **`BOOTSTRAP_EPOCH_RESTART`** + **SBR-ACK**（high HELLO_ACK）。valid HELLO でなければ通常後退 → Cell **RX-only cold** + session INVALID |
| 双方 SESSION_ACTIVE 後の sole Controller re-HELLO（同一 process） | `next_tx_seq` 連続 | 経路 A half-open |
| **Controller が RX gap/overflow/fatal desync を検出** | **RX-only cold** + session fence → **直ちに** `next_tx_seq` HELLO | Cell: half-open または SBR-HELLO。ACK は Cell TX 継続。Controller: baseline 未成立なら **SBR-ACK**、成立済みなら通常連続 |
| **Cell が RX gap/overflow/fatal desync を検出** | **RX-only cold** + session fence + 下段 **continuity-loss 通知順序** | RESET 喪失 / `WOULD_BLOCK` でも **local fence は戻さない**。Controller は PING/PONG liveness fence 後に `next_tx_seq` HELLO。Cell: **SBR-HELLO**（high HELLO 可）。ACK は Cell TX 継続。Controller: 通常連続または **SBR-ACK**。**物理 re-Link up 不要** |
| `RESET_LINK` | 補助。session **即 INVALID**; close/reopen 観測で **双方 sequence cold** | **唯一の必須脱出口にしない** |
| 非 HELLO の dup/regress / non-matching ACK | — | 通常 reject。**baseline にしない**（`U4-N-BASELINE-NONHELLO` / `U4-N-ACK-BASELINE-NONMATCH`） |
| 予約 `sequence == UINT32_MAX` 受信 | reject + `ncg1_reject_seq_reserved` + session INVALID + **RX-only cold**（SBR/BOOTSTRAP より前） | Controller は `next_tx_seq` HELLO または liveness 経路。**wrap 継続禁止** |

**Cell continuity-loss 通知順序（SESSION_ACTIVE 検出時; exact; 短縮・入替禁止）:**

Cell が **SESSION_ACTIVE** 中に RX gap / overflow / fatal framing desync / 予約 `UINT32_MAX` 等の **session-breaking** を検出したとき、次を **同一 atomic action** として実行する（途中状態を peer や上位へ「まだ ACTIVE」と見せない）:

1. **pre-fence snapshot:** 旧 active `session_generation` と `session_cookie` を **local 変数へ snapshot**（以降 wire 通知ヘッダの唯一の authority）。
2. **session + RX fence（同一 atomic）:** control session を **INVALID** → `LINK_UP_NO_SESSION` 相当; inflight 全破棄; logical ingress の旧世代一括破棄; **local RX-only sequence epoch cold**（`have_rx_seq=false`）; **local TX `next_tx_seq` は継続**（触らない）; structured counters（`rx_overflow` / gap 等 + `session_fence_inflight_dropped`）。
3. **高優先 `RESET_SESSION` notice を最大 1 件だけ作成:** C3 session object 内の **exact 1 reserved fixed slot**へ置く（heap / unbounded queue / 通常 TX queue 空きへ依存しない）。no-ack; **inflight map に入れない**; TX 優先度は通常 PING/業務より **高い**（notice を先に drain）。**2 件目以降を積んではならない**（重複は merge/drop + counter）。notice の NCL1 header **`session_generation` / `session_cookie` は step 1 の pre-fence snapshot**（post-fence の「active 無し」や 0/0 で送らない — §7.4 RESET continuity-loss 行）。**sender-side session fence は step 2 で既に完了**している（下段 lifecycle (a)）。
4. **RESET frame の raw-adapter TX accept:** NCG1 sequence は **継続 `next_tx_seq`**（cold しない）。**raw-adapter accept 直後にのみ** `next_tx_seq++`（通常規則; lifecycle (d)）。**他の旧 session message**（旧 gen/cookie の PING 応答・CTRL_ERROR・業務 DATA 等）の **新規 TX は禁止**（fence 済み世代の送信を再開しない）。**本 accept で通常 `RESET_SESSION` 送信 accept の sender fence を再実行してはならない**（lifecycle (a)）。
5. **`WOULD_BLOCK` / 通知喪失:** notice が TX ring full で accept できない、または wire 上で喪失しても **step 2 の local fence は絶対に戻さない**（ACTIVE へ rollback 禁止）。回復は peer の liveness miss → Controller `next_tx_seq` HELLO、または Cell 側 **SBR-HELLO**（§5.5.3）。**物理 re-Link up を必須脱出口にしない**。
6. **Controller が同様に検出した場合:** atomic に session INVALID + RX-only cold + **直ちに `next_tx_seq` HELLO**（RESET_SESSION 通知は任意; Cell 側 pre-fence 手順の必須対称ではない）。

**Pending Cell continuity-loss RESET notice lifecycle（reserved slot; exact; 短縮・入替禁止）:**

検出/作成（上段 steps 1–3）から raw-adapter TX accept 前後までの **pending notice** について、次を固定する:

1. **(a) fence once at detection/creation:** sender-side session fence（step 2: session INVALID → `LINK_UP_NO_SESSION`、inflight/logical 破棄、RX-only cold、TX 継続）は **continuity-loss 検出と notice 作成時に exact 1 回だけ**。reserved slot 上の notice が後から **raw-adapter TX accept** されても、**通常 `RESET_SESSION` 送信 accept の sender fence を再実行してはならない**（session/parser/sequence を accept 時に再度 fence/cold しない）。accept は bytes を raw TX ring へ渡すことと **NCG1 sequence 消費（step 4）** のみ。
2. **(b) cancel on valid HELLO toward new session:** Cell が **valid HELLO bootstrap を受理して新 session へ遷移する直前**（half-open 連続 accept → `HELLO_RECEIVED`、`BOOTSTRAP_EPOCH_RESTART`、**SBR-HELLO** を含む）に、reserved slot に **not-yet-raw-adapter-accepted** の旧 continuity-loss notice が残っていれば、**同一 atomic action** でその notice を **cancel/clear** し、structured counter **`continuity_reset_notice_cancelled++`** する。cancel 後に当該旧 notice を TX してはならない。
3. **(c) already raw-adapter accepted → strict FIFO:** notice が **既に raw-adapter accept 済み**（bytes が raw TX ring / adapter 所有）のとき、後続の `HELLO_ACK` その他 TX accept は **strict FIFO** で notice の後に並ぶ。**reorder 禁止**（HELLO_ACK を notice より先に wire へ出さない; 既 accept 済み bytes を抜き出して後ろへ送らない）。
4. **(d) sequence consume:** **cancel before raw-adapter accept** は **NCG1 sequence を消費しない**（`next_tx_seq` 不変）。**raw-adapter accept** は通常どおり sequence を消費する（step 4: accept 時に `next_tx_seq++`）。

**禁止（continuity-loss notice 追加）:** (14) raw-adapter TX accept 時に通常 `RESET_SESSION` sender fence を再実行すること。(15) not-yet-accepted 旧 notice を残したまま valid HELLO を新 session へ遷移させること（cancel 欠落）。(16) already-accepted notice と後続 HELLO_ACK を reorder すること。(17) cancel で `next_tx_seq` を進める、または accept 前に sequence を消費すること。

**禁止:** (1) HELLO bootstrap を active cookie/gen 不一致だけで reject して **旧 session を維持**すること。(2) 同一 process の HELLO timeout 毎に sequence cold → seq0 再送すること。(3) sequence 段で無条件 discard し、dup/regress 時に NCL1 valid HELLO を見れず `BOOTSTRAP_EPOCH_RESTART` 不能なこと。(4) sequence cold 後も旧 `last_rx_seq+1` を期待し続けて HELLO(seq=0) を永久拒否すること。(5) Cell が HELLO を送って「逆 half-open」を解消しようとすること（Controller-only）。(6) `RESET_SESSION` / half-open だけで **双方 sequence を無条件 0** にすること。(7) gap/overflow/`RESET_PARSER` で **無関係な local TX を cold** すること。(8) baseline 未成立時に matching HELLO_ACK 以外の high sequence を baseline にすること。(9) reverse ACK loss（seq1 ACK）を exact0 だけで永久拒否すること。(10) `RESET_LINK` だけを必須脱出口にすること。(11) RX overflow / RESET / gap を **物理 Link down** と呼び、re-Link up 無しでは HELLO 回復不能とすること。(12) continuity-loss 後に pre-fence 以外の旧 session message を送ること、または notice 喪失で local fence を戻すこと。(13) wire に `sequence == UINT32_MAX` を送る、または受信を SBR/BOOTSTRAP で accept すること。(14)–(17) 上段 pending notice lifecycle 禁止。

**Fair-delivery と有限時間回復:** 単なる link up は delivery 保証ではない。無限 packet loss 下での `SESSION_ACTIVE` 再到達は主張しない。ただし link up かつ非 ACTIVE の間、HELLO retry は停止しない（§8.11 `hello_retry_unlimited_while_link_up`；上限回数で永久放棄して dead にしない）。**Fair-delivery assumption:** USB byte stream が継続的に read/write 可能であり、かつ HELLO / HELLO_ACK の少なくとも一組が有限回の送信試行内に peer へ配送される場合、各 retry delay は `hello_retry_max`（**5000 ms**）で上限され、かつ上記 ACK 喪失 / restart / reverse baseline / RX-only cold 経路が閉じているため、`SESSION_ACTIVE` 再到達までの待ちは有限時間に収まる。手動 unplug 必須・retry 停止・seq0-dup 永久停止・exact0-only reverse ACK 拒否による待機は不合格。

#### 5.6.2 HELLO 遷移ベクトル（U0 ID; U4 で fixture 化）

| ID | 種別 | 内容 |
| --- | --- | --- |
| `U4-G-HALFOPEN-REHELLO` | golden / behavioral | Cell `SESSION_ACTIVE` + valid HELLO bootstrap（**連続 sequence**）→ session fence（seq epoch 継続）→ 新 gen+cookie `HELLO_ACK` OK → 双方 ACTIVE |
| `U4-G-HELLO-RETRY-NEXT-SEQ` | golden / behavioral | Controller HELLO_ACK timeout（同一 process）→ **cold しない** → HELLO を **`next_tx_seq`**（例: seq1）で再送し Cell が accept |
| `U4-G-ACKLOSS-LAST0-HALFOPEN` | golden / behavioral | **必須:** Cell が HELLO seq0 受理・ACTIVE・`last_rx_seq=0`、ACK 喪失 → Controller が seq1 HELLO → half-open 成功（seq0 再送で duplicate 停止しない） |
| `U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE` | golden / behavioral | **必須:** HELLO seq0 + ACK seq0 喪失 → re-HELLO seq1 + Cell ACK seq1 → Controller **SBR-ACK** で seq1 を baseline atomic accept → ACTIVE（exact0 永久拒否しない） |
| `U4-G-RESTART-SEQ0-LAST0` | golden / behavioral | **必須:** Controller restart → HELLO seq0、Cell ACTIVE `last_rx_seq=0` → `BOOTSTRAP_EPOCH_RESTART` で accept → `HELLO_RECEIVED` |
| `U4-G-RESTART-SEQ0-LAST-HIGH` | golden / behavioral | **必須:** Controller restart → HELLO seq0、Cell ACTIVE `last_rx_seq` high → `BOOTSTRAP_EPOCH_RESTART` で accept → `HELLO_RECEIVED` |
| `U4-G-RESTART-ACK-HIGH-BASELINE` | golden / behavioral | **必須:** Controller restart 後、Cell が high TX sequence で HELLO_ACK → Controller **SBR-ACK** で high seq を baseline accept → ACTIVE |
| `U4-G-CELL-RESTART-ACK0-RETRY` | golden / behavioral | **必須:** Cell restartでTX/RX cold、Controllerは旧RX baseline保持。liveness後のhigh HELLOをCellがSBR-HELLO受理しACK seq0を返す。Controllerはregressとしてreject + RX-only cold + session fenceし、直ちに次HELLOを送る。Cell ACK seq1をControllerがSBR-ACKで受理して有限回復 |
| `U4-G-CELL-RXCOLD-HIGH-HELLO` | golden / behavioral | **必須:** Cell が gap/overflow で **RX-only cold** + session INVALID 後、Controller high `next_tx_seq` HELLO → Cell **SBR-HELLO** → Cell TX 継続 sequence で ACK |
| `U4-G-CTRL-RXCOLD-HELLO-HIGH-ACK` | golden / behavioral | **必須:** Controller が gap で **RX-only cold** 後、直ちに `next_tx_seq` HELLO → Cell half-open/ACK high → Controller **SBR-ACK** または通常連続 |
| `U4-G-CELL-CONTINUITY-RESET-SESSION` | golden / behavioral | **必須:** Cell ACTIVE continuity-loss → pre-fence snapshot + atomic fence + `RESET_SESSION` notice 最大 1（snapshot header / 継続 seq）; WOULD_BLOCK でも fence 非 rollback; **raw-adapter TX accept で通常 RESET_SESSION sender fence を再実行しない**（fence once）; accept のみ sequence 消費 |
| `U4-G-CONTINUITY-RESET-NOTICE-CANCEL-ON-HELLO` | golden / behavioral | **必須:** pending not-yet-adapter-accepted continuity-loss notice がある状態で Cell が valid HELLO を新 session へ受理 → **atomic cancel** + `continuity_reset_notice_cancelled++`; cancel は NCG1 sequence 非消費 |
| `U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK` | golden / behavioral | **必須:** continuity-loss notice が raw-adapter accept 済みのあと HELLO_ACK を送る場合、**strict FIFO** で notice が HELLO_ACK より先; reorder 禁止 |
| `U4-N-CONTINUITY-RESET-STALE-NEW-SESSION` | negative / behavioral | 旧 pre-fence snapshot の遅着 RESET: **§8.1 sequence validation/accept が先**。連続 seq なら `last_rx_seq` 前進後、NCL1 不一致で drop/reject。**control state/session 不変**; sequence を rollback しない; 新 session を fence しない。非 ACTIVE 遅着も同順（idempotent drop）。**stale RESET に SBR/baseline 特権なし**。dup/regress は通常 reject; gap/reserved は通常 RX-only-cold |
| `U4-N-CONTINUITY-RESET-STALE-SEQ-ADVANCE` | negative / behavioral | **必須:** 連続 stale RESET（active mismatch または non-active）が sequence accept で `last_rx_seq` を進め、semantic drop 後も **sequence を戻さない / 新 session を fence しない** ことを固定（「state/sequence とも不変」実装は不合格） |
| `U4-N-SEQ-U32-MAX` | negative | wire `sequence == UINT32_MAX` を SBR/BOOTSTRAP より前に reject + `ncg1_reject_seq_reserved` + session INVALID + RX-only cold |
| `U4-N-HELLO-ACTIVE-COOKIE-REJECT` | negative（**禁止実装**の反例） | `SESSION_ACTIVE` 中の valid HELLO を「cookie≠active」だけで reject し **旧 session 維持** → **不合格** |
| `U4-N-HELLO-RETRY-SEQ0-COLD` | negative（**禁止実装**の反例） | 同一 process HELLO timeout で sequence cold + seq0 再送し、Cell `last_rx_seq=0` ACTIVE が duplicate 永久停止 → **不合格** |
| `U4-N-SEQ-DISCARD-NO-NCL1-PEEK` | negative（**禁止実装**の反例） | dup/regress を sequence 段で無条件 discard し valid HELLO の `BOOTSTRAP_EPOCH_RESTART` 不能 → **不合格** |
| `U4-N-ACK-BASELINE-NONMATCH` | negative | baseline 未成立時に **non-matching** HELLO_ACK（任意 seq）→ reject + baseline にしない |
| `U4-N-BASELINE-NONHELLO` | negative | baseline 未成立時に **arbitrary non-HELLO**（例: PING/DATA 業務）任意 seq → reject + `ncg1_reject_baseline`（SBR 対象外） |
| `U4-N-HELLO-INVALID-ROLE` | negative | Controller が HELLO を RX → reject + `hello_invalid_role`、initiator を捨てない |
| `U4-N-HELLO-BAD-BOOTSTRAP` | negative | HELLO なのに gen≠0 または cookie≠0 → reject + `hello_invalid_bootstrap`（bootstrap 例外なし） |
| `U4-G-DUP-HELLO-RECEIVED` | golden | Cell `HELLO_RECEIVED` 中の duplicate valid HELLO → 旧応答破棄、新 request に ACK |

## 6. Backpressure と raw CDC non-custody

### 6.1 Backpressure

1. raw TX ring full → 送信 API は **`WOULD_BLOCK`**（または同等 private status）。busy-spin で Core を止めない。
2. raw RX は §4.5。
3. logical ingress full → 新規 NCL1 accept 拒否。
4. backpressure を Application `PARKED_RETRY` や `DURABLY_RECORDED` に写像しない。

### 6.2 Raw CDC non-custody（MUST）

次は **いずれも Transport Custody でも Application Receipt でもない**:

| 観測 | 意味しないこと |
| --- | --- |
| `write()` / TinyUSB queue 成功 | peer が frame を受理した |
| NCG1 encode 成功 | peer が logical message を適用した |
| NCG1 decode 成功 | Transport Custody durable commit |
| PONG 受信 | assignment / Site Membership / Attachment / RF TX 許可 |
| HELLO 完了 | Site Membership / Attachment / security session |

Cell Agent の Transport Custody と Application Receipt の分離は [01](01-architecture.md) / [14](14-foundation-ports-and-simulator.md) / [19](19-m3-control-byte-stream-framing.md) に従う。**raw CDC ring は volatile** であり、power-cut 後に再送責任を持たない。

## 7. NCG1 上の最小 logical control envelope（private）

### 7.1 位置と version domain 分離

| Domain | 識別 | U0/U4 規範 | 将来 |
| --- | --- | --- | --- |
| **NCG1 frame format** | docs/19 `version` byte | exact 1 | framing v2 は別 major |
| **NCL1 envelope format** | header `logical_version` | **exact 1**。`!=1` は **bootstrap 前でも reject**（HELLO も例外なし） | v2 は新 magic または logical_version=2 + 別 freeze。v1 実装は v2 を受理しない |
| **Negotiated control protocol version** | HELLO `min/max/selected_control_version`（u16） | U4 は **1 のみ**（semantic catalog: HELLO/PING/PONG/RESET） | 将来 2+ は catalog 拡張。**NCL1 logical_version とは別 domain**（[06章](06-versioning-and-compatibility.md)） |
| Secure radio wire | 未割当 | **unallocated** | R6 |
| Public C ABI | 変更なし | NCL1 を public 化しない | 別 ADR |

規則:

1. peer が `logical_version != 1` の NCL1 を送ったら **negotiate せず reject**（`ERR_VERSION` / framing drop + stats）。
2. `logical_version=1` でも `selected_control_version` 交差が空なら `HELLO_VERSION_MISMATCH`。
3. control protocol v2 を導入しても NCL1 envelope v1 を流用してよいが、**version 番号空間を共有しない**（文書と test で別名）。
4. NCL1 は **authentication ではない**。CRC/NCG1 成功 ≠ 信頼できる peer。

### 7.2 NCL1 header（DATA type payload および構造化 control body）

全 multi-byte は **unsigned big-endian**。C struct の `memcpy` / host endian / padding に依存しない。

```text
offset  size  field
0       4     logical_magic       exact ASCII "NCL1" = 4e 43 4c 31
4       1     logical_version     exact 1
5       1     message_type        closed catalog §7.3
6       2     flags               u16 BE; v1 reserved = 0 only
8       4     request_id          u32 BE; 0 = no correlation (only where allowed)
12      4     session_generation  u32 BE; 0 only when §7.4 が明示許可
16      8     session_cookie      u64 BE; 0 only when §7.4 が明示許可;
                                  else MUST equal active session_cookie (≠0)
24      2     body_length         u16 BE; 0..MAX_NCL1_BODY
26      B     body                exact body_length bytes
```

| 定数 | 値 |
| --- | ---: |
| `NCL1_HEADER_BYTES` | **26** |
| `MAX_NCG1_PAYLOAD` | 1024（docs/19） |
| `MAX_NCL1_BODY` | **998**（`1024 - 26`） |
| `MAX_NCL1_MESSAGE` | **1024**（header+body が NCG1 payload に exact fit） |

規則:

1. `logical_version != 1` → reject（silent ignore 禁止）。
2. `flags != 0` → reject。
3. `body_length > 998` → reject。
4. `26 + body_length` が NCG1 `payload_length` と **不一致** → reject。
5. unknown `message_type` → reject（skip 成功にしない）。
6. `session_cookie` は **header が唯一の wire authority**。HELLO_ACK body に cookie を重複搭載しない。
7. §7.4 が `session_cookie ≠ 0` を要求する message で cookie=`0` → reject。
8. `SESSION_ACTIVE` で §7.4 が active 一致を要求する message の cookie が active と不一致 → reject（generation 不一致と同じ fence 方針）。

### 7.3 message_type catalog と NCG1 type closed matrix（U1–U4 minimal）

**名前空間:** NCG1 header `type`（docs/19 §5）と NCL1 header `message_type`（本節）は **独立した数値名前空間**である。値が偶然重なっても同一枚举ではない（例: NCG1 `PING=0x01` と NCL1 `HELLO=0x01` は **別 field**。混同して「type=1 は常に PING」と解釈してはならない）。U0 は未実装のため値の再割当は可能だったが、本 freeze は **現行値を固定**し、混同防止を validation 順と named reject で閉じる。

#### 7.3.1 NCL1 message_type catalog

| message_type | 値 | body | 相関 |
| --- | ---: | --- | --- |
| `HELLO` | `0x01` | §8.4 | request: non-zero `request_id` |
| `HELLO_ACK` | `0x02` | §8.4 | response: 同じ `request_id` |
| `CTRL_ERROR` | `0x03` | §8.6 | optional; 参照 request があれば echo |
| `PING_BODY` | `0x10` | §8.2 | request: non-zero |
| `PONG_BODY` | `0x11` | §8.2 | response: echo request_id |
| `RESET_BODY` | `0x12` | §8.3 | request: non-zero; **no-ack**（§8.3） |

`0x00` および未記載値は v1 reject + counter `ncl1_reject_unknown_message_type`。

#### 7.3.2 Closed exact binding matrix（NCG1 `type` × NCL1 `message_type`）

U4 USB control path では、受理してよい組合せは下表の **✓ のみ**。それ以外は **必ず reject**（silent accept 禁止）。「典型」「推奨」ではない。

| NCL1 message_type ↓ \ NCG1 type → | `PING` 0x01 | `PONG` 0x02 | `DATA` 0x03 | `RESET` 0x04 | other |
| --- | :---: | :---: | :---: | :---: | :---: |
| `HELLO` 0x01 | ✗ | ✗ | **✓** | ✗ | ✗ |
| `HELLO_ACK` 0x02 | ✗ | ✗ | **✓** | ✗ | ✗ |
| `CTRL_ERROR` 0x03 | ✗ | ✗ | **✓** | ✗ | ✗ |
| `PING_BODY` 0x10 | **✓** | ✗ | ✗ | ✗ | ✗ |
| `PONG_BODY` 0x11 | ✗ | **✓** | ✗ | ✗ | ✗ |
| `RESET_BODY` 0x12 | ✗ | ✗ | ✗ | **✓** | ✗ |
| unknown / 0x00 | ✗ | ✗ | ✗ | ✗ | ✗ |

**Named reject（必須例）:**

| 違反 | counter（§8.10） | error_code（送る場合） |
| --- | --- | --- |
| `PING_BODY` inside NCG1 `DATA`（または PONG/RESET） | `ncl1_reject_type_binding` | `ERR_TYPE_BINDING` |
| `HELLO` / `HELLO_ACK` / `CTRL_ERROR` inside NCG1 `PING`（または PONG/RESET） | `ncl1_reject_type_binding` | `ERR_TYPE_BINDING` |
| `PONG_BODY` inside non-`PONG` | `ncl1_reject_type_binding` | `ERR_TYPE_BINDING` |
| `RESET_BODY` inside non-`RESET` | `ncl1_reject_type_binding` | `ERR_TYPE_BINDING` |
| unknown `message_type`（binding 前） | `ncl1_reject_unknown_message_type` | `ERR_UNKNOWN_MESSAGE` |

NCG1 `type` 自体が docs/19 で unknown なら **NCL1 を解釈せず** framing 層で reject（既存 docs/19 規則）。

### 7.4 session_generation / session_cookie / request_id 許可表

| message | session_generation | session_cookie（NCL1 header） | request_id |
| --- | --- | --- | --- |
| `HELLO` | **0**（未確立） | **0** | **≠ 0** |
| `HELLO_ACK` OK | **≠ 0**（Cell が割当） | **≠ 0**（Cell CSPRNG; §5.2.1） | HELLO と同一 |
| `HELLO_ACK` error | **0** | **0** | HELLO と同一 |
| `PING_BODY` / `PONG_BODY` | active と一致 **≠ 0** | active と一致 **≠ 0** | PING ≠ 0; PONG は echo |
| `RESET_BODY`（**peer が SESSION_ACTIVE 中に送る通常 RESET**） | 受信側 **active と一致 ≠ 0** | 受信側 **active と一致 ≠ 0** | **≠ 0** |
| `RESET_BODY`（**Cell continuity-loss 通知; §5.6.1**） | **pre-fence snapshot** の旧 active gen **≠ 0**（送信時 active は既に INVALID） | **pre-fence snapshot** の旧 active cookie **≠ 0** | **≠ 0**（inflight 非登録） |
| `CTRL_ERROR` | active があれば **≠ 0** で一致必須。未確立時は **0** | active があれば active と一致 **≠ 0**。未確立時は **0** | 参照があれば echo、なければ 0 可 |

**全 active message**（`PING_BODY` / `PONG_BODY` / 通常 `RESET_BODY` / active 時 `CTRL_ERROR`）は header 上で **generation と cookie の両方**が **受信時点の active** と bit-exact 一致しなければならない。Cell continuity-loss の `RESET_SESSION` notice の例外は **送信側だけ**であり、送信側は **pre-fence snapshot** を載せる。**受信側に stale 許可例外はない:** 受信時点が `SESSION_ACTIVE` なら current active gen/cookie と一致する場合だけ RESET を受理して fence する。

**Stale / 遅着 continuity-loss RESET の受信順序（exact; active mismatch と non-active drop の両方に適用; §8.1 / §8.3 と同一）:**

1. **sequence validation/accept が先**（§8.1 step 1 / §5.5.2 通常規則）。stale RESET に **SBR / `BOOTSTRAP_EPOCH_RESTART` / baseline 特権はない**（NCL1 を見て sequence を特別 accept に変えない）。
2. **連続 stale RESET**（`have_rx_seq` かつ `seq == last_rx_seq + 1`）は sequence 段で **accept** し **`last_rx_seq` を前進**させる。その後 NCL1 意味検査で mismatch / non-active drop しても **control state / session は変更しない**。**sequence を rollback してはならない**。**新 session / current session を fence してはならない**。
3. **duplicate / regress** は通常 reject（該当 sequence counter; HELLO bootstrap 例外のみ §5.5.3）。stale RESET 専用の緩和なし。
4. **gap / 予約 `UINT32_MAX`** は通常の fail-closed（session INVALID + **RX-only cold** 等; §5.5.2）。stale ラベルで上書きしない。
5. **active mismatch:** 新 ACTIVE と gen/cookie 不一致 → NCL1 reject + `ncl1_reject_session_mismatch`（または相当）; session 維持。**non-active drop:** 非 ACTIVE への遅着 → idempotent drop + counter; session/state 維持。いずれも step 2 の sequence 前進は保持する。

cookie を HELLO_ACK にしか載せない設計は **U4 では禁止**（再起動後 generation 再利用に対する stale-frame fence が効かない）。**continuity-loss 後に pre-fence 以外の旧 gen/cookie の message を新規 TX することは禁止**（§5.6.1）。pending notice の sender lifecycle は §5.6.1（fence once / cancel-on-HELLO / FIFO / sequence consume）。

## 8. PING / PONG / RESET / HELLO 交渉（U1–U4）

### 8.1 共通 validation（exact order; 短縮・入替禁止）

受信側は次を **この順** で検査する。失敗した段で frame/message を破棄し、対応 counter（§8.10）を上げる。必要なら `CTRL_ERROR`（§8.7）。**後段の検査結果で前段をやり直して accept に変えてはならない**（ただし step 1 の **限定 peek** は §5.5.3 の SBR / `BOOTSTRAP_EPOCH_RESTART` 専用であり、通常 path の順序入替ではない）。

1. **NCG1 framing / stream / sequence** — docs/19 accept（magic/version/type/flags/len/**CRC**）+ U4 `stream_or_cell_id` + §5.5.2 sequence epoch。
   - **予約 terminal（必須; 最優先）:** framing 成功後・`stream_or_cell_id` 検査の前後どちらでもよいが、**SBR / `BOOTSTRAP_EPOCH_RESTART` / 通常 baseline / 通常連続 `last+1` の判定より必ず前**に `sequence == UINT32_MAX` を検査する。該当なら **最終 reject** + `ncg1_reject_seq_reserved++` + session INVALID + **RX-only cold** + local TX 継続。**NCL1 peek しない**（HELLO でも accept しない）。
   - **通常:** sequence が accept / baseline 不成立 / gap で最終 reject なら **NCL1 を解釈しない**。
   - **限定例外 A（必須; baseline 未成立）:** framing 成功・`stream_or_cell_id=0`・NCG1 type **`DATA`**・`have_rx_seq == false`・**`seq != UINT32_MAX`** のとき、exact0 以外でも sequence 段で **無条件最終 discard してはならない**。payload を NCL1 として **peek** し、(Cell + Valid HELLO) なら §5.5.3 **SBR-HELLO**、(Controller + HELLO_SENT + matching sole HELLO inflight `request_id` の valid HELLO_ACK) なら §5.5.3 **SBR-ACK** を **atomic accept** して step 2 以降へ。どちらでもなければ通常 baseline 不成立 reject（**non-HELLO / non-matching ACK は baseline にしない**）。
   - **限定例外 B（必須; dup/regress）:** sequence が **duplicate または 後退** であり、かつ framing 成功・`stream_or_cell_id=0`・NCG1 type **`DATA`**・**`seq != UINT32_MAX`** のとき、sequence 段で **無条件最終 discard してはならない**。payload を NCL1 として **peek** し、exact Valid HELLO bootstrap なら §5.5.3 `BOOTSTRAP_EPOCH_RESTART` を適用して step 2 以降を通常 HELLO path として続行する。valid HELLO でなければ通常 dup/regress 終了（NCL1 業務解釈なし）。gap には peek 例外を適用しない。
2. **NCL1 最低長 / header / version / flags / length** — payload ≥ `NCL1_HEADER_BYTES`(**26**); `logical_magic` exact `"NCL1"`; `logical_version` exact 1; `flags` exact 0; `body_length` ≤ `MAX_NCL1_BODY`(**998**); `26 + body_length` が NCG1 `payload_length` と exact 一致。
3. **`message_type` 判明** — catalog §7.3.1 の既知値であること。unknown → reject + `ncl1_reject_unknown_message_type`（body を業務解釈しない）。
4. **exact NCG1-type binding** — §7.3.2 closed matrix。例: `PING_BODY` inside `DATA`、`HELLO` inside `PING` は **必ず** reject + `ncl1_reject_type_binding`（`ERR_TYPE_BINDING`）。
5. **body layout** — 当該 `message_type` の exact body_length と field 配置（§8.2–§8.6）。
6. **generation / cookie / request_id** — §7.4 / §5.2 / §5.5.1。**HELLO bootstrap は gen=0,cookie=0 が合法**であり、active cookie 一致検査を適用しない（§5.6）。active 向け message のみ active 一致。HELLO_ACK は sole inflight `request_id` 一致（SBR-ACK 含む）。
7. **reserved** — body/header の reserved が 0。state 固有規則（例: PING は `SESSION_ACTIVE` のみ）は本段の後、または §7.4 と同時に適用してよいが、**type binding より前に state/cookie で落として HELLO half-open を潰してはならない**。

### 8.2 PING / PONG（opaque echo token; wall clock 禁止）

NCG1 type `PING` / `PONG` の payload は **NCL1** とする（U-series）。empty PING（payload_length=0）は **liveness 非適合** として U4 では reject。

**PING body**（`message_type=PING_BODY`）:

```text
offset  size  field
0       8     opaque_echo_token   u64-as-bytes; caller-chosen opaque
                                  （CSPRNG 推奨。wall clock / unix_ms 禁止）
```

body_length exact **8**。

**PONG body**（`message_type=PONG_BODY`）:

```text
offset  size  field
0       8     opaque_echo_token   PING と bit-exact echo
```

body_length exact **8**。

規則:

1. PONG は同一 `request_id` + `opaque_echo_token` + active `session_generation` + **active `session_cookie`（header）** のときだけ受理。
2. PING は `SESSION_ACTIVE` のみ。未 session での PING は ignore + counter（HELLO を促す）。
3. PONG 欠落は liveness failure（§8.11）。Site Membership / Attachment / RF TX を自動開始しない。
4. **`sender_unix_ms` / あらゆる wall-clock フィールドは body に存在しない**（廃止）。liveness は **monotonic clock のみ**（§8.11）。
5. PING/PONG の NCL1 header `session_cookie` が 0 または active 不一致 → reject（body token の成否より先に §8.1 順で落ちる）。

### 8.3 RESET（no-ack; 双方送信可）

NCG1 type `RESET`、payload は NCL1 `RESET_BODY`。**送信 role:** Controller と Cell の **双方**が `RESET_BODY` を送ってよい（§5.6 送信 role matrix）。

```text
offset  size  field
0       1     reset_code     closed §8.3.1
1       3     reserved       exact 0
```

body_length exact **4**。

**request_id authority（RESET）:** header `request_id` は **送信端 local allocator から nonzero**。**no-ack のため inflight map へ入れない**（§5.5.1）。ACK 待ち・timeout・matching 応答経路を作ってはならない。

#### 8.3.1 reset_code

| code | 名前 | 送信 accept 時の **当該端** local 動作 | 受信時の **当該端** local 動作 | sequence（各端） | Controller re-HELLO |
| ---: | --- | --- | --- | --- | --- |
| 0x01 | `RESET_SESSION` | session fence → `LINK_UP_NO_SESSION`。parser は維持可 | 同左（受信端も session fence） | **各端とも TX+RX sequence 継続**（cold しない; §5.5.2） | **Controller-only** `next_tx_seq`（sole initiator） |
| 0x02 | `RESET_PARSER` | **送信端:** local **RX parser + RX sequence epoch のみ cold** + session INVALID → `LINK_UP_NO_SESSION`。**送信端 local TX `next_tx_seq` は継続** | **受信端:** local **RX parser + RX sequence epoch のみ cold** + session INVALID → `LINK_UP_NO_SESSION`。**受信端 local TX は継続** | **各端とも RX-only cold; 各端 local TX 継続**（相手端の epoch を wire だけで書き換えない） | Controller は `next_tx_seq` で HELLO（**自 TX は cold していない**） |
| 0x03 | `RESET_LINK` | **session 即 INVALID** → `LINK_UP_NO_SESSION` + adapter に link restart 要求（close/reopen 可） | **session 即 INVALID**（同左）+ 必要なら local も restart 要求 | sequence は **即 cold しない**。**観測した link reopen** で **当該端 TX+RX 双方 cold**（§5.5.2 物理 link down→up） | reopen 観測後 HELLO **seq0**（双方 cold 後） |

unknown code → reject。

**RESET は no-ack（必須）:**

1. RESET に対する **専用 ACK message は存在しない**。`HELLO_ACK` / `PONG_BODY` / `CTRL_ERROR` を RESET の確認応答に流用しない。
2. 受信側は RESET を受理したら **ローカルで** 上表どおり session/parser/link を fence し、structured counter を上げる。**`RESET_SESSION` だけで双方 sequence を無条件 0 にしてはならない。** **`RESET_PARSER` は送信 accept 端と受信端のそれぞれで local RX のみ cold**し、**各端の local TX は継続**する（「どちらか一方だけ」「TX も cold」と読んではならない）。
3. 再通信は **Controller の re-HELLO** からのみ（sole initiator）。Cell は HELLO を送らない。
4. Controller は RESET **送信 accept 後**および **peer RESET 受信後**、§8.11 の **local re-HELLO timer**（monotonic）で HELLO を再送する。ACK 待ちでデッドロックしない。`RESET_SESSION` / `RESET_PARSER`（TX 継続）後は **`next_tx_seq`**。`RESET_LINK` で reopen 観測後は seq0。
5. 旧 generation / cookie の request は全て fence。Application Outcome に昇格しない。Cell continuity-loss の `RESET_SESSION` 送信は §5.6.1 **pre-fence snapshot** を header に載せる（§7.4）。**pending notice lifecycle:** sender fence は検出/作成時に 1 回だけ; raw-adapter TX accept で通常 `RESET_SESSION` sender fence を再実行しない; not-yet-accepted notice は valid HELLO 新 session 遷移直前に atomic cancel + `continuity_reset_notice_cancelled++`（sequence 非消費）; already-accepted は HELLO_ACK より strict FIFO 先; accept 時のみ sequence 消費。
6. **`RESET_LINK` は補助**であり、RX continuity loss の **唯一の必須脱出口にしない**（§5.6.1）。session は受理で **即 INVALID**だが、sequence cold は **観測 reopen** に紐づく。
7. RESET を **物理 Link down と同義に扱わない**（§5.2 規則1）。`RESET_SESSION` / `RESET_PARSER` 後も link up のまま HELLO 回復してよい。
8. continuity-loss RESET の **pre-fence snapshot は送信権限だけ**を与える。受信側は current `SESSION_ACTIVE` gen/cookie と一致する場合だけ受理して current session を fence する。**Stale / 遅着（active mismatch と non-active drop の両方）:** **sequence validation/accept が先**。連続 stale RESET は `last_rx_seq` を前進させたうえで NCL1 semantic mismatch/drop し、**control state/session は不変**; **sequence を rollback しない**; **新 session を fence しない**。duplicate/regress は通常 reject。gap/reserved は通常 RX-only-cold。**stale RESET に SBR/baseline 特権なし**。非 ACTIVE 遅着は idempotent drop + counter（session 不変; 連続なら sequence 前進は保持）。

### 8.4 HELLO / HELLO_ACK

NCG1 type `DATA`、NCL1 `HELLO` / `HELLO_ACK`。**Controller → Cell のみ HELLO。**

**HELLO body**:

```text
offset  size  field
0       2     min_control_version   u16 BE; U4 では 1
2       2     max_control_version   u16 BE; U4 では 1; min<=max
4       2     flags_supported       u16 BE; v1 は 0 のみ
6       2     reserved              exact 0
```

body_length exact **8**。

**HELLO_ACK body**（cookie は **含めない** — NCL1 header が authority）:

```text
offset  size  field
0       2     selected_control_version  u16 BE; must ∈ [peer min, peer max] ∩ local
2       2     flags_selected            u16 BE; v1 は 0
4       2     result_code               u16 BE; §8.4.1
6       2     reserved                  exact 0
```

body_length exact **8**。

**HELLO_OK 時と error 時の header 規約（§7.4 再掲）:**

| result | NCL1 header `session_generation` | NCL1 header `session_cookie` | body |
| --- | --- | --- | --- |
| `HELLO_OK` | **≠ 0**（Cell 割当） | **≠ 0**（§5.2.1 CSPRNG; **規約上の「未使用/未確立」値 0 ではない**） | 上表 8 bytes |
| error（`VERSION_MISMATCH` / `BUSY` / `DENIED`） | **0** | **0** | 上表 8 bytes |

`session_cookie` は wall clock ではない。HELLO_ACK **body に cookie フィールドは存在しない**（旧 16-byte body の cookie 重複 layout は廃止）。

#### 8.4.1 HELLO result_code

| code | 名前 | session_generation wire | session_cookie wire | 次状態 |
| ---: | --- | --- | --- | --- |
| 0x0000 | `HELLO_OK` | **≠ 0**（Cell 割当） | **≠ 0**（CSPRNG） | `SESSION_ACTIVE`（§5.2 ACTIVE 遷移点） |
| 0x0001 | `HELLO_VERSION_MISMATCH` | **0** | **0** | session 不成立 |
| 0x0002 | `HELLO_BUSY` | **0** | **0** | 一時的拒否。Controller が再試行可。CSPRNG 不能時もこれを返してよい |
| 0x0003 | `HELLO_DENIED` | **0** | **0** | 永続的拒否（identity 未準備等） |

規則:

1. Controller のみ HELLO（`session_generation=0`, `session_cookie=0`, `request_id≠0`）。
2. Cell は交差 control protocol version を選び、OK 時は **新規 generation + header session_cookie** を載せる。CSPRNG 不能なら **HELLO_OK を出さない**（§5.2.1）。
3. Controller は `request_id` 一致・`HELLO_OK`・version 一致・header `generation≠0`・header `cookie≠0` でのみ `SESSION_ACTIVE`。
4. HELLO 成功は **security session 完了を意味しない**。
5. **node_fingerprint フィールドは存在しない**。
6. HELLO_OK 後の active PING/PONG/RESET は **同一 cookie を header で毎回検証**する（body に cookie を再送しない）。

### 8.5 交渉シーケンス（規範シナリオ）

```text
Controller                         Cell Agent
    | link open / CDC up                |
    |--------- NCG1 DATA: HELLO ------->|
    |<-------- NCG1 DATA: HELLO_ACK ----|
    |       SESSION_ACTIVE both         |
    |--------- NCG1 PING -------------->|
    |<-------- NCG1 PONG ---------------|
    |--------- NCG1 RESET (optional) -->|
    |       back to LINK_UP_NO_SESSION  |
```

### 8.6 CTRL_ERROR body

```text
offset  size  field
0       2     error_code     u16 BE; §8.6.1
2       2     reserved       0
4       4     related_request_id  u32 BE; 0 if none
```

body_length exact **8**。

#### 8.6.1 error_code（初期）

| code | 名前 |
| ---: | --- |
| 0x0001 | `ERR_INVALID_NCL1` |
| 0x0002 | `ERR_UNKNOWN_MESSAGE` |
| 0x0003 | `ERR_SESSION_MISMATCH` |
| 0x0004 | `ERR_STATE` |
| 0x0005 | `ERR_CAPACITY` |
| 0x0006 | `ERR_VERSION` |
| 0x0007 | `ERR_TYPE_BINDING` |

### 8.7 CTRL_ERROR 応答禁止と rate / budget / fence（error loop 閉鎖）

| 規則 | 規範 |
| --- | --- |
| **CTRL_ERROR への CTRL_ERROR 禁止** | `message_type=CTRL_ERROR` を受けて **さらに CTRL_ERROR を返してはならない**。stats のみ |
| 自己励起禁止 | CTRL_ERROR 送信失敗・encode 失敗を理由に CTRL_ERROR を再送しない |
| rate budget | 同一 session（または link 未確立時は同一 link）あたり **sliding 1 秒で最大 8 件**。超過分は drop + counter |
| burst fence | 連続 32 件の logical reject（CTRL_ERROR 送信有無を問わず）で `RESET_SESSION` 相当の local fence を行い HELLO から再開 |
| secret | error body / log に key material を出さない（[05章](05-security-and-compliance.md)） |
| framing 失敗 | docs/19 resync。必ずしも CTRL_ERROR を送らない（byte 境界が信頼できないため） |

### 8.8 エラー処理原則（その他）

1. logical 失敗で USB link を必ず切る必要はない（overflow fence は除く）。
2. session mismatch は message reject。連続しきい値（実装 MAY: 16）で RESET_SESSION を送ってよい。
3. U4 は **fail-closed**: 不明 version / 不明 type / reserved ≠0 は受理しない。

### 8.9 Golden / negative vector 要件と必須 gate 化タイミング

| 時期 | 要件 |
| --- | --- |
| **U0（本章）** | vector **ID と意味**を固定。fixture ファイル自体は未必須 |
| **U4 実装 PR** | 下表 ID の **実 vector ファイル**（JSON または docs/19 同型）を追加し、independent generator + production codec **bridge** を **Required host gate** にする。compile-only 不可 |
| U4 以降 | vector 改変が bridge を落とす自己検査を CI に含める |

| ID | 種別 | 内容 |
| --- | --- | --- |
| `U4-G-HELLO-OK` | golden | HELLO → HELLO_ACK OK の exact bytes（NCG1+NCL1; header gen+cookie; HELLO_ACK body **8**; `stream_or_cell_id=0`; sequence 規則） |
| `U4-G-PING-PONG` | golden | SESSION_ACTIVE 上の PING/PONG opaque token echo（**header cookie が active と一致**） |
| `U4-G-RESET-SESSION` | golden | RESET_SESSION 後に旧 generation/cookie PING が reject |
| `U4-N-BAD-MAGIC` | negative | NCL1 magic 破壊 |
| `U4-N-VER` | negative | logical_version≠1 |
| `U4-N-FLAGS` | negative | flags≠0 |
| `U4-N-BODY-LEN` | negative | body_length 不一致 / overflow（`MAX_NCL1_BODY=998`） |
| `U4-N-REQ-ZERO` | negative | HELLO/PING で request_id=0 |
| `U4-N-SESS-ZERO` | negative | PING で session_generation=0 |
| `U4-N-COOKIE-ZERO` | negative | PING で session_cookie=0（active 文脈） |
| `U4-N-STALE-GEN` | negative | 旧 generation（cookie 一致でも reject） |
| `U4-N-STALE-COOKIE` | negative | generation 一致・**cookie 不一致**（再起動 collision fence） |
| `U4-N-HELLO-OK-COOKIE-ZERO` | negative | HELLO_ACK OK なのに header cookie=0 |
| `U4-N-STREAM-ID` | negative | U4 control path で `stream_or_cell_id != 0` |
| `U4-N-SEQ-GAP` | negative | NCG1 sequence gap → session INVALID + **RX-only** parser/RX cold（TX 継続） |
| `U4-N-SEQ-U32-MAX` | negative | wire `sequence == UINT32_MAX` → reject + `ncg1_reject_seq_reserved` + session INVALID + **RX-only cold**（SBR/BOOTSTRAP/通常 baseline **より前**; last+1 wrap 禁止） |
| `U4-N-SEQ-DUP` | negative | NCG1 sequence duplicate/replay |
| `U4-G-CELL-CONTINUITY-RESET-SESSION` | golden / behavioral | Cell ACTIVE で gap/overflow 検出 → **pre-fence snapshot** + atomic fence + 高優先 `RESET_SESSION` notice **最大 1**（header=snapshot, seq=継続 `next_tx_seq`）; WOULD_BLOCK でも fence 非 rollback; **raw-adapter TX accept で通常 RESET_SESSION sender fence 再実行禁止**（fence once）; accept のみ sequence 消費 |
| `U4-G-CONTINUITY-RESET-NOTICE-CANCEL-ON-HELLO` | golden / behavioral | pending not-yet-accepted notice + valid HELLO 新 session 遷移 → atomic cancel + `continuity_reset_notice_cancelled++`; cancel は NCG1 sequence 非消費 |
| `U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK` | golden / behavioral | already raw-adapter-accepted notice は後続 HELLO_ACK より **strict FIFO 先**; reorder 禁止 |
| `U4-N-CONTINUITY-RESET-STALE-NEW-SESSION` | negative / behavioral | 旧 snapshot 遅着 RESET: sequence validation/accept が先; 連続なら `last_rx_seq` 前進後 NCL1 drop/reject; control state/session 不変; sequence rollback 禁止; 新 session fence 禁止; stale に SBR/baseline 特権なし（active mismatch と non-active drop の両方） |
| `U4-N-CONTINUITY-RESET-STALE-SEQ-ADVANCE` | negative / behavioral | 連続 stale RESET が `last_rx_seq` を進め semantic drop 後も sequence を戻さないこと（「sequence も不変」実装は不合格） |
| `U4-N-UNKNOWN-TYPE` | negative | message_type 未定義 |
| `U4-N-EMPTY-PING` | negative | NCG1 PING payload_length=0 を session 層 reject |
| `U4-N-CTRL-ERROR-LOOP` | negative | CTRL_ERROR に CTRL_ERROR を返さない |
| `U4-N-COOKIE-RNG-FAIL` | negative / behavioral | Cell CSPRNG 不能時に HELLO_OK を出さない（fail-closed） |
| `U4-N-TYPE-BIND-PING-IN-DATA` | negative | `PING_BODY` inside NCG1 `DATA` → reject + `ncl1_reject_type_binding` / `ERR_TYPE_BINDING` |
| `U4-N-TYPE-BIND-HELLO-IN-PING` | negative | `HELLO` inside NCG1 `PING` → reject + `ncl1_reject_type_binding` / `ERR_TYPE_BINDING` |
| `U4-G-HALFOPEN-REHELLO` | golden / behavioral | §5.6.2 half-open: ACTIVE 中 valid HELLO（連続 seq）→ session fence → 新 session |
| `U4-G-HELLO-RETRY-NEXT-SEQ` | golden / behavioral | §5.6.2 同一 process HELLO timeout → **`next_tx_seq`** 再送（cold しない） |
| `U4-G-ACKLOSS-LAST0-HALFOPEN` | golden / behavioral | §5.6.2 **必須:** ACK 喪失・Cell `last_rx_seq=0` ACTIVE → seq1 HELLO half-open |
| `U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE` | golden / behavioral | §5.6.2 **必須:** reverse ACK loss seq1 → Controller **SBR-ACK** baseline |
| `U4-G-RESTART-SEQ0-LAST0` | golden / behavioral | §5.6.2 **必須:** Controller restart・Cell last=0 → `BOOTSTRAP_EPOCH_RESTART` |
| `U4-G-RESTART-SEQ0-LAST-HIGH` | golden / behavioral | §5.6.2 **必須:** Controller restart・Cell last high → `BOOTSTRAP_EPOCH_RESTART` |
| `U4-G-RESTART-ACK-HIGH-BASELINE` | golden / behavioral | §5.6.2 **必須:** Controller restart 後 high HELLO_ACK → **SBR-ACK** |
| `U4-G-CELL-RESTART-ACK0-RETRY` | golden / behavioral | §5.6.2 **必須:** Cell restart ACK seq0 regress → Controller RX-only cold + immediate re-HELLO → 次ACKをSBR-ACKで受理 |
| `U4-G-CELL-RXCOLD-HIGH-HELLO` | golden / behavioral | §5.6.2 **必須:** Cell RX-only cold 後 high HELLO → **SBR-HELLO** + continued ACK |
| `U4-G-CTRL-RXCOLD-HELLO-HIGH-ACK` | golden / behavioral | §5.6.2 **必須:** Controller RX-only cold 後 HELLO + high ACK |
| `U4-N-HELLO-RETRY-SEQ0-COLD` | negative（禁止実装） | 同一 process timeout で cold+seq0 → last0 ACTIVE 永久停止 |
| `U4-N-SEQ-DISCARD-NO-NCL1-PEEK` | negative（禁止実装） | dup/regress を無条件 discard し bootstrap restart 不能 |
| `U4-N-ACK-BASELINE-NONMATCH` | negative | non-matching ACK を baseline にしない |
| `U4-N-BASELINE-NONHELLO` | negative | arbitrary non-HELLO を baseline にしない |
| `U4-N-HELLO-INVALID-ROLE` | negative | Controller 側 HELLO RX reject |
| `U4-N-HELLO-BAD-BOOTSTRAP` | negative | HELLO で gen≠0 または cookie≠0 |

### 8.10 Structured counter 最小 catalog（private; U4/U7 安定集合）

本節は **conformance / diagnostics に必要な安定集合**だけを固定する。実装内部の細 counter 追加は同一 PR で本章へ足すか、U7 で private 拡張してよいが、**下表の名前・意味・飽和・reset 方針は変更時に docs+gate 更新必須**。

| 規則 | 規範 |
| --- | --- |
| 型 | 各 counter は **u64**。加算は **saturating**（`UINT64_MAX` で止め、wrap しない） |
| 可視性 | production-private。public C ABI に出さない。U7 diagnostics export が snapshot を読む |
| reset | **process start / session object 新規作成**で 0。session fence や **HELLO 成功では reset しない**（累積観測）。明示 diagnostic reset API は U7 任意で、使うなら全 catalog 同時 |
| snapshot | 単一 reader 向けに **一貫した複写**（tear 読みを避ける）。export schema は U7 |
| 単位 | 「1 reject / 1 事象 = +1」。byte 数は別 counter を足す場合のみ |

| counter 名 | 意味 | 主に上がる reject / 事象 |
| --- | --- | --- |
| `rx_overflow` | RX raw ring が保持不能 | §4.5 overflow fence |
| `ncg1_reject_stream_id` | `stream_or_cell_id != 0`（U4） | §5.5.2 |
| `ncg1_reject_seq_gap` | sequence gap | §5.5.2 |
| `ncg1_reject_seq_dup` | sequence duplicate/replay | §5.5.2 |
| `ncg1_reject_seq_regress` | sequence 後退 | §5.5.2 |
| `ncg1_reject_seq_reserved` | wire `sequence == UINT32_MAX`（U4 予約 terminal） | §5.5.2 / §8.1（SBR/BOOTSTRAP より前） |
| `ncg1_reject_baseline` | epoch 先頭が sequence≠0 | §5.5.2 |
| `ncl1_reject_short` | payload < 26 | §8.1 step 2 |
| `ncl1_reject_magic` | magic ≠ NCL1 | §8.1 step 2 |
| `ncl1_reject_version` | logical_version ≠ 1 | §8.1 step 2 |
| `ncl1_reject_flags` | flags ≠ 0 | §8.1 step 2 |
| `ncl1_reject_body_len` | body_length / payload 不一致・oversize | §8.1 step 2 |
| `ncl1_reject_unknown_message_type` | message_type 未定義 | §8.1 step 3 |
| `ncl1_reject_type_binding` | §7.3.2 matrix 違反（PING_BODY in DATA、HELLO in PING 等） | §8.1 step 4 |
| `ncl1_reject_body_layout` | exact body 不一致 | §8.1 step 5 |
| `ncl1_reject_session_mismatch` | active gen/cookie 不一致（active 向け message） | §8.1 step 6 |
| `ncl1_reject_request` | request_id 規則違反・stale/replay 応答 | §5.5.1 |
| `ncl1_reject_state` | 状態不許可（未 ACTIVE の PING 等） | state rules |
| `ncl1_reject_reserved` | reserved ≠ 0 | §8.1 step 7 |
| `hello_invalid_role` | Controller が HELLO を RX 等 | §5.3 / §5.6 |
| `hello_invalid_bootstrap` | HELLO なのに gen/cookie ≠ 0 | §5.6 |
| `hello_halfopen_fence` | SESSION_ACTIVE 中 valid HELLO で fence 実行 | §5.6.1 |
| `hello_bootstrap_epoch_restart` | §5.5.3 `BOOTSTRAP_EPOCH_RESTART` 適用 | restart HELLO seq0 等 |
| `hello_baseline_resync` | §5.5.3 **SBR-HELLO**（Cell; baseline 未成立 + valid HELLO 任意 seq） | peer-continuation high HELLO |
| `hello_ack_baseline_resync` | §5.5.3 **SBR-ACK**（Controller; baseline 未成立 + matching HELLO_ACK 任意 seq） | reverse ACK loss / high ACK |
| `hello_retry` | Controller HELLO 再送（timeout path） | §8.11 |
| `session_fence_inflight_dropped` | fence で破棄した inflight 件数 | reconnect / half-open / RESET |
| `continuity_reset_notice_cancelled` | pending Cell continuity-loss `RESET_SESSION` notice を raw-adapter accept 前に cancel | §5.6.1 lifecycle (b): valid HELLO 新 session 遷移直前の atomic cancel（sequence 非消費） |
| `ctrl_error_rate_drop` | CTRL_ERROR rate budget 超過 drop | §8.7 |
| `pong_miss` | PONG timeout 1 回 | §8.11 |
| `ping_dispatch_miss` | PING dispatch/accept が `ping_dispatch_slack` 期限超過 | §8.11 |
| `liveness_fail` | miss threshold 到達、または ping_dispatch_miss 経路の session fence | §8.11 |

U7 は本 catalog を diagnostics に接続する（export / soak ログ）。名前安定性が conformance 契約である。

### 8.11 Liveness / HELLO retry profile default（monotonic clock only）

**時計:** liveness と retry の判定には **monotonic clock のみ**を用いる。wall clock / `sender_unix_ms` / NTP 補正は **禁止**（スリープや時計ステップで誤 fence しない）。

下表は **profile default**（U0 固定の開始値）。物理最適値ではない。**U7 HIL/soak 測定で同一 PR 更新可**（本章・test・診断の閾値を揃える）。half-open（§5.6.1）の有限時間回復は **fair-delivery assumption** の下でのみ主張する: USB byte stream が継続的に read/write 可能であり、かつ HELLO / HELLO_ACK の少なくとも一組が有限回の送信試行内に配送される場合、各 retry delay は `hello_retry_max`（**5000 ms**）上限のため待ちは有限。単なる link up だけでは delivery 保証にならない。無限 packet loss 下の回復保証は主張しないが、link up 中は HELLO retry を止めない。

| パラメータ | Default | 意味 |
| --- | ---: | --- |
| `ping_cadence` | **5000 ms** | `SESSION_ACTIVE` 中の PING 間隔下限（monotonic）。**基準:** 直前 PING について matching PONG を受理した時点、または `pong_timeout` 満了時点から起算し、その後 `ping_cadence` 経過してから次 PING を **送ってよい（eligible）**。送信 accept 直後からの単純壁時計間隔で多重送出しない |
| `ping_dispatch_slack` | **1000 ms** | PING が eligible になってから、Controller が NCG1 PING frame の **TX accept を完了しなければならない最遅 deadline**（monotonic）。`eligible_at + ping_dispatch_slack` までに accept 必須。**「送ってよい」だけを実装し永遠に PING しない / 遅延し続ける実装は不適合** |
| `pong_timeout` | **2000 ms** | 各 PING 送信 accept から matching PONG 待ち上限 |
| `pong_miss_threshold` | **3** | 連続 `pong_miss` がこの回数に達したら local session fence → `LINK_UP_NO_SESSION` + `liveness_fail++`。RF/Membership は触らない |
| `hello_initial_delay` | **0 ms** | link up 後、最初の HELLO まで（Controller） |
| `hello_retry_initial` | **200 ms** | HELLO_ACK 待ち timeout 初回 |
| `hello_retry_max` | **5000 ms** | HELLO backoff 上限（fair-delivery 下の有限時間回復の delay cap） |
| `hello_backoff_multiplier` | **2** | 失敗毎に timeout を ×2（上限で飽和） |
| `hello_retry_jitter` | **±20%** | timeout に対称 jitter（monotonic 上の乱択; 鍵用途ではない） |
| `hello_retry_unlimited_while_link_up` | **true** | link up かつ非 ACTIVE の間、HELLO retry を **停止しない**（上限回数で永久放棄して dead にしない）。無限 loss でも retry は継続するが回復は主張しない。実装は counter `hello_retry` で観測 |
| `rehello_after_reset_delay` | **hello_retry_initial** | 自 RESET 送信後または peer RESET 観測後、Controller が re-HELLO するまでの local timer |

規則:

1. Cell は PING initiator にならない（Controller-only liveness 送信）。Cell は PONG を返す。
2. **PING 同時 inflight 最大 1:** matching PONG 受理または `pong_timeout` 満了の前に次 PING を重ねない。cadence 起算は規則どおり「前回 PING の結果確定（PONG 受理 / timeout）後」。SESSION_ACTIVE 直後の **最初の PING** も、ACTIVE 遷移時点を `eligible_at` として `ping_dispatch_slack` 内に TX accept 必須（inflight=1 を維持したまま）。
3. **MUST dispatch/accept:** Controller は `SESSION_ACTIVE` 中、各 PING について `eligible_at + ping_dispatch_slack` までに adapter が frame bytes を **accept** すること。`WOULD_BLOCK` が deadline まで続く、または実装が PING を送らない場合 → `ping_dispatch_miss++` + **local session fence** → `LINK_UP_NO_SESSION` + `liveness_fail++` + Controller は **`next_tx_seq` で re-HELLO**（§5.6; sequence cold しない）。**SESSION_ACTIVE のまま永遠に PING しない実装は不適合。** **dispatch miss 後に fence/re-HELLO を省略して ACTIVE を維持する実装は不適合。**
4. PONG miss は **自動 re-HELLO** を Controller に許可する（fence 後 §5.6）。物理 unplug 必須にしない。
5. half-open: fair-delivery assumption の下、Cell が ACTIVE のままでも Controller HELLO retry 継続（**`next_tx_seq`**、cold しない）および §5.5.3 により §5.6.1 で有限時間回復。無限 packet loss では回復を主張しないが retry は止めない。
6. default 値変更は U7 測定ログを PR に残す。docs-only の憶測変更は禁止ではないが、HIL 未実施なら「測定確定」と書かない。

## 9. Physical radio boundary freeze（wire bytes は非固定）

### 9.1 固定すること

1. **Logical bearer message は radio/USB wire へ `memcpy` 直列化しない。** 必ず versioned encode。
2. **Foundation logical / virtual / loopback TxPermit は physical RF を認可しない。** TEST/loopback 専用（[14章](14-foundation-ports-and-simulator.md)、[22章](22-m3-owner-cell-agent-skeleton.md)）。`NIN-CMP-012`。
3. **Physical Compliance Permit が physical TX の唯一の認可エッジ**（sole physical TX edge; `NIN-CMP-001`〜`005`、`012`、`013`）。
4. **TX 順序**は §2.3 / ADR-0003 §3.2 のみ。

### 9.2 Physical TX 順序（再掲; Normative）

```text
(1) W1: secure wire/MAC が immutable TX plan / exact bytes を確定
(2) P1: Compliance Gate が SiteAssignment × HardwareProfile × RegulatoryProfile
        × live radio settings × ledger を検査・予約し、exact plan へ Permit 発行
(3) H1: sole transmit-with-permit 入口が re-validate + single-use consume
(4) D1: SX1262 SPI TX
```

Permit 発行後に bytes または PHY を変更してはならない。変更が必要なら (1) からやり直し。

### 9.3 Physical Compliance Permit binding（MUST; NIN-CMP-001 整合）

発行時および consume 時に少なくとも次へ **bind** する（one-shot）。**1 項目でも live と不一致なら発行拒否または consume 拒否。**

| 項目 | 説明 |
| --- | --- |
| hardware profile ID / revision | HardwareProfile |
| regulatory profile ID / revision | RegulatoryProfile |
| **SiteAssignment identity** | site / assignment 識別子（NIN-CMP-001） |
| **SiteAssignment revision** | assignment 文書 revision |
| **SiteAssignment epoch** | membership / attachment / assignment epoch（適用中の世代） |
| physical transmitter identity | どの radio/path か |
| channel | 周波数 channel 識別 |
| PHY parameters | bandwidth / SF / CR / 等 profile 範囲内 |
| frame digest | 送信 bytes の digest（algorithm は後続 wire freeze で固定） |
| frame byte length | exact |
| conservatively calculated maximum airtime | ledger 予約と一致 |
| not-before / expiry | 時間窓（wall clock 依存の詳細は profile; permit 自体は発行時スナップショット） |
| permit sequence | 単調・再利用禁止 |

**発行後変異:**

- SiteAssignment identity/revision/epoch、Hardware/Regulatory profile revision、live radio settings、または frame digest/length/PHY が **発行時スナップショットと異なる** → **consume 拒否**（TX しない）。新 plan + 新 permit が必要。
- active TX reservation がある profile/assignment の in-place 変更禁止（[05章](05-security-and-compliance.md) Profile変更）。

規則:

1. beacon / Membership・Attachment control / ACK / retry / relay / diagnostics も **例外なく** permit 必須。
2. USB control path・scheduler priority・operator override は denial を上書きできない。
3. permit なしで SX1262 TX へ到達する code path を作ってはならない。
4. Owner Task Join ACK は physical TX を認可しない。

### 9.4 固定しないこと（後続 Normative）

| 項目 | 状態 |
| --- | --- |
| secure compact radio wire major/minor | **version unallocated** |
| frame byte layout / AEAD coverage | 未固定 |
| MAC slotting / beacon format | 未固定 |
| Japan production profile の具体数値 | 05章どおり SKU 確認後 |
| SX1262 register map の public 化 | HAL private |
| Network Attachment/Join full protocol | §14 |
| relay / multi-parent | §14 |

**R-series 実装は本 §9 に違反する wire 短絡を行ってはならない。** wire を固定する PR は別 Normative 文書 + version domain 更新を必須とする。

## 10. 実装 slice カタログ

### 10.1 USB series（U1–U7）

| Slice | 内容 | 依存 | 完了の意味にしないこと |
| --- | --- | --- | --- |
| **U0** | 本章 + ADR-0003 boundary freeze（docs） | M3 framing/owner docs | 実装完了 |
| **U1** | POSIX explicit-path termios/poll、§3.2 UX、bounded rings、WOULD_BLOCK、default 容量の測定フック。**現状: implementation candidate / host PTY CTest**（`ports/posix/usb_serial` + C1 `src/transport/byte_stream.h`）。**Required HIL Linux+macOS pending — U1 complete ではない** | U0 | NCG1、HELLO、**series 完成**、physical USB HIL PASS |
| **U2** | ESP32-S3 `esp_tinyusb==2.1.1` CDC-ACM adapter（A2）、fixed 4KiB rings、LISTENING→attach+DTR UP、owner task fence、host pure adversarial tests + **esp32s3 compile/link**。**現状: implementation candidate**。**Required HIL flash+host CDC roundtrip pending — U2 complete ではない**。callback は TinyUSB **task** 文脈（hard-ISR 主張なし） | U0、ESP-IDF **v5.5.3**、C1 LISTENING/endpoint_token | device HIL なしの完成主張; U3 session |
| **U3** | NCG1 を C3 session + C4 pump 経由で U1/U2 に接続、resync stats、payload ownership。**現状: implementation candidate**（`src/transport/control_session.*` + host fake C1 CTest + structural gate）。**U3↔U4 production-private boundary candidate も同 object**（§4.3.1: logical epoch / tracked TX / claim 中 RX-only cold）。U4 の **NCL1 pure codec は実装候補済み**、HELLO state machine / session lifecycle / logical_control は未実装 | U1+U2 または fake stream、docs/19 | HELLO session engine、custody、USB series 完成、U1/U2 HIL 完了の代替主張、U4 complete |
| **U4** | NCL1 + HELLO/PING/PONG/RESET、session_generation/cookie fencing、§8.9 vectors **Required gate** | U3 + §4.3.1 boundary | assignment、security、public ABI |
| **U5** | 最小 assignment / cell role 通知（**別 logical freeze 後**） | U4、docs/22 cell skeleton | full topology、Site Membership/Attachment 完了 |
| **U6** | Transport Custody と control path の結合境界（durable spool ≠ raw CDC） | U4/U5、storage port | Application Receipt |
| **U7** | diagnostics（§8.10 counter snapshot 接続）、log 分離 gate、reconnect/backpressure/liveness soak（§8.11 測定） | U4+ | M3 complete、RF |

#### U1–U7 acceptance と **Required HIL**（series 完成条件）

USB series を **完成**と名乗るには、下表の **Required HIL** を満たすこと。未実施なら **未完成**と書く。compile green は完成ではない。

| Slice | Host / CI | Simulator | Fuzz | HIL / physical |
| --- | --- | --- | --- | --- |
| U1 | open 失敗、poll timeout、4KiB backpressure unit、§3.2 診断 path | fake PTY 可 | n/a または path parser | **Required HIL（U1 完了主張時）:** **Linux および macOS** の **両方**で **実 USB CDC 列挙 + explicit path open/read/write/close**（片方 OS のみでは U1 complete を名乗らない） |
| U2 | packaging + esp32s3 **compile/link** + **`esp_tinyusb==2.1.1` + committed locks** + host pure state/ring/owner/orch CTest + control-CDC isolation gates | n/a | n/a | **Required HIL（U2 完了主張時）:** (1) ESP32-S3 実機 flash + host からの **CDC I/O 往復**。(2) **Negative:** host が old-generation payload を TX ring/driver に載せた直後に **DTR deassert→assert**（または unplug/replug）し、新 generation の session/framing が **stale old-gen bytes を受理しない**こと（U2 は ring isolation + software FIFO soft-clear のみ; wire/in-flight 回収は非主張）。**compile ≠ HIL**。**現状 pending — U2 complete を名乗らない**。ESP-IDF **v5.5.3** |
| U3 | framing golden + 1-byte/任意 chunk inject + ownership handoff + CRC/resync + overflow/generation fence + **C1 all-or-none TX**（WOULD_BLOCK full-frame retention; partial-OK negative/fence）+ wrong-owner zero-mutation + reopen + post-I/O gen ticket + **§4.3.1 logical epoch / tracked TX resolution / claim 中 RX-only cold vs legacy full fence**（host fake stream `control_session_u3` + `control_session_u3_gate`） | byte fault inject | NCG1 fuzz 継続 | optional device framing; series 完成には U7 と合わせて評価。**現状 host candidate — series complete / U4 complete ではない** |
| U4 | §8.9 vectors + state machine table **Required** | session loss/reorder | NCL1 fuzz smoke | optional |
| U5–U6 | 各 freeze に従う | — | — | 各 freeze に従う |
| U7 | diagnostics unit | — | — | **Required HIL（U-series 完成主張前）:** unplug/reconnect smoke、RX overflow/backpressure smoke、liveness/HELLO 回復 smoke を **Linux および macOS** の **両方** × ESP 実機で実施。**soak:** 単一 PR が宣言する wall 時間 **≥ 30 min continuous**（link up 維持）で unplug 0 回・session fence 0 回・`liveness_fail==0`・counter snapshot を測定ログに残す。**30 min 未満や片 OS のみでは U-series 完成を名乗らない** |

**未実施の Required HIL がある限り「USB series 完成」「U1 complete on device」等を名乗ってはならない。**

### 10.2 Radio series（R1–R10）

| Slice | 内容 | 依存 | 完了の意味にしないこと |
| --- | --- | --- | --- |
| **R1** | `ninlil_radio_hal` 契約 docs + spy port（**transmit-with-permit 唯一入口**） | §9、docs/05 | real SX1262 |
| **R2** | Physical Compliance Permit object + one-shot consume（host pure）+ SiteAssignment bind fields | R1 | legal certification |
| **R3** | Airtime calculator interface + reference vectors（profile 値は lab stub 可） | R2 | Japan production 数値確定 |
| **R4** | SX1262 backend **reset/init/SPI** only、TX path は compile stub deny | R1、drivers layout | RF TX |
| **R5** | LAB_ONLY profile loader + permit bind **全項目** mismatch test（SiteAssignment 含む） | R2–R3 | FIELD/PRODUCTION |
| **R6** | Secure radio wire **Normative freeze**（ここで初めて version 割当） | M5 security prep | 実装完了 |
| **R7** | Wire encode/decode + AEAD golden（cross-language）→ immutable plan API | R6 | HIL |
| **R8** | MAC minimal (beacon/slot candidates) experimental | R6 | production MAC |
| **R9** | SX1262 TX path が **permit 消費後のみ** SPI TX、spy で bypass 0 | **R4 + R5 + R7**（最低）。R8 は任意 | soak/RF SLO |
| **R10** | LAB HIL: frequency / ToA / LBT measurement evidence | R9、hardware | production candidate |

R9 依存の意図: 実 SPI backend（R4）、compliance bind 全項目（R5）、immutable wire bytes（R7）が揃って初めて sole TX edge を閉じられる。

#### R-series evidence 境界

| 証拠 | 言えること | 言えないこと |
| --- | --- | --- |
| host pure permit tests | bypass path 0 on spy | 法規適合 |
| esp32s3 compile | image builds | RF works |
| R10 HIL | その SKU/profile での測定 | 全国/全 antenna 認証 |
| simulator airtime | model 一貫性 | 実電波 |

**compile success must not equal HIL.** 文書・CI job 名・PR 説明で混同禁止。

## 11. FreeRTOS Owner Task Join と docs/03 identity 層の分離

### 11.1 問題

[22章](22-m3-owner-cell-agent-skeleton.md) と `ninlil_esp_idf/owner_task.h` は lifecycle 定数:

- `NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK`
- `NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED`

を用いる。これは **FreeRTOS owner task の join / reclaim 証跡**であり、[03章](03-identity-and-join.md) が定義する **Device Identity / Site Membership / Attachment / Route Lease / Traffic Grant** のいずれでもない。**Owner Task Join は physical RF 許可でも Control HELLO でもない。**

> 注: docs/03 は章題に “Join” を含むが、**「Network Join」という単一 state / 用語は docs/03 に存在しない**。存在するかのように引用しない。

### 11.2 文書語彙（本 slice から MUST）

| 使う語 | 意味 |
| --- | --- |
| **Owner Task Join ACK** | owner task が suspend 後に join 証跡を公開した状態（旧表記 JOIN_ACK の意味） |
| **Owner Task Failed Joined** | task は reclaim 済みだが failure 終了 |
| **Network Join** | **単一 state として使わない**。非主張・混同注意の umbrella としてだけ触れ、必ず **Attachment / Membership / Control HELLO** 等を併記する。裸の成功語にしない（[15章](15-glossary.md)） |
| **Control HELLO** | 本章 §8 の USB control session 交渉 |
| **Site Membership / Attachment** | docs/03 本線の具体層（U0 では未確定・後続 freeze） |

### 11.3 移行名（C 記号は本 slice で変更しない）

| 現行 C 記号（維持） | 規定移行名（将来 rename PR） |
| --- | --- |
| `NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK` | `NINLIL_ESP_IDF_OWNER_LC_TASK_JOIN_ACK` |
| `NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED` | `NINLIL_ESP_IDF_OWNER_LC_FAILED_TASK_JOINED` |
| `ninlil_esp_idf_owner_mark_join_ack_core` | `ninlil_esp_idf_owner_mark_task_join_ack_core` |

規則:

1. **本 U0 docs-only slice では既存 C 記号を変更しない**（互換・差分爆破を避ける）。
2. 新規文書・新規 test 説明は **Owner Task Join** 語を使い、docs/03 の Membership/Attachment と併記して区別する。
3. rename PR は port header / docs/22 / CHANGELOG を同一で更新し、public `include/ninlil/*` に出さない。

## 12. Public ABI / privacy

1. NCL1・USB adapter API・session 状態・C1/C3/C4 は **production-private**。`include/ninlil/*` へ追加しない。
2. public 化条件は docs/19 §10.2 に準じ、logical catalog・security 合成・conformance・migration note を要する。
3. 本 freeze は public wire の固定完了を宣言しない。
4. KGuard 固有語彙を portable Core へ入れない。

## 13. Testing / CI への接続

| Gate | いつ | 内容 |
| --- | --- | --- |
| `radio_usb_boundary_docs_gate` | U0 から PR | 本章・ADR-0003・用語・slice・**構造的不変条件**・forbidden claims・docs/06。self-test は意図的 mutation で実 checker が fail することを証明 |
| existing NCG1 tests | 継続 | framing 退行防止 |
| U1–U4 CTest | 各実装 PR | §10.1 |
| U4 vector bridge | U4 から **Required** | §8.9 実 vector |
| esp-idf.yml compile | U2+ | **build only** |
| Required HIL | U1/U2/U7 完了主張時 | §10.1。未実行を green 完成にしない |
| R1–R10 | 各実装 PR | §10.2。R10 なしに production radio と言わない |

## 14. 後続に残す freeze（Open / later; 今回未確定）

次は **U0 で確定していない**。実装が先走っても「U0 で決まった」と書いてはならない。

1. **Network Attachment / Join**（docs/03 本線; Control HELLO とは別）
2. **relay** path と hop metadata
3. **multi-parent** / multi-Cell topology
4. 完全 assignment / topology epoch / controller_term logical messages
5. Transport Custody spool と USB の正確な handoff state machine
6. control channel AEAD / identity bind
7. secure radio wire version 割当と byte layout（R6）
8. Japan production RegulatoryProfile 数値
9. Windows controller transport
10. Owner Task Join C 記号 rename
11. TCP/LAN control transport の本番選定
12. multi-interface USB（control + log + bulk 同時）descriptor 固定

## 15. Acceptance（本 U0 docs slice）

- [x] ADR-0003 Accepted: compile dependency と runtime flow を分離し図と表を一致
- [x] 本章が ownership / private session object / queue（entry+byte）/ reconnect / fencing / backpressure / overflow fence / non-custody / channel 分離 / POSIX UX を定義
- [x] NCL1 + PING/PONG/RESET/HELLO が U1–U4 実装可能な精度（Controller-only、**header session_cookie 全 active 検証**、CSPRNG fail-closed、NCG1 sequence U4 policy + **方向別 TX/RX epoch authority** + **SBR-HELLO / SBR-ACK** + **`BOOTSTRAP_EPOCH_RESTART`**、version domain 分離、wall clock 廃止）
- [x] **Half-open / reverse-ACK / RX-only-cold recovery**: SESSION_ACTIVE 中 valid HELLO → fence → HELLO_RECEIVED; **同一 process HELLO retry は `next_tx_seq`**; **SBR-ACK** で reverse ACK loss / high ACK; **SBR-HELLO** で Cell RX-only cold 後 high HELLO; gap/overflow は RX-only cold; 必須 vectors §5.6.2; デッドロック禁止
- [x] **§5.2 規則1:** session-breaking（RX overflow / RESET / gap 等）を **物理 Link down と呼ばない**; re-Link up 無しでも HELLO 回復可（§5.6.1 整合）
- [x] **Cell continuity-loss 通知順序 exact**（pre-fence snapshot → atomic fence + 高優先 `RESET_SESSION` notice 最大 1; wire=snapshot / seq 継続; WOULD_BLOCK でも fence 非 rollback; §4.5/§5.6.1/§7.4/§8.3）
- [x] **Pending continuity-loss RESET lifecycle**（(a) fence once at detection — raw-adapter TX accept で通常 RESET_SESSION sender fence 再実行禁止; (b) valid HELLO 新 session 直前に not-yet-accepted notice atomic cancel + `continuity_reset_notice_cancelled`; (c) already-accepted は HELLO_ACK より strict FIFO; (d) cancel は sequence 非消費 / accept は通常消費）
- [x] **Stale RESET sequence order**（sequence validation/accept が先; 連続 stale は `last_rx_seq` 前進後 NCL1 drop; control state/session 不変・sequence rollback 禁止・新 session fence 禁止; dup/regress 通常 / gap·reserved 通常 RX-only-cold; stale に SBR/baseline 特権なし; active mismatch と non-active drop の両方）
- [x] **`sequence == UINT32_MAX` U4 予約 terminal**（TX 禁止; RX は SBR/BOOTSTRAP より前に reject + `ncg1_reject_seq_reserved` + session INVALID + RX-only cold; last+1 wrap 禁止; vector `U4-N-SEQ-U32-MAX`）
- [x] **NCG1↔NCL1 closed exact matrix** + validation order + SBR/BOOTSTRAP 限定 peek + type-binding negatives
- [x] **送信 role matrix exact**（HELLO C-only / ACK Cell-only / PING C-only / PONG Cell-only / RESET・CTRL_ERROR both）
- [x] **Structured counter 最小 catalog**（§8.10; `hello_baseline_resync` / `hello_ack_baseline_resync` / `ncg1_reject_seq_reserved`; HELLO 成功で counter reset しない）と **monotonic liveness/HELLO retry**（§8.11; **`ping_dispatch_slack` MUST accept** + dispatch miss → fence + re-HELLO; inflight=1）
- [x] RESET **no-ack** + 双方送信 + **request_id は local allocator nonzero・inflight 非登録**; **`RESET_SESSION` 双方 sequence 継続** / `RESET_PARSER` は **送信 accept 端・受信端とも local RX-only cold + 各端 local TX 継続** / `RESET_LINK` は session 即 INVALID・sequence は **観測 reopen で双方 cold**（必須脱出口ではない）
- [x] physical TX 順序と Permit bindings（SiteAssignment 含む）; logical permit 非認可; wire version unallocated
- [x] CTRL_ERROR loop 閉鎖規則
- [x] USB series Required HIL: U1 実 USB **Linux および macOS**; U7 smoke **Linux および macOS**; soak ≥30 min continuous 宣言; ESP-IDF **v5.5.3** pin
- [x] U2: `esp_tinyusb==2.1.1` exact pin + committed app locks; C1 `endpoint_token` + `LINK_LISTENING`; A2 candidate under `ports/esp-idf`（host pure + target compile/link）。**Required HIL pending — U2 complete ではない**
- [x] Owner Task Join と docs/03 Membership/Attachment の文書分離 + Network Join umbrella は Attachment/Membership/Control HELLO 併記（裸成功語禁止）
- [x] 開発者向け読み順（§1）
- [x] U1–U7 / R1–R10（R9 ≥ R4+R5+R7）と evidence 境界
- [x] 後続 freeze（Attachment/Membership、relay、multi-parent 等）を未確定と明示
- [x] docs index / glossary / roadmap / docs/05 / docs/06 整合 + U0 self-review 記録（旧 NO-GO を正直に記録; 実コード/HIL 未実施は非主張）
- [x] documentation consistency gate（構造検査 + row/section scoped + 本改訂 false-green mutation; self-test が実 checker を落とす）
- [ ] U1 Required HIL Linux+macOS physical USB CDC（**pending**）
- [ ] U2 Required HIL ESP flash + host CDC roundtrip（**pending**）
- [ ] SX1262 production code（対象外・**未実装**）
- [ ] Site Membership / Attachment 本線 / relay / multi-parent（対象外・未確定）
- [ ] U4 vector fixture bridge / U-series 完成 HIL 実測（**未実施**; 完成主張しない）
- [ ] U7 HIL/soak による liveness 数値の測定確定（default のみ; **未実施**）
