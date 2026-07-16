# ADR-0003: Radio / USB Boundary Dependency Direction

状態: Accepted<br>
決定日: 2026-07-16

## Context

M3 は packaging、NCG1 framing、platform adapters、owner/Cell skeleton、durable storage port まで進んだが、**USB CDC 実装**と **SX1262 / physical radio 実装**は未着手である。この境界をコードで先に固定すると、次の誤りが起きやすい:

1. portable logical Runtime が USB/termios/TinyUSB や RadioLib/SX1262 を直接参照する。
2. Foundation の virtual / loopback `TxPermit` を physical RF 送信許可と混同する。
3. Controller↔Cell の private control protocol を public C ABI や production radio wire と同時に固定する。
4. KGuard 固有 message / policy / QR 語彙を portable Core へ持ち込む。
5. FreeRTOS owner lifecycle の `JOIN_ACK`（task reclaim）を docs/03 の Site Membership / Attachment（曖昧 umbrella label「Network Join」）と混同する。
6. compile/source dependency と runtime call/data flow を同一の矢印で描き、adapter が Core を「呼ぶ」のか Core が adapter を「含む」のかが曖昧になる。

U0（USB 境界）と M4 手前の physical radio 境界を **仕様で先に freeze** し、実装 slice（U1–U7 / R1–R10）を独立に開始可能にする必要がある。

本 ADR は **依存方向（compile/source）** と **runtime の call/data flow** を **別図・別定義** で固定する。USB の queue/session 詳細は [23章](../23-usb-radio-boundary.md)、NCG1 framing は [19章](../19-m3-control-byte-stream-framing.md)、physical compliance 概念は [05章](../05-security-and-compliance.md) を正本とする。

## Decision

### 1. 構成要素（図と表で同一集合）

依存図・許可表・禁止表は、次の **同一構成要素集合** だけを用いる。別名で層を増やしたり、図に無い要素を表へ書かない。

| ID | 構成要素 | 置き場所（目標） | 役割 |
| --- | --- | --- | --- |
| C0 | **Portable logical Runtime (Core)** | `src/` portable / public `include/ninlil` | business/reducer、public Runtime API |
| C1 | **Portable byte-stream contract** | portable private header（**非 public ABI**） | open/read/write/close、link 状態、`WOULD_BLOCK` の抽象 vtable のみ。platform 型を載せない |
| C2 | **NCG1 framing codec** | portable private（既存 docs/19） | byte-stream 上の frame encode/decode |
| C3 | **NCL1 codec / control session** | portable private（docs/23） | logical envelope、HELLO/session、PING/PONG/RESET。**session object と payload ownership を持つ** |
| C4 | **Composition / pump** | private（port または private runtime glue; **非 public**） | adapter ↔ session の byte pump、session ↔ owner mailbox の handoff。Core public API を汚染しない |
| A1 | **POSIX controller transport adapter** | `ports/posix/`（または host controller port） | termios/poll、explicit path、raw rings |
| A2 | **ESP USB CDC adapter** | `ports/esp-idf/` | `esp_tinyusb` CDC-ACM、raw rings、link 状態 |
| L1 | **Cell Agent local composition layer**（docs/01 の 4 product planes ではない） | port / firmware private | owner task、assignment 適用（後続）、custody（後続） |
| P1 | **Physical Compliance Gate / Permit** | compliance component / Cell local gate | physical TX の sole authorization edge |
| W1 | **Secure compact radio wire / MAC codec** | 後続 Normative（**bytes/version 本 ADR では非固定**） | immutable TX plan/bytes の確定 |
| H1 | **ninlil_radio_hal** | `drivers/` 背後の HAL 契約 | **唯一**の transmit-with-permit 入口 |
| D1 | **SX1262 HAL / backend** | `drivers/sx126x/` | SPI/GPIO 実機 backend |
| K1 | **KGuard integration** | `integrations/kguard/` | product vertical のみ |

### 2. Compile / source dependency（MUST）

矢印 **A → B** は「A の translation unit が B の header を include してよい / B の library に link してよい」。**実行時に誰が誰を呼ぶかではない**。

```text
K1 (KGuard integration)
  --> C0 (Portable Core)     [public API only]
  --> (optional) product-local adapters outside Core

C0 (Portable Core)
  --> C1 (byte-stream contract abstract only)
  -X-> A1, A2, D1, K1 schema, termios, TinyUSB, SX1262, RadioLib, SQLite

C2 (NCG1 codec)          [portable private]
  --> (C only; no platform)

C3 (NCL1 codec/session)  [portable private]
  --> C2
  -X-> A1, A2, C0 public headers as required surface, K1

C4 (composition/pump)    [private glue]
  --> C1, C2, C3
  --> A1 or A2  (as concrete byte-stream implementors)
  --> L1        (owner mailbox / local composition layer; not public Core)
  -X-> K1 vocabulary as required Core types
  -X-> P1/W1/H1/D1 as USB series dependency

A1 (POSIX adapter)
  --> C1 (implements contract)
  --> POSIX termios/poll
  -X-> C0 business reducers, P1, W1, H1, D1, K1

A2 (ESP USB CDC adapter)
  --> C1 (implements contract)
  --> pinned ESP-IDF / esp_tinyusb
  -X-> C0 business reducers, P1 as USB path, W1, H1, D1, K1

L1 (Cell local composition layer)
  --> C0 port vtables as needed
  --> P1 (when radio TX path exists)
  -X-> A1/A2 internals (uses C1/C4 only)

P1 (Physical Compliance Gate)
  --> profile/ledger/SiteAssignment inputs
  -X-> A1, A2, K1, C0 application payload interpretation

W1 (secure wire/MAC codec)
  --> security session materials (M5+)
  -X-> C0 public memcpy of logical structs, A1, A2

H1 (radio HAL)
  --> P1 permit type (consume API)
  --> D1 backend
  -X-> C0, C3, A1, A2, K1

D1 (SX1262 backend)
  --> SPI/GPIO port only
  -X-> C0, C3, A1, A2, K1
```

| 構成要素 | compile/source で依存してよい | compile/source で依存してはいけない |
| --- | --- | --- |
| C0 Portable Core | C11、自身の private model、port **vtable 抽象**（C1 の abstract ops を含む） | A1/A2、termios、TinyUSB、ESP-IDF、D1、RadioLib、K1 schema、USB path 文字列、P1 具象 |
| C1 byte-stream contract | C11 のみ（関数ポインタ表） | 具象 adapter、driver |
| C2 NCG1 codec | C11 / portable only | platform USB/radio |
| C3 NCL1 codec/session | C2 | A1/A2、C0 public 必須化、K1、radio |
| C4 composition/pump | C1–C3、A1 または A2、L1 private | K1 必須語彙、public `include/ninlil` への型露出、D1 |
| A1 POSIX adapter | C1、POSIX | C0 reducer 改変、P1 実装、SX1262、K1 |
| A2 ESP CDC adapter | C1、ESP-IDF / esp_tinyusb | C0 への USB 型露出、K1、physical RF TX |
| L1 Cell local composition layer | Core port 抽象、C4 出力、P1 | A1/A2 内部 ring 直操作 |
| P1 Compliance Gate | HardwareProfile、RegulatoryProfile、SiteAssignment、live settings、ledger | application 業務解釈、Foundation virtual permit 流用、USB adapter、K1 |
| W1 secure wire/MAC | security session（後続） | portable Core raw wire struct 露出、logical `memcpy` |
| H1 radio HAL | P1 permit、D1 | C0、C3、USB、K1 |
| D1 SX1262 | radio HAL 契約、SPI/GPIO | C0、control protocol、K1 |
| K1 KGuard | C0 **public** API、product adapters | portable Core / C3 必須語彙への逆流 |

**MUST**: 逆方向の compile-time / link-time / source include 依存は禁止（上表 `-X->` および「依存してはいけない」列）。

### 3. Runtime call / data flow（MUST; compile 図とは別）

矢印は **実行時の call または byte/message の流れ**。include 可否を表さない。

#### 3.1 USB control plane（Controller ↔ Cell）

```text
[Controller process]                         [Cell / ESP process]

C0 / product logic                           L1 owner / local composition layer
       |                                            ^
       v                                            | owned logical messages
C4 pump (host)                                      C4 pump (device)
       |                                            ^
       v                                            |
C3 session (NCL1)  --NCL1 messages--          C3 session (NCL1)
       |                                            ^
       v                                            |
C2 NCG1 encode/decode <==== NCG1 frames ====> C2 NCG1 encode/decode
       |                                            ^
       v                                            |
C1 ops write/read                           C1 ops write/read
       |                                            ^
       v                                            |
A1 termios/poll  <====== USB CDC bytes =====> A2 esp_tinyusb CDC
```

規則:

1. A1/A2 は **raw bytes と link 状態だけ** を扱う。NCL1 を解釈しない。
2. C3 が session 状態と **payload ownership** を持つ（[23章 §4](../23-usb-radio-boundary.md)）。
3. C0 public API は USB fd / TinyUSB handle / NCL1 内部 buffer を受け取らない。
4. raw CDC `write` 成功は Transport Custody / Application Receipt / Site Membership・Attachment（曖昧 umbrella: Network Join）成功ではない。

#### 3.2 Physical RF TX path（sole edge; order is Normative）

**Physical TX の順序は次のみ**（並び替え禁止）:

```text
(1) W1 secure wire/MAC codec
      が immutable TX plan + exact frame bytes を確定
      （この後の bytes/PHY パラメータ変更は禁止）
        |
        v
(2) P1 Physical Compliance Gate
      が SiteAssignment / HardwareProfile / RegulatoryProfile /
      live radio settings / airtime ledger を検査し予約し、
      **exact plan への** Physical Compliance Permit を発行
        |
        v
(3) H1 ninlil_radio_hal の **唯一**の transmit-with-permit 入口が
      permit を再検証し single-use consume
        |
        v
(4) D1 SX1262 backend が SPI TX
```

| 段階 | 実行時に起きること | 起きてはいけないこと |
| --- | --- | --- |
| (1) W1 | immutable plan/bytes 確定 | plan 未確定のまま permit 要求 |
| (2) P1 | exact plan へ Permit 発行 + ledger 予約 | SiteAssignment/profile/live mismatch での発行; plan 変更を許す発行 |
| (3) H1 | re-validate + single-use consume | permit なし TX; consume 後の再送; bytes/PHY の差替え |
| (4) D1 | 消費済み permit に紐づく exact bytes のみ TX | 別 path からの register poke TX |

Foundation logical / virtual / loopback TxPermit はこの path に **入らない**（[05章](../05-security-and-compliance.md) `NIN-CMP-012`）。

### 4. 許可する依存・禁止する短絡（MUST / MUST NOT）

1. **MUST**: portable Core は directory 名に関係なく KGuard、ESP-IDF、TinyUSB、termios、SX1262、RadioLib、SQLite を直接参照しない（[01章](../01-architecture.md) Dependency rule の具体化）。
2. **MUST**: USB / POSIX serial は **A1/A2 + C1** に閉じる。logical Runtime は byte-stream contract または C4 経由でのみ見る。
3. **MUST NOT**: raw CDC bulk の `write()` 成功を Transport Custody・Application Receipt・Site Membership / Attachment（曖昧 umbrella: Network Join）成功とみなす。
4. **MUST NOT**: Foundation / loopback の logical `TxPermit` を physical RF 送信許可として扱う。
5. **MUST**: physical radio TX の唯一の認可エッジは **Physical Compliance Permit（P1）** である（[05章](../05-security-and-compliance.md) `NIN-CMP-002`）。scheduler / application / USB control path はこれを上書きできない。
6. **MUST**: H1 の transmit-with-permit 以外に physical TX へ到達する code path を作らない。
7. **MUST NOT**: logical bearer message や public transaction struct を `memcpy` して radio/USB wire にする。encode は versioned codec のみ。
8. **MUST NOT**: 本境界 freeze の時点で secure radio wire の production byte layout や version 番号を固定する。version domain は **未割当（unallocated）** のまま残す。
9. **MUST**: KGuard 固有 vocabulary は `integrations/kguard/` に閉じ、portable Core と private control protocol の必須語彙にしない。
10. **MUST**: private control protocol と USB adapter API は conformance と RFC を満たすまで **public C ABI / installed header に昇格しない**。
11. **MUST**: FreeRTOS owner lifecycle の task join 語彙と Site Membership / Attachment（曖昧 umbrella label Network Join）を文書・テスト・operator 文言で混同しない（[23章](../23-usb-radio-boundary.md) §11、[15章](../15-glossary.md)）。
12. **MUST**: Permit 発行後に TX bytes または PHY を変更してはならない。変更が必要なら **新 plan → 新 permit** のみ。

### 5. 初期 backend 選定（実装 slice の前提）

| 面 | 初期選定 | 備考 |
| --- | --- | --- |
| Cell Agent USB | **ESP32-S3 USB OTG Device CDC-ACM**、**pinned `esp_tinyusb` path**（**path 選定のみ**; managed component の **exact version / lock は U2** — [23章 §3.1](../23-usb-radio-boundary.md)。ESP-IDF pin は [18章](../18-m3-prep-esp-idf-component.md) / `ports/esp-idf/ESP_IDF_VERSION` = **v5.5.3**） | 他 USB stack は後続 ADR; **U0 は esp_tinyusb exact version を pin しない** |
| Controller USB | **Linux / macOS** の **explicit device path** + **POSIX `termios` + `poll`** | 詳細 UX は [23章 §3.2](../23-usb-radio-boundary.md); Windows は未固定 |
| Control framing | 既存 private **NCG1**（[19章](../19-m3-control-byte-stream-framing.md)） | 論理 envelope は [23章](../23-usb-radio-boundary.md) |
| Physical radio wire | **非固定（unallocated）** | R6 で初めて version 割当 |
| SX1262 | HAL 背後のみ | R-series 実装 |

### 6. 実装 slice 境界との関係

本 ADR は **U0 / physical radio boundary freeze（docs only）** を許可する。USB 本番コード（U1+）と SX1262 本番コード（R1+）は、[23章](../23-usb-radio-boundary.md) の slice 定義と acceptance を満たす PR でのみ開始する。compile success を HIL PASS と主張してはならない。

## Rationale

- compile dependency と runtime flow を分離しないと、「Core が USB を呼ぶ」「USB が Core を include する」が同一矢印で誤読される。
- TX 順序を wire 確定 → Compliance Permit → HAL consume → SX1262 に固定しないと、permit 後の bytes 差替えや permit なし SPI TX が混入する。
- control protocol を private のまま置くことで、USB の経験を public ABI に焼き付ける前に golden / fuzz / HIL で修正できる。
- radio wire を今固定すると、session security（M5）と compliance profile 未確定のまま互換負債が固まる。

## Consequences

- USB / radio 実装 PR は本 ADR と [23章](../23-usb-radio-boundary.md) への適合を review gate とする。
- public `include/ninlil/*` への USB/radio 型追加は、別 ADR + versioning（[06章](../06-versioning-and-compatibility.md)）なしに行わない。
- KGuard vertical（M6）は public Ninlil API と experimental adapter のみを使い、Core 依存を逆流させない。
- docs/22 の C 記号 `JOIN_ACK` / `FAILED_JOINED` は本 slice では変更しない。移行名は [23章](../23-usb-radio-boundary.md) §11 が規定する。
- docs gate は本 ADR の **compile dependency 図** と **runtime TX order** の両方を検査対象とする。

## Related requirements

- [01-architecture.md](../01-architecture.md) — roles、planes、dependency rule
- [05-security-and-compliance.md](../05-security-and-compliance.md) — TxPermit / Compliance Gate
- [06-versioning-and-compatibility.md](../06-versioning-and-compatibility.md) — independent version domains
- [09-roadmap.md](../09-roadmap.md) — M3 / M4 / M5 / U–R slices
- [19-m3-control-byte-stream-framing.md](../19-m3-control-byte-stream-framing.md) — NCG1
- [22-m3-owner-cell-agent-skeleton.md](../22-m3-owner-cell-agent-skeleton.md) — owner lifecycle
- [23-usb-radio-boundary.md](../23-usb-radio-boundary.md) — USB ownership、logical envelope、U1–U7 / R1–R10
