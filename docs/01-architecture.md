# 01. Ninlil Architecture

状態: Normative architecture baseline (Fable review reflected)

## 全体像

Ninlil は1つの firmware libraryではなく、複数の役割に分かれた分散 Runtime です。

```text
Product Application
      |
      | Submission / Receipt / Outcome API
      v
Site Controller
  - service registry
  - admission / policy
  - durable transaction journal
  - destination and path selection
      |
      | gateway protocol over USB / LAN / Wi-Fi
      v
Cell Agent / Parent
  - local scheduler
  - compliance gate
  - bounded emergency spool
  - radio metrics
      |
      | one or more bearers / relays
      v
Endpoint Runtime
  - identity / session
  - replay / dedup
  - application dispatch
  - persistent outcome cache
      |
      v
Endpoint Application
```

小規模構成では Site Controller と Cell Agent を同じ機器に置けます。ただし logical responsibility は分離し、後から複数親機へ拡張できるようにします。

## Runtime の役割

### Product Application

- business intent を作る。
- application schema を encode / decode する。
- application effect の意味を決める。
- Ninlil の receipt を利用者向け状態へ変換する。

Ninlil 内部の parent、channel、retry 回数を直接選びません。必要な場合は `path policy` や receipt level を宣言し、site policy の範囲内で Ninlil が実経路を選びます。

### Site Controller

- service contract と site policy の正本
- logical transaction と target roster の正本
- admission、deadline、fairness、quota
- parent / relay / bearer の選択
- durable journal と receipt aggregation
- topology epoch と assignment lease

Site Controller が cloud に到達できなくても、cache 済みの membership、policy、journal により local operation を継続できる設計にします。初期profileは1 siteにつき1 active Controller writerとし、`controller_term + assignment_epoch`でCell Agentのdownlink ownerをfenceします。

### Cell Agent / Parent

- USB / LAN と radio frame の橋渡し
- Cell 単位の TxArbiter
- LBT、休止、airtime 等の compliance hard gate
- beacon / slot 等の local MAC
- bounded transport custody spool
- link metrics と hardware diagnostics

Cell Agent は `leak` や `display` の業務 rule を持ちません。ただし signed service policy に基づく generic traffic class と durability requirement は理解できます。

Cell Agentの保存確認はTransport Custodyであり、`DURABLY_RECORDED`等のApplication Receiptではありません。

### Relay

- controller から許可された route の frame だけを forward する。
- application payload を解釈しない。
- 自身の load、power、link quality、airtime 状態を報告する。
- `DRAINING` 中は新規 child を受け入れない。

### Endpoint Runtime

- device identity と session state
- replay protection と duplicate suppression
- service / schema / capability の検査
- application apply contractに従うdispatch
- application outcome の永続 cache
- sleepy node の wake / receive window coordination

### Endpoint Application

- 実際に表示、計測、制御する。
- `APPLIED` または `VERIFIED` を返す根拠を作る。
- local fail-safe と physical interlock を持つ。

## 4つの plane

### Application Plane

- Application Envelope
- Service Contract
- Intent / Event / State / Transfer
- Receipt
- schema registry

### Control Plane

- Device Identity
- Site Membership
- Attachment
- Security Session
- Route Lease
- Traffic Grant
- parent assignment / topology epoch

### Data Plane

- secure frame
- bearer
- scheduler / MAC
- relay forwarding
- fragmentation / reassembly
- ACK transport

### Management Plane

- provisioning
- configuration revision
- diagnostics / logs / counters
- firmware / asset update
- key rotation / revocation
- conformance and support bundle

Management Plane の大きな data は Wi-Fi / USB を優先し、LoRa の safety / interactive capacity を消費させません。

## Bearer abstraction

Bearer は「byte列を送れる」だけでは足りません。少なくとも次を公開します。

- 最大 frame / transfer size
- uplink / downlink 能力
- sleepy node compatibility
- estimated latency と cost
- send reservation の可否
- local broadcast / unicast
- link metrics
- availability / degraded reason
- regulatory profile binding の有無

LoRa、Wi-Fi、USB の違いを消すのではなく、違いを capability と cost として共通 schedulerへ渡します。

## Application API と wire の分離

Application API は logical message を扱います。Wire protocol は bearer の制約に合わせた compact frame を扱います。

- logical payload 上限と1 frame payload上限を同じにしない。
- public transaction ID と wire 上の compact handle を同じにしなくてよい。
- application schema と network control message を同じ enum にしない。
- schema encoding は service contract で宣言し、Ninlil Core は payload の業務意味を読まない。

この分離により、wire v1 を改善しても application API を破壊しない構造を作ります。

## Storage model

Durable storage が必要な対象:

- transaction と target roster
- admission result と deadline
- attempt と bearer/path
- receipt
- non-replaceable event
- persistent dedup / outcome cache
- identity epoch、nonce reservation、replay watermark
- route / assignment epoch の last-known-good
- compliance ledger の保守的 checkpoint

すべてを同じ頻度で flash へ書きません。port は durability level、wear budget、atomicity を明示し、Runtime は reservation / batching / checkpoint を使います。

## Bounded resource invariant

次の全てに、entries、bytes、TTL、overflow behavior を定義します。

- ingress queue
- per-service queue
- per-node queue
- retry attempts
- transaction journal retention
- dedup / replay window
- fragment reassembly
- transfer resume state
- relay spool
- diagnostic log

overflow は silent drop にしません。semantic family に応じて、coalesce、replace、defer、reject、fail を記録します。

## 目標 component boundary

名称は RFC で確定しますが、責務は次の単位へ分けます。

```text
ninlil_core          transaction / receipt / runtime lifecycle
ninlil_contract      service descriptor / application envelope
ninlil_identity      identity / membership / attachment
ninlil_security      AEAD / key epoch / replay
ninlil_policy        admission / quota / path policy
ninlil_queue         bounded queue / durable outbox
ninlil_mac           scheduling / beacon / slot
ninlil_compliance    regulatory profile / airtime gate
ninlil_transfer      bounded fragmentation / resume
ninlil_route         relay / topology / drain
ninlil_bearer        common bearer interface
ninlil_storage       NVS / POSIX durable storage interface
ninlil_diagnostics   metrics / trace / support bundle
ninlil_radio_hal     physical radio driver boundary
```

## Port 方針

### Public API

- C ABI を基準にする。
- C++ wrapper は optional convenience layer とする。
- callback だけに依存せず、event queue / poll model も用意する。
- caller-owned buffer と bounded allocator を選べるようにする。
- exception、RTTI、unbounded heap を public contract の前提にしない。

### ESP-IDF port

- component 単位で導入可能にする。
- FreeRTOS task、NVS、timer、Wi-Fi、OTA、mbedTLS を adapter 経由で使用する。
- `esp_event` は通知に利用できるが、durable outbox の代替にはしない。
- SX1262 driver は radio HAL の behind に置く。

### POSIX port

- deterministic simulator
- application integration test
- protocol golden vector
- fault injection
- contributor が実機なしで実行できる conformance test

を担当します。

## 目標 repository layout

次はM3以降を含む長期layoutです。[08-foundation-release.md](08-foundation-release.md)のlayoutは、この構造のM1a subsetを規範化します。

```text
ninlil/
  README.md
  docs/
  rfcs/
  include/ninlil/          public C API
  components/              portable implementation
  ports/
    esp-idf/
    posix/
  drivers/
    sx126x/
  host/                    controller reference runtime
  simulator/
  examples/
    reliable-command/
    durable-event/
    latest-state/
    generic-sensor/
  integrations/
    kguard/
  tests/
    conformance/
    fuzz/
    hil/
```

## Dependency rule

- portable Coreはdirectory名に関係なく、KGuard、ESP-IDF、TinyUSB、termios、RadioLib、SX1262、SQLiteを直接参照しない。
- `ports/` と `drivers/` が platform dependency を吸収する。
- `integrations/kguard/` は public Ninlil API だけを使う。
- example は private header を include しない。
- test hook が production behavior を bypass しない。

USB control transport、private control protocol、Physical Compliance Permit、secure radio wire、SX1262 の **依存方向の正本** は Accepted [ADR-0003](adr/0003-radio-usb-dependency-direction.md) と [23章](23-usb-radio-boundary.md) である。**compile/source dependency と runtime call/data flow は別図**（ADR 正本）。要約:

**Compile/source（include/link; 逆依存禁止）:** Portable Core → byte-stream contract 抽象のみ。NCL1 session / NCG1 codec は portable private。POSIX termios/poll と ESP `esp_tinyusb` CDC は adapter に閉じ Core を汚染しない。KGuard は public API のみ。

**Runtime physical RF TX（sole edge; 順序固定）:**

```text
Secure wire/MAC (immutable TX plan/bytes)
  -> Physical Compliance Gate (SiteAssignment/profile/ledger/live; exact-plan Permit)
    -> ninlil_radio_hal transmit-with-permit (re-validate + single-use consume)
      -> SX1262 HAL/backend
```

Foundation の logical / virtual / loopback TxPermit は physical RF を認可しない。logical bearer message の `memcpy` 直列化は禁止する。secure compact radio wire は **R6** で `wire_profile_id=0x11` を **docs-only Accepted 仮** として draft 割当（正本 [30章](30-r6-secure-radio-wire.md) / [ADR-0010](adr/0010-r6-secure-radio-wire.md); **R7 実装・HIL・R6 complete ではない**）。

## Legacy lab slice との関係

KGuard側の旧`linkos/`にある`host/`、`firmware/`、19-byte wireはLegacy LinkOS Lab v1として、次を検証した外部の移行元資産に限定します。この独立repositoryにLegacy directoryが存在することは前提にしません。

- AES-GCM cross-language golden vector
- node 個別鍵
- durable PC journal
- applied / durably-recorded receipt
- radio Port abstraction
- parent / display / event node build

一方、KGuard message enum、16-bit node ID の恒久 identity 利用、1 parent / 1 hop 前提、display 専用 retry は public architecture に昇格させません。

## Foundation後のOpen architecture questions

- 128-bit public transaction IDのwire compression
- Site Controller HA / active-active write
- Cell Agent emergency spool の durability level
- controller / endpoint 間 E2E と hop-by-hop envelope の exact layout
- regulatory profile の署名・配布 format

これらはFoundationの実装判断を要求しません。後続milestoneでRFCとprototypeにより決めます。Foundation M1aのscopeは08章、public ABIは12章、reducerは13章、port/fixtureは14章を正本とします。
