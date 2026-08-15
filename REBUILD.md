# Ninlil Runtime 再構築計画（Rebuild Blueprint）

状態: 提案（Informative）。既存コードの正本仕様を変更しない。

このドキュメントは、現行の Ninlil Runtime を分解し、「何を作っていたのか」「なぜ規模が破綻したのか」を整理した上で、大幅に小さくシンプルな OSS として作り直すための設計方針をまとめたものである。

---

## 1. このOSSは何だったのか

一文で言うと:

> LoRa・Wi-Fi・USB など不安定で帯域の狭い現場ネットワーク向けに、「送信した」ではなく **届いた・保存された・適用された** を区別して追跡する、組み込み向け C11 通信 Runtime / SDK。

中核の設計思想は次の4点で、これ自体は今も価値がある。

1. **Transaction 指向**: アプリは packet を送るのではなく「要求（transaction）」を提出する。Runtime が永続化・再送・再起動後の回復・重複抑止を同一 transaction として追跡する。
2. **Receipt と Outcome の分離**: 「bytes が相手に届いた」ことと「相手アプリが適用した」ことを区別する。証拠が失われれば結果は `UNKNOWN` であり、成功に丸めない。
3. **Admission control**: 要求を無条件に受け付けず、期限・容量・経路・（法規制）を検査してから受け付ける。全リソースに固定上限がある。
4. **Portable Core + Port**: Core は socket・ESP-IDF・radio driver・製品語彙を知らない。storage / clock / entropy / bearer は platform adapter（vtable）が提供する。

### 現行リポジトリの構成要素（分解）

| 領域 | 実体 | 規模 |
| --- | --- | --- |
| Portable Core (`src/model`, `src/runtime`) | admission / deadline / retry / dedupe / outcome の状態機械、durable store codec、multi-frame durable transfer (`mfdt_v1`)、relay (`route_relay_v1`) | 約 120,000 行 |
| Transport (`src/transport`) | byte stream framing、NRW1 LINK/FRAG/再組立、POSIX TLS / USB serial bearer | 約 54,000 行 |
| Radio (`src/radio`) | SX1262 制御、airtime 計算、法規 permit authority、LAB 用 handshake / secure wire / crypto (HKDF, AEAD, EDHOC profile) | 約 47,000 行 |
| Tests | ABI drift、契約テスト、fuzz、golden vector 検証 | 約 260,000 行 |
| Tools | vector 生成器・ドキュメント gate・ABI manifest 生成（1ファイル 1MB 級の生成 Python を含む） | 約 280,000 行 |
| Spec / Docs | 46MB の golden vectors、295 ファイルの文書、requirements-traceability、compatibility matrix、成熟度タクソノミ | — |

合計はテスト・ツール込みで約 76 万行。**一方で `RELEASE_SUPPORTED`（完成）に到達した機能は 1 つもなく**、実機 HIL・実運用・920MHz 法規適合は未達のままである。

---

## 2. なぜ失敗したか（診断）

コードが間違っていたのではなく、**プロセスの重さと機能の広さが、動く成果より先に積み上がった**ことが原因である。

1. **仕様先行・ゲート先行**: 動く垂直スライスより先に、ABI manifest、drift gate、docs gate、traceability YAML、成熟度タクソノミ（SPEC_ACCEPTED / PROPOSED / HOST_CANDIDATE…）という航空宇宙級のプロセスを個人規模の pre-release OSS に適用した。以後すべての変更コストが跳ね上がった。
2. **横に広げすぎた**: relay tree、multi-parent、multi-frame transfer、crypto/EDHOC、法規 authority、USB + TLS + LoRa を、どれか 1 つが実証される前に並行着手した。
3. **生成物のコミット**: 1MB 級の vector 生成 Python や 46MB の golden vectors がリポジトリの大半を占め、本質のコードが埋もれた。
4. **コードネームの氾濫**: `mfdt_v1` `rrmp` `d3s1〜d3s4` `r7` `c3〜c6` `NRW1` `NCL1` など、文書を読まないと意味が取れない名前がファイル名・API に浸透し、新規参加コストを極大化した。
5. **API 表面積の肥大**: 公開 API 1 関数あたり最大 14 種の到達可能 status、20 フィールドの resource limits、全 struct への ABI header。堅牢性の表現がそのまま使いにくさになった。

## 3. 残す価値（再構築の核）

再構築で守るのは思想であって実装ではない。

- **「送った ≠ 届いた ≠ 適用された」の3値追跡** — このOSSの独自価値はここに尽きる。
- 再起動を跨ぐ durable outbox と重複抑止（idempotency key）。
- 期限と容量による admission（受け付けないことを明示的に返す）。
- bearer / storage / clock を差し替え可能にする小さな port 境界。

## 4. 新設計: 最小コア

新しい一文の定義:

> **不安定なリンク上の組み込み機器向け、永続アウトボックス付きメッセージングライブラリ。** メッセージごとに SENT / DELIVERED / APPLIED / EXPIRED / UNKNOWN を追跡する。

### 規模目標（ハード上限）

| 領域 | 上限 |
| --- | --- |
| コア (`src/`) | 5,000 行 |
| 公開ヘッダ | 1 ファイル・400 行 |
| ports（POSIX 参照実装） | 1,500 行 |
| tests | 5,000 行 |
| docs | README + 3 ページ |
| リポジトリ合計 | **15,000 行以内**（現行の約 1/50） |

### 公開 API 案（関数 10 個）

```c
/* ninlil.h — 単一ヘッダ */
ninlil_t *ninlil_create(const ninlil_config_t *cfg, const ninlil_port_t *port);
void      ninlil_destroy(ninlil_t *n);

/* 提出: 期限・宛先・冪等キー付き。容量超過や期限切れは即時 reject */
ninlil_status_t ninlil_submit(ninlil_t *n, const ninlil_msg_t *msg, ninlil_id_t *out_id);
ninlil_status_t ninlil_cancel(ninlil_t *n, ninlil_id_t id);

/* 駆動: スレッドを作らない。呼び出し側ループから回す */
ninlil_status_t ninlil_step(ninlil_t *n, uint32_t budget, uint64_t *out_next_wake_ms);

/* 受信側: 適用完了を明示的に報告（これが APPLIED の唯一の根拠） */
ninlil_status_t ninlil_ack_applied(ninlil_t *n, ninlil_id_t id);

/* 観測 */
ninlil_status_t ninlil_query(ninlil_t *n, ninlil_id_t id, ninlil_msg_state_t *out);
ninlil_status_t ninlil_list(ninlil_t *n, ninlil_msg_state_t *buf, size_t cap, size_t *out_n);

/* イベント通知は callback 1 本: state 遷移のみを通知 */
typedef void (*ninlil_on_event_t)(void *user, const ninlil_event_t *ev);
```

status は `OK / E_ARG / E_FULL / E_EXPIRED / E_STORAGE / E_STATE` の 6 種に畳む。
「commit したか不明」は status ではなく message state の `UNKNOWN` で表現する。

### Port 境界（vtable 3 個）

```c
typedef struct { /* append / read / delete / sync — KVでもファイルでも実装可 */ } ninlil_storage_t;
typedef struct { uint64_t (*now_ms)(void *); } ninlil_clock_t;
typedef struct { /* send(bytes) / poll(recv) / mtu — UDP, serial, LoRa 何でも */ } ninlil_bearer_t;
```

### ディレクトリ構成

```
ninlil/
  include/ninlil.h        # 単一公開ヘッダ
  src/core.c              # transaction 状態機械（admission / retry / expiry）
  src/outbox.c            # durable queue + 冪等キー dedupe
  src/wire.c              # 最小フレーミング（magic + ver + type + id + payload + CRC）
  ports/posix/            # ファイル storage + UDP bearer（参照実装）
  examples/echo/          # 2 プロセスで submit → deliver → ack_applied を通すデモ
  tests/                  # 通常の unit test のみ（golden vector 基盤なし）
  README.md
  docs/design.md          # 状態機械とワイヤ形式、各 1 ページ
```

## 5. 捨てるもの（明示）

以下は新リポジトリに**持ち込まない**。必要になったら「動くデモが先」の条件付きで別レイヤーとして検討する。

- relay tree / multi-parent / multi-controller
- multi-frame durable transfer（まず単一フレームに収まるサイズ上限で運用）
- 暗号層・EDHOC・HKDF（機密性は bearer 側の TLS / 既存 link 暗号に委譲）
- 法規 permit authority・airtime 計算・SX1262 制御（bearer 実装側の責務）
- ABI manifest / drift gate / struct header / ILP32 golden
- 成熟度タクソノミ、requirements-traceability、compatibility matrix、docs gate
- golden vector 生成器と 46MB の spec vectors
- コードネーム全般（`mfdt` `rrmp` `d3s*` `NRW1` 等）— 名前は平易な英語のみ

## 6. 再肥大化を防ぐ運用ルール

1. **デモ駆動**: 動く example で示せない機能は追加しない。仕様書だけの機能を持たない。
2. **LOC 予算を CI で強制**: `src/` 5,000 行超で CI を落とす。超えるなら何かを削る。
3. **文書はコードの後**: README と design.md の 2 点以外の文書を増やさない。
4. **status を増やさない**: 新しいエラー種別は既存 6 種に写像できないときのみ追加。
5. **バージョンは 0.x のまま素直に壊す**: ABI 凍結・互換性契約は 1.0 まで持たない。

## 7. 移行ステップ

1. 新リポジトリ（または `v2/` サブツリー）に `include/ninlil.h` の骨格と `core.c` の状態機械を書く。現行 `src/model/runtime_lifecycle_model.c` の状態遷移表は読み物として参照する（コードは移植しない）。
2. POSIX port（ファイル storage + UDP bearer）と `examples/echo` を通す。ここまでで「submit → 再起動 → 再送 → DELIVERED → APPLIED」の垂直スライスを完成させる。
3. 電源断を模した storage テストと dedupe テストを足す（通常の CTest、vector 基盤なし）。
4. 現行リポジトリはアーカイブし、README から新リポジトリへ誘導する。
5. 以後、ESP32 port → LoRa bearer の順で、各段とも動くデモ付きでのみ追加する。
