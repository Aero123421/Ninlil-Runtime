# 19. M3-slice: Controller↔Cell Agent control byte-stream framing

状態: **Normative for this M3 framing slice only**（**M3 incomplete**）
対象: USB CDC / TCP 等の **reliable ordered byte stream** 上で共通に使う、transport-agnostic な **bounded control frame codec / incremental parser**

## 1. 位置付けと非主張

本章は [09-roadmap.md](09-roadmap.md) の **M3**（ESP-IDF Port and Cell Agent skeleton）のうち、**gateway control transport の最下層 framing** だけを固定する。

### 1.1 Claim の正確化

| 層 | 状態 |
| --- | --- |
| portable codec 実装（`src/model/control_frame_codec.*`、`ninlil_runtime_private` 統合） | **production-candidate**（main に載せる private 実装として host 検証済み） |
| wire layout / private header API | **非 public**（install しない。public ABI に載せない） |
| USB/TCP/Cell Agent / logical control messages / security | **未実装・未検証**（完成扱いしない） |
| M3 milestone / V1 | **incomplete** |

次を **主張しない**:

- M3 milestone 完了 / Cell Agent firmware 完成
- USB CDC driver / CDC task / Wi-Fi / TCP socket / NVS / FreeRTOS owner task 実装済み
- SX1262 / radio MAC / Join / KGuard / security session 完了
- control/gateway **application message** の意味論完了
- framing success = delivery / custody / Application Receipt success
- public C ABI の変更または public wire の固定完了
- V1 / field readiness / production control transport
- on-target 全 conformance 完了（ESP-IDF は packaging compile/link まで）

既存の **Ninlil application radio wire**・Legacy LinkOS 19-byte wire・Runtime Store `NLR1`・Domain Store・typed simulated bearer を **置換しない**。

| 文書 | 関係 |
| --- | --- |
| [01-architecture.md](01-architecture.md) | Site Controller ↔ Cell Agent は `gateway protocol over USB / LAN / Wi-Fi` |
| [06-versioning-and-compatibility.md](06-versioning-and-compatibility.md) | Control/gateway protocol は独立 version domain |
| [12-foundation-abi.md](12-foundation-abi.md) | public ABI 不変。本章 API は production-private（非 public） |
| [14-foundation-ports-and-simulator.md](14-foundation-ports-and-simulator.md) | Transport Custody ≠ Application Receipt |
| [18-m3-prep-esp-idf-component.md](18-m3-prep-esp-idf-component.md) | packaging 済み private source へ本 codec を接続 |
| [07-testing-and-quality.md](07-testing-and-quality.md) | golden / mutation / host ASan / ESP compile gates |

## 2. なぜ length-prefixed frame か（COBS/SLIP を選ばない）

対象は **loss しない ordered stream**（USB CDC bulk/ACM、TCP）である。

- length と magic が取れれば frame 境界は決定的に切れる。
- COBS/SLIP は delimiter 再同期に有利だが、**overhead と escape 実装**が必要で、本 slice の最小境界には不要。
- 本 slice は **magic scan + fixed max length + dual CRC fail-closed** で noise / truncation から resync する。
- 将来 unreliable datagram へ載せる場合は別 RFC で framing を再評価する。COBS を本 slice の必須とはしない。

## 3. Version domain

| Domain | 値 | 備考 |
| --- | --- | --- |
| Control frame format | major=`1`（byte `version` field） | 本章の wire layout |
| Control/gateway protocol (logical) | 最小 NCL1 v1 は [23章](23-usb-radio-boundary.md)（HELLO/PING/PONG/RESET のみ; private） | assignment/custody/security の完全 catalog は未固定 |
| Public C ABI | 変更なし | `include/ninlil/*` を触らない |
| Data wire / radio | 非対象 | application radio frame と分離 |

`version != 1` は **受理しない**（silent ignore 禁止）。将来 major は新 magic または明示 version negotiation 後にだけ導入する。

## 4. Wire layout（Normative）

全 multi-byte 整数は **unsigned big-endian**。C struct memory / host endian / padding に依存しない。

```text
offset  size  field
0       4     magic              exact ASCII "NCG1" = 4e 43 47 31
4       1     version            exact 1
5       1     type               closed catalog (§5)
6       2     flags              u16 BE; v1 は reserved=0 only
8       4     stream_or_cell_id  u32 BE (§6)
12      4     sequence           u32 BE
16      2     payload_length     u16 BE; 0..MAX_PAYLOAD
18      4     header_crc32c      u32 BE; CRC32C(bytes[0..17])
22      N     payload            exact payload_length bytes
22+N    4     frame_crc32c       u32 BE; CRC32C(bytes[0 .. 22+N-1])
```

| 定数 | 値 |
| --- | ---: |
| `HEADER_PREFIX_BYTES`（CRC 前） | 18 |
| `HEADER_BYTES`（fixed header） | 22 |
| `FRAME_CRC_BYTES` | 4 |
| `FRAME_OVERHEAD_BYTES` | 26 |
| `MAX_PAYLOAD_BYTES` | 1024 |
| `MAX_FRAME_BYTES` | 1050 |

規則:

1. total length は exact `26 + payload_length`。trailing byte を frame の一部とみなさない。
2. `payload_length > 1024` は **overflow** として fail-closed reject（読み飛ばし推定で受理しない）。
3. declared length に満たない入力は **truncation**（one-shot では reject、incremental では NEED_MORE）。
4. JSON / 可変 text schema を frame 必須 payload にしない。opaque bytes のみ。
5. heap / VLA / unbounded reassembly buffer を要求しない。caller-owned fixed buffer のみ。

### 4.1 CRC32C

- Castagnoli reflected polynomial `0x82f63b78`、initial/final XOR `0xffffffff`。
- Runtime Store / Domain Store envelope と **同一 algorithm**（corruption detection の portable 共通実装）。
- ASCII `123456789` の golden は `0xe3069283`。
- **header_crc32c** は security/authentication ではない。壊れた length を payload 読了前に落とすための early integrity。
- **frame_crc32c** も authentication ではない。full-frame bit error / cut-paste 検出。
- 暗号・MAC・session・replay は [05](05-security-and-compliance.md) / M4–M5 の別境界。**framing CRC 成功 ≠ 認証成功**。

## 5. Type catalog（closed, v1 experimental）

| type | 値 | payload | 意味（framing 層） |
| --- | ---: | --- | --- |
| `PING` | `0x01` | 0..1024 opaque | liveness; higher layer が解釈 |
| `PONG` | `0x02` | 0..1024 opaque | reply |
| `DATA` | `0x03` | 0..1024 opaque | control-plane message body carrier |
| `RESET` | `0x04` | 0..1024 opaque | stream reset / fence signal |

- `0x00` と `0x05..0xFF` は v1 で **unknown type** → reject（skip して成功扱いにしない）。
- payload の業務意味のうち、**U1–U4 最小 logical control**（NCL1 HELLO/PING/PONG/RESET）は [23章](23-usb-radio-boundary.md) が正本。custody message、assignment、TxPermit、security 等の **完全 protocol は未固定**。本 framing 章は type を closed に保ち、NCL1 未適用の payload を opaque として運ぶだけとする。

## 6. stream_or_cell_id と既存 ID 型

| 層 | 型 | 役割 |
| --- | --- | --- |
| Public identity | `ninlil_id128_t`（16 bytes） | device / runtime / site 等の stable public ID |
| Control frame multiplex | `uint32_t stream_or_cell_id` | **attachment/session 内** の stream または cell 論理 channel |

整合規則:

1. framing 層の `stream_or_cell_id` は **public 128-bit identity の代替ではない**。
2. [01](01-architecture.md) / [03](03-identity-and-join.md) の「wire 上 compact handle と public ID を同一にしなくてよい」に従い、u32 BE を framing handle とする。
3. higher layer が `controller_term + assignment_epoch` 等で cell を fence するとき、その session 内で u32 を bind する。bind 規則自体は後続 M3/M4。
4. framing codec は id の非 zero 強制をしない（0 も合法な handle 候補）。意味検証は上位。

`sequence` は per-`(stream_or_cell_id)` の単調カウンタ想定だが、**wrap / gap / replay ポリシーは上位**。codec は任意 u32 を透過する。**USB U4 single bootstrap/control stream** の exact 上位ポリシー（authority / 初期値 0 / +1 / duplicate / gap→session fence / wrap fail-closed / parser·link reset / `stream_or_cell_id` exact 0）は [23章 §5.5.2](23-usb-radio-boundary.md) が正本。

## 7. Flags

v1: **全 bit reserved zero**。`flags != 0` は reject。

将来 fragment / priority 等を major または flags 拡張で入れる場合は、本章と golden を同一 PR で更新する。unknown bit の silent clear は禁止。

## 8. Custody / Application Receipt / security 境界

```text
byte stream
  -> framing accept (magic/version/type/flags/len/CRC)
    -> control transport custody (durable spool / delivery to local agent)
      -> Application Receipt (DURABLY_RECORDED / APPLIED / ...)
```

必須の分離:

| 成功 | 意味しないこと |
| --- | --- |
| framing decode OK | peer が payload を業務適用した |
| framing decode OK | Transport Custody の durable commit |
| framing decode OK | Application Receipt |
| frame_crc OK | AEAD / session authenticity |
| USB/TCP write OK | peer が frame を受理した（上位 ACK が必要） |

Cell Agent の保存確認は Transport Custody であり、`DURABLY_RECORDED` 等の Application Receipt ではない（[01](01-architecture.md)）。本 framing はそのさらに下位の **byte 境界** だけを扱う。

## 9. Incremental parser 契約（fail-closed）

### 9.1 入力

- 1 byte 単位および任意 chunk の `feed` を許す。
- caller-owned parser state（固定 size）。heap なし。
- 受理 frame の payload は caller-owned payload buffer へ copy（borrow-only 永続 view を parser 外へ返さない）。

### 9.2 状態機械（概念）

固定 size の sliding window（max frame 1050）上で動作する。heap なし。

1. **FILL**: caller feed から必要最小限だけ window へ追加（連結 frame の後続を食い過ぎない）。
2. **ALIGN**: window 先頭が full magic `NCG1` またはその proper prefix でなければ、残差から **次の full magic** または **最長 magic-prefix suffix** へ決定的 compact。
3. **READ_HEADER**: header 22 bytes まで蓄積。
4. **VALIDATE_HEADER**（untrusted length）: version/type/flags/payload_length/header_crc。
   失敗時: **先頭 1 byte を捨てた残差** `bytes[1..]` に対し、再び full magic または最長 magic-prefix suffix を保持（header 内 embedded magic を失わない）。payload を読まず reject。
5. **READ_BODY**: header_crc 成功後だけ declared `payload_length` + frame_crc を読む（length は trusted）。
6. **VALIDATE_FRAME**: frame_crc 検査。
   失敗時: length は header_crc で確定済みのため、**corrupt candidate 全体**（exact `26 + payload_length`）を捨て、残差先頭から再開。直後の valid concatenated frame を保持する。payload 内 1-byte 再走査はしない（1024B fixed memory と trusted length 契約）。
7. **EMIT**: 1 complete frame を caller へ渡し、残差は次 candidate。

### 9.3 否定系（必須）

| 条件 | 動作 |
| --- | --- |
| bad magic / noise | ALIGN compact（full magic or magic-prefix suffix） |
| bad version / type / flags / length / header_crc | untrusted resync: drop 1 + compact residual |
| truncation mid-frame | NEED_MORE（reject しない） |
| bad frame_crc（header_crc 済み） | discard entire trusted candidate; residual 継続 |
| concatenated valid frames | 逐次 EMIT（trusted discard 後も次 frame を失わない） |
| header 内 embedded magic | untrusted resync で次 candidate として再評価 |
| 1-byte feed | 上記と同等の最終結果 |

silent drop や「CRC 失敗を成功に近い degraded accept」は禁止。

### 9.4 Parser stats（単位厳密）

全 counter は `uint32_t`、`UINT32_MAX` に **saturate**（wrap しない）。

| フィールド | 単位 | 定義 |
| --- | --- | --- |
| `frames_accepted` | frames | EMIT した complete frame 数 |
| `bytes_consumed` | bytes | feed から window へ取り込んだ入力 byte 数 |
| **`resync_skips`** | **bytes** | **resync で discard した byte 数**（event 回数ではない） |
| reject counters | events | 各 reject 種別の発生回数（1 reject = +1、saturate） |

`resync_skips` の加算規則:

| path | 加算量 |
| --- | ---: |
| untrusted reject（magic/header） | `1 + residual compact dropped` |
| trusted frame_crc fail | `frame_length + residual compact dropped` |
| noise ALIGN compact | compact が drop した bytes |

untrusted と trusted で単位を混ぜない（どちらも **discarded bytes**）。

### 9.5 Fixed memory budget

| 項目 | 値 | 備考 |
| --- | ---: | --- |
| sliding window | 1050 | `MAX_BYTES` |
| parser object ceiling | **1152** | `sizeof(parser) ≤ 1152`（ILP32/LP64）。compile-time `_Static_assert` |
| caller payload_storage | **1024** | object 外。accepted payload copy 用 |
| working-set ceiling | **2176** | `1152 + 1024`。parser + payload の合計上限 |

heap / VLA 禁止。payload buffer を parser 内に埋め込まない。

### 9.6 feed() guard と部分消費

- 1 回の `feed` は最大 `FEED_GUARD_ITERS = MAX_BYTES * 4` 回の内部 iteration。
- 各 iteration は `try_window` →（NEED_MORE かつ input 残あり）**1 byte append → 直後に必ず `try_window`**。
- 最後の guard iteration で complete frame が揃った場合、同 call で EMIT（zero-length feed 待ち禁止）。
- guard 尽きた場合は最終 `try_window` の後、未消費 input が残れば residual re-feed（通常 **`0 < *out_consumed < input_length`**）。
- pure noise（非 magic）ではおおよそ **1 input byte / 1 guard iteration**。したがって input 境界の pin は **`FEED_GUARD_ITERS-1 / == / +1`（+ trailing valid frame）**。
- 禁止: `*out_consumed == input_length` かつ `NEED_MORE` かつ complete frame が window に残留（frame_ready=0）。
- **force-progress append は持たない**（append 直後 try 契約と矛盾するため）。well-formed な fresh parser では guard 後 `out_consumed==0` かつ residual input は到達不能 invariant。
- zero-length feed（input_length=0）: 消費 0、window/stats 不変（empty / `N` / `NCG` prefix を test）。

### 9.7 Output / alias 契約

- 参加 range の **alias または address overflow**（`uintptr_t` + `UINTPTR_MAX` 減算で判定）: `NINLIL_E_INVALID_ARGUMENT`、**全 output 不変**。
- alias 排除後の他 INVALID: 文書化した out を zero / 初期化してよい。
- zero-length `ninlil_bytes_view_t` は `data == NULL` 必須。

## 10. Private API 境界と将来 public 化条件

### 10.1 現在

- 実装: `src/model/control_frame_codec.c` — **production-candidate** private portable code（`ninlil_runtime_private` 統合）
- header: `src/model/control_frame_codec.h` — **production-private / 非 public**（install しない）
- wire/API の public 化は未実施。`include/ninlil/*` への追加・変更 **禁止**（本 slice）
- ESP-IDF component は既存 [18](18-m3-prep-esp-idf-component.md) の private source authority 経由で **compile/link** するだけ。public include には出さない。

### 10.2 将来 public 化する前に必須

1. control/gateway **logical message** catalog と version negotiation の RFC。
2. security session との合成（AEAD coverage、replay、identity bind）の Normative 決定。
3. public C ABI の struct header / status / ownership 規則への適合レビュー。
4. host golden + mutation + fuzz smoke + ESP-IDF on-target subset。
5. CHANGELOG / 06章 compatibility matrix / migration note。
6. Application Receipt / custody API と成功語彙が混線しない命名レビュー。

満たすまで `ninlil_control_*` を public header に昇格させない。

## 11. 実装配置

```text
src/model/control_frame_codec.h    # production-private API（非 public）
src/model/control_frame_codec.c    # production-candidate encode/decode/parser
tests/model/control_frame_codec_test.c              # handwritten boundary
tests/model/control_frame_vector_oracle_bridge_test.c  # production C × fixture
spec/vectors/control-frame-v1.json # golden + mutation recipes
tools/control_frame_vector_gen.py  # check / emit-c-fixture / self-test
cmake/ninlil_runtime_private_sources.cmake  # source authority に追加
```

JSON mutation recipe と production C は `emit-c-fixture` の **materialised** bytes+`expected_result` で接続する。Python だけ / C 手書きだけが別々に green になる false-pass を禁止。

portable source は ESP-IDF / FreeRTOS / socket header を include しない。

## 12. Acceptance（本 framing slice のみ）

- [ ] docs が magic/version/type/flags/id/sequence/length/dual CRC/endian/max を閉じている
- [ ] zero heap / no VLA / caller-owned buffers / C11 / BE deterministic encode
- [ ] host golden vectors（independent generator と一致）
- [ ] negative: bad magic/version/type/flags/CRC、overflow length、truncation、noise resync、concat frames、1-byte incremental
- [ ] host Debug CTest 通過
- [ ] ASan 可能な環境では ASan CTest 通過
- [ ] tests-OFF private archive に public ABI 変更なし、本 codec は private symbols
- [ ] ESP-IDF component source authority に接続され esp32s3 smoke が link 可能
- [ ] public `include/ninlil/*` 無変更
- [ ] M3 complete / USB driver / security complete を文書が主張しない

## 13. 明示的に残る work

- USB CDC / TCP port task と backpressure（境界は [23章](23-usb-radio-boundary.md) U0 freeze / 実装は U1–U7）
- control logical messages の assignment/custody 拡張（NCL1 最小 HELLO 系は 23章; 完全 protocol は後続）
- custody spool と Application Receipt の結合
- authentication / encryption of control channel
- Cell Agent skeleton 全体との結合
- on-target conformance beyond compile smoke
