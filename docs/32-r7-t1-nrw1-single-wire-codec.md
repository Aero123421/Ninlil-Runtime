# 32. R7 T1 NRW1 SINGLE Wire Codec

状態: **Accepted / R7 T1 NRW1 SINGLE private pure wire codec implementation candidate; independent POST-CI 2026-07-19 P0=P1=P2=0 GO**  
正本 ADR: [ADR-0012](adr/0012-r7-t1-nrw1-single-wire-codec.md)（Accepted）  
受入記録: [2026-07-19 R7 T1 Accepted review](reviews/2026-07-19-r7-t1-single-wire-codec-accepted.md)  
前提: [30章](30-r6-secure-radio-wire.md) の R6 wire freeze、
[31章](31-r7-crypto-provider-and-aead.md) の Accepted T0 private crypto provider

本章は、`wire_profile_id=0x11` の `DATA / SINGLE` を byte-exact に Seal/Open する
**production-private、stateless な pure codec 候補**を R7 T1 として定義する。
T1 は W1 が後続で利用する byte codec であり、W1/L1、counter/storage、replay admission、
relay、LINK_ACK、fragmentation、CELL/HA、M4/M5、radio driver の完成ではない。

**SEMANTIC: R7_T1_PRIVATE_PURE_SINGLE_CODEC_ONLY**  
**SEMANTIC: R7_T1_CALLER_SUPPLIES_KEYS_IVS_COUNTERS**  
**SEMANTIC: R7_T1_NO_N6_R2_R5_COMPILE_DEPENDENCY**  
**SEMANTIC: R7_T1_DUAL_ENVELOPE_REQUIRED**  
**SEMANTIC: R7_T1_FAILURE_CALLER_MUTATION_ZERO**  
**SEMANTIC: R7_T1_LAYER_ATOMIC_PUBLISH**  
**SEMANTIC: R7_T1_NO_STATE_BYPASS_COMPOSITE_API**  
**SEMANTIC: R7_T1_SUBSET_VECTORS_NOT_R7_FULL_MATERIALIZATION**  
**SEMANTIC: R7_T1_PUBLIC_ABI_UNCHANGED**

## 1. Decision and boundary

依存方向は次の exact graph とする。

```text
future W1 orchestration
    -> R7 T1 private pure SINGLE codec
        -> R7 T0 portable crypto wrapper
            -> Host OpenSSL 3 adapter / ESP-IDF mbedTLS adapter
```

T1 production sourceは `src/radio/r7_wire_codec.{h,c}` とし、private archive と
ESP-IDF private componentからのみ使う。`include/ninlil/`、install include、public libraryへ
公開しない。T1 sourceは次をincludeまたはcallしてはならない。

- `n6_*`、R2 permit、R5 profile、radio HAL、SX1262、USB/TCP、OS clock/storage
- Host OpenSSL header、ESP mbedTLS header、platform factory header
- KGuard固有型、application schema、logical transaction型

crypto primitive、nonce XOR、認証前publish policyを再実装せず、必ず31章の
`ninlil_r7_crypto_*` wrapperを使う。R6 N6 production sourceとR7 T0 provider contractは
変更しない。

## 2. T1 closed scope

### 2.1 含む

1. outer DATA AAD19のpack/parse
2. E2E SINGLE AAD14のpack/parse
3. E2E SINGLE blobのSeal/Open
4. outer DATA/SINGLE frameのSeal/Open
5. LOCAL terminal tupleとrelay tupleのstructural validation
6. exact length/capacity、checked arithmetic、全partial alias reject
7. failure時の全caller output/input/length mutation zero
8. 独立oracle、golden bridge、negative/mutation/packaging/stack/platform/ESP link gates

### 2.2 含まない

- raw application plaintextへouter hop AEADだけを掛けるAPI
- E2Eとouterを一発で処理してstateful orderを迂回するcomposite Seal/Open API
- E2E/outer counter allocate/burn、RX replay precheck、durable admit
- context/route lookup、`record.max_hops`、lease、grant、queue、ACK policyの決定
- LINK_ACK body、FRAG_START/CONT/ACK body、reassembly/tombstone state machine
- relay forward、L1/W1 event bus、STAMP、FRAME_READY、R1 issue pipeline
- binding canonical encode、traffic-secret HKDF schedule（後続T1b）
- M4 Attachment、M5 resume、CELL_64、HA、multi-parent
- RF/USB HIL、ESP実機KAT、Japan legal、production radio
- `spec/vectors/r7-radio-wire-v1.json` の全materialization

## 3. Exact wire constants and fields

T1は30章 §§6–7を変更せず、次をexactに実装する。

| item | exact value/domain |
| --- | ---: |
| wire profile | `0x11`、minorなし |
| outer kind | DATA=`1` only |
| outer flags | bits 3..1=`0`; bit0 ACK_REQUESTED=`0|1` |
| outer AAD | 19 bytes |
| E2E type | SINGLE=`1` only; low nibble=`0` |
| E2E AAD | 14 bytes |
| GCM tag | each layer 16 bytes |
| application plaintext N | `1..190` |
| E2E sealed blob | `30+N` = `31..220` |
| outer frame | `65+N` = `66..255` |
| context id | `1..UINT32_MAX-1` |
| counter | `1..UINT64_MAX-1` |

整数は全てbig-endian。encode APIではprofile/kind/typeをcaller fieldにせず定数として
生成する。decode APIはvisible bytesを検査し、profile、kind、type、reserved bitsの不一致を
structural failureにする。

outer DATA route tupleは次のclosed setとする。

| route_handle | route_generation | hop_remaining | T1 result |
| ---: | ---: | ---: | --- |
| 0 | 0 | 0 | valid terminal/local tuple |
| nonzero | nonzero | 1..255 | structurally valid relay tuple |
| other | other | any | reject |

T1は`record.max_hops`を知らないため、nonzero tupleのlease/max_hops妥当性を主張しない。
後続ownerがcodec呼出し前に検査する。

## 4. Private API v1

型と関数名はprivate source ABIで固定し、wire/public ABIにはしない。statusは`int32_t`で
次のclosed setを持つ。

| value | status | meaning |
| ---: | --- | --- |
| 0 | `NINLIL_R7_WIRE_OK` | 全出力をatomic publishした |
| 1 | `NINLIL_R7_WIRE_INVALID_ARGUMENT` | caller API shape/provider/NULLが不正 |
| 2 | `NINLIL_R7_WIRE_STRUCTURAL` | profile/catalog/reserved/route/context/counter bytesが不正 |
| 3 | `NINLIL_R7_WIRE_LENGTH_CLASS` | wire/app length domainが不正 |
| 4 | `NINLIL_R7_WIRE_CAPACITY` | output capacityがrequired exact valueでない |
| 5 | `NINLIL_R7_WIRE_ALIAS` | 禁止spanが1 byte以上overlap |
| 6 | `NINLIL_R7_WIRE_AUTH_FAILED` | GCM認証失敗 |
| 7 | `NINLIL_R7_WIRE_BACKEND_FAILED` | provider/library operation failure |
| 8 | `NINLIL_R7_WIRE_INTERNAL_CONTRACT` | impossible callback/result/produced shape |

wire APIはprovider shapeをstep 1で直接検査し、不正ならwire `INVALID_ARGUMENT`、crypto call 0と
する。その後、wire-owned exact bufferをT0 wrapperへ渡した結果は次にmapする。

| crypto result after wire prevalidation | wire result |
| --- | --- |
| `OK` | `OK`（さらにproduced shape検査後） |
| `AUTH_FAILED` on Open | `AUTH_FAILED` |
| `BACKEND_FAILED` | `BACKEND_FAILED` |
| `INTERNAL_CONTRACT` | `INTERNAL_CONTRACT` |
| `INVALID_ARGUMENT` / `CAPACITY` / `ALIAS` | `INTERNAL_CONTRACT` |
| unknown | `INTERNAL_CONTRACT` |

wire prevalidation後のT0 `INVALID_ARGUMENT/CAPACITY/ALIAS`はcaller faultではなく、wire内部組立の
契約違反である。後段結果を成功または別のcaller errorへ縮退しない。

private structs:

```c
typedef int32_t ninlil_r7_wire_status;

typedef struct ninlil_r7_wire_outer_data_fields {
    uint8_t  ack_requested;      /* exact 0 or 1 */
    uint8_t  hop_remaining;
    uint32_t hop_context_id;
    uint64_t hop_counter;
    uint16_t route_handle;
    uint16_t route_generation;
} ninlil_r7_wire_outer_data_fields;

typedef struct ninlil_r7_wire_e2e_single_fields {
    uint32_t e2e_context_id;
    uint64_t e2e_counter;
} ninlil_r7_wire_e2e_single_fields;
```

required API families:

```c
ninlil_r7_wire_status ninlil_r7_wire_pack_outer_data_aad(
    const ninlil_r7_wire_outer_data_fields *fields,
    uint8_t *out_aad19, size_t out_capacity);
ninlil_r7_wire_status ninlil_r7_wire_parse_outer_data_aad(
    const uint8_t *aad19, size_t aad_len,
    ninlil_r7_wire_outer_data_fields *out_fields);

ninlil_r7_wire_status ninlil_r7_wire_pack_e2e_single_aad(
    const ninlil_r7_wire_e2e_single_fields *fields,
    uint8_t *out_aad14, size_t out_capacity);
ninlil_r7_wire_status ninlil_r7_wire_parse_e2e_single_aad(
    const uint8_t *aad14, size_t aad_len,
    ninlil_r7_wire_e2e_single_fields *out_fields);

ninlil_r7_wire_status ninlil_r7_wire_seal_e2e_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16], const uint8_t static_iv12[12],
    const ninlil_r7_wire_e2e_single_fields *fields,
    const uint8_t *app, size_t app_len,
    uint8_t *out_blob, size_t out_capacity, size_t *out_len);
ninlil_r7_wire_status ninlil_r7_wire_open_e2e_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16], const uint8_t static_iv12[12],
    const uint8_t *blob, size_t blob_len,
    ninlil_r7_wire_e2e_single_fields *out_fields,
    uint8_t *out_app, size_t out_capacity, size_t *out_len);

ninlil_r7_wire_status ninlil_r7_wire_seal_outer_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16], const uint8_t static_iv12[12],
    const ninlil_r7_wire_outer_data_fields *fields,
    const uint8_t *e2e_blob, size_t e2e_blob_len,
    uint8_t *out_frame, size_t out_capacity, size_t *out_len);
ninlil_r7_wire_status ninlil_r7_wire_open_outer_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16], const uint8_t static_iv12[12],
    const uint8_t *frame, size_t frame_len,
    ninlil_r7_wire_outer_data_fields *out_fields,
    uint8_t *out_e2e_blob, size_t out_capacity, size_t *out_len);
```

各Seal/Openはprovider、key16、static_iv12、field、input、input length、output、
output capacity、output length pointerを明示引数に持つ。key/IV/counterを生成、保存、
incrementしない。

pack output capacityは19または14のexact、Seal/Open output capacityは入力長から一意に
求めたrequired exact valueでなければならない。output lengthとdecoded fieldsは成功時だけ
publishする。

## 5. Per-API exact validation and call order

ここでいうprovider callback countはraw AES-GCM callback数である。provider shape validationと
nonce helperはcallbackではない。各APIは下記の上から最初のfailureを返し、後段statusで
上書きしない。

### 5.1 AAD pack/parse

`pack_outer_data_aad` / `pack_e2e_single_aad`:

1. required pointer shape
2. caller field domain（context/counter、outerはACK/route tupleも含む）
3. exact output capacity（19 / 14）
4. field inputとoutputのchecked span/alias
5. local candidateへpack、exact shape確認、outputへ一括publish

`parse_outer_data_aad` / `parse_e2e_single_aad`:

1. required pointer shape
2. input length exact（19 / 14。under/overとも`LENGTH_CLASS`）
3. visible profile/kind-or-type/reserved/context/counter/route structural check
4. inputとdecoded field outputのchecked span/alias
5. local field candidateを一括publish

全pack/parse pathでprovider callback countは0、failure mutationは0。

### 5.2 `seal_e2e_single`

1. provider exact shape、required pointer shape
2. caller E2E field domainとapplication length `1..190`
3. output capacity exact `30+N`
4. 全caller spanのchecked overflow/alias
5. fixed profile/typeを含むAAD14をlocal candidateへpack
6. sole nonce helper（failureならprovider callback 0）
7. AES-GCM Seal callback exact 1
8. crypto status mapとproduced `N+16` exact shape
9. `AAD14 || CT || TAG16`をlocal blobで確認し、blob/output lengthを一括publish

step 1–6 failureはprovider callback 0、step 7以降はexact 1。

### 5.3 `open_e2e_single`

1. provider exact shape、required pointer shape
2. input blob length `31..220`（checked `N=blob_len-30`）
3. visible AAD14のprofile/type/low nibble/context/counter structural check
4. output capacity exact `N`
5. 全caller spanのchecked overflow/alias
6. sole nonce helper（visible counterを使用）
7. AES-GCM Open callback exact 1
8. crypto status mapとproduced `N` exact shape
9. decoded field candidate、application、output lengthを一括publish

step 1–6 failureはprovider callback 0、step 7以降はexact 1。standalone E2E Openも30章
§7.2のstructural-before-AEAD順序を守り、outer経由時だけ検査する実装にしない。

### 5.4 `seal_outer_single`

1. provider exact shape、required pointer shape
2. caller outer field domain
3. input E2E blob length `31..220`
4. input E2E blobのvisible AAD14/type/context/counterとSINGLE length structural check
5. output capacity exact `35+blob_len`
6. 全caller spanのchecked overflow/alias
7. outer AAD19 packとsole nonce helper
8. AES-GCM Seal callback exact 1
9. crypto status mapとproduced `blob_len+16` exact shape
10. `AAD19 || CT || TAG16`をlocal frameで確認し、frame/output lengthを一括publish

step 1–7 failureはprovider callback 0、step 8以降はexact 1。step 4はE2E tag authenticityを
証明せず、visible structural guardだけである。

### 5.5 `open_outer_single`

1. provider exact shape、required pointer shape
2. input packet length `66..255`（checked `blob_len=frame_len-35`）
3. visible AAD19のprofile/kind/reserved/ACK/route/context/counter structural check
4. output capacity exact `blob_len`
5. 全caller spanのchecked overflow/alias
6. sole nonce helper（visible counterを使用）
7. AES-GCM Open callback exact 1
8. crypto status mapとproduced `blob_len` exact shape
9. outer-authenticated candidate内のE2E AAD14/type/context/counter/SINGLE length structural check
10. outer field candidate、E2E blob、output lengthを一括publish

step 1–6 failureはprovider callback 0、step 7以降はexact 1。step 9 failureでもcaller outputは
mutation zeroで、provider callback countは1。各layerはそのlayerのfield/output/lengthだけを
atomic publishする。

counter `0`/`UINT64_MAX`はnonce helper/provider call 0。T1はnonce XORを再実装しない。

T1 production APIはcomposite Seal/Openを持たない。30章の送信順序はE2E counter burn→E2E
Seal→owner/group durable transition→hop counter burn→outer Sealであり、受信順序も各layerの
replay/durable admissionを挟む。one-shot APIはこのstateful interleaveを迂回するため禁止する。
golden bridgeはtest内でlayer APIを順に呼んでfull frame bytesを検証してよいが、そのhelperを
production sourceへ入れない。outer Sealは入力がstructurally validなSINGLE E2E blobでない限り
provider call 0でrejectする。これはaccidental misuseを防ぐstructural guardであり、E2E keyを
持たないouter layerはtagの真正性やblob provenanceを証明できない。真正なlocal E2E blobを渡す
owner/slot invariantと、relayでouter-authenticated blobだけを再wrapするprovenance invariantは
後続W1が所有する。T1の「outer-only禁止」はraw application plaintextを直接受けるAPIを提供
しないという意味であり、悪意あるtrusted callerがE2E形状に偽装したbytesまで暗号学的に拒否
できるとの主張ではない。

T1 pure codecはstructural checkとAEADだけを所有する。30章のstateful order
`structural -> replay precheck -> AEAD -> durable admission -> body`のうち、replay/durable stepsを
代行した、または省略して安全になったとは主張しない。

## 6. Ownership, alias, and mutation contract

provider object、key、IV、field struct、non-empty input、output、output length、decode field outputの
各spanをchecked arithmetic後にpairwise検査する。exact in-placeとpartial overlapは禁止し、
`end(A)==begin(B)`の隣接だけ許す。pointer end overflowと`size_t > UINTPTR_MAX`をfail closedにする。

全failure statusで次をbyte-exact mutation zeroに保つ。

- caller output buffer全域とoutput length
- decoded field outputs
- provider object、key、IV、field input、wire/application input

T1はbounded local candidateへ生成/復号し、成功後だけそのlayerの出力をpublishする。
candidate、nonce、AAD、plaintext copyは
success/failure全pathで31章と同じvolatile-store + compiler fence patternを持つT1-local helperで
消去する。T0のprivate ABI/sourceをzeroize共有のために変更しない。heap、VLA、unbounded
recursionを使わない。

## 7. Independent oracle and T1 subset vectors

T1は新しい独立stdlib Python oracle `tools/r7_wire_single_oracle.py` を持つ。T0の
`tools/r7_radio_wire_oracle.py` と37-vector artifactを変更しない。oracleはproduction C、
OpenSSL/cryptography binding、generated C fixtureを計算の正本にしない。

T1 artifactは次のprivate pathを使う。

```text
tests/radio/private/r7_wire_single_t1_vectors.json
tests/radio/private/r7_wire_single_t1_vectors.gen.h
```

format idは `ninlil-r7-wire-single-t1-v1`。JSONはstable key order、lowercase hex、stable ID、
末尾newlineを持ち、異なるtemporary directoryと`PYTHONHASHSEED`で2回生成してbyte-identicalを
検査する。C bridgeは生成件数をexactに全件消費し、skip/duplicate/unknownをfailする。

mandatory success IDs:

- `R7-T1-SINGLE-N1`
- `R7-T1-SINGLE-N16`
- `R7-T1-SINGLE-N24`
- `R7-T1-SINGLE-N32`
- `R7-T1-SINGLE-N190`
- `R7-T1-SINGLE-HIGH-COUNTER`
- `R7-T1-SINGLE-RELAY-TUPLE`

各vectorはapplication bytes、両field set、key/IV、nonce、AAD、CT、tag、E2E blob、outer full
frameを持つ。N=16/24/32のouter長は81/89/97、N=1は66、N=190は255をassertする。

このartifactは30章 §18.15–16のfull artifactではなく、`spec/vectors/r7-radio-wire-v1.json`
を作成した、またはmandatory full vector/state setを満たしたと主張してはならない。T1 subsetを
full pathへcopy/renameしない。

## 8. Negative and mutation gates

少なくとも次をproduction APIへ実行する。

- profile、kind、reserved bits、E2E type/low nibbleの各invalid
- context 0/MAX、counter 0/MAX、route tuple不一致
- N=0/191、packet 65/256、E2E blob 30/221、underflow前subtract
- exact capacity -1/+1、NULL、全input/output/key/IV/field/length partial alias classes
- outer/E2E AAD、CT、tagのbit flip。tagは各128 bitを個別にflip
- broken provider、unknown raw status、partial write、input poison、wrong produced length
- failure時canary、output/length/decoded fields/input mutation zero
- outer Sealへ非E2E bytesを渡した場合のprovider call 0

mutation self-testは、vector drop、bridge skip、expected tag flip、gate skip、source authority重複、
package leak、stack ceiling違反、platform crypto header混入をそれぞれ実際にredにする。

## 9. Build, packaging, stack, and ESP gates

T1は新しいsingle authorityを持つ。

```text
cmake/ninlil_r7_wire_sources.cmake
cmake/ninlil_r7_wire_ctest.cmake
tools/nrw1_t1_ctest_gate.py
```

CTest名は `nrw1_t1_*` とし、T1 gateがnormal/sanitizer profileごとの登録multisetをexact管理する。
既存T0の16/15 test exact-set authorityは`r7_*`だけを引き続きexact管理し、sourceもtoolも
変更しない。CIはT0とT1の両gateを必須実行する。T1を別prefixにする理由は、Accepted済みT0の
required names/count/behaviorを削除・skip・presence-onlyへ弱めずsliceを追加するためである。

受入matrix:

1. Linux/macOS、Clang/GCC、Debug/Release strict build
2. ASan/UBSan full CTest。sanitizerでtest skipを増やさない
3. oracle deterministic twice、freshness、bridge exact count、mutation self-tests
4. tests-OFF fresh buildでprivate archive object/symbol exact once
5. install tree/public libraries/includesへwire symbol/header/vector/test/tool 0
6. portable sourceにOS/heap/VLA/OpenSSL/mbedTLS/N6/R2/R5/HAL token/dependency 0
7. GCC Release exact `-O2` + `-fstack-usage` compile command authority
8. production wire functionsはstatic frame `<=2560 bytes`。dynamic/bounded/VLAはreject
9. ESP-IDF v5.5.3 componentへportable source exact once、final ESP32-S3 ELFから実参照
10. T0/R6 hash/gateおよびfull existing CTest無退行

2560 bytesはT1 host candidate単体の初期ceilingであり、adapter callback chainやESP task stackの
十分性を意味しない。ESP compile/linkは実機KAT、RF、USB、timing、power-cut HILの代替ではない。

## 10. Acceptance boundary

T1をAcceptedへ変更できるのは、production code freeze後に次を全て満たした場合だけとする。

- §9のlocal/push/PR/ESP CI evidenceが全成功
- independent review P0=0/P1=0/P2=0
- implementation SHA、CI run ID、vector count、stack resultをreview recordに固定
- README/roadmap/CHANGELOGが「T1 private pure SINGLE codec candidate」と未完了境界を正確に表示

Accepted後も次は未実装または未検証である。

- 30章 §18.15–16のfull wire/state artifact
- counter/storage/replay/durable admission、FRAG/LINK/CELL/HA、W1/L1
- M4/M5、ESP実機KAT、RF/USB HIL、Japan legal、production radio
