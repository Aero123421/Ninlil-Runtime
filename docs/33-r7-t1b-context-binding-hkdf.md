# 33. R7 T1b Context Binding and HKDF Schedule

状態: **Proposed / docs-only; implementation and acceptance pending**  
提案 ADR: [ADR-0013](adr/0013-r7-t1b-context-binding-hkdf.md)（Proposed）  
前提: [30章](30-r6-secure-radio-wire.md) の Accepted R6 wire freeze、
[31章](31-r7-crypto-provider-and-aead.md) の Accepted T0、
[32章](32-r7-t1-nrw1-single-wire-codec.md) の Accepted T1

本章は NRW1 の Hop/E2E context binding bytes、binding digest、traffic secret からの
key/IV導出を **production-private、portable C11のpure候補**として固定する。
R6 §8のbytesと式を変更しない。T1bはcontext install、鍵配布、counter、storage、replay、
W1/N6/M4/M5、radio、法規または実機HILを完成させない。

**SEMANTIC: R7_T1B_PRIVATE_PURE_BINDING_SCHEDULE_ONLY**  
**SEMANTIC: R7_T1B_R6_SECTION8_BYTE_EXACT**  
**SEMANTIC: R7_T1B_FIXED_PROFILE_AND_LABELS_NOT_CALLER_SELECTED**  
**SEMANTIC: R7_T1B_VERIFIED_DERIVE_ONLY**  
**SEMANTIC: R7_T1B_ATOMIC_TYPED_KEY_BUNDLES**  
**SEMANTIC: R7_T1B_FAILURE_CALLER_MUTATION_ZERO**  
**SEMANTIC: R7_T1B_INTERNAL_SECRETS_ZERO_ALL_PATHS**  
**SEMANTIC: R7_T1B_PUBLIC_ABI_UNCHANGED**

## 1. Boundary and dependency direction

依存方向は次のexact graphとする。

```text
future authenticated capsule/install owner (M4/N6/W1)
    -> R7 T1b private context binding + verified key schedule
        -> R7 T0 portable crypto wrapper
            -> Host OpenSSL 3 adapter / ESP-IDF mbedTLS adapter
```

production source authorityは次の2 filesだけとする。

```text
src/radio/r7_context_binding.h
src/radio/r7_context_binding.c
```

build/test registration authorityは`cmake/ninlil_nrw1_t1b_ctest.cmake`の1 fileとし、top-level
`CMakeLists.txt`はこのauthorityをexact once includeする。

これらはprivate archiveとESP-IDF private componentからだけ使用し、`include/ninlil/`、install
include、public libraryへ公開しない。portable sourceはOS、heap、VLA、OpenSSL、mbedTLS、N6、
R2、R5、W1、radio HAL、SX1262、USB、KGuard型をinclude/callしてはならない。
R6/T0/T1のAccepted source/API/semanticを変更しない。

## 2. Closed scope and non-claims

T1bに含むもの:

1. Hop/E2E `encode_canon` inputのvalidationとbyte-exact encode
2. T0 SHA-256 wrapperによるbinding digest
3. authenticated ownerから渡されたexpected digestとの固定時間比較
4. T0 HKDF Extract/Expand wrapperによるtyped Hop/E2E key bundleのatomic導出
5. failure mutation zero、partial-alias reject、secret zeroization
6. 独立oracle、golden、fault/mutation、package/platform/stack、ESP final-link gates

T1bに含まないもの:

- expected digestまたは`traffic_secret32`の生成、認証、配布、保存、cache
- authenticated capsuleのparse、context install、handle発行、key generation/rotation
- counter allocate/burn、nonce、AEAD Seal/Open、replay admission、durable TX/RX
- T1 codecとのcomposite API、W1/L1、N6、M4/M5、Attachment/Join
- LINK/FRAG/CELL/HA、relay、routing、radio MAC、RF/USB HIL
- FIELD/PRODUCTION/Japan legalまたはR7 full completion
- full `spec/vectors/r7-radio-wire-v1.json` materialization

## 3. Exact private types and domains

### 3.1 Common span

```c
typedef struct ninlil_r7_binding_bytes {
    const uint8_t *bytes;
    uint16_t length;
} ninlil_r7_binding_bytes;
```

`length > 0`なら`bytes != NULL`、`length == 0`なら`bytes == NULL`をexact shapeとする。
callerはcall中、top-level struct、全pointer target、provider、expected digest、traffic secretを
生存かつbyte-immutableに保つ。実装はpointerを保持せず、return後に読まない。

### 3.2 Hop input

```c
typedef struct ninlil_r7_hop_binding_input {
    uint8_t environment_code;
    ninlil_r7_binding_bytes site_domain;
    uint64_t membership_epoch;
    ninlil_r7_binding_bytes attachment_id;
    uint64_t attachment_epoch;
    ninlil_r7_binding_bytes initiator_stable_id;
    ninlil_r7_binding_bytes responder_stable_id;
    ninlil_r7_binding_bytes controller_authority_id;
    uint64_t controller_term;
    uint32_t hop_context_id;
    uint8_t direction_code;
} ninlil_r7_hop_binding_input;
```

`wire_profile_id=0x11`と`allowed_kind_mask=0x0003`はcaller fieldにせず、encoderがfixed bytesを
挿入する。caller選択APIまたはgeneric mask APIを置かない。

### 3.3 E2E input

```c
typedef struct ninlil_r7_e2e_binding_input {
    uint8_t environment_code;
    ninlil_r7_binding_bytes site_domain;
    uint64_t membership_epoch;
    ninlil_r7_binding_bytes e2e_security_id;
    uint64_t e2e_security_epoch;
    ninlil_r7_binding_bytes sender_stable_id;
    ninlil_r7_binding_bytes receiver_stable_id;
    ninlil_r7_binding_bytes authority_id;
    uint64_t authority_term;
    uint32_t e2e_context_id;
    uint8_t direction_code;
} ninlil_r7_e2e_binding_input;
```

E2E inputへattachment、route、Hop contextまたはparent fieldを追加しない。

### 3.4 Environment matrix

`environment_code`はLAB=`1`、FIELD=`2`だけとする。全context IDは
`1..UINT32_MAX-1`、directionはIR=`0`またはRI=`1`だけとする。

| environment | site domain | stable/security/attachment IDs | authority ID / term | epochs |
| --- | --- | --- | --- | --- |
| FIELD `2` | exact 16、not-all-zero | relevant fields each 1..32 | 1..32 / `>0` | relevant fields all `>0` |
| LAB controller | 1..16 | relevant fields each 1..32 | 1..32 / `>0` | membership/attachment/security all `>0` |
| LAB no-controller | 1..16 | non-authority fields each 1..32 | exact length 0 + NULL / exact term `0` | membership/attachment/security all `>0` |

Hopのrelevant epochはmembership/attachment/controller term、E2Eは
membership/e2e-security/authority termである。authority lengthとtermの片方だけがzeroの混成を
rejectする。LABのsite domainにはnot-all-zeroを追加要求しない。FIELDの全zeroだけをrejectする。

## 4. Byte-exact canonical encoding

整数はBE exact width、opaqueは`u16be length || bytes`、labelはASCII bytesのみでNULを含めない。

Hopは次をordered concatする。

```text
ASCII("NINLIL-R6-HOP-CTX-v1")                    20
u8 0x11                                           1
u8 environment_code                               1
opaque site_domain                              2+S
u64 membership_epoch                              8
opaque attachment_id                            2+A
u64 attachment_epoch                              8
opaque initiator_stable_id                      2+I
opaque responder_stable_id                      2+R
opaque controller_authority_id                  2+C
u64 controller_term                               8
u32 hop_context_id                                 4
u8 direction_code                                  1
u16 0x0003                                         2
```

exact lengthは`63 + S + A + I + R + C`、最大は`207`。有効最小はFIELD `83`、
LAB controller `68`、LAB no-controller `67`である。

E2Eは次をordered concatする。

```text
ASCII("NINLIL-R6-E2E-CTX-v1")                    20
u8 0x11                                           1
u8 environment_code                               1
opaque site_domain                              2+S
u64 membership_epoch                              8
opaque e2e_security_id                          2+Q
u64 e2e_security_epoch                            8
opaque sender_stable_id                         2+X
opaque receiver_stable_id                       2+Y
opaque authority_id                             2+U
u64 authority_term                                8
u32 e2e_context_id                                 4
u8 direction_code                                  1
```

exact lengthは`61 + S + Q + X + Y + U`、最大は`205`。有効最小はFIELD `81`、
LAB controller `66`、LAB no-controller `65`である。

encode output capacityは算出したrequired lengthとexact equalでなければならない。成功時だけ
canonical bytesと`out_len`を一括publishする。余剰capacityも不足capacityもrejectする。

## 5. Exact status and API

statusは`int32_t`のprivate closed setとし、wire/public ABIにしない。

| value | status | meaning |
| ---: | --- | --- |
| 0 | `NINLIL_R7_BINDING_OK` | 全outputをatomic publishした |
| 1 | `NINLIL_R7_BINDING_INVALID_ARGUMENT` | NULL、pointer/zero-length span shape、provider shapeが不正 |
| 2 | `NINLIL_R7_BINDING_STRUCTURAL` | site/ID length domain、environment、matrix、epoch、context、directionが不正 |
| 3 | `NINLIL_R7_BINDING_CAPACITY` | canonical output capacityがexactでない |
| 4 | `NINLIL_R7_BINDING_ALIAS` | mutable outputとcaller spanが1 byte以上overlap |
| 5 | `NINLIL_R7_BINDING_MISMATCH` | recomputed digestとexpected digestが不一致 |
| 6 | `NINLIL_R7_BINDING_BACKEND_FAILED` | crypto backend operation failure |
| 7 | `NINLIL_R7_BINDING_INTERNAL_CONTRACT` | impossible T0 result/shapeまたはunknown result |

required APIは次の6つだけとする。

```c
int32_t ninlil_r7_encode_hop_binding(
    const ninlil_r7_hop_binding_input *input,
    uint8_t *out, size_t out_capacity, size_t *out_len);
int32_t ninlil_r7_encode_e2e_binding(
    const ninlil_r7_e2e_binding_input *input,
    uint8_t *out, size_t out_capacity, size_t *out_len);

int32_t ninlil_r7_digest_hop_binding(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *input,
    uint8_t out_digest32[32]);
int32_t ninlil_r7_digest_e2e_binding(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *input,
    uint8_t out_digest32[32]);
```

typed output bundles:

```c
typedef struct ninlil_r7_hop_key_bundle {
    uint8_t data_key16[16];
    uint8_t data_iv12[12];
    uint8_t ack_key16[16];
    uint8_t ack_iv12[12];
} ninlil_r7_hop_key_bundle;

typedef struct ninlil_r7_e2e_key_bundle {
    uint8_t key16[16];
    uint8_t iv12[12];
} ninlil_r7_e2e_key_bundle;

int32_t ninlil_r7_derive_hop_key_bundle_verified(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *input,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_hop_key_bundle *out_bundle);

int32_t ninlil_r7_derive_e2e_key_bundle_verified(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *input,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_e2e_key_bundle *out_bundle);
```

PRKを返すAPI、labelをcallerが選ぶAPI、個別laneだけを導出するAPI、expected digestなしのderive、
T1 Sealとのcomposite APIをproductionへ置かない。

## 6. Validation, alias, and publish order

全APIのvalidation priorityは次のexact orderとする。

1. top-level/provider/required output pointer shape
2. 全opaque pointer/zero-length shape
3. site/ID length domain、environment matrix、epoch、context、direction domain
4. encodeだけrequired capacity
5. checked `uintptr_t` span endとmutable-output alias
6. local canonical candidateのencodeとexact length確認
7. provider operation、digest comparison、HKDF operation
8. result shape確認とatomic publish

前段errorを後段statusで上書きしない。steps 1–6のfailureはprovider callback 0。

全mutable outputs（canonical buffer、`out_len`、digest、bundle）は互いに、top-level input struct、
その全non-empty pointed spans、provider object、expected digest、traffic secretと1 byte以上overlapしては
ならない。read-only input同士のoverlapは許容する。provider `ctx`のsizeはABIから不明なため、
callerはT0 contractどおり全caller/wrapper spanとのdisjointを保証する。pointer end overflowは
`ALIAS`、pointerを参照する前のshape/length errorは先行statusとする。

failure時はcallerの全input、output buffer全域、`out_len`、digest、bundleをbyte-exactに変更しない。
zero-fillはmutation zeroではない。実装は最大207-byte canonical candidateへ組み立て、成功時だけ
publishする。

## 7. Digest verification and HKDF schedule

binding digestはT0 `ninlil_r7_crypto_sha256`だけで計算する。独自SHAまたはplatform crypto callを
置かない。verified deriveはcanonical inputからlocal digestを再計算し、32 bytesすべてを読む
固定iteration比較でexpected digestと照合する。mismatch時はSHA callback exact 1、HKDF callback 0、
output mutation 0とする。

expected digestは将来のauthenticated capsule/install ownerが供給しなければならない。
T1bはprovenanceを証明できないためinstall authorityではない。ownerが同じuntrusted inputへ
`digest_*`を呼び、その結果をexpectedとして折り返すことは禁止する。これを型で完全強制するのは
M4 capsule tokenの責務だが、T1bには少なくともexpectedなしderiveという迂回APIを置かない。

digest一致後のexact schedule:

```text
PRK_hop = HKDF-Extract(local_digest32, traffic_secret32)
DATA key16 = HKDF-Expand(PRK_hop, "NINLIL-R6-HOP-DATA-KEY-v1", 16)
DATA iv12  = HKDF-Expand(PRK_hop, "NINLIL-R6-HOP-DATA-IV-v1", 12)
ACK  key16 = HKDF-Expand(PRK_hop, "NINLIL-R6-HOP-ACK-KEY-v1", 16)
ACK  iv12  = HKDF-Expand(PRK_hop, "NINLIL-R6-HOP-ACK-IV-v1", 12)

PRK_e2e = HKDF-Extract(local_digest32, traffic_secret32)
E2E key16 = HKDF-Expand(PRK_e2e, "NINLIL-R6-E2E-KEY-v1", 16)
E2E iv12  = HKDF-Expand(PRK_e2e, "NINLIL-R6-E2E-IV-v1", 12)
```

labelはASCII bytes、NULなし、caller非選択。lengthは順に25/24/24/23/20/19であり、T0の
`info_len 0..25`内に全て収まる。key/IVを個別publishせず、全Expand成功後にtyped bundleを
一括publishする。salt、IKM、labelが変われば必ず再計算し、cacheしない。

## 8. Provider call counts and status mapping

| path | SHA | Extract | Expand | result |
| --- | ---: | ---: | ---: | --- |
| prevalidation/capacity/alias failure | 0 | 0 | 0 | exact caller error |
| digest success | 1 | 0 | 0 | OK |
| verified mismatch | 1 | 0 | 0 | MISMATCH |
| Hop verified success | 1 | 1 | 4 | OK |
| E2E verified success | 1 | 1 | 2 | OK |

SHA/Extract/Expandのbackend failureはattempted callbackまでで停止し、後続call 0。
T1bからT0 wrapperを正しいshapeで呼んだ後、`BACKEND_FAILED`は同名へmapし、
`INVALID_ARGUMENT`、`CAPACITY`、`ALIAS`、`AUTH_FAILED`、`INTERNAL_CONTRACT`、unknownは
`INTERNAL_CONTRACT`へmapする。unknownを成功へ縮退しない。

local canonical bytes、local digest、traffic-secret copy、PRK、全OKM candidateは全return pathで
compilerが消去を省略できないprivate secure-zero helperによりzeroizeする。caller traffic secretは
read-onlyで変更しない。heap/VLA/global mutable cacheを使わない。portable production functionの
GCC Release exact `-O2 -fstack-usage` static frame ceilingは各`<=2560 bytes`とする。

## 9. Oracle, vectors, and negative tests

T1b subset artifactは次とし、full R7 artifactと名称・受入表示を分離する。

```text
tools/r7_t1b_binding_oracle.py
spec/vectors/r7-t1b-binding-subset.json
tests/radio/private/r7_t1b_binding_vectors.h
```

oracleはPython standard libraryだけを使い、production C helper/OpenSSL/mbedTLS bindingをimport
しない。SHA/HMAC/HKDFは`hashlib`/`hmac`で独立計算する。同一clean inputから2回生成したJSONが
byte-identicalで、canonical lowercase hex、stable vector IDs、sorted deterministic outputである
こと、generated C header freshnessと全vector消費をgateする。

positive manifestは次のexact 24 IDs、`vector_count=24`とする。JSON、generated C header、oracle、
KAT pin、C bridgeはID multisetをこの集合とexact equalityで検査し、missing、extra、duplicateをrejectする。

```text
R7-T1B-HOP-FIELD-D0-MIN
R7-T1B-HOP-FIELD-D0-MAX
R7-T1B-HOP-FIELD-D1-MIN
R7-T1B-HOP-FIELD-D1-MAX
R7-T1B-HOP-LAB-CONTROLLER-D0-MIN
R7-T1B-HOP-LAB-CONTROLLER-D0-MAX
R7-T1B-HOP-LAB-CONTROLLER-D1-MIN
R7-T1B-HOP-LAB-CONTROLLER-D1-MAX
R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MIN
R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MAX
R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MIN
R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MAX
R7-T1B-E2E-FIELD-D0-MIN
R7-T1B-E2E-FIELD-D0-MAX
R7-T1B-E2E-FIELD-D1-MIN
R7-T1B-E2E-FIELD-D1-MAX
R7-T1B-E2E-LAB-CONTROLLER-D0-MIN
R7-T1B-E2E-LAB-CONTROLLER-D0-MAX
R7-T1B-E2E-LAB-CONTROLLER-D1-MIN
R7-T1B-E2E-LAB-CONTROLLER-D1-MAX
R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MIN
R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MAX
R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MIN
R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MAX
```

各entryはcanonical bytes、digest、PRK、全key/IVを固定する。各environment/layerのMAX entryは
epoch/term=`UINT64_MAX`の有効positiveを少なくとも1 fieldでpinし、R6の`>0` domainをterminal扱い
しない。必須mutationは各integer、
各opaque length/body、environment、direction、context、epoch、expected digest 1-bit、traffic secret
1-bit、各label lane separationを覆う。このsuiteのexpected output差分を確認するが、一般的な
avalanche性は主張しない。

negative setはNULL/zero-length pointer shape、site/ID over/under length、FIELD zero site、
mixed authority/term、epoch/term `==0`、context ID `==0`または`==UINT32_MAX`、direction/env unknown、
capacity under/over、pointer overflow、
全partial alias、digest mismatch、SHA/Extract/各Expand fault/unknown resultを覆い、callback count、
failure mutation zero、secret zeroization test seamを確認する。round-tripまたはproduction helperだけを
oracleにしない。

## 10. Build and acceptance gates

新規source/vector/tool/testは一つのCMake source authorityへexplicitに登録する。tests-OFF private
archiveではproduction object/symbol exact once、install/public include/library/vector/tool leakage 0を
検査する。HostはAccepted OpenSSL 3 adapter、ESPはAccepted mbedTLS adapterだけをlinkする。

CTest prefixは`nrw1_t1b_*`とする。これはT0 `r7_*`にもT1 `nrw1_t1_*`にもprefix一致せず、
両方のexact-set authorityを変更しない。
normal profileのexact登録multisetは次の13 names、各exact onceとする。

```text
nrw1_t1b_binding_portable_strict
nrw1_t1b_vectors_bridge
nrw1_t1b_oracle_self_test
nrw1_t1b_oracle_verify
nrw1_t1b_kat_pin
nrw1_t1b_kat_pin_self_test
nrw1_t1b_platform_split_gate
nrw1_t1b_platform_split_gate_self_test
nrw1_t1b_tests_off_packaging_gate
nrw1_t1b_tests_off_packaging_gate_self_test
nrw1_t1b_ctest_gate_self_test
nrw1_t1b_stack_gate_self_test
nrw1_t1b_stack_gate
```

sanitizer profileは最後の`nrw1_t1b_stack_gate`だけを除くexact 12 namesとする。production stackの
compiler artifactをsanitizer buildでauthorityにしないための唯一の差であり、self-testを含む他の
skipを許さない。portable strict testがpositive/negative/fault/callback-count/alias/failure-mutation/
zeroizationを全て消費し、専用gate self-testは故意の欠落をredにする。

受入条件:

1. Linux/macOS、GCC/Clang、Debug/Release strict build
2. ASan/UBSanとinvalid-pointer-pair検査
3. oracle deterministic twice、freshness、stable ID/count、full bridge consumption
4. failure/fault/alias/mutation self-testsが故意の欠落をredにする
5. tests-OFF package/private symbol/install leakage gate
6. portable source token/dependency、heap/VLA/global-cache absence gate
7. GCC exact `-O2 -fstack-usage`と2560-byte ceiling
8. ESP-IDF v5.5.3 component source exact once、ESP32-S3 final ELFから6 APIを実参照
9. T0/T1/R6 gatesとfull existing CTest無退行
10. fixed implementation SHAのpush/PR CIとpush/PR ESP CI全成功
11. independent review P0=0/P1=0/P2=0、vector count/stack/run IDsをreview recordへ固定

ESP compile/linkは実機KAT、RF/USB HIL、timing、power-lossまたはFIELD readinessの代替ではない。

## 11. Ambiguity resolutions and rejected alternative

- R6のFIELD/LAB表はauthority IDとtermを組として解釈し、LAB no-controllerだけ双方zeroを許す。
  mixed zeroを許さない。Hop attachment ID/epochはLAB no-controllerでもnonzeroである。
- Hop/E2E最大は式から207/205 bytes。20-byte binding labelを含めた値であり、payload最大と混同しない。
- 6 HKDF labelは19..25 bytesでT0上限25以内。NULを渡さない。
- T0 wrapper後に現れるcaller-error statusはT1b内部組立の違反であり、caller errorへ戻さない。

最強の代案は、generic `derive(label, digest, secret)`とPRK/individual outputsを公開してW1で自由に
組み立てる設計である。API数とstackは小さくなるが、Hop/E2E、DATA/ACK、label、partial publish、
expected-digest確認をcallerが取り違えられる。通信基盤の誤用耐性を優先し、fixed labelとtyped
atomic bundleを持つverified deriveだけを採用する。

## 12. Acceptance boundary and next tranche

本章とADRがmergeされてもT1bはdocs-only Proposedである。production source、subset artifact、
全gate、固定SHAのCI、独立reviewが揃うまでAcceptedまたはimplementedと表示しない。

T1b Accepted後の次trancheは、authenticated capsule provenanceとN6 context installの間に
`verified derive -> durable lane initialization -> handle publish`をfail-closedに接続する
stateful owner sliceとする。LINK/FRAG/W1を同時に混ぜず、counter/storage/recoveryのfailure domainを
独立受入れする。
