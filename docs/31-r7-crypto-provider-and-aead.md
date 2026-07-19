# 31. R7 Private Crypto Provider and AEAD Boundary

状態: **Accepted / R7 T0 private crypto provider implementation candidate**  
正本 ADR: [ADR-0011](adr/0011-r7-crypto-provider-boundary.md)（Accepted）  
前提: [30章](30-r6-secure-radio-wire.md) の R6 wire freeze は不変

本章は R7/W1 が NRW1 の AES-128-GCM、HKDF-SHA-256、SHA-256 を利用するための
**production-private 境界**を定義する。public ABI ではない。このAcceptedはT0 private
crypto provider implementation candidateだけを対象とし、
codec、W1/L1、ESP 実行、RF/USB HIL、M4/M5、Japan legal、production radio の完了を
主張しない。

**SEMANTIC: R7_CRYPTO_PRIVATE_ONLY**  
**SEMANTIC: R6_N6_HASH_PIN_UNCHANGED**  
**SEMANTIC: R7_PROVIDER_ABI_EXACT_V1**  
**SEMANTIC: PORTABLE_WRAPPER_OWNS_VALIDATION**  
**SEMANTIC: HOST_OPENSSL3_ESP_MBEDTLS_SPLIT**  
**SEMANTIC: NO_PRODUCTION_HAND_WRITTEN_AES_GHASH**  
**SEMANTIC: AEAD_FAILURE_CALLER_MUTATION_ZERO**  
**SEMANTIC: OPEN_VERIFY_BEFORE_PUBLISH**  
**SEMANTIC: ALL_PARTIAL_ALIAS_REJECT**  
**SEMANTIC: INTERNAL_SECRET_ZERO_ALL_PATHS**

## 1. Scope and dependency direction

R6 の `src/radio/n6_*` 3 production sources とその provider contract は、固定 hash で
受入済みの host candidate である。R7 T0 はそれらを変更しない。R7 は次の依存方向を
持つ別の private family を追加する。

```text
W1 / R7 codec
    -> R7 portable crypto wrapper
        -> exact R7 provider ABI v1
            -> Host OpenSSL 3 adapter
            -> ESP-IDF mbedTLS adapter
```

W1/R7 から N6/R2/R5 header への compile dependency は作らない。N6 と R7 provider の
統一は、R6 hash pin を更新する根拠、移行手順、独立再監査を備えた後続 tranche とする。
T0 で暗黙に統一しない。

## 2. Platform split

| layer | Host Linux/macOS | ESP32-S3 ESP-IDF | condition |
|---|---|---|---|
| portable wrapper / nonce / validation | same C11 sources | same C11 sources | OS、heap、VLA、crypto library header なし |
| primitive adapter | OpenSSL **3.x** EVP/provider APIs | ESP-IDF supplied mbedTLS | 片方だけを compile/link |
| independent oracle | Python standard library only | build host only | production source、C helper、Python crypto binding を使わない |

production C に手書き AES、GHASH、暗号 S-box table を置いてはならない。Python oracle の
独立実装だけを例外とする。portable wrapper は library の side-channel 保証を越える
constant-time claim を行わない。adapter/library の初期化・内部 allocation 失敗は typed
failure とし、成功に縮退しない。

## 3. Exact private provider ABI v1

provider ops は先頭から次を exact order で持つ。

1. `abi_version` (`u32`, exact `1`)
2. `struct_size` (`u32`, exact `sizeof(v1)`, undersize/oversize reject)
3. `reserved_zero` (`u64`, exact zero)
4. `ctx`
5. `sha256`
6. `hkdf_extract_sha256`
7. `hkdf_expand_sha256`
8. raw `aes128_gcm_seal`
9. raw `aes128_gcm_open`

全 callback は non-NULL。未知 version、shape mismatch、reserved nonzero、callback 欠落は
provider 呼出し 0 で reject する。raw Seal/Open callback は candidate capacity と
candidate output-length pointer も受け取り、success 時の exact produced length を返す。
wrapper は length mismatch を `INTERNAL_CONTRACT` とし、caller へ publish しない。
callback は同期的に exactly one return し、SHA/HKDF/Seal は success/backend failure、Open
だけは success/auth/backend failure の closed result を返す。unknown result は成功に
しない。callback は wrapper から受けた pointer を保持、別threadへ渡す、return後に読む、
同じproviderでwrapperへ再入してはならない。入力 validation と caller publish policy は
portable wrapper が所有する。caller は wrapper がreturnするまでprovider object自体を生存・
byte-immutableに保ち、wrapperはprovider objectをread-onlyとして扱う。private ABI を
install/include tree へ公開しない。

HKDF は RFC 5869 の Extract と Expand を別 callback にする。PRK は 32 bytes。raw adapter
は RFC 5869 KAT の length domain を扱う。portable R7 schedule wrapper は salt 32、IKM 32、
info 0..25、output 12 または 16 bytes に限定する。RFC の 42/82-byte OKM KAT は raw
adapter に対して実行し、R7 wrapper の domain を偽って広げない。R7 の 6 labels と
salt/IKM binding は docs/30 §8 を byte-exact に従う。

## 4. Closed status catalog

portable API の status は次の closed set とする。数値は実装仕様で固定し、C `enum` の
layout を wire/public ABI にしない。

| status | meaning | provider calls |
|---|---|---:|
| `OK` | success and caller output published | required exact calls |
| `INVALID_ARGUMENT` | NULL/length/catalog/provider shape | 0 when found in prevalidation |
| `CAPACITY` | output capacity is not exact required size | 0 |
| `ALIAS` | any non-empty forbidden span overlap | 0 |
| `AUTH_FAILED` | GCM authentication rejected | open callback 1 |
| `BACKEND_FAILED` | provider/library operational failure | attempted callback count only |
| `INTERNAL_CONTRACT` | success shape or impossible backend result violated | no further calls |

Unknown backend result maps to `BACKEND_FAILED` or `INTERNAL_CONTRACT`; it never maps to `OK`.

## 5. AEAD shape and lengths

| item | exact domain |
|---|---:|
| AES key | 16 bytes |
| nonce | 12 bytes |
| GCM tag | 16 bytes |
| AAD | 0..19 bytes; wire caller later narrows to 14 or 19 |
| plaintext/ciphertext body | 0..220 bytes |
| sealed output | `ciphertext || tag16`, 16..236 bytes |
| SHA-256 wrapper message | 0..2048 bytes（FRAG reassembled ceilingを含む） |
| R7 HKDF wrapper salt / IKM | each exact 32 bytes |
| R7 HKDF wrapper info / OKM | info 0..25; OKM exact 12 or 16 bytes |

Seal required capacity is `plaintext_len + 16`; Open required capacity is
`sealed_len - 16`. Capacity must equal the required length, not merely be greater. Both APIs receive
an output-capacity value and an in/out length pointer. On entry, output length is caller state; only
success replaces it with the exact published length.

Validation uses checked arithmetic before pointer range calculations. A zero-length logical span may
use NULL only where the signature explicitly allows it. Key、nonce、non-empty AAD、non-empty input、
non-empty output と output-length storage の不正 shape は reject する。

## 6. Alias and failure-mutation contract

Provider object、key、nonce、AAD、input、output、output-length storage の全 non-empty spans
を pairwise 検査する。1 byte でも重なる partial alias と exact in-place alias は reject
する。`end(A) == begin(B)` の隣接だけを許可する。`uintptr_t` overflow を reject し、
undefined pointer ordering に依存しない。`size_t` が `uintptr_t` より広い実装では、length
が `UINTPTR_MAX` を越えた時点で reject してから end-address を計算する。provider `ctx` は
adapter-owned lifetime objectで、全call完了まで生存し、caller data spans と disjoint、
callback 自身の private state 以外を mutate しない。adapter はcall-local crypto contextを
使って並行するdistinct callsにreentrant/thread-safeでなければならず、shared mutable ctxを
使う場合はadapter自身が同期する。

複合エラーの validation priority は exact に (1) provider header/shape、(2) required pointer
shape、(3) numeric length/catalog、(4) exact capacity、(5) span overflow/alias、(6) bounded copy、
(7) backend result/produced length とする。後段エラーで前段statusを上書きしない。

`INVALID_ARGUMENT`、`CAPACITY`、`ALIAS`、`AUTH_FAILED`、`BACKEND_FAILED`、
`INTERNAL_CONTRACT` のすべてで、次は byte-exact mutation zero である。

- caller output buffer 全域
- caller output length
- provider object、key、nonce、AAD、input
- prevalidation failure 時の provider call count

caller output を failure 時に zero-fill することは mutation zero ではないため禁止する。
wrapper は bounded caller inputs を wrapper-owned copy へ複製してから callback へ渡す。
これにより partial-write または input-poison backend failure でも caller inputs を保つ。
zeroize 対象は wrapper が所有する input copy、candidate、temporary である。

## 7. Verify-before-publish and zeroization

Open は caller input/output を raw backend に渡さない。最大 236-byte sealed input copy と
最大 220-byte の wrapper-owned candidate
へ復号し、16-byte tag の認証成功と backend output shape の検証後にだけ caller output へ
一括 publish する。認証失敗や backend failure で candidate の一部も公開しない。

Seal も key/nonce/AAD/plaintext の bounded input copies と最大 236-byte の wrapper-owned
candidate を使い、backend success と returned exact length を確認後にだけ `CT || TAG16`
を publish する。これにより壊れた backend が input/candidate を mutate して失敗しても
caller mutation zero を保つ。

candidate、PRK、key schedule output、nonce work copy、tag、digest temporary は success/fail
の全 return path で volatile-store helper により zeroize する。compiler/library が提供する
より強い erase primitive がある adapter 内ではそれも利用する。

## 8. Nonce helper

R7 の sole nonce helper は docs/30 の規則を実装する。

```text
nonce[0..3]  = static_iv12[0..3]
nonce[4..11] = static_iv12[4..11] XOR counter_u64_be
```

counter domain は `1..UINT64_MAX-1`。`0` と `UINT64_MAX` は provider 呼出し 0、output mutation
zero で reject する。codec/test が XOR を再実装して別の正本を作ってはならない。test は
production helper の KAT と、独立 oracle の expected bytes の両方を確認する。

## 9. Oracle, vectors, and negative tests

independent oracle は Python standard library のみを用い、AES/GHASH を独立実装し、SHA-256
は `hashlib`、HMAC/HKDF は `hmac` を使う。OpenSSL binding、`cryptography`、production C
helper、生成済み C bytes を計算の正本にしない。

必須 vector:

- NIST SP 800-38D: empty、one-block、AAD あり、non-block body、bad tag
- RFC 5869 SHA-256 representative test cases; PRK と OKM の両方（42/82-byte OKM は raw
  adapter KAT、R7 schedule wrapper は 12/16-byte domain）
- SHA-256: empty、`abc`、multi-block
- docs/30 binding bytes/digests、6 key/IV outputs、counter 1 / `UINT64_MAX-1` nonce
- plaintext/AAD 0、1、block edge、max; sealed min/max

必須 negative:

- key/nonce/AAD/PT/CT/tag/label の bit mutation; tag 全 128 bit
- NULL、under/over/exact length、capacity、全 partial-alias classes、pointer overflow seam
- poison/partial-write backend、unknown status、canary、Open prior-publish detector
- failure mutation zero と provider call count

oracle は異なる temporary directory と `PYTHONHASHSEED` で 2 回生成して byte-identical、
lowercase、stable-order であることを検査する。committed JSON と generated private header の
freshness を gate し、C bridge の実行 vector 数が生成件数と exact equal でなければ fail。
oracle/gate/bridge-skip/tag-truncation/prior-publish を各 mutation self-test で壊し、gate が
実際に赤になることを確認する。

## 10. Build, source authority, and packaging

- portable、host、ESP source sets は一つの CMake authority で explicit に管理する。
- Host は `find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)` と private link を行う。
  OpenSSL は **exact major 3**（`OPENSSL_VERSION` が 3.x 以外、空、または major>=4 は
  configure fail）。adapter は `OPENSSL_VERSION_MAJOR != 3` を compile-time error にする。
- ESP component は `PRIV_REQUIRES mbedtls`。OpenSSL source/header/token が ESP expanded
  source set に入ったら structural gate が fail する。
- ESP-IDF v5.5.3 のNinlil componentを使う全appは `CONFIG_MBEDTLS_HKDF_C=y` を必須とする。
  adapter は
  `MBEDTLS_HKDF_C` が無い build を compile-time error にし、未解決HKDFを含むarchiveを
  成功扱いにしない。
- ESP受入はcomponent archive生成だけでは不十分。private provider factoryを実参照した
  ESP32-S3最終ELFをlinkし、factoryが `GLOBAL HIDDEN`、adapter objectとHKDF Extract/Expandが
  map/ELFへ入ったことを検査する。factory/headerをpublic include/APIへ昇格させない。
- mbedTLS adapter が Host source set に入った場合も fail する。
- production source は target/archive に exact once。test/oracle/generated fixture は
  production archive に入れない。
- private headers、vector JSON、generated private header、tests/tools path は install/public
  include tree に出さない。
- tests-OFF packaging は archive **member 名** に加え、**fresh OFF private archive 自身の
  `nm` defined symbol** を検査する。`ninlil_r7_crypto_test_spans_forbidden` その他
  TEST_BUILD seam / test / oracle / fixture symbol が tests-OFF private archive に
  定義されていれば fail。tests-ON archive は seam を持ち得るため、親 tests-ON tree の
  archive を流用しない。
- install tree は path 禁止に加え、インストールされた **static/shared library 全ての
  `nm` defined symbol** を検査する。`ninlil_r7_crypto_*`、`ninlil_r7_mbedtls_*`、
  provider factory / private seam が public 配布 lib へ混ざれば fail。`nm` 欠落・
  非ゼロ終了は fail closed。

## 11. T0 acceptance gates

1. strict fresh Debug/Release build on Clang and GCC
2. focused crypto/KAT/oracle tests and full CTest。登録済み `r7_*` 集合は profile の
   expected exact set と完全一致（required 存在だけでは不足。`r7_unexpected_test` や
   suffix copy は red）。authority: `tools/r7_t0_ctest_gate.py`。
   normal profile = **16** CTest（core 15 + production `r7_crypto_stack_gate` 1）、
   sanitizer profile = **15**（production stack gate は 0）
3. ASan/UBSan full test; no test weakening or skip
4. Python compile、oracle self-test、freshness、mutation self-test
5. tests-OFF build/install/archive/**nm private-symbol** leakage inspection
   （`tools/r7_crypto_tests_off_packaging_gate.py`；member + symbol + install nm）
6. **GCC Release exact `-O2` authority**（CMake 既定 Release の `-O3` を採用しない）。
   CI は `-DCMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG"` と
   `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` を使い、`compile_commands.json` 上の
   `r7_crypto_portable.c` / `r7_crypto_nonce.c` production compile 行に
   `-fstack-usage` と、最適化flag列が **唯一の `-O2` exact once** であることを実証する。
   前後を問わず他の `-O*`、未知の `-O*`、bare `-O`、重複 `-O2` が1つでもあれば
   failする。YAML 文字列確認だけでは不足。`.su` では各 portable
   wrapper の static frame が **2560 bytes 以下**、`dynamic`/`bounded` ではなく
   `static` と判定されること。SHA-256 の最大2048-byte input copyを含むT0候補の基準値は
   2208 bytes。Clang Release は `-O2` で揃えてよいが、**GCC `.su` / compile_commands が
   §11.6 の正本**であり Clang 側で曖昧化しない。これはadapter callbackを含むcall-chain
   総量や ESP task stackの十分性を主張せず、それらはESP integration/HILで別に計測する
7. Linux/macOS OpenSSL **exact 3** host build and KAT。macOS CI は GITHUB_ENV の
   `OPENSSL_ROOT` を shell の `-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT"` で渡し、
   `${{ env.OPENSSL_ROOT }}` を使わない
8. ESP-IDF v5.5.3 compile/link with mbedTLS adapter
9. R6 docs/source hash pins and all R6 gates unchanged/pass
10. independent review with P0=P1=P2=0 before ADR acceptance

ESP compile/link は実行 KAT、実機 entropy、timing、RF/USB HIL の成功ではない。T0 を通っても
docs/30 §18.15–16 の全 R7 artifact、W1/L1、codec、FRAG/LINK、CELL_64、HA、M4/M5、legal、
production radio が完了したとは主張しない。

## 12. T0 acceptance record and completion boundary

T0 private crypto provider implementation candidateは、本章 §§1–11のproduction code、test、
push/PR CI、ESP-IDF CIを満たし、2026-07-19の独立POST-CI監査
**P0=0 / P1=0 / P2=0 GO**をもってAcceptedとする。監査対象implementation SHAは
`1458c2079f55e7bbf75ce86fc270a4ad31675bf0`。公式evidenceはpush CI
`29676558922`、PR CI `29676560388`、push ESP-IDF `29676558929`、PR ESP-IDF
`29676560411`で、全てsuccess。独立監査記録は
[R7 T0 Accepted review](reviews/2026-07-19-r7-t0-crypto-provider-accepted.md)を正本の補助証拠とする。

このAcceptedはR7全体の完成を意味しない。docs/30 §18.15–16のfull wire/state、W1/L1、
counter/storage、FRAG/LINK/CELL/HA、M4/M5、ESP実機KAT、RF/USB HIL、Japan legal、
production radioは未実装または未検証であり、後続sliceの独立した受入条件を満たすまで
完成扱いにしない。
