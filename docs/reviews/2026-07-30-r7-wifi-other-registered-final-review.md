# 2026-07-30 R7 / Wi-Fi `OTHER_REGISTERED` independent final review

状態: **target-software candidate GO — P0=0 / P1=0 / P2=0**

実行日: 2026-07-30 JST  
対象: ADR-0026 R7 raw crypto / Wi-Fi allocator co-tenant lane  
基準HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`

この記録は、private/default-OFF Wi-Fi compositionにおけるR7 raw cryptoの
`OTHER_REGISTERED` owner、予約量、fault fence、closureを対象にした独立最終レビューである。
レビュー担当はこのlaneの実装を担当しておらず、本レビューではproduction code、test、
ADR、compatibility matrix、workflowを変更していない。Grok Buildは使用していない。

対象はdirty shared workspace上の未commit候補であるため、HEADだけでは内容を再現できない。
レビューした主要authorityのSHA-256を次に固定する。

| Authority | SHA-256 |
| --- | --- |
| `docs/adr/0018-wifi-bearer.md` | `e53639e31d6c39c57d67696a81d20a2e08e9372df89104cf19bd223a7ce73362` |
| `docs/adr/0026-r7-wifi-other-registered-allocation.md` | `6fdb2c99c1b76ae2f1301d399deafc9236ec1c0515316866e4f2fb5a32c88cec` |
| `docs/work/2026-07-29-r7-wifi-other-registered-close.md` | `b55b4f90d1d9c9f6badcb550c094aa2e40f5024f38fb59ed48d50354c9064397` |
| `ports/esp-idf/src/r7_crypto_mbedtls.c` | `faddc0c04e8acd3cea6bd649fca2a257b918e267883aca1c875e5a69155ee0ff` |
| `ports/esp-idf/src/r7_crypto_mbedtls.h` | `5a90c8f241c4fb448eb9f49efbf8a95b2b45e37b475b2b4e5f3e549c8d042aca` |
| `src/transport/wifi_v1/wifi_esp_tls_allocator.c` | `1e81d42083fa094bba10a56c16d852032b946729163de3fa1fbeccd2208573f5` |
| `src/transport/wifi_v1/wifi_esp_tls_allocator.h` | `1aa17a5a3bf3b7d47449f415c6be6e2895d377681592c216421c6a45669fcd48` |
| `src/transport/wifi_v1/wifi_esp_mbedtls_profile_probe.c` | `be70502d1f50ef2eab85c428ecb3ae4649a9c6d33dbdba95819c20143f20cfe1` |
| `src/transport/wifi_v1/wifi_tls_resource_policy.h` | `be765326e1e9d7c9f08bb729c843634a2f3ed3c1a4660a1c69a8c2b042aa58c4` |
| `tests/transport/wifi_v1/wifi_v1_r7_other_registered_fault_test.c` | `7bdf7390fd0e2d189bc7c5c0816c64b96995482ea0296a2a1d3168486b12b601` |
| `tests/support/fake_esp_mbedtls/fake_esp_mbedtls.c` | `8440ea3404a1ba0f8f78335aa78dff7dafd107b086ee025e56d6528ebbd160dc` |
| `tools/r7_wifi_allocator_closure_gate.py` | `07f4b5fd9a9a3bf5c8eba26dca4a774a77a0866c5afd16731803d47fae6a40be` |
| `tools/wifi_v1_esp_resource_gate.py` | `fd7f016aa917656bc1d4a084512669629e54345dc1f691a32677b653ec44e979` |
| `tools/wifi_v1_esp_idf_map_proof_local_arm64.sh` | `d46b8025551bc8815c0164985eb3b66225ebae7ffef6ceb46deeea266d96d43a` |
| `ports/esp-idf/wifi_hil_app/main/main.c` | `80f21ab24f3ef223bdabfd882ec817a050f0b6e829e9655ea561381c7b77b041` |

## Verdict

| Severity | Open findings |
| --- | ---: |
| P0 | **0** |
| P1 | **0** |
| P2 | **0** |

P0/P1 repairを要する欠陥は再現しなかったため、production codeとtestへの修正は行っていない。
このGOはR7 co-tenant allocatorの**target-software candidate**だけを対象にする。
physical allocator traceとphysical AP HILはともに`NOT_RUN`であり、ADR-0018 C7/C8は
引き続きREDである。

## Target allocation and composition result

ESP-IDF v5.5.3のeffective configurationでは`MBEDTLS_BLOCK_CIPHER_C`が定義されない。
profile probeはこのmacroが定義されたbuildをcompile-time errorにし、最終ELFにも
このprobeがretentionされる。active GCM allocation pathは次のとおりである。

```text
mbedtls_gcm_setkey
  -> mbedtls_cipher_setup
  -> cipher_wrap AES ctx_alloc
  -> mbedtls_calloc(1, sizeof(mbedtls_aes_context))
```

ESP32-S3 target ABI上のAES context requestは280 bytesである。allocatorの16-byte
header、4-byte tail canary、8-byte alignmentを適用したcharged spanは304 bytesになる。
HKDFの同時peakはSHA-256 context 128 bytes + HMAC buffer 152 bytes = 280 bytesであり、
serialized five-callback laneの最大値はGCMの304 bytesである。従ってcallback peakを
合算せず最大値を取るADR-0026の予約量は正しい。

| Contract | Reviewed exact value |
| --- | ---: |
| R7 component id | `0x52375231` |
| `OTHER_REGISTERED(R7_RAW_V1)` reservation | **304 B INTERNAL** |
| Wi-Fi + R7 total reservation | **262448 B** |
| tiered internal composition envelope | **164144 B** |
| conservative internal-only feasibility | **327984 B** |
| allocation trace capacity | **32 records** |

`wifi_tls_resource_policy.h`、allocator API、ADR-0026、work close、target probe、
closure evidenceの値は一致した。

## Owner, fault, OOM and lifecycle review

R7のSHA-256、HKDF Extract、HKDF Expand、GCM Seal、GCM Openは全てR7 ownerへenterし、
全return pathでchecked leaveする。callback call-stateはatomic guardでserializedとなり、
recursiveまたはconcurrent entryはowner contract違反としてfatal fenceへ閉じる。

次のfailureはprocess-wide fatal fenceになることをsourceとHost fault testで確認した。

- bootstrap前またはownerなしallocation
- recursive callback / allocator recursion
- cross-owner entryまたはfree
- foreign free / double free
- wrong owner leave / double leave
- arena metadata破損
- outstanding allocationを残したowner release

一方、予約arenaの通常OOMはlocal backend failureである。別arenaへspillせず、
`CRYPTO_GLOBAL`へ付け替えず、fatal fenceも立てない。OOM後のretry成功もHost testで
確認した。

owner snapshotは`current_bytes`、`peak_bytes`、`outstanding_allocations`、
`reserved_bytes`とfatal stateを公開する。固定長traceはallocationせず、
overflow時はdropped countを保持する。provider closeはcurrent/outstandingが
zeroの場合だけR7 arenaをzeroize/releaseし、Wi-Fiが継続利用し得る
`CRYPTO_GLOBAL`をreleaseしない。

unknown component id、duplicate `OTHER_REGISTERED` registration、second familyは
fail closedである。duplicate provider factoryは失敗時に出力を変更しないため、
一方のcloseで別名handleを無効化する経路はない。

## Host independent verification

fresh dedicated build directoryを使用した。

- normal: `build/review-r7-wifi-normal`
- AppleClang ASan+UBSan: `build/review-r7-wifi-asan`

| Verification | Result |
| --- | --- |
| normal `wifi_v1_r7_other_registered_fault_test` | **1/1 PASS** |
| ASan+UBSan same test | **1/1 PASS** |
| `r7_wifi_allocator_closure_gate.py self-test` | **PASS** |
| `wifi_v1_esp_resource_gate.py self-test` | **PASS** |

ASan+UBSanは
`ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1`
で実行し、sanitizer findingは0だった。AppleのASanではleak detectorを無効化しているため、
別個のLeakSanitizer evidenceは主張しない。

Host fakeはowner/fault injectionのdeterministic boundaryであり、ESP targetのexact
mbedTLS type sizeを主張しない。108/280-byte context requestと各charged spanは、
別のESP final-ELF profile probeで測定しているため、Host fakeのrequest sizeをtarget
authorityへ流用していない。

## Standalone Wi-Fi-off compatibility

`NINLIL_ENABLE_PRIVATE_WIFI_V1`を定義せず、`ESP_PLATFORM=1`、
`MBEDTLS_HKDF_C=1`、strict warningで`r7_crypto_mbedtls.c`を独立compileした。

```text
provider_init symbol: retained
provider_close symbol: retained
Wi-Fi allocator undefined relocations: 0
compile result: PASS
```

従ってWi-Fi compositionを無効にしたstandalone R7 providerは従来どおり
`ctx == NULL` boundaryを維持し、Wi-Fi allocatorへのlink dependencyを取得しない。

## Pinned ESP-IDF final ELF / map / closure proof

次をclean buildとして再実行した。

```sh
bash tools/wifi_v1_esp_idf_map_proof_local_arm64.sh
```

| Item | Evidence |
| --- | --- |
| image | `docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1` |
| container architecture | `aarch64` |
| ESP-IDF / target | `v5.5.3` / `esp32s3` |
| final owner workspace | 9008 B, ceiling 12288 B |
| final DIRAM | used 171703 B / total 341760 B / free 170057 B |
| composition envelope / link slack | 164144 B / 5913 B |
| stack frames checked / ceiling | 384 / 8192 B |
| final proof result | **PASS** |

Final-ELF probes:

| Probe | Measured |
| --- | ---: |
| `sizeof(max_align_t)` | 16 |
| `_Alignof(max_align_t)` | 8 |
| SHA-256 context request / charge | 108 / 128 B |
| HMAC charge | 152 B |
| AES context request / GCM charge | 280 / 304 B |
| R7 reservation | 304 B |

最終artifact:

| Artifact | SHA-256 |
| --- | --- |
| `ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.elf` | `2a04a55f1d8520bb7bd97b447d475823088dc488e78fa1d37f96ed9f0fbeb188` |
| `ports/esp-idf/wifi_hil_app/build/ninlil_wifi_hil.map` | `81f5ea019aaf76f81ffa76c52059eddca9f01dcb6ab9a713c92e14545f4bddb0` |
| `ports/esp-idf/wifi_hil_app/build/esp-idf/ninlil/libninlil.a` | `f839e5e5cc05287eaad23e832e921a5a56f1c832bd70bd1632c01c7efacdbbce` |
| `ports/esp-idf/wifi_hil_app/build/r7_wifi_allocator_closure_evidence.json` | `e9d0919ae3f0b2959451f0d08aa217e27ca1bfdc70986caea8869c8ce5a9039b` |

closure gateはpinned `hkdf.c`、`md.c`、`gcm.c`、`cipher.c`、
`cipher_wrap.c`、`gcm.h`、`aes.h`のsource hashを確認する。HKDF/GCMのexact
callback roots、archive definitions、undefined relocations、final map retentionを
相互照合し、Host-only symbolのproduction closure混入が0であることを確認した。

canonical closure root:

```text
755959d4d2d7f00501b1967e1aa7002fb39a5460cbb54e137fd47323176c0387
```

## Status recommendation

### ADR-0026

**Acceptedへ進めてよい。** 独立レビュー条件は満たされ、狭いdecision
「R7 raw cryptoを304-byte INTERNAL予約の`OTHER_REGISTERED` co-tenantとして
構成する」はsource、fault test、target probe、final closureで閉じている。
status-only editorial changeを行う場合も、次のnon-claimを削除してはならない。

- physical allocator runtime peak/trace: `NOT_RUN`
- physical ESP32-S3 callback execution: `NOT_RUN`
- physical AP HIL: `NOT_RUN`
- ADR-0018 C7/C8: RED
- Wi-Fi `RELEASE_SUPPORTED`: 未達

### Wi-Fi software state

Wi-Fi全体の状態は**変更しない**ことを推奨する。

| Surface | Current / recommended state | Reason |
| --- | --- | --- |
| ADR-0018 Wi-Fi Packet Link | `Proposed`のまま | 本reviewはco-tenant allocatorだけを閉じ、全exact design acceptanceや実経路を閉じない |
| `posix-tcp-tls-wifi-reference` | `PROPOSED`のまま | ADR-0026 target laneからPOSIX feature promotionは導出できない |
| `esp32s3-wifi-sta-tcp-tls` | `PROPOSED`のまま | physical AP/allocator HIL、driver/LwIP evidence、C7/C8が未達 |
| R7 Wi-Fi co-tenant sub-lane | target-software candidate GO | compile/link/map/closureとHost fault behaviorだけをclaim |

ADR-0026 Acceptedは、ADR-0018の`SPEC_ACCEPTED`、ESP Wi-Fi implementation acceptance、
HIL、または`RELEASE_SUPPORTED`を意味しない。従って本reviewでは
`compatibility-matrix.json`を変更していない。

## Physical follow-up

実機promotionでは、このclosure rootに一致するimageをESP32-S3へflashし、
少なくとも次をraw transcriptとartifact hash付きで保存する必要がある。

1. RFC 5869 / AES-128-GCM KAT後の`STATUS`
2. `R7_ALLOC_TRACE`
3. `r7_peak=304`
4. `r7_current=0`
5. `r7_outstanding=0`
6. `allocator_fatal=0`
7. 必須trace segmentのdropなし
8. 実AP/DHCP/TCP、Wi-Fi断、allocator OOMを含むADR-0018 C7/C8 HIL

それまではphysical allocator traceとphysical AP HILを`NOT_RUN`として扱う。
