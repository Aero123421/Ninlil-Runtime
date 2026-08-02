# 2026-07-29 Wi-Fi ESP PSRAM tier resource candidate

状態: **Wi-Fi TLS-only target software candidate PASS / C7 RED / C8 RED / physical HIL NOT_RUN**

本記録はADR-0018のESP32-S3向けTLS資源修正と、その時点で実行した証拠をまとめる。
`SPEC_ACCEPTED`、`RELEASE_SUPPORTED`、実機成立、Wi-Fi実経路全体のresource closureを
意味しない。

## 結果

- 2 TLS sessionの予約を、secret-criticalなinternal arenaと、明示分類したTLS I/O専用
  PSRAM arenaへ分離した。
- session admission前に両arenaを実予約し、PSRAM無効、free不足、largest-free不足、
  予約後internal floor不足をfail closedにした。
- `mbedtls_ssl_setup()`中のpinned inbound/outbound I/O allocationだけをPSRAMへ許可した。
  generic/default heapへのallocation単位spillはない。
- PSRAM pointerはarena所属だけでなく、exact payload start、USED、original requested size、
  tail canaryまで照合する。interior、free-area、wrong-size、freed pointerは成功しない。
- freeはcurrent ownerのarenaだけを候補にする。session Aからsession Bまたは
  `CRYPTO_GLOBAL`のallocationをfreeできない。
- ordinary arena OOMはsession-local failure、classifier違反はsession contract failure、
  owner欠落・再入・metadata/canary破損はglobal fatal fenceとして分離した。
- close、reconnect、init failureではmbedTLS-owned objectを先に解放し、outstanding exact 0を
  確認してarena全体をzeroize/releaseする。

## 固定した資源値

| 項目 | 値 | 配置 |
| --- | ---: | --- |
| `CRYPTO_GLOBAL` | 65,536 bytes | internal 8-bit |
| session secret-critical arena | 12,288 bytes / session | internal 8-bit |
| session classified I/O arena | 86,016 bytes / session | PSRAM 8-bit |
| session total | 98,304 bytes / session | 上記2 tierの合計 |
| 2-session PSRAM reservation | 172,032 bytes | PSRAM 8-bit |
| post-admission internal floor | 65,536 bytes | internal |
| TLS execution stack envelope | 8,192 bytes | internal |
| TLS crypto DMA | 0 bytes | hardware crypto profile無効 |
| tiered simultaneous internal candidate | 163,840 bytes | `65536 + 2*12288 + 65536 + 8192` |

元の保守的なinternal-only release feasibility条件は
`2*98304 + 65536 + 65536 = 327680 bytes`のまま機械仕様、C定数、ADRへ保持した。
163,840-byte tiered envelopeはphysical target trace前のsoftware candidateであり、
327,680-byte条件を置換・引下げしない。

## 実装上の境界

- arena metadata、block link、requested size、state、tail canaryは予約arena内に置く。
  ledger用の追加heapはない。
- raw platform allocationはglobal internal、session internal、session PSRAMのexact 3予約
  callsiteだけで、raw releaseは1か所へ集約した。
- PSRAM I/O classification windowは`mbedtls_ssl_setup()`の同期callだけである。
  pinned target値はinbound 16,685 bytes、outbound 4,415 bytes。
- OOM後もclassifier scopeは終了するが、不足したexpected allocationをcontract違反へ
  誤分類せず、session-local `UNAVAILABLE`として扱う。
- canaryまたはarena metadata破損は、通常OOMとして継続せずallocator全体をfenceする。

## 検証

### Machine vector / independent gates

```text
vector sha256:
  38d8050206d8de832dfe9395f6f39b99e1119eb06fa60ee2112af2cd375b25ff
acceptance IDs: 79
object paths: 117
integer leaves: 386
string leaves: 692
digest leaves: 96
scalar leaves: 1078
Python / Node unknown, bool-int, scalar mutation accepted: 0
C11 donor full cross-product: 6162 reject
```

実行:

```sh
python3 tools/wifi_bearer_spec_vector_gen.py --check
python3 tools/wifi_bearer_spec_vector_gen.py --self-test
python3 tools/wifi_bearer_spec_gate.py --check
python3 tools/wifi_bearer_spec_gate.py --self-test
node tools/wifi_bearer_spec_gate.mjs --check
node tools/wifi_bearer_spec_gate.mjs --self-test
python3 tools/wifi_v1_esp_resource_gate.py self-test
```

全てPASS。

### Host normal / ASan + UBSan

```sh
ctest --test-dir build-wifi-tier --output-on-failure \
  -R '^(wifi_bearer_spec_|wifi_v1_)'

ASAN_OPTIONS='detect_leaks=0:halt_on_error=1:abort_on_error=1' \
UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
ctest --test-dir build-wifi-tier-asan --output-on-failure \
  -R '^(wifi_bearer_spec_|wifi_v1_)'
```

- normal: **33/33 PASS**
- ASan + UBSan: **33/33 PASS**
- AppleClang/macOSのLeakSanitizerは未対応のため`detect_leaks=0`。ASan/UBSan自体は有効。
- pure allocator negativeはfragmentation、overflow/OOM、interior/free/wrong-size/freed pointer、
  canary破損、cross-owner freeを含む。

### ESP-IDF clean target proof

実行:

```sh
bash tools/wifi_v1_esp_idf_map_proof_local_arm64.sh
```

結果:

```text
ESP-IDF: v5.5.3
container image digest:
  sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1
final DIRAM total: 341,760
final DIRAM used: 170,111
final DIRAM free: 171,649
tiered candidate envelope: 163,840
link-time slack: 7,809
target owner workspace: 9,008 <= 12,288
stack-usage entries: 374, each <= 8,192
component production members: 29
Host-only members in ESP component: 0
resource gate: PASS
claim=wifi_tls_only_target_software_candidate
r7_other_registered=UNIMPLEMENTED
C7=RED
C8=RED
physical_hil=NOT_RUN
```

machine vectorに残す171,825 / 7,985は修正前snapshotのhistorical map observationである。
現在のclean final mapは171,649 / 7,809で、candidate envelope以上という構成証拠だけを示す。
runtime peakや実機成立の証拠にはしない。

## 未閉鎖・非主張

1. **R7 co-tenant / `OTHER_REGISTERED`は未実装。** ADR-0018はAccepted R7 ESP raw adapterを
   allocator owner closureへ含めるが、現実装は`CRYPTO_GLOBAL`と`TLS_SESSION`だけである。
   `ports/esp-idf/src/r7_crypto_mbedtls.c`はtarget compileされるものの、factory/raw callbackは
   owner enter/leaveを通らず、HIL final call graphにも保持されない。R7用budgetを測定なしに
   0または既存budgetへ押し込まない。
2. **Wi-Fi driver/LwIP resource domainは未閉鎖。** driver、event/task、LwIP、socket、netif、
   DHCP、PBUFのexact pool/count/bytes、runtime peak/watermark、OOM、reconnect、sleep/wakeは
   TLS allocator/mapから推測しない。
3. **target execution / physical HILは未実施。** ESP target compile、archive、ELF、map、
   source/config gateはPASSしたが、実機上のallocator fault injection、2-session handshake、
   AP/DHCP/TCP、PSRAM shortage/fragmentation、reconnect反復はNOT_RUN。
4. **C7/C8と`RELEASE_SUPPORTED`はRED。** 本結果だけでproduction enable、stable public API、
   実機対応完了を宣言しない。

