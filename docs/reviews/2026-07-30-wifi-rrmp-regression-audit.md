# Wi-Fi / Fabric / RRMP / NRW1 FRAG regression audit

監査日時: 2026-07-30 12:14 JST  
対象: private/default-OFF Wi-Fi real path、Fabric接続、Route Relay /
Multi-parent（以下RRMP）、NRW1 LINK/FRAG  
監査方法: 独立したfresh Host build、ASan/UBSan build、pinned ESP-IDF
compile/link/map境界、Normative仕様・Accepted ADR・machine-readable stateの照合  
コード変更: なし。この文書だけを追加した。

## 結論

| 判定対象 | 結果 | 結論 |
| --- | --- | --- |
| 現在のprivate software candidate回帰 | **PASS** | Host通常系、ASan/UBSan、10,000件Wi-Fi TCP/TLS、Fabric actual adapter、RRMP、FRAGは全てgreen |
| ESP32-S3 compile/link/map境界 | **PASS** | Wi-Fi、RRMP、FRAGはいずれもpinned ESP-IDF v5.5.3で最終ELF/mapまで生成 |
| physical ESP/AP/RF/power-cut HIL | **NOT_RUN** | 対象実機が接続されていない。compile/linkをHILへ読み替えていない |
| `RELEASE_SUPPORTED` / 「100%完成」 | **FAIL** | P0=0、open P1=4。Wi-Fi SPEC受入、FRAG release software matrix、physical HIL/soak、immutable release evidenceが未完了 |

現在のコードをprivate candidateとして継続することにはGOを出せる。一方、
`RELEASE_SUPPORTED`、physical field readiness、24h安定性を名乗ることには
NO-GOである。

## 監査スナップショットと再現境界

- Git HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`
- 監査時worktree: dirty（`git status --short` 380行）
- したがって本監査はHEAD単体ではなく、下記byte snapshotに対する結果である。
- current Host再検証で使用した主なauthority hash:
  - `CMakeLists.txt`:
    `ac76d15c339227b3fe13a283219b7ebbcf82ece5b224983d16b9c0ba96aeddd0`
  - `compatibility-matrix.json`:
    `6d933ac42d835e90eb21e6589a63d3cfa41b2f0aa0c39c0b10c685b4bcc87e65`
  - ADR-0018:
    `e53639e31d6c39c57d67696a81d20a2e08e9372df89104cf19bd223a7ce73362`
  - ADR-0019:
    `dabf5771a1a2bcedb70449b388642caf3c69c79a0a91e67b831201a3b377dc24`
  - ADR-0020:
    `23adab9897c983bff0fdd413aab65beabe016f2a558c22d472dc487e4b8c4821`
  - `docs/30-r6-secure-radio-wire.md`:
    `c57b821f4a034dff8ee78c579b39d4cde379df1c40f3260f57bf89d4d8938869`
  - `docs/34-v2-runtime-fabric-completion.md`:
    `ccf88e90803669720de90e30be8d0fc7e6dd278e8b75a7bb38b2f2d558ab469f`

ESP target境界は
`/Users/dt/.codex/tmp/ninlil-wifi-rrmp-target.mln2JH`へ隔離した
snapshotで実施した。後述の監査中修正2件はCI source列挙とRRMP
claim manifest/gateだけで、target実装TUは変更していない。修正後のcurrent
treeについてはHost側を再configure・再build・再実行した。

## Normative stateの照合

| Slice | machine-readable state | HIL | 結果 |
| --- | --- | --- | --- |
| POSIX TCP/TLS Wi-Fi reference | `PROPOSED` / ceiling `PROPOSED` | 不要 | **PASS**（stateとADR-0018が一致） |
| ESP32-S3 Wi-Fi STA/TCP/TLS | `PROPOSED` / ceiling `PROPOSED` | required、`hil_verified=false` | **PASS**（過大主張なし） |
| NRW1 LINK/FRAG | `SPEC_ACCEPTED` / ceiling `SPEC_ACCEPTED` | required、`hil_verified=false` | **PASS**（design stateと非主張が一致） |
| Relay | `SPEC_ACCEPTED` / ceiling `SPEC_ACCEPTED` | required、`hil_verified=false` | **PASS** |
| Multi-parent / multi-controller | `SPEC_ACCEPTED` / ceiling `SPEC_ACCEPTED` | required、`hil_verified=false` | **PASS** |

根拠は`compatibility-matrix.json:160-215`、ADR-0018
`docs/adr/0018-wifi-bearer.md:3-13`、ADR-0019
`docs/adr/0019-route-relay.md:3-16`、ADR-0020
`docs/adr/0020-multi-parent.md:3-16`である。RRMPのAcceptedはdesign
authorityだけであり、implementation complete、HIL、release support、public ABIを
意味しない。

## Fresh検証結果

### Host通常系

build directory:
`/tmp/ninlil-wifi-rrmp-audit-normal.W0POnz`

主要profile:

```text
Debug
NINLIL_BUILD_HOST_RUNTIME=ON
NINLIL_BUILD_TESTS=ON
NINLIL_ENABLE_STRICT_WARNINGS=ON
NINLIL_ENABLE_PRIVATE_FABRIC_V1=ON
NINLIL_ENABLE_PRIVATE_WIFI_V1=ON
NINLIL_ENABLE_R7_FRAG_PRIVATE=ON
NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON
NINLIL_ENABLE_MFDT_V1_PRIVATE=OFF
NINLIL_WIFI_OPENSSL_AUTHORITY=ON
OpenSSL exact 3.5.7 static authority
```

| 実行 | 結果 |
| --- | --- |
| 対象65 CTest（Wi-Fi、Fabric spec、RRMP spec/status/implementation、FRAG、actual Fabric E2E） | **PASS 65/65**、0 failed、65.55s |
| Fabric専用21 CTest | **PASS 21/21**、0 failed、9.66s |
| Wi-Fi full TCP/TLS/Fabric `FRAMES=10000` | **PASS** |
| OpenSSL strict provenance gate | **PASS**、`authority_claim_allowed=true`、`provenance_status=OK` |

10,000件経路はordered deliveryに加え、bidirectional、slow reader、
malformed fail-closed、credential expiry/mismatch、bad KU/EKU/SAN/SKI/AKI、
exporter、revoke/rotate、simulated AP disconnect、midstream restart、
durable journal、blackhole fenceを全てPASSした。

OpenSSL gateは公式3.5.7 archive SHA-256
`a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8`、
exact static archive、CMake cache、fresh binaryのlink command、dynamic
dependency不在、retained symbol、isolated `OSSL_LIB_CTX`を検査した。

### ASan / UBSan

build directory:
`/tmp/ninlil-wifi-rrmp-audit-asan.CNC7nr`

```text
NINLIL_ENABLE_SANITIZERS=ON
ASAN_OPTIONS=halt_on_error=1:detect_leaks=0
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
```

| 実行 | 結果 |
| --- | --- |
| 対象65 CTest | **PASS 65/65**、0 failed、71.89s |
| Fabric専用21 CTest | **PASS 21/21**、0 failed、10.68s |
| Wi-Fi full TCP/TLS/Fabric `FRAMES=10000` | **PASS** |
| Apple LeakSanitizer | **NOT_RUN** |

AppleのASan runtimeはLeakSanitizerを提供しないため`detect_leaks=0`とした。
これはASan/UBSan結果を弱めるものではないが、leak検査のPASS証拠でもない。

### ESP32-S3 target境界

全てcompile/link/map evidenceであり、target-executed testやphysical HILではない。

| Slice | 実行結果 | 証明できた範囲 | physical |
| --- | --- | --- | --- |
| Wi-Fi direct mbedTLS + Fabric HIL app | **PASS** | client/server両roleを含む最終ELF/map、owner workspace `9008 <= 12288`、DIRAM used `171703 / 341760`、384-byte最大frame `<= 8192`、direct mbedTLS exporter symbol | **NOT_RUN** |
| RRMP | **PASS** | final ELF/map、Kconfig ON、sim TU不在、internal BSS `3140 <= 32768`、resource gate | **NOT_RUN** |
| NRW1 FRAG | **PASS** | final ELF/map、12-source packaging authority、feature default OFF/public leak 0、stack ceiling 4096、FRAG BSS `9416 <= 49152` | **NOT_RUN** |

実機device path
`/dev/cu.usbmodem*`、`/dev/cu.usbserial*`、`/dev/ttyACM*`、
`/dev/ttyUSB*`は0件だった。

## Traceability判定

traceability欠落は検出しなかった。

- `requirements-traceability.yaml`はFoundation PR1の10行専用であり、
  Wi-Fi/RRMP/FRAG名が無いこと自体は欠陥ではない。
- Coverage V2正本は`docs/07-testing-and-quality.md:22-29`の定義どおり、
  Foundation `docs/12`〜`docs/14`、40 `NIN-FND-*`、303 vectorへの
  delegated authority、`NIN-INV-001`〜`014`を対象にする。全feature
  Normative文書の見出し台帳ではない。
- all-privateをfresh configureし、
  `tools/traceability_complete_coverage_gate.py`を実行した結果は
  **PASS**:
  `sources=3 headings=254 requirements=40 vectors=303 invariants=14
  subclaims=21 test_links=503 profiles=all-private`。
- Wi-Fi/FRAGは必要なgeneric invariant（nonce、queue/retry/dedup/
  reassembly/journal）へprofile別証拠が接続されている。RRMP固有designは
  ADR-0019/0020と専用vector/gate/status gateが正本である。

## Open findings

### P1-01 — Wi-FiはまだSPEC_ACCEPTEDではない

**結果: FAIL（100%完成 / release promotionに対して）**

ADR-0018は明示的に`Proposed`であり、Host 10,000件やESP compile/linkを
SPEC受入へ読み替えることを禁止している
（`docs/adr/0018-wifi-bearer.md:3-13`）。SPEC_ACCEPTED gateは
同文書`2152-2190`の8項目を全て閉じる必要がある。

必要な修正:

1. 8項目を個別machine-readable acceptance rowへ分解する。
2. 独立model/KAT、pinned dependency/closure、X.509/credential/resource、
   S1〜S6、private adapter vectorの各証拠を接続する。
3. 未解決P0/P1=0の独立review後だけADR/matrixを
   `SPEC_ACCEPTED`へ遷移する。

受入試験:

- SPEC gate checkとmutation self-test。
- Python/Node/Cの独立oracle一致。
- `Proposed -> SPEC_ACCEPTED`以外の直接promotion、HIL falseのまま
  `RELEASE_SUPPORTED`化、public install露出を全てnegativeで拒否。

### P1-02 — FRAG release software matrixが完全には閉じていない

**結果: FAIL**

`docs/34-v2-runtime-fabric-completion.md:524-529`はFRAGについて、
exact KAT、実際の2〜13 fragment、loss/reorder/duplicate/conflict、fuzz、
resource exhaustion、timer edge、tombstone、restartを要求する。

現在のtestは強いが、release matrixの全組合せを閉じてはいない。

- `tests/radio/r7_frag/r7_frag_state_test.c:91-134`はlength/plan境界と
  13到達可能性を検査する。
- 同`171-316`は選択された3-fragment相当でreorder/duplicate/conflictを
  検査する。
- `tests/radio/r7_frag/r7_frag_durable_snapshot_test.c:407-443`は
  256回のsnapshot single-byte property mutatorを持つ。
- しかし、実際のwire/session/reassembly lifecycleをfrag count
  2、3、…、13の各値で完走する登録testと、FRAG wire/state parserを
  広く対象にしたfuzz campaign/artifactは確認できなかった。

必要な修正と受入試験:

1. frag count 2〜13それぞれでSTART/全CONT/ACK/complete/exact-onceを
   実行するtable-driven Host testを追加する。
2. 各countでloss、reverse reorder、identical duplicate、conflicting
   duplicate、missing START、resource `max/+1`、timer exact boundary、
   tombstone expiry、restartを適用する。
3. wire decoder、state admission、durable snapshotを対象に、
   deterministic seed/corpus、ASan/UBSan、raw artifact付きの
   bounded fuzz jobを登録する。

### P1-03 — physical target実行、HIL、soakが未実施

**結果: NOT_RUN（したがってrelease gateはFAIL）**

- Wi-Fi HIL appはbuildをcompile/link evidenceだけと明記し、
  実AP上で2台を動かすまで`physical_ap_hil=NOT_RUN`とする
  （`ports/esp-idf/wifi_hil_app/README.md:20-22,116-126`）。
- RRMP manifestはphysical 2-hop、3-hop、multi-parent、RF power-cutを
  全て0/`NOT_RUN`とする
  （`tools/rrmp_software_hil_manifest.json:5-21,95-106`）。
- FRAGはmatrix上`required_hil=true`かつ`hil_verified=false`である。
- `docs/34-v2-runtime-fabric-completion.md:519-533`はWi-Fi実AP両方向、
  disconnect/sleep/resource、FRAG 2実機RF/loss、Relay 3 RF実機/24h、
  Multi-parent 2 parent + 1 endpointを要求する。

最低受入campaign:

1. Wi-Fi: ESP client↔Host server、Host client↔ESP server、実AP、
   disconnect/reconnect、IP変更、sleep/wake、credential rotation、
   allocator/heap/pool/stack/watchdog、24h。
2. FRAG: 2 ESP32-S3/SX1262実機RF、deterministic loss/reorder injection、
   exact-once、resource/timer boundary。
3. Relay: 3 RF実機で2-hop/3-hop、planned drain、sudden loss、restart、
   queue exhaustion、24h。
4. Multi-parent: 2 parent + 1 endpointでduplicate uplink、single-owner
   downlink、handoff、split-brain/backhaul loss、old-context replay。
5. 各artifactにsource commit、toolchain/image digest、profile、seed、
   device ID、duration、raw log、fault pointを保存する。

### P1-04 — 現在の結果はimmutable release evidenceではない

**結果: FAIL**

監査対象は380行のdirty/untracked差分を含むため、HEAD SHAだけでは同じbyte
snapshotを再現できない。`docs/34-v2-runtime-fabric-completion.md:532-533`
が要求するsource SHA付きacceptance artifactにはまだ昇格できない。

必要な修正:

1. 共有変更をreview済みcommitへ固定する。
2. clean cloneからnormal、ASan/UBSan、strict OpenSSL、target
   compile/link/map、all-private traceabilityを再実行する。
3. CI run URL/ID、commit SHA、toolchain/container digest、raw resultを
   1つのrelease evidence manifestへ結ぶ。

### P2-01 — Apple上のleak検査は未実施

**結果: NOT_RUN**

Apple ASanで`detect_leaks=1`はruntime非対応だった。Linux
LeakSanitizerまたは同等の明示的leak campaignで補完する。これは今回の
ASan/UBSan PASSをFAILに変えないが、leak-freeの主張はまだできない。

## 監査中に検出し、修正後PASSへ戻った事項

### FRAG ESP CI source authority drift

当初、`tools/esp_idf_ci_docker_run.sh`はFRAG production sourceを8件
hard-codeし、single authorityの10件から
`r7_frag_issue_coordinator.c`と`r7_r2_authority_clock.c`を落としていた。
公式CI recipeの再現は**FAIL**した。

共有側修正後は`tools/r7_frag_stack_gate.py list-production`を唯一の
production列挙元として利用する。再検証結果:

- authority-driven production TU count: 10
- stack gate self-test: **PASS**
- fresh target `.su` check: **PASS**

この事項はopen findingではない。

### RRMP software/HIL manifestのstale claim

当初manifestはAccepted ADR/matrixと矛盾する古い
`NO_GO_P1_REPAIR_REQUIRED`、`spec_accepted=0`を保持していた。
共有側修正後は次で一致した。

- `software_acceptance=GO_PRIVATE_SOFTWARE_CANDIDATE`
- `spec_accepted=1`
- `implementation_candidate=1`
- physical HIL claimsは全て0/`NOT_RUN`
- `open_p1_repairs=[]`

新規`tools/rrmp_software_manifest_gate.py`のcheck/self-testと、CMakeへ
登録された2 CTestを独立実行し、**PASS 2/2**を確認した。physical
evidenceを捏造せずtruth-syncできているため、この事項もopen findingではない。

## 完了順

1. **FRAG Host release matrix**を閉じる。実機なしで完了でき、physical
   campaignのfalse-greenを減らす。
2. **Wi-Fi SPEC_ACCEPTED gate**を8項目単位で閉じ、独立review後にだけ
   stateを昇格する。
3. 変更を**review済みcommit**へ固定し、clean Linux/macOS CIとtarget
   proofを再生成する。
4. **Wi-Fi / FRAG / RRMP physical HILと24h soak**を実行する。
5. 全raw evidenceをcompatibility matrixへ接続して初めて
   `RELEASE_SUPPORTED`を判断する。

## 非主張

本監査は次をPASSと主張しない。

- physical ESP32-S3実行、実AP、実RF、power-cut
- 24h soak、現場距離、node数/SLO、battery life
- 法規・認証・技適
- security audit complete
- stable public ABIまたは`RELEASE_SUPPORTED`

