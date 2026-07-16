# Ninlil Runtime

Ninlil Runtime は、LoRa、Wi-Fi、USBのような不安定で細い現場network上で、「送信した」ではなく「届いた、保存された、適用された」を分けて追跡する、組み込み向け通信 Runtime / SDKを目指すprojectです。

KGuard は最初の reference application ですが、Ninlil Core は KGuard の業務語彙を知りません。LoRa、Wi-Fi、USB などを bearer として扱い、要求の期限、宛先、必要な証拠、電力、容量、経路、法規上の制約に基づいて通信を管理します。

**現時点ではSDKとして利用できないpre-alphaです。** Public Runtimeの実行経路、production storage、実transport、ESP-IDF portは未完成であり、製品や現場へ導入できるreleaseではありません。

## 現在の状態

**Pre-alpha** です。M0 specification baselineとFoundation PR1は完了しています。PR2の主要なadmission/reducer model、PR3a/b/c/dのcanonical TEST fixture、Runtime Lifecycle L1、Runtime Store v1のportable codec/bootstrap pure modelとbootstrap-only Storage orchestrationまで実装されていますが、public Runtimeとして動作する縦切りはまだ完成していません。

実装済みの範囲:

- `include/ninlil/*.h`のpublic ABI宣言と、C11 / C++17 consumer compile smoke
- enum、`sizeof`、`offsetof`、reason registry、Operator projection、hook mirror、仕様vector、requirements traceabilityの機械検査
- public output初期化/nullability、small/future `struct_size`、unsupported値分類に使うinternal pure C11 helper
- scheduler candidate、deadline projection、Required Receipt、resource ledger/batch、Submission preflight/admissionのpure C11 model
- Runtime config/Platform検証、11種capacity導出、Storage/Bearer/Clock/entropy分類、Stage 9 health gateのpure C11 Lifecycle model
- Runtime Store v1の17 bootstrap key、typed big-endian record、CRC32C、境界/破損検査を行うportable C11 codec
- Stage1 successだけが発行するheader/pointer-free accepted-config projectionからcanonical binding/identity、17-record presence/integrity、profile/identity decision、compact lazy bootstrap planを作るRuntime Store L2a2 pure model
- Lifecycle/Runtime Store Coreをpublic `ninlil`とTEST fixtureから分離し、subprojectでも単独buildできる非export `ninlil_runtime_private` STATIC target
- **M3-prep + M3-basic:** portable Core/private library を ESP-IDF component として package し、pinned ESP-IDF `v5.5.3` で ESP32-S3 smoke を target build。加えて port-owned clock / entropy / execution adapters（[ports/esp-idf](ports/esp-idf/README.md)、[docs/18](docs/18-m3-prep-esp-idf-component.md)、[docs/20](docs/20-m3-basic-esp-idf-platform-adapters.md)）。NVS / owner-task body / USB / Wi-Fi / SX1262 / HIL は未実装。**M3 complete / ESP-IDF port complete / hardware verified ではない**
- **M3-slice control framing:** Controller↔Cell Agent 向け private `NCG1` bounded byte-stream frame codec（[docs/19](docs/19-m3-control-byte-stream-framing.md)）。USB/TCP driver・Cell Agent task・logical control messages は未実装。**M3 complete ではない**
- 1 READ_ONLY snapshotでの17 exact key判定、empty namespace証明、17-record/FULL初期化、既存profile検証、commit-unknown fencingを行うprivate Runtime Store L2b1 orchestrator
- Domain Store v1のfamily 5/6 catalog、4KiB record/3KiB chunk上限、最大256-member atomic witness、backlink/capacity/health/recovery順を固定したNormative D0仕様
- Domain Store D1-Aのkey/envelope/digest/witness primitiveと、D1-B1のINTERNAL_INVARIANT / BEARER_STATE / CLOCK_BASELINE / ATTEMPT_REUSE_FENCE / WITNESS_HEAD_INDEX exact body codec・同一record検証・独立golden vector
- Domain Store D1-B2 / D1-B3a..o body codec（SCHEDULER_OWNER / ORDERED_INGRESS / BLOB / ATTEMPT / ATTEMPT_ID_INDEX / CANCEL_STATE / EVIDENCE_CELL / DELIVERY / RESULT_CACHE / REVERSE_REPLY / EVENT_SPOOL / RETRY_SUMMARY / MANAGEMENT_LEDGER / RETENTION_BASIS / CLEANUP_PLAN）。**D1-B3b controller-ingress retrofit implemented**（ORDERED_INGRESS `controller_ingress_*` 32-byte local durable-copy block）。**D1-B3g EVIDENCE_CELL production implemented**。**D1-B3h DELIVERY production implemented**。**D1-B3i RESULT_CACHE production implemented**（kind9/10 `digest||token_generation||phase` exact 42 bytes）。**D1-B3j REVERSE_REPLY production implemented**（exact 330 / raw80+raw86 / key+header bijection / counter-state-timer-I/availability closed matrix）。**D1-B3k EVENT_SPOOL production implemented**（exact 300 / ID128=tx / revision=spool_revision / state×cause / resume 0..8 / discard iff DISCARDED / reservation KEY_DIGEST）。**D1-B3l RETRY_SUMMARY production implemented**（vector format `ninlil-domain-store-v1-d1b3l`; CUMULATIVE exact 84 / RECENT exact 80 / composite key / kind-slot-fold / bools）。**D1-B3m MANAGEMENT_LEDGER production implemented**（vector format `ninlil-domain-store-v1-d1b3m`; exact 364 / kind15-16 matrix / canonical digest recompute）。**D1-B3n RETENTION_BASIS production implemented**（vector format `ninlil-domain-store-v1-d1b3n`; 90+N→106/170 / pending-trusted-eligible matrix / KEY_DIGEST）。**D1-B3o CLEANUP_PLAN production implemented**（vector format `ninlil-domain-store-v1-d1b3o`; 126+N→142/206 / phase remaining/fence matrix / KEY_DIGEST+PVD bijection）。**D2-S3 implementation complete**（exact-profile family5/6 structural same-record scan path + witness 7e/7f local + sibling oracle `domain-scan-structural-v1.json` / `ninlil-domain-scan-structural-v1-d2s3`）。**D2-S4 implementation complete**（same-snapshot private exact_get + presence/borrowed value + sibling oracle `domain-scan-exact-get-v1.json` / `ninlil-domain-scan-exact-get-v1-d2s4`）。**D2-S5 implementation complete**（composition oracle `domain-scan-composition-v1.json` / `ninlil-domain-scan-composition-v1-d2s5` + `note_terminal_corrupt` D3 injection seam）。**D2 (bounded scanner) / DSR1_SCAN / DSR2_ESP_BOUND complete**。**D2-S6 private fail-closed seam implemented**（L2b1 BTS no-reread + private stage5 seam; Stage 5 / D3 / D4 / public Runtime still pending）。**D3-S0 Normative architecture freeze complete**（docs only; `docs/17` §18）。**D3-S1a closed-mode/context freeze complete**（docs only; `docs/17` §18.12）。**D3-S1 exact-1 implementation complete**（`DSI1_BACKLINK` core / modes 1..20 / crossrow oracle `ninlil-domain-scan-crossrow-v1-d3s1` vector_count 94）。**D3-S2a declared multi-count freeze complete**（docs only; `docs/17` §18.13）。**D3-S3a BLOB lifecycle Normative freeze complete**（docs only; `docs/17` §18.14）。**D3-S2 implementation / D3-S3 implementation / D3-S4..S12 / D3 overall still pending**。Stage 5 / remaining D3 finding correctness / D4 / public Runtime / ESP-IDF / hardware still pending
- atomic FULL admission write-setとcommit結果別ownership/recovery projection
- exact namespace、snapshot、capacity、fault、commit-unknownを扱うin-memory Storage conformance fixture
- bounded Allocator、Execution、Virtual Clock、Deterministic Entropy v1 fixture
- 2 endpoint間のtyped message deep-copy、有限FIFO、receive loan、Virtual TxPermitを扱うsimulated Bearer / Tx Gate fixture
- stateless synthetic grant、deny precedence、TEST-only composition guardを扱うOrigin Authorization fixture
- 現在の開発branchの全CTestが成功することを、通常buildとASan/UBSan buildで検査（件数はcontract追加に伴って変動）

未実装または未統合の範囲:

- public Runtime APIのfunction bodyと`runtime_step` orchestration
- Bearer、Tx Gate、Origin Authorizationのprovider/Runtime統合
- restart-safe SQLite portとproduction durable storage
- Runtime Storeのdomain journal recovery、counter/capacity相互検証、identity rotationとpublic Runtime bodyへの統合
- Domain Store D3相互validation の残 slice（EVIDENCE live L/cardinality multi-row / witness chain / capacity / health 等; **D3-S0 architecture freeze is docs-only complete**; **D3-S1a closed-mode/context freeze is docs-only complete**; **D3-S1 exact-1 implementation complete**; **D3-S2a declared multi-count freeze is docs-only complete**; **D3-S3a BLOB lifecycle freeze is docs-only complete**; **D3-S2 implementation / D3-S3 implementation / D3-S4..S12 / D3 overall / Stage 5 D3 bind still pending**）、D4 operation別commit-unknown convergence
- Stage 5 completion / public Runtime publish / Bearer・clock・entropy open / identity rotation / health reconstruction（**D2-S6 private fail-closed seam は実装済み; Stage 5 と public Runtime は still pending**）
- end-to-endのReliable Command / Durable Event path
- ESP-IDF storage/NVS、FreeRTOS owner-task body、USB transport、LoRa bearer/radio MAC、Cell Agent（**M3-prep packaging + M3-basic clock/entropy/execution adapters + private control frame codecまで。M3 complete / port completeではない**）
- Display node / Leak nodeを使う実機end-to-end検証
- `NIN-PR1-OUTPUT-001`、`NIN-PR1-STRUCT-001`、`NIN-PR1-UNSUPPORTED-001`はhelper testまでで、public runtime APIへ未統合のため`partial`

- 公開 API、wire、storage format の互換性はまだ保証しません。
- 最初に実装する範囲は、[Foundation Release](docs/08-foundation-release.md)で固定するM1a transaction kernelです。
- relay、multi-parent、production radio MAC は roadmap 上の後続 milestone であり、Foundation Release の完成条件には含めません。

Ninlil V1のhardware exitには、PC Controller、ESP-IDF port、USB接続、LoRa通信、Display nodeとLeak nodeによる実機end-to-end testをすべて通す必要があります。これは`1.0.0`の必要条件であり、十分条件ではありません。`1.0.0`は[Roadmap](docs/09-roadmap.md)のM11を含む全milestone exit gateを満たした後にだけreleaseします。現在のfixture/CI成功をV1完成やfield readinessとは扱いません。

## V1 contract goals

V1では、次のcontractを実装・検証することを目標とします。現在のpre-alphaがこれらを提供済みという意味ではありません。

- API受付、送信、受信、永続保存、application反映を別の事実として扱う。
- admissionした transaction を、終端 Outcome まで追跡する。
- retry、再起動、経路変更を跨ぐidentityと、application effectの重複を抑止する契約を提供する。
- queue、retry、dedup、fragment、journalを有限にする。
- 容量不足や達成不能を成功に見せず、調整案または理由付き拒否を返す。
- applicationを特定のradio、parent、channelへ直接結合しない。

Ninlilは、任意の負荷や任意の障害下での必達を約束しません。SLOは、明示したtraffic envelope、hardware profile、fault modelの下でadmissionしたtransactionに対して定義します。

### 保証を読むときの境界

| 表現 | Ninlilが意味すること | 意味しないこと |
| --- | --- | --- |
| `ADMITTED` | authorityがlocal durable custodyを引き受け、release/profileで必須の検査とlocal予約を完了した | 相手へ到着、即時送信、期限内effect |
| duplicate suppression | 同じlogical operationを同じtransactionへ収束し、persistent IDをapplicationへ渡す | 任意のphysical effectの無条件exactly-once |
| durable | 指定storage portとfault modelの範囲で、commit済みrecordを復元する | media全損、未検出hardware故障、無限保持容量 |
| EventFactを失わない | **admission済み**EventFactをsilent drop/replaceしない | spool満杯やstorage故障でも全検知を必ずadmitすること |
| simulator合格 | state、crash、loss、duplicate等のmodelが規範どおり | 実RF性能、電池寿命、法令適合 |

Application effectのexactly-onceには、absolute/idempotent operation、applicationとのatomic apply、またはapplication側persistent dedupのいずれかが必要です。

## ドキュメント

仕様の読み順と正本ルールは [Documentation Index](docs/README.md) を参照してください。

最初に読む文書:

1. [Project Charter](docs/00-project-charter.md)
2. [Architecture](docs/01-architecture.md)
3. [Application Contracts](docs/02-application-contracts.md)
4. [Identity and Join](docs/03-identity-and-join.md)
5. [Runtime API and Storage](docs/04-runtime-api-and-storage.md)
6. [Foundation Release](docs/08-foundation-release.md)
7. [Operator Model](docs/11-operator-model.md)
8. [Glossary](docs/15-glossary.md)

Project運用文書:

- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)
- [Apache License 2.0](LICENSE)

## Buildとtest

必要なのはCMake 3.16以上と、C11 / C++17に対応するC・C++ compilerです。通常buildではstrict warning付きのconsumer smoke、ABI/contract checker、negative testをCTestから実行します。

**Test / oracle 前提**: Domain Store D1-A / D1-B1 / D1-B2 / D1-B3a / D1-B3b / D1-B3c / D1-B3d / D1-B3e / D1-B3f / D1-B3g の vector 生成・検査（`domain_store_vector_oracle` CTest）には **Python 3** interpreter が必要です（`find_package(Python3 COMPONENTS Interpreter REQUIRED)`）。production runtime 自体は Python に依存しません。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

ASan / UBSan対応compiler（GCC、Clang、AppleClang）では、別build directoryで同じsuiteを実行できます。

```sh
CC=clang CXX=clang++ cmake -S . -B build-sanitize \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

CTestの件数はcontract追加に伴って変わるため、特定件数ではなく全test成功をgateとします。GitHub ActionsではUbuntu上のGCC通常buildとClang sanitizer buildに同じ手順を使用します。ESP-IDF ESP32-S3 target buildは host CI から分離した別 workflow（公式 Docker image `espressif/idf:v5.5.3`）で実行します。

## Portabilityとversioning

Portable CoreはC11で実装し、host thread、filesystem、radio driverを直接参照しません。現在の検証実績は、GitHub Actions上のUbuntuで行うGCC通常buildとClang ASan/UBSan build、およびmacOSでのlocal development checkです。これらはpre-alpha checkpointの検証環境であり、platform support宣言ではありません。

ESP-IDFはV1のtargetです。**M3-prep** のcomponent packagingとpinned `v5.5.3` / ESP32-S3 compile smokeに加え、**M3-basic** のclock / entropy / execution adaptersまで実装済みです。storage / owner-task body / USB / radio bearerと実機HILは未実装であり、port completeではありません。それ以外のplatformもPort ABIによる移植候補になり得ますが、現時点では検証、互換性、supportを約束しません。詳細は[M3-prep ESP-IDF component](docs/18-m3-prep-esp-idf-component.md)と[M3-basic platform adapters](docs/20-m3-basic-esp-idf-platform-adapters.md)を参照してください。

`0.x`でbreaking changeを行う場合も、minor version bump、CHANGELOG、migration note、compatibility matrixを必須とします。`1.0.0`はV1 hardware exitだけではなく、M11までの全exit gateを満たした後にreleaseします。詳細は[Versioning and Compatibility](docs/06-versioning-and-compatibility.md)を参照してください。

## Repositoryの位置付け

- このrepositoryは、Ninlil Runtimeの仕様、public header、portable implementation、contract toolingを収める独立repositoryです。
- KGuard Product V1、PoC、Legacy LinkOS Labは別projectのconsumerまたは移行元であり、このrepository内に`productv1/`、`poc1/`、`linkos/` directoryが存在することを前提にしません。
- 文書中のKGuard / LinkOS参照は設計境界と移行文脈を示すもので、build dependencyではありません。

Ninlil CoreへKGuard、Product V1、PoC、Legacy LinkOSの業務codeをimportしてはいけません。将来のKGuard integrationは、このrepositoryが提供するpublic APIだけをconsumerとして利用します。

## 名称

正式名称は **Ninlil Runtime**、SDKは **Ninlil SDK** とします。

- controller daemon: `ninlild`
- operator CLI: `ninlilctl`
- C symbol prefix: `ninlil_`
- ESP-IDF component prefix: `ninlil_`

旧称`LinkOS`はlegacy labを指す場合だけ使用します。

## License

Ninlil Runtimeは[Apache License 2.0](LICENSE)で提供します。脆弱性の報告は[Security Policy](SECURITY.md)に従ってください。
