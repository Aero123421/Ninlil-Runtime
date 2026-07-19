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
- **M3-prep + M3-basic:** portable Core/private library を ESP-IDF component として package し、pinned ESP-IDF `v5.5.3` で ESP32-S3 smoke を target build。加えて port-owned clock / entropy / execution adapters（[ports/esp-idf](ports/esp-idf/README.md)、[docs/18](docs/18-m3-prep-esp-idf-component.md)、[docs/20](docs/20-m3-basic-esp-idf-platform-adapters.md)）。**M3 complete / ESP-IDF port complete / hardware verified ではない**
- **M3-slice control framing:** Controller↔Cell Agent 向け private `NCG1` bounded byte-stream frame codec（[docs/19](docs/19-m3-control-byte-stream-framing.md)）。USB/TCP driver・logical control messages は未実装。**M3 complete ではない**
- **M3-slice owner-task / Cell Agent skeleton / loopback TxPermit:** FreeRTOS dedicated owner-task adapter、generic Cell Agent firmware skeleton（Controller assignment）、deny-by-default virtual/loopback TxPermit（[docs/22](docs/22-m3-owner-cell-agent-skeleton.md)）。USB/radio/Join/security 完了は未実装。**M3 complete ではない**
- **M3-slice durable storage candidate:** format 4 dual-slot durable-storage 候補（[docs/21](docs/21-m3-esp-idf-durable-storage.md); PR #80 merged）。host conformance 済みだが ESP FULL は `COMMIT_UNKNOWN`、実機 power-cut HIL 未実施。**M3 complete / field-ready ではない**
- **U0 USB / physical radio boundary freeze (docs):** compile/runtime 依存分離 [ADR-0003](docs/adr/0003-radio-usb-dependency-direction.md)、NCL1 HELLO（Controller-only）/ session ownership / Compliance Permit sole TX edge（immutable plan 後）/ Required HIL / U1–U7・R1–R10（[docs/23](docs/23-usb-radio-boundary.md)）。**U0 時点の secure radio wire は unallocated（R6 で `wire_profile_id=0x11` docs draft 初割当）。compile ≠ HIL。Attachment/Join・relay・multi-parent は後続。**
- **U1 implementation candidate / host tests:** portable C1 byte-stream contract（`src/transport/byte_stream.h`; single-owner after open including observers）+ A1 POSIX USB/serial adapter（`ports/posix/usb_serial`; termios/poll、**`O_CLOEXEC`**、4KiB rings、WOULD_BLOCK、RX overflow continuity、generation fence）。host PTY/syscall-seam CTest。**Required HIL Linux+macOS physical USB CDC pending — U1 complete ではない。**
- **U2 A2 ESP CDC implementation candidate:** C1 `endpoint_token` + `LINK_LISTENING` + physical attach/DTR UP; A2 `ports/esp-idf` + **`esp_tinyusb==2.1.1`** locks; host pure adversarial CTest + esp32s3 compile/link。**Required HIL flash+host CDC roundtrip pending — U2 complete ではない。USB series 未完成。SX1262 physical RF TX/RX・radio MAC・production radio は未実装（R4 control-plane candidate は別条）。public ABI 非変更。compile ≠ HIL。**
- **R1 ninlil_radio_hal host candidate:** production-private sole `transmit_with_permit` + host spy（success order: **digest→validate→consume→edge×1**; default-deny; §9.3 bind fields; R2 seam only）。**このR1 slice単体はR2/R4/SX1262/RF/legal/HILを完成させない。R1 complete / production radio ではない。public ABI 非変更。**
- **R2 Physical Compliance Permit authority host candidate:** production-private durable permit authority（FIFO / expiry advance / fresh-epoch clock fence / exact live bind / consume durability）をhost vectors・fault injectionで検証。**Japan legal profile / physical RF / HIL / production radio completeではない。public ABI非変更。**
- **R3 LoRa airtime host candidate:** production-private `airtime_calculator`（closed SX1262 LoRa; integer ceil-us; independent oracle + C bridge）。**Japan production 数値 / duty·LBT / R3 complete / HIL ではない。public ABI 非変更。**
- **R4 SX1262 control-plane host candidate:** production-private `drivers/sx126x` reset/init/SPI allowlist + STDBY_RC + board config 注入 + explicit `request_transmit` TX_DENIED（SetTx 構造的不在）。ESP-IDF SPI/GPIO bus adapter candidate。CTest `sx1262_r4` + `sx1262_r4_gate`（[docs/28](docs/28-r4-sx1262-control-plane-backend.md) / [ADR-0008](docs/adr/0008-r4-sx1262-control-plane-backend.md)）。**R4 complete / physical RF TX-RX / HIL / legal ではない。public ABI 非変更。compile ≠ HIL。**
- **R5 LAB_ONLY profile loader + full permit bind host/ESP packaging candidate:** private `src/radio/profile_loader.{h,c}`（LAB_ONLY fail-closed; §9.3 full bind matrix issue+consume; R2 live commit + R3 airtime handoff; staged activate; R1 sole edge）。host CTest `profile_r5` / `profile_r5_gate` / golden oracle; ESP-IDF component は private portable sources として packaging（[docs/29](docs/29-r5-lab-only-profile-loader.md) / [ADR-0009](docs/adr/0009-r5-lab-only-profile-loader.md)）。**R5 complete / FIELD / PRODUCTION / Japan legal / RF / HIL ではない。public ABI 非変更。compile ≠ HIL。**
- **R6 NRW1 compact context-handle wire（docs freeze Accepted; independent re-GO 2026-07-19 P0=P1=P2=0）:** `wire_profile_id=0x11`（no major/minor; post-attachment data）; one-way contexts + hop DATA/ACK lanes; E2E `e2e_security_id`/`epoch≥1` independent of Attachment; durable lifecycle + storage recovery; route terminal invariant; LINK_ACK TX-gen vs RX-validate split; fragment tombstone reserve/fingerprint; HA single sealer; CELL_64_V1; outer 19B + E2E 14B; SINGLE **81/89/97**; oracle-checked LAB airtime（[docs/30](docs/30-r6-secure-radio-wire.md) / [ADR-0010](docs/adr/0010-r6-secure-radio-wire.md); `radio_wire_r6_docs_gate`）。**R6 docs freeze Accepted ≠ R7 full AEAD codec / M4·M5 / ESP N6 capacity / RF·USB 実機 HIL / Japan legal / production radio complete。public ABI 非変更。compile ≠ HIL。**
- **R6 Chunk D private N6 host candidate（fixed-hash integration GO）:** production-private `src/radio/n6_*` の durable record codec、HMAC/HKDF-SHA-256 provider、bounded context store、authenticated local-identity adapter。Mac/Linux host tests、tests-OFF private archive、ESP-IDF component compile/link・stack gateまで検証済み。**R7 full AEAD wire codec、M4/M5 binder、ESP N6容量成立、RF/USB実機HIL、production radioは未実装・未検証。public ABI 非変更。compile ≠ HIL。**
- **R7 T0 private crypto provider implementation candidate（Accepted / independent POST-CI GO 2026-07-19 P0=P1=P2=0）:** portable validation/alias/zeroization wrapper、Host OpenSSL **exact 3.x**、ESP-IDF v5.5.3 mbedTLS、AES-128-GCM / HKDF-SHA-256 / SHA-256、37-vector独立oracle bridgeをproduction-private境界へ追加（[docs/31](docs/31-r7-crypto-provider-and-aead.md) / [ADR-0011](docs/adr/0011-r7-crypto-provider-boundary.md) Accepted）。tests-OFF member/symbol/install leakage、exact CTest set、GCC `-O2` stack evidence、ESP最終ELF linkをfail-closed検査。**このAcceptedはT0 private crypto provider候補だけを対象とする。R7 full wire codec・counter/storage・FRAG/LINK/CELL/HA、実機KAT、RF/USB HIL、Japan legal、production radioは未実装・未検証。public ABI非変更。compile/link ≠ HIL。**
- **R7 T1 NRW1 SINGLE private pure wire codec implementation candidate（Accepted / independent POST-CI GO 2026-07-19 P0=P1=P2=0）:** DATA/SINGLE dual-envelopeの8 private API、bounded C11 codec、独立subset vectors、Host OpenSSL bridge、ESP-IDF mbedTLS final-ELF link、alias・failure atomicity・package/stack/platform/CTestのfail-closed gateを追加（[docs/32](docs/32-r7-t1-nrw1-single-wire-codec.md) / [ADR-0012](docs/adr/0012-r7-t1-nrw1-single-wire-codec.md) Accepted / [review](docs/reviews/2026-07-19-r7-t1-single-wire-codec-accepted.md)）。push/PR CIとpush/PR ESP-IDF CIは全成功。**AcceptedはT1 private pure SINGLE codec候補だけを対象とする。30章 §18のfull artifact/state、counter/storage/replay/durable admission、FRAG/LINK/CELL/HA、W1/L1、実機KAT、RF/USB HIL、Japan legal、production radioは未実装・未検証。public ABI非変更。compile/link ≠ HIL。**
- **R7 T1b context binding / verified HKDF schedule implementation candidate（Accepted / independent POST-CI GO 2026-07-19 P0=P1=P2=0）:** Hop/E2E canonical encode/digestとexpected-digest必須のtyped key bundle導出をprivate portable C11で実装し、exact 24-vector oracle、Host OpenSSL、ESP-IDF mbedTLS final-ELF link、failure/alias/zeroization/package/stack/CTest mutation gateを追加（[docs/33](docs/33-r7-t1b-context-binding-hkdf.md) / [ADR-0013](docs/adr/0013-r7-t1b-context-binding-hkdf.md) Accepted / [review](docs/reviews/2026-07-19-r7-t1b-context-binding-hkdf-accepted.md)）。push/PR CIとpush/PR ESP-IDF CIは全成功。**AcceptedはT1b private stateless候補だけを対象とする。expected digest/traffic secretの生成・認証・配布・保存、context install、counter/nonce/AEAD/replay/durable state、T1 composite、W1/L1/N6/M4/M5、Attachment/Join、LINK/FRAG/CELL/HA、実機KAT、RF/USB HIL、Japan legal、production radio、R7 fullは未完。public ABI非変更。compile/link ≠ HIL。**
- **U3 C3 control-session + C4 pump implementation candidate:** private `src/transport/control_session.*`（NCG1 を C1 byte-stream へ接続; copy-out payload ownership; bounded ingress/TX intent 16/8192; generation/RX-overflow/close fail-closed fence; saturating stats snapshot; zero heap/VLA）。host fake-stream CTest `control_session_u3` + structural/mutation gate + ESP32-S3 component compile/link。**HELLO session state machine / cookie lifecycle / custody / assignment / security は未実装（U4+）。U1/U2 Required HIL および USB series complete を主張しない。public ABI 非変更。compile ≠ HIL。**
- **U4 NCL1 pure codec candidate:** private `src/model/ncl1_codec.*`（exact 26-byte header、closed message/type binding、big-endian encode/decode）と独立生成した47 wire vectors（required ID 46）を追加。**pure codec/wire slice のみであり、HELLO session state machine、cookie lifecycle、liveness、custody、assignment、security、U4 series complete、HILを主張しない。**
- 1 READ_ONLY snapshotでの17 exact key判定、empty namespace証明、17-record/FULL初期化、既存profile検証、commit-unknown fencingを行うprivate Runtime Store L2b1 orchestrator
- **Private Stage 5 empty-domain metadata-init orchestrator**（`src/runtime/stage5_empty_metadata.*`; docs/17 §1/§5/§10.1/§16）: L2b1 NEW_BOOTSTRAP 後向け **private initializer/fencer 契約は complete**。全 API が L2b1 `accepted_validation` authority を必須とし、同一 txn で `build_bootstrap_plan`+`record_at` と get の **byte-exact bootstrap-17** を再証明（内部整合のみを authority 一致と呼ばない）。16-key 分類 + D1 future 分類 + fence 伝播。Stage 5 全体 complete / public Runtime は非claim。**D2-S6 seam 契約は不変**
- Domain Store v1のfamily 5/6 catalog、4KiB record/3KiB chunk上限、最大256-member atomic witness、backlink/capacity/health/recovery順を固定したNormative D0仕様
- Domain Store D1-Aのkey/envelope/digest/witness primitiveと、D1-B1のINTERNAL_INVARIANT / BEARER_STATE / CLOCK_BASELINE / ATTEMPT_REUSE_FENCE / WITNESS_HEAD_INDEX exact body codec・同一record検証・独立golden vector
- Domain Store D1-B2 / D1-B3a..o body codec（SCHEDULER_OWNER / ORDERED_INGRESS / BLOB / ATTEMPT / ATTEMPT_ID_INDEX / CANCEL_STATE / EVIDENCE_CELL / DELIVERY / RESULT_CACHE / REVERSE_REPLY / EVENT_SPOOL / RETRY_SUMMARY / MANAGEMENT_LEDGER / RETENTION_BASIS / CLEANUP_PLAN）。**D1-B3b controller-ingress retrofit implemented**（ORDERED_INGRESS `controller_ingress_*` 32-byte local durable-copy block）。**D1-B3g EVIDENCE_CELL production implemented**。**D1-B3h DELIVERY production implemented**。**D1-B3i RESULT_CACHE production implemented**（kind9/10 `digest||token_generation||phase` exact 42 bytes）。**D1-B3j REVERSE_REPLY production implemented**（exact 330 / raw80+raw86 / key+header bijection / counter-state-timer-I/availability closed matrix）。**D1-B3k EVENT_SPOOL production implemented**（exact 300 / ID128=tx / revision=spool_revision / state×cause / resume 0..8 / discard iff DISCARDED / reservation KEY_DIGEST）。**D1-B3l RETRY_SUMMARY production implemented**（vector format `ninlil-domain-store-v1-d1b3l`; CUMULATIVE exact 84 / RECENT exact 80 / composite key / kind-slot-fold / bools）。**D1-B3m MANAGEMENT_LEDGER production implemented**（vector format `ninlil-domain-store-v1-d1b3m`; exact 364 / kind15-16 matrix / canonical digest recompute）。**D1-B3n RETENTION_BASIS production implemented**（vector format `ninlil-domain-store-v1-d1b3n`; 90+N→106/170 / pending-trusted-eligible matrix / KEY_DIGEST）。**D1-B3o CLEANUP_PLAN production implemented**（vector format `ninlil-domain-store-v1-d1b3o`; 126+N→142/206 / phase remaining/fence matrix / KEY_DIGEST+PVD bijection）。**D2-S3 implementation complete**（exact-profile family5/6 structural same-record scan path + witness 7e/7f local + sibling oracle `domain-scan-structural-v1.json` / `ninlil-domain-scan-structural-v1-d2s3`）。**D2-S4 implementation complete**（same-snapshot private exact_get + presence/borrowed value + sibling oracle `domain-scan-exact-get-v1.json` / `ninlil-domain-scan-exact-get-v1-d2s4`）。**D2-S5 implementation complete**（composition oracle `domain-scan-composition-v1.json` / `ninlil-domain-scan-composition-v1-d2s5` + `note_terminal_corrupt` D3 injection seam）。**D2 (bounded scanner) / DSR1_SCAN / DSR2_ESP_BOUND complete**。**D2-S6 private fail-closed seam implemented**（L2b1 BTS no-reread + private stage5 seam; Stage 5 / D3 / D4 / public Runtime still pending）。**D3-S0 Normative architecture freeze complete**（docs only; `docs/17` §18）。**D3-S1a closed-mode/context freeze complete**（docs only; `docs/17` §18.12）。**D3-S1 exact-1 implementation complete**（`DSI1_BACKLINK` core / modes 1..20 / crossrow oracle `ninlil-domain-scan-crossrow-v1-d3s1` vector_count 94）。**D3-S2a declared multi-count freeze complete**（docs only; `docs/17` §18.13）。**D3-S3a BLOB lifecycle Normative freeze complete**（docs only; `docs/17` §18.14）。**D3-S4a DSW1_ALL_OLD_NEW Normative freeze complete**（docs only; `docs/17` §18.15）。**D3-S2 implementation / D3-S3 implementation / D3-S4 implementation / D3-S5..S12 / D3 overall still pending**。Stage 5 / remaining D3 finding correctness / D4 / public Runtime / ESP-IDF / hardware still pending
- atomic FULL admission write-setとcommit結果別ownership/recovery projection
- exact namespace、snapshot、capacity、fault、commit-unknownを扱うin-memory Storage conformance fixture
- **POSIX SQLite storage port（host production候補）**: `ports/posix/sqlite_storage` + port-owned factory（`ports/posix/include`）。opaque namespace BLOB、finite handle/txn/iterator pool、WAL + `synchronous=FULL`、schema v1 migration拒否、host conformance test（snapshot isolation / ordering / restart / capacity / busy / bad schema / binary bytes / commit-unknown seam）。CMake `NINLIL_BUILD_POSIX_SQLITE_STORAGE` は SQLite3 検出時のみ buildし、無い環境の core を壊さない。**public Runtime body / M1a complete / field-ready は claim しない**
- bounded Allocator、Execution、Virtual Clock、Deterministic Entropy v1 fixture
- 2 endpoint間のtyped message deep-copy、有限FIFO、receive loan、Virtual TxPermitを扱うsimulated Bearer / Tx Gate fixture
- stateless synthetic grant、deny precedence、TEST-only composition guardを扱うOrigin Authorization fixture
- 現在の開発branchの全CTestが成功することを、通常buildとASan/UBSan buildで検査（件数はcontract追加に伴って変動）

未実装または未統合の範囲:

- **public Runtime API body（blocker）:** 全14関数の正本 semantic + generic Command/Event restart E2E が揃うまで `Ninlil::ninlil` は INTERFACE（headers only）。definition count や UNSUPPORTED stub を「実装済み」にしない
- public `runtime_step` orchestration、service_register / submit / cancel / event_resume|discard / delivery の durable 業務 path
- Bearer、Tx Gate、Origin Authorizationのprovider/Runtime統合
- Runtime 統合済みの production durable storage と Stage 5 recovery writer（ESP dual-slot storage candidate と POSIX SQLite host candidate はいずれも Runtime body 未接続; M1a complete / field-ready 非claim）
- Runtime Storeのdomain journal recovery、counter/capacity相互検証、identity rotationとpublic Runtime bodyへの統合
- Domain Store D3相互validation の残 slice（EVIDENCE live L/cardinality multi-row / witness chain / capacity / health 等; **D3-S0 architecture freeze is docs-only complete**; **D3-S1a closed-mode/context freeze is docs-only complete**; **D3-S1 exact-1 implementation complete**; **D3-S2a declared multi-count freeze is docs-only complete**; **D3-S3a BLOB lifecycle freeze is docs-only complete**; **D3-S4a DSW1_ALL_OLD_NEW freeze is docs-only complete**; **D3-S2/S3/S4 implementation / D3-S5..S12 / D3 overall / Stage 5 D3 bind still pending**）、D4 business operation別commit-unknown convergence（empty metadata init は private candidate のみ）
- Stage 5 completion / public Runtime publish / Bearer・clock・entropy open / identity rotation / health reconstruction（**D2-S6 private fail-closed seam は実装済み; Stage 5 complete と public Runtime は still pending**）
- end-to-endのReliable Command / Durable Event path
- ESP-IDF storage の実機 FULL attestation / power-cut HIL、USB series 完成（U1/U2 Required HIL / U3 device path / U4–U7）、LoRa bearer/radio MAC、SX1262 physical RF TX/RX・SetTx path・production radio、完全 logical control / assignment / custody protocol、public Runtime owner wiring（**M3-prep packaging + M3-basic adapters + control framing + owner/cell/loopback skeleton + storage candidate + U0 boundary docs + U1 host candidate + U2 ESP CDC candidate + U3 host C3/C4 framing-session candidate + R1 radio_hal + R2 PCP authority + R3 airtime + R4 SX1262 control-plane + R5 LAB_ONLY profile loader host/ESP packaging candidate まで実装済み。storage は ESP_UNPROVEN; physical RF TX/RX / radio MAC / RF HIL / production radio / U1–U3/R1–R5 complete / USB series complete / M3 complete / port complete / FIELD / PRODUCTION / Japan legal ではない**）
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

必要なのはCMake 3.16以上と、C11 / C++17に対応するC・C++ compilerです。通常buildではstrict warning付きのconsumer smoke、ABI/contract checker、negative testをCTestから実行します。POSIX SQLite storage port を有効にするには host に SQLite3 development package が必要です（未検出時は port だけ skip）。

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

ESP-IDFはV1のtargetです。**M3-prep** のcomponent packagingとpinned `v5.5.3` / ESP32-S3 compile smokeに加え、**M3-basic** のclock / entropy / execution adapters、**M3-slice** のowner-task / Cell Agent skeleton / loopback TxPermit、dual-slot durable-storage candidate、**U2** ESP CDC-ACM adapter candidate（`esp_tinyusb==2.1.1`）、**R4** SX1262 control-plane portable + ESP SPI/GPIO bus candidate、および **R5** LAB_ONLY private profile_loader packaging candidate まで component に収録済みです。**U0** で USB/radio の依存方向と境界を docs freeze 済み（[ADR-0003](docs/adr/0003-radio-usb-dependency-direction.md)、[docs/23](docs/23-usb-radio-boundary.md)）。**U1** は host POSIX USB/serial adapter の **implementation candidate / host tests** まで（Required HIL Linux+macOS pending; U1 complete ではない）。**U2** は host pure tests + target compile/link まで（Required HIL flash+host CDC roundtrip pending; U2 complete ではない）。**U3** は private C3 control-session + C4 pump の **host implementation candidate**（fake C1; NCG1 framing ownership; HELLO/NCL1 は U4）まで。**R4** は control-plane のみ（physical RF TX/RX / SetTx path / radio MAC 未実装）。**R5** は LAB_ONLY host/ESP packaging candidate のみ（FIELD / PRODUCTION / Japan legal / RF / HIL / R5 complete ではない）。storageの実機power-cut HIL / FULL attestation、USB series 完成、physical radio production、public Runtime owner wiringは未完了で、port completeではありません。それ以外のplatformもPort ABIによる移植候補になり得ますが、現時点では検証、互換性、supportを約束しません。詳細は[M3-prep](docs/18-m3-prep-esp-idf-component.md)、[M3-basic](docs/20-m3-basic-esp-idf-platform-adapters.md)、[M3 durable storage](docs/21-m3-esp-idf-durable-storage.md)、[M3 owner/cell skeleton](docs/22-m3-owner-cell-agent-skeleton.md)、[USB/radio boundary](docs/23-usb-radio-boundary.md)、[R4 control-plane](docs/28-r4-sx1262-control-plane-backend.md)、[R5 LAB_ONLY profile loader](docs/29-r5-lab-only-profile-loader.md)を参照してください。

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
