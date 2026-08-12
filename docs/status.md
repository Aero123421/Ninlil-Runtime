# Ninlil Runtime current status

> **Document class: Informative status ledger.** The machine-readable completion authority is
> [`compatibility-matrix.json`](../compatibility-matrix.json); normative behavior comes from the
> normative specifications and Accepted ADRs. This page must not promote a state by itself.
>
> **Translation status:** Japanese original, synchronized 2026-08-12. No English translation is
> maintained for this detailed ledger; [`README.en.md`](../README.en.md) is a non-normative overview.

[`README.md`](../README.md) には、今日使える範囲、未証明の範囲、compact stateだけを置きます。
この文書は、READMEから分離した長い実装根拠、次gate、V1順序、検証区分を保持します。

## 状態の読み方

`RELEASE_SUPPORTED`だけを100%完成と呼びます。`SPEC_ACCEPTED`は実装開始可能な仕様が
固まった状態、`HOST_CANDIDATE`と`TARGET_CANDIDATE`はそれぞれHostとESP targetの
実装候補であり、実機確認の代わりにはなりません。

物理USB、SX1262 RF、flash power-cut、実AP、24時間soakは、対応機材を接続して得た
再現可能なartifactが揃うまで`HIL_VERIFIED`へ進めません。詳細な完成条件は
[V2 Runtime Fabric Completion Contract](34-v2-runtime-fabric-completion.md)を正本とします。

## V1 functional LAB software evidence

V1を実機で使える最小経路へ絞る[ADR-0034](adr/0034-v1-functional-lab-scope.md)は
Acceptedです。[ADR-0035](adr/0035-v1-compact-radio-mapping.md)のRF mappingはProposedで、
private codec・mapping・packet-link・exact airtime gateまで実装されています。

NVB1 codec、exact LAB binding codec、N6接続owner、durable LAB provisioner、固定上限
NCG1 bridgeのHost候補まで実装済みです。公開POSIX USB portを使う実PTYでbinding永続化、
双方向packet、close/reopen generationを確認しました。別のHost縦断では、実Fabric / NRA1 /
NRW1 / R7 / R9 / SX1262 spyを通るApplicationと逆向きAPPLIED Receipt、重複拒否を確認しました。
R7送信保留は同じsealed objectを再開し、応答不要のApplicationは相関枠を消費しないことも
Host試験で確認しています。

USB bridge・provisioner・radio adapterを一つのbounded stepで所有する固定board ownerも
実装し、Host模擬経路でUSB→SX1262 spy→peerと逆向きReceipt→USBを確認しました。同じownerは
ESP-IDF v5.5.3の全private同時ON構成のcomponent archiveへcompile/package済みです。
USB接続世代ごとのtrusted clock anchorと、最初のdurable bindingからController Runtime IDを
採用してからRFを開始する起動契約もHost通常・ASan/UBSan試験で確認しました。

そのownerへESP32-S3のUSB CDC・SX1262・clock・既存Flash Storageを接続するboard imageを
実装し、USB親機／peerともESP-IDF v5.5.3でcompile/link済みです。通常profileは既存上限内の
4 namespaceを使い、診断用session Storageをlinkしません。未検証のFULL commitは
`COMMIT_UNKNOWN`としてfail closedのため、物理power-cut受入前の耐久成功は主張しません。
独立した実機ごとに異なるboot-local clockを持つbindingと、汎用peerが初回bindingから自身の
Runtime IDを採用する起動契約もHost試験済みです。同じESP sourceからUSB親機／汎用peerの
2つのboard imageを生成し、どちらもtarget compile/link済みです。

Linux/macOS側では既存FabricへUSB親機を接続するprivate adapterを実装し、固定2 peer binding／
4 path、送受信、backpressure、切断時のlost/unknownをHost通常・ASan/UBSan試験で確認しました。
利用者が起動するController接続プローブは実装済みで、実PTY上の別processとの`BOARD_INFO`照合、
binding適用、SQLite-backed Composition生成、Fabric登録に加え、任意の1..128-byte
ApplicationDataを公開`ninlil_submit()`からUSBへ送り、逆向きVERIFIED Receiptで`SATISFIED`に
なる一回送信をHost通常・ASan/UBSanで確認しました。常駐loopではありません。

peer側は初回bindingから固定Compositionを生成し、同一Runtimeへ3つのServiceを登録するHost
起動・close試験とESP peer target buildまで合格しました。Host上では実radio packet-linkを
介したDesiredState受信→peer callback→VERIFIED Receipt返送と、同じpeer Runtimeの公開
`ninlil_submit()`からのEventFact上り送信も通常・ASan/UBSanで合格しています。さらに
Controllerの別processが公開`ninlil_submit()`で送ったApplicationDataを、実PTY、固定USB親機
owner、NRA1/NRW1/R7/R9/SX1262 spy、peer Runtime callbackへ一続きで届け、peer Runtimeが
生成したVERIFIED Receiptを同じ経路で返して`SATISFIED`になるHost縦断も通常・ASan/UBSanで
合格しました。

実機起動、物理USB/RF HIL、flash-FULL耐久経路は未完であるため、縦断機能の状態は
`PROPOSED`のままです。仕様候補やcompile成功を物理HIL済みとは扱いません。

## 完成までの進捗台帳

POSIX TCP/TLS、POSIX USB serial、V1 compositionの公開package行は、READMEにあった状態を
履歴ごと移したものです。3 featureはcompatibility matrixへexact dependency、state ceiling、
HIL未確認を含めて登録済みです。このinformative表だけでは状態を昇格できず、matrixと
Accepted ADR、独立review evidenceの整合をgateが検査します。

| 機能 | 現在の状態 | 次の必須gate |
| --- | --- | --- |
| Portable Core / Host Runtime | **SPEC_ACCEPTED / local Host候補** | 4 Service登録、submit、dedupe、query/list、memory/SQLite cold restartを含むtests-OFF installed consumerとworktree clean-roomはlocal合格済み。複数targetのtarget-local retry/outcome/late evidence、durable pre-sendの`DISPATCHING`投影、evidence counterのMAX/restart境界は通常・Sanitizerで合格。targeted managementのcurrent-epoch chronologyとcross-epoch unsafe overtakingの無変更fail-closedも合格したが、一般old-epoch timerのdurable Recovery Fence convergence/restart healingは未完。raw evidence cell全履歴、milestone独立レビュー、同一immutable SHAのLinux/macOS clean-room・Sanitizerも未完 |
| Canonical Domain Store | **SPEC_ACCEPTED / scanner・target build候補** | D3-S4 authority 468/468、通常・Sanitizer・ESP compile/linkは合格。ただしDomain-ON public Runtimeは`NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY=0`で意図的にfail closed。D3-S5..S12、D4、T2/T3/T6、canonical operational writer、restart/cleanup受入を閉じるまでpublic binding完成とは扱わない |
| Identity / Attachment / session install | **PROPOSED / repair中** | pre-attachment scratch lifecycle、quota/token/cookie境界、protocol magic registryを独立authorityで再検証中。M4/M5のFULL durable Attachment、Hop/E2E key install、restart/HILも未完 |
| Fabric Bearer / NFL1 / path registry | **SPEC_ACCEPTED / experimental public package** | `ninlil/fabric_v1.h`と`Ninlil::fabric_v1`を公開。tests-OFF install、2組のRuntime/Fabricによるforward＋reverse Receipt、正当なavailability更新後のcold restart、tamper負例を通常・Sanitizer・独立レビューで確認。次はcomposition ownerから内部engineを束ねる |
| POSIX TCP/TLS Wi-Fi reference | **PROPOSED** | private/default-OFFのWi-Fi bearer候補。Host software試験とESP build証拠はあるが、ADR-0018の受入と実AP HILは未完 |
| POSIX TCP/TLS reference | **SPEC_ACCEPTED / experimental public Host package** | ADR-0030の`ninlil/posix_tls_v1.h`と`Ninlil::posix_tls_v1`を公開。installed public APIだけの2プロセス実TLSでverified Receipt、同じSQLiteを使う2周のclean restartを確認。物理AP・長時間HILは`NOT_RUN` |
| POSIX USB serial reference | **SPEC_ACCEPTED / experimental public Host package** | ADR-0031の`ninlil/posix_usb_serial_v1.h`と`Ninlil::posix_usb_serial_v1`を公開。tests-OFF install後の外部C11 consumerで実PTY双方向通信、close/reopen、generation更新を通常・ASan/UBSan・独立レビューで確認。Linux実行CIとLinux/macOS物理USB CDC HILは別gate |
| ESP32-S3 Wi-Fi STA/TCP/TLS | **PROPOSED / TLS target build合格** | R7 `OTHER_REGISTERED`同居管理はADR-0026として受入済み。internal/PSRAM予約、通常・Sanitizer、ESP-IDF v5.5.3 compile/link/mapも合格。Wi-Fi/LwIPの実行時資源、実AP・切断/restart・peak・soak HILを閉じる |
| NRW1 LINK / FRAG / reassembly | **SPEC_ACCEPTED / target build合格** | 全authority bridgeとsemantic hook、通常・Sanitizer、ESP compile/link、全private候補の同時compile/link/mapは合格。target実行、loss/reorder/restartと物理RF HILを閉じる |
| Relay | **SPEC_ACCEPTED / software候補レビュー合格** | 64KiB以下のatomic storage bundle、strict dual-image import、FULL/CU matrix、通常・Sanitizer各18/18は合格。公開ABI判断と3台RF HILを閉じる |
| Multi-parent / multi-Controller | **SPEC_ACCEPTED / software候補レビュー合格** | durable used-attempt台帳、old/new exact authority CAS、global split-brain fence、10,000 lifecycleは合格。公開ABI判断と実機failover HILを閉じる |
| Multi-frame durable transfer | **SPEC_ACCEPTED / Host software候補** | private MFDT protocol v1、revision 2 OPEN、Host 4-slot coordinator、Runtimeごとのsidecar、1〜4 target admission/restart reconciliationを実装。公開`ninlil_submit()`から2つのHost Runtimeを通常の`ninlil_runtime_step()`だけで駆動し、927〜32768 byteの分割・再構成・digest検証、Application Service apply、positive evidence、handoff、既存Receipt、durable closure、terminal/content releaseまで通常・ASan/UBSanで合格。READY、HANDED_OFF、Receipt closed、retained terminalのcold restartと不一致fail-closedも確認済み。残件はinstalled module/package受入、ESP exact-1 owner、MF-O08 target promotion、物理Wi-Fi/RF/power-cut HIL |
| V1 composition | **SPEC_ACCEPTED / Host・ESP package候補** | ADR-0032の公開`composition_v1` base owner（workspace/create、Runtime/Fabric借用、bounded step、terminal release、close/destroy）を実装。tests-OFF install後の公開APIだけで2つのCompositionを駆動するApplicationData→Receipt E2Eを通常・ASan/UBSanで確認。HostとESP-IDFは同じFabric/Composition source authorityを使用し、ESP32-S3 component archiveのexact-one、最終ELF symbol/map、公開headerだけのtarget翻訳単位を確認済み。target上のdurable create/step/close、Bearer前sidecar recovery、MFDT/FRAG/relay/multi-parent接続とlarge-data/relay受入は未完。8-module制度や汎用plugin frameworkはV1非対象 |
| V1 functional LAB vertical slice | **PROPOSED / Host・target候補** | ADR-0034でLinux/macOS→USB親機→単一hop SX1262→指定peer/Service→APPLIED ReceiptをV1の実機完成線としてAccepted。NRA1/NVB1 codec、exact LAB binding、fresh N6接続owner、`NLB1` FULL保存・cold-restart floor・fresh reset/fence、固定上限NCG1 bridgeは通常Host試験とESP packaging gateに合格。公開POSIX USB portの実PTYでbinding、双方向packet、close/reopenを確認。固定board ownerを使うHost模擬E2EでUSB→NRA1/NRW1/R7/R9/SX1262 spy→peerと逆向きAPPLIED Receipt→USBを確認し、通常・ASan/UBSanに合格。同じESP sourceからUSB親機／汎用peerの2 imageを生成し、既存Flash adapter・4 namespaceを接続、session-ledger symbolなしでtarget compile/link済み。未検証FULLは`COMMIT_UNKNOWN`のままです。別clock epochと両roleのidentity adoptionはHostで確認済み。PC側private adapterは固定2 peer binding／4 path、送受信、backpressure、切断時lost/unknownを通常・ASan/UBSanで確認済み。Controller診断は実process＋PTYでclock照合、binding適用、SQLite Composition、Fabric登録に加え、公開submit→実PTY→USB親機owner→NRA1/NRW1/R7/R9/SX1262 spy→peer Runtime callback→逆向きVERIFIED Receipt→SATISFIEDの一続きのHost縦断が通常・ASan/UBSanで合格。generic peerは初回bindingから固定Compositionを起動し、同一Runtimeに最大3 Serviceを登録するHost lifecycle試験とESP target buildに合格。peer公開submit→EventFact上りも通常・Sanitizerで合格。残件はFlash power-cut受入と昇格、実機起動・物理3台HIL。20件/10秒はV2 |
| OSS package / docs / release CI | **HOST_CANDIDATE** | actionlint・全shellcheck・固定OpenSSL authorityは合格。commit-tree dry run、公開asset照合、独立review（`RELEASE_SUPPORTED`は未昇格） |

OSS行の`HOST_CANDIDATE`は、公開install/package/release機構のHost software候補を意味します。
Portable Coreや各transport機能の完成、remote release成功、物理HIL、法規適合をまとめて
主張する状態ではありません。

## V1ソフトウェア完成までの順序

[ADR-0034](adr/0034-v1-functional-lab-scope.md)により、大型データ・relay統合はV2へ
移しました。V1はまずUSB＋単一hop SX1262実経路を小容量ApplicationDataで閉じます。
仕様がAcceptedでも、未実装の経路を完成扱いにはしません。

1. ~~Portable Fabric公開と実Runtime取引~~ — 完了
2. ~~POSIX TCP/TLS公開と2プロセスrestart E2E~~ — 完了
3. ~~POSIX USB serial公開とinstalled PTY E2E~~ — 完了
4. USB control framingと単一hop ApplicationData↔NRW1 SINGLE mappingを固定 — NCG1/NVB1 bridge、exact LAB binding、N6接続owner、durable LAB provisioner、公開POSIX USB portのbinding・双方向PTYと、別経路の実Fabric→NRA1→NRW1→SX1262 spy→Receipt Host縦断まで完了
5. private SX1262 packet-linkをESP32-S3へ載せる — USB bridge、provisioner、packet-linkを束ねる固定board owner、接続世代ごとのclock anchor、bindingからのController/peer ID採用をHost模擬E2Eで実装。同じsourceのUSB親機／汎用peer imageは既存Flash adapter・4 namespaceを接続し、session-ledgerなしでtarget compile/linkに合格。PC側private USB→Fabric adapterは固定2 peer／4 path。Controller別processの公開submit→実PTY→USB親機owner→NRA1/NRW1/R7/R9/SX1262 spy→peer固定Composition callback→逆向きVERIFIED Receipt→SATISFIEDまでを一続きのHost縦断で確認済み。peer公開submit EventFactもHost合格。残件はFlash power-cut受入・昇格と実機起動・物理USB/RF HIL
6. README・SDK配布物・CIの最終整合監査 — 項目5の実装完了後にHost/ESP software gate、独立差分レビュー、remote CIを閉じる
7. 3台で物理USB＋SX1262の10件/10秒HIL — 機材で実行するまで`NOT_RUN`。実AP、電源断、20件/10秒、relay/multi-parentはV2 gate

## 検証区分

| 区分 | 内容 |
| --- | --- |
| **Host software evidenceあり** | Portable Core、POSIX SQLite、service、durable retry/dedupe、公開Fabric、公開POSIX TCP/TLSの2プロセスrestart E2E、公開POSIX USB serialのPTY E2E、private V1 USB bridgeの永続binding・双方向packet・再接続PTY、固定2 peer／4 pathのPC USB→Fabric adapter、Controller別processの公開submit→実PTY→USB親機owner→NRA1/NRW1/R7/R9/SX1262 spy→peer Runtime callback→逆向きVERIFIED Receipt→SATISFIEDの一続きの縦断、初回bindingから最大3 Serviceを登録し公開submit EventFactも通すpeer固定Composition、private relay/multi-parent、公開submitからApplication Receiptまでのprivate multi-frame Host経路、`composition_v1` base owner。ESP実行と実機経路は未完であり、機能ごとの正式状態は進捗台帳を優先します |
| **ESP compile/link evidence** | ESP-IDF v5.5.3 compile/link/map、PSRAM/stack/resource gate、Wi-Fi/SX1262/USBのtarget adapter、公開Fabric/Compositionとprivate V1 radio packet-link・固定board ownerのcomponent packaging。全private機能の同時ONに加え、USB CDC・SX1262・clock・既存Flash Storage、RF開始前のboot entropy→DRBG切替、peer固定Compositionを接続したUSB親機／peer imageの最終ELFまで合格。通常profileにsession-ledger symbolはありません。target実行と物理経路は未確認なので、platform状態は`SPEC_ACCEPTED`のままです |
| **物理HIL待ち** | ESP flash、実AP、USB CDC、SX1262 TX/RX、2/3-hop、multi-parent failover、電源断、長時間soak。SX1262は2台双方向raw RF runnerまで用意済みですが、機材未接続のため一律`NOT_RUN`です |
