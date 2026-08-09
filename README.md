# Ninlil Runtime

Ninlil Runtime は、LoRa・Wi-Fi・USB など不安定で帯域の狭い現場ネットワーク上で、「送信した」ではなく **届いた・保存された・適用された** を分けて追跡する、組み込み向け通信 Runtime / SDK です。

Ninlil Core は、特定のアプリケーション固有の業務語彙に依存しません。Bearer・期限・宛先・必要な証拠・電力・容量・経路・法規上の制約に基づいて通信を管理します。

## 現在の状態

`main` は、Portable Core / Host RuntimeとOSS配布境界を持つ**プレリリースSDK**です。
公開header、`Ninlil::runtime`、`Ninlil::fabric_v1`、Linux/macOS向けの
`Ninlil::posix_tls_v1`と`Ninlil::posix_usb_serial_v1`、任意のPOSIX SQLite
storage portをinstallできます。relay、multi-parent、multi-frame transferなどの
内部engineは、V1の小さなcomposition APIから利用できる形にするまで個別のpublic
ABIとしてexportしません。

機能状態の正本は[Compatibility matrix](compatibility-matrix.json)です。
[V2 Runtime Fabric Completion Contract](docs/34-v2-runtime-fabric-completion.md)は
Runtime 1.0のProposed完成契約候補であり、関連ADRとともに`SPEC_ACCEPTED`になるまでは
単独の実装・完成判定authorityにしません。
仕様、実装、Host試験、ESP target build、実機HIL、配布証拠を別々に管理し、
テスト件数や概算パーセントだけで完成扱いにしません。

> **LAB_ONLY / pre-release:** production運用、920 MHz法規適合、field SLO、
> 物理USB/RF、実AP、flash power-cutの完了は主張しません。

V1を実機で使える最小経路へ絞る[ADR-0034](docs/adr/0034-v1-functional-lab-scope.md)は
Acceptedです。[ADR-0035](docs/adr/0035-v1-compact-radio-mapping.md)のRF mappingは
Proposedで、private codec・mapping・packet-link・exact airtime gateまで実装されています。
NVB1 codec、exact LAB binding codec、N6接続owner、durable LAB provisioner、
固定上限NCG1 bridgeのHost候補まで実装済みです。公開POSIX USB portを使う実PTYで
binding永続化、双方向packet、close/reopen generationを確認しました。別のHost縦断では、
実Fabric/NRA1/NRW1/R7/R9/SX1262 spyを通るApplicationと逆向きAPPLIED Receipt、重複拒否を
確認しました。R7送信保留は同じsealed objectを再開し、応答不要のApplicationは相関枠を
消費しないこともHost試験で確認しています。USB bridge・provisioner・radio adapterを
一つのbounded stepで所有する固定board ownerも実装し、Host模擬経路で
USB→SX1262 spy→peerと逆向きReceipt→USBを確認しました。同じownerはESP-IDF v5.5.3の
全private同時ON構成のcomponent archiveへcompile/package済みです。USB接続世代ごとの
trusted clock anchorと、最初のdurable bindingからController Runtime IDを採用してから
RFを開始する起動契約もHost通常・ASan/UBSan試験で確認しました。さらに、そのownerへ
ESP32-S3のUSB CDC・SX1262・clock・既存Flash Storageを接続するboard imageを実装し、
USB親機／peerともESP-IDF v5.5.3でcompile/link済みです。通常profileは既存上限内の
4 namespaceを使い、診断用session Storageをlinkしません。未検証のFULL commitは
`COMMIT_UNKNOWN`としてfail closedのため、物理power-cut受入前の耐久成功は主張しません。
独立した実機ごとに異なるboot-local clockを持つ
bindingと、汎用peerが初回bindingから自身のRuntime IDを採用する起動契約もHost試験済みです。
同じESP sourceからUSB親機／汎用peerの2つのboard imageを生成し、どちらもtarget
compile/link済みです。Linux/macOS側では既存FabricへUSB親機を接続するprivate
adapterを実装し、固定2 peer binding／4 path、送受信、backpressure、切断時の
lost/unknownをHost通常・ASan/UBSan試験で確認しました。利用者が起動する
Controller接続プローブは実装済みで、実PTY上の別processとの`BOARD_INFO`照合、binding
適用、SQLite-backed Composition生成、Fabric登録に加え、任意の1..128-byte
ApplicationDataを公開`ninlil_submit()`からUSBへ送り、逆向きVERIFIED Receiptで
`SATISFIED`になる一回送信をHost通常・ASan/UBSanで確認しました。常駐loopではありません。
peer側は初回bindingから固定Compositionを生成し、同一Runtimeへ3つの
Serviceを登録するHost起動・close試験とESP peer target buildまで合格しました。Host上では
実radio packet-linkを介したDesiredState受信→peer callback→VERIFIED Receipt返送と、同じ
peer Runtimeの公開`ninlil_submit()`からのEventFact上り送信も通常・ASan/UBSanで合格しています。
さらにControllerの別processが公開`ninlil_submit()`で送ったApplicationDataを、実PTY、
固定USB親機owner、NRA1/NRW1/R7/R9/SX1262 spy、peer Runtime callbackへ一続きで届け、
peer Runtimeが生成したVERIFIED Receiptを同じ経路で返して`SATISFIED`になるHost縦断も
通常・ASan/UBSanで合格しました。実機起動、物理USB/RF HIL、flash-FULL耐久経路は
未完であるため、
縦断機能の状態は`PROPOSED`のままです。
仕様候補やcompile成功を物理HIL済みとは扱いません。

### 完成までの進捗台帳

`RELEASE_SUPPORTED`だけを100%完成と呼びます。`SPEC_ACCEPTED`は実装開始可能な
仕様が固まった状態、`HOST_CANDIDATE`と`TARGET_CANDIDATE`はそれぞれHostとESP targetの
実装候補であり、実機確認の代わりにはなりません。

| 機能 | 現在の状態 | 次の必須gate |
| --- | --- | --- |
| Portable Core / Host Runtime | **SPEC_ACCEPTED / local Host候補** | 4 Service登録、submit、dedupe、query/list、memory/SQLite cold restartを含むtests-OFF installed consumerとworktree clean-roomはlocal合格済み。複数targetのtarget-local retry/outcome/late evidence、durable pre-sendの`DISPATCHING`投影、evidence counterのMAX/restart境界は通常・Sanitizerで合格。raw evidence cell全履歴、milestone独立レビュー、同一immutable SHAのLinux/macOS clean-room・Sanitizerが未完 |
| Canonical Domain Store | **SPEC_ACCEPTED / scanner・target build候補** | D3-S4 authority 468/468、通常・Sanitizer・ESP compile/linkは合格。ただしDomain-ON public Runtimeは`NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY=0`で意図的にfail closed。D3-S5..S12、D4、T2/T3/T6、canonical operational writer、restart/cleanup受入を閉じるまでpublic binding完成とは扱わない |
| Identity / Attachment / session install | **PROPOSED / private Host candidate** | precondition contractとNIAF S5 amendmentはAcceptedです。固定容量・fail-closedなprivate consumer kernelと、caller指定専用namespaceのprivate NIAF standalone ownerはHost候補です。NIAFはCore/Foundation Domain Store durability authority配下でcanonical Domain schema-1 catalogとは独立し、availabilityを公開しません。PA-S0 software gateとPA-S1aのexact libedhoc/zcbor default-OFF依存・test-only custom-memory候補は独立reviewでGOですが、PA-S2 cryptoやEDHOC ownerではありません。ESP32-S3 compile/linkとframe evidenceまでで、target実行は未実施です。Compositionへの注入、PA-S1全体、PA-S2..S6、direct/cold Join、物理HILは未完です。 |
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
| Three-node NJM1 automatic Join / relay LAB | **LAB_HIL_VERIFIED / private** | 同一ESP32-S3＋SX1262 imageを3台へ書き込み、共有机上で自動Join、論理2-hop、4-byte DATA＋相関ACK、親消失時のdirect reroute、旧site lease満了後の別site再Joinを実RFで確認。Mac Mesh LAB Consoleは親機1台のUSBだけからRF-onlyノードの親経路・hop・RSSI/SNRを表示し、30秒超の経路維持、2-hop Ping/Pong、B停止時のC自動迂回まで3台実機で確認済み。1 Controller＋7 RFの直列Ping/Pong sweepはHost試験済みだが、8台実機HILは`NOT_RUN`。これはunauthenticated NJM1 private LABだけの証拠で、上記V1 NRA1/NRW1 slice、RRMP、Production Attachment、RF隔離、距離、法規適合、10件/10秒、soakを昇格しない。詳細は[36章](docs/36-three-node-auto-join-relay-lab.md)と[実機証跡](docs/work/2026-08-09-three-node-njm1-rf-hil.md) |
| OSS package / docs / release CI | **HOST_CANDIDATE** | actionlint・全shellcheck・固定OpenSSL authorityは合格。commit-tree dry run、公開asset照合、独立review（`RELEASE_SUPPORTED`は未昇格） |

OSS行の`HOST_CANDIDATE`は、公開install/package/release機構のHost software候補を
意味します。Portable Coreや各transport機能の完成、remote release成功、物理HIL、
法規適合をまとめて主張する状態ではありません。

private NJM1 3-board LABだけは物理SX1262 RF evidenceを取得済みです。物理USBを含む
V1 ApplicationData vertical slice、RRMP、flash power-cut、実AP、24時間soakは、対応する
再現可能なartifactが揃うまで`HIL_VERIFIED`へ進めません。現行状態はCompatibility
matrix、V1 scopeはADR-0034を正本とします。[34章](docs/34-v2-runtime-fabric-completion.md)は
Runtime 1.0のProposed完成契約候補です。

V1 LAB後にNinlil Runtime 1.0へ進む作業順は
[37章](docs/37-runtime-1.0-integration-program.md)と
[ADR-0038](docs/adr/0038-runtime-1.0-integration-program.md)で提案しています。
private NJM1を製品扱いせず、Production Attachment、Fabric、secure radio、RRMP、
Wi-Fi、multi-frame、残るApplication contractを同じRuntime/Compositionへ統合します。
ADR-0034のV1 LAB scopeと`HIL_VERIFIED` ceilingは変更せず、このProposed計画文書
自体も実装や完成状態を昇格しません。

### V1ソフトウェア完成までの順序

ADR-0034により、項目4の大型データ・relay統合はV2へ移しました。V1はまず
項目5のUSB＋単一hop SX1262実経路を小容量ApplicationDataで閉じます。
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
| **Host software evidenceあり** | Portable Core、POSIX SQLite、service、durable retry/dedupe、公開Fabric、公開POSIX TCP/TLSの2プロセスrestart E2E、公開POSIX USB serialのPTY E2E、private V1 USB bridgeの永続binding・双方向packet・再接続PTY、固定2 peer／4 pathのPC USB→Fabric adapter、Controller別processの公開submit→実PTY→USB親機owner→NRA1/NRW1/R7/R9/SX1262 spy→peer Runtime callback→逆向きVERIFIED Receipt→SATISFIEDの一続きの縦断、初回bindingから最大3 Serviceを登録し公開submit EventFactも通すpeer固定Composition、private relay/multi-parent、公開submitからApplication Receiptまでのprivate multi-frame Host経路、`composition_v1` base owner。ESP実行と実機経路は未完であり、機能ごとの正式状態は上表を優先します |
| **ESP compile/link evidence** | ESP-IDF v5.5.3 compile/link/map、PSRAM/stack/resource gate、Wi-Fi/SX1262/USBのtarget adapter、公開Fabric/Compositionとprivate V1 radio packet-link・固定board ownerのcomponent packaging。全private機能の同時ONに加え、USB CDC・SX1262・clock・既存Flash Storage、RF開始前のboot entropy→DRBG切替、peer固定Compositionを接続したUSB親機／peer imageの最終ELFまで合格。通常profileにsession-ledger symbolはありません。target実行と物理経路は未確認なので、platform状態は`SPEC_ACCEPTED`のままです |
| **private NJM1物理HIL** | 同一imageのESP32-S3＋SX1262 3台で、923.0 MHz / BW125 / SF7 / CR4/5 / 10 dBm、既存CAD/LBT＋R5 permit pathを使用。自動Join、共有机上の論理2-hop、4-byte DATA/ACK、親機1 USBのRF topology、30秒超の経路維持、Ping/Pong、親消失reroute、旧site expiry後の別site再Joinを確認済み。Production Attachment、RRMP、法規適合、距離、RF隔離、負荷・soakの証拠ではありません |
| **残る物理HIL** | V1 USB CDC→NRA1/NRW1 ApplicationData縦断、10件/10秒、実AP、multi-parent、電源断、長時間soakは`NOT_RUN`。private NJM1のPASSをこれらへ代用しません |

## アーキテクチャ

```
 Application services / arbitrary ApplicationData
                    |
                    v
        +--------------------------+
        | Portable Runtime Core    |
        | admission / deadline     |
        | retry / dedupe / outcome |
        +------------+-------------+
                     |
           +---------+---------+
           v                   v
    Durable Storage       Fabric / Bearers
    POSIX SQLite          Wi-Fi / USB / LoRa
           |                   |
           +---------+---------+
                     v
               Peer Runtime
```

Coreはsocket、ESP-IDF、SX1262、アプリ固有語彙を知りません。platform adapterが
storage・clock・entropy・Bearerを提供し、private機能はAccepted public ABIの外側で
段階的に昇格します。

## 5 分 quickstart

前提: Linux または macOS、CMake ≥ 3.20、C11 コンパイラ、**OpenSSL 3.x**（Host Runtime / host tests）。**SQLite3** は任意の POSIX storage port 用です。
Repository の build / CTest と install 済み CMake package の独立 consumer は、
どちらも CMake ≥ 3.20 を要求します。

```bash
git clone https://github.com/Aero123421/Ninlil-Runtime.git
cd Ninlil-Runtime
cmake -S . -B tmp-v1 \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build tmp-v1 -j
ctest --test-dir tmp-v1 --output-on-failure
```

### V1 USB Controller接続プローブ（private LAB）

Linux/macOSで、USB親機とのclock照合、1〜2個のexact binding適用、SQLite-backed
Composition生成、最大4 pathのFabric登録を確認できます。任意で1件のDesiredStateを
指定peer/Serviceへ送り、VERIFIED Receiptまで待てます。既定ではbuildされず、Domain
schema 1候補との同時利用も意図的に拒否します。

```bash
cmake -S . -B tmp-controller \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_V1_LAB_CONTROLLER=ON \
  -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=OFF
cmake --build tmp-controller \
  --target ninlil_v1_lab_controller ninlil_v1_lab_controller_probe_test -j
ctest --test-dir tmp-controller -R '^v1_lab_controller_probe$' \
  --output-on-failure

./tmp-controller/ninlil_v1_lab_controller \
  --usb /dev/cu.usbmodem-DEVICE \
  --database ./controller.sqlite3 \
  --binding ./peer-a.nlb1 \
  --binding ./peer-b.nlb1 \
  --send-binding 1 \
  --send-service 1 \
  --payload-hex 01020304
```

接続確認だけなら末尾の`--send-*`と`--payload-hex`を省略します。

bindingは秘密を含むprivate LAB配布物です。プローブは内容を表示せず、binding pathの
最終componentがsymlinkのもの、hard-link、実行ユーザー以外が所有するファイル、
group/other権限付きファイルを拒否します。現段階では接続確認後に終了し、Application
送信は上記の一回診断だけです。常駐運転、binding発行・在庫管理は行いません。

現行SDKの詳細: [Host Runtime SDK](docs/host-runtime-sdk.md)

### installしてCMakeから使う

```bash
cmake --install tmp-v1 --prefix "$PWD/tmp-install"
```

consumer側:

```cmake
find_package(Ninlil CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE Ninlil::runtime)
```

用途に応じて`Ninlil::fabric_v1`、`Ninlil::posix_tls_v1`、
`Ninlil::posix_usb_serial_v1`も同じinstalled packageからlinkできます。

POSIX SQLite adapterのexport名と、testsを含まないclean installの確認方法は
[Host Runtime SDK](docs/host-runtime-sdk.md)を参照してください。

### private候補を開発・検証する

以下は既定で`OFF`です。公開ABIやproduction supportを意味しません。

| CMake option | 候補機能 |
| --- | --- |
| `NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING` | Canonical Domain Store runtime binding |
| `NINLIL_ENABLE_PRIVATE_FABRIC_V1` | Fabric registry / NFL1 / path selection |
| `NINLIL_ENABLE_PRIVATE_WIFI_V1` | POSIX/ESP Wi‑Fi packet-link |
| `NINLIL_ENABLE_R7_FRAG_PRIVATE` | secure radio fragmentation/reassembly |
| `NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1` | relay / multi-parent |
| `NINLIL_ENABLE_MFDT_V1_PRIVATE` | multi-frame durable transfer |

全private候補を同時にHost検証する例:

```bash
cmake -S . -B tmp-all-private -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON \
  -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON \
  -DNINLIL_ENABLE_PRIVATE_WIFI_V1=ON \
  -DNINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=ON \
  -DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON \
  -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON
cmake --build tmp-all-private -j
ctest --test-dir tmp-all-private --output-on-failure
```

system OpenSSLを使うWi‑Fi Host buildはLAB用です。authority証拠には
`tools/wifi_v1_build_pinned_openssl.sh`とCIで固定したOpenSSL profileを使います。

## Examples（host simulation）

`examples/v1_lab/` の 4 本。いずれも host 上で `submit → delivery` を再現します。

**M1a 公開 family は DesiredState + EventFact のみ**（[ADR-0024](docs/adr/0024-m1a-public-family-matrix-freeze.md)）。named reserved `LATEST_STATE_RESERVED` / `MEASUREMENT_RESERVED` は `service_register = NINLIL_E_UNSUPPORTED` のままで、first-class public family ではありません。Display / Leak は製品ラベルの **display snapshot event (EventFact)** / **leak measurement event (EventFact)** です（service_id 文字列は `latest-state` / `leak-measurement` だが family enum は EventFact）。

| Example | 説明 | 実行（historical target name; label-only） |
| --- | --- | --- |
| **Controller** | Site Controller から統合 topology へ DesiredState を submit | `cd tmp-v1 && ./ninlil_v1_lab_controller_submit_example` |
| **Cell** | Cell Agent — USB custody + radio TX 経路 | `cd tmp-v1 && ./ninlil_v1_lab_cell_custody_example` |
| **Display** | Display ノード相当の 2-process loopback 上行 — **display snapshot event (EventFact)** | `cd tmp-v1 && ./ninlil_v1_lab_display_latest_state_example` |
| **Leak** | Leak ノード相当の 2-process loopback 上行 — **leak measurement event (EventFact)** | `cd tmp-v1 && ./ninlil_v1_lab_leak_measurement_example` |

Executable / CTest 名 `*_display_latest_state_*` / `*_leak_measurement_*` は **互換用の historical label のみ**（deprecation 候補; 改名しない）。reserved public family の有効化を意味しません（ADR-0024）。

一括実行: `ctest -R 'v1_lab_.*_example' --test-dir tmp-v1 --output-on-failure`

## Capability / Service / ApplicationData

[Application Contracts（docs/02）](docs/02-application-contracts.md) に準拠します。

- **Service（`ServiceDescriptor`）** — Runtime 起動時に登録する静的な通信契約（contract family、方向、payload 上限、required evidence、route / bearer 方針など）。
- **Capability** — Join / Attachment 後に確定する effective capability（requested ∩ device supported ∩ policy）。Admission は fresh capability snapshot で検査します（[Identity and Join（docs/03）](docs/03-identity-and-join.md) §Capability negotiation）。
- **ApplicationData** — admission 後に Runtime が所有する 1 件の論理 data / intent の **概念名**です。独立した public C type ではなく、**Transaction + payload + descriptor snapshot** として durable store に保存します（docs/02 §SubmissionとApplicationData）。

## Build と test

| 種別 | コマンド |
| --- | --- |
| 通常 Debug | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j && ctest --test-dir build --output-on-failure` |
| ASan / UBSan | `CC=clang CXX=clang++ cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug -DNINLIL_ENABLE_SANITIZERS=ON && cmake --build build-sanitize -j && ctest --test-dir build-sanitize --output-on-failure` |

**前提:** Python 3（vector oracle 生成）、OpenSSL 3.x（Host R7 crypto tests）、SQLite3 development package（POSIX storage port; 未検出時は port のみ skip）。

統合 E2E gate: `ctest -R v1_integration_gate --test-dir tmp-v1 --output-on-failure`

## 対応 platform

| Platform | 状態 |
| --- | --- |
| **POSIX host（Linux x86_64 / macOS arm64）** | **HOST_CANDIDATE（software-ready）** — LAB quickstart・examples・統合 E2E・consumer install smoke・release archive clean-room は Host ソフトウェア検証対象。**`RELEASE_SUPPORTED` ではない**。物理 HIL は未 |
| **ESP-IDF v5.5.3（ESP32-S3 target build）** | compile / link smoke（`.github/workflows/esp-idf.yml`）。**HIL pending** — flash / USB 実機 / RF / power-cut は RC 残件（software smoke ≠ field HIL） |

## 制限・security・法規

- **LAB_ONLY** — 国内実運用・production 法規認定・field SLO は主張しません。
- 脆弱性報告: [SECURITY.md](SECURITY.md)（非公開 Security Advisory 経由）。
- ライセンス: [Apache License 2.0](LICENSE)。

## ドキュメント

| 文書 | 内容 |
| --- | --- |
| [Documentation index](docs/README.md) | 仕様の読み順・正本ルール |
| [Host Runtime SDK](docs/host-runtime-sdk.md) | 現行CMake packageのbuild・install・利用 |
| [SDK distribution manifest](docs/sdk-distribution-manifest.md) | 現行install tree・export境界・release artifacts |
| [Compatibility matrix](compatibility-matrix.json) | version・platform・feature状態・HIL境界のmachine-readable正本 |
| [Dependency inventory](dependency-inventory.json) | Host / ESP-IDF dependency、version、license、lock hash、container digestのmachine-readable正本 |
| [Release Guide](docs/releasing.md) | immutable source identity、source archive、SBOM、attestationの公開手順 |
| [Requirements traceability](requirements-traceability.yaml) | Foundation PR1の厳密な試験対応表。Coverage V2がbaseline / all-private両profileのNormative見出し・要件・vector・invariantを検査 |
| [V1 LAB quickstart](docs/v1-lab-quickstart.md) | `v1.0-lab-rc2`履歴スナップショット |
| [V1 LAB developer](docs/v1-lab-developer.md) | `v1.0-lab-rc2`開発者向け履歴 |
| [V1 LAB distribution](docs/v1-lab-distribution-manifest.md) | `v1.0-lab-rc2`配布履歴 |
| [RC 残件](docs/work/2026-07-23-v1-rc-residuals.md) | 物理実機系のみの残作業 |
| [CHANGELOG](CHANGELOG.md) | 利用者向け変更履歴 |
| [CONTRIBUTING](CONTRIBUTING.md) | 貢献手順 |
| [Pre-V1 実装履歴](docs/release-history.md) | M0–R7 candidate スライス履歴（README から退避） |

仕様の入口: [Project Charter](docs/00-project-charter.md) → [Architecture](docs/01-architecture.md) → [Application Contracts](docs/02-application-contracts.md) → [Runtime API](docs/04-runtime-api-and-storage.md)

## License

Ninlil Runtime は [Apache License 2.0](LICENSE) で提供します。
