# Ninlil Runtime

Ninlil Runtime は、LoRa、Wi-Fi、USBのような不安定で細い現場network上で、「送信した」ではなく「届いた、保存された、適用された」を分けて追跡する、組み込み向け通信 Runtime / SDK です。

KGuard は最初の reference application ですが、Ninlil Core は KGuard の業務語彙を知りません。LoRa、Wi-Fi、USB などを bearer として扱い、要求の期限、宛先、必要な証拠、電力、容量、経路、法規上の制約に基づいて通信を管理します。

## 現在の状態

**M0 specification baseline complete / Foundation PR1 ABI and contract tooling checkpoint (pre-alpha)** です。実装は開始していますが、現時点の成果はpublic ABI宣言と、その契約差分を検出するtoolingが中心です。

実装済みの範囲:

- `include/ninlil/*.h`のpublic ABI宣言と、C11 / C++17 consumer compile smoke
- enum、`sizeof`、`offsetof`、reason registry、Operator projection、hook mirror、仕様vector、requirements traceabilityの機械検査
- public output初期化/nullability、small/future `struct_size`、unsupported値分類に使うinternal pure C11 helper

未実装または未統合の範囲:

- public runtime APIのfunction body、transaction reducer、durable storage、bearer orchestration
- radio MAC、実RF、ESP-IDF component、Cell Agent
- `NIN-PR1-OUTPUT-001`、`NIN-PR1-STRUCT-001`、`NIN-PR1-UNSUPPORTED-001`はhelper testまでで、public runtime APIへ未統合のため`partial`

- 公開 API、wire、storage format の互換性はまだ保証しません。
- 最初に実装する範囲は、[Foundation Release](docs/08-foundation-release.md)で固定するM1a transaction kernelです。
- relay、multi-parent、production radio MAC は roadmap 上の後続 milestone であり、Foundation Release の完成条件には含めません。
- OSS license は公開release前のblockerです。初期推奨はApache-2.0ですが、repository ownerの決定前です。

## Ninlilが約束すること

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

## Buildとtest

必要なのはCMake 3.16以上と、C11 / C++17に対応するC・C++ compilerです。通常buildではstrict warning付きのconsumer smoke、ABI/contract checker、negative testをCTestから実行します。

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

CTestの件数はcontract追加に伴って変わるため、特定件数ではなく全test成功をgateとします。GitHub ActionsでもUbuntu上のGCC通常buildとClang sanitizer buildに同じ手順を使用します。

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
