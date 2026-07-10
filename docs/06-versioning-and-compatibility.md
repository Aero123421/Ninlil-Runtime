# 06. Versioning and Compatibility

状態: Normative Foundation baseline（post-M1a evolutionはdraft）<br>
対象: Foundation以降の全release

## 原則

Ninlilは複数の独立したversion domainを持ちます。単一の`protocol_version`にまとめません。

| Domain | Version rule | 互換性の単位 |
| --- | --- | --- |
| Runtime / SDK release | SemVer | source/API behavior |
| Public C ABI | ABI major/minor | header + binary |
| Data wire | family/major/minor | Endpoint間application transport |
| Control/gateway protocol | major/minor | Controller–Cell Agent–Endpoint control |
| Application schema | namespace/schema/major/minor | payload semantics |
| Service descriptor | immutable revision | admission/policy snapshot |
| Capability manifest | schema version + revision | supported feature set |
| Persistent storage | storage schema version | crash-safe data |
| Hardware profile | schema + revision | board/radio/antenna binding |
| Regulatory profile | schema + revision | TX hard gate |
| Diagnostics/export | event schema version | tooling and support bundle |

## Legacy boundary

現行`linkos/`の19-byte wireは **Legacy LinkOS Lab Wire 1** と呼びます。

- Ninlil Wire v1ではありません。
- KGuard固有enum、16-bit node ID、legacy SQLite/NVS、CLI/envを互換契約にしません。
- Legacy labはbench再現とone-way fixtureにだけ使用します。
- 新storageへin-place migrationしません。必要なevidenceはread-only export/importで扱います。

## Runtime / SDK SemVer

- `0.x`: breaking changeを許しますが、minor bump、CHANGELOG、migration note、compatibility matrixが必須です。
- `1.0+`: public APIのbreaking changeはmajor bumpを必須とします。
- bug fixでもwire、storage、schemaのdomain version変更が必要なら、それぞれ独立にbumpします。
- release versionから他domain versionを推測してはなりません。

## Public C ABI

- opaque handleを使用します。
- public structは`abi_version`と`struct_size`を先頭に持ちます。
- minor ABIは末尾field追加だけを許し、既存fieldのoffset/meaningを変えません。
- enumの未知値を受け取る可能性を考慮し、switch defaultをfail-safeにします。
- public C++ ABI、exception、STL type、compiler-specific layoutを契約にしません。
- allocator ownership、pointer lifetime、callback re-entryを04章どおり固定します。

## Wireとcapability negotiation

Attachment時に次を交換します。

- supported data wire range
- supported control protocol range
- required critical capabilities
- optional capabilities
- schema fingerprint/alias table
- security suite range
- hardware/regulatory profile binding

規則:

- 交差集合から1組を選び、attachment/sessionへ固定します。
- unknown critical capabilityはattach拒否です。
- unknown optional capabilityは無効化し、negotiation resultへ明示します。
- security、receipt evidence、complianceをsilent downgradeしてはなりません。
- version mismatchを単なる`offline`として表示しません。構造化reasonを返します。
- attachment-scoped short address/schema handleをstable identityとして保存しません。

## Application schema evolution

Schema identityは`namespace + schema ID + major`です。

- breaking semantic changeは新majorまたは新schema IDです。
- minor追加は、old readerが無視でき、defaultが明示されたoptional fieldだけです。
- required fieldの追加、field type変更、既存enum意味変更はbreakingです。
- field/tag IDを再利用してはなりません。
- unknown critical fieldはrejectします。
- unknown optional fieldはskipできます。
- Receiptはschema versionとcontent digest/generationへbindingします。
- gateway/relayは明示的application adapterなしにpayload version変換をしません。

## Service descriptor revision

- descriptor revisionはimmutableです。
- canonical digestが異なる同一revisionを受理してはなりません。
- transactionはadmission時のdescriptor revisionをsnapshot参照します。
- descriptor updateを既存transactionへ遡及適用しません。
- old revisionを廃止する前に、active transactionとfield fleetの使用がないことを確認します。

## Persistent storage migration

- migrationはversionごとの明示関数とします。
- 再実行可能でなければなりません。
- migration marker、source version、target versionをdurable記録します。
- 各write pointでcrashしても、oldまたはnewの一貫した状態へ回復できなければなりません。
- irreversible migration後にold binaryを起動した場合、明示的に拒否します。
- schema不明、migration途中を推測で読みません。
- legacy LinkOS DBをNinlil DBへin-place変換しません。

## Regulatory / hardware compatibility

- unknown profile schema/revisionへdefault fallbackしません。
- HardwareProfileとRegulatoryProfileの互換範囲をmachine-readableにします。
- profile revision変更はactive permit、ledger、sessionとの整合を検査します。
- revoked/expired profileをrollback先にしません。

## Rolling upgrade order

初期推奨順:

1. 新旧versionを理解するControllerを先に配置する。
2. Cell Agentを1 cellずつ更新する。
3. mains-powered Endpointを更新する。
4. sleepy/battery Endpointをmaintenance windowで更新する。
5. old version使用がなくなったevidenceを確認する。
6. old compatibility pathを別releaseで廃止する。

Update中もdownlink owner、membership epoch、transaction identityを維持します。互換matrixにない組合せはattach拒否し、勝手にold protocolへfallbackしません。

## Machine-readable compatibility matrix

各releaseは`compatibility-matrix.json`を含みます。最低限:

```text
runtime release
C ABI range
data wire range
control protocol range
storage schema range
application schema fixtures
hardware/regulatory profile schema range
supported ESP-IDF/POSIX versions
legacy adapter status
deprecation/removal release
```

Matrixと実test targetをCIで一致させます。文書だけに存在するsupported combinationを作りません。

## Deprecation

Public alphaまでに、次を決めます。

- field fleetのminimum support期間
- N-1/N-2互換範囲
- deprecation notice期間
- critical update時の例外
- LTS branchの有無

1.0前でも、deprecationなしにfield device supportを削除する場合はrelease noteで明示し、operator actionを提供します。

## Acceptance tests

- public C headerのold/new compile/link matrix
- unknown small `struct_size`とfuture large `struct_size`
- supported wire/control versionのgolden vector
- unknown optional/critical capability
- schema field追加、field order変更、unknown enum、required field追加拒否
- Controller/Cell Agent/Endpointのmixed-version matrix
- rolling upgradeとrollback simulator
- storage migration全write pointのcrash injection
- unsupported regulatory profile schemaでphysical TXゼロ
- compatibility matrix記載targetとCI targetの一致

## Release gate

Release tag前に、次がすべて必要です。

- 各domainのversion bumpが実変更と一致する。
- CHANGELOGと必要なmigration guideがある。
- compatibility matrixが生成・検証済みである。
- golden vectorとmixed-version testが通る。
- storage migration crash matrixが通る。
- undocumented breaking changeがない。

## Foundationで固定するもの

- Runtime release: `0.1.0`予定
- Public C ABI: `0.1` experimental
- Storage schema: `1` experimental
- Simulated bearer protocol: test fixture only
- Ninlil public data wire: **未割当**
- Ninlil control protocol: **未割当**

Wireを実装していないFoundationで`wire v1`を先取り採番しません。
