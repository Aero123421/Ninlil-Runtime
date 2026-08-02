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
| Control/gateway protocol | major/minor | Controller–Cell semantic catalog（HELLO 交渉の `control_version`）。byte-stream framing `NCG1` v1 は [19章](19-m3-control-byte-stream-framing.md)。**NCL1 envelope `logical_version` とは別 domain**（[23章](23-usb-radio-boundary.md)）。**private control protocol v1**（HELLO/PING/PONG/RESET）は [23章](23-usb-radio-boundary.md)。**private control protocol v2**（assignment [25章](25-u5-cell-operating-assignment.md) + custody [26章](26-u6-transport-custody.md)）は negotiated `selected_control_version=2` でのみ合法。**public control protocol / public ABI catalog** は **未割当 (unallocated)** |
| NCL1 envelope format | `logical_version` byte | NCG1 payload 内 header 形式（U4: `NCL1_HEADER_BYTES=26`、offset 16 `session_cookie` u64、`MAX_NCL1_BODY=998`）。U4 は exact 1。v2 は reject または別 freeze（control protocol major と番号空間を共有しない） |
| Secure compact radio wire | **wire_profile_id only**（**no major/minor domain**） | Endpoint/Cell physical RF frame。**R6 draft:** `wire_profile_id=0x11` = NRW1/AES-128-GCM/HKDF-SHA-256 + one-way contexts / DATA·ACK lanes / E2E security id（[30章](30-r6-secure-radio-wire.md) / [ADR-0010](adr/0010-r6-secure-radio-wire.md) Accepted 仮）。post-attachment data profile; M4 join/bootstrap は別 profile。**R7 codec/AEAD 実装・HIL・production radio complete ではない**。USB NCG1/NCL1 と番号空間非共有（[23章 §9](23-usb-radio-boundary.md)） |
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
- application-specific enum、16-bit node ID、legacy SQLite/NVS、CLI/envを互換契約にしません。
- Legacy labはbench再現とone-way fixtureにだけ使用します。
- 新storageへin-place migrationしません。必要なevidenceはread-only export/importで扱います。

## Runtime / SDK SemVer

- `0.x`: breaking changeを許しますが、minor bump、CHANGELOG、migration note、compatibility matrixが必須です。
- `1.0+`: public APIのbreaking changeはmajor bumpを必須とします。
- CMake packageのversion選択も同じ境界を使います。`0.x`は同一minor内だけを
  compatibleと判定し、`1.0+`は同一major内をcompatibleと判定します。
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

各releaseはrepository rootの
[`compatibility-matrix.json`](../compatibility-matrix.json)を含みます。最低限:

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
[`tools/compatibility_matrix_gate.py`](../tools/compatibility_matrix_gate.py)はCMake release、
public ABI、Foundation storage schema、ESP-IDF component/pin、CI runner、evidence path、
HIL必須機能の状態をfail-closedで照合します。`HIL_VERIFIED`または
`RELEASE_SUPPORTED`へ進める変更は、対応する再現可能なevidenceと同じchangeでmatrixを
更新しなければなりません。

`features[].evidence`は仕様・実装・通常CIの追跡先、`hil_evidence`は実機手順と
取得artifactの最低2ファイル、`release_evidence`はrelease gate・互換性・独立reviewを含む
最低3ファイルです。`required_hil=true`の行は`hil_verified=true`と実在する
`hil_evidence`なしに`HIL_VERIFIED`以上へ進めません。`RELEASE_SUPPORTED`はさらに
`release_evidence`が無ければgateが拒否します。単にbooleanだけを書き換えて完成表示することは
できません。

各`hil_evidence` / `release_evidence`参照はclass、repository相対path、SHA-256を持ち、
参照先JSONはschema、40桁source commit、対象feature/platformを表す`subject_id`、
test ID、platform ID、PASS結果、実在するUTC日時を持ちます。HIL証跡は最低2件、
release証跡は最低3件が必要です。required HIL対象を`RELEASE_SUPPORTED`へ進める場合も、
HIL証跡を省略できません。

### M3-prep / M3-basic ESP-IDF pin（support 宣言ではない）

Foundation pre-alpha の **M3-prep** / **M3-basic** では、ESP-IDF を次の concrete tag に pin して target **compile smoke**（M3-basic では basic adapter link を含む）を CI します。これは production support matrix の完成でも、M3 exit でもありません。port-owned factory は `ports/esp-idf/include/ninlil_esp_idf/` に置き、`include/ninlil` public ABI は変更しません（[20章](20-m3-basic-esp-idf-platform-adapters.md)）。

| Item | Pin |
| --- | --- |
| ESP-IDF | `v5.5.3`（正本: `ports/esp-idf/ESP_IDF_VERSION`） |
| Target | `esp32s3` |
| Evidence | `.github/workflows/esp-idf.yml` + `ports/esp-idf/smoke_app` |
| Docs | [18-m3-prep-esp-idf-component.md](18-m3-prep-esp-idf-component.md) |

host POSIX CI（`.github/workflows/ci.yml`）とは分離します。pin 変更時は docs / `idf_component.yml` / workflow を同一変更で揃えます。

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
- Ninlil **complete / public** control protocol（public catalog / public ABI）: **未割当**
- Ninlil **private minimal** control catalog（U1–U4 NCL1 HELLO/PING/PONG/RESET; [23章](23-usb-radio-boundary.md)）: private Normative（`control_version` 交渉値は U4 で 1）。public 採番・ABI 昇格とは別
- Ninlil **private control protocol v2**（U5 assignment + U6 custody; [25章](25-u5-cell-operating-assignment.md) / [26章](26-u6-transport-custody.md); ADR-0005/0006）: private Normative（`selected_control_version=2`）。NCL1 envelope v1 は維持。v1 closed catalog へ type を silent 追加しない。public 採番・ABI 昇格とは別
- Ninlil **private MFDT protocol v1**（multi-frame durable transfer）:
  **SPEC_ACCEPTED design authority**。Accepted HELLO/control versionはexact 1または2のまま、
  active sessionへbindした独立`private_mfdt_admission_v1` MFN1 transcriptを使う。
  private NCL1 typeはAccepted catalog直後の最小連続範囲`0x34..0x43`
  （MFN1 `0x34/0x35`、transfer `0x36..0x43`）。docs/23·25·26とADR-0006を
  re-freezeせずbyte-exact維持する。base control version 1/2と別version domainであり、
  default-ON、public ABI、release support allocationではない。正本は
  [ADR-0021](adr/0021-multi-frame-durable-custody.md)。

Wireを実装していないFoundationで`wire v1`を先取り採番しません。private U4 catalog の存在を public control protocol v1 割当とみなしません。private U5/U6 catalog も public 割当とみなしません。

### ADR-0017 Fabric candidateのversion分離（Proposed）

[ADR-0017](adr/0017-bearer-registry-path-selection.md)の`SPEC_ACCEPTED`候補は、既存domainを
次のように維持する。ADR状態はProposedのままであり、下表はsupport/public allocation claimではない。

| Domain | Exact candidate / rule |
| --- | --- |
| Runtime Platform C ABI | `NINLIL_ABI_VERSION=0x0001`不変、単一`ninlil_bearer_ops_t`。array/tail field追加0 |
| Installed/public Fabric ABI | 未割当。public header、export symbol、install target、SemVer compatibility claim 0 |
| Private Fabric source API | candidate `0x0001`。`NINLIL_ENABLE_PRIVATE_FABRIC_V1=OFF` default、exact-size struct、unknown version拒否 |
| NFL1 logical envelope | candidate version 1。public application wireでもNRW1でもない |
| NFL1 length domains | header 584、codec構造受理587..1925、codec buffer ceiling 2048。6-kind意味論positive最大は1797 |
| Fabric storage | dedicated `ninlil.fabric.v1` schema 1 candidate。`FBM1/FBR1/FBP1/FBC1/FBA1/FBT1`、273 records / 137,940 CU bytes、FULL staging 546 / 275,880。FBA1は688-byte payload / 712-byte valueでcall-scoped permit claimを同居させ、別permit claim recordは持たない。Foundation schema 1、ESP format 4、radio-security store不変 |
| Compact radio mapping | 未割当。NFL1↔NRW1を推測せず、別Accepted ADR/KATまでRF packet admission/TX 0 |

mixed versionはdescriptorのlocal/peer versionがともにNFL1 exact 1で、peer capabilityの
`NFL1_V1` bitもある場合だけを許す。peer 0、2、unknown、capability不一致では
UNSUPPORTED/attach拒否とし、raw `ninlil_bearer_message_t`、field drop、zero補完へfallbackしない。
rollback binaryが`ninlil.fabric.v1` unknown schema/migration markerを見た場合はREAD_WRITE call 0で
拒否する。schema 1にはpredecessor migrationがなく、空namespaceへのfresh adoptionだけを許す。
将来migrationはsource/target/migration generation/rollback floorと全write-point
COMMIT_UNKNOWN KATを持つ新schema ADRなしに開始しない。
Accepted 30章が示す現ESP port `max_namespaces=2`では、3個目の
`ninlil.fabric.v1`を有効化しない。既存Foundation/radio-security namespaceへ混在させず、
target storage profileの別review/evidenceまでESP FabricはUNSUPPORTEDである。

compatibility matrixへFabricを載せるのは少なくとも次を満たしたreleaseだけである。

- public Platform ABI manifestがbit/offset exact不変で、old non-Fabric consumerがcompile/linkする
- private feature OFF buildがFabric symbol/object/storage namespaceを参照しない
- feature ONのsame-version KATとold/new/unknown拒否matrixが通る
- `tools/fabric_bearer_spec_vector_gen.py --check`がbyte-identicalである
- compact RF mapping未実装buildがNRW1をemitせず、Accepted 30章のTxPermit sole authorityを迂回しない

### ADR-0018 Wi-Fi candidate allocation summary（Proposed、未割当）

[ADR-0018](adr/0018-wifi-bearer.md)のWi-Fi packet-link / NWB1 / TLS profileは**Proposed
docs-only**であり、下表はsupport・public allocation・`SPEC_ACCEPTED` claimではない。

| Domain | Exact candidate / rule |
| --- | --- |
| NWB1 framing | version 1候補。header 40、payload structural 587..1925、total 627..1965。境界reject 586/1926・626/1966。CRC32C Castagnoli。public on-air support 0 |
| NWB1 session | post-attachment exporter only。pre-attachment `peer_session_id`だけではNWB1 0 |
| Network durable metadata | namespace `ninlil.wifi.network.v1`、`NWD1` 160-byte record候補、committed 1,280 / staging 2,560 CU。password plaintext storage 0 |
| TLS suite | `NINLIL-WIFI-TLS13-P256-V1`候補: `0x1301` / `0x0017` / `0x0403` only |
| Host TLS pin | static `openssl-3.5.7`（peeled `8cf17aae…`）target 0x01/0x02。R7 generic OpenSSL 3.x major pinとは非同一authority |
| ESP TLS pin | ESP-IDF `2c211b23…` + mbedTLS `ffb280bb…` direct。ESP-TLS public API 0 |
| Machine vectors | `spec/vectors/wifi-bearer-spec-v1.json` + Python/Node/C11 gates。independent inventory 79 acceptance IDs with ID→semantic contract (not set-check only); COMMIT_UNKNOWN closed set includes BOTH |

Wi-Fiをcompatibility matrix / `RELEASE_SUPPORTED`へ載せる条件はADR-0018の
`SPEC_ACCEPTED` gateと`RELEASE_SUPPORTED` gateが閉じた後だけである。本summaryの存在を
reserved採番や実装完了とみなさない。

### R5 RegulatoryProfile schema 2 (R6)

Fixed 160-byte envelope; schema field 1→2; schema1 reserved[112..155]=0; schema2 authority_clock_epoch_id at [112..128). R6 0x11 requires schema 2. Loader support is R7.
