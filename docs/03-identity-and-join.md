# 03. Ninlil Identity and Join

状態: Normative identity baseline (Fable review reflected)

## 目的

製造 identity、現場所属、現在の親機、relay 経路、通信許可を「Join」という一つの状態に混ぜないための model を定めます。

## 5つの独立した状態

| 概念 | 答える質問 | 典型寿命 |
| --- | --- | --- |
| Device Identity | この物理機器は誰か | 製造から廃棄まで |
| Site Membership | この管理domainで何を許可されるか | 配備・移設・失効まで |
| Attachment | 今どの parent / bearer と session を持つか | 短期 lease |
| Route Lease | controller までどう運ぶか | topology epoch 単位 |
| Traffic Grant | どの service をどれだけ送れるか | policy / capacity 単位 |

原則:

```text
requested capability
∩ device supported capability
∩ membership authorization
∩ current capacity
= effective grant
```

Parent や relay が変わっても Device Identity と Site Membership は変えません。Site が変わる場合は Attachment だけでなく Membership と session credential を切り替えます。

## Identity

### Stable Device Identity

- 製造時に一意に割り当てる。
- hardware asset / credential と binding する。
- radio の16-bit short addressと分ける。
- QRにsecretを入れない。
- clone detection と revoke の単位にする。

Public ID の具体bit幅は RFC で決めます。Wire上では attachment-scoped short locator を使えます。

### Installation / Logical Endpoint Identity

機器交換で維持したい場所・役割を表します。

例:

- zone A の valve
- 3階の display
- tank 2 の level endpoint

Pending transaction を旧 device から新 device へ暗黙移送しません。交換操作が新しい target binding と再確認を行います。

### Application Instance Identity

同じ device 内に複数 service がある場合、device identity と application endpoint を分離します。

## Credential の層

概念上、次を分けます。

1. Device root credential
2. Membership credential / authorization
3. Attachment session key
4. End-to-end application protection context
5. Hop / cell control protection context

1台の leaf に site-wide master secret を配り、他nodeのkeyを導出できる構造は採用しません。

具体的な cryptographic suite は [05-security-and-compliance.md](05-security-and-compliance.md) で扱います。

## 状態機械

### Device Identity

```text
UNPROVISIONED
  -> PROVISIONED
       -> RETIRED
```

`QUARANTINED`はDevice Identity lifecycleの値ではなく、既知identityとmembership/verification状態から導出するaccess conditionです。Factory identityを維持したまま出入りでき、自由なapplication trafficを許しません。

### Membership

```text
NONE
  -> PENDING
       -> ACTIVE
            -> SUSPENDED
            -> REVOKED
```

Membership が `ACTIVE` でない場合、local application の安全動作は継続できますが、通常の network application traffic は許可しません。

### Attachment

```text
DETACHED
  -> DISCOVERING
       -> AUTHENTICATING
            -> ATTACHED
                 -> DEGRADED
                 -> DETACHED
```

### Route Lease

```text
NONE
  -> CANDIDATE
       -> ACTIVE
            -> DRAINING
            -> EXPIRED
            -> FAILED
```

### Traffic Grant

```text
REQUESTED
  -> GRANTED
       -> THROTTLED
       -> EXHAUSTED
       -> RENEWING
       -> EXPIRED
       -> REVOKED
```

## 状態の連動とowner

各状態は独立概念ですが、通常のapplication trafficを許す条件は次の全てです。

```text
Identity = PROVISIONED
&& Membership = ACTIVE
&& Attachment in {ATTACHED, DEGRADED}
&& RouteLease = ACTIVE
&& TrafficGrant in {GRANTED, THROTTLED}
```

M4 identity lifecycle以降のDirect 1-hop profileでも、内部Route Leaseは省略しません。ただしAttachment成功時に同じauthorityが短期leaseを同時発行でき、通常operator UIにはRoute Leaseを独立表示しません。M1aは14章のsynthetic TEST identity/grantのみを使い、このproduction lifecycleを実装済みとして扱いません。

- Device Identityはfactory/provisioning authorityが所有します。
- Site Membershipとmembership epochはSite Authorityが所有します。
- Attachment/session/short locatorはactive Site Controller authorityが発行します。
- Route LeaseとTraffic Grantはactive Site Controllerが発行し、Cell Agent/Endpointが有限leaseとしてcacheします。
- M4 identity lifecycle以降の初期field profileは、1 siteにつき1 active Site Controller writerとN個のCell Agentだけを許可します。Active-active controller writeは将来RFCです。

Membership epochが変わる場合、旧session、short locator、route、grant、未dispatch downlinkをatomicにfenceします。旧epochのframe、receipt、grantを新epochで受理してはいけません。

## Provisioning と通常Joinを分ける

### Provisioning

重く、頻度が低い処理です。工場または保守経路で行います。

- device identity / credential
- hardware / firmware attestation material
- factory capability manifest
- initial trust anchor
- service mode policy

USB、secure local Wi-Fi、BLE等を候補にし、LoRaへ大きな credential bundle を載せません。

### Site Enrollment

- target site / domain を確認する。
- operator authorization を記録する。
- membership policy と application allowlist を発行する。
- 旧site membership、session、pending downlink を fence する。
- commissioning test の完了前に `ACTIVE` と表示しない。

### Normal Attach / Resume

- beacon / parent discovery
- challenge-response または resume proof
- protocol / schema / capability negotiation
- short locator assignment
- route lease
- traffic grant
- attach confirm

親機再起動やrelay変更でfull provisioningをやり直しません。

## Capability negotiation

Nodeの自己申告だけを信用しません。

```text
requested
∩ device manifest
∩ membership policy
∩ runtime implementation
∩ current bearer / power / capacity
= effective capability
```

Unknown critical capabilityは拒否し、optional capabilityは明示的に無効化します。

## Quarantine

既知のfactory identityを持つが、site membershipが未確定のdeviceだけを対象にします。

許可候補:

- identity proof
- firmware / hardware metadata
- limited diagnostics
- enrollment request

禁止:

- relayになること
- actuator commandを受けること
- 正式telemetryへ混入すること
- 他nodeへのmessage
- unrestricted retry / broadcast

未知credentialのframeには情報を返しません。

QuarantineにはTTL、rate limit、resource quotaを持たせます。

## Sleepy node

- Attach lease と sleep schedule を分ける。
- node が眠っている間に5秒 downlink を admission しない。
- expected next receive window を capacity model へ渡す。
- event wake と routine health wake を分ける。
- resume credential と last grant を bounded にcacheする。
- battery nodeのbackup scan頻度をpower profileへ含める。

## Cold start / Join storm

同時復電時に、application traffic用capacityをJoinだけで使い切らないようにします。

- device固有jitter
- bounded contention window
- signed resumeをfull joinより優先
- control-plane専用quota
- per-identity / per-cell rate limit
- overload時のretry-after / next window
- unknown sourceへstateを割り当てない

## Relay変更

Relay変更はSite EnrollmentではなくRoute Lease更新です。

計画撤去:

```text
ACTIVE
  -> DRAINING
       -> stop new children
       -> compute alternate routes
       -> issue new route leases
       -> collect attach evidence
       -> wait for sleepy descendants or list unresolved nodes
       -> removal assessment
```

`SAFE_TO_REMOVE`はRoute Lease stateではなく、最新topology snapshotに対する判定結果です。判定にはsnapshot epoch、未移行node、sleepy descendantの最終確認時刻、有効期限を含めます。代替経路がなければ返しません。強制撤去は、未移行nodeと影響範囲を記録する別操作にします。

Removal profileは次を具体値で必ず定義します。

- 作業完了期限
- drain最大待機時間
- sleepy descendantのlast-seen許容age
- topology snapshot / assessmentのTTL
- never-wake nodeを`unresolved`へ移す時点
- 強制撤去を承認できるrole
- 撤去後reconcileとrollbackの期限

最大待機を超えた場合は無期限の`DRAINING`にせず、未移行node一覧と`NOT_SAFE`または期限付きforced-removal assessmentを返します。

突然故障:

- cached backupへrandomized reattach
- logical transaction identityを維持
- duplicate application effectを抑止
- subtree全体のfull Join stormを避ける

## Multi-parent attachment

- `controller_term + assignment_epoch`がdownlink ownerをfenceする。
- downlink ownerはepoch内で1 parentにfenceする。
- uplinkは複数parentが受信してもよい。
- controllerがlogical event / transactionでdedupする。
- parent切替時にattempt IDは変わるがtransaction IDは変わらない。
- nodeはprimary / backup discovery情報を持てる。
- 1-radio nodeのchannel scan costをpower profileへ含める。

## Offline operation

### Known node reattach

Cloud断中でも、cache済みmembershipと有効なlocal authorityでreattachできます。

### New membership / site move

権限のないoffline controllerが恒久membershipを発行しません。新siteで`ACTIVE`にするには、旧membershipのrevokeまたは期限切れを証明する必要があります。証明できない強制移設は`FORCED_MOVE_WITH_SPLIT_RISK`として人間の明示承認を要求し、新siteは旧membership epochのframeを常に拒否します。

将来、期限付きoffline enrollmentを許す場合は、事前委任されたsigned allocationと監査記録を必須にします。

### Physical removal while offline

- `physical_removed_pending_sync`として記録する。
- old route / grantをlocalで停止する。
- cloud台帳の確定と同一視しない。
- 復旧時のconflictを人間へ提示する。

## Device replacement

1. old deviceをdrain / revokeする。
2. pending transactionsとoutcome unknownを確認する。
3. new deviceを同じlogical installationへ明示bindする。
4. calibration / policyはinstallationから候補提示する。
5. credential、nonce、dedup、event counterをコピーしない。
6. end-to-end commissioning testを通す。

## Decommission / reuse

- membership、session、route、grantを失効する。
- pending application dataを旧siteに帰属させる。
- secret zeroizationの成功・失敗を記録する。
- factory identityと製造証跡は維持する。
- firmware compatibilityとself-test後にstockへ戻す。

## Management APIとQRの境界

NinlilはQR画像、camera、画面UIを所有しません。KGuard等のmanagement applicationがQRからstable public identityを読み、次のidempotent APIを呼びます。

```text
enroll device to site
bind device to logical installation
commission attachment and application test
drain route / installation
remove membership
prepare device for reuse
```

各operationはoperation ID、actor、site、device、expected epochを持ちます。QRへsecretを入れません。API受付だけで「設置完了」「撤去可能」と表示せず、commissioning evidenceまたはremoval assessmentを必要とします。

## Human-facing states

内部状態をそのまま運用者へ見せません。最低限、次を説明できる表示へ変換します。

- 未登録
- 現場承認待ち
- 現場所属済み・未接続
- 接続中
- 接続済み・通信制限あり
- 経路移行中
- 隔離中
- 失効済み
- 撤去可能
- 撤去すると影響あり

単に `offline` と表示して、電池sleep、membership失効、route断、親機故障を混同しません。

表示文言、原因、次操作、owner、timeoutへの規範的な写像は[11-operator-model.md](11-operator-model.md)を使用します。1-hop profileではRoute Leaseを通常UIから隠し、問題時だけ原因として展開します。

## Fable reviewで維持した判断

- Identity / Membership / Attachment / Route Lease / Traffic Grantの5層を維持する。
- UIは5層をそのまま見せず、operator stateへ変換する。
- 1-hopではRoute Leaseを通常UIから隠す。
- Quarantineをidentity life-cycleではなく導出access conditionとして明確化する。
- relay drainには有限timeout、snapshot TTL、未解決一覧、強制撤去承認を必須にする。
