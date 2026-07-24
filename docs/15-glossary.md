# 15. Glossary

状態: Maintained terminology reference<br>
対象: Ninlil Runtime全体

## 目的

Ninlilでは、似て見える事実を意図的に別の言葉で表します。本章は仕様、実装、UI、supportで同じ意味を使うための語彙表です。規範要件と矛盾する場合は、[Documentation Index](README.md)の優先順位に従います。

## 1件の要求を追う言葉

| 用語 | 意味 | まだ意味しないこと |
| --- | --- | --- |
| Submission | applicationがNinlilへ提出した候補 | Ninlilが処理責任を引き受けたこと |
| Admission | authorityが検査、local durable commit、必要なlocal予約をatomicに完了する処理 | 遠隔nodeへの到達やapplication effect |
| Transaction | admission後にNinlilが終端まで追跡するlogical operation | 1回のpacketや1回の送信attempt |
| Target | admission時に固定された具体的な到達対象 | selector、現在聞こえたradio address、交換後の別device |
| Attempt | transaction/eventを運ぶ1回の配送試行 | 新しいbusiness operation |
| Observation | bearerや経路で観測した事実 | positive application evidence |
| Delivery Disposition | 受信側が配送を適用できなかった理由や再試行要求 | ReceiptやTransaction Outcome |
| Receipt | `RECEIVED`、`DURABLY_RECORDED`、`APPLIED`、`VERIFIED`のpositive evidence | 期限判定や全target完了 |
| Outcome | admitted transactionの最終的またはactiveな評価 | transportだけの成否 |
| Late evidence | deadline判定後に届いた新しいReceipt | 元のterminal Outcomeの書換え |

```text
Submission
   ├─ REJECTED / IDEMPOTENCY_CONFLICT  -> Transactionは作られない
   └─ ADMITTED                         -> Transactionを作る
                                            |
                                      Attempt 0..N
                                            |
                             Observation / Disposition / Receipt
                                            |
                               ACTIVE または TERMINAL Outcome
```

## Identityとconfiguration

| 用語 | 安定範囲 |
| --- | --- |
| Source application instance | idempotency keyを発行するapplication instanceのstable identity |
| Service identity | `namespace + service ID`。descriptor更新を跨いで同じserviceを表す |
| Service descriptor revision | immutableな契約snapshot。deadline、evidence、limit等のrevision |
| Transaction ID | admission時にRuntimeが作る128-bit identity |
| Event ID | originがdurable admission前に作り、再送でも維持する128-bit identity |
| Attempt ID | 配送試行ごとに作る128-bit identity |
| Idempotency key | callerがlogical operationの重複を収束させるために付けるbounded key |
| Content digest | payload bytesのalgorithm付きdigest |
| Canonical submission digest | descriptor revision、source、target、期限、evidence、metadata、payloadを含む正規digest |

Device Identity、Site Membership、Attachment、Route Lease、Traffic Grantは別の層です。QR設置、撤去、再利用を扱う場合も、1つの「接続済み」flagへ潰しません。詳細は[03. Identity and Join](03-identity-and-join.md)を参照してください。

## Runtime role

| Role | 一言でいうと | M1a |
| --- | --- | --- |
| Controller | admissionとtransaction結果を管理するauthority | 実装必須 |
| Endpoint | applicationへ配送し、origin EventFactを保持する端末Runtime | 実装必須 |
| Cell Agent | Controllerの手足としてbearer、schedule、permitを実行するagent | type予約、実装はM3 |
| Simulator harness | 複数Runtime、virtual clock、faultを外から駆動するtest harness | 実装必須。Runtime roleではない |

## Application family

公開familyは6つです。

1. `EventFact`
2. `LatestState`
3. `MeasurementBatch`
4. `DesiredStateCommand`
5. `BoundedTransfer`
6. `ConfigRevision`

`NetworkControl`は内部protocol trafficであり、applicationが登録する7番目のpublic familyではありません。M1aが実装するのは`EventFact`と`DesiredStateCommand`だけです。

## EventFactの保持

- `NINLIL_NO_DEADLINE`: required Receiptまたは監査付きdiscardまで、deadlineによるterminal化をしない。
- `PARKED_RETRY`: 有限のretry cycleを使い切り、payloadを保持したままfresh `availability_epoch + available=1`（成功可能性の実改善）またはoperator resumeを待つactive state。Degradation epochでは再開せず、Runtime resourceの`capacity_epoch`とも別domainです。
- Resume: 同じevent/transaction identityを維持して新しい有限retry cycleを開始する管理操作。
- Discard: reason、actor、時刻、event identity、直前evidenceを先にdurable auditしてから保持を解放する明示操作。

`PARKED_RETRY`は成功でも失敗でもなく、silent dropでもありません。

## 人へ見せる言葉

内部stateやreason codeをそのまま現場利用者へ表示しません。[11. Operator Model](11-operator-model.md)に従い、最低でも次を分けます。

- 受付済み
- 配送・証拠待ち
- 完了
- 一部完了
- 期限超過
- 結果不明
- 容量不足で未受付
- policy不適合で未受付
- originで安全に保存できなかったlocal safety状態

特に`ADMITTED`を「届いた」、radio TXを「反映済み」、`DURABLY_RECORDED`を「cloud同期済み」と表現してはいけません。

## Control transport と radio 境界

詳細正本: [23. USB control transport and physical radio boundary](23-usb-radio-boundary.md)、[ADR-0003](adr/0003-radio-usb-dependency-direction.md)。

| 用語 | 意味 | まだ意味しないこと |
| --- | --- | --- |
| NCG1 | Controller↔Cell の private byte-stream frame（[19章](19-m3-control-byte-stream-framing.md)） | Application Receipt、security session |
| NCL1 | NCG1 payload 内の private logical control envelope（[23章](23-usb-radio-boundary.md)）。`logical_version` は envelope format domain | 完全な assignment/custody protocol、public ABI、negotiated control protocol version と同一 domain |
| Control protocol version | HELLO で交渉する semantic catalog version（NCL1 envelope version とは別） | NCL1 `logical_version`、radio wire version |
| Control HELLO | USB control session の version/session_generation/session_cookie 交渉。**Controller-only initiator** | Site Membership、Attachment、Network security join |
| session_generation | Cell が割当てる control session 単調世代。reconnect で fence | topology assignment epoch 全体（後続） |
| session_cookie | HELLO_OK 時に Cell CSPRNG が選ぶ opaque **nonzero** u64。**NCL1 header** に載せ全 active message で wire 検証。wall clock / durable counter ではない | durable Network membership、HELLO_ACK body 専用フィールド |
| Raw CDC non-custody | USB ring の volatile 配送。write 成功は peer 受理を意味しない | Transport Custody、Application Receipt |
| Logical / virtual TxPermit | TEST/loopback simulated bearer 用 | physical RF 送信許可 |
| Physical Compliance Permit | physical radio TX の唯一の認可エッジ（immutable plan 後に発行; sole TX edge） | legal certification の自動取得 |
| Secure radio wire | NRW1 compact dual-envelope RF frame（[30章](30-r6-secure-radio-wire.md)） | **R6** `wire_profile_id=0x11` docs-only **Accepted 仮**（R7 実装・HIL・complete ではない）。U0 時点は unallocated だった |
| Owner Task Join ACK | FreeRTOS owner task の join/reclaim 証跡（docs/22 lifecycle） | Network Join / Attachment / Control HELLO / physical RF |
| Network Join | **単一 state として使わない**。非主張・混同注意の umbrella / non-claim のみ許可し、必ず Attachment / Membership / Control HELLO 等を併記する。docs/03 に同名用語は無い | U0 で未確定の本線を「Join 完了」と書くこと |

## 旧称

| 旧称 | 現在の意味 |
| --- | --- |
| LinkOS | `linkos/`に凍結したLegacy LinkOS Lab v1だけを指す |
| ADMITTED_NOW | 使用禁止。`ADMITTED_READY`を使用する |
| COUNTER_OFFER | 使用禁止。Submission Result名は`COUNTER_OFFERED` |
| JOIN_ACK（owner lifecycle 文脈） | **Owner Task Join ACK** を指す。Network Join ではない。C 記号は当面 `NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK` のまま（移行名: `..._TASK_JOIN_ACK`、[23章 §11](23-usb-radio-boundary.md)） |
