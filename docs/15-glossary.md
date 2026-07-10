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

## 旧称

| 旧称 | 現在の意味 |
| --- | --- |
| LinkOS | `linkos/`に凍結したLegacy LinkOS Lab v1だけを指す |
| KGuard LinkOS | D-041でNinlil Runtimeへ改称済み |
| ADMITTED_NOW | 使用禁止。`ADMITTED_READY`を使用する |
| COUNTER_OFFER | 使用禁止。Submission Result名は`COUNTER_OFFERED` |
