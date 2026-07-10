# 11. Operator Model

状態: Normative pre-alpha<br>
対象: Ninlilを組み込むcontroller UI、CLI、reference application

## 目的

内部のAttachment、Receipt、Disposition、Outcomeを、そのまま現場利用者へ見せても次の行動は分かりません。本章は、Ninlilを組み込むproductが必ず提供する「状態、意味、次の操作、担当、待ち時間」の共通contractを定めます。

Ninlil Coreは日本語文言や業務手順を持ちません。Coreは安定したreason codeとevidenceを返し、product adapterが本章の状態へ射影します。

## Projection contract

Reason code registryの正本は[`foundation-m1a-reason-codes.yaml`](../schemas/foundation-m1a-reason-codes.yaml)です。Registryの`operator_state_hint`はsupport/runbook用の原因keyであり、単独で最終Operator Stateを決めません。Product adapterは、まず下表のtransaction/submission stateとOutcomeを使い、次にreason、effect certainty、Event originかどうかで安全な次操作を絞ります。同じreasonを異なるstateで同じ成功/失敗表示へ潰してはなりません。

| Projection context | Default Operator State |
| --- | --- |
| admitted active state | 下表の`OP_ACCEPTED` / `OP_WAITING_WINDOW` / `OP_IN_PROGRESS` / `OP_EVENT_HELD` |
| terminal Outcome | 下表の`OP_COMPLETED` / `OP_CANCELLED` / `OP_FAILED_DEFINITIVE` / `OP_EVENT_DISCARDED` / `OP_EXPIRED` / `OP_RESULT_UNCERTAIN` |
| origin EventFactをlocalでadmitできなかった | reasonにかかわらず`OP_LOCAL_SAFETY`をprimary表示し、reason hintを原因として併記 |
| submission capacity/rate exhaustion | `OP_REJECTED_CAPACITY` |
| その他のsemantic rejection | `OP_REJECTED_POLICY` |
| current endpoint/route observationだけがunavailable | terminal Outcomeへ格上げせず`OP_ENDPOINT_UNAVAILABLE`を補助表示 |
| group target結果が混在 | `OP_PARTIAL` |

PR 1のgenerated registry検査は、全public reasonにnon-empty `operator_state_hint`があり、このprojection contractへのlinkが一致することを機械検査します。Product固有adapterは全到達可能な`state/outcome/reason/effect certainty`組合せをtestし、未写像をgeneric「失敗」へfallbackしません。

PR 1のmachine checkでは、このsectionの`Default Operator State`にあるbacktick付き`OP_*`参照と、`## 共通Operator State`表の`Operator code`定義をsection境界内だけで照合します。各codeは両表にexactly 1回存在し、重複、欠損、registry外参照、曖昧なheading一致を許しません。これは既存projectionのlink整合を閉じる検査であり、product固有の文言、timeout、到達可能tupleを新たに定義しません。

## 表示の原則

- 「受付済み」「送信済み」「端末到達」「application反映」「物理確認」を同じ成功表示にしない。
- `ADMITTED`を「届いた」と表示しない。
- `OUTCOME_UNKNOWN`を「失敗」と断定しない。
- 一部targetだけ成功したgroupを「完了」と表示しない。
- operatorが安全に再実行できるかを、reason codeとservice apply contractから判定する。
- UI、CLI、support bundleは同じstable operator codeを使用する。

## 共通Operator State

| Operator code | 利用者向け意味 | 主な内部根拠 | 安全な次操作 | 禁止する表示・操作 | Default owner / timeout |
| --- | --- | --- | --- | --- | --- |
| `OP_ACCEPTED` | 要求を預かり、処理待ち | `ADMITTED_READY` | 通常は待つ。詳細で期限とtargetを確認 | 「端末へ届いた」と表示しない | Runtime / service deadlineまで |
| `OP_WAITING_WINDOW` | 再試行可能時刻まで待機中 | M1aのinternal retry-not-beforeをpublic `WAITING_WINDOW`へ射影 | `runtime_step`が返すnext wakeまで待つ。期限が近ければoperatorへ通知 | 相手が予約windowを公開した、または経路が必ず復旧すると表示しない | Runtime / next wake + service deadline |
| `OP_IN_PROGRESS` | 配送または証拠待ち | `DISPATCHING`、`AWAITING_EVIDENCE`、cancel `PENDING_REMOTE_FENCE` | 通常は待つ。attemptとlast observation、cancel待ちの場合はremote fence結果を確認可能にする | radio TXやcancel API受付だけで完了にしない | Runtime / evidence graceまで |
| `OP_EVENT_HELD` | 事実は端末に保存済みだが、自動配送cycleをいったん停止中 | EventFactの`PARKED_RETRY` | payload保持、last reason、last attempt、再開条件を確認。接続/容量復旧を待つか、権限あるoperatorがresume/discardを選ぶ | 「消失」「完了」「自動再送中」と表示しない。監査なしにdiscardしない | Runtime + product operator / profileのescalation時間 |
| `OP_COMPLETED` | 要求したevidenceへ到達 | `SATISFIED` | 追加操作不要 | required evidenceより弱い段階で表示しない | Application owner |
| `OP_CANCELLED` | effect前に停止できたことを確認済み | `CANCELLED_BEFORE_EFFECT`、local/remote `FENCED_BEFORE_DISPATCH` | 追加操作不要。必要なら別のnew transactionを作る | effect後の取消成功と表示しない | Request owner |
| `OP_FAILED_DEFINITIVE` | 現在のtransactionは確定的に達成不能 | `FAILED_DEFINITIVE`（監査付きEvent discard以外） | exact reasonとeffect certaintyを確認し、修正が必要ならnew transactionとして提出 | 元transactionをretryでactiveへ戻さない | Product/config owner / 即時 |
| `OP_EVENT_DISCARDED` | required Receiptなしにoperatorが監査付きでEvent保持を終了 | EventFact `FAILED_DEFINITIVE` + `OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT` + discard audit | actor、reason、event ID、last evidence、audit時刻を確認。必要なら別のnew Eventとして扱う | 「正常配送完了」「自動再送中」「証拠あり」と表示しない | Authorized operator + support / 即時監査 |
| `OP_PARTIAL` | 一部targetだけ完了 | target別結果が混在 | 未達target一覧を確認し、product policyで対象を絞って新規要求 | 元transactionを成功へ書き換えない。一括再送を自動実行しない | Product operator / 直ちに表示 |
| `OP_EXPIRED` | 期限内の証拠を確認できなかった | `EXPIRED` | 現在状態をreconcileし、serviceが安全な場合だけ新規transactionを作る | 「何も起きなかった」と断定しない | Product operator / 期限到達時 |
| `OP_RESULT_UNCERTAIN` | effectが起きた可能性はあるが断定できない | `OUTCOME_UNKNOWN`、cancel `TOO_LATE_EFFECT_POSSIBLE` | 現物、endpoint state、late evidenceを照合。絶対状態commandなら確認後に新generationを提出可能 | toggle/increment等の非idempotent操作を盲目的に再実行しない。TOO_LATEをcancel成功と表示しない | Product owner + field operator / 即時escalation |
| `OP_REJECTED_CAPACITY` | 安全に預かる容量がない | submission reject `CAPACITY_EXHAUSTED` | 古い診断のcleanup、負荷低減、storage復旧後にguidanceどおり再提出 | 要求を捨てて成功扱いしない | Runtime operator / 即時 |
| `OP_REJECTED_POLICY` | 宛先、権限、schemaまたは条件が不適合 | reason付き`REJECTED` | reason別runbookへ誘導し、設定・対象・versionを修正 | 同一条件の無限retryをしない | Product/config owner / 即時 |
| `OP_ENDPOINT_UNAVAILABLE` | 対象が現在利用できない | route/attachment/capability observationと未達Outcome | 電源、設置、親、最終seenを確認 | 「故障」と断定しない | Field operator / profile timeout後 |
| `OP_LOCAL_SAFETY` | originで事実を安全に受付できなかった | local EventFact admission reject、storage/grant fault | product固有fail-safeを直ちに実行し、local indicationと監査記録を残す | 検知自体が保存済みと表示しない | Endpoint application + field operator / 即時 |

Productはdefault timeoutをtraffic/environment profileで具体値へ置き換えます。「しばらく待つ」のような無期限表現は禁止します。

## Late evidence

期限後に`APPLIED`等が届いた場合、UIは次を同時に表示します。

1. 期限時点の判定: `OP_EXPIRED`または`OP_RESULT_UNCERTAIN`
2. 最新の事実: 例「期限後に端末反映を確認 14:32:10」

Late evidenceで元transactionのterminal Outcomeを`OP_COMPLETED`へ反転しません。業務上「現在は目的状態になった」と判断する場合は、productのreconciliation結果を別recordとして表示します。

## Group操作

Group transactionには、aggregate表示とtarget別表示の両方が必要です。

- `OP_COMPLETED`: 全targetがrequired evidenceへ到達
- `OP_PARTIAL`: 成功targetと未達/失敗targetが混在
- `OP_EXPIRED`: 成功targetがなく、全targetの期限判定が確定
- `OP_RESULT_UNCERTAIN`: 少なくとも1 targetでeffect可能性を排除できず、全体を安全に再実行できない

「失敗targetだけ再実行」は元transactionのretryではなく、新しいtarget roster、transaction ID、idempotency keyを持つ新規操作です。交換・撤去済みtargetを暗黙に新deviceへ付け替えません。

## Support bundle

利用者がsupportへ渡すbundleには最低限、次を含めます。payloadやsecretは含めません。

- operator code、reason code、retry guidance
- transaction ID、service identity/revision、target別状態
- deadline verdict、latest evidence stage、late evidence有無
- last attachment/route observationの時刻とage
- capacity/degraded summary
- runtime、ABI、storage schema、profile version

## Product profileの責務

各reference applicationは、次を追加仕様として固定します。

- 表示文言と色・icon
- codeごとの具体timeout
- 誰が対応するか
- 安全なretry/reconcile手順
- local fail-safe
- escalation条件
- 現場撤去・交換・再設置時の例外手順

KGuard固有の写像は[10-kguard-integration.md](10-kguard-integration.md)を正本とします。
