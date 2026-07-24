# Fable Review Record: 2026-07-10

状態: Reflected<br>
Reviewer: Claude Code / Fable 5 (high effort)<br>
対象: `ninlil/README.md`、`ninlil/docs/00`〜`10`、reference application integration

## Review boundary

Fableには、概念の整合性、考慮漏れ、人間の使いやすさ、OSSとしての思想、Foundationの実装可能性を依頼しました。Cryptography、security correctness、法令・認証値の正しさは、ユーザー指示どおり評価対象から外しました。05章はoperatorが誤解しない表現だけを対象にしました。

Fableはread-onlyでレビューし、sourceや仕様書を編集していません。

## Verdict

判定は「条件付きで実装へ進められる」でした。Architectureのやり直しは不要ですが、M1着手前に6件の仕様未確定を閉じる必要があるという結論です。

## Blocking findings and disposition

| # | Finding | Disposition |
| ---: | --- | --- |
| B1 | EventFactの「失わない」と必須deadline、有限attempt、不変terminalが矛盾 | 採用。M1a EventFactを`NINLIL_NO_DEADLINE`、retry cycle枯渇を`PARKED_RETRY`、再接続で再開、監査付きdiscardとした |
| B2 | Identity/GrantがM4なのにFoundation fixtureがgrant/epochを参照 | 採用。14章でTEST fixture identity、synthetic grant、epoch、virtual permitを規範化する |
| B3 | idempotency scopeがdescriptor revision更新で切れる | 採用。scopeを`source application instance + service identity`へ変更し、revisionはcanonical digestへ含める |
| B4 | delivery contextの非同期lifetimeが未定義 | 採用。12章でcopyableな世代付きtoken、complete/timeout、owner-thread完了、payload copy、resource計上を固定する。古いpointerと永久handle保持を避けるため、最終仕様はopaque context pointerより安全なvalue tokenとした |
| B5 | public type fieldが未定義で実装者判断が残る | 採用。Fable案より強く、12章でM1aのenum値、struct layout、callback、provider ABIを先に固定する |
| B6 | public familyが6なのにdescriptor表が7 | 採用。6 public family + internal NetworkControlへ統一した |

## Scope recommendations

- Optional POSIX loopback bearer exampleを採用する。Radio/complianceの代替ではなく、実process間demoとbearer interface検証に使う。
- Counter-offer生成、offer保存、acceptance raceをM2へ送る。Reserved enum/APIと「勝手に要求を弱めない」原則は残す。
- `ADMITTED_SCHEDULED`はM1aで生成しない予約値とする。
- Cancel、late evidence、named crash boundaries、finite resource profileはFoundationの価値なので残す。

## Concepts kept after review

- ConfigRevisionを独立public familyとして維持する。
- `ADMITTED_READY`を維持し、即時送信を意味しないと明記する。
- Identity / Membership / Attachment / Route Lease / Traffic Grantの5層を維持し、UIではoperator stateへ変換する。
- Single-owner event loopを維持し、async wrapperは上層に置く。
- API status / Submission Result / Delivery Disposition / Outcome / Observationの5層分離を維持する。

## Additional improvements

採用した主な改善は、operator action matrix、Ninlil自身のADR、command lifecycle図、Outcome/deadline reducer、reason code registry、descriptor preset/default、Foundationと後続milestoneのgate分離、Legacy名称の用語固定です。

Fable初回reviewはreference applicationによる価値確認を早めるexperimental laneを提案しました。最終整合監査でenvironment境界を厳密化し、M1a後はsoftware-only `TEST` lane、PC + USB Cell Agent + command/event Endpoints + SX1262のphysical `LAB` laneはM3 ESP-IDF/Cell AgentとM5 LAB Tx Gate/radio subsetの完了後と分離しました。どちらもNinlil conformance、production radio、field SLOの代わりにはしません。

## Final implementation-readiness pass

最終対象は`ninlil/README.md`、00〜16章、ADR、reason registry、Foundation fixtureです。Fable 5 high effortへ、security、cryptography、法令・認証の正当性を除外したread-only最終reviewを依頼しました。

最終判定:

- **PASS**
- implementation blockers: **0件**
- M1a PR 1開始: **YES**

Fableの最終提案と反映結果:

| # | 提案 | 反映 |
| ---: | --- | --- |
| 1 | 16章でgenerated table mirrorとvector inventory/reference検査を区別する | 採用。explicit mirrorとinventoryを別契約として記載した |
| 2 | `PARKED_RETRY`の遷移禁止をtimer/自動遷移へ限定し、明示管理操作を妨げない | 採用。Receiptによる収束と監査付きdiscardの例外も明記した |
| 3 | evidence deadline時点とgrace close時点の責務を分離する | 採用。deadlineまでにdurable ingressしたno-effect proofはdeadline側、late/unknown/possibleはclose側と固定した |
| 4 | synthetic grantのdecision digestをopaque fixture定数と明記する | 採用。preimage/encoderをM1aで定義せず、exact bindingだけを検査する |
| 5 | timeout上限をnamed constant化し、effect-certainty macro prefixを統一する | 採用。C ABIとstate/vector参照を同じ名称へ揃えた |

別系統のCodex整合監査でもP0/P1は0でした。途中で検出したavailabilityの古いtrue再利用と、1 eventにprimary crash hookが二重適用され得る問題は、最終判定前に仕様とfixtureを修正しています。

このPASSはFoundation M1aのportable `TEST`実装開始可を意味します。ESP-IDF、SX1262実RF、physical LAB、security/compliance実装、国内運用適合、production SLOの完了を意味しません。
