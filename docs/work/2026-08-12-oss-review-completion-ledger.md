# 2026-08-11 OSS review completion ledger

日付: 2026-08-12

## 目的

commit `9cc907fe3a384aba9bf0e984b62fa55fa1207f3f` を対象にした
「Ninlil Runtime 徹底レビュー」の全指摘を、修正済み・作業中・未着手・外部確認待ちに
分けて追跡する。件数や文書更新だけで完了扱いにせず、各行は対応する実装、focused
test、独立reviewが現行byte列で揃った時だけrepository-localの`CLOSED`へ進める。
remote CIやrepository管理設定が必要な証拠は各行と非claimで別に追跡し、stacked PR全体は
同一commitのremote CIがgreenになるまで完成・release-readyとは扱わない。

受領原文は[immutable copyと全414行provenance map](../reviews/2026-08-11-ninlil-runtime-exhaustive-review-index.md)
でSHA固定する。原文にOR番号や全件subtotalはなく、ORは修正境界へ正規化したIDなので、
原文1 findingとOR 1行のbijectionは主張しない。provenance mapが原文の全spanと
OR-01〜37のmany-to-many対応の正本であり、各行からのlocal証拠は
[evidence graph](../reviews/2026-08-11-ninlil-runtime-exhaustive-review-evidence.md)で辿る。

状態:

- `CLOSED`: repository-localの修正、再現可能な検証、独立reviewが完了した。
- `IN_PROGRESS`: 専用trancheで実装または検証中。
- `OPEN`: 現行treeで未解決を再確認した。
- `EXTERNAL`: 法的事実またはrepository管理権限の確認が必要。
- `NO_ACTION`: reviewで安全・妥当と確認され、変更対象ではない。

## 全項目

| ID | 指摘 | 状態 | closure / 次の証拠 |
| --- | --- | --- | --- |
| OR-01 | Traceabilityの名称がassertion強度を過大主張 | CLOSED | PR #116でRegistration Coverageへ改称し、非claimを固定。独立review GO、remote CI 26/26 |
| OR-02 | 引用CTestの実行成功とassertion強度を検証しない | CLOSED | 現行byte列でbaseline cited 47/47、all-private cited 45件＋required fixture 1件=46/46のfresh local JUnitと`junit_pass_links=1312`を確認し、21 subclaim / 29 anchorをactive assertion-bearing領域へ固定。materializerも同一authorityへ同期し、generate/check byte一致、旧function anchor・stale manifest・coherent assertion削除/comment/`#if 0`/常時真化mutationはlocal RED。独立review GO。条件十分性/semantic sufficiency/line・branch coverageは非claim |
| OR-03 | README quickstartがsanitizer全suiteを入口にして失敗・長時間化 | CLOSED | focused smokeへ分離し、full normal buildとClang sanitizerを別手順化。remote CI 26/26 |
| OR-04 | 主要6 decoderのfuzz harnessが0 | CLOSED | private opt-in Clang/libFuzzer 6 target、deterministic seed authority、実compile/link probe、tests-OFF false-green拒否を追加。Ubuntu 24.04/Clang 18で6×1,000 run、semantic reachability 33/33、独立review GO。remote定期fuzzはrelease非claim |
| OR-05 | ABI golden不在がPASS、ILP32 authorityなし | CLOSED | missing fail-closed、LP64/ILP32 goldenとcross authority/self-test、public layout mutationをlocal PASS。official amd64 ESP CIの初回実績はrelease非claim |
| OR-06 | `byte_stream.h` / `posix_usb_serial_v1.h`がABI manifest対象外 | CLOSED | 48 constants/5 layouts/34 fieldsを追加しpublic-layout deletion mutation RED、ABI focused 9/9 PASS |
| OR-07 | MFDT/R7 ESP DRAM gateが実mapを検査しない | CLOSED | official ESP-IDF v5.5.3 amd64 launcherのfresh feature-ON build/mapで、R7 FRAG 9,416/49,152 bytes、MFDT 0/49,152 bytesを実測して両gateをPASS。split-line/zero-row/oversize mutationと独立reviewもPASS。物理HILは非claim |
| OR-08 | Node.jsが未宣言・未固定・SBOM不在 | CLOSED | Node >=18、CI 22.18.0 pin、inventory/notice、SPDX `APPLICATION` + `BUILD_TOOL_OF` |
| OR-09 | copyright holder/SPDX/DCO経路が不在 | EXTERNAL | review基準799本から追加13本・削除1本のnet +12となるfirst-party C/H 811/811 SPDX、実集合gate、source-license inventory、DCO 1.1 gate/workflowはlocal CLOSED。正式holder/yearとNOTICE、remote DCO required化だけはowner/legal/admin証拠待ち。Apache LICENSE本文は変更しない |
| OR-10 | 公開3 packageがcompatibility matrixに不在 | CLOSED | POSIX TLS / POSIX USB / Compositionをexact dependency、`SPEC_ACCEPTED` ceiling、Required HIL未確認で追加。各featureの欠落・依存改変・false HIL mutation RED |
| OR-11 | MQTT-SN/LoRaWAN/CoAP/Zenohとの差別化説明がない | CLOSED | PR #116のREADME比較表でtransport ACKとdurable/application evidenceの違いを説明 |
| OR-12 | README statusが39行のjargon壁・巨大table | CLOSED | 詳細ledgerを`docs/status.md`へ移し、READMEは利用可能面・未証明面・focused入口へ短縮。link/self-test PASS |
| OR-13 | C SDKなのに主経路のC例がない | CLOSED | service→submit→admission kind→step→Receipt→restart/queryのpublic C11例を追加 |
| OR-14 | 公開中核headerにownership/lifetime/thread/status説明がない | CLOSED | Runtime 14 public functionの各宣言直前へownership/consume、owner/callback allowance、reachable status集合、semantic output境界を追加。Platform Storage txn/iter・Bearer received lifecycle、Service callback evidence deep-copy、Transaction caller bufferも宣言位置へ固定。content gate baselineとCTestはPASSし、全comment削除・代表status削除・destroy consume削除は3/3 RED。C11/C++17 8/8、cancel targeted-managementとdelivery-specific Storage mappingを含むfresh focused CTest 18/18、ABI golden/layout PASS、C token差分0。独立再review GO |
| OR-15 | 英語overviewがない | CLOSED | 非規範的`README.en.md`と日本語正本/translation statusを追加し、README/link gateで同期 |
| OR-16 | build option一覧がない | CLOSED | CMake user-facing authorityとexact一致する`docs/build-options.md`を追加。現在23 entry、欠落/余剰をgateで拒否 |
| OR-17 | generic exampleがREADMEから見つからない | CLOSED | 既存`multi_service_node`をLAB例より先に日英READMEから案内。新example層は追加せず既存E2E CTestへ接続 |
| OR-18 | README手順が作る一時dirをignoreしない | CLOSED | `tmp-controller*`、`tmp-install*`、`tmp-all-private*`、`tmp-generic*`を追加 |
| OR-19 | architecture layeringの機械gateがない | CLOSED | Public/Contract/Model/Runtime/Transport/Radioの全first-party includeを宣言方向＋exact private seamへfail-closed化。platform/macro/非標準include、C translation-phase迂回、cross-layer mutationはlocal RED、独立再review GO |
| OR-20 | installable Runtime source setへLAB/session ledgerが混入 | CLOSED | 専用Host source authorityをexact single list化し、38 implementation objectのarchive multisetを完全照合。normal/Domain-ON/sanitizer consumer、`control_session`/`logical_session` authority混入とdirect `target_sources` injection負例、独立reviewをPASS |
| OR-21 | MFDT/R7/RRMPのprocess-global mutable state | CLOSED | RRMP durable scratchとlegacy bind pointer、MFDT production全体、R7 issue coordinator/checked-issue stateをcaller ownerへ移行。MFDT normal/sanitizer各31/31とoversize slot/fini各2/2、R7 ownerをremote routeへexact必須化したnormal 18/18・sanitizer 12/12、RRMP all-profile/sanitizer/ESP evidenceをPASS。R7 required/build/selector 6削除mutationとmutable-static/source/archive負例を含む独立review GO |
| OR-22 | `ninlil_runtime_step`の`in_step`を7箇所で手動clear | CLOSED | 単一epilogueへ集約。CMake選択compilerと実target定義を含む4 profileでentry/exitのclosed control-flowとfunction body内`in_step` member access exact pairをpreprocess検査し、17 all-profile mutation＋1 conditional profile matrixを固定。error後の即時step回復も既存delivery testで確認しfocused 3/3 PASS、独立review GO |
| OR-23 | top-level CMakeの83%がtest登録 | CLOSED | tracked `b9e656f`（top-level 7,695行、tests block 6,435行、`add_test` 372件）からtests-only payloadだけを機械分離したisolated replayでdefault 432/all-private 516（disabled 16）のnormalized CTest rosterをsemantic exact確認。実split commitは他修正を同梱するためcommit全体のexact同値は非claim。現行rosterはdefault 452/all-private 541（disabled 21）、tests-OFF 0。Domain public Runtime非ready時のComposition 3件とMFDT Runtime-owner 2件はcompile/link-onlyへ是正 |
| OR-24 | domain-store最大vector oracleに独立KATなし | CLOSED | encoded envelope固定値KAT 10件（3264-byte最大2件）に加え、異なる実body encoder/subtype 10件をfield入力→complete body literalで固定。encoder bit mutation、catalog body/length co-mutation、最大3264→3263 length mutationはRED。OpenSSL SHA/table CRC別実装照合、focused test、独立reviewをPASS |
| OR-25 | 実行line/branch coverage地図がない | CLOSED | header smokeではなく既存Runtime deliveryをinstrumentする非閾値LCOV/text/profdata workflowへ修正し、local artifact生成とworkflow構造・退行negativeをPASS。coverage率の閾値、remote artifact保持、完成度は非claim |
| OR-26 | C/C++ CodeQLがない | CLOSED | official CodeQL v4 commit pin、tests-OFF installable Host＋6-feature all-private Host production build、scope退行negativeを追加。PR #117 head `3892766`でremote analysis/upload SUCCESS、独立review GO。ESP固有sourceは非claim |
| OR-27 | protocol magic self-testがsource treeへ書き並列競合 | CLOSED | unique temp repo内だけでmutation。8 process並列、source残留0、lock削除 |
| OR-28 | ESP radio receive chainのstack frame gate欠落 | CLOSED | streaming SHA/CRCとowner scratchへ変更。Host max848B、ESP32-S3 fresh max720B。official launcherのactive exact commandと3 source artifactを固定し、削除/decoy/source-root drift、malformed/dynamic/duplicate `.su`負例、normal/san/gateをPASS |
| OR-29 | long cwd、r7 compiler決め打ち、180秒/SQLite wall-clock上限 | CLOSED | long cwdを短い`/tmp`資源pathへ分離。KATはCMake compiler明示・profile別bridge、D3対象testは600秒、MFDT 10,000-step lifecycleは300秒、SQLiteは70ms下限＋CTest 60秒。semantic boundは不変でnormal/san/負例PASS |
| OR-30 | historical 3文書が現行正本に見える | CLOSED | 3本文へHISTORICAL banner・固定tag・現行Host SDK/READMEリンクを追加。古い値は履歴として保持 |
| OR-31 | Proposed中のprivate prototypeが規則違反に見える | CLOSED | docs/34にdefault-OFF/non-install/non-export/non-authority境界を追加。default-ON・install/export・evidence昇格のsource mutation RED |
| OR-32 | 47 normative docsのsource/translation statusが未記載 | CLOSED | review SHAのdocs直下47件、現行51件をsource language付き中央closed registryで完全列挙。Charterはこのexact-one中央記録を各文書の明記とする解釈へ固定し、未登録source追加・不正language・番号付き索引漏れをgateで拒否 |
| OR-33 | repository description/topics/badge/Discussionsが空 | EXTERNAL | canonical main CI badgeはlocal CLOSED。description、topics、Discussionsはrepository admin設定の適用とAPI再確認待ち |
| OR-34 | 公開archiveとLAB/simulator/private candidateの境界が曖昧 | CLOSED | 明示source authorityとLAB/simulator/既知private familyのconfigure/member/symbol fenceを追加、独立mutation review PASS |
| OR-35 | positive design / verification / security findings（境界、vector freshness、nonce/replay/AEAD/TLS/file checks等） | NO_ACTION | 原文の肯定的観察をprovenance mapへ明示し、修正件数や完成率へ数えない。現行安全境界を回帰gateで維持し、別の弱化差分を入れない |
| OR-36 | Charterが要求するREADME/concept/tutorial/how-to/reference/explanationの分離がない | CLOSED | docs indexへ6種類・6 distinct targetのclosed taxonomyを追加し、current concept/tutorialを新設。分類欠落・誤routing mutationをMarkdown gateでRED、focused tutorial smokeと独立reviewをPASS |
| OR-37 | public alphaまでのNormative英語正本が未整備 | NO_ACTION | review対象SHAと現行Charterはいずれも`Experimental / pre-alpha`で、READMEもpre-releaseと明記するため、原文の「prerelease公開済み=public alpha」前提は不成立。英語Normative完成は主張せず、public-alpha昇格前の将来exit gateとしてCharter要件を維持 |

## 完了作業中に追加発見した項目

| ID | 指摘 | 状態 | closure / 次の証拠 |
| --- | --- | --- | --- |
| XR-01 | Targeted managementが過去timerを追い越し、時計回帰・effect可能性・fixed backoffを正しく扱わない | OPEN | current-epoch chronology、same-time priority、successive same-epoch Runtime current-baseline（`A -> B -> A`のepoch ID再利用はClock Port契約で禁止）、ordered input、effect deadline/evidence close、2nd no-send後のeffect-possible保持、fixed backoff、delivery-complete token recovery、invalid/overflow Receipt timerのfail-closed、terminal cached Receiptのretry wake/restartはnormal/sanitizer 13/13と独立reviewで閉鎖。old-epoch active correctness timerを持つownerへのnew-epoch cancel/resume/discardは`E_CLOCK_UNCERTAIN`・health・全mutation 0でunsafe overtakingを停止。一般old-epoch timerのkind-21 durable Recovery Fence convergenceとrestart healingは未実装で、[専用記録](2026-08-12-oss-review-targeted-management-linearization.md)の非claimどおりOPEN |

## 進め方

1. ABI/ESP資源gateとOSS入口文書を、互いに独立なtrancheとして先行する。
2. security/runtime境界（OR-19〜22、28〜29）を、再現→最小修正→source mutationで閉じる。
3. fuzz/coverage/CodeQL/JUnit/domain KATを追加し、計測結果をartifactとして残す。
4. matrix/ADR/header/translation/legal/public archiveを閉じる。
5. 各trancheを独立reviewし、stacked PRのCIがgreenになった後もagent自身ではmergeしない。

## 非claim

この台帳の作成だけでは、未解決行の完成、物理HIL、RF soak、法規適合、stable releaseを
主張しない。copyright holder/yearはrepository owner名から推測しない。
