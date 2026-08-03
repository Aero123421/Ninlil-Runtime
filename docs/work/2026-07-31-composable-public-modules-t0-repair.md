# Composable public modules T0 contract repair

日付: 2026-07-31

状態: **independent NO-GO P1/P2 repair complete; re-review pending**

判定: ADR-0028は`Proposed`、全moduleは`PRIVATE_CANDIDATE`、全packageは`ABSENT`

## 目的

private/default-OFFの高度機能をそのまま公開せず、Portable Coreから分離したoptional
moduleとして将来公開するためのT0仕様、machine manifest、schema、fail-closed gateを
実装可能な粒度へ閉じた。public header、public target、module実装、HILの完成は本trancheの
主張に含めない。

## 閉じたレビュー所見

| 所見 | 修復 |
| --- | --- |
| module API 4状態とcompletion 7状態が混同される | 4状態ごとのcompletion floor、package availability、acceptance条件をexact mapping化。`PACKAGE_EXPERIMENTAL`をHost/Target/HILへ自動変換しない |
| dependencyが曖昧 | mapped featureとtransitive dependency closureを分離。所有moduleの強制開始状態を`enforced_from_owner_module_state`へ改名し、Identity/Membership/Attachment/sessionはversioned Core/Foundation provider preconditionへbind。package module dependencyは別配列 |
| R7 engineがRF mappingを暗黙に所有する | pure fragmentation moduleと、未Accepted NFL1↔R7↔NRW1 mappingへ依存するradio adapterを別module/featureに固定 |
| Fabric→Route/Relay observerの公開shapeが無い | version、size、field順、callback signature、copy ownership、call-only lifetime、reentry、drain、stale generationを持つC ABI v1を固定 |
| Fabric selection portが名前だけ | request/candidate/result/registration handleのfield順、status、authority echo、Fabric最終決定、deterministic tie-break、stale/cross-instance/partial時の送信0をexact化 |
| Identity/Attachment provider C ABIが型名だけ | 6 callbackのexact signature、全request/result/event、binding/key/subscription opaque handle、status/verdict/operation enum、size/unknown policyをmachine shape化 |
| key flag/usageとsubscribe順序が未定義 | 6 usage bit、required/allowed flag mask、unknown-bit rejection、resolve→validate→subscribe→publish、unsubscribe drain後releaseを固定 |
| restart floorが論理説明だけ | `NIAF` schema 1の単一FULL atomic checkpoint、COMMIT_UNKNOWN authoritative read、torn/corrupt/ambiguous/unknownのfail-closed recoveryを固定 |
| module stateだけでpublic specへ進める | module固有Accepted仕様と、immutable candidateへbindした独立GO（P0/P1/P2=0、artifact SHA一致）を必須化。promotionはexact single administrative childだけ。現時点は全て`NOT_CREATED`/`NOT_RUN` |
| multi-instance/resource authorityが抽象的 | 各moduleにexact 2 Runtime + 2 distinct module instance、positive/negative binding、storage realm/writer fence、physical driver owner exact 1、bounded child、aggregate all-or-none reserveを固定 |
| CMake `COMPONENTS` semanticsが曖昧 | required/optional/unrequested、transitive dependency、platform mismatch、target作成条件、metadata変数をexact化 |
| Wi-Fi commonのPOSIX/ESP stateが1値へ潰れる | `COMPLETION_STATE_BY_PLATFORM`を追加し、platformとそのplatformへmappedされたfeatureのminimumを公開。aggregate値は全platform entryのminimum |
| v1/v2 coexistenceを推測できる | `V2_NOT_ALLOCATED`はco-install claimではないと固定し、将来v2が必要とする別target/header/prefix/store/wire/ADRを列挙 |
| compile macroでpublic layoutが変わるfalse green | C11/C++、undefined/0/1 macro matrix、size/alignment/offset/symbol比較と、conditional fieldを注入してcompile失敗を必ず観測する負例契約を固定 |
| acceptance/evidenceが追跡不能 | strict JSON evidenceをtest ID、platform、tested parent、runner registration、CI job/execution、exit code、SHAへbind。promotion childの非administrative差分、空test/任意file/未登録runnerを拒否。未実装test、evidence、HILは正直に`NOT_RUN` |
| ADR本文・code/commentの文字列でAcceptedに見せられる | H1+空行+3行目のcanonical metadata lineだけをparseし、重複・HTML comment・code fence内のstate文字列を拒否 |

## 変更authority

- `docs/adr/0028-composable-public-runtime-modules.md`
- `docs/34-v2-runtime-fabric-completion.md`
- `public-module-manifest.json`
- `spec/public-module-manifest-v1.schema.json`
- `tools/public_module_manifest_gate.py`
- `compatibility-matrix.json#/module_api_domain`
- `tools/compatibility_matrix_gate.py`

`compatibility-matrix.json`にはmanifestの
`/module_api_completion_mapping`、`/identity_attachment_precondition_contract`、
`/fabric_selection_port_contract`、`/acceptance_evidence_contract`、
`/modules/*/promotion_authority`へのpath/pointerを追加した。schemaとcustom gateの両方を
fail closedにし、unknown key/version/state、mapping/ABI/resource/CMake/coexistence drift、
acceptance coverage欠落をin-memory mutationで拒否する。

## 検証

```text
python3 -m py_compile tools/public_module_manifest_gate.py tools/compatibility_matrix_gate.py
  PASS
python3 -m json.tool public-module-manifest.json
python3 -m json.tool spec/public-module-manifest-v1.schema.json
python3 -m json.tool compatibility-matrix.json
  PASS
python3 tools/public_module_manifest_gate.py check
  PASS
python3 tools/public_module_manifest_gate.py self-test
  PASS
python3 tools/compatibility_matrix_gate.py check
  PASS
python3 tools/compatibility_matrix_gate.py self-test
  PASS
python3 tools/markdown_link_gate.py check
  PASS
python3 tools/markdown_link_gate.py self-test
  PASS
git diff --check -- <scoped files>
  PASS
state invariant (8 modules / 19 acceptance rows)
  PASS: PRIVATE_CANDIDATE / ABSENT / NOT_CREATED / NOT_RUN
UTF-8, LF, final newline check on scoped files
  PASS
```

custom gateのself-testは、少なくとも次のmutationを実際にrejectする。

- 4状態/7状態mapping改変
- observer field reorderまたはschema ABI version改変
- runtime countを2から1へ弱化
- 2×2 module coverage欠落
- ABI negative runnerをoptional化
- Wi-Fi per-platform metadata欠落
- 未割当v2のco-install claim
- mapped completionが`SPEC_ACCEPTED`未満のpublic spec昇格
- Identity/Attachment precondition contractまたは2×2 evidence record欠落
- 旧`minimum_module_api_state` fieldの再導入
- Identity feature dependencyからversioned precondition IDを除去
- raw key export許可、stale-generation負例の除去
- provider callback signature、key usage/flag mask、opaque handle size policyのsilent変更
- subscribe失敗後のavailability公開、unsubscribe drain前のbinding release
- checkpoint atomicity弱化、torn record受容
- Fabric selectionのstale/cross-instance fallback
- module固有Accepted仕様・GO review無しのpublic spec昇格
- PASS claimに空test、任意JSON evidence、未登録またはcommentだけのrunner/CI invocationを使用
- provider/selection/evidence schema constのsilent変更
- ADR stateをHTML comment、code fence、重複lineへsmuggle

## 未実施・非主張

- 最新の独立reviewは`P0=0 / P1=5 / P2=2`のNO-GO。本記録はその修復であり、
  P0/P1/P2=0の独立再レビューまでADR-0028をAcceptedへしない。
- manifestが指す`tests/public_modules/*`とHIL runnerは計画authorityで、現時点は
  `NOT_RUN`。ファイルが無いものをPASSと扱わない。
- public header、public CMake/ESP-IDF component、module bodyの実装は未着手。
- 実AP、USB、physical RF、power-cut、soakは未実施。
- 本trancheではRuntime、CMake実装、Foundation normative docsを編集していない。

## Root P1 closure: Core/Foundation precondition

Root独立監査で、`identity-attachment-session-install` completion featureから各public
moduleが実際に受け取るversioned authorityが未定義というP1を検出した。これを架空のpackage
componentにせず、`ninlil_identity_attachment_precondition_v1` Core/Foundation
preconditionとして修復した。

- dependency enforcement fieldを`enforced_from_owner_module_state`へ改名した。
- Identity featureを必要とする7 moduleは
  `precondition_contract_id=ninlil_identity_attachment_precondition_v1`を明記する。
- pure `radio_frag_v1`だけはidentity/session/I/Oを持たないため明示除外した。
- versioned provider portとbinding snapshotへidentity tuple、membership epoch、
  Attachment/session/security generation、expiry/invalidation、non-exporting key handleを固定した。
- expiry tickはproviderだけが比較し、forward gapはfresh resolveと全旧handle invalidation後だけ
  許容する。non-success key operationはoutputをzeroizeして長さ0にする。
- provider descriptor、binding metadata、opaque handle、callback/contextのownership/lifetime、
  owner-thread、reentry、unregister drainを固定した。
- restart後のhandle再利用を禁止し、Core/Foundation Domain Store single writerが
  non-secret ID/digestとmonotonic floorだけを永続化する。
- cross/stale/expired/revoked/superseded/rollback/restart-old-handleをfail closedにする
  `PM-IDENTITY-PRECONDITION-2X2-01`を追加した。test/evidenceは未実装のため`NOT_RUN`。

本修復後もADR-0028は`Proposed`、全moduleは`PRIVATE_CANDIDATE`、packageは`ABSENT`である。
独立re-reviewでP0/P1/P2=0になる前に昇格しない。

## Independent NO-GO P1/P2 closure

最新reviewのP1=5を次のauthorityへ閉じた。

1. Identity/Attachment providerは6 callbackと全C ABI型をexact machine shape化した。
2. Fabric selectionは別versioned portとしてauthority/stale/cross-instance/fail-closedを固定した。
3. `PUBLIC_API_SPEC_ACCEPTED`にmodule固有Accepted仕様と独立GO artifactを必須化した。
4. PASS evidenceをcommit/test/platform/runner/CI executionへbindし、空・任意fileを拒否した。
5. ADR stateをcanonical metadataからだけparseし、comment/code fence substringを拒否した。

P2=2に含まれたkey usage/flag/prefix/unknown-bit、atomic restart checkpoint、
torn/corrupt/COMMIT_UNKNOWN、subscribe failure release順、unsubscribe drain順をcontractと
mutationへ追加した。全変更はT0仕様/gateであり、実装済み・公開済み・HIL済みというclaim
には使わない。
