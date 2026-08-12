# OSS review: specification / public-header tranche

日付: 2026-08-12

## 対象

Project ReviewのOR-10、OR-14、OR-31、OR-32だけを対象に、既存の正本とgateを
拡張した。公開ABI、宣言、定数、completion state、CMake optionは追加・変更していない。

## 変更

- [compatibility matrix](../../compatibility-matrix.json)へ、公開POSIX TLS、公開POSIX USB
  serial、V1 Compositionの3 featureを追加した。いずれもAccepted ADRに対応する
  `SPEC_ACCEPTED`のまま、`state_ceiling=SPEC_ACCEPTED`、物理HIL未確認として固定した。
  POSIX TLSはFabric、CompositionはRuntime / Fabric / Relay / Multi-parent / MFDTへの
  依存を明示し、USB byte-stream portはADRどおりRuntime/Fabric非依存とした。
- matrix gateを英語形式の`- Status: Accepted`と`Final verdict` / `Result` / `Decision`
  review authorityへ対応させた。唯一のlive status、exact GO、P0/P1/P2、README row、
  feature集合・順序・依存をfail-closedで照合する。英語statusのunderclaim、重複、NO-GO、
  feature欠落、Composition依存改変をself-testへ加えた。
- 元レビュー対象の`runtime.h`、`platform.h`、`service.h`、`transaction.h`と、公開packageの
  `fabric_v1.h`、`composition_v1.h`、`posix_tls_v1.h`へ、既存のNormative契約を指す
  ownership / lifetime / owner-context / re-entry / status taxonomyの短い要約を追加した。
  OR-14 follow-upではRuntimeの14 public functionすべてについて、各宣言の直前へborrow/copy/
  consume、owner-context、callback allowance、reachable status集合、API statusとsemantic outputの
  境界を固定した。特にdestroyはDESTROYING前の失敗だけ非consume、DESTROYING後はcleanup statusに
  関係なくRuntime/Service/token handleをconsumeすると明記した。宣言、定数、型layoutは変更して
  いない。
- Platform callbackは宣言位置でStorage handle/transaction/iterator lifecycle、`put`のdeep-copy、
  `commit`/`rollback`のstatus非依存consume、Bearer receive成功bufferのexactly-once releaseを明記した。
  Service callbackはcallback view/token pointerの非保持と、COMPLETE/KNOWN_RESULT evidenceがreturn後の
  Runtime同期deep-copyまで生存する境界を固定した。Transaction型はcaller-owned query/list bufferと
  API status / semantic resultの違いを宣言位置へ記載した。
- `public_header_contract_gate.py`を追加し、14 public function inventory、各reachable status集合、上記の
  ownership/consume/callback/deep-copy要点を宣言直前commentへbindした。全契約comment削除、代表status
  行削除、destroyのpost-validation consume削除をin-memory mutationし、3/3 REDを要求する。CTestの
  check/self-testへ登録した。
- Status再照合では、通常のsubmit Storage mutationで到達する`NINLIL_E_UNSUPPORTED`を公開集合へ含めた。
  一方、delivery completion中の`UNSUPPORTED_SCHEMA`は7.2 exact tableどおり
  `NINLIL_E_STORAGE_CORRUPT`へcontextual mappingし、active token/evidence/health境界を負例で固定した。
- [V2 completion contract](../34-v2-runtime-fabric-completion.md)へ、Proposed中に許せる
  prototypeをdefault-OFF、非install / 非export、private、通常build・実機・releaseから
  非到達に限定した。この例外は新状態を作らず、採番、S/C gate、Host/Target、HIL、supportの
  evidenceにならない。
- [docs index](../README.md)に、レビュー対象SHAで47件、現行treeで49件ある`docs/`直下の
  全Markdownをsource language付きで明示する中央policyを追加した。Markdown link gateが
  実ファイル集合との完全一致と番号付き仕様の読む順番を照合する。欠けていた35章も索引へ
  追加した。英語原文の[build options](../build-options.md)にあった誤った「日本語原文」表示も
  修正した。

## 独立再監査

- 3公開featureをAccepted ADR、独立review、README行へ再照合した。TLSはFabricへ依存し、
  USB serialはRuntime/Fabric非依存、CompositionはRuntime / Fabric / Relay / Multi-parent /
  MFDTへ依存する。3件ともRequired HILで`hil_verified=false`、ceilingは`SPEC_ACCEPTED`のまま。
  各featureについて欠落、依存改変、false HIL昇格をin-memory mutationし、すべてREDを確認した。
- 7公開headerはC commentを除去したtoken列が`HEAD`と一致した。各headerの最初の公開identifierを
  変える宣言mutationは差分を検出し、C11/C++17 self-contained smokeとABI golden/layoutを
  再実行した。ただし、この証拠だけでは契約commentを全削除してもfalse-greenになるため、OR-14の
  closure証拠としては不十分だった。上記content gateを追加し、4中核headerの契約そのものを検査した。
- Proposed prototype境界をcompletion matrix gateのsource authorityへ接続した。docs/34の
  `default-OFF`、`非install / 非export`、通常build/public header/実機/release非到達、状態・
  evidence非昇格の各条件を検査し、default-ON、install/export、support evidence化の3変異を
  source fileへ書かずに拒否した。現行default buildの5 private optionも全てOFFである。
- 初回translation gateは番号付き37件だけを見ており、レビューの47件を閉じたという記録が
  false-greenだった。レビューSHA `9cc907f`の`docs/`直下がexactly 47件であること、現行は
  `status.md`と`build-options.md`を加え49件であることを再計数し、49件の明示台帳へ修正した。
  temp treeへ未登録の新規sourceを追加するmutationがREDになることを確認した。

## 検証

- `python3 tools/compatibility_matrix_gate.py check` / `self-test` — PASS
- `python3 tools/markdown_link_gate.py check --root .` / `self-test` — PASS
- C11/C++17 self-contained header smoke（元レビュー対象4 header × 2）— 8/8 PASS
- `abi_manifest_golden` / `abi_public_layout_manifest_gate` — 2/2 PASS
- `public_header_contract_gate` / `public_header_contract_gate_self_test` — 2/2 PASS、
  全comment・代表status・destroy consumeの3 mutationは3/3 RED
- fresh CMake treeでC/C++ smoke 2件、中核4 header self-contained 8件、ABI golden/negative/layout/
  layout self-test 4件、public-header contract 2件、cancel targeted-managementを含むRuntime spineと
  delivery-specific Storage mapping 2件 — 18/18 PASS
- 7 headerをコメント除去して`HEAD`と比較 — 宣言・定数差分0、各宣言mutation RED
- `mfdt_v1_install_boundary_gate`、`esp_idf_r7_frag_packaging_gate`、
  `mfdt_v1_host_profile_boundary_gate`（source-only）— PASS
- default-OFF private symbol archive（Fabric、RRMP proxy/archive）— 3/3 PASS
- `python3 -m py_compile`、JSON parse、focused work-record link check、`git diff --check` — PASS

後続統合で`NINLIL_BUILD_DECODER_FUZZERS`をdefault-OFF/non-installed optionとして
`docs/build-options.md`へ追加し、`build_options_docs_gate check`は23 entriesでPASSした。

## 非主張

- TLS実AP、物理USB CDC、ESP/RF統合、power-cut、soak、法規、release supportは未確認で、
  matrixでは`hil_verified=false`のままである。
- Proposed prototypeはAccepted仕様や公開featureではない。default-ON / install / public APIへの
  昇格には通常のS1〜S6と独立reviewが必要である。
- Public-header gateはreview済み契約文とstatus集合の削除・driftを検出するsource gateであり、動的な
  全path coverageや将来実装からのstatus集合自動導出を主張しない。実装経路を変える場合はNormative、
  header契約、gate authorityを同時に再reviewする。
- `runtime_step`の`NINLIL_E_UNSUPPORTED`はopt-in private-candidate attachment由来のconditional status
  として明示しただけで、public Foundation feature、Accepted仕様、completionへの昇格を主張しない。
- repository root README、status ledger、public CMake option、ADR status、SPDX/legal、GitHub設定は
  このtrancheで変更していない。
- `.DS_Store`と`dist/`は変更せず、commit / pushも行っていない。
