# Composable public modules T0 independent re-review repair

日付: 2026-07-31

状態: **independent re-review NO-GO repair implemented; another review pending**

判定は昇格させない。ADR-0028は`Proposed`、全moduleは`PRIVATE_CANDIDATE`、全packageは
`ABSENT`、module固有specは`NOT_CREATED`、review/test/evidence/HILは`NOT_RUN`である。

## 対象

独立再レビューの`P0=0 / P1=5 / P2=4`で指摘された9項目を、公開実装やHIL完了を
主張せずT0 contract/gate/CIとして修復した。本記録はP0/P1/P2が0になったという
自己判定ではなく、次の独立再レビューへ渡す差分記録である。

| Finding | RED | Repair |
| --- | --- | --- |
| public module gateが実行経路に無い | `if(FALSE)`欠落、`echo ctest`、`DISABLED` catalogが旧検査を通り得た | CMakeへ`check/self-test`を実`add_test`。configured CTest JSONでexact-once、non-disabled、Python/script/arg一致を検査し、Ubuntu/macOS CIでfocused + full CTestを実行 |
| evidenceが自己申告 | exit code、CI execution ID、任意logを手書きできた | v1 evidenceをlocal replayable CTest receiptへ限定。tested commit/tree、clean worktree、CMake rebuild、active CTest entryのcommand/working directory、観測exit/stdout/stderrをgateが再実行して照合。offline verifierの無いCI/HILは`NOT_RUN`以外を拒否 |
| review provenance/separation無し | reviewer名とGOを自己申告できた | reviewer node ID+login、GitHub review receipt、OIDC attestation digest、implementer roster/separationのclosed contractを追加。offline verifier未実装のv1ではGOをfail closed |
| Identity output domain不足 | `verified/released/callbacks_drained`へ2以上、`changed_floor_mask`未知bit、operation pointer/size曖昧 | u32 boolean exact 0/1、10 floor bits/mask、authenticator入力、6 operation別nonce/AAD/input/output/verified shape、auth failure statusを固定 |
| Fabric numeric domain不足 | unknown security/path/health、flag bit、unbounded score | security compatibility、path kind、health、flags mask 0、base/adjustment/combined score boundsを固定 |
| checkpoint checksum不足 | record size、digest coverage、CRC variantを変更可能 | exact 308 bytes、SHA-256 offset/coverage、CRC-32C Castagnoli polynomial/init/refin/refout/xorout/coverage/little-endianを固定 |
| bool-as-int | Pythonで`true == 1` | manifest/matrixはbooleanを許すJSON pathを列挙し、それ以外のboolを拒否。evidence/review receiptはboolを全拒否。integer helperも`type(value) is int` |
| path escape | lexical prefixだけでroot外やsymlinkを防げない | spec/review/evidence/test/receipt/build/registration/ADR/schema pathをcanonical repo-relative、resolved root confinement、全component non-symlinkで検査 |
| ADR H1未bind | lookalike H1へ差替え可能 | exact `# ADR-0028: Composable Public Runtime Modules`へbind |

## RED mutationとGREEN

`tools/public_module_manifest_gate.py self-test`へ次を追加した。

- configured CTestからgate欠落、`echo ctest`置換、`DISABLED`
- fabricated CI receipt、replayと異なるexit/stdout、unverifiable HIL PASS
- reviewer separation未検証、自己申告verifiedでもoffline provenance verifier無しのGO
- Fabric security/path/health/flags/score drift
- Identity u32 boolean、changed-floor unknown bit、key-operation shape drift
- checkpoint size、SHA-256 coverage、CRC32C polynomial drift
- manifest/matrix/evidence numeric fieldへのboolean
- repository path traversalおよびsymlink component
- ADR H1差替え
- independent review/evidence schema const drift

各mutationは意図したfailure reasonでrejectされ、baselineはGREENである。

## 変更authority

- `CMakeLists.txt`
- `.github/workflows/ci.yml`
- `public-module-manifest.json`
- `spec/public-module-manifest-v1.schema.json`
- `tools/public_module_manifest_gate.py`
- `compatibility-matrix.json#/module_api_domain`
- `tools/compatibility_matrix_gate.py`
- `docs/adr/0028-composable-public-runtime-modules.md`
- `docs/34-v2-runtime-fabric-completion.md`

README、root completion ledger、public header/module implementationは変更していない。

## Fresh closure review P1 repair（追記）

2026-07-31 の fresh closure review が示した P1=3 を追加修復した。この追記も
自己GOではなく、次の独立reviewに渡す差分である。

- moduleごとの wire profile、storage schema、physical namespace、partition、single writer、
  writer ownerをgate内の独立した exact ledgerへ固定した。manifestから推測しない。
- 17 module acceptance と2 cross-module acceptanceについて、IDだけではなくmodule、全文の
  requirement、test path、HIL classificationをexact pinした。次の5 mutationはすべてREDである:
  Fabricへの`BOGUS-WIRE`、MFDTへの`BOGUS-STORAGE`、Fabric namespace/partition差替え、
  Fabric 2x2 requirement弱体化、`PM-FAB-ABI-01`のtrivial sourceへのretarget。
- replay receiptはactive CTest name/commandだけでなく、CMake File API codemodelから
  declared targetが宣言済みsourceを持ち、CTest executableがそのtarget artifactであることを
  検査する。root内のunrelated always-pass target/source fixtureもREDである。
- receipt contractにplatform/profile matrixを明記した。OS、architecture、toolchain family、
  Debug/Release、sanitizer、toolchain/compiler identity、CMake cache digestをbindし、ESPでは
  ESP-IDF target/versionとfinal ELF/map digestを追加必須にした。Host receiptのESPラベル替えは
  fail closedである。

この時点で全moduleは引き続き`PRIVATE_CANDIDATE`、packageは`ABSENT`、19 acceptance rowは
test/evidence/HILとも`NOT_RUN`である。対象public target/sourceは未作成なので、実receipt、
ESP build、physical HILを主張しない。

## 検証

```text
python3 -m py_compile tools/public_module_manifest_gate.py tools/compatibility_matrix_gate.py
  PASS
python3 -m json.tool public-module-manifest.json
python3 -m json.tool spec/public-module-manifest-v1.schema.json
python3 -m json.tool compatibility-matrix.json
  PASS
python3 tools/public_module_manifest_gate.py check
python3 tools/public_module_manifest_gate.py self-test
  PASS / PASS
python3 tools/compatibility_matrix_gate.py check
python3 tools/compatibility_matrix_gate.py self-test
  PASS / PASS
python3 tools/markdown_link_gate.py check
python3 tools/markdown_link_gate.py self-test
  PASS / PASS
cmake -S . -B build/public-modules-t0 -DNINLIL_BUILD_TESTS=ON
python3 tools/public_module_manifest_gate.py verify-ctest-registration \
  --build-dir build/public-modules-t0
ctest --test-dir build/public-modules-t0 --no-tests=error \
  -R '^public_module_manifest_gate(_self_test)?$'
  PASS: exact 2 tests, 2/2
CI YAML semantic parse
  PASS: ubuntu-dynamic-strict / macos-dynamic each contain exact focused path
state invariant
  PASS: 8 modules / 19 acceptance rows remain unpromoted and NOT_RUN
scoped whitespace / UTF-8 / LF / final newline
  PASS

python3 -m py_compile tools/public_module_manifest_gate.py
python3 -m json.tool public-module-manifest.json
python3 -m json.tool spec/public-module-manifest-v1.schema.json
python3 tools/public_module_manifest_gate.py check
python3 tools/public_module_manifest_gate.py self-test
  PASS
cmake -S . -B build/public-modules-p1-0731 \
  -DNINLIL_BUILD_TESTS=ON -DNINLIL_ENABLE_STRICT_WARNINGS=ON
python3 tools/public_module_manifest_gate.py verify-ctest-registration \
  --build-dir build/public-modules-p1-0731
ctest --test-dir build/public-modules-p1-0731 --output-on-failure \
  -R '^public_module_manifest_gate(_self_test)?$'
  PASS: exact 2 tests, 2/2
```

## 未実施・非主張

- 独立再レビューは未実施。P0/P1/P2=0を主張しない。
- Linux GitHub-hosted runnerとmacOS GitHub-hosted runnerの新workflow runは未取得。
  workflow上の実経路とlocal macOS configured CTestは検査済みである。
- v1にはGitHub OIDC review/evidence bundleのoffline verifierが無い。そのため署名付き
  CI/HIL/review GOへ昇格させず、該当stateは`NOT_RUN`のままにする。
- `tests/public_modules/*`、public package、実機HILは未実装・未実行である。
