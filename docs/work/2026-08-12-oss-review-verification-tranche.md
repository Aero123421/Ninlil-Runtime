# 2026-08-12 OSS review verification tranche (OR-02/24/25/26)

## 変更

- traceability registration gateは任意のCTest JUnit XMLを入力に取り、manifestから
  引用されたCTestがPASSしたことを確認できるようにした。これはregistration coverageの
  補助実行証跡であり、assertion強度・全assertion実行・coverage率の証明ではない。
  source anchor削除とJUnit PASS欠落のnegative self-testを追加した。CIではbaselineの
  full CTest JUnitに加え、all-private manifestから抽出したexact cited setを実行し、
  profile別JUnitを必須にした。抽出漏れはgate側のmissing PASS evidenceでfail closedする。
  追加reviewで、関数名・scenario定数・説明commentだけのanchorでは実assertionを
  no-op化してもfalse-greenになる残件を確認したため、14 invariant / 21 subclaimの
  29 anchorをactiveで完全なassertion-bearing source領域へ付け替えた。gateはcomment内、
  不完全な呼出し、`REQUIRE(1)`等の明白な常時真条件を拒否し、sourceとmanifestを同時に
  書き換えるassertion削除・comment-out・`#if 0`化・常時真化の代表mutationもREDにする。これは
  lexical floorであり、条件の十分性、全assertion実行、line/branch coverageは非claimの
  ままである。
  独立reviewで、`traceability_coverage_v2_materialize.py`が旧function/`TRACE-*`
  anchorを再生成し、checked manifestと不一致かつ新gateでREDになるP1を確認した。
  materializerの決定的anchor authorityを同じ29 assertion-bearing領域へ同期し、
  `--write` / `--check` / `--self-test`を追加した。`--write`は新gateを通過した値だけを
  出力し、`--check`はcanonical bytesの完全一致を要求する。旧function anchor mutationは
  gate validationとfreshness比較の両方でREDとなり、既存V2 self-testからmaterializer
  check/self-testも必須実行する。
- `domain_store_vector_gen.py`へ、docs/17 §4/§7に対応するencoded envelope固定値KATを
  10件追加した。BLOB/REVERSE_REPLYの最大body 3264 bytesを含み、24-byte framing
  header、record type/version、payload length、domain format、subtype、flags、revision、
  primary ID、head/PVD、body length/body、complete value SHA-256、wire CRC32Cを生成関数の
  外に固定する。subtype / flags / body / CRCとcatalog-facing metadata / SHA / CRCを
  一緒に変える4種のcoherent mutationをREDにする。加えて、01/60/62/64/7D/10/22/23/
  26/34の異なる10 subtype body encoderへfield入力を与えた結果を、encoderを使わず記述した
  complete body literal 10件へ直接照合する。各encoder出力のbit mutationと、内部prefix検査後に
  catalog-facing body/lengthを同時変更する10件のmutationをREDにする。最大body mutationは
  bodyを3264から3263 bytesへ実際に短縮し、`body_length`も3263へ変更してREDを確認する。
- `clang_coverage_artifact.py`とClang coverage workflowを追加した。公開headerだけのsmokeを
  coverage対象にするとRuntime sourceが一行もlinkされないため、既存の
  `v1_runtime_delivery` executableをinstrumentして実行する。LCOV、llvm-cov text、profdataを
  artifactに残すだけで、閾値・100%・release判定は行わない。workflow identity gateは
  header-only smokeへの退行をnegative self-testで拒否する。
- C/C++ CodeQL workflowを追加した。公式`github/codeql-action` v4 commit
  `5595ccaf912efad79be6eef63a5619ff05969be3`（upstream tag `v4.37.6`）を
  init/analyzeへ固定した。tests-OFFのinstallable Host buildに加え、6 private
  featureを同時に有効化した`host_completion_all_private_build`も同じmanual
  databaseへ必須入力とし、private production sourceが解析外になる退行をworkflow
  identity gateの負例で拒否する。ESP固有adapter/toolchainはこのCodeQL証拠の対象外である。
- CodeQL workflowのsemantic envelopeも閉じた。triggerは`push(main)`、
  `pull_request`、週次scheduleだけ、permissionsは`contents: read`と
  `security-events: write`だけ、checkoutはevent refかつcredential非保持、jobと6 stepも
  exactである。`pull_request_target`へ変え、`write-all`とPR head checkoutを同時に
  注入する負例はREDになる。
- Coverage workflowも同じく、`push(main)` / `pull_request`、read-only
  permissions、event-ref checkout、単一job、5 step、instrumented command列、artifact
  upload設定をsemantic YAMLでexact化した。`pull_request_target + write-all + PR head`
  の複合変異はREDになる。
- reusable CI / ESP-IDF workflowは、root field、`push(main)` / `pull_request` /
  `workflow_call`入力、read-only permission、concurrencyをsemantic YAMLで閉じた。
  Release workflowはtag pushとmanual dry-runだけを許可し、root permission、全job set、
  needs / runner / timeout / permission / privileged condition、3 checkout refを個別照合した
  上で、parsed semantic tree全体のSHA-256を固定する。comment decoyを残した
  `pull_request_target + write-all + PR-head checkout`複合変異はCI / ESP / Releaseの
  すべてでREDになる。full 448 CTestのserial実測が約41分であるため、release verify
  jobの外側timeoutは45分から90分へ広げた。個別CTest timeoutは変更しない。

## ローカル検証

| 検証 | 結果 |
| --- | --- |
| traceability self-test（anchor/JUnit・coherent assertion削除/comment/`#if 0`/常時真化負例を含む） | PASS |
| traceability materializer generate/check | PASS（再生成前後SHA-256一致） |
| traceability materializer self-test（旧function anchor / stale manifest負例） | PASS |
| baseline cited JUnit（manifest 47 CTest） | 47/47 PASS |
| all-private cited JUnit（manifest 45 CTest + required fixture setup 1） | 46/46 PASS |
| profile別JUnit入力つきtraceability gate | PASS（`junit_pass_links=1312`） |
| domain-store generator check + encoded-envelope 10 KAT + typed-body encoder 10 KAT self-test | PASS |
| domain-store固定値の別実装照合（OpenSSL SHA-256 + table CRC32C、10件） | PASS |
| focused CTest（domain oracle + traceability） | 3/3 PASS |
| release / reusable CI / ESP workflow identity check/self-test | PASS |
| CodeQL / coverage workflow semantic identity + YAML parse | PASS |
| local AppleClang delivery coverage artifact（profraw/LCOV/text/profdata） | PASS（Runtime private 80 build edge、LCOV 94,959行、text 82,172行） |
| `git diff --check` | PASS |

## NOT_RUN

remote CodeQLとGitHub artifact workflowはlocalから実行しない。local Xcode toolchainで
coverage artifactの生成経路は確認したが、Ubuntu/Clang remote artifactはNOT_RUNである。
ローカルの単一delivery executableもcoverage率やrelease readinessとして主張しない。
