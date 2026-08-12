# OSS review decoder fuzz tranche

日付: 2026-08-12

## 対象

2026-08-11 OSS reviewのOR-04。対象は外部bytesを受ける既存6境界:
NFL1、RRMP NRM1、R7 wire、R7 FRAG、N6 durable record、Domain Store body。

## 境界

- harnessはprivate、default-OFF、`EXCLUDE_FROM_ALL`、非install。
- harnessはtests-only graphに属するため、fuzzer ON / tests OFFのconfigureは
  target 0で黙って成功せずfatal errorになる。
- public ABI / wire / storage形式とproduction decoderは変更しない。
- 新しいfuzz frameworkは作らず、各`LLVMFuzzerTestOneInput`は既存decode APIを
  直接呼ぶ。
- seedは`spec/vectors`の既存KATとN6の独立固定byte KATから決定的に生成する。
- crash修正時だけ最小入力を`tests/fuzz/regressions/<target>/`へ凍結する。

## 実装と証拠

- Clang + ASan/UBSan + libFuzzer用6 targetとaggregate targetを追加。
- compiler IDだけで受理せず、configure時に`-fsanitize=fuzzer`の実compile/linkを
  probeする。libFuzzer runtimeを含まないAppleClang等は遅いlink failureではなく
  修復案つきconfigure errorになる。
- seed generatorは全seedのorigin/size/SHA-256 manifestを出し、missing/extra/
  byte driftを拒否する。self-testは実seedを1 byte変異してREDを確認する。
- Ubuntu 24.04 / Clang 18 containerで6 targetをcompile/linkし、各1,000 runの
  local bounded smokeを完走した。
- `NINLIL_BUILD_DECODER_FUZZERS=ON`かつ`NINLIL_BUILD_TESTS=OFF`のfresh
  configureが修復案つきで失敗することを確認し、同じnegative configureを
  `decoder_fuzz_tests_off_configure_self_test`として通常CTestへ登録した。
- GitHub Actionsでは6 processを並列に各300秒実行し、wall timeを約5分に抑える。
  crash artifactは失敗時に回収する。
- workflow identity gateは`decoder-fuzz` jobのrunner、timeout、strict shell、8 step、
  compiler/options、6-entry corpus対応、各300秒/4096-byte/10秒/2048MiBのlibFuzzer
  argv、全process wait後のaggregate exit、failure-only artifactをsemantic YAMLでexactに
  固定する。5 entry削除＋1秒化の複合変異はREDになる。

## 非claim

local 1,000 runは網羅性や無欠陥を意味しない。remote 5分jobが初回greenになる前は
CI実績をclaimしない。新規crash回帰入力は現時点0件である。
