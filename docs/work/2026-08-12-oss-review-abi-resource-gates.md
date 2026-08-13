# 2026-08-12 OSS review ABI / ESP resource gates

## 対象

OSS reviewで見つかったABI goldenのmissing skip、ILP32 layout authority、
`byte_stream.h` / `posix_usb_serial_v1.h`のmanifest未登録、およびfeature-ON
ESP mapに未接続だったMFDT/R7 FRAG DRAM budget gateを対象にした。
公開API、定数値、wire、storage仕様は変更していない。

## 変更

- goldenが無いtargetは既定でFATAL_ERRORにした。skipは明示した
  `-DNINLIL_ABI_GOLDEN_ALLOW_MISSING=ON`だけで可能で、negative CMake testが
  既定拒否とoverrideを確認する。
- byte-streamとPOSIX USB serialの48定数、5 layout、34 fieldをABI manifestと
  LP64 goldenへ追加した。専用集合gateは公開headerから定数・struct・fieldを抽出して
  manifestへの欠落をfail-closedにし、`bytes_read` row削除mutationをREDにする。
- `arm-none-eabi-gcc`でfreestanding authority objectを生成し、固定幅record sectionを
  host Pythonで復元するILP32-le-32 manifestを追加した。ESP official launcherでも
  Xtensa toolchainで同じgoldenをcheckする。
- official ESP launcherのFRAG=ON / MFDT=ON fresh mapへ、それぞれ既存
  `r7_frag_esp_dram_budget_gate.py check --map` と
  `mfdt_v1_esp_dram_budget_gate.py check --map`を接続した。

## 検証

| 検証 | 結果 |
| --- | --- |
| ABI focused CTest（drift/golden/coverage/public-layout/ILP32） | 9/9 PASS |
| ILP32 golden generate/check（arm-none-eabi-gcc） | PASS |
| MFDT / R7 FRAG gate self-test | PASS |
| ESP launcher dry-run | PASS |
| `git diff --check` | PASS |

## Remote verification / 非claim

PR #117 head `3892766741569c536f4456de0a860090445e8926` の
[ESP-IDF run 31614757984](https://github.com/Aero123421/Ninlil-Runtime/actions/runs/31614757984)
で、immutable ESP-IDF v5.5.3 amd64 imageを使うofficial launcherをfresh実行した。
feature-ONの実mapに対してR7 FRAGは9,416/49,152 bytes、MFDTは0/49,152 bytesで
両budget gateがPASSし、job全体もSUCCESSした。これはcompile/linkとmap resourceの証拠で
あり、実機flash、物理HIL、RF/power挙動は証明しない。
