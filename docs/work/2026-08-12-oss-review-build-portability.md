# 2026-08-12 OSS review build/test portability closure

## 対象

2026-08-11 OSS reviewのOR-29に残っていた通常build/testの不安定要因を対象にした。
public ABI、wire、storage形式、protocol semanticsは変更していない。

## 最小修正

- R7 KAT bridgeへCMakeが選択した`CMAKE_C_COMPILER`を明示する。
- 指定compilerが存在しない場合はPython tracebackを出さず、1行の診断と終了code 1で
  fail closedにする。
- 通常profileはrelease bridgeだけ、`NINLIL_ENABLE_SANITIZERS=ON` profileは
  ASan+UBSan bridgeだけをcompile/executeする。通常buildからcompiler-rt前提を除いた。
- D3-S4 vector oracleの重いself-testだけCTest timeoutを180秒から600秒へ変更し、
  sibling testの180秒ceilingは維持した。
- all-private MFDT lifecycle 10,000-step testは単独約36秒だが、重いoracleとの並列時に
  120秒を超えたため、semantic step boundは変えずCTest wall timeoutだけ300秒にした。
- SQLite busy timeout testは意味のある70ms下限を維持し、負荷依存の1500ms上限を
  削除した。無限hangは`posix_sqlite_storage`全体のCTest `TIMEOUT 60`で検出する。

## 検証

| 検証 | 結果 |
| --- | --- |
| normal R7 KAT check/self-test + SQLite | 3/3 PASS |
| ASan+UBSan R7 KAT check/self-test | 2/2 PASS |
| ASan+UBSan SQLite | 1/1 PASS、3.49秒 |
| D3-S4 vector oracle self-test | 1/1 PASS、単独76.85秒 |
| MFDT lifecycle 10,000 step | 1/1 PASS、単独35.84秒 |
| CTest command | normalは`--compiler=/usr/bin/cc`、sanitizerは同compiler + `--sanitize-bridge` |
| CTest timeout property | D3対象test 600秒、MFDT lifecycle 300秒、SQLite 60秒 |
| 存在しないcompiler負例 | 終了code 1、短い診断、tracebackなし |
| `git diff --check`（対象差分） | PASS |

remote Linux/GCC/Clang CIの結果はこのlocal記録だけでは主張しない。
