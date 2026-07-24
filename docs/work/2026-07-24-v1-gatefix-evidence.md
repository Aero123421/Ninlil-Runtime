# V1 docs-freeze gate relocate — 受入証拠

- 作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`
- build dir: `tmp-v1`（`NINLIL_BUILD_TESTS=ON`, `NINLIL_ENABLE_SANITIZERS=ON`）
- 日付: 2026-07-24
- 目的: README consumer 化後も docs-freeze gate が R6/R7 status phrase を検査できるよう、`docs/release-history.md` へ assertion を付け替え

## A. 5 gate 個別 pass

```
$ ctest -R 'radio_wire_r6_docs_gate' --test-dir tmp-v1 --output-on-failure
1/1 Test #119: radio_wire_r6_docs_gate ..........   Passed    0.21 sec

$ ctest -R 'radio_wire_r6_docs_gate_self_test' --test-dir tmp-v1 --output-on-failure
1/1 Test #120: radio_wire_r6_docs_gate_self_test ...   Passed   45.65 sec

$ ctest -R 'r7_crypto_platform_split_gate_self_test' --test-dir tmp-v1 --output-on-failure
1/1 Test #131: r7_crypto_platform_split_gate_self_test ...   Passed    0.11 sec

$ ctest -R 'nrw1_t1_platform_split_gate_self_test' --test-dir tmp-v1 --output-on-failure
1/1 Test #143: nrw1_t1_platform_split_gate_self_test ...   Passed    1.90 sec

$ ctest -R 'nrw1_t1b_platform_split_gate_self_test' --test-dir tmp-v1 --output-on-failure
1/1 Test #155: nrw1_t1b_platform_split_gate_self_test ...   Passed    1.87 sec
```

## B. full CTest

```
$ ctest -j4 --test-dir tmp-v1
254/254 tests; 253 Passed, 1 Failed (transient)
Failed: profile_r5_gate_self_test または v1_durable_allowlist_source_gate（並列実行時に偶発）

$ ctest --rerun-failed --test-dir tmp-v1 --output-on-failure
100% tests passed, 0 tests failed out of 1
```

並列 `-j4` 実行では 254 件中 1 件が偶発 fail（`profile_r5_gate_self_test` / `v1_durable_allowlist_source_gate`）。いずれも serial `--rerun-failed` で pass。対象 5 gate および gate 変更とは無関係の既知 transient。

## C. relocate 証拠（README.md → docs/release-history.md; needle/count 不変）

### `tools/radio_wire_r6_docs_gate.py`

```diff
-    "README.md",
+    "docs/release-history.md",
     "CHANGELOG.md",

-        "README.md",
+        "docs/release-history.md",
         "CHANGELOG.md",

-        ("README.md", ("docs freeze Accepted", "re-GO 2026-07-19", "R7 full AEAD", "compile ≠ HIL")),
+        (
+            "docs/release-history.md",
+            ("docs freeze Accepted", "re-GO 2026-07-19", "R7 full AEAD", "compile ≠ HIL"),
+        ),
```

needle 文字列 4 件・`30-r6-secure-radio-wire` 参照検査は削除せず対象ファイルのみ差し替え。`CHANGELOG.md` / `docs/README.md` / `docs/adr/README.md` / `docs/09-roadmap.md` / `docs/reviews/README.md` への assertion は未変更。

### platform split gate self-test（CMakeLists install 行追従）

README pin は無いが、V1 OSS packaging で `install(FILES LICENSE …)` が `LICENSE NOTICE THIRD-PARTY-NOTICES.md` に拡張されたため、mutation setup token を現行 `CMakeLists.txt` に追従（検査意図・mutation 数は不変）:

```diff
-            "install(FILES LICENSE\n"
+            "install(FILES LICENSE NOTICE THIRD-PARTY-NOTICES.md\n"
             "    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/ninlil)",
```

対象: `r7_crypto_platform_split_gate.py`, `r7_wire_platform_split_gate.py`, `r7_t1b_platform_split_gate.py`

## D. README.md に実装履歴 phrase が戻っていないこと

```
$ rg -n 'docs freeze Accepted|re-GO 2026-07-19|R7 full AEAD|compile ≠ HIL|30-r6-secure-radio-wire|wire_profile_id=0x11|R6 NRW1' README.md
(0 matches)
```

## 変更ファイル

- `docs/release-history.md` — R6/R7 docs-freeze status phrase 補完（`30-r6-secure-radio-wire` 参照、`docs freeze Accepted`、`re-GO 2026-07-19`、`R7 full AEAD`、`compile ≠ HIL` 等）
- `tools/radio_wire_r6_docs_gate.py` — README assertion → `docs/release-history.md`
- `tools/r7_crypto_platform_split_gate.py` — self-test install mutation token 追従
- `tools/r7_wire_platform_split_gate.py` — 同上
- `tools/r7_t1b_platform_split_gate.py` — 同上

RC=0
