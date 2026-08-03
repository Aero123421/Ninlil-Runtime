# Traceability complete coverage V2

状態: software verified。共有CMake/CI統合、baseline/all-privateのprofile別再実行、partial-profile false-green mutationを完了した。実機/HIL/RF/legalの完了主張ではない。

## 目的

旧coverageは列挙済みH2の存在確認に留まり、H3/H4、全`NIN-FND-*`、configured CTestで実際に有効なtestとの結合を完全には証明していなかった。V2はfalse-greenを閉じ、仕様unitから有効なtest evidenceまでを機械検査する。

## Coverage unit

- 12〜14章のfence外H2/H3/H4: 254
- 明示`NIN-FND-*`: 40
- delegated vector authority: 303 definitions
- `NIN-INV-001`〜`NIN-INV-014`: 14 invariants / 21 subclaims

見出しIDは完全heading pathへ明示的に結び、文書順序から再生成しない。V2 update toolは既存path-to-ID対応を保持し、path setが変化した場合は自動採番せずreviewを要求する。

## Direct invariant evidence

- `NIN-INV-005`: transaction ID不変、logical retryのfresh attempt、observation前crash replayのsame attempt、protected wire再送のfresh nonceを個別subclaim化した。
- `NIN-INV-010`: queue、retry、dedup、reassembly、journalを5 subclaim化し、各profile境界のexact limitとlimit+1/1-byte-short拒否をfocused assertionへ結んだ。
- `NIN-INV-012`: `radio_hal_r1`に加えて`sx1262_r9`と`sx1262_r9_sole_edge_gate`を必須evidenceにした。

## False-green closure

- Markdown fence内のfake heading/requirementを除外する。
- byte SHA-256でsource driftを検出するが、hashをsemantic proofとして扱わない。
- CMake text検索をauthorityにせず、configured CTest JSONだけを読む。
- CTest `DISABLED` propertyを有効testから除外する。all-privateでpublic Runtime readinessにより無効化されるtestを実際に検出し、非適用profileをmanifestへ明示した。
- self-testはomission、duplicate、FND omission、reorder、disabled/`if(FALSE)`、fenced heading、byte hash、invariant section外移動を検査する。

## Local evidence

2026-07-29に次を実行した。

```text
python3 tools/traceability_complete_coverage_gate.py --self-test
python3 tools/traceability_complete_coverage_gate.py --check \
  --profile baseline=build/trace-audit \
  --profile all-private=build/root-all-private
```

結果:

```text
traceability complete coverage V2 self-test ok
traceability complete coverage V2 ok: sources=3 headings=254 requirements=40 vectors=303 invariants=14 subclaims=21 test_links=1306 profiles=all-private,baseline
```

Focused CTest:

```text
baseline: v1_runtime_delivery, v1_runtime_capability,
          typed_simulated_bearer_fixture = 3/3 PASS
all-private: wifi_v1_journal_test, nrw1_frag_state_private,
             nrw1_frag_prod_integration_private = 3/3 PASS
vector_inventory_check, vector_reference_check = 2/2 PASS
traceability legacy + V2 baseline = 4/4 PASS
traceability legacy + V2 all-private = 4/4 PASS
```

## CMake / CI integration

- baseline CTestは`baseline=<configured build dir>`を渡す。
- Domain Schema 1を含む全private feature同時ON CTestは`all-private=<configured build dir>`を渡す。
- Domain ONかつprivate featureが1つでも欠けるtreeはcomplete profileとして登録しない。MFDTだけOFFのmutation treeで未登録を確認した。
- `ci.yml`はUbuntu baseline jobとhost all-features jobでself-testとprofile checkを明示実行する。
- 上記local gateがgreenになったため`NIN-PR1-TRACE-COVERAGE-001`を`verified`へ更新した。

## Claim boundary

これはsoftware traceability coverageの証拠であり、ESP32-S3実機、RF、HIL、法規適合、remote CI runや全releaseの完了証明ではない。
