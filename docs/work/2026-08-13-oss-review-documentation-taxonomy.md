# OSS review: documentation information architecture

日付: 2026-08-13

## 対象

原レビュー159行 / OR-36は、Project Charterが要求する`README`、`concept`、`tutorial`、
`how-to`、`reference`、`explanation`の分離が、番号付き仕様と作業記録の一覧だけでは
満たされていないと指摘した。

## 変更

`docs/README.md`を現行情報アーキテクチャの入口とし、6分類を6つのdistinct targetへ固定した。

| 類型 | target |
| --- | --- |
| README | repository root `README.md` |
| concept | `docs/runtime-concepts.md` |
| tutorial | `docs/host-runtime-tutorial.md` |
| how-to | `docs/host-runtime-sdk.md` |
| reference | `docs/sdk-distribution-manifest.md` |
| explanation | `docs/01-architecture.md` |

分類はnavigationだけを表し、リンク先のNormative / Informative状態やfeature maturityを
変更しない。conceptとtutorialは現行Host Runtimeへ絞り、historical LAB資料や巨大な
Normative referenceを初学者入口へ混ぜない。

## 検証

`tools/markdown_link_gate.py`はtaxonomy marker、header、category順、exact target、6 targetの
distinctnessをactive Markdown上で検査し、taxonomy全体のcode-fence化も拒否する。
tutorialのactive bash fenceもconfigure/build target/CTest regex/
`--no-tests=error`を含むexact 4 blockへ結合する。tutorial行削除、tutorial→how-to誤routing、
build targetとCTest regexの改変はself-testでREDになる。
新規2文書はtop-level language registryへ追加し、51文書のclosed setを維持する。

```text
python3 tools/markdown_link_gate.py check
python3 tools/markdown_link_gate.py self-test
ctest --test-dir <build> -R '^markdown_link_gate(_self_test)?$' --output-on-failure
ctest --test-dir <build> -R '^v1_integration_gate_e2e$' --output-on-failure
```

focused direct check/self-test、CTest 2/2、tutorial smoke 1/1、release distribution self-test、
全local link scanをPASSした。

## 非claim

この分類は全仕様の英訳、public alpha、情報の網羅性、物理HIL、またはRuntime完成を
主張しない。英語Normative正本はCharterどおりpublic-alpha前の別exit gateである。
