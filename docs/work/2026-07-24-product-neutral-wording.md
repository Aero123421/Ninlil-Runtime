# 製品非依存の公開表現への統一

日付: 2026-07-24  
対象: repository の公開文書、ソースコメント、品質ゲート

## 目的

Ninlil Runtime を独立した汎用 OSS / SDK として説明できるよう、特定の利用製品を前提にした名称と記述を現行ファイルから除去する。

## 変更

- README と project charter をapplication非依存の説明へ変更した。
- application integration profile を汎用の reference application profile へ改称した。
- ADR、roadmap、port 文書、レビュー記録を製品非依存の表現へ置き換えた。
- Core への製品語彙混入を検査する mutation gate を、一般化した product-specific vocabulary gate へ変更した。
- U5/U6の凍結文書はfreeze v2として再固定し、Accepted ADR-0016と独立Sol highレビューでsemantic不変を確認した。

## 影響範囲

- public C API、wire、storage format、runtime behavior は変更しない。
- U5/U6のalgorithm、処理順、数値、Normative claimは変更しない。
- 既公開tagとGit履歴は改変しない。
- 今後の利用製品固有schema、policy、UI、SLOは、Ninlil public APIを利用する外部adapter側で管理する。

## 受入条件

- 現行の追跡対象ファイルに削除対象の固有名称・表記揺れが0件。
- renamed documentへのリンク切れがない。
- structural/mutation gateとfull CTestが成功する。
- GitHub Actionsが成功してからmainへ統合する。

## 検証結果

- 現行ファイル名・本文の削除対象名称: 0件
- `git diff --check`: PASS
- product vocabulary / Radio-USB / U5-U6 freeze v2 / R6 cross-pinのcheck・mutation self-test: PASS
- Sol high独立freeze監査: `P0=0 / P1=0 / P2=0 GO`
- sanitizer buildのfull CTest: `255/255 PASS`
