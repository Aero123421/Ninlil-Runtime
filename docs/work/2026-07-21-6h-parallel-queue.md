# 6時間並列実行キュー(2026-07-21 22:30 JST編成; 納期優先・品質条件不変)

## Critical path再評価

A1(ADR Accepted判定中)→A2(a2進行中→b→c→d→e)→A3(S5..S12: **各sliceのNormative freezeが未着手**のためfreeze著作が先頭)→A4→B1(public Runtime body=最大トランチ)→B2..B5→C..D。
最長鎖はA2完遂→A3であり、B1の**監査・計画・契約抽出はA系と独立に前倒し可能**(コード実装はA4後)。

## レーン割当(現在)

| レーン | 現ジョブ | 次ジョブ(完了後直結) |
| --- | --- | --- |
| Sol xhigh | ADR-0015 r3(実行中) | ACCEPTED-OK→R28 commit/PR/CI→main統合。NO-GO→Qwen修正即dispatch |
| Grok(A2レーン継続) | A2-a2独立ゲート群(実行中) | →Sol highゲート→A2-b vector生成 |
| Qwen(既定worker) | **B1契約監査を即dispatch**(read-only抽出; 新worktree ninlil-fable-b1-audit) | →B1トランチ計画素材→(A3-S5 freeze素案著作) |
| Sol high | 待機 | A2-a2ゲート→B1計画レビュー→A3-S5 freeze素案レビュー |
| Fable | キュー編成・回収・QA | 各完了の即時検収と次dispatch、R28 PR処理、README/push |

## 6時間内の完了目標

1. R28 main統合(ADR Accepted化を含む; レビュー結果次第で追加1往復)。
2. A2-a2ゲートGO + A2-b着手(可能ならvector初回生成→Sol oracle候補レビュー1巡目)。
3. B1契約監査完了+B1トランチ計画rev1のSol highレビュー1巡目。
4. A3-S5(DSW2_SUPERSEDE_CHAIN)freeze素案の著作着手。
5. 台帳・README進捗更新+push(区切りごと)。

## 運用固定

- 長時間job=nohup+sentinel+Monitor方式で回収。
- 競合編集禁止: worktree単位で1 worker。d3s3 worktreeはADR r3完了までレビュー専有。
- 未承認仕様の先行実装禁止(A3実装はfreeze+計画レビュー後)。
- 全workerへNormative根拠/禁止事項/負系/完了コマンド/期待出力を初回提示(往復削減)。
