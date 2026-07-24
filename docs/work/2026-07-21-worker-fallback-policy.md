# 実装workerフォールバック運用規則（root指示 2026-07-21）

優先順（循環）: **Qwen 3.8 Max Preview → Cursor CLI Auto → Grok 4.5 → Qwen 3.8 Max Preview**

## 切替条件
- 切替は**可用性障害のみ**: quota/rate limit、認証失敗、model unavailable、サービス障害を確認できた場合。
- 通常の実装失敗・テスト不合格・品質不足は切替理由に**しない**（同workerへ修正させる）。短い一時エラーは限定的に再試行してから判断。
- Cursor Autoも不能→Grok 4.5へ。Grokも不能→Qwen制限の回復を確認して先頭へ戻る。

## 起動形
- Qwen: `opencode run -m alibaba-token-plan/qwen3.8-max-preview [-c]`
- Cursor: `cursor-agent -p --model auto --trust --force --output-format stream-json --stream-partial-output --workspace <worktree> "<prompt>"`（コマンドは cursor-agent。ログイン済みPro / Auto default）
- Grok: `grok -p "<prompt>" -m grok-4.5 --always-approve`

## 引継ぎ義務
切替時は既存worktree・仕様・受入条件・未完了差分・直前テスト結果を完全に引き継ぎ、作業の重複・消失を防ぐ。切替理由/時刻/担当/引継ぎ内容/結果を docs/work へ記録。

## レビュー独立性
- 実装者が誰でも **Solレビューは必須の独立ゲート**。
- Grokが実装者の期間は、Grok自身の出力をGrokレビューで「独立レビュー済み」と数えない（Sol必須+可能なら別モデルの追加QA）。

## 適用状況の注記（2026-07-21時点）
- 本規則以前の履歴: A2-a骨格は品質理由でQwen→Grokへ再委任済み（規則制定前の判断）。以後の品質問題は同worker修正で対応し、切替は可用性障害のみとする。A2-aのゲートレビューは当初からSol high（Grok自己レビューは不使用）であり独立性は維持されている。
- バックグラウンド実行中の作業（R28 r3=Qwen、A2-a r3後続=Grok）は中断せず、次工程から本規則を適用。

## 【停止】旧循環規則の停止(root指示 2026-07-21 23:5x JST)
- Qwenアップグレードに伴い、実装workerは**Qwenのまま継続**。Cursor Auto/Grokへの**自動フォールバックは無効**(rootの再指示まで)。
- quota/stall発生時もQwen再試行・回復確認を行い、長時間継続不能なら代替せずrootへ報告。
- Grokは追加レビュワーとしてのみ使用可(実装フォールバック先ではない)。
- 実施記録: B1 rev2のCursorジョブ(pid 48731/48733/48839)を安全停止。**Cursor編集ゼロ**(draft mtime 22:39=起動前のまま)を確認、二重編集なし。B1 rev2はupgraded Qwenへ全所見・監査・受入条件を引継いで再dispatch。
- A2-a2のGrok実装済み差分はSol独立QA対象として維持。以後の修正はQwenへ。
