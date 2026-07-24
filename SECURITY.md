# Security Policy

## Project status

**V1 LAB RC2（タグ `v1.0-lab-rc2`）** は隔離 LAB 向け host simulation の機能完成リリースです。**LAB_ONLY** — 国内実運用、production 法規認定、credential 保護の最終保証、physical RF/USB HIL、regulatory compliance、field SLO は **主張しません**。統合 E2E gate と CTest 成功は、security certification や現場運用承認の代わりに使用しないでください。物理実機系の残件は [RC 残件](docs/work/2026-07-23-v1-rc-residuals.md) を参照してください。

## Reporting a vulnerability

脆弱性または機密性のあるsecurity問題を見つけた場合は、[GitHubの非公開Security Advisoryを作成](https://github.com/Aero123421/Ninlil-Runtime/security/advisories/new)してください。Exploit details、credential、device identifier、現場情報、未修正の再現手順をpublic issueへ投稿しないでください。

## What to include

可能な範囲で次を含めてください。

- 影響を受けるcommit、version、component
- 想定したpreconditionと影響
- 最小の再現手順またはtest
- 既知の回避策
- 情報公開に関する制約

## Response expectations

Project maintainerは報告を確認し、再現性と影響範囲を評価します。現時点では、初回応答、修正、release、公開までのSLAを約束していません。修正状況が公開可能になった場合は、Security Advisoryまたはrelease documentationで案内します。
