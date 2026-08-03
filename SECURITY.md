# Security Policy

## Project status

現行`main`はRuntime完成作業中であり、production support済みreleaseではありません。
履歴タグ`v1.0-lab-rc2`は隔離LAB向けhost simulation候補です。
**LAB_ONLY** — 国内実運用、production法規認定、credential保護の最終保証、
physical RF/USB/Wi-Fi HIL、regulatory compliance、field SLOは**主張しません**。
統合E2E、target compile、CTest成功はsecurity certificationや現場運用承認の代わりに
使用しないでください。機能別の現在stateとHIL境界は
[`compatibility-matrix.json`](compatibility-matrix.json)、物理実機系の履歴残件は
[RC残件](docs/work/2026-07-23-v1-rc-residuals.md)を参照してください。

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
