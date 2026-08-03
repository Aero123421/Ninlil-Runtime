# Governance

Ninlil Runtime は、[Apache License 2.0](LICENSE)で提供する、特定製品に依存しない
通信Runtime / SDKです。Projectの判断は、実装者の所属ではなく、公開された
仕様、互換性、再現可能な検証結果、利用者への影響に基づきます。

## 参加者の役割

- **Contributor**: Issue、文書、code、test、reviewを提供する参加者。
- **Reviewer**: 特定領域の変更を技術的にレビューするContributor。
- **Maintainer**: triage、merge、release、権限管理を担う参加者。
- **Release steward**: 1回のreleaseについてchecklistと証跡を管理するMaintainer。

役割は雇用関係や企業を代表しません。Maintainerの追加・退任は、候補者の
継続的な貢献、判断の透明性、利用者対応、規範順守を根拠に、既存Maintainerが
公開IssueまたはPull Requestへ記録します。RepositoryのGitHub権限を持つ人が
その時点のMaintainerです。

## 意思決定

通常の変更は、Pull Request上のreviewとCI結果に基づくlazy consensusで決めます。
合理的な異論がなければMaintainerがmergeできます。異論がある場合は、選択肢、
互換性、運用上の影響を記録し、必要な追加testまたは小さな実験で解決します。

次の変更は、実装より先にNormative仕様とAccepted ADRを更新します。

- public API / ABI、wire、永続化format、security・法規境界
- support policyまたは互換性保証の変更
- 不可逆なrepository運用・governance変更

複数Maintainerがいる場合、上記の重大変更とstable releaseには、作者以外を含む
2名以上のMaintainer承認を原則とします。Maintainerが1名の期間は、自身でmerge
できますが、判断理由、未解決リスク、検証結果をPull Requestへ明記します。

## Mergeとrelease

- Mergeは、変更範囲に対応するtest、文書、compatibility評価を満たした後に行います。
- Branch protectionとrequired checksをGitHub設定で有効にすることを推奨します。
- Releaseは[Release Guide](docs/releasing.md)に従い、release commitをtagで固定します。
- CI成功を、実機試験、security認証、法令適合性の代わりに扱いません。

## 利益相反と異議

Reviewerは、自身または所属組織に直接の利益相反がある場合に明示します。
行動規範・security報告の対象者は、その案件の判断から外れます。

判断に異議がある場合は、元のIssueまたはPull Requestへ、新しい根拠、再現手順、
利用者への影響を提示してください。単なる投票数より、仕様との整合性と検証可能な
証拠を優先します。

## Governanceの変更

この文書の変更は通常のPull Requestで提案できます。変更理由、移行方法、
既存Contributorと利用者への影響を明記し、変更履歴をrepositoryに残します。
