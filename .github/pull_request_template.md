## Purpose

<!-- 解決する問題と、利用者に見える結果を簡潔に記載してください。 -->

## Scope

- In scope:
- Out of scope:

## Change type

- [ ] Documentation only
- [ ] Implementation / test without public contract change
- [ ] Public API / ABI
- [ ] Wire protocol
- [ ] Storage format / migration
- [ ] Security / compliance boundary
- [ ] Port / hardware

## Contract and compatibility

<!-- 関連するNormative仕様、ADR、互換性、migrationを記載してください。該当なしの場合は理由を記載してください。 -->

## Verification

<!-- 実行したcommand、test、simulation、HILと結果。未実施の項目は理由と影響を記載してください。 -->

## Failure and operational behavior

<!-- timeout、retry、resource exhaustion、restart、backpressure、operator actionへの影響。 -->

## Documentation and release note

- [ ] 利用者向け文書を更新した、または不要な理由を記載した
- [ ] `CHANGELOG.md` の `Unreleased` を更新した、または不要な理由を記載した
- [ ] LAB / simulation / compile / HIL / productionの検証区分を正確に記載した

## Checklist

- [ ] 変更を1つの独立検証可能な目的に絞った
- [ ] Application固有語彙をportable Coreへ追加していない
- [ ] 新しいobservable behaviorにpositive / boundary / failure testがある
- [ ] Secret、credential、個人情報、generated build treeを含めていない
- [ ] 未検証のsecurity、法令適合性、field readinessを主張していない
- [ ] 関連するIssueをリンクした
