# Support

Ninlil Runtime はcommunity-maintained OSSです。無償の応答時間、修正期限、
個別導入支援、または特定hardware・法域での動作を保証しません。

## 問い合わせ先

| 内容 | 連絡先 |
| --- | --- |
| 再現可能な不具合 | GitHub IssueのBug report |
| 利用方法・porting・設計上の質問 | GitHub IssueのQuestion |
| 機能提案 | GitHub IssueのFeature request |
| 脆弱性・credential漏えい | [SECURITY.md](SECURITY.md)の非公開手順 |
| 行動規範違反 | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)の非公開手順 |

公開Issueへ秘密情報、device固有credential、個人情報、未修正の脆弱性を投稿しないで
ください。

## Support対象

Support対象は、各GitHub Releaseのrelease noteとそのartifactに記載された範囲です。
`main` branch、未releaseのcommit、experimental port、LAB_ONLY profileは開発中で、
互換性や運用適合性が変わることがあります。

問い合わせには可能な範囲で次を含めてください。

- release tagまたは完全なcommit SHA
- OS、toolchain、CMake、ESP-IDFなどのversion
- 使用したport、hardware、build option
- 最小の再現手順、期待結果、実際の結果
- 秘密情報を除いたlog、backtrace、test結果

Maintainerは、再現性、影響、support中のreleaseかどうか、修正可能性を確認して
優先度を判断します。情報不足、support外、特定製品固有の問題は、追加情報の依頼、
適切なintegration層への案内、またはcloseとなることがあります。

## Safetyと法令

通信距離、電波出力、周波数、duty cycle、技術基準、credential保護、実機耐障害性は、
hardware、設定、法域、運用環境に依存します。Release noteが明示的に検証済みとする
範囲を超えて、production利用や法令適合を推定しないでください。利用者は、導入先の
安全評価、認証、法令確認、回帰試験を自身の責任で行います。

Security更新が必要な場合は、[SECURITY.md](SECURITY.md)に記載された方法とrelease
noteを優先してください。
