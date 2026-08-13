# Ninlil Runtime concepts

状態: 現行 `main` の利用者向け概念ガイド（Informative）

このページは、公開Host Runtime SDKを初めて読む人のための短いメンタルモデルです。
正確な要件は[Foundation C ABI](12-foundation-abi.md)、
[Foundation State Machine](13-foundation-state-machine.md)、Accepted ADRを優先します。

## Transactionは「送信」より長く生きる

Applicationが提出する1件の要求はtransactionです。Runtimeは、永続化、送信試行、
Receipt、deadline、再起動後の回復を同じtransactionとして追跡します。1回のradio送信や
socket writeはattemptにすぎず、それ自体を業務上の成功とは扱いません。

## ReceiptとOutcomeを分ける

Receiptは「どの証拠を得たか」、Outcomeは「要求全体をどう判定できるか」です。
例えばtransportがbytesを受け取っても、相手Applicationが適用した証拠にはなりません。
証拠が失われた場合は、実際には効果が起きた可能性を残したまま`UNKNOWN`になり得ます。

この区別により、UIや運用は「受付済み」「配送済み」「適用済み」「結果不明」を混同せずに
表示できます。用語の完全な一覧は[Glossary](15-glossary.md)を参照してください。

## Application familyは意図を表す

- DesiredStateは、相手に到達させたい絶対状態やcommandを表します。
- EventFactは、発生した事実を失わず届けるために使います。
- reserved familyは、公開ABIで利用可能になるまで有効な機能として扱いません。

Ninlil Coreは製品固有のpayloadを解釈しません。service ID、schema、business ruleは
Application側が所有します。境界の具体例は
[Reference Application Integration](10-reference-application-integration.md)にあります。

## Runtime、Port、Bearerの役割を分ける

Runtimeはtransactionの状態と証拠を管理します。Portはstorage、clock、entropyなどの
platform機能を提供し、Bearerはbytesを運びます。Coreがsocket、radio driver、製品語彙へ
直接依存しないため、同じcontractをHostと組み込みtargetで検証できます。

役割と依存方向の詳細は[Architecture](01-architecture.md)を参照してください。

## Durableでも無制限ではない

重要な状態はtransactionとして永続化しますが、queue、record、payload、step workには
固定上限があります。容量不足やclock/storageの不確実性を成功へ丸めず、呼出側が判断できる
statusと診断へ変換するのが基本です。

## 次に読む

- 手を動かして最初の検証を行う: [Host Runtime first tutorial](host-runtime-tutorial.md)
- buildやinstallの目的別手順を調べる: [Host Runtime SDK](host-runtime-sdk.md)
- 配布物のexact surfaceを確認する: [SDK distribution manifest](sdk-distribution-manifest.md)
