# 00. Ninlil Project Charter

状態: Normative project charter (Fable review reflected)<br>
対象: Ninlil Runtime 全体<br>
現在の maturity: Experimental / pre-alpha

## 一文での定義

Ninlil Runtime は、不安定・低帯域・間欠的な現場ネットワークで、複数 application の通信要求を、期限、重要度、電力、経路、容量、法規制に基づいて受付・配送・確認する、組み込み向け分散通信 Runtime / SDK です。

## なぜ必要か

現場 IoT では、application が `send(packet)` を呼べたことと、目的が達成されたことは同じではありません。

- radio が busy で送れない。
- node が眠っている。
- relay や親機が変わる。
- 同じ要求が再送され、application が二重適用する。
- 大きな payload が重要な短い event を妨げる。
- API は成功したが、device は反映していない。
- 法規上、今は送信してはいけない。

個別製品がこれらを毎回作ると、失敗状態、identity、retry、証跡が製品ごとにばらばらになります。Ninlil はこの共通部分を application から分離します。

## 堅牢性の定義

Ninlil は「どんな入力でも必ず送る」とは約束しません。物理帯域、干渉、故障、法規制があるためです。

代わりに、次を約束の中心にします。

1. 要求を無条件に受け付けない。
2. 受け付ける前に、release/profileが必須とする契約、期限、宛先、経路、容量を検査し、どこまで検査済みかを返す。
3. 受け付けた transaction の現在地と結果を追跡する。
4. 達成不能なら、調整、延期、別 bearer、拒否を明示する。
5. 成功していない処理を成功と表示しない。
6. retry、queue、fragment、dedup、storage を有限にする。
7. 再起動、経路変更、重複配送を跨いでもlogical transactionを維持し、persistent duplicate suppressionのためのidentityと契約を提供する。

SLO は、全入力ではなく、明示した traffic envelope と fault model の下で admission された transaction に対して定義します。Physical/application effect の exactly-once は無条件には保証せず、idempotent operationまたはapplicationとのatomic apply contractが必要です。

## 対象とする利用形態

- 小さな重要 command
- 失ってはいけない event
- 最新だけが重要な state
- 間引き・集約可能な telemetry
- 有限サイズの設定・text transfer
- 給電 node と sleepy battery node
- 1台または複数の親機
- controller 管理の relay tree / forest
- LoRa、Wi-Fi、USB と将来 bearer
- cloud なしで継続する local operation
- 現場間の移設、機器交換、段階撤去

これらは Ninlil が支える代表的な利用形態です。Ninlil の public model は、特定の製品・業務ドメインの語彙に依存しません。

## 非目標

- Linux、FreeRTOS、ESP-IDF を置き換える汎用 OS
- TCP/IP や LoRaWAN の全面的な代替
- video / audio stream の搬送
- 無限サイズの file transfer
- 任意負荷、任意 hop、任意干渉での無条件配送保証
- application 固有の安全判断、閾値、業務 workflow
- antenna、module、設置方法を含む認証適合性の自動証明
- radio jamming の防止
- 動的 code plugin を field node へ配布する仕組み

## 成功の測り方

### Application 開発者

- product 固有 schema と service contract を追加しても Ninlil Core を変更しない。
- `accepted` と `applied` を API 上で誤認しない。
- sleepy node や容量不足の要求が、送信後ではなく受付時に説明される。
- generic command、event、state の example から短時間で開始できる。

### Port / hardware 開発者

- bearer と storage の明確な interface がある。
- ESP-IDF と POSIX simulator で同じ conformance test を実行できる。
- application policy を radio driver に持ち込まない。

### 運用者

- 「なぜ届かないか」「どこまで進んだか」「次に何をすべきか」が診断情報から分かる。
- 機器交換や relay 撤去で、影響を受ける node を事前に確認できる。
- failure、degraded、outcome unknown を success と区別できる。

### Maintainer / contributor

- architecture、API、wire、compatibility、test、release の変更手順が文書化される。
- 個別製品の source や hardware を持っていなくても、simulator と generic example で貢献できる。
- breaking change が RFC と migration guide なしに入らない。

## OSS としての品質基準

1. Public API と内部実装を分離する。
2. SDK SemVer、wire version、application schema version、regulatory profile version を別管理する。
3. 再現可能な build と dependency lock を持つ。
4. unit test だけでなく、golden vector、property test、fuzz、simulator、HIL、RF soak を用意する。
5. README、concept、tutorial、how-to、reference、explanation を分ける。
6. LICENSE、SECURITY、CONTRIBUTING、CODE_OF_CONDUCT、release process を公開段階に応じて整備する。
7. generic example を product-specific integration example より先に説明する。
8. 実測していない performance や compliance を宣伝しない。

## 言語とドキュメント方針

- 初期設計と reference integration 資料は日本語で作成する。
- public alpha までに、normative API / protocol / porting / contribution 文書の英語版を正本として整備する。
- 日本語 overview と運用資料を維持する。
- 翻訳で規範が分岐しないよう、normative source と translation status を各文書に明記する。

## License の扱い

Repository ownerはApache License 2.0を採用済みです。配布条件の正本はrepository rootの[`LICENSE`](../LICENSE)です。

NOTICE要否の確定、third-party dependency license inventory、source distributionへの必要表示、SBOMとの整合、release compliance最終監査はM11のexit gateで完了します。Copyright ownerやyearは、確認できない情報を推測して追加しません。

## Application との境界

### Ninlil に置く

- transaction / attempt identity
- application contract と admission
- destination resolution の共通機構
- queue、retry、dedup、receipt
- identity、membership、attachment、route、traffic grant
- bearer abstraction
- scheduler と compliance hard gate
- diagnostics と conformance test

### Application / integration layer に置く

- domain 固有の schema
- 安全判断や業務 rule
- UI の文言、色、操作 flow
- deployment / asset / work order などの業務 model
- service ごとの policy と SLO 要求

## 意思決定原則

- 便利な shortcut より、失敗状態を明示する。
- 魔法の自動化より、観測可能で説明できる自動化を選ぶ。
- wire の数 byte 節約だけで public model を歪めない。
- application API と wire encoding を分ける。
- genericity は「任意 blob」ではなく、拡張点と契約の明確さで作る。
- feature 数より、境界、不変条件、移植性、診断性を優先する。
- 現在の lab code を互換性理由だけで公開仕様に昇格させない。

## 1.0 まで固定しないもの

- 最終 wire header layout
- transaction ID の wire 上の圧縮方式
- multi-parent の全 algorithm
- 全地域の regulatory profile
- dynamic routing の高度な最適化
- public cloud control plane

これらは RFC と実測により段階的に固定します。
