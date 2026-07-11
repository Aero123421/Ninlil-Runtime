# Ninlil Documentation

状態: M0 public baseline complete / M1a Domain Store D0 fixed, D1-A・D1-B1・D1-B2・D1-B3a (SCHEDULER_OWNER 0x26)・D1-B3b (ORDERED_INGRESS 0x27 + message_semantic_digest; **controller-ingress retrofit implemented**)・D1-B3c (BLOB 0x30 manifest/chunk)・D1-B3d (ATTEMPT 0x31)・D1-B3e (ATTEMPT_ID_INDEX 0x34)・D1-B3f (CANCEL_STATE 0x33)・**D1-B3g (EVIDENCE_CELL 0x32) implemented**・**D1-B3h (DELIVERY 0x40) implemented**・**D1-B3i (RESULT_CACHE 0x41) implemented** (kind9/10 phase identity 42-byte correction)・**D1-B3j (REVERSE_REPLY 0x42) implemented** (exact 330 / raw80+raw86 / closed state matrix)・**D1-B3k (EVENT_SPOOL 0x50) implemented** (exact 300 / state×cause / resume-discard / reservation KEY_DIGEST)・**D1-B3l (RETRY_SUMMARY 0x51) implemented** (CUMULATIVE84/RECENT80 kind-slot-fold; vector format `ninlil-domain-store-v1-d1b3l`)・**D1-B3m (MANAGEMENT_LEDGER 0x52) implemented** (exact364/kind15-16 matrix/canonical digest; vector format `ninlil-domain-store-v1-d1b3m`)・**D1-B3n (RETENTION_BASIS 0x61) implemented** (90+N→106/170 state matrix; vector format `ninlil-domain-store-v1-d1b3n`)・**D1-B3o docs-only Normative freeze**（17章§8.6/§8.6.1: CLEANUP_PLAN 0x63; future format `d1b3o` reserved・artifact未; **implementation pending・D2-S3 blocked**）、**D2-S0 scanner contract freeze**、**D2-S1 scanner core implemented**（`src/runtime` private; oracle `spec/vectors/domain-scan-v1.json` format `ninlil-domain-scan-v1-d2s1`）、**D2-S2 implementation complete**（17章§15.10 / §17.1.2: production `begin_profiled` + same-txn 17-get gate + iterator reconciliation + oracle `spec/vectors/domain-scan-profile-v1.json` format `ninlil-domain-scan-profile-v1-d2s2` + production bridge/tests; TEST transport begin is test-macro only；**D2 incomplete** — S3–S5/DSR1/DSR2 complete未、Stage 5/public Runtime/ESP hardware未）、D1 remaining implementation + D2–D4 otherwise pre-alpha<br>
対象release: Foundation / pre-alpha

## 正本と優先順位

Ninlilの次期設計は、このディレクトリを正本とします。

矛盾がある場合の優先順位:

1. [Ninlil ADR](adr/)で`Accepted`となった決定
2. 本ディレクトリで`Normative`と記載された要件
3. Foundation Releaseのconformance fixtureとacceptance test
4. KGuard integrationに限り`productv1/docs/99-decision-log.md`の採用・移行決定
5. legacy `linkos/`のcodeとtest
6. 説明用example

KGuard側のdecision logは、Ninlilのgeneric public contractを単独で上書きできません。generic contractを変える場合はNinlil ADR/RFCを先に更新します。

Legacy codeの現在の挙動は、新しい公開仕様を暗黙に固定しません。

## 規範語

- **MUST / 必須**: 準拠実装が必ず満たす。
- **MUST NOT / 禁止**: 準拠実装が行ってはならない。
- **SHOULD / 推奨**: 逸脱理由を文書化した場合だけ外せる。
- **MAY / 任意**: 実装・profileが選択できる。

`例`、`候補`、`将来`、`Open question`は、それだけでは規範要件ではありません。

## 読む順番

| # | 文書 | 決めること |
| ---: | --- | --- |
| 00 | [Project Charter](00-project-charter.md) | 目的、非目標、品質基準 |
| 01 | [Architecture](01-architecture.md) | 役割、plane、port、依存方向 |
| 02 | [Application Contracts](02-application-contracts.md) | data family、admission、receipt、outcome |
| 03 | [Identity and Join](03-identity-and-join.md) | identity、membership、attachment、route、grant |
| 04 | [Runtime API and Storage](04-runtime-api-and-storage.md) | C API、ownership、threading、journal、crash recovery |
| 05 | [Security and Compliance](05-security-and-compliance.md) | trust boundary、key/replay、radio transmission hard gate |
| 06 | [Versioning and Compatibility](06-versioning-and-compatibility.md) | API/wire/schema/storageの独立version |
| 07 | [Testing and Quality](07-testing-and-quality.md) | simulator、fuzz、HIL、release gate |
| 08 | [Foundation Release](08-foundation-release.md) | 最初に実装する範囲とacceptance criteria |
| 09 | [Roadmap](09-roadmap.md) | relay、multi-parent、Wi-Fi、production MACへの段階 |
| 10 | [KGuard Integration](10-kguard-integration.md) | KGuardとの境界とlegacy移行 |
| 11 | [Operator Model](11-operator-model.md) | 内部状態を原因・次操作・担当へ写像する規則 |
| 12 | [Foundation C ABI](12-foundation-abi.md) | M1aの完全なpublic type、callback、port ABI |
| 13 | [Foundation State Machine](13-foundation-state-machine.md) | M1aの決定的reducer、deadline、cancel、recovery |
| 14 | [Foundation Ports and Simulator](14-foundation-ports-and-simulator.md) | storage/bearer/clock、fixture、canonical encoding |
| 15 | [Glossary](15-glossary.md) | 仕様・実装・UIで共有する語彙と誤解しやすい境界 |
| 16 | [Foundation Implementation Plan](16-foundation-implementation-plan.md) | M1aを検証可能な連続PRへ分ける実装順 |
| 17 | [Foundation Domain Store v1](17-foundation-domain-store.md) | private domain record、atomic witness、recovery、capacity再計算 |

## 実装開始条件

Foundation実装は次を満たしてから各sliceを開始します。Public ABI/reducer/bootstrap sliceは開始済みですが、Stage 5 domain recovery以降は[17章](17-foundation-domain-store.md)のD0 gateを先に満たします。

- 00〜14の重大な矛盾がない。
- Foundationで固定するpublic type、state transition、error、resource limit、storage transactionが明記されている。
- Fableによる思想・人間の使いやすさ・OSS観点レビューを反映済みである。
- security/complianceはFableとは別に、仕様上のhard boundaryをCodex側で確認している。
- 未決事項がFoundationの実装判断を要求しないか、明示的なdefaultを持つ。

## 変更手順

1. 変更理由、影響するcontract、compatibilityを記載する。
2. normative requirementを先に更新する。
3. acceptance testまたはconformance fixtureを追加・変更する。
4. implementationを変更する。
5. 互換性を破る場合はRFCとmigration noteを作る。

公開alpha以降はEnglish normative sourceへ移行します。それまでは本日本語版を設計正本とし、翻訳を規範として扱いません。
