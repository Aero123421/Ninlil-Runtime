# Changelog

Ninlil Runtimeの利用者に影響する変更をこのファイルへ記録します。日付付きreleaseが始まるまでは、開発中の変更を`Unreleased`へまとめます。

## Unreleased

### Added

- Foundation M1aのpublic C ABI headerとC11/C++17 consumer smoke。
- ABI manifest、reason registry、Operator projection、hook registry、仕様vector、requirements traceabilityの検査tool。
- Scheduler、deadline、Required Receipt、resource accounting、Submission preflight/admissionのpure C11 model。
- Atomic FULL admission write-setとcommit result別のownership/recovery model。
- In-memory Storage、Allocator、Execution、Virtual Clock、Deterministic Entropy v1のTEST conformance fixture。
- Ubuntu GCC通常buildとClang ASan/UBSan buildを実行するGitHub Actions CI。
- Apache License 2.0、contribution guide、direct confidential reporting linkを含むsecurity policy。

### Changed

- Project statusをPR1-only checkpointから、Foundation PR2主要modelとPR3a/b fixture実装済みのpre-alpha checkpointへ更新。
- Apache License 2.0の採用決定をProject CharterとM11 compliance gateへ反映。
- `1.0.0`はhardware exitだけでなくM11までの全exit gate後とし、platformの現行検証実績とplanned targetを分離。

### Known limitations

- Public Runtime APIのfunction bodyと`runtime_step`は未完成です。
- Bearer、Tx Gate、Origin Authorization、SQLite、Reliable Command、Durable Eventはend-to-endで未統合です。
- ESP-IDF、USB、LoRa、Display/Leak nodeの実機pathは未完成です。
- Public API、wire、storage formatの互換性はまだ保証しません。
- Security、regulatory compliance、production SLO、field readinessを保証するreleaseではありません。

このcheckpointはpre-alphaです。Fixtureやsimulator testの成功は、production deploymentや実radioの安全性・信頼性を証明しません。
