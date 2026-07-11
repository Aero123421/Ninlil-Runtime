# Changelog

Ninlil Runtimeの利用者に影響する変更をこのファイルへ記録します。日付付きreleaseが始まるまでは、開発中の変更を`Unreleased`へまとめます。

## Unreleased

### Added

- Domain Store D2-S2 production profiled begin（same-txn 17 exact get + profile gate + one-iterator reconciliation）、sibling oracle `spec/vectors/domain-scan-profile-v1.json`（format `ninlil-domain-scan-profile-v1-d2s2`）、independent generator、production bridge、and unit acceptance。S1 transport begin is TEST-macro only and absent from tests-OFF private symbols. Does not complete D2 / DSR1 / DSR2 / Stage 5 / hardware.
- Foundation M1aのpublic C ABI headerとC11/C++17 consumer smoke。
- ABI manifest、reason registry、Operator projection、hook registry、仕様vector、requirements traceabilityの検査tool。
- Scheduler、deadline、Required Receipt、resource accounting、Submission preflight/admissionのpure C11 model。
- Runtime config/Platform検証、11種capacity導出、Storage/Bearer/Clock/entropy分類、Stage 9 health gateを含むRuntime Lifecycle L1 pure C11 model。
- Runtime Store v1の17 bootstrap key、typed big-endian record、CRC32C、境界/破損検査を行うportable C11 codec。
- Stage1 successだけが発行するheader/pointer-free accepted-config projectionに束縛したcanonical profile/identity、17-record aggregate validation、presence/profile/identity decision、compact lazy bootstrap planのRuntime Store L2a2 pure C11 model。
- Lifecycle/Runtime Store sourceをTEST-only reducerから分離した、非export・subproject build対応の`ninlil_runtime_private` STATIC targetとcomposition smoke gate。
- Atomic FULL admission write-setとcommit result別のownership/recovery model。
- In-memory Storage、Allocator、Execution、Virtual Clock、Deterministic Entropy v1のTEST conformance fixture。
- 2 endpoint typed simulated Bearer、bounded FIFO、receive loan、shared Virtual Tx Gate / one-shot permitのTEST conformance fixture。
- Stateless synthetic grant、closed deny precedence、fault seam、TEST-only composition assertionを備えたOrigin Authorization fixture。
- Ubuntu GCC通常buildとClang ASan/UBSan buildを実行するGitHub Actions CI。
- Apache License 2.0、contribution guide、direct confidential reporting linkを含むsecurity policy。

### Changed

- Project statusをPR1-only checkpointから、Foundation PR2主要modelとPR3a/b/c/d fixture実装済みのpre-alpha checkpointへ更新。
- Apache License 2.0の採用決定をProject CharterとM11 compliance gateへ反映。
- `1.0.0`はhardware exitだけでなくM11までの全exit gate後とし、platformの現行検証実績とplanned targetを分離。

### Known limitations

- Public Runtime APIのfunction bodyと`runtime_step`は未完成です。
- Bearer、Tx Gate、Origin Authorization、SQLite、Reliable Command、Durable Eventはend-to-endで未統合です。
- ESP-IDF、USB、LoRa、Display/Leak nodeの実機pathは未完成です。
- Public API、wire、storage formatの互換性はまだ保証しません。
- Security、regulatory compliance、production SLO、field readinessを保証するreleaseではありません。

このcheckpointはpre-alphaです。Fixtureやsimulator testの成功は、production deploymentや実radioの安全性・信頼性を証明しません。
