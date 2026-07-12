# Changelog

Ninlil Runtimeの利用者に影響する変更をこのファイルへ記録します。日付付きreleaseが始まるまでは、開発中の変更を`Unreleased`へまとめます。

## Unreleased

### Added

- Domain Store D2-S4 same-snapshot production-private exact `get` seam（`ninlil_domain_scan_exact_get` legal in `OPEN`/`EXHAUSTED` only; sole live zero-prefix iterator; exact one Storage `get` on bound READ_ONLY txn; does not consume `row_budget` or change ok-row counters/iterator position）。private presence enum `ABSENT`/`PRESENT` + borrowed `workspace->value` observation（present zero-length via presence; clean NOT_FOUND → OK+ABSENT）。Port-path failure leaves caller output unchanged and sets sticky/`FAILED` as `advance`。S4 key alias exception: key may borrow external or `key[]`/`previous_key[]` but must be disjoint from `value[]`。No unused xref digest/kind/count session fields; no second 4096 buffer; workspace `sizeof <= 8192`; mutation 0。sibling oracle `spec/vectors/domain-scan-exact-get-v1.json`（format `ninlil-domain-scan-exact-get-v1-d2s4`）、independent generator with S1/S2/S3 full SHA pins、production bridge、unit acceptance。S1/S2/S3 JSON and D1 d1b3o JSON byte-for-byte frozen。**D2-S4 implementation complete only** — does not claim D2 / DSR1 / DSR2 / Stage 5 / public Runtime / D3 relationship semantics / full-ID set / ESP hardware。
- Domain Store D2-S3 exact-profile structural same-record scan path（family 5/6 CURRENT closed catalog family5 `01`+family6 §7 全29 subtypes REQUIRED → `ninlil_model_domain_validate_typed_record` for business+`7d` with public API large-local separated into no-output helper; `7e`/`7f` scanner-local parse key+envelope+pure decode+key/body/header bijection + independent header mutates）。workspace `row_validate_scratch` union（typed/witness; `sizeof <= 8192`）。status: `UNSUPPORTED`（record_version/domain_format future）non-terminal with true future→corrupt precedence; profile mismatch / future_profile skip S3 decode; BTS 4097 / unknown subtype / lex OOO。sibling oracle `spec/vectors/domain-scan-structural-v1.json`（format `ninlil-domain-scan-structural-v1-d2s3`）、independent generator with D1 d1b3o full SHA/count pin composition + S1 transport body-nonvalidation hash/ID pin、production bridge、closed catalog coverage。S1/S2 JSON and D1 d1b3o JSON byte-for-byte frozen。**D2-S3 implementation complete only** — does not claim D2 / DSR1 / DSR2 / Stage 5 / public Runtime / S4 exact-get / D3 cross-row / ESP hardware。
- Domain Store D1-B3o CLEANUP_PLAN (`0x63`) pure body encode/decode、126+N body same-record validator（family6 flags0 / COMPOSITE(63, subject_kind||subject_primary_key_digest) / primary_id TX raw16 or DELIVERY composite first16 / PVD+head nonzero / record_revision==batch_generation>=1 / subject_primary_key_digest=KEY_DIGEST complete primary not bare composite / subject_primary_value_digest NZ + equals header PVD / cleanup+batch generation>=1 / count inequalities + phase1/2/3 remaining/fence closed matrix）、independent oracle format `ninlil-domain-store-v1-d1b3o`（append-only after 1460 B3n vectors; prior prefix byte-for-byte）、parser bit44 (synthetic future test bit→45) / tests。Does not implement D2-S3、Stage 5、or public Runtime; live counts/basis/fence aggregate are D3。
- Domain Store D1-B3n RETENTION_BASIS (`0x61`) pure body encode/decode、90+N body same-record validator（family6 flags0 / COMPOSITE(61, subject_kind||RAW16) / primary_id TX raw16 or DELIVERY composite first16 / PVD+head nonzero / revision>=1 / subject_primary_key_digest=KEY_DIGEST complete primary not bare composite / ACTIVE pending|overflow|trusted + ELIGIBLE + CLEANUP_COMMITTED closed matrix / bools 0|1 / checked basis+window）、independent oracle format `ninlil-domain-store-v1-d1b3n`（append-only after 1391 B3m vectors; prior prefix byte-for-byte）、parser bit43 / tests。Does not implement D2-S3、Stage 5、or public Runtime.
- Domain Store D1-B3m MANAGEMENT_LEDGER (`0x52`) pure body encode/decode、exact 364-byte same-record validator（family6 flags0 / composite key=tx||op plain / primary_id=tx / PVD+head nonzero / immutable revision exact1 / kind15 EVENT_RESUME + kind16 EVENT_DISCARD closed matrix / independent streaming SHA-256 canonical request digest recompute）、independent oracle format `ninlil-domain-store-v1-d1b3m`（append-only after 1287 B3l vectors; prior prefix byte-for-byte）、parser bit42 / tests。Does not implement B3n–B3o、D2-S3、Stage 5、or public Runtime.
- Domain Store D1-B3l RETRY_SUMMARY (`0x51`) pure body encode/decode、CUMULATIVE exact 84 / RECENT exact 80 same-record validator（family6 flags0 / composite key=tx||kind||slot / primary_id=tx / PVD+head nonzero / revision>=1 / kind-slot-fold arithmetic / bools / empty-aggregate when folded=0）、independent oracle format `ninlil-domain-store-v1-d1b3l`（append-only after 1222 B3k vectors; prior prefix byte-for-byte）、parser bit41 / tests。Does not implement B3m–B3o、D2-S3、Stage 5、or public Runtime.
- Domain Store D1-B3k EVENT_SPOOL (`0x50`) pure body encode/decode、exact 300-byte same-record validator（family6 flags0 / ID128=tx / primary_id=tx / PVD+head nonzero / record_revision==spool_revision / state×cause / resume 0..8 / discard iff DISCARDED / reservation KEY_DIGEST）、independent oracle format `ninlil-domain-store-v1-d1b3k`、parser/bridge/tests。Does not implement B3l–B3o、D2-S3、Stage 5、or public Runtime.
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
