# R6 final integration — Accepted re-GO (status finalization)

**Date:** 2026-07-19  
**Branch:** `codex/r6-radio-wire`  
**状態:** **final Accepted re-GO**（R6 docs freeze Accepted / Stage 9）  
**Independent integration re-audit:** **P0=0 / P1=0 / P2=0 GO**  
**Storage header/pin separate re-audit:** **P0=0 / P1=0 / P2=0 GO**  

**Not claimed:** R7 full AEAD codec complete, M4/M5 handshake complete, ESP N6 capacity ready, RF/USB **実機 HIL**, Japan legal, production radio complete. compile/link ≠ HIL. gate PASS ≠ arbitrary natural-language proof.  
**Status-only closure:** **final status-only delta independent recheck P0=0 / P1=0 / P2=0 GO**（status/progress/review/gate 文言だけを同じ independent reviewer が再確認。layout/API/constants は未変更）。

本記録は pre-status full audit（下表 fixed hashes）で **P0=P1=P2=0 GO** を得たのち、R6 docs freeze を **Accepted** へ status 最終化する。  
pre-status full audit と status-only delta post-review は別々に実施し、どちらも **P0=0 / P1=0 / P2=0 GO**。後者は status/progress/review/gate のみを対象とし、layout/API/constants が不変であることも確認した。

## Supersession（historical NO-GO の formal supersede）

| 記録 | 位置づけ |
| --- | --- |
| [2026-07-17 R6 freeze self-review](2026-07-17-r6-secure-radio-wire-freeze-self-review.md) | **historical self-review** — 当時の **NO-GO スナップショット**（Accepted 仮 / not GO）。削除・改竄しない。**本記録により formal superseded。** |
| [2026-07-18 Chunk D self-review](2026-07-18-r6-chunk-d-n6-private-host-self-review.md) | **historical self-review** — 当時の **NO-GO スナップショット**。削除・改竄しない。**本記録により formal superseded。** |
| **本記録（2026-07-19）** | **final Accepted re-GO**。historical 17/18 を **formal supersede** する。 |

## Independent re-audit results（pre-status full audit）

| 監査 | P0 | P1 | P2 | 判定 |
| --- | ---: | ---: | ---: | --- |
| independent integration re-audit | 0 | 0 | 0 | **GO** |
| storage header/pin separate re-audit | 0 | 0 | 0 | **GO** |
| final status-only delta independent recheck | 0 | 0 | 0 | **GO** |

### Prior NO-GO snapshot findings（closed before re-GO）

| 等級 | 件数（再監査前） | 扱い |
| --- | --- | --- |
| P0 | 0 | — |
| P1 | 1（§20.3 closed set 漏れ） | root 修正 → re-audit **closed** |
| P2 | 3（header comment / R6 外 6 files scope / index 導線） | root 修正 → re-audit **closed** |

## R6 外 6 ファイル（portability / test determinism prerequisite）

R6 機能追加ではない。Linux GCC13 / Clang18 / macOS CI を **同じ厳格設定**で通すための移植性・テスト決定性 prerequisite。  
**テスト緩和ではない。** 既存意味・期待値・件数を保持する。

| path | 理由（1 行） |
| --- | --- |
| `src/model/domain_store_body_codec.c` | callee write を GCC が追えない保守解析向け zero-init |
| `tests/port/posix_usb_serial_test.c` | EINTR/EAGAIN/partial I/O を正確に扱い PTY test を決定化 |
| `tests/support/typed_simulated_bearer.c` | 同じ保守解析向け zero-init |
| `tools/abi_drift_schema.c` | GCC13 `-Wformat-truncation` を bounded copy で除去 |
| `tools/operator_projection_schema.c` | 同上 |
| `tools/profile_r5_gate.py` | `build-*` を copytree から除外し自己再帰 / 巨大コピーを防止 |

## Pre-status audited base hashes（full audit target; frozen）

Independent re-GO が対象とした **pre-status** sha256。status finalization 後も **監査済み base** として残す。

| artifact | sha256 |
| --- | --- |
| context.c | `4686edcb01f5d16aa5b1649db938e80eccbef9ded8add1b62ab3c8ddb97c267d` |
| context.h | `1901a595b29e91af938cfa1f9acc0cc7eaf8151698eb44885c08b8d38833844c` |
| context test | `3216c40f89e7a2567f7e1394687fcbe75d8a32f8191e73eebcd2086dd6813b2e` |
| crypto | `bdbb9a2bf2cc860101da41d2425192904c12c7f42fd2fcf77b3c42716bdc71b2` |
| codec.c | `01c82e48612d030fa61a25549827467664bcc66c9ca053ff166511cf27ec346c` |
| codec.h | `2b181c32e3a2ce43634a401af27cc7f52ed5b4b96f8b86597a35006a1f10060d` |
| codec test | `b301f0879cb6d8f882ad7db47688ec9821fcd7b83e7607b9d5ab59d2db6a16b1` |
| docs30 (pre-status) | `a63f43db8cd9fc396ca05677b2d240c5ddfea526a95aa7fadc4ff57c56969f14` |
| ADR-0010 (pre-status) | `d5c4cf14ffd9bc6a042a1540aa00790f48151da6075d40a1c07cc8e46dc5a6c6` |
| storage gate | `56d4aaa9d26f33f74674876cc534b1d27c9242ae24e952ca0bf5802483e1545c` |
| storage selftest | `6be7b1d54ab7b93ee8965fb2529fbec0488123dac1a0f9c383d69b5f0c555a06` |
| docs07 | `9cde313317cbe2a3dd2952de6635a56302629bd9534c4aa4af8e953f7a5bfac9` |
| chunk gate | `1585a2e8ffce98fb9144d4abe6f9f67c6ae3c658a5efa882f16cf73029e373c1` |
| frame gate | `cba2321d6e66a793a30b026708ca1ba8dcdefba340d8a3be0430b7b444f69221` |
| packaging cmake | `27dc73ffcb5649fd40ceffb4111e3408e8e512b5e84e7ada2370434babae8299` |

## Status-only final hashes（post finalization editorial）

status / progress / review index / gate のみの最終化後 hash。**本記録自身の hash は不要。**  
（記入後に再計算し一致確認する。）

| artifact | sha256 |
| --- | --- |
| docs30 | `91d37378ae14baa0a9565a52225c1950f739aadb0f02da98bd8990a1e7c89666` |
| ADR-0010 | `3798a2d74c2d387004a74177e06aa62130cee8923098853951050f2fd42e56ba` |
| radio_wire_r6_docs_gate.py | `22e1a93e3da2cd6a0b3cb5d176e50bcefa713690ea4a5e1fd6c4e65b81e5c003` |
| README.md | `833f697c671e747681c6e900d03a27f6671045d8334c2f746ef90595dbb2cee1` |
| docs/README.md | `b3fd03c5c145d5af7c48fa762cd97e6742722c6e494c6d396958ca779bc33e07` |
| docs/09-roadmap.md | `5766a6163dbf388699e4cd25cd484b7c89c6044a7088ca4c3de5fe70c5441384` |
| docs/23-usb-radio-boundary.md | `ae9f8491831319b353ab599b4ece311fe3ee8682b89f378f6e76afced43d994d` |
| docs/adr/README.md | `b74752de04617d45edd038dd47f3cab037a85bb8684e45aeb4dd457ee2258110` |
| docs/reviews/README.md | `ea7275e513f38b4d2ea0665688af001f698a7e932b0c3b17f6cb751aa4bd1a12` |
| CHANGELOG.md | `ae7a943a7a7a42cc9feb864e691c4a95cc09994ca3b7c7e3010ca67c24a6aa26` |
| `.gitattributes` | `bfd1ca7391ceb8dafafffc71483532e12335d19dd96f1abf1e46903334dacab0` |
| context test (post-audit whitespace-only) | `d508406c0b00f8057828fcb712a0482d6f589d11990dc4b01dab9c2228a4258b` |

### Integration whitespace hygiene delta

- CommonMark hard-break の行末2スペースを仕様どおり許可する `.gitattributes` を追加。他の Git whitespace 検査は維持。
- `n6_context_store_test.c` と docs gate の空白だけの行から不要な空白を除去。context test の pre-status hash は監査対象履歴として上表に保持し、post-audit hash を本表へ別記。
- docs30 は EOF の余分な空行だけを除去。wire layout / API / constants / semantic token は非変更。

## Evidence（root 実測）

| check | result |
| --- | --- |
| macOS Release | 182/182 |
| focused ASan/UBSan | 2/2 |
| Linux GCC13 | 181/181 |
| Linux Clang18 | 181/181 |
| official ESP-IDF v5.5.3 smoke + HIL firmware | compile/link and stack/public/private/map/USB gates **PASS** |
| R6 focused | 18/18 |
| docs mutation | 286/286 caught（status finalization rollback / overclaim mutationsを含む） |
| storage authority self-test | PASS |

**明示:** compile/link **≠** HIL。上記 ESP は firmware compile/link と gate PASS のみ。実機 HIL 完了は主張しない。

## R6 docs freeze Accepted vs remaining incompletes

| 完了 | 未完 |
| --- | --- |
| R6 docs freeze **Accepted** / Stage 9 | R7 full AEAD codec |
| independent re-GO P0=P1=P2=0（integration + storage pin） | M4 / M5 handshake 実装 |
| Chunk D host candidate **fixed-hash integration GO** | ESP N6 capacity |
| historical 17/18 **formal superseded** | RF / USB **実機 HIL** |
| | Japan legal / production radio |

## Verdict

**R6 docs freeze Accepted.** Independent re-GO **P0=0 / P1=0 / P2=0 GO**.  
Historical 2026-07-17 / 2026-07-18 は NO-GO スナップショットとして残置し、**本記録が formal supersede** する。  
**status-only delta independent recheck P0=0 / P1=0 / P2=0 GO**（status 文言最終化後の post-review）。  
R7 full AEAD / M4·M5 / ESP capacity / 実機 HIL / legal / production **未完**。  
gate PASS ≠ GO proof; gate PASS ≠ arbitrary natural-language proof.
