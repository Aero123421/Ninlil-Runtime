# R7 T1 NRW1 SINGLE private pure wire codec — Accepted review record

**Date:** 2026-07-19  
**PR:** [#101](https://github.com/Aero123421/Ninlil-Runtime/pull/101) (`codex/r7-wire-codec-t1`)  
**Audited implementation SHA:** `b3d367e7ac57d420894797517283dbca8d827eeb`  
**状態:** **Accepted — R7 T1 private pure SINGLE codec implementation candidate only**

## Independent review result

| review | P0 | P1 | P2 | verdict |
| --- | ---: | ---: | ---: | --- |
| PRE-CI implementation / false-green audit | 0 | 0 | 0 | **GO** |
| POST-CI implementation / evidence / final delta audit | 0 | 0 | 0 | **GO** |

POST-CI監査は固定SHA、origin、PR head、4 workflow run、24 check entriesが同一であることを確認した。
最初のGCC警告後のdeltaは、equal-width GCCが`-Wtype-limits -Werror`で拒否する冗長な
`UINTPTR_MAX + 1`自己確認だけを除去した。production predicate、domain境界、alias、callback、
mutation-zeroの保証は変更していない。

## Official CI evidence

| workflow | event | run | jobs | result |
| --- | --- | ---: | ---: | --- |
| CI | push | `29683705762` | 11 / 11 | success |
| CI | pull_request | `29683707058` | 11 / 11 | success |
| ESP-IDF | push | `29683705743` | 1 / 1 | success |
| ESP-IDF | pull_request | `29683707056` | 1 / 1 | success |

すべてのrunは上記SHAを実行した。Linux GCC 13 / Clang、macOS AppleClang、ASan/UBSan、
pointer-compare sanitizer、tests-OFF install/package、ESP-IDF v5.5.3 ESP32-S3 final-ELFを含む。

## Fixed acceptance evidence

| evidence | result |
| --- | --- |
| T1 subset vectors | exact 7、digest `0b564f6bc0f7b244d61042a662cc16bee7ea87db7c98961ae20d184e34aa8b35` |
| focused CTest | normal exact 13 / 13、sanitizer exact 12 / 12 |
| local full CTest | Release 212 / 212、ASan/UBSan 209 / 209 |
| production private API | exact 8、tests-OFF test seam 0、public/install leakage 0 |
| GCC 13 stack authority | exact `-O2` + `-fstack-usage`、required production最大観測864 bytes、ceiling 2560 PASS |
| local AppleClang stack | production最大観測800 bytes、ceiling 2560 PASS |
| independent oracle | stdlib-only self-test/verify、deterministic generation、production bridge全PASS |

## Acceptance boundary

| Accepted | Not accepted / pending |
| --- | --- |
| outer AAD19 / E2E AAD14 pack・parse | 30章 §18.15–16 full wire/state artifact |
| DATA/SINGLE dual-envelope 4 Seal/Open layer API | counter/storage/replay/durable admission |
| failure mutation zero / layer atomic publish / alias拒否 | FRAG / LINK_ACK / CELL / HA |
| Host OpenSSL 3 bridge + ESP mbedTLS final-link | W1 / L1、M4 / M5 |
| private packaging / platform / stack / exact CTest gates | ESP実機KAT、RF/USB HIL、Japan legal、production radio |

## Verdict

**R7 T1 private pure SINGLE codec implementation candidate Accepted.**  
独立PRE-CIおよびPOST-CI監査は **P0=0 / P1=0 / P2=0 GO**。このAcceptedはT1 sliceだけを
対象とし、R7全体、実機、法令適合、production radioの完成を意味しない。compile/link ≠ HIL。
