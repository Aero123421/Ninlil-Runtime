# R7 T0 private crypto provider — Accepted review record

**Date:** 2026-07-19  
**PR:** #98 (`codex/r7-wire-aead`)  
**Audited implementation SHA:** `1458c2079f55e7bbf75ce86fc270a4ad31675bf0`  
**状態:** **Accepted — R7 T0 private crypto provider implementation candidate only**

## Independent review results

| review | P0 | P1 | P2 | verdict |
| --- | ---: | ---: | ---: | --- |
| POST-CI implementation / evidence audit | 0 | 0 | 0 | **GO** |
| Accepted editorial delta audit | 0 | 0 | 0 | **GO** |

editorial deltaはREADME、CHANGELOG、testing/roadmap/spec/index、ADR-0011、ADR indexの
状態同期だけであり、production code、public/private API、wire layout、constantsを変更して
いない。独立監査はAccepted範囲と未実装境界も再確認した。

## Official CI evidence

| workflow | run | result |
| --- | ---: | --- |
| push CI | `29676558922` | success |
| PR CI | `29676560388` | success |
| push ESP-IDF | `29676558929` | success |
| PR ESP-IDF | `29676560411` | success |

GCC 13 authorityはforced-negative configureのfail-closed、実
`compile_commands.json` / `.su`、exact `-O2`、`-fstack-usage`、
`-maccumulate-outgoing-args`、static frame ceiling 2560を確認した。R7 normal profileは
exact 16/16、Clang Release full CTest、Host sanitizer、macOS、tests-OFF packaging、
ESP32-S3 final ELF linkを含む公式jobが全てsuccess。

## Acceptance boundary

| Accepted | Not accepted / pending |
| --- | --- |
| production-private portable validation / alias / failure-mutation / zeroization wrapper | R7 full wire/state codec |
| Host OpenSSL exact 3.x adapter | counter / durable storage integration |
| ESP-IDF v5.5.3 mbedTLS compile/final-link adapter | FRAG / LINK / CELL / HA integration |
| AES-128-GCM / HKDF-SHA-256 / SHA-256 independent vectors and gates | ESP実機KAT、RF/USB HIL |
| tests-OFF private leakage and stack evidence | Japan legal、production radio |

## Verdict

**R7 T0 private crypto provider implementation candidate Accepted.**  
独立POST-CI監査とAccepted editorial delta監査はともに
**P0=0 / P1=0 / P2=0 GO**。これはR7全体、実機、法令適合、production radioの完成を
意味しない。compile/link ≠ HIL。
