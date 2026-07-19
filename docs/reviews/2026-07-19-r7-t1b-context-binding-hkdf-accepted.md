# R7 T1b context binding / verified HKDF schedule — Accepted review record

**Date:** 2026-07-19  
**PR:** [#103](https://github.com/Aero123421/Ninlil-Runtime/pull/103) (`codex/r7-t1b-implementation`)  
**Audited implementation SHA:** `ec4c39ec5d37176de63646f5bcc9d48140684760`  
**状態:** **Accepted — R7 T1b private stateless context binding / verified HKDF implementation candidate only**

## Independent review result

| review | P0 | P1 | P2 | verdict |
| --- | ---: | ---: | ---: | --- |
| PRE-CI implementation / false-green audit | 0 | 0 | 0 | **GO** |
| POST-CI implementation / evidence / final delta audit | 0 | 0 | 0 | **GO** |

POST-CI監査はlocal HEAD、origin branch、PR head、4 workflow runが上記固定SHAで一致し、
worktreeがcleanであることを確認した。修正前監査で検出したKAT pin、成功時tail、digest全byte比較、
alias試験の4件は、独立した実経路とproduction mutation gateを含めて解消済みである。

## Official CI evidence

| workflow | event | run | jobs | result |
| --- | --- | ---: | ---: | --- |
| CI | push | `29688126011` | 11 / 11 | success |
| CI | pull_request | `29688140162` | 11 / 11 | success |
| ESP-IDF | push | `29688125982` | 1 / 1 | success |
| ESP-IDF | pull_request | `29688140145` | 1 / 1 | success |

すべてのrunは上記固定SHAを実行した。Linux GCC 13 / Clang、macOS AppleClang、ASan/UBSan、
tests-OFF install/package、ESP-IDF v5.5.3 ESP32-S3 final-ELFを含む。GCC 13.3 authorityは
exact `-O2 -fstack-usage -Wframe-larger-than=2560 -maccumulate-outgoing-args`でfull CTest
224 / 224をpush/PRそれぞれで通過した。

## Fixed acceptance evidence

| evidence | result |
| --- | --- |
| T1b subset vectors | exact 24、JSON SHA `977f0911a5cb825dc860f1388fac602b223ed3ccbb4635ce4881696b94e892fe` |
| domain-separated artifact | SHA `b47b39b1a81b68982564276d0a76d178cc595777dbafdf694f299787045dc30b` |
| focused CTest | normal exact 13 / 13、sanitizer exact 12 / 12 |
| local full CTest | Release 225 / 225、ASan/UBSan 221 / 221 |
| portable / bridge | portable 3408 checks、bridge 24 / 24、digest mismatch 512 trials |
| stack evidence | GCC 13 production 6 API ≤2560 bytes、local AppleClang最大観測480 bytes |
| ESP final-ELF | production 6 APIをexact実参照、component source exact once |
| false-green resistance | KAT 14 / 14 mutations、production overcopy/digest-loop 3 / 3 mutantsを拒否 |

## Acceptance boundary

| Accepted | Not accepted / pending |
| --- | --- |
| Hop/E2E canonical binding encode + digest | expected digest / traffic secretの生成・認証・配布・保存 |
| expected-digest必須のtyped key bundle導出 | capsule parse、context install、handle、generation/rotation |
| failure mutation zero / alias拒否 / secret zeroization | counter、nonce、AEAD、replay、durable TX/RX state |
| private packaging / platform / stack / exact CTest gates | T1 composite、W1/L1/N6/M4/M5、Attachment/Join |
| Host OpenSSL 3 + ESP mbedTLS final-link | LINK/FRAG/CELL/HA、relay/routing/MAC |
| 24-vector independent subset oracle | full R7 artifact、実機KAT、RF/USB HIL、FIELD/Japan legal、production radio |

## Verdict

**R7 T1b private stateless context binding / verified HKDF implementation candidate Accepted.**  
独立PRE-CIおよびPOST-CI監査は **P0=0 / P1=0 / P2=0 GO**。このAcceptedはT1b sliceだけを
対象とし、R7全体、実機、法令適合、production radioの完成を意味しない。compile/link ≠ HIL。
