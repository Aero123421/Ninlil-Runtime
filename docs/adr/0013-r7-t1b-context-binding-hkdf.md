# ADR-0013: R7 T1b Context Binding and Verified HKDF Schedule

状態: **Proposed — docs-only; implementation and acceptance pending**  
提案日: 2026-07-19  
非主張: T1b implementation、R7 full、context install、counter/storage/replay、W1/N6、M4/M5、実機HIL、legal、production radio

## Context

ADR-0011のT0 crypto providerとADR-0012のT1 SINGLE codecはAcceptedになったが、T1のcallerへ
渡すkey/IVが、どのsite、membership、attachment/security identity、direction、contextに属するかを
R6 §8どおりbyte-exactに結び付けるproduction実装はない。ここをW1/N6 installと一括実装すると、
canonical bytes、HKDF schedule、authenticated provenance、durable stateのfailure domainが混ざる。

一方、generic HKDFまたはcaller-selected labelをそのまま上位へ渡すと、Hop/E2E、DATA/ACK lane、
direction、expected digestの取り違えをAPIが防げない。

## Decision

1. T1bをproduction-private、portable C11、stateless pure binding/schedule sliceとする。
2. R6 §8のHop/E2E canonical input、FIELD/LAB matrix、digest、6 labelsをbyte-exactに実装し、
   R6/T0/T1のAccepted契約を変更しない。
3. fixed `wire_profile_id=0x11`、Hop mask `0x0003`、HKDF labelsをcaller fieldにしない。
4. canonical encode、digest、およびexpected digest必須のverified deriveだけを提供する。
   expectedなしderive、generic label、PRK、individual lane output、T1とのcomposite APIを置かない。
5. HopはDATA key/IV + ACK key/IV、E2Eはkey/IVをtyped bundleとして全成功時だけatomic publishする。
6. authenticated expected digestのprovenanceとcontext installは後続M4/N6/W1 ownerの責務とする。
   T1bはprovenanceを主張しないが、expectedなしの迂回APIは提供しない。
7. failure mutation zero、mutable-output partial alias reject、provider callback count、internal secret
   zeroization、zero heap/VLA、bounded stackを閉じる。
8. T1b専用の独立subset vector/oracleを追加する。これをfull
   `spec/vectors/r7-radio-wire-v1.json` materializationと称さない。
9. Host strict/sanitizer/oracle/mutation/package/platform/stackとESP final-linkを受入条件とし、
   既存T0/T1/R6 gateを弱めない。public ABIを変更しない。

Exact type、API、bytes、validation順、call count、test matrix、non-claimsは
[docs/33](../33-r7-t1b-context-binding-hkdf.md)を正本とする。

## Consequences

- 後続ownerはraw labelやPRKを扱わず、layer別のatomic bundleを受け取れる。
- T1bだけではtraffic secretまたはexpected digestの真正性、鍵install、nonce一意性、replay安全性を
  提供しない。
- `digest_*`はhandshake生成/照合に必要だが、install ownerがuntrusted inputから得たdigestを
  expectedとして折り返すことは禁止される。M4 capsule tokenがprovenanceを型で閉じる。
- 次trancheはauthenticated capsuleからN6 durable lane初期化、handle publishまでのstateful ownerを
  独立して受入れる。LINK/FRAG/W1 fullを同時に混ぜない。

## Rejected alternatives

- **Generic `derive(label, digest, secret)`:** APIは小さいがlayer/lane/label取り違えを許す。
- **PRKまたはindividual outputsを公開:** partial install/publishとsecret lifetimeをcallerへ漏らす。
- **Expected digest照合を完全に後段だけへ置く:** T1bにderive bypassが残る。
- **M4/N6/W1 installを同時実装:** durable recoveryとpure byte correctnessを独立監査できない。
- **T1 codecとのone-shot composite:** counter burn/replay/durable admissionを挟めない迂回経路になる。

## Acceptance boundary

このADRがmergeされても状態はProposedであり、T1b実装またはR7完成を意味しない。固定実装SHA、
全CI、ESP final-link、独立review P0=0/P1=0/P2=0を記録した後だけ、別差分でAcceptedへ変更する。
