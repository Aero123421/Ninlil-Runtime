# ADR-0012: R7 T1 NRW1 SINGLE Pure Wire Codec

状態: **Proposed**  
提案日: 2026-07-19  
非主張: R7 full、counter/storage、FRAG/LINK/CELL/HA、W1/L1、M4/M5、実機HIL、legal、production radio

## Context

ADR-0011でprivate crypto provider境界はAcceptedになったが、NRW1のwire bytesを生成・検証する
production codecは未実装である。一度にFRAG、LINK_ACK、durable state、W1 orchestrationまで
導入すると、wire byte correctnessとstate-machine correctnessのfailure domainが混ざり、独立
検証と段階統合が難しくなる。一方、header parseだけではT0 cryptoを消費せず、上位sliceの
有用な基盤にならない。

## Decision

1. R7 T1は`wire_profile_id=0x11`のDATA/SINGLE dual-envelopeだけを扱うproduction-private、
   stateless pure codecとする。
2. callerがprovider、key、IV、counter、context/route fieldを渡す。codecは生成、保存、burn、
   replay/durable admissionを行わない。
3. E2Eとouterのlayer APIを分離し、counter burn/replay/durable admissionを挟めないcomposite
   Seal/Openはproduction APIに置かない。outer Sealはstructurally validなSINGLE E2E blobだけを
   受け、raw application plaintextを直接受けるAPIを置かない。このstructural guardはE2E tagの
   真正性/provenanceを証明せず、それは後続W1 owner/slot/state invariantが所有する。
4. private wire status、exact capacity、全partial alias reject、failure mutation zero、各layer
   Openのverify-before-publishを閉じる。
5. cryptoとnonceはADR-0011 wrapperだけを使い、N6/R2/R5/HAL/platformへのcompile dependencyを
   作らない。public ABIを変更しない。
6. T1専用の独立oracleとprivate subset vectorsを追加する。このsubsetをR6 §18のfull
   `spec/vectors/r7-radio-wire-v1.json`と称さない。
7. host strict/sanitizer/oracle/mutation/packaging/stack/platformとESP final-linkを受入条件とし、
   既存T0/R6 gateを弱めない。

Exact API、wire fields、validation order、test matrix、non-claimsは
[docs/32](../32-r7-t1-nrw1-single-wire-codec.md)を参照する。

## Consequences

- W1、LINK_ACK、FRAGが再利用できるbyte codec核を、stateful runtimeから独立して検証できる。
- T1だけでは送信許可、鍵導入、nonce永続一意性、replay安全性、radio TXを提供しない。
- 後続T1bでbinding/HKDF schedule、T2以降でLINK/FRAG/W1/N6 integrationを追加する。
- full R7 materializationまでT1 subset artifactとfull normative artifactの二つの概念が存在する。
  名前と受入表示を分離し、部分成果をfull completionに見せない。

## Rejected alternatives

- **Structural header parse only:** T0 cryptoを使わず、次sliceの中核として弱い。
- **Binding/HKDF scheduleも同時実装:** environment/binding matrixを混ぜてT1のfailure domainが広がる。
- **Mini-W1またはN6統合を同時実装:** durable ownership/event/state machine監査までscopeが膨らむ。
- **FRAG/LINK/full §18一括:** 最小完結sliceにならず、未完成部分を完成扱いする危険が高い。
