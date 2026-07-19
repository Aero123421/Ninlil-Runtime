# ADR-0011: R7 Private Crypto Provider Boundary

状態: **Accepted**  
提案日: 2026-07-19  
受入日: 2026-07-19（R7 T0 private crypto provider implementation candidate only）  
非主張: R7 full codec/W1/L1、M4/M5、ESP実行、RF/USB HIL、Japan legal、production radio

## Context

R7 は AES-128-GCM を必要とするが、production C に新しい手書き AES/GHASH を導入すると、
既知 vector を通っても side-channel、認証前 publish、failure mutation、実装差のリスクが
残る。一方、R6 N6 host candidate の3 production sourcesは固定 hash で受入済みであり、
T0 で provider shape を直接変更すると R6 の証跡を壊す。

## Decision

1. R6 N6 sources/provider は不変に保ち、R7/W1 専用の versioned private provider ABI v1 を
   新設する。統一移行は独立した後続 tranche とする。
2. portable wrapper が validation、exact capacity、alias、candidate-before-publish、failure
   mutation zero、zeroization を所有する。
3. cryptographic primitive は Host Linux/macOS で OpenSSL 3、ESP-IDF で mbedTLS adapter に
   委譲する。production 手書き AES/GHASH を禁止する。
4. provider ABI は exact version/size/reserved と SHA-256、HKDF Extract/Expand、raw
   AES-128-GCM Seal/Open callback を持つ。private only、fail closed とする。
5. Open は認証成功前に caller plaintext へ書かず、Seal/Open とも内部 bounded candidate
   成功後にだけ publish する。全 failure で caller output/length/input mutation zero。
6. 独立 stdlib Python oracle、固定 KAT、negative/mutation gates、platform source split、
   tests-OFF leakage、ESP compile separation を受入条件とする。

Exact contract、limits、status、test matrix、非主張は [docs/31](../31-r7-crypto-provider-and-aead.md)
を参照する。

## Consequences

- portable Core は crypto library と OS に依存しない。
- Host/ESP adapter は platform library に private dependency を持つ。
- 一時的に N6 provider と R7 provider の2 private familyが存在する。これは暗黙の ABI 破壊
  より安全だが、重複の統一には別ADR/移行監査が必要。
- OpenSSL/mbedTLS の保証を越える side-channel claim は行わない。
- R7 T0 private crypto provider implementation candidateは、push/PR/ESP-IDF CI全成功と
  独立POST-CI監査 **P0=0 / P1=0 / P2=0 GO**によりAccepted。R7全体の未完了範囲は
  [docs/31 §12](../31-r7-crypto-provider-and-aead.md)に従う。

## Rejected alternatives

- **production手書きAES/GHASH:** 検証負担とside-channel riskが過大。
- **R6 N6 providerをT0で直接拡張:** 固定hashと受入証跡を破壊する。
- **認証前にcaller outputへ復号:** bad tag/backend failureでplaintextを公開し得る。
- **failure時caller outputをzero-fill:** mutation zero契約に反する。

## Related

[docs/31](../31-r7-crypto-provider-and-aead.md) ·
[docs/30](../30-r6-secure-radio-wire.md) ·
[ADR-0010](0010-r6-secure-radio-wire.md) ·
[docs/05](../05-security-and-compliance.md) ·
[docs/07](../07-testing-and-quality.md)
