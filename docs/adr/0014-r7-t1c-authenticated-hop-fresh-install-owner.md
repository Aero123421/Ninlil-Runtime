# ADR-0014: R7 T1c Authenticated Hop Fresh-Install Owner

状態: **Proposed — docs-only（implementation / acceptance pending）**  
提案日: 2026-07-19  
受入日: —（未受入）  
非主張: R7 full、E2E install、resume/M5、W1/L1、counter/AEAD/replay、
LINK/FRAG/CELL/HA、RF/USB/LoRa HIL、legal、production radio、実装候補 Accepted

## Context

ADR-0013 の T1b private stateless binding/schedule と R6 Chunk D の N6 durable install engine
は揃ったが、production では次が未接続のままである。

1. M4 authenticated capsule / install token の provenance
2. expected digest と traffic secret の真正性
3. N6 Hop fresh 4-key FULL（DATA+ACK+N6AL+N6HW）と handle publish
4. production authority stamp（現行 raw `bind_authority_stamp` は production で必ず失敗）

一方、次を同時に混ぜると failure domain が監査不能になる。

- M4 handshake parser + M5 resume + W1 orchestration の一括
- T1b を捨てた derive 差替えだけ
- provider 統一と、T1c 以外の N6 hash-pin/semantic 移行
- raw node_id / trusted boolean を token field に載せる設計

local-identity は既に `ninlil_n6_bind_local_identity_accepted` の exact ABI / sole binder /
INIT-only 契約で閉じている。T1c はこれを変更・兼用せず、N6 が既に BOUND→BOOTED/READY
であることを前提とする。

## Decision

1. **R7 T1c** を production-private stateful **Authenticated Hop Fresh-Install Owner** とする。
   Hop 一方向 fresh install のみ。E2E / resume / M5 は別 tranche。
2. **T1c-A:** R2 accepted class-D snapshot からのみ stamp を copy-in する opaque accepted-authority
   token / ops / sole production binder（`bind_authority_stamp_accepted`）を仕様化する。
   各 token は one-shot だが、stampはsame epoch + non-regressing nowのaccepted refreshを許可する。
   1 accepted stamp generationは最大1 durable install attemptにだけ使い、次attemptはfresh tokenで
   refresh必須とする。
   raw stamp field / boolean は trust にならない。既存 raw bind は fixture/test-only +
   production fail-closed のまま。R2 sample producer / L1 full 完成は主張しない。
3. **T1c-B:** M4 が mint する incomplete Hop install token と、別 ops の one-shot consume、
   固定容量 copy-owned claim を仕様化する。claim は T1b Hop binding 全情報 + expected digest32 +
   traffic secret32 + key_generation + alloc_side を持ち、caller pointer span を保持しない。
4. local/receiver `node_id16` は M4-authenticated stable ID から N6 node-id KDF で導出し、
   direction×alloc_side の closed table で mapping する。raw node_id を token field にしない。
   bound local identity と byte 一致必須。
5. sole production install API は `ninlil_n6_install_hop_accepted`。validated T0 providerを
   call-lifetime immutable borrowで明示注入する。既存
   `install_hop` / `install_e2e` を一般 token 化しない。fixture 経路は TEST_ONLY。
   productionで許すT0 providerはHost `ninlil_r7_crypto_openssl3_provider_init` またはESP-IDF
   `ninlil_r7_crypto_mbedtls_provider_init` の成功出力だけとし、T1c callsite exact-setで固定する。
   この制限はT1c accepted-install境界固有で、T0 private ABI一般を狭めない。
   public `include/ninlil` ABI 変更なし。
   accepted stamp/install entryはopaque N6 stateを所有する`n6_context_store.c`、token/claim/T1bの
   pure preparationは新T1c TUに置く。raw authenticated capsuleを受ける記号は作らない。
6. owner 順序は exact:
   top-level prevalidation（providerを含む; token 未消費 / I/O 0）→ stamp bound 確認 → token one-shot consume →
   claim validation → node ids derive/local match → T1b verified derive（expected 必須）→
   same claim から private capsule 組立 → N6 RO precheck → stamp generation consume →
   handle id pre-reserve → 既存 N6 Hop fresh 4-key FULL →
   FULL_OK だけ handle publish。
   token は consume 開始後、OK / definite fail / COMMIT_UNKNOWN すべて terminal。
7. T1b bundle を discard して N6 derive を使うのは、same digest=salt / same secret=IKM /
   same four R6 Hop labels の同一 schedule を正本化し、cross-implementation equality oracle/gate が
   全 Hop vectors で bundle と N6 key/IV 一致を証明する場合だけ許可する。飾りの derive 禁止。
   provider 統一は別 tranche。accepted entryはN6 TUに置き、implementation acceptanceで
   limited withdrawal中のN6 candidate pinをAcceptedと仮定せず、T1c変更後のsource manifestを
   GCC13/full regression/mutation/fresh independent review付きで直接re-acceptする。
8. COMMIT_UNKNOWN は handle 0、`recover_cu` 以外禁止。ALL_PROPOSED 後は pending secret 破棄 +
   DORMANT、同 token/secret 再注入/再試行禁止。resume/M5 は含めない。
   T1c内の自動/in-place復旧はなく、M5またはtyped authority/proofを伴うretirement/reclaim後の
   fresh re-provisioningまでcontextはunavailable・TX/RX 0とする。raw operator bypassは作らない。
   rollback-proven definite non-corrupt fail / ALL_OLDはdurable non-apply証明後、fresh stamp +
   新authenticated tokenでの再試行を一律禁止しない。CORRUPT/cleanup failureはFENCED。
   READYからのmulti-context installを維持するためCU planはclosed install kind+pre-stateをcopy-ownし、
   ALL_OLDでexact復元する。**install CUの**ALL_PROPOSEDだけ全live/pending secret/handle/lease/
   ticketをzero/invalidateしてDORMANT。TX/RX CUのAccepted post-actionは変更しない。
9. ownership / zeroization / alias / reentry / failure mutation zero / heap·VLA·stack /
   storage sequence / handle lifetime / state·CU matrix / validation priority を docs/34 で exact 定義。
10. independent oracle/vector/fault/mutation/CTest/package/public ABI/GCC13 `-O2` stack /
    ESP final-ELF + ESP32-S3 target-executed crypto equality KAT gates を **定義**する。
    実装/JSON/target evidenceの存在や Accepted を偽装しない。
11. docs-only Proposedでは docs/30–33 / ADR-0010–0013 の Normative semantics / Accepted statusを
    変更しない。implementation acceptanceでは docs/30 private closed setとdocs/07/hash pinを
    同時更新し、candidate baselineに未完のGCC13、N6 full regression・mutation・独立再監査を
    必須とし、限定withdrawalを新T1c hashの受入で解消する。

Exact types、API、order、mapping、CU、gates、non-claims は
[docs/34](../34-r7-t1c-authenticated-hop-fresh-install-owner.md) を正本とする。

## Consequences

- production Hop fresh install の成功経路は authenticated token owner に一本化できる。
- local-identity と authority stamp の trust 境界が raw field から accepted adapter へ揃う。
- T1c だけでは M4 handshake、M5 resume、W1 TX/RX、AEAD 利用、E2E install、R7 full を提供しない。
- N6 / T0 の provider 二重系は一時的に残り、equality gate で schedule 一致を pin する。
- 本 ADR は **Proposed docs-only**。implementation candidate Accepted ではない。

## Rejected alternatives

- **M4+M5+W1 一括:** durable recovery / pure binding / wire orchestration を独立監査できない。
- **derive 差替えだけ:** provenance・stamp・node map・FULL linearization が残る。
- **bundle RAM 移行 + provider 統一:** provider全体の移行監査が巨大化しT1c接続を遅延させる。
- **raw token fields（node_id / trusted bool / 生 capsule）:** R6 fail-closed と local-identity
  accepted パターンを迂回する。
- **既存 `install_hop` の一般 token 化:** fixture 経路と production provenance が混線する。
- **local-identity binder の兼用・ABI 変更:** INIT-only sole binder 契約を壊す。

## Acceptance boundary

本 ADR は **Proposed**。docs-only 仕様の固定であり、次を意味しない。

- production C / CMake / vectors / CTest の実装完了
- independent review GO / review record
- E2E install、resume/M5、W1/L1、counter/nonce/AEAD/replay
- LINK/FRAG/CELL/HA、RF/USB HIL、Japan legal、production radio、R7 full

implementation candidate 受入時は docs/34 §12.5 の bar と独立 review P0=P1=P2=0、
固定 SHA、review record を要する。compile/link ≠ HIL。

## Related

[docs/34](../34-r7-t1c-authenticated-hop-fresh-install-owner.md) ·
[docs/33](../33-r7-t1b-context-binding-hkdf.md) ·
[ADR-0013](0013-r7-t1b-context-binding-hkdf.md) ·
[docs/30](../30-r6-secure-radio-wire.md) ·
[ADR-0010](0010-r6-secure-radio-wire.md) ·
[docs/31](../31-r7-crypto-provider-and-aead.md) ·
[ADR-0011](0011-r7-crypto-provider-boundary.md)
