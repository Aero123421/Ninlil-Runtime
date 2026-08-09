# ADR-0023: Production Attachment over EDHOC

状態: **Proposed — specification candidate（implementation / acceptance pending）**  
提案日: 2026-07-29  
SPEC_ACCEPTED日: —  
RELEASE_SUPPORTED日: —

## Context

現行のLAB joinは、factory identity、Site Membership、pre-attachment carrier、
peer authentication、Hop/E2E context installをproduction trustへ接続しない。USB、Wi-Fi、
compact radioが別々のjoinを持つと、carrier変更でidentityやdurable truthが変わり、
一部contextだけをpublishする失敗も起きる。

[feasibility record](../work/2026-07-28-production-attachment-edhoc-feasibility.md)は
RFC 9528 EDHOCと候補実装を調査したが、依存採用もproduction完成も主張していない。
本ADRはcarrier-independentなProduction Attachment契約を先に固定し、実装採用を後段の
証拠へ分離する。

## Decision

1. Production Attachmentの認証鍵交換はRFC 9528 **method 3**、RPKをCCSで表現し`kid`で
   解決する。実装はcipher suite **2と3の両方**を実装する。1回のattemptはaccepted policyが
   exactly 1 suiteへpinし、自動downgradeしない。suite変更はfresh policy revisionとfresh
   EDHOCを要求する。peer public credential resolverとlocal static-DH private-key operatorは
   別のprivate portとする。local private keyをPortable Core、EDHOC workspace、durable
   storageへexportせず、factory identityへbindされたcopy-owned credential descriptorと
   opaque key referenceを使ってP-256 ECDHだけを実行する。local CCS/public-key digest、
   credential revision、provider generation、factory identity bindingの不一致・rollbackは
   wire出力0でfail closedする。
2. EDHOC `message_4`を必須とする。EAD_1〜EAD_4はすべてemptyだけを受理し、未知EADを
   ignoreしない。Attachment固有dataはmessage_4成功後の別のprotected exchangeで運ぶ。
3. USB、Wi-Fi、compact radioは同じ`NAC1` recordを運ぶ。USB/Wi-Fi streamは`NAS1`、
   compact radioは`NAR1`で運び、既存NFL1/NWB1/NRW1をpre-attachmentへ流用しない。
   この3 magicはNinlil全体のwire/storage namespaceで一意でなければならない。
   `NPA1`と`NPS1`はAccepted ADR-0020のmulti-parent durable recordとして既に予約済み
   なので、Production Attachmentで再利用してはならない。carrierや保存場所が異なることを
   magic衝突の許可理由にしない。repository-wide正本は
   `spec/protocol-magic-registry-v1.json`、fail-closed gateは
   `tools/protocol_magic_registry_gate.py`とする。gateはduplicate JSON keyをdecode前に
   拒否し、owner/artifact/status/authorityをclosed domain化する。machine-sourceの
   fixed roots/extensionsを走査し、全4-byte uppercase/digit literalをentryまたは理由付き
   exclusionへexact分類する。未登録、stale entry/exclusion、collision、scan弱化を拒否し、
   `NLR1/N6TX/N6RX/N6AL/N6HW`を含む既存namespaceも台帳化する。
4. compact radioの未知peerはstateless cookie challengeを通過するまでEDHOC、
   credential、install stateを割り当てない。NAC1 headerを含むCOOKIE_RESPONSEはexact
   159 bytes（88+32+2+37）で124-byte fragment payloadを超えるため、fixed 2-fragment
   cookie scratchだけはglobal/per-source quota内で許す。cookieはDoS admissionだけで
   identity/authenticationの証明にはしない。USB/Wi-Fiでcookieを省略できるのはaccepted
   carrier admissionとquotaが両方成立する場合だけ。
   pre-auth owner identityの先頭は`source_locator_digest32`であり、per-source 1、
   global 8、fixed 2-fragment scratch、token capacity 2 / refill 2 s、idle 9 s、
   current/previous cookie bucketsだけを許す。cookie成功前のidentity allocationと
   credential resolver callは0とする。
   `carrier_transcript_digest`はdocs/35 §4.1のbyte-exact SHA-256 preimage
   （label/`session_id`/`exchange_generation`/`attempt_index`/`attachment_epoch`/
   method/suite/`cookie_mode`/length-prefixed complete NAC1 entries）であり、
   例示文字列hashや曖昧なtranscript参照を禁止する。
5. receiverが自分のinbound Hop/E2E context idとminimum key generationを割り当てる。
   message_4後は、deviceからprotected `ATTACH_PROPOSE`、authorityから完全な
   `ATTACH_INSTALL`、device/authority双方のprotected confirmationの順とする。
   unprotected proposal/install、片方向confirmation、暗黙のID推測は禁止する。
6. Attachment installは、local nodeごとにHop IR/RI各4 records、E2E IR/RI各3 records、
   `PENDING` Attachment marker 1 recordのexact **15-key**を、1回のdurable `FULL`として
   installする。member complete keyは章30 canonical layoutでmaterializeし、
   unsigned-byte lexicographic順へsortする（semantic表示順は受理しない）。device/authority
   はrole-specific N6AT key/valueを持つ。dual confirmation後、同じmarkerだけを第二の
   single-key FULLで`ACTIVE`へreplaceして再読取する。現行の一方向N6 install APIを4回
   逐次呼出し、成功済みhandleを見せる実装は禁止する。これはfuture private N6/T1c batch
   ownerを必要とする。
7. 15-key `FULL_OK`、peer confirmation、marker ACTIVE replace `FULL_OK`のすべてが成立する前は
   Application DATA TX/RX、route publication、context handle publicationを0にする。
   definite failureは全候補を破棄し、`COMMIT_UNKNOWN`はwrite-set value-imageをfresh
   read-only recoveryで分類する。chosen modelは
   **WRITE_SET_OBSERVED_OLD_PROPOSED_NEW**（attachment-scoped namespaceは未採用）:
   - **EXACT_OLD**: 各write-set keyのdurableがobserved OLDと一致（marker absent;
     非marker 14 rowsは同一membership/peerの既存N6AL/N6HW/laneを含む。**OLD=0 member
     強制は禁止** — re-attachをpartial/corruptと分類してはならない）
   - **EXACT_NEW**: 全15 keyがproposed NEWと一致（PENDING 15 または ACTIVE marker）
   - **PARTIAL_n / EXTRA / THIRD**: corrupt/fenced
   N6AL floor / N6HW high-waterは単調非減少（10k attach/reattach/restartで下げない）。
   OLD cardinalityは15 rowsの`old_present`から導出し、8や14をprotocol constantにしない。
   PA-S0 fixtureは合法lane OLDを含むnon-marker 14 rows presentを意図的に使い、
   per-row OLD/NEW/STABLE/THIRDと10,000 restart cyclesを実行検証する。
   non-marker valueはcanonical N6 codec wire（N6TX/N6RX/N6AL/N6HW/N6AT）であり、
   synthetic `VALUE-V1` fillerはruntime storage/KATに使わない。
8. restart後は必ずfresh session id、exchange generation、EDHOC ephemeral、traffic secret、
   context id/key generationでやり直す。same-context resume、secret persistence、
   secret reinjectionはv1で禁止する。durable old contextはDORMANT/FENCEDのままpublishしない。
9. factory identityが`PROVISIONED`、Site Membershipが`ACTIVE`であることを前提とする。
   Attachmentはenrollment、membership作成・更新、QR secret解決を行わない。QR等が渡せるのは
   stable public identifierだけで、accepted management authorityがopaque membership claimへ
   解決する。
   PA-S0 machine contractはこれらのcopy-owned exact claimとlocal P-256 static-DH portを
   materializeするが、上流Accepted証拠が未確立なら
   `UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED`としてowner startをfail closedする。このcontract
   fixtureだけでdependency ready、real provider KAT、cryptographic interoperabilityを
   主張しない。
10. authority term、credential-set revision、revocation generation、assignment epochは
    non-regressionを要求する。leaseはtrusted clock epochと
    `not_before <= now < expires_at`で判定し、OS wall clockをauthorityにしない。
    stale/revoked/expired/authority-replaced Attachmentはold contextをfenceする。
11. control protectionはAES-CCM-16-64-128（COSE algorithm 10）を使い、direction別16-byte
    keyと13-byte base IVをprivate EDHOC exporter labels 32768〜32771から得る。Hop/E2E
    direction別traffic secretはlabels 32772〜32775から得る。labelの再利用、短縮、
    application-purpose兼用を禁止する。
12. Production Attachment ownerはcaller-owned bounded storageを使う。heap growth、VLA、
    callback reentry、borrowed credential/record pointer保持を禁止する。credential、
    ephemeral、PRK、exporter secret、traffic secret、plaintext copyはterminal pathで
    zeroizeする。詳細contractは[35章](../35-production-attachment-edhoc-profile.md)を正本とする。
13. PA-S0のsuite 2/3 `message_1..message_4`はprofile state-machine fixtureであり、
    `SYNTHETIC_PROFILE_STATE_MACHINE_NOT_CRYPTO_KAT`と明示する。Message 4前exporter 0、
    EAD_1..4 non-empty terminal、downgrade自動retry 0をmachine gateする。RFC 9529 traceは
    algorithm referenceでありprofile negotiation positiveではない。
14. NAR1 owner keyはsource locatorを含み、固定5 slotsへ実際にpacketを投入してreorder success、
    duplicate no-progress、conflict/gap/overlap/mixed/timeout/source/inner mismatchの
    zero-publicationを証明する。NAS1は612-byte incremental ownerでpartial successと
    short/trailing/future/inner-carrier failureを実行する。outcome文字列だけを証拠にしない。
15. pre-auth fixed two-fragment scratchはPython/Node/C11で実遷移させる。fragment 0/1、
    same duplicate、conflicting duplicate terminal release、completion release、
    per-source 1/global 8/token capacity 2、1999/2000 ms refill、8999/9000 ms idle、
    current/previous/older cookie bucketを含む31 transitions / 17 branchesを固定し、
    全branch countをnon-zeroにする。older bucketは既存scratchもterminal releaseし、
    cookie成功前のidentity allocation/credential resolver callは常に0とする。

## Dependency direction

```text
accepted factory identity + accepted Site Membership + trusted clock/policy
  -> pre-attachment carrier (NAS1 or NAR1)
  -> bounded Production Attachment owner
  -> EDHOC method 3 / suite 2 or 3 / message_4
  -> protected PROPOSE -> INSTALL -> dual confirmation
  -> future sole private T1c/N6 15-key FULL batch owner
  -> FULL_OK + peer confirmation
  -> opaque Attachment/context handles
```

Portable Coreへsocket、ESP-IDF、SX1262、EDHOC library type、credential backend handleを
露出しない。KDF、carrier、storage、clock、credential resolverはprivate portsから注入する。

## Consequences

- 1つのApplication Data契約をUSB、Wi-Fi、LoRaの上に載せられ、carrier変更でidentityを
  再定義しない。
- compact radioで大きいinstall recordを送るため最大5 fragmentsを要する。
- 現行T1c/N6の一方向fresh installは再利用可能な下位部品だが、現行APIをそのまま
  Production Attachment ownerにしてはならない。
- relay、multi-parent、route optimizationはAttached後の別仕様であり、Production
  Attachment成功を推測する根拠にならない。
- composable public modulesのIdentity/Membership/Attachment dependency closureは
  [ADR-0028](0028-composable-public-runtime-modules.md)自身のreview laneで閉じる。
  PA-S0 repairはそのADRを自己Accepted化せず、ここでは依存方向だけを参照する。

## Open evidence register

以下は**仕様の未決定ではなく、実装・受入証拠の未完**である。完了前に本ADRをAcceptedまたは
RELEASE_SUPPORTEDへ変更しない。

| ID | OPEN evidence | close condition |
| --- | --- | --- |
| PA-O01 | EDHOC dependency未採用 | exact source/license manifest、diff gate、独立review |
| PA-O02 | bounded allocator未実証 | 全allocation point failure、peak/live bytes、zeroization、Host/ESP evidence |
| PA-O03 | suite 2/3 crypto adapter未実装 | RFC 9529 + independent KAT + Host/ESP cross-provider equality |
| PA-O04 | peer credential resolver / local static-DH key operator未実装 | unknown/stale/revoked/rotation、local public/private mismatch、provider-generation rollback、key-export禁止、reentry mutation gates |
| PA-O05 | NAS1/NAR1 owner未実装 | loss/reorder/duplicate/timeout/join-storm tests |
| PA-O06 | 15-key N6 batch owner未実装 | exact write-set、fault-at-every-op、COMMIT_UNKNOWN restart matrix |
| PA-O07 | protected exchange AEAD未実装 | nonce/AAD/ciphertext KAT、dual-confirmation state matrix |
| PA-O08 | physical HIL未実施 | Linux/macOS USB、ESP32-S3 Wi-Fi、ESP32-S3+SX1262 target E2E |
| PA-O09 | field/legal未完 | separate deployment evidence; protocol acceptanceから自動導出しない |
| PA-O10 | independent acceptance review未実施 | Proposed snapshot固定後P0=P1=P2=0 |

PA-S2aはPA-O03を分解するprivate candidateであり、PA-S2を完了しない。exact libedhoc
`edhoc_keys`の4-byte opaque key id、fixed raw-key slot、closed suite 2/3 contextを通じて、
SHA-256、HKDF-SHA-256、suite 2 AES-CCM-16-64-128、suite 3
ChaCha20-Poly1305だけを検証する。ECDH/signature callbacksはnon-NULL fail-closed stubで、
credential resolver/local static-DH/EDHOC handshakeの証拠ではない。Host KAT、ESP compile、
ESP target KATは別statusであり、target KAT前にHost/ESP equalityまたはsuite 3 target
correctnessを主張しない。既存R7 crypto ABIは変更・流用しない。

## Non-claims

本ADRとmachine-readable vectorは、dependency adoption、実装、public ABI、EDHOC
interoperability、cryptographic correctness、ESP-IDF build、USB/Wi-Fi/RF HIL、relay、
multi-parent、same-context resume、field、legal、production supportを主張しない。
