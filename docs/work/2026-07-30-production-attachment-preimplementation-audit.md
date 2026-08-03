# Production Attachment pre-implementation audit

日付: 2026-07-30  
対象: Proposed ADR-0023 / docs/35  
判定: **NO-GO for implementation / Accepted promotion**

## Findings

### PA-P1-01 — protocol magic collision

Production Attachment candidateの`NPA1` / `NPS1`がAccepted ADR-0020のdurable
multi-parent recordsと衝突していた。`NAC1` / `NAS1` / `NAR1`へ再採番し、generator、
vector、Python/Node/C11 gatesを同期した。詳細と8/8 PASSは
[magic namespace repair](2026-07-30-production-attachment-magic-namespace-repair.md)
を参照する。

状態: **repaired; independent re-review pending**

### PA-P1-02 — local static-DH credential authority missing

旧candidateはpeer public credential resolverだけを記述し、method 3で必須となるlocal
static private keyを、factory identity・canonical CCS/public key・credential revisionへ
どうbindして利用するかを定義していなかった。これでは実装者がraw private key export、
process-global key、またはcredential resolverへの曖昧な兼用を選べてしまう。

ADR/docsへ次を追加した。

- peer public credential resolverとlocal static-DH private-key operatorを分離
- copy-owned local credential descriptor
- factory stable identity、canonical CCS/public-key digest、credential revision、
  provider generation、opaque key referenceのbinding
- P-256 ECDHだけを許可し、private scalar/backend pointerをexportしない
- wrong key binding、generation rollback、reentry/partial outputをwire 0でfail closed
- ECDH resultのbounded ownershipとzeroization

状態: **Normative prose repaired only**。exact private-port shape、machine vector、
Host/ESP provider KAT、public/private mismatch/rollback/reentry negatives、独立reviewが
未完なので、PA-S1/PA-S2開始前に閉じる。

## Remaining review questions

1. local credential descriptorとFactory Identity moduleのsole authority
2. opaque key referenceのrestart/rotation semanticsとbounded size
3. providerがpublic/private key bindingを証明するexact contract
4. EDHOC dependency adapterがprivate keyを内部heapへcopyしないことの証拠
5. suite 2/3双方のHost/ESP cross-provider KAT
6. PA magicを含むrepo-wide namespace registry/gate

ADR-0023はProposed、PA-S0はin progressのまま維持する。runtime、dependency adoption、
HIL、Production supportは主張しない。
