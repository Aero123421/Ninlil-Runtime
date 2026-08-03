# Production Attachment fresh re-review NO-GO repair

日付: 2026-07-31  
対象: Proposed ADR-0023 / docs 35 / PA-S0 machine authorities  
起点:
[`2026-07-31-production-attachment-repair-rereview.md`](../reviews/2026-07-31-production-attachment-repair-rereview.md)  
状態: **P1=1 / P2=2 repair candidate complete; fresh independent closure review pending**

## Scope and immutable evidence

fresh independent re-reviewの判定 **NO-GO P0=0 / P1=1 / P2=2** は変更していない。
baseline reviewとfresh re-reviewはimmutable recordとして保持した。本記録は3 findingsへの
repair candidateとlocal software evidenceだけを記録し、独立closureやAccepted promotionを
自己宣言しない。

Grok Buildその他の外部AI CLIは使用していない。この作業単位ではcommit/pushしていない。

## Repairs

### P1: pre-auth scratch/token lifecycle

- fixed 8 scratch / per-source 1 / fixed 16 token-owner tableをPython、Node.js、C11で別々に実装。
- exact 31 input transitions / 17 branchesを実行:
  fragment 0/1、same duplicate、conflicting duplicate terminal release、complete release、
  per-source/global quota、token capacity deny、1999/2000 ms refill、8999/9000 ms idle、
  current/previous bucket、older bucket with/without existing owner。
- 各行でresult、branch mask、active/global/source count、source tokens、received mask、
  expiry delta、completion/release/terminal counters、identity/resolver call 0を比較。
- C-owned coherent probesはsame→conflict payload、2000→1999 ms、older→current bucketを
  input側だけ変更し、実行結果が変わることを確認。

### P2: global magic registry

- strict duplicate-key JSON loaderとclosed root/policy/domain/scan/entry/exclusion schema。
- `owner` / `artifact` / `status` / `authority` / exclusion reasonをclosed value domain化。
- machine source 7 roots / 11 extensionsをrecursive scanし、4-byte uppercase/digit literalを
  exact 65 global entriesまたは理由付き97 exclusionsへ分類（162 candidates）。
- `NLR1`、`N6TX`、`N6RX`、`N6AL`、`N6HW`、PA、Fabric、MFDT、route/multi-parent、
  Wi-Fi、ESP/POSIX storage/transportを同じglobal collision namespaceへ登録。
- Python self-test 14件:
  collision、reserved PA theft、required/machine entry missing、unknown owner/status/authority、
  boolean artifact、entry/exclusion overlap、duplicate exclusion、stale entry、scan弱化、
  duplicate JSON status key、undeclared repository literal。
- Node.js authorityも同じclosed domainsとrepository inventoryを独立走査する。

### P2: independent transition-specific authority

- expected-modelからcomposition importを除去し、fixtureとは別の固定byte SHAと独立authorityで
  generator defect / fixture editを分離。
- Python/Nodeはpre-auth transitionを独立実行。C11は全9 local-key failure rows、
  全4 EAD stage、downgrade、pre-auth transitionをrow/input単位で実行。
- repaired coherent adversarial campaignを12から16 trialsへ拡張し、refill境界、
  duplicate/conflict、older bucket、branch coverage driftを追加。

## Verification

Vector SHA-256:
`11e3e8dcbbd6bdc331c13e0818aa5dadb87f1840c9e46e7d7b961ee816972962`

Normal focused CTest (`build-pa-recheck`):

```text
production_attachment_edhoc_vector_oracle              PASS
production_attachment_edhoc_vector_oracle_self_test    PASS
production_attachment_edhoc_python_gate                PASS
production_attachment_edhoc_python_gate_self_test      PASS
production_attachment_edhoc_node_gate                  PASS
production_attachment_edhoc_node_gate_self_test        PASS
production_attachment_magic_registry_gate              PASS
production_attachment_magic_registry_gate_self_test    PASS
production_attachment_edhoc_c11_gate                   PASS
production_attachment_edhoc_fixture_freshness          PASS
10/10 PASS
```

False-green / mutation evidence:

- Python: mutations **9,346**、object paths **829**、unknown-key **829/829** rejected、
  scalar leaf **8,418**、false green **0**。
- Node.js: mutations **9,341**、object paths **829**、unknown-key **829/829** rejected、
  scalar leaf **8,418**、false green **0**。
- independent repaired coherent campaign: **16** trials。
- global magic registry: entries **65**、explicit exclusions **97**、
  scanned candidates **162**、mutants **14/14 rejected**。
- strict C11: **70** executed acceptance IDs。pre-authは31 transitions / 17 non-zero
  branchesと3 C-owned coherent input probesを実行。

Sanitizer evidence (`build-pa-san-recheck`):

```text
NINLIL_ENABLE_SANITIZERS=ON
production_attachment_edhoc_c11_gate 1/1 PASS
executed_cases=70
```

Additional freshness/tool checks:

- vector generator `--check`: fresh
- vector generator `--self-test`: PASS
- Python `py_compile`: PASS
- Node.js syntax check: PASS
- expected-model fixed-vector comparison: PASS

## Remaining evidence and non-claims

- 本repair後のfresh independent closure review
- accepted EDHOC dependency/source/license、bounded allocator、real suite 2/3 provider KAT
- production credential resolver/local static-DH/NAR/NAS/EDHOC/N6 batch owners
- protected exchange real AEAD/fault-at-every-operation
- Linux/macOS USB、ESP32-S3 Wi-Fi、ESP32-S3+SX1262 physical HIL
- field/legal deployment evidence

ADR-0023とdocs 35は **Proposed** のまま。physical HILは **NOT_RUN**。
`SPEC_ACCEPTED`、implementation complete、cryptographic interoperability、
production/release supportを主張しない。
