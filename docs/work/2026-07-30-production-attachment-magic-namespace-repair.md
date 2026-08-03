# Production Attachment protocol-magic namespace repair

日付: 2026-07-30  
対象: Proposed ADR-0023 / docs/35 / production-attachment specification gates  
実装・production support claim: なし

## 問題

Production Attachment candidateがcarrier record/wrapperへ割り当てていた`NPA1`と
`NPS1`は、Accepted ADR-0020のmulti-parent durable assignment page / parent-set
recordと衝突していた。transportとstorageの利用箇所が異なっても、診断、fuzzing、
永続dataの識別、将来の共通decoderで曖昧になるため、4-byte magicを再利用できない。

## 修復

- carrier-independent record: `NPA1` → `NAC1`
- USB/Wi-Fi stream wrapper: `NPS1` → `NAS1`
- compact-radio fragment: `NPR1` → `NAR1`
- binding/cookie labels、fixture keys、acceptance IDs、Python/Node/C11 oracleを同じ
  Proposed revisionへ同期
- ADR-0023/docs/35へNinlil全体でmagicを一意にする規則と、ADR-0020の予約値を
  再利用しない規則を追加

旧fixtureとの黙示互換や自動migrationは提供しない。ADR-0023は未Acceptedであり、
実装も存在しないため、衝突したcandidate wireを固定する理由はない。

## 検証

- generator write/check/self-test: PASS
- regenerated vector SHA-256:
  `af46a942cbb97d9af49c49a2e962c324da5f6bee65ba7466a7aee0dfd226ea0b`
- Python closed-tree gate + mutation campaign: PASS
- Node closed-tree gate + mutation campaign: PASS
- C11 independent byte-contract gate: PASS
- fixture freshness: PASS
- CTest `^production_attachment_edhoc_`: **8/8 PASS**
- 対象差分 `git diff --check`: PASS

物理USB/Wi-Fi/RF HIL、EDHOC dependency adoption、Production Attachment runtime
implementationはこの修復では実行しておらず、引き続き`NOT_RUN` / OPENである。
