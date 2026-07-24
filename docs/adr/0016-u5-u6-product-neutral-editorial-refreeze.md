# ADR-0016: U5/U6 Product-Neutral Editorial Re-Freeze

状態: Accepted<br>
決定日: 2026-07-24

## Context

U5/U6のNormative文書は、`spec/frozen/u5-u6-normative-freeze-v1.json`でexact bytesを固定しています。一方、独立した汎用OSSとして公開する現行文書には、個別製品を前提にしない語彙が必要です。

凍結済み文書を黙って書き換えたり、既存pinを上書きしたりすると、Normative contractの改変とeditorial changeを区別できません。製品非依存化だけを行い、algorithm、順序、数値、wire、storage、API、規範上の主張が不変であることを独立監査とmutation gateで証明する必要があります。

## Decision

1. `docs/25-u5-cell-operating-assignment.md`、`docs/26-u6-transport-custody.md`、`docs/adr/0005-u5-cell-operating-assignment-control-v2.md`の計4行だけを製品非依存の語彙へ変更する。
2. `docs/adr/0006-u6-transport-custody.md`は変更しない。
3. v1 manifestは履歴として保持し、現行bytesを`spec/frozen/u5-u6-normative-freeze-v2.json`で新たに固定する。
4. v2は4文書の`byte_length`と`sha256`だけを現行bytesへ更新する。L6 body/hash、ordered phases、declarations、constraints、authority prose、document paths、schema、hash algorithmはv1と同一にする。
5. `tools/u5_u6_docs_gate.py`はv2 manifestとmanifest digestをpinする。`tools/radio_wire_r6_docs_gate.py`のdocs/25 cross-pinも同じbytesへ更新する。
6. 本変更は[独立レビュー](../reviews/2026-07-24-u5-u6-product-neutral-refreeze.md)の`P0=0 / P1=0 / P2=0 GO`を受入根拠とする。

## Consequences

- U5/U6のNormative meaning、実装状態、互換性、wire/storage/API contractは変わらない。
- 実装完成、HIL、legal、production readinessの新しいclaimは発生しない。
- v1 manifestと過去のGit履歴は改変しない。
- 今後のNormative bytes変更には、別のfreeze version、Accepted ADR、独立レビュー、gate pin更新が引き続き必要である。

## Related

- [U5 CellOperatingAssignment](../25-u5-cell-operating-assignment.md)
- [U6 Transport Custody](../26-u6-transport-custody.md)
- [ADR-0005](0005-u5-cell-operating-assignment-control-v2.md)
- [ADR-0006](0006-u6-transport-custody.md)
- [Independent editorial re-freeze review](../reviews/2026-07-24-u5-u6-product-neutral-refreeze.md)
