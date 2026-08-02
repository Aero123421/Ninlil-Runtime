# 2026-07-29 Domain Store schema 1 SPEC_ACCEPTED review

状態: **SPEC_ACCEPTED review GO — P0=0 / P1=0 / P2=0**

この記録は、ADR-0022の設計受入に対する独立レビュー結果です。
`SPEC_ACCEPTED`はexact designとmachine authorityの受入だけを意味します。
Runtime実装、target、HIL、migration、または`RELEASE_SUPPORTED`を主張しません。

## Reviewed authority

- [ADR-0022](../adr/0022-domain-store-schema1-runtime-binding.md)
- `spec/vectors/domain-store-schema1-runtime-binding-v1.json`
- `tools/domain_store_schema1_binding_vector_gen.py`
- `tools/domain_store_schema1_binding_gate.py`
- `tools/domain_store_schema1_binding_gate.mjs`
- `CMakeLists.txt`

## Domain review manifest authority

algorithm: `ninlil-domain-review-manifest-v1`

Ordered members (JSON → Node gate → Python gate → generator):

1. `spec/vectors/domain-store-schema1-runtime-binding-v1.json`
2. `tools/domain_store_schema1_binding_gate.mjs`
3. `tools/domain_store_schema1_binding_gate.py`
4. `tools/domain_store_schema1_binding_vector_gen.py`

Framing (per member, UTF-8, concatenated in order):

```text
{path}\n{byte_length_decimal}\n{sha256_hex}\n
```

`manifest_sha256` = SHA-256 hex of the concatenation of all four frames.
`json_sha256` = SHA-256 hex of member (1) alone.

check_command: `python3 tools/domain_store_schema1_review_manifest_gate.py check`

json_sha256: `b65774346dd1ae4c46d082c561d6c7086c86dbd44d01a37e50464eb04fafbc29`
manifest_sha256: `480e878733a6e39ba6e2cca57a1ead8483eb116bd96e0fafe125683bd3cb4825`

## Closed findings

1. StartupをT0、T1a、T1b、T2、T3、T4、T5、T6、T7へ分離し、
   T5/T6完了前のBearer、callback、handle、publishを0にした。
2. LAB 34 kind、136 mutation、cross-row、metadata、MIXED、provider duplicateを
   raw row/namespaceから独立分類する。
3. framing-validな将来format/schema/versionは`UNSUPPORTED`、
   length/CRC/framing/key-family binding破損は`STORAGE_CORRUPT`へ分離する。
4. NTS3とM4Tは、将来schema/version判定より先にcurrent framingの
   key/body bindingを検証する。
5. owner、failure domain、依存方向、既存Accepted contractの優先、
   alternatives、D22-01〜D22-08、S1〜S6 traceをADRへ固定した。

## Independent verification

- generator check / self-test: **PASS**
- Python gate check / self-test: **PASS**
- Node gate check / self-test: **PASS**
- 空build directoryからのfocused CTest: **6 / 6 PASS**
- startup 13 case、closed-status 13 caseの独立再計算: **PASS**
- NTS3 / M4T future key末尾変更の4通り:
  Python / Nodeとも`STORAGE_CORRUPT`で拒否
- `git diff --check`: **PASS**

## Verdict

ADR-0022のS1〜S6は、最終snapshotに対して
**P0=0 / P1=0 / P2=0、SPEC_ACCEPTED GO**。
後続実装でNormative変更が必要になった場合はProposedへ戻し、再受入する。
