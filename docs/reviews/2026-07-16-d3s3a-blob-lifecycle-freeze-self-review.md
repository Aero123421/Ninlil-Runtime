# D3-S3a BLOB lifecycle Normative freeze — self-review checklist

状態: **docs-only self-review（非規範）**
対象: `docs/17-foundation-domain-store.md` §18.14
日付: 2026-07-16

## Final P0-1/2/3 disposition

| ID | Issue | Resolution |
| --- | --- | --- |
| **#14** | Mode30 RR ↔ manifest ↔ DELIVERY binding / cross-delivery digest | raw80 equality + transaction_id; owner_kind=DELIVERY blob_kind=REPLY |
| **#15** | reply_kind BLOB length | RECEIPT 0..128; non-RECEIPT total_length=0 chunk_count=0 content_digest=SHA256(empty); SHA length0 ≠ skip length rules |
| **#16** | RECEIPT RESULT↔cell↔BLOB | stage/length/digest/bytes; pin cell ≤128 then stream-compare under single 4096 |

## Arithmetic

| Item | Value |
| --- | ---: |
| sizeof | **754** |
| ceiling | **768** (headroom 14) |
| outer | **9920** = 8384+448+320+768 |
| packed | **9865** ≤ 9872 ≤ 9920 |
| RECEIPT pin | `receipt_evidence_bytes[128]` + len + stage |

## Greps

```bash
rg -n "Adjudication #14|#15|#16|receipt_evidence_bytes|sizeof \*\*754\*\*|9920" docs/17-foundation-domain-store.md
rg -n "sizeof \*\*620\*\*|9792|620/640" docs/17-foundation-domain-store.md || true
git diff --check
```

Self-review author: main-spec implementer. Not Normative.
