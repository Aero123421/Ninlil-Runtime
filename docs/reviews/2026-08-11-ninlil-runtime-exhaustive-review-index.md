# 2026-08-11 Ninlil Runtime 徹底レビュー provenance index

状態: review-source provenance / exhaustive span mapping

## Authority

- review target: `9cc907fe3a384aba9bf0e984b62fa55fa1207f3f`
- received attachment: 46,448 bytes、414 logical lines、SHA-256
  `5e7154f6a1a8990e579f7275cd0353fddb2d37ec7e2a628c774b38d1da3f4512`
- repository copy: [review source](2026-08-11-ninlil-runtime-exhaustive-review-source.txt)
- completion state: [completion ledger](../work/2026-08-12-oss-review-completion-ledger.md)
- per-item evidence: [OR evidence graph](2026-08-11-ninlil-runtime-exhaustive-review-evidence.md)

Repository copyはtext fileとして末尾LFを1 byteだけ補った表現である。末尾LFを除けば
received attachmentとbyte exactになり、上記received SHA-256へ戻る。この変換と両digestは
`tools/oss_review_provenance_gate.py`が検証する。

OR IDは原文の番号ではない。原文には全項目の通し番号・総件数がなく、1つの指摘を複数の
修正境界へ分割した箇所と、複数の環境依存原因を1つの修正境界へ束ねた箇所がある。
したがって「1行の原文finding = 1 OR row」とは主張しない。次のmachine-readable mapが、
原文414行をgap/overlapなしで分類し、各修正単位へmany-to-manyで結ぶ唯一の正本である。

`context`は見出し・方法論・空行を、`observation`は変更不要の肯定的監査結果を、
`finding`は具体的な不整合を、`recommendation`は先行findingの再掲・推奨作業を表す。
Charter全体の完成ではなく、原文が具体的に指摘した欠落だけを対応ORへ結ぶ。

<!-- ninlil-oss-review-provenance-v1:begin -->
```json
{
  "schema": "ninlil-oss-review-provenance-v1",
  "review_target": "9cc907fe3a384aba9bf0e984b62fa55fa1207f3f",
  "source": {
    "path": "docs/reviews/2026-08-11-ninlil-runtime-exhaustive-review-source.txt",
    "canonical_bytes": 46449,
    "canonical_lines": 414,
    "canonical_sha256": "e912e6bd7eaa698d5313267ff058bfe27818119eb0409884ef1c21e9b7fe39ec",
    "received_bytes": 46448,
    "received_sha256": "5e7154f6a1a8990e579f7275cd0353fddb2d37ec7e2a628c774b38d1da3f4512",
    "normalization": "append-final-lf"
  },
  "ledger_path": "docs/work/2026-08-12-oss-review-completion-ledger.md",
  "spans": [
    {"start": 1, "end": 14, "kind": "context", "or_ids": []},
    {"start": 15, "end": 23, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 24, "end": 26, "kind": "finding", "or_ids": ["OR-04"]},
    {"start": 27, "end": 29, "kind": "finding", "or_ids": ["OR-25", "OR-26"]},
    {"start": 30, "end": 32, "kind": "finding", "or_ids": ["OR-09"]},
    {"start": 33, "end": 35, "kind": "finding", "or_ids": ["OR-01", "OR-02"]},
    {"start": 36, "end": 38, "kind": "finding", "or_ids": ["OR-03"]},
    {"start": 39, "end": 41, "kind": "context", "or_ids": []},
    {"start": 42, "end": 54, "kind": "finding", "or_ids": ["OR-01", "OR-02"]},
    {"start": 55, "end": 69, "kind": "finding", "or_ids": ["OR-03"]},
    {"start": 70, "end": 77, "kind": "finding", "or_ids": ["OR-03", "OR-27", "OR-29"]},
    {"start": 78, "end": 86, "kind": "finding", "or_ids": ["OR-04"]},
    {"start": 87, "end": 98, "kind": "finding", "or_ids": ["OR-05"]},
    {"start": 99, "end": 100, "kind": "finding", "or_ids": ["OR-05", "OR-06"]},
    {"start": 101, "end": 101, "kind": "finding", "or_ids": ["OR-07"]},
    {"start": 102, "end": 103, "kind": "recommendation", "or_ids": ["OR-05", "OR-06"]},
    {"start": 104, "end": 116, "kind": "finding", "or_ids": ["OR-08"]},
    {"start": 117, "end": 130, "kind": "finding", "or_ids": ["OR-09"]},
    {"start": 131, "end": 141, "kind": "finding", "or_ids": ["OR-10"]},
    {"start": 142, "end": 146, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 147, "end": 153, "kind": "finding", "or_ids": ["OR-11"]},
    {"start": 154, "end": 157, "kind": "context", "or_ids": []},
    {"start": 158, "end": 158, "kind": "finding", "or_ids": ["OR-04"]},
    {"start": 159, "end": 159, "kind": "finding", "or_ids": ["OR-36"]},
    {"start": 160, "end": 160, "kind": "finding", "or_ids": ["OR-13", "OR-17"]},
    {"start": 161, "end": 161, "kind": "finding", "or_ids": ["OR-37"]},
    {"start": 162, "end": 162, "kind": "finding", "or_ids": ["OR-32"]},
    {"start": 163, "end": 163, "kind": "finding", "or_ids": ["OR-31"]},
    {"start": 164, "end": 164, "kind": "finding", "or_ids": ["OR-20", "OR-34"]},
    {"start": 165, "end": 165, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 166, "end": 166, "kind": "finding", "or_ids": ["OR-08"]},
    {"start": 167, "end": 169, "kind": "recommendation", "or_ids": ["OR-31"]},
    {"start": 170, "end": 170, "kind": "context", "or_ids": []},
    {"start": 171, "end": 178, "kind": "finding", "or_ids": ["OR-12"]},
    {"start": 179, "end": 179, "kind": "context", "or_ids": []},
    {"start": 180, "end": 188, "kind": "finding", "or_ids": ["OR-13"]},
    {"start": 189, "end": 209, "kind": "finding", "or_ids": ["OR-14"]},
    {"start": 210, "end": 211, "kind": "context", "or_ids": []},
    {"start": 212, "end": 212, "kind": "finding", "or_ids": ["OR-03"]},
    {"start": 213, "end": 213, "kind": "finding", "or_ids": ["OR-15"]},
    {"start": 214, "end": 214, "kind": "finding", "or_ids": ["OR-18"]},
    {"start": 215, "end": 215, "kind": "finding", "or_ids": ["OR-16"]},
    {"start": 216, "end": 216, "kind": "finding", "or_ids": ["OR-13", "OR-17"]},
    {"start": 217, "end": 218, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 219, "end": 219, "kind": "context", "or_ids": []},
    {"start": 220, "end": 235, "kind": "finding", "or_ids": ["OR-19"]},
    {"start": 236, "end": 249, "kind": "finding", "or_ids": ["OR-21"]},
    {"start": 250, "end": 256, "kind": "finding", "or_ids": ["OR-22"]},
    {"start": 257, "end": 264, "kind": "finding", "or_ids": ["OR-23"]},
    {"start": 265, "end": 267, "kind": "context", "or_ids": []},
    {"start": 268, "end": 275, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 276, "end": 290, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 291, "end": 291, "kind": "context", "or_ids": []},
    {"start": 292, "end": 300, "kind": "finding", "or_ids": ["OR-24"]},
    {"start": 301, "end": 317, "kind": "finding", "or_ids": ["OR-25", "OR-26"]},
    {"start": 318, "end": 333, "kind": "finding", "or_ids": ["OR-27"]},
    {"start": 334, "end": 335, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 336, "end": 349, "kind": "observation", "or_ids": ["OR-35"]},
    {"start": 350, "end": 365, "kind": "finding", "or_ids": ["OR-28"]},
    {"start": 366, "end": 366, "kind": "context", "or_ids": []},
    {"start": 367, "end": 374, "kind": "finding", "or_ids": ["OR-29"]},
    {"start": 375, "end": 376, "kind": "finding", "or_ids": ["OR-03"]},
    {"start": 377, "end": 385, "kind": "finding", "or_ids": ["OR-29"]},
    {"start": 386, "end": 388, "kind": "context", "or_ids": []},
    {"start": 389, "end": 389, "kind": "recommendation", "or_ids": ["OR-03"]},
    {"start": 390, "end": 390, "kind": "recommendation", "or_ids": ["OR-13"]},
    {"start": 391, "end": 391, "kind": "recommendation", "or_ids": ["OR-11"]},
    {"start": 392, "end": 392, "kind": "recommendation", "or_ids": ["OR-12"]},
    {"start": 393, "end": 393, "kind": "recommendation", "or_ids": ["OR-19"]},
    {"start": 394, "end": 394, "kind": "recommendation", "or_ids": ["OR-33"]},
    {"start": 395, "end": 395, "kind": "context", "or_ids": []},
    {"start": 396, "end": 396, "kind": "recommendation", "or_ids": ["OR-09"]},
    {"start": 397, "end": 397, "kind": "recommendation", "or_ids": ["OR-15"]},
    {"start": 398, "end": 398, "kind": "recommendation", "or_ids": ["OR-21", "OR-22"]},
    {"start": 399, "end": 399, "kind": "recommendation", "or_ids": ["OR-14"]},
    {"start": 400, "end": 400, "kind": "recommendation", "or_ids": ["OR-10"]},
    {"start": 401, "end": 401, "kind": "recommendation", "or_ids": ["OR-05", "OR-06"]},
    {"start": 402, "end": 402, "kind": "recommendation", "or_ids": ["OR-08"]},
    {"start": 403, "end": 403, "kind": "recommendation", "or_ids": ["OR-30"]},
    {"start": 404, "end": 404, "kind": "context", "or_ids": []},
    {"start": 405, "end": 405, "kind": "recommendation", "or_ids": ["OR-04"]},
    {"start": 406, "end": 406, "kind": "recommendation", "or_ids": ["OR-25"]},
    {"start": 407, "end": 407, "kind": "recommendation", "or_ids": ["OR-26"]},
    {"start": 408, "end": 408, "kind": "recommendation", "or_ids": ["OR-01", "OR-02"]},
    {"start": 409, "end": 409, "kind": "recommendation", "or_ids": ["OR-24"]},
    {"start": 410, "end": 410, "kind": "recommendation", "or_ids": ["OR-31"]},
    {"start": 411, "end": 411, "kind": "recommendation", "or_ids": ["OR-20", "OR-34"]},
    {"start": 412, "end": 414, "kind": "context", "or_ids": []}
  ]
}
```
<!-- ninlil-oss-review-provenance-v1:end -->

## Charter判定の境界

- 原文158行目はCharter品質基準全体ではなく、実測欄の`fuzz 0件`をOR-04へ結ぶ。
  物理HILとRF soakは引き続き非claimであり、OR-04から完成を推測しない。
- 原文159行目は従来未収載だったためOR-36として独立させる。
- 原文161行目の「prerelease公開済み = public alpha」は、対象SHAのCharterが
  `Experimental / pre-alpha`、READMEが`プレリリースSDK`と明記していた事実と一致しない。
  OR-37はこの前提誤りと将来のpublic-alpha gateを明示し、英語Normative完成を主張しない。
- 原文162行目の「各文書」は、各top-level文書について原文言語とtranslation statusを
  中央のclosed registryへexact 1件記録する意味である。各本文へ同じmetadataを複製しない。
- 原文165行目ほか肯定的な設計・security・verification結果はOR-35のNO_ACTIONにまとめ、
  それらを修正対象や完成率へ数えない。

## 非claim

gateはspan tupleのnormalized digestとaccepted status vectorも固定し、原文mapやledger/evidenceを
coherentに書き換えて未解決・外部項目を閉じる変更を拒否する。OR-37の判定根拠である
Charter/READMEのpre-alpha・pre-release表現とpublic-alpha English exitもsentinel化する。

この索引は原文の全行が分類済みであることを証明する。個々のORが正しいこと、Charter全体、
public alpha、物理HIL、RF soak、legal/admin作業、または追加発見XR-01の完了は証明しない。
