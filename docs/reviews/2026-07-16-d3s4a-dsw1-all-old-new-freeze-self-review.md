# D3-S4a DSW1_ALL_OLD_NEW Normative freeze — self-review checklist

状態: **docs-only self-review（非規範）** — post final NO-GO private result carrier / Mode34 chunk-index semantics + §18.14 byte-exact preserve
対象: `docs/17-foundation-domain-store.md` **§18.15**
日付: 2026-07-16
Branch: `codex/d3s4-witness-freeze` @ origin/main `8f1e00a`

## Integration

| Item | Value |
| --- | --- |
| S3a §18.14 | **byte-equivalent** to `origin/main` extract（utf8 **31829**; no trailing blank before §18.15） |
| S3 | **754 / 768**, outer **9920**（unchanged） |
| S4 §18.15 | closed primary normalization（Mode17 pure rows + BLOB manifest/chunk）+ dual digest pins + Mode31/32 progression + RETIRED-header inventory + substep progress + Mode34 same-txn manifest proof + private result carrier/publication |
| S4 sizeof / ceiling | **949 / 960** |
| private scan result | append exact present/disposition u8 pair; host **56→56**（offsets52/53）, target ceiling **64**, finalize temporary stack ≤**64**; not in S4/outer arena |
| full outer | **10880** = 8384+448+320+768+960 |
| packed full | 8384+421+306+754+949=**10814** ≤ align8 **10816** ≤ **10880** |

## NO-GO dispositions

| ID | Resolution |
| --- | --- |
| P0 primary collision | `peer_key[45]` holds the forward request; S4 closed-normalized raw[255]/raw2[64]/aux[16]+lengths+role+owner/body-variant alias are independently pinned and compared with returned primary body + PVD. Same derived key is not identity proof |
| P0 BLOB primary rows | BLOB manifest owner kinds 1/2/3 map to ANCHOR/INGRESS/DELIVERY exact raw; chunk maps `blob_id_digest` to a forward-built manifest and compares returned manifest body+PVD. Mode17 evaluator remains unchanged |
| P0 RETIRED zero/partial | Mode33 sequential RETIRED_HEADER_INVENTORY sets S6 before CHUNK_BIND, including zero/partial chunks; no successor/incoming walk is added |
| P0 Mode31/32 S5+S6 | same-successor RETIRED or fully-ABSENT SUPERSEDE predecessor candidate atomically sets bit7+bit5 in either successor-carrier mode; `(1,1)` is valid disposition 3. Mode31 ordinary semantics remain ALL_NEW |
| P0 dual membership | `pin_digest_a` + `pin_digest_b` until MEMBERSHIP_DUAL close; target-specific entry.new compare |
| P1 quota=1 | `member_substep` 0→1→2→3; each get advances; no same-get infinite loop |
| P1 §18.14 dup lines | removed; main-equivalent |
| P1 deferred completion | Mode32 S5/S5+S6 and Mode33 RETIRED S6 are sticky, finalize as DEFERRED_READY with explicit private disposition; never local D3 success |
| P1 sticky cleanup | bit7/bit5 survive GROUP_CLOSE/pass/yield and clear only at fresh begin or finalize/abort cleanup after disposition sampling |
| P1 Mode34 empty/multi-carrier | per-carrier close sets no completion bit; one global lex iterator atomically proves A/B/C exhaustion, including empty arms |
| P1 Mode34 manifest authority | each WITNESSED header pins M/C/manifest digest in its own Mode34 transaction; MEMBERSHIP_DUAL validates every expected chunk framing/index and feeds each encoded chunk once before final SHA. Prior Mode31/32 snapshots are not authority |
| P1 Mode34 returned index | requested/returned index is exact `floor(i/8)` for every ordinal; the same index repeated up to 8 within a chunk is required/合法. M=2 `[0,0]` and M=9 `[0×8,1]` positives separate normal re-get from boundary repeat/skip, iterator duplicate row/key, and request mismatch mutations |
| P1 private disposition carrier | private result appends exact `d3s4_disposition_present` + `d3s4_disposition`; `(1,0)` LOCAL_COMPLETE differs from `(0,0)` none. Higher composition accepts status OK + present 1 only |
| P1 output/cleanup order | derive/sample → Port cleanup → one full-result publish → context zero. Abort, cleanup failure, alias/prevalidation/invalid-state preserve whole poisoned output; evaluator-off publishes canonical none only after cleanup success |
| P1 request raw lifetime | 255-byte primary-raw pin becomes request scratch only after the primary lifetime closes; simultaneous A/B/global raws remain distinct |
| P1 state mapping | phase/pass/mode and every compact enum/mask have closed valid/invalid/MBZ ownership |
| P1 positive oracle | independent generator + production bridge, full closed-normalization role coverage, Mode31/32 progression positives, and component-by-component raw/length/role/owner mutations are mandatory |
| P2 wording/whitespace | D3-S2/S3/S4 implementation status made unambiguous; trailing whitespace removed |

## Greps

```bash
rg -n "d3s4_disposition_present|floor\(i/8\)|M=9/C=2|S4 closed primary normalization|BLOB chunk|RETIRED_HEADER_INVENTORY|sizeof \*\*949\*\*|10880" docs/17-foundation-domain-store.md | head
rg -n "576/592|10512|9744" docs/17-foundation-domain-store.md || true
diff -u <(git show origin/main:docs/17-foundation-domain-store.md | awk '/^### 18\.14 /{p=1} p') <(awk '/^### 18\.14 /{p=1} /^### 18\.15 /{if(p) exit} p' docs/17-foundation-domain-store.md)
test "$(git show origin/main:docs/17-foundation-domain-store.md | awk '/^### 18\.14 /{p=1} p' | shasum -a 256 | cut -d' ' -f1)" = "$(awk '/^### 18\.14 /{p=1} /^### 18\.15 /{if(p) exit} p' docs/17-foundation-domain-store.md | shasum -a 256 | cut -d' ' -f1)"
python3 -c "assert 949<=960; assert 56<=64; assert 8384+448+320+768+960==10880; assert (8384+421+306+754+949+7)//8*8==10816; print('OK')"
git diff --check
git diff --cached --check
```

Self-review author: main-spec implementer. Not Normative.
