# 2026-07-30 D3-S4 oracle resource compaction

状態: **P1-3 implementation candidate PASS / semantic authority preserved / full selected freshness scope 16/16 PASS**

本記録は、D3-S4 crossrow oracle の単一巨大JSON、生成C fixtureの重複、
self-testの資源使用量を縮小しつつ、既存の468-vector semantic authorityを
維持した実装候補と検証証拠をまとめる。

これはNormative仕様またはADRをこの記録だけで変更するものではない。末尾の
Normative/ADR文案は、仕様変更として別途受理するための提案である。

## 作業境界

- 開始HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`
- 開始時の単一D3-S4 authority:
  - path: `spec/vectors/domain-scan-crossrow-v1.json`
  - bytes: `53,984,354`
  - lines: `1,179,907`
  - raw SHA-256:
    `f0655bfa8fd61f7a09a82401effad78a44ed8edaf807b02047515c045245a7a0`
- 開始時に未追跡だったD3-S4実装候補のSHA-256:
  - generator:
    `f4a42e9ff45bb0408d96d2556ea0096042a2401463026e4cdc6e348a4b26373e`
  - D3-S3 projection:
    `d082fc149456e97ac3595cbc669e825b16aae0b6555536f7f12d18bca20b324f`
  - C bridge:
    `af7a34da1775154273f4d6298474d5ff2a3af69e4ce2729bdd95c55fb7639a3a`
- `CMakeLists.txt`とDSD1 generatorには同時進行の既存差分があったため、
  本作業はD3-S4 authority/shard dependencyとmanifest consumer対応だけを加えた。
- commit、push、Normative/Accepted ADRの直接変更は行っていない。

## 維持したsemantic authority

manifest化やC fixture圧縮とは独立した固定値を、Python reader、Node reader、
生成C fixture、C bridgeの複数箇所で照合する。

| pin | 値 |
| --- | --- |
| expanded vector count | `468` |
| D3-S4 suffix count | `185` |
| positive expected count | `133` |
| negative mutation count | `191` |
| content SHA-256 | `b18f717e2752c9d617d575c86194ef644f301706263674f2666a5d29ed951e25` |
| order SHA-256 | `17ec848715537a261f274a392d23c586045b87bc0adf1fe65cb1e15c7f0c8c4d` |
| negative projection SHA-256 | `74e0ded28a87d77f002db181a496a70efd29f601833c08d2379e717fff7f00ee` |
| compact canonical expanded SHA-256 | `33d936597ce617952043f6a0324ba616b8d71acf41cc8744d1b3f771abd54f15` |

negative projectionは各negative vectorの
`id/kind/mode/negative_base/declared_mutation_fields/expected.d3s4_first_reason/faults`
を順序どおりcanonical JSON化したものを固定する。したがって、単なるvector数一致ではなく、
negative mutationの対象、理由、fault列、順序の変化も拒否する。

## 実装

### Manifestとordered semantic shards

`spec/vectors/domain-scan-crossrow-v1.json`を20,227-byteのmanifestにし、
expanded semantic documentを次のcontent-addressed generationへ分割した。

```text
spec/vectors/domain-scan-crossrow-v1.d/
  33d936597ce617952043f6a0324ba616b8d71acf41cc8744d1b3f771abd54f15/
    000-d3s1-slice-00.json
    001-d3s2-slice-00.json
    002-d3s3-slice-00.json
    003-d3s3-slice-01.json
    004-d3s4-slice-00.json
    005-d3s4-slice-01.json
    006-d3s4-slice-02.json
    007-d3s4-slice-03.json
```

| shard | bytes | raw SHA-256 |
| --- | ---: | --- |
| `000-d3s1-slice-00.json` | 1,096,900 | `415358a9852f0264e85bfd2a6c1f0250bacd2af0b4125e51ec5518c5b35ed99b` |
| `001-d3s2-slice-00.json` | 782,667 | `0bf76b791f374ff6403f3333c9356c6bee95450b851dadd0f729194e8c6d0569` |
| `002-d3s3-slice-00.json` | 7,270,777 | `ba5f47ef106ff2c742e4f2c1cd13c75fc060c00485f9579ec597d0b3bd26eb86` |
| `003-d3s3-slice-01.json` | 829,808 | `dbfc3a7b4b3db65327a91d5521445a45f86236fdebe30ca784725a1a3eeade36` |
| `004-d3s4-slice-00.json` | 6,826,991 | `b27465f329fb1ccbb2030a705fd32f11358639600a619eb5267057184321a034` |
| `005-d3s4-slice-01.json` | 7,317,850 | `e3b2d514e237b8a9db22fdef79c78a8cc847ecf748b77d4d1fdc218f59e21938` |
| `006-d3s4-slice-02.json` | 7,324,817 | `7acc1e5370ea9f0e631fbab6da7ac1bacef17eb3652f043c717998602cfd6697` |
| `007-d3s4-slice-03.json` | 6,381,618 | `9a8f4b8835dc24f714b918e23fc3011e7a6c5165c8a70fe9de17328e2f88ff5f` |

最大shardは7,324,817 bytesで、固定上限10 MiB (`10,485,760`)未満である。
manifestと8 shardsの合計は37,851,655 bytesで、旧単一JSONから
16,132,699 bytes、29.9%削減した。

Python readerは、manifest/shardのcanonical byte表現、相対path逸脱、raw SHA、
slice count/range/先頭末尾ID、全体count/order/content/negative/canonical digestを検査する。
Node readerはPythonをimportまたは起動せず、同じ固定値を独立再計算する。

writerは全shardを一時generationへ生成・検査してからcontent-addressed directoryへ
installし、最後のmanifest `os.replace()`だけを可視化点にする。既存generationは
並行readerのため残す。fault injectionで次を確認した。

- generation install後、manifest replace前: 旧authorityが完全に読め、未公開generationを
  通常例外時にrollbackする。
- manifest replace後: 新authorityが完全に読める。

これはnamespace上のold-or-new可視性を保証する実装候補であり、directory/fileの
`fsync`を含む電源断durabilityまでは主張しない。

### Consumersとbuild freshness

- D3-S4 generator、D3-S3 projection、DSD1 composition generatorをmanifest readerへ接続。
- D3-S3 legacy consumerには、検証済み468-vector authorityから固定283-vector
  predecessorをbuild directoryへ投影する。
- CMake custom commandsはmanifest、reader、8 shardsをすべて明示dependencyに持つ。
- shardだけをtouchした再buildで、D3-S3 projectionとD3-S4 typed fixtureの両方が再生成された。
- D3-S3 fixture emit/freshnessには投影authority pathを明示し、manifestを旧readerへ
  誤入力しない。

### Generated C fixture

完全一致するimmutable byte列を一度だけemitし、各vectorはintern済みblobを参照する。
semantic fieldやvector順は変更していない。C fixtureにはexpanded count、negative count、
content/order/negative/canonical SHAの固定macroを出し、C bridge側の独立literal pinと照合する。

| 項目 | 変更前 | 変更後 |
| --- | ---: | ---: |
| generated header bytes | 39,460,472 | 14,862,106 |
| 削減 | - | 24,598,366 bytes (62.3%) |
| unique blobs | - | 3,484 |
| referenced blobs | - | 24,245 |
| unique blob bytes | - | 2,547,629 |
| referenced blob bytes | - | 6,950,230 |

最終header SHA-256:
`50244fcde7e77acc025f09da893982cc14a658fd06e6d6dd166131c9f8b85e47`

### Generator/self-test資源

- authority content hashをstreaming計算へ変更。
- full-document `deepcopy`をstructural copy-on-writeへ変更。
- suffix mutationは対象vectorだけをcopyする。
- emit semantic checkをchild processへ分離し、suffixをstream処理する。
- self-testの一時出力はOS temporary directoryだけを使う。
- source authorityと既存`tmp-a2`を前後hash snapshotし、source-tree writeが0であることを検査する。

同一fresh tree、macOS上の実測:

| command | 変更前 elapsed / max RSS | 変更後 elapsed / max RSS |
| --- | --- | --- |
| generator `check` | 4.80 s / 643,448,832 B | 2.69 s / 466,337,792 B |
| `emit-c-fixture` | 6.57 s / 643,579,904 B | 3.20 s / 464,633,856 B |
| generator `self-test` | 121.62 s / 約1.64 GiB | 下記3回 / 最大912,637,952 B |
| streaming manifest authority `check` | 該当なし | 0.77 s / 269,942,784 B |
| independent Node authority check | 該当なし | 0.40 s / 262,635,520 B |
| full `generate` | 該当なし | 8.00 s / 669,663,232 B |

self-testは過剰反復を避け、同じfresh treeで3回だけ測定した。

```text
77.01 s / 860,274,688 B
77.94 s / 909,737,984 B
78.85 s / 912,637,952 B
```

nearest-rankの観測P95は78.85 sで、CTest timeout 180 sに対して
101.15 s (56.2%)のmarginを持つ。3 sampleのbounded spot measurementであり、
長期的な性能分布の主張ではない。

## Fresh configure/build/test証拠

fresh build directory:
`/tmp/ninlil-d3s4-build.J9GdHY`

```sh
cmake -S . -B /tmp/ninlil-d3s4-build.J9GdHY \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_EXAMPLES=OFF \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/ninlil-d3s4-build.J9GdHY \
  --target ninlil_domain_store_scanner_crossrow_d3s4_oracle_bridge_test
```

AppleClang strict C11 buildを含む。`NINLIL_BUILD_EXAMPLES`はこのtreeで未使用という
CMake warningが出たが、configure/build/testは成功した。

選択したauthority/projection/DSD1/D3-S1..S4/freshness scopeは
**16/16 PASS、38.16 s**。

```text
domain_scan_dsd1_composition_vector_oracle
domain_store_scanner_dsd1_composition_oracle_bridge
domain_scan_dsd1_composition_fixture_freshness
domain_scan_crossrow_d3s4_manifest_authority
domain_scan_crossrow_d3s4_manifest_node_authority
domain_scan_crossrow_d3s3_projection_check
domain_scan_crossrow_d3s3_projection_self_test
domain_scan_crossrow_d3s4_manifest_authority_self_test
domain_scan_crossrow_d3s4_vector_oracle
domain_store_scanner_crossrow_oracle_bridge
domain_store_scanner_crossrow_d3s2_oracle_bridge
domain_scan_crossrow_fixture_freshness
domain_store_scanner_crossrow_d3s3_oracle_bridge
domain_scan_crossrow_d3s3_fixture_freshness
domain_store_scanner_crossrow_d3s4_oracle_bridge
domain_scan_crossrow_d3s4_fixture_freshness
```

追加確認:

- 2回のfull generateでmanifest+全shard treeがbyte-identical。
- source authority treeと`tmp-a2`はgenerate/self-test前後でbyte-identical。
- DSD1 standalone self-test PASS。
- shard-only mtime変更後のbuildでD3-S3 projectionとD3-S4 fixtureを再生成。

## 最終source hash一覧

| file | bytes | SHA-256 |
| --- | ---: | --- |
| `spec/vectors/domain-scan-crossrow-v1.json` | 20,227 | `16cf9389d48ba74c079d0b0ce00e775bf8c89eb32480edd359d5994e4c9b4e89` |
| `tools/domain_scan_crossrow_d3s4_vector_gen.py` | 1,040,536 | `920a56ca7cb21b8d06155c124de2afd522e6f407c8c0b4d6f3e18bbe10a2ab6b` |
| `tools/domain_scan_crossrow_d3s4_authority.py` | 33,976 | `5cb678be058998dc7077a7fab7c6129232cb4176081631bbdd56fdeb43ab428e` |
| `tools/domain_scan_crossrow_d3s4_manifest_check.mjs` | 13,958 | `5766063a366eb17438c855ddc0e6aa657a52acdd0e8d9eca7f643c452061d686` |
| `tools/domain_scan_crossrow_d3s3_projection.py` | 7,424 | `f0800edab67ce34eac811aa7aaeb9c1f3c27c0c780c89afba8e033102940783e` |
| `tools/domain_scan_dsd1_composition_vector_gen.py` | 51,913 | `17e17e48b031756a5dd15fff1b673beb66ea8ed032b53e3148a0ca637fed57c7` |
| `tests/runtime/domain_store_scanner_crossrow_d3s4_oracle_bridge_test.c` | 90,808 | `09a4ce75684d37f99f80f17832bb38f133afdc52be6dd222edac9471867128d0` |

DSD1 generatorの本作業直前再構成SHA-256は
`fb8bc7b25dae4ebb065de90ff0e985287b21553ea979abd18134e67a0e23ebb2`。
本作業差分はmanifest reader import、D3-S4 canonical expanded SHA pin、
manifest/full-document両対応loadに限定した。

## Normative追加文案（未受理）

1. D3-S4のsemantic authorityは、manifestを順序どおり展開して得る
   `ninlil-domain-scan-crossrow-v1-d3s4` documentである。manifest/shardという
   packaging自体はsemantic意味を追加・削除しない。
2. expanded documentのcanonical formは、manifestの`expanded_key_order`に従う
   top-level key順、compact JSON、UTF-8、末尾LF 1個とする。
3. manifestはexpanded format、vector count、content SHA、vector order SHA、
   negative count/projection SHA、canonical expanded SHA、最大shard bytesを固定する。
4. shardsはmanifest記載順に連結する。各shardはcanonical byte表現、raw SHA、
   vector count、global range、first/last IDを満たし、各fileは10 MiB以下とする。
5. conforming readerは絶対path、`..`、manifest root外参照、重複path、
   非canonical shard、raw/count/range/ID/order/semantic digest不一致をfail closedにする。
6. 468 vectors、185 suffix、191 negative mutationsおよび既存の全semantic digestを
   packaging変更だけで変更してはならない。

## ADR追加文案（未受理）

**Decision:** D3-S4 authorityの物理配置をcontent-addressed immutable shard generationと
小さいmanifestへ分離する。writerは新generationを完全生成・検査・installした後、
manifestを単一atomic replaceし、既存generationを並行readerのため保持する。
cleanupはreader lifetimeを考慮した別操作とし、publish pathには含めない。

**Reason:** 単一53.98 MB JSONと重複C fixtureは、checkout、review、generator、
self-test、CIの時間とmemoryを不必要に増やす。semantic digestをexpanded documentへ
固定すれば、物理分割による意味の漂流を防ぎながら資源を削減できる。

**Consequences:** 全consumerはmanifest-aware readerまたは検証済みprojectionを使う。
CMakeは全shardをdependencyへ列挙する。generation directoryはcanonical expanded SHAで
識別され、旧generationの回収には別途retention方針が必要である。電源断durabilityを
要求する場合は、file/directory `fsync`を含む追加ADRが必要である。

## 未主張

- 本記録だけでNormative仕様またはAccepted ADRが変わったとは主張しない。
- 全391 CTest、ASan/UBSan、ESP-IDF/実機経路を本作業で再実行したとは主張しない。
- 3回のself-test値を長期的なCI性能保証または統計的な母集団P95とは扱わない。
- atomic manifest replaceだけから、電源断後の永続性を推測しない。
- 同時進行の他差分を本作業の成果として扱わない。
