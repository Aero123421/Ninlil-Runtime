# 2026-07-29 RRMP final repair independent review

状態: **independent software repair review GO — P0=0 / P1=0**

実行日: 2026-07-30 JST  
対象tranche: 2026-07-29 Route/Relay + Multi-parent V1 software candidate  
基準HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`

この記録は、ADR-0019 / ADR-0020のprivate/default-OFF RRMP実装候補に
対して行った最終repair差分の独立レビュー結果である。レビュー担当は
最終repairの実装を担当せず、本レビュー中にproduction code、test、
README、compatibility matrixを変更していない。Grok Buildは使用していない。

レビュー対象はdirty shared workspace上の未commit候補であるため、HEADだけでは
内容を再現できない。対象authorityのSHA-256を次に固定する。

| Authority | SHA-256 |
| --- | --- |
| `src/runtime/route_relay_v1/rrmp_core.c` | `01b125a847e7c6655ed102e05e84adcdd87a154eef9b064fc737503200cf6e6b` |
| `tests/runtime/route_relay_v1/rrmp_storage_atomicity_test.c` | `bbf54f61bf0a5ad855ff21a9a34a59eb46dd568018423434d81654eaebb720ae` |
| `docs/adr/0019-route-relay.md` | `b184d5708508773e03a2d8bf0c4b532392fd0404dcc772e21c7a9f4945be444b` |
| `docs/adr/0020-multi-parent.md` | `29863d3fae96f49142d09f919dba44edbb0f6d3c9d9ec5e1bb081e43081421af` |
| `spec/vectors/route-relay-multiparent-spec-v1.json` | `7c133639252fa5cc1cc26001703a70c64215bd4f1a14efa9912ba154240d0dce` |

## Review scope

最終repairで重点確認した範囲:

1. `finish_writepoint_full()`がouter FULL definite failure後にfresh readで
   exact durable OLDを確認し、RAMをOLDから再構築すること。
2. exact OLD再構築後に、callerがpre-recoveryの挿入indexを使って
   rollbackを二重適用しないこと。
3. `parent_select`が`last_attempt_id16`、`selected_parent`、
   `attempt_selected`をmutationより前にcaptureすること。
4. middle-index regressionが修正前実装をREDにし、現行実装をGREENにすること。
5. QST4 global attempt ledger、bounded RRM1 bundle、storage ABI、
   stack、workspace/ESP resource値がADR、vector、source、manifest間で一致すること。
6. normal / ASan+UBSan Host、10k lifecycle、Python / Node semantic
   authority、ESP-IDF final ELF/mapが全て現行snapshotを検証すること。

関連するsoftware acceptance記録は
[RRMP V1 software acceptance](../work/2026-07-29-route-relay-multiparent-v1-software-acceptance.md)。

## Source review result

### Exact durable OLD recovery

`rrmp_core.c:4120-4150`の`finish_writepoint_full()`は、storage commit失敗が
`DEFINITE_FAILURE`なら`owner_storage_recover_internal(owner, 1)`を呼ぶ。
このrecoverはfresh storageからexpected OLDを要求し、その内容からowner RAMを
再構築する。exact OLDでなければ`CORRUPT`にし、storage hard fenceを閉じる。
`COMMIT_UNKNOWN`はroute/parent namespaceを`CU_PARTIAL`にして同様にfenceする。

`rrmp_core.c:4158-4165`の
`writepoint_restored_exact_durable_old()`は、storage bound、
`DEFINITE_FAILURE`、hard fenceなしの組合せだけを「RAMは既にexact OLD」と判定する。
各write gateがmutation開始前に`storage_last_outcome=NONE`へ戻すため、
過去operationのstale outcomeを誤って再利用しない。

`forward_admit`の失敗path（`rrmp_core.c:5320-5340`）と
`parent_select`の失敗path（`rrmp_core.c:7788-7796`）は、この判定が真なら
queue/evidence/route/attemptやparent scopeへindex-based rollbackを再適用しない。
これにより、recover後に同じindexを占めるdurable OLD rowを誤って削除しない。

### Parent selection capture order

`rrmp_core.c:7737-7739`でold attempt ID、old selected parent、
old selected flagをcaptureし、その後`rrmp_core.c:7775`で新parentを選択、
`rrmp_core.c:7780-7786`でattempt rowとscope stateをmutationする。
旧値のcapture順序は正しい。

### Middle-index regression

`rrmp_storage_atomicity_test.c:1208-1284`は、既存attempt A/Cの間へ
attempt Bがsortされる状態で`parent_select` outer CASをdefinite failureにする。
durable witness不変、namespace exportのbyte-exact OLD、ACTIVE route、
A/C両方の`SAME_ATTEMPT_RESELECT`、downlink許可を検証する。

`rrmp_storage_atomicity_test.c:1286-1384`は同じmiddle-index条件を
`forward_admit`のroute/evidence/queue/attemptを含むFULL writepointへ適用する。
両testは`main`（`1387-1397`）から必ず実行される。

## Repair-before RED / current GREEN

false-greenを除外するため、現行sourceからreview用mutantを一時生成し、
`writepoint_restored_exact_durable_old()`を常にfalseにして修正前の
「recover後にもstale index rollbackを実行する」挙動を再現した。
tracked sourceは変更せず、mutant objectだけでfocused testを再linkした。

修正前mutantの実測RED:

```text
EQ .../rrmp_storage_atomicity_test.c:1265 after_export_len=96043 old_export_len=96123
CHECK .../rrmp_storage_atomicity_test.c:1394 test_parent_select_definite_failure_restores_mid_index_old() == 0
```

元objectを復元して同じtestを再linkした現行実装:

```text
rrmp_storage_atomicity_test OK
```

このmutationは、単にCASが失敗したことではなく、exact OLDをrehydrateした後に
stale insertion indexで既存C rowを削除する旧bugを直接検出する。

## Independent verification

fresh dedicated build directory:

- normal: `build/review-rrmp-final-normal`
- Clang ASan+UBSan: `build/review-rrmp-final-asan`

| Verification | Result |
| --- | --- |
| normal `ninlil_rrmp_codec_test` | PASS |
| normal `ninlil_rrmp_sm_test` | PASS |
| normal `ninlil_rrmp_crash_corrupt_test` | PASS |
| normal `ninlil_rrmp_storage_atomicity_test` | PASS |
| normal `ninlil_rrmp_token_ledger_test` | PASS |
| normal `ninlil_rrmp_sim_lifecycle_test` | PASS |
| normal `ninlil_rrmp_composition_test` | PASS |
| normal focused total | **7/7 PASS** |
| ASan+UBSan same seven executables | **7/7 PASS** |
| exact lifecycle | **10,000/10,000 install, activate, admit, complete, retire PASS** |
| strict all-feature private archive | PASS |
| RRMP private-symbol archive gate | PASS |
| route/relay/multi-parent focused configured spec suite | PASS |

10k executableの実測summary:

```text
10k exact install=10000 activate=10000 admit=10000 complete=10000 retire=10000
rrmp_sim_lifecycle_test OK
```

ASan+UBSan 7/7には同じ10k lifecycleが含まれ、sanitizer findingは0だった。

## Machine authority and vectors

次の全てを現行snapshotから再実行した。

| Gate | Result |
| --- | --- |
| generator `--check` | PASS; vector SHA-256 `7c133639…d0dce` |
| generator `--self-test` | PASS; 114 cases |
| Python gate `--check` | PASS; 114/114; exact REQUIRED_IDS |
| Python gate `--self-test` | PASS; 12,882 donor pairs rejected |
| Node gate `--check` | PASS; 114/114; exact REQUIRED_IDS |
| Node gate `--self-test` | PASS; 12,882 donor pairs rejected |
| Python/Node semantic parity | PASS |

Python/Node self-testはschema/type/layout drift、duplicate key、S6 chain mutation、
slot reserved-byte campaign、NaN/non-JSON numeric、API/storage metadata driftを
それぞれrejectした。machine authorityは単なるvector再読ではなく、
mutant/donor negative evidenceを含む。

## QST4 exact record and resource arithmetic

QST4 schema 4はheader exact 56 B、attempt row exact 80 B、
handoff tuple exact 224 Bである。attempt rowのpacked C layoutは
`rrmp_core.c:228-238`の`_Static_assert`で80 Bを固定する。
capacityと最大値はADR-0020 §12.7、C constants、vectorで一致した。

```text
56
+ 64 * 64
+ 124 * 72
+ 64 * 320
+ 16,320
+ 256 * 80
+ 64 * 224
= 84,696 bytes
```

確認したexact値:

| Item | Value |
| --- | ---: |
| QST4 header | 56 B |
| used-attempt row / capacity | 80 B / 256 |
| handoff tuple / capacity | 224 B / 64 |
| QST4 maximum | **84,696 B** |
| RRM1 manifest | 256 B |
| RRM1 chunk maximum / count | 61,440 B / 5 |
| logical export maximum | 307,200 B |
| logical export required maximum | 290,720 B |
| bounded headroom | 16,480 B |
| Platform Storage single-value ceiling | 65,536 B |

RRM1はlogical exportを単一storage valueへ保存せず、manifest M1と
canonical C0..C4へ分割する。従って各`put`は最大61,440 Bで、
65,536 B ceiling以下である。storage ABI gateはこのbounded piece-vector
contractと、v1 callbackがbundle mutationに使われないことを検証した。

QST4 import/export reviewでは、schema 4 `RRMPQST4`のみwriteし、reserved zero、
attempt tupleのcanonical sort、lifecycle/flags/digest/deadline、
handoff old/new tupleのlexical orderとexact bindingを検証する。
missing、duplicate、out-of-order、unknown rowはrejectする。
global `(owner_scope_id, attempt_id16)` ledgerはscope reinstallではclearされず、
A→B→A、restart、assignment epoch前進後も同attemptを拒否する。

## Storage ABI, stack and live resource result

| Gate / value | Result |
| --- | --- |
| `tools/rrmp_storage_abi_gate.py` | PASS |
| `tools/rrmp_frame_stack_gate.py` | PASS; ceiling 2,048 B; zeroed CRC uses 9 |
| owner workspace budget | 393,216 B (384 KiB) |
| measured owner workspace | 388,048 B |
| namespace export scratch | 307,200 B |
| bounded piece scratch | 61,440 B |
| target software-FULL smoke store | 307,456 B |
| exact simultaneous live total | **1,064,144 B (1,039.203125 KiB)** |
| resource authority check with executed Host probe | PASS |
| resource authority self-test | PASS |

exact total:

```text
388,048 + 307,200 + 61,440 + 307,456 = 1,064,144 bytes
```

source、software manifest、physical-HIL template、executed Host workspace probeの
同じ値を`rrmp_esp_dram_budget_gate.py`がcross-checkした。大容量bufferは
ESP PSRAM capability allocationであり、internal DRAM fallbackを持たない。

## ESP-IDF final ELF / map proof

2026-07-30 00:23 JSTに、Apple Silicon native arm64のpinned containerで
`tools/rrmp_esp_idf_map_proof.sh`をfullcleanから実行した。

| Item | Evidence |
| --- | --- |
| ESP-IDF | **v5.5.3** |
| target | ESP32-S3 |
| feature | `CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1` |
| final ELF | `ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.elf` |
| final map | `ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.map` |
| ELF SHA-256 | `589777e28ca045f8a359775dccf6e2f0b8d5c5c017d1799affd8f927a9ef9976` |
| map SHA-256 | `e68bb41e30da1113851a9062f730d66d94c92277c4c485886a4fdb5e5c1e8a47` |
| app `text/data/bss` | 293,855 / 76,676 / 680,337 B |
| RRMP internal BSS | **3,140 B** |
| RRMP internal-BSS budget | 32,768 B |
| map/resource proof | **PASS** |

final ELF/mapには`rrmp_core`、`rrmp_codec`、`rrmp_store`、`rrmp_util`、
`rrmp_seam`、`rrmp_composition`、`rrmp_target_smoke`のproduction/target
objectsが存在する。必要RRMP symbolsもfinal ELFに残る。一方、
`rrmp_sim`、Host lifecycle fixture、Host deterministic compositionは
final ESP ELFへ混入していない。

この結果はcompile/link/map/resource software proofであり、実機boot、
allocation runtime measurement、RF送受信、flash power-cutを証明しない。

## Findings

| Severity | Open findings |
| --- | ---: |
| P0 | **0** |
| P1 | **0** |

最終repair範囲にpromotionを止めるP0/P1は残っていない。

非blocking editorial observationとして、review範囲外の
`rrmp_host_lifecycle_fixture.c:771`にqueue/opaque handleをvolatileと呼ぶ古い
commentが残るが、後続restart testと現行QST4 contractはそれらをdurableとして
実際に検証している。code behavior、wire/storage contract、P0/P1 verdictには
影響しない。

## Promotion recommendation

この独立reviewは、ADR-0019 / ADR-0020のS1〜S6および最終software repairに
対して**joint SPEC_ACCEPTED promotionを妨げるP0/P1が0**であると判定する。
両ADRは相互依存するため片方だけを昇格せず、root authorityが次を同一変更で
行うことを推奨する。

1. ADR-0019とADR-0020を`Proposed`から`SPEC_ACCEPTED`へjoint promotionする。
2. vector claimsとADR indexを同じaccepted snapshotへ合わせる。
3. compatibility matrixの`relay`と`multi-parent-multi-controller`を
   `PROPOSED`から`SPEC_ACCEPTED`へ更新し、state ceilingも
   `SPEC_ACCEPTED`に留める。
4. authority変更後にspec generator/check/self-test、Python/Node gate、
   compatibility/traceability gateを再実行する。

本review artifact自体はstatus authorityを変更していない。記録時点では
ADR-0019、ADR-0020、vector claims、compatibility matrixの両featureは
引き続き**Proposed**であり、形式上はまだ`SPEC_ACCEPTED`ではない。

## Physical residuals and non-claims

software review完了後も次は未達である。

- physical ESP32-S3 boot/runtime PSRAM measurement: **NOT_RUN / null**
- physical RF 2-hop / 3-hop: **NOT_RUN**
- physical multi-parent air diversity/failover: **NOT_RUN**
- physical flash power-cut dual-slot campaign: **NOT_RUN**
- public installed route/parent ABI: nonclaim; private/default-OFF
- production carrier/provider end-to-end proof: nonclaim
- security audit complete: nonclaim
- `TARGET_CANDIDATE` / `RELEASE_SUPPORTED`: nonclaim

従って本verdictは**software repair review GO / SPEC_ACCEPTED promotion eligible**
までであり、physical HIL/RF PASSやrelease supportを意味しない。
