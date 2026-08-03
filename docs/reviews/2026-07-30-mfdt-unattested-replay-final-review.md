# 2026-07-30 MFDT unattested NRC1 replay independent final review

状態: **private/default-OFF software repair candidate GO — P0=0 / P1=0 / P2=0**

実行日: 2026-07-30 JST
対象: ESP-style `COMMIT_UNKNOWN` / exact `NEW` 後のunattested NRC1 retry bypass修復
基準HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`

この記録はdirty shared workspace上の未commit候補に対する独立最終レビューである。
レビュー担当は修復実装を担当しておらず、Grok Buildは使用していない。
本レビューでproduction behaviorは変更していない。修正したのは、現実装の
`ERR_CU_NEW_NOT_PROMOTED`契約と矛盾していたproduction adapterおよびtest冒頭の
stale comment各1件と、このreview record / review indexだけである。

## Verdict

| Severity | Open findings |
| --- | ---: |
| P0 | **0** |
| P1 | **0** |
| P2 | **0** |

修復は、private/default-OFFの**独立レビュー済みsoftware candidate**として進めてよい。
unattested ESP targetで、同一request IDのCU/NEWがwarm/coldいずれのretained-state
shapeからも外部`OK`へ変わる経路は再現しなかった。

このGOは次を意味しない。

- ADR-0021の`SPEC_ACCEPTED`
- platform-rooted attestation実装の完成
- ESP32-S3実機HIL / RF / physical power-cut PASS
- `RELEASE_SUPPORTED`

ADR-0021のMF-O08は**OPEN / release blocker**のままであり、上記の非claimを維持する。

## Reviewed snapshot

対象は未commit候補であるため、主要authorityと実装のSHA-256を固定する。

| Authority / source | SHA-256 |
| --- | --- |
| `docs/26-u6-transport-custody.md` | `f68b7008a62d3ae18f630babf88d2213ebf2946d4c77a37d8d95d164730edc59` |
| `docs/adr/0006-u6-transport-custody.md` | `d4ea04596d0fb0a1d802c4043f537c21c82da84cd5581bd0a215f53f286bc2bc` |
| `docs/adr/0021-multi-frame-durable-custody.md` | `f2d2ea450cd16b80f08f54720452cd812908dc04bbac6e6c66b57fc266731203` |
| `docs/work/2026-07-30-mfdt-unattested-nrc1-replay-repair.md` | `96fb56fa83dc157fe3ce86ca73ae91dd80216a92551e708c5c515835eaa7818b` |
| `src/runtime/mfdt_v1/mfdt_v1_engine.c` | `554ef694a44d5660d9f24bf6a8ca5de1b7877693bbe2ec757ae0c0ab97ebe98a` |
| `src/runtime/mfdt_v1/mfdt_v1_hil_gate.c` | `62d6ce3c47132d990668c010ba73a61d054c18ec64935b1617e3a38de1872d0f` |
| `src/runtime/mfdt_v1/mfdt_v1_store_esp.c` | `a25f150f491b37e90b6c0743ea5e096a2c5952565eb9b47997bc3a6efa9c3f89` |
| `tests/runtime/mfdt_v1/mfdt_v1_e2e_test.c` | `04ba193e460a1a35f33411e6f7f8fc524f1349ec7684c52baaf169e7ad346b27` |
| `tests/runtime/mfdt_v1/mfdt_v1_esp_store_cu_test.c` | `318ed10f9442f62941418fe91e1bf041c602272dfe081a44d06cfcef346a9684` |
| `spec/vectors/multi-frame-durable-transfer-spec-v1.json` | `635f71c5833ee150376e8fd9edde8c18e3c9ca73ce193d0600de62801243959b` |
| `tools/multi_frame_durable_transfer_spec_vector_gen.py` | `9af5ac005c64eab073ae3e4ef487c0eb23662ce70082145219e75dfe3cfd9e6d` |

Accepted U6 Normative specとAccepted ADR-0006にはworking-tree差分がなく、修復による変更は
ない。従って本候補はAccepted U6を再定義せず、Proposed ADR-0021の狭い追加制約として
監査した。

## Replay authority audit

`nrc1_replay_eligible()`は、`ESP_PLATFORM` buildでは
`ninlil_mfdt_v1_hil_full_promotion_enabled()`だけをauthorityにする。
caller suppliedの`host_mode`はtarget branchで参照されない。Host buildだけが
FULL-capable profileとして`host_mode`または明示gateを利用する。

public `ninlil_mfdt_v1_nrc1_lookup()`とsuccess commit pathの
`commit_resp_with_active()`は、digestとcached response lengthを検査した後、replay
ineligibleならresponse全体をzeroizeして`ERR_COMMIT_UNKNOWN`を返す。
lookup-first helperがineligible hitをmissとして後続処理へ渡す形でも、各handlerの
外部success exitは`commit_resp_with_active()`の同じeligibility判定を通る。
pipelineはhandler resultが`OK`かつbodyありの場合だけwire responseを出す。
従ってearly lookup、active recovery、late duplicateのいずれにも別の`OK`出口はない。

次のmatrixをsource、vector、Host regression testで照合した。

| Retained state / retry | ESP target, gate OFF | Host FULL-capable |
| --- | --- | --- |
| warm active+NRC1 | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` replay |
| cold active+NRC1 | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` replay |
| warm NRC1-only | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` replay |
| cold NRC1-only | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` replay |
| cold NM30+NRC1 | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` replay |

ESP compile-time branchはcallerの`host_mode=1`でも変わらない。pinned ESP-IDF final ELF
にもtarget smoke call pathと対象engineがretentionされている。

## CU media classification and attestation

ESP durable read-back分類は次の契約を維持する。

| Class | External result |
| --- | --- |
| OLD | retryable storage result; NEW custodyへのpromotionなし |
| NEW | raw durable classification + local mirror; `ERR_CU_NEW_NOT_PROMOTED` |
| PARTIAL | corrupt/unknown fence; successなし |
| EXTRA | corrupt/unknown fence; successなし |
| THIRD | corrupt/unknown fence; successなし |

NULL-buffer length probeを含むrestart ABI、delete時のNEW / OLD / THIRD、classifierの
ABSENT / BOTHも別testで確認した。冒頭コメントに残っていた
「all NEW → OK」「CU read-back NEW → OK」はこの契約と矛盾するP2だったため、
実行コードを変えずに2件だけ修正した。修正後のtargeted inventoryは全てPASSした。

attestation gateはstatic default OFFである。
`ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation()`はNULL/emptyをparameter
error、全てのnon-empty inputをstate errorとして拒否し、gateをenableしない。
setter、weak hook、magic parser、外部verifierへの抜け道はない。magic prefix、
non-zero tail、opaque/digest-shaped bytesのnegative testもfail closedである。

## Negative control (RED mutation)

testが修復を実際に検出することを確認するため、`nrc1_replay_eligible()`を一時的に
常時eligibleへ戻した。`mfdt_v1_e2e_private`は期待どおり10 assertionでREDとなり、
次を検出した。

- warm/cold active+NRC1のcached response露出
- warm/cold NRC1-onlyのcached response露出
- retained NM30+NRC1のterminal retry露出

mutationは直ちに元へ戻した。復元後にnormal / sanitizer全26件とpinned target proofを
freshに再実行しており、RED mutationのsource residueはない。

## Host and spec verification

修正後スナップショットで次を再実行した。

```sh
ctest --test-dir build-codex-mfdt-final-normal \
  -R '^(multi_frame_durable_transfer_.*|mfdt_v1_.*)$' \
  --output-on-failure
```

結果: **26/26 PASS**。先頭10件のvector oracle、Python、Node、C、acceptance gateと
各self-testは**10/10 PASS**。

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
ctest --test-dir build-codex-mfdt-final-asan \
  -R '^(multi_frame_durable_transfer_.*|mfdt_v1_.*)$' \
  --output-on-failure
```

結果: **26/26 PASS**、sanitizer finding 0。spec/oracle/acceptance subsetも
**10/10 PASS**。

install/private boundaryは次を独立確認した。

```text
installed libninlil_runtime.a MFDT symbols: 0
private runtime MFDT symbols: 306
dedicated MFDT private archive symbols: 300
installed MFDT public header: 0
```

shared workspace全体のunfiltered CTestは本scopeの判定に使用していない。同時進行中の
RRMP status/link変更により、MFDT外のmarkdown link 2件とcompatibility statusが
未統合だったためである。MFDT 26-test inventoryにはその失敗を混入させていない。

## Pinned ESP-IDF final ELF / map / DRAM proof

コメント修正後にclean target buildを再生成した。

```sh
ESP_IDF_PIN=v5.5.3 bash tools/mfdt_v1_esp_idf_map_proof.sh
```

| Item | Evidence |
| --- | --- |
| ESP-IDF / target | `v5.5.3` / `esp32s3` |
| firmware binary | `0x52170` / 336240 bytes |
| final ELF | 5794956 bytes |
| final map | 4266925 bytes |
| MFDT DRAM BSS gate | `963 / 49152` bytes |
| final `.dram0.bss` | `0x7820` bytes |
| target smoke / required symbols | retained |
| lab store in final map | 0 |
| proof result | **PASS** |

| Artifact | SHA-256 |
| --- | --- |
| `ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.elf` | `a5df3941abe6e5ab1fdd81f89ab982632c33a624f4cf3d9ce0b3da4a44767c51` |
| `ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.map` | `244e5eeff310c0ca44d6d4331564c626870ad8f286902d2c16a14695ac8cf422` |

これはcompile/link/mapとtarget call-pathのsoftware evidenceであり、実機実行の代替ではない。

## Status recommendation and nonclaims

修復は**independent-reviewed private/default-OFF software candidate GO**とする。
ADR-0021、compatibility matrix、release statusをこのレビューだけで昇格してはならない。

| Surface | Recommendation |
| --- | --- |
| Accepted U6 / ADR-0006 | **変更なし** |
| ADR-0021 | `Proposed`のまま |
| MFDT private/default-OFF repair | software candidate GO |
| MF-O08 platform-rooted evidence / trust anchor | **OPEN / release blocker** |
| ESP32-S3 physical HIL | **NOT_RUN** |
| RF HIL | **NOT_RUN** |
| physical power-cut / reconstruct | **NOT_RUN** |
| `full_esp_hil_attested` | `false` |
| `physical_powercut_executed` | `false` |
| `SPEC_ACCEPTED` / `RELEASE_SUPPORTED` | **not claimed** |

実機promotionには、Accepted evidence schemaとtrust anchor、device/build/profile binding、
anti-rollback・expiry・revocation authority、negative rollback/revocation test、pinned
target closure、およびphysical power-cut matrixが必要である。それまではMF-O08を閉じず、
unattested replay gateをOFFのまま維持する。
