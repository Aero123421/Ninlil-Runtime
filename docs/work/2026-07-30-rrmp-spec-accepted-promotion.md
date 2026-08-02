# 2026-07-30 RRMP joint SPEC_ACCEPTED promotion

状態: **promotion metadata complete in RRMP authority tranche — P0=0 / P1=0**

対象:

- ADR-0019 Route Authority and Relay Lifecycle
- ADR-0020 Multi-parent Ownership, Diversity and Failover
- joint RRMP generator、vector、private API catalog、Python / Node / C gates

## Verdict

ADR-0019とADR-0020を片側だけ昇格せず、2026-07-30付でjoint
**Accepted / SPEC_ACCEPTED**へ昇格した。根拠は
[RRMP final repair independent review](../reviews/2026-07-29-rrmp-final-repair-review.md)
の **GO — P0=0 / P1=0** と、昇格後authorityに対する本記録の再検証である。

これはdesign authorityの受入だけであり、Normative wire/storage bytes、
production implementation source、公開ABIを変更していない。

## Exact claim boundary

| Claim | Value |
| --- | ---: |
| `spec_accepted` | **1** |
| `implementation` | **0** |
| `hil` | **0** |
| `release_supported` | **0** |
| `public_abi` | **0** |

private/default-OFF software candidateとHost/ESP compile/link/map evidenceは存在するが、
上表の非claimを昇格させない。特にphysical ESP boot/runtime PSRAM、RF 2/3-hop、
multi-parent air failover、flash power-cutはすべて **NOT_RUN** のままである。

## Promotion changes

1. 両ADRのstatus、受入日、SPEC_ACCEPTED日、acceptance evidence、非claim境界を同期した。
2. generatorを唯一のmaterializerとしてvectorとprivate API catalogを再生成した。
3. vector top-level statusを`SPEC_ACCEPTED`、P1 repair statusを
   `SPEC_ACCEPTED_DESIGN_AUTHORITY`へ更新した。
4. Python / Node独立pinとself-test pinを`spec_accepted=1`、他claim=0へ同期した。
5. C fixtureを同じclaim境界へ同期した。実C11 `-Werror`検証で見つかった同一bound
   macroの重複emitをgeneratorで除去し、重複macroを恒久的に拒否するself-testを追加した。
6. production C/C++実装、public headers、README、ADR index、
   `compatibility-matrix.json`は本担当では変更していない。README/index/matrixは
   root integration ownerが同じpromotion trancheで同期する。

## Pre-promotion review snapshot

独立review artifactに記録された次のhashは、review時点の
**pre-promotion Proposed snapshot** を固定する歴史証拠である。昇格後ファイルのhashと
一致しないことが正しく、review artifact自体は書き換えない。

| Authority | Pre-promotion SHA-256 |
| --- | --- |
| `src/runtime/route_relay_v1/rrmp_core.c` | `01b125a847e7c6655ed102e05e84adcdd87a154eef9b064fc737503200cf6e6b` |
| `tests/runtime/route_relay_v1/rrmp_storage_atomicity_test.c` | `bbf54f61bf0a5ad855ff21a9a34a59eb46dd568018423434d81654eaebb720ae` |
| `docs/adr/0019-route-relay.md` | `b184d5708508773e03a2d8bf0c4b532392fd0404dcc772e21c7a9f4945be444b` |
| `docs/adr/0020-multi-parent.md` | `29863d3fae96f49142d09f919dba44edbb0f6d3c9d9ec5e1bb081e43081421af` |
| `spec/vectors/route-relay-multiparent-spec-v1.json` | `7c133639252fa5cc1cc26001703a70c64215bd4f1a14efa9912ba154240d0dce` |

## Post-promotion authority snapshot

| Authority | Post-promotion SHA-256 |
| --- | --- |
| `docs/adr/0019-route-relay.md` | `dabf5771a1a2bcedb70449b388642caf3c69c79a0a91e67b831201a3b377dc24` |
| `docs/adr/0020-multi-parent.md` | `23adab9897c983bff0fdd413aab65beabe016f2a558c22d472dc487e4b8c4821` |
| `spec/vectors/route-relay-multiparent-spec-v1.json` | `66d527a2f49ca25c8055ea5fad7cb4c9f46a5cae03bd6c8b1ad1333a04fabdd4` |
| private API catalog | `187788389ef4f52332b09e985d1ec17440795df32d6210051c60910da0291330` |
| generator | `192188b96b1d0ddbf5c0d19f3307a77b5bcf15dbd7ca71e388c5ad5a39915ad4` |
| Python gate | `3cb035ffdf807eb733f333194ae2b5742a93653995883d859ca0e6f77d22074b` |
| Node gate | `2b5e61d522bfbf438899dbfa822ef8abe287ee46c2b670b1433546fc57e63b33` |
| deterministic C fixture | `b0505fb7437966027f631fe34e51111a1b9cd8fd303266fd94c6f2c16c2fef69` |

vector内のrestoration hashesはgenerator、Python gate、Node gateと一致し、
authority envelopeは
`ebe2c64251451d26d67ca84efd5188b80f0ae33f6e95a9ccb33f9960703814d6`
である。

## Verification

| Gate | Result |
| --- | --- |
| generator `--check` | PASS; 114 cases |
| generator `--self-test` | PASS; deterministic vector/C fixture、duplicate macro reject |
| Python `--check` | PASS; 114/114 exact REQUIRED_IDS |
| Python `--self-test` | PASS; 12,882/12,882 donor mutations rejected |
| Node `--check` | PASS; 114/114 exact REQUIRED_IDS |
| Node `--self-test` | PASS; 12,882/12,882 donor mutations rejected |
| C fixture emit twice + byte comparison | PASS |
| C11 syntax `-Wall -Wextra -Werror` | PASS |
| C preprocessor claim pins | PASS; `1/0/0/0/0` exact |
| normal focused RRMP/spec/resource/symbol suite | **18/18 PASS** |
| Clang ASan+UBSan focused RRMP/spec/resource/symbol suite | **18/18 PASS** |
| exact lifecycle included in both C suites | **10,000/10,000 PASS** |
| `git diff --check` for this tranche | PASS |
| stale RRMP status wording audit | PASS; status-level `Proposed` / pending acceptance = 0 |

ASan buildの初回symbol archive gateは対象archiveが未ビルドだったためREDになった。
同じASan構成で`ninlil_runtime_private`をビルド後、当該gateと全18件を再実行して
18/18 PASSを確認した。これはsource defectではなくbuild prerequisiteの明示化である。

## Integration boundary

root integration ownerは、同一promotionとしてADR indexとcompatibility matrixの
`relay` / `multi-parent-multi-controller`を`SPEC_ACCEPTED`へ同期し、state ceilingを
`SPEC_ACCEPTED`より上へ上げない。その同期後にcompatibility matrix gateを実行する。
本記録はREADME/index/matrixの完了を先取りして主張しない。

