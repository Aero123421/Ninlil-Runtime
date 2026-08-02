# Production Attachment PA-S0 NO-GO repair

日付: 2026-07-31  
対象: Proposed ADR-0023 / docs 35 / PA-S0 specification authorities  
起点:
[`2026-07-31-production-attachment-independent-review.md`](../reviews/2026-07-31-production-attachment-independent-review.md)  
状態: **repair candidate complete; fresh independent re-review pending**

## Scope and non-claims

pre-repair独立監査のP1=5 / P2=4へ、仕様、deterministic vector、独立authority、
Python/Node/C11 gatesを同期した。production runtime、public ABI、dependency採用、
real EDHOC/provider crypto correctness、physical HIL、field/legal、
`SPEC_ACCEPTED`/`RELEASE_SUPPORTED`は変更していない。

Grok Buildその他の外部AI CLIは使用していない。commit/pushはこの作業では行わない。

## Repair summary

### P1

1. **Per-row re-attachment truth**
   - 15 rowsそれぞれに`old_present`、OLD value/SHA/context、NEW value/contextを固定。
   - OLD cardinality constantを削除。fixtureはlegal lane OLD 6 + AL 4 + HW 4、
     marker absent。
   - OLD/NEW/STABLE/THIRD row classifierと10,000 restart-per-cycle monotonic
     transcriptをPython/Node/C11で実行。
2. **Constructible prerequisites**
   - copy-owned Factory Identity `PROVISIONED` claim、Site Membership `ACTIVE`
     claim、role別CCS/public digest/kid/provider generation/opaque key reference。
   - caller-owned 32-byte one-write P-256 static-DH port、no private/backend export、
     no reentry、partial output/PRK後zeroization。
   - 9 failure familiesをwire/exporter/published/private export 0でterminal化。
   - 上流Acceptance未確立を明記し、startはfail closed。
3. **EDHOC attempt state machine**
   - suite 2/3それぞれMessage 1..4 NAC1をmaterialize。
   - Message 4前exporter 0、EAD_1..4 non-empty terminal、automatic downgrade 0。
   - synthetic profile traceとreal provider KATを明確に分離。
4. **Actual NAR owner**
   - fixed 5 slotsへ実packetを投入。
   - canonical/reorder success、exact duplicate no-progress、conflict、gap+timeout、
     overlap、mixed tuple、outer/inner mismatch、source mismatchを実行。
   - failure publicationは0。
5. **Source-first pre-auth owner**
   - owner key先頭をsource locatorに固定。
   - per-source 1/global 8、fixed 2 fragments、token capacity/refill 2/2 s、
     idle 9 s、current/previous bucket、cookie前identity/resolver allocation 0。

### P2

1. global magic registryとcollision/self-test gateを追加。
2. 612-byte NAS incremental ownerでpartial successとshort/trailing/future/
   inner-carrier failureを実行。
3. emission-only CLI、pure construction、expected model、independent formula/state
   authorityを分離。coherent drift 12件と全machine leaf campaignを追加。
4. ADR-0028 laneは変更せず、ADR-0023/docs 35からdependency closureを
   cross-reference。P2-04の正式closureはADR-0028側の独立review事項。

## Principal files

- `docs/adr/0023-production-attachment-edhoc-profile.md`
- `docs/adr/README.md`
- `docs/35-production-attachment-edhoc-profile.md`
- `docs/reviews/2026-07-31-production-attachment-independent-review.md`
- `docs/reviews/README.md`
- `spec/protocol-magic-registry-v1.json`
- `spec/vectors/production-attachment-edhoc-v1.json`
- `tools/production_attachment_edhoc_vector_gen.py`
- `tools/production_attachment_edhoc_composition.py`
- `tools/production_attachment_edhoc_compose.py`
- `tools/production_attachment_edhoc_expected_model.py`
- `tools/production_attachment_edhoc_independent_authority.py`
- `tools/production_attachment_edhoc_schema_authority.py`
- `tools/production_attachment_edhoc_closed_key_schema.json`
- `tools/production_attachment_edhoc_gate.py`
- `tools/production_attachment_edhoc_gate.mjs`
- `tools/protocol_magic_registry_gate.py`
- `tests/radio/production_attachment_edhoc_vector_test.c`
- `CMakeLists.txt`

## Verification

Vector SHA-256:
`f9cef8d9d9ea74b4914d9dcae5562df9f6b9583dc28f0ed238adde2d3765806e`

Normal focused CTest:

```text
production_attachment_edhoc_vector_oracle              PASS
production_attachment_edhoc_vector_oracle_self_test    PASS
production_attachment_edhoc_python_gate                PASS
production_attachment_edhoc_python_gate_self_test      PASS
production_attachment_edhoc_node_gate                  PASS
production_attachment_edhoc_node_gate_self_test        PASS
production_attachment_magic_registry_gate              PASS
production_attachment_magic_registry_gate_self_test    PASS
production_attachment_edhoc_c11_gate                   PASS
production_attachment_edhoc_fixture_freshness          PASS
10/10 PASS
```

Mutation/closed-schema evidence:

- Python: total mutations 8,324、scalar leaf campaign 7,458、
  767/767 unknown-key rejected、false-green 0。
- Node: total mutations 8,319、scalar leaf campaign 7,458、
  767/767 unknown-key rejected、false-green 0。
- independent repaired coherent CRC/digest campaign: 12 trials。
- C11: 70 distinct executed acceptance cases。

Sanitizer evidence:

```text
NINLIL_ENABLE_SANITIZERS=ON
production_attachment_edhoc_c11_gate 1/1 PASS
```

## Remaining evidence

- fresh independent review of this repaired snapshot
- accepted EDHOC dependency/source/license and allocator evidence
- real suite 2/3 Host/ESP provider KAT and cross-provider equality
- production credential resolver/local static-DH/NAR/NAS/EDHOC/N6 batch owners
- protected exchange real AEAD ciphertext and fault-at-every-op evidence
- Linux/macOS USB, ESP32-S3 Wi-Fi, ESP32-S3+SX1262 physical HIL
- field/legal deployment evidence

ADR-0023 and docs 35 remain **Proposed**. HIL status is **NOT_RUN**.
