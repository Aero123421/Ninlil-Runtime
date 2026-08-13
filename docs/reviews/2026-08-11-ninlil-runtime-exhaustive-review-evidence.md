# 2026-08-11 OSS review evidence graph

状態: per-OR local evidence authority

この索引は[原文provenance](2026-08-11-ninlil-runtime-exhaustive-review-index.md)で正規化した
OR-01〜37を、repository-localの作業記録、実装/gate authority、focused verificationへ結ぶ。
同じartifactを複数ORが共有する場合も各ORから明示的に辿れる。`CLOSED`はlocal修正・検証・
独立reviewが揃った状態であり、remote evidenceやexternal owner actionを置換しない。

最終HEADの独立review receiptとremote run/job rollupはPR #117へ記録し、この索引自体を
書き換えて検証対象SHAを変える循環を避ける。

<!-- ninlil-oss-review-evidence-v1:begin -->
```json
{
  "schema": "ninlil-oss-review-evidence-v1",
  "pull_request": "https://github.com/Aero123421/Ninlil-Runtime/pull/117",
  "entries": [
    {"id":"OR-01","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-verification-tranche.md","docs/work/2026-08-12-oss-review-docs-build-ux.md"],"authorities":["tools/traceability_complete_coverage_gate.py"],"checks":["traceability_complete_coverage_gate self-test"],"remote":"ci"},
    {"id":"OR-02","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-verification-tranche.md"],"authorities":["tools/traceability_complete_coverage_gate.py","requirements-traceability-coverage.json"],"checks":["dual-profile cited JUnit 47/47 and 46/46"],"remote":"ci"},
    {"id":"OR-03","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-docs-build-ux.md"],"authorities":["README.md","README.en.md"],"checks":["v1_integration_gate_e2e"],"remote":"ci"},
    {"id":"OR-04","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-decoder-fuzz.md"],"authorities":[".github/workflows/ci.yml","tools/decoder_fuzz_seed_corpus.py"],"checks":["six decoder fuzz targets and 33 semantic probes"],"remote":"decoder-fuzz"},
    {"id":"OR-05","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-abi-resource-gates.md"],"authorities":["cmake/abi_manifest_golden.cmake","tests/abi/golden/ILP32-le-32.manifest"],"checks":["abi drift focused 9/9"],"remote":"ci"},
    {"id":"OR-06","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-abi-resource-gates.md"],"authorities":["tools/abi_drift_schema.c"],"checks":["public layout deletion mutations"],"remote":"ci"},
    {"id":"OR-07","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-abi-resource-gates.md"],"authorities":["tools/r7_frag_esp_dram_budget_gate.py","tools/mfdt_v1_esp_dram_budget_gate.py"],"checks":["official ESP feature-ON map gates"],"remote":"esp"},
    {"id":"OR-08","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-docs-build-ux.md"],"authorities":["CMakeLists.txt","dependency-inventory.json","tools/release_workflow_identity_gate.py"],"checks":["Node pin and SBOM mutations"],"remote":"ci"},
    {"id":"OR-09","status":"EXTERNAL","records":["docs/work/2026-08-12-oss-review-legal-community-tranche.md"],"authorities":["tools/third_party_notice_gate.py","tools/dco_signoff_gate.py"],"checks":["first-party C/H 811/811 SPDX"],"remote":"dco-and-admin"},
    {"id":"OR-10","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-ux-docs-tranche.md"],"authorities":["compatibility-matrix.json","tools/compatibility_matrix_gate.py"],"checks":["feature omission and dependency mutations"],"remote":"ci"},
    {"id":"OR-11","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-docs-build-ux.md"],"authorities":["README.md","README.en.md"],"checks":["markdown link and README sync gates"],"remote":"ci"},
    {"id":"OR-12","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-ux-docs-tranche.md"],"authorities":["README.md","docs/status.md"],"checks":["README focused entry and status links"],"remote":"ci"},
    {"id":"OR-13","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-docs-build-ux.md"],"authorities":["README.md"],"checks":["README C11 example strict compile"],"remote":"ci"},
    {"id":"OR-14","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-spec-docs-tranche.md"],"authorities":["tools/public_header_contract_gate.py","include/ninlil/runtime.h"],"checks":["public header contract mutations and focused 18/18"],"remote":"ci"},
    {"id":"OR-15","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-docs-build-ux.md","docs/work/2026-08-12-oss-review-spec-docs-tranche.md"],"authorities":["README.en.md","docs/README.md"],"checks":["README and language registry gates"],"remote":"ci"},
    {"id":"OR-16","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-ux-docs-tranche.md"],"authorities":["docs/build-options.md","tools/build_options_docs_gate.py"],"checks":["23-option exact authority"],"remote":"ci"},
    {"id":"OR-17","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-ux-docs-tranche.md"],"authorities":["README.md","examples/multi_service_node"],"checks":["multi_service_node_host_actual_e2e"],"remote":"ci"},
    {"id":"OR-18","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-docs-build-ux.md"],"authorities":[".gitignore"],"checks":["README workflow worktree hygiene"],"remote":"ci"},
    {"id":"OR-19","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-layering-invariant.md"],"authorities":["tools/layering_invariant_gate.py"],"checks":["layering gate check and mutation self-test"],"remote":"ci"},
    {"id":"OR-20","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-installed-runtime-boundary.md"],"authorities":["cmake/ninlil_host_runtime_sources.cmake","cmake/installed_host_runtime_tests_off_smoke.cmake"],"checks":["exact Host source and archive multiset"],"remote":"ci"},
    {"id":"OR-21","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-mfdt-owner-state.md","docs/work/2026-08-12-oss-review-r7-owner-state.md","docs/work/2026-08-12-oss-review-rrmp-owner-scratch.md","docs/work/2026-08-12-oss-review-rrmp-serial-owner.md"],"authorities":["tools/ci_completion_feature_host_matrix.sh"],"checks":["owner-state normal and sanitizer matrices"],"remote":"ci-and-esp"},
    {"id":"OR-22","status":"CLOSED","records":["docs/work/2026-08-13-oss-review-runtime-step-epilogue.md"],"authorities":["src/runtime/runtime_public.c","tools/runtime_step_epilogue_gate.py"],"checks":["four-profile configured-compiler single-epilogue mutations and v1_runtime_delivery faults"],"remote":"ci"},
    {"id":"OR-23","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-cmake-test-authority.md"],"authorities":["CMakeLists.txt","cmake/ninlil_ctest.cmake"],"checks":["tracked pre/post split semantic roster audit"],"remote":"ci"},
    {"id":"OR-24","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-verification-tranche.md"],"authorities":["tools/domain_store_vector_gen.py"],"checks":["domain store KAT and oracle mutations"],"remote":"ci"},
    {"id":"OR-25","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-verification-tranche.md"],"authorities":[".github/workflows/coverage.yml","tools/release_workflow_identity_gate.py"],"checks":["coverage map workflow mutations"],"remote":"coverage"},
    {"id":"OR-26","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-verification-tranche.md"],"authorities":[".github/workflows/codeql.yml","tools/release_workflow_identity_gate.py"],"checks":["CodeQL envelope and scope mutations"],"remote":"codeql"},
    {"id":"OR-27","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-docs-build-ux.md"],"authorities":["tools/protocol_magic_registry_gate.py"],"checks":["8-process self-test and source residue zero"],"remote":"ci"},
    {"id":"OR-28","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-fabric-radio-stack.md"],"authorities":["tools/esp_storage_stack_gate.py","tools/esp_idf_component_packaging_gate.py"],"checks":["exact static stack artifacts and mutations"],"remote":"esp"},
    {"id":"OR-29","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-build-portability.md"],"authorities":["cmake/ninlil_ctest.cmake"],"checks":["long cwd/compiler/timeout/wall-clock focused negatives"],"remote":"ci"},
    {"id":"OR-30","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-ux-docs-tranche.md"],"authorities":["docs/v1-lab-quickstart.md","docs/v1-lab-developer.md","docs/v1-lab-distribution-manifest.md"],"checks":["historical banners and current links"],"remote":"ci"},
    {"id":"OR-31","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-spec-docs-tranche.md"],"authorities":["docs/34-v2-runtime-fabric-completion.md"],"checks":["private prototype boundary mutations"],"remote":"ci"},
    {"id":"OR-32","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-spec-docs-tranche.md"],"authorities":["docs/README.md","tools/markdown_link_gate.py"],"checks":["51-document source-language closed registry"],"remote":"ci"},
    {"id":"OR-33","status":"EXTERNAL","records":["docs/work/2026-08-12-oss-review-legal-community-tranche.md"],"authorities":["README.md"],"checks":["CI badge local; repository metadata owner action pending"],"remote":"admin"},
    {"id":"OR-34","status":"CLOSED","records":["docs/work/2026-08-12-oss-review-installed-runtime-boundary.md"],"authorities":["cmake/ninlil_host_runtime_sources.cmake","tools/layering_invariant_gate.py"],"checks":["private source and symbol injection negatives"],"remote":"ci"},
    {"id":"OR-35","status":"NO_ACTION","records":["docs/reviews/2026-08-11-ninlil-runtime-exhaustive-review-index.md"],"authorities":["tools/oss_review_provenance_gate.py"],"checks":["positive observation spans mapped without promotion"],"remote":"not-applicable"},
    {"id":"OR-36","status":"CLOSED","records":["docs/work/2026-08-13-oss-review-documentation-taxonomy.md"],"authorities":["docs/README.md","docs/host-runtime-tutorial.md","tools/markdown_link_gate.py"],"checks":["six distinct documentation classes and exact-command tutorial smoke"],"remote":"ci"},
    {"id":"OR-37","status":"NO_ACTION","records":["docs/reviews/2026-08-11-ninlil-runtime-exhaustive-review-index.md"],"authorities":["docs/00-project-charter.md","README.md"],"checks":["target and current maturity remain pre-alpha"],"remote":"not-applicable"}
  ]
}
```
<!-- ninlil-oss-review-evidence-v1:end -->

## Remote evidence boundary

Final-head remote evidence is accepted only when PR #117 reports no failed, cancelled, skipped, or
pending checks and the specialized ESP、CodeQL、coverage、DCO jobs match that head SHA. Physical HIL、
RF soak、legal holder/year、required-check administration、repository description/topics/Discussionsは
このgraphのlocal evidenceから推測しない。
