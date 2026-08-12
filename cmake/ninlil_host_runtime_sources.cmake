# Single authority for the installable Host Runtime implementation.
#
# This list is intentionally smaller than NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES:
# the private archive is an integration/test vehicle and may contain LAB and
# default-OFF candidates, while Ninlil::runtime is a public SDK artifact.
# Paths are relative to the repository root. Do not use file(GLOB), append LAB
# sources, or reuse the mutable private-source list here.

set(NINLIL_HOST_RUNTIME_RELATIVE_SOURCES
    src/model/control_frame_codec.c
    src/model/domain_store_body_codec.c
    src/model/domain_store_codec.c
    src/model/ncl1_codec.c
    src/model/resource_ledger.c
    src/model/resource_ledger_batch.c
    src/model/runtime_lifecycle_model.c
    src/model/runtime_store_bootstrap.c
    src/model/runtime_store_codec.c
    src/model/submission_admission.c
    src/model/submission_preflight.c
    src/runtime/domain_store_d3s1.c
    src/runtime/domain_store_d3s2.c
    src/runtime/domain_store_d3s3.c
    src/runtime/domain_store_d3s4.c
    src/runtime/domain_store_scanner.c
    src/runtime/runtime_public.c
    src/runtime/runtime_terminal_owner_projection.c
    src/runtime/runtime_store_orchestrator.c
    src/runtime/runtime_store_stage5_seam.c
    src/runtime/runtime_v1_spine_durable.c
    src/runtime/runtime_v1_delivery_durable.c
    src/runtime/runtime_v1_transaction_codec.c
    src/runtime/runtime_v1_bearer_wire.c
    src/runtime/runtime_v1_capability.c
    src/runtime/runtime_v1_event_ledger_codec.c
    src/runtime/runtime_v1_event_mgmt.c
    src/runtime/runtime_v1_family_capability.c
    src/runtime/runtime_v1_target_resolver.c
    src/runtime/submission_canonical_v1.c
    src/runtime/stage5_empty_metadata.c
    src/runtime/v1_durable_allowlist.c
    src/runtime/v1_durable_restart.c
    src/runtime/storage_canonical_plan.c
    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}
)
