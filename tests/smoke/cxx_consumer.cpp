#include <ninlil/runtime.h>

#include <cstddef>
#include <cstdint>

namespace {

void exercise_abi_types()
{
    ninlil_service_descriptor_t descriptor{};
    descriptor.abi_version = NINLIL_ABI_VERSION;
    descriptor.struct_size = static_cast<uint16_t>(sizeof(ninlil_service_descriptor_t));

    ninlil_transaction_snapshot_t snapshot{};
    snapshot.abi_version = NINLIL_ABI_VERSION;
    snapshot.struct_size = static_cast<uint16_t>(sizeof(ninlil_transaction_snapshot_t));
    snapshot.targets = nullptr;
    snapshot.target_capacity = 0;
    snapshot.target_count = 0;

    ninlil_metrics_snapshot_t metrics{};
    metrics.abi_version = NINLIL_ABI_VERSION;
    metrics.struct_size = static_cast<uint16_t>(sizeof(ninlil_metrics_snapshot_t));

    static_assert(NINLIL_ABI_VERSION == 0x0001u, "ABI version mismatch");
    static_assert(NINLIL_STORAGE_SCHEMA_M1A == 1u, "storage schema mismatch");
    static_assert(
        NINLIL_FOUNDATION_MAX_EXACT_TARGETS == 4u,
        "exact-target profile mismatch");
    static_assert(NINLIL_ROLE_CONTROLLER == 1u, "controller role mismatch");
    static_assert(NINLIL_ROLE_ENDPOINT == 2u, "endpoint role mismatch");
    static_assert(
        NINLIL_ROLE_CELL_AGENT == 3u,
        "cell-agent role mismatch");
    static_assert(
        NINLIL_ROLE_CELL_AGENT_RESERVED == NINLIL_ROLE_CELL_AGENT,
        "cell-agent compatibility alias mismatch");
    static_assert(NINLIL_ENV_TEST == 1u, "test environment mismatch");
    static_assert(NINLIL_ENV_LAB == 2u, "lab environment mismatch");
    static_assert(NINLIL_ENV_FIELD == 3u, "field environment mismatch");
    static_assert(
        NINLIL_ENV_PRODUCTION == 4u,
        "production environment mismatch");
    static_assert(
        NINLIL_ENV_LAB_RESERVED == NINLIL_ENV_LAB,
        "lab compatibility alias mismatch");
    static_assert(
        NINLIL_ENV_FIELD_RESERVED == NINLIL_ENV_FIELD,
        "field compatibility alias mismatch");
    static_assert(
        NINLIL_ENV_PRODUCTION_RESERVED == NINLIL_ENV_PRODUCTION,
        "production compatibility alias mismatch");
    static_assert(sizeof(ninlil_id128_t) == 16u, "id128 size mismatch");
    static_assert(sizeof(ninlil_text_id_t) == 64u, "text_id size mismatch");

    (void)descriptor;
    (void)snapshot;
    (void)metrics;
}

} // namespace

int main()
{
    exercise_abi_types();
    return 0;
}
