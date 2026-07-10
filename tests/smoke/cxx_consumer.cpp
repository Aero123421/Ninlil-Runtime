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
