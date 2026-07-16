#include "in_memory_storage.h"
#include "storage_conformance.h"

#include <stdio.h>

int main(void)
{
    static const uint8_t storage_namespace[] = {
        0x73u, 0x68u, 0x61u, 0x72u, 0x65u, 0x64u, 0x00u, 0xffu
    };
    const ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    int result;

    if (storage == NULL) {
        return 1;
    }
    result = ninlil_test_storage_conformance_run(
        ninlil_test_storage_ops(storage),
        storage_namespace,
        (uint32_t)sizeof(storage_namespace),
        NINLIL_STORAGE_SCHEMA_M1A);
    ninlil_test_storage_destroy(storage);
    if (result == 0) {
        (void)printf("in-memory shared storage conformance ok\n");
    }
    return result;
}
