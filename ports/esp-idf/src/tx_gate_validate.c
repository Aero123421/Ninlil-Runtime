#include "ninlil_esp_idf/cell_agent.h"

int ninlil_esp_idf_tx_gate_ops_validate(const ninlil_tx_gate_ops_t *ops)
{
    if (ops == NULL) {
        return 0;
    }
    if (ops->abi_version != NINLIL_ABI_VERSION) {
        return 0;
    }
    if (ops->struct_size < (uint16_t)sizeof(*ops)) {
        return 0;
    }
    if (ops->acquire == NULL || ops->release_unused == NULL) {
        return 0;
    }
    return 1;
}
