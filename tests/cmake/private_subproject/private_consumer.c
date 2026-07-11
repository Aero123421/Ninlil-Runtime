#include "runtime_lifecycle_model.h"

#include <string.h>

int main(void)
{
    ninlil_resource_limits_t limits;
    ninlil_model_capacity_limits_t derived;
    (void)memset(&limits, 0, sizeof(limits));
    return ninlil_model_runtime_derive_capacity_limits(&limits, &derived)
        == NINLIL_OK ? 0 : 1;
}
