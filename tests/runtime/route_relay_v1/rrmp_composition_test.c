#include "rrmp_host_lifecycle_fixture.h"
#include "rrmp_test_common.h"

#include <stdio.h>
#include <stdalign.h>

enum { RRMP_WS_MAX = 512 * 1024 };
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_ws[RRMP_WS_MAX];

int main(void)
{
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    int32_t st;
    RRMP_CHECK(need > 0u);
    RRMP_CHECK(need <= RRMP_WS_MAX);
    RRMP_CHECK(need <= NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES);
    st = ninlil_rrmp_host_lifecycle_run(g_ws, need);
    if (st != NINLIL_RRMP_HOST_LIFE_OK) {
        fprintf(stderr, "host lifecycle failed st=%d\n", (int)st);
        return 1;
    }
    printf("rrmp_composition_test OK host_lifecycle ws=%zu\n", need);
    return 0;
}
