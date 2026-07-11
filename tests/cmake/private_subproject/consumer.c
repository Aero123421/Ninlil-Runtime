#include <ninlil/runtime.h>

static int would_fail_if_child_werror_leaked(void)
{
    return 0;
}

int main(void)
{
    return NINLIL_STORAGE_SCHEMA_M1A == 1u ? 0 : 1;
}
