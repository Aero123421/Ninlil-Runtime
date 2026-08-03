/*
 * Host runner for ninlil_r7_frag_target_smoke_run (deterministic vectors).
 */

#include "r7_crypto_openssl3.h"
#include "r7_frag_target_smoke.h"

#include <stdio.h>

int main(void)
{
    ninlil_r7_crypto_provider prov;
    int32_t st;

    if (ninlil_r7_crypto_openssl3_provider_init(&prov) != NINLIL_R7_CRYPTO_OK) {
        fprintf(stderr, "provider init fail\n");
        return 1;
    }
    st = ninlil_r7_frag_target_smoke_run(&prov);
    if (st != 0) {
        fprintf(stderr, "r7_frag_target_smoke FAIL code=%d\n", (int)st);
        return 1;
    }
    fprintf(stderr, "r7_frag_target_smoke: OK (LINK_ACK+multi+reorder+restart+retry)\n");
    return 0;
}
