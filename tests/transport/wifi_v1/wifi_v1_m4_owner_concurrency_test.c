/*
 * Concurrent mint/ready/consume/restart against M4 owner registry.
 * Validates mutex serialization (no use-after-reuse under race).
 * Build with TSan when available (non-Apple CI).
 */
#include "wifi_attachment_m4.h"

static ninlil_wifi_m4_owner_t g_m4_owner;

#include <pthread.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void bump_fail(void)
{
    (void)__atomic_fetch_add(&failures, 1, __ATOMIC_RELAXED);
}

#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__);          \
            bump_fail();                                                        \
        }                                                                       \
    } while (0)

enum { NTHREADS = 8, NITERS = 200 };

static void *worker(void *arg)
{
    uintptr_t id = (uintptr_t)arg;
    uint32_t i;
    for (i = 0u; i < (uint32_t)NITERS; ++i) {
        ninlil_wifi_m4_full_evidence_t ev;
        ninlil_wifi_m4_full_evidence_t alias;
        ninlil_wifi_status_t st;
        (void)memset(&ev, 0, sizeof(ev));
        st = ninlil_wifi_m4_evidence_reset(&g_m4_owner, &ev);
        if (st == NINLIL_WIFI_CAPACITY) {
            /* Another thread holds all slots; retry after consume path. */
            continue;
        }
        if (st != NINLIL_WIFI_OK) {
            bump_fail();
            continue;
        }
        /* Empty live handle is not ready. */
        if (ninlil_wifi_m4_evidence_ready_for_attach(&ev) != NINLIL_WIFI_DENIED) {
            bump_fail();
        }
        alias = ev;
        if ((i & 3u) == 0u) {
            (void)ninlil_wifi_m4_owner_restart(&g_m4_owner);
            if (ninlil_wifi_m4_evidence_ready_for_attach(&alias)
                != NINLIL_WIFI_DENIED) {
                bump_fail();
            }
        } else if ((i & 3u) == 1u) {
            ninlil_wifi_m4_evidence_consume(&ev);
            if (ninlil_wifi_m4_evidence_ready_for_attach(&alias)
                != NINLIL_WIFI_DENIED) {
                bump_fail();
            }
        } else {
            st = ninlil_wifi_m4_evidence_reset(&g_m4_owner, &ev);
            if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_CAPACITY) {
                bump_fail();
            }
            if (ninlil_wifi_m4_evidence_ready_for_attach(&alias)
                != NINLIL_WIFI_DENIED) {
                bump_fail();
            }
            ninlil_wifi_m4_evidence_consume(&ev);
        }
        (void)id;
    }
    return NULL;
}

int main(void)
{
    ninlil_wifi_m4_owner_init(&g_m4_owner);

    pthread_t th[NTHREADS];
    uintptr_t t;
    failures = 0;
    CHECK(ninlil_wifi_m4_owner_restart(&g_m4_owner) == NINLIL_WIFI_OK);

    for (t = 0u; t < (uintptr_t)NTHREADS; ++t) {
        if (pthread_create(&th[t], NULL, worker, (void *)t) != 0) {
            failures += 1;
        }
    }
    for (t = 0u; t < (uintptr_t)NTHREADS; ++t) {
        (void)pthread_join(th[t], NULL);
    }

    /* Synthetic first-slot still denied after concurrent churn. */
    {
        ninlil_wifi_m4_full_evidence_t forged;
        (void)memset(&forged, 0, sizeof(forged));
        forged.opaque[0] = 0x4cu;
        forged.opaque[1] = 0x48u;
        forged.opaque[2] = 0x34u;
        forged.opaque[3] = 0x4du;
        forged.opaque[8] = 1u;
        forged.opaque[16] = 1u;
        CHECK(ninlil_wifi_m4_evidence_ready_for_attach(&forged)
            == NINLIL_WIFI_DENIED);
    }

    if (failures != 0) {
        (void)fprintf(
            stderr, "wifi_v1_m4_owner_concurrency_test FAIL failures=%d\n",
            failures);
        return 1;
    }
    (void)printf("wifi_v1_m4_owner_concurrency_test PASS\n");
    return 0;
}
