/*
 * Deterministic barrier test: concurrent membership_load A then B where A
 * completes after B must not overwrite B's result (logical stale completion).
 *
 * Requires NINLIL_WIFI_M4_TEST_HOOKS on the library and this TU.
 */
#include "wifi_attachment_m4.h"

static ninlil_wifi_m4_owner_t g_m4_owner;

#include "in_memory_storage.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__);          \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_a_in_io;
static int g_release_a;
static int g_b_done;

static const ninlil_storage_ops_t *g_ops;
static void *g_store;
static ninlil_wifi_m4_full_evidence_t *g_ev;
static ninlil_wifi_status_t g_a_st;

static void io_hook(void *user)
{
    int is_a = (user != NULL) ? 1 : 0;
    if (!is_a) {
        return;
    }
    (void)pthread_mutex_lock(&g_mu);
    g_a_in_io = 1;
    (void)pthread_cond_broadcast(&g_cv);
    while (g_release_a == 0) {
        (void)pthread_cond_wait(&g_cv, &g_mu);
    }
    (void)pthread_mutex_unlock(&g_mu);
}

static void *thread_a(void *arg)
{
    (void)arg;
    /* Mark hook user non-NULL => this load is the "old" A path. */
    ninlil_wifi_m4_test_set_storage_io_hook(io_hook, (void *)1);
    /* Empty path → MISSING if applied; must not clobber B's FULL. */
    g_a_st = ninlil_wifi_m4_membership_load_classify(
        &g_m4_owner, g_ops, g_store, "m4-empty", 5000u, g_ev);
    ninlil_wifi_m4_test_set_storage_io_hook(NULL, NULL);
    return NULL;
}

int main(void)
{
    ninlil_wifi_m4_owner_init(&g_m4_owner);

    ninlil_test_storage_t *store;
    ninlil_test_storage_config_t cfg;
    const ninlil_storage_ops_t *ops;
    ninlil_wifi_m4_full_evidence_t ev;
    ninlil_wifi_m4_membership_lease_t lease;
    uint8_t peer[16];
    uint8_t auth[16];
    uint8_t bind[32];
    pthread_t th;
    ninlil_wifi_status_t bst;
    failures = 0;

    CHECK(ninlil_wifi_m4_owner_restart(&g_m4_owner) == NINLIL_WIFI_OK);

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 32u;
    cfg.max_bytes_per_namespace = 65536u;
    store = ninlil_test_storage_create(&cfg);
    CHECK(store != NULL);
    ops = ninlil_test_storage_ops(store);
    g_ops = ops;
    g_store = store;
    g_ev = &ev;

    (void)memset(peer, 0xab, sizeof(peer));
    (void)memset(auth, 0xd0, sizeof(auth));
    (void)memset(bind, 0xb1, sizeof(bind));
    (void)memset(&lease, 0, sizeof(lease));
    (void)memcpy(lease.member_runtime_id, peer, 16u);
    lease.lease_not_before_ms = 1000u;
    lease.lease_not_after_ms = 999999u;
    (void)memcpy(lease.authority_id, auth, 16u);
    (void)memcpy(lease.binding_digest, bind, 32u);
    CHECK(ninlil_wifi_m4_membership_store_full(ops, store, "m4-full", &lease)
        == NINLIL_WIFI_OK);

    CHECK(ninlil_wifi_m4_evidence_reset(&g_m4_owner, &ev) == NINLIL_WIFI_OK);

    /* Start A: will park in I/O hook before reading empty path. */
    g_a_in_io = 0;
    g_release_a = 0;
    g_b_done = 0;
    CHECK(pthread_create(&th, NULL, thread_a, NULL) == 0);

    (void)pthread_mutex_lock(&g_mu);
    while (g_a_in_io == 0) {
        (void)pthread_cond_wait(&g_cv, &g_mu);
    }
    (void)pthread_mutex_unlock(&g_mu);

    /* B: newer load of FULL path completes while A is still in I/O. */
    ninlil_wifi_m4_test_set_storage_io_hook(NULL, NULL);
    bst = ninlil_wifi_m4_membership_load_classify(&g_m4_owner, ops, store, "m4-full", 5000u, &ev);
    CHECK(bst == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_m4_evidence_membership_live(&ev) == 1);
    CHECK(ninlil_wifi_m4_evidence_class_membership(&ev)
        == NINLIL_WIFI_M4_CLASS_FULL);
    g_b_done = 1;

    /* Release A: stale completion must DENY and leave B's FULL intact. */
    (void)pthread_mutex_lock(&g_mu);
    g_release_a = 1;
    (void)pthread_cond_broadcast(&g_cv);
    (void)pthread_mutex_unlock(&g_mu);
    (void)pthread_join(th, NULL);

    CHECK(g_a_st == NINLIL_WIFI_DENIED);
    CHECK(ninlil_wifi_m4_evidence_membership_live(&ev) == 1);
    CHECK(ninlil_wifi_m4_evidence_class_membership(&ev)
        == NINLIL_WIFI_M4_CLASS_FULL);

    ninlil_wifi_m4_evidence_consume(&ev);
    ninlil_test_storage_destroy(store);
    CHECK(ninlil_wifi_m4_owner_restart(&g_m4_owner) == NINLIL_WIFI_OK);

    if (failures != 0) {
        (void)fprintf(stderr, "wifi_v1_m4_stale_load_barrier_test FAIL\n");
        return 1;
    }
    (void)printf(
        "wifi_v1_m4_stale_load_barrier_test PASS a_stale=DENIED b_full=kept\n");
    return 0;
}
