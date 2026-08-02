#include "wifi_credentials.h"

#include "in_memory_storage.h"

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

int main(void)
{
    ninlil_wifi_credential_store_t store;
    ninlil_wifi_credential_store_t cold;
    ninlil_test_storage_t *storage;
    ninlil_test_storage_config_t cfg;
    const ninlil_storage_ops_t *ops;
    uint8_t d1[32];
    uint8_t d2[32];
    failures = 0;
    (void)memset(d1, 0xa5, sizeof(d1));
    (void)memset(d2, 0x5a, sizeof(d2));
    ninlil_wifi_credential_store_init(&store);
    CHECK(ninlil_wifi_credential_stage(&store, d1, 1u) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_activate(&store) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_is_active(&store) == 1);
    CHECK(ninlil_wifi_credential_stage(&store, d1, 1u) == NINLIL_WIFI_FENCED);
    CHECK(ninlil_wifi_credential_stage(&store, d2, 2u) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_commit(&store) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_observe(&store, d1, 2u) == NINLIL_WIFI_FENCED);
    CHECK(ninlil_wifi_credential_observe(&store, d2, 2u) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_observe(&store, d2, 1u) == NINLIL_WIFI_FENCED);

    /* Durable NWD1 FULL put + cold reopen. */
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 32u;
    cfg.max_bytes_per_namespace = 65536u;
    storage = ninlil_test_storage_create(&cfg);
    CHECK(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    CHECK(ninlil_wifi_credential_bind_storage(
              &store, ops, ops->user, "nwd1.cred")
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_durable_put_full(&store) == NINLIL_WIFI_OK);
    ninlil_wifi_credential_store_init(&cold);
    CHECK(ninlil_wifi_credential_bind_storage(
              &cold, ops, ops->user, "nwd1.cred")
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_durable_reopen(&cold) == NINLIL_WIFI_OK);
    CHECK(cold.committed.valid == 1);
    CHECK(cold.committed.revision == 2u);
    CHECK(memcmp(cold.committed.secret_ref_digest, d2, 32u) == 0);

    CHECK(ninlil_wifi_credential_revoke(&store) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_is_active(&store) == 0);
    CHECK(ninlil_wifi_credential_observe(&store, d2, 2u)
        == NINLIL_WIFI_UNAVAILABLE);
    ninlil_test_storage_destroy(storage);
    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_credentials_test: PASS\n");
    return 0;
}
