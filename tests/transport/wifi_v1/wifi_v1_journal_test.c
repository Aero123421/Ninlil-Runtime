/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Durable attempt journal: CU put/get, cold restart, crash write-point.
 */
#include "wifi_journal.h"

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

static void check_journal_storage_boundary(void)
{
    ninlil_test_storage_config_t cfg;
    ninlil_test_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_wifi_journal_t journal;
    ninlil_wifi_journal_attempt_t attempt;

    /*
     * TRACE-INV010-JOURNAL-BOUNDARY
     * The fixed 160-byte image plus the storage contract's row/key overhead
     * fits an exact-size namespace.  One byte less fails closed with CAPACITY.
     */
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 1u;
    cfg.max_entries_per_namespace = 1u;
    cfg.max_bytes_per_namespace =
        NINLIL_WIFI_JOURNAL_VALUE_BYTES + 16u
        + (sizeof(NINLIL_WIFI_JOURNAL_KEY_ATTEMPT) - 1u);
    storage = ninlil_test_storage_create(&cfg);
    CHECK(storage != NULL);
    if (storage != NULL) {
        ops = ninlil_test_storage_ops(storage);
        ninlil_wifi_journal_init(&journal);
        CHECK(ninlil_wifi_journal_open(
                  &journal, ops, ops->user, "wifi.journal.boundary")
            == NINLIL_WIFI_OK);
        (void)memset(&attempt, 0, sizeof(attempt));
        attempt.attempt_id = 1u;
        attempt.phase = (uint8_t)NINLIL_WIFI_PHASE_HANDSHAKING;
        CHECK(ninlil_wifi_journal_put_attempt(&journal, &attempt)
            == NINLIL_WIFI_OK);
        ninlil_wifi_journal_close(&journal);
        ninlil_test_storage_destroy(storage);
    }

    cfg.max_bytes_per_namespace =
        NINLIL_WIFI_JOURNAL_VALUE_BYTES + 16u
        + (sizeof(NINLIL_WIFI_JOURNAL_KEY_ATTEMPT) - 1u) - 1u;
    storage = ninlil_test_storage_create(&cfg);
    CHECK(storage != NULL);
    if (storage != NULL) {
        ops = ninlil_test_storage_ops(storage);
        ninlil_wifi_journal_init(&journal);
        CHECK(ninlil_wifi_journal_open(
                  &journal, ops, ops->user, "wifi.journal.boundary")
            == NINLIL_WIFI_OK);
        (void)memset(&attempt, 0, sizeof(attempt));
        attempt.attempt_id = 2u;
        attempt.phase = (uint8_t)NINLIL_WIFI_PHASE_HANDSHAKING;
        CHECK(ninlil_wifi_journal_put_attempt(&journal, &attempt)
            == NINLIL_WIFI_CAPACITY);
        ninlil_wifi_journal_close(&journal);
        ninlil_test_storage_destroy(storage);
    }
}

int main(void)
{
    ninlil_test_storage_config_t cfg;
    ninlil_test_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_wifi_journal_t j1;
    ninlil_wifi_journal_t j2;
    ninlil_wifi_journal_attempt_t a;
    ninlil_wifi_journal_attempt_t b;
    failures = 0;
    check_journal_storage_boundary();

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 32u;
    cfg.max_bytes_per_namespace = 65536u;
    storage = ninlil_test_storage_create(&cfg);
    CHECK(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    CHECK(ops != NULL);

    ninlil_wifi_journal_init(&j1);
    CHECK(ninlil_wifi_journal_open(
              &j1, ops, ops->user, "wifi.journal.v1")
        == NINLIL_WIFI_OK);

    (void)memset(&a, 0, sizeof(a));
    a.attempt_id = 7u;
    a.mono_ms = 12345u;
    a.endpoint_index = 1u;
    a.generation = 2u;
    a.phase = (uint8_t)NINLIL_WIFI_PHASE_HANDSHAKING;
    a.write_point = 2u; /* tls_ok write-point before crash */
    a.session_id[0] = 0xab;
    a.secret_ref_digest[0] = 0x11;
    a.endpoint_digest[0] = 0x22;

    CHECK(ninlil_wifi_journal_put_attempt(&j1, &a) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_journal_attempt_valid(&a) == 1);
    (void)memset(&b, 0, sizeof(b));
    CHECK(ninlil_wifi_journal_get_attempt(&j1, &b) == NINLIL_WIFI_OK);
    CHECK(b.attempt_id == 7u);
    CHECK(b.write_point == 2u);
    CHECK(b.phase == (uint8_t)NINLIL_WIFI_PHASE_HANDSHAKING);
    CHECK(b.session_id[0] == 0xab);

    /* Simulate crash: close without further writes. */
    ninlil_wifi_journal_close(&j1);

    /* Cold-process restart: new journal handle, same storage namespace. */
    ninlil_wifi_journal_init(&j2);
    CHECK(ninlil_wifi_journal_open(
              &j2, ops, ops->user, "wifi.journal.v1")
        == NINLIL_WIFI_OK);
    (void)memset(&b, 0, sizeof(b));
    CHECK(ninlil_wifi_journal_recover(&j2, &b) == NINLIL_WIFI_OK);
    CHECK(b.attempt_id == 7u);
    CHECK(b.write_point == 2u);
    CHECK(b.mono_ms == 12345u);
    CHECK(b.endpoint_index == 1u);
    CHECK(b.generation == 2u);

    /* Negative: digest tamper → CORRUPT. */
    {
        ninlil_wifi_journal_attempt_t bad = b;
        bad.image_digest[0] ^= 0xffu;
        CHECK(ninlil_wifi_journal_attempt_valid(&bad) == 0);
    }

    /* Advance write-point to attached after recovery. */
    b.write_point = 3u;
    b.phase = (uint8_t)NINLIL_WIFI_PHASE_ATTACHED;
    CHECK(ninlil_wifi_journal_put_attempt(&j2, &b) == NINLIL_WIFI_OK);
    (void)memset(&a, 0, sizeof(a));
    CHECK(ninlil_wifi_journal_get_attempt(&j2, &a) == NINLIL_WIFI_OK);
    CHECK(a.write_point == 3u);

    ninlil_wifi_journal_close(&j2);
    ninlil_test_storage_destroy(storage);

    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_journal_test: PASS\n");
    return 0;
}
