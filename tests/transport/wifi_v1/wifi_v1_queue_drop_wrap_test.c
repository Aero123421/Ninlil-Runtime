/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Ring-queue drop_sequence wrap + boundary + random survivor integrity.
 */
#include "wifi_nfl1_min.h"
#include "wifi_nwb1.h"
#include "wifi_queues.h"

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

static void make_record(uint8_t *rec, size_t *len, uint32_t seq)
{
    uint8_t sid[16];
    uint8_t pay[587];
    size_t pay_len = 0u;
    (void)memset(sid, 0x11, sizeof(sid));
    CHECK(ninlil_wifi_nfl1_min_encode(pay, sizeof(pay), &pay_len, seq + 1u)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_nwb1_encode(
              sid, seq, pay, (uint32_t)pay_len, rec, NINLIL_WIFI_NWB1_TOTAL_MAX,
              len)
        == NINLIL_WIFI_OK);
}

int main(void)
{
    ninlil_wifi_record_queue_t q;
    uint8_t rec[NINLIL_WIFI_NWB1_TOTAL_MAX];
    size_t len = 0u;
    uint32_t i;
    failures = 0;

    /* Fill full queue with seq 0..DEPTH-1 */
    ninlil_wifi_queue_init(&q);
    for (i = 0u; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
        make_record(rec, &len, i);
        CHECK(ninlil_wifi_queue_push(&q, rec, len) == NINLIL_WIFI_OK);
    }
    CHECK(ninlil_wifi_queue_is_full(&q));

    /* Pop 3 to advance head (wrap path setup). */
    CHECK(ninlil_wifi_queue_pop(&q) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_queue_pop(&q) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_queue_pop(&q) == NINLIL_WIFI_OK);
    /* Push 3 more: seq 100..102 wrapping tail. */
    for (i = 0u; i < 3u; ++i) {
        make_record(rec, &len, 100u + i);
        CHECK(ninlil_wifi_queue_push(&q, rec, len) == NINLIL_WIFI_OK);
    }
    CHECK(q.count == NINLIL_WIFI_TX_QUEUE_DEPTH);

    /* Drop middle original sequence 4 — survivors must stay intact. */
    {
        uint32_t dropped = ninlil_wifi_queue_drop_sequence(&q, 4u);
        CHECK(dropped == 1u);
        CHECK(q.head == 0u);
        CHECK(q.count == (uint8_t)(NINLIL_WIFI_TX_QUEUE_DEPTH - 1u));
    }

    /* Drop a wrapped high sequence. */
    {
        uint32_t dropped = ninlil_wifi_queue_drop_sequence(&q, 101u);
        CHECK(dropped == 1u);
        CHECK(q.head == 0u);
    }

    /* Empty drop */
    CHECK(ninlil_wifi_queue_drop_sequence(&q, 0xffffffffu) == 0u);

    /* Random-ish: fill wrap, drop every even seq, verify odd survivors order. */
    ninlil_wifi_queue_init(&q);
    for (i = 0u; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
        make_record(rec, &len, i * 3u + 7u);
        CHECK(ninlil_wifi_queue_push(&q, rec, len) == NINLIL_WIFI_OK);
    }
    for (i = 0u; i < 5u; ++i) {
        CHECK(ninlil_wifi_queue_pop(&q) == NINLIL_WIFI_OK);
    }
    for (i = 0u; i < 5u; ++i) {
        make_record(rec, &len, 1000u + i);
        CHECK(ninlil_wifi_queue_push(&q, rec, len) == NINLIL_WIFI_OK);
    }
    /* Drop one known */
    (void)ninlil_wifi_queue_drop_sequence(&q, 1000u);
    {
        const uint8_t *p = NULL;
        size_t L = 0u;
        uint32_t seen = 0u;
        while (ninlil_wifi_queue_peek(&q, &p, &L) == NINLIL_WIFI_OK) {
            uint32_t seq = ((uint32_t)p[32] << 24) | ((uint32_t)p[33] << 16)
                | ((uint32_t)p[34] << 8) | (uint32_t)p[35];
            CHECK(seq != 1000u);
            CHECK(L >= 36u);
            seen += 1u;
            CHECK(ninlil_wifi_queue_pop(&q) == NINLIL_WIFI_OK);
        }
        CHECK(seen == (uint32_t)(NINLIL_WIFI_TX_QUEUE_DEPTH - 1u));
    }

    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_queue_drop_wrap_test PASS\n");
    return 0;
}
