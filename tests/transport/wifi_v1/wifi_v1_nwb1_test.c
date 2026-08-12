/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private Wi-Fi v1 NWB1/stream/queue unit tests (real codec, no fake transport).
 */
#include "wifi_nwb1.h"
#include "wifi_nfl1_min.h"
#include "wifi_queues.h"
#include "wifi_stream.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

int main(void)
{
    uint8_t nfl1[587];
    size_t nfl1_len = 0u;
    uint8_t session[16];
    uint8_t record[1965];
    size_t record_len = 0u;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0u;
    uint32_t sequence = 0u;
    ninlil_wifi_rx_stream_t stream;
    ninlil_wifi_record_queue_t q;
    size_t i;

    failures = 0;
    (void)memset(session, 0x11, sizeof(session));
    CHECK(
        ninlil_wifi_nfl1_min_encode(nfl1, sizeof(nfl1), &nfl1_len, 0x010203u)
        == NINLIL_WIFI_OK);
    CHECK(nfl1_len == 587u);
    CHECK(ninlil_wifi_nfl1_structural_ok(nfl1, nfl1_len));

    CHECK(
        ninlil_wifi_nwb1_encode(
            session, 0u, nfl1, (uint32_t)nfl1_len, record, sizeof(record),
            &record_len)
        == NINLIL_WIFI_OK);
    CHECK(record_len == 627u);
    CHECK(
        ninlil_wifi_nwb1_classify(
            record, record_len, session, 1, 0u, &payload, &payload_len, &sequence)
        == NINLIL_WIFI_OK);
    CHECK(sequence == 0u);
    CHECK(payload_len == 587u);

    /* Truncated: stream would-block */
    ninlil_wifi_rx_stream_init(&stream);
    ninlil_wifi_rx_stream_set_session(&stream, session, 0u);
    {
        const uint8_t *rec = NULL;
        size_t rec_len = 0u;
        CHECK(
            ninlil_wifi_rx_stream_feed(
                &stream, record, 40u, &rec, &rec_len, &sequence)
            == NINLIL_WIFI_WOULD_BLOCK);
        CHECK(
            ninlil_wifi_rx_stream_feed(
                &stream, record + 40, record_len - 40u, &rec, &rec_len, &sequence)
            == NINLIL_WIFI_OK);
        CHECK(rec_len == record_len);
    }

    /* Oversize length field => corrupt */
    {
        uint8_t bad[80];
        const uint8_t *rec = NULL;
        size_t rec_len = 0u;
        (void)memset(bad, 0, sizeof(bad));
        bad[0] = 'N';
        bad[1] = 'W';
        bad[2] = 'B';
        bad[3] = '1';
        bad[8] = 0xff;
        bad[9] = 0xff;
        bad[10] = 0xff;
        bad[11] = 0xff;
        ninlil_wifi_rx_stream_init(&stream);
        CHECK(
            ninlil_wifi_rx_stream_feed(
                &stream, bad, sizeof(bad), &rec, &rec_len, &sequence)
            == NINLIL_WIFI_CORRUPT);
    }

    /* Queue backpressure */
    ninlil_wifi_queue_init(&q);
    for (i = 0u; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
        CHECK(ninlil_wifi_queue_push(&q, record, record_len) == NINLIL_WIFI_OK);
    }
    CHECK(
        ninlil_wifi_queue_push(&q, record, record_len) == NINLIL_WIFI_BACKPRESSURE);

    /* Sequence UINT32_MAX reject */
    CHECK(
        ninlil_wifi_nwb1_encode(
            session, 0xffffffffu, nfl1, (uint32_t)nfl1_len, record, sizeof(record),
            &record_len)
        == NINLIL_WIFI_SEQUENCE_REJECT);

    if (failures != 0) {
        (void)fprintf(stderr, "wifi_v1_nwb1_test failures=%d\n", failures);
        return 1;
    }
    (void)printf("wifi_v1_nwb1_test: PASS\n");
    return 0;
}
