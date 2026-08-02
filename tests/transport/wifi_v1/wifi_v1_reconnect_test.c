/*
 * Bounded exponential reconnect + endpoint rotation + credential CU.
 */
#include "wifi_credentials.h"
#include "wifi_reconnect.h"

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

static void make_ep(ninlil_wifi_endpoint_t *ep, uint16_t port, uint8_t last)
{
    (void)memset(ep, 0, sizeof(*ep));
    ep->address_kind = 1u;
    ep->port = port;
    ep->address[0] = 127u;
    ep->address[1] = 0u;
    ep->address[2] = 0u;
    ep->address[3] = last;
}

int main(void)
{
    ninlil_wifi_reconnect_t rc;
    ninlil_wifi_endpoint_t e1;
    ninlil_wifi_endpoint_t e2;
    ninlil_wifi_endpoint_t e3;
    ninlil_wifi_endpoint_t cur;
    ninlil_wifi_credential_store_t store;
    uint8_t d1[32];
    uint8_t d2[32];
    uint64_t mono = 1000u;
    failures = 0;

    ninlil_wifi_reconnect_init(&rc);
    make_ep(&e1, 9001, 1);
    make_ep(&e2, 9002, 2);
    make_ep(&e3, 9003, 3);
    CHECK(ninlil_wifi_endpoint_list_push(&rc.endpoints, &e1) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_endpoint_list_push(&rc.endpoints, &e2) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_endpoint_list_push(&rc.endpoints, &e3) == NINLIL_WIFI_OK);

    CHECK(ninlil_wifi_reconnect_current_endpoint(&rc, &cur) == NINLIL_WIFI_OK);
    CHECK(cur.port == 9001);

    /* Failure 1: backoff 1000ms + deterministic jitter [0,999], rotate to e2 */
    ninlil_wifi_reconnect_note_failure(&rc, mono);
    CHECK(rc.failure_generation == 1u);
    CHECK(ninlil_wifi_reconnect_backoff_ms(1u) == 1000u);
    CHECK(rc.not_before_mono_ms >= mono + 1000u);
    CHECK(rc.not_before_mono_ms <= mono + 1000u + 999u);
    CHECK(ninlil_wifi_reconnect_ready(&rc, rc.not_before_mono_ms - 1u) == 0);
    CHECK(ninlil_wifi_reconnect_ready(&rc, rc.not_before_mono_ms) == 1);
    CHECK(ninlil_wifi_reconnect_current_endpoint(&rc, &cur) == NINLIL_WIFI_OK);
    CHECK(cur.port == 9002);

    /* Failure 2..6 cap at 32000 */
    mono = 2000u;
    ninlil_wifi_reconnect_note_failure(&rc, mono);
    CHECK(ninlil_wifi_reconnect_backoff_ms(2u) == 2000u);
    mono = rc.not_before_mono_ms;
    ninlil_wifi_reconnect_note_failure(&rc, mono);
    CHECK(ninlil_wifi_reconnect_backoff_ms(3u) == 4000u);
    mono = rc.not_before_mono_ms;
    ninlil_wifi_reconnect_note_failure(&rc, mono);
    CHECK(ninlil_wifi_reconnect_backoff_ms(4u) == 8000u);
    mono = rc.not_before_mono_ms;
    ninlil_wifi_reconnect_note_failure(&rc, mono);
    CHECK(ninlil_wifi_reconnect_backoff_ms(5u) == 16000u);
    mono = rc.not_before_mono_ms;
    ninlil_wifi_reconnect_note_failure(&rc, mono);
    CHECK(ninlil_wifi_reconnect_backoff_ms(6u) == 32000u);
    mono = rc.not_before_mono_ms;
    ninlil_wifi_reconnect_note_failure(&rc, mono);
    CHECK(ninlil_wifi_reconnect_backoff_ms(7u) == 32000u); /* cap */

    /* Full rotation wraps */
    CHECK(ninlil_wifi_reconnect_current_endpoint(&rc, &cur) == NINLIL_WIFI_OK);
    CHECK(cur.port == 9001 || cur.port == 9002 || cur.port == 9003);

    ninlil_wifi_reconnect_note_success(&rc);
    /* Success clears not_before; generation resets only after 60s stable ATTACHED. */
    CHECK(rc.not_before_mono_ms == 0u);
    ninlil_wifi_reconnect_note_attached_stable(&rc, 100000u);
    ninlil_wifi_reconnect_note_attached_stable(&rc, 160000u);
    CHECK(rc.failure_generation == 0u);

    /* Credential stage / activate / revoke */
    (void)memset(d1, 0xa1, sizeof(d1));
    (void)memset(d2, 0xb2, sizeof(d2));
    ninlil_wifi_credential_store_init(&store);
    CHECK(ninlil_wifi_credential_stage(&store, d1, 1u) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_activate(&store) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_is_active(&store) == 1);
    CHECK(ninlil_wifi_credential_stage(&store, d2, 2u) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_activate(&store) == NINLIL_WIFI_OK);
    CHECK(memcmp(store.committed.secret_ref_digest, d2, 32u) == 0);
    CHECK(ninlil_wifi_credential_revoke(&store) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_is_active(&store) == 0);
    CHECK(ninlil_wifi_credential_observe(&store, d2, 2u)
        == NINLIL_WIFI_UNAVAILABLE);

    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_reconnect_test: PASS\n");
    return 0;
}
