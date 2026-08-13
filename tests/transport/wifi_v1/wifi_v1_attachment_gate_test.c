/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Negative: PEER_SESSION alone does not enable NWB1.
 * Incomplete M4 evidence stays PEER_SESSION (publish=0).
 */
#include "wifi_attachment_m4.h"
#include "wifi_session.h"

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
    ninlil_wifi_m4_owner_t m4_owner;
    ninlil_wifi_m4_owner_init(&m4_owner);

    ninlil_wifi_session_t session;
    uint8_t payload[587];
    uint8_t fake_sid[16];
    ninlil_wifi_m4_full_evidence_t empty;
    failures = 0;
    (void)memset(payload, 0x11, sizeof(payload));
    (void)memset(fake_sid, 0x42, sizeof(fake_sid));

    ninlil_wifi_session_init(&session);
    session.phase = NINLIL_WIFI_PHASE_PEER_SESSION;
    session.peer_session_valid = 1;
    (void)memcpy(session.ids.peer_session_id, fake_sid, 16u);
    CHECK(ninlil_wifi_session_send_payload(&session, payload, 587u)
        == NINLIL_WIFI_INVALID_STATE);

    CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &empty) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_session_accept_m4_full_evidence(&session, &empty)
        == NINLIL_WIFI_OK);
    CHECK(session.phase == NINLIL_WIFI_PHASE_PEER_SESSION);
    CHECK(ninlil_wifi_session_send_payload(&session, payload, 587u)
        == NINLIL_WIFI_INVALID_STATE);

    CHECK(ninlil_wifi_session_confirm_m4_pa_full(&session, fake_sid, payload)
        == NINLIL_WIFI_DENIED);

    ninlil_wifi_session_close(&session);
    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_attachment_gate_test: PASS\n");
    return 0;
}
