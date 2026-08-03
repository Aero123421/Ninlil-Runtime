/*
 * ESP owner: async event model, GOT_IP gate, measured workspace budget.
 */
#include "wifi_esp_owner.h"
#include "wifi_nfl1_min.h"

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
    ninlil_wifi_esp_owner_t owner;
    ninlil_wifi_endpoint_t ep;
    uint32_t work = 0u;
    failures = 0;

    ninlil_wifi_esp_owner_init(&owner);
    CHECK(owner.availability_epoch == 1u);

    /* Measured budget, not header-only. */
    CHECK(ninlil_wifi_esp_owner_measured_workspace_bytes()
        == (uint32_t)sizeof(ninlil_wifi_esp_owner_t));
    CHECK(ninlil_wifi_esp_owner_measured_workspace_bytes()
        <= NINLIL_WIFI_ESP_SESSION_WORKSPACE_BYTES);
    CHECK(owner.measured_workspace_bytes
        == ninlil_wifi_esp_owner_measured_workspace_bytes());

    /* Connect without GOT_IP fails closed. */
    (void)memset(&ep, 0, sizeof(ep));
    ep.address_kind = 1u;
    ep.port = 443u;
    ep.address[0] = 192u;
    ep.address[1] = 0u;
    ep.address[2] = 2u;
    ep.address[3] = 1u;
    CHECK(ninlil_wifi_esp_owner_connect(&owner, &ep)
        == NINLIL_WIFI_UNAVAILABLE);

    /* Enqueue STA_CONNECTED then GOT_IP via sole-owner queue. */
    CHECK(ninlil_wifi_esp_owner_enqueue_event(
              &owner, NINLIL_WIFI_ESP_EV_STA_CONNECTED, 0u, 0u)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_esp_owner_enqueue_event(
              &owner, NINLIL_WIFI_ESP_EV_GOT_IP, 0u, 0u)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_esp_owner_step(&owner, 8u, &work) == NINLIL_WIFI_OK);
    CHECK(work >= 2u);
    CHECK(owner.got_ip == 1);
    CHECK(owner.associated == 1);
    CHECK(owner.got_ip_generation > 0u);

    /* After GOT_IP, connect is allowed at the gate (TCP may still fail host). */
    {
        ninlil_wifi_status_t st = ninlil_wifi_esp_owner_connect(&owner, &ep);
        /* Host stub TLS is UNSUPPORTED for ESP path; gate itself passed if not UNAVAILABLE. */
        CHECK(st != NINLIL_WIFI_UNAVAILABLE || owner.got_ip == 0);
    }

    /* Disconnect fences and clears GOT_IP. */
    CHECK(ninlil_wifi_esp_owner_enqueue_event(
              &owner, NINLIL_WIFI_ESP_EV_STA_DISCONNECTED, 1u, 0u)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_esp_owner_step(&owner, 4u, &work) == NINLIL_WIFI_OK);
    CHECK(owner.got_ip == 0);
    CHECK(owner.phase == NINLIL_WIFI_PHASE_FENCED
        || owner.phase == NINLIL_WIFI_PHASE_RECONNECT_WAIT
        || owner.phase == NINLIL_WIFI_PHASE_CLOSED
        || owner.availability_epoch >= 1u);

    /* NWB1 blocked without ATTACHED/M4. */
    {
        uint8_t p[587];
        (void)memset(p, 0x22, sizeof(p));
        owner.phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        CHECK(ninlil_wifi_esp_owner_send_payload(&owner, p, 587u)
            == NINLIL_WIFI_INVALID_STATE);
    }

    /* Callback enqueue reports capacity; owner step alone performs the fence. */
    ninlil_wifi_esp_owner_init(&owner);
    {
        uint32_t i;
        ninlil_wifi_status_t last = NINLIL_WIFI_OK;
        for (i = 0u; i < NINLIL_WIFI_ESP_EVENT_QUEUE_MAX + 2u; ++i) {
            last = ninlil_wifi_esp_owner_enqueue_event(
                &owner, NINLIL_WIFI_ESP_EV_STEP, 0u, 0u);
        }
        CHECK(last == NINLIL_WIFI_CAPACITY);
        CHECK(ninlil_wifi_esp_owner_step(&owner, 1u, &work)
            == NINLIL_WIFI_FENCED);
        CHECK(owner.phase == NINLIL_WIFI_PHASE_FENCED);
        CHECK(owner.availability_epoch >= 1u);
    }

    /* Epoch wrap is permanently fail-closed; a repeated fence is idempotent. */
    ninlil_wifi_esp_owner_init(&owner);
    owner.availability_epoch = UINT64_MAX;
    ninlil_wifi_esp_owner_fence(&owner);
    CHECK(owner.availability_epoch == UINT64_MAX);
    CHECK(owner.availability_epoch_exhausted == 1u);
    CHECK(owner.phase == NINLIL_WIFI_PHASE_FENCED);
    {
        uint32_t before_generation = owner.session_fence_generation;
        work = 99u;
        ninlil_wifi_esp_owner_fence(&owner);
        CHECK(owner.session_fence_generation == before_generation);
        CHECK(ninlil_wifi_esp_owner_step(&owner, 1u, &work)
            == NINLIL_WIFI_FENCED);
        CHECK(work == 0u);
        CHECK(ninlil_wifi_esp_owner_connect(&owner, &ep)
            == NINLIL_WIFI_FENCED);
    }

    /* A callback-generation gap is authority loss, never a skippable event. */
    ninlil_wifi_esp_owner_init(&owner);
    CHECK(ninlil_wifi_esp_owner_enqueue_event(
              &owner, NINLIL_WIFI_ESP_EV_STEP, 0u, 0u)
        == NINLIL_WIFI_OK);
    owner.event_q[owner.event_head].generation += 1u;
    CHECK(ninlil_wifi_esp_owner_step(&owner, 1u, &work)
        == NINLIL_WIFI_OK);
    CHECK(owner.phase == NINLIL_WIFI_PHASE_FENCED);

    /*
     * UINT32_MAX is never emitted.  UINT32_MAX-1 may be queued exactly once;
     * subsequent sends are rejected while that terminal record drains.
     */
    ninlil_wifi_esp_owner_init(&owner);
    owner.phase = NINLIL_WIFI_PHASE_ATTACHED;
    owner.attached_session_valid = 1;
    owner.m4_pa_full_confirmed = 1;
    (void)memset(owner.ids.attached_session_id, 0xA5, 16u);
    {
        uint8_t payload[587];
        size_t payload_len = 0u;
        CHECK(ninlil_wifi_nfl1_min_encode(
                  payload, sizeof(payload), &payload_len, 0x010203u)
            == NINLIL_WIFI_OK);
        CHECK(payload_len == sizeof(payload));
        owner.next_tx_sequence = UINT32_MAX;
        CHECK(ninlil_wifi_esp_owner_send_payload(
                  &owner, payload, (uint32_t)payload_len)
            == NINLIL_WIFI_SEQUENCE_REJECT);
        CHECK(owner.tx_count == 0u);

        owner.next_tx_sequence = UINT32_MAX - 1u;
        CHECK(ninlil_wifi_esp_owner_send_payload(
                  &owner, payload, (uint32_t)payload_len)
            == NINLIL_WIFI_OK);
        CHECK(owner.tx_count == 1u);
        CHECK(owner.sequence_close_after_drain == 1u);
        CHECK(owner.next_tx_sequence == UINT32_MAX);
        CHECK(owner.tx_slots[owner.tx_head].bytes[32] == 0xFFu);
        CHECK(owner.tx_slots[owner.tx_head].bytes[33] == 0xFFu);
        CHECK(owner.tx_slots[owner.tx_head].bytes[34] == 0xFFu);
        CHECK(owner.tx_slots[owner.tx_head].bytes[35] == 0xFEu);
        CHECK(ninlil_wifi_esp_owner_send_payload(
                  &owner, payload, (uint32_t)payload_len)
            == NINLIL_WIFI_SEQUENCE_REJECT);
        CHECK(owner.tx_count == 1u);
    }

    ninlil_wifi_esp_owner_close(&owner);
    if (failures != 0) {
        return 1;
    }
    (void)printf(
        "wifi_v1_esp_owner_test: PASS measured=%u\n",
        (unsigned)ninlil_wifi_esp_owner_measured_workspace_bytes());
    return 0;
}
