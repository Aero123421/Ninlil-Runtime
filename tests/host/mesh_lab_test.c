#include "mesh_lab.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t A[8] = {1, 1, 1, 1, 1, 1, 1, 1};
static const uint8_t B[8] = {2, 2, 2, 2, 2, 2, 2, 2};
static const uint8_t C[8] = {3, 3, 3, 3, 3, 3, 3, 3};
static const uint8_t HIL_A[8] = {0xe0, 0x72, 0xa1, 0xd8, 0x3e, 0x74, 0x4e, 0x31};
static const uint8_t HIL_B[8] = {0xe0, 0x72, 0xa1, 0xf7, 0xff, 0x0c, 0x4e, 0x31};
static const uint8_t HIL_C[8] = {0xe0, 0x72, 0xa1, 0xd7, 0x77, 0x28, 0x4e, 0x31};
static const uint8_t SITE[8] = {9, 8, 7, 6, 5, 4, 3, 2};
static const uint8_t B_SAME_SEQ[8] = {2, 2, 2, 2, 7, 7, 7, 7};
static const uint8_t C_SAME_SEQ[8] = {3, 3, 3, 3, 7, 7, 7, 7};

static void deliver(ninlil_mesh_lab_t *to, const ninlil_mesh_lab_tx_t *tx,
    uint64_t now, ninlil_mesh_lab_tx_t *reply, ninlil_mesh_lab_event_t *event)
{
    assert(tx->length != 0u);
    assert(ninlil_mesh_lab_receive(
        to, tx->bytes, tx->length, -55, 8, now, reply, event));
}

/* C joins through B, but B must never reverse its hop-1 parent direction and
 * select its hop-2 child C, including after B's parent becomes unavailable. */
static void test_two_hop_parent_direction(void)
{
    ninlil_mesh_lab_t a, b, c;
    ninlil_mesh_lab_tx_t beacon, request, accept, relay;
    ninlil_mesh_lab_event_t event;
    ninlil_mesh_lab_snapshot_t snap;

    ninlil_mesh_lab_init(&a, A);
    ninlil_mesh_lab_init(&b, B);
    ninlil_mesh_lab_init(&c, C);
    assert(ninlil_mesh_lab_become_controller(&a, SITE, 1u, 0u));
    assert(ninlil_mesh_lab_set_test_penalty(&c, A, 200u));

    assert(ninlil_mesh_lab_tick(&a, 0u, &beacon));
    deliver(&b, &beacon, 0u, &request, &event);
    assert(ninlil_mesh_lab_tick(&a, 3000u, &beacon));
    deliver(&b, &beacon, 3000u, &request, &event);
    assert(!ninlil_mesh_lab_tick(&b, 9999u, &request));
    assert(ninlil_mesh_lab_tick(&b, 10000u, &request));
    deliver(&a, &request, 10001u, &accept, &event);
    deliver(&b, &accept, 10002u, &relay, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_JOINED);

    assert(!ninlil_mesh_lab_tick(&b, 10501u, &beacon));
    assert(ninlil_mesh_lab_tick(&b, 10502u, &beacon));
    deliver(&c, &beacon, 10502u, &request, &event);
    assert(ninlil_mesh_lab_tick(&a, 13000u, &beacon));
    deliver(&b, &beacon, 13000u, &request, &event);
    assert(ninlil_mesh_lab_tick(&b, 13500u, &beacon));
    deliver(&c, &beacon, 13500u, &request, &event);
    assert(!ninlil_mesh_lab_tick(&c, 20501u, &request));
    assert(ninlil_mesh_lab_tick(&c, 20502u, &request));
    assert(request.length != 0u);
    deliver(&b, &request, 20503u, &relay, &event);
    assert(relay.length != 0u);
    deliver(&a, &relay, 20504u, &accept, &event);
    assert(accept.length != 0u);
    deliver(&b, &accept, 20505u, &relay, &event);
    assert(relay.length != 0u);
    deliver(&c, &relay, 20506u, &request, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_JOINED);
    ninlil_mesh_lab_snapshot(&c, &snap);
    assert(snap.joined && !snap.joining && snap.hops == 2u
        && memcmp(snap.parent_id, B, 8u) == 0);

    /* C(hop2) advertises twice. B(hop1) must retain upstream A(hop0). */
    assert(ninlil_mesh_lab_tick(&c, 21006u, &beacon));
    deliver(&b, &beacon, 21006u, &request, &event);
    assert(request.length == 0u);
    assert(ninlil_mesh_lab_tick(&a, 22000u, &beacon));
    deliver(&b, &beacon, 22000u, &request, &event);
    assert(ninlil_mesh_lab_tick(&b, 22500u, &beacon));
    deliver(&c, &beacon, 22500u, &request, &event);
    assert(ninlil_mesh_lab_tick(&c, 23000u, &beacon));
    deliver(&b, &beacon, 23000u, &request, &event);
    assert(request.length == 0u);
    ninlil_mesh_lab_snapshot(&b, &snap);
    assert(snap.joined && !snap.joining && snap.hops == 1u
        && memcmp(snap.parent_id, A, 8u) == 0);

    /* After parent loss, the same downstream candidate is still rejected
     * until the existing lease expires. */
    (void)ninlil_mesh_lab_tick(&b, 28000u, &request);
    ninlil_mesh_lab_snapshot(&b, &snap);
    assert(snap.joined); /* Two roughly-3s missed parent opportunities. */
    assert(!ninlil_mesh_lab_tick(&b, 34001u, &request));
    ninlil_mesh_lab_snapshot(&b, &snap);
    assert(!snap.joined && !snap.joining && snap.hops == 1u
        && memcmp(snap.parent_id, A, 8u) == 0);

    /* PENALTY 200 excludes A from hysteresis as well as first selection.
     * Once reset, the same stronger direct A candidate may route-change. */
    assert(ninlil_mesh_lab_tick(&a, 34002u, &beacon));
    deliver(&c, &beacon, 34002u, &request, &event);
    deliver(&c, &beacon, 34003u, &request, &event);
    ninlil_mesh_lab_snapshot(&c, &snap);
    assert(snap.joined && !snap.joining && snap.hops == 2u
        && memcmp(snap.parent_id, B, 8u) == 0);
    assert(ninlil_mesh_lab_set_test_penalty(&c, A, 0u));
    deliver(&c, &beacon, 34004u, &request, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_ROUTE_CHANGED);
    assert(request.length != 0u && memcmp(request.bytes + 40u, A, 8u) == 0);
}

/* Two joining nodes may start with the same sequence counter. Deduplication
 * must retain origin so the controller accepts both requests. */
static void test_same_sequence_distinct_origins(void)
{
    ninlil_mesh_lab_t a, b, c;
    ninlil_mesh_lab_tx_t beacon, b_request, c_request, accept, unused;
    ninlil_mesh_lab_event_t event;

    ninlil_mesh_lab_init(&a, A);
    ninlil_mesh_lab_init(&b, B_SAME_SEQ);
    ninlil_mesh_lab_init(&c, C_SAME_SEQ);
    assert(ninlil_mesh_lab_become_controller(&a, SITE, 1u, 0u));
    assert(ninlil_mesh_lab_tick(&a, 0u, &beacon));
    deliver(&b, &beacon, 0u, &unused, &event);
    deliver(&c, &beacon, 0u, &unused, &event);
    assert(ninlil_mesh_lab_tick(&a, 3000u, &beacon));
    deliver(&b, &beacon, 3000u, &b_request, &event);
    deliver(&c, &beacon, 3000u, &c_request, &event);
    assert(ninlil_mesh_lab_tick(&b, 10000u, &b_request));
    assert(ninlil_mesh_lab_tick(&c, 10000u, &c_request));
    assert(b_request.length != 0u && c_request.length != 0u);
    assert(memcmp(b_request.bytes + 20u, c_request.bytes + 20u, 4u) == 0);
    assert(memcmp(b_request.bytes + 24u, c_request.bytes + 24u, 8u) != 0);
    /* Same starting sequence, same beacon phase: retries are bounded yet
     * deterministically dephased by node identity. */
    assert(b.next_join_ms >= 13000u && b.next_join_ms <= 13700u);
    assert(c.next_join_ms >= 13000u && c.next_join_ms <= 13700u);
    assert(b.next_join_ms != c.next_join_ms);

    deliver(&a, &b_request, 10001u, &accept, &event);
    assert(accept.length != 0u);
    deliver(&b, &accept, 10002u, &unused, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_JOINED);
    deliver(&a, &c_request, 10003u, &accept, &event);
    assert(accept.length != 0u);
    deliver(&c, &accept, 10004u, &unused, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_JOINED);
}

static void test_half_duplex_turnaround_guard(void)
{
    uint64_t due = ninlil_mesh_lab_response_not_before(1000u);

    assert(NINLIL_MESH_LAB_TURNAROUND_GUARD_MS >= 200u
        && NINLIL_MESH_LAB_TURNAROUND_GUARD_MS <= 250u);
    assert(due == 1225u);
    assert(!ninlil_mesh_lab_tx_due(1000u, due));
    assert(!ninlil_mesh_lab_tx_due(1224u, due));
    assert(ninlil_mesh_lab_tx_due(1225u, due));
    due = ninlil_mesh_lab_data_after_parent_not_before(1000u);
    assert(NINLIL_MESH_LAB_DATA_AFTER_PARENT_GUARD_MS == 500u);
    assert(!ninlil_mesh_lab_tx_due(1499u, due));
    assert(ninlil_mesh_lab_tx_due(1500u, due));
}

static void test_response_receive_dwell(void)
{
    ninlil_mesh_lab_t controller;
    ninlil_mesh_lab_tx_t tx;
    ninlil_mesh_lab_tx_t beacon;

    (void)memset(&tx, 0, sizeof(tx));
    tx.length = 64u;
    tx.bytes[5] = 2u; /* JOIN_REQUEST, including a forwarded request. */
    assert(NINLIL_MESH_LAB_RESPONSE_DWELL_MS == 1500u);
    assert(NINLIL_MESH_LAB_DATA_ACK_WAIT_MS == 3000u);
    assert(NINLIL_MESH_LAB_DATA_ACK_WAIT_MS
        > NINLIL_MESH_LAB_RESPONSE_DWELL_MS
            + 2u * NINLIL_MESH_LAB_TURNAROUND_GUARD_MS);
    assert(ninlil_mesh_lab_response_dwell_until(&tx, 1000u) == 2500u);
    assert(!ninlil_mesh_lab_periodic_tx_due(2499u, 2500u));
    assert(ninlil_mesh_lab_periodic_tx_due(2500u, 2500u));
    tx.bytes[5] = 4u; /* DATA also awaits its ACK. */
    assert(ninlil_mesh_lab_response_dwell_until(&tx, 1000u) == 2500u);
    tx.bytes[5] = 3u; /* JOIN_ACCEPT needs room for downstream forwarding. */
    assert(ninlil_mesh_lab_response_dwell_until(&tx, 1000u) == 2500u);
    tx.bytes[5] = 5u; /* ACK has the same bounded forwarding window. */
    assert(ninlil_mesh_lab_response_dwell_until(&tx, 1000u) == 2500u);
    assert(!ninlil_mesh_lab_tx_due(3999u,
        ninlil_mesh_lab_data_ack_retry_at(HIL_C, 169u, 1u, 1000u)));

    ninlil_mesh_lab_init(&controller, A);
    assert(ninlil_mesh_lab_become_controller(&controller, SITE, 1u, 0u));
    assert(ninlil_mesh_lab_tick(&controller, 0u, &beacon));
    /* A periodic beacon is otherwise due, but the app scheduler leaves the
     * PHY in RX until the dwell boundary rather than queuing it. */
    assert(!ninlil_mesh_lab_periodic_tx_due(2499u, 2500u));
    assert(ninlil_mesh_lab_periodic_tx_due(2500u, 2500u));
    assert(ninlil_mesh_lab_tick(&controller, 2500u, &beacon));
}

static void test_membership_expiry_clears_pending_state(void)
{
    ninlil_mesh_lab_t node;

    ninlil_mesh_lab_init(&node, C);
    node.joined = 1u;
    node.site_id[0] = 1u;
    node.parent_id[0] = 2u;
    node.lease_until_ms = 100u;
    node.parent_last_seen_ms = 1u;
    node.seen[0].active = 1u;
    node.seen_cursor = 1u;
    ninlil_mesh_lab_maintain(&node, 100u);
    assert(!node.joined && node.site_epoch == 0u);
    assert(!node.seen[0].active && node.seen_cursor == 0u);

    node.joined = 1u;
    node.site_id[0] = 1u;
    node.parent_id[0] = 2u;
    node.lease_until_ms = UINT64_MAX;
    node.parent_last_seen_ms = 1u;
    ninlil_mesh_lab_maintain(&node, 12002u);
    assert(!node.joined && !node.joining);
}

static void test_hil_beacon_dephase_and_relay_stability(void)
{
    ninlil_mesh_lab_t a, b, c;
    ninlil_mesh_lab_tx_t beacon, request, accept, unused, a_pending, b_pending;
    ninlil_mesh_lab_event_t event;
    ninlil_mesh_lab_snapshot_t snap;
    uint64_t now;
    uint64_t a_until = 0u;
    uint64_t b_until = 0u;
    uint8_t a_active = 0u;
    uint8_t b_active = 0u;
    uint8_t a_collision = 0u;
    uint8_t b_collision = 0u;

    assert(ninlil_mesh_lab_beacon_interval_ms(HIL_A, 1u)
        != ninlil_mesh_lab_beacon_interval_ms(HIL_B, 1u));
    assert(ninlil_mesh_lab_beacon_interval_ms(HIL_B, 1u)
        != ninlil_mesh_lab_beacon_interval_ms(HIL_B, 2u));
    ninlil_mesh_lab_init(&a, HIL_A);
    ninlil_mesh_lab_init(&b, HIL_B);
    ninlil_mesh_lab_init(&c, HIL_C);
    assert(ninlil_mesh_lab_become_controller(&a, SITE, 1u, 0u));
    assert(ninlil_mesh_lab_set_test_penalty(&c, HIL_A, 200u));
    assert(ninlil_mesh_lab_tick(&a, 0u, &beacon));
    deliver(&b, &beacon, 0u, &unused, &event);
    assert(ninlil_mesh_lab_tick(&a, 3000u, &beacon));
    deliver(&b, &beacon, 3000u, &unused, &event);
    assert(ninlil_mesh_lab_tick(&b, 10000u, &request));
    deliver(&a, &request, 10001u, &accept, &event);
    deliver(&b, &accept, 10002u, &unused, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_JOINED);
    /* Fake 250ms half-duplex airtime: overlapping A/B beacons are dropped
     * for both receivers rather than being blindly delivered. */
    for (now = 10003u; now <= 49000u; now += 10u) {
        if (a_active && now >= a_until) {
            if (!a_collision) {
                deliver(&b, &a_pending, now, &unused, &event);
            }
            a_active = 0u;
        }
        if (b_active && now >= b_until) {
            if (!b_collision) {
                deliver(&c, &b_pending, now, &unused, &event);
            }
            b_active = 0u;
        }
        if (ninlil_mesh_lab_tick(&a, now, &beacon)) {
            assert(beacon.bytes[5] == 1u);
            a_pending = beacon;
            a_until = now + 250u;
            a_collision = 0u;
            if (b_active) {
                a_collision = 1u;
                b_collision = 1u;
            }
            a_active = 1u;
        }
        if (ninlil_mesh_lab_tick(&b, now, &beacon)) {
            assert(beacon.bytes[5] == 1u); /* Relay must not rejoin. */
            b_pending = beacon;
            b_until = now + 250u;
            b_collision = 0u;
            if (a_active) {
                a_collision = 1u;
                b_collision = 1u;
            }
            b_active = 1u;
        }
        (void)ninlil_mesh_lab_tick(&c, now, &request);
    }
    ninlil_mesh_lab_snapshot(&c, &snap);
    assert(snap.rx_count >= 2u); /* At least two non-collided B beacons. */
    ninlil_mesh_lab_snapshot(&b, &snap);
    assert(snap.joined && !snap.joining && snap.hops == 1u
        && memcmp(snap.parent_id, HIL_A, 8u) == 0);
}

/* PENALTY 200 is an explicit HIL candidate exclusion. It never falls back to
 * the excluded direct parent; a later mature relay can still be selected.
 * 199 remains the highest ordinary score penalty and stays eligible. */
static void test_initial_parent_discovery_window(void)
{
    ninlil_mesh_lab_t a, b, c, scored;
    ninlil_mesh_lab_tx_t a_beacon, b_beacon, request, unused;
    ninlil_mesh_lab_event_t event;

    ninlil_mesh_lab_init(&a, A);
    ninlil_mesh_lab_init(&b, B);
    ninlil_mesh_lab_init(&c, C);
    assert(ninlil_mesh_lab_become_controller(&a, SITE, 1u, 0u));
    assert(ninlil_mesh_lab_become_controller(&b, SITE, 1u, 0u));
    assert(ninlil_mesh_lab_set_test_penalty(&c, A, 200u));
    assert(ninlil_mesh_lab_tick(&a, 0u, &a_beacon));
    deliver(&c, &a_beacon, 0u, &unused, &event);
    assert(ninlil_mesh_lab_tick(&a, 3000u, &a_beacon));
    deliver(&c, &a_beacon, 3000u, &unused, &event);
    assert(!ninlil_mesh_lab_tick(&c, 10000u, &request));
    assert(ninlil_mesh_lab_tick(&b, 11000u, &b_beacon));
    deliver(&c, &b_beacon, 11000u, &unused, &event);
    assert(ninlil_mesh_lab_tick(&b, 14000u, &b_beacon));
    deliver(&c, &b_beacon, 14000u, &request, &event);
    assert(request.length != 0u && memcmp(request.bytes + 40u, B, 8u) == 0);

    ninlil_mesh_lab_init(&scored, C);
    assert(ninlil_mesh_lab_set_test_penalty(&scored, A, 199u));
    deliver(&scored, &a_beacon, 0u, &unused, &event);
    deliver(&scored, &a_beacon, 3000u, &unused, &event);
    assert(!ninlil_mesh_lab_tick(&scored, 9999u, &request));
    assert(ninlil_mesh_lab_tick(&scored, 10000u, &request));
    assert(memcmp(request.bytes + 40u, A, 8u) == 0);
}

int main(void)
{
    ninlil_mesh_lab_t a, b, c;
    ninlil_mesh_lab_tx_t one, two, three, data, retry, incoming, incoming_relay, reply;
    ninlil_mesh_lab_event_t event;
    ninlil_mesh_lab_snapshot_t snap;
    uint8_t payload[4] = {0xaa, 0xbb, 0xcc, 0xdd};

    ninlil_mesh_lab_init(&a, A);
    ninlil_mesh_lab_init(&b, B);
    ninlil_mesh_lab_init(&c, C);
    assert(ninlil_mesh_lab_become_controller(&a, SITE, 1u, 0u));

    assert(ninlil_mesh_lab_tick(&a, 0u, &one));
    deliver(&b, &one, 0u, &two, &event);
    assert(two.length == 0u);
    assert(ninlil_mesh_lab_tick(&a, 3000u, &one));
    deliver(&b, &one, 3000u, &two, &event);
    assert(two.length == 0u);
    assert(!ninlil_mesh_lab_tick(&b, 9999u, &two));
    assert(ninlil_mesh_lab_tick(&b, 10000u, &two));
    assert(two.length != 0u);
    deliver(&a, &two, 10001u, &three, &event);
    deliver(&b, &three, 10002u, &one, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_JOINED);

    assert(!ninlil_mesh_lab_tick(&b, 10501u, &one));
    assert(ninlil_mesh_lab_tick(&b, 10502u, &one));
    deliver(&c, &one, 10502u, &two, &event);
    assert(ninlil_mesh_lab_tick(&a, 13000u, &one));
    deliver(&b, &one, 13000u, &two, &event);
    assert(ninlil_mesh_lab_tick(&b, 13500u, &one));
    deliver(&c, &one, 13500u, &two, &event);
    assert(two.length == 0u);
    assert(!ninlil_mesh_lab_tick(&c, 20501u, &two));
    assert(ninlil_mesh_lab_tick(&c, 20502u, &two));
    deliver(&b, &two, 20503u, &three, &event);
    deliver(&a, &three, 20504u, &one, &event);
    deliver(&b, &one, 20505u, &two, &event);
    deliver(&c, &two, 20506u, &three, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_JOINED);
    ninlil_mesh_lab_snapshot(&c, &snap);
    assert(snap.joined && snap.hops == 2u && memcmp(snap.parent_id, B, 8u) == 0);

    /* A valid beacon from the selected parent renews the LAB lease. */
    assert(ninlil_mesh_lab_tick(&a, 22000u, &one));
    deliver(&b, &one, 22000u, &two, &event);
    assert(ninlil_mesh_lab_tick(&b, 22500u, &one));
    assert(ninlil_mesh_lab_selected_parent_beacon(&c, one.bytes, one.length));
    deliver(&c, &one, 22501u, &two, &event);
    ninlil_mesh_lab_snapshot(&c, &snap);
    assert(snap.lease_until_ms == 42501u);

    assert(ninlil_mesh_lab_send_data(
        &c, A, payload, sizeof(payload), 23000u, &one));
    assert(one.length == 68u);
    assert(ninlil_mesh_lab_tx_requires_ack(&c, &one));
    data = one;
    deliver(&b, &one, 23000u, &two, &event);
    assert(!ninlil_mesh_lab_tx_requires_ack(&b, &two));
    deliver(&a, &two, 23001u, &three, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_DATA);
    assert(event.payload_length == sizeof(payload));
    assert(memcmp(event.payload, payload, sizeof(payload)) == 0);

    /* A source DATA can still await its ACK while C accepts another DATA and
     * produces an immediate ACK/relay response in a separate bounded slot. */
    assert(ninlil_mesh_lab_send_data(
        &a, C, payload, sizeof(payload), 23001u, &incoming));
    deliver(&b, &incoming, 23002u, &incoming_relay, &event);
    deliver(&c, &incoming_relay, 23003u, &reply, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_DATA && reply.length != 0u
        && reply.bytes[5] == 5u);
    assert(ninlil_mesh_lab_tx_requires_ack(&c, &data));

    deliver(&b, &three, 23002u, &one, &event);
    deliver(&c, &one, 23003u, &two, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_ACK);
    assert(ninlil_mesh_lab_ack_matches_tx(&data, &event));
    event.payload[0] ^= 1u;
    assert(!ninlil_mesh_lab_ack_matches_tx(&data, &event));
    assert(ninlil_mesh_lab_retry_data(&c, &data, 23004u, &retry));
    assert(retry.length == data.length
        && memcmp(retry.bytes + 20u, data.bytes + 20u, 4u) != 0);
    assert(ninlil_mesh_lab_tx_requires_ack(&c, &retry));
    assert(!ninlil_mesh_lab_ack_matches_tx(&retry, &event));
    assert(ninlil_mesh_lab_data_ack_retry_at(HIL_C, 169u, 1u, 23000u)
        >= 26000u && ninlil_mesh_lab_data_ack_retry_at(HIL_C, 169u, 1u, 23000u)
        < 26701u);
    assert(ninlil_mesh_lab_data_ack_retry_at(HIL_C, 169u, 1u, 23000u)
        != ninlil_mesh_lab_data_ack_retry_at(HIL_C, 170u, 2u, 23000u));

    /* Exact duplicate is rejected and counted. */
    assert(!ninlil_mesh_lab_receive(
        &c, one.bytes, one.length, -55, 8, 23004u, &two, &event));
    ninlil_mesh_lab_snapshot(&c, &snap);
    assert(snap.duplicate_count == 1u);

    /* The controller also uses the learned reverse route for downlink. */
    assert(ninlil_mesh_lab_send_data(
        &a, C, payload, sizeof(payload), 23005u, &one));
    deliver(&b, &one, 23006u, &two, &event);
    deliver(&c, &two, 23007u, &three, &event);
    assert(event.kind == NINLIL_MESH_LAB_EVENT_DATA);
    assert(memcmp(event.payload, payload, sizeof(payload)) == 0);

    /* Old LAB membership expires; a node can discover another site again. */
    assert(!ninlil_mesh_lab_tick(&c, 43000u, &one));
    ninlil_mesh_lab_snapshot(&c, &snap);
    assert(!snap.joined && snap.site_epoch == 0u);

    test_two_hop_parent_direction();
    test_same_sequence_distinct_origins();
    test_half_duplex_turnaround_guard();
    test_response_receive_dwell();
    test_membership_expiry_clears_pending_state();
    test_hil_beacon_dephase_and_relay_stability();
    test_initial_parent_discovery_window();
    puts("mesh_lab_test OK");
    return 0;
}
