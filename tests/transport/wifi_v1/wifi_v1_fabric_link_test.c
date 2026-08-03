/*
 * Fabric packet-link: open SM, cancel/close reclaim, TxPermit atomic consume,
 * release-after-close, second_open DENIED.
 */
#include "wifi_fabric_adapter.h"
#include "wifi_nfl1_min.h"
#include "wifi_session.h"

#include <ninlil/platform.h>
#include <ninlil/version.h>

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

static void fill_permit(
    ninlil_tx_permit_t *p,
    uint8_t tag,
    const ninlil_id128_t *attempt,
    uint64_t expires)
{
    (void)memset(p, 0, sizeof(*p));
    p->abi_version = NINLIL_ABI_VERSION;
    p->struct_size = (uint16_t)sizeof(*p);
    (void)memset(p->permit_id.bytes, tag, 16u);
    p->attempt_id = *attempt;
    (void)memset(p->clock_epoch_id.bytes, 0xa1, 16u);
    p->expires_at_ms = expires;
}

static void test_scoped_authority(void)
{
    ninlil_wifi_session_t session;
    ninlil_wifi_fabric_link_user_t user;
    ninlil_wifi_fabric_call_scope_v1_t standalone_scope;
    ninlil_wifi_fabric_call_scope_v1_t scope_a;
    ninlil_wifi_fabric_call_scope_v1_t scope_b;
    ninlil_wifi_fabric_call_scope_v1_t scope_a2;
    ninlil_fabric_packet_link_ops_v1_t bootstrap_ops;
    ninlil_fabric_packet_link_ops_v1_t standalone_ops;
    ninlil_fabric_packet_link_ops_v1_t ops_a;
    ninlil_fabric_packet_link_ops_v1_t ops_b;
    ninlil_fabric_packet_link_ops_v1_t ops_a2;
    ninlil_fabric_packet_link_handle_t handle = NULL;
    ninlil_fabric_packet_link_handle_t other_handle = NULL;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_packet_view_v1_t packet;
    ninlil_tx_permit_t permit;
    ninlil_id128_t attempt;
    uint8_t cookie_a;
    uint8_t cookie_b;
    uint8_t nfl1[587];
    size_t nfl1_len = 0u;

    (void)memset(&session, 0, sizeof(session));
    ninlil_wifi_session_init(&session);
    session.phase = NINLIL_WIFI_PHASE_ATTACHED;
    session.attached_session_valid = 1;
    session.m4_pa_full_confirmed = 1;
    session.availability_epoch = 33u;
    (void)memset(session.ids.attached_session_id, 0x31, 16u);
    (void)memset(&user, 0, sizeof(user));
    user.session = &session;
    user.permit_now_ms = 1000u;
    user.permit_clock_epoch_set = 1u;
    (void)memset(user.permit_clock_epoch_id, 0xa1, 16u);
    ninlil_wifi_fabric_packet_link_ops_init(&bootstrap_ops, &user);

    /* Cookie-less standalone table cannot even open. */
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
        &standalone_ops, &user, &standalone_scope, NULL);
    CHECK(standalone_ops.open(standalone_ops.user, &handle)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(handle == NULL);

    cookie_a = 0xa1u;
    cookie_b = 0xb2u;
    CHECK(ninlil_wifi_fabric_packet_link_authority_prepare(
              &user, &cookie_a)
        == 1);
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
        &ops_a, &user, &scope_a, &cookie_a);
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
        &ops_b, &user, &scope_b, &cookie_b);
    CHECK(ops_a.open(ops_a.user, &handle) == NINLIL_FABRIC_LINK_OK);
    CHECK(handle != NULL);
    CHECK(ops_b.open(ops_b.user, &other_handle)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(other_handle == NULL);

    CHECK(ninlil_wifi_nfl1_min_encode(
              nfl1, sizeof(nfl1), &nfl1_len, 0x55u)
        == NINLIL_WIFI_OK);
    (void)memset(&attempt, 0x52, sizeof(attempt));
    fill_permit(&permit, 0x61u, &attempt, 200000u);
    (void)memset(&packet, 0, sizeof(packet));
    packet.api_version = 1u;
    packet.struct_size = (uint16_t)sizeof(packet);
    packet.bytes = nfl1;
    packet.length = (uint32_t)nfl1_len;
    packet.attempt_id = attempt;
    packet.permit = &permit;

    /* PREPARED is registration-only: provider TX side effect remains zero. */
    CHECK(ops_a.start_send(
              ops_a.user, handle, &packet, &token)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(token == NULL);
    CHECK(ninlil_wifi_queue_is_empty(&session.txq));
    CHECK(ninlil_wifi_fabric_packet_link_authority_activate(
              &user, &cookie_b)
        == 0);
    CHECK(ninlil_wifi_fabric_packet_link_authority_activate(
              &user, &cookie_a)
        == 1);
    CHECK(ops_a.start_send(
              ops_a.user, handle, &packet, &token)
        == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(token != NULL);
    CHECK(user.accepted_send_count == 1u);
    CHECK(ops_a.cancel_send(ops_a.user, handle, token)
        == NINLIL_FABRIC_LINK_OK);
    ops_a.release_send(ops_a.user, handle, token);
    ops_a.close(ops_a.user, handle);
    CHECK(ninlil_wifi_fabric_packet_link_authority_drain(
              &user, &cookie_a)
        == 1);
    CHECK(ninlil_wifi_fabric_packet_link_authority_unbind(
              &user, &cookie_a)
        == 1);

    /* Unregister invalidates the copied scope and keeps TX at zero. */
    handle = NULL;
    CHECK(ops_a.open(ops_a.user, &handle) == NINLIL_FABRIC_LINK_DENIED);
    CHECK(handle == NULL);
    token = (ninlil_fabric_packet_token_t)(uintptr_t)1u;
    CHECK(ops_a.start_send(
              ops_a.user,
              (ninlil_fabric_packet_link_handle_t)(uintptr_t)1u,
              &packet,
              &token)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(token == NULL);
    CHECK(ninlil_wifi_queue_is_empty(&session.txq));

    /* Same-address rebind advances generation; the old scope stays dead. */
    CHECK(ninlil_wifi_fabric_packet_link_authority_prepare(
              &user, &cookie_a)
        == 1);
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
        &ops_a2, &user, &scope_a2, &cookie_a);
    CHECK(ninlil_wifi_fabric_packet_link_authority_activate(
              &user, &cookie_a)
        == 1);
    CHECK(ops_a.open(ops_a.user, &handle) == NINLIL_FABRIC_LINK_DENIED);
    CHECK(ops_a2.open(ops_a2.user, &handle) == NINLIL_FABRIC_LINK_OK);
    ops_a2.close(ops_a2.user, handle);
    CHECK(ninlil_wifi_fabric_packet_link_authority_unbind(
              &user, &cookie_a)
        == 1);
    ninlil_wifi_session_close(&session);
}

int main(void)
{
    ninlil_wifi_session_t session;
    ninlil_wifi_fabric_link_user_t user;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_packet_link_handle_t handle = NULL;
    ninlil_fabric_packet_link_handle_t handle2 = NULL;
    ninlil_fabric_packet_view_v1_t packet;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_tx_permit_t permit;
    ninlil_id128_t attempt;
    ninlil_fabric_link_status_t st;
    uint8_t nfl1[587];
    size_t nfl1_len = 0u;
    failures = 0;
    test_scoped_authority();

    ninlil_wifi_session_init(&session);
    session.phase = NINLIL_WIFI_PHASE_ATTACHED;
    session.attached_session_valid = 1;
    session.m4_pa_full_confirmed = 1;
    session.availability_epoch = 10u;
    (void)memset(session.ids.attached_session_id, 0x11, 16u);

    (void)memset(&user, 0, sizeof(user));
    user.session = &session;
    user.permit_now_ms = 1000u;
    user.permit_clock_epoch_set = 1u;
    user.durable_outer_permit_authority = 1u;
    (void)memset(user.permit_clock_epoch_id, 0xa1, 16u);
    ninlil_wifi_fabric_packet_link_ops_init(&ops, &user);

    st = ops.open(ops.user, &handle);
    CHECK(st == NINLIL_FABRIC_LINK_OK);
    CHECK(handle != NULL);

    /* second_open while open → DENIED */
    st = ops.open(ops.user, &handle2);
    CHECK(st == NINLIL_FABRIC_LINK_DENIED);
    CHECK(handle2 == NULL);

    CHECK(ninlil_wifi_nfl1_min_encode(nfl1, sizeof(nfl1), &nfl1_len, 1u)
        == NINLIL_WIFI_OK);
    (void)memset(&attempt, 0, sizeof(attempt));
    (void)memset(attempt.bytes, 0xb2, 16u);
    (void)memset(&packet, 0, sizeof(packet));
    packet.api_version = 1u;
    packet.struct_size = (uint16_t)sizeof(packet);
    packet.bytes = nfl1;
    packet.length = (uint32_t)nfl1_len;
    packet.attempt_id = attempt;

    /* NULL permit → DENIED TX0 */
    packet.permit = NULL;
    st = ops.start_send(ops.user, handle, &packet, &token);
    CHECK(st == NINLIL_FABRIC_LINK_DENIED);
    CHECK(token == NULL);
    CHECK(user.send_slots[0].in_use == 0u);
    CHECK(ninlil_wifi_queue_is_empty(&session.txq));

    fill_permit(&permit, 0xe1, &attempt, 200000u);
    packet.permit = &permit;
    st = ops.start_send(ops.user, handle, &packet, &token);
    CHECK(st == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(token != NULL);
    CHECK(user.send_slots[0].in_use == 1u);
    CHECK(!ninlil_wifi_queue_is_empty(&session.txq));

    /* Reused same permit_id → DENIED */
    {
        ninlil_fabric_packet_token_t t2 = NULL;
        st = ops.start_send(ops.user, handle, &packet, &t2);
        CHECK(st == NINLIL_FABRIC_LINK_DENIED);
        CHECK(t2 == NULL);
    }

    /*
     * Queue/slot full → WOULD_BLOCK with consume count unchanged.
     * Fill all send slots with distinct fresh permits.
     */
    {
        ninlil_fabric_packet_token_t tokens[NINLIL_WIFI_TX_QUEUE_DEPTH];
        ninlil_tx_permit_t permits[NINLIL_WIFI_TX_QUEUE_DEPTH];
        uint32_t i;
        uint32_t consume_at_full;
        ninlil_fabric_packet_token_t t_full = NULL;
        ninlil_tx_permit_t p_full;
        uint32_t accepted = 1u; /* already one retained above */

        tokens[0] = token;
        for (i = 1u; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
            fill_permit(&permits[i], (uint8_t)(0xf0u + i), &attempt, 200000u);
            packet.permit = &permits[i];
            tokens[i] = NULL;
            st = ops.start_send(ops.user, handle, &packet, &tokens[i]);
            if (st == NINLIL_FABRIC_LINK_RETAINED) {
                CHECK(tokens[i] != NULL);
                accepted += 1u;
            } else if (st == NINLIL_FABRIC_LINK_WOULD_BLOCK) {
                CHECK(tokens[i] == NULL);
                break;
            } else {
                CHECK(0);
            }
        }
        CHECK(accepted >= 1u);
        consume_at_full = user.permit_live_count;
        fill_permit(&p_full, 0xee, &attempt, 200000u);
        packet.permit = &p_full;
        st = ops.start_send(ops.user, handle, &packet, &t_full);
        CHECK(st == NINLIL_FABRIC_LINK_WOULD_BLOCK);
        CHECK(t_full == NULL);
        CHECK(user.permit_live_count == consume_at_full);

        /* Drain retained tokens so later cases can run. */
        for (i = 0u; i < accepted; ++i) {
            if (tokens[i] != NULL) {
                (void)ops.cancel_send(ops.user, handle, tokens[i]);
                ops.release_send(ops.user, handle, tokens[i]);
            }
        }
        CHECK(user.send_slots[0].in_use == 0u);
        CHECK(ninlil_wifi_queue_is_empty(&session.txq));
        token = NULL;
    }

    /* Re-acquire one retained for cancel path below. */
    fill_permit(&permit, 0xe1, &attempt, 200000u);
    packet.permit = &permit;
    /* e1 already consumed — use new id */
    fill_permit(&permit, 0xe5, &attempt, 200000u);
    packet.permit = &permit;
    st = ops.start_send(ops.user, handle, &packet, &token);
    CHECK(st == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(token != NULL);

    /* Cancel: terminal + session TX reclaimed */
    st = ops.cancel_send(ops.user, handle, token);
    CHECK(st == NINLIL_FABRIC_LINK_OK);
    CHECK(user.send_slots[0].terminal == 1u);
    CHECK(user.send_slots[0].cancelled == 1u);
    CHECK(ninlil_wifi_queue_is_empty(&session.txq));

    /* Release after cancel frees slot */
    ops.release_send(ops.user, handle, token);
    CHECK(user.send_slots[0].in_use == 0u);

    /* Fresh permit, then close while retained */
    fill_permit(&permit, 0xe2, &attempt, 200000u);
    packet.permit = &permit;
    token = NULL;
    st = ops.start_send(ops.user, handle, &packet, &token);
    CHECK(st == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(user.send_slots[0].in_use == 1u);
    ops.close(ops.user, handle);
    CHECK(user.open == 0u);
    CHECK(user.send_slots[0].terminal == 1u);
    CHECK(user.send_slots[0].in_use == 1u); /* retained until release */
    CHECK(ninlil_wifi_queue_is_empty(&session.txq)); /* close cancelled TX */

    /* release-after-close must free slot */
    ops.release_send(ops.user, handle, token);
    CHECK(user.send_slots[0].in_use == 0u);

    /* Reopen after full reclaim */
    handle = NULL;
    st = ops.open(ops.user, &handle);
    CHECK(st == NINLIL_FABRIC_LINK_OK);

    /* Expired permit */
    fill_permit(&permit, 0xe3, &attempt, 500u); /* expires < now 1000 */
    packet.permit = &permit;
    token = NULL;
    st = ops.start_send(ops.user, handle, &packet, &token);
    CHECK(st == NINLIL_FABRIC_LINK_DENIED);
    CHECK(token == NULL);

    /* Attempt mismatch */
    fill_permit(&permit, 0xe4, &attempt, 200000u);
    (void)memset(permit.attempt_id.bytes, 0xcc, 16u);
    packet.permit = &permit;
    st = ops.start_send(ops.user, handle, &packet, &token);
    CHECK(st == NINLIL_FABRIC_LINK_DENIED);

    /*
     * Per-send completion is sequence-specific. A later queued record must not
     * keep the first token pending merely because the whole TX queue is nonempty.
     */
    {
        ninlil_tx_permit_t p1;
        ninlil_tx_permit_t p2;
        ninlil_fabric_packet_token_t t1 = NULL;
        ninlil_fabric_packet_token_t t2 = NULL;
        ninlil_fabric_link_completion_v1_t completion;
        uint32_t first_sequence;

        fill_permit(&p1, 0xc1, &attempt, 200000u);
        packet.permit = &p1;
        CHECK(ops.start_send(ops.user, handle, &packet, &t1)
            == NINLIL_FABRIC_LINK_RETAINED);
        first_sequence = user.send_slots[0].sequence_at_accept;

        fill_permit(&p2, 0xc2, &attempt, 200000u);
        packet.permit = &p2;
        CHECK(ops.start_send(ops.user, handle, &packet, &t2)
            == NINLIL_FABRIC_LINK_RETAINED);
        CHECK(session.txq.count == 2u);

        session.last_tx_completed_sequence = first_sequence;
        session.last_tx_completed_valid = 1;
        (void)memset(&completion, 0xa5, sizeof(completion));
        CHECK(ops.poll_send(ops.user, handle, t1, &completion)
            == NINLIL_FABRIC_LINK_OK);
        CHECK(completion.kind
            == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
        CHECK(session.txq.count == 2u);
        ops.release_send(ops.user, handle, t1);

        CHECK(ops.cancel_send(ops.user, handle, t2)
            == NINLIL_FABRIC_LINK_OK);
        ops.release_send(ops.user, handle, t2);
        /* Sequence 0 was only test-marked completed; remove its queued record. */
        (void)ninlil_wifi_queue_drop_sequence(&session.txq, first_sequence);
        session.last_tx_completed_valid = 0;
        CHECK(ninlil_wifi_queue_is_empty(&session.txq));
    }

    /* Receive loans are generation-bound; a forged/stale token cannot release. */
    user.rx_loan_active = 1u;
    user.active_rx_loan_generation = 7u;
    user.next_rx_loan_generation = 7u;
    user.rx_record_len = 10u;
    ops.release_received(
        ops.user, handle, (void *)(uintptr_t)((8u << 8) | 0x5du));
    CHECK(user.rx_loan_active == 1u);
    CHECK(user.rx_record_len == 10u);
    ops.release_received(
        ops.user, handle, (void *)(uintptr_t)((7u << 8) | 0x5du));
    CHECK(user.rx_loan_active == 0u);
    CHECK(user.rx_record_len == 0u);

    /* Failure outputs are zero-on-entry, including invalid user/handle paths. */
    {
        ninlil_fabric_packet_link_handle_t bad_handle =
            (ninlil_fabric_packet_link_handle_t)(uintptr_t)0x1234u;
        ninlil_fabric_packet_token_t bad_token =
            (ninlil_fabric_packet_token_t)(uintptr_t)0x1234u;
        ninlil_fabric_link_completion_v1_t completion;
        ninlil_fabric_link_state_v1_t state;
        const uint8_t *bytes = (const uint8_t *)(uintptr_t)0x1234u;
        uint32_t length = 1234u;
        void *loan = (void *)(uintptr_t)0x1234u;

        CHECK(ops.open(NULL, &bad_handle) == NINLIL_FABRIC_LINK_DENIED);
        CHECK(bad_handle == NULL);
        packet.permit = &permit;
        CHECK(ops.start_send(NULL, handle, &packet, &bad_token)
            == NINLIL_FABRIC_LINK_DENIED);
        CHECK(bad_token == NULL);
        (void)memset(&completion, 0xa5, sizeof(completion));
        CHECK(ops.poll_send(NULL, handle, token, &completion)
            == NINLIL_FABRIC_LINK_DENIED);
        CHECK(completion.api_version == 0u && completion.kind == 0u);
        CHECK(ops.receive_next(
                  NULL, handle, &bytes, &length, &loan)
            == NINLIL_FABRIC_LINK_DENIED);
        CHECK(bytes == NULL && length == 0u && loan == NULL);
        (void)memset(&state, 0xa5, sizeof(state));
        CHECK(ops.state(NULL, handle, &state) == NINLIL_FABRIC_LINK_DENIED);
        CHECK(state.api_version == 0u && state.availability_epoch == 0u);
    }

    /* Epoch wrap is fail-closed and never becomes zero/fresh again. */
    session.availability_epoch = UINT64_MAX;
    session.availability_epoch_exhausted = 0;
    session.phase = NINLIL_WIFI_PHASE_ATTACHED;
    ninlil_wifi_session_fence(&session);
    CHECK(session.availability_epoch == UINT64_MAX);
    CHECK(session.availability_epoch_exhausted == 1);

    ops.close(ops.user, handle);
    ninlil_wifi_session_close(&session);

    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_fabric_link_test: PASS\n");
    return 0;
}
