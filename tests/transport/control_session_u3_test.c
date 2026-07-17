/*
 * U3 host tests: C3 control session + C4 pump over fake C1 stream.
 * Deterministic; no timing sleeps; no physical USB.
 * Does not claim U3 series complete, HELLO/NCL1, or HIL.
 */

#include "control_session.h"
#include "fake_byte_stream.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int encode_frame(
    uint8_t type,
    uint32_t stream_id,
    uint32_t sequence,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out,
    uint32_t *out_len)
{
    ninlil_model_control_frame_fields_t fields;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = type;
    fields.flags = 0u;
    fields.stream_or_cell_id = stream_id;
    fields.sequence = sequence;
    fields.payload.data = payload_len > 0u ? payload : NULL;
    fields.payload.length = payload_len;
    *out_len = 0u;
    REQUIRE(
        ninlil_model_control_frame_encode(
            &fields, out, NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES, out_len)
        == NINLIL_OK);
    return 0;
}

static int setup_bound(
    ninlil_ctrl_session_object_t *obj,
    ninlil_ctrl_session_t **session,
    ninlil_fake_byte_stream_t *fake)
{
    ninlil_ctrl_session_error_t err;

    ninlil_fake_byte_stream_init(fake);
    ninlil_fake_byte_stream_open_up(fake, 1u);
    REQUIRE(
        ninlil_ctrl_session_init_object(obj, session) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_bind(*session, &fake->view, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_state(*session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_bound_generation(*session) == 1u);
    return 0;
}

static int stats_equal(
    const ninlil_ctrl_session_stats_t *a,
    const ninlil_ctrl_session_stats_t *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static int test_object_ceilings(void)
{
    REQUIRE(ninlil_ctrl_session_object_size() <= NINLIL_CTRL_SESSION_OBJECT_BYTES);
    REQUIRE(ninlil_ctrl_session_object_align() == 8u);
    REQUIRE(NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES == 16u);
    REQUIRE(NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP == 8192u);
    return 0;
}

static int test_framing_golden_roundtrip(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    uint8_t out_payload[16];
    ninlil_ctrl_session_frame_t taken;
    ninlil_ctrl_session_stats_t stats;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA,
            7u,
            3u,
            payload,
            (uint32_t)sizeof(payload),
            frame,
            &flen)
        != 0) {
        return 1;
    }
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);
    REQUIRE(
        ninlil_ctrl_session_take_rx(
            session, out_payload, sizeof(out_payload), &taken, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(taken.type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA);
    REQUIRE(taken.stream_or_cell_id == 7u);
    REQUIRE(taken.sequence == 3u);
    REQUIRE(taken.payload_length == 4u);
    REQUIRE(memcmp(taken.payload, payload, 4u) == 0);
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.frames_enqueued == 1u);
    REQUIRE(stats.frames_taken == 1u);
    REQUIRE(stats.frames_accepted >= 1u);
    return 0;
}

static int test_one_byte_chunk_inject(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    uint8_t payload[] = {0x11, 0x22};
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    uint32_t i;
    uint8_t out_payload[8];
    ninlil_ctrl_session_frame_t taken;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_PING,
            0u,
            0u,
            payload,
            2u,
            frame,
            &flen)
        != 0) {
        return 1;
    }
    for (i = 0u; i < flen; ++i) {
        REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, &frame[i], 1u));
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    }
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);
    REQUIRE(
        ninlil_ctrl_session_take_rx(
            session, out_payload, sizeof(out_payload), &taken, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(taken.payload_length == 2u);
    REQUIRE(out_payload[0] == 0x11 && out_payload[1] == 0x22);
    return 0;
}

static int test_arbitrary_chunk_inject(void)
{
    ninlil_ctrl_session_error_t err;
    uint8_t p1[] = {1};
    uint8_t p2[] = {2, 3, 4};
    uint8_t f1[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t f2[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t concat[2048];
    uint32_t l1 = 0u;
    uint32_t l2 = 0u;
    uint32_t total;
    const uint32_t chunks[] = {1u, 3u, 7u, 13u, 64u, 200u, 500u};
    uint32_t ci;
    uint8_t out[8];
    ninlil_ctrl_session_frame_t taken;

    if (encode_frame(NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 1u, 0u, p1, 1u, f1, &l1)
        != 0) {
        return 1;
    }
    if (encode_frame(NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 1u, 1u, p2, 3u, f2, &l2)
        != 0) {
        return 1;
    }
    (void)memcpy(concat, f1, l1);
    (void)memcpy(concat + l1, f2, l2);
    total = l1 + l2;

    for (ci = 0u; ci < (uint32_t)(sizeof(chunks) / sizeof(chunks[0])); ++ci) {
        ninlil_ctrl_session_object_t obj2;
        ninlil_ctrl_session_t *s2 = NULL;
        ninlil_fake_byte_stream_t fake2;
        uint32_t chunk = chunks[ci];
        uint32_t off = 0u;

        if (setup_bound(&obj2, &s2, &fake2) != 0) {
            return 1;
        }
        while (off < total) {
            uint32_t n = chunk;
            if (n > total - off) {
                n = total - off;
            }
            REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake2, concat + off, n));
            REQUIRE(
                ninlil_ctrl_session_pump(s2, 0u, &err) == NINLIL_CTRL_SESSION_OK);
            off += n;
        }
        REQUIRE(ninlil_ctrl_session_ingress_count(s2) == 2u);
        REQUIRE(
            ninlil_ctrl_session_take_rx(s2, out, sizeof(out), &taken, &err)
            == NINLIL_CTRL_SESSION_OK);
        REQUIRE(taken.sequence == 0u);
        REQUIRE(
            ninlil_ctrl_session_take_rx(s2, out, sizeof(out), &taken, &err)
            == NINLIL_CTRL_SESSION_OK);
        REQUIRE(taken.sequence == 1u);
    }
    return 0;
}

static int test_crc_garbage_resync_and_retention(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    uint8_t good_payload[] = {0xaa};
    uint8_t good[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t glen = 0u;
    uint8_t noise[] = {0x00, 0xff, 0x4e, 0x43, 0x00, 0x01, 0x02, 0x03};
    uint8_t bad[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t blen = 0u;
    uint8_t stream[4096];
    uint32_t slen = 0u;
    uint8_t out[8];
    ninlil_ctrl_session_frame_t taken;
    ninlil_ctrl_session_stats_t before_fence;
    ninlil_ctrl_session_stats_t after_rebind;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, 9u, good_payload, 1u, good,
            &glen)
        != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, 1u, good_payload, 1u, bad,
            &blen)
        != 0) {
        return 1;
    }
    bad[blen - 1u] ^= 0xffu;

    (void)memcpy(stream + slen, noise, sizeof(noise));
    slen += (uint32_t)sizeof(noise);
    (void)memcpy(stream + slen, bad, blen);
    slen += blen;
    (void)memcpy(stream + slen, good, glen);
    slen += glen;

    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, stream, slen));
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    {
        int spins = 0;
        while (ninlil_ctrl_session_ingress_count(session) == 0u && spins < 8) {
            REQUIRE(
                ninlil_ctrl_session_pump(session, 0u, &err)
                == NINLIL_CTRL_SESSION_OK);
            ++spins;
        }
    }
    REQUIRE(ninlil_ctrl_session_ingress_count(session) >= 1u);
    REQUIRE(
        ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(taken.sequence == 9u);
    ninlil_ctrl_session_stats(session, &before_fence);
    REQUIRE(before_fence.resync_skips > 0u);
    REQUIRE(
        before_fence.rejects_bad_frame_crc >= 1u
        || before_fence.rejects_bad_header >= 1u);
    REQUIRE(before_fence.frames_accepted >= 1u);

    /* Fence + rebind must retain cumulative framing counters. */
    ninlil_fake_byte_stream_inject_overflow(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_RX_OVERFLOW);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &after_rebind);
    REQUIRE(after_rebind.resync_skips >= before_fence.resync_skips);
    REQUIRE(after_rebind.frames_accepted >= before_fence.frames_accepted);
    REQUIRE(after_rebind.rejects_bad_frame_crc
            + after_rebind.rejects_bad_header
        >= before_fence.rejects_bad_frame_crc + before_fence.rejects_bad_header);
    REQUIRE(after_rebind.rebind_count >= 1u);
    return 0;
}

static int test_rx_overflow_fence(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_stats_t stats;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    ninlil_fake_byte_stream_inject_overflow(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_RX_OVERFLOW);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.rx_overflow_fences >= 1u);
    return 0;
}

static int test_generation_change_fence(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    uint8_t out[4];
    ninlil_ctrl_session_frame_t taken;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, 1u, (const uint8_t *)"Z",
            1u, frame, &flen)
        != 0) {
        return 1;
    }
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);

    ninlil_fake_byte_stream_link_down(&fake);
    ninlil_fake_byte_stream_link_up_again(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_GENERATION_MISMATCH);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);

    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(out[0] == 'Z');
    return 0;
}

static int test_gen_toctou_on_read(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    ninlil_ctrl_session_stats_t stats;
    uint64_t bound;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    bound = ninlil_ctrl_session_bound_generation(session);
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, 5u, (const uint8_t *)"Q",
            1u, frame, &flen)
        != 0) {
        return 1;
    }
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    ninlil_fake_byte_stream_bump_gen_on_next_read(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_GENERATION_MISMATCH);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    /* Old session must not have accepted the frame into ingress. */
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.generation_fences >= 1u);
    REQUIRE(fake.link_generation != bound);
    return 0;
}

static int test_gen_toctou_on_write(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_stats_t stats;
    uint64_t accepts_before;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 1u;
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &stats);
    accepts_before = stats.tx_accepts;

    ninlil_fake_byte_stream_bump_gen_on_next_write(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_GENERATION_MISMATCH);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    ninlil_ctrl_session_stats(session, &stats);
    /* Must not count TX accept for old bound session. */
    REQUIRE(stats.tx_accepts == accepts_before);
    REQUIRE(stats.generation_fences >= 1u);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);
    return 0;
}

static int test_reopen_old_generation_reject(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_status_t st;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_PING, 0u, 0u, NULL, 0u, frame, &flen)
        != 0) {
        return 1;
    }
    ninlil_fake_byte_stream_close(&fake);
    /* Close observed on pump: exact CLOSED + full fence (no void/OR hide). */
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_CLOSED);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);

    ninlil_fake_byte_stream_open_up(&fake, 1u);
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_CONTINUITY_LOST);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);
    return 0;
}

static int test_tx_all_or_none_would_block_and_partial_violation(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_model_control_frame_fields_t fields;
    uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    uint8_t tx_buf[2048];
    uint32_t tx_n;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result =
        NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    ninlil_bytes_view_t encoded;
    ninlil_ctrl_session_stats_t stats;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.stream_or_cell_id = 5u;
    fields.sequence = 11u;
    fields.payload.data = payload;
    fields.payload.length = (uint32_t)sizeof(payload);

    /* Full all-or-none TX. */
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_OK);
    payload[0] = 0xff; /* caller free after copy */
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);
    tx_n = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n >= NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES);
    encoded.data = tx_buf;
    encoded.length = tx_n;
    REQUIRE(
        ninlil_model_control_frame_decode(encoded, &view, &result) == NINLIL_OK);
    REQUIRE(view.payload[0] == 0x10);

    /* WOULD_BLOCK: accepted==0, full frame residual retained. */
    payload[0] = 0x10;
    fields.sequence = 12u;
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 0);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);

    /* Partial OK inject: fail-closed, no false TX accept custody. */
    fields.sequence = 13u;
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &stats);
    {
        uint64_t accepts = stats.tx_accepts;
        ninlil_fake_byte_stream_force_partial_ok_once(&fake, 1u);
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err)
            == NINLIL_CTRL_SESSION_IO_ERROR);
        REQUIRE(
            ninlil_ctrl_session_state(session)
            == NINLIL_CTRL_SESSION_STATE_FENCED);
        ninlil_ctrl_session_stats(session, &stats);
        REQUIRE(stats.tx_accepts == accepts);
        REQUIRE(stats.tx_partial_ok_fences >= 1u);
    }
    return 0;
}

static int test_wrong_owner_zero_mutation(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_error_t sticky_before;
    ninlil_ctrl_session_error_t sticky_after;
    ninlil_ctrl_session_stats_t before;
    ninlil_ctrl_session_stats_t after;
    ninlil_model_control_frame_fields_t fields;
    uint32_t intent_before;
    uint32_t residual_before;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &before);
    ninlil_ctrl_session_last_error(session, &sticky_before);
    intent_before = ninlil_ctrl_session_tx_intent_count(session);
    residual_before = ninlil_ctrl_session_tx_wire_residual(session);

    ninlil_fake_byte_stream_set_caller_token(&fake, 99u);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WRONG_OWNER);
    REQUIRE(err.stage == NINLIL_CTRL_SESSION_STAGE_OWNER);

    /* Zero mutation of all session-owned state. */
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == intent_before);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == residual_before);
    ninlil_ctrl_session_stats(session, &after);
    REQUIRE(stats_equal(&before, &after));
    ninlil_ctrl_session_last_error(session, &sticky_after);
    REQUIRE(memcmp(&sticky_before, &sticky_after, sizeof(sticky_before)) == 0);

    /* Bind wrong-owner also zero-mutate. */
    ninlil_ctrl_session_unbind(session, &err);
    ninlil_fake_byte_stream_set_caller_token(&fake, 99u);
    {
        ninlil_ctrl_session_stats_t b2;
        ninlil_ctrl_session_stats_t a2;
        ninlil_ctrl_session_stats(session, &b2);
        REQUIRE(
            ninlil_ctrl_session_bind(session, &fake.view, &err)
            == NINLIL_CTRL_SESSION_WRONG_OWNER);
        ninlil_ctrl_session_stats(session, &a2);
        REQUIRE(stats_equal(&b2, &a2));
        REQUIRE(
            ninlil_ctrl_session_state(session)
            == NINLIL_CTRL_SESSION_STATE_FENCED);
    }

    ninlil_fake_byte_stream_set_caller_token(&fake, 1u);
    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    return 0;
}

static int test_ingress_full_drop_counter(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_stats_t stats;
    uint32_t i;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    for (i = 0u; i < 17u; ++i) {
        if (encode_frame(
                NINLIL_MODEL_CONTROL_FRAME_TYPE_PING, 0u, i, NULL, 0u, frame,
                &flen)
            != 0) {
            return 1;
        }
        REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    }
    REQUIRE(
        ninlil_ctrl_session_ingress_count(session)
        == NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES);
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.frames_dropped_ingress_full >= 1u);
    return 0;
}

static int test_counter_saturation_and_retention_seam(void)
{
#if !defined(NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM)
    (void)fprintf(stderr, "test seam macro not enabled\n");
    return 1;
#else
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_stats_t stats;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    uint8_t out[4];
    ninlil_ctrl_session_frame_t taken;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    /* Force committed counters near UINT64_MAX. */
    ninlil_ctrl_session_test_force_committed_framing_stats(
        session, UINT64_MAX - 1u, UINT64_MAX - 2u);
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_PING, 0u, 0u, NULL, 0u, frame, &flen)
        != 0) {
        return 1;
    }
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &stats);
    /* Live + committed saturates. */
    REQUIRE(stats.frames_accepted == UINT64_MAX);
    REQUIRE(stats.resync_skips >= UINT64_MAX - 2u);

    /* Fence/rebind retains saturated committed values. */
    ninlil_fake_byte_stream_inject_overflow(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_RX_OVERFLOW);
    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.frames_accepted == UINT64_MAX);
    REQUIRE(stats.resync_skips == UINT64_MAX || stats.resync_skips >= UINT64_MAX - 2u);
    return 0;
#endif
}

static int test_ingress_tx_wrap_compaction_fifo(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    uint32_t i;
    uint8_t out[64];
    ninlil_ctrl_session_frame_t taken;
    ninlil_model_control_frame_fields_t fields;
    uint8_t payloads[16][8];
    uint8_t sizes[16];

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }

    /* Fill ingress with variable payloads (sizes 1..8 cycling). */
    for (i = 0u; i < 16u; ++i) {
        uint32_t plen = (i % 8u) + 1u;
        uint32_t j;
        sizes[i] = (uint8_t)plen;
        for (j = 0u; j < plen; ++j) {
            payloads[i][j] = (uint8_t)(0xA0u + i + j);
        }
        if (encode_frame(
                NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA,
                i,
                i,
                payloads[i],
                plen,
                frame,
                &flen)
            != 0) {
            return 1;
        }
        REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    }
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 16u);

    /* Take half → compact path with wrap. */
    for (i = 0u; i < 8u; ++i) {
        REQUIRE(
            ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
            == NINLIL_CTRL_SESSION_OK);
        REQUIRE(taken.sequence == i);
        REQUIRE(taken.payload_length == sizes[i]);
        REQUIRE(memcmp(taken.payload, payloads[i], sizes[i]) == 0);
    }
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 8u);

    /* Re-enqueue 8 more with different IDs; FIFO must preserve remaining 8..15 then new. */
    for (i = 0u; i < 8u; ++i) {
        uint32_t seq = 100u + i;
        uint8_t p[] = { (uint8_t)(0x50u + i) };
        if (encode_frame(
                NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, seq, seq, p, 1u, frame, &flen)
            != 0) {
            return 1;
        }
        REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    }
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 16u);
    for (i = 8u; i < 16u; ++i) {
        REQUIRE(
            ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
            == NINLIL_CTRL_SESSION_OK);
        REQUIRE(taken.sequence == i);
        REQUIRE(taken.payload_length == sizes[i]);
        REQUIRE(memcmp(taken.payload, payloads[i], sizes[i]) == 0);
    }
    for (i = 0u; i < 8u; ++i) {
        REQUIRE(
            ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
            == NINLIL_CTRL_SESSION_OK);
        REQUIRE(taken.sequence == 100u + i);
        REQUIRE(taken.payload_length == 1u);
        REQUIRE(out[0] == (uint8_t)(0x50u + i));
    }

    /* TX intent: fill 16, drain via pump, refill, verify wire order. */
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    for (i = 0u; i < 16u; ++i) {
        fields.sequence = i;
        REQUIRE(
            ninlil_ctrl_session_submit_tx(session, &fields, &err)
            == NINLIL_CTRL_SESSION_OK);
    }
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 16u);
    {
        int spins = 0;
        while ((ninlil_ctrl_session_tx_intent_count(session) > 0u
                   || ninlil_ctrl_session_tx_wire_residual(session) > 0u)
            && spins < 64) {
            ninlil_ctrl_session_status_t st =
                ninlil_ctrl_session_pump(session, 0u, &err);
            REQUIRE(
                st == NINLIL_CTRL_SESSION_OK
                || st == NINLIL_CTRL_SESSION_WOULD_BLOCK);
            ++spins;
        }
    }
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 0u);
    {
        uint8_t wire[8192];
        uint32_t wn = ninlil_fake_byte_stream_take_tx(&fake, wire, sizeof(wire));
        uint32_t off = 0u;
        uint32_t got = 0u;
        while (off < wn && got < 16u) {
            ninlil_bytes_view_t enc;
            ninlil_model_control_frame_view_t view;
            ninlil_model_control_frame_result_t res =
                NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
            uint32_t fl = 0u;
            enc.data = wire + off;
            enc.length = wn - off;
            REQUIRE(
                ninlil_model_control_frame_decode_prefix(enc, &view, &fl, &res)
                == NINLIL_OK);
            REQUIRE(res == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);
            REQUIRE(view.sequence == got);
            off += fl;
            ++got;
        }
        REQUIRE(got == 16u);
    }
    return 0;
}

static int test_malformed_c1_shapes_fail_closed(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_status_t st;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    ninlil_fake_byte_stream_force_read_ok_over_capacity_once(&fake);
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_IO_ERROR);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);

    ninlil_fake_byte_stream_set_caller_token(&fake, 1u);
    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_force_read_would_block_nonzero_once(&fake);
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_IO_ERROR);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);

    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_force_write_would_block_nonzero_once(&fake);
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_IO_ERROR);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    return 0;
}

static int test_loopback_two_sessions(void)
{
    ninlil_ctrl_session_object_t oa;
    ninlil_ctrl_session_object_t ob;
    ninlil_ctrl_session_t *sa = NULL;
    ninlil_ctrl_session_t *sb = NULL;
    ninlil_fake_byte_stream_t fa;
    ninlil_fake_byte_stream_t fb;
    ninlil_ctrl_session_error_t err;
    ninlil_model_control_frame_fields_t fields;
    uint8_t payload[] = {'u', '3'};
    uint8_t wire[2048];
    uint32_t wn;
    uint8_t out[8];
    ninlil_ctrl_session_frame_t taken;

    if (setup_bound(&oa, &sa, &fa) != 0) {
        return 1;
    }
    if (setup_bound(&ob, &sb, &fb) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.stream_or_cell_id = 42u;
    fields.sequence = 7u;
    fields.payload.data = payload;
    fields.payload.length = 2u;
    REQUIRE(
        ninlil_ctrl_session_submit_tx(sa, &fields, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_pump(sa, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    wn = ninlil_fake_byte_stream_take_tx(&fa, wire, sizeof(wire));
    REQUIRE(wn > 0u);
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fb, wire, wn));
    REQUIRE(ninlil_ctrl_session_pump(sb, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_take_rx(sb, out, sizeof(out), &taken, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(out[0] == 'u' && out[1] == '3');
    return 0;
}

/* ---- U3↔U4 production-private boundary (logical epoch / tracked TX) ---- */

static int begin_epoch(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_logical_epoch_t *epoch)
{
    ninlil_ctrl_session_error_t err;

    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, epoch, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(epoch->epoch_id != 0u);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);
    return 0;
}

static int test_tracked_wb_pending_cancel_wire0_seq_reuse(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_token_t token2 = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH;
    uint8_t payload[] = {0x01, 0x02};
    uint8_t tx_buf[2048];
    uint32_t tx_n;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 42u;
    fields.payload.data = payload;
    fields.payload.length = 2u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(token != 0u);

    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED);

    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 0u);

    /* After cancel, writable must not emit the cancelled frame. */
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 0);
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    tx_n = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n == 0u);

    /* Sequence reuse allowed after cancel. */
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token2, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(token2 != 0u);
    REQUIRE(token2 != token);
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token2, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);
    return 0;
}

static int test_tracked_full_ok_exact_and_double_resolve(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_stats_t stats;
    uint64_t accepts_before;
    uint8_t tx_buf[2048];
    uint32_t tx_n;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result =
        NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    ninlil_bytes_view_t encoded;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 7u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &stats);
    accepts_before = stats.tx_accepts;
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.tx_accepts == accepts_before + 1u);
    tx_n = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n >= NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES);
    encoded.data = tx_buf;
    encoded.length = tx_n;
    REQUIRE(
        ninlil_model_control_frame_decode(encoded, &view, &result) == NINLIL_OK);
    REQUIRE(view.sequence == 7u);

    /* Double resolve after consume: zero mutation, not success. */
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);
    return 0;
}

static int test_tracked_encode_wire_cancel(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    uint8_t tx_buf[2048];
    uint32_t tx_n;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 9u;
    fields.payload.data = (const uint8_t *)"X";
    fields.payload.length = 1u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    /* Force encode onto wire without accept. */
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 0u);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);

    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 0);
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    tx_n = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n == 0u);
    return 0;
}

static int test_tracked_cancel_vs_raw_accept_boundary(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 3u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    /* Accept first: cancel cannot undo. */
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);
    REQUIRE(res != NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    return 0;
}

static int test_tracked_accept_then_fenced_gen_toctou(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_stats_t stats;
    uint64_t accepts_before;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 11u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &stats);
    accepts_before = stats.tx_accepts;
    ninlil_fake_byte_stream_bump_gen_on_next_write(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_GENERATION_MISMATCH);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 0);
    /* Accept fact retained as ACCEPTED_THEN_FENCED; not counted as current-epoch accept. */
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.tx_accepts == accepts_before);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED);
    return 0;
}

static int test_tracked_preaccept_down_fenced_unaccepted(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 12u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    /* Force write status LINK_DOWN with accepted==0 before any accept. */
    fake.force_status = NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_ERR_LINK_DOWN);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    return 0;
}

static int test_tracked_partial_ok_indeterminate(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 13u;
    fields.payload.data = payload;
    fields.payload.length = (uint32_t)sizeof(payload);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_force_partial_ok_once(&fake, 1u);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_IO_ERROR);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL);
    return 0;
}

static int test_logical_rx_cold_preserves_tx_token_bound(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    uint32_t dropped_frames = 0u;
    uint32_t dropped_bytes = 0u;
    uint64_t gen;
    uint8_t out[8];
    ninlil_ctrl_session_frame_t taken;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    gen = ninlil_ctrl_session_bound_generation(session);
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, 1u, (const uint8_t *)"A",
            1u, frame, &flen)
        != 0) {
        return 1;
    }
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 99u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);

    REQUIRE(
        ninlil_ctrl_session_logical_rx_cold(
            session,
            &epoch,
            NINLIL_CTRL_SESSION_RX_COLD_REASON_RX_OVERFLOW,
            &dropped_frames,
            &dropped_bytes,
            &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(err.status == NINLIL_CTRL_SESSION_RX_OVERFLOW);
    REQUIRE(dropped_frames == 1u);
    REQUIRE(dropped_bytes >= 1u);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_bound_generation(session) == gen);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED);

    /* take_rx empty after cold. */
    REQUIRE(
        ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
        == NINLIL_CTRL_SESSION_NEED_MORE);
    return 0;
}

static int test_claim_overflow_stays_bound_legacy_fences(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    uint64_t gen;

    /* Claimed path: RX_OVERFLOW → RX-only cold, BOUND + TX preserved. */
    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    gen = ninlil_ctrl_session_bound_generation(session);
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 1u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    {
        ninlil_ctrl_session_stats_t st0;
        ninlil_ctrl_session_stats_t st1;
        ninlil_ctrl_session_stats(session, &st0);
        ninlil_fake_byte_stream_inject_overflow(&fake);
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err)
            == NINLIL_CTRL_SESSION_RX_OVERFLOW);
        ninlil_ctrl_session_stats(session, &st1);
        /* Claim RX-cold: logical_rx_colds++, never rx_overflow_fences. */
        REQUIRE(st1.logical_rx_colds == st0.logical_rx_colds + 1u);
        REQUIRE(st1.rx_overflow_fences == st0.rx_overflow_fences);
    }
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_bound_generation(session) == gen);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_OK);

    /* Legacy non-claim path: same inject → full FENCED (existing contract). */
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 0);
    {
        ninlil_ctrl_session_stats_t st0;
        ninlil_ctrl_session_stats_t st1;
        ninlil_ctrl_session_stats(session, &st0);
        ninlil_fake_byte_stream_inject_overflow(&fake);
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err)
            == NINLIL_CTRL_SESSION_RX_OVERFLOW);
        ninlil_ctrl_session_stats(session, &st1);
        REQUIRE(st1.rx_overflow_fences == st0.rx_overflow_fences + 1u);
    }
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    return 0;
}

static int test_epoch_begin_dirty_and_legacy_submit_rejected(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_stats_t before;
    ninlil_ctrl_session_stats_t after;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 1u;
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &before);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_INVALID_STATE);
    ninlil_ctrl_session_stats(session, &after);
    REQUIRE(stats_equal(&before, &after));
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 0);

    /* Clear dirty TX via cancel-equivalent: pump accept then start clean. */
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    ninlil_ctrl_session_stats(session, &before);
    REQUIRE(
        ninlil_ctrl_session_submit_tx(session, &fields, &err)
        == NINLIL_CTRL_SESSION_INVALID_STATE);
    ninlil_ctrl_session_stats(session, &after);
    REQUIRE(stats_equal(&before, &after));
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 0u);
    return 0;
}

static int test_stale_epoch_and_wrong_owner_zero_mutation(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_ctrl_session_logical_epoch_t stale;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_stats_t before;
    ninlil_ctrl_session_stats_t after;
    ninlil_ctrl_session_error_t sticky_before;
    ninlil_ctrl_session_error_t sticky_after;
    uint32_t df = 99u;
    uint32_t db = 99u;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    stale = epoch;
    stale.epoch_id = epoch.epoch_id + 100u;
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 1u;

    ninlil_ctrl_session_stats(session, &before);
    ninlil_ctrl_session_last_error(session, &sticky_before);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &stale, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);
    REQUIRE(token == 0u);
    REQUIRE(
        ninlil_ctrl_session_logical_rx_cold(
            session,
            &stale,
            NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT,
            &df,
            &db,
            &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);
    REQUIRE(df == 0u && db == 0u);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &stale, &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);
    ninlil_ctrl_session_stats(session, &after);
    REQUIRE(stats_equal(&before, &after));
    ninlil_ctrl_session_last_error(session, &sticky_after);
    REQUIRE(memcmp(&sticky_before, &sticky_after, sizeof(sticky_before)) == 0);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);

    /* Wrong-owner on pump under claim: zero mutation of epoch/TX. */
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_ctrl_session_stats(session, &before);
    ninlil_ctrl_session_last_error(session, &sticky_before);
    ninlil_fake_byte_stream_set_caller_token(&fake, 999u);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WRONG_OWNER);
    ninlil_ctrl_session_stats(session, &after);
    REQUIRE(stats_equal(&before, &after));
    ninlil_ctrl_session_last_error(session, &sticky_after);
    REQUIRE(memcmp(&sticky_before, &sticky_after, sizeof(sticky_before)) == 0);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 1u);
    ninlil_fake_byte_stream_set_caller_token(&fake, 1u);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    return 0;
}

static int test_rebind_stale_token_and_epoch_wrap(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 1u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    /* Generation change fences and marks FENCED_UNACCEPTED. */
    ninlil_fake_byte_stream_link_down(&fake);
    ninlil_fake_byte_stream_link_up_again(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_GENERATION_MISMATCH);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 0);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    /* Stale epoch after fence. */
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);

    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    /* Epoch wrap fail-closed. */
    ninlil_ctrl_session_test_force_epoch_next(session, 0u);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_EPOCH_EXHAUSTED);
    ninlil_ctrl_session_test_force_epoch_next(session, UINT64_MAX);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(epoch.epoch_id == UINT64_MAX);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_EPOCH_EXHAUSTED);
    return 0;
}

static int test_tracked_wb_accepted_nonzero_indeterminate(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 20u;
    fields.payload.data = (const uint8_t *)"abcd";
    fields.payload.length = 4u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_force_write_would_block_nonzero_once(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_IO_ERROR);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL);
    return 0;
}

static int test_token_exhaustion_fail_closed(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_stats_t before;
    ninlil_ctrl_session_stats_t after;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 1u;

    /* Direct exhaustion via seam (token_next == 0). */
    ninlil_ctrl_session_test_force_token_next(session, 0u);
    ninlil_ctrl_session_stats(session, &before);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_TOKEN_EXHAUSTED);
    REQUIRE(token == 0u);
    REQUIRE(err.status == NINLIL_CTRL_SESSION_TOKEN_EXHAUSTED);
    ninlil_ctrl_session_stats(session, &after);
    REQUIRE(after.tracked_submits == before.tracked_submits);
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 0u);

    /* Final mint at UINT64_MAX then next submit exhausted. */
    ninlil_ctrl_session_test_force_token_next(session, UINT64_MAX);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(token == UINT64_MAX);
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_TOKEN_EXHAUSTED);
    REQUIRE(token == 0u);
    return 0;
}

static int test_rx_cold_reason_closed_catalog(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_ctrl_session_stats_t before;
    ninlil_ctrl_session_stats_t after;
    ninlil_ctrl_session_error_t sticky_before;
    ninlil_ctrl_session_error_t sticky_after;
    uint32_t df = 7u;
    uint32_t db = 7u;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    /* status_t small ints that used to collide with reason 1..4. */
    const ninlil_ctrl_session_status_t status_colliders[] = {
        NINLIL_CTRL_SESSION_OK, /* 0 */
        NINLIL_CTRL_SESSION_WOULD_BLOCK, /* 1 — must NOT become EXPLICIT */
        NINLIL_CTRL_SESSION_NEED_MORE, /* 2 */
        NINLIL_CTRL_SESSION_ERR_LINK_DOWN, /* 3 */
        NINLIL_CTRL_SESSION_INVALID_ARGUMENT, /* 4 */
        NINLIL_CTRL_SESSION_STALE_EPOCH,
        NINLIL_CTRL_SESSION_RX_OVERFLOW,
    };
    uint32_t si;

    /* Tagged reasons must be disjoint from status small range. */
    REQUIRE(
        NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT
        != (ninlil_ctrl_session_rx_cold_reason_t)NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(
        NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT
        == (ninlil_ctrl_session_rx_cold_reason_t)0x52430001u);
    REQUIRE(
        (NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT
            & NINLIL_CTRL_SESSION_RX_COLD_REASON_TAG)
        == NINLIL_CTRL_SESSION_RX_COLD_REASON_TAG);

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, 1u, (const uint8_t *)"Z",
            1u, frame, &flen)
        != 0) {
        return 1;
    }
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);

    ninlil_ctrl_session_stats(session, &before);
    ninlil_ctrl_session_last_error(session, &sticky_before);

    /*
     * Status masquerading as reason (incl. WOULD_BLOCK==1 former EXPLICIT
     * collision): INVALID_ARGUMENT, zero mutation, ingress retained.
     */
    for (si = 0u;
         si < (uint32_t)(sizeof(status_colliders) / sizeof(status_colliders[0]));
         ++si) {
        df = 7u;
        db = 7u;
        REQUIRE(
            ninlil_ctrl_session_logical_rx_cold(
                session,
                &epoch,
                (ninlil_ctrl_session_rx_cold_reason_t)status_colliders[si],
                &df,
                &db,
                &err)
            == NINLIL_CTRL_SESSION_INVALID_ARGUMENT);
        REQUIRE(df == 0u && db == 0u);
        REQUIRE(err.status == NINLIL_CTRL_SESSION_INVALID_ARGUMENT);
        REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);
        ninlil_ctrl_session_stats(session, &after);
        REQUIRE(after.logical_rx_colds == before.logical_rx_colds);
        REQUIRE(after.rx_overflow_fences == before.rx_overflow_fences);
        ninlil_ctrl_session_last_error(session, &sticky_after);
        REQUIRE(memcmp(&sticky_before, &sticky_after, sizeof(sticky_before)) == 0);
    }

    /* Valid closed tagged reason derives sticky status (not free status_t). */
    REQUIRE(
        ninlil_ctrl_session_logical_rx_cold(
            session,
            &epoch,
            NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT,
            &df,
            &db,
            &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(df == 1u);
    REQUIRE(err.status == NINLIL_CTRL_SESSION_CONTINUITY_LOST);
    REQUIRE(err.status != NINLIL_CTRL_SESSION_OK);
    REQUIRE(err.framing_result == (uint32_t)NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    return 0;
}

static int test_end_epoch_requires_terminal_resolved(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 5u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    /* Terminal held until resolve: end must fail. */
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_INVALID_STATE);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 0);
    return 0;
}

static int test_intent_cancel_before_pump_no_wire(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_stats_t before;
    ninlil_ctrl_session_stats_t after;
    uint8_t payload[] = {0xa1, 0xb2, 0xc3, 0xd4};
    uint8_t tx_buf[2048];
    uint32_t tx_n;
    uint32_t intent_n;
    uint32_t intent_b;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 77u;
    fields.payload.data = payload;
    fields.payload.length = (uint32_t)sizeof(payload);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    /* Still INTENT: no pump yet. */
    intent_n = ninlil_ctrl_session_tx_intent_count(session);
    REQUIRE(intent_n == 1u);
    ninlil_ctrl_session_stats(session, &before);
    intent_b = before.tx_intent_bytes;
    REQUIRE(intent_b == (uint32_t)sizeof(payload));
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);

    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    ninlil_ctrl_session_stats(session, &after);
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 0u);
    REQUIRE(after.tx_intent_bytes == 0u);
    REQUIRE(after.tx_intent_bytes < intent_b);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);

    /* Subsequent pump must not encode or send the cancelled frame. */
    REQUIRE(ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);
    REQUIRE(ninlil_ctrl_session_tx_intent_count(session) == 0u);
    tx_n = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n == 0u);
    return 0;
}

static int test_parser_mid_bytes_cold_no_contamination(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_status_t st;
    ninlil_ctrl_session_stats_t st_before_suffix;
    ninlil_ctrl_session_stats_t st_after_suffix;
    uint8_t full[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t good[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;
    uint32_t glen = 0u;
    uint32_t mid;
    uint32_t df = 0u;
    uint32_t db = 0u;
    uint8_t out[16];
    ninlil_ctrl_session_frame_t taken;
    uint8_t payload_full[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t payload_good[] = {0xaa, 0xbb};
    uint64_t gen;
    uint64_t frames_enq_before;
    uint64_t frames_acc_before;
    uint32_t wire_before_suffix;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    gen = ninlil_ctrl_session_bound_generation(session);
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    /* Pending tracked TX during cold must be preserved (BOUND/TX/token). */
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 41u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);

    /* Stage A: encode tracked head onto wire under forced WB (exactly 1 pump). */
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(
        st == NINLIL_CTRL_SESSION_WOULD_BLOCK || st == NINLIL_CTRL_SESSION_OK);
    REQUIRE(st == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);

    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 3u, 100u, payload_full,
            (uint32_t)sizeof(payload_full), full, &flen)
        != 0) {
        return 1;
    }
    REQUIRE(flen > 22u);
    mid = flen / 2u;
    if (mid < 8u) {
        mid = 8u;
    }
    REQUIRE(mid < flen);

    /* Stage B: feed prefix only (exactly 1 pump). */
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, full, mid));
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(
        st == NINLIL_CTRL_SESSION_WOULD_BLOCK || st == NINLIL_CTRL_SESSION_OK);
    REQUIRE(st == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);

    /* Stage C: RX-only cold (no pump). */
    REQUIRE(
        ninlil_ctrl_session_logical_rx_cold(
            session,
            &epoch,
            NINLIL_CTRL_SESSION_RX_COLD_REASON_PARSER_CONTINUITY,
            &df,
            &db,
            &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_bound_generation(session) == gen);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);

    /*
     * Stage D (anti-false-green, before any new full frame):
     * inject ONLY old frame suffix → exactly 1 pump → ingress_count==0.
     * Without parser reset, suffix would complete the old frame.
     */
    ninlil_ctrl_session_stats(session, &st_before_suffix);
    frames_enq_before = st_before_suffix.frames_enqueued;
    frames_acc_before = st_before_suffix.frames_accepted;
    wire_before_suffix = ninlil_ctrl_session_tx_wire_residual(session);
    REQUIRE(wire_before_suffix > 0u);
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, full + mid, flen - mid));
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(
        st == NINLIL_CTRL_SESSION_WOULD_BLOCK || st == NINLIL_CTRL_SESSION_OK);
    REQUIRE(st == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);
    ninlil_ctrl_session_stats(session, &st_after_suffix);
    REQUIRE(st_after_suffix.frames_enqueued == frames_enq_before);
    REQUIRE(st_after_suffix.frames_accepted == frames_acc_before);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_bound_generation(session) == gen);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 1);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == wire_before_suffix);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED);

    /* Stage E: only after suffix-only zero-ingress, accept one new full frame. */
    if (encode_frame(
            NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 9u, 200u, payload_good,
            (uint32_t)sizeof(payload_good), good, &glen)
        != 0) {
        return 1;
    }
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, good, glen));
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(
        st == NINLIL_CTRL_SESSION_WOULD_BLOCK || st == NINLIL_CTRL_SESSION_OK);
    REQUIRE(st == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 1u);
    REQUIRE(
        ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(taken.stream_or_cell_id == 9u);
    REQUIRE(taken.sequence == 200u);
    REQUIRE(taken.payload_length == 2u);
    REQUIRE(out[0] == 0xaa && out[1] == 0xbb);
    REQUIRE(
        ninlil_ctrl_session_take_rx(session, out, sizeof(out), &taken, &err)
        == NINLIL_CTRL_SESSION_NEED_MORE);
    REQUIRE(ninlil_ctrl_session_ingress_count(session) == 0u);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    return 0;
}

static int test_terminal_survives_fence_rebind(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_ctrl_session_logical_epoch_t epoch2;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_status_t st;
    uint64_t gen_old;
    uint64_t gen_stream_at_unbind;
    uint64_t gen_stream_after_bump;
    uint64_t gen_bound_after;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    gen_old = ninlil_ctrl_session_bound_generation(session);
    REQUIRE(gen_old != 0u);
    REQUIRE(fake.link_generation == gen_old);
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 55u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    /* Stage: accept tracked TX (exactly 1 pump). */
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_OK);
    /* Terminal RAW_ACCEPTED held; do not resolve yet. */
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_INVALID_STATE);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, &epoch2, &err)
        == NINLIL_CTRL_SESSION_INVALID_STATE);

    REQUIRE(
        ninlil_ctrl_session_unbind(session, &err) == NINLIL_CTRL_SESSION_OK);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    gen_stream_at_unbind = fake.link_generation;
    REQUIRE(gen_stream_at_unbind == gen_old);

    /*
     * Mandatory generation bump (not same-gen rebind false-green):
     * unbind alone does not advance C1 generation. Explicit
     * link_down → link_up_again must increase fake.link_generation
     * before bind, and bound_generation must capture that new value.
     */
    ninlil_fake_byte_stream_link_down(&fake);
    REQUIRE(fake.link == NINLIL_BYTE_STREAM_LINK_DOWN);
    ninlil_fake_byte_stream_link_up_again(&fake);
    gen_stream_after_bump = fake.link_generation;
    REQUIRE(fake.link == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(gen_stream_after_bump != gen_old);
    REQUIRE(gen_stream_after_bump != gen_stream_at_unbind);
    REQUIRE(gen_stream_after_bump > gen_old);
    REQUIRE(gen_stream_after_bump == gen_old + 1u);

    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    gen_bound_after = ninlil_ctrl_session_bound_generation(session);
    REQUIRE(gen_bound_after == gen_stream_after_bump);
    REQUIRE(gen_bound_after == gen_old + 1u);
    REQUIRE(gen_bound_after != gen_old);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);

    /* Unresolved terminal still blocks begin across the new generation. */
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, &epoch2, &err)
        == NINLIL_CTRL_SESSION_INVALID_STATE);
    REQUIRE(ninlil_ctrl_session_logical_epoch_is_claimed(session) == 0);

    /* Same token / same terminal result held across generation bump. */
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);

    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);

    /* After resolve, begin is allowed and records the new generation. */
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_begin(session, &epoch2, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(epoch2.bound_stream_generation == gen_bound_after);
    REQUIRE(epoch2.bound_stream_generation == gen_old + 1u);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch2, &err)
        == NINLIL_CTRL_SESSION_OK);
    return 0;
}

static int test_read_path_rx_overflow_claim_vs_legacy(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_stats_t st0;
    ninlil_ctrl_session_stats_t st1;
    uint64_t gen;

    /* --- claim path: read() itself returns RX_OVERFLOW (not poll event) --- */
    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    gen = ninlil_ctrl_session_bound_generation(session);
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 1u;
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    ninlil_ctrl_session_stats(session, &st0);
    ninlil_fake_byte_stream_force_read_rx_overflow_once(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_RX_OVERFLOW);
    ninlil_ctrl_session_stats(session, &st1);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_BOUND);
    REQUIRE(ninlil_ctrl_session_bound_generation(session) == gen);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);
    REQUIRE(st1.logical_rx_colds == st0.logical_rx_colds + 1u);
    REQUIRE(st1.rx_overflow_fences == st0.rx_overflow_fences);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 1, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED);
    REQUIRE(
        ninlil_ctrl_session_logical_epoch_end(session, &epoch, &err)
        == NINLIL_CTRL_SESSION_OK);

    /* --- legacy non-claim: same read() overflow → full fence --- */
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 0);
    ninlil_ctrl_session_stats(session, &st0);
    ninlil_fake_byte_stream_force_read_rx_overflow_once(&fake);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_RX_OVERFLOW);
    ninlil_ctrl_session_stats(session, &st1);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    REQUIRE(st1.rx_overflow_fences == st0.rx_overflow_fences + 1u);
    return 0;
}

/*
 * Operational path (mandatory evidence): same tracked token
 * WB (no wire) → PENDING → clear WB → OK accept → RAW_ACCEPTED → STALE.
 * Uses fake TX ring / bytes_written as actual write record (not stats alone).
 */
static int test_tracked_wb_then_accept_exact_path(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_status_t st;
    ninlil_ctrl_session_stats_t sess_before;
    ninlil_ctrl_session_stats_t sess_after_wb;
    ninlil_ctrl_session_stats_t sess_after_ok;
    uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t tx_buf[2048];
    uint32_t tx_n;
    uint32_t tx_n2;
    uint64_t fake_written_before;
    uint64_t fake_written_after_wb;
    uint64_t fake_written_after_ok;
    uint64_t accepts_before;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result =
        NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    ninlil_bytes_view_t encoded;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.stream_or_cell_id = 8u;
    fields.sequence = 90u;
    fields.payload.data = payload;
    fields.payload.length = (uint32_t)sizeof(payload);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(token != 0u);

    ninlil_ctrl_session_stats(session, &sess_before);
    accepts_before = sess_before.tx_accepts;
    fake_written_before = fake.stats.bytes_written;
    REQUIRE(fake.tx_len == 0u);

    /* Stage 1: forced WB — exactly one pump, no actual write. */
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_WOULD_BLOCK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);
    REQUIRE(fake.tx_len == 0u);
    fake_written_after_wb = fake.stats.bytes_written;
    REQUIRE(fake_written_after_wb == fake_written_before);
    tx_n = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n == 0u);
    ninlil_ctrl_session_stats(session, &sess_after_wb);
    REQUIRE(sess_after_wb.tx_accepts == accepts_before);

    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) > 0u);

    /* Stage 2: clear WB — exactly one pump → full accept. */
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 0);
    st = ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(st == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_ctrl_session_tx_wire_residual(session) == 0u);
    ninlil_ctrl_session_stats(session, &sess_after_ok);
    REQUIRE(sess_after_ok.tx_accepts == accepts_before + 1u);
    fake_written_after_ok = fake.stats.bytes_written;
    REQUIRE(fake_written_after_ok > fake_written_after_wb);
    REQUIRE(fake.tx_len > 0u);

    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);

    /* Same token re-resolve is stale (consumed). */
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_STALE_EPOCH);

    /* Actual write record: exactly one NCG1 frame on the fake TX ring. */
    tx_n = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n >= NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES);
    REQUIRE(tx_n == (uint32_t)(fake_written_after_ok - fake_written_before));
    encoded.data = tx_buf;
    encoded.length = tx_n;
    REQUIRE(
        ninlil_model_control_frame_decode(encoded, &view, &result) == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);
    REQUIRE(view.type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA);
    REQUIRE(view.stream_or_cell_id == 8u);
    REQUIRE(view.sequence == 90u);
    REQUIRE(view.payload_length == 4u);
    REQUIRE(view.payload[0] == 0x10 && view.payload[3] == 0x40);
    /* No second frame left. */
    tx_n2 = ninlil_fake_byte_stream_take_tx(&fake, tx_buf, sizeof(tx_buf));
    REQUIRE(tx_n2 == 0u);
    REQUIRE(fake.tx_len == 0u);
    return 0;
}

static int test_accepted_gt_requested_indeterminate(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_stats_t stats;
    uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t over;

    if (setup_bound(&obj, &session, &fake) != 0) {
        return 1;
    }
    if (begin_epoch(session, &epoch) != 0) {
        return 1;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 88u;
    fields.payload.data = payload;
    fields.payload.length = (uint32_t)sizeof(payload);
    REQUIRE(
        ninlil_ctrl_session_tracked_submit_tx(
            session, &epoch, &fields, &token, &err)
        == NINLIL_CTRL_SESSION_OK);
    /*
     * Raw accepted > requested length: no clamp in fake. Must not be treated
     * as full OK or FENCED_UNACCEPTED.
     */
    over = NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES + 64u;
    ninlil_fake_byte_stream_force_write_ok_accepted_raw_once(&fake, over);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_IO_ERROR);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED);
    ninlil_ctrl_session_stats(session, &stats);
    REQUIRE(stats.tx_partial_ok_fences >= 1u);
    REQUIRE(
        ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(res == NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL);
    REQUIRE(res != NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    REQUIRE(res != NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH);
    REQUIRE(res != NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED);
    return 0;
}

static int test_non_ok_accepted_gt0_indeterminate(void)
{
    ninlil_ctrl_session_object_t obj;
    ninlil_ctrl_session_t *session = NULL;
    ninlil_fake_byte_stream_t fake;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_logical_epoch_t epoch;
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    const ninlil_byte_stream_status_t statuses[] = {
        NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
        NINLIL_BYTE_STREAM_CLOSED,
        NINLIL_BYTE_STREAM_IO_ERROR,
    };
    uint32_t i;

    for (i = 0u; i < (uint32_t)(sizeof(statuses) / sizeof(statuses[0])); ++i) {
        if (setup_bound(&obj, &session, &fake) != 0) {
            return 1;
        }
        if (begin_epoch(session, &epoch) != 0) {
            return 1;
        }
        (void)memset(&fields, 0, sizeof(fields));
        fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
        fields.sequence = 30u + i;
        fields.payload.data = (const uint8_t *)"wxyz";
        fields.payload.length = 4u;
        REQUIRE(
            ninlil_ctrl_session_tracked_submit_tx(
                session, &epoch, &fields, &token, &err)
            == NINLIL_CTRL_SESSION_OK);
        ninlil_fake_byte_stream_force_write_status_once(&fake, statuses[i], 1u);
        REQUIRE(
            ninlil_ctrl_session_pump(session, 0u, &err)
            == NINLIL_CTRL_SESSION_IO_ERROR);
        REQUIRE(
            ninlil_ctrl_session_state(session)
            == NINLIL_CTRL_SESSION_STATE_FENCED);
        REQUIRE(
            ninlil_ctrl_session_tx_resolve(session, token, 0, &res, &err)
            == NINLIL_CTRL_SESSION_OK);
        REQUIRE(res == NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL);
        REQUIRE(res != NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    }
    return 0;
}

int main(void)
{
    if (test_object_ceilings() != 0) {
        return 1;
    }
    if (test_framing_golden_roundtrip() != 0) {
        return 1;
    }
    if (test_one_byte_chunk_inject() != 0) {
        return 1;
    }
    if (test_arbitrary_chunk_inject() != 0) {
        return 1;
    }
    if (test_crc_garbage_resync_and_retention() != 0) {
        return 1;
    }
    if (test_rx_overflow_fence() != 0) {
        return 1;
    }
    if (test_generation_change_fence() != 0) {
        return 1;
    }
    if (test_gen_toctou_on_read() != 0) {
        return 1;
    }
    if (test_gen_toctou_on_write() != 0) {
        return 1;
    }
    if (test_reopen_old_generation_reject() != 0) {
        return 1;
    }
    if (test_tx_all_or_none_would_block_and_partial_violation() != 0) {
        return 1;
    }
    if (test_wrong_owner_zero_mutation() != 0) {
        return 1;
    }
    if (test_ingress_full_drop_counter() != 0) {
        return 1;
    }
    if (test_counter_saturation_and_retention_seam() != 0) {
        return 1;
    }
    if (test_ingress_tx_wrap_compaction_fifo() != 0) {
        return 1;
    }
    if (test_malformed_c1_shapes_fail_closed() != 0) {
        return 1;
    }
    if (test_loopback_two_sessions() != 0) {
        return 1;
    }
    if (test_tracked_wb_pending_cancel_wire0_seq_reuse() != 0) {
        return 1;
    }
    if (test_tracked_full_ok_exact_and_double_resolve() != 0) {
        return 1;
    }
    if (test_tracked_encode_wire_cancel() != 0) {
        return 1;
    }
    if (test_tracked_cancel_vs_raw_accept_boundary() != 0) {
        return 1;
    }
    if (test_tracked_accept_then_fenced_gen_toctou() != 0) {
        return 1;
    }
    if (test_tracked_preaccept_down_fenced_unaccepted() != 0) {
        return 1;
    }
    if (test_tracked_partial_ok_indeterminate() != 0) {
        return 1;
    }
    if (test_logical_rx_cold_preserves_tx_token_bound() != 0) {
        return 1;
    }
    if (test_claim_overflow_stays_bound_legacy_fences() != 0) {
        return 1;
    }
    if (test_epoch_begin_dirty_and_legacy_submit_rejected() != 0) {
        return 1;
    }
    if (test_stale_epoch_and_wrong_owner_zero_mutation() != 0) {
        return 1;
    }
    if (test_rebind_stale_token_and_epoch_wrap() != 0) {
        return 1;
    }
    if (test_tracked_wb_accepted_nonzero_indeterminate() != 0) {
        return 1;
    }
    if (test_token_exhaustion_fail_closed() != 0) {
        return 1;
    }
    if (test_rx_cold_reason_closed_catalog() != 0) {
        return 1;
    }
    if (test_end_epoch_requires_terminal_resolved() != 0) {
        return 1;
    }
    if (test_non_ok_accepted_gt0_indeterminate() != 0) {
        return 1;
    }
    if (test_intent_cancel_before_pump_no_wire() != 0) {
        return 1;
    }
    if (test_parser_mid_bytes_cold_no_contamination() != 0) {
        return 1;
    }
    if (test_terminal_survives_fence_rebind() != 0) {
        return 1;
    }
    if (test_read_path_rx_overflow_claim_vs_legacy() != 0) {
        return 1;
    }
    if (test_accepted_gt_requested_indeterminate() != 0) {
        return 1;
    }
    if (test_tracked_wb_then_accept_exact_path() != 0) {
        return 1;
    }
    (void)printf("control_session_u3_test: all passed\n");
    return 0;
}
