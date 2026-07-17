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
    (void)ninlil_ctrl_session_pump(session, 0u, &err);
    REQUIRE(
        ninlil_ctrl_session_state(session) == NINLIL_CTRL_SESSION_STATE_FENCED
        || ninlil_ctrl_session_unbind(session, &err) == NINLIL_CTRL_SESSION_OK);

    ninlil_fake_byte_stream_open_up(&fake, 1u);
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err)
        == NINLIL_CTRL_SESSION_CONTINUITY_LOST);
    REQUIRE(
        ninlil_ctrl_session_bind(session, &fake.view, &err)
        == NINLIL_CTRL_SESSION_OK);
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, frame, flen));
    REQUIRE(
        ninlil_ctrl_session_pump(session, 0u, &err) == NINLIL_CTRL_SESSION_OK);
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
    (void)printf("control_session_u3_test: all passed\n");
    return 0;
}
