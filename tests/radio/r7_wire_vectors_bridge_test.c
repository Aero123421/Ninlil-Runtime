/*
 * R7 T1 subset vector bridge: production-linked layer Seal/Open (docs/32 §7).
 * Executes every generated vector exactly once. No skip/duplicate/unknown.
 * Test-only golden composition of layer APIs; not a production composite API.
 */

#include "r7_crypto_openssl3.h"
#include "r7_wire_codec.h"
#include "private/r7_wire_single_t1_vectors.gen.h"

#include <stdio.h>
#include <string.h>

#define NINLIL_R7_WIRE_ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define NINLIL_R7_WIRE_HEX_MAX ((size_t)512u)

_Static_assert(
    NINLIL_R7_WIRE_ARRAY_COUNT(ninlil_r7_wire_t1_vectors)
        == NINLIL_R7_WIRE_T1_VECTOR_COUNT,
    "T1 generated vector count mismatch");
_Static_assert(NINLIL_R7_WIRE_T1_VECTOR_COUNT == 7u, "T1 mandatory vector count");

static int fail(const char *id, const char *what)
{
    fprintf(stderr, "nrw1_t1_vectors_bridge FAIL id=%s check=%s\n", id, what);
    return 0;
}

static int hex_nibble(char value, uint8_t *out)
{
    if (value >= '0' && value <= '9') {
        *out = (uint8_t)(value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *out = (uint8_t)(10 + (value - 'a'));
        return 1;
    }
    return 0;
}

static int decode_hex(
    const char *hex, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    size_t chars = 0u;
    size_t i;

    if (hex == NULL || out == NULL || out_len == NULL) {
        return 0;
    }
    while (hex[chars] != '\0') {
        chars++;
        if (chars > out_capacity * 2u) {
            return 0;
        }
    }
    if ((chars & 1u) != 0u) {
        return 0;
    }
    for (i = 0u; i < chars; i += 2u) {
        uint8_t hi;
        uint8_t lo;
        if (!hex_nibble(hex[i], &hi) || !hex_nibble(hex[i + 1u], &lo)) {
            return 0;
        }
        out[i / 2u] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = chars / 2u;
    return 1;
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int run_one(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_wire_t1_vector *v)
{
    uint8_t app[190];
    uint8_t e2e_key[16];
    uint8_t e2e_iv[12];
    uint8_t hop_key[16];
    uint8_t hop_iv[12];
    uint8_t exp_e2e_blob[220];
    uint8_t exp_frame[255];
    uint8_t e2e_blob[220];
    uint8_t frame[255];
    uint8_t opened_app[190];
    uint8_t opened_blob[220];
    size_t app_len = 0u;
    size_t e2e_key_len = 0u;
    size_t e2e_iv_len = 0u;
    size_t hop_key_len = 0u;
    size_t hop_iv_len = 0u;
    size_t exp_blob_len = 0u;
    size_t exp_frame_len = 0u;
    size_t e2e_len = 0u;
    size_t frame_len = 0u;
    size_t opened_app_len = 0u;
    size_t opened_blob_len = 0u;
    ninlil_r7_wire_e2e_single_fields e2e_fields;
    ninlil_r7_wire_e2e_single_fields e2e_out;
    ninlil_r7_wire_outer_data_fields outer_fields;
    ninlil_r7_wire_outer_data_fields outer_out;
    ninlil_r7_wire_status st;

    if (!decode_hex(v->app, app, sizeof(app), &app_len)
        || app_len != (size_t)v->n) {
        return fail(v->id, "app");
    }
    if (!decode_hex(v->e2e_key16, e2e_key, sizeof(e2e_key), &e2e_key_len)
        || e2e_key_len != 16u
        || !decode_hex(v->e2e_iv12, e2e_iv, sizeof(e2e_iv), &e2e_iv_len)
        || e2e_iv_len != 12u
        || !decode_hex(v->hop_key16, hop_key, sizeof(hop_key), &hop_key_len)
        || hop_key_len != 16u
        || !decode_hex(v->hop_iv12, hop_iv, sizeof(hop_iv), &hop_iv_len)
        || hop_iv_len != 12u
        || !decode_hex(
            v->e2e_blob, exp_e2e_blob, sizeof(exp_e2e_blob), &exp_blob_len)
        || exp_blob_len != (size_t)(30u + v->n)
        || !decode_hex(
            v->outer_frame, exp_frame, sizeof(exp_frame), &exp_frame_len)
        || exp_frame_len != (size_t)v->outer_len) {
        return fail(v->id, "hex decode");
    }

    e2e_fields.e2e_context_id = v->e2e_context_id;
    e2e_fields.e2e_counter = v->e2e_counter;
    outer_fields.ack_requested = v->ack_requested;
    outer_fields.hop_remaining = v->hop_remaining;
    outer_fields.hop_context_id = v->hop_context_id;
    outer_fields.hop_counter = v->hop_counter;
    outer_fields.route_handle = v->route_handle;
    outer_fields.route_generation = v->route_generation;

    st = ninlil_r7_wire_seal_e2e_single(
        provider,
        e2e_key,
        e2e_iv,
        &e2e_fields,
        app,
        app_len,
        e2e_blob,
        exp_blob_len,
        &e2e_len);
    if (st != NINLIL_R7_WIRE_OK || e2e_len != exp_blob_len
        || !bytes_eq(e2e_blob, exp_e2e_blob, exp_blob_len)) {
        return fail(v->id, "seal_e2e");
    }

    st = ninlil_r7_wire_seal_outer_single(
        provider,
        hop_key,
        hop_iv,
        &outer_fields,
        e2e_blob,
        e2e_len,
        frame,
        exp_frame_len,
        &frame_len);
    if (st != NINLIL_R7_WIRE_OK || frame_len != exp_frame_len
        || !bytes_eq(frame, exp_frame, exp_frame_len)) {
        return fail(v->id, "seal_outer");
    }

    (void)memset(&outer_out, 0xA5, sizeof(outer_out));
    st = ninlil_r7_wire_open_outer_single(
        provider,
        hop_key,
        hop_iv,
        frame,
        frame_len,
        &outer_out,
        opened_blob,
        e2e_len,
        &opened_blob_len);
    if (st != NINLIL_R7_WIRE_OK || opened_blob_len != e2e_len
        || !bytes_eq(opened_blob, e2e_blob, e2e_len)
        || outer_out.ack_requested != outer_fields.ack_requested
        || outer_out.hop_remaining != outer_fields.hop_remaining
        || outer_out.hop_context_id != outer_fields.hop_context_id
        || outer_out.hop_counter != outer_fields.hop_counter
        || outer_out.route_handle != outer_fields.route_handle
        || outer_out.route_generation != outer_fields.route_generation) {
        return fail(v->id, "open_outer");
    }

    (void)memset(&e2e_out, 0x5A, sizeof(e2e_out));
    st = ninlil_r7_wire_open_e2e_single(
        provider,
        e2e_key,
        e2e_iv,
        opened_blob,
        opened_blob_len,
        &e2e_out,
        opened_app,
        app_len,
        &opened_app_len);
    if (st != NINLIL_R7_WIRE_OK || opened_app_len != app_len
        || !bytes_eq(opened_app, app, app_len)
        || e2e_out.e2e_context_id != e2e_fields.e2e_context_id
        || e2e_out.e2e_counter != e2e_fields.e2e_counter) {
        return fail(v->id, "open_e2e");
    }
    return 1;
}

int main(void)
{
    ninlil_r7_crypto_provider provider;
    size_t i;
    const char *seen[NINLIL_R7_WIRE_T1_VECTOR_COUNT];
    size_t seen_count = 0u;

    if (ninlil_r7_crypto_openssl3_provider_init(&provider)
        != NINLIL_R7_CRYPTO_OK) {
        fprintf(stderr, "nrw1_t1_vectors_bridge FAIL provider init\n");
        return 1;
    }

    for (i = 0u; i < NINLIL_R7_WIRE_T1_VECTOR_COUNT; i++) {
        const ninlil_r7_wire_t1_vector *v = &ninlil_r7_wire_t1_vectors[i];
        size_t j;
        for (j = 0u; j < seen_count; j++) {
            if (strcmp(seen[j], v->id) == 0) {
                return fail(v->id, "duplicate") ? 1 : 1;
            }
        }
        if (!run_one(&provider, v)) {
            return 1;
        }
        seen[seen_count++] = v->id;
    }
    if (seen_count != NINLIL_R7_WIRE_T1_VECTOR_COUNT) {
        fprintf(stderr, "nrw1_t1_vectors_bridge FAIL count\n");
        return 1;
    }
    printf(
        "nrw1_t1_vectors_bridge OK total=%u subset=ninlil-r7-wire-single-t1-v1\n",
        (unsigned)NINLIL_R7_WIRE_T1_VECTOR_COUNT);
    return 0;
}
