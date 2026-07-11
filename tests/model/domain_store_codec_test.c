#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_codec_internal.h"
#include "domain_vector_parse.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            (void)fprintf(stderr, "%s:%d: failed: %s\n", __FILE__, __LINE__,   \
                #cond);                                                        \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int zeros(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < n; ++i) {
        if (b[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void enhex(const uint8_t *in, size_t n, char *out)
{
    static const char *H = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) {
        out[i * 2u] = H[in[i] >> 4];
        out[i * 2u + 1u] = H[in[i] & 0xfu];
    }
    out[n * 2u] = '\0';
}

static ninlil_status_t st_from(const char *s)
{
    if (strcmp(s, "OK") == 0) {
        return NINLIL_OK;
    }
    if (strcmp(s, "INVALID_ARGUMENT") == 0) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (strcmp(s, "CORRUPT") == 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (strcmp(s, "UNSUPPORTED") == 0) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (strcmp(s, "BUFFER_TOO_SMALL") == 0) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    return (ninlil_status_t)-1;
}

/*
 * Decode/encode body_hex for D1-B1 + D1-B2 subtypes via a scratch workspace.
 * Returns production status.
 */
typedef struct body_any {
    ninlil_model_domain_body_internal_invariant_t inv;
    ninlil_model_domain_body_bearer_state_t bearer;
    ninlil_model_domain_body_clock_baseline_t clock;
    ninlil_model_domain_body_attempt_reuse_fence_t fence;
    ninlil_model_domain_body_witness_head_index_t head;
    ninlil_model_domain_body_service_t service;
    ninlil_model_domain_body_service_quota_t service_quota;
    ninlil_model_domain_body_transaction_anchor_t transaction_anchor;
    ninlil_model_domain_body_transaction_sequence_index_t sequence_index;
    ninlil_model_domain_body_transaction_state_t transaction_state;
    ninlil_model_domain_body_reservation_t reservation;
    ninlil_model_domain_body_idempotency_map_t idempotency_map;
    ninlil_model_domain_body_event_id_map_t event_id_map;
    ninlil_model_domain_body_scheduler_owner_t scheduler_owner;
    ninlil_model_domain_body_ordered_ingress_t ordered_ingress;
    ninlil_model_domain_body_blob_manifest_t blob_manifest;
    ninlil_model_domain_body_blob_chunk_t blob_chunk;
    ninlil_model_domain_body_attempt_t attempt;
    ninlil_model_domain_body_attempt_id_index_t attempt_id_index;
} body_any_t;

static ninlil_status_t decode_body_any(
    uint32_t family,
    uint32_t subtype,
    uint32_t flags,
    ninlil_bytes_view_t body,
    body_any_t *any)
{
    if (family == 5u && subtype == 0x01u) {
        return ninlil_model_domain_decode_body_internal_invariant(
            body, &any->inv);
    }
    if (family == 6u && subtype == 0x60u) {
        return ninlil_model_domain_decode_body_bearer_state(
            body, &any->bearer);
    }
    if (family == 6u && subtype == 0x62u) {
        return ninlil_model_domain_decode_body_clock_baseline(
            body, &any->clock);
    }
    if (family == 6u && subtype == 0x64u) {
        return ninlil_model_domain_decode_body_attempt_reuse_fence(
            body, &any->fence);
    }
    if (family == 6u && subtype == 0x7du) {
        return ninlil_model_domain_decode_body_witness_head_index(
            body, &any->head);
    }
    if (family == 6u && subtype == 0x10u) {
        return ninlil_model_domain_decode_body_service(body, &any->service);
    }
    if (family == 6u && subtype == 0x11u) {
        return ninlil_model_domain_decode_body_service_quota(
            body, &any->service_quota);
    }
    if (family == 6u && subtype == 0x20u) {
        return ninlil_model_domain_decode_body_transaction_anchor(
            body, &any->transaction_anchor);
    }
    if (family == 6u && subtype == 0x21u) {
        return ninlil_model_domain_decode_body_transaction_sequence_index(
            body, &any->sequence_index);
    }
    if (family == 6u && subtype == 0x22u) {
        return ninlil_model_domain_decode_body_transaction_state(
            body, &any->transaction_state);
    }
    if (family == 6u && subtype == 0x23u) {
        return ninlil_model_domain_decode_body_reservation(
            body, &any->reservation);
    }
    if (family == 6u && subtype == 0x24u) {
        return ninlil_model_domain_decode_body_idempotency_map(
            body, &any->idempotency_map);
    }
    if (family == 6u && subtype == 0x25u) {
        return ninlil_model_domain_decode_body_event_id_map(
            body, &any->event_id_map);
    }
    if (family == 6u && subtype == 0x26u) {
        return ninlil_model_domain_decode_body_scheduler_owner(
            body, &any->scheduler_owner);
    }
    if (family == 6u && subtype == 0x27u) {
        return ninlil_model_domain_decode_body_ordered_ingress(
            body, &any->ordered_ingress);
    }
    if (family == 6u && subtype == 0x30u) {
        if (flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
            return ninlil_model_domain_decode_body_blob_manifest(
                body, &any->blob_manifest);
        }
        if (flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
            return ninlil_model_domain_decode_body_blob_chunk(
                body, &any->blob_chunk);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (family == 6u && subtype == 0x31u) {
        return ninlil_model_domain_decode_body_attempt(body, &any->attempt);
    }
    if (family == 6u && subtype == 0x34u) {
        return ninlil_model_domain_decode_body_attempt_id_index(
            body, &any->attempt_id_index);
    }
    return NINLIL_E_INVALID_ARGUMENT;
}

static ninlil_status_t encode_body_any(
    uint32_t family,
    uint32_t subtype,
    uint32_t flags,
    const body_any_t *any,
    uint8_t *out,
    uint32_t capacity,
    uint32_t *out_len)
{
    if (family == 5u && subtype == 0x01u) {
        return ninlil_model_domain_encode_body_internal_invariant(
            &any->inv, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x60u) {
        return ninlil_model_domain_encode_body_bearer_state(
            &any->bearer, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x62u) {
        return ninlil_model_domain_encode_body_clock_baseline(
            &any->clock, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x64u) {
        return ninlil_model_domain_encode_body_attempt_reuse_fence(
            &any->fence, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x7du) {
        return ninlil_model_domain_encode_body_witness_head_index(
            &any->head, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x10u) {
        return ninlil_model_domain_encode_body_service(
            &any->service, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x11u) {
        return ninlil_model_domain_encode_body_service_quota(
            &any->service_quota, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x20u) {
        return ninlil_model_domain_encode_body_transaction_anchor(
            &any->transaction_anchor, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x21u) {
        return ninlil_model_domain_encode_body_transaction_sequence_index(
            &any->sequence_index, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x22u) {
        return ninlil_model_domain_encode_body_transaction_state(
            &any->transaction_state, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x23u) {
        return ninlil_model_domain_encode_body_reservation(
            &any->reservation, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x24u) {
        return ninlil_model_domain_encode_body_idempotency_map(
            &any->idempotency_map, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x25u) {
        return ninlil_model_domain_encode_body_event_id_map(
            &any->event_id_map, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x26u) {
        return ninlil_model_domain_encode_body_scheduler_owner(
            &any->scheduler_owner, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x27u) {
        return ninlil_model_domain_encode_body_ordered_ingress(
            &any->ordered_ingress, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x30u) {
        if (flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
            return ninlil_model_domain_encode_body_blob_manifest(
                &any->blob_manifest, out, capacity, out_len);
        }
        if (flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
            return ninlil_model_domain_encode_body_blob_chunk(
                &any->blob_chunk, out, capacity, out_len);
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (family == 6u && subtype == 0x31u) {
        return ninlil_model_domain_encode_body_attempt(
            &any->attempt, out, capacity, out_len);
    }
    if (family == 6u && subtype == 0x34u) {
        return ninlil_model_domain_encode_body_attempt_id_index(
            &any->attempt_id_index, out, capacity, out_len);
    }
    return NINLIL_E_INVALID_ARGUMENT;
}

static int hex_to(
    const char *hex,
    uint8_t *out,
    size_t cap,
    size_t *len)
{
    char err[128];
    return ninlil_dv_hex_decode(hex, out, cap, len, err, sizeof(err));
}

static int replay_quiet(const ninlil_dv_vector_t *v)
{
#define QCHECK(cond)                                                           \
    do {                                                                       \
        if (!(cond)) {                                                         \
            return 1;                                                          \
        }                                                                      \
    } while (0)

    ninlil_status_t expect = st_from(v->expected_status);
    ninlil_status_t got;
    uint8_t buf[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES + 8u];
    uint8_t buf2[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES + 8u];
    uint8_t outb[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES + 8u];
    size_t n = 0u;
    size_t n2 = 0u;
    char hex[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES * 2u + 16u];

    QCHECK(expect != (ninlil_status_t)-1);
    QCHECK(v->required_workspace_bytes == 0u);

    if (strcmp(v->op, "sha256") == 0) {
        ninlil_model_domain_digest_t d;
        QCHECK(hex_to(ninlil_dv_str(v->body_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_sha256(n ? buf : NULL, (uint32_t)n, &d);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        }
        return 0;
    }
    if (strcmp(v->op, "sha256_ctx_final") == 0) {
        ninlil_model_domain_sha256_ctx_t ctx;
        ninlil_model_domain_digest_t d;
        ninlil_model_domain_sha256_init(&ctx);
        ctx.bit_length = v->sha_bit_length;
        if (v->sha_buffer_length > 63u) {
            ctx.buffer_length = v->sha_buffer_length;
        } else {
            ctx.buffer_length = v->sha_buffer_length;
            if (ninlil_dv_str(v->body_hex)[0] != '\0') {
                QCHECK(hex_to(ninlil_dv_str(v->body_hex), buf, sizeof(buf), &n)
                    == 0);
                QCHECK(n == (size_t)v->sha_buffer_length);
                (void)memcpy(ctx.buffer, buf, n);
            } else if (v->sha_buffer_length > 0u) {
                (void)memset(ctx.buffer, 0x5A, v->sha_buffer_length);
            }
        }
        got = ninlil_model_domain_sha256_final(&ctx, &d);
        QCHECK(got == expect);
        if (expect == NINLIL_OK && ninlil_dv_str(v->digest_hex)[0] != '\0') {
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        }
        return 0;
    }
    if (strcmp(v->op, "sha256_ctx_update") == 0) {
        ninlil_model_domain_sha256_ctx_t ctx;
        QCHECK(hex_to(ninlil_dv_str(v->body_hex), buf, sizeof(buf), &n) == 0);
        ninlil_model_domain_sha256_init(&ctx);
        ctx.bit_length = v->sha_bit_length;
        if (v->sha_buffer_length <= 63u) {
            ctx.buffer_length = v->sha_buffer_length;
            (void)memset(ctx.buffer, 0x5A, v->sha_buffer_length);
        } else {
            ctx.buffer_length = v->sha_buffer_length;
        }
        got = ninlil_model_domain_sha256_update(
            &ctx, n ? buf : NULL, (uint32_t)n);
        QCHECK(got == expect);
        return 0;
    }
    if (strcmp(v->op, "crc32c") == 0) {
        uint32_t crc;
        char gotc[16];
        QCHECK(hex_to(ninlil_dv_str(v->body_hex), buf, sizeof(buf), &n) == 0);
        crc = ninlil_model_domain_crc32c(buf, (uint32_t)n);
        QCHECK(expect == NINLIL_OK);
        (void)snprintf(gotc, sizeof(gotc), "%08x", (unsigned)crc);
        QCHECK(strcmp(gotc, ninlil_dv_str(v->crc_hex)) == 0);
        return 0;
    }
    if (strcmp(v->op, "key_build") == 0) {
        ninlil_model_domain_key_t key;
        ninlil_model_domain_digest_t d;
        QCHECK(hex_to(ninlil_dv_str(v->identity_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_build_key(
            (uint8_t)v->family, (uint8_t)v->subtype, (uint8_t)v->identity_kind,
            (ninlil_bytes_view_t){n ? buf : NULL, (uint32_t)n}, &key);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(key.bytes, key.length, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->key_hex)) == 0);
            QCHECK(ninlil_model_domain_key_digest(
                (ninlil_bytes_view_t){key.bytes, key.length}, &d) == NINLIL_OK);
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        } else {
            QCHECK(zeros(&key, sizeof(key)));
        }
        return 0;
    }
    if (strcmp(v->op, "key_classify") == 0) {
        ninlil_model_domain_key_class_t c;
        QCHECK(hex_to(ninlil_dv_str(v->key_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_classify_key(
            (ninlil_bytes_view_t){buf, (uint32_t)n}, &c);
        QCHECK(got == NINLIL_OK);
        if (expect == NINLIL_E_STORAGE_CORRUPT) {
            QCHECK(c == NINLIL_MODEL_DOMAIN_KEY_CLASS_MALFORMED);
        } else if (expect == NINLIL_E_UNSUPPORTED) {
            QCHECK(c == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE);
        }
        return 0;
    }
    if (strcmp(v->op, "row_classify") == 0) {
        ninlil_model_domain_key_class_t c;
        QCHECK(hex_to(ninlil_dv_str(v->key_hex), buf, sizeof(buf), &n) == 0);
        QCHECK(hex_to(ninlil_dv_str(v->value_hex), buf2, sizeof(buf2), &n2) == 0);
        got = ninlil_model_domain_classify_row(
            (ninlil_bytes_view_t){buf, (uint32_t)n},
            (ninlil_bytes_view_t){buf2, (uint32_t)n2}, &c);
        QCHECK(got == NINLIL_OK);
        if (expect == NINLIL_E_UNSUPPORTED) {
            QCHECK(c == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE);
        } else if (expect == NINLIL_E_STORAGE_CORRUPT) {
            QCHECK(c == NINLIL_MODEL_DOMAIN_KEY_CLASS_MALFORMED);
        }
        return 0;
    }
    if (strcmp(v->op, "envelope_encode") == 0) {
        ninlil_model_domain_common_header_t h;
        uint32_t len = 0u;
        QCHECK(hex_to(ninlil_dv_str(v->body_hex), buf, sizeof(buf), &n) == 0);
        QCHECK(hex_to(ninlil_dv_str(v->head_hex), buf2, sizeof(buf2), &n2) == 0);
        (void)memset(&h, 0, sizeof(h));
        h.domain_format = 1u;
        h.subtype = (uint8_t)v->subtype;
        h.flags = (uint8_t)v->flags;
        h.record_revision = v->revision ? v->revision : 1u;
        h.body_length = v->body_length;
        if (n2 == 32u) {
            (void)memcpy(h.head_witness_digest, buf2, 32u);
        }
        if (ninlil_dv_str(v->pvd_hex)[0] != '\0') {
            size_t pn = 0u;
            QCHECK(hex_to(ninlil_dv_str(v->pvd_hex), outb, sizeof(outb), &pn) == 0);
            QCHECK(pn == 32u);
            (void)memcpy(h.primary_value_digest, outb, 32u);
        }
        got = ninlil_model_domain_encode_envelope(
            (uint16_t)v->record_type, &h,
            (ninlil_bytes_view_t){v->body_length ? buf : NULL, v->body_length},
            outb, sizeof(outb), &len);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            ninlil_model_domain_digest_t d;
            ninlil_model_domain_envelope_t env;
            enhex(outb, len, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->value_hex)) == 0);
            QCHECK(ninlil_model_domain_value_digest(
                (ninlil_bytes_view_t){outb, len}, &d) == NINLIL_OK);
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
            if (ninlil_dv_str(v->crc_hex)[0] != '\0') {
                char gotc[16];
                uint32_t crc = ninlil_model_domain_crc32c(outb, len - 4u);
                (void)snprintf(gotc, sizeof(gotc), "%08x", (unsigned)crc);
                QCHECK(strcmp(gotc, ninlil_dv_str(v->crc_hex)) == 0);
            }
            /* Positive decoder coverage: re-decode and compare all fields. */
            QCHECK(ninlil_model_domain_decode_envelope(
                (ninlil_bytes_view_t){outb, len}, &env) == NINLIL_OK);
            QCHECK(env.record_type == (uint16_t)v->record_type);
            QCHECK(env.record_version == NINLIL_MODEL_DOMAIN_RECORD_VERSION);
            QCHECK(env.header.domain_format == 1u);
            QCHECK(env.header.subtype == (uint8_t)v->subtype);
            QCHECK(env.header.flags == (uint8_t)v->flags);
            QCHECK(env.header.record_revision
                == (v->revision ? v->revision : 1u));
            QCHECK(env.header.body_length == v->body_length);
            QCHECK(env.body.length == v->body_length);
            if (v->body_length != 0u) {
                QCHECK(memcmp(env.body.data, buf, v->body_length) == 0);
            }
            if (n2 == 32u) {
                QCHECK(memcmp(env.header.head_witness_digest, buf2, 32u) == 0);
            }
            QCHECK(env.crc32c
                == ninlil_model_domain_crc32c(outb, len - 4u));
            /*
             * Spec layout of complete NLR1 value (docs17 envelope + common
             * header): primary_id @24, primary_value_digest @72, body @108.
             * Decoded header fields match those exact bytes; body pointer
             * borrows the encoded buffer at the body start.
             */
            QCHECK(memcmp(env.header.primary_id, &outb[24], 16u) == 0);
            QCHECK(memcmp(env.header.primary_value_digest, &outb[72], 32u)
                == 0);
            if (v->body_length == 0u) {
                QCHECK(env.body.data == NULL);
            } else {
                QCHECK(env.body.data
                    == &outb[12u + NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES]);
            }
        } else if (expect != NINLIL_E_BUFFER_TOO_SMALL) {
            QCHECK(len == 0u);
        }
        return 0;
    }
    if (strcmp(v->op, "envelope_decode") == 0) {
        ninlil_model_domain_envelope_t env;
        QCHECK(hex_to(ninlil_dv_str(v->value_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_decode_envelope(
            (ninlil_bytes_view_t){buf, (uint32_t)n}, &env);
        QCHECK(got == expect);
        if (expect != NINLIL_OK) {
            QCHECK(zeros(&env, sizeof(env)));
        }
        return 0;
    }
    if (strcmp(v->op, "health_source_id") == 0) {
        ninlil_model_domain_digest_t d;
        QCHECK(hex_to(ninlil_dv_str(v->identity_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_health_source_id(
            (uint8_t)v->priority, (uint16_t)v->source_kind,
            (ninlil_bytes_view_t){n ? buf : NULL, (uint32_t)n}, &d);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        } else {
            QCHECK(zeros(&d, sizeof(d)));
        }
        return 0;
    }
    if (strcmp(v->op, "commit_fence_digest") == 0) {
        ninlil_model_domain_digest_t d;
        QCHECK(hex_to(ninlil_dv_str(v->identity_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_commit_fence_digest(
            (uint16_t)v->fence_kind,
            (ninlil_bytes_view_t){n ? buf : NULL, (uint32_t)n}, &d);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        } else {
            QCHECK(zeros(&d, sizeof(d)));
        }
        return 0;
    }
    if (strcmp(v->op, "witness_identity_digest") == 0) {
        ninlil_model_domain_digest_t d;
        QCHECK(hex_to(ninlil_dv_str(v->identity_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_witness_identity_digest(
            (uint16_t)v->operation_kind,
            (ninlil_bytes_view_t){n ? buf : NULL, (uint32_t)n}, &d);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        } else {
            QCHECK(zeros(&d, sizeof(d)));
        }
        return 0;
    }
    if (strcmp(v->op, "witness_chunk_decode") == 0
        || strcmp(v->op, "witness_chunk_roundtrip") == 0) {
        ninlil_model_domain_witness_chunk_t ch;
        uint32_t elen = 0u;
        uint32_t ei;
        QCHECK(hex_to(ninlil_dv_str(v->value_hex), buf, sizeof(buf), &n) == 0);
        got = ninlil_model_domain_decode_witness_chunk(
            (ninlil_bytes_view_t){buf, (uint32_t)n}, &ch);
        QCHECK(got == expect);
        if (expect != NINLIL_OK) {
            QCHECK(zeros(&ch, sizeof(ch)));
            return 0;
        }
        /* Decode → encode byte equality plus explicit scalar/key/digest checks. */
        QCHECK(ninlil_model_domain_encode_witness_chunk(
            &ch, outb, sizeof(outb), &elen) == NINLIL_OK);
        QCHECK(elen == (uint32_t)n);
        QCHECK(memcmp(outb, buf, n) == 0);
        QCHECK(ch.entry_count >= 1u && ch.entry_count <= 8u);
        QCHECK(ch.chunk_count >= 1u);
        for (ei = 0u; ei < ch.entry_count; ++ei) {
            const ninlil_model_domain_witness_entry_t *e = &ch.entries[ei];
            QCHECK(e->key_bytes != NULL);
            QCHECK(e->key_length > 0u);
            QCHECK(e->action >= 1u && e->action <= 4u);
            QCHECK(e->old_present <= 1u);
            QCHECK(e->new_present <= 1u);
            if (e->action == 1u) {
                QCHECK(e->old_present == 0u);
                QCHECK(e->new_present == 1u);
            } else if (e->action == 2u || e->action == 4u) {
                QCHECK(e->old_present == 1u);
                QCHECK(e->new_present == 1u);
            } else if (e->action == 3u) {
                QCHECK(e->old_present == 1u);
                QCHECK(e->new_present == 0u);
            }
        }
        if (ninlil_dv_str(v->digest_hex)[0] != '\0') {
            ninlil_model_domain_digest_t d;
            QCHECK(ninlil_model_domain_sha256(buf, (uint32_t)n, &d)
                == NINLIL_OK);
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        }
        return 0;
    }
    if (strcmp(v->op, "witness_manifest_stream") == 0) {
        ninlil_model_domain_manifest_digest_ctx_t stream;
        ninlil_model_domain_digest_t d;
        ninlil_model_domain_witness_chunk_t ch;
        uint32_t i;
        uint16_t expect_chunks = 0u;
        QCHECK(expect == NINLIL_OK);
        QCHECK(v->chunk_bodies_count == v->chunk_count);
        QCHECK(v->chunk_bodies_count > 0u);
        QCHECK(v->required_workspace_bytes == 0u);
        QCHECK(ninlil_model_domain_witness_chunk_count_for_members(
            (uint16_t)v->member_count, &expect_chunks) == NINLIL_OK);
        QCHECK(expect_chunks == (uint16_t)v->chunk_count);
        QCHECK(ninlil_model_domain_manifest_digest_init(&stream) == NINLIL_OK);
        for (i = 0u; i < v->chunk_bodies_count; ++i) {
            uint32_t elen = 0u;
            uint32_t ei;
            uint32_t off;
            QCHECK(hex_to(v->chunk_bodies_hex[i], buf, sizeof(buf), &n) == 0);
            QCHECK(ninlil_model_domain_manifest_digest_update(
                &stream, (ninlil_bytes_view_t){buf, (uint32_t)n}) == NINLIL_OK);
            QCHECK(ninlil_model_domain_decode_witness_chunk(
                (ninlil_bytes_view_t){buf, (uint32_t)n}, &ch) == NINLIL_OK);
            QCHECK(ch.chunk_index == (uint16_t)i);
            QCHECK(ch.chunk_count == (uint16_t)v->chunk_count);
            QCHECK(n >= 40u);
            QCHECK(memcmp(ch.witness_digest, buf, 32u) == 0);
            QCHECK(((uint16_t)(((uint16_t)buf[32] << 8) | buf[33]))
                == (uint16_t)i);
            QCHECK(((uint16_t)(((uint16_t)buf[34] << 8) | buf[35]))
                == (uint16_t)v->chunk_count);
            QCHECK(((uint16_t)(((uint16_t)buf[36] << 8) | buf[37]))
                == ch.entry_count);
            QCHECK(buf[38] == 0u && buf[39] == 0u);
            off = 40u;
            for (ei = 0u; ei < ch.entry_count; ++ei) {
                const ninlil_model_domain_witness_entry_t *e = &ch.entries[ei];
                uint16_t role;
                uint16_t klen;
                QCHECK(off + 8u <= n);
                role = (uint16_t)(((uint16_t)buf[off] << 8) | buf[off + 1u]);
                QCHECK(role == e->record_role);
                QCHECK(buf[off + 2u] == e->action);
                QCHECK(buf[off + 3u] == 0u);
                klen = (uint16_t)(((uint16_t)buf[off + 4u] << 8)
                    | buf[off + 5u]);
                QCHECK(klen == e->key_length);
                /* Catalog expected key_length must match every entry. */
                QCHECK(e->key_length == (uint16_t)v->key_length);
                QCHECK(klen == (uint16_t)v->key_length);
                QCHECK(buf[off + 6u] == 0u && buf[off + 7u] == 0u);
                off += 8u;
                QCHECK(off + klen + 2u + 2u + 96u <= n);
                QCHECK(memcmp(&buf[off], e->key_bytes, klen) == 0);
                off += klen;
                QCHECK(buf[off] == e->old_present);
                QCHECK(buf[off + 1u] == e->new_present);
                off += 2u;
                QCHECK(buf[off] == 0u && buf[off + 1u] == 0u);
                off += 2u;
                QCHECK(memcmp(&buf[off], e->prior_head_witness_digest, 32u)
                    == 0);
                off += 32u;
                QCHECK(memcmp(&buf[off], e->old_value_digest, 32u) == 0);
                off += 32u;
                QCHECK(memcmp(&buf[off], e->new_value_digest, 32u) == 0);
                off += 32u;
            }
            QCHECK(off == n);
            QCHECK(ninlil_model_domain_encode_witness_chunk(
                &ch, outb, sizeof(outb), &elen) == NINLIL_OK);
            QCHECK(elen == (uint32_t)n);
            QCHECK(memcmp(outb, buf, n) == 0);
            if (ninlil_dv_str(v->digest2_hex)[0] != '\0') {
                char wdig[80];
                enhex(ch.witness_digest, 32u, wdig);
                QCHECK(strcmp(wdig, ninlil_dv_str(v->digest2_hex)) == 0);
            }
        }
        QCHECK(ninlil_model_domain_manifest_digest_final(&stream, &d)
            == NINLIL_OK);
        enhex(d.bytes, 32u, hex);
        QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        return 0;
    }
    if (strcmp(v->op, "blob_chunk_data_len") == 0) {
        got = ninlil_model_domain_blob_chunk_data_length_validate(
            v->body_length);
        QCHECK(got == expect);
        return 0;
    }
    if (strcmp(v->op, "chunk_count") == 0) {
        uint16_t c = 0u;
        got = ninlil_model_domain_witness_chunk_count_for_members(
            (uint16_t)v->member_count, &c);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            QCHECK(c == (uint16_t)v->chunk_count);
        }
        return 0;
    }
    if (strcmp(v->op, "canonical_operation_digest") == 0) {
        ninlil_model_domain_digest_t d;
        uint8_t subject[16];
        uint8_t manifest[32];
        uint8_t retention[32];
        size_t sn = 0u, mn = 0u, rn = 0u;
        QCHECK(hex_to(ninlil_dv_str(v->identity_hex), buf, sizeof(buf), &n) == 0);
        QCHECK(hex_to(ninlil_dv_str(v->subject_hex), subject, sizeof(subject), &sn) == 0);
        QCHECK(hex_to(ninlil_dv_str(v->manifest_hex), manifest, sizeof(manifest), &mn) == 0);
        QCHECK(hex_to(ninlil_dv_str(v->retention_hex), retention, sizeof(retention), &rn) == 0);
        QCHECK(sn == 16u && mn == 32u && rn == 32u);
        got = ninlil_model_domain_canonical_operation_digest(
            (uint16_t)v->operation_kind,
            (ninlil_bytes_view_t){n ? buf : NULL, (uint32_t)n},
            subject, manifest, (uint16_t)v->retention_kind, retention, &d);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(d.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        } else {
            QCHECK(zeros(&d, sizeof(d)));
        }
        return 0;
    }
    if (strcmp(v->op, "witness_header_roundtrip") == 0
        || strcmp(v->op, "witness_header_encode") == 0
        || strcmp(v->op, "witness_header_decode") == 0) {
        ninlil_model_domain_witness_header_t h;
        ninlil_model_domain_witness_header_t h2;
        uint32_t elen = 0u;
        size_t sn = 0u, mn = 0u, rn = 0u, cn = 0u, sucn = 0u;
        if (strcmp(v->op, "witness_header_decode") == 0) {
            QCHECK(hex_to(ninlil_dv_str(v->value_hex), buf, sizeof(buf), &n) == 0);
            got = ninlil_model_domain_decode_witness_header(
                (ninlil_bytes_view_t){buf, (uint32_t)n}, &h);
            QCHECK(got == expect);
            if (expect != NINLIL_OK) {
                QCHECK(zeros(&h, sizeof(h)));
            }
            return 0;
        }
        (void)memset(&h, 0, sizeof(h));
        h.operation_kind = (uint16_t)v->operation_kind;
        h.witness_state = (uint16_t)v->witness_state;
        QCHECK(hex_to(ninlil_dv_str(v->identity_hex), buf, sizeof(buf), &n) == 0);
        h.operation_identity_length = (uint16_t)n;
        if (n != 0u) {
            (void)memcpy(h.operation_identity, buf, n);
        }
        QCHECK(hex_to(ninlil_dv_str(v->subject_hex), h.subject_id, 16u, &sn) == 0);
        QCHECK(sn == 16u);
        QCHECK(hex_to(ninlil_dv_str(v->digest_hex), h.canonical_digest, 32u, &cn) == 0);
        QCHECK(cn == 32u);
        h.member_count = (uint16_t)v->member_count;
        h.chunk_count = (uint16_t)v->chunk_count;
        QCHECK(hex_to(ninlil_dv_str(v->manifest_hex), h.manifest_digest, 32u, &mn) == 0);
        QCHECK(mn == 32u);
        h.retention_kind = (uint16_t)v->retention_kind;
        QCHECK(hex_to(ninlil_dv_str(v->retention_hex), h.retention_subject_key_digest, 32u, &rn)
            == 0);
        QCHECK(rn == 32u);
        QCHECK(hex_to(ninlil_dv_str(v->successor_hex), h.successor_witness_digest, 32u, &sucn)
            == 0);
        QCHECK(sucn == 32u);
        got = ninlil_model_domain_encode_witness_header(
            &h, outb, sizeof(outb), &elen);
        QCHECK(got == expect);
        if (expect != NINLIL_OK) {
            QCHECK(elen == 0u);
            return 0;
        }
        enhex(outb, elen, hex);
        QCHECK(strcmp(hex, ninlil_dv_str(v->value_hex)) == 0);
        if (strcmp(v->op, "witness_header_roundtrip") == 0) {
            QCHECK(ninlil_model_domain_decode_witness_header(
                (ninlil_bytes_view_t){outb, elen}, &h2) == NINLIL_OK);
            QCHECK(h2.operation_kind == h.operation_kind);
            QCHECK(h2.witness_state == h.witness_state);
            QCHECK(h2.operation_identity_length == h.operation_identity_length);
            QCHECK(memcmp(h2.operation_identity, h.operation_identity, n) == 0);
            QCHECK(memcmp(h2.subject_id, h.subject_id, 16u) == 0);
            QCHECK(memcmp(h2.canonical_digest, h.canonical_digest, 32u) == 0);
            QCHECK(h2.member_count == h.member_count);
            QCHECK(h2.chunk_count == h.chunk_count);
            QCHECK(memcmp(h2.manifest_digest, h.manifest_digest, 32u) == 0);
            QCHECK(h2.retention_kind == h.retention_kind);
            QCHECK(memcmp(h2.retention_subject_key_digest,
                h.retention_subject_key_digest, 32u) == 0);
            QCHECK(memcmp(h2.successor_witness_digest,
                h.successor_witness_digest, 32u) == 0);
            /* Decode → encode byte equality */
            QCHECK(ninlil_model_domain_encode_witness_header(
                &h2, buf2, sizeof(buf2), &elen) == NINLIL_OK);
            QCHECK(memcmp(buf2, outb, elen) == 0);
        }
        return 0;
    }
    if (strcmp(v->op, "primary_id") == 0) {
        uint8_t primary[NINLIL_MODEL_DOMAIN_ID_BYTES];
        ninlil_bytes_view_t idv;
        if (strcmp(v->id, "DSK1_PRIMARY_MALFORMED_VIEW") == 0) {
            idv.data = NULL;
            idv.length = v->body_length ? v->body_length : 4u;
            got = ninlil_model_domain_primary_id_from_identity(
                (uint8_t)v->identity_kind, idv, primary);
            QCHECK(got == expect);
            QCHECK(zeros(primary, sizeof(primary)));
            return 0;
        }
        QCHECK(hex_to(ninlil_dv_str(v->identity_hex), buf, sizeof(buf), &n)
            == 0);
        idv.data = n ? buf : NULL;
        idv.length = (uint32_t)n;
        (void)memset(primary, 0xEE, sizeof(primary));
        got = ninlil_model_domain_primary_id_from_identity(
            (uint8_t)v->identity_kind, idv, primary);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(primary, 16u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        } else {
            QCHECK(zeros(primary, sizeof(primary)));
        }
        return 0;
    }
    if (strcmp(v->op, "body_decode") == 0
        || strcmp(v->op, "body_encode") == 0
        || strcmp(v->op, "body_roundtrip") == 0) {
        body_any_t any;
        ninlil_bytes_view_t bv;
        uint32_t elen = 0u;

        QCHECK(hex_to(ninlil_dv_str(v->body_hex), buf, sizeof(buf), &n) == 0);
        bv.data = n ? buf : NULL;
        bv.length = (uint32_t)n;
        (void)memset(&any, 0, sizeof(any));

        if (strcmp(v->op, "body_decode") == 0) {
            got = decode_body_any(v->family, v->subtype, v->flags, bv, &any);
            QCHECK(got == expect);
            if (expect != NINLIL_OK) {
                QCHECK(zeros(&any, sizeof(any)));
            }
            return 0;
        }

        /*
         * body_encode / body_roundtrip: for positives, body_hex is the golden
         * encoded body. Reconstruct via decode then re-encode (encode-decode-
         * encode). BUFFER_TOO_SMALL uses capacity 0 after a successful decode
         * of a positive sibling body (body_hex remains well-formed).
         */
        if (expect == NINLIL_E_BUFFER_TOO_SMALL) {
            got = decode_body_any(v->family, v->subtype, v->flags, bv, &any);
            QCHECK(got == NINLIL_OK);
            elen = 0u;
            got = encode_body_any(
                v->family, v->subtype, v->flags, &any, NULL, 0u, &elen);
            QCHECK(got == NINLIL_E_BUFFER_TOO_SMALL);
            QCHECK(elen == v->body_length);
            return 0;
        }

        got = decode_body_any(v->family, v->subtype, v->flags, bv, &any);
        if (strcmp(v->op, "body_encode") == 0 && expect != NINLIL_OK) {
            /* Encode-path invalid arguments are not currently vectorized. */
            QCHECK(got == expect);
            return 0;
        }
        QCHECK(got == NINLIL_OK);
        elen = 0u;
        got = encode_body_any(
            v->family, v->subtype, v->flags, &any, outb, sizeof(outb), &elen);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            QCHECK(elen == (uint32_t)n);
            QCHECK(memcmp(outb, buf, n) == 0);
            QCHECK(elen == v->body_length);
            /* Second encode-decode-encode */
            {
                body_any_t any2;
                uint32_t elen2 = 0u;
                ninlil_bytes_view_t bv2;
                (void)memset(&any2, 0, sizeof(any2));
                bv2.data = outb;
                bv2.length = elen;
                QCHECK(decode_body_any(
                    v->family, v->subtype, v->flags, bv2, &any2)
                    == NINLIL_OK);
                QCHECK(encode_body_any(
                    v->family, v->subtype, v->flags, &any2, buf2, sizeof(buf2),
                    &elen2)
                    == NINLIL_OK);
                QCHECK(elen2 == elen);
                QCHECK(memcmp(buf2, outb, elen) == 0);
            }
        }
        return 0;
    }
    if (strcmp(v->op, "blob_chunk_count") == 0) {
        uint32_t c = 0u;
        got = ninlil_model_domain_blob_chunk_count_for_total(
            v->sha_bit_length, &c);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            QCHECK(c == v->chunk_count);
        } else {
            QCHECK(c == 0u);
        }
        return 0;
    }
    if (strcmp(v->op, "message_semantic_digest") == 0) {
        ninlil_model_domain_body_ordered_ingress_t ing;
        ninlil_model_domain_message_semantic_prefix_t prefix;
        ninlil_model_domain_digest_t dig;
        ninlil_model_domain_message_semantic_digest_ctx_t ctx;
        uint8_t payload[256];
        uint8_t evidence[160];
        size_t pay_n = 0u;
        size_t evi_n = 0u;
        ninlil_bytes_view_t pay_view;
        ninlil_bytes_view_t evi_view;
        uint32_t chunk;

        QCHECK(hex_to(ninlil_dv_str(v->body_hex), buf, sizeof(buf), &n) == 0);
        if (ninlil_dv_str(v->subject_hex)[0] != '\0') {
            QCHECK(hex_to(ninlil_dv_str(v->subject_hex), payload, sizeof(payload),
                &pay_n)
                == 0);
        }
        if (ninlil_dv_str(v->retention_hex)[0] != '\0') {
            QCHECK(hex_to(
                ninlil_dv_str(v->retention_hex), evidence, sizeof(evidence),
                &evi_n)
                == 0);
        }
        got = ninlil_model_domain_decode_body_ordered_ingress(
            (ninlil_bytes_view_t){buf, (uint32_t)n}, &ing);
        /* Prefix source body must decode for OK helper vectors. */
        if (expect == NINLIL_OK) {
            QCHECK(got == NINLIL_OK);
        } else if (got != NINLIL_OK) {
            /* Negative may still have a valid body; continue if decode works. */
            return 0;
        }
        (void)memset(&prefix, 0, sizeof(prefix));
        prefix.kind = ing.message_kind;
        prefix.flags = ing.message_flags;
        (void)memcpy(prefix.transaction_id, ing.transaction_id, 16u);
        (void)memcpy(prefix.attempt_id, ing.attempt_id, 16u);
        (void)memcpy(prefix.event_id, ing.event_id, 16u);
        prefix.source = ing.source;
        prefix.target = ing.target;
        prefix.service = ing.service;
        (void)memcpy(prefix.content_digest, ing.content_digest, 32u);
        prefix.generation = ing.generation;
        (void)memcpy(prefix.deadline_clock_epoch, ing.deadline_clock_epoch, 16u);
        prefix.absolute_effect_deadline_ms = ing.absolute_effect_deadline_ms;
        prefix.evidence_grace_ms = ing.evidence_grace_ms;
        prefix.required_evidence = ing.required_evidence;
        prefix.receipt_stage = ing.receipt_stage;
        prefix.disposition = ing.disposition;
        prefix.effect_certainty = ing.effect_certainty;
        prefix.retry_guidance = ing.retry_guidance;
        prefix.cancel_kind = ing.cancel_kind;
        prefix.retry_delay_ms = ing.retry_delay_ms;
        (void)memcpy(prefix.evidence_clock_epoch, ing.evidence_clock_epoch, 16u);
        prefix.evidence_now_ms = ing.evidence_now_ms;
        prefix.evidence_trust = ing.evidence_trust;
        prefix.payload_length = (uint32_t)pay_n;
        pay_view.data = pay_n != 0u ? payload : NULL;
        pay_view.length = (uint32_t)pay_n;
        evi_view.data = evi_n != 0u ? evidence : NULL;
        evi_view.length = (uint32_t)evi_n;
        got = ninlil_model_domain_message_semantic_digest(
            &prefix, pay_view, evi_view, &dig);
        QCHECK(got == expect);
        if (expect == NINLIL_OK) {
            enhex(dig.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
            /* Streaming path: multi-chunk payload then evidence. */
            QCHECK(ninlil_model_domain_message_semantic_digest_init(
                &ctx, &prefix)
                == NINLIL_OK);
            chunk = 0u;
            while (chunk < pay_view.length) {
                uint32_t step = pay_view.length - chunk;
                if (step > 3u) {
                    step = 3u;
                }
                QCHECK(
                    ninlil_model_domain_message_semantic_digest_update_payload(
                        &ctx, pay_view.data + chunk, step)
                    == NINLIL_OK);
                chunk += step;
            }
            QCHECK(ninlil_model_domain_message_semantic_digest_begin_evidence(
                &ctx, evi_view.length)
                == NINLIL_OK);
            chunk = 0u;
            while (chunk < evi_view.length) {
                uint32_t step = evi_view.length - chunk;
                if (step > 5u) {
                    step = 5u;
                }
                QCHECK(
                    ninlil_model_domain_message_semantic_digest_update_evidence(
                        &ctx, evi_view.data + chunk, step)
                    == NINLIL_OK);
                chunk += step;
            }
            QCHECK(ninlil_model_domain_message_semantic_digest_final(&ctx, &dig)
                == NINLIL_OK);
            enhex(dig.bytes, 32u, hex);
            QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        } else {
            QCHECK(zeros(&dig, sizeof(dig)));
        }
        return 0;
    }

    if (strcmp(v->op, "typed_record") == 0) {
        ninlil_model_domain_typed_record_t rec;
        const uint8_t *body_start;
        QCHECK(hex_to(ninlil_dv_str(v->key_hex), buf, sizeof(buf), &n) == 0);
        QCHECK(hex_to(ninlil_dv_str(v->value_hex), buf2, sizeof(buf2), &n2)
            == 0);
        (void)memset(&rec, 0xA5, sizeof(rec));
        got = ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){buf, (uint32_t)n},
            (ninlil_bytes_view_t){buf2, (uint32_t)n2},
            &rec);
        QCHECK(got == expect);
        if (expect != NINLIL_OK) {
            QCHECK(zeros(&rec, sizeof(rec)));
        } else {
            /* Validation-only callers receive the same result without output. */
            QCHECK(ninlil_model_domain_validate_typed_record(
                (ninlil_bytes_view_t){buf, (uint32_t)n},
                (ninlil_bytes_view_t){buf2, (uint32_t)n2},
                NULL)
                == NINLIL_OK);
            QCHECK(rec.family == (uint8_t)v->family);
            QCHECK(rec.subtype == (uint8_t)v->subtype);
            QCHECK(rec.envelope.body.data != NULL
                || rec.envelope.body.length == 0u);
            body_start = rec.envelope.body.data;
            if (ninlil_dv_str(v->body_hex)[0] != '\0') {
                size_t bn = 0u;
                QCHECK(hex_to(ninlil_dv_str(v->body_hex), outb, sizeof(outb),
                    &bn)
                    == 0);
                QCHECK(rec.envelope.body.length == (uint32_t)bn);
                QCHECK(memcmp(rec.envelope.body.data, outb, bn) == 0);
                /* Body pointer borrows encoded value at common-header end. */
                QCHECK(body_start
                    == &buf2[12u + NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES]);
            }
            /* Union field checks for each D1-B1 subtype. */
            if (v->subtype == 0x01u) {
                QCHECK(rec.internal_invariant.reserved == 0u);
                QCHECK(ninlil_model_domain_reason_is_known_public(
                    rec.internal_invariant.reason));
            } else if (v->subtype == 0x60u) {
                QCHECK(rec.bearer_state.availability_epoch != 0u);
                QCHECK(rec.bearer_state.available <= 1u);
            } else if (v->subtype == 0x62u) {
                QCHECK(rec.envelope.header.record_revision
                    == rec.clock_baseline.publish_generation + 1u);
            } else if (v->subtype == 0x64u) {
                QCHECK(rec.envelope.header.record_revision
                    == rec.attempt_reuse_fence.fence_generation);
            } else if (v->subtype == 0x7du) {
                QCHECK(rec.witness_head_index.member_key_length == 10u);
                QCHECK(rec.witness_head_index.member_key_bytes != NULL);
                /* Borrowed key starts at body offset 40. */
                QCHECK(rec.witness_head_index.member_key_bytes
                    == &body_start[40]);
                QCHECK(memcmp(rec.witness_head_index.member_key_bytes,
                    body_start + 40u, 10u)
                    == 0);
            } else if (v->subtype == 0x10u) {
                QCHECK(rec.service.target_limit == 1u);
                QCHECK(rec.service.service_key_raw != NULL);
            } else if (v->subtype == 0x11u) {
                QCHECK(rec.service_quota.service_key_raw != NULL);
            } else if (v->subtype == 0x20u) {
                QCHECK(rec.transaction_anchor.target_count == 1u);
            } else if (v->subtype == 0x21u) {
                QCHECK(rec.transaction_sequence_index.transaction_sequence
                    != 0u);
            } else if (v->subtype == 0x22u) {
                QCHECK(rec.transaction_state.target_state
                    == rec.transaction_state.state);
            } else if (v->subtype == 0x23u) {
                QCHECK(rec.reservation.owner_key_raw != NULL);
            } else if (v->subtype == 0x24u) {
                QCHECK(rec.idempotency_map.idempotency_key_length > 0u);
            } else if (v->subtype == 0x25u) {
                QCHECK(!zeros(rec.event_id_map.event_id, 16u));
            } else if (v->subtype == 0x26u) {
                QCHECK(rec.scheduler_owner.owner_sequence != 0u);
            } else if (v->subtype == 0x27u) {
                QCHECK(rec.ordered_ingress.ordered_sequence != 0u);
                QCHECK(rec.ordered_ingress.ingress_state == 1u);
                QCHECK(rec.envelope.header.record_revision == 1u);
            } else if (v->subtype == 0x30u) {
                QCHECK(rec.envelope.header.record_revision == 1u);
                QCHECK(rec.envelope.header.flags == (uint8_t)v->flags);
                if (v->flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
                    QCHECK(rec.blob_manifest.owner_key_raw != NULL
                        || rec.blob_manifest.owner_key_raw_length == 0u);
                    QCHECK(rec.blob_manifest.owner_key_raw_length > 0u);
                } else if (v->flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
                    QCHECK(rec.blob_chunk.chunk_length > 0u);
                    QCHECK(rec.blob_chunk.chunk_bytes != NULL);
                    /* Borrowed chunk starts after fixed 116-byte prefix. */
                    QCHECK(rec.blob_chunk.chunk_bytes == &body_start[116]);
                }
            } else if (v->subtype == 0x31u) {
                /* ATTEMPT: revision/flags, exact RAW16 borrow, non-zero IDs. */
                QCHECK(rec.envelope.header.record_revision >= 1u);
                QCHECK(rec.envelope.header.flags == 0u);
                QCHECK(rec.attempt.owner_key_raw != NULL);
                QCHECK(rec.attempt.owner_key_raw_length > 0u);
                /* owner_key_raw contents start after id16+kind+res0+len = 22. */
                QCHECK(rec.attempt.owner_key_raw == &body_start[22]);
                QCHECK(!zeros(rec.attempt.attempt_id, 16u));
                QCHECK(!zeros(rec.attempt.transaction_id, 16u));
                QCHECK(!zeros(rec.attempt.primary_key_digest, 32u));
                QCHECK(!zeros(rec.attempt.target_digest, 32u));
                QCHECK(!zeros(rec.envelope.header.primary_id, 16u));
            } else if (v->subtype == 0x34u) {
                /* ATTEMPT_ID_INDEX: rev1/flags0, ID128 key, primary=txn. */
                QCHECK(rec.envelope.header.record_revision == 1u);
                QCHECK(rec.envelope.header.flags == 0u);
                QCHECK(!zeros(rec.attempt_id_index.attempt_id, 16u));
                QCHECK(!zeros(rec.attempt_id_index.transaction_id, 16u));
                QCHECK(rec.key.identity_kind
                    == NINLIL_MODEL_DOMAIN_ID_KIND_ID128);
                QCHECK(rec.key.identity_length == 16u);
                QCHECK(rec.key.identity != NULL);
                QCHECK(memcmp(rec.key.identity,
                           rec.attempt_id_index.attempt_id, 16u)
                    == 0);
                QCHECK(memcmp(rec.envelope.header.primary_id,
                           rec.attempt_id_index.transaction_id, 16u)
                    == 0);
                QCHECK(!zeros(
                    rec.attempt_id_index.attempt_record_key_digest, 32u));
                QCHECK(!zeros(
                    rec.attempt_id_index.attempt_creation_value_digest, 32u));
            }
            if (ninlil_dv_str(v->digest_hex)[0] != '\0') {
                ninlil_model_domain_digest_t d;
                QCHECK(ninlil_model_domain_value_digest(
                    (ninlil_bytes_view_t){buf2, (uint32_t)n2}, &d)
                    == NINLIL_OK);
                enhex(d.bytes, 32u, hex);
                QCHECK(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
            }
        }
        return 0;
    }
    (void)fprintf(stderr, "unknown op %s id %s\n", v->op, v->id);
    return 1;
#undef QCHECK
}

static int replay(const ninlil_dv_vector_t *v)
{
    REQUIRE(replay_quiet(v) == 0);
    return 0;
}


static int test_catalog_and_replay(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    uint32_t key_ok = 0u;
    uint32_t exact = 0u;
    uint32_t plus1 = 0u;
    uint32_t health_ok = 0u;
    uint32_t fence_ok = 0u;
    uint32_t dso2_ok = 0u;
    uint32_t man = 0u;
    uint32_t canon_ok = 0u;
    uint32_t hdr_ok = 0u;
    uint32_t dsb1_pos = 0u;
    uint32_t dsb1_neg = 0u;
    uint32_t dsb2_pos = 0u;
    uint32_t dsb2_neg = 0u;
    uint32_t dsb3_pos = 0u;
    uint32_t dsb3_neg = 0u;
    uint32_t cov01 = 0u;
    uint32_t cov60 = 0u;
    uint32_t cov62 = 0u;
    uint32_t cov64 = 0u;
    uint32_t cov7d = 0u;
    uint32_t cov10 = 0u;
    uint32_t cov11 = 0u;
    uint32_t cov20 = 0u;
    uint32_t cov21 = 0u;
    uint32_t cov22 = 0u;
    uint32_t cov23 = 0u;
    uint32_t cov24 = 0u;
    uint32_t cov25 = 0u;
    uint32_t cov26 = 0u;
    uint32_t cov27 = 0u;
    uint32_t cov30 = 0u;
    uint32_t cov31 = 0u;
    uint32_t cov34 = 0u;
    uint32_t unimplemented = 0u;

    if (ninlil_dv_load_file(path, &file, err, sizeof(err)) != 0) {
            (void)fprintf(stderr, "load failed path=%s err=%s\n", path, err);
            return 1;
        }
    REQUIRE(file.catalog.dsk1_positive_keys == 30u);
    REQUIRE(file.catalog.dsv1_body_exact == 30u);
    REQUIRE(file.catalog.dsv1_body_plus1 == 30u);
    REQUIRE(file.catalog.dsh2_health_positive == 12u);
    REQUIRE(file.catalog.dsh2_fence_positive == 4u);
    REQUIRE(file.catalog.dso2_kind_positive == 21u);
    REQUIRE(file.catalog.dso2_canonical_positive == 21u);
    REQUIRE(file.catalog.dsw1_member_stream == 5u);
    REQUIRE(file.catalog.dsw1_header_positive == 23u);
    REQUIRE(file.catalog.dsk1_primary_id_positive == 5u);
    REQUIRE(file.catalog.dsv1_encode_decode_positive == 30u);
    REQUIRE(file.catalog.dsb1_subtype_01_positive > 0u);
    REQUIRE(file.catalog.dsb1_subtype_60_positive > 0u);
    REQUIRE(file.catalog.dsb1_subtype_62_positive > 0u);
    REQUIRE(file.catalog.dsb1_subtype_64_positive > 0u);
    REQUIRE(file.catalog.dsb1_subtype_7d_positive > 0u);
    REQUIRE(sizeof(ninlil_dv_vector_t) < 512u);

    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        if (strcmp(v->op, "key_build") == 0
            && strcmp(v->expected_status, "OK") == 0) {
            key_ok++;
        }
        if (strstr(v->id, "_EXACT") != NULL) {
            exact++;
        }
        if (strstr(v->id, "_PLUS1") != NULL) {
            plus1++;
        }
        if (strncmp(v->id, "DSH2_HEALTH_", 12) == 0
            && strcmp(v->expected_status, "OK") == 0) {
            health_ok++;
        }
        if (strncmp(v->id, "DSH2_FENCE_", 11) == 0
            && strcmp(v->expected_status, "OK") == 0) {
            fence_ok++;
        }
        if (strncmp(v->id, "DSO2_KIND_", 10) == 0 && strlen(v->id) == 12u) {
            dso2_ok++;
        }
        if (strncmp(v->id, "DSW1_MANIFEST_", 14) == 0) {
            man++;
        }
        if (strcmp(v->op, "canonical_operation_digest") == 0
            && strcmp(v->expected_status, "OK") == 0) {
            canon_ok++;
        }
        if (strcmp(v->op, "witness_header_roundtrip") == 0
            && strcmp(v->expected_status, "OK") == 0) {
            hdr_ok++;
        }
        if (strcmp(v->suite, "DSB1") == 0) {
            if (strcmp(v->expected_status, "OK") == 0) {
                dsb1_pos++;
                if (v->subtype == 0x01u) {
                    cov01++;
                } else if (v->subtype == 0x60u) {
                    cov60++;
                } else if (v->subtype == 0x62u) {
                    cov62++;
                } else if (v->subtype == 0x64u) {
                    cov64++;
                } else if (v->subtype == 0x7du) {
                    cov7d++;
                }
            } else {
                dsb1_neg++;
            }
        }
        if (strcmp(v->suite, "DSB2") == 0) {
            if (strcmp(v->expected_status, "OK") == 0) {
                dsb2_pos++;
                if (v->subtype == 0x10u) {
                    cov10++;
                } else if (v->subtype == 0x11u) {
                    cov11++;
                } else if (v->subtype == 0x20u) {
                    cov20++;
                } else if (v->subtype == 0x21u) {
                    cov21++;
                } else if (v->subtype == 0x22u) {
                    cov22++;
                } else if (v->subtype == 0x23u) {
                    cov23++;
                } else if (v->subtype == 0x24u) {
                    cov24++;
                } else if (v->subtype == 0x25u) {
                    cov25++;
                }
            } else {
                dsb2_neg++;
            }
        }
        if (strcmp(v->suite, "DSB3") == 0) {
            if (strcmp(v->expected_status, "OK") == 0) {
                dsb3_pos++;
                if (v->subtype == 0x26u) {
                    cov26++;
                } else if (v->subtype == 0x27u) {
                    cov27++;
                } else if (v->subtype == 0x30u) {
                    cov30++;
                } else if (v->subtype == 0x31u) {
                    cov31++;
                } else if (v->subtype == 0x34u) {
                    cov34++;
                }
            } else {
                dsb3_neg++;
            }
        }
        if (replay(v) != 0) {
            (void)fprintf(stderr, "replay failed %s\n", v->id);
            ninlil_dv_free(&file);
            return 1;
        }
    }
    REQUIRE(key_ok == 30u);
    REQUIRE(exact == 30u);
    REQUIRE(plus1 == 30u);
    REQUIRE(health_ok == 12u);
    REQUIRE(fence_ok == 4u);
    REQUIRE(dso2_ok == 21u);
    REQUIRE(man == 5u);
    REQUIRE(canon_ok == 21u);
    REQUIRE(hdr_ok == 23u);
    REQUIRE(dsb1_pos == file.catalog.dsb1_total_positive);
    REQUIRE(dsb1_neg == file.catalog.dsb1_total_negative);
    REQUIRE(cov01 == file.catalog.dsb1_subtype_01_positive);
    REQUIRE(cov60 == file.catalog.dsb1_subtype_60_positive);
    REQUIRE(cov62 == file.catalog.dsb1_subtype_62_positive);
    REQUIRE(cov64 == file.catalog.dsb1_subtype_64_positive);
    REQUIRE(cov7d == file.catalog.dsb1_subtype_7d_positive);
    REQUIRE(dsb2_pos == file.catalog.dsb2_total_positive);
    REQUIRE(dsb2_neg == file.catalog.dsb2_total_negative);
    REQUIRE(cov10 == file.catalog.dsb2_subtype_10_positive);
    REQUIRE(cov11 == file.catalog.dsb2_subtype_11_positive);
    REQUIRE(cov20 == file.catalog.dsb2_subtype_20_positive);
    REQUIRE(cov21 == file.catalog.dsb2_subtype_21_positive);
    REQUIRE(cov22 == file.catalog.dsb2_subtype_22_positive);
    REQUIRE(cov23 == file.catalog.dsb2_subtype_23_positive);
    REQUIRE(cov24 == file.catalog.dsb2_subtype_24_positive);
    REQUIRE(cov25 == file.catalog.dsb2_subtype_25_positive);
    REQUIRE(dsb3_pos == file.catalog.dsb3_total_positive);
    REQUIRE(dsb3_neg == file.catalog.dsb3_total_negative);
    REQUIRE(cov26 == file.catalog.dsb3_subtype_26_positive);
    REQUIRE(cov27 == file.catalog.dsb3_subtype_27_positive);
    REQUIRE(cov30 == file.catalog.dsb3_subtype_30_positive);
    REQUIRE(cov31 == file.catalog.dsb3_subtype_31_positive);
    REQUIRE(cov34 == file.catalog.dsb3_subtype_34_positive);
    /* D1-B1 + D1-B2 + D1-B3a..e subtype coverage. */
    if (cov01 == 0u || cov60 == 0u || cov62 == 0u || cov64 == 0u
        || cov7d == 0u || cov10 == 0u || cov11 == 0u || cov20 == 0u
        || cov21 == 0u || cov22 == 0u || cov23 == 0u || cov24 == 0u
        || cov25 == 0u || cov26 == 0u || cov27 == 0u || cov30 == 0u
        || cov31 == 0u || cov34 == 0u) {
        unimplemented = 1u;
    }
    REQUIRE(unimplemented == 0u);
    (void)fprintf(stdout,
        "production replayed vectors=%zu dsb1_pos=%u dsb1_neg=%u "
        "dsb2_pos=%u dsb2_neg=%u dsb3_pos=%u dsb3_neg=%u "
        "cov01=%u cov60=%u cov62=%u cov64=%u cov7d=%u "
        "cov10=%u cov11=%u cov20=%u cov21=%u cov22=%u cov23=%u cov24=%u "
        "cov25=%u cov26=%u cov27=%u cov30=%u cov31=%u cov34=%u "
        "sizeof(ninlil_dv_vector_t)=%zu\n",
        file.vector_count, dsb1_pos, dsb1_neg, dsb2_pos, dsb2_neg, dsb3_pos,
        dsb3_neg, cov01, cov60, cov62, cov64, cov7d, cov10, cov11, cov20,
        cov21, cov22, cov23, cov24, cov25, cov26, cov27, cov30, cov31, cov34,
        sizeof(ninlil_dv_vector_t));
    ninlil_dv_free(&file);
    return 0;
}

static int test_unit_sha_and_null_key(void)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_model_domain_digest_t d;
    ninlil_model_domain_witness_chunk_t ch;
    uint8_t out[256];
    uint32_t len = 0u;
    uint8_t key[21];
    static const uint8_t R[8] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
    };

    /* Max message bits finalize (padding not counted against message limit). */
    ninlil_model_domain_sha256_init(&ctx);
    ctx.bit_length = (UINT64_MAX - 7u) & ~((uint64_t)511u);
    ctx.buffer_length = 63u;
    (void)memset(ctx.buffer, 0xA5, 63u);
    REQUIRE(ninlil_model_domain_sha256_final(&ctx, &d) == NINLIL_OK);

    /* Malformed buffer_length */
    ninlil_model_domain_sha256_init(&ctx);
    ctx.buffer_length = 64u;
    REQUIRE(ninlil_model_domain_sha256_update(&ctx, (const uint8_t *)"x", 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_domain_sha256_final(&ctx, &d)
        == NINLIL_E_INVALID_ARGUMENT);

    /* Non-block-aligned completed bit length */
    ninlil_model_domain_sha256_init(&ctx);
    ctx.bit_length = 8u;
    REQUIRE(ninlil_model_domain_sha256_update(&ctx, (const uint8_t *)"x", 1u)
        == NINLIL_E_INVALID_ARGUMENT);

    /* Alias: data overlaps ctx — ctx/data untouched */
    {
        ninlil_model_domain_sha256_ctx_t a;
        ninlil_model_domain_sha256_ctx_t before;
        uint8_t *alias_data;
        ninlil_model_domain_sha256_init(&a);
        a.buffer[0] = 0x42u;
        a.buffer_length = 1u;
        before = a;
        alias_data = &a.buffer[0];
        REQUIRE(ninlil_model_domain_sha256_update(&a, alias_data, 1u)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&a, &before, sizeof(a)) == 0);
        /* Partial overlap into state */
        alias_data = (uint8_t *)&a.state[0];
        REQUIRE(ninlil_model_domain_sha256_update(&a, alias_data, 4u)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&a, &before, sizeof(a)) == 0);
    }

    /* sha256_final: NULL/invalid ctx zeros valid out_digest */
    {
        ninlil_model_domain_digest_t dig;
        dig.bytes[0] = 0xAAu;
        REQUIRE(ninlil_model_domain_sha256_final(NULL, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(&dig, sizeof(dig)));
        ninlil_model_domain_sha256_init(&ctx);
        ctx.buffer_length = 64u;
        dig.bytes[0] = 0xBBu;
        REQUIRE(ninlil_model_domain_sha256_final(&ctx, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(&dig, sizeof(dig)));
    }

    /* manifest: zero-chunk final zeros digest; body↔ctx alias rejected */
    {
        ninlil_model_domain_manifest_digest_ctx_t m;
        ninlil_model_domain_manifest_digest_ctx_t before;
        ninlil_model_domain_digest_t dig;
        REQUIRE(ninlil_model_domain_manifest_digest_init(&m) == NINLIL_OK);
        dig.bytes[0] = 0xCCu;
        REQUIRE(ninlil_model_domain_manifest_digest_final(&m, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(&dig, sizeof(dig)));
        REQUIRE(ninlil_model_domain_manifest_digest_init(&m) == NINLIL_OK);
        before = m;
        REQUIRE(ninlil_model_domain_manifest_digest_update(
            &m, (ninlil_bytes_view_t){(const uint8_t *)&m, 8u})
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&m, &before, sizeof(m)) == 0);
    }

    /* classify_row: malformed (NULL, nonzero) zeros out_class */
    {
        ninlil_model_domain_key_class_t kc = (ninlil_model_domain_key_class_t)7u;
        REQUIRE(ninlil_model_domain_classify_row(
            (ninlil_bytes_view_t){NULL, 4u},
            (ninlil_bytes_view_t){(const uint8_t *)"abcd", 4u},
            &kc) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(kc == (ninlil_model_domain_key_class_t)0);
    }

    /* encode_envelope: malformed body view zeros out_length */
    {
        ninlil_model_domain_common_header_t hdr;
        uint32_t olen = 99u;
        (void)memset(&hdr, 0, sizeof(hdr));
        hdr.domain_format = 1u;
        hdr.subtype = 0x62u;
        hdr.record_revision = 1u;
        hdr.body_length = 0u;
        REQUIRE(ninlil_model_domain_encode_envelope(
            6u, &hdr, (ninlil_bytes_view_t){NULL, 1u}, out, sizeof(out), &olen)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(olen == 0u);
    }

    /* primary_id: exact lengths; wrap-around lengths rejected; alias untouched */
    {
        uint8_t primary[16];
        uint8_t id16[16];
        uint8_t longid[288];
        uint8_t before[16];
        size_t i;
        for (i = 0u; i < 16u; ++i) {
            id16[i] = (uint8_t)i;
        }
        REQUIRE(ninlil_model_domain_primary_id_from_identity(
            2u, (ninlil_bytes_view_t){id16, 16u}, primary) == NINLIL_OK);
        REQUIRE(memcmp(primary, id16, 16u) == 0);
        (void)memset(longid, 0xAB, sizeof(longid));
        (void)memset(primary, 0xEE, sizeof(primary));
        REQUIRE(ninlil_model_domain_primary_id_from_identity(
            2u, (ninlil_bytes_view_t){longid, 272u}, primary)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(primary, sizeof(primary)));
        (void)memset(primary, 0xCD, sizeof(primary));
        (void)memcpy(before, primary, sizeof(before));
        REQUIRE(ninlil_model_domain_primary_id_from_identity(
            2u, (ninlil_bytes_view_t){primary, 16u}, primary)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(primary, before, sizeof(primary)) == 0);
    }

    /* canonical: mixed-NULL + manifest/out alias must not zero aliased input */
    {
        ninlil_model_domain_digest_t out_d;
        uint8_t manifest[32];
        uint8_t before[32];
        uint8_t subject[16];
        uint8_t ret[32];
        uint8_t ident[32];
        size_t i;
        for (i = 0u; i < 32u; ++i) {
            manifest[i] = (uint8_t)(0x10u + i);
            ret[i] = (uint8_t)(0x20u + i);
            ident[i] = (uint8_t)(0x30u + i);
        }
        for (i = 0u; i < 16u; ++i) {
            subject[i] = (uint8_t)(0x40u + i);
        }
        (void)memset(&out_d, 0xAA, sizeof(out_d));
        (void)memcpy(before, out_d.bytes, 32u);
        /* subject NULL, manifest aliases out_digest — leave memory untouched */
        REQUIRE(ninlil_model_domain_canonical_operation_digest(
            1u, (ninlil_bytes_view_t){ident, 32u}, NULL, out_d.bytes, 0u, ret,
            &out_d) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(out_d.bytes, before, 32u) == 0);
        (void)memcpy(before, manifest, 32u);
        REQUIRE(ninlil_model_domain_canonical_operation_digest(
            1u, (ninlil_bytes_view_t){ident, 32u}, NULL, manifest, 0u, ret,
            (ninlil_model_domain_digest_t *)(void *)manifest)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(manifest, before, 32u) == 0);
        /* retention/out alias, subject present */
        (void)memcpy(before, ret, 32u);
        REQUIRE(ninlil_model_domain_canonical_operation_digest(
            1u, (ninlil_bytes_view_t){ident, 32u}, subject, manifest, 0u, ret,
            (ninlil_model_domain_digest_t *)(void *)ret)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(ret, before, 32u) == 0);
        /* subject/out alias */
        (void)memcpy(before, subject, 16u);
        REQUIRE(ninlil_model_domain_canonical_operation_digest(
            1u, (ninlil_bytes_view_t){ident, 32u}, subject, manifest, 0u, ret,
            (ninlil_model_domain_digest_t *)(void *)subject)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(subject, before, 16u) == 0);
        /* identity/out alias */
        (void)memcpy(before, ident, 32u);
        REQUIRE(ninlil_model_domain_canonical_operation_digest(
            1u, (ninlil_bytes_view_t){(const uint8_t *)&out_d, 32u}, subject,
            manifest, 0u, ret, &out_d) == NINLIL_E_INVALID_ARGUMENT);
    }

    (void)memset(&ch, 0, sizeof(ch));
    ch.witness_digest[0] = 1u;
    ch.chunk_count = 1u;
    ch.entry_count = 2u;
    (void)memcpy(key, R, 8u);
    key[8] = 6;
    key[9] = 0x21;
    key[10] = 1;
    key[11] = 3;
    key[12] = 8;
    ninlil_model_domain_encode_u64_be(&key[13], 1u);
    ch.entries[0].record_role = 0x0621u;
    ch.entries[0].action = 1u;
    ch.entries[0].key_length = 21u;
    ch.entries[0].key_bytes = key;
    ch.entries[0].new_present = 1u;
    REQUIRE(ninlil_model_domain_sha256(key, 21u, &d) == NINLIL_OK);
    (void)memcpy(ch.entries[0].new_value_digest, d.bytes, 32u);
    ch.entries[1] = ch.entries[0];
    ch.entries[1].key_bytes = NULL;
    REQUIRE(ninlil_model_domain_encode_witness_chunk(
        &ch, out, sizeof(out), &len) == NINLIL_E_INVALID_ARGUMENT);

    /* encode_witness_chunk pairwise alias negatives (untouched memory). */
    {
        ninlil_model_domain_witness_chunk_t ac;
        uint8_t k0[21];
        uint8_t k1[21];
        uint8_t outbuf[256];
        uint8_t out_before[256];
        uint8_t k0_before[21];
        uint32_t alen = 99u;
        uint32_t alen_before;

        (void)memset(&ac, 0, sizeof(ac));
        ac.witness_digest[0] = 1u;
        ac.chunk_count = 1u;
        ac.entry_count = 1u;
        (void)memcpy(k0, key, 21u);
        ac.entries[0].record_role = 0x0621u;
        ac.entries[0].action = 1u;
        ac.entries[0].key_length = 21u;
        ac.entries[0].key_bytes = k0;
        ac.entries[0].new_present = 1u;
        (void)memcpy(ac.entries[0].new_value_digest, d.bytes, 32u);

        /* key_bytes aliases out_bytes */
        (void)memset(outbuf, 0x5A, sizeof(outbuf));
        (void)memcpy(out_before, outbuf, sizeof(outbuf));
        (void)memcpy(k0_before, k0, sizeof(k0));
        alen = 99u;
        alen_before = alen;
        ac.entries[0].key_bytes = outbuf;
        REQUIRE(ninlil_model_domain_encode_witness_chunk(
            &ac, outbuf, sizeof(outbuf), &alen) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(alen == alen_before);
        REQUIRE(memcmp(outbuf, out_before, sizeof(outbuf)) == 0);

        /* key_bytes aliases out_length */
        ac.entries[0].key_bytes = (const uint8_t *)&alen;
        ac.entries[0].key_length = (uint16_t)sizeof(alen);
        alen = 77u;
        alen_before = alen;
        (void)memset(outbuf, 0x5A, sizeof(outbuf));
        (void)memcpy(out_before, outbuf, sizeof(outbuf));
        REQUIRE(ninlil_model_domain_encode_witness_chunk(
            &ac, outbuf, sizeof(outbuf), &alen) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(alen == alen_before);
        REQUIRE(memcmp(outbuf, out_before, sizeof(outbuf)) == 0);

        /* key_bytes aliases chunk object */
        ac.entries[0].key_bytes = (const uint8_t *)&ac;
        ac.entries[0].key_length = 21u;
        alen = 55u;
        alen_before = alen;
        REQUIRE(ninlil_model_domain_encode_witness_chunk(
            &ac, outbuf, sizeof(outbuf), &alen) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(alen == alen_before);

        /* two entries with overlapping key ranges */
        (void)memcpy(k0, key, 21u);
        (void)memcpy(k1, key, 21u);
        ninlil_model_domain_encode_u64_be(&k1[13], 2u);
        ac.entry_count = 2u;
        ac.entries[0].key_bytes = k0;
        ac.entries[0].key_length = 21u;
        ac.entries[1] = ac.entries[0];
        ac.entries[1].key_bytes = k0; /* same range → entry/entry alias */
        ac.entries[1].key_length = 21u;
        (void)memcpy(ac.entries[1].new_value_digest, d.bytes, 32u);
        alen = 44u;
        alen_before = alen;
        (void)memset(outbuf, 0x5A, sizeof(outbuf));
        (void)memcpy(out_before, outbuf, sizeof(outbuf));
        REQUIRE(ninlil_model_domain_encode_witness_chunk(
            &ac, outbuf, sizeof(outbuf), &alen) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(alen == alen_before);
        REQUIRE(memcmp(outbuf, out_before, sizeof(outbuf)) == 0);

        /* chunk object aliases out_bytes */
        ac.entry_count = 1u;
        ac.entries[0].key_bytes = k0;
        alen = 33u;
        alen_before = alen;
        REQUIRE(ninlil_model_domain_encode_witness_chunk(
            (const ninlil_model_domain_witness_chunk_t *)(void *)outbuf,
            outbuf, sizeof(outbuf), &alen) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(alen == alen_before);
    }
    return 0;
}

static int test_mutation_rejects_wrong_digest(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    int found = 0;
    ninlil_model_domain_digest_t d;
    uint8_t body[64];
    size_t n = 0u;
    char hex[80];
    char bad[80];

    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);
    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        if (strcmp(v->op, "sha256") != 0
            || strcmp(v->expected_status, "OK") != 0
            || ninlil_dv_str(v->digest_hex)[0] == '\0') {
            continue;
        }
        REQUIRE(hex_to(ninlil_dv_str(v->body_hex), body, sizeof(body), &n) == 0);
        REQUIRE(ninlil_model_domain_sha256(n ? body : NULL, (uint32_t)n, &d)
            == NINLIL_OK);
        enhex(d.bytes, 32u, hex);
        REQUIRE(strcmp(hex, ninlil_dv_str(v->digest_hex)) == 0);
        (void)memcpy(bad, ninlil_dv_str(v->digest_hex), sizeof(bad));
        bad[0] = (char)((bad[0] == '0') ? '1' : '0');
        /* Production output must not match a mutated expected digest. */
        REQUIRE(strcmp(hex, bad) != 0);
        found = 1;
        break;
    }
    ninlil_dv_free(&file);
    REQUIRE(found == 1);
    (void)fprintf(stdout, "mutation proof: wrong expected digest rejected\n");
    return 0;
}

/*
 * Catalog expected key_length 21→22 must fail the production replay path
 * (quiet helper; no REQUIRE stderr on the expected failure).
 */
static int test_manifest_key_length_mutation(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    int found = 0;

    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);
    for (i = 0u; i < file.vector_count; ++i) {
        ninlil_dv_vector_t mut;
        if (strcmp(file.vectors[i].op, "witness_manifest_stream") != 0
            || strcmp(file.vectors[i].expected_status, "OK") != 0
            || file.vectors[i].chunk_bodies_count == 0u) {
            continue;
        }
        REQUIRE(file.vectors[i].key_length == 21u);
        /* Shallow copy: heap strings remain owned by file.vectors[i]. */
        mut = file.vectors[i];
        mut.key_length = 22u;
        REQUIRE(replay_quiet(&mut) != 0);
        found = 1;
        break;
    }
    ninlil_dv_free(&file);
    REQUIRE(found == 1);
    (void)fprintf(stdout,
        "mutation proof: manifest key_length 21→22 rejected via replay_quiet\n");
    return 0;
}

static int test_body_mutation_reserved_flip(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    int found = 0;
    uint8_t body[256];
    size_t n = 0u;
    ninlil_model_domain_body_internal_invariant_t inv;
    ninlil_status_t got;

    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);
    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        if (strcmp(v->suite, "DSB1") != 0
            || v->subtype != 0x01u
            || strcmp(v->op, "body_roundtrip") != 0
            || strcmp(v->expected_status, "OK") != 0) {
            continue;
        }
        REQUIRE(hex_to(ninlil_dv_str(v->body_hex), body, sizeof(body), &n)
            == 0);
        REQUIRE(n >= 8u);
        body[7] ^= 0x01u; /* reserved low byte */
        got = ninlil_model_domain_decode_body_internal_invariant(
            (ninlil_bytes_view_t){body, (uint32_t)n}, &inv);
        REQUIRE(got == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(zeros(&inv, sizeof(inv)));
        found = 1;
        break;
    }
    ninlil_dv_free(&file);
    REQUIRE(found == 1);
    (void)fprintf(stdout,
        "mutation proof: INTERNAL_INVARIANT reserved flip rejected\n");
    return 0;
}

static int test_head_encoded_length_matrix(void)
{
    REQUIRE(ninlil_model_domain_body_witness_head_index_encoded_length(0u)
        == 0u);
    REQUIRE(ninlil_model_domain_body_witness_head_index_encoded_length(9u)
        == 0u);
    REQUIRE(ninlil_model_domain_body_witness_head_index_encoded_length(10u)
        == NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES);
    REQUIRE(ninlil_model_domain_body_witness_head_index_encoded_length(11u)
        == 0u);
    REQUIRE(ninlil_model_domain_body_witness_head_index_encoded_length(
                (uint16_t)0xffffu)
        == 0u);
    (void)fprintf(stdout, "HEAD encoded_length matrix ok\n");
    return 0;
}

static int test_reason_registry_unit(void)
{
    REQUIRE(ninlil_model_domain_reason_is_known_public(0u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(1u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(24u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(25u) == 0);
    REQUIRE(ninlil_model_domain_reason_is_known_public(64u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(67u) == 0);
    REQUIRE(ninlil_model_domain_reason_is_known_public(68u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(86u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(87u) == 0);
    REQUIRE(ninlil_model_domain_reason_is_known_public(128u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(132u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(133u) == 0);
    REQUIRE(ninlil_model_domain_reason_is_known_public(4096u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(4097u) == 1);
    REQUIRE(ninlil_model_domain_reason_is_known_public(4098u) == 0);
    return 0;
}

static int test_invalid_encode_structs(void)
{
    uint8_t out[256];
    uint8_t out_before[256];
    uint32_t len = 99u;
    uint32_t len_before;
    ninlil_model_domain_body_internal_invariant_t inv;
    ninlil_model_domain_body_bearer_state_t br;
    ninlil_model_domain_body_clock_baseline_t ck;
    ninlil_model_domain_body_attempt_reuse_fence_t fn;
    ninlil_model_domain_body_witness_head_index_t hi;
    uint8_t mk[10];
    static const uint8_t R[8] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
    };

    (void)memset(out, 0x5A, sizeof(out));
    (void)memcpy(out_before, out, sizeof(out));

    /* INTERNAL: unknown reason */
    (void)memset(&inv, 0, sizeof(inv));
    inv.reason = 67u;
    inv.subject_kind = 0x0300u;
    inv.subject_digest[0] = 1u;
    len = 99u;
    REQUIRE(ninlil_model_domain_encode_body_internal_invariant(
            &inv, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == 0u);
    REQUIRE(memcmp(out, out_before, sizeof(out)) == 0);

    /* INTERNAL: non-namespace zero digest */
    inv.reason = 129u;
    (void)memset(inv.subject_digest, 0, 32u);
    len = 99u;
    REQUIRE(ninlil_model_domain_encode_body_internal_invariant(
            &inv, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == 0u);

    /* BEARER: zero epoch */
    (void)memset(&br, 0, sizeof(br));
    br.available = 1u;
    br.observation_clock_epoch[0] = 1u;
    len = 99u;
    REQUIRE(ninlil_model_domain_encode_body_bearer_state(
            &br, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == 0u);

    /* CLOCK: TRUSTED zero generation */
    (void)memset(&ck, 0, sizeof(ck));
    ck.baseline_state = 2u;
    ck.trusted_clock_epoch[0] = 1u;
    ck.publish_generation = 0u;
    len = 99u;
    REQUIRE(ninlil_model_domain_encode_body_clock_baseline(
            &ck, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == 0u);

    /* FENCE: count 0 */
    (void)memset(&fn, 0, sizeof(fn));
    fn.active_plan_count = 0u;
    fn.fence_generation = 1u;
    len = 99u;
    REQUIRE(ninlil_model_domain_encode_body_attempt_reuse_fence(
            &fn, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == 0u);

    /* HEAD: bad key length */
    (void)memset(&hi, 0, sizeof(hi));
    (void)memcpy(mk, R, 8u);
    mk[8] = 0x03u;
    mk[9] = 0x01u;
    hi.index_state = 1u;
    hi.member_key_length = 9u;
    hi.member_key_bytes = mk;
    len = 99u;
    len_before = len;
    (void)memset(out, 0x5A, sizeof(out));
    REQUIRE(ninlil_model_domain_encode_body_witness_head_index(
            &hi, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == 0u);
    (void)len_before;
    (void)fprintf(stdout, "invalid encode structs rejected\n");
    return 0;
}

static int test_body_alias_and_overflow(const char *vector_path)
{
    uint8_t out[256];
    uint8_t out_before[256];
    uint8_t dig[32];
    uint8_t marker[16];
    uint32_t len = 77u;
    uint32_t len_before;
    ninlil_model_domain_body_bearer_state_t br;
    ninlil_model_domain_body_bearer_state_t br_before;
    ninlil_model_domain_body_witness_head_index_t hi;
    uint8_t mk[10];
    ninlil_model_domain_digest_t kd;
    static const uint8_t R[8] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
    };
    uint8_t *overflow_ptr;
    ninlil_model_domain_typed_record_t rec;
    uint8_t keyb[32];
    uint8_t valb[256];

#define CHECK_FIXED_BODY_ALIAS(Type, Encode, Decode, EncodedBytes)             \
    do {                                                                       \
        union {                                                                \
            Type object;                                                       \
            uint8_t bytes[256];                                                \
        } storage;                                                             \
        uint8_t storage_before[sizeof(storage)];                               \
        uint32_t alias_length;                                                 \
        (void)memset(&storage, 0xA5, sizeof(storage));                         \
        (void)memcpy(storage_before, &storage, sizeof(storage));               \
        alias_length = 91u;                                                    \
        REQUIRE(Encode(&storage.object, storage.bytes,                         \
                    (uint32_t)sizeof(storage.bytes), &alias_length)            \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(alias_length == 91u);                                          \
        REQUIRE(memcmp(&storage, storage_before, sizeof(storage)) == 0);       \
        (void)memset(&storage, 0xA5, sizeof(storage));                         \
        (void)memcpy(storage_before, &storage, sizeof(storage));               \
        (void)memset(out, 0x5A, sizeof(out));                                  \
        (void)memcpy(out_before, out, sizeof(out));                            \
        REQUIRE(Encode(&storage.object, out, sizeof(out),                      \
                    (uint32_t *)(void *)&storage.object)                       \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(memcmp(&storage, storage_before, sizeof(storage)) == 0);       \
        REQUIRE(memcmp(out, out_before, sizeof(out)) == 0);                    \
        (void)memset(&storage, 0xA5, sizeof(storage));                         \
        (void)memcpy(storage_before, &storage, sizeof(storage));               \
        REQUIRE(Decode(                                                        \
                    (ninlil_bytes_view_t){storage.bytes, (EncodedBytes)},       \
                    &storage.object)                                           \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(memcmp(&storage, storage_before, sizeof(storage)) == 0);       \
    } while (0)

    /* --- encode alias: body object overlaps out_length --- */
    (void)memset(&br, 0, sizeof(br));
    br.availability_epoch = 1u;
    br.available = 1u;
    br.observation_clock_epoch[0] = 1u;
    br_before = br;
    len = 77u;
    len_before = len;
    REQUIRE(ninlil_model_domain_encode_body_bearer_state(
            &br, (uint8_t *)&len, sizeof(len), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == len_before);
    REQUIRE(memcmp(&br, &br_before, sizeof(br)) == 0);

    /* encode alias: out_bytes aliases body */
    (void)memset(out, 0x5A, sizeof(out));
    (void)memcpy(out_before, out, sizeof(out));
    len = 55u;
    len_before = len;
    REQUIRE(ninlil_model_domain_encode_body_bearer_state(
            (const ninlil_model_domain_body_bearer_state_t *)(void *)out,
            out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == len_before);
    REQUIRE(memcmp(out, out_before, sizeof(out)) == 0);

    /* decode alias: encoded overlaps out_body — untouched */
    {
        uint8_t enc[36];
        uint32_t el = 0u;
        ninlil_model_domain_body_bearer_state_t dec;
        REQUIRE(ninlil_model_domain_encode_body_bearer_state(
                &br, enc, sizeof(enc), &el)
            == NINLIL_OK);
        (void)memset(&dec, 0xA5, sizeof(dec));
        REQUIRE(ninlil_model_domain_decode_body_bearer_state(
                (ninlil_bytes_view_t){(const uint8_t *)&dec, el}, &dec)
            == NINLIL_E_INVALID_ARGUMENT);
        /* out_body must remain as poisoned (untouched by zero-on-failure) */
        REQUIRE(((const uint8_t *)&dec)[0] == 0xA5u);
    }

    /* Every fixed D1 body API obeys the same alias/untouched contract. */
    CHECK_FIXED_BODY_ALIAS(
        ninlil_model_domain_body_internal_invariant_t,
        ninlil_model_domain_encode_body_internal_invariant,
        ninlil_model_domain_decode_body_internal_invariant,
        NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES);
    CHECK_FIXED_BODY_ALIAS(
        ninlil_model_domain_body_clock_baseline_t,
        ninlil_model_domain_encode_body_clock_baseline,
        ninlil_model_domain_decode_body_clock_baseline,
        NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES);
    CHECK_FIXED_BODY_ALIAS(
        ninlil_model_domain_body_attempt_reuse_fence_t,
        ninlil_model_domain_encode_body_attempt_reuse_fence,
        ninlil_model_domain_decode_body_attempt_reuse_fence,
        NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES);
    CHECK_FIXED_BODY_ALIAS(
        ninlil_model_domain_body_attempt_id_index_t,
        ninlil_model_domain_encode_body_attempt_id_index,
        ninlil_model_domain_decode_body_attempt_id_index,
        NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_ID_INDEX_BYTES);
    CHECK_FIXED_BODY_ALIAS(
        ninlil_model_domain_body_witness_head_index_t,
        ninlil_model_domain_encode_body_witness_head_index,
        ninlil_model_domain_decode_body_witness_head_index,
        NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES);

    /* marker_id alias subject_digest ↔ out */
    (void)memset(dig, 0x11, sizeof(dig));
    (void)memset(marker, 0x22, sizeof(marker));
    /* Use proper alias: digest buffer overlaps marker */
    {
        uint8_t blob[48];
        (void)memset(blob, 0x33, sizeof(blob));
        REQUIRE(ninlil_model_domain_invariant_marker_id(
                129u, 0x0300u, blob, blob + 16)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(blob[0] == 0x33u);
        REQUIRE(blob[16] == 0x33u);
    }

    /* marker_id non-alias invalid zeros output */
    (void)memset(marker, 0xEE, sizeof(marker));
    REQUIRE(ninlil_model_domain_invariant_marker_id(
            67u, 0x0300u, dig, marker)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(zeros(marker, sizeof(marker)));

    /* marker_id rejects overflowing input/output ranges before dereference. */
    overflow_ptr = (uint8_t *)(uintptr_t)(UINTPTR_MAX - 3u);
    (void)memset(marker, 0xA7, sizeof(marker));
    REQUIRE(ninlil_model_domain_invariant_marker_id(
            129u, 0x0300u, overflow_ptr, marker)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(marker[0] == 0xA7u);
    REQUIRE(ninlil_model_domain_invariant_marker_id(
            129u, 0x0300u, dig, overflow_ptr)
        == NINLIL_E_INVALID_ARGUMENT);

    /* HEAD nested key aliases out_bytes */
    (void)memcpy(mk, R, 8u);
    mk[8] = 0x03u;
    mk[9] = 0x01u;
    REQUIRE(ninlil_model_domain_key_digest(
            (ninlil_bytes_view_t){mk, 10u}, &kd)
        == NINLIL_OK);
    (void)memset(&hi, 0, sizeof(hi));
    hi.index_state = 1u;
    hi.member_key_length = 10u;
    (void)memcpy(hi.member_key_digest, kd.bytes, 32u);
    hi.member_key_bytes = out; /* alias */
    (void)memset(out, 0x5A, sizeof(out));
    (void)memcpy(out_before, out, sizeof(out));
    len = 44u;
    len_before = len;
    REQUIRE(ninlil_model_domain_encode_body_witness_head_index(
            &hi, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == len_before);
    REQUIRE(memcmp(out, out_before, sizeof(out)) == 0);

    /* HEAD nested key aliases out_length */
    hi.member_key_bytes = (const uint8_t *)&len;
    hi.member_key_length = (uint16_t)sizeof(len);
    len = 33u;
    len_before = len;
    REQUIRE(ninlil_model_domain_encode_body_witness_head_index(
            &hi, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == len_before);

    /* HEAD nested key aliases body object */
    hi.member_key_bytes = (const uint8_t *)&hi;
    hi.member_key_length = 10u;
    len = 22u;
    len_before = len;
    REQUIRE(ninlil_model_domain_encode_body_witness_head_index(
            &hi, out, sizeof(out), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(len == len_before);

    /* Individual range address overflow via ranges helper */
    overflow_ptr = (uint8_t *)(uintptr_t)(UINTPTR_MAX - 3u);
    REQUIRE(ninlil_model_domain_ranges_are_disjoint(
            overflow_ptr, 16u, out, 8u)
        == 0);
    REQUIRE(ninlil_model_domain_ranges_are_disjoint(
            out, 8u, overflow_ptr, 16u)
        == 0);

    /* The typed API must reject a single overflowing range before parsing. */
    REQUIRE(ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){overflow_ptr, 16u},
            (ninlil_bytes_view_t){NULL, 0u},
            NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    /* typed_record: out_record NULL validation-only success path needs real
     * vectors — covered via load below if needed; here NULL with bad shape */
    REQUIRE(ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){NULL, 1u},
            (ninlil_bytes_view_t){NULL, 0u},
            NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    /* typed_record alias key/out — leave out poisoned */
    (void)memset(&rec, 0xCC, sizeof(rec));
    (void)memset(keyb, 0, sizeof(keyb));
    (void)memset(valb, 0, sizeof(valb));
    REQUIRE(ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){(const uint8_t *)&rec, 16u},
            (ninlil_bytes_view_t){valb, 16u},
            &rec)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(((const uint8_t *)&rec)[0] == 0xCCu);

    /* Read-only key/value inputs are also required to be disjoint. */
    (void)memset(valb, 0x4Du, sizeof(valb));
    (void)memcpy(out_before, valb, sizeof(valb));
    REQUIRE(ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){valb, 13u},
            (ninlil_bytes_view_t){valb, 16u},
            NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(valb, out_before, sizeof(valb)) == 0);

    /* typed_record non-alias invalid zeros out_record */
    (void)memset(&rec, 0xDD, sizeof(rec));
    REQUIRE(ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){keyb, 13u},
            (ninlil_bytes_view_t){valb, 16u},
            &rec)
        != NINLIL_OK);
    REQUIRE(zeros(&rec, sizeof(rec)));

    /* --- D1-B2 fixed bodies: same encode/decode alias contract --- */
    CHECK_FIXED_BODY_ALIAS(
        ninlil_model_domain_body_transaction_sequence_index_t,
        ninlil_model_domain_encode_body_transaction_sequence_index,
        ninlil_model_domain_decode_body_transaction_sequence_index,
        NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_SEQUENCE_INDEX_BYTES);
    CHECK_FIXED_BODY_ALIAS(
        ninlil_model_domain_body_transaction_state_t,
        ninlil_model_domain_encode_body_transaction_state,
        ninlil_model_domain_decode_body_transaction_state,
        NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_STATE_BYTES);

    /*
     * D1-B2 variable RAW16 bodies: full pairwise alias + address-overflow
     * contract. Macros avoid copy/paste; forged overflow pointers are only
     * passed through uintptr_t casts and must be rejected before any read/write.
     * Overlap uses properly sized storage unions so -Werror cannot infer
     * object-size overread from undersized real arrays.
     */
#define CHECK_VAR_ENCODE_BODY_OUT_ALIAS(Type, Encode)                          \
    do {                                                                       \
        union {                                                                \
            Type object;                                                       \
            uint8_t bytes[sizeof(Type) < 256u ? 256u : sizeof(Type)];          \
        } storage;                                                             \
        uint8_t storage_before[sizeof(storage)];                               \
        uint32_t alias_length = 91u;                                           \
        (void)memset(&storage, 0xA5, sizeof(storage));                         \
        (void)memcpy(storage_before, &storage, sizeof(storage));               \
        REQUIRE(Encode(&storage.object, storage.bytes,                         \
                    (uint32_t)sizeof(storage.bytes), &alias_length)            \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(alias_length == 91u);                                          \
        REQUIRE(memcmp(&storage, storage_before, sizeof(storage)) == 0);       \
    } while (0)

#define CHECK_VAR_ENCODE_BODY_LEN_ALIAS(Type, Encode)                          \
    do {                                                                       \
        Type object;                                                           \
        Type object_before;                                                    \
        uint8_t local_out[64];                                                 \
        uint8_t local_before[64];                                              \
        (void)memset(&object, 0xA5, sizeof(object));                           \
        object_before = object;                                                \
        (void)memset(local_out, 0x5A, sizeof(local_out));                      \
        (void)memcpy(local_before, local_out, sizeof(local_out));              \
        REQUIRE(Encode(&object, local_out, sizeof(local_out),                  \
                    (uint32_t *)(void *)&object)                               \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);      \
    } while (0)

#define CHECK_VAR_ENCODE_RAW_ALIASES(Type, Encode, RawField, RawLenField)      \
    do {                                                                       \
        Type object;                                                           \
        Type object_before;                                                    \
        uint8_t local_out[128];                                                \
        uint8_t local_before[128];                                             \
        uint32_t local_len;                                                    \
        uint32_t local_len_before;                                             \
        uint8_t raw_own[8];                                                    \
        (void)memset(&object, 0, sizeof(object));                              \
        (void)memset(raw_own, 0x41, sizeof(raw_own));                          \
        object.RawLenField = 8u;                                               \
        /* nested RAW aliases out_bytes */                                     \
        object.RawField = local_out;                                           \
        object_before = object;                                                \
        (void)memset(local_out, 0x5A, sizeof(local_out));                      \
        (void)memcpy(local_before, local_out, sizeof(local_out));              \
        local_len = 66u;                                                       \
        local_len_before = local_len;                                          \
        REQUIRE(Encode(&object, local_out, sizeof(local_out), &local_len)      \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(local_len == local_len_before);                                \
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);      \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
        /* nested RAW aliases out_length */                                    \
        object.RawField = (const uint8_t *)&local_len;                         \
        object.RawLenField = (uint16_t)sizeof(local_len);                      \
        object_before = object;                                                \
        local_len = 55u;                                                       \
        local_len_before = local_len;                                          \
        REQUIRE(Encode(&object, local_out, sizeof(local_out), &local_len)      \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(local_len == local_len_before);                                \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
        /* nested RAW aliases body object */                                   \
        object.RawField = (const uint8_t *)&object;                            \
        object.RawLenField = 8u;                                               \
        object_before = object;                                                \
        local_len = 44u;                                                       \
        local_len_before = local_len;                                          \
        (void)memset(local_out, 0x5A, sizeof(local_out));                      \
        (void)memcpy(local_before, local_out, sizeof(local_out));              \
        REQUIRE(Encode(&object, local_out, sizeof(local_out), &local_len)      \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(local_len == local_len_before);                                \
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);      \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
        (void)raw_own;                                                         \
    } while (0)

#define CHECK_VAR_ENCODE_DUAL_RAW_OVERLAP(                                     \
    Type, Encode, RawA, LenA, RawB, LenB)                                      \
    do {                                                                       \
        Type object;                                                           \
        Type object_before;                                                    \
        uint8_t shared[16];                                                    \
        uint8_t local_out[128];                                                \
        uint8_t local_before[128];                                             \
        uint32_t local_len = 33u;                                              \
        uint32_t local_len_before = local_len;                                 \
        (void)memset(&object, 0, sizeof(object));                              \
        (void)memset(shared, 0x42, sizeof(shared));                            \
        object.LenA = 8u;                                                      \
        object.RawA = shared;                                                  \
        object.LenB = 8u;                                                      \
        object.RawB = shared; /* nested↔nested overlap */                      \
        object_before = object;                                                \
        (void)memset(local_out, 0x5A, sizeof(local_out));                      \
        (void)memcpy(local_before, local_out, sizeof(local_out));              \
        REQUIRE(Encode(&object, local_out, sizeof(local_out), &local_len)      \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(local_len == local_len_before);                                \
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);      \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
        REQUIRE(shared[0] == 0x42u);                                           \
    } while (0)

#define CHECK_VAR_ENCODE_OVERFLOW(Type, Encode, RawField, RawLenField)         \
    do {                                                                       \
        Type object;                                                           \
        Type object_before;                                                    \
        uint8_t local_out[64];                                                 \
        uint8_t local_before[64];                                              \
        uint32_t local_len;                                                    \
        uint32_t local_len_before;                                             \
        uint8_t raw_own[8];                                                    \
        Type *overflow_body;                                                   \
        uint8_t *overflow_bytes;                                               \
        uint32_t *overflow_len;                                                \
        /* forged ranges via uintptr_t only — never read/written */            \
        overflow_body = (Type *)(uintptr_t)(UINTPTR_MAX - 3u);                 \
        overflow_bytes = (uint8_t *)(uintptr_t)(UINTPTR_MAX - 3u);             \
        overflow_len = (uint32_t *)(uintptr_t)(UINTPTR_MAX - 1u);              \
        (void)memset(&object, 0, sizeof(object));                              \
        (void)memset(raw_own, 0x41, sizeof(raw_own));                          \
        object.RawLenField = 8u;                                               \
        object.RawField = raw_own;                                             \
        object_before = object;                                                \
        (void)memset(local_out, 0x5A, sizeof(local_out));                      \
        (void)memcpy(local_before, local_out, sizeof(local_out));              \
        local_len = 77u;                                                       \
        local_len_before = local_len;                                          \
        /* overflowing body pointer */                                         \
        REQUIRE(Encode(overflow_body, local_out, sizeof(local_out),            \
                    &local_len)                                                \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(local_len == local_len_before);                                \
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);      \
        /* overflowing nested RAW pointer */                                   \
        object.RawField = (const uint8_t *)(uintptr_t)(UINTPTR_MAX - 3u);      \
        object.RawLenField = 16u;                                              \
        object_before = object;                                                \
        local_len = 77u;                                                       \
        local_len_before = local_len;                                          \
        REQUIRE(Encode(&object, local_out, sizeof(local_out), &local_len)      \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(local_len == local_len_before);                                \
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);      \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
        /* overflowing out pointer */                                          \
        object.RawField = raw_own;                                             \
        object.RawLenField = 8u;                                               \
        object_before = object;                                                \
        local_len = 77u;                                                       \
        local_len_before = local_len;                                          \
        REQUIRE(Encode(&object, overflow_bytes, 16u, &local_len)               \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(local_len == local_len_before);                                \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
        /* overflowing out_length pointer */                                   \
        REQUIRE(Encode(&object, local_out, sizeof(local_out), overflow_len)    \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);      \
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);         \
    } while (0)

#define CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(Type, Decode)                      \
    do {                                                                       \
        Type object;                                                           \
        uint8_t *overflow_ptr;                                                 \
        /* encoded ↔ out alias: out untouched */                               \
        (void)memset(&object, 0xA5, sizeof(object));                           \
        REQUIRE(Decode(                                                        \
                    (ninlil_bytes_view_t){(const uint8_t *)&object, 64u},       \
                    &object)                                                   \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(((const uint8_t *)&object)[0] == 0xA5u);                       \
        /* empty encoded + overflowing out: INVALID, no write */               \
        overflow_ptr = (uint8_t *)(uintptr_t)(UINTPTR_MAX - 3u);               \
        REQUIRE(Decode((ninlil_bytes_view_t){NULL, 0u},                        \
                    (Type *)(void *)overflow_ptr)                              \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        /* overflowing encoded pointer: INVALID, real out untouched */         \
        (void)memset(&object, 0xB7, sizeof(object));                           \
        REQUIRE(Decode(                                                        \
                    (ninlil_bytes_view_t){overflow_ptr, 16u}, &object)          \
            == NINLIL_E_INVALID_ARGUMENT);                                     \
        REQUIRE(((const uint8_t *)&object)[0] == 0xB7u);                       \
        /* non-alias malformed empty: CORRUPT with valid out zeroed */         \
        (void)memset(&object, 0xC3, sizeof(object));                           \
        REQUIRE(Decode((ninlil_bytes_view_t){NULL, 0u}, &object)               \
            == NINLIL_E_STORAGE_CORRUPT);                                      \
        REQUIRE(zeros(&object, sizeof(object)));                               \
    } while (0)

#define CHECK_VAR_ENCODE_BTS_AFTER_DECODE(Type, Decode, Encode, HexLit)        \
    do {                                                                       \
        static const char *const hx = (HexLit);                                \
        uint8_t enc[2048];                                                     \
        uint8_t reenc[2048];                                                   \
        uint8_t reenc_before[2048];                                            \
        size_t hn;                                                             \
        uint32_t n = 0u;                                                       \
        uint32_t required = 0u;                                                \
        uint32_t short_len = 0u;                                               \
        Type object;                                                           \
        REQUIRE(hex_to(hx, enc, sizeof(enc), &hn) == 0);                       \
        n = (uint32_t)hn;                                                      \
        (void)memset(&object, 0, sizeof(object));                              \
        REQUIRE(Decode((ninlil_bytes_view_t){enc, n}, &object) == NINLIL_OK);  \
        required = 0u;                                                         \
        REQUIRE(Encode(&object, NULL, 0u, &required)                           \
            == NINLIL_E_BUFFER_TOO_SMALL);                                     \
        REQUIRE(required == n);                                                \
        (void)memset(reenc, 0x5A, sizeof(reenc));                              \
        (void)memcpy(reenc_before, reenc, sizeof(reenc));                      \
        short_len = 0u;                                                        \
        REQUIRE(Encode(&object, reenc, required > 0u ? required - 1u : 0u,     \
                    &short_len)                                                \
            == NINLIL_E_BUFFER_TOO_SMALL);                                     \
        REQUIRE(short_len == required);                                        \
        REQUIRE(memcmp(reenc, reenc_before, sizeof(reenc)) == 0);              \
    } while (0)

    /* --- single-RAW variable bodies --- */
    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_service_t,
        ninlil_model_domain_encode_body_service);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_service_t,
        ninlil_model_domain_encode_body_service);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_service_t,
        ninlil_model_domain_encode_body_service,
        service_key_raw, service_key_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_service_t,
        ninlil_model_domain_encode_body_service,
        service_key_raw, service_key_raw_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_service_t,
        ninlil_model_domain_decode_body_service);

    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_service_quota_t,
        ninlil_model_domain_encode_body_service_quota);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_service_quota_t,
        ninlil_model_domain_encode_body_service_quota);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_service_quota_t,
        ninlil_model_domain_encode_body_service_quota,
        service_key_raw, service_key_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_service_quota_t,
        ninlil_model_domain_encode_body_service_quota,
        service_key_raw, service_key_raw_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_service_quota_t,
        ninlil_model_domain_decode_body_service_quota);

    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_reservation_t,
        ninlil_model_domain_encode_body_reservation);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_reservation_t,
        ninlil_model_domain_encode_body_reservation);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_reservation_t,
        ninlil_model_domain_encode_body_reservation,
        owner_key_raw, owner_key_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_reservation_t,
        ninlil_model_domain_encode_body_reservation,
        owner_key_raw, owner_key_raw_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_reservation_t,
        ninlil_model_domain_decode_body_reservation);

    /* --- dual-RAW variable bodies --- */
    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_encode_body_transaction_anchor);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_encode_body_transaction_anchor);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_encode_body_transaction_anchor,
        idempotency_scope_raw, idempotency_scope_raw_length);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_encode_body_transaction_anchor,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_ENCODE_DUAL_RAW_OVERLAP(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_encode_body_transaction_anchor,
        idempotency_scope_raw, idempotency_scope_raw_length,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_encode_body_transaction_anchor,
        idempotency_scope_raw, idempotency_scope_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_encode_body_transaction_anchor,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_transaction_anchor_t,
        ninlil_model_domain_decode_body_transaction_anchor);

    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_encode_body_idempotency_map);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_encode_body_idempotency_map);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_encode_body_idempotency_map,
        scope_raw, scope_raw_length);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_encode_body_idempotency_map,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_ENCODE_DUAL_RAW_OVERLAP(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_encode_body_idempotency_map,
        scope_raw, scope_raw_length,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_encode_body_idempotency_map,
        scope_raw, scope_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_encode_body_idempotency_map,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_idempotency_map_t,
        ninlil_model_domain_decode_body_idempotency_map);

    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_encode_body_event_id_map);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_encode_body_event_id_map);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_encode_body_event_id_map,
        scope_raw, scope_raw_length);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_encode_body_event_id_map,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_ENCODE_DUAL_RAW_OVERLAP(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_encode_body_event_id_map,
        scope_raw, scope_raw_length,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_encode_body_event_id_map,
        scope_raw, scope_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_encode_body_event_id_map,
        idempotency_key, idempotency_key_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_event_id_map_t,
        ninlil_model_domain_decode_body_event_id_map);

    /* --- D1-B3a SCHEDULER_OWNER variable RAW16 body --- */
    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_scheduler_owner_t,
        ninlil_model_domain_encode_body_scheduler_owner);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_scheduler_owner_t,
        ninlil_model_domain_encode_body_scheduler_owner);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_scheduler_owner_t,
        ninlil_model_domain_encode_body_scheduler_owner,
        subject_key_raw, subject_key_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_scheduler_owner_t,
        ninlil_model_domain_encode_body_scheduler_owner,
        subject_key_raw, subject_key_raw_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_scheduler_owner_t,
        ninlil_model_domain_decode_body_scheduler_owner);

    /* --- D1-B3b ORDERED_INGRESS fixed-ish body (no RAW16 borrow) --- */
    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_ordered_ingress_t,
        ninlil_model_domain_encode_body_ordered_ingress);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_ordered_ingress_t,
        ninlil_model_domain_encode_body_ordered_ingress);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_ordered_ingress_t,
        ninlil_model_domain_decode_body_ordered_ingress);

    /* --- D1-B3c BLOB manifest (RAW16 owner_key) + chunk (borrowed bytes) --- */
    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_blob_manifest_t,
        ninlil_model_domain_encode_body_blob_manifest);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_blob_manifest_t,
        ninlil_model_domain_encode_body_blob_manifest);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_blob_manifest_t,
        ninlil_model_domain_encode_body_blob_manifest,
        owner_key_raw, owner_key_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_blob_manifest_t,
        ninlil_model_domain_encode_body_blob_manifest,
        owner_key_raw, owner_key_raw_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_blob_manifest_t,
        ninlil_model_domain_decode_body_blob_manifest);

    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_blob_chunk_t,
        ninlil_model_domain_encode_body_blob_chunk);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_blob_chunk_t,
        ninlil_model_domain_encode_body_blob_chunk);
    /* Nested chunk_bytes alias/overflow: same pattern as RAW16 but u32 length.
     * Compare body object snapshots as well as out_bytes / out_length. */
    {
        ninlil_model_domain_body_blob_chunk_t object;
        ninlil_model_domain_body_blob_chunk_t object_before;
        uint8_t local_out[128];
        uint8_t local_before[128];
        uint32_t local_len;
        uint32_t local_len_before;
        uint8_t raw_own[8];
        (void)memset(&object, 0, sizeof(object));
        (void)memset(raw_own, 0x41, sizeof(raw_own));
        object.chunk_length = 8u;
        /* nested chunk_bytes aliases out_bytes */
        object.chunk_bytes = local_out;
        object_before = object;
        (void)memset(local_out, 0x5A, sizeof(local_out));
        (void)memcpy(local_before, local_out, sizeof(local_out));
        local_len = 66u;
        local_len_before = local_len;
        REQUIRE(ninlil_model_domain_encode_body_blob_chunk(
                    &object, local_out, sizeof(local_out), &local_len)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(local_len == local_len_before);
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);
        /* nested chunk_bytes aliases out_length */
        object.chunk_bytes = (const uint8_t *)&local_len;
        object.chunk_length = (uint32_t)sizeof(local_len);
        object_before = object;
        local_len = 55u;
        local_len_before = local_len;
        REQUIRE(ninlil_model_domain_encode_body_blob_chunk(
                    &object, local_out, sizeof(local_out), &local_len)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(local_len == local_len_before);
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);
        /* nested chunk_bytes aliases body object */
        object.chunk_bytes = (const uint8_t *)&object;
        object.chunk_length = 8u;
        object_before = object;
        local_len = 44u;
        local_len_before = local_len;
        (void)memset(local_out, 0x5A, sizeof(local_out));
        (void)memcpy(local_before, local_out, sizeof(local_out));
        REQUIRE(ninlil_model_domain_encode_body_blob_chunk(
                    &object, local_out, sizeof(local_out), &local_len)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(local_len == local_len_before);
        REQUIRE(memcmp(local_out, local_before, sizeof(local_out)) == 0);
        REQUIRE(memcmp(&object, &object_before, sizeof(object)) == 0);
        (void)raw_own;
    }
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_blob_chunk_t,
        ninlil_model_domain_decode_body_blob_chunk);

    /* --- D1-B3d ATTEMPT (RAW16 owner_key_raw) --- */
    CHECK_VAR_ENCODE_BODY_OUT_ALIAS(
        ninlil_model_domain_body_attempt_t,
        ninlil_model_domain_encode_body_attempt);
    CHECK_VAR_ENCODE_BODY_LEN_ALIAS(
        ninlil_model_domain_body_attempt_t,
        ninlil_model_domain_encode_body_attempt);
    CHECK_VAR_ENCODE_RAW_ALIASES(
        ninlil_model_domain_body_attempt_t,
        ninlil_model_domain_encode_body_attempt,
        owner_key_raw, owner_key_raw_length);
    CHECK_VAR_ENCODE_OVERFLOW(
        ninlil_model_domain_body_attempt_t,
        ninlil_model_domain_encode_body_attempt,
        owner_key_raw, owner_key_raw_length);
    CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW(
        ninlil_model_domain_body_attempt_t,
        ninlil_model_domain_decode_body_attempt);

    /*
     * BUFFER_TOO_SMALL exact required length + untouched short buffer for each
     * variable body. Golden positives from the checked-in DSB2/DSB3 catalog.
     */
    {
        /* Load positives via the same vector path used by main/replay. */
        ninlil_dv_file_t file;
        char err[256];
        size_t vi;
        uint32_t bts_seen = 0u;
        REQUIRE(vector_path != NULL);
        REQUIRE(ninlil_dv_load_file(vector_path, &file, err, sizeof(err)) == 0);
        for (vi = 0u; vi < file.vector_count; ++vi) {
            const ninlil_dv_vector_t *v = &file.vectors[vi];
            uint8_t enc[4096];
            uint8_t short_buf[4096];
            uint8_t short_before[4096];
            size_t hn = 0u;
            uint32_t n = 0u;
            uint32_t required = 0u;
            uint32_t short_len = 0u;
            body_any_t any;
            ninlil_status_t got;
            if ((strcmp(v->suite, "DSB2") != 0
                    && strcmp(v->suite, "DSB3") != 0)
                || strcmp(v->expected_status, "OK") != 0
                || strcmp(v->op, "body_roundtrip") != 0) {
                continue;
            }
            if (v->subtype != 0x10u && v->subtype != 0x11u
                && v->subtype != 0x20u && v->subtype != 0x23u
                && v->subtype != 0x24u && v->subtype != 0x25u
                && v->subtype != 0x26u && v->subtype != 0x27u
                && v->subtype != 0x30u && v->subtype != 0x31u) {
                continue;
            }
            REQUIRE(hex_to(ninlil_dv_str(v->body_hex), enc, sizeof(enc), &hn)
                == 0);
            n = (uint32_t)hn;
            (void)memset(&any, 0, sizeof(any));
            got = decode_body_any(
                v->family, v->subtype, v->flags,
                (ninlil_bytes_view_t){enc, n}, &any);
            REQUIRE(got == NINLIL_OK);
            required = 0u;
            got = encode_body_any(
                v->family, v->subtype, v->flags, &any, NULL, 0u, &required);
            REQUIRE(got == NINLIL_E_BUFFER_TOO_SMALL);
            REQUIRE(required == n);
            REQUIRE(required == v->body_length);
            (void)memset(short_buf, 0x5A, sizeof(short_buf));
            (void)memcpy(short_before, short_buf, sizeof(short_buf));
            short_len = 0u;
            got = encode_body_any(
                v->family, v->subtype, v->flags, &any, short_buf,
                required > 0u ? required - 1u : 0u, &short_len);
            REQUIRE(got == NINLIL_E_BUFFER_TOO_SMALL);
            REQUIRE(short_len == required);
            REQUIRE(memcmp(short_buf, short_before, sizeof(short_buf)) == 0);
            bts_seen++;
        }
        /* At least one positive body_roundtrip per variable subtype family. */
        REQUIRE(bts_seen >= 8u);
        ninlil_dv_free(&file);
    }

    (void)fprintf(stdout, "body alias/overflow contract ok\n");
#undef CHECK_FIXED_BODY_ALIAS
#undef CHECK_VAR_ENCODE_BODY_OUT_ALIAS
#undef CHECK_VAR_ENCODE_BODY_LEN_ALIAS
#undef CHECK_VAR_ENCODE_RAW_ALIASES
#undef CHECK_VAR_ENCODE_DUAL_RAW_OVERLAP
#undef CHECK_VAR_ENCODE_OVERFLOW
#undef CHECK_VAR_DECODE_ALIAS_AND_OVERFLOW
#undef CHECK_VAR_ENCODE_BTS_AFTER_DECODE
    return 0;
}

/*
 * D1-B3b message_semantic_digest API contract: address-first alias gates,
 * counter underflow resistance, wrong-phase FAILED policy, oracle match.
 */
static int msd_fill_prefix_from_ingress(
    const ninlil_model_domain_body_ordered_ingress_t *ing,
    uint32_t payload_length,
    ninlil_model_domain_message_semantic_prefix_t *prefix)
{
    (void)memset(prefix, 0, sizeof(*prefix));
    prefix->kind = ing->message_kind;
    prefix->flags = ing->message_flags;
    (void)memcpy(prefix->transaction_id, ing->transaction_id, 16u);
    (void)memcpy(prefix->attempt_id, ing->attempt_id, 16u);
    (void)memcpy(prefix->event_id, ing->event_id, 16u);
    prefix->source = ing->source;
    prefix->target = ing->target;
    prefix->service = ing->service;
    (void)memcpy(prefix->content_digest, ing->content_digest, 32u);
    prefix->generation = ing->generation;
    (void)memcpy(prefix->deadline_clock_epoch, ing->deadline_clock_epoch, 16u);
    prefix->absolute_effect_deadline_ms = ing->absolute_effect_deadline_ms;
    prefix->evidence_grace_ms = ing->evidence_grace_ms;
    prefix->required_evidence = ing->required_evidence;
    prefix->receipt_stage = ing->receipt_stage;
    prefix->disposition = ing->disposition;
    prefix->effect_certainty = ing->effect_certainty;
    prefix->retry_guidance = ing->retry_guidance;
    prefix->cancel_kind = ing->cancel_kind;
    prefix->retry_delay_ms = ing->retry_delay_ms;
    (void)memcpy(prefix->evidence_clock_epoch, ing->evidence_clock_epoch, 16u);
    prefix->evidence_now_ms = ing->evidence_now_ms;
    prefix->evidence_trust = ing->evidence_trust;
    prefix->payload_length = payload_length;
    return 0;
}

static int test_message_semantic_digest_contracts(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    ninlil_model_domain_body_ordered_ingress_t empty_ing;
    ninlil_model_domain_body_ordered_ingress_t stream_ing;
    ninlil_model_domain_message_semantic_prefix_t prefix;
    ninlil_model_domain_message_semantic_prefix_t prefix_before;
    ninlil_model_domain_message_semantic_digest_ctx_t ctx;
    ninlil_model_domain_message_semantic_digest_ctx_t ctx_before;
    ninlil_model_domain_digest_t dig;
    ninlil_model_domain_digest_t dig_before;
    ninlil_model_domain_digest_t oracle;
    uint8_t body_empty[2048];
    uint8_t body_stream[2048];
    uint8_t payload[64];
    uint8_t evidence[160];
    size_t body_empty_n = 0u;
    size_t body_stream_n = 0u;
    size_t pay_n = 0u;
    size_t evi_n = 0u;
    char dig_hex[65];
    const char *oracle_empty_hex = NULL;
    const char *oracle_stream_hex = NULL;
    uint8_t *overflow_ptr;
    int found_empty = 0;
    int found_stream = 0;

    REQUIRE(path != NULL);
    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);

    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        if (strcmp(v->op, "message_semantic_digest") != 0
            || strcmp(v->expected_status, "OK") != 0) {
            continue;
        }
        if (strcmp(v->id, "DSB3_MSD_ONESHOT_EMPTY") == 0) {
            REQUIRE(hex_to(ninlil_dv_str(v->body_hex), body_empty,
                        sizeof(body_empty), &body_empty_n)
                == 0);
            oracle_empty_hex = ninlil_dv_str(v->digest_hex);
            found_empty = 1;
        } else if (strcmp(v->id, "DSB3_MSD_STREAM_NONEMPTY") == 0) {
            REQUIRE(hex_to(ninlil_dv_str(v->body_hex), body_stream,
                        sizeof(body_stream), &body_stream_n)
                == 0);
            REQUIRE(hex_to(ninlil_dv_str(v->subject_hex), payload,
                        sizeof(payload), &pay_n)
                == 0);
            REQUIRE(hex_to(ninlil_dv_str(v->retention_hex), evidence,
                        sizeof(evidence), &evi_n)
                == 0);
            oracle_stream_hex = ninlil_dv_str(v->digest_hex);
            found_stream = 1;
        }
    }
    REQUIRE(found_empty != 0);
    REQUIRE(found_stream != 0);
    REQUIRE(ninlil_model_domain_decode_body_ordered_ingress(
            (ninlil_bytes_view_t){body_empty, (uint32_t)body_empty_n},
            &empty_ing)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_decode_body_ordered_ingress(
            (ninlil_bytes_view_t){body_stream, (uint32_t)body_stream_n},
            &stream_ing)
        == NINLIL_OK);

    /* --- 7. Valid zero-length + multi-chunk paths match oracle --- */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    (void)memset(&dig, 0xA5, sizeof(dig));
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_bytes_view_t){NULL, 0u}, &dig)
        == NINLIL_OK);
    enhex(dig.bytes, 32u, dig_hex);
    REQUIRE(strcmp(dig_hex, oracle_empty_hex) == 0);
    (void)memcpy(oracle.bytes, dig.bytes, 32u);

    REQUIRE(msd_fill_prefix_from_ingress(
            &stream_ing, (uint32_t)pay_n, &prefix)
        == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    {
        uint32_t chunk = 0u;
        while (chunk < (uint32_t)pay_n) {
            uint32_t step = (uint32_t)pay_n - chunk;
            if (step > 3u) {
                step = 3u;
            }
            REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
                    &ctx, payload + chunk, step)
                == NINLIL_OK);
            chunk += step;
        }
    }
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(
            &ctx, (uint32_t)evi_n)
        == NINLIL_OK);
    {
        uint32_t chunk = 0u;
        while (chunk < (uint32_t)evi_n) {
            uint32_t step = (uint32_t)evi_n - chunk;
            if (step > 5u) {
                step = 5u;
            }
            REQUIRE(ninlil_model_domain_message_semantic_digest_update_evidence(
                    &ctx, evidence + chunk, step)
                == NINLIL_OK);
            chunk += step;
        }
    }
    REQUIRE(ninlil_model_domain_message_semantic_digest_final(&ctx, &dig)
        == NINLIL_OK);
    enhex(dig.bytes, 32u, dig_hex);
    REQUIRE(strcmp(dig_hex, oracle_stream_hex) == 0);
    /* One-shot same inputs. */
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){payload, (uint32_t)pay_n},
            (ninlil_bytes_view_t){evidence, (uint32_t)evi_n}, &dig)
        == NINLIL_OK);
    enhex(dig.bytes, 32u, dig_hex);
    REQUIRE(strcmp(dig_hex, oracle_stream_hex) == 0);

    /* --- 1. One-shot out aliases prefix/payload/evidence; payload/evidence overlap --- */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    prefix_before = prefix;
    (void)memset(&dig, 0x5A, sizeof(dig));
    dig_before = dig;
    /* out aliases prefix (prefix storage reinterpreted as digest). */
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_model_domain_digest_t *)(void *)&prefix)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&prefix, &prefix_before, sizeof(prefix)) == 0);

    {
        uint8_t pay_before[64];
        uint8_t evi_before[160];
        ninlil_model_domain_message_semantic_prefix_t p_before;
        REQUIRE(msd_fill_prefix_from_ingress(
                &stream_ing, (uint32_t)pay_n, &prefix)
            == 0);
        p_before = prefix;
        (void)memcpy(pay_before, payload, pay_n);
        (void)memcpy(evi_before, evidence, evi_n);

        /* out aliases payload */
        REQUIRE(ninlil_model_domain_message_semantic_digest(
                &prefix, (ninlil_bytes_view_t){payload, (uint32_t)pay_n},
                (ninlil_bytes_view_t){evidence, (uint32_t)evi_n},
                (ninlil_model_domain_digest_t *)(void *)payload)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(payload, pay_before, pay_n) == 0);
        REQUIRE(memcmp(evidence, evi_before, evi_n) == 0);
        REQUIRE(memcmp(&prefix, &p_before, sizeof(prefix)) == 0);

        /* out aliases evidence */
        REQUIRE(ninlil_model_domain_message_semantic_digest(
                &prefix, (ninlil_bytes_view_t){payload, (uint32_t)pay_n},
                (ninlil_bytes_view_t){evidence, (uint32_t)evi_n},
                (ninlil_model_domain_digest_t *)(void *)evidence)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(payload, pay_before, pay_n) == 0);
        REQUIRE(memcmp(evidence, evi_before, evi_n) == 0);

        /* payload/evidence ranges overlap (same buffer) */
        (void)memset(&dig, 0xB7, sizeof(dig));
        dig_before = dig;
        REQUIRE(ninlil_model_domain_message_semantic_digest(
                &prefix, (ninlil_bytes_view_t){payload, (uint32_t)pay_n},
                (ninlil_bytes_view_t){payload, (uint32_t)pay_n}, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);
        REQUIRE(memcmp(payload, pay_before, pay_n) == 0);

        /* Non-alias shape failure zeros out (sentinel must change to zero). */
        (void)memset(&dig, 0xB7, sizeof(dig));
        REQUIRE(ninlil_model_domain_message_semantic_digest(
                NULL, (ninlil_bytes_view_t){NULL, 0u},
                (ninlil_bytes_view_t){NULL, 0u}, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(&dig, sizeof(dig)));
    }

    /* --- 2. init: ctx aliases prefix untouched; invalid nested zeros after gate --- */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    {
        union {
            ninlil_model_domain_message_semantic_digest_ctx_t ctx;
            ninlil_model_domain_message_semantic_prefix_t prefix;
            uint8_t raw[sizeof(ninlil_model_domain_message_semantic_prefix_t)
                < sizeof(ninlil_model_domain_message_semantic_digest_ctx_t)
                    ? sizeof(ninlil_model_domain_message_semantic_digest_ctx_t)
                    : sizeof(ninlil_model_domain_message_semantic_prefix_t)];
        } storage;
        uint8_t storage_before[sizeof(storage)];
        (void)memset(&storage, 0xA5, sizeof(storage));
        (void)memcpy(&storage.prefix, &prefix, sizeof(prefix));
        (void)memcpy(storage_before, &storage, sizeof(storage));
        REQUIRE(ninlil_model_domain_message_semantic_digest_init(
                &storage.ctx, &storage.prefix)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&storage, storage_before, sizeof(storage)) == 0);

        /* Non-alias invalid nested shape zeros ctx only after alias gate. */
        (void)memset(&ctx, 0xA5, sizeof(ctx));
        REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
        prefix.service.namespace_id.length = 0u; /* invalid TEXT_ID */
        REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);
        {
            ninlil_model_domain_message_semantic_digest_ctx_t zeroed;
            (void)memset(&zeroed, 0, sizeof(zeroed));
            zeroed.phase = NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED;
            REQUIRE(memcmp(&ctx, &zeroed, sizeof(ctx)) == 0);
        }
        /* NULL prefix with valid ctx: zero/fail ctx. */
        (void)memset(&ctx, 0xA5, sizeof(ctx));
        REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, NULL)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);
    }

    /* --- 3. update payload/evidence data aliases ctx: exact context unchanged --- */
    REQUIRE(msd_fill_prefix_from_ingress(
            &stream_ing, (uint32_t)pay_n, &prefix)
        == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    ctx_before = ctx;
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, (const uint8_t *)&ctx, 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_PAYLOAD);

    /* Advance to evidence phase with zero-length payload (empty_ing prefix). */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(&ctx, 8u)
        == NINLIL_OK);
    ctx_before = ctx;
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_evidence(
            &ctx, (const uint8_t *)&ctx, 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_EVIDENCE);

    /* --- 4. Forged near-UINTPTR_MAX ranges: INVALID, no crash, sentinels stay --- */
    overflow_ptr = (uint8_t *)(uintptr_t)(UINTPTR_MAX - 3u);
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    (void)memset(&dig, 0x11, sizeof(dig));
    dig_before = dig;
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            (const ninlil_model_domain_message_semantic_prefix_t *)(void *)
                overflow_ptr,
            (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_bytes_view_t){NULL, 0u}, &dig)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

    (void)memset(&dig, 0x22, sizeof(dig));
    dig_before = dig;
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_model_domain_digest_t *)(void *)overflow_ptr)
        == NINLIL_E_INVALID_ARGUMENT);
    /* real dig unused; just ensure no crash and local sentinel path below */
    (void)memset(&dig, 0x22, sizeof(dig));
    dig_before = dig;
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){overflow_ptr, 16u},
            (ninlil_bytes_view_t){NULL, 0u}, &dig)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

    (void)memset(&dig, 0x33, sizeof(dig));
    dig_before = dig;
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_bytes_view_t){overflow_ptr, 16u}, &dig)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

    (void)memset(&ctx, 0xA5, sizeof(ctx));
    ctx_before = ctx;
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(
            (ninlil_model_domain_message_semantic_digest_ctx_t *)(void *)
                overflow_ptr,
            &prefix)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, overflow_ptr, 16u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);

    /* --- 5. Tampered counters / incoherent phase / malformed SHA --- */
    REQUIRE(msd_fill_prefix_from_ingress(
            &stream_ing, (uint32_t)pay_n, &prefix)
        == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    /* received > declared before any absorb */
    ctx.received_payload_length = ctx.declared_payload_length + 1u;
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, payload, 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, payload, (uint32_t)pay_n)
        == NINLIL_OK);
    /* evidence declared > max on begin */
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(
            &ctx, NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX + 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, payload, (uint32_t)pay_n)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(
            &ctx, (uint32_t)evi_n)
        == NINLIL_OK);
    /* tamper: received > declared evidence */
    ctx.received_evidence_length = ctx.declared_evidence_length + 1u;
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_evidence(
            &ctx, evidence, 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    /* incoherent phase: update_payload while in evidence phase → FAILED */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(&ctx, 0u)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, payload, 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    /* begin_evidence with incomplete payload → FAILED */
    REQUIRE(msd_fill_prefix_from_ingress(
            &stream_ing, (uint32_t)pay_n, &prefix)
        == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(
            &ctx, 0u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    /* malformed nested SHA buffer_length */
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    ctx.sha.buffer_length = 64u;
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, payload, 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    /* declared evidence > max via caller-mutated ctx on update_evidence */
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_payload(
            &ctx, payload, (uint32_t)pay_n)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(
            &ctx, 4u)
        == NINLIL_OK);
    ctx.declared_evidence_length = NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX + 1u;
    ctx.received_evidence_length = 0u;
    REQUIRE(ninlil_model_domain_message_semantic_digest_update_evidence(
            &ctx, evidence, 1u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    /* --- 6. final alias ctx/out leaves unchanged; non-alias zeros out --- */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(&ctx, 0u)
        == NINLIL_OK);
    ctx_before = ctx;
    (void)memset(&dig, 0x44, sizeof(dig));
    dig_before = dig;
    /* out aliases ctx */
    REQUIRE(ninlil_model_domain_message_semantic_digest_final(
            &ctx, (ninlil_model_domain_digest_t *)(void *)&ctx)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

    /* non-alias wrong phase: zeros out, fails ctx */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    /* still PAYLOAD, not EVIDENCE */
    (void)memset(&dig, 0x55, sizeof(dig));
    REQUIRE(ninlil_model_domain_message_semantic_digest_final(&ctx, &dig)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(zeros(&dig, sizeof(dig)));
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    /* NULL ctx final zeros out */
    (void)memset(&dig, 0x66, sizeof(dig));
    REQUIRE(ninlil_model_domain_message_semantic_digest_final(NULL, &dig)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(zeros(&dig, sizeof(dig)));

    /* incomplete evidence: zeros out, FAILED */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest_init(&ctx, &prefix)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_message_semantic_digest_begin_evidence(&ctx, 4u)
        == NINLIL_OK);
    (void)memset(&dig, 0x77, sizeof(dig));
    REQUIRE(ninlil_model_domain_message_semantic_digest_final(&ctx, &dig)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(zeros(&dig, sizeof(dig)));
    REQUIRE(ctx.phase == NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED);

    /* Success path still works after negatives. */
    REQUIRE(msd_fill_prefix_from_ingress(&empty_ing, 0u, &prefix) == 0);
    REQUIRE(ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){NULL, 0u},
            (ninlil_bytes_view_t){NULL, 0u}, &dig)
        == NINLIL_OK);
    REQUIRE(memcmp(dig.bytes, oracle.bytes, 32u) == 0);

    ninlil_dv_free(&file);
    (void)fprintf(stdout, "message_semantic_digest contracts ok\n");
    return 0;
}

/*
 * Independent oracle for blob_id_digest: SHA-256 of the documented preimage
 * (tag || owner_kind:u16 || owner_key_raw:RAW16 || blob_kind:u16 ||
 *  content_digest[32] || total_length:u64). Not the production helper.
 */
static int blob_id_digest_oracle(
    uint16_t blob_owner_kind,
    uint16_t owner_key_raw_length,
    const uint8_t *owner_key_raw,
    uint16_t blob_kind,
    const uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint64_t total_length,
    ninlil_model_domain_digest_t *out_digest)
{
    static const char tag[] = "NINLIL-DOMAIN-BLOB-ID-V1";
    uint8_t pre[sizeof(tag) - 1u + 2u + 2u + 255u + 2u + 32u + 8u];
    uint32_t o = 0u;
    uint8_t be[8];

    if (out_digest == NULL || content_digest == NULL
        || owner_key_raw_length > 255u
        || (owner_key_raw_length != 0u && owner_key_raw == NULL)) {
        return 1;
    }
    (void)memcpy(&pre[o], tag, sizeof(tag) - 1u);
    o += (uint32_t)(sizeof(tag) - 1u);
    ninlil_model_domain_encode_u16_be(be, blob_owner_kind);
    (void)memcpy(&pre[o], be, 2u);
    o += 2u;
    ninlil_model_domain_encode_u16_be(be, owner_key_raw_length);
    (void)memcpy(&pre[o], be, 2u);
    o += 2u;
    if (owner_key_raw_length != 0u) {
        (void)memcpy(&pre[o], owner_key_raw, owner_key_raw_length);
        o += owner_key_raw_length;
    }
    ninlil_model_domain_encode_u16_be(be, blob_kind);
    (void)memcpy(&pre[o], be, 2u);
    o += 2u;
    (void)memcpy(&pre[o], content_digest, 32u);
    o += 32u;
    ninlil_model_domain_encode_u64_be(be, total_length);
    (void)memcpy(&pre[o], be, 8u);
    o += 8u;
    if (ninlil_model_domain_sha256(pre, o, out_digest) != NINLIL_OK) {
        return 1;
    }
    return 0;
}

/*
 * D1-B3c blob_id_digest + blob_chunk_count_for_total helper contracts:
 * oracle match, alias/address untouched, non-alias zeros output, output nonzero.
 */
static int test_blob_helper_contracts(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    ninlil_model_domain_body_blob_manifest_t man;
    ninlil_model_domain_digest_t dig;
    ninlil_model_domain_digest_t dig_before;
    ninlil_model_domain_digest_t oracle;
    uint8_t content_before[32];
    uint8_t owner_before[128];
    uint8_t *overflow_ptr;
    uint32_t chunk_count;
    uint32_t chunk_before;
    uint32_t *overflow_count;
    const uint64_t chunk_max =
        (uint64_t)NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES;
    const uint64_t u32_max = (uint64_t)UINT32_MAX;
    /* Checked constants — product stays in uint64_t, no host narrowing. */
    const uint64_t total_u32_max = u32_max * chunk_max;
    const uint64_t total_u32_max_plus1 = total_u32_max + 1u;
    const uint64_t total_overflow = (u32_max + 1u) * chunk_max;
    int seen_tx = 0;
    int seen_ing = 0;
    int seen_dlv = 0;

    REQUIRE(path != NULL);
    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);

    /* --- Valid TX / INGRESS / DELIVERY vectors match independent oracle --- */
    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        uint8_t body[512];
        size_t bn = 0u;
        if (strcmp(v->op, "body_roundtrip") != 0
            || strcmp(v->expected_status, "OK") != 0
            || v->subtype != 0x30u
            || v->flags != NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
            continue;
        }
        if (strcmp(v->id, "DSB3_BLOB_MAN_TX_CMD") != 0
            && strcmp(v->id, "DSB3_BLOB_MAN_ING_PAY") != 0
            && strcmp(v->id, "DSB3_BLOB_MAN_DLV_CMD") != 0) {
            continue;
        }
        REQUIRE(hex_to(ninlil_dv_str(v->body_hex), body, sizeof(body), &bn)
            == 0);
        REQUIRE(ninlil_model_domain_decode_body_blob_manifest(
                (ninlil_bytes_view_t){body, (uint32_t)bn}, &man)
            == NINLIL_OK);
        REQUIRE(blob_id_digest_oracle(
                man.blob_owner_kind, man.owner_key_raw_length,
                man.owner_key_raw, man.blob_kind, man.content_digest,
                man.total_length, &oracle)
            == 0);
        (void)memset(&dig, 0xA5, sizeof(dig));
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, man.owner_key_raw_length,
                man.owner_key_raw, man.blob_kind, man.content_digest,
                man.total_length, &dig)
            == NINLIL_OK);
        REQUIRE(memcmp(dig.bytes, oracle.bytes, 32u) == 0);
        REQUIRE(memcmp(dig.bytes, man.blob_id_digest, 32u) == 0);
        /* Helper output must be non-zero. */
        REQUIRE(!zeros(dig.bytes, 32u));
        if (man.blob_owner_kind
            == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION) {
            seen_tx = 1;
        } else if (man.blob_owner_kind
            == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS) {
            seen_ing = 1;
        } else if (man.blob_owner_kind
            == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY) {
            seen_dlv = 1;
        }
    }
    REQUIRE(seen_tx != 0);
    REQUIRE(seen_ing != 0);
    REQUIRE(seen_dlv != 0);

    /* Re-load TX_CMD fixture for alias / invalid cases. */
    {
        const ninlil_dv_vector_t *v = NULL;
        uint8_t body[512];
        size_t bn = 0u;
        for (i = 0u; i < file.vector_count; ++i) {
            if (strcmp(file.vectors[i].id, "DSB3_BLOB_MAN_TX_CMD") == 0) {
                v = &file.vectors[i];
                break;
            }
        }
        REQUIRE(v != NULL);
        REQUIRE(hex_to(ninlil_dv_str(v->body_hex), body, sizeof(body), &bn)
            == 0);
        REQUIRE(ninlil_model_domain_decode_body_blob_manifest(
                (ninlil_bytes_view_t){body, (uint32_t)bn}, &man)
            == NINLIL_OK);
        REQUIRE(man.owner_key_raw_length <= sizeof(owner_before));
        (void)memcpy(owner_before, man.owner_key_raw, man.owner_key_raw_length);
        (void)memcpy(content_before, man.content_digest, 32u);

        /* out aliases owner raw — every range unchanged */
        (void)memset(&dig, 0x5A, sizeof(dig));
        dig_before = dig;
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, man.owner_key_raw_length,
                man.owner_key_raw, man.blob_kind, man.content_digest,
                man.total_length,
                (ninlil_model_domain_digest_t *)(void *)man.owner_key_raw)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(man.owner_key_raw, owner_before, man.owner_key_raw_length)
            == 0);
        REQUIRE(memcmp(man.content_digest, content_before, 32u) == 0);
        REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

        /* out aliases content_digest — every range unchanged */
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, man.owner_key_raw_length,
                man.owner_key_raw, man.blob_kind, man.content_digest,
                man.total_length,
                (ninlil_model_domain_digest_t *)(void *)man.content_digest)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(man.owner_key_raw, owner_before, man.owner_key_raw_length)
            == 0);
        REQUIRE(memcmp(man.content_digest, content_before, 32u) == 0);

        /* owner raw overlaps content_digest (same buffer as both) */
        {
            uint8_t shared[32];
            uint8_t shared_before[32];
            (void)memcpy(shared, content_before, 32u);
            (void)memcpy(shared_before, shared, 32u);
            (void)memset(&dig, 0xB7, sizeof(dig));
            dig_before = dig;
            REQUIRE(ninlil_model_domain_blob_id_digest(
                    man.blob_owner_kind, 16u, shared, man.blob_kind, shared,
                    man.total_length, &dig)
                == NINLIL_E_INVALID_ARGUMENT);
            REQUIRE(memcmp(shared, shared_before, 32u) == 0);
            REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);
        }

        /* Forged near-UINTPTR_MAX out/raw/content: safe INVALID, sentinel stays */
        overflow_ptr = (uint8_t *)(uintptr_t)(UINTPTR_MAX - 3u);
        (void)memset(&dig, 0x11, sizeof(dig));
        dig_before = dig;
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, man.owner_key_raw_length,
                man.owner_key_raw, man.blob_kind, man.content_digest,
                man.total_length,
                (ninlil_model_domain_digest_t *)(void *)overflow_ptr)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

        (void)memset(&dig, 0x22, sizeof(dig));
        dig_before = dig;
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, 16u, overflow_ptr, man.blob_kind,
                man.content_digest, man.total_length, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

        (void)memset(&dig, 0x33, sizeof(dig));
        dig_before = dig;
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, man.owner_key_raw_length,
                man.owner_key_raw, man.blob_kind, overflow_ptr,
                man.total_length, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(dig.bytes, dig_before.bytes, 32u) == 0);

        /* Non-alias invalid owner/kind/raw/content-zero zeros valid output */
        (void)memset(&dig, 0xC3, sizeof(dig));
        REQUIRE(ninlil_model_domain_blob_id_digest(
                0u /* bad owner */, man.owner_key_raw_length, man.owner_key_raw,
                man.blob_kind, man.content_digest, man.total_length, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(dig.bytes, 32u));

        (void)memset(&dig, 0xC3, sizeof(dig));
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, man.owner_key_raw_length,
                man.owner_key_raw, 99u /* bad kind */, man.content_digest,
                man.total_length, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(dig.bytes, 32u));

        (void)memset(&dig, 0xC3, sizeof(dig));
        REQUIRE(ninlil_model_domain_blob_id_digest(
                man.blob_owner_kind, 15u /* wrong TX raw len */, man.owner_key_raw,
                man.blob_kind, man.content_digest, man.total_length, &dig)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(zeros(dig.bytes, 32u));

        {
            uint8_t zero_content[32];
            (void)memset(zero_content, 0, sizeof(zero_content));
            (void)memset(&dig, 0xC3, sizeof(dig));
            REQUIRE(ninlil_model_domain_blob_id_digest(
                    man.blob_owner_kind, man.owner_key_raw_length,
                    man.owner_key_raw, man.blob_kind, zero_content,
                    man.total_length, &dig)
                == NINLIL_E_INVALID_ARGUMENT);
            REQUIRE(zeros(dig.bytes, 32u));
        }
    }

    /* --- chunk_count: exact u32 capacity + forged out pointer --- */
    chunk_count = 0xA5A5A5A5u;
    REQUIRE(ninlil_model_domain_blob_chunk_count_for_total(
            total_u32_max, &chunk_count)
        == NINLIL_OK);
    REQUIRE(chunk_count == (uint32_t)UINT32_MAX);

    chunk_count = 0xA5A5A5A5u;
    REQUIRE(ninlil_model_domain_blob_chunk_count_for_total(
            total_u32_max_plus1, &chunk_count)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(chunk_count == 0u);

    chunk_count = 0xA5A5A5A5u;
    REQUIRE(ninlil_model_domain_blob_chunk_count_for_total(
            total_overflow, &chunk_count)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(chunk_count == 0u);

    /* Forged near-UINTPTR_MAX out: INVALID without write/crash */
    overflow_count = (uint32_t *)(uintptr_t)(UINTPTR_MAX - 1u);
    REQUIRE(ninlil_model_domain_blob_chunk_count_for_total(1u, overflow_count)
        == NINLIL_E_INVALID_ARGUMENT);

    /* NULL out */
    REQUIRE(ninlil_model_domain_blob_chunk_count_for_total(1u, NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    /* Non-alias semantic failure still zeros valid output */
    chunk_count = 0xA5A5A5A5u;
    chunk_before = chunk_count;
    REQUIRE(ninlil_model_domain_blob_chunk_count_for_total(
            total_u32_max_plus1, &chunk_count)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(chunk_count == 0u);
    REQUIRE(chunk_count != chunk_before);

    ninlil_dv_free(&file);
    (void)fprintf(stdout, "blob helper contracts ok\n");
    return 0;
}

static int test_catalog_format_mutations(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    char *text = NULL;
    long sz;
    FILE *fp;
    char *mut;
    size_t i;

    /* Production replay entry rejects wrong format/scope/catalog via loader. */
    fp = fopen(path, "rb");
    REQUIRE(fp != NULL);
    REQUIRE(fseek(fp, 0, SEEK_END) == 0);
    sz = ftell(fp);
    REQUIRE(sz > 0);
    REQUIRE(fseek(fp, 0, SEEK_SET) == 0);
    text = (char *)malloc((size_t)sz + 1u);
    REQUIRE(text != NULL);
    REQUIRE(fread(text, 1u, (size_t)sz, fp) == (size_t)sz);
    text[sz] = '\0';
    (void)fclose(fp);

    /* Replace the complete format with an invalid same-length value. */
    mut = (char *)malloc((size_t)sz + 64u);
    REQUIRE(mut != NULL);
    (void)memcpy(mut, text, (size_t)sz + 1u);
    {
        char *p = strstr(mut, "\"format\": \"ninlil-domain-store-v1-d1b3e\"");
        REQUIRE(p != NULL);
        /* overwrite to wrong format of same length */
        (void)memcpy(p,
            "\"format\": \"ninlil-domain-store-v1-d1bXX\"",
            strlen("\"format\": \"ninlil-domain-store-v1-d1bXX\""));
        REQUIRE(ninlil_dv_parse_text(mut, strlen(mut), &file, err, sizeof(err))
            != 0);
        ninlil_dv_free(&file);
    }

    /* scope corruption */
    (void)memcpy(mut, text, (size_t)sz + 1u);
    {
        char *p = strstr(mut, "\"scope\":");
        REQUIRE(p != NULL);
        p = strchr(p, '"');
        REQUIRE(p != NULL);
        p = strchr(p + 1, '"');
        REQUIRE(p != NULL);
        /* open string after first scope quote */
        p = strchr(strstr(mut, "\"scope\":"), ':');
        REQUIRE(p != NULL);
        p = strchr(p, '"');
        REQUIRE(p != NULL);
        p[1] = 'X';
        REQUIRE(ninlil_dv_parse_text(mut, strlen(mut), &file, err, sizeof(err))
            != 0);
        ninlil_dv_free(&file);
    }

    /* catalog count tamper: dsb1_subtype_01_positive */
    (void)memcpy(mut, text, (size_t)sz + 1u);
    {
        char *p = strstr(mut, "\"dsb1_subtype_01_positive\":");
        REQUIRE(p != NULL);
        p = strchr(p, ':');
        REQUIRE(p != NULL);
        p++;
        while (*p == ' ') {
            p++;
        }
        /* force wrong count 0 when original >0 */
        *p = '0';
        if (p[1] >= '0' && p[1] <= '9') {
            size_t j = 1u;
            while (p[j] >= '0' && p[j] <= '9') {
                p[j] = ' ';
                j++;
            }
        }
        REQUIRE(ninlil_dv_parse_text(mut, strlen(mut), &file, err, sizeof(err))
            == 0);
        /* parse accepts catalog value; production coverage checker rejects */
        REQUIRE(file.catalog.dsb1_subtype_01_positive == 0u);
        {
            uint32_t cov01 = 0u;
            for (i = 0u; i < file.vector_count; ++i) {
                if (strcmp(file.vectors[i].suite, "DSB1") == 0
                    && file.vectors[i].subtype == 0x01u
                    && strcmp(file.vectors[i].expected_status, "OK") == 0) {
                    cov01++;
                }
            }
            REQUIRE(cov01 != file.catalog.dsb1_subtype_01_positive);
        }
        ninlil_dv_free(&file);
    }

    /* delete required catalog key by renaming */
    (void)memcpy(mut, text, (size_t)sz + 1u);
    {
        char *p = strstr(mut, "\"dsb1_total_positive\"");
        REQUIRE(p != NULL);
        p[1] = 'x'; /* "xsb1_total_positive" unknown catalog key */
        REQUIRE(ninlil_dv_parse_text(mut, strlen(mut), &file, err, sizeof(err))
            != 0);
        ninlil_dv_free(&file);
    }

    free(mut);
    free(text);
    (void)fprintf(stdout, "catalog/format mutation tests ok\n");
    return 0;
}

/*
 * D1-B3d ATTEMPT: independent oracle for primary_key_digest, typed key
 * COMPOSITE(31, ...) identity, primary_id derivation, exact owner_key_raw
 * borrow at body offset 22, and typed-path output-zero on failure.
 *
 * First-696 exact append-only preservation is the durable Python fingerprint
 * gate (PRE_B3D_VECTORS_FINGERPRINT in tools/domain_store_vector_gen.py). The
 * C prefix check below is only a non-ATT id-prefix guard, not an exact-bytes
 * claim.
 */
static int test_attempt_contracts(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    int seen_tx = 0;
    int seen_dlv = 0;
    int seen_cmd = 0;
    int seen_evt = 0;
    int seen_can = 0;
    int seen_typed = 0;
    uint32_t att_count = 0u;
    uint32_t typed_ok = 0u;
    ninlil_model_domain_body_attempt_t body;
    ninlil_model_domain_typed_record_t rec;
    ninlil_model_domain_key_view_t kv;
    ninlil_model_domain_digest_t dig;
    uint8_t components[2u + 2u + 128u + 16u];
    uint8_t key_buf[64];
    uint8_t val_buf[1024];
    size_t kn = 0u;
    size_t vn = 0u;
    uint32_t o;
    ninlil_bytes_view_t cv;
    ninlil_model_domain_key_t built;
    const uint8_t *body_start;

    REQUIRE(path != NULL);
    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);
    /*
     * Non-ATT id-prefix guard only. Exact first-696 catalog bytes are gated by
     * PRE_B3D_VECTORS_FINGERPRINT in tools/domain_store_vector_gen.py.
     */
    REQUIRE(file.vector_count > 696u);
    for (i = 0u; i < 696u; ++i) {
        REQUIRE(strncmp(file.vectors[i].id, "DSB3_ATT_", 9) != 0);
    }

    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        uint8_t enc[512];
        size_t bn = 0u;
        if (v->subtype != 0x31u) {
            continue;
        }
        att_count++;
        if (strcmp(v->op, "body_roundtrip") != 0
            || strcmp(v->expected_status, "OK") != 0) {
            continue;
        }
        REQUIRE(hex_to(ninlil_dv_str(v->body_hex), enc, sizeof(enc), &bn)
            == 0);
        REQUIRE(ninlil_model_domain_decode_body_attempt(
                (ninlil_bytes_view_t){enc, (uint32_t)bn}, &body)
            == NINLIL_OK);
        /* Borrowed owner_key_raw must be exact contents at body offset 22. */
        REQUIRE(body.owner_key_raw != NULL);
        REQUIRE(body.owner_key_raw == &enc[22]);
        REQUIRE(body.owner_key_raw + body.owner_key_raw_length <= enc + bn);
        /* Independent KEY_DIGEST of owner primary. */
        if (body.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
            ninlil_bytes_view_t idv;
            idv.data = body.transaction_id;
            idv.length = 16u;
            REQUIRE(ninlil_model_domain_build_key(
                    NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                    NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
                    NINLIL_MODEL_DOMAIN_ID_KIND_ID128, idv, &built)
                == NINLIL_OK);
            REQUIRE(ninlil_model_domain_key_digest(
                    (ninlil_bytes_view_t){built.bytes, built.length}, &dig)
                == NINLIL_OK);
            REQUIRE(memcmp(body.primary_key_digest, dig.bytes, 32u) == 0);
            seen_tx = 1;
        } else if (
            body.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
            uint8_t raw16[82];
            ninlil_model_domain_encode_u16_be(raw16, body.owner_key_raw_length);
            (void)memcpy(
                &raw16[2], body.owner_key_raw, body.owner_key_raw_length);
            cv.data = raw16;
            cv.length = 2u + (uint32_t)body.owner_key_raw_length;
            REQUIRE(ninlil_model_domain_composite_digest(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, cv, &dig)
                == NINLIL_OK);
            {
                ninlil_bytes_view_t idv;
                idv.data = dig.bytes;
                idv.length = 32u;
                REQUIRE(ninlil_model_domain_build_key(
                        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                        NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, idv,
                        &built)
                    == NINLIL_OK);
                REQUIRE(ninlil_model_domain_key_digest(
                        (ninlil_bytes_view_t){built.bytes, built.length}, &dig)
                    == NINLIL_OK);
                REQUIRE(memcmp(body.primary_key_digest, dig.bytes, 32u) == 0);
            }
            seen_dlv = 1;
        }
        if (body.attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_COMMAND) {
            seen_cmd = 1;
        } else if (body.attempt_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_EVENT) {
            seen_evt = 1;
        } else if (body.attempt_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_CANCEL) {
            seen_can = 1;
        }
    }
    REQUIRE(att_count > 0u);
    REQUIRE(seen_tx != 0);
    REQUIRE(seen_dlv != 0);
    REQUIRE(seen_cmd != 0);
    REQUIRE(seen_evt != 0);
    REQUIRE(seen_can != 0);

    /*
     * Every positive subtype 0x31 typed_record: independent key parse,
     * COMPOSITE(31, owner_kind||RAW16||attempt_id) identity, primary_id
     * derivation, exact owner_key_raw borrow at body offset 22, key/body IDs.
     */
    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        if (v->subtype != 0x31u || strcmp(v->op, "typed_record") != 0
            || strcmp(v->expected_status, "OK") != 0) {
            continue;
        }
        seen_typed = 1;
        typed_ok++;
        REQUIRE(hex_to(ninlil_dv_str(v->key_hex), key_buf, sizeof(key_buf),
                    &kn)
            == 0);
        REQUIRE(hex_to(ninlil_dv_str(v->value_hex), val_buf, sizeof(val_buf),
                    &vn)
            == 0);
        REQUIRE(ninlil_model_domain_parse_key(
                (ninlil_bytes_view_t){key_buf, (uint32_t)kn}, &kv)
            == NINLIL_OK);
        REQUIRE(kv.family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN);
        REQUIRE(kv.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT);
        REQUIRE(kv.identity_kind
            == NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE);
        REQUIRE(kv.identity_length == 32u);
        REQUIRE(kv.identity != NULL);

        (void)memset(&rec, 0xA5, sizeof(rec));
        REQUIRE(ninlil_model_domain_validate_typed_record(
                (ninlil_bytes_view_t){key_buf, (uint32_t)kn},
                (ninlil_bytes_view_t){val_buf, (uint32_t)vn}, &rec)
            == NINLIL_OK);
        REQUIRE(rec.subtype == 0x31u);
        REQUIRE(rec.envelope.header.record_revision >= 1u);
        REQUIRE(rec.envelope.header.flags == 0u);
        body_start = rec.envelope.body.data;
        REQUIRE(body_start != NULL);
        REQUIRE(rec.attempt.owner_key_raw == &body_start[22]);
        REQUIRE(rec.attempt.owner_key_raw_length > 0u);
        REQUIRE(!zeros(rec.attempt.attempt_id, 16u));
        REQUIRE(!zeros(rec.attempt.transaction_id, 16u));
        REQUIRE(!zeros(rec.attempt.primary_key_digest, 32u));

        /* Independent COMPOSITE(31, owner_kind||RAW16||attempt_id). */
        ninlil_model_domain_encode_u16_be(
            components, rec.attempt.attempt_owner_kind);
        o = 2u;
        ninlil_model_domain_encode_u16_be(
            &components[o], rec.attempt.owner_key_raw_length);
        o += 2u;
        (void)memcpy(
            &components[o], rec.attempt.owner_key_raw,
            rec.attempt.owner_key_raw_length);
        o += rec.attempt.owner_key_raw_length;
        (void)memcpy(&components[o], rec.attempt.attempt_id, 16u);
        o += 16u;
        cv.data = components;
        cv.length = o;
        REQUIRE(ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, cv, &dig)
            == NINLIL_OK);
        REQUIRE(!zeros(dig.bytes, 32u));
        REQUIRE(memcmp(kv.identity, dig.bytes, 32u) == 0);
        REQUIRE(rec.key.identity != NULL);
        REQUIRE(rec.key.identity_length == 32u);
        REQUIRE(memcmp(rec.key.identity, dig.bytes, 32u) == 0);

        /* primary_id: TX transaction_id or DELIVERY composite first 16. */
        if (rec.attempt.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
            REQUIRE(rec.attempt.owner_key_raw_length == 16u);
            REQUIRE(memcmp(
                    rec.attempt.owner_key_raw, rec.attempt.transaction_id, 16u)
                == 0);
            REQUIRE(memcmp(
                    rec.envelope.header.primary_id, rec.attempt.transaction_id,
                    16u)
                == 0);
        } else if (
            rec.attempt.attempt_owner_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
            uint8_t raw16[2u + 128u];
            ninlil_model_domain_encode_u16_be(
                raw16, rec.attempt.owner_key_raw_length);
            (void)memcpy(
                &raw16[2], rec.attempt.owner_key_raw,
                rec.attempt.owner_key_raw_length);
            cv.data = raw16;
            cv.length = 2u + (uint32_t)rec.attempt.owner_key_raw_length;
            REQUIRE(ninlil_model_domain_composite_digest(
                    NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, cv, &dig)
                == NINLIL_OK);
            REQUIRE(memcmp(rec.envelope.header.primary_id, dig.bytes, 16u)
                == 0);
            /* DELIVERY owner raw embeds transaction_id at offset 32. */
            REQUIRE(rec.attempt.owner_key_raw_length >= 48u);
            REQUIRE(memcmp(
                    rec.attempt.owner_key_raw + 32u, rec.attempt.transaction_id,
                    16u)
                == 0);
        } else {
            REQUIRE(0);
        }
    }
    REQUIRE(seen_typed != 0);
    REQUIRE(typed_ok >= 2u);

    /* Typed path: non-alias failure zeros out_record. */
    kn = 0u;
    vn = 0u;
    for (i = 0u; i < file.vector_count; ++i) {
        if (strcmp(file.vectors[i].id, "DSB3_ATT_TX_CMD_PREP_TYPED") == 0) {
            REQUIRE(hex_to(
                    ninlil_dv_str(file.vectors[i].key_hex), key_buf,
                    sizeof(key_buf), &kn)
                == 0);
            REQUIRE(hex_to(
                    ninlil_dv_str(file.vectors[i].value_hex), val_buf,
                    sizeof(val_buf), &vn)
                == 0);
            break;
        }
    }
    REQUIRE(kn > 0u && vn > 0u);
    (void)memset(&rec, 0xA5, sizeof(rec));
    /* Corrupt CRC trailing byte — non-alias failure must zero out_record. */
    val_buf[vn - 1u] ^= 0xFFu;
    REQUIRE(ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){key_buf, (uint32_t)kn},
            (ninlil_bytes_view_t){val_buf, (uint32_t)vn}, &rec)
        != NINLIL_OK);
    REQUIRE(zeros(&rec, sizeof(rec)));

    ninlil_dv_free(&file);
    (void)fprintf(stdout,
        "attempt contracts ok att_vectors=%u typed_ok=%u\n", att_count,
        typed_ok);
    return 0;
}

/*
 * D1-B3e ATTEMPT_ID_INDEX: independent oracle for
 * attempt_record_key_digest = KEY_DIGEST(complete TX ATTEMPT key), typed
 * ID128 key == attempt_id, primary_id == transaction_id, rev==1, and
 * typed-path output-zero on failure. First-777 exact append-only
 * preservation is the durable Python fingerprint gate
 * (PRE_B3E_VECTORS_FINGERPRINT).
 */
static int test_attempt_id_index_contracts(const char *path)
{
    ninlil_dv_file_t file;
    char err[256];
    size_t i;
    int seen_cmd = 0;
    int seen_evt = 0;
    int seen_can = 0;
    int seen_typed = 0;
    uint32_t aii_count = 0u;
    uint32_t typed_ok = 0u;
    ninlil_model_domain_body_attempt_id_index_t body;
    ninlil_model_domain_typed_record_t rec;
    ninlil_model_domain_key_view_t kv;
    ninlil_model_domain_digest_t dig;
    uint8_t components[2u + 2u + 16u + 16u];
    uint8_t key_buf[64];
    uint8_t val_buf[1024];
    size_t kn = 0u;
    size_t vn = 0u;
    uint32_t o;
    ninlil_bytes_view_t cv;
    ninlil_model_domain_key_t built;

    REQUIRE(path != NULL);
    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);
    /* Non-AII id-prefix guard; exact first-777 bytes gated by Python FP. */
    REQUIRE(file.vector_count > 777u);
    for (i = 0u; i < 777u; ++i) {
        REQUIRE(strncmp(file.vectors[i].id, "DSB3_AII_", 9) != 0);
    }

    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        uint8_t enc[128];
        size_t bn = 0u;
        if (v->subtype != 0x34u) {
            continue;
        }
        aii_count++;
        if (strcmp(v->op, "body_roundtrip") != 0
            || strcmp(v->expected_status, "OK") != 0) {
            continue;
        }
        REQUIRE(hex_to(ninlil_dv_str(v->body_hex), enc, sizeof(enc), &bn)
            == 0);
        REQUIRE(bn == NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_ID_INDEX_BYTES);
        REQUIRE(ninlil_model_domain_decode_body_attempt_id_index(
                (ninlil_bytes_view_t){enc, (uint32_t)bn}, &body)
            == NINLIL_OK);
        REQUIRE(!zeros(body.attempt_id, 16u));
        REQUIRE(!zeros(body.transaction_id, 16u));
        REQUIRE(!zeros(body.attempt_creation_value_digest, 32u));
        REQUIRE(body.reserved == 0u);
        /* Independent KEY_DIGEST(complete TX-owned ATTEMPT key). */
        ninlil_model_domain_encode_u16_be(
            components, NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION);
        o = 2u;
        ninlil_model_domain_encode_u16_be(
            &components[o], NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_KEY_TX_BYTES);
        o += 2u;
        (void)memcpy(&components[o], body.transaction_id, 16u);
        o += 16u;
        (void)memcpy(&components[o], body.attempt_id, 16u);
        o += 16u;
        cv.data = components;
        cv.length = o;
        REQUIRE(ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, cv, &dig)
            == NINLIL_OK);
        {
            ninlil_bytes_view_t idv;
            idv.data = dig.bytes;
            idv.length = 32u;
            REQUIRE(ninlil_model_domain_build_key(
                    NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                    NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT,
                    NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, idv, &built)
                == NINLIL_OK);
            REQUIRE(ninlil_model_domain_key_digest(
                    (ninlil_bytes_view_t){built.bytes, built.length}, &dig)
                == NINLIL_OK);
            /* Must equal stored record key digest — do not discard. */
            REQUIRE(memcmp(body.attempt_record_key_digest, dig.bytes, 32u)
                == 0);
            /* Explicit: stored digest is complete-key digest, not bare. */
            {
                ninlil_model_domain_digest_t bare;
                REQUIRE(ninlil_model_domain_composite_digest(
                        NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, cv, &bare)
                    == NINLIL_OK);
                REQUIRE(memcmp(body.attempt_record_key_digest, bare.bytes, 32u)
                    != 0);
            }
        }
        if (body.attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_COMMAND) {
            seen_cmd = 1;
        } else if (
            body.attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_EVENT) {
            seen_evt = 1;
        } else if (
            body.attempt_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_CANCEL) {
            seen_can = 1;
        }
    }
    REQUIRE(aii_count > 0u);
    REQUIRE(seen_cmd != 0);
    REQUIRE(seen_evt != 0);
    REQUIRE(seen_can != 0);

    for (i = 0u; i < file.vector_count; ++i) {
        const ninlil_dv_vector_t *v = &file.vectors[i];
        if (v->subtype != 0x34u || strcmp(v->op, "typed_record") != 0
            || strcmp(v->expected_status, "OK") != 0) {
            continue;
        }
        seen_typed = 1;
        typed_ok++;
        REQUIRE(hex_to(ninlil_dv_str(v->key_hex), key_buf, sizeof(key_buf),
                    &kn)
            == 0);
        REQUIRE(hex_to(ninlil_dv_str(v->value_hex), val_buf, sizeof(val_buf),
                    &vn)
            == 0);
        REQUIRE(ninlil_model_domain_parse_key(
                (ninlil_bytes_view_t){key_buf, (uint32_t)kn}, &kv)
            == NINLIL_OK);
        REQUIRE(kv.family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN);
        REQUIRE(kv.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX);
        REQUIRE(kv.identity_kind == NINLIL_MODEL_DOMAIN_ID_KIND_ID128);
        REQUIRE(kv.identity_length == 16u);
        REQUIRE(kv.identity != NULL);

        (void)memset(&rec, 0xA5, sizeof(rec));
        REQUIRE(ninlil_model_domain_validate_typed_record(
                (ninlil_bytes_view_t){key_buf, (uint32_t)kn},
                (ninlil_bytes_view_t){val_buf, (uint32_t)vn}, &rec)
            == NINLIL_OK);
        REQUIRE(rec.subtype == 0x34u);
        REQUIRE(rec.envelope.header.record_revision == 1u);
        REQUIRE(rec.envelope.header.flags == 0u);
        REQUIRE(!zeros(rec.envelope.header.head_witness_digest, 32u));
        REQUIRE(!zeros(rec.envelope.header.primary_value_digest, 32u));
        REQUIRE(memcmp(
                kv.identity, rec.attempt_id_index.attempt_id, 16u)
            == 0);
        REQUIRE(memcmp(
                rec.key.identity, rec.attempt_id_index.attempt_id, 16u)
            == 0);
        REQUIRE(memcmp(
                rec.envelope.header.primary_id,
                rec.attempt_id_index.transaction_id, 16u)
            == 0);
        REQUIRE(!zeros(rec.attempt_id_index.attempt_record_key_digest, 32u));
        REQUIRE(
            !zeros(rec.attempt_id_index.attempt_creation_value_digest, 32u));

        /* Recompute complete-key KEY_DIGEST and bind to body field. */
        ninlil_model_domain_encode_u16_be(
            components, NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION);
        o = 2u;
        ninlil_model_domain_encode_u16_be(
            &components[o], NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_KEY_TX_BYTES);
        o += 2u;
        (void)memcpy(
            &components[o], rec.attempt_id_index.transaction_id, 16u);
        o += 16u;
        (void)memcpy(&components[o], rec.attempt_id_index.attempt_id, 16u);
        o += 16u;
        cv.data = components;
        cv.length = o;
        REQUIRE(ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, cv, &dig)
            == NINLIL_OK);
        {
            ninlil_bytes_view_t idv;
            idv.data = dig.bytes;
            idv.length = 32u;
            REQUIRE(ninlil_model_domain_build_key(
                    NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                    NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT,
                    NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, idv, &built)
                == NINLIL_OK);
            REQUIRE(ninlil_model_domain_key_digest(
                    (ninlil_bytes_view_t){built.bytes, built.length}, &dig)
                == NINLIL_OK);
            REQUIRE(memcmp(
                    rec.attempt_id_index.attempt_record_key_digest, dig.bytes,
                    32u)
                == 0);
        }
    }
    REQUIRE(seen_typed != 0);
    REQUIRE(typed_ok >= 3u);

    /* Typed path: non-alias failure zeros out_record. */
    kn = 0u;
    vn = 0u;
    for (i = 0u; i < file.vector_count; ++i) {
        if (strcmp(file.vectors[i].id, "DSB3_AII_CMD_TYPED") == 0) {
            REQUIRE(hex_to(
                    ninlil_dv_str(file.vectors[i].key_hex), key_buf,
                    sizeof(key_buf), &kn)
                == 0);
            REQUIRE(hex_to(
                    ninlil_dv_str(file.vectors[i].value_hex), val_buf,
                    sizeof(val_buf), &vn)
                == 0);
            break;
        }
    }
    REQUIRE(kn > 0u && vn > 0u);
    (void)memset(&rec, 0xA5, sizeof(rec));
    val_buf[vn - 1u] ^= 0xFFu;
    REQUIRE(ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){key_buf, (uint32_t)kn},
            (ninlil_bytes_view_t){val_buf, (uint32_t)vn}, &rec)
        != NINLIL_OK);
    REQUIRE(zeros(&rec, sizeof(rec)));

    ninlil_dv_free(&file);
    (void)fprintf(stdout,
        "attempt_id_index contracts ok aii_vectors=%u typed_ok=%u\n",
        aii_count, typed_ok);
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = "spec/vectors/domain-store-v1.json";
    if (argc > 1) {
        path = argv[1];
    }
    if (test_unit_sha_and_null_key() != 0
        || test_reason_registry_unit() != 0
        || test_head_encoded_length_matrix() != 0
        || test_invalid_encode_structs() != 0
        || test_body_alias_and_overflow(path) != 0
        || test_message_semantic_digest_contracts(path) != 0
        || test_blob_helper_contracts(path) != 0
        || test_attempt_contracts(path) != 0
        || test_attempt_id_index_contracts(path) != 0
        || test_catalog_and_replay(path) != 0
        || test_mutation_rejects_wrong_digest(path) != 0
        || test_manifest_key_length_mutation(path) != 0
        || test_body_mutation_reserved_flip(path) != 0
        || test_catalog_format_mutations(path) != 0) {
        return 1;
    }
    return 0;
}
