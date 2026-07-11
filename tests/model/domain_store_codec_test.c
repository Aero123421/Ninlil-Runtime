#include "domain_store_codec.h"
#include "domain_store_codec_internal.h"
#include "domain_vector_parse.h"

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
    return (ninlil_status_t)-1;
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

    REQUIRE(ninlil_dv_load_file(path, &file, err, sizeof(err)) == 0);
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
    (void)fprintf(stdout,
        "production replayed vectors=%zu sizeof(ninlil_dv_vector_t)=%zu\n",
        file.vector_count, sizeof(ninlil_dv_vector_t));
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

int main(int argc, char **argv)
{
    const char *path = "spec/vectors/domain-store-v1.json";
    if (argc > 1) {
        path = argv[1];
    }
    if (test_unit_sha_and_null_key() != 0
        || test_catalog_and_replay(path) != 0
        || test_mutation_rejects_wrong_digest(path) != 0
        || test_manifest_key_length_mutation(path) != 0) {
        return 1;
    }
    return 0;
}
