#include "domain_vector_parse.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(char *err, size_t err_cap, const char *msg)
{
    if (err == NULL || err_cap == 0u) {
        return;
    }
    (void)snprintf(err, err_cap, "%s", msg);
}

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

typedef struct {
    const char *p;
    const char *end;
    char *err;
    size_t err_cap;
} parse_ctx;

static void skip_ws(parse_ctx *c)
{
    while (c->p < c->end && is_ws(*c->p)) {
        c->p++;
    }
}

static int peek(parse_ctx *c)
{
    skip_ws(c);
    return c->p < c->end ? (unsigned char)*c->p : -1;
}

static int take(parse_ctx *c, char expect)
{
    skip_ws(c);
    if (c->p >= c->end || *c->p != expect) {
        set_err(c->err, c->err_cap, "unexpected character");
        return -1;
    }
    c->p++;
    return 0;
}

/* Heap-allocate decoded JSON string (exactly sized). */
static int parse_string_heap(parse_ctx *c, char **out)
{
    size_t n = 0u;
    size_t cap = 64u;
    char *buf;
    skip_ws(c);
    if (c->p >= c->end || *c->p != '"') {
        set_err(c->err, c->err_cap, "expected string");
        return -1;
    }
    c->p++;
    buf = (char *)malloc(cap);
    if (buf == NULL) {
        set_err(c->err, c->err_cap, "oom");
        return -1;
    }
    while (c->p < c->end && *c->p != '"') {
        char ch = *c->p++;
        if (ch == '\\') {
            if (c->p >= c->end) {
                free(buf);
                set_err(c->err, c->err_cap, "truncated escape");
                return -1;
            }
            ch = *c->p++;
            if (ch == '"' || ch == '\\' || ch == '/') {
                /* keep */
            } else if (ch == 'n') {
                ch = '\n';
            } else if (ch == 't') {
                ch = '\t';
            } else if (ch == 'r') {
                ch = '\r';
            } else {
                free(buf);
                set_err(c->err, c->err_cap, "unsupported escape");
                return -1;
            }
        }
        if (n + 1u >= NINLIL_DV_MAX_HEX_CHARS) {
            free(buf);
            set_err(c->err, c->err_cap, "string too long");
            return -1;
        }
        if (n + 1u >= cap) {
            size_t nc = cap * 2u;
            char *nb;
            if (nc > NINLIL_DV_MAX_HEX_CHARS) {
                nc = NINLIL_DV_MAX_HEX_CHARS;
            }
            nb = (char *)realloc(buf, nc);
            if (nb == NULL) {
                free(buf);
                set_err(c->err, c->err_cap, "oom");
                return -1;
            }
            buf = nb;
            cap = nc;
        }
        buf[n++] = ch;
    }
    if (c->p >= c->end || *c->p != '"') {
        free(buf);
        set_err(c->err, c->err_cap, "unterminated string");
        return -1;
    }
    c->p++;
    buf[n] = '\0';
    *out = buf;
    return 0;
}

static int parse_string_fixed(parse_ctx *c, char *out, size_t out_cap)
{
    char *tmp = NULL;
    if (parse_string_heap(c, &tmp) != 0) {
        return -1;
    }
    if (strlen(tmp) >= out_cap) {
        free(tmp);
        set_err(c->err, c->err_cap, "string too long");
        return -1;
    }
    (void)memcpy(out, tmp, strlen(tmp) + 1u);
    free(tmp);
    return 0;
}

static int parse_u64(parse_ctx *c, uint64_t *out)
{
    uint64_t v = 0u;
    int digits = 0;
    skip_ws(c);
    if (c->p >= c->end || !isdigit((unsigned char)*c->p)) {
        set_err(c->err, c->err_cap, "expected number");
        return -1;
    }
    while (c->p < c->end && isdigit((unsigned char)*c->p)) {
        uint64_t digit = (uint64_t)(*c->p - '0');
        if (v > (UINT64_MAX - digit) / 10u) {
            set_err(c->err, c->err_cap, "numeric overflow");
            return -1;
        }
        v = v * 10u + digit;
        c->p++;
        digits++;
    }
    if (digits == 0) {
        set_err(c->err, c->err_cap, "expected number");
        return -1;
    }
    *out = v;
    return 0;
}

static int parse_u32(parse_ctx *c, uint32_t *out)
{
    uint64_t v = 0u;
    if (parse_u64(c, &v) != 0) {
        return -1;
    }
    if (v > UINT32_MAX) {
        set_err(c->err, c->err_cap, "numeric overflow");
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

int ninlil_dv_hex_decode(
    const char *hex,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    char *err,
    size_t err_cap)
{
    size_t len;
    size_t i;
    if (hex == NULL || out_len == NULL) {
        set_err(err, err_cap, "null hex");
        return -1;
    }
    len = strlen(hex);
    if ((len % 2u) != 0u) {
        set_err(err, err_cap, "odd hex length");
        return -1;
    }
    if ((len / 2u) > out_cap) {
        set_err(err, err_cap, "hex exceeds destination capacity");
        return -1;
    }
    for (i = 0u; i < len; ++i) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            set_err(err, err_cap, "invalid hex character");
            return -1;
        }
    }
    for (i = 0u; i < len / 2u; ++i) {
        char a = hex[i * 2u];
        char b = hex[i * 2u + 1u];
        uint8_t hi = (uint8_t)((a <= '9') ? (a - '0') : (a - 'a' + 10));
        uint8_t lo = (uint8_t)((b <= '9') ? (b - '0') : (b - 'a' + 10));
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = len / 2u;
    return 0;
}

void ninlil_dv_vector_clear(ninlil_dv_vector_t *v)
{
    uint32_t i;
    if (v == NULL) {
        return;
    }
    free(v->identity_hex);
    free(v->key_hex);
    free(v->value_hex);
    free(v->body_hex);
    free(v->head_hex);
    free(v->pvd_hex);
    free(v->digest_hex);
    free(v->digest2_hex);
    free(v->crc_hex);
    free(v->notes);
    free(v->subject_hex);
    free(v->retention_hex);
    free(v->manifest_hex);
    free(v->successor_hex);
    if (v->chunk_bodies_hex != NULL) {
        for (i = 0u; i < v->chunk_bodies_count; ++i) {
            free(v->chunk_bodies_hex[i]);
        }
        free(v->chunk_bodies_hex);
    }
    (void)memset(v, 0, sizeof(*v));
}

static int set_heap_string(
    char **slot,
    uint64_t *bits,
    uint64_t bit,
    char *value,
    char *err,
    size_t err_cap,
    const char *name)
{
    if ((*bits & bit) != 0u) {
        free(value);
        set_err(err, err_cap, "duplicate field");
        (void)name;
        return -1;
    }
    *slot = value;
    *bits |= bit;
    return 0;
}

static int known_suite(const char *s)
{
    return strcmp(s, "DSK1") == 0
        || strcmp(s, "DSV1") == 0
        || strcmp(s, "DSH2") == 0
        || strcmp(s, "DSO2") == 0
        || strcmp(s, "DSW1") == 0
        || strcmp(s, "DSB1") == 0;
}

static int known_op(const char *op)
{
    return strcmp(op, "sha256") == 0
        || strcmp(op, "sha256_ctx_final") == 0
        || strcmp(op, "sha256_ctx_update") == 0
        || strcmp(op, "crc32c") == 0
        || strcmp(op, "key_build") == 0
        || strcmp(op, "key_classify") == 0
        || strcmp(op, "row_classify") == 0
        || strcmp(op, "envelope_encode") == 0
        || strcmp(op, "envelope_decode") == 0
        || strcmp(op, "health_source_id") == 0
        || strcmp(op, "commit_fence_digest") == 0
        || strcmp(op, "witness_identity_digest") == 0
        || strcmp(op, "witness_chunk_decode") == 0
        || strcmp(op, "witness_chunk_roundtrip") == 0
        || strcmp(op, "witness_manifest_stream") == 0
        || strcmp(op, "blob_chunk_data_len") == 0
        || strcmp(op, "chunk_count") == 0
        || strcmp(op, "canonical_operation_digest") == 0
        || strcmp(op, "witness_header_roundtrip") == 0
        || strcmp(op, "witness_header_decode") == 0
        || strcmp(op, "witness_header_encode") == 0
        || strcmp(op, "primary_id") == 0
        || strcmp(op, "body_encode") == 0
        || strcmp(op, "body_decode") == 0
        || strcmp(op, "body_roundtrip") == 0
        || strcmp(op, "typed_record") == 0;
}

static int has_str(const ninlil_dv_vector_t *v, uint64_t bit)
{
    return (v->str_bits & bit) != 0u;
}

static int has_num(const ninlil_dv_vector_t *v, uint64_t bit)
{
    return (v->num_bits & bit) != 0u;
}

static int is_ok_status(const ninlil_dv_vector_t *v)
{
    return strcmp(v->expected_status, "OK") == 0;
}

/*
 * Operation catalog: required input fields (presence of key) and required
 * expected/output fields when status is OK. Empty string still counts as
 * present when the key appears.
 */
static int validate_op_fields(
    const ninlil_dv_vector_t *v, char *err, size_t err_cap)
{
    const char *op = v->op;
    int ok = is_ok_status(v);

#define NEED_STR(bit)                                                          \
    do {                                                                       \
        if (!has_str(v, (bit))) {                                              \
            set_err(err, err_cap, "missing required field for op");            \
            return -1;                                                         \
        }                                                                      \
    } while (0)
#define NEED_NUM(bit)                                                          \
    do {                                                                       \
        if (!has_num(v, (bit))) {                                              \
            set_err(err, err_cap, "missing required field for op");            \
            return -1;                                                         \
        }                                                                      \
    } while (0)

    if (strcmp(op, "sha256") == 0) {
        NEED_STR(NINLIL_DV_STR_BODY);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "sha256_ctx_final") == 0) {
        NEED_NUM(NINLIL_DV_NUM_SHA_BIT);
        NEED_NUM(NINLIL_DV_NUM_SHA_BUFFER);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "sha256_ctx_update") == 0) {
        NEED_NUM(NINLIL_DV_NUM_SHA_BIT);
        NEED_NUM(NINLIL_DV_NUM_SHA_BUFFER);
        NEED_STR(NINLIL_DV_STR_BODY);
    } else if (strcmp(op, "crc32c") == 0) {
        NEED_STR(NINLIL_DV_STR_BODY);
        NEED_STR(NINLIL_DV_STR_CRC);
    } else if (strcmp(op, "key_build") == 0) {
        NEED_NUM(NINLIL_DV_NUM_FAMILY);
        NEED_NUM(NINLIL_DV_NUM_SUBTYPE);
        NEED_NUM(NINLIL_DV_NUM_IDENTITY_KIND);
        NEED_STR(NINLIL_DV_STR_IDENTITY);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_KEY);
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "key_classify") == 0) {
        NEED_STR(NINLIL_DV_STR_KEY);
    } else if (strcmp(op, "row_classify") == 0) {
        NEED_STR(NINLIL_DV_STR_KEY);
        NEED_STR(NINLIL_DV_STR_VALUE);
    } else if (strcmp(op, "envelope_encode") == 0) {
        NEED_NUM(NINLIL_DV_NUM_RECORD_TYPE);
        NEED_NUM(NINLIL_DV_NUM_SUBTYPE);
        NEED_NUM(NINLIL_DV_NUM_BODY_LENGTH);
        NEED_NUM(NINLIL_DV_NUM_REVISION);
        NEED_STR(NINLIL_DV_STR_BODY);
        NEED_STR(NINLIL_DV_STR_HEAD);
        NEED_STR(NINLIL_DV_STR_PVD);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_VALUE);
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "envelope_decode") == 0) {
        NEED_STR(NINLIL_DV_STR_VALUE);
    } else if (strcmp(op, "health_source_id") == 0) {
        NEED_NUM(NINLIL_DV_NUM_PRIORITY);
        NEED_NUM(NINLIL_DV_NUM_SOURCE_KIND);
        NEED_STR(NINLIL_DV_STR_IDENTITY);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "commit_fence_digest") == 0) {
        NEED_NUM(NINLIL_DV_NUM_FENCE_KIND);
        NEED_STR(NINLIL_DV_STR_IDENTITY);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "witness_identity_digest") == 0) {
        NEED_NUM(NINLIL_DV_NUM_OPERATION_KIND);
        NEED_STR(NINLIL_DV_STR_IDENTITY);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "witness_chunk_decode") == 0
        || strcmp(op, "witness_chunk_roundtrip") == 0) {
        NEED_STR(NINLIL_DV_STR_VALUE);
    } else if (strcmp(op, "witness_manifest_stream") == 0) {
        NEED_NUM(NINLIL_DV_NUM_MEMBER_COUNT);
        NEED_NUM(NINLIL_DV_NUM_CHUNK_COUNT);
        NEED_NUM(NINLIL_DV_NUM_KEY_LENGTH);
        NEED_STR(NINLIL_DV_STR_CHUNKS);
        NEED_STR(NINLIL_DV_STR_DIGEST);
        NEED_STR(NINLIL_DV_STR_DIGEST2);
    } else if (strcmp(op, "blob_chunk_data_len") == 0) {
        NEED_NUM(NINLIL_DV_NUM_BODY_LENGTH);
    } else if (strcmp(op, "chunk_count") == 0) {
        NEED_NUM(NINLIL_DV_NUM_MEMBER_COUNT);
        if (ok) {
            NEED_NUM(NINLIL_DV_NUM_CHUNK_COUNT);
        }
    } else if (strcmp(op, "canonical_operation_digest") == 0) {
        NEED_NUM(NINLIL_DV_NUM_OPERATION_KIND);
        NEED_NUM(NINLIL_DV_NUM_RETENTION_KIND);
        NEED_STR(NINLIL_DV_STR_IDENTITY);
        NEED_STR(NINLIL_DV_STR_SUBJECT);
        NEED_STR(NINLIL_DV_STR_MANIFEST);
        NEED_STR(NINLIL_DV_STR_RETENTION);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "witness_header_roundtrip") == 0
        || strcmp(op, "witness_header_encode") == 0) {
        NEED_NUM(NINLIL_DV_NUM_OPERATION_KIND);
        NEED_NUM(NINLIL_DV_NUM_WITNESS_STATE);
        NEED_NUM(NINLIL_DV_NUM_MEMBER_COUNT);
        NEED_NUM(NINLIL_DV_NUM_CHUNK_COUNT);
        NEED_NUM(NINLIL_DV_NUM_RETENTION_KIND);
        NEED_STR(NINLIL_DV_STR_IDENTITY);
        NEED_STR(NINLIL_DV_STR_SUBJECT);
        NEED_STR(NINLIL_DV_STR_DIGEST);
        NEED_STR(NINLIL_DV_STR_MANIFEST);
        NEED_STR(NINLIL_DV_STR_RETENTION);
        NEED_STR(NINLIL_DV_STR_SUCCESSOR);
        if (strcmp(op, "witness_header_roundtrip") == 0 && ok) {
            NEED_STR(NINLIL_DV_STR_VALUE);
        }
    } else if (strcmp(op, "witness_header_decode") == 0) {
        NEED_STR(NINLIL_DV_STR_VALUE);
    } else if (strcmp(op, "primary_id") == 0) {
        NEED_NUM(NINLIL_DV_NUM_IDENTITY_KIND);
        if (strcmp(v->id, "DSK1_PRIMARY_MALFORMED_VIEW") == 0) {
            NEED_NUM(NINLIL_DV_NUM_BODY_LENGTH);
        } else {
            NEED_STR(NINLIL_DV_STR_IDENTITY);
        }
        if (ok) {
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else if (strcmp(op, "body_encode") == 0
        || strcmp(op, "body_decode") == 0
        || strcmp(op, "body_roundtrip") == 0) {
        NEED_NUM(NINLIL_DV_NUM_FAMILY);
        NEED_NUM(NINLIL_DV_NUM_SUBTYPE);
        NEED_STR(NINLIL_DV_STR_BODY);
        if (strcmp(op, "body_encode") == 0 || strcmp(op, "body_roundtrip") == 0) {
            NEED_NUM(NINLIL_DV_NUM_BODY_LENGTH);
        }
    } else if (strcmp(op, "typed_record") == 0) {
        NEED_NUM(NINLIL_DV_NUM_FAMILY);
        NEED_NUM(NINLIL_DV_NUM_SUBTYPE);
        NEED_STR(NINLIL_DV_STR_KEY);
        NEED_STR(NINLIL_DV_STR_VALUE);
        if (ok) {
            NEED_STR(NINLIL_DV_STR_BODY);
            NEED_STR(NINLIL_DV_STR_DIGEST);
        }
    } else {
        set_err(err, err_cap, "unknown op");
        return -1;
    }
#undef NEED_STR
#undef NEED_NUM
    return 0;
}

static int set_u32_field(
    ninlil_dv_vector_t *v,
    const char *key,
    uint32_t value,
    char *err,
    size_t err_cap)
{
#define SETU(name, field, nbit, mbit)                                          \
    if (strcmp(key, name) == 0) {                                              \
        if ((v->num_bits & (nbit)) != 0u) {                                    \
            set_err(err, err_cap, "duplicate " name);                          \
            return -1;                                                         \
        }                                                                      \
        v->field = value;                                                      \
        v->num_bits |= (nbit);                                                 \
        v->mand_bits |= (mbit);                                                \
        return 0;                                                              \
    }
    SETU("required_workspace_bytes", required_workspace_bytes,
        NINLIL_DV_NUM_WORKSPACE, NINLIL_DV_MAND_WORKSPACE)
    SETU("family", family, NINLIL_DV_NUM_FAMILY, 0u)
    SETU("subtype", subtype, NINLIL_DV_NUM_SUBTYPE, 0u)
    SETU("identity_kind", identity_kind, NINLIL_DV_NUM_IDENTITY_KIND, 0u)
    SETU("record_type", record_type, NINLIL_DV_NUM_RECORD_TYPE, 0u)
    SETU("flags", flags, NINLIL_DV_NUM_FLAGS, 0u)
    SETU("revision", revision, NINLIL_DV_NUM_REVISION, 0u)
    SETU("priority", priority, NINLIL_DV_NUM_PRIORITY, 0u)
    SETU("source_kind", source_kind, NINLIL_DV_NUM_SOURCE_KIND, 0u)
    SETU("fence_kind", fence_kind, NINLIL_DV_NUM_FENCE_KIND, 0u)
    SETU("operation_kind", operation_kind, NINLIL_DV_NUM_OPERATION_KIND, 0u)
    SETU("member_count", member_count, NINLIL_DV_NUM_MEMBER_COUNT, 0u)
    SETU("chunk_count", chunk_count, NINLIL_DV_NUM_CHUNK_COUNT, 0u)
    SETU("body_length", body_length, NINLIL_DV_NUM_BODY_LENGTH, 0u)
    SETU("key_length", key_length, NINLIL_DV_NUM_KEY_LENGTH, 0u)
    SETU("sha_buffer_length", sha_buffer_length, NINLIL_DV_NUM_SHA_BUFFER, 0u)
    SETU("witness_state", witness_state, NINLIL_DV_NUM_WITNESS_STATE, 0u)
    SETU("retention_kind", retention_kind, NINLIL_DV_NUM_RETENTION_KIND, 0u)
#undef SETU
    set_err(err, err_cap, "unknown numeric key");
    return -1;
}

static int parse_string_array(parse_ctx *c, ninlil_dv_vector_t *v)
{
    if (take(c, '[') != 0) {
        return -1;
    }
    skip_ws(c);
    if (peek(c) == ']') {
        c->p++;
        return 0;
    }
    for (;;) {
        char *tmp = NULL;
        char **nb;
        if (v->chunk_bodies_count >= NINLIL_DV_MAX_CHUNKS) {
            set_err(c->err, c->err_cap, "too many chunk bodies");
            return -1;
        }
        if (parse_string_heap(c, &tmp) != 0) {
            return -1;
        }
        if (v->chunk_bodies_count == v->chunk_bodies_cap) {
            uint32_t nc = v->chunk_bodies_cap == 0u ? 4u : v->chunk_bodies_cap * 2u;
            if (nc > NINLIL_DV_MAX_CHUNKS) {
                nc = NINLIL_DV_MAX_CHUNKS;
            }
            nb = (char **)realloc(
                v->chunk_bodies_hex, (size_t)nc * sizeof(char *));
            if (nb == NULL) {
                free(tmp);
                set_err(c->err, c->err_cap, "oom");
                return -1;
            }
            v->chunk_bodies_hex = nb;
            v->chunk_bodies_cap = nc;
        }
        v->chunk_bodies_hex[v->chunk_bodies_count++] = tmp;
        skip_ws(c);
        if (peek(c) == ',') {
            c->p++;
            continue;
        }
        if (peek(c) == ']') {
            c->p++;
            return 0;
        }
        set_err(c->err, c->err_cap, "expected , or ] in array");
        return -1;
    }
}

static int parse_vector_object(parse_ctx *c, ninlil_dv_vector_t *v)
{
    (void)memset(v, 0, sizeof(*v));
    if (take(c, '{') != 0) {
        return -1;
    }
    skip_ws(c);
    if (peek(c) == '}') {
        c->p++;
        set_err(c->err, c->err_cap, "empty vector object");
        return -1;
    }
    for (;;) {
        char key[64];
        if (parse_string_fixed(c, key, sizeof(key)) != 0) {
            ninlil_dv_vector_clear(v);
            return -1;
        }
        if (take(c, ':') != 0) {
            ninlil_dv_vector_clear(v);
            return -1;
        }
        skip_ws(c);
        if (strcmp(key, "chunk_bodies_hex") == 0) {
            if ((v->str_bits & NINLIL_DV_STR_CHUNKS) != 0u) {
                set_err(c->err, c->err_cap, "duplicate chunk_bodies_hex");
                ninlil_dv_vector_clear(v);
                return -1;
            }
            if (parse_string_array(c, v) != 0) {
                ninlil_dv_vector_clear(v);
                return -1;
            }
            v->str_bits |= NINLIL_DV_STR_CHUNKS;
        } else if (strcmp(key, "sha_bit_length") == 0) {
            uint64_t u = 0u;
            if ((v->num_bits & NINLIL_DV_NUM_SHA_BIT) != 0u) {
                set_err(c->err, c->err_cap, "duplicate sha_bit_length");
                ninlil_dv_vector_clear(v);
                return -1;
            }
            if (parse_u64(c, &u) != 0) {
                ninlil_dv_vector_clear(v);
                return -1;
            }
            v->sha_bit_length = u;
            v->num_bits |= NINLIL_DV_NUM_SHA_BIT;
        } else if (peek(c) == '"') {
            char *value = NULL;
            if (parse_string_heap(c, &value) != 0) {
                ninlil_dv_vector_clear(v);
                return -1;
            }
            if (strcmp(key, "id") == 0) {
                if ((v->mand_bits & NINLIL_DV_MAND_ID) != 0u) {
                    free(value);
                    set_err(c->err, c->err_cap, "duplicate id");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                if (strlen(value) >= NINLIL_DV_MAX_ID) {
                    free(value);
                    set_err(c->err, c->err_cap, "id too long");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                (void)memcpy(v->id, value, strlen(value) + 1u);
                free(value);
                v->mand_bits |= NINLIL_DV_MAND_ID;
            } else if (strcmp(key, "suite") == 0) {
                if ((v->mand_bits & NINLIL_DV_MAND_SUITE) != 0u) {
                    free(value);
                    set_err(c->err, c->err_cap, "duplicate suite");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                if (strlen(value) >= NINLIL_DV_MAX_SUITE) {
                    free(value);
                    set_err(c->err, c->err_cap, "suite too long");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                (void)memcpy(v->suite, value, strlen(value) + 1u);
                free(value);
                v->mand_bits |= NINLIL_DV_MAND_SUITE;
            } else if (strcmp(key, "op") == 0) {
                if ((v->mand_bits & NINLIL_DV_MAND_OP) != 0u) {
                    free(value);
                    set_err(c->err, c->err_cap, "duplicate op");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                if (strlen(value) >= NINLIL_DV_MAX_OP) {
                    free(value);
                    set_err(c->err, c->err_cap, "op too long");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                (void)memcpy(v->op, value, strlen(value) + 1u);
                free(value);
                v->mand_bits |= NINLIL_DV_MAND_OP;
            } else if (strcmp(key, "expected_status") == 0) {
                if ((v->mand_bits & NINLIL_DV_MAND_STATUS) != 0u) {
                    free(value);
                    set_err(c->err, c->err_cap, "duplicate expected_status");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                if (strlen(value) >= NINLIL_DV_MAX_STATUS) {
                    free(value);
                    set_err(c->err, c->err_cap, "status too long");
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
                (void)memcpy(v->expected_status, value, strlen(value) + 1u);
                free(value);
                v->mand_bits |= NINLIL_DV_MAND_STATUS;
            } else if (strcmp(key, "identity_hex") == 0) {
                if (set_heap_string(&v->identity_hex, &v->str_bits,
                        NINLIL_DV_STR_IDENTITY, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "key_hex") == 0) {
                if (set_heap_string(&v->key_hex, &v->str_bits, NINLIL_DV_STR_KEY,
                        value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "value_hex") == 0) {
                if (set_heap_string(&v->value_hex, &v->str_bits,
                        NINLIL_DV_STR_VALUE, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "body_hex") == 0) {
                if (set_heap_string(&v->body_hex, &v->str_bits, NINLIL_DV_STR_BODY,
                        value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "head_hex") == 0) {
                if (set_heap_string(&v->head_hex, &v->str_bits, NINLIL_DV_STR_HEAD,
                        value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "pvd_hex") == 0) {
                if (set_heap_string(&v->pvd_hex, &v->str_bits, NINLIL_DV_STR_PVD,
                        value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "digest_hex") == 0) {
                if (set_heap_string(&v->digest_hex, &v->str_bits,
                        NINLIL_DV_STR_DIGEST, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "digest2_hex") == 0) {
                if (set_heap_string(&v->digest2_hex, &v->str_bits,
                        NINLIL_DV_STR_DIGEST2, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "crc_hex") == 0) {
                if (set_heap_string(&v->crc_hex, &v->str_bits, NINLIL_DV_STR_CRC,
                        value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "notes") == 0) {
                if (set_heap_string(&v->notes, &v->str_bits, NINLIL_DV_STR_NOTES,
                        value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "subject_hex") == 0) {
                if (set_heap_string(&v->subject_hex, &v->str_bits,
                        NINLIL_DV_STR_SUBJECT, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "retention_hex") == 0) {
                if (set_heap_string(&v->retention_hex, &v->str_bits,
                        NINLIL_DV_STR_RETENTION, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "manifest_hex") == 0) {
                if (set_heap_string(&v->manifest_hex, &v->str_bits,
                        NINLIL_DV_STR_MANIFEST, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else if (strcmp(key, "successor_hex") == 0) {
                if (set_heap_string(&v->successor_hex, &v->str_bits,
                        NINLIL_DV_STR_SUCCESSOR, value, c->err, c->err_cap, key)
                    != 0) {
                    ninlil_dv_vector_clear(v);
                    return -1;
                }
            } else {
                free(value);
                set_err(c->err, c->err_cap, "unknown string key");
                ninlil_dv_vector_clear(v);
                return -1;
            }
        } else if (isdigit((unsigned char)peek(c))) {
            uint32_t u = 0u;
            if (parse_u32(c, &u) != 0) {
                ninlil_dv_vector_clear(v);
                return -1;
            }
            if (set_u32_field(v, key, u, c->err, c->err_cap) != 0) {
                ninlil_dv_vector_clear(v);
                return -1;
            }
        } else {
            set_err(c->err, c->err_cap, "unsupported value type");
            ninlil_dv_vector_clear(v);
            return -1;
        }
        skip_ws(c);
        if (peek(c) == ',') {
            c->p++;
            continue;
        }
        if (peek(c) == '}') {
            c->p++;
            break;
        }
        set_err(c->err, c->err_cap, "expected , or } in object");
        ninlil_dv_vector_clear(v);
        return -1;
    }
    if ((v->mand_bits
            & (NINLIL_DV_MAND_ID | NINLIL_DV_MAND_SUITE | NINLIL_DV_MAND_OP
                | NINLIL_DV_MAND_STATUS | NINLIL_DV_MAND_WORKSPACE))
        != (NINLIL_DV_MAND_ID | NINLIL_DV_MAND_SUITE | NINLIL_DV_MAND_OP
            | NINLIL_DV_MAND_STATUS | NINLIL_DV_MAND_WORKSPACE)) {
        set_err(c->err, c->err_cap, "missing mandatory vector field");
        ninlil_dv_vector_clear(v);
        return -1;
    }
    if (!known_suite(v->suite)) {
        set_err(c->err, c->err_cap, "unknown suite");
        ninlil_dv_vector_clear(v);
        return -1;
    }
    if (!known_op(v->op)) {
        set_err(c->err, c->err_cap, "unknown op");
        ninlil_dv_vector_clear(v);
        return -1;
    }
    if (validate_op_fields(v, c->err, c->err_cap) != 0) {
        ninlil_dv_vector_clear(v);
        return -1;
    }
    return 0;
}

static int ensure_cap(ninlil_dv_file_t *f)
{
    size_t nc;
    ninlil_dv_vector_t *nv;
    if (f->vector_count < f->vector_capacity) {
        return 0;
    }
    nc = f->vector_capacity == 0u ? 32u : f->vector_capacity * 2u;
    if (nc > NINLIL_DV_MAX_VECTORS) {
        return -1;
    }
    nv = (ninlil_dv_vector_t *)realloc(
        f->vectors, nc * sizeof(ninlil_dv_vector_t));
    if (nv == NULL) {
        return -1;
    }
    f->vectors = nv;
    f->vector_capacity = nc;
    return 0;
}

static int parse_catalog(parse_ctx *c, ninlil_dv_file_t *file)
{
    ninlil_dv_catalog_t *cat = &file->catalog;
    (void)memset(cat, 0, sizeof(*cat));
    file->catalog_bits = 0u;
    if (take(c, '{') != 0) {
        return -1;
    }
    skip_ws(c);
    if (peek(c) == '}') {
        c->p++;
        set_err(c->err, c->err_cap, "empty catalog");
        return -1;
    }
    for (;;) {
        char key[64];
        uint32_t u = 0u;
        if (parse_string_fixed(c, key, sizeof(key)) != 0
            || take(c, ':') != 0
            || parse_u32(c, &u) != 0) {
            return -1;
        }
#define CAT(name, field, bit)                                                  \
    if (strcmp(key, name) == 0) {                                              \
        if ((file->catalog_bits & (bit)) != 0u) {                              \
            set_err(c->err, c->err_cap, "duplicate catalog key");               \
            return -1;                                                         \
        }                                                                      \
        cat->field = u;                                                        \
        file->catalog_bits |= (bit);                                           \
    } else
        CAT("dsk1_positive_keys", dsk1_positive_keys, NINLIL_DV_CAT_DSK1_KEYS)
        CAT("dsv1_body_exact", dsv1_body_exact, NINLIL_DV_CAT_DSV1_EXACT)
        CAT("dsv1_body_plus1", dsv1_body_plus1, NINLIL_DV_CAT_DSV1_PLUS1)
        CAT("dsh2_health_positive", dsh2_health_positive, NINLIL_DV_CAT_DSH2_HEALTH)
        CAT("dsh2_fence_positive", dsh2_fence_positive, NINLIL_DV_CAT_DSH2_FENCE)
        CAT("dso2_kind_positive", dso2_kind_positive, NINLIL_DV_CAT_DSO2_KIND)
        CAT("dso2_canonical_positive", dso2_canonical_positive,
            NINLIL_DV_CAT_DSO2_CANON)
        CAT("dsw1_member_stream", dsw1_member_stream, NINLIL_DV_CAT_DSW1_STREAM)
        CAT("dsw1_header_positive", dsw1_header_positive, NINLIL_DV_CAT_DSW1_HEADER)
        CAT("dsk1_primary_id_positive", dsk1_primary_id_positive,
            NINLIL_DV_CAT_DSK1_PRIMARY)
        CAT("dsv1_encode_decode_positive", dsv1_encode_decode_positive,
            NINLIL_DV_CAT_DSV1_ENCDEC)
        CAT("dsb1_subtype_01_positive", dsb1_subtype_01_positive,
            NINLIL_DV_CAT_DSB1_01)
        CAT("dsb1_subtype_60_positive", dsb1_subtype_60_positive,
            NINLIL_DV_CAT_DSB1_60)
        CAT("dsb1_subtype_62_positive", dsb1_subtype_62_positive,
            NINLIL_DV_CAT_DSB1_62)
        CAT("dsb1_subtype_64_positive", dsb1_subtype_64_positive,
            NINLIL_DV_CAT_DSB1_64)
        CAT("dsb1_subtype_7d_positive", dsb1_subtype_7d_positive,
            NINLIL_DV_CAT_DSB1_7D)
        CAT("dsb1_total_positive", dsb1_total_positive, NINLIL_DV_CAT_DSB1_POS)
        CAT("dsb1_total_negative", dsb1_total_negative, NINLIL_DV_CAT_DSB1_NEG)
#undef CAT
        {
            set_err(c->err, c->err_cap, "unknown catalog key");
            return -1;
        }
        skip_ws(c);
        if (peek(c) == ',') {
            c->p++;
            continue;
        }
        if (peek(c) == '}') {
            c->p++;
            if ((file->catalog_bits & NINLIL_DV_CAT_REQUIRED_MASK)
                != NINLIL_DV_CAT_REQUIRED_MASK) {
                set_err(c->err, c->err_cap, "missing catalog key");
                return -1;
            }
            return 0;
        }
        set_err(c->err, c->err_cap, "catalog object syntax");
        return -1;
    }
}

int ninlil_dv_parse_text(
    const char *text,
    size_t text_len,
    ninlil_dv_file_t *out,
    char *err,
    size_t err_cap)
{
    parse_ctx c;
    (void)memset(out, 0, sizeof(*out));
    c.p = text;
    c.end = text + text_len;
    c.err = err;
    c.err_cap = err_cap;
    if (take(&c, '{') != 0) {
        return -1;
    }
    for (;;) {
        char key[64];
        skip_ws(&c);
        if (peek(&c) == '}') {
            c.p++;
            break;
        }
        if (parse_string_fixed(&c, key, sizeof(key)) != 0 || take(&c, ':') != 0) {
            ninlil_dv_free(out);
            return -1;
        }
        skip_ws(&c);
        if (strcmp(key, "version") == 0) {
            if ((out->top_bits & NINLIL_DV_TOP_VERSION) != 0u) {
                set_err(err, err_cap, "duplicate version");
                ninlil_dv_free(out);
                return -1;
            }
            if (parse_u32(&c, &out->version) != 0) {
                ninlil_dv_free(out);
                return -1;
            }
            if (out->version != 1u) {
                set_err(err, err_cap, "version must be 1");
                ninlil_dv_free(out);
                return -1;
            }
            out->top_bits |= NINLIL_DV_TOP_VERSION;
        } else if (strcmp(key, "format") == 0) {
            if ((out->top_bits & NINLIL_DV_TOP_FORMAT) != 0u) {
                set_err(err, err_cap, "duplicate format");
                ninlil_dv_free(out);
                return -1;
            }
            if (parse_string_fixed(&c, out->format, sizeof(out->format)) != 0) {
                ninlil_dv_free(out);
                return -1;
            }
            if (strcmp(out->format, NINLIL_DV_FORMAT_REQUIRED) != 0) {
                set_err(err, err_cap, "invalid format string");
                ninlil_dv_free(out);
                return -1;
            }
            out->top_bits |= NINLIL_DV_TOP_FORMAT;
        } else if (strcmp(key, "scope") == 0) {
            if ((out->top_bits & NINLIL_DV_TOP_SCOPE) != 0u) {
                set_err(err, err_cap, "duplicate scope");
                ninlil_dv_free(out);
                return -1;
            }
            if (parse_string_fixed(&c, out->scope, sizeof(out->scope)) != 0) {
                ninlil_dv_free(out);
                return -1;
            }
            if (strcmp(out->scope, NINLIL_DV_SCOPE_REQUIRED) != 0) {
                set_err(err, err_cap, "invalid scope string");
                ninlil_dv_free(out);
                return -1;
            }
            out->top_bits |= NINLIL_DV_TOP_SCOPE;
        } else if (strcmp(key, "required_workspace_bytes_definition") == 0) {
            char *tmp = NULL;
            if ((out->top_bits & NINLIL_DV_TOP_WS_DEF) != 0u) {
                set_err(err, err_cap, "duplicate workspace definition");
                ninlil_dv_free(out);
                return -1;
            }
            if (parse_string_heap(&c, &tmp) != 0) {
                ninlil_dv_free(out);
                return -1;
            }
            free(tmp);
            out->top_bits |= NINLIL_DV_TOP_WS_DEF;
        } else if (strcmp(key, "catalog") == 0) {
            if ((out->top_bits & NINLIL_DV_TOP_CATALOG) != 0u) {
                set_err(err, err_cap, "duplicate catalog");
                ninlil_dv_free(out);
                return -1;
            }
            if (parse_catalog(&c, out) != 0) {
                ninlil_dv_free(out);
                return -1;
            }
            out->top_bits |= NINLIL_DV_TOP_CATALOG;
        } else if (strcmp(key, "vectors") == 0) {
            if ((out->top_bits & NINLIL_DV_TOP_VECTORS) != 0u) {
                set_err(err, err_cap, "duplicate vectors");
                ninlil_dv_free(out);
                return -1;
            }
            if (take(&c, '[') != 0) {
                ninlil_dv_free(out);
                return -1;
            }
            skip_ws(&c);
            if (peek(&c) != ']') {
                for (;;) {
                    ninlil_dv_vector_t vec;
                    size_t i;
                    if (ensure_cap(out) != 0) {
                        set_err(err, err_cap, "too many vectors");
                        ninlil_dv_free(out);
                        return -1;
                    }
                    if (parse_vector_object(&c, &vec) != 0) {
                        ninlil_dv_free(out);
                        return -1;
                    }
                    for (i = 0u; i < out->vector_count; ++i) {
                        if (strcmp(out->vectors[i].id, vec.id) == 0) {
                            set_err(err, err_cap, "duplicate vector id");
                            ninlil_dv_vector_clear(&vec);
                            ninlil_dv_free(out);
                            return -1;
                        }
                    }
                    out->vectors[out->vector_count++] = vec;
                    skip_ws(&c);
                    if (peek(&c) == ',') {
                        c.p++;
                        continue;
                    }
                    if (peek(&c) == ']') {
                        break;
                    }
                    set_err(err, err_cap, "vectors array syntax");
                    ninlil_dv_free(out);
                    return -1;
                }
            }
            if (take(&c, ']') != 0) {
                ninlil_dv_free(out);
                return -1;
            }
            out->top_bits |= NINLIL_DV_TOP_VECTORS;
        } else {
            set_err(err, err_cap, "unknown top-level key");
            ninlil_dv_free(out);
            return -1;
        }
        skip_ws(&c);
        if (peek(&c) == ',') {
            c.p++;
            continue;
        }
        if (peek(&c) == '}') {
            c.p++;
            break;
        }
        set_err(err, err_cap, "top-level object syntax");
        ninlil_dv_free(out);
        return -1;
    }
    skip_ws(&c);
    if (c.p != c.end) {
        set_err(err, err_cap, "trailing garbage");
        ninlil_dv_free(out);
        return -1;
    }
    if ((out->top_bits & NINLIL_DV_TOP_REQUIRED_MASK)
        != NINLIL_DV_TOP_REQUIRED_MASK) {
        set_err(err, err_cap, "missing top-level key");
        ninlil_dv_free(out);
        return -1;
    }
    if (out->vector_count == 0u) {
        set_err(err, err_cap, "no vectors");
        ninlil_dv_free(out);
        return -1;
    }
    return 0;
}

int ninlil_dv_load_file(
    const char *path,
    ninlil_dv_file_t *out,
    char *err,
    size_t err_cap)
{
    FILE *f;
    long sz;
    char *buf;
    int rc;
    f = fopen(path, "rb");
    if (f == NULL) {
        set_err(err, err_cap, "open failed");
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        set_err(err, err_cap, "seek failed");
        return -1;
    }
    sz = ftell(f);
    if (sz < 0 || sz > 16 * 1024 * 1024) {
        fclose(f);
        set_err(err, err_cap, "file size invalid");
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    buf = (char *)malloc((size_t)sz + 1u);
    if (buf == NULL) {
        fclose(f);
        set_err(err, err_cap, "oom");
        return -1;
    }
    if (fread(buf, 1u, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        set_err(err, err_cap, "read failed");
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);
    rc = ninlil_dv_parse_text(buf, (size_t)sz, out, err, err_cap);
    free(buf);
    return rc;
}

void ninlil_dv_free(ninlil_dv_file_t *file)
{
    size_t i;
    if (file == NULL) {
        return;
    }
    if (file->vectors != NULL) {
        for (i = 0u; i < file->vector_count; ++i) {
            ninlil_dv_vector_clear(&file->vectors[i]);
        }
        free(file->vectors);
    }
    (void)memset(file, 0, sizeof(*file));
}
