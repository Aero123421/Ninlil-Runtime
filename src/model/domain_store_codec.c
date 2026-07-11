#include "domain_store_codec.h"
#include "domain_store_codec_internal.h"

#include <string.h>

static const uint8_t KEY_ROOT[8] = {
    0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
};

static const char PREIMAGE_COMPOSITE[] = "NINLIL-DOMAIN-KEY-V1";
static const char PREIMAGE_KEY_DIGEST[] = "NINLIL-DOMAIN-ENCODED-KEY-V1";
static const char PREIMAGE_HEALTH[] = "NINLIL-DOMAIN-HEALTH-SOURCE-V1";
static const char PREIMAGE_FENCE[] = "NINLIL-DOMAIN-COMMIT-FENCE-V1";
static const char PREIMAGE_MANIFEST[] = "NINLIL-DOMAIN-MANIFEST-V1";
static const char PREIMAGE_OPERATION[] = "NINLIL-DOMAIN-OPERATION-V1";

_Static_assert(
    NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES
        + NINLIL_MODEL_DOMAIN_PRIVATE_BODY_MAX_BYTES
        + NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD
        == NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES,
    "domain envelope bound drift");

/* --- range helpers --- */

int ninlil_model_domain_ranges_are_disjoint(
    const void *left, size_t left_length,
    const void *right, size_t right_length)
{
    uintptr_t ls, rs, le, re;
    if (left_length == 0u || right_length == 0u) {
        return 1;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }
    ls = (uintptr_t)left;
    rs = (uintptr_t)right;
    if (left_length > UINTPTR_MAX - ls || right_length > UINTPTR_MAX - rs) {
        return 0;
    }
    le = ls + left_length;
    re = rs + right_length;
    return le <= rs || re <= ls;
}

int ninlil_model_domain_encode_ranges_are_disjoint(
    const void *input, size_t input_length,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    const int has_in = input != NULL && input_length != 0u;
    const int has_out = out_bytes != NULL && capacity != 0u;
    return (!has_in
            || ninlil_model_domain_ranges_are_disjoint(
                input, input_length, out_length, sizeof(*out_length)))
        && (!has_out
            || ninlil_model_domain_ranges_are_disjoint(
                out_bytes, capacity, out_length, sizeof(*out_length)))
        && (!has_in || !has_out
            || ninlil_model_domain_ranges_are_disjoint(
                input, input_length, out_bytes, capacity));
}

int ninlil_model_domain_bytes_view_shape_is_valid(ninlil_bytes_view_t view)
{
    return (view.length == 0u && view.data == NULL)
        || (view.length > 0u && view.data != NULL);
}

void ninlil_model_domain_encode_u16_be(uint8_t *d, uint16_t v)
{
    d[0] = (uint8_t)(v >> 8u);
    d[1] = (uint8_t)v;
}
void ninlil_model_domain_encode_u32_be(uint8_t *d, uint32_t v)
{
    d[0] = (uint8_t)(v >> 24u);
    d[1] = (uint8_t)(v >> 16u);
    d[2] = (uint8_t)(v >> 8u);
    d[3] = (uint8_t)v;
}
void ninlil_model_domain_encode_u64_be(uint8_t *d, uint64_t v)
{
    ninlil_model_domain_encode_u32_be(d, (uint32_t)(v >> 32u));
    ninlil_model_domain_encode_u32_be(&d[4], (uint32_t)v);
}
uint16_t ninlil_model_domain_decode_u16_be(const uint8_t *s)
{
    return (uint16_t)(((uint16_t)s[0] << 8u) | s[1]);
}
uint32_t ninlil_model_domain_decode_u32_be(const uint8_t *s)
{
    return ((uint32_t)s[0] << 24u) | ((uint32_t)s[1] << 16u)
        | ((uint32_t)s[2] << 8u) | (uint32_t)s[3];
}
uint64_t ninlil_model_domain_decode_u64_be(const uint8_t *s)
{
    return ((uint64_t)ninlil_model_domain_decode_u32_be(s) << 32u)
        | (uint64_t)ninlil_model_domain_decode_u32_be(&s[4]);
}

int ninlil_model_domain_digest_is_zero(
    const uint8_t digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint32_t i;
    for (i = 0u; i < NINLIL_MODEL_DOMAIN_DIGEST_BYTES; ++i) {
        if (digest[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int ninlil_model_domain_id_is_zero(
    const uint8_t id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    uint32_t i;
    for (i = 0u; i < NINLIL_MODEL_DOMAIN_ID_BYTES; ++i) {
        if (id[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int digests_equal(const uint8_t *a, const uint8_t *b);

static int witness_metadata_matrix_ok(
    uint16_t operation_kind,
    ninlil_bytes_view_t operation_identity,
    const uint8_t subject_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint16_t retention_kind,
    const uint8_t retention_subject_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES]);

static int digests_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, NINLIL_MODEL_DOMAIN_DIGEST_BYTES) == 0;
}

static int multi_ranges_ok(const void *const *ptrs, const size_t *lens, size_t n)
{
    size_t i, j;
    for (i = 0u; i < n; ++i) {
        for (j = i + 1u; j < n; ++j) {
            if (!ninlil_model_domain_ranges_are_disjoint(
                    ptrs[i], lens[i], ptrs[j], lens[j])) {
                return 0;
            }
        }
    }
    return 1;
}

/* --- subtype / body max / identity --- */

int ninlil_model_domain_identity_kind_length_is_valid(
    uint8_t identity_kind, uint8_t identity_length)
{
    switch (identity_kind) {
    case NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON:
        return identity_length == 0u;
    case NINLIL_MODEL_DOMAIN_ID_KIND_ID128:
        return identity_length == 16u;
    case NINLIL_MODEL_DOMAIN_ID_KIND_U64:
        return identity_length == 8u;
    case NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_RAW:
    case NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE:
        return identity_length == 32u;
    default:
        return 0;
    }
}

static int subtype_expected_kind(uint8_t family, uint8_t subtype, uint8_t *out)
{
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH) {
        if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
            *out = NINLIL_MODEL_DOMAIN_ID_KIND_ID128;
            return 1;
        }
        return 0;
    }
    if (family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return 0;
    }
    switch (subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE:
        *out = NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON;
        return 1;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
        *out = NINLIL_MODEL_DOMAIN_ID_KIND_ID128;
        return 1;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS:
        *out = NINLIL_MODEL_DOMAIN_ID_KIND_U64;
        return 1;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER:
        *out = NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE;
        return 1;
    default:
        return 0;
    }
}

int ninlil_model_domain_subtype_is_known(uint8_t family, uint8_t subtype)
{
    uint8_t k;
    return subtype_expected_kind(family, subtype, &k);
}

int ninlil_model_domain_max_body_for_subtype(
    uint8_t family, uint8_t subtype, uint32_t *out_max)
{
    if (out_max == NULL) {
        return 0;
    }
    *out_max = 0u;
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH) {
        if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
            *out_max = 96u; /* section 6 exact body */
            return 1;
        }
        return 0;
    }
    if (family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return 0;
    }
    switch (subtype) {
    case 0x10u: *out_max = 768u; return 1;
    case 0x11u: *out_max = 512u; return 1;
    case 0x20u: *out_max = 1536u; return 1;
    case 0x21u: *out_max = 64u; return 1;
    case 0x22u: *out_max = 512u; return 1;
    case 0x23u: *out_max = 512u; return 1;
    case 0x24u: *out_max = 512u; return 1;
    case 0x25u: *out_max = 512u; return 1;
    case 0x26u: *out_max = 512u; return 1;
    case 0x27u: *out_max = 1536u; return 1;
    case 0x30u: *out_max = 3264u; return 1;
    case 0x31u: *out_max = 512u; return 1;
    case 0x32u: *out_max = 1024u; return 1;
    case 0x33u: *out_max = 512u; return 1;
    case 0x34u: *out_max = 128u; return 1;
    case 0x40u: *out_max = 1024u; return 1;
    case 0x41u: *out_max = 1024u; return 1;
    case 0x42u: *out_max = 3264u; return 1;
    case 0x50u: *out_max = 1536u; return 1;
    case 0x51u: *out_max = 768u; return 1;
    case 0x52u: *out_max = 1024u; return 1;
    case 0x60u: *out_max = 64u; return 1;
    case 0x61u: *out_max = 512u; return 1;
    case 0x62u: *out_max = 64u; return 1;
    case 0x63u: *out_max = 512u; return 1;
    case 0x64u: *out_max = 64u; return 1;
    case 0x7du: *out_max = 192u; return 1;
    case 0x7eu: *out_max = 3000u; return 1;
    case 0x7fu: *out_max = 384u; return 1;
    default: return 0;
    }
}

ninlil_status_t ninlil_model_domain_expected_identity_kind(
    uint8_t family, uint8_t subtype, uint8_t *out_kind)
{
    if (out_kind == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_kind = 0u;
    if (!subtype_expected_kind(family, subtype, out_kind)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_max_body_bytes(
    uint8_t family, uint8_t subtype, uint32_t *out_max_body)
{
    if (out_max_body == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_max_body = 0u;
    if (!ninlil_model_domain_max_body_for_subtype(family, subtype, out_max_body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

static int flags_are_valid_for_subtype(uint8_t subtype, uint8_t flags)
{
    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB) {
        return flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST
            || flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK;
    }
    return flags == 0u;
}

/* --- CRC32C --- */

uint32_t ninlil_model_domain_crc32c(const uint8_t *bytes, uint32_t length)
{
    uint32_t crc = UINT32_MAX;
    uint32_t i;
    if (bytes == NULL && length != 0u) {
        return 0u;
    }
    for (i = 0u; i < length; ++i) {
        uint32_t bit;
        crc ^= bytes[i];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1u) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

/* --- SHA-256 --- */

static const uint32_t SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static uint32_t rotr32(uint32_t v, uint32_t n)
{
    return (v >> n) | (v << (32u - n));
}

static void sha256_process_block(
    ninlil_model_domain_sha256_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t w[64], a,b,c,d,e,f,g,h,i;
    for (i = 0u; i < 16u; ++i) {
        w[i] = ninlil_model_domain_decode_u32_be(&block[i * 4u]);
    }
    for (i = 16u; i < 64u; ++i) {
        const uint32_t s0 = rotr32(w[i - 15u], 7u) ^ rotr32(w[i - 15u], 18u)
            ^ (w[i - 15u] >> 3u);
        const uint32_t s1 = rotr32(w[i - 2u], 17u) ^ rotr32(w[i - 2u], 19u)
            ^ (w[i - 2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i = 0u; i < 64u; ++i) {
        const uint32_t S1 = rotr32(e,6u)^rotr32(e,11u)^rotr32(e,25u);
        const uint32_t ch = (e&f)^((~e)&g);
        const uint32_t t1 = h+S1+ch+SHA256_K[i]+w[i];
        const uint32_t S0 = rotr32(a,2u)^rotr32(a,13u)^rotr32(a,22u);
        const uint32_t maj = (a&b)^(a&c)^(b&c);
        const uint32_t t2 = S0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void ninlil_model_domain_sha256_init(ninlil_model_domain_sha256_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

static int sha256_ctx_structurally_valid(
    const ninlil_model_domain_sha256_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    /* Completed-block bit length is always a multiple of 512. */
    if ((ctx->bit_length & 511u) != 0u) {
        return 0;
    }
    if (ctx->buffer_length > 63u) {
        return 0;
    }
    return 1;
}

/*
 * Append bytes without message-bit limit (used for padding in final).
 * When a full block is processed, completed-block bit accounting may wrap
 * past UINT64_MAX for padding after a max-length message; that is intentional
 * because total message bits were captured before padding.
 */
static void sha256_absorb(
    ninlil_model_domain_sha256_ctx_t *ctx,
    const uint8_t *data,
    uint32_t length)
{
    uint32_t offset = 0u;
    while (offset < length) {
        const uint32_t space = 64u - ctx->buffer_length;
        const uint32_t remaining = length - offset;
        const uint32_t take = remaining < space ? remaining : space;
        (void)memcpy(&ctx->buffer[ctx->buffer_length], &data[offset], take);
        ctx->buffer_length += take;
        offset += take;
        if (ctx->buffer_length == 64u) {
            sha256_process_block(ctx, ctx->buffer);
            ctx->bit_length += 512u; /* may wrap for padding only */
            ctx->buffer_length = 0u;
        }
    }
}

ninlil_status_t ninlil_model_domain_sha256_update(
    ninlil_model_domain_sha256_ctx_t *ctx,
    const uint8_t *data, uint32_t length)
{
    uint64_t incoming_bits;
    uint64_t buffered_bits;
    uint64_t known_bits;

    if (ctx == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (length == 0u) {
        return NINLIL_OK;
    }
    if (data == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Reject data↔ctx overlap before any absorb/memcpy (C11 alias UB). */
    if (!ninlil_model_domain_ranges_are_disjoint(
            data, length, ctx, sizeof(*ctx))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!sha256_ctx_structurally_valid(ctx)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Message bits (not padding) must fit in the 64-bit length field:
     * completed blocks + buffered + incoming <= UINT64_MAX bits.
     */
    incoming_bits = (uint64_t)length * 8u;
    buffered_bits = (uint64_t)ctx->buffer_length * 8u;
    if (buffered_bits > UINT64_MAX - ctx->bit_length) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    known_bits = ctx->bit_length + buffered_bits;
    if (incoming_bits > UINT64_MAX - known_bits) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    sha256_absorb(ctx, data, length);
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_sha256_final(
    ninlil_model_domain_sha256_ctx_t *ctx,
    ninlil_model_domain_digest_t *out_digest)
{
    uint8_t padding[128];
    uint64_t total_bits;
    uint32_t pad_length;
    uint32_t index;

    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ctx != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            ctx, sizeof(*ctx), out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (ctx == NULL || !sha256_ctx_structurally_valid(ctx)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Message bit length before padding (padding is not message content). */
    total_bits = ctx->bit_length + ((uint64_t)ctx->buffer_length * 8u);
    (void)memset(padding, 0, sizeof(padding));
    padding[0] = 0x80u;
    if (ctx->buffer_length < 56u) {
        pad_length = 56u - ctx->buffer_length;
    } else {
        pad_length = 64u - ctx->buffer_length + 56u;
    }
    /* pad_length zeros after 0x80 already; absorb 0x80 + zeros */
    sha256_absorb(ctx, padding, pad_length);
    (void)memset(padding, 0, 8u);
    ninlil_model_domain_encode_u32_be(&padding[0], (uint32_t)(total_bits >> 32u));
    ninlil_model_domain_encode_u32_be(&padding[4], (uint32_t)total_bits);
    sha256_absorb(ctx, padding, 8u);
    for (index = 0u; index < 8u; ++index) {
        ninlil_model_domain_encode_u32_be(
            &out_digest->bytes[index * 4u], ctx->state[index]);
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_sha256(
    const uint8_t *data, uint32_t length,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_status_t status;
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (length != 0u && data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            data, length, out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if ((length == 0u && data != NULL) || (length > 0u && data == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(&ctx, data, length);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    return ninlil_model_domain_sha256_final(&ctx, out_digest);
}



/* --- operation identity / health / fence registries --- */

ninlil_status_t ninlil_model_domain_operation_identity_length(
    uint16_t operation_kind, uint16_t *out_length)
{
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    switch (operation_kind) {
    case 1u: *out_length = 32u; return NINLIL_OK;
    case 2u: case 3u: *out_length = 16u; return NINLIL_OK;
    case 4u: *out_length = 8u; return NINLIL_OK;
    case 5u: *out_length = 32u; return NINLIL_OK;
    case 6u: *out_length = 40u; return NINLIL_OK;
    case 7u: case 8u: *out_length = 8u; return NINLIL_OK;
    /*
     * D1 pre-alpha operation identity correction: kind 9/10 add phase:u16
     * (docs17 §10). Exact 42 = digest[32] || token_generation:u64 || phase:u16.
     * Legacy 40-byte form is not accepted.
     */
    case 9u: case 10u: *out_length = 42u; return NINLIL_OK;
    case 11u: *out_length = 50u; return NINLIL_OK;
    case 12u: *out_length = 42u; return NINLIL_OK;
    case 13u: *out_length = 8u; return NINLIL_OK;
    case 14u: *out_length = 42u; return NINLIL_OK;
    case 15u: case 16u: *out_length = 32u; return NINLIL_OK;
    case 17u: *out_length = 14u; return NINLIL_OK;
    case 18u: *out_length = 42u; return NINLIL_OK;
    case 19u: *out_length = 24u; return NINLIL_OK;
    case 20u: *out_length = 8u; return NINLIL_OK;
    case 21u: *out_length = 66u; return NINLIL_OK;
    default: return NINLIL_E_INVALID_ARGUMENT;
    }
}

static int be64_is_nonzero(const uint8_t *p)
{
    return ninlil_model_domain_decode_u64_be(p) != 0u;
}

static int id16_field_nonzero(const uint8_t *p)
{
    return !ninlil_model_domain_id_is_zero(p);
}

int ninlil_model_domain_operation_identity_is_valid(
    uint16_t operation_kind, ninlil_bytes_view_t operation_identity)
{
    uint16_t expected = 0u;
    uint16_t phase;
    uint16_t resource_kind;
    uint32_t blocked;
    uint64_t epoch;
    const uint8_t *d;

    if (!ninlil_model_domain_bytes_view_shape_is_valid(operation_identity)
        || ninlil_model_domain_operation_identity_length(
            operation_kind, &expected) != NINLIL_OK
        || operation_identity.length != expected
        || expected == 0u) {
        return 0;
    }
    d = operation_identity.data;
    /* Kind-specific closed fields (docs17 section 10 identity table). */
    switch (operation_kind) {
    case 1u: /* service_complete_key_digest[32] — opaque digest */
    case 5u: /* attempt_complete_key_digest[32] */
        return 1;
    case 2u:
    case 3u: /* transaction_id[16] must be nonzero */
        return id16_field_nonzero(d);
    case 4u:
    case 7u:
    case 8u:
    case 13u: /* ordered_sequence:u64 must be nonzero (family-3 sequence) */
        return be64_is_nonzero(d);
    case 6u: /* digest[32] || post_send_operation_generation:u64 */
        return be64_is_nonzero(&d[32]);
    case 9u:
    case 10u:
        /*
         * digest[32] || token_generation:u64 || phase:u16.
         * Kind 9 phase ∈ {1 SUCCESS, 2 COUNTER_EXHAUSTED}.
         * Kind 10 phase ∈ {1 COMPLETE, 2 TOKEN_TIMEOUT}.
         */
        phase = ninlil_model_domain_decode_u16_be(&d[40]);
        return be64_is_nonzero(&d[32]) && phase >= 1u && phase <= 2u;
    case 11u: /* delivery[32] || reconcile_retry:u64 || inv:u64 || phase:u16 */
        phase = ninlil_model_domain_decode_u16_be(&d[48]);
        return be64_is_nonzero(&d[32])
            && be64_is_nonzero(&d[40])
            && phase >= 1u && phase <= 3u;
    case 12u: /* cancel[32] || post_revision:u64 || phase:u16 */
        phase = ninlil_model_domain_decode_u16_be(&d[40]);
        return be64_is_nonzero(&d[32])
            && phase >= 1u && phase <= 4u;
    case 14u: /* subject[32] || phase:u16 || post_revision:u64 */
        phase = ninlil_model_domain_decode_u16_be(&d[32]);
        return phase >= 1u && phase <= 5u
            && be64_is_nonzero(&d[34]);
    case 15u:
    case 16u: /* transaction_id[16] || operation_id[16] — both nonzero */
        return id16_field_nonzero(d) && id16_field_nonzero(&d[16]);
    case 17u: /* resource_kind:u16 || epoch:u64 || blocked:u32 */
        resource_kind = ninlil_model_domain_decode_u16_be(d);
        epoch = ninlil_model_domain_decode_u64_be(&d[2]);
        blocked = ninlil_model_domain_decode_u32_be(&d[10]);
        return resource_kind >= 1u && resource_kind <= 11u
            && epoch != 0u
            && blocked <= 1u;
    case 18u: /* plan[32] || cleanup_phase:u16 || batch:u64 */
        phase = ninlil_model_domain_decode_u16_be(&d[32]);
        return phase >= 1u && phase <= 3u
            && be64_is_nonzero(&d[34]);
    case 19u: /* runtime_id[16] || clock_publish_generation:u64 — both nonzero */
        return id16_field_nonzero(d) && be64_is_nonzero(&d[16]);
    case 20u:
        /*
         * BEARER_STATE availability_epoch is non-zero and strictly increasing
         * after first observation (docs17 section 8.6 / kind 20 identity).
         */
        return be64_is_nonzero(d);
    case 21u: /* target[32] || old[32] || recovery_action:u16 */
        phase = ninlil_model_domain_decode_u16_be(&d[64]);
        return phase >= 1u && phase <= 3u;
    default:
        return 0;
    }
}


static int health_identity_contents_ok(
    uint16_t source_kind,
    ninlil_bytes_view_t identity)
{
    uint16_t stage;
    uint16_t method;
    uint16_t timer_kind;
    uint16_t event_kind;
    const uint8_t *d = identity.data;

    switch (source_kind) {
    case 1u: /* CREATE_STORAGE_FAILURE: stage:u16 || method:u16 || ordinal:u32 */
        if (identity.length != 8u) {
            return 0;
        }
        stage = ninlil_model_domain_decode_u16_be(d);
        method = ninlil_model_domain_decode_u16_be(&d[2]);
        return stage >= 1u && stage <= 8u
            && method >= 1u && method <= 11u;
    case 5u: /* CLOCK_FENCE: owner[32] || timer_kind:u16 || epoch[16] */
        if (identity.length != 50u) {
            return 0;
        }
        timer_kind = ninlil_model_domain_decode_u16_be(&d[32]);
        /* Non-zero stored clock epoch required for durable CLOCK_FENCE. */
        return timer_kind >= 1u && timer_kind <= 8u
            && !ninlil_model_domain_id_is_zero(&d[34]);
    case 8u: /* EVENT_COUNTER: tx_key_digest[32] || event_counter_kind:u16 */
        if (identity.length != 34u) {
            return 0;
        }
        event_kind = ninlil_model_domain_decode_u16_be(&d[32]);
        return event_kind >= 1u && event_kind <= 5u;
    default:
        /* Other kinds are opaque digests/fixed lengths already gated. */
        return 1;
    }
}

ninlil_status_t ninlil_model_domain_health_registry_validate(
    uint8_t priority, uint16_t source_kind, uint16_t source_identity_length)
{
    /* Priority 5 has no durable source. */
    if (priority == 5u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (priority == 1u && source_kind == 1u
        && source_identity_length == 8u) {
        return NINLIL_OK;
    }
    if (priority == 2u && source_kind == 2u
        && source_identity_length == 32u) {
        return NINLIL_OK;
    }
    if (priority == 3u && source_kind == 3u
        && source_identity_length == 32u) {
        return NINLIL_OK;
    }
    if (priority == 4u && source_kind == 4u
        && source_identity_length == 32u) {
        return NINLIL_OK;
    }
    if (priority == 6u && source_kind == 5u
        && source_identity_length == 50u) {
        return NINLIL_OK;
    }
    if (priority == 7u) {
        if (source_kind == 6u && source_identity_length == 32u) {
            return NINLIL_OK;
        }
        if (source_kind == 7u && source_identity_length == 32u) {
            return NINLIL_OK;
        }
        if (source_kind == 8u && source_identity_length == 34u) {
            return NINLIL_OK;
        }
        if (source_kind == 9u && source_identity_length == 32u) {
            return NINLIL_OK;
        }
        if (source_kind == 10u && source_identity_length == 32u) {
            return NINLIL_OK;
        }
        if (source_kind == 12u && source_identity_length == 32u) {
            return NINLIL_OK;
        }
    }
    if (priority == 8u && source_kind == 11u
        && source_identity_length == 32u) {
        return NINLIL_OK;
    }
    return NINLIL_E_INVALID_ARGUMENT;
}

ninlil_status_t ninlil_model_domain_fence_registry_validate(
    uint16_t fence_kind, uint16_t fence_identity_length)
{
    switch (fence_kind) {
    case NINLIL_MODEL_DOMAIN_FENCE_KIND_WITNESS:
        return fence_identity_length == 32u
            ? NINLIL_OK : NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_MODEL_DOMAIN_FENCE_KIND_BOOTSTRAP:
        return fence_identity_length == 8u
            ? NINLIL_OK : NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_MODEL_DOMAIN_FENCE_KIND_CLOCK_BASELINE:
    case NINLIL_MODEL_DOMAIN_FENCE_KIND_IDENTITY_ROTATION:
        return fence_identity_length == 32u
            ? NINLIL_OK : NINLIL_E_INVALID_ARGUMENT;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

/* --- keys --- */

static int current_key_fields_ok(
    uint8_t family, uint8_t subtype, uint8_t key_format,
    uint8_t identity_kind, uint8_t identity_length, uint32_t total_len)
{
    uint8_t expected_kind;
    if (key_format != NINLIL_MODEL_DOMAIN_KEY_FORMAT_V1
        || total_len != 13u + (uint32_t)identity_length
        || total_len < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES
        || total_len > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES
        || !subtype_expected_kind(family, subtype, &expected_kind)
        || identity_kind != expected_kind
        || !ninlil_model_domain_identity_kind_length_is_valid(
            identity_kind, identity_length)) {
        return 0;
    }
    return 1;
}

ninlil_status_t ninlil_model_domain_build_key(
    uint8_t family, uint8_t subtype, uint8_t identity_kind,
    ninlil_bytes_view_t identity, ninlil_model_domain_key_t *out_key)
{
    uint8_t expected_kind;
    uint32_t total;
    if (out_key == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (identity.length != 0u && identity.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            identity.data, identity.length, out_key, sizeof(*out_key))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_key, 0, sizeof(*out_key));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(identity)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!subtype_expected_kind(family, subtype, &expected_kind)
        || identity_kind != expected_kind
        || identity.length > 255u
        || !ninlil_model_domain_identity_kind_length_is_valid(
            identity_kind, (uint8_t)identity.length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    total = 13u + identity.length;
    if (total < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES
        || total > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(out_key->bytes, KEY_ROOT, 8u);
    out_key->bytes[8] = family;
    out_key->bytes[9] = subtype;
    out_key->bytes[10] = NINLIL_MODEL_DOMAIN_KEY_FORMAT_V1;
    out_key->bytes[11] = identity_kind;
    out_key->bytes[12] = (uint8_t)identity.length;
    if (identity.length != 0u) {
        (void)memcpy(&out_key->bytes[13], identity.data, identity.length);
    }
    out_key->length = total;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_classify_key(
    ninlil_bytes_view_t encoded_key,
    ninlil_model_domain_key_class_t *out_class)
{
    /* Key-only structural classification (not full future-row predicate). */
    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded_key.length != 0u && encoded_key.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded_key.data, encoded_key.length, out_class, sizeof(*out_class))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = (ninlil_model_domain_key_class_t)0;
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded_key)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_MODEL_DOMAIN_KEY_CLASS_MALFORMED;
    if (encoded_key.length == 0u
        || encoded_key.length > NINLIL_MODEL_DOMAIN_KEY_MAX_BYTES) {
        return NINLIL_OK;
    }
    if (encoded_key.length >= 8u
        && memcmp(encoded_key.data, KEY_ROOT, 7u) == 0
        && encoded_key.data[7] >= 2u
        && encoded_key.length <= NINLIL_MODEL_DOMAIN_KEY_MAX_BYTES) {
        *out_class = NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE;
        return NINLIL_OK;
    }
    if (encoded_key.length < 8u
        || memcmp(encoded_key.data, KEY_ROOT, 8u) != 0) {
        return NINLIL_OK;
    }
    if (encoded_key.length < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES
        || encoded_key.length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
        return NINLIL_OK;
    }
    if (!current_key_fields_ok(
            encoded_key.data[8], encoded_key.data[9], encoded_key.data[10],
            encoded_key.data[11], encoded_key.data[12], encoded_key.length)) {
        return NINLIL_OK;
    }
    *out_class = NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT;
    return NINLIL_OK;
}

static int nlr1_framing_is_valid(ninlil_bytes_view_t value)
{
    uint32_t payload_length;
    uint32_t stored;
    uint32_t computed;
    if (value.length < NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD
        || value.length > NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES
        || value.data == NULL
        || memcmp(value.data, "NLR1", 4u) != 0) {
        return 0;
    }
    payload_length = ninlil_model_domain_decode_u32_be(&value.data[8]);
    if (payload_length
            != value.length - NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD
        || payload_length
            > NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES
                - NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD) {
        return 0;
    }
    stored = ninlil_model_domain_decode_u32_be(
        &value.data[12u + payload_length]);
    computed = ninlil_model_domain_crc32c(value.data, 12u + payload_length);
    return stored == computed;
}

ninlil_status_t ninlil_model_domain_classify_row(
    ninlil_bytes_view_t encoded_key,
    ninlil_bytes_view_t encoded_value,
    ninlil_model_domain_key_class_t *out_class)
{
    ninlil_model_domain_key_class_t key_class;
    ninlil_status_t status;
    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Alias only among real (non-NULL, non-empty) ranges; leave output
     * untouched on alias. Malformed NULL/nonzero views are non-alias errors. */
    if (encoded_key.data != NULL && encoded_key.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded_key.data, encoded_key.length,
            out_class, sizeof(*out_class))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded_value.data != NULL && encoded_value.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded_value.data, encoded_value.length,
            out_class, sizeof(*out_class))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded_key.data != NULL && encoded_key.length != 0u
        && encoded_value.data != NULL && encoded_value.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded_key.data, encoded_key.length,
            encoded_value.data, encoded_value.length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = (ninlil_model_domain_key_class_t)0;
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded_key)
        || !ninlil_model_domain_bytes_view_shape_is_valid(encoded_value)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_MODEL_DOMAIN_KEY_CLASS_MALFORMED;
    status = ninlil_model_domain_classify_key(encoded_key, &key_class);
    if (status != NINLIL_OK) {
        *out_class = (ninlil_model_domain_key_class_t)0;
        return status;
    }
    if (key_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        *out_class = NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT;
        return NINLIL_OK;
    }
    if (encoded_key.length >= 8u
        && encoded_key.length <= NINLIL_MODEL_DOMAIN_KEY_MAX_BYTES
        && memcmp(encoded_key.data, KEY_ROOT, 7u) == 0
        && encoded_key.data[7] >= 2u
        && encoded_value.length >= 16u
        && encoded_value.length <= NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES
        && nlr1_framing_is_valid(encoded_value)) {
        *out_class = NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE;
        return NINLIL_OK;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_parse_key(
    ninlil_bytes_view_t encoded_key,
    ninlil_model_domain_key_view_t *out_view)
{
    ninlil_model_domain_key_class_t key_class;
    ninlil_status_t status;
    if (out_view == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded_key.length != 0u && encoded_key.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded_key.data, encoded_key.length, out_view, sizeof(*out_view))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_view, 0, sizeof(*out_view));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded_key)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_classify_key(encoded_key, &key_class);
    if (status != NINLIL_OK) {
        return status;
    }
    if (key_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        /* Key-side future only; full row needs classify_row. */
        return NINLIL_E_UNSUPPORTED;
    }
    if (key_class != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_view->family = encoded_key.data[8];
    out_view->subtype = encoded_key.data[9];
    out_view->key_format = encoded_key.data[10];
    out_view->identity_kind = encoded_key.data[11];
    out_view->identity_length = encoded_key.data[12];
    out_view->identity = out_view->identity_length == 0u
        ? NULL : &encoded_key.data[13];
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_composite_digest(
    uint8_t subtype, ninlil_bytes_view_t components,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_status_t status;
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (components.length != 0u && components.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            components.data, components.length, out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(components)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_COMPOSITE,
        (uint32_t)(sizeof(PREIMAGE_COMPOSITE) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_sha256_update(&ctx, &subtype, 1u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    if (components.length != 0u) {
        status = ninlil_model_domain_sha256_update(
            &ctx, components.data, components.length);
        if (status != NINLIL_OK) {
            (void)memset(out_digest, 0, sizeof(*out_digest));
            return status;
        }
    }
    return ninlil_model_domain_sha256_final(&ctx, out_digest);
}

ninlil_status_t ninlil_model_domain_key_digest(
    ninlil_bytes_view_t complete_key,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_status_t status;
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (complete_key.length != 0u && complete_key.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            complete_key.data, complete_key.length,
            out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(complete_key)
        || complete_key.length == 0u
        || complete_key.length > NINLIL_MODEL_DOMAIN_KEY_MAX_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_KEY_DIGEST,
        (uint32_t)(sizeof(PREIMAGE_KEY_DIGEST) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_sha256_update(
        &ctx, complete_key.data, complete_key.length);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    return ninlil_model_domain_sha256_final(&ctx, out_digest);
}

ninlil_status_t ninlil_model_domain_primary_id_from_identity(
    uint8_t identity_kind, ninlil_bytes_view_t identity,
    uint8_t out_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    uint32_t expected_length;

    if (out_primary_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (identity.length != 0u && identity.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            identity.data, identity.length,
            out_primary_id, NINLIL_MODEL_DOMAIN_ID_BYTES)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_primary_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
    if (!ninlil_model_domain_bytes_view_shape_is_valid(identity)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Exact kind lengths without lossy uint8 cast: lengths 256/264/272/288
     * must not wrap to 0/8/16/32 and pass.
     */
    if (identity.length > 255u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    switch (identity_kind) {
    case NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON:
        expected_length = 0u;
        break;
    case NINLIL_MODEL_DOMAIN_ID_KIND_ID128:
        expected_length = 16u;
        break;
    case NINLIL_MODEL_DOMAIN_ID_KIND_U64:
        expected_length = 8u;
        break;
    case NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_RAW:
    case NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE:
        expected_length = 32u;
        break;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (identity.length != expected_length) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    switch (identity_kind) {
    case NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON:
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_ID_KIND_ID128:
        (void)memcpy(out_primary_id, identity.data, 16u);
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_ID_KIND_U64:
        (void)memcpy(&out_primary_id[8], identity.data, 8u);
        return NINLIL_OK;
    case NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_RAW:
    case NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE:
        (void)memcpy(out_primary_id, identity.data, 16u);
        return NINLIL_OK;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}


/* --- pure digests --- */

ninlil_status_t ninlil_model_domain_value_digest(
    ninlil_bytes_view_t complete_encoded_value,
    ninlil_model_domain_digest_t *out_digest)
{
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (complete_encoded_value.length != 0u && complete_encoded_value.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            complete_encoded_value.data, complete_encoded_value.length,
            out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(complete_encoded_value)
        || complete_encoded_value.length
            < NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD
        || complete_encoded_value.length
            > NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return ninlil_model_domain_sha256(
        complete_encoded_value.data, complete_encoded_value.length, out_digest);
}

ninlil_status_t ninlil_model_domain_health_source_id(
    uint8_t priority, uint16_t source_kind,
    ninlil_bytes_view_t source_identity,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    uint8_t kind_be[2];
    uint8_t raw16_len[2];
    ninlil_status_t status;
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (source_identity.length != 0u && source_identity.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            source_identity.data, source_identity.length,
            out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(source_identity)
        || source_identity.length > 65535u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ninlil_model_domain_health_registry_validate(
            priority, source_kind, (uint16_t)source_identity.length)
        != NINLIL_OK
        || !health_identity_contents_ok(source_kind, source_identity)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(kind_be, source_kind);
    ninlil_model_domain_encode_u16_be(raw16_len, (uint16_t)source_identity.length);
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_HEALTH,
        (uint32_t)(sizeof(PREIMAGE_HEALTH) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_sha256_update(&ctx, &priority, 1u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    status = ninlil_model_domain_sha256_update(&ctx, kind_be, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    status = ninlil_model_domain_sha256_update(&ctx, raw16_len, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    if (source_identity.length != 0u) {
        status = ninlil_model_domain_sha256_update(
            &ctx, source_identity.data, source_identity.length);
        if (status != NINLIL_OK) {
            (void)memset(out_digest, 0, sizeof(*out_digest));
            return status;
        }
    }
    return ninlil_model_domain_sha256_final(&ctx, out_digest);
}

ninlil_status_t ninlil_model_domain_commit_fence_digest(
    uint16_t fence_kind, ninlil_bytes_view_t fence_identity,
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    uint8_t kind_be[2];
    uint8_t raw16_len[2];
    ninlil_status_t status;
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (fence_identity.length != 0u && fence_identity.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            fence_identity.data, fence_identity.length,
            out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(fence_identity)
        || fence_identity.length > 65535u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ninlil_model_domain_fence_registry_validate(
            fence_kind, (uint16_t)fence_identity.length) != NINLIL_OK) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(kind_be, fence_kind);
    ninlil_model_domain_encode_u16_be(raw16_len, (uint16_t)fence_identity.length);
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_FENCE,
        (uint32_t)(sizeof(PREIMAGE_FENCE) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_sha256_update(&ctx, kind_be, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    status = ninlil_model_domain_sha256_update(&ctx, raw16_len, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    if (fence_identity.length != 0u) {
        status = ninlil_model_domain_sha256_update(
            &ctx, fence_identity.data, fence_identity.length);
        if (status != NINLIL_OK) {
            (void)memset(out_digest, 0, sizeof(*out_digest));
            return status;
        }
    }
    return ninlil_model_domain_sha256_final(&ctx, out_digest);
}

ninlil_status_t ninlil_model_domain_witness_identity_digest(
    uint16_t operation_kind, ninlil_bytes_view_t operation_identity,
    ninlil_model_domain_digest_t *out_digest)
{
    uint8_t components[2u + 2u + NINLIL_MODEL_DOMAIN_OPERATION_IDENTITY_MAX];
    uint32_t length;
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (operation_identity.length != 0u && operation_identity.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            operation_identity.data, operation_identity.length,
            out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(operation_identity)
        || !ninlil_model_domain_operation_identity_is_valid(
            operation_kind, operation_identity)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(components, operation_kind);
    ninlil_model_domain_encode_u16_be(
        &components[2], (uint16_t)operation_identity.length);
    length = 4u;
    if (operation_identity.length != 0u) {
        (void)memcpy(&components[4], operation_identity.data,
            operation_identity.length);
        length += operation_identity.length;
    }
    return ninlil_model_domain_composite_digest(
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER,
        (ninlil_bytes_view_t){components, length}, out_digest);
}

ninlil_status_t ninlil_model_domain_canonical_operation_digest(
    uint16_t operation_kind,
    ninlil_bytes_view_t operation_identity,
    const uint8_t subject_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    const uint8_t manifest_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint16_t retention_kind,
    const uint8_t retention_subject_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    ninlil_model_domain_digest_t *out_digest)
{
    ninlil_model_domain_sha256_ctx_t ctx;
    uint8_t scratch[2];
    ninlil_status_t status;
    const void *ptrs[5];
    size_t lens[5];
    size_t n = 0u;

    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Pairwise alias over every present non-empty range independently of
     * other inputs being NULL. Leave all memory untouched on overlap.
     */
    if (subject_id != NULL) {
        ptrs[n] = subject_id;
        lens[n] = NINLIL_MODEL_DOMAIN_ID_BYTES;
        n++;
    }
    if (manifest_digest != NULL) {
        ptrs[n] = manifest_digest;
        lens[n] = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
        n++;
    }
    if (retention_subject_key_digest != NULL) {
        ptrs[n] = retention_subject_key_digest;
        lens[n] = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
        n++;
    }
    if (operation_identity.data != NULL && operation_identity.length != 0u) {
        ptrs[n] = operation_identity.data;
        lens[n] = operation_identity.length;
        n++;
    }
    ptrs[n] = out_digest;
    lens[n] = sizeof(*out_digest);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (subject_id == NULL || manifest_digest == NULL
        || retention_subject_key_digest == NULL
        || !ninlil_model_domain_bytes_view_shape_is_valid(operation_identity)
        || ninlil_model_domain_digest_is_zero(manifest_digest)
        || !witness_metadata_matrix_ok(
            operation_kind, operation_identity, subject_id,
            retention_kind, retention_subject_key_digest)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_OPERATION,
        (uint32_t)(sizeof(PREIMAGE_OPERATION) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u16_be(scratch, operation_kind);
    status = ninlil_model_domain_sha256_update(&ctx, scratch, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    ninlil_model_domain_encode_u16_be(
        scratch, (uint16_t)operation_identity.length);
    status = ninlil_model_domain_sha256_update(&ctx, scratch, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    if (operation_identity.length != 0u) {
        status = ninlil_model_domain_sha256_update(
            &ctx, operation_identity.data, operation_identity.length);
        if (status != NINLIL_OK) {
            (void)memset(out_digest, 0, sizeof(*out_digest));
            return status;
        }
    }
    status = ninlil_model_domain_sha256_update(
        &ctx, subject_id, NINLIL_MODEL_DOMAIN_ID_BYTES);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    status = ninlil_model_domain_sha256_update(
        &ctx, manifest_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    ninlil_model_domain_encode_u16_be(scratch, retention_kind);
    status = ninlil_model_domain_sha256_update(&ctx, scratch, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    status = ninlil_model_domain_sha256_update(
        &ctx, retention_subject_key_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
    if (status != NINLIL_OK) {
        (void)memset(out_digest, 0, sizeof(*out_digest));
        return status;
    }
    return ninlil_model_domain_sha256_final(&ctx, out_digest);
}

ninlil_status_t ninlil_model_domain_manifest_digest_init(
    ninlil_model_domain_manifest_digest_ctx_t *ctx)
{
    if (ctx == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    ninlil_model_domain_sha256_init(&ctx->sha);
    return ninlil_model_domain_sha256_update(
        &ctx->sha, (const uint8_t *)PREIMAGE_MANIFEST,
        (uint32_t)(sizeof(PREIMAGE_MANIFEST) - 1u));
}

ninlil_status_t ninlil_model_domain_manifest_digest_update(
    ninlil_model_domain_manifest_digest_ctx_t *ctx,
    ninlil_bytes_view_t chunk_body)
{
    ninlil_status_t status;
    if (ctx == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ninlil_model_domain_bytes_view_shape_is_valid(chunk_body)
        || chunk_body.length == 0u
        || chunk_body.length > NINLIL_MODEL_DOMAIN_MANIFEST_CHUNK_BODY_MAX
        || ctx->chunk_bodies_seen >= NINLIL_MODEL_DOMAIN_WITNESS_CHUNK_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Overlap with entire manifest ctx (not only nested SHA). */
    if (!ninlil_model_domain_ranges_are_disjoint(
            chunk_body.data, chunk_body.length, ctx, sizeof(*ctx))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_sha256_update(
        &ctx->sha, chunk_body.data, chunk_body.length);
    if (status != NINLIL_OK) {
        return status;
    }
    ctx->chunk_bodies_seen += 1u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_manifest_digest_final(
    ninlil_model_domain_manifest_digest_ctx_t *ctx,
    ninlil_model_domain_digest_t *out_digest)
{
    if (out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ctx != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            ctx, sizeof(*ctx), out_digest, sizeof(*out_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_digest, 0, sizeof(*out_digest));
    if (ctx == NULL || ctx->chunk_bodies_seen == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return ninlil_model_domain_sha256_final(&ctx->sha, out_digest);
}

/* --- envelope --- */

static int subtype_allows_zero_head(uint8_t family, uint8_t subtype)
{
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
        return 1;
    }
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX;
    }
    return 0;
}

static int subtype_is_immutable_primary(uint8_t family, uint8_t subtype)
{
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
        return 1;
    }
    if (family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return 0;
    }
    return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB; /* manifest only on flag */
}

static int subtype_primary_value_digest_must_zero(
    uint8_t family, uint8_t subtype)
{
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH) {
        return 1;
    }
    if (family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return 0;
    }
    return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK;
}

static int common_header_local_invariants_ok(
    uint8_t family,
    const ninlil_model_domain_common_header_t *header)
{
    const int head_zero = ninlil_model_domain_digest_is_zero(
        header->head_witness_digest);
    const int pvd_zero = ninlil_model_domain_digest_is_zero(
        header->primary_value_digest);
    int immutable;

    if (header->record_revision == 0u) {
        return 0;
    }
    if (!flags_are_valid_for_subtype(header->subtype, header->flags)) {
        return 0;
    }
    /* Head witness zero/nonzero (section 4). */
    if (subtype_allows_zero_head(family, header->subtype)) {
        /* HEAD_INDEX BASELINE zero / WITNESSED non-zero both representable. */
    } else if (head_zero) {
        return 0;
    }
    /* Immutable primary revision 1. BLOB applies to manifest flag only. */
    immutable = subtype_is_immutable_primary(family, header->subtype);
    if (header->subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB) {
        immutable = (header->flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST);
    }
    if (immutable && header->record_revision != 1u) {
        return 0;
    }
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && header->subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT
        && header->record_revision != 1u) {
        return 0;
    }
    /* primary_value_digest zero for primaries; non-zero for secondaries. */
    if (subtype_primary_value_digest_must_zero(family, header->subtype)) {
        if (!pvd_zero) {
            return 0;
        }
    } else if (pvd_zero) {
        return 0;
    }
    return 1;
}

static int common_header_valid_for_encode(
    uint16_t record_type,
    const ninlil_model_domain_common_header_t *header,
    uint32_t body_length)
{
    uint8_t family;
    uint32_t max_body;
    if (header == NULL) {
        return 0;
    }
    if (record_type == NINLIL_MODEL_DOMAIN_RECORD_TYPE_HEALTH) {
        family = NINLIL_MODEL_DOMAIN_FAMILY_HEALTH;
    } else if (record_type == NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN) {
        family = NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN;
    } else {
        return 0;
    }
    if (header->domain_format != NINLIL_MODEL_DOMAIN_FORMAT_VERSION
        || !ninlil_model_domain_max_body_for_subtype(
            family, header->subtype, &max_body)
        || header->body_length != body_length
        || body_length > max_body
        || body_length > NINLIL_MODEL_DOMAIN_PRIVATE_BODY_MAX_BYTES
        || !common_header_local_invariants_ok(family, header)) {
        return 0;
    }
    return 1;
}

static void encode_common_header(
    const ninlil_model_domain_common_header_t *header,
    uint8_t out[NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES])
{
    ninlil_model_domain_encode_u16_be(&out[0], header->domain_format);
    out[2] = header->subtype;
    out[3] = header->flags;
    ninlil_model_domain_encode_u64_be(&out[4], header->record_revision);
    (void)memcpy(&out[12], header->primary_id, 16u);
    (void)memcpy(&out[28], header->head_witness_digest, 32u);
    (void)memcpy(&out[60], header->primary_value_digest, 32u);
    ninlil_model_domain_encode_u32_be(&out[92], header->body_length);
}

ninlil_status_t ninlil_model_domain_encode_envelope(
    uint16_t record_type,
    const ninlil_model_domain_common_header_t *header,
    ninlil_bytes_view_t body,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    uint32_t payload_length;
    uint32_t required;
    uint32_t crc;
    uint8_t common[NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES];
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ninlil_model_domain_encode_ranges_are_disjoint(
            header, header == NULL ? 0u : sizeof(*header),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Alias only when body bytes are real; NULL/nonzero is a later shape error. */
    if (body.data != NULL && body.length != 0u
        && (!ninlil_model_domain_encode_ranges_are_disjoint(
                body.data, body.length, out_bytes, capacity, out_length)
            || (header != NULL
                && !ninlil_model_domain_ranges_are_disjoint(
                    header, sizeof(*header), body.data, body.length)))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !ninlil_model_domain_bytes_view_shape_is_valid(body)
        || !common_header_valid_for_encode(record_type, header, body.length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    payload_length = NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES + body.length;
    required = NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD + payload_length;
    if (required > NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    out_bytes[0] = (uint8_t)'N';
    out_bytes[1] = (uint8_t)'L';
    out_bytes[2] = (uint8_t)'R';
    out_bytes[3] = (uint8_t)'1';
    ninlil_model_domain_encode_u16_be(&out_bytes[4], record_type);
    ninlil_model_domain_encode_u16_be(
        &out_bytes[6], NINLIL_MODEL_DOMAIN_RECORD_VERSION);
    ninlil_model_domain_encode_u32_be(&out_bytes[8], payload_length);
    encode_common_header(header, common);
    (void)memcpy(&out_bytes[12], common, sizeof(common));
    if (body.length != 0u) {
        (void)memcpy(
            &out_bytes[12u + NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES],
            body.data, body.length);
    }
    crc = ninlil_model_domain_crc32c(out_bytes, 12u + payload_length);
    ninlil_model_domain_encode_u32_be(&out_bytes[12u + payload_length], crc);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_envelope(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_envelope_t *out_envelope)
{
    uint16_t record_type;
    uint16_t record_version;
    uint32_t payload_length;
    uint32_t stored_crc;
    uint32_t computed_crc;
    uint8_t family;
    uint32_t max_body;
    uint32_t body_length;

    if (out_envelope == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Alias first: do not modify output on overlap. */
    if (encoded.length != 0u && encoded.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_envelope, sizeof(*out_envelope))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_envelope, 0, sizeof(*out_envelope));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (encoded.length < NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD
        || encoded.length > NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES
        || memcmp(encoded.data, "NLR1", 4u) != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    record_type = ninlil_model_domain_decode_u16_be(&encoded.data[4]);
    record_version = ninlil_model_domain_decode_u16_be(&encoded.data[6]);
    payload_length = ninlil_model_domain_decode_u32_be(&encoded.data[8]);
    if (payload_length
            > NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES
                - NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD
        || payload_length
            != encoded.length - NINLIL_MODEL_DOMAIN_ENVELOPE_OVERHEAD) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    stored_crc = ninlil_model_domain_decode_u32_be(
        &encoded.data[12u + payload_length]);
    computed_crc = ninlil_model_domain_crc32c(
        encoded.data, 12u + payload_length);
    if (stored_crc != computed_crc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_HEALTH
        && record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (record_version == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    /*
     * Future record_version: framing-only contract. Do not parse payload as
     * a v1 common header (would false-corrupt valid future layouts).
     */
    if (record_version != NINLIL_MODEL_DOMAIN_RECORD_VERSION) {
        /* Framing-valid future version: non-alias failure zeros output. */
        return NINLIL_E_UNSUPPORTED;
    }

    /*
     * record_version == 1: domain_format is the next u16 of payload when
     * at least 2 bytes are present. Future domain_format > 1 is UNSUPPORTED
     * without requiring the full 96-byte v1 common header.
     */
    if (payload_length < 2u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    {
        const uint16_t domain_format =
            ninlil_model_domain_decode_u16_be(&encoded.data[12]);
        if (domain_format == 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (domain_format != NINLIL_MODEL_DOMAIN_FORMAT_VERSION) {
            return NINLIL_E_UNSUPPORTED;
        }
    }
    /* Current domain_format == 1: require full common header framing. */
    if (payload_length < NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_envelope->header.domain_format =
        ninlil_model_domain_decode_u16_be(&encoded.data[12]);
    out_envelope->header.subtype = encoded.data[14];
    out_envelope->header.flags = encoded.data[15];
    out_envelope->header.record_revision =
        ninlil_model_domain_decode_u64_be(&encoded.data[16]);
    (void)memcpy(out_envelope->header.primary_id, &encoded.data[24], 16u);
    (void)memcpy(out_envelope->header.head_witness_digest, &encoded.data[40], 32u);
    (void)memcpy(out_envelope->header.primary_value_digest, &encoded.data[72], 32u);
    body_length = ninlil_model_domain_decode_u32_be(&encoded.data[104]);
    out_envelope->header.body_length = body_length;
    if (payload_length
        != NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES + body_length
        || body_length > NINLIL_MODEL_DOMAIN_PRIVATE_BODY_MAX_BYTES) {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (out_envelope->header.domain_format == 0u) {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_envelope->record_type = record_type;
    out_envelope->record_version = record_version;
    out_envelope->body.data = body_length == 0u
        ? NULL : &encoded.data[12u + NINLIL_MODEL_DOMAIN_COMMON_HEADER_BYTES];
    out_envelope->body.length = body_length;
    out_envelope->crc32c = stored_crc;

    if (out_envelope->header.domain_format
        != NINLIL_MODEL_DOMAIN_FORMAT_VERSION) {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (out_envelope->header.record_revision == 0u) {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    family = record_type == NINLIL_MODEL_DOMAIN_RECORD_TYPE_HEALTH
        ? NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        : NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN;
    if (!ninlil_model_domain_max_body_for_subtype(
            family, out_envelope->header.subtype, &max_body)
        || body_length > max_body
        || !common_header_local_invariants_ok(family, &out_envelope->header)) {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}


/* --- witness framing --- */

uint32_t ninlil_model_domain_witness_header_encoded_length(
    uint16_t operation_identity_length)
{
    if (operation_identity_length > NINLIL_MODEL_DOMAIN_OPERATION_IDENTITY_MAX) {
        return 0u;
    }
    return 2u + 2u + 2u + (uint32_t)operation_identity_length
        + 16u + 32u + 2u + 2u + 32u + 2u + 2u + 32u + 32u;
}

uint32_t ninlil_model_domain_witness_entry_encoded_length(uint16_t key_length)
{
    if (key_length == 0u || key_length > 255u) {
        return 0u;
    }
    return 2u + 1u + 1u + 2u + 2u + (uint32_t)key_length
        + 1u + 1u + 2u + 32u + 32u + 32u;
}

uint32_t ninlil_model_domain_witness_chunk_encoded_length(
    const ninlil_model_domain_witness_chunk_t *chunk)
{
    uint32_t total = 40u;
    uint16_t i;
    if (chunk == NULL || chunk->entry_count == 0u
        || chunk->entry_count > NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK) {
        return 0u;
    }
    for (i = 0u; i < chunk->entry_count; ++i) {
        const uint32_t el =
            ninlil_model_domain_witness_entry_encoded_length(
                chunk->entries[i].key_length);
        if (el == 0u || total > UINT32_MAX - el) {
            return 0u;
        }
        total += el;
    }
    if (total > NINLIL_MODEL_DOMAIN_MANIFEST_CHUNK_BODY_MAX) {
        return 0u;
    }
    return total;
}

ninlil_status_t ninlil_model_domain_witness_chunk_count_for_members(
    uint16_t member_count, uint16_t *out_chunk_count)
{
    uint16_t chunks;
    if (out_chunk_count == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_chunk_count = 0u;
    if (member_count == 0u
        || member_count > NINLIL_MODEL_DOMAIN_WITNESS_MEMBER_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    chunks = (uint16_t)((member_count
        + NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK - 1u)
        / NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK);
    if (chunks == 0u || chunks > NINLIL_MODEL_DOMAIN_WITNESS_CHUNK_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_chunk_count = chunks;
    return NINLIL_OK;
}

static int is_witness_metadata_role(uint16_t record_role)
{
    const uint8_t family = (uint8_t)(record_role >> 8);
    const uint8_t subtype = (uint8_t)(record_role & 0xffu);
    return family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        && (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER);
}

int ninlil_model_domain_witness_member_key_is_valid(
    uint16_t record_role, uint16_t key_length, const uint8_t *key_bytes)
{
    uint8_t family;
    uint8_t subtype;
    uint8_t role_family;
    uint8_t role_low;
    if (key_bytes == NULL || key_length == 0u || key_length > 255u) {
        return 0;
    }
    role_family = (uint8_t)(record_role >> 8);
    role_low = (uint8_t)(record_role & 0xffu);
    if (key_length < 8u || memcmp(key_bytes, KEY_ROOT, 8u) != 0) {
        return 0;
    }
    if (key_length < 9u) {
        return 0;
    }
    family = key_bytes[8];
    if (family != role_family) {
        return 0;
    }
    if (family == 0x03u || family == 0x04u) {
        uint8_t suffix;
        if (key_length != 10u || role_low != 0u) {
            return 0;
        }
        suffix = key_bytes[9];
        if (family == 0x03u) {
            return suffix >= 1u && suffix <= 4u;
        }
        return suffix >= 1u && suffix <= 11u;
    }
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        || family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        if (key_length < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES
            || key_length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
            return 0;
        }
        subtype = key_bytes[9];
        if (subtype != role_low) {
            return 0;
        }
        return current_key_fields_ok(
            family, subtype, key_bytes[10], key_bytes[11], key_bytes[12],
            key_length);
    }
    return 0;
}

int ninlil_model_domain_witness_entry_shape_is_valid(
    const ninlil_model_domain_witness_entry_t *entry)
{
    int old_zero;
    int new_zero;
    int prior_zero;
    int is_meta;
    if (entry == NULL
        || entry->key_length == 0u || entry->key_length > 255u
        || entry->key_bytes == NULL
        || entry->old_present > 1u || entry->new_present > 1u
        || !ninlil_model_domain_witness_member_key_is_valid(
            entry->record_role, entry->key_length, entry->key_bytes)) {
        return 0;
    }
    old_zero = ninlil_model_domain_digest_is_zero(entry->old_value_digest);
    new_zero = ninlil_model_domain_digest_is_zero(entry->new_value_digest);
    prior_zero = ninlil_model_domain_digest_is_zero(
        entry->prior_head_witness_digest);
    is_meta = is_witness_metadata_role(entry->record_role);

    switch (entry->action) {
    case NINLIL_MODEL_DOMAIN_WITNESS_ACTION_CREATE:
        if (entry->old_present != 0u || entry->new_present != 1u
            || !old_zero || new_zero || !prior_zero) {
            return 0;
        }
        break;
    case NINLIL_MODEL_DOMAIN_WITNESS_ACTION_REPLACE:
        if (entry->old_present != 1u || entry->new_present != 1u
            || old_zero || new_zero
            || digests_equal(entry->old_value_digest, entry->new_value_digest)) {
            return 0;
        }
        if (is_meta) {
            if (!prior_zero) {
                return 0;
            }
        } else {
            const uint8_t fam = (uint8_t)(entry->record_role >> 8);
            const uint8_t st = (uint8_t)(entry->record_role & 0xffu);
            if (fam == 0x03u || fam == 0x04u) {
                /* Zero prior represents BASELINE; non-zero WITNESSED. */
            } else if (fam == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
                || fam == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
                /* Semantic rows that require non-zero head must carry non-zero prior. */
                if (!subtype_allows_zero_head(fam, st) && prior_zero) {
                    return 0;
                }
            } else {
                return 0;
            }
        }
        break;
    case NINLIL_MODEL_DOMAIN_WITNESS_ACTION_ERASE:
        if (entry->old_present != 1u || entry->new_present != 0u
            || old_zero || !new_zero) {
            return 0;
        }
        if (is_meta) {
            if (!prior_zero) {
                return 0;
            }
        } else {
            const uint8_t fam = (uint8_t)(entry->record_role >> 8);
            const uint8_t st = (uint8_t)(entry->record_role & 0xffu);
            if (fam == 0x03u || fam == 0x04u) {
                /* BASELINE zero prior representable. */
            } else if (fam == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
                || fam == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
                if (!subtype_allows_zero_head(fam, st) && prior_zero) {
                    return 0;
                }
            } else {
                return 0;
            }
        }
        break;
    case NINLIL_MODEL_DOMAIN_WITNESS_ACTION_SUPERSEDE:
        if (entry->record_role
                != (uint16_t)((NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN << 8)
                    | NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER)
            || entry->old_present != 1u || entry->new_present != 1u
            || old_zero || new_zero
            || digests_equal(entry->old_value_digest, entry->new_value_digest)
            || !prior_zero) {
            return 0;
        }
        break;
    default:
        return 0;
    }
    return 1;
}

static int retention_fields_valid(
    uint16_t retention_kind,
    const uint8_t retention_subject_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    if (retention_kind > 4u) {
        return 0;
    }
    if (retention_kind == 0u) {
        return ninlil_model_domain_digest_is_zero(retention_subject_key_digest);
    }
    return !ninlil_model_domain_digest_is_zero(retention_subject_key_digest);
}


/*
 * Section 10.0 witness header metadata matrix (decidable from header fields).
 * Locally derivable subjects use KEY_DIGEST prefix helpers below. Relations
 * requiring external builder/snapshot state (TRANSACTION_ANCHOR KEY_DIGEST from
 * bare transaction ID; DELIVERY key for kinds 8–12; kind-6 owner; kind-18
 * cleanup subject) only enforce closed retention sets and zero/nonzero
 * digest consistency.
 */
static int retention_consistent(uint16_t retention_kind,
    const uint8_t retention_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    if (retention_kind > 4u) {
        return 0;
    }
    if (retention_kind == 0u) {
        return ninlil_model_domain_digest_is_zero(retention_digest);
    }
    return !ninlil_model_domain_digest_is_zero(retention_digest);
}

static int retention_is_one_of(uint16_t retention_kind,
    const uint8_t retention_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    const uint16_t *allowed, size_t allowed_count)
{
    size_t i;
    int found = 0;
    if (!retention_consistent(retention_kind, retention_digest)) {
        return 0;
    }
    for (i = 0u; i < allowed_count; ++i) {
        if (allowed[i] == retention_kind) {
            found = 1;
            break;
        }
    }
    return found;
}

static int subject_matches_prefix16(
    const uint8_t subject[NINLIL_MODEL_DOMAIN_ID_BYTES],
    const uint8_t *bytes)
{
    return memcmp(subject, bytes, NINLIL_MODEL_DOMAIN_ID_BYTES) == 0;
}

/*
 * Normative KEY_DIGEST prefix without calling witness metadata (no recursion).
 * KEY_DIGEST(complete_key) = SHA-256("NINLIL-DOMAIN-ENCODED-KEY-V1" || key).
 */
static int subject_prefix_from_complete_key(
    const uint8_t *key_bytes,
    uint32_t key_length,
    uint8_t out_subject[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_model_domain_digest_t dig;
    ninlil_status_t status;

    if (key_bytes == NULL || key_length == 0u || out_subject == NULL) {
        return 0;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_KEY_DIGEST,
        (uint32_t)(sizeof(PREIMAGE_KEY_DIGEST) - 1u));
    if (status != NINLIL_OK) {
        return 0;
    }
    status = ninlil_model_domain_sha256_update(&ctx, key_bytes, key_length);
    if (status != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_sha256_final(&ctx, &dig) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out_subject, dig.bytes, NINLIL_MODEL_DOMAIN_ID_BYTES);
    return 1;
}

/* Family 6 ORDERED_INGRESS (0x27) u64 identity complete key. */
static int subject_from_ordered_ingress_sequence(
    const uint8_t sequence_be[8],
    uint8_t out_subject[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    uint8_t key[21];
    if (sequence_be == NULL) {
        return 0;
    }
    (void)memcpy(key, KEY_ROOT, 8u);
    key[8] = NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN;
    key[9] = NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
    key[10] = NINLIL_MODEL_DOMAIN_KEY_FORMAT_V1;
    key[11] = NINLIL_MODEL_DOMAIN_ID_KIND_U64;
    key[12] = 8u;
    (void)memcpy(&key[13], sequence_be, 8u);
    return subject_prefix_from_complete_key(key, 21u, out_subject);
}

/* Family 4 capacity key: root || 0x04 || resource_kind (1..11). */
static int subject_from_family4_capacity(
    uint16_t resource_kind,
    uint8_t out_subject[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    uint8_t key[10];
    if (resource_kind < 1u || resource_kind > 11u) {
        return 0;
    }
    (void)memcpy(key, KEY_ROOT, 8u);
    key[8] = 0x04u;
    key[9] = (uint8_t)resource_kind;
    return subject_prefix_from_complete_key(key, 10u, out_subject);
}

/* Family 6 BEARER_STATE (0x60) singleton complete key. */
static int subject_from_bearer_state_singleton(
    uint8_t out_subject[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    uint8_t key[13];
    (void)memcpy(key, KEY_ROOT, 8u);
    key[8] = NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN;
    key[9] = NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE;
    key[10] = NINLIL_MODEL_DOMAIN_KEY_FORMAT_V1;
    key[11] = NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON;
    key[12] = 0u;
    return subject_prefix_from_complete_key(key, 13u, out_subject);
}

static int witness_metadata_matrix_ok(
    uint16_t operation_kind,
    ninlil_bytes_view_t operation_identity,
    const uint8_t subject_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint16_t retention_kind,
    const uint8_t retention_subject_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    static const uint16_t RET_023[] = {0u, 2u, 3u};
    static const uint16_t RET_23[] = {2u, 3u};
    uint8_t expected_subject[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint16_t resource_kind;

    if (subject_id == NULL || retention_subject_key_digest == NULL
        || ninlil_model_domain_id_is_zero(subject_id)
        || !ninlil_model_domain_operation_identity_is_valid(
            operation_kind, operation_identity)) {
        return 0;
    }

    switch (operation_kind) {
    case 1u: /* SERVICE key digest; retention fixed 0 */
        return operation_identity.length == 32u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_kind == 0u
            && ninlil_model_domain_digest_is_zero(retention_subject_key_digest);
    case 2u:
    case 3u: /* transaction ID; retention fixed 2 (anchor KEY_DIGEST external) */
        return operation_identity.length == 16u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_kind == 2u
            && !ninlil_model_domain_digest_is_zero(retention_subject_key_digest);
    case 15u:
    case 16u: /* transaction_id || operation_id */
        return operation_identity.length == 32u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_kind == 2u
            && !ninlil_model_domain_digest_is_zero(retention_subject_key_digest);
    case 4u: /* ORDERED_INGRESS KEY_DIGEST prefix; retention 0/2/3 */
        if (operation_identity.length != 8u
            || !retention_is_one_of(retention_kind, retention_subject_key_digest,
                RET_023, 3u)
            || !subject_from_ordered_ingress_sequence(
                operation_identity.data, expected_subject)) {
            return 0;
        }
        return subject_matches_prefix16(subject_id, expected_subject);
    case 5u: /* attempt key digest */
        return operation_identity.length == 32u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_is_one_of(retention_kind, retention_subject_key_digest,
                RET_23, 2u);
    case 6u: /* send record key digest || generation */
        return operation_identity.length == 40u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_is_one_of(retention_kind, retention_subject_key_digest,
                RET_23, 2u);
    case 7u: /* ORDERED_INGRESS KEY_DIGEST prefix; retention 0/2/3 */
        if (operation_identity.length != 8u
            || !retention_is_one_of(retention_kind, retention_subject_key_digest,
                RET_023, 3u)
            || !subject_from_ordered_ingress_sequence(
                operation_identity.data, expected_subject)) {
            return 0;
        }
        return subject_matches_prefix16(subject_id, expected_subject);
    case 8u:
        /*
         * Identity is ordered_sequence; subject is DELIVERY KEY_DIGEST prefix
         * (external delivery key) — not locally derivable from identity alone.
         */
        return operation_identity.length == 8u
            && retention_kind == 3u
            && !ninlil_model_domain_digest_is_zero(retention_subject_key_digest);
    case 9u:
    case 10u: /* delivery key digest || token_generation || phase */
        return operation_identity.length == 42u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_kind == 3u
            && digests_equal(retention_subject_key_digest, operation_identity.data);
    case 11u: /* delivery key digest || reconcile fields */
        return operation_identity.length == 50u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_kind == 3u
            && digests_equal(retention_subject_key_digest, operation_identity.data);
    case 12u: /* cancel key digest || revision || phase */
        return operation_identity.length == 42u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_is_one_of(retention_kind, retention_subject_key_digest,
                RET_23, 2u);
    case 13u: /* ORDERED_INGRESS KEY_DIGEST prefix; retention fixed 2 */
        if (operation_identity.length != 8u
            || retention_kind != 2u
            || ninlil_model_domain_digest_is_zero(retention_subject_key_digest)
            || !subject_from_ordered_ingress_sequence(
                operation_identity.data, expected_subject)) {
            return 0;
        }
        return subject_matches_prefix16(subject_id, expected_subject);
    case 14u: /* subject_primary_key_digest || phase || revision */
        return operation_identity.length == 42u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_kind == 2u
            && digests_equal(retention_subject_key_digest, operation_identity.data);
    case 17u: /* family-4 capacity KEY_DIGEST prefix; retention fixed 0 */
        if (operation_identity.length != 14u
            || retention_kind != 0u
            || !ninlil_model_domain_digest_is_zero(retention_subject_key_digest)) {
            return 0;
        }
        resource_kind = ninlil_model_domain_decode_u16_be(operation_identity.data);
        if (!subject_from_family4_capacity(resource_kind, expected_subject)) {
            return 0;
        }
        return subject_matches_prefix16(subject_id, expected_subject);
    case 18u: /* cleanup plan key digest || phase || batch; retention 2/3 */
        return operation_identity.length == 42u
            && retention_is_one_of(retention_kind, retention_subject_key_digest,
                RET_23, 2u);
    case 19u: /* runtime_id || publish_generation; retention fixed 0 */
        return operation_identity.length == 24u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_kind == 0u
            && ninlil_model_domain_digest_is_zero(retention_subject_key_digest);
    case 20u: /* BEARER_STATE singleton KEY_DIGEST prefix; retention fixed 0 */
        if (operation_identity.length != 8u
            || retention_kind != 0u
            || !ninlil_model_domain_digest_is_zero(retention_subject_key_digest)
            || !subject_from_bearer_state_singleton(expected_subject)) {
            return 0;
        }
        return subject_matches_prefix16(subject_id, expected_subject);
    case 21u: /* target key digest || old digest || action; retention 0/2/3 */
        return operation_identity.length == 66u
            && subject_matches_prefix16(subject_id, operation_identity.data)
            && retention_is_one_of(retention_kind, retention_subject_key_digest,
                RET_023, 3u);
    default:
        return 0;
    }
}

static int witness_header_invariants_ok(
    const ninlil_model_domain_witness_header_t *header, int check_canonical)
{
    uint16_t expected_chunks;
    ninlil_model_domain_digest_t canon;
    ninlil_bytes_view_t identity;
    if (header == NULL) {
        return 0;
    }
    identity.data = header->operation_identity_length == 0u
        ? NULL : header->operation_identity;
    identity.length = header->operation_identity_length;
    if (!ninlil_model_domain_operation_identity_is_valid(
            header->operation_kind, identity)) {
        return 0;
    }
    if (header->witness_state < NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE
        || header->witness_state > NINLIL_MODEL_DOMAIN_WITNESS_STATE_RETIRED) {
        return 0;
    }
    if (ninlil_model_domain_id_is_zero(header->subject_id)) {
        return 0;
    }
    if (header->member_count == 0u
        || header->member_count > NINLIL_MODEL_DOMAIN_WITNESS_MEMBER_MAX) {
        return 0;
    }
    if (ninlil_model_domain_witness_chunk_count_for_members(
            header->member_count, &expected_chunks) != NINLIL_OK
        || header->chunk_count != expected_chunks) {
        return 0;
    }
    if (!retention_fields_valid(
            header->retention_kind, header->retention_subject_key_digest)) {
        return 0;
    }
    if (!witness_metadata_matrix_ok(
            header->operation_kind, identity, header->subject_id,
            header->retention_kind, header->retention_subject_key_digest)) {
        return 0;
    }
    if (header->witness_state == NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE) {
        if (!ninlil_model_domain_digest_is_zero(
                header->successor_witness_digest)) {
            return 0;
        }
    } else if (ninlil_model_domain_digest_is_zero(
                   header->successor_witness_digest)) {
        return 0;
    }
    if (ninlil_model_domain_digest_is_zero(header->canonical_digest)
        || ninlil_model_domain_digest_is_zero(header->manifest_digest)) {
        return 0;
    }
    if (check_canonical) {
        if (ninlil_model_domain_canonical_operation_digest(
                header->operation_kind, identity, header->subject_id,
                header->manifest_digest, header->retention_kind,
                header->retention_subject_key_digest, &canon) != NINLIL_OK
            || !digests_equal(canon.bytes, header->canonical_digest)) {
            return 0;
        }
    }
    return 1;
}

static int entry_keys_are_sorted(
    const ninlil_model_domain_witness_chunk_t *chunk)
{
    uint16_t i;
    for (i = 1u; i < chunk->entry_count; ++i) {
        const ninlil_model_domain_witness_entry_t *prev =
            &chunk->entries[i - 1u];
        const ninlil_model_domain_witness_entry_t *cur = &chunk->entries[i];
        const uint16_t min_len = prev->key_length < cur->key_length
            ? prev->key_length : cur->key_length;
        int cmp;
        if (prev->key_bytes == NULL || cur->key_bytes == NULL
            || prev->key_length == 0u || cur->key_length == 0u) {
            return 0;
        }
        cmp = memcmp(prev->key_bytes, cur->key_bytes, min_len);
        if (cmp > 0) {
            return 0;
        }
        if (cmp == 0 && prev->key_length >= cur->key_length) {
            return 0;
        }
    }
    return 1;
}

static int chunk_prefix_is_valid(
    const ninlil_model_domain_witness_chunk_t *chunk)
{
    if (chunk->chunk_count == 0u
        || chunk->chunk_count > NINLIL_MODEL_DOMAIN_WITNESS_CHUNK_MAX
        || chunk->chunk_index >= chunk->chunk_count
        || chunk->entry_count == 0u
        || chunk->entry_count > NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK
        || ninlil_model_domain_digest_is_zero(chunk->witness_digest)) {
        return 0;
    }
    if (chunk->chunk_index + 1u < chunk->chunk_count
        && chunk->entry_count
            != (uint16_t)NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK) {
        return 0;
    }
    return 1;
}

ninlil_status_t ninlil_model_domain_encode_witness_header(
    const ninlil_model_domain_witness_header_t *header,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    uint32_t required;
    uint32_t offset = 0u;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ninlil_model_domain_encode_ranges_are_disjoint(
            header, header == NULL ? 0u : sizeof(*header),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !witness_header_invariants_ok(header, 1)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    required = ninlil_model_domain_witness_header_encoded_length(
        header->operation_identity_length);
    if (required == 0u
        || required > NINLIL_MODEL_DOMAIN_WITNESS_HEADER_BODY_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], header->operation_kind);
    offset += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], header->witness_state);
    offset += 2u;
    ninlil_model_domain_encode_u16_be(
        &out_bytes[offset], header->operation_identity_length);
    offset += 2u;
    if (header->operation_identity_length != 0u) {
        (void)memcpy(&out_bytes[offset], header->operation_identity,
            header->operation_identity_length);
        offset += header->operation_identity_length;
    }
    (void)memcpy(&out_bytes[offset], header->subject_id, 16u);
    offset += 16u;
    (void)memcpy(&out_bytes[offset], header->canonical_digest, 32u);
    offset += 32u;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], header->member_count);
    offset += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], header->chunk_count);
    offset += 2u;
    (void)memcpy(&out_bytes[offset], header->manifest_digest, 32u);
    offset += 32u;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], header->retention_kind);
    offset += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], 0u);
    offset += 2u;
    (void)memcpy(&out_bytes[offset], header->retention_subject_key_digest, 32u);
    offset += 32u;
    (void)memcpy(&out_bytes[offset], header->successor_witness_digest, 32u);
    offset += 32u;
    *out_length = offset;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_witness_header(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_witness_header_t *out_header)
{
    uint32_t offset = 0u;
    uint16_t identity_length;
    uint16_t reserved;
    if (out_header == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.length != 0u && encoded.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_header, sizeof(*out_header))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_header, 0, sizeof(*out_header));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.length < 6u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_header->operation_kind =
        ninlil_model_domain_decode_u16_be(&encoded.data[offset]);
    offset += 2u;
    out_header->witness_state =
        ninlil_model_domain_decode_u16_be(&encoded.data[offset]);
    offset += 2u;
    identity_length =
        ninlil_model_domain_decode_u16_be(&encoded.data[offset]);
    offset += 2u;
    if (identity_length > NINLIL_MODEL_DOMAIN_OPERATION_IDENTITY_MAX
        || encoded.length < offset + identity_length + 16u + 32u + 2u + 2u
            + 32u + 2u + 2u + 32u + 32u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_header->operation_identity_length = identity_length;
    if (identity_length != 0u) {
        (void)memcpy(out_header->operation_identity,
            &encoded.data[offset], identity_length);
        offset += identity_length;
    }
    (void)memcpy(out_header->subject_id, &encoded.data[offset], 16u);
    offset += 16u;
    (void)memcpy(out_header->canonical_digest, &encoded.data[offset], 32u);
    offset += 32u;
    out_header->member_count =
        ninlil_model_domain_decode_u16_be(&encoded.data[offset]);
    offset += 2u;
    out_header->chunk_count =
        ninlil_model_domain_decode_u16_be(&encoded.data[offset]);
    offset += 2u;
    (void)memcpy(out_header->manifest_digest, &encoded.data[offset], 32u);
    offset += 32u;
    out_header->retention_kind =
        ninlil_model_domain_decode_u16_be(&encoded.data[offset]);
    offset += 2u;
    reserved = ninlil_model_domain_decode_u16_be(&encoded.data[offset]);
    offset += 2u;
    (void)memcpy(out_header->retention_subject_key_digest,
        &encoded.data[offset], 32u);
    offset += 32u;
    (void)memcpy(out_header->successor_witness_digest,
        &encoded.data[offset], 32u);
    offset += 32u;
    if (reserved != 0u || offset != encoded.length) {
        (void)memset(out_header, 0, sizeof(*out_header));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (!witness_header_invariants_ok(out_header, 1)) {
        (void)memset(out_header, 0, sizeof(*out_header));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t encode_witness_entry(
    const ninlil_model_domain_witness_entry_t *entry,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_used)
{
    uint32_t required =
        ninlil_model_domain_witness_entry_encoded_length(entry->key_length);
    uint32_t offset = 0u;
    if (required == 0u
        || !ninlil_model_domain_witness_entry_shape_is_valid(entry)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], entry->record_role);
    offset += 2u;
    out_bytes[offset++] = entry->action;
    out_bytes[offset++] = 0u;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], entry->key_length);
    offset += 2u;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], 0u);
    offset += 2u;
    (void)memcpy(&out_bytes[offset], entry->key_bytes, entry->key_length);
    offset += entry->key_length;
    out_bytes[offset++] = entry->old_present;
    out_bytes[offset++] = entry->new_present;
    ninlil_model_domain_encode_u16_be(&out_bytes[offset], 0u);
    offset += 2u;
    (void)memcpy(&out_bytes[offset], entry->prior_head_witness_digest, 32u);
    offset += 32u;
    (void)memcpy(&out_bytes[offset], entry->old_value_digest, 32u);
    offset += 32u;
    (void)memcpy(&out_bytes[offset], entry->new_value_digest, 32u);
    offset += 32u;
    *out_used = offset;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_encode_witness_chunk(
    const ninlil_model_domain_witness_chunk_t *chunk,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    uint32_t required;
    uint32_t offset = 40u;
    uint16_t i;
    uint16_t j;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Pairwise disjoint: chunk object, every entry.key_bytes range, and
     * output (out_bytes/capacity + out_length). Alias must leave all
     * participating memory untouched (header contract).
     */
    if (!ninlil_model_domain_encode_ranges_are_disjoint(
            chunk, chunk == NULL ? 0u : sizeof(*chunk),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (chunk != NULL) {
        for (i = 0u; i < chunk->entry_count
             && i < NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK;
             ++i) {
            const ninlil_model_domain_witness_entry_t *ei = &chunk->entries[i];
            if (ei->key_bytes != NULL && ei->key_length != 0u) {
                if (!ninlil_model_domain_encode_ranges_are_disjoint(
                        ei->key_bytes, ei->key_length,
                        out_bytes, capacity, out_length)
                    || !ninlil_model_domain_ranges_are_disjoint(
                        ei->key_bytes, ei->key_length,
                        chunk, sizeof(*chunk))) {
                    return NINLIL_E_INVALID_ARGUMENT;
                }
                for (j = (uint16_t)(i + 1u);
                     j < chunk->entry_count
                     && j < NINLIL_MODEL_DOMAIN_WITNESS_ENTRIES_PER_CHUNK;
                     ++j) {
                    const ninlil_model_domain_witness_entry_t *ej =
                        &chunk->entries[j];
                    if (ej->key_bytes != NULL && ej->key_length != 0u
                        && !ninlil_model_domain_ranges_are_disjoint(
                            ei->key_bytes, ei->key_length,
                            ej->key_bytes, ej->key_length)) {
                        return NINLIL_E_INVALID_ARGUMENT;
                    }
                }
            }
        }
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || chunk == NULL
        || !chunk_prefix_is_valid(chunk)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Shape before sort (memcmp on invalid key_bytes is UB). */
    for (i = 0u; i < chunk->entry_count; ++i) {
        if (!ninlil_model_domain_witness_entry_shape_is_valid(
                &chunk->entries[i])) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    if (!entry_keys_are_sorted(chunk)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    required = ninlil_model_domain_witness_chunk_encoded_length(chunk);
    if (required == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(out_bytes, chunk->witness_digest, 32u);
    ninlil_model_domain_encode_u16_be(&out_bytes[32], chunk->chunk_index);
    ninlil_model_domain_encode_u16_be(&out_bytes[34], chunk->chunk_count);
    ninlil_model_domain_encode_u16_be(&out_bytes[36], chunk->entry_count);
    ninlil_model_domain_encode_u16_be(&out_bytes[38], 0u);
    for (i = 0u; i < chunk->entry_count; ++i) {
        uint32_t used = 0u;
        ninlil_status_t status = encode_witness_entry(
            &chunk->entries[i], &out_bytes[offset], capacity - offset, &used);
        if (status != NINLIL_OK) {
            (void)memset(out_bytes, 0, capacity);
            *out_length = 0u;
            return status;
        }
        offset += used;
    }
    *out_length = offset;
    return NINLIL_OK;
}

static ninlil_status_t decode_witness_entry(
    const uint8_t *bytes, uint32_t available,
    ninlil_model_domain_witness_entry_t *out_entry, uint32_t *out_used)
{
    uint32_t offset = 0u;
    uint8_t reserved_u8;
    uint16_t reserved_a, reserved_b, key_length;
    if (available < 8u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_entry->record_role =
        ninlil_model_domain_decode_u16_be(&bytes[offset]);
    offset += 2u;
    out_entry->action = bytes[offset++];
    reserved_u8 = bytes[offset++];
    key_length = ninlil_model_domain_decode_u16_be(&bytes[offset]);
    offset += 2u;
    reserved_a = ninlil_model_domain_decode_u16_be(&bytes[offset]);
    offset += 2u;
    if (reserved_u8 != 0u || reserved_a != 0u
        || key_length == 0u || key_length > 255u
        || available < offset + key_length + 2u + 2u + 96u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_entry->key_length = key_length;
    out_entry->key_bytes = &bytes[offset];
    offset += key_length;
    out_entry->old_present = bytes[offset++];
    out_entry->new_present = bytes[offset++];
    reserved_b = ninlil_model_domain_decode_u16_be(&bytes[offset]);
    offset += 2u;
    if (reserved_b != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(out_entry->prior_head_witness_digest, &bytes[offset], 32u);
    offset += 32u;
    (void)memcpy(out_entry->old_value_digest, &bytes[offset], 32u);
    offset += 32u;
    (void)memcpy(out_entry->new_value_digest, &bytes[offset], 32u);
    offset += 32u;
    if (!ninlil_model_domain_witness_entry_shape_is_valid(out_entry)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_used = offset;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_witness_chunk(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_witness_chunk_t *out_chunk)
{
    uint32_t offset = 40u;
    uint16_t i;
    uint16_t reserved;
    if (out_chunk == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.length != 0u && encoded.data != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_chunk, sizeof(*out_chunk))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_chunk, 0, sizeof(*out_chunk));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.length < 40u
        || encoded.length > NINLIL_MODEL_DOMAIN_MANIFEST_CHUNK_BODY_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(out_chunk->witness_digest, encoded.data, 32u);
    out_chunk->chunk_index =
        ninlil_model_domain_decode_u16_be(&encoded.data[32]);
    out_chunk->chunk_count =
        ninlil_model_domain_decode_u16_be(&encoded.data[34]);
    out_chunk->entry_count =
        ninlil_model_domain_decode_u16_be(&encoded.data[36]);
    reserved = ninlil_model_domain_decode_u16_be(&encoded.data[38]);
    if (reserved != 0u || !chunk_prefix_is_valid(out_chunk)) {
        (void)memset(out_chunk, 0, sizeof(*out_chunk));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    for (i = 0u; i < out_chunk->entry_count; ++i) {
        uint32_t used = 0u;
        ninlil_status_t status;
        if (offset > encoded.length) {
            (void)memset(out_chunk, 0, sizeof(*out_chunk));
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = decode_witness_entry(
            &encoded.data[offset], encoded.length - offset,
            &out_chunk->entries[i], &used);
        if (status != NINLIL_OK) {
            (void)memset(out_chunk, 0, sizeof(*out_chunk));
            return status;
        }
        offset += used;
    }
    if (offset != encoded.length || !entry_keys_are_sorted(out_chunk)) {
        (void)memset(out_chunk, 0, sizeof(*out_chunk));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}


ninlil_status_t ninlil_model_domain_blob_chunk_data_length_validate(
    uint32_t chunk_data_length)
{
    if (chunk_data_length == 0u) {
        return NINLIL_OK;
    }
    if (chunk_data_length > NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}
