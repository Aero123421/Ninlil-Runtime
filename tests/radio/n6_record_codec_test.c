/*
 * N6 record codec product-level KAT (docs/30 §5.3).
 *
 * Independent fixed-byte oracles for all 11 forms:
 *   LK, TX, RX, HWK, HWV, ALK, ALV, RTK, RTV, CFK, CFV
 *
 * Expected wires and field values are independent literals — not derived
 * from production encode/validate. CRC32C expected construction uses a
 * local Castagnoli implementation (not ninlil_n6_crc32c). Symmetric-only
 * roundtrip acceptance is forbidden.
 *
 * Portable C: typed hosts live in unions; alias spacing uses _Alignof(host_u)
 * (not sizeof(max_align_t)); size_t canaries use memcpy; no unaligned
 * size_t* or uint8_t[]→struct* casts. Failure KAT pins exact status codes.
 *
 * Not R6 complete. No stub/TODO. No test relaxation.
 */

#include "n6_record_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Independent exact wire sizes (docs/30 §5.3). */
#define T_LK_N ((size_t)48u)
#define T_TX_N ((size_t)68u)
#define T_RX_N ((size_t)68u)
#define T_HWK_N ((size_t)32u)
#define T_HWV_N ((size_t)28u)
#define T_ALK_N ((size_t)24u)
#define T_ALV_N ((size_t)56u)
#define T_RTK_N ((size_t)28u)
#define T_RTV_N ((size_t)48u)
#define T_CFK_N ((size_t)28u)
#define T_CFV_N ((size_t)64u)

#define T_TX_COV ((size_t)64u)
#define T_RX_COV ((size_t)64u)
#define T_HWV_COV ((size_t)24u)
#define T_ALV_COV ((size_t)52u)
#define T_RTV_COV ((size_t)44u)
#define T_CFV_COV ((size_t)60u)

#define T_VALUE_COVERED_BITS ((size_t)2464u)
#define T_VALUE_STORED_CRC_BITS ((size_t)192u)

/*
 * Closed-domain unique field negatives (encode+decode each):
 * LK7 TX10 RX9 HWK4 HWV4 ALK5 ALV6 RTK7 RTV11 CFK7 CFV11 = 81 fields
 * (TX/RX reserved1[0..2] per-byte). ×2 = 162. HWV/RTV zero folded in.
 *
 * Lane matrix (extra): HOP+DATA ok, E2E+E2E ok, E2E+HOP_DATA fail,
 * E2E+ACK fail — each encode+decode = 8. Existing HOP+ACK success and
 * HOP+E2E fail remain in host→literal / closed-domain.
 */
#define T_CASE_CLOSED_DOMAIN_FIELDS ((unsigned)81u)
#define T_CASE_CLOSED_DOMAIN ((unsigned)(T_CASE_CLOSED_DOMAIN_FIELDS * 2u))
#define T_CASE_LANE_MATRIX ((unsigned)8u)

#define T_CASE_HOST_TO_LITERAL ((unsigned)11u)
#define T_CASE_LITERAL_TO_FIELDS ((unsigned)11u)
#define T_CASE_DECODE_LEN_PER ((unsigned)6u) /* NULL-in,0,N-1,N+1,SIZE_MAX,exact */
#define T_CASE_DECODE_LEN ((unsigned)(11u * T_CASE_DECODE_LEN_PER))
#define T_CASE_ENCODE_CAP_PER ((unsigned)4u)
#define T_CASE_ENCODE_CAP ((unsigned)(11u * T_CASE_ENCODE_CAP_PER))
/* full, out=in+1, in@out+host_align, out_len@out, out_len@in */
#define T_CASE_ENCODE_ALIAS_PER ((unsigned)5u)
#define T_CASE_ENCODE_ALIAS ((unsigned)(11u * T_CASE_ENCODE_ALIAS_PER))
/* full, out=in+1, in=out+1 */
#define T_CASE_DECODE_ALIAS_PER ((unsigned)3u)
#define T_CASE_DECODE_ALIAS ((unsigned)(11u * T_CASE_DECODE_ALIAS_PER))
/* 11×(out=NULL) + 11×3 encode NULL (in/out/out_len) */
#define T_CASE_NULL_KAT ((unsigned)(11u + 11u * 3u))
#define T_CASE_WRONG_DECODER ((unsigned)110u)
#define T_CASE_CRC_BITS ((unsigned)(T_VALUE_COVERED_BITS + T_VALUE_STORED_CRC_BITS))
#define T_CASE_CRC_KAT ((unsigned)4u)
#define T_CASE_TOTAL                                                               \
    ((unsigned)(T_CASE_CRC_KAT + T_CASE_HOST_TO_LITERAL + T_CASE_LITERAL_TO_FIELDS  \
        + T_CASE_DECODE_LEN + T_CASE_ENCODE_CAP + T_CASE_ENCODE_ALIAS               \
        + T_CASE_DECODE_ALIAS + T_CASE_NULL_KAT + T_CASE_WRONG_DECODER              \
        + T_CASE_CRC_BITS + T_CASE_CLOSED_DOMAIN + T_CASE_LANE_MATRIX))

#define REQUIRE(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            (void)fprintf(stderr, "REQUIRE failed %s:%d: %s\n", __FILE__,     \
                __LINE__, #cond);                                              \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static unsigned g_cases;

static void case_hit(void)
{
    ++g_cases;
}

/* Typed host storage — no uint8_t[]→struct* casts. */
typedef union host_u {
    ninlil_n6_lane_key_t lk;
    ninlil_n6_tx_value_t tx;
    ninlil_n6_rx_value_t rx;
    ninlil_n6_hw_key_t hwk;
    ninlil_n6_hw_value_t hwv;
    ninlil_n6_al_key_t alk;
    ninlil_n6_al_value_t alv;
    ninlil_n6_rt_key_t rtk;
    ninlil_n6_rt_value_t rtv;
    ninlil_n6_cf_key_t cfk;
    ninlil_n6_cf_value_t cfv;
} host_u;

/* Real host alignment for alias spacing — NOT sizeof(max_align_t).
 * On x86_64 glibc max_align_t is often 32; host_u is typically 8.
 * Alias geometry must still run for ALK(24)/HWV,RTK,CFK(28). */
#define T_HOST_ALIGN ((size_t)_Alignof(host_u))

/* max_align arena for wire/alias work (strict alignment clean). */
typedef union arena_u {
    max_align_t align;
    uint8_t bytes[512];
} arena_u;

typedef union wire_u {
    max_align_t align;
    uint8_t bytes[80];
} wire_u;

static int mem_eq(const void *a, const void *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static int canary_eq(const void *p, size_t n, uint8_t v)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0u; i < n; ++i) {
        if (b[i] != v) {
            return 0;
        }
    }
    return 1;
}

static void size_t_store(void *dst, size_t v)
{
    (void)memcpy(dst, &v, sizeof(v));
}

static size_t size_t_load(const void *src)
{
    size_t v;
    (void)memcpy(&v, src, sizeof(v));
    return v;
}

/* Independent CRC32C Castagnoli (poly 0x82f63b78, init/xor 0xffffffff). */
static uint32_t test_crc32c(const uint8_t *p, size_t n)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    unsigned b;
    if (p == NULL && n != 0u) {
        return 0u;
    }
    for (i = 0u; i < n; ++i) {
        crc ^= p[i];
        for (b = 0u; b < 8u; ++b) {
            if ((crc & 1u) != 0u) {
                crc = (crc >> 1) ^ 0x82f63b78u;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xffffffffu;
}

static void put_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static void put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static void put_u64_be(uint8_t *p, uint64_t v)
{
    put_u32_be(p, (uint32_t)((v >> 32) & 0xffffffffu));
    put_u32_be(p + 4, (uint32_t)(v & 0xffffffffu));
}

static uint32_t get_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;
    for (i = 0u; i < out_len; ++i) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static const char *const HEX_LK =
    "0102010001020304000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0102030405060708";
static const char *const HEX_TX =
    "4e3654580002000021222324252627280102030405060708303132333435363738393a3b3c3d3e3f111213141516171802000000404142434445464748494a4b8ee687f5";
static const char *const HEX_RX =
    "4e365258000200003132333435363738090a0b0c0d0e0f10505152535455565758595a5b5c5d5e5f191a1b1c1d1e1f2001000000606162636465666768696a6b48fd9e30";
static const char *const HEX_HWK =
    "01020100707172737475767778797a7b7c7d7e7f808182838485868788898a8b";
static const char *const HEX_HWV =
    "4e36485700010000414243444546474851525354555657580c4845fd";
static const char *const HEX_ALK =
    "020102001112131415161718808182838485868788898a8b";
static const char *const HEX_ALV =
    "4e36414c0002000001020304050607080000000011121314151617182122232425262728909192939495969798999a9b9c9d9e9fc4f15591";
static const char *const HEX_RTK =
    "03020001112233443132333435363738a0a1a2a3a4a5a6a7a8a9aaab";
static const char *const HEX_RTV =
    "4e365254000200011122334431323334353637384142434445464748b0b1b2b3b4b5b6b7b8b9babb01000200421134a8";
static const char *const HEX_CFK =
    "04010102556677885152535455565758c0c1c2c3c4c5c6c7c8c9cacb";
static const char *const HEX_CFV =
    "4e36434600020001556677885152535455565758d0d1d2d3d4d5d6d7d8d9dadbdcdddedf6162636465666768e0e1e2e3e4e5e6e7e8e9eaeb02010105d5c6221e";

typedef enum {
    F_LK = 0,
    F_TX,
    F_RX,
    F_HWK,
    F_HWV,
    F_ALK,
    F_ALV,
    F_RTK,
    F_RTV,
    F_CFK,
    F_CFV,
    F_COUNT
} form_id_t;

static size_t form_wire_n(form_id_t f)
{
    static const size_t n[F_COUNT] = {
        T_LK_N, T_TX_N, T_RX_N, T_HWK_N, T_HWV_N, T_ALK_N, T_ALV_N, T_RTK_N,
        T_RTV_N, T_CFK_N, T_CFV_N
    };
    return n[(int)f];
}

static size_t form_host_n(form_id_t f)
{
    static const size_t n[F_COUNT] = {
        sizeof(ninlil_n6_lane_key_t),
        sizeof(ninlil_n6_tx_value_t),
        sizeof(ninlil_n6_rx_value_t),
        sizeof(ninlil_n6_hw_key_t),
        sizeof(ninlil_n6_hw_value_t),
        sizeof(ninlil_n6_al_key_t),
        sizeof(ninlil_n6_al_value_t),
        sizeof(ninlil_n6_rt_key_t),
        sizeof(ninlil_n6_rt_value_t),
        sizeof(ninlil_n6_cf_key_t),
        sizeof(ninlil_n6_cf_value_t)
    };
    return n[(int)f];
}

static const char *form_hex(form_id_t f)
{
    static const char *const h[F_COUNT] = {
        HEX_LK, HEX_TX, HEX_RX, HEX_HWK, HEX_HWV, HEX_ALK, HEX_ALV, HEX_RTK,
        HEX_RTV, HEX_CFK, HEX_CFV
    };
    return h[(int)f];
}

static int form_is_value(form_id_t f)
{
    return f == F_TX || f == F_RX || f == F_HWV || f == F_ALV || f == F_RTV
        || f == F_CFV;
}

static size_t form_cov(form_id_t f)
{
    switch (f) {
    case F_TX:
    case F_RX:
        return T_TX_COV;
    case F_HWV:
        return T_HWV_COV;
    case F_ALV:
        return T_ALV_COV;
    case F_RTV:
        return T_RTV_COV;
    case F_CFV:
        return T_CFV_COV;
    default:
        return 0u;
    }
}

static int decode_form(form_id_t f, const uint8_t *in, size_t n, host_u *out)
{
    /* Never form &out->member when out is NULL (UBSan null-member). */
    switch (f) {
    case F_LK:
        return ninlil_n6_decode_lane_key(
            in, n, out != NULL ? &out->lk : NULL);
    case F_TX:
        return ninlil_n6_decode_n6tx_value(
            in, n, out != NULL ? &out->tx : NULL);
    case F_RX:
        return ninlil_n6_decode_n6rx_value(
            in, n, out != NULL ? &out->rx : NULL);
    case F_HWK:
        return ninlil_n6_decode_n6hw_key(
            in, n, out != NULL ? &out->hwk : NULL);
    case F_HWV:
        return ninlil_n6_decode_n6hw_value(
            in, n, out != NULL ? &out->hwv : NULL);
    case F_ALK:
        return ninlil_n6_decode_n6al_key(
            in, n, out != NULL ? &out->alk : NULL);
    case F_ALV:
        return ninlil_n6_decode_n6al_value(
            in, n, out != NULL ? &out->alv : NULL);
    case F_RTK:
        return ninlil_n6_decode_n6rt_key(
            in, n, out != NULL ? &out->rtk : NULL);
    case F_RTV:
        return ninlil_n6_decode_n6rt_value(
            in, n, out != NULL ? &out->rtv : NULL);
    case F_CFK:
        return ninlil_n6_decode_n6cf_key(
            in, n, out != NULL ? &out->cfk : NULL);
    case F_CFV:
        return ninlil_n6_decode_n6cf_value(
            in, n, out != NULL ? &out->cfv : NULL);
    default:
        return 2;
    }
}

static int encode_form(
    form_id_t f, const host_u *in, uint8_t *out, size_t cap, size_t *out_len)
{
    /* Never form &in->member when in is NULL (UBSan null-member). */
    switch (f) {
    case F_LK:
        return ninlil_n6_encode_lane_key(
            in != NULL ? &in->lk : NULL, out, cap, out_len);
    case F_TX:
        return ninlil_n6_encode_n6tx_value(
            in != NULL ? &in->tx : NULL, out, cap, out_len);
    case F_RX:
        return ninlil_n6_encode_n6rx_value(
            in != NULL ? &in->rx : NULL, out, cap, out_len);
    case F_HWK:
        return ninlil_n6_encode_n6hw_key(
            in != NULL ? &in->hwk : NULL, out, cap, out_len);
    case F_HWV:
        return ninlil_n6_encode_n6hw_value(
            in != NULL ? &in->hwv : NULL, out, cap, out_len);
    case F_ALK:
        return ninlil_n6_encode_n6al_key(
            in != NULL ? &in->alk : NULL, out, cap, out_len);
    case F_ALV:
        return ninlil_n6_encode_n6al_value(
            in != NULL ? &in->alv : NULL, out, cap, out_len);
    case F_RTK:
        return ninlil_n6_encode_n6rt_key(
            in != NULL ? &in->rtk : NULL, out, cap, out_len);
    case F_RTV:
        return ninlil_n6_encode_n6rt_value(
            in != NULL ? &in->rtv : NULL, out, cap, out_len);
    case F_CFK:
        return ninlil_n6_encode_n6cf_key(
            in != NULL ? &in->cfk : NULL, out, cap, out_len);
    case F_CFV:
        return ninlil_n6_encode_n6cf_value(
            in != NULL ? &in->cfv : NULL, out, cap, out_len);
    default:
        return 2;
    }
}

static void fill_bytes(uint8_t *p, size_t n, uint8_t start)
{
    size_t i;
    for (i = 0u; i < n; ++i) {
        p[i] = (uint8_t)(start + (uint8_t)i);
    }
}

static void host_lk(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->lk.layer_code = 1u;
    h->lk.kind_or_lane = 2u;
    h->lk.direction_code = 1u;
    h->lk.reserved0 = 0u;
    h->lk.context_id = 0x01020304u;
    fill_bytes(h->lk.binding_digest32, 32u, 0x00u);
    h->lk.key_generation = 0x0102030405060708ull;
}

static void host_tx(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->tx.magic = 0x4e365458u;
    h->tx.schema = 2u;
    h->tx.reserved_exclusive = 0x2122232425262728ull;
    h->tx.key_generation = 0x0102030405060708ull;
    fill_bytes(h->tx.binding_digest_prefix16, 16u, 0x30u);
    h->tx.membership_epoch = 0x1112131415161718ull;
    h->tx.alloc_side = 2u;
    fill_bytes(h->tx.ns_fingerprint12, 12u, 0x40u);
}

static void host_rx(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->rx.magic = 0x4e365258u;
    h->rx.schema = 2u;
    h->rx.accept_reserved_through = 0x3132333435363738ull;
    h->rx.key_generation = 0x090a0b0c0d0e0f10ull;
    fill_bytes(h->rx.binding_digest_prefix16, 16u, 0x50u);
    h->rx.membership_epoch = 0x191a1b1c1d1e1f20ull;
    h->rx.alloc_side = 1u;
    fill_bytes(h->rx.ns_fingerprint12, 12u, 0x60u);
}

static void host_hwk(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->hwk.rec_kind = 1u;
    h->hwk.layer_code = 2u;
    h->hwk.direction_code = 1u;
    fill_bytes(h->hwk.scope_digest28, 28u, 0x70u);
}

static void host_hwv(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->hwv.magic = 0x4e364857u;
    h->hwv.schema = 1u;
    h->hwv.high_water_key_generation = 0x4142434445464748ull;
    h->hwv.last_update_authority_now_ms = 0x5152535455565758ull;
}

static void host_alk(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->alk.rec_kind = 2u;
    h->alk.layer_code = 1u;
    h->alk.alloc_side = 2u;
    h->alk.membership_epoch = 0x1112131415161718ull;
    fill_bytes(h->alk.ns_fingerprint12, 12u, 0x80u);
}

static void host_alv(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->alv.magic = 0x4e36414cu;
    h->alv.schema = 2u;
    h->alv.next_free_or_peer_floor = 0x01020304u;
    h->alv.active_count = 0x0506u;
    h->alv.retired_tombstone_count = 0x0708u;
    h->alv.membership_epoch = 0x1112131415161718ull;
    h->alv.last_alloc_authority_now_ms = 0x2122232425262728ull;
    fill_bytes(h->alv.receiver_node_id, 16u, 0x90u);
}

static void host_rtk(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->rtk.rec_kind = 3u;
    h->rtk.layer_code = 2u;
    h->rtk.direction_code = 0u;
    h->rtk.alloc_side = 1u;
    h->rtk.context_id = 0x11223344u;
    h->rtk.membership_epoch = 0x3132333435363738ull;
    fill_bytes(h->rtk.ns_fingerprint12, 12u, 0xa0u);
}

static void host_rtv(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->rtv.magic = 0x4e365254u;
    h->rtv.schema = 2u;
    h->rtv.flags = 0x0001u;
    h->rtv.context_id = 0x11223344u;
    h->rtv.membership_epoch = 0x3132333435363738ull;
    h->rtv.last_key_generation_high_water = 0x4142434445464748ull;
    fill_bytes(h->rtv.binding_digest12, 12u, 0xb0u);
    h->rtv.alloc_side = 1u;
    h->rtv.direction_code = 0u;
    h->rtv.layer_code = 2u;
}

static void host_cfk(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->cfk.rec_kind = 4u;
    h->cfk.layer_code = 1u;
    h->cfk.direction_code = 1u;
    h->cfk.alloc_side = 2u;
    h->cfk.context_id = 0x55667788u;
    h->cfk.membership_epoch = 0x5152535455565758ull;
    fill_bytes(h->cfk.ns_fingerprint12, 12u, 0xc0u);
}

static void host_cfv(host_u *h)
{
    (void)memset(h, 0, sizeof(*h));
    h->cfv.magic = 0x4e364346u;
    h->cfv.schema = 2u;
    h->cfv.flags = 0x0001u;
    h->cfv.context_id = 0x55667788u;
    h->cfv.membership_epoch = 0x5152535455565758ull;
    fill_bytes(h->cfv.fence_stamp_epoch_id, 16u, 0xd0u);
    h->cfv.fence_stamp_now_ms = 0x6162636465666768ull;
    fill_bytes(h->cfv.binding_digest12, 12u, 0xe0u);
    h->cfv.alloc_side = 2u;
    h->cfv.direction_code = 1u;
    h->cfv.layer_code = 1u;
    h->cfv.reason = 5u;
}

static void host_for(form_id_t f, host_u *h)
{
    switch (f) {
    case F_LK:
        host_lk(h);
        break;
    case F_TX:
        host_tx(h);
        break;
    case F_RX:
        host_rx(h);
        break;
    case F_HWK:
        host_hwk(h);
        break;
    case F_HWV:
        host_hwv(h);
        break;
    case F_ALK:
        host_alk(h);
        break;
    case F_ALV:
        host_alv(h);
        break;
    case F_RTK:
        host_rtk(h);
        break;
    case F_RTV:
        host_rtv(h);
        break;
    case F_CFK:
        host_cfk(h);
        break;
    case F_CFV:
        host_cfv(h);
        break;
    default:
        break;
    }
}

static int check_fields(form_id_t f, const host_u *h)
{
    uint8_t exp[32];
    switch (f) {
    case F_LK:
        REQUIRE(h->lk.layer_code == 1u && h->lk.kind_or_lane == 2u);
        REQUIRE(h->lk.direction_code == 1u && h->lk.reserved0 == 0u);
        REQUIRE(h->lk.context_id == 0x01020304u);
        fill_bytes(exp, 32u, 0x00u);
        REQUIRE(memcmp(h->lk.binding_digest32, exp, 32u) == 0);
        REQUIRE(h->lk.key_generation == 0x0102030405060708ull);
        return 0;
    case F_TX:
        REQUIRE(h->tx.magic == 0x4e365458u && h->tx.schema == 2u);
        REQUIRE(h->tx.reserved0 == 0u);
        REQUIRE(h->tx.reserved_exclusive == 0x2122232425262728ull);
        REQUIRE(h->tx.key_generation == 0x0102030405060708ull);
        fill_bytes(exp, 16u, 0x30u);
        REQUIRE(memcmp(h->tx.binding_digest_prefix16, exp, 16u) == 0);
        REQUIRE(h->tx.membership_epoch == 0x1112131415161718ull);
        REQUIRE(h->tx.alloc_side == 2u);
        REQUIRE(h->tx.reserved1[0] == 0u && h->tx.reserved1[1] == 0u
            && h->tx.reserved1[2] == 0u);
        fill_bytes(exp, 12u, 0x40u);
        REQUIRE(memcmp(h->tx.ns_fingerprint12, exp, 12u) == 0);
        REQUIRE(h->tx.value_crc32c == 0x8ee687f5u);
        return 0;
    case F_RX:
        REQUIRE(h->rx.magic == 0x4e365258u && h->rx.schema == 2u);
        REQUIRE(h->rx.reserved0 == 0u);
        REQUIRE(h->rx.accept_reserved_through == 0x3132333435363738ull);
        REQUIRE(h->rx.key_generation == 0x090a0b0c0d0e0f10ull);
        fill_bytes(exp, 16u, 0x50u);
        REQUIRE(memcmp(h->rx.binding_digest_prefix16, exp, 16u) == 0);
        REQUIRE(h->rx.membership_epoch == 0x191a1b1c1d1e1f20ull);
        REQUIRE(h->rx.alloc_side == 1u);
        fill_bytes(exp, 12u, 0x60u);
        REQUIRE(memcmp(h->rx.ns_fingerprint12, exp, 12u) == 0);
        REQUIRE(h->rx.value_crc32c == 0x48fd9e30u);
        return 0;
    case F_HWK:
        REQUIRE(h->hwk.rec_kind == 1u && h->hwk.layer_code == 2u);
        REQUIRE(h->hwk.direction_code == 1u && h->hwk.reserved0 == 0u);
        fill_bytes(exp, 28u, 0x70u);
        REQUIRE(memcmp(h->hwk.scope_digest28, exp, 28u) == 0);
        return 0;
    case F_HWV:
        REQUIRE(h->hwv.magic == 0x4e364857u && h->hwv.schema == 1u);
        REQUIRE(h->hwv.reserved0 == 0u);
        REQUIRE(h->hwv.high_water_key_generation == 0x4142434445464748ull);
        REQUIRE(h->hwv.last_update_authority_now_ms == 0x5152535455565758ull);
        REQUIRE(h->hwv.value_crc32c == 0x0c4845fdu);
        return 0;
    case F_ALK:
        REQUIRE(h->alk.rec_kind == 2u && h->alk.layer_code == 1u);
        REQUIRE(h->alk.alloc_side == 2u && h->alk.reserved0 == 0u);
        REQUIRE(h->alk.membership_epoch == 0x1112131415161718ull);
        fill_bytes(exp, 12u, 0x80u);
        REQUIRE(memcmp(h->alk.ns_fingerprint12, exp, 12u) == 0);
        return 0;
    case F_ALV:
        REQUIRE(h->alv.magic == 0x4e36414cu && h->alv.schema == 2u);
        REQUIRE(h->alv.reserved0 == 0u && h->alv.reserved1 == 0u);
        REQUIRE(h->alv.next_free_or_peer_floor == 0x01020304u);
        REQUIRE(h->alv.active_count == 0x0506u);
        REQUIRE(h->alv.retired_tombstone_count == 0x0708u);
        REQUIRE(h->alv.membership_epoch == 0x1112131415161718ull);
        REQUIRE(h->alv.last_alloc_authority_now_ms == 0x2122232425262728ull);
        fill_bytes(exp, 16u, 0x90u);
        REQUIRE(memcmp(h->alv.receiver_node_id, exp, 16u) == 0);
        REQUIRE(h->alv.value_crc32c == 0xc4f15591u);
        return 0;
    case F_RTK:
        REQUIRE(h->rtk.rec_kind == 3u && h->rtk.layer_code == 2u);
        REQUIRE(h->rtk.direction_code == 0u && h->rtk.alloc_side == 1u);
        REQUIRE(h->rtk.context_id == 0x11223344u);
        REQUIRE(h->rtk.membership_epoch == 0x3132333435363738ull);
        fill_bytes(exp, 12u, 0xa0u);
        REQUIRE(memcmp(h->rtk.ns_fingerprint12, exp, 12u) == 0);
        return 0;
    case F_RTV:
        REQUIRE(h->rtv.magic == 0x4e365254u && h->rtv.schema == 2u);
        REQUIRE(h->rtv.flags == 0x0001u);
        REQUIRE(h->rtv.context_id == 0x11223344u);
        REQUIRE(h->rtv.membership_epoch == 0x3132333435363738ull);
        REQUIRE(h->rtv.last_key_generation_high_water == 0x4142434445464748ull);
        fill_bytes(exp, 12u, 0xb0u);
        REQUIRE(memcmp(h->rtv.binding_digest12, exp, 12u) == 0);
        REQUIRE(h->rtv.alloc_side == 1u && h->rtv.direction_code == 0u);
        REQUIRE(h->rtv.layer_code == 2u && h->rtv.reserved0 == 0u);
        REQUIRE(h->rtv.value_crc32c == 0x421134a8u);
        return 0;
    case F_CFK:
        REQUIRE(h->cfk.rec_kind == 4u && h->cfk.layer_code == 1u);
        REQUIRE(h->cfk.direction_code == 1u && h->cfk.alloc_side == 2u);
        REQUIRE(h->cfk.context_id == 0x55667788u);
        REQUIRE(h->cfk.membership_epoch == 0x5152535455565758ull);
        fill_bytes(exp, 12u, 0xc0u);
        REQUIRE(memcmp(h->cfk.ns_fingerprint12, exp, 12u) == 0);
        return 0;
    case F_CFV:
        REQUIRE(h->cfv.magic == 0x4e364346u && h->cfv.schema == 2u);
        REQUIRE(h->cfv.flags == 0x0001u);
        REQUIRE(h->cfv.context_id == 0x55667788u);
        REQUIRE(h->cfv.membership_epoch == 0x5152535455565758ull);
        fill_bytes(exp, 16u, 0xd0u);
        REQUIRE(memcmp(h->cfv.fence_stamp_epoch_id, exp, 16u) == 0);
        REQUIRE(h->cfv.fence_stamp_now_ms == 0x6162636465666768ull);
        fill_bytes(exp, 12u, 0xe0u);
        REQUIRE(memcmp(h->cfv.binding_digest12, exp, 12u) == 0);
        REQUIRE(h->cfv.alloc_side == 2u && h->cfv.direction_code == 1u);
        REQUIRE(h->cfv.layer_code == 1u && h->cfv.reason == 5u);
        REQUIRE(h->cfv.value_crc32c == 0xd5c6221eu);
        return 0;
    default:
        return 1;
    }
}

static void re_crc(uint8_t *wire, size_t cov)
{
    put_u32_be(wire + cov, test_crc32c(wire, cov));
}

/* ---- Tests ---- */

static int test_crc_kat(void)
{
    static const uint8_t msg[] = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    static const uint8_t z4[4] = { 0, 0, 0, 0 };
    REQUIRE(test_crc32c(msg, sizeof(msg)) == 0xe3069283u);
    case_hit();
    REQUIRE(ninlil_n6_crc32c(msg, sizeof(msg)) == 0xe3069283u);
    case_hit();
    REQUIRE(test_crc32c(NULL, 0u) == 0u);
    case_hit();
    REQUIRE(test_crc32c(z4, 4u) == 0x48674bc7u);
    case_hit();
    return 0;
}

static int test_host_to_literal_and_literal_to_fields(void)
{
    form_id_t f;
    for (f = F_LK; f < F_COUNT; ++f) {
        wire_u expect;
        arena_u enc;
        host_u host;
        size_t n = form_wire_n(f);
        size_t elen = 0xdeadbeefu;
        REQUIRE(n <= sizeof(expect.bytes));
        REQUIRE(parse_hex(form_hex(f), expect.bytes, n) == 0);
        if (form_is_value(f)) {
            size_t cov = form_cov(f);
            REQUIRE(test_crc32c(expect.bytes, cov)
                == get_u32_be(expect.bytes + cov));
        }
        host_for(f, &host);
        (void)memset(enc.bytes, 0xcc, sizeof(enc.bytes));
        REQUIRE(encode_form(f, &host, enc.bytes, sizeof(enc.bytes), &elen)
            == NINLIL_N6_CODEC_OK);
        REQUIRE(elen == n);
        REQUIRE(mem_eq(enc.bytes, expect.bytes, n));
        case_hit();

        (void)memset(&host, 0xa5, sizeof(host));
        REQUIRE(decode_form(f, expect.bytes, n, &host) == NINLIL_N6_CODEC_OK);
        if (check_fields(f, &host) != 0) {
            return 1;
        }
        case_hit();
    }
    return 0;
}

static int test_decode_length_matrix(void)
{
    form_id_t f;
    for (f = F_LK; f < F_COUNT; ++f) {
        size_t n = form_wire_n(f);
        size_t hn = form_host_n(f);
        wire_u wire;
        host_u host;
        host_u snap;
        size_t lengths[4];
        size_t li;
        REQUIRE(parse_hex(form_hex(f), wire.bytes, n) == 0);
        lengths[0] = 0u;
        lengths[1] = n - 1u;
        lengths[2] = n + 1u;
        lengths[3] = (size_t)SIZE_MAX;

        (void)memset(&host, 0x5a, sizeof(host));
        (void)memcpy(&snap, &host, sizeof(host));
        REQUIRE(decode_form(f, NULL, n, &host)
            == NINLIL_N6_CODEC_INVALID_ARGUMENT);
        REQUIRE(mem_eq(&host, &snap, sizeof(host)));
        case_hit();

        for (li = 0u; li < 4u; ++li) {
            (void)memset(&host, 0x5a, sizeof(host));
            (void)memcpy(&snap, &host, sizeof(host));
            REQUIRE(decode_form(f, wire.bytes, lengths[li], &host)
                == NINLIL_N6_CODEC_REJECT);
            REQUIRE(mem_eq(&host, &snap, sizeof(host)));
            REQUIRE(canary_eq(&host, hn, 0x5au));
            case_hit();
        }
        (void)memset(&host, 0x5a, sizeof(host));
        REQUIRE(decode_form(f, wire.bytes, n, &host) == NINLIL_N6_CODEC_OK);
        case_hit();
    }
    return 0;
}

static int test_encode_capacity_matrix(void)
{
    form_id_t f;
    for (f = F_LK; f < F_COUNT; ++f) {
        size_t n = form_wire_n(f);
        host_u host;
        arena_u arena;
        arena_u snap;
        size_t out_len;
        size_t canary;
        size_t i;
        host_for(f, &host);
        REQUIRE(n + 16u <= sizeof(arena.bytes));

        (void)memset(arena.bytes, 0xa5, sizeof(arena.bytes));
        (void)memcpy(snap.bytes, arena.bytes, sizeof(arena.bytes));
        out_len = 0x11111111u;
        canary = out_len;
        REQUIRE(encode_form(f, &host, arena.bytes, 0u, &out_len)
            == NINLIL_N6_CODEC_INVALID_ARGUMENT);
        REQUIRE(out_len == canary);
        REQUIRE(mem_eq(arena.bytes, snap.bytes, sizeof(arena.bytes)));
        case_hit();

        (void)memset(arena.bytes, 0xa5, sizeof(arena.bytes));
        (void)memcpy(snap.bytes, arena.bytes, sizeof(arena.bytes));
        out_len = 0x22222222u;
        canary = out_len;
        REQUIRE(encode_form(f, &host, arena.bytes, n - 1u, &out_len)
            == NINLIL_N6_CODEC_INVALID_ARGUMENT);
        REQUIRE(out_len == canary);
        REQUIRE(mem_eq(arena.bytes, snap.bytes, sizeof(arena.bytes)));
        case_hit();

        (void)memset(arena.bytes, 0xa5, sizeof(arena.bytes));
        out_len = 0x33333333u;
        REQUIRE(encode_form(f, &host, arena.bytes, n, &out_len)
            == NINLIL_N6_CODEC_OK);
        REQUIRE(out_len == n);
        for (i = n; i < n + 16u; ++i) {
            REQUIRE(arena.bytes[i] == 0xa5u);
        }
        case_hit();

        (void)memset(arena.bytes, 0xa5, sizeof(arena.bytes));
        out_len = 0x44444444u;
        REQUIRE(encode_form(f, &host, arena.bytes, n + 1u, &out_len)
            == NINLIL_N6_CODEC_OK);
        REQUIRE(out_len == n);
        for (i = n; i < n + 16u; ++i) {
            REQUIRE(arena.bytes[i] == 0xa5u);
        }
        case_hit();
    }
    return 0;
}

/*
 * Encode alias: full, out=in+1, in inside out at host_align offset,
 * out_len@out, out_len@in. Full arena snapshot memcmp after reject.
 * Spacing uses _Alignof(host_u), never sizeof(max_align_t).
 */
static int test_encode_alias_matrix(void)
{
    form_id_t f;
    const size_t align = T_HOST_ALIGN;

    for (f = F_LK; f < F_COUNT; ++f) {
        size_t n = form_wire_n(f);
        size_t hn = form_host_n(f);
        host_u good;
        size_t out_len;
        size_t canary;
        host_for(f, &good);

        /* 1) full alias: out base == host base */
        {
            host_u host;
            host_u snap;
            (void)memcpy(&host, &good, sizeof(host));
            (void)memcpy(&snap, &host, sizeof(host));
            out_len = 0x55555555u;
            canary = out_len;
            REQUIRE(encode_form(f, &host, (uint8_t *)&host, n, &out_len)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(out_len == canary);
            REQUIRE(mem_eq(&host, &snap, sizeof(host)));
            case_hit();
        }

        /* 2) partial out = input + 1 (host aligned) */
        {
            host_u host;
            host_u snap;
            uint8_t *pout;
            (void)memcpy(&host, &good, sizeof(host));
            (void)memcpy(&snap, &host, sizeof(host));
            pout = ((uint8_t *)&host) + 1u;
            out_len = 0x66666666u;
            canary = out_len;
            REQUIRE(encode_form(f, &host, pout, n, &out_len)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(out_len == canary);
            REQUIRE(mem_eq(&host, &snap, sizeof(host)));
            case_hit();
        }

        /* 3) partial input starts inside out at host_align (input=out+align) */
        {
            arena_u arena;
            arena_u snap;
            host_u *pin;
            uint8_t *pout;
            REQUIRE(align + hn + n <= sizeof(arena.bytes));
            REQUIRE(align < n); /* host base inside out[0..n) */
            (void)memset(arena.bytes, 0xdd, sizeof(arena.bytes));
            pout = arena.bytes;
            pin = (host_u *)(void *)(arena.bytes + align);
            (void)memcpy(pin, &good, sizeof(*pin));
            (void)memcpy(snap.bytes, arena.bytes, sizeof(arena.bytes));
            out_len = 0x77777777u;
            canary = out_len;
            REQUIRE(encode_form(f, pin, pout, n, &out_len)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(out_len == canary);
            REQUIRE(mem_eq(arena.bytes, snap.bytes, sizeof(arena.bytes)));
            case_hit();
        }

        /* 4) out_len aliases into out[] at aligned offset 8 */
        {
            arena_u blob;
            arena_u snap;
            size_t *olen;
            const size_t off = 8u;
            REQUIRE(off + sizeof(size_t) <= n);
            (void)memset(blob.bytes, 0xcc, sizeof(blob.bytes));
            olen = (size_t *)(void *)(blob.bytes + off);
            size_t_store(olen, 0x88888888u);
            canary = size_t_load(olen);
            (void)memcpy(snap.bytes, blob.bytes, sizeof(blob.bytes));
            REQUIRE(encode_form(f, &good, blob.bytes, n, olen)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(size_t_load(olen) == canary);
            REQUIRE(mem_eq(blob.bytes, snap.bytes, sizeof(blob.bytes)));
            case_hit();
        }

        /* 5) out_len aliases into logical input at aligned offset 8 */
        {
            host_u host;
            host_u snap;
            arena_u outbuf;
            arena_u out_snap;
            size_t *olen;
            const size_t off = 8u;
            REQUIRE(off + sizeof(size_t) <= hn);
            (void)memcpy(&host, &good, sizeof(host));
            olen = (size_t *)(void *)(((uint8_t *)&host) + off);
            size_t_store(olen, 0x99999999u);
            canary = size_t_load(olen);
            (void)memcpy(&snap, &host, sizeof(host));
            (void)memset(outbuf.bytes, 0xaa, sizeof(outbuf.bytes));
            (void)memcpy(out_snap.bytes, outbuf.bytes, sizeof(outbuf.bytes));
            REQUIRE(encode_form(f, &host, outbuf.bytes, n, olen)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(size_t_load(olen) == canary);
            REQUIRE(mem_eq(&host, &snap, sizeof(host)));
            REQUIRE(mem_eq(outbuf.bytes, out_snap.bytes, sizeof(outbuf.bytes)));
            case_hit();
        }
    }
    return 0;
}

/*
 * Decode alias: full + out=in+1 + in=out+1.
 * Snapshot covers entire host_u (sizeof output struct) and wire arena.
 * Spacing uses _Alignof(host_u), never sizeof(max_align_t).
 */
static int test_decode_alias_matrix(void)
{
    form_id_t f;
    const size_t align = T_HOST_ALIGN;

    for (f = F_LK; f < F_COUNT; ++f) {
        size_t n = form_wire_n(f);
        wire_u lit;
        REQUIRE(parse_hex(form_hex(f), lit.bytes, n) == 0);

        /* full: out host base == wire base via shared arena */
        {
            typedef union {
                max_align_t a;
                uint8_t bytes[sizeof(host_u) + 80u];
            } dec_arena_t;
            dec_arena_t arena;
            dec_arena_t snap;
            host_u *pout;
            uint8_t *pin;
            REQUIRE(n + sizeof(host_u) <= sizeof(arena.bytes));
            (void)memset(arena.bytes, 0x5a, sizeof(arena.bytes));
            pin = arena.bytes;
            (void)memcpy(pin, lit.bytes, n);
            pout = (host_u *)(void *)arena.bytes;
            (void)memcpy(snap.bytes, arena.bytes, sizeof(arena.bytes));
            REQUIRE(decode_form(f, pin, n, pout)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(mem_eq(arena.bytes, snap.bytes, sizeof(arena.bytes)));
            case_hit();
        }

        /*
         * partial out = input + 1:
         * host_u* is aligned; wire pin starts one byte before host so
         * (uint8_t*)pout == pin + 1. pin is uint8_t* (any alignment ok).
         */
        {
            typedef union {
                max_align_t a;
                uint8_t bytes[sizeof(host_u) + 16u + 80u];
            } da_t;
            da_t arena;
            da_t snap;
            host_u *pout;
            uint8_t *pin;
            size_t host_off = align;
            REQUIRE(host_off >= 1u);
            REQUIRE(host_off + sizeof(host_u) <= sizeof(arena.bytes));
            REQUIRE(host_off - 1u + n <= sizeof(arena.bytes));
            (void)memset(arena.bytes, 0x5a, sizeof(arena.bytes));
            pout = (host_u *)(void *)(arena.bytes + host_off);
            pin = ((uint8_t *)pout) - 1u;
            (void)memcpy(pin, lit.bytes, n);
            (void)memcpy(snap.bytes, arena.bytes, sizeof(arena.bytes));
            REQUIRE(decode_form(f, pin, n, pout)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(mem_eq(arena.bytes, snap.bytes, sizeof(arena.bytes)));
            case_hit();
        }

        /* partial input = out + 1: pin = (uint8_t*)pout + 1 */
        {
            typedef union {
                max_align_t a;
                uint8_t bytes[sizeof(host_u) + 80u];
            } da_t;
            da_t arena;
            da_t snap;
            host_u *pout;
            uint8_t *pin;
            REQUIRE(1u + n <= sizeof(arena.bytes));
            (void)memset(arena.bytes, 0x5a, sizeof(arena.bytes));
            pout = (host_u *)(void *)arena.bytes;
            pin = ((uint8_t *)pout) + 1u;
            (void)memcpy(pin, lit.bytes, n);
            (void)memcpy(snap.bytes, arena.bytes, sizeof(arena.bytes));
            REQUIRE(decode_form(f, pin, n, pout)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(mem_eq(arena.bytes, snap.bytes, sizeof(arena.bytes)));
            case_hit();
        }
    }
    return 0;
}

static int test_null_kat(void)
{
    form_id_t f;
    for (f = F_LK; f < F_COUNT; ++f) {
        size_t n = form_wire_n(f);
        wire_u wire;
        host_u host;
        host_u host_snap;
        arena_u out_arena;
        arena_u out_snap;
        size_t out_len;
        size_t canary;

        REQUIRE(parse_hex(form_hex(f), wire.bytes, n) == 0);
        host_for(f, &host);

        /* decoder out=NULL */
        {
            wire_u wsnap;
            (void)memcpy(wsnap.bytes, wire.bytes, sizeof(wire.bytes));
            REQUIRE(decode_form(f, wire.bytes, n, NULL)
                == NINLIL_N6_CODEC_INVALID_ARGUMENT);
            REQUIRE(mem_eq(wire.bytes, wsnap.bytes, sizeof(wire.bytes)));
            case_hit();
        }

        /* encoder in=NULL */
        (void)memset(out_arena.bytes, 0xab, sizeof(out_arena.bytes));
        (void)memcpy(out_snap.bytes, out_arena.bytes, sizeof(out_arena.bytes));
        out_len = 0xaaaaaaaaU;
        canary = out_len;
        REQUIRE(encode_form(f, NULL, out_arena.bytes, n, &out_len)
            == NINLIL_N6_CODEC_INVALID_ARGUMENT);
        REQUIRE(out_len == canary);
        REQUIRE(mem_eq(out_arena.bytes, out_snap.bytes, sizeof(out_arena.bytes)));
        case_hit();

        /* encoder out=NULL */
        (void)memcpy(&host_snap, &host, sizeof(host));
        out_len = 0xbbbbbbbbU;
        canary = out_len;
        REQUIRE(encode_form(f, &host, NULL, n, &out_len)
            == NINLIL_N6_CODEC_INVALID_ARGUMENT);
        REQUIRE(out_len == canary);
        REQUIRE(mem_eq(&host, &host_snap, sizeof(host)));
        case_hit();

        /* encoder out_len=NULL */
        (void)memset(out_arena.bytes, 0xcd, sizeof(out_arena.bytes));
        (void)memcpy(out_snap.bytes, out_arena.bytes, sizeof(out_arena.bytes));
        (void)memcpy(&host_snap, &host, sizeof(host));
        REQUIRE(encode_form(f, &host, out_arena.bytes, n, NULL)
            == NINLIL_N6_CODEC_INVALID_ARGUMENT);
        REQUIRE(mem_eq(out_arena.bytes, out_snap.bytes, sizeof(out_arena.bytes)));
        REQUIRE(mem_eq(&host, &host_snap, sizeof(host)));
        case_hit();
    }
    return 0;
}

static int test_wrong_decoder_matrix(void)
{
    form_id_t src;
    form_id_t dst;
    unsigned hits = 0u;
    for (src = F_LK; src < F_COUNT; ++src) {
        wire_u wire;
        size_t n = form_wire_n(src);
        REQUIRE(parse_hex(form_hex(src), wire.bytes, n) == 0);
        for (dst = F_LK; dst < F_COUNT; ++dst) {
            host_u host;
            host_u snap;
            if (dst == src) {
                continue;
            }
            (void)memset(&host, 0x5a, sizeof(host));
            (void)memcpy(&snap, &host, sizeof(host));
            REQUIRE(decode_form(dst, wire.bytes, n, &host)
                == NINLIL_N6_CODEC_REJECT);
            REQUIRE(mem_eq(&host, &snap, sizeof(host)));
            case_hit();
            ++hits;
        }
    }
    REQUIRE(hits == T_CASE_WRONG_DECODER);
    return 0;
}

static int test_value_crc_all_bits(void)
{
    static const form_id_t vals[6] = {
        F_TX, F_RX, F_HWV, F_ALV, F_RTV, F_CFV
    };
    unsigned covered_hits = 0u;
    unsigned crc_hits = 0u;
    size_t vi;
    for (vi = 0u; vi < 6u; ++vi) {
        form_id_t f = vals[vi];
        size_t n = form_wire_n(f);
        size_t cov = form_cov(f);
        wire_u good;
        size_t bit;
        REQUIRE(parse_hex(form_hex(f), good.bytes, n) == 0);
        for (bit = 0u; bit < cov * 8u; ++bit) {
            wire_u bad;
            host_u host;
            host_u snap;
            size_t byte = bit / 8u;
            uint8_t mask = (uint8_t)(1u << (bit % 8u));
            (void)memcpy(bad.bytes, good.bytes, n);
            bad.bytes[byte] = (uint8_t)(bad.bytes[byte] ^ mask);
            (void)memset(&host, 0x5a, sizeof(host));
            (void)memcpy(&snap, &host, sizeof(host));
            REQUIRE(decode_form(f, bad.bytes, n, &host)
                == NINLIL_N6_CODEC_REJECT);
            REQUIRE(mem_eq(&host, &snap, sizeof(host)));
            case_hit();
            ++covered_hits;
        }
        for (bit = 0u; bit < 32u; ++bit) {
            wire_u bad;
            host_u host;
            host_u snap;
            size_t byte = cov + (bit / 8u);
            uint8_t mask = (uint8_t)(1u << (bit % 8u));
            (void)memcpy(bad.bytes, good.bytes, n);
            bad.bytes[byte] = (uint8_t)(bad.bytes[byte] ^ mask);
            (void)memset(&host, 0x5a, sizeof(host));
            (void)memcpy(&snap, &host, sizeof(host));
            REQUIRE(decode_form(f, bad.bytes, n, &host)
                == NINLIL_N6_CODEC_REJECT);
            REQUIRE(mem_eq(&host, &snap, sizeof(host)));
            case_hit();
            ++crc_hits;
        }
    }
    REQUIRE(covered_hits == T_VALUE_COVERED_BITS);
    REQUIRE(crc_hits == T_VALUE_STORED_CRC_BITS);
    return 0;
}

/* Decode value after independent re-CRC; host mutation 0. */
static int reject_decode_value(
    form_id_t f, uint8_t *wire, size_t n, size_t cov, int do_recrc)
{
    host_u host;
    host_u snap;
    if (do_recrc) {
        re_crc(wire, cov);
    }
    (void)memset(&host, 0x5a, sizeof(host));
    (void)memcpy(&snap, &host, sizeof(host));
    REQUIRE(decode_form(f, wire, n, &host) == NINLIL_N6_CODEC_REJECT);
    REQUIRE(mem_eq(&host, &snap, sizeof(host)));
    case_hit();
    return 0;
}

/* Encode bad host; out arena + out_len mutation 0. */
static int reject_encode_host(form_id_t f, const host_u *bad)
{
    arena_u out;
    arena_u snap;
    size_t n = form_wire_n(f);
    size_t out_len = 0xcafebabeu;
    size_t canary = out_len;
    (void)memset(out.bytes, 0x3c, sizeof(out.bytes));
    (void)memcpy(snap.bytes, out.bytes, sizeof(out.bytes));
    REQUIRE(encode_form(f, bad, out.bytes, n, &out_len)
        == NINLIL_N6_CODEC_REJECT);
    REQUIRE(out_len == canary);
    REQUIRE(mem_eq(out.bytes, snap.bytes, sizeof(out.bytes)));
    case_hit();
    return 0;
}

static int reject_decode_key(form_id_t f, const uint8_t *wire, size_t n)
{
    host_u host;
    host_u snap;
    (void)memset(&host, 0x5a, sizeof(host));
    (void)memcpy(&snap, &host, sizeof(host));
    REQUIRE(decode_form(f, wire, n, &host) == NINLIL_N6_CODEC_REJECT);
    REQUIRE(mem_eq(&host, &snap, sizeof(host)));
    case_hit();
    return 0;
}

static int domain_value_pair(
    form_id_t f,
    void (*mut_wire)(uint8_t *w),
    void (*mut_host)(host_u *h))
{
    wire_u w;
    host_u h;
    size_t n = form_wire_n(f);
    size_t cov = form_cov(f);
    REQUIRE(parse_hex(form_hex(f), w.bytes, n) == 0);
    mut_wire(w.bytes);
    if (reject_decode_value(f, w.bytes, n, cov, 1) != 0) {
        return 1;
    }
    host_for(f, &h);
    mut_host(&h);
    if (reject_encode_host(f, &h) != 0) {
        return 1;
    }
    return 0;
}

static int domain_key_pair(
    form_id_t f,
    void (*mut_wire)(uint8_t *w),
    void (*mut_host)(host_u *h))
{
    wire_u w;
    host_u h;
    size_t n = form_wire_n(f);
    REQUIRE(parse_hex(form_hex(f), w.bytes, n) == 0);
    mut_wire(w.bytes);
    if (reject_decode_key(f, w.bytes, n) != 0) {
        return 1;
    }
    host_for(f, &h);
    mut_host(&h);
    if (reject_encode_host(f, &h) != 0) {
        return 1;
    }
    return 0;
}

/* ---- closed-domain mutators (wire / host), independent literals ---- */

static void w_tx_magic(uint8_t *w)
{
    put_u32_be(w + 0, 0x00000000u);
}
static void h_tx_magic(host_u *h)
{
    h->tx.magic = 0u;
}
static void w_tx_schema(uint8_t *w)
{
    put_u16_be(w + 4, 1u);
}
static void h_tx_schema(host_u *h)
{
    h->tx.schema = 1u;
}
static void w_tx_reserved0(uint8_t *w)
{
    put_u16_be(w + 6, 1u);
}
static void h_tx_reserved0(host_u *h)
{
    h->tx.reserved0 = 1u;
}
static void w_tx_rex(uint8_t *w)
{
    put_u64_be(w + 8, 0ull);
}
static void h_tx_rex(host_u *h)
{
    h->tx.reserved_exclusive = 0ull;
}
static void w_tx_kgen(uint8_t *w)
{
    put_u64_be(w + 16, 0ull);
}
static void h_tx_kgen(host_u *h)
{
    h->tx.key_generation = 0ull;
}
static void w_tx_epoch(uint8_t *w)
{
    put_u64_be(w + 40, 0ull);
}
static void h_tx_epoch(host_u *h)
{
    h->tx.membership_epoch = 0ull;
}
static void w_tx_alloc(uint8_t *w)
{
    w[48] = 1u;
}
static void h_tx_alloc(host_u *h)
{
    h->tx.alloc_side = 1u;
}
static void w_tx_reserved1_0(uint8_t *w)
{
    w[49] = 1u;
}
static void h_tx_reserved1_0(host_u *h)
{
    h->tx.reserved1[0] = 1u;
}
static void w_tx_reserved1_1(uint8_t *w)
{
    w[50] = 1u;
}
static void h_tx_reserved1_1(host_u *h)
{
    h->tx.reserved1[1] = 1u;
}
static void w_tx_reserved1_2(uint8_t *w)
{
    w[51] = 1u;
}
static void h_tx_reserved1_2(host_u *h)
{
    h->tx.reserved1[2] = 1u;
}

static void w_rx_magic(uint8_t *w)
{
    put_u32_be(w + 0, 0u);
}
static void h_rx_magic(host_u *h)
{
    h->rx.magic = 0u;
}
static void w_rx_schema(uint8_t *w)
{
    put_u16_be(w + 4, 0u);
}
static void h_rx_schema(host_u *h)
{
    h->rx.schema = 0u;
}
static void w_rx_reserved0(uint8_t *w)
{
    put_u16_be(w + 6, 1u);
}
static void h_rx_reserved0(host_u *h)
{
    h->rx.reserved0 = 1u;
}
static void w_rx_kgen(uint8_t *w)
{
    put_u64_be(w + 16, 0ull);
}
static void h_rx_kgen(host_u *h)
{
    h->rx.key_generation = 0ull;
}
static void w_rx_epoch(uint8_t *w)
{
    put_u64_be(w + 40, 0ull);
}
static void h_rx_epoch(host_u *h)
{
    h->rx.membership_epoch = 0ull;
}
static void w_rx_alloc(uint8_t *w)
{
    w[48] = 2u;
}
static void h_rx_alloc(host_u *h)
{
    h->rx.alloc_side = 2u;
}
static void w_rx_reserved1_0(uint8_t *w)
{
    w[49] = 1u;
}
static void h_rx_reserved1_0(host_u *h)
{
    h->rx.reserved1[0] = 1u;
}
static void w_rx_reserved1_1(uint8_t *w)
{
    w[50] = 1u;
}
static void h_rx_reserved1_1(host_u *h)
{
    h->rx.reserved1[1] = 1u;
}
static void w_rx_reserved1_2(uint8_t *w)
{
    w[51] = 1u;
}
static void h_rx_reserved1_2(host_u *h)
{
    h->rx.reserved1[2] = 1u;
}

static void w_hwv_magic(uint8_t *w)
{
    put_u32_be(w + 0, 0u);
}
static void h_hwv_magic(host_u *h)
{
    h->hwv.magic = 0u;
}
static void w_hwv_schema(uint8_t *w)
{
    put_u16_be(w + 4, 2u);
}
static void h_hwv_schema(host_u *h)
{
    h->hwv.schema = 2u;
}
static void w_hwv_reserved0(uint8_t *w)
{
    put_u16_be(w + 6, 1u);
}
static void h_hwv_reserved0(host_u *h)
{
    h->hwv.reserved0 = 1u;
}
static void w_hwv_zero(uint8_t *w)
{
    put_u64_be(w + 8, 0ull);
}
static void h_hwv_zero(host_u *h)
{
    h->hwv.high_water_key_generation = 0ull;
}

static void w_alv_magic(uint8_t *w)
{
    put_u32_be(w + 0, 0u);
}
static void h_alv_magic(host_u *h)
{
    h->alv.magic = 0u;
}
static void w_alv_schema(uint8_t *w)
{
    put_u16_be(w + 4, 1u);
}
static void h_alv_schema(host_u *h)
{
    h->alv.schema = 1u;
}
static void w_alv_reserved0(uint8_t *w)
{
    put_u16_be(w + 6, 1u);
}
static void h_alv_reserved0(host_u *h)
{
    h->alv.reserved0 = 1u;
}
static void w_alv_reserved1(uint8_t *w)
{
    put_u32_be(w + 16, 1u);
}
static void h_alv_reserved1(host_u *h)
{
    h->alv.reserved1 = 1u;
}
static void w_alv_floor(uint8_t *w)
{
    put_u32_be(w + 8, 0u);
}
static void h_alv_floor(host_u *h)
{
    h->alv.next_free_or_peer_floor = 0u;
}
static void w_alv_epoch(uint8_t *w)
{
    put_u64_be(w + 20, 0ull);
}
static void h_alv_epoch(host_u *h)
{
    h->alv.membership_epoch = 0ull;
}

static void w_rtv_magic(uint8_t *w)
{
    put_u32_be(w + 0, 0u);
}
static void h_rtv_magic(host_u *h)
{
    h->rtv.magic = 0u;
}
static void w_rtv_schema(uint8_t *w)
{
    put_u16_be(w + 4, 1u);
}
static void h_rtv_schema(host_u *h)
{
    h->rtv.schema = 1u;
}
static void w_rtv_flags(uint8_t *w)
{
    put_u16_be(w + 6, 0u);
}
static void h_rtv_flags(host_u *h)
{
    h->rtv.flags = 0u;
}
static void w_rtv_cid0(uint8_t *w)
{
    put_u32_be(w + 8, 0u);
}
static void h_rtv_cid0(host_u *h)
{
    h->rtv.context_id = 0u;
}
static void w_rtv_cidmax(uint8_t *w)
{
    put_u32_be(w + 8, 0xffffffffu);
}
static void h_rtv_cidmax(host_u *h)
{
    h->rtv.context_id = 0xffffffffu;
}
static void w_rtv_epoch(uint8_t *w)
{
    put_u64_be(w + 12, 0ull);
}
static void h_rtv_epoch(host_u *h)
{
    h->rtv.membership_epoch = 0ull;
}
static void w_rtv_last0(uint8_t *w)
{
    put_u64_be(w + 20, 0ull);
}
static void h_rtv_last0(host_u *h)
{
    h->rtv.last_key_generation_high_water = 0ull;
}
static void w_rtv_alloc(uint8_t *w)
{
    w[40] = 0u;
}
static void h_rtv_alloc(host_u *h)
{
    h->rtv.alloc_side = 0u;
}
static void w_rtv_dir(uint8_t *w)
{
    w[41] = 2u;
}
static void h_rtv_dir(host_u *h)
{
    h->rtv.direction_code = 2u;
}
static void w_rtv_layer(uint8_t *w)
{
    w[42] = 0u;
}
static void h_rtv_layer(host_u *h)
{
    h->rtv.layer_code = 0u;
}
static void w_rtv_reserved0(uint8_t *w)
{
    w[43] = 1u;
}
static void h_rtv_reserved0(host_u *h)
{
    h->rtv.reserved0 = 1u;
}

static void w_cfv_magic(uint8_t *w)
{
    put_u32_be(w + 0, 0u);
}
static void h_cfv_magic(host_u *h)
{
    h->cfv.magic = 0u;
}
static void w_cfv_schema(uint8_t *w)
{
    put_u16_be(w + 4, 1u);
}
static void h_cfv_schema(host_u *h)
{
    h->cfv.schema = 1u;
}
static void w_cfv_flags(uint8_t *w)
{
    put_u16_be(w + 6, 0u);
}
static void h_cfv_flags(host_u *h)
{
    h->cfv.flags = 0u;
}
static void w_cfv_cid0(uint8_t *w)
{
    put_u32_be(w + 8, 0u);
}
static void h_cfv_cid0(host_u *h)
{
    h->cfv.context_id = 0u;
}
static void w_cfv_cidmax(uint8_t *w)
{
    put_u32_be(w + 8, 0xffffffffu);
}
static void h_cfv_cidmax(host_u *h)
{
    h->cfv.context_id = 0xffffffffu;
}
static void w_cfv_epoch(uint8_t *w)
{
    put_u64_be(w + 12, 0ull);
}
static void h_cfv_epoch(host_u *h)
{
    h->cfv.membership_epoch = 0ull;
}
static void w_cfv_reason0(uint8_t *w)
{
    w[59] = 0u;
}
static void h_cfv_reason0(host_u *h)
{
    h->cfv.reason = 0u;
}
static void w_cfv_reason6(uint8_t *w)
{
    w[59] = 6u;
}
static void h_cfv_reason6(host_u *h)
{
    h->cfv.reason = 6u;
}
static void w_cfv_alloc(uint8_t *w)
{
    w[56] = 0u;
}
static void h_cfv_alloc(host_u *h)
{
    h->cfv.alloc_side = 0u;
}
static void w_cfv_dir(uint8_t *w)
{
    w[57] = 3u;
}
static void h_cfv_dir(host_u *h)
{
    h->cfv.direction_code = 3u;
}
static void w_cfv_layer(uint8_t *w)
{
    w[58] = 0u;
}
static void h_cfv_layer(host_u *h)
{
    h->cfv.layer_code = 0u;
}

static void w_lk_layer(uint8_t *w)
{
    w[0] = 0u;
}
static void h_lk_layer(host_u *h)
{
    h->lk.layer_code = 0u;
}
static void w_lk_lane_mismatch(uint8_t *w)
{
    w[0] = 1u;
    w[1] = 3u;
} /* HOP + E2E kind */
static void h_lk_lane_mismatch(host_u *h)
{
    h->lk.layer_code = 1u;
    h->lk.kind_or_lane = 3u;
}
static void w_lk_dir(uint8_t *w)
{
    w[2] = 2u;
}
static void h_lk_dir(host_u *h)
{
    h->lk.direction_code = 2u;
}
static void w_lk_reserved(uint8_t *w)
{
    w[3] = 1u;
}
static void h_lk_reserved(host_u *h)
{
    h->lk.reserved0 = 1u;
}
static void w_lk_cid0(uint8_t *w)
{
    put_u32_be(w + 4, 0u);
}
static void h_lk_cid0(host_u *h)
{
    h->lk.context_id = 0u;
}
static void w_lk_cidmax(uint8_t *w)
{
    put_u32_be(w + 4, 0xffffffffu);
}
static void h_lk_cidmax(host_u *h)
{
    h->lk.context_id = 0xffffffffu;
}
static void w_lk_kgen0(uint8_t *w)
{
    put_u64_be(w + 40, 0ull);
}
static void h_lk_kgen0(host_u *h)
{
    h->lk.key_generation = 0ull;
}

static void w_hwk_kind(uint8_t *w)
{
    w[0] = 2u;
}
static void h_hwk_kind(host_u *h)
{
    h->hwk.rec_kind = 2u;
}
static void w_hwk_layer(uint8_t *w)
{
    w[1] = 0u;
}
static void h_hwk_layer(host_u *h)
{
    h->hwk.layer_code = 0u;
}
static void w_hwk_dir(uint8_t *w)
{
    w[2] = 3u;
}
static void h_hwk_dir(host_u *h)
{
    h->hwk.direction_code = 3u;
}
static void w_hwk_reserved(uint8_t *w)
{
    w[3] = 1u;
}
static void h_hwk_reserved(host_u *h)
{
    h->hwk.reserved0 = 1u;
}

static void w_alk_kind(uint8_t *w)
{
    w[0] = 1u;
}
static void h_alk_kind(host_u *h)
{
    h->alk.rec_kind = 1u;
}
static void w_alk_layer(uint8_t *w)
{
    w[1] = 0u;
}
static void h_alk_layer(host_u *h)
{
    h->alk.layer_code = 0u;
}
static void w_alk_alloc(uint8_t *w)
{
    w[2] = 0u;
}
static void h_alk_alloc(host_u *h)
{
    h->alk.alloc_side = 0u;
}
static void w_alk_reserved(uint8_t *w)
{
    w[3] = 1u;
}
static void h_alk_reserved(host_u *h)
{
    h->alk.reserved0 = 1u;
}
static void w_alk_epoch(uint8_t *w)
{
    put_u64_be(w + 4, 0ull);
}
static void h_alk_epoch(host_u *h)
{
    h->alk.membership_epoch = 0ull;
}

static void w_rtk_kind(uint8_t *w)
{
    w[0] = 1u;
}
static void h_rtk_kind(host_u *h)
{
    h->rtk.rec_kind = 1u;
}
static void w_rtk_layer(uint8_t *w)
{
    w[1] = 0u;
}
static void h_rtk_layer(host_u *h)
{
    h->rtk.layer_code = 0u;
}
static void w_rtk_dir(uint8_t *w)
{
    w[2] = 2u;
}
static void h_rtk_dir(host_u *h)
{
    h->rtk.direction_code = 2u;
}
static void w_rtk_alloc(uint8_t *w)
{
    w[3] = 0u;
}
static void h_rtk_alloc(host_u *h)
{
    h->rtk.alloc_side = 0u;
}
static void w_rtk_cid0(uint8_t *w)
{
    put_u32_be(w + 4, 0u);
}
static void h_rtk_cid0(host_u *h)
{
    h->rtk.context_id = 0u;
}
static void w_rtk_cidmax(uint8_t *w)
{
    put_u32_be(w + 4, 0xffffffffu);
}
static void h_rtk_cidmax(host_u *h)
{
    h->rtk.context_id = 0xffffffffu;
}
static void w_rtk_epoch(uint8_t *w)
{
    put_u64_be(w + 8, 0ull);
}
static void h_rtk_epoch(host_u *h)
{
    h->rtk.membership_epoch = 0ull;
}

static void w_cfk_kind(uint8_t *w)
{
    w[0] = 3u;
}
static void h_cfk_kind(host_u *h)
{
    h->cfk.rec_kind = 3u;
}
static void w_cfk_layer(uint8_t *w)
{
    w[1] = 0u;
}
static void h_cfk_layer(host_u *h)
{
    h->cfk.layer_code = 0u;
}
static void w_cfk_dir(uint8_t *w)
{
    w[2] = 2u;
}
static void h_cfk_dir(host_u *h)
{
    h->cfk.direction_code = 2u;
}
static void w_cfk_alloc(uint8_t *w)
{
    w[3] = 0u;
}
static void h_cfk_alloc(host_u *h)
{
    h->cfk.alloc_side = 0u;
}
static void w_cfk_cid0(uint8_t *w)
{
    put_u32_be(w + 4, 0u);
}
static void h_cfk_cid0(host_u *h)
{
    h->cfk.context_id = 0u;
}
static void w_cfk_cidmax(uint8_t *w)
{
    put_u32_be(w + 4, 0xffffffffu);
}
static void h_cfk_cidmax(host_u *h)
{
    h->cfk.context_id = 0xffffffffu;
}
static void w_cfk_epoch(uint8_t *w)
{
    put_u64_be(w + 8, 0ull);
}
static void h_cfk_epoch(host_u *h)
{
    h->cfk.membership_epoch = 0ull;
}

static int test_closed_domain_all_branches(void)
{
    unsigned before = g_cases;

    /* TX 10 (reserved1[0..2] per-byte) */
    if (domain_value_pair(F_TX, w_tx_magic, h_tx_magic) != 0
        || domain_value_pair(F_TX, w_tx_schema, h_tx_schema) != 0
        || domain_value_pair(F_TX, w_tx_reserved0, h_tx_reserved0) != 0
        || domain_value_pair(F_TX, w_tx_rex, h_tx_rex) != 0
        || domain_value_pair(F_TX, w_tx_kgen, h_tx_kgen) != 0
        || domain_value_pair(F_TX, w_tx_epoch, h_tx_epoch) != 0
        || domain_value_pair(F_TX, w_tx_alloc, h_tx_alloc) != 0
        || domain_value_pair(F_TX, w_tx_reserved1_0, h_tx_reserved1_0) != 0
        || domain_value_pair(F_TX, w_tx_reserved1_1, h_tx_reserved1_1) != 0
        || domain_value_pair(F_TX, w_tx_reserved1_2, h_tx_reserved1_2) != 0) {
        return 1;
    }
    /* RX 9 (reserved1[0..2] per-byte) */
    if (domain_value_pair(F_RX, w_rx_magic, h_rx_magic) != 0
        || domain_value_pair(F_RX, w_rx_schema, h_rx_schema) != 0
        || domain_value_pair(F_RX, w_rx_reserved0, h_rx_reserved0) != 0
        || domain_value_pair(F_RX, w_rx_kgen, h_rx_kgen) != 0
        || domain_value_pair(F_RX, w_rx_epoch, h_rx_epoch) != 0
        || domain_value_pair(F_RX, w_rx_alloc, h_rx_alloc) != 0
        || domain_value_pair(F_RX, w_rx_reserved1_0, h_rx_reserved1_0) != 0
        || domain_value_pair(F_RX, w_rx_reserved1_1, h_rx_reserved1_1) != 0
        || domain_value_pair(F_RX, w_rx_reserved1_2, h_rx_reserved1_2) != 0) {
        return 1;
    }
    /* HWV 4 (includes high_water=0 unique) */
    if (domain_value_pair(F_HWV, w_hwv_magic, h_hwv_magic) != 0
        || domain_value_pair(F_HWV, w_hwv_schema, h_hwv_schema) != 0
        || domain_value_pair(F_HWV, w_hwv_reserved0, h_hwv_reserved0) != 0
        || domain_value_pair(F_HWV, w_hwv_zero, h_hwv_zero) != 0) {
        return 1;
    }
    /* ALV 6 */
    if (domain_value_pair(F_ALV, w_alv_magic, h_alv_magic) != 0
        || domain_value_pair(F_ALV, w_alv_schema, h_alv_schema) != 0
        || domain_value_pair(F_ALV, w_alv_reserved0, h_alv_reserved0) != 0
        || domain_value_pair(F_ALV, w_alv_reserved1, h_alv_reserved1) != 0
        || domain_value_pair(F_ALV, w_alv_floor, h_alv_floor) != 0
        || domain_value_pair(F_ALV, w_alv_epoch, h_alv_epoch) != 0) {
        return 1;
    }
    /* RTV 11 (includes last_hw=0 unique) */
    if (domain_value_pair(F_RTV, w_rtv_magic, h_rtv_magic) != 0
        || domain_value_pair(F_RTV, w_rtv_schema, h_rtv_schema) != 0
        || domain_value_pair(F_RTV, w_rtv_flags, h_rtv_flags) != 0
        || domain_value_pair(F_RTV, w_rtv_cid0, h_rtv_cid0) != 0
        || domain_value_pair(F_RTV, w_rtv_cidmax, h_rtv_cidmax) != 0
        || domain_value_pair(F_RTV, w_rtv_epoch, h_rtv_epoch) != 0
        || domain_value_pair(F_RTV, w_rtv_last0, h_rtv_last0) != 0
        || domain_value_pair(F_RTV, w_rtv_alloc, h_rtv_alloc) != 0
        || domain_value_pair(F_RTV, w_rtv_dir, h_rtv_dir) != 0
        || domain_value_pair(F_RTV, w_rtv_layer, h_rtv_layer) != 0
        || domain_value_pair(F_RTV, w_rtv_reserved0, h_rtv_reserved0) != 0) {
        return 1;
    }
    /* CFV 11 */
    if (domain_value_pair(F_CFV, w_cfv_magic, h_cfv_magic) != 0
        || domain_value_pair(F_CFV, w_cfv_schema, h_cfv_schema) != 0
        || domain_value_pair(F_CFV, w_cfv_flags, h_cfv_flags) != 0
        || domain_value_pair(F_CFV, w_cfv_cid0, h_cfv_cid0) != 0
        || domain_value_pair(F_CFV, w_cfv_cidmax, h_cfv_cidmax) != 0
        || domain_value_pair(F_CFV, w_cfv_epoch, h_cfv_epoch) != 0
        || domain_value_pair(F_CFV, w_cfv_reason0, h_cfv_reason0) != 0
        || domain_value_pair(F_CFV, w_cfv_reason6, h_cfv_reason6) != 0
        || domain_value_pair(F_CFV, w_cfv_alloc, h_cfv_alloc) != 0
        || domain_value_pair(F_CFV, w_cfv_dir, h_cfv_dir) != 0
        || domain_value_pair(F_CFV, w_cfv_layer, h_cfv_layer) != 0) {
        return 1;
    }
    /* LK 7 */
    if (domain_key_pair(F_LK, w_lk_layer, h_lk_layer) != 0
        || domain_key_pair(F_LK, w_lk_lane_mismatch, h_lk_lane_mismatch) != 0
        || domain_key_pair(F_LK, w_lk_dir, h_lk_dir) != 0
        || domain_key_pair(F_LK, w_lk_reserved, h_lk_reserved) != 0
        || domain_key_pair(F_LK, w_lk_cid0, h_lk_cid0) != 0
        || domain_key_pair(F_LK, w_lk_cidmax, h_lk_cidmax) != 0
        || domain_key_pair(F_LK, w_lk_kgen0, h_lk_kgen0) != 0) {
        return 1;
    }
    /* HWK 4 */
    if (domain_key_pair(F_HWK, w_hwk_kind, h_hwk_kind) != 0
        || domain_key_pair(F_HWK, w_hwk_layer, h_hwk_layer) != 0
        || domain_key_pair(F_HWK, w_hwk_dir, h_hwk_dir) != 0
        || domain_key_pair(F_HWK, w_hwk_reserved, h_hwk_reserved) != 0) {
        return 1;
    }
    /* ALK 5 */
    if (domain_key_pair(F_ALK, w_alk_kind, h_alk_kind) != 0
        || domain_key_pair(F_ALK, w_alk_layer, h_alk_layer) != 0
        || domain_key_pair(F_ALK, w_alk_alloc, h_alk_alloc) != 0
        || domain_key_pair(F_ALK, w_alk_reserved, h_alk_reserved) != 0
        || domain_key_pair(F_ALK, w_alk_epoch, h_alk_epoch) != 0) {
        return 1;
    }
    /* RTK 7 */
    if (domain_key_pair(F_RTK, w_rtk_kind, h_rtk_kind) != 0
        || domain_key_pair(F_RTK, w_rtk_layer, h_rtk_layer) != 0
        || domain_key_pair(F_RTK, w_rtk_dir, h_rtk_dir) != 0
        || domain_key_pair(F_RTK, w_rtk_alloc, h_rtk_alloc) != 0
        || domain_key_pair(F_RTK, w_rtk_cid0, h_rtk_cid0) != 0
        || domain_key_pair(F_RTK, w_rtk_cidmax, h_rtk_cidmax) != 0
        || domain_key_pair(F_RTK, w_rtk_epoch, h_rtk_epoch) != 0) {
        return 1;
    }
    /* CFK 7 */
    if (domain_key_pair(F_CFK, w_cfk_kind, h_cfk_kind) != 0
        || domain_key_pair(F_CFK, w_cfk_layer, h_cfk_layer) != 0
        || domain_key_pair(F_CFK, w_cfk_dir, h_cfk_dir) != 0
        || domain_key_pair(F_CFK, w_cfk_alloc, h_cfk_alloc) != 0
        || domain_key_pair(F_CFK, w_cfk_cid0, h_cfk_cid0) != 0
        || domain_key_pair(F_CFK, w_cfk_cidmax, h_cfk_cidmax) != 0
        || domain_key_pair(F_CFK, w_cfk_epoch, h_cfk_epoch) != 0) {
        return 1;
    }

    REQUIRE((g_cases - before) == T_CASE_CLOSED_DOMAIN);
    return 0;
}


/* Lane kind×layer matrix beyond the fixed HOP+ACK oracle and HOP+E2E fail. */
static int test_lane_kind_matrix(void)
{
    unsigned before = g_cases;
    host_u h;
    arena_u enc;
    size_t elen;
    host_u out;
    host_u snap;
    wire_u wire;

    /* HOP + DATA success (layer=1, kind=1) */
    host_lk(&h);
    h.lk.layer_code = 1u;
    h.lk.kind_or_lane = 1u;
    elen = 0u;
    (void)memset(enc.bytes, 0xcc, sizeof(enc.bytes));
    REQUIRE(encode_form(F_LK, &h, enc.bytes, T_LK_N, &elen) == NINLIL_N6_CODEC_OK);
    REQUIRE(elen == T_LK_N);
    REQUIRE(enc.bytes[0] == 1u && enc.bytes[1] == 1u);
    case_hit();
    (void)memset(&out, 0x5a, sizeof(out));
    REQUIRE(decode_form(F_LK, enc.bytes, T_LK_N, &out) == NINLIL_N6_CODEC_OK);
    REQUIRE(out.lk.layer_code == 1u && out.lk.kind_or_lane == 1u);
    case_hit();

    /* E2E + E2E success (layer=2, kind=3) */
    host_lk(&h);
    h.lk.layer_code = 2u;
    h.lk.kind_or_lane = 3u;
    elen = 0u;
    (void)memset(enc.bytes, 0xcc, sizeof(enc.bytes));
    REQUIRE(encode_form(F_LK, &h, enc.bytes, T_LK_N, &elen) == NINLIL_N6_CODEC_OK);
    REQUIRE(elen == T_LK_N);
    REQUIRE(enc.bytes[0] == 2u && enc.bytes[1] == 3u);
    case_hit();
    (void)memset(&out, 0x5a, sizeof(out));
    REQUIRE(decode_form(F_LK, enc.bytes, T_LK_N, &out) == NINLIL_N6_CODEC_OK);
    REQUIRE(out.lk.layer_code == 2u && out.lk.kind_or_lane == 3u);
    case_hit();

    /* E2E + HOP_DATA failure (layer=2, kind=1) */
    host_lk(&h);
    h.lk.layer_code = 2u;
    h.lk.kind_or_lane = 1u;
    elen = 0xcafebabeu;
    (void)memset(enc.bytes, 0x3c, sizeof(enc.bytes));
    {
        arena_u snap_enc;
        (void)memcpy(snap_enc.bytes, enc.bytes, sizeof(enc.bytes));
        REQUIRE(encode_form(F_LK, &h, enc.bytes, T_LK_N, &elen)
            == NINLIL_N6_CODEC_REJECT);
        REQUIRE(elen == 0xcafebabeu);
        REQUIRE(mem_eq(enc.bytes, snap_enc.bytes, sizeof(enc.bytes)));
    }
    case_hit();
    REQUIRE(parse_hex(HEX_LK, wire.bytes, T_LK_N) == 0);
    wire.bytes[0] = 2u;
    wire.bytes[1] = 1u;
    (void)memset(&out, 0x5a, sizeof(out));
    (void)memcpy(&snap, &out, sizeof(out));
    REQUIRE(decode_form(F_LK, wire.bytes, T_LK_N, &out) == NINLIL_N6_CODEC_REJECT);
    REQUIRE(mem_eq(&out, &snap, sizeof(out)));
    case_hit();

    /* E2E + ACK failure (layer=2, kind=2) */
    host_lk(&h);
    h.lk.layer_code = 2u;
    h.lk.kind_or_lane = 2u;
    elen = 0xdeadbeefu;
    (void)memset(enc.bytes, 0x3d, sizeof(enc.bytes));
    {
        arena_u snap_enc;
        (void)memcpy(snap_enc.bytes, enc.bytes, sizeof(enc.bytes));
        REQUIRE(encode_form(F_LK, &h, enc.bytes, T_LK_N, &elen)
            == NINLIL_N6_CODEC_REJECT);
        REQUIRE(elen == 0xdeadbeefu);
        REQUIRE(mem_eq(enc.bytes, snap_enc.bytes, sizeof(enc.bytes)));
    }
    case_hit();
    REQUIRE(parse_hex(HEX_LK, wire.bytes, T_LK_N) == 0);
    wire.bytes[0] = 2u;
    wire.bytes[1] = 2u;
    (void)memset(&out, 0x5a, sizeof(out));
    (void)memcpy(&snap, &out, sizeof(out));
    REQUIRE(decode_form(F_LK, wire.bytes, T_LK_N, &out) == NINLIL_N6_CODEC_REJECT);
    REQUIRE(mem_eq(&out, &snap, sizeof(out)));
    case_hit();

    REQUIRE((g_cases - before) == T_CASE_LANE_MATRIX);
    return 0;
}

int main(void)
{
    REQUIRE(T_LK_N == 48u && T_TX_N == 68u && T_RX_N == 68u);
    REQUIRE(T_HWK_N == 32u && T_HWV_N == 28u);
    REQUIRE(T_ALK_N == 24u && T_ALV_N == 56u);
    REQUIRE(T_RTK_N == 28u && T_RTV_N == 48u);
    REQUIRE(T_CFK_N == 28u && T_CFV_N == 64u);
    REQUIRE((T_TX_COV + T_RX_COV + T_HWV_COV + T_ALV_COV + T_RTV_COV + T_CFV_COV)
            * 8u
        == T_VALUE_COVERED_BITS);
    REQUIRE(6u * 32u == T_VALUE_STORED_CRC_BITS);
    REQUIRE(T_HOST_ALIGN > 0u);
    REQUIRE(T_HOST_ALIGN < T_ALK_N); /* 24: all 11 wire sizes exceed host align */
    REQUIRE(T_HOST_ALIGN < T_HWV_N);
    REQUIRE(T_HOST_ALIGN < T_RTK_N);
    REQUIRE(T_HOST_ALIGN < T_CFK_N);
    REQUIRE(T_CASE_CLOSED_DOMAIN_FIELDS == 81u);
    REQUIRE(T_CASE_CLOSED_DOMAIN == 162u);
    REQUIRE(T_CASE_LANE_MATRIX == 8u);
    REQUIRE(T_CASE_NULL_KAT == 44u);
    REQUIRE(T_CASE_ENCODE_ALIAS == 55u);
    REQUIRE(T_CASE_DECODE_ALIAS == 33u);

    /*
     * Fixed total:
     * 4+11+11+66+44+55+33+44+110+2656+162+8 = 3204
     */
    REQUIRE(T_CASE_TOTAL == 3204u);

    g_cases = 0u;

    if (test_crc_kat() != 0) {
        return 1;
    }
    if (test_host_to_literal_and_literal_to_fields() != 0) {
        return 1;
    }
    if (test_decode_length_matrix() != 0) {
        return 1;
    }
    if (test_encode_capacity_matrix() != 0) {
        return 1;
    }
    if (test_encode_alias_matrix() != 0) {
        return 1;
    }
    if (test_decode_alias_matrix() != 0) {
        return 1;
    }
    if (test_null_kat() != 0) {
        return 1;
    }
    if (test_wrong_decoder_matrix() != 0) {
        return 1;
    }
    if (test_value_crc_all_bits() != 0) {
        return 1;
    }
    if (test_closed_domain_all_branches() != 0) {
        return 1;
    }
    if (test_lane_kind_matrix() != 0) {
        return 1;
    }

    REQUIRE(g_cases == T_CASE_TOTAL);
    (void)printf("n6_record_codec_test: OK cases=%u\n", g_cases);
    return 0;
}
