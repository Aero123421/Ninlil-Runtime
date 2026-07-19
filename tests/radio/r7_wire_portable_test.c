/*
 * R7 T1 wire production API: docs/32 §§5–8 full acceptance matrix.
 * Production archive link only. Not R7 full / W1 / HIL / Accepted.
 */

#include "r7_crypto_openssl3.h"
#include "r7_wire_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures;

static void failf(const char *name, const char *detail)
{
    fprintf(stderr, "nrw1_t1_wire_portable FAIL %s: %s\n", name, detail);
    g_failures++;
}

static void expect_status(
    const char *name, ninlil_r7_wire_status got, ninlil_r7_wire_status want)
{
    if (got != want) {
        fprintf(stderr, "nrw1_t1_wire_portable FAIL %s got=%d want=%d\n",
            name, (int)got, (int)want);
        g_failures++;
    }
}

static int mem_eq(const void *a, const void *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static void zmem(void *p, size_t n)
{
    size_t i;
    uint8_t *b = (uint8_t *)p;
    for (i = 0u; i < n; i++) {
        b[i] = 0u;
    }
}

/* ---- recording provider ---- */

typedef struct {
    size_t seal_calls;
    size_t open_calls;
    int force_raw;
    int poison_all_inputs; /* flip first byte of key/nonce/aad/pt-or-sealed */
    int partial_write;
    int wrong_produced;
    /*
     * After a successful raw Open, corrupt plaintext[0] (profile) so outer
     * post-auth structural_e2e_blob fails while AEAD auth already succeeded.
     */
    int forge_invalid_e2e_pt;
    ninlil_r7_crypto_provider real;
} rec_ctx;

static ninlil_r7_crypto_raw_status rec_sha(
    void *ctx, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    rec_ctx *c = (rec_ctx *)ctx;
    return c->real.sha256(c->real.ctx, msg, msg_len, out);
}
static ninlil_r7_crypto_raw_status rec_ext(
    void *ctx, const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
    size_t ikm_len, uint8_t out[32])
{
    rec_ctx *c = (rec_ctx *)ctx;
    return c->real.hkdf_extract_sha256(
        c->real.ctx, salt, salt_len, ikm, ikm_len, out);
}
static ninlil_r7_crypto_raw_status rec_exp(
    void *ctx, const uint8_t prk[32], const uint8_t *info, size_t info_len,
    uint8_t *out, size_t okm_len)
{
    rec_ctx *c = (rec_ctx *)ctx;
    return c->real.hkdf_expand_sha256(
        c->real.ctx, prk, info, info_len, out, okm_len);
}

static void poison_ptr(const uint8_t *p, size_t n)
{
    if (p != NULL && n > 0u) {
        ((uint8_t *)(uintptr_t)p)[0] ^= 0xA5u;
    }
}

static ninlil_r7_crypto_raw_status rec_seal(
    void *ctx, const uint8_t key[16], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
    uint8_t *out, size_t out_cap, size_t *produced)
{
    rec_ctx *c = (rec_ctx *)ctx;
    ninlil_r7_crypto_raw_status st;
    c->seal_calls++;
    if (c->poison_all_inputs) {
        poison_ptr(key, 16u);
        poison_ptr(nonce, 12u);
        poison_ptr(aad, aad_len);
        poison_ptr(pt, pt_len);
    }
    if (c->force_raw != 0) {
        if (c->partial_write && out != NULL && out_cap > 0u) {
            out[0] = 0xEEu;
        }
        if (produced != NULL) {
            *produced = c->wrong_produced ? (out_cap + 1u) : 0u;
        }
        return (ninlil_r7_crypto_raw_status)c->force_raw;
    }
    st = c->real.aes128_gcm_seal(
        c->real.ctx, key, nonce, aad, aad_len, pt, pt_len, out, out_cap,
        produced);
    if (c->wrong_produced && produced != NULL && st == NINLIL_R7_CRYPTO_RAW_OK) {
        *produced = out_cap + 1u;
    }
    return st;
}

static ninlil_r7_crypto_raw_status rec_open(
    void *ctx, const uint8_t key[16], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len, const uint8_t *sealed, size_t sealed_len,
    uint8_t *out, size_t out_cap, size_t *produced)
{
    rec_ctx *c = (rec_ctx *)ctx;
    ninlil_r7_crypto_raw_status st;
    c->open_calls++;
    if (c->poison_all_inputs) {
        poison_ptr(key, 16u);
        poison_ptr(nonce, 12u);
        poison_ptr(aad, aad_len);
        poison_ptr(sealed, sealed_len);
    }
    if (c->force_raw != 0) {
        if (c->partial_write && out != NULL && out_cap > 0u) {
            out[0] = 0xEEu;
        }
        if (produced != NULL) {
            *produced = c->wrong_produced ? (out_cap + 1u) : 0u;
        }
        return (ninlil_r7_crypto_raw_status)c->force_raw;
    }
    st = c->real.aes128_gcm_open(
        c->real.ctx, key, nonce, aad, aad_len, sealed, sealed_len, out, out_cap,
        produced);
    if (c->wrong_produced && produced != NULL && st == NINLIL_R7_CRYPTO_RAW_OK) {
        *produced = out_cap + 1u;
    }
    if (c->forge_invalid_e2e_pt && st == NINLIL_R7_CRYPTO_RAW_OK && out != NULL
        && out_cap > 0u) {
        /* Profile ID corruption → STRUCTURAL at outer step 9 (docs/32 §5.5). */
        out[0] = 0x00u;
    }
    return st;
}

static void make_rec(rec_ctx *c, ninlil_r7_crypto_provider *out)
{
    zmem(c, sizeof(*c));
    if (ninlil_r7_crypto_openssl3_provider_init(&c->real) != NINLIL_R7_CRYPTO_OK) {
        failf("provider", "init");
        return;
    }
    out->abi_version = NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION;
    out->struct_size = (uint32_t)sizeof(*out);
    out->reserved_zero = 0u;
    out->ctx = c;
    out->sha256 = rec_sha;
    out->hkdf_extract_sha256 = rec_ext;
    out->hkdf_expand_sha256 = rec_exp;
    out->aes128_gcm_seal = rec_seal;
    out->aes128_gcm_open = rec_open;
}

static void reset_rec(rec_ctx *c)
{
    c->seal_calls = 0u;
    c->open_calls = 0u;
    c->force_raw = 0;
    c->poison_all_inputs = 0;
    c->partial_write = 0;
    c->wrong_produced = 0;
    c->forge_invalid_e2e_pt = 0;
}

/* ---- fixtures ---- */
static const uint8_t K16[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
static const uint8_t IV12[12] = {
    0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xa9,0xba,0xcb};
static const uint8_t HK16[16] = {
    0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
    0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
static const uint8_t HIV12[12] = {
    0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4};

/* dest may be unaligned (alias matrix); always write via void* memcpy. */
static void fill_e2e(void *dest)
{
    ninlil_r7_wire_e2e_single_fields tmp;
    zmem(&tmp, sizeof(tmp));
    tmp.e2e_context_id = 0x01020304u;
    tmp.e2e_counter = 1u;
    (void)memcpy(dest, &tmp, sizeof(tmp));
}
static void fill_outer(void *dest)
{
    ninlil_r7_wire_outer_data_fields tmp;
    zmem(&tmp, sizeof(tmp));
    tmp.ack_requested = 0u;
    tmp.hop_remaining = 0u;
    tmp.hop_context_id = 0x0A0B0C0Du;
    tmp.hop_counter = 1u;
    (void)memcpy(dest, &tmp, sizeof(tmp));
}
static void fill_app(uint8_t *a, size_t n, uint8_t s)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        a[i] = (uint8_t)(s + i);
    }
}

/*
 * Full caller snapshot for crypto APIs (docs/32 §6 mutation-zero).
 * prov_bytes is an explicit full-object byte image (seeded + compared).
 */
typedef struct {
    uint8_t prov_bytes[sizeof(ninlil_r7_crypto_provider)];
    int has_prov;
    uint8_t key[16];
    int has_key;
    uint8_t iv[12];
    int has_iv;
    /* Seal input fields / Open must not mutate these either when used as inputs */
    ninlil_r7_wire_e2e_single_fields e2e_in;
    int has_e2e_in;
    ninlil_r7_wire_outer_data_fields outer_in;
    int has_outer_in;
    /* Open decoded field outputs (mutation-zero on failure) */
    ninlil_r7_wire_e2e_single_fields e2e_dec;
    int has_e2e_dec;
    ninlil_r7_wire_outer_data_fields outer_dec;
    int has_outer_dec;
    uint8_t input[256];
    size_t input_len;
    int has_input;
    uint8_t output[256];
    size_t out_cap;
    int has_output;
    size_t out_len;
    int has_out_len;
} snap_t;

/* Back-compat alias used by existing bitflip/alias helpers. */
typedef snap_t caller_snap;

static void snap_seed_prov(snap_t *s, const ninlil_r7_crypto_provider *prov)
{
    if (prov == NULL) {
        s->has_prov = 0;
        return;
    }
    (void)memcpy(s->prov_bytes, prov, sizeof(s->prov_bytes));
    s->has_prov = 1;
}

static void snap_take_full(
    snap_t *s,
    const ninlil_r7_crypto_provider *prov,
    const uint8_t *key,
    const uint8_t *iv,
    const ninlil_r7_wire_e2e_single_fields *e2e_in,
    const ninlil_r7_wire_outer_data_fields *outer_in,
    const ninlil_r7_wire_e2e_single_fields *e2e_dec,
    const ninlil_r7_wire_outer_data_fields *outer_dec,
    const uint8_t *input,
    size_t input_len,
    const uint8_t *output,
    size_t out_cap,
    const size_t *out_len)
{
    size_t n;

    zmem(s, sizeof(*s));
    snap_seed_prov(s, prov);
    if (key != NULL) {
        (void)memcpy(s->key, key, 16u);
        s->has_key = 1;
    }
    if (iv != NULL) {
        (void)memcpy(s->iv, iv, 12u);
        s->has_iv = 1;
    }
    if (e2e_in != NULL) {
        (void)memcpy(&s->e2e_in, e2e_in, sizeof(s->e2e_in));
        s->has_e2e_in = 1;
    }
    if (outer_in != NULL) {
        (void)memcpy(&s->outer_in, outer_in, sizeof(s->outer_in));
        s->has_outer_in = 1;
    }
    if (e2e_dec != NULL) {
        (void)memcpy(&s->e2e_dec, e2e_dec, sizeof(s->e2e_dec));
        s->has_e2e_dec = 1;
    }
    if (outer_dec != NULL) {
        (void)memcpy(&s->outer_dec, outer_dec, sizeof(s->outer_dec));
        s->has_outer_dec = 1;
    }
    s->input_len = input_len;
    if (input != NULL && input_len > 0u) {
        n = input_len > 256u ? 256u : input_len;
        (void)memcpy(s->input, input, n);
        s->has_input = 1;
    }
    s->out_cap = out_cap;
    if (output != NULL && out_cap > 0u) {
        n = out_cap > 256u ? 256u : out_cap;
        (void)memcpy(s->output, output, n);
        s->has_output = 1;
    }
    if (out_len != NULL) {
        /* memcpy: alias matrix may place out_len at unaligned addresses */
        (void)memcpy(&s->out_len, out_len, sizeof(s->out_len));
        s->has_out_len = 1;
    }
}

static int snap_eq_all(
    const caller_snap *a, const caller_snap *b, size_t out_cap, int has_e2e,
    int has_outer, size_t input_len)
{
    size_t n;

    if (a->has_prov != b->has_prov) {
        return 0;
    }
    if (a->has_prov
        && !mem_eq(a->prov_bytes, b->prov_bytes, sizeof(a->prov_bytes))) {
        return 0;
    }
    if (a->has_key != b->has_key
        || (a->has_key && !mem_eq(a->key, b->key, 16u))) {
        return 0;
    }
    if (a->has_iv != b->has_iv
        || (a->has_iv && !mem_eq(a->iv, b->iv, 12u))) {
        return 0;
    }
    if (has_e2e) {
        if (!a->has_e2e_in || !b->has_e2e_in
            || !mem_eq(&a->e2e_in, &b->e2e_in, sizeof(a->e2e_in))) {
            return 0;
        }
    }
    if (has_outer) {
        if (!a->has_outer_in || !b->has_outer_in
            || !mem_eq(&a->outer_in, &b->outer_in, sizeof(a->outer_in))) {
            return 0;
        }
    }
    if (a->has_e2e_dec || b->has_e2e_dec) {
        if (!a->has_e2e_dec || !b->has_e2e_dec
            || !mem_eq(&a->e2e_dec, &b->e2e_dec, sizeof(a->e2e_dec))) {
            return 0;
        }
    }
    if (a->has_outer_dec || b->has_outer_dec) {
        if (!a->has_outer_dec || !b->has_outer_dec
            || !mem_eq(&a->outer_dec, &b->outer_dec, sizeof(a->outer_dec))) {
            return 0;
        }
    }
    if (input_len > 0u) {
        n = input_len > 256u ? 256u : input_len;
        if (!a->has_input || !b->has_input
            || a->input_len != b->input_len
            || !mem_eq(a->input, b->input, n)) {
            return 0;
        }
    }
    if (out_cap > 0u) {
        n = out_cap > 256u ? 256u : out_cap;
        if (!a->has_output || !b->has_output
            || !mem_eq(a->output, b->output, n)) {
            return 0;
        }
    }
    if (a->has_out_len != b->has_out_len
        || (a->has_out_len && a->out_len != b->out_len)) {
        return 0;
    }
    return 1;
}

static int snap_eq_strict(const snap_t *a, const snap_t *b)
{
    return snap_eq_all(
        a, b, a->out_cap, a->has_e2e_in, a->has_outer_in, a->input_len);
}

static void expect_cb0(
    const char *name, rec_ctx *rc, size_t seal0, size_t open0)
{
    if (rc->seal_calls != seal0 || rc->open_calls != open0) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s callback seal=%zu open=%zu "
            "want seal=%zu open=%zu\n",
            name, rc->seal_calls, rc->open_calls, seal0, open0);
        g_failures++;
    }
}

static void expect_cb1_seal(const char *name, rec_ctx *rc)
{
    expect_cb0(name, rc, 1u, 0u);
}

static void expect_cb1_open(const char *name, rec_ctx *rc)
{
    expect_cb0(name, rc, 0u, 1u);
}

/* ---- success ---- */
static void test_success(rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_e2e_single_fields e2e, eout;
    ninlil_r7_wire_outer_data_fields outer, oout;
    uint8_t app[16], app1[1], app24[24], app190[190];
    uint8_t blob[220], frame[255], oapp[190], oblob[220];
    size_t bl = 0u, fl = 0u, ol = 0u;

    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x50u);
    reset_rec(rc);
    expect_status("ok_e2e",
        ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app, 16u, blob, 46u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status("ok_outer",
        ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, bl, frame, 81u, &fl),
        NINLIL_R7_WIRE_OK);
    expect_status("ok_oouter",
        ninlil_r7_wire_open_outer_single(p, HK16, HIV12, frame, fl, &oout, oblob, bl, &ol),
        NINLIL_R7_WIRE_OK);
    expect_status("ok_oe2e",
        ninlil_r7_wire_open_e2e_single(p, K16, IV12, oblob, ol, &eout, oapp, 16u, &ol),
        NINLIL_R7_WIRE_OK);
    if (!mem_eq(app, oapp, 16) || !mem_eq(&e2e, &eout, sizeof(e2e))
        || !mem_eq(&outer, &oout, sizeof(outer))) {
        failf("ok_roundtrip", "mismatch");
    }
    app1[0] = 0x41u;
    fill_e2e(&e2e);
    fill_outer(&outer);
    expect_status("ok_n1",
        ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app1, 1u, blob, 31u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status("ok_n1_outer",
        ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, bl, frame, 66u, &fl),
        NINLIL_R7_WIRE_OK);
    if (fl != 66u) {
        failf("ok_n1_outer", "len");
    }
    fill_app(app190, 190u, 0x10u);
    fill_e2e(&e2e);
    fill_outer(&outer);
    expect_status("ok_n190",
        ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app190, 190u, blob, 220u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status("ok_n190_outer",
        ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, bl, frame, 255u, &fl),
        NINLIL_R7_WIRE_OK);
    if (fl != 255u) {
        failf("ok_n190_outer", "len");
    }
    fill_app(app24, 24u, 0x58u);
    fill_e2e(&e2e);
    fill_outer(&outer);
    outer.ack_requested = 1u;
    outer.hop_remaining = 3u;
    outer.route_handle = 0x1234u;
    outer.route_generation = 0x5678u;
    expect_status("ok_relay",
        ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app24, 24u, blob, 54u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status("ok_relay_outer",
        ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, bl, frame, 89u, &fl),
        NINLIL_R7_WIRE_OK);
}

/* ---- NULL matrix all 8 APIs + provider shape all 4 crypto ---- */
static void test_nulls_and_provider_shapes(rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_e2e_single_fields e2e, eout, bad_e2e;
    ninlil_r7_wire_outer_data_fields outer, oout, bad_outer;
    uint8_t app[16], blob[46], frame[81], out[256];
    uint8_t key[16], iv[12];
    size_t ol = 0u;
    ninlil_r7_crypto_provider bad;
    snap_t before, after;
    int path;
    int k;
    int null_case;

    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x40u);
    (void)memset(blob, 0x5A, sizeof(blob));
    (void)memset(frame, 0x5B, sizeof(frame));

    /*
     * AAD pack/parse required-NULL matrix lives in
     * test_aad_null_length_structural (exact 8 + mutation-zero canaries).
     *
     * 4 crypto APIs × every required NULL, each with:
     *   - poisoned output capacity / out_len / decoded fields
     *   - snap_t.prov_bytes + key + IV + field/input + output + out_len
     *   - callback count 0
     * null_case: 0=provider, 1=key, 2=iv, 3=fields/or out_fields, 4=app/blob/e2e_blob/frame,
     *            5=out buffer, 6=out_len  (open uses same indices with path-specific names)
     */
    for (path = 0; path < 4; path++) {
        int is_open = (path == 1 || path == 3);
        int is_outer = (path >= 2);
        size_t out_cap = is_open ? (is_outer ? 46u : 16u) : (is_outer ? 81u : 46u);

        for (null_case = 0; null_case < 7; null_case++) {
            const ninlil_r7_crypto_provider *prov_arg = p;
            const uint8_t *key_arg;
            const uint8_t *iv_arg;
            const ninlil_r7_wire_e2e_single_fields *e2e_arg = &e2e;
            const ninlil_r7_wire_outer_data_fields *outer_arg = &outer;
            const uint8_t *in_arg;
            uint8_t *out_arg = out;
            size_t *ol_arg = &ol;
            ninlil_r7_wire_e2e_single_fields *eout_arg = &eout;
            ninlil_r7_wire_outer_data_fields *oout_arg = &oout;
            ninlil_r7_wire_status st;
            const char *tag;

            (void)memcpy(key, is_outer ? HK16 : K16, 16u);
            (void)memcpy(iv, is_outer ? HIV12 : IV12, 12u);
            key_arg = key;
            iv_arg = iv;
            fill_e2e(&e2e);
            fill_outer(&outer);
            fill_app(app, 16u, 0x40u);
            (void)memset(out, 0xA5, sizeof(out));
            ol = 0xBEEFu;
            (void)memset(&eout, 0xC3, sizeof(eout));
            (void)memset(&oout, 0xC4, sizeof(oout));
            in_arg = is_open ? (is_outer ? frame : blob)
                             : (is_outer ? blob : app);

            if (null_case == 0) {
                prov_arg = NULL;
            } else if (null_case == 1) {
                key_arg = NULL;
            } else if (null_case == 2) {
                iv_arg = NULL;
            } else if (null_case == 3) {
                if (is_open) {
                    if (is_outer) {
                        oout_arg = NULL;
                    } else {
                        eout_arg = NULL;
                    }
                } else {
                    if (is_outer) {
                        outer_arg = NULL;
                    } else {
                        e2e_arg = NULL;
                    }
                }
            } else if (null_case == 4) {
                in_arg = NULL;
            } else if (null_case == 5) {
                out_arg = NULL;
            } else {
                ol_arg = NULL;
            }

            snap_take_full(
                &before, p, key, iv,
                is_outer ? NULL : &e2e, is_outer ? &outer : NULL,
                is_open && !is_outer ? &eout : NULL,
                is_open && is_outer ? &oout : NULL,
                (null_case == 4) ? NULL : in_arg,
                is_open ? (is_outer ? 81u : 46u) : (is_outer ? 46u : 16u),
                out, out_cap, &ol);

            /* When input is non-NULL, refresh input image from the real buffer. */
            if (null_case != 4) {
                if (is_open && is_outer) {
                    snap_take_full(
                        &before, p, key, iv, NULL, &outer, NULL, &oout, frame,
                        81u, out, out_cap, &ol);
                } else if (is_open) {
                    snap_take_full(
                        &before, p, key, iv, NULL, NULL, &eout, NULL, blob, 46u,
                        out, out_cap, &ol);
                } else if (is_outer) {
                    snap_take_full(
                        &before, p, key, iv, NULL, &outer, NULL, NULL, blob, 46u,
                        out, out_cap, &ol);
                } else {
                    snap_take_full(
                        &before, p, key, iv, &e2e, NULL, NULL, NULL, app, 16u,
                        out, out_cap, &ol);
                }
            } else {
                /* input NULL: still snap other callers */
                if (is_open && is_outer) {
                    snap_take_full(
                        &before, p, key, iv, NULL, &outer, NULL, &oout, NULL, 0u,
                        out, out_cap, &ol);
                } else if (is_open) {
                    snap_take_full(
                        &before, p, key, iv, NULL, NULL, &eout, NULL, NULL, 0u,
                        out, out_cap, &ol);
                } else if (is_outer) {
                    snap_take_full(
                        &before, p, key, iv, NULL, &outer, NULL, NULL, NULL, 0u,
                        out, out_cap, &ol);
                } else {
                    snap_take_full(
                        &before, p, key, iv, &e2e, NULL, NULL, NULL, NULL, 0u,
                        out, out_cap, &ol);
                }
            }

            reset_rec(rc);
            if (path == 0) {
                tag = "se2e_null";
                st = ninlil_r7_wire_seal_e2e_single(
                    prov_arg, key_arg, iv_arg, e2e_arg, in_arg, 16u, out_arg,
                    46u, ol_arg);
            } else if (path == 1) {
                tag = "oe2e_null";
                st = ninlil_r7_wire_open_e2e_single(
                    prov_arg, key_arg, iv_arg, in_arg, 46u, eout_arg, out_arg,
                    16u, ol_arg);
            } else if (path == 2) {
                tag = "sout_null";
                st = ninlil_r7_wire_seal_outer_single(
                    prov_arg, key_arg, iv_arg, outer_arg, in_arg, 46u, out_arg,
                    81u, ol_arg);
            } else {
                tag = "oout_null";
                st = ninlil_r7_wire_open_outer_single(
                    prov_arg, key_arg, iv_arg, in_arg, 81u, oout_arg, out_arg,
                    46u, ol_arg);
            }
            expect_status(tag, st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
            expect_cb0(tag, rc, 0u, 0u);

            if (is_open && is_outer) {
                snap_take_full(
                    &after, p, key, iv, NULL, &outer, NULL,
                    oout_arg != NULL ? &oout : NULL,
                    null_case == 4 ? NULL : frame,
                    null_case == 4 ? 0u : 81u, out, out_cap,
                    ol_arg != NULL ? &ol : NULL);
            } else if (is_open) {
                snap_take_full(
                    &after, p, key, iv, NULL, NULL,
                    eout_arg != NULL ? &eout : NULL, NULL,
                    null_case == 4 ? NULL : blob,
                    null_case == 4 ? 0u : 46u, out, out_cap,
                    ol_arg != NULL ? &ol : NULL);
            } else if (is_outer) {
                snap_take_full(
                    &after, p, key, iv, NULL,
                    outer_arg != NULL ? &outer : NULL, NULL, NULL,
                    null_case == 4 ? NULL : blob,
                    null_case == 4 ? 0u : 46u, out, out_cap,
                    ol_arg != NULL ? &ol : NULL);
            } else {
                snap_take_full(
                    &after, p, key, iv, e2e_arg != NULL ? &e2e : NULL, NULL,
                    NULL, NULL, null_case == 4 ? NULL : app,
                    null_case == 4 ? 0u : 16u, out, out_cap,
                    ol_arg != NULL ? &ol : NULL);
            }
            /*
             * Compare only spans that remain addressable after the NULL case.
             * Provider object under test is always `p` (even when arg is NULL).
             * out/out_len/decoded may be the NULL argument itself — then omit.
             */
            if (before.has_prov && after.has_prov
                && !mem_eq(before.prov_bytes, after.prov_bytes,
                       sizeof(before.prov_bytes))) {
                failf(tag, "prov_bytes mutated");
            }
            if (null_case != 1 && before.has_key && after.has_key
                && !mem_eq(before.key, after.key, 16u)) {
                failf(tag, "key mutated");
            }
            if (null_case != 2 && before.has_iv && after.has_iv
                && !mem_eq(before.iv, after.iv, 12u)) {
                failf(tag, "iv mutated");
            }
            if (null_case != 3) {
                if (before.has_e2e_in && after.has_e2e_in
                    && !mem_eq(&before.e2e_in, &after.e2e_in,
                           sizeof(before.e2e_in))) {
                    failf(tag, "e2e_in mutated");
                }
                if (before.has_outer_in && after.has_outer_in
                    && !mem_eq(&before.outer_in, &after.outer_in,
                           sizeof(before.outer_in))) {
                    failf(tag, "outer_in mutated");
                }
                if (before.has_e2e_dec && after.has_e2e_dec
                    && !mem_eq(&before.e2e_dec, &after.e2e_dec,
                           sizeof(before.e2e_dec))) {
                    failf(tag, "e2e_dec mutated");
                }
                if (before.has_outer_dec && after.has_outer_dec
                    && !mem_eq(&before.outer_dec, &after.outer_dec,
                           sizeof(before.outer_dec))) {
                    failf(tag, "outer_dec mutated");
                }
            }
            if (null_case != 4 && before.has_input && after.has_input
                && (before.input_len != after.input_len
                    || !mem_eq(before.input, after.input, before.input_len))) {
                failf(tag, "input mutated");
            }
            if (null_case != 5 && before.has_output && after.has_output
                && !mem_eq(before.output, after.output,
                       out_cap > 256u ? 256u : out_cap)) {
                failf(tag, "output mutated");
            }
            if (null_case != 6 && before.has_out_len && after.has_out_len
                && before.out_len != after.out_len) {
                failf(tag, "out_len mutated");
            }
        }
    }

    /* Preserve legacy explicit NULL names (still exercise exact status). */
    reset_rec(rc);
    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x40u);
    ol = 0u;
    expect_status("se2e_np", ninlil_r7_wire_seal_e2e_single(NULL, K16, IV12, &e2e, app, 16u, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("se2e_nk", ninlil_r7_wire_seal_e2e_single(p, NULL, IV12, &e2e, app, 16u, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("se2e_ni", ninlil_r7_wire_seal_e2e_single(p, K16, NULL, &e2e, app, 16u, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("se2e_nf", ninlil_r7_wire_seal_e2e_single(p, K16, IV12, NULL, app, 16u, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("se2e_na", ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, NULL, 16u, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("se2e_no", ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app, 16u, NULL, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("se2e_nl", ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app, 16u, out, 46u, NULL), NINLIL_R7_WIRE_INVALID_ARGUMENT);

    expect_status("oe2e_np", ninlil_r7_wire_open_e2e_single(NULL, K16, IV12, blob, 46u, &eout, out, 16u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oe2e_nk", ninlil_r7_wire_open_e2e_single(p, NULL, IV12, blob, 46u, &eout, out, 16u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oe2e_ni", ninlil_r7_wire_open_e2e_single(p, K16, NULL, blob, 46u, &eout, out, 16u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oe2e_nb", ninlil_r7_wire_open_e2e_single(p, K16, IV12, NULL, 46u, &eout, out, 16u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oe2e_nf", ninlil_r7_wire_open_e2e_single(p, K16, IV12, blob, 46u, NULL, out, 16u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oe2e_na", ninlil_r7_wire_open_e2e_single(p, K16, IV12, blob, 46u, &eout, NULL, 16u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oe2e_nl", ninlil_r7_wire_open_e2e_single(p, K16, IV12, blob, 46u, &eout, out, 16u, NULL), NINLIL_R7_WIRE_INVALID_ARGUMENT);

    expect_status("sout_np", ninlil_r7_wire_seal_outer_single(NULL, HK16, HIV12, &outer, blob, 46u, out, 81u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("sout_nk", ninlil_r7_wire_seal_outer_single(p, NULL, HIV12, &outer, blob, 46u, out, 81u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("sout_ni", ninlil_r7_wire_seal_outer_single(p, HK16, NULL, &outer, blob, 46u, out, 81u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("sout_nf", ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, NULL, blob, 46u, out, 81u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("sout_nb", ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, NULL, 46u, out, 81u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("sout_no", ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, 46u, NULL, 81u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("sout_nl", ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, 46u, out, 81u, NULL), NINLIL_R7_WIRE_INVALID_ARGUMENT);

    expect_status("oout_np", ninlil_r7_wire_open_outer_single(NULL, HK16, HIV12, frame, 81u, &oout, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oout_nk", ninlil_r7_wire_open_outer_single(p, NULL, HIV12, frame, 81u, &oout, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oout_ni", ninlil_r7_wire_open_outer_single(p, HK16, NULL, frame, 81u, &oout, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oout_nfrm", ninlil_r7_wire_open_outer_single(p, HK16, HIV12, NULL, 81u, &oout, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oout_nf", ninlil_r7_wire_open_outer_single(p, HK16, HIV12, frame, 81u, NULL, out, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oout_no", ninlil_r7_wire_open_outer_single(p, HK16, HIV12, frame, 81u, &oout, NULL, 46u, &ol), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status("oout_nl", ninlil_r7_wire_open_outer_single(p, HK16, HIV12, frame, 81u, &oout, out, 46u, NULL), NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_cb0("nulls_legacy", rc, 0u, 0u);

    /*
     * Exact precedence: required-pointer / provider-shape failures win over
     * later LENGTH_CLASS / STRUCTURAL domain checks (docs/32 §5.2–5.5 step 1).
     */
    zmem(&bad_e2e, sizeof(bad_e2e)); /* context 0 → structural if reached */
    zmem(&bad_outer, sizeof(bad_outer));
    bad_outer.hop_context_id = 0u;
    reset_rec(rc);
    expect_status(
        "se2e_prec_appnull_badfield",
        ninlil_r7_wire_seal_e2e_single(
            p, K16, IV12, &bad_e2e, NULL, 0u, out, 46u, &ol),
        NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status(
        "se2e_prec_keynull_badlen",
        ninlil_r7_wire_seal_e2e_single(
            p, NULL, IV12, &e2e, app, 0u, out, 46u, &ol),
        NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status(
        "sout_prec_blobnull_badfield",
        ninlil_r7_wire_seal_outer_single(
            p, HK16, HIV12, &bad_outer, NULL, 0u, out, 81u, &ol),
        NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status(
        "oe2e_prec_blobnull_badlen",
        ninlil_r7_wire_open_e2e_single(
            p, K16, IV12, NULL, 0u, &eout, out, 16u, &ol),
        NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status(
        "oout_prec_framenull_badlen",
        ninlil_r7_wire_open_outer_single(
            p, HK16, HIV12, NULL, 0u, &oout, out, 46u, &ol),
        NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_status(
        "se2e_prec_provnull_badfield",
        ninlil_r7_wire_seal_e2e_single(
            NULL, K16, IV12, &bad_e2e, app, 16u, out, 46u, &ol),
        NINLIL_R7_WIRE_INVALID_ARGUMENT);
    expect_cb0("null_prec", rc, 0u, 0u);

    /*
     * Invalid provider shape — all kinds on all 4 crypto APIs:
     * abi, struct_size, reserved_zero, and each of 5 callbacks NULL.
     */
    for (path = 0; path < 4; path++) {
        int is_open = (path == 1 || path == 3);
        int is_outer = (path >= 2);
        size_t out_cap = is_open ? (is_outer ? 46u : 16u) : (is_outer ? 81u : 46u);

        for (k = 0; k < 8; k++) {
            const char *tag;

            bad = *p;
            if (k == 0) {
                bad.abi_version = 0u;
            } else if (k == 1) {
                bad.struct_size = 1u;
            } else if (k == 2) {
                bad.reserved_zero = 1u;
            } else if (k == 3) {
                bad.sha256 = NULL;
            } else if (k == 4) {
                bad.hkdf_extract_sha256 = NULL;
            } else if (k == 5) {
                bad.hkdf_expand_sha256 = NULL;
            } else if (k == 6) {
                bad.aes128_gcm_seal = NULL;
            } else {
                bad.aes128_gcm_open = NULL;
            }

            (void)memcpy(key, is_outer ? HK16 : K16, 16u);
            (void)memcpy(iv, is_outer ? HIV12 : IV12, 12u);
            fill_e2e(&e2e);
            fill_outer(&outer);
            fill_app(app, 16u, 0x40u);
            (void)memset(out, 0xA5, sizeof(out));
            ol = 0xBEEFu;
            (void)memset(&eout, 0xC3, sizeof(eout));
            (void)memset(&oout, 0xC4, sizeof(oout));

            if (is_open && is_outer) {
                snap_take_full(
                    &before, &bad, key, iv, NULL, &outer, NULL, &oout, frame,
                    81u, out, out_cap, &ol);
            } else if (is_open) {
                snap_take_full(
                    &before, &bad, key, iv, NULL, NULL, &eout, NULL, blob, 46u,
                    out, out_cap, &ol);
            } else if (is_outer) {
                snap_take_full(
                    &before, &bad, key, iv, NULL, &outer, NULL, NULL, blob, 46u,
                    out, out_cap, &ol);
            } else {
                snap_take_full(
                    &before, &bad, key, iv, &e2e, NULL, NULL, NULL, app, 16u,
                    out, out_cap, &ol);
            }

            reset_rec(rc);
            if (path == 0) {
                tag = "shape_se2e";
                expect_status(
                    tag,
                    ninlil_r7_wire_seal_e2e_single(
                        &bad, key, iv, &e2e, app, 16u, out, 46u, &ol),
                    NINLIL_R7_WIRE_INVALID_ARGUMENT);
            } else if (path == 1) {
                tag = "shape_oe2e";
                expect_status(
                    tag,
                    ninlil_r7_wire_open_e2e_single(
                        &bad, key, iv, blob, 46u, &eout, out, 16u, &ol),
                    NINLIL_R7_WIRE_INVALID_ARGUMENT);
            } else if (path == 2) {
                tag = "shape_sout";
                expect_status(
                    tag,
                    ninlil_r7_wire_seal_outer_single(
                        &bad, key, iv, &outer, blob, 46u, out, 81u, &ol),
                    NINLIL_R7_WIRE_INVALID_ARGUMENT);
            } else {
                tag = "shape_oout";
                expect_status(
                    tag,
                    ninlil_r7_wire_open_outer_single(
                        &bad, key, iv, frame, 81u, &oout, out, 46u, &ol),
                    NINLIL_R7_WIRE_INVALID_ARGUMENT);
            }
            expect_cb0(tag, rc, 0u, 0u);

            if (is_open && is_outer) {
                snap_take_full(
                    &after, &bad, key, iv, NULL, &outer, NULL, &oout, frame,
                    81u, out, out_cap, &ol);
            } else if (is_open) {
                snap_take_full(
                    &after, &bad, key, iv, NULL, NULL, &eout, NULL, blob, 46u,
                    out, out_cap, &ol);
            } else if (is_outer) {
                snap_take_full(
                    &after, &bad, key, iv, NULL, &outer, NULL, NULL, blob, 46u,
                    out, out_cap, &ol);
            } else {
                snap_take_full(
                    &after, &bad, key, iv, &e2e, NULL, NULL, NULL, app, 16u,
                    out, out_cap, &ol);
            }
            if (!snap_eq_strict(&before, &after)) {
                failf(tag, "caller mutated on shape reject");
            }
        }
    }
}

/* ---- fault injection all 4 paths × fault kinds ---- */
static void test_faults(rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_e2e_single_fields e2e;
    ninlil_r7_wire_outer_data_fields outer;
    uint8_t app[16], blob[46], frame[81];
    size_t bl = 0u, fl = 0u;
    snap_t before, after;
    uint8_t key[16], iv[12], out[256];
    size_t ol;
    ninlil_r7_wire_e2e_single_fields eout;
    ninlil_r7_wire_outer_data_fields oout;
    int path, fault;

    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x50u);
    expect_status("fault_prep_e2e",
        ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app, 16u, blob, 46u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status("fault_prep_outer",
        ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, bl, frame, 81u, &fl),
        NINLIL_R7_WIRE_OK);

    /*
     * fault: 0=backend, 1=unknown raw, 2=auth (Open only — Seal maps AUTH to
     * contract at crypto layer; still exercised as force_raw for Seal to prove
     * INTERNAL_CONTRACT + mutation-zero + callback 1), 3=partial write,
     * 4=wrong produced, 5=poison (copies only; success path, caller inputs
     * immutable via prov_bytes/key/IV/field/input).
     * No path is skipped for Seal AUTH — mapped status is INTERNAL_CONTRACT.
     */
    for (path = 0; path < 4; path++) {
        for (fault = 0; fault < 6; fault++) {
            ninlil_r7_wire_status want;
            size_t out_cap;
            const uint8_t *in_ptr;
            size_t in_len;
            int is_open = (path == 1 || path == 3);
            int is_outer = (path >= 2);
            const char *tag;

            (void)memcpy(key, is_outer ? HK16 : K16, 16u);
            (void)memcpy(iv, is_outer ? HIV12 : IV12, 12u);
            fill_e2e(&e2e);
            fill_outer(&outer);
            fill_app(app, 16u, 0x50u);
            /* Keep valid sealed inputs for Open paths (blob/frame). */
            (void)memset(out, 0xA5, sizeof(out));
            ol = 0xBEEFu;
            (void)memset(&eout, 0xC3, sizeof(eout));
            (void)memset(&oout, 0xC4, sizeof(oout));
            out_cap = is_open ? (is_outer ? 46u : 16u) : (is_outer ? 81u : 46u);
            in_ptr = is_open ? (is_outer ? frame : blob) : (is_outer ? blob : app);
            in_len = is_open ? (is_outer ? fl : bl) : (is_outer ? bl : 16u);

            if (is_open && is_outer) {
                snap_take_full(
                    &before, p, key, iv, NULL, &outer, NULL, &oout, in_ptr,
                    in_len, out, out_cap, &ol);
            } else if (is_open) {
                snap_take_full(
                    &before, p, key, iv, NULL, NULL, &eout, NULL, in_ptr,
                    in_len, out, out_cap, &ol);
            } else if (is_outer) {
                snap_take_full(
                    &before, p, key, iv, NULL, &outer, NULL, NULL, in_ptr,
                    in_len, out, out_cap, &ol);
            } else {
                snap_take_full(
                    &before, p, key, iv, &e2e, NULL, NULL, NULL, in_ptr,
                    in_len, out, out_cap, &ol);
            }

            reset_rec(rc);
            if (fault == 0) {
                rc->force_raw = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
                want = NINLIL_R7_WIRE_BACKEND_FAILED;
            } else if (fault == 1) {
                rc->force_raw = 99;
                want = NINLIL_R7_WIRE_BACKEND_FAILED;
            } else if (fault == 2) {
                rc->force_raw = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
                /* Open: AUTH_FAILED. Seal: portable maps AUTH→INTERNAL_CONTRACT. */
                want = is_open ? NINLIL_R7_WIRE_AUTH_FAILED
                               : NINLIL_R7_WIRE_INTERNAL_CONTRACT;
            } else if (fault == 3) {
                rc->force_raw = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
                rc->partial_write = 1;
                want = NINLIL_R7_WIRE_BACKEND_FAILED;
            } else if (fault == 4) {
                rc->force_raw = 0;
                rc->wrong_produced = 1;
                want = NINLIL_R7_WIRE_INTERNAL_CONTRACT;
            } else {
                /*
                 * Poison mutates crypto-layer copies only for key/nonce/aad/pt.
                 * Seal still authenticates with poisoned copies → OK publish.
                 * Open poisons sealed copy → GCM AUTH_FAILED (not silent OK).
                 */
                rc->force_raw = 0;
                rc->poison_all_inputs = 1;
                want = is_open ? NINLIL_R7_WIRE_AUTH_FAILED : NINLIL_R7_WIRE_OK;
            }

            if (path == 0) {
                tag = "fault_se2e";
                expect_status(
                    tag,
                    ninlil_r7_wire_seal_e2e_single(
                        p, key, iv, &e2e, app, 16u, out, 46u, &ol),
                    want);
            } else if (path == 1) {
                tag = "fault_oe2e";
                expect_status(
                    tag,
                    ninlil_r7_wire_open_e2e_single(
                        p, key, iv, blob, bl, &eout, out, 16u, &ol),
                    want);
            } else if (path == 2) {
                tag = "fault_sout";
                expect_status(
                    tag,
                    ninlil_r7_wire_seal_outer_single(
                        p, key, iv, &outer, blob, bl, out, 81u, &ol),
                    want);
            } else {
                tag = "fault_oout";
                expect_status(
                    tag,
                    ninlil_r7_wire_open_outer_single(
                        p, key, iv, frame, fl, &oout, out, 46u, &ol),
                    want);
            }

            if (is_open && is_outer) {
                snap_take_full(
                    &after, p, key, iv, NULL, &outer, NULL, &oout, in_ptr,
                    in_len, out, out_cap, &ol);
            } else if (is_open) {
                snap_take_full(
                    &after, p, key, iv, NULL, NULL, &eout, NULL, in_ptr,
                    in_len, out, out_cap, &ol);
            } else if (is_outer) {
                snap_take_full(
                    &after, p, key, iv, NULL, &outer, NULL, NULL, in_ptr,
                    in_len, out, out_cap, &ol);
            } else {
                snap_take_full(
                    &after, p, key, iv, &e2e, NULL, NULL, NULL, in_ptr,
                    in_len, out, out_cap, &ol);
            }

            if (fault != 5 || is_open) {
                /*
                 * Failure path (all faults except Seal-poison success): full
                 * mutation-zero including decoded fields, out capacity, out_len.
                 * Open-poison is AUTH_FAILED → same failure contract.
                 */
                if (!snap_eq_strict(&before, &after)) {
                    failf(tag, "caller mutated on fault");
                }
                if (is_open) {
                    expect_cb1_open(tag, rc);
                } else {
                    expect_cb1_seal(tag, rc);
                }
            } else {
                /* Seal poison success: inputs + provider immutable; out published */
                if (!before.has_prov || !after.has_prov
                    || !mem_eq(before.prov_bytes, after.prov_bytes,
                           sizeof(before.prov_bytes))) {
                    failf(tag, "poison prov_bytes");
                }
                if (!mem_eq(before.key, after.key, 16u)
                    || !mem_eq(before.iv, after.iv, 12u)) {
                    failf(tag, "poison key/iv");
                }
                if (before.has_e2e_in
                    && !mem_eq(&before.e2e_in, &after.e2e_in,
                           sizeof(before.e2e_in))) {
                    failf(tag, "poison e2e_in");
                }
                if (before.has_outer_in
                    && !mem_eq(&before.outer_in, &after.outer_in,
                           sizeof(before.outer_in))) {
                    failf(tag, "poison outer_in");
                }
                if (in_len > 0u
                    && !mem_eq(before.input, after.input, in_len)) {
                    failf(tag, "poison input (app/blob/frame)");
                }
                expect_cb1_seal(tag, rc);
            }
            reset_rec(rc);
        }
    }
}

/*
 * Bit-flip / structural anomaly matrix for Open paths (docs/32 §5.3 / §5.5 / §8).
 * Layers: open_e2e (after E2E seal) and open_outer (after dual-envelope seal).
 * Every case: full caller snapshot (prov/key/IV/input/output/out_len/decoded)
 * must be mutation-zero on the expected failure status + exact callback count.
 */
static void bf_assert_open_e2e(
    const char *name,
    rec_ctx *rc,
    ninlil_r7_crypto_provider *p,
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_wire_status want_st,
    size_t want_open_cb)
{
    ninlil_r7_wire_e2e_single_fields eout;
    uint8_t out[190];
    size_t ol;
    size_t out_cap = blob_len - (NINLIL_R7_WIRE_E2E_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN);
    snap_t before, after;
    ninlil_r7_wire_status st;

    if (out_cap > sizeof(out)) {
        failf(name, "out_cap");
        return;
    }
    (void)memset(out, 0xA5, out_cap);
    ol = 0xBEEFu;
    (void)memset(&eout, 0xC3, sizeof(eout));
    snap_take_full(
        &before, p, key, iv, NULL, NULL, &eout, NULL, blob, blob_len, out,
        out_cap, &ol);
    reset_rec(rc);
    st = ninlil_r7_wire_open_e2e_single(
        p, key, iv, blob, blob_len, &eout, out, out_cap, &ol);
    expect_status(name, st, want_st);
    if (rc->open_calls != want_open_cb || rc->seal_calls != 0u) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s callback open=%zu seal=%zu want_open=%zu\n",
            name, rc->open_calls, rc->seal_calls, want_open_cb);
        g_failures++;
    }
    snap_take_full(
        &after, p, key, iv, NULL, NULL, &eout, NULL, blob, blob_len, out, out_cap,
        &ol);
    if (!snap_eq_strict(&before, &after)) {
        failf(name, "caller mutated");
    }
}

static void bf_assert_open_outer(
    const char *name,
    rec_ctx *rc,
    ninlil_r7_crypto_provider *p,
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_wire_status want_st,
    size_t want_open_cb)
{
    ninlil_r7_wire_outer_data_fields oout;
    uint8_t out[220];
    size_t ol;
    size_t out_cap =
        frame_len - (NINLIL_R7_WIRE_OUTER_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN);
    snap_t before, after;
    ninlil_r7_wire_status st;

    if (out_cap > sizeof(out)) {
        failf(name, "out_cap");
        return;
    }
    (void)memset(out, 0xA5, out_cap);
    ol = 0xBEEFu;
    (void)memset(&oout, 0xC4, sizeof(oout));
    snap_take_full(
        &before, p, key, iv, NULL, NULL, NULL, &oout, frame, frame_len, out,
        out_cap, &ol);
    reset_rec(rc);
    st = ninlil_r7_wire_open_outer_single(
        p, key, iv, frame, frame_len, &oout, out, out_cap, &ol);
    expect_status(name, st, want_st);
    if (rc->open_calls != want_open_cb || rc->seal_calls != 0u) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s callback open=%zu seal=%zu want_open=%zu\n",
            name, rc->open_calls, rc->seal_calls, want_open_cb);
        g_failures++;
    }
    snap_take_full(
        &after, p, key, iv, NULL, NULL, NULL, &oout, frame, frame_len, out,
        out_cap, &ol);
    if (!snap_eq_strict(&before, &after)) {
        failf(name, "caller mutated");
    }
}

static void test_bitflips(rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_e2e_single_fields e2e;
    ninlil_r7_wire_outer_data_fields outer;
    uint8_t app[16], blob[46], frame[81], bad[81];
    uint8_t key_e[16], iv_e[12], key_o[16], iv_o[12];
    size_t bl = 0u, fl = 0u;

    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x50u);
    (void)memcpy(key_e, K16, 16u);
    (void)memcpy(iv_e, IV12, 12u);
    (void)memcpy(key_o, HK16, 16u);
    (void)memcpy(iv_o, HIV12, 12u);

    /* Seal-open prep for both layers (E2E then outer dual-envelope). */
    reset_rec(rc);
    expect_status(
        "bf_prep_e2e",
        ninlil_r7_wire_seal_e2e_single(
            p, key_e, iv_e, &e2e, app, 16u, blob, 46u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "bf_prep_outer",
        ninlil_r7_wire_seal_outer_single(
            p, key_o, iv_o, &outer, blob, bl, frame, 81u, &fl),
        NINLIL_R7_WIRE_OK);
    if (bl != 46u || fl != 81u) {
        failf("bf_prep", "lens");
        return;
    }

    /* ---- 1) Visible header structural flips → STRUCTURAL, callback 0 ---- */
    (void)memcpy(bad, blob, bl);
    bad[0] ^= 0x01u; /* profile */
    bf_assert_open_e2e(
        "bf_e2e_struct_profile", rc, p, key_e, iv_e, bad, bl,
        NINLIL_R7_WIRE_STRUCTURAL, 0u);

    (void)memcpy(bad, blob, bl);
    bad[1] ^= 0x01u; /* type low nibble reserved */
    bf_assert_open_e2e(
        "bf_e2e_struct_type_nibble", rc, p, key_e, iv_e, bad, bl,
        NINLIL_R7_WIRE_STRUCTURAL, 0u);

    (void)memcpy(bad, frame, fl);
    bad[0] ^= 0x01u; /* outer profile */
    bf_assert_open_outer(
        "bf_outer_struct_profile", rc, p, key_o, iv_o, bad, fl,
        NINLIL_R7_WIRE_STRUCTURAL, 0u);

    (void)memcpy(bad, frame, fl);
    bad[1] ^= 0x02u; /* reserved bits in kind_flags (bit1), not ack */
    bf_assert_open_outer(
        "bf_outer_struct_reserved", rc, p, key_o, iv_o, bad, fl,
        NINLIL_R7_WIRE_STRUCTURAL, 0u);

    /*
     * ---- 2) Domain-preserving AAD bit flips → AUTH_FAILED, callback 1 ----
     * e2e context 0x01020304; flip a high bit in the last context byte keeps ≠0/MAX.
     * e2e counter=1; flip bit 1 → counter=3 still valid.
     * outer hop_context 0x0A0B0C0D; flip LSB of last BE byte.
     * outer hop_counter=1; flip bit 2 → 5 still valid.
     * outer ack 0↔1 both domain-valid for hop_remaining=0 route (0,0).
     */
    (void)memcpy(bad, blob, bl);
    bad[5] ^= 0x01u; /* context_id last BE byte */
    bf_assert_open_e2e(
        "bf_e2e_aad_ctx_auth", rc, p, key_e, iv_e, bad, bl,
        NINLIL_R7_WIRE_AUTH_FAILED, 1u);

    (void)memcpy(bad, blob, bl);
    bad[13] ^= 0x02u; /* counter low byte bit1 */
    bf_assert_open_e2e(
        "bf_e2e_aad_ctr_auth", rc, p, key_e, iv_e, bad, bl,
        NINLIL_R7_WIRE_AUTH_FAILED, 1u);

    (void)memcpy(bad, frame, fl);
    bad[6] ^= 0x01u; /* hop_context_id last BE byte */
    bf_assert_open_outer(
        "bf_outer_aad_ctx_auth", rc, p, key_o, iv_o, bad, fl,
        NINLIL_R7_WIRE_AUTH_FAILED, 1u);

    (void)memcpy(bad, frame, fl);
    bad[14] ^= 0x04u; /* hop_counter */
    bf_assert_open_outer(
        "bf_outer_aad_ctr_auth", rc, p, key_o, iv_o, bad, fl,
        NINLIL_R7_WIRE_AUTH_FAILED, 1u);

    (void)memcpy(bad, frame, fl);
    bad[1] ^= 0x01u; /* ack bit only */
    bf_assert_open_outer(
        "bf_outer_aad_ack_auth", rc, p, key_o, iv_o, bad, fl,
        NINLIL_R7_WIRE_AUTH_FAILED, 1u);

    /* ---- 3) Ciphertext 1-bit and tag 1-bit → AUTH_FAILED, callback 1 ---- */
    (void)memcpy(bad, blob, bl);
    bad[NINLIL_R7_WIRE_E2E_AAD_LEN] ^= 0x01u; /* first CT byte */
    bf_assert_open_e2e(
        "bf_e2e_ct_bit", rc, p, key_e, iv_e, bad, bl, NINLIL_R7_WIRE_AUTH_FAILED,
        1u);

    (void)memcpy(bad, blob, bl);
    bad[bl - 1u] ^= 0x01u; /* last tag byte */
    bf_assert_open_e2e(
        "bf_e2e_tag_bit", rc, p, key_e, iv_e, bad, bl, NINLIL_R7_WIRE_AUTH_FAILED,
        1u);

    (void)memcpy(bad, frame, fl);
    bad[NINLIL_R7_WIRE_OUTER_AAD_LEN] ^= 0x01u;
    bf_assert_open_outer(
        "bf_outer_ct_bit", rc, p, key_o, iv_o, bad, fl, NINLIL_R7_WIRE_AUTH_FAILED,
        1u);

    (void)memcpy(bad, frame, fl);
    bad[fl - 1u] ^= 0x01u;
    bf_assert_open_outer(
        "bf_outer_tag_bit", rc, p, key_o, iv_o, bad, fl, NINLIL_R7_WIRE_AUTH_FAILED,
        1u);

    /*
     * Full 128-bit outer/e2e tag matrix (existing coverage retained): each bit
     * AUTH_FAILED + callback 1 + mutation zero via helpers.
     */
    {
        size_t bit;
        char name[64];

        for (bit = 0u; bit < 128u; bit++) {
            (void)memcpy(bad, blob, bl);
            bad[bl - 16u + (bit / 8u)] ^= (uint8_t)(1u << (bit % 8u));
            (void)snprintf(name, sizeof(name), "bf_e2e_tag_bit_%zu", bit);
            bf_assert_open_e2e(
                name, rc, p, key_e, iv_e, bad, bl, NINLIL_R7_WIRE_AUTH_FAILED,
                1u);
        }
        for (bit = 0u; bit < 128u; bit++) {
            (void)memcpy(bad, frame, fl);
            bad[fl - 16u + (bit / 8u)] ^= (uint8_t)(1u << (bit % 8u));
            (void)snprintf(name, sizeof(name), "bf_outer_tag_bit_%zu", bit);
            bf_assert_open_outer(
                name, rc, p, key_o, iv_o, bad, fl, NINLIL_R7_WIRE_AUTH_FAILED,
                1u);
        }
    }

    /*
     * ---- 4) Outer Open: AEAD auth OK, post-auth inner E2E structural fail ----
     * Production path (docs/32 §5.5 steps 7–9): after Open callback exact 1 and
     * produced shape, structural_e2e_blob(blob_cand) runs. A controlled provider
     * returns RAW_OK with correct produced length but profile-corrupted
     * plaintext → STRUCTURAL, callback 1, no publish (mutation zero).
     * Standalone E2E Open has no post-auth structural step on application PT;
     * that path is intentionally not simulated here.
     */
    {
        ninlil_r7_wire_outer_data_fields oout;
        uint8_t out[46];
        size_t ol;
        snap_t before, after;
        ninlil_r7_wire_status st;

        (void)memset(out, 0xA5, sizeof(out));
        ol = 0xBEEFu;
        (void)memset(&oout, 0xC4, sizeof(oout));
        snap_take_full(
            &before, p, key_o, iv_o, NULL, NULL, NULL, &oout, frame, fl, out,
            46u, &ol);
        reset_rec(rc);
        rc->forge_invalid_e2e_pt = 1;
        st = ninlil_r7_wire_open_outer_single(
            p, key_o, iv_o, frame, fl, &oout, out, 46u, &ol);
        expect_status("bf_outer_postauth_inner_struct", st, NINLIL_R7_WIRE_STRUCTURAL);
        if (rc->open_calls != 1u || rc->seal_calls != 0u) {
            failf("bf_outer_postauth_inner_struct", "callback");
        }
        snap_take_full(
            &after, p, key_o, iv_o, NULL, NULL, NULL, &oout, frame, fl, out, 46u,
            &ol);
        if (!snap_eq_strict(&before, &after)) {
            failf("bf_outer_postauth_inner_struct", "caller mutated");
        }
        rc->forge_invalid_e2e_pt = 0;
    }

    fprintf(stderr, "nrw1_t1_wire_portable bitflip/structural matrix OK\n");
}

/*
 * ---- crypto alias coverage: exact and partial overlap (docs/32 §6) ----
 *
 * Per crypto API, n caller spans, C(n,2) unordered pairs, each executed once
 * with C17-valid typed host objects and byte-span storage.  Exact and
 * partial overlap are both covered below; adjacency / overflow stay separate.
 */
enum {
    ASP_PROV = 0,
    ASP_KEY,
    ASP_IV,
    ASP_FIELD, /* Seal: input fields. Open: decoded field output. */
    ASP_IN,    /* Seal e2e: app; Seal outer: e2e blob; Open: blob/frame */
    ASP_OUT,
    ASP_OLEN,
    ASP_N = 7
};

/*
 * C17-valid host: API-typed spans always address their declared object, while
 * byte spans use byte_host.  unsigned char may inspect any object
 * representation, but this test never reinterprets byte_host as a typed API
 * object (or reads an inactive union member).
 */
typedef struct {
    ninlil_r7_crypto_provider prov;
    ninlil_r7_wire_e2e_single_fields e2e;
    ninlil_r7_wire_outer_data_fields outer;
    size_t olen;
    uint8_t byte_host[1024];
} alias_typed_host;

typedef struct {
    void *ptr;
    size_t len;
} alias_desc;

static size_t alias_binom2(size_t n)
{
    return (n * (n - 1u)) / 2u;
}

static ninlil_r7_wire_status alias_call_path(
    int path,
    const ninlil_r7_crypto_provider *prov_p,
    const uint8_t *key_p,
    const uint8_t *iv_p,
    void *field_p,
    const uint8_t *in_p,
    size_t in_len,
    uint8_t *out_p,
    size_t out_cap,
    size_t *olen_p)
{
    if (path == 0) {
        return ninlil_r7_wire_seal_e2e_single(
            prov_p, key_p, iv_p,
            (const ninlil_r7_wire_e2e_single_fields *)field_p, in_p, in_len,
            out_p, out_cap, olen_p);
    }
    if (path == 1) {
        return ninlil_r7_wire_open_e2e_single(
            prov_p, key_p, iv_p, in_p, in_len,
            (ninlil_r7_wire_e2e_single_fields *)field_p, out_p, out_cap, olen_p);
    }
    if (path == 2) {
        return ninlil_r7_wire_seal_outer_single(
            prov_p, key_p, iv_p,
            (const ninlil_r7_wire_outer_data_fields *)field_p, in_p, in_len,
            out_p, out_cap, olen_p);
    }
    return ninlil_r7_wire_open_outer_single(
        prov_p, key_p, iv_p, in_p, in_len,
        (ninlil_r7_wire_outer_data_fields *)field_p, out_p, out_cap, olen_p);
}

static int alias_is_byte_span(int sp)
{
    return sp == ASP_KEY || sp == ASP_IV || sp == ASP_IN || sp == ASP_OUT;
}

static void alias_init_typed_host(
    alias_typed_host *host,
    int path,
    const ninlil_r7_crypto_provider *good_prov,
    const uint8_t *wire_src,
    size_t in_len,
    size_t out_cap,
    alias_desc d[ASP_N])
{
    int is_open = (path == 1 || path == 3);
    int is_outer = (path >= 2);

    zmem(host, sizeof(*host));
    host->prov = *good_prov;
    if (is_outer) {
        fill_outer(&host->outer);
    } else {
        fill_e2e(&host->e2e);
    }
    host->olen = 0xDEADBEEFu;
    (void)memcpy(host->byte_host, is_outer ? HK16 : K16, 16u);
    (void)memcpy(host->byte_host + 32u, is_outer ? HIV12 : IV12, 12u);
    if (is_open || is_outer) {
        (void)memcpy(host->byte_host + 64u, wire_src, in_len);
    } else {
        fill_app(host->byte_host + 64u, in_len, 0x50u);
    }
    (void)memset(host->byte_host + 384u, 0xA5, out_cap);

    d[ASP_PROV].ptr = &host->prov;
    d[ASP_PROV].len = sizeof(host->prov);
    d[ASP_KEY].ptr = host->byte_host;
    d[ASP_KEY].len = 16u;
    d[ASP_IV].ptr = host->byte_host + 32u;
    d[ASP_IV].len = 12u;
    d[ASP_FIELD].ptr = is_outer ? (void *)&host->outer : (void *)&host->e2e;
    d[ASP_FIELD].len = is_outer ? sizeof(host->outer) : sizeof(host->e2e);
    d[ASP_IN].ptr = host->byte_host + 64u;
    d[ASP_IN].len = in_len;
    d[ASP_OUT].ptr = host->byte_host + 384u;
    d[ASP_OUT].len = out_cap;
    d[ASP_OLEN].ptr = &host->olen;
    d[ASP_OLEN].len = sizeof(host->olen);
}

static void alias_paint_byte_span(
    int path,
    int sp,
    uint8_t *dst,
    const uint8_t *wire_src,
    size_t in_len,
    size_t out_cap)
{
    int is_open = (path == 1 || path == 3);
    int is_outer = (path >= 2);

    if (sp == ASP_KEY) {
        (void)memcpy(dst, is_outer ? HK16 : K16, 16u);
    } else if (sp == ASP_IV) {
        (void)memcpy(dst, is_outer ? HIV12 : IV12, 12u);
    } else if (sp == ASP_IN) {
        if (is_open || is_outer) {
            (void)memcpy(dst, wire_src, in_len);
        } else {
            fill_app(dst, in_len, 0x50u);
        }
    } else { /* ASP_OUT */
        (void)memset(dst, 0xA5, out_cap);
    }
}

/* Snapshot all caller spans for one path via descriptor table. */
static void alias_snap_path(
    snap_t *s,
    int path,
    const alias_desc *d,
    size_t in_len,
    size_t out_cap)
{
    int is_open = (path == 1 || path == 3);
    int is_outer = (path >= 2);

    if (is_open && is_outer) {
        snap_take_full(
            s, (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
            (const uint8_t *)d[ASP_KEY].ptr, (const uint8_t *)d[ASP_IV].ptr,
            NULL, NULL, NULL,
            (const ninlil_r7_wire_outer_data_fields *)d[ASP_FIELD].ptr,
            (const uint8_t *)d[ASP_IN].ptr, in_len,
            (const uint8_t *)d[ASP_OUT].ptr, out_cap,
            (const size_t *)d[ASP_OLEN].ptr);
    } else if (is_open) {
        snap_take_full(
            s, (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
            (const uint8_t *)d[ASP_KEY].ptr, (const uint8_t *)d[ASP_IV].ptr,
            NULL, NULL,
            (const ninlil_r7_wire_e2e_single_fields *)d[ASP_FIELD].ptr, NULL,
            (const uint8_t *)d[ASP_IN].ptr, in_len,
            (const uint8_t *)d[ASP_OUT].ptr, out_cap,
            (const size_t *)d[ASP_OLEN].ptr);
    } else if (is_outer) {
        snap_take_full(
            s, (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
            (const uint8_t *)d[ASP_KEY].ptr, (const uint8_t *)d[ASP_IV].ptr,
            NULL, (const ninlil_r7_wire_outer_data_fields *)d[ASP_FIELD].ptr,
            NULL, NULL, (const uint8_t *)d[ASP_IN].ptr, in_len,
            (const uint8_t *)d[ASP_OUT].ptr, out_cap,
            (const size_t *)d[ASP_OLEN].ptr);
    } else {
        snap_take_full(
            s, (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
            (const uint8_t *)d[ASP_KEY].ptr, (const uint8_t *)d[ASP_IV].ptr,
            (const ninlil_r7_wire_e2e_single_fields *)d[ASP_FIELD].ptr, NULL,
            NULL, NULL, (const uint8_t *)d[ASP_IN].ptr, in_len,
            (const uint8_t *)d[ASP_OUT].ptr, out_cap,
            (const size_t *)d[ASP_OLEN].ptr);
    }
}

/* Snapshot only caller objects that a successful call must not mutate. */
static void alias_snap_immutable(
    snap_t *s,
    int path,
    const alias_desc *d,
    size_t in_len)
{
    int is_open = (path == 1 || path == 3);
    int is_outer = (path >= 2);

    if (is_open) {
        snap_take_full(
            s, (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
            (const uint8_t *)d[ASP_KEY].ptr, (const uint8_t *)d[ASP_IV].ptr,
            NULL, NULL, NULL, NULL,
            (const uint8_t *)d[ASP_IN].ptr, in_len, NULL, 0u, NULL);
    } else if (is_outer) {
        snap_take_full(
            s, (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
            (const uint8_t *)d[ASP_KEY].ptr, (const uint8_t *)d[ASP_IV].ptr,
            NULL, (const ninlil_r7_wire_outer_data_fields *)d[ASP_FIELD].ptr,
            NULL, NULL, (const uint8_t *)d[ASP_IN].ptr, in_len,
            NULL, 0u, NULL);
    } else {
        snap_take_full(
            s, (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
            (const uint8_t *)d[ASP_KEY].ptr, (const uint8_t *)d[ASP_IV].ptr,
            (const ninlil_r7_wire_e2e_single_fields *)d[ASP_FIELD].ptr,
            NULL, NULL, NULL, (const uint8_t *)d[ASP_IN].ptr, in_len,
            NULL, 0u, NULL);
    }
}

static void test_alias_all_pairs(rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_e2e_single_fields e2e;
    ninlil_r7_wire_outer_data_fields outer;
    uint8_t app[16], blob[46], frame[81];
    size_t bl = 0u, fl = 0u;
    int path;

    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x50u);
    expect_status("alias_prep",
        ninlil_r7_wire_seal_e2e_single(p, K16, IV12, &e2e, app, 16u, blob, 46u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status("alias_prep_o",
        ninlil_r7_wire_seal_outer_single(p, HK16, HIV12, &outer, blob, bl, frame, 81u, &fl),
        NINLIL_R7_WIRE_OK);

    /* adjacent success: key || out (legacy; not part of exact matrix counts) */
    {
        struct {
            uint8_t key[16];
            uint8_t out[46];
        } adj;
        size_t ol = 0u;
        (void)memcpy(adj.key, K16, 16);
        fill_e2e(&e2e);
        expect_status("alias_adjacent",
            ninlil_r7_wire_seal_e2e_single(
                p, adj.key, IV12, &e2e, app, 16u, adj.out, 46u, &ol),
            NINLIL_R7_WIRE_OK);
    }

    /* pointer-end overflow (legacy pack case) */
    {
        uint8_t *near = (uint8_t *)(uintptr_t)(UINTPTR_MAX - 8u);
        fill_outer(&outer);
        reset_rec(rc);
        expect_status("ptr_overflow_pack",
            ninlil_r7_wire_pack_outer_data_aad(&outer, near, 19u),
            NINLIL_R7_WIRE_ALIAS);
        if (rc->seal_calls != 0u) {
            failf("ptr_overflow", "cb");
        }
    }

    /*
     * Exact and partial matrices: each path executes every C(7,2)=21
     * unordered pair.  A valid C caller can overlap two byte arguments, so
     * those pairs call the production API directly.  A provider, fields, or
     * size_t out_len argument must instead point at its own declared typed
     * object.  C17 offers no valid way to make either that object and a
     * different typed object overlap (exactly or partially) without an
     * effective-type violation.  Those pairs therefore exercise the same
     * range predicate through the private test-only span-checker seam, using
     * an unsigned-char view of this declared typed host.
     */
    for (int partial = 0; partial < 2; partial++) {
        const char *matrix = partial ? "partial" : "exact";

        for (path = 0; path < 4; path++) {
            const size_t nspan = (size_t)ASP_N;
            const size_t expect_pairs = alias_binom2(nspan);
            const size_t expect_direct = 9u; /* 6 byte + prov/field/olen↔out */
            size_t ran = 0u;
            size_t api_ran = 0u;
            size_t seam_ran = 0u;
            size_t prov_out_direct = 0u;
            size_t field_out_direct = 0u;
            size_t olen_out_direct = 0u;
            int is_open = (path == 1 || path == 3);
            int is_outer = (path >= 2);
            size_t in_len =
                is_open ? (is_outer ? fl : bl) : (is_outer ? bl : 16u);
            size_t out_cap =
                is_open ? (is_outer ? 46u : 16u) : (is_outer ? 81u : 46u);
            const uint8_t *wire_src =
                is_open ? (is_outer ? frame : blob) : (is_outer ? blob : app);
            int a;
            int b;

            if (nspan != 7u || expect_pairs != 21u) {
                failf(partial ? "alias_partial_cov" : "alias_exact_cov",
                    "span/C(n,2) table");
            }

            for (a = 0; a < ASP_N; a++) {
                for (b = a + 1; b < ASP_N; b++) {
                    alias_typed_host host;
                    alias_desc d[ASP_N];
                    snap_t before, after;

                    alias_init_typed_host(
                        &host, path, p, wire_src, in_len, out_cap, d);

                    if ((alias_is_byte_span(a) && alias_is_byte_span(b))
                        || (b == ASP_OUT
                            && (a == ASP_PROV || a == ASP_FIELD))
                        || (a == ASP_OUT && b == ASP_OLEN)) {
                        ninlil_r7_wire_status st;

                        if (alias_is_byte_span(a) && alias_is_byte_span(b)) {
                            uint8_t *shared = host.byte_host + 640u;

                            d[a].ptr = shared;
                            d[b].ptr = shared + (partial ? 1u : 0u);
                            /* Keep a structural wire input intact when present. */
                            if (a != ASP_IN) {
                                alias_paint_byte_span(
                                    path, a, d[a].ptr, wire_src, in_len, out_cap);
                            }
                            if (b != ASP_IN) {
                                alias_paint_byte_span(
                                    path, b, d[b].ptr, wire_src, in_len, out_cap);
                            }
                            if (a == ASP_IN) {
                                alias_paint_byte_span(
                                    path, a, d[a].ptr, wire_src, in_len, out_cap);
                            }
                            if (b == ASP_IN) {
                                alias_paint_byte_span(
                                    path, b, d[b].ptr, wire_src, in_len, out_cap);
                            }
                        } else {
                            uint8_t *const host_bytes =
                                (uint8_t *)(void *)&host;
                            size_t member_offset;
                            int typed_sp = (a == ASP_OUT) ? b : a;

                            if (typed_sp == ASP_PROV) {
                                member_offset = offsetof(alias_typed_host, prov);
                            } else if (typed_sp == ASP_FIELD) {
                                member_offset = is_outer
                                    ? offsetof(alias_typed_host, outer)
                                    : offsetof(alias_typed_host, e2e);
                            } else {
                                member_offset = offsetof(alias_typed_host, olen);
                            }
                            /* Character view is based at the enclosing host. */
                            d[ASP_OUT].ptr =
                                host_bytes + member_offset + (partial ? 1u : 0u);
                            if (typed_sp == ASP_PROV) {
                                prov_out_direct++;
                            } else if (typed_sp == ASP_FIELD) {
                                field_out_direct++;
                            } else {
                                olen_out_direct++;
                            }
                        }

                        alias_snap_path(&before, path, d, in_len, out_cap);
                        reset_rec(rc);
                        st = alias_call_path(
                            path,
                            (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
                            (const uint8_t *)d[ASP_KEY].ptr,
                            (const uint8_t *)d[ASP_IV].ptr, d[ASP_FIELD].ptr,
                            (const uint8_t *)d[ASP_IN].ptr, in_len,
                            (uint8_t *)d[ASP_OUT].ptr, out_cap,
                            (size_t *)d[ASP_OLEN].ptr);
                        if (st != NINLIL_R7_WIRE_ALIAS) {
                            fprintf(stderr,
                                "nrw1_t1_wire_portable FAIL alias_%s path=%d "
                                "pair=%d,%d st=%d want=ALIAS\n",
                                matrix, path, a, b, (int)st);
                            g_failures++;
                        }
                        expect_cb0(matrix, rc, 0u, 0u);
                        api_ran++;
                    } else {
                        const unsigned char *repr =
                            (const unsigned char *)(const void *)&host;
                        const unsigned char *other = repr + (partial ? 1u : 0u);

                        alias_snap_path(&before, path, d, in_len, out_cap);
                        reset_rec(rc);
                        if (!ninlil_r7_wire_test_spans_forbidden(
                                repr, d[a].len, other, d[b].len)) {
                            fprintf(stderr,
                                "nrw1_t1_wire_portable FAIL alias_%s seam "
                                "path=%d pair=%d,%d\n",
                                matrix, path, a, b);
                            g_failures++;
                        }
                        expect_cb0(matrix, rc, 0u, 0u);
                        seam_ran++;
                    }

                    alias_snap_path(&after, path, d, in_len, out_cap);
                    if (!snap_eq_strict(&before, &after)) {
                        fprintf(stderr,
                            "nrw1_t1_wire_portable FAIL alias_%s mut path=%d "
                            "pair=%d,%d\n",
                            matrix, path, a, b);
                        g_failures++;
                    }
                    ran++;
                }
            }

            if (ran != expect_pairs || api_ran != expect_direct
                || api_ran + seam_ran != expect_pairs || prov_out_direct != 1u
                || field_out_direct != 1u || olen_out_direct != 1u) {
                fprintf(stderr,
                    "nrw1_t1_wire_portable FAIL alias_%s_cov path=%d "
                    "nspan=%zu C(n,2)=%zu ran=%zu api=%zu seam=%zu "
                    "typed=%zu/%zu/%zu\n",
                    matrix, path, nspan, expect_pairs, ran, api_ran, seam_ran,
                    prov_out_direct, field_out_direct, olen_out_direct);
                g_failures++;
            } else {
                fprintf(stderr,
                    "nrw1_t1_wire_portable alias_%s path=%d nspan=%zu "
                    "C(n,2)=%zu ran=%zu api=%zu seam=%zu typed=%zu/%zu/%zu OK\n",
                    matrix, path, nspan, expect_pairs, ran, api_ran, seam_ran,
                    prov_out_direct, field_out_direct, olen_out_direct);
            }
        }
    }

    /*
     * Adjacency matrix: byte pairs are valid direct callers and must succeed.
     * For a pair containing a typed API object, portable C17 cannot require
     * end(A)==begin(B): separate typed members may have implementation padding.
     * The codec's own test-only span predicate therefore proves those exact
     * no-intersection boundaries against an unsigned-char host view.
     */
    for (path = 0; path < 4; path++) {
        const size_t nspan = (size_t)ASP_N;
        const size_t expect_pairs = alias_binom2(nspan);
        size_t ran = 0u;
        size_t api_ran = 0u;
        size_t seam_ran = 0u;
        int is_open = (path == 1 || path == 3);
        int is_outer = (path >= 2);
        size_t in_len =
            is_open ? (is_outer ? fl : bl) : (is_outer ? bl : 16u);
        size_t out_cap =
            is_open ? (is_outer ? 46u : 16u) : (is_outer ? 81u : 46u);
        const uint8_t *wire_src =
            is_open ? (is_outer ? frame : blob) : (is_outer ? blob : app);
        int a;
        int b;

        if (nspan != 7u || expect_pairs != 21u) {
            failf("alias_adj_cov", "span/C(n,2) table");
        }

        for (a = 0; a < ASP_N; a++) {
            for (b = a + 1; b < ASP_N; b++) {
                alias_typed_host host;
                alias_desc d[ASP_N];
                snap_t before, after;

                alias_init_typed_host(
                    &host, path, p, wire_src, in_len, out_cap, d);
                if (alias_is_byte_span(a) && alias_is_byte_span(b)) {
                    uint8_t *shared = host.byte_host + 640u;
                    ninlil_r7_wire_status st;
                    size_t produced = 0u;
                    uint8_t expect_app[16];

                    d[a].ptr = shared;
                    d[b].ptr = shared + d[a].len;
                    if ((uint8_t *)d[a].ptr + d[a].len != d[b].ptr) {
                        failf("alias_adj", "not end==begin");
                    }
                    if (a != ASP_IN) {
                        alias_paint_byte_span(
                            path, a, d[a].ptr, wire_src, in_len, out_cap);
                    }
                    if (b != ASP_IN) {
                        alias_paint_byte_span(
                            path, b, d[b].ptr, wire_src, in_len, out_cap);
                    }
                    if (a == ASP_IN) {
                        alias_paint_byte_span(
                            path, a, d[a].ptr, wire_src, in_len, out_cap);
                    }
                    if (b == ASP_IN) {
                        alias_paint_byte_span(
                            path, b, d[b].ptr, wire_src, in_len, out_cap);
                    }

                    alias_snap_immutable(&before, path, d, in_len);
                    reset_rec(rc);
                    st = alias_call_path(
                        path,
                        (const ninlil_r7_crypto_provider *)d[ASP_PROV].ptr,
                        (const uint8_t *)d[ASP_KEY].ptr,
                        (const uint8_t *)d[ASP_IV].ptr, d[ASP_FIELD].ptr,
                        (const uint8_t *)d[ASP_IN].ptr, in_len,
                        (uint8_t *)d[ASP_OUT].ptr, out_cap,
                        (size_t *)d[ASP_OLEN].ptr);
                    if (st != NINLIL_R7_WIRE_OK) {
                        fprintf(stderr,
                            "nrw1_t1_wire_portable FAIL alias_adj path=%d "
                            "pair=%d,%d st=%d want=OK\n",
                            path, a, b, (int)st);
                        g_failures++;
                    }
                    if (is_open) {
                        expect_cb1_open("alias_adj", rc);
                    } else {
                        expect_cb1_seal("alias_adj", rc);
                    }
                    (void)memcpy(&produced, d[ASP_OLEN].ptr, sizeof(produced));
                    if (produced != out_cap) {
                        failf("alias_adj", "out_len");
                    }
                    fill_app(expect_app, 16u, 0x50u);
                    if (!is_open && !is_outer) {
                        if (!mem_eq(d[ASP_OUT].ptr, blob, bl) || produced != bl) {
                            failf("alias_adj", "seal_e2e blob bytes");
                        }
                    } else if (!is_open) {
                        if (!mem_eq(d[ASP_OUT].ptr, frame, fl) || produced != fl) {
                            failf("alias_adj", "seal_outer frame bytes");
                        }
                    } else if (!is_outer) {
                        ninlil_r7_wire_e2e_single_fields gold;
                        fill_e2e(&gold);
                        if (!mem_eq(d[ASP_OUT].ptr, expect_app, 16u)
                            || !mem_eq(d[ASP_FIELD].ptr, &gold, sizeof(gold))) {
                            failf("alias_adj", "open_e2e fields/app");
                        }
                    } else {
                        ninlil_r7_wire_outer_data_fields gold;
                        fill_outer(&gold);
                        if (!mem_eq(d[ASP_OUT].ptr, blob, bl)
                            || !mem_eq(d[ASP_FIELD].ptr, &gold, sizeof(gold))) {
                            failf("alias_adj", "open_outer fields/blob");
                        }
                    }
                    alias_snap_immutable(&after, path, d, in_len);
                    if (!snap_eq_strict(&before, &after)) {
                        fprintf(stderr,
                            "nrw1_t1_wire_portable FAIL alias_adj input mut "
                            "path=%d pair=%d,%d\n",
                            path, a, b);
                        g_failures++;
                    }
                    api_ran++;
                } else {
                    const unsigned char *repr =
                        (const unsigned char *)(const void *)&host;

                    alias_snap_path(&before, path, d, in_len, out_cap);
                    reset_rec(rc);
                    if (ninlil_r7_wire_test_spans_forbidden(
                            repr, d[a].len, repr + d[a].len, d[b].len)) {
                        fprintf(stderr,
                            "nrw1_t1_wire_portable FAIL alias_adj seam "
                            "path=%d pair=%d,%d\n",
                            path, a, b);
                        g_failures++;
                    }
                    expect_cb0("alias_adj", rc, 0u, 0u);
                    alias_snap_path(&after, path, d, in_len, out_cap);
                    if (!snap_eq_strict(&before, &after)) {
                        fprintf(stderr,
                            "nrw1_t1_wire_portable FAIL alias_adj seam mut "
                            "path=%d pair=%d,%d\n",
                            path, a, b);
                        g_failures++;
                    }
                    seam_ran++;
                }
                ran++;
            }
        }

        if (ran != expect_pairs || api_ran + seam_ran != expect_pairs) {
            fprintf(stderr,
                "nrw1_t1_wire_portable FAIL alias_adj_cov path=%d "
                "nspan=%zu C(n,2)=%zu ran=%zu api=%zu seam=%zu\n",
                path, nspan, expect_pairs, ran, api_ran, seam_ran);
            g_failures++;
        } else {
            fprintf(stderr,
                "nrw1_t1_wire_portable alias_adj path=%d nspan=%zu "
                "C(n,2)=%zu ran=%zu api=%zu seam=%zu OK\n",
                path, nspan, expect_pairs, ran, api_ran, seam_ran);
        }
    }

    /*
     * Pointer-end overflow: only spans NOT dereferenced before alias.
     * Fake near-UINTPTR_MAX pointer + declared length → ALIAS, cb0, mut0.
     * SIZE_MAX > UINTPTR_MAX length class: conditional on platform.
     */
    {
        /* path → safe overflow span ids (not read before alias). */
        static const int safe0[] = {
            ASP_KEY, ASP_IV, ASP_IN, ASP_OUT, ASP_OLEN, -1};
        static const int safe1[] = {
            ASP_KEY, ASP_IV, ASP_FIELD, ASP_OUT, ASP_OLEN, -1};
        static const int safe2[] = {
            ASP_KEY, ASP_IV, ASP_OUT, ASP_OLEN, -1};
        static const int safe3[] = {
            ASP_KEY, ASP_IV, ASP_FIELD, ASP_OUT, ASP_OLEN, -1};
        const int *safe_lists[4];
        uint8_t *const poison =
            (uint8_t *)(uintptr_t)(UINTPTR_MAX - 7u);

        safe_lists[0] = safe0;
        safe_lists[1] = safe1;
        safe_lists[2] = safe2;
        safe_lists[3] = safe3;

        for (path = 0; path < 4; path++) {
            int is_open = (path == 1 || path == 3);
            int is_outer = (path >= 2);
            size_t in_len =
                is_open ? (is_outer ? fl : bl) : (is_outer ? bl : 16u);
            size_t out_cap =
                is_open ? (is_outer ? 46u : 16u) : (is_outer ? 81u : 46u);
            size_t field_len =
                is_outer ? sizeof(ninlil_r7_wire_outer_data_fields)
                         : sizeof(ninlil_r7_wire_e2e_single_fields);
            const uint8_t *wire_src =
                is_open ? (is_outer ? frame : blob) : (is_outer ? blob : app);
            const int *sp;
            int nsafe = 0;

            for (sp = safe_lists[path]; *sp >= 0; sp++) {
                ninlil_r7_crypto_provider slot_prov = *p;
                uint8_t slot_key[16];
                uint8_t slot_iv[12];
                union {
                    ninlil_r7_wire_e2e_single_fields e2e;
                    ninlil_r7_wire_outer_data_fields outer;
                } slot_field;
                uint8_t slot_in[220];
                uint8_t slot_out[255];
                size_t slot_olen = 0xDEADBEEFu;
                alias_desc d[ASP_N];
                snap_t before, after;
                ninlil_r7_wire_status st;
                const ninlil_r7_crypto_provider *arg_prov;
                const uint8_t *arg_key;
                const uint8_t *arg_iv;
                void *arg_field;
                const uint8_t *arg_in;
                uint8_t *arg_out;
                size_t *arg_olen;
                int ov = *sp;

                (void)memcpy(slot_key, is_outer ? HK16 : K16, 16u);
                (void)memcpy(slot_iv, is_outer ? HIV12 : IV12, 12u);
                if (is_outer) {
                    fill_outer(&slot_field.outer);
                } else {
                    fill_e2e(&slot_field.e2e);
                }
                (void)memcpy(slot_in, wire_src, in_len);
                (void)memset(slot_out, 0xA5, out_cap);

                d[ASP_PROV].ptr = &slot_prov;
                d[ASP_PROV].len = sizeof(slot_prov);
                d[ASP_KEY].ptr = slot_key;
                d[ASP_KEY].len = 16u;
                d[ASP_IV].ptr = slot_iv;
                d[ASP_IV].len = 12u;
                d[ASP_FIELD].ptr = &slot_field;
                d[ASP_FIELD].len = field_len;
                d[ASP_IN].ptr = slot_in;
                d[ASP_IN].len = in_len;
                d[ASP_OUT].ptr = slot_out;
                d[ASP_OUT].len = out_cap;
                d[ASP_OLEN].ptr = &slot_olen;
                d[ASP_OLEN].len = sizeof(slot_olen);

                alias_snap_path(&before, path, d, in_len, out_cap);

                arg_prov = &slot_prov;
                arg_key = slot_key;
                arg_iv = slot_iv;
                arg_field = &slot_field;
                arg_in = slot_in;
                arg_out = slot_out;
                arg_olen = &slot_olen;
                if (ov == ASP_KEY) {
                    arg_key = poison;
                } else if (ov == ASP_IV) {
                    arg_iv = poison;
                } else if (ov == ASP_FIELD) {
                    arg_field = poison;
                } else if (ov == ASP_IN) {
                    arg_in = poison;
                } else if (ov == ASP_OUT) {
                    arg_out = poison;
                } else if (ov == ASP_OLEN) {
                    arg_olen = (size_t *)(void *)poison;
                }

                reset_rec(rc);
                st = alias_call_path(
                    path, arg_prov, arg_key, arg_iv, arg_field, arg_in, in_len,
                    arg_out, out_cap, arg_olen);

                if (st != NINLIL_R7_WIRE_ALIAS) {
                    fprintf(stderr,
                        "nrw1_t1_wire_portable FAIL alias_overflow path=%d "
                        "span=%d st=%d want=ALIAS\n",
                        path, ov, (int)st);
                    g_failures++;
                }
                expect_cb0("alias_overflow", rc, 0u, 0u);

                /* Snap only real caller storage (never dereference poison). */
                alias_snap_path(&after, path, d, in_len, out_cap);
                if (!snap_eq_strict(&before, &after)) {
                    fprintf(stderr,
                        "nrw1_t1_wire_portable FAIL alias_overflow mut "
                        "path=%d span=%d\n",
                        path, ov);
                    g_failures++;
                }
                nsafe++;
            }
            fprintf(stderr,
                "nrw1_t1_wire_portable alias_overflow path=%d safe_spans=%d "
                "OK\n",
                path, nsafe);
        }

        /*
         * size_t > UINTPTR_MAX as a public pairwise span length is not
         * dynamically reachable through domain-valid API arguments: max
         * wire frame 255, blob 220, app 190, AAD 19/14, key 16, iv 12, and
         * field/provider sizeof all sit well below any real UINTPTR_MAX.
         * Production still fail-closes that predicate inside
         * ninlil_r7_wire_spans_forbidden (pinned by platform_split_gate).
         * Portable test asserts the domain/UINTPTR relationship; no
         * unasserted success call.
         */
        {
            const int wide_size_t = (SIZE_MAX > (size_t)UINTPTR_MAX) ? 1 : 0;
            const size_t domain_span_max = NINLIL_R7_WIRE_FRAME_MAX; /* 255 */

            if (NINLIL_R7_WIRE_FRAME_MAX > domain_span_max
                || NINLIL_R7_WIRE_E2E_BLOB_MAX > domain_span_max
                || NINLIL_R7_WIRE_APP_MAX > domain_span_max) {
                failf("domain_span_max", "internal constant order");
            }
            if (domain_span_max > (size_t)UINTPTR_MAX
                || NINLIL_R7_WIRE_E2E_BLOB_MAX > (size_t)UINTPTR_MAX
                || NINLIL_R7_WIRE_APP_MAX > (size_t)UINTPTR_MAX
                || NINLIL_R7_WIRE_OUTER_AAD_LEN > (size_t)UINTPTR_MAX
                || NINLIL_R7_WIRE_E2E_AAD_LEN > (size_t)UINTPTR_MAX
                || sizeof(ninlil_r7_crypto_provider) > (size_t)UINTPTR_MAX
                || sizeof(ninlil_r7_wire_outer_data_fields) > (size_t)UINTPTR_MAX
                || sizeof(size_t) > (size_t)UINTPTR_MAX) {
                failf(
                    "domain_le_uintptr",
                    "public domain span exceeds UINTPTR_MAX");
            }
            if (wide_size_t) {
                /*
                 * size_t can represent values > UINTPTR_MAX, but every
                 * domain-valid pairwise length used by the public wire API
                 * is <= domain_span_max <= UINTPTR_MAX, so the production
                 * (len > UINTPTR_MAX) arm is not reachable via valid domain.
                 */
                if (!(SIZE_MAX > (size_t)UINTPTR_MAX)) {
                    failf("wide_size_t", "branch invariant broken");
                }
                if (!((size_t)UINTPTR_MAX + (size_t)1u > (size_t)UINTPTR_MAX)) {
                    failf("wide_size_t", "cannot form >UINTPTR_MAX size_t");
                }
                if (domain_span_max > (size_t)UINTPTR_MAX) {
                    failf(
                        "wide_size_t",
                        "domain max must stay <= UINTPTR_MAX");
                }
                fprintf(stderr,
                    "nrw1_t1_wire_portable alias_overflow "
                    "wide-size_t: SIZE_MAX>UINTPTR_MAX but public domain "
                    "max span %zu <= UINTPTR_MAX — >UINTPTR_MAX "
                    "unreachable via valid domain OK\n",
                    domain_span_max);
            } else {
                if (SIZE_MAX > (size_t)UINTPTR_MAX) {
                    failf(
                        "size_le_uintptr",
                        "expected SIZE_MAX<=UINTPTR_MAX on this platform");
                }
                fprintf(stderr,
                    "nrw1_t1_wire_portable alias_overflow "
                    "SIZE_MAX<=UINTPTR_MAX and domain_max=%zu<=UINTPTR_MAX "
                    "— len>UINTPTR_MAX not representable/reachable OK\n",
                    domain_span_max);
            }
        }
    }
}

/*
 * pack/parse OK roundtrip + residual domain structural (context 0 / MAX).
 * AAD NULL / wrong-length / profile·kind·type·reserved structural matrix is
 * test_aad_null_length_structural (exact 26 with mutation-zero).
 */
static void test_aad_domains(void)
{
    ninlil_r7_wire_outer_data_fields outer, oout;
    ninlil_r7_wire_e2e_single_fields e2e, eout;
    uint8_t aad19[19], aad14[14], bad[20];

    fill_outer(&outer);
    expect_status("pack_o", ninlil_r7_wire_pack_outer_data_aad(&outer, aad19, 19u), NINLIL_R7_WIRE_OK);
    zmem(&oout, sizeof(oout));
    expect_status("parse_o", ninlil_r7_wire_parse_outer_data_aad(aad19, 19u, &oout), NINLIL_R7_WIRE_OK);
    if (!mem_eq(&outer, &oout, sizeof(outer))) {
        failf("parse_o", "padding");
    }
    fill_e2e(&e2e);
    expect_status("pack_e", ninlil_r7_wire_pack_e2e_single_aad(&e2e, aad14, 14u), NINLIL_R7_WIRE_OK);
    zmem(&eout, sizeof(eout));
    expect_status("parse_e", ninlil_r7_wire_parse_e2e_single_aad(aad14, 14u, &eout), NINLIL_R7_WIRE_OK);
    if (!mem_eq(&e2e, &eout, sizeof(e2e))) {
        failf("parse_e", "padding");
    }
    (void)memcpy(bad, aad19, 19u);
    (void)memset(bad + 3, 0, 4);
    expect_status("parse_o_ctx0", ninlil_r7_wire_parse_outer_data_aad(bad, 19u, &oout), NINLIL_R7_WIRE_STRUCTURAL);
    (void)memcpy(bad, aad14, 14u);
    (void)memset(bad + 2, 0xff, 4);
    expect_status("parse_e_ctxmax", ninlil_r7_wire_parse_e2e_single_aad(bad, 14u, &eout), NINLIL_R7_WIRE_STRUCTURAL);
}

/*
 * Mandatory boundary matrix — part 1 (docs/32 §8): status ABI, length class,
 * exact capacity ±1, and validation-precedence collisions. Callback 0 and full
 * caller mutation-zero on every failure case.
 */
static size_t g_mb_cases;

static void mb_tick(void)
{
    g_mb_cases++;
}

static void mb_expect_cb0(const char *name, rec_ctx *rc)
{
    if (rc->seal_calls != 0u || rc->open_calls != 0u) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s callback seal=%zu open=%zu want=0\n",
            name, rc->seal_calls, rc->open_calls);
        g_failures++;
    }
}

/* pack AAD: fields + out buffer mutation zero, no crypto callbacks */
static void mb_pack_e2e(
    const char *name,
    const ninlil_r7_wire_e2e_single_fields *fields,
    size_t cap,
    ninlil_r7_wire_status want)
{
    uint8_t out[32];
    ninlil_r7_wire_e2e_single_fields fcopy;
    ninlil_r7_wire_status st;
    size_t i;
    size_t n;

    mb_tick();
    fcopy = *fields;
    n = cap < sizeof(out) ? cap : sizeof(out);
    (void)memset(out, 0xA5, sizeof(out));
    st = ninlil_r7_wire_pack_e2e_single_aad(fields, out, cap);
    expect_status(name, st, want);
    if (!mem_eq(&fcopy, fields, sizeof(fcopy))) {
        failf(name, "fields mutated");
    }
    for (i = 0u; i < n; i++) {
        if (out[i] != 0xA5u) {
            failf(name, "out mutated");
            break;
        }
    }
}

static void mb_pack_outer(
    const char *name,
    const ninlil_r7_wire_outer_data_fields *fields,
    size_t cap,
    ninlil_r7_wire_status want)
{
    uint8_t out[32];
    ninlil_r7_wire_outer_data_fields fcopy;
    ninlil_r7_wire_status st;
    size_t i;
    size_t n;

    mb_tick();
    fcopy = *fields;
    n = cap < sizeof(out) ? cap : sizeof(out);
    (void)memset(out, 0xA5, sizeof(out));
    st = ninlil_r7_wire_pack_outer_data_aad(fields, out, cap);
    expect_status(name, st, want);
    if (!mem_eq(&fcopy, fields, sizeof(fcopy))) {
        failf(name, "fields mutated");
    }
    for (i = 0u; i < n; i++) {
        if (out[i] != 0xA5u) {
            failf(name, "out mutated");
            break;
        }
    }
}

static void mb_seal_e2e(
    const char *name,
    rec_ctx *rc,
    ninlil_r7_crypto_provider *p,
    const uint8_t *key,
    const uint8_t *iv,
    const ninlil_r7_wire_e2e_single_fields *fields,
    const uint8_t *app,
    size_t app_len,
    size_t out_cap,
    ninlil_r7_wire_status want)
{
    uint8_t out[256];
    size_t ol;
    snap_t before, after;
    ninlil_r7_wire_status st;
    size_t paint = out_cap < sizeof(out) ? out_cap : sizeof(out);

    mb_tick();
    (void)memset(out, 0xA5, sizeof(out));
    ol = 0xBEEFu;
    snap_take_full(
        &before, p, key, iv, fields, NULL, NULL, NULL, app, app_len, out, paint,
        &ol);
    reset_rec(rc);
    st = ninlil_r7_wire_seal_e2e_single(
        p, key, iv, fields, app, app_len, out, out_cap, &ol);
    expect_status(name, st, want);
    mb_expect_cb0(name, rc);
    snap_take_full(
        &after, p, key, iv, fields, NULL, NULL, NULL, app, app_len, out, paint,
        &ol);
    if (!snap_eq_strict(&before, &after)) {
        failf(name, "caller mutated");
    }
}

static void mb_open_e2e(
    const char *name,
    rec_ctx *rc,
    ninlil_r7_crypto_provider *p,
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *blob,
    size_t blob_len,
    size_t out_cap,
    ninlil_r7_wire_status want)
{
    ninlil_r7_wire_e2e_single_fields eout;
    uint8_t out[256];
    size_t ol;
    snap_t before, after;
    ninlil_r7_wire_status st;
    size_t paint = out_cap < sizeof(out) ? out_cap : sizeof(out);

    mb_tick();
    (void)memset(out, 0xA5, sizeof(out));
    ol = 0xBEEFu;
    (void)memset(&eout, 0xC3, sizeof(eout));
    snap_take_full(
        &before, p, key, iv, NULL, NULL, &eout, NULL, blob, blob_len, out, paint,
        &ol);
    reset_rec(rc);
    st = ninlil_r7_wire_open_e2e_single(
        p, key, iv, blob, blob_len, &eout, out, out_cap, &ol);
    expect_status(name, st, want);
    mb_expect_cb0(name, rc);
    snap_take_full(
        &after, p, key, iv, NULL, NULL, &eout, NULL, blob, blob_len, out, paint,
        &ol);
    if (!snap_eq_strict(&before, &after)) {
        failf(name, "caller mutated");
    }
}

static void mb_seal_outer(
    const char *name,
    rec_ctx *rc,
    ninlil_r7_crypto_provider *p,
    const uint8_t *key,
    const uint8_t *iv,
    const ninlil_r7_wire_outer_data_fields *fields,
    const uint8_t *e2e_blob,
    size_t e2e_blob_len,
    size_t out_cap,
    ninlil_r7_wire_status want)
{
    uint8_t out[256];
    size_t ol;
    snap_t before, after;
    ninlil_r7_wire_status st;
    size_t paint = out_cap < sizeof(out) ? out_cap : sizeof(out);

    mb_tick();
    (void)memset(out, 0xA5, sizeof(out));
    ol = 0xBEEFu;
    snap_take_full(
        &before, p, key, iv, NULL, fields, NULL, NULL, e2e_blob, e2e_blob_len,
        out, paint, &ol);
    reset_rec(rc);
    st = ninlil_r7_wire_seal_outer_single(
        p, key, iv, fields, e2e_blob, e2e_blob_len, out, out_cap, &ol);
    expect_status(name, st, want);
    mb_expect_cb0(name, rc);
    snap_take_full(
        &after, p, key, iv, NULL, fields, NULL, NULL, e2e_blob, e2e_blob_len, out,
        paint, &ol);
    if (!snap_eq_strict(&before, &after)) {
        failf(name, "caller mutated");
    }
}

static void mb_open_outer(
    const char *name,
    rec_ctx *rc,
    ninlil_r7_crypto_provider *p,
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *frame,
    size_t frame_len,
    size_t out_cap,
    ninlil_r7_wire_status want)
{
    ninlil_r7_wire_outer_data_fields oout;
    uint8_t out[256];
    size_t ol;
    snap_t before, after;
    ninlil_r7_wire_status st;
    size_t paint = out_cap < sizeof(out) ? out_cap : sizeof(out);

    mb_tick();
    (void)memset(out, 0xA5, sizeof(out));
    ol = 0xBEEFu;
    (void)memset(&oout, 0xC4, sizeof(oout));
    snap_take_full(
        &before, p, key, iv, NULL, NULL, NULL, &oout, frame, frame_len, out,
        paint, &ol);
    reset_rec(rc);
    st = ninlil_r7_wire_open_outer_single(
        p, key, iv, frame, frame_len, &oout, out, out_cap, &ol);
    expect_status(name, st, want);
    mb_expect_cb0(name, rc);
    snap_take_full(
        &after, p, key, iv, NULL, NULL, NULL, &oout, frame, frame_len, out, paint,
        &ol);
    if (!snap_eq_strict(&before, &after)) {
        failf(name, "caller mutated");
    }
}

static void test_mandatory_boundaries(rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_e2e_single_fields e2e;
    ninlil_r7_wire_outer_data_fields outer;
    uint8_t app[16], app_wide[256], blob[46], frame[81], wire_big[256];
    uint8_t key[16], iv[12], hkey[16], hiv[12];
    size_t bl = 0u, fl = 0u;
    const size_t expected_cases = 1u  /* ABI */
        + 9u                         /* length class */
        + 12u                        /* capacity ±1 */
        + 14u;                       /* precedence collisions */

    g_mb_cases = 0u;
    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x50u);
    fill_app(app_wide, sizeof(app_wide), 0x50u);
    (void)memcpy(key, K16, 16u);
    (void)memcpy(iv, IV12, 12u);
    (void)memcpy(hkey, HK16, 16u);
    (void)memcpy(hiv, HIV12, 12u);
    reset_rec(rc);
    expect_status(
        "mb_prep_e2e",
        ninlil_r7_wire_seal_e2e_single(
            p, key, iv, &e2e, app, 16u, blob, 46u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "mb_prep_outer",
        ninlil_r7_wire_seal_outer_single(
            p, hkey, hiv, &outer, blob, bl, frame, 81u, &fl),
        NINLIL_R7_WIRE_OK);

    /* ---- (1) status ABI pin ---- */
    mb_tick();
    {
        static const ninlil_r7_wire_status catalog[] = {
            NINLIL_R7_WIRE_OK,
            NINLIL_R7_WIRE_INVALID_ARGUMENT,
            NINLIL_R7_WIRE_STRUCTURAL,
            NINLIL_R7_WIRE_LENGTH_CLASS,
            NINLIL_R7_WIRE_CAPACITY,
            NINLIL_R7_WIRE_ALIAS,
            NINLIL_R7_WIRE_AUTH_FAILED,
            NINLIL_R7_WIRE_BACKEND_FAILED,
            NINLIL_R7_WIRE_INTERNAL_CONTRACT,
        };
        size_t i;

        if (sizeof(ninlil_r7_wire_status) != 4u) {
            failf("mb_status_abi", "sizeof != 4");
        }
        for (i = 0u; i < 9u; i++) {
            if (catalog[i] != (ninlil_r7_wire_status)i) {
                fprintf(stderr,
                    "nrw1_t1_wire_portable FAIL mb_status_abi idx=%zu val=%d\n",
                    i, (int)catalog[i]);
                g_failures++;
            }
        }
    }

    /* ---- (2) length class: N / frame / blob / underflow-short ---- */
    mb_seal_e2e(
        "mb_len_seal_e2e_N0", rc, p, key, iv, &e2e, app_wide, 0u, 46u,
        NINLIL_R7_WIRE_LENGTH_CLASS);
    mb_seal_e2e(
        "mb_len_seal_e2e_N191", rc, p, key, iv, &e2e, app_wide, 191u, 221u,
        NINLIL_R7_WIRE_LENGTH_CLASS);

    (void)memset(wire_big, 0x5A, sizeof(wire_big));
    (void)memcpy(wire_big, frame, fl);
    mb_open_outer(
        "mb_len_open_outer_frame65", rc, p, hkey, hiv, wire_big, 65u, 46u,
        NINLIL_R7_WIRE_LENGTH_CLASS);
    mb_open_outer(
        "mb_len_open_outer_frame256", rc, p, hkey, hiv, wire_big, 256u, 46u,
        NINLIL_R7_WIRE_LENGTH_CLASS);

    (void)memcpy(wire_big, blob, bl);
    mb_open_e2e(
        "mb_len_open_e2e_blob30", rc, p, key, iv, wire_big, 30u, 16u,
        NINLIL_R7_WIRE_LENGTH_CLASS);
    mb_open_e2e(
        "mb_len_open_e2e_blob221", rc, p, key, iv, wire_big, 221u, 16u,
        NINLIL_R7_WIRE_LENGTH_CLASS);

    /* Short lengths that would underflow blob_len-30 without the min check. */
    mb_open_e2e(
        "mb_len_open_e2e_under_0", rc, p, key, iv, wire_big, 0u, 1u,
        NINLIL_R7_WIRE_LENGTH_CLASS);
    mb_open_e2e(
        "mb_len_open_e2e_under_14", rc, p, key, iv, wire_big, 14u, 1u,
        NINLIL_R7_WIRE_LENGTH_CLASS);
    mb_open_e2e(
        "mb_len_open_e2e_under_29", rc, p, key, iv, wire_big, 29u, 1u,
        NINLIL_R7_WIRE_LENGTH_CLASS);

    /* ---- (3) exact capacity required -1 / +1 ---- */
    mb_pack_outer("mb_cap_pack_outer_m1", &outer, 18u, NINLIL_R7_WIRE_CAPACITY);
    mb_pack_outer("mb_cap_pack_outer_p1", &outer, 20u, NINLIL_R7_WIRE_CAPACITY);
    mb_pack_e2e("mb_cap_pack_e2e_m1", &e2e, 13u, NINLIL_R7_WIRE_CAPACITY);
    mb_pack_e2e("mb_cap_pack_e2e_p1", &e2e, 15u, NINLIL_R7_WIRE_CAPACITY);

    mb_seal_e2e(
        "mb_cap_seal_e2e_m1", rc, p, key, iv, &e2e, app, 16u, 45u,
        NINLIL_R7_WIRE_CAPACITY);
    mb_seal_e2e(
        "mb_cap_seal_e2e_p1", rc, p, key, iv, &e2e, app, 16u, 47u,
        NINLIL_R7_WIRE_CAPACITY);
    mb_open_e2e(
        "mb_cap_open_e2e_m1", rc, p, key, iv, blob, bl, 15u,
        NINLIL_R7_WIRE_CAPACITY);
    mb_open_e2e(
        "mb_cap_open_e2e_p1", rc, p, key, iv, blob, bl, 17u,
        NINLIL_R7_WIRE_CAPACITY);
    mb_seal_outer(
        "mb_cap_seal_outer_m1", rc, p, hkey, hiv, &outer, blob, bl, 80u,
        NINLIL_R7_WIRE_CAPACITY);
    mb_seal_outer(
        "mb_cap_seal_outer_p1", rc, p, hkey, hiv, &outer, blob, bl, 82u,
        NINLIL_R7_WIRE_CAPACITY);
    mb_open_outer(
        "mb_cap_open_outer_m1", rc, p, hkey, hiv, frame, fl, 45u,
        NINLIL_R7_WIRE_CAPACITY);
    mb_open_outer(
        "mb_cap_open_outer_p1", rc, p, hkey, hiv, frame, fl, 47u,
        NINLIL_R7_WIRE_CAPACITY);

    /* ---- (4) precedence collisions ---- */
    {
        ninlil_r7_wire_e2e_single_fields bad_e2e;
        ninlil_r7_wire_outer_data_fields bad_outer;
        ninlil_r7_crypto_provider bad_prov;
        uint8_t bad_blob[46];
        uint8_t bad_frame[81];
        uint8_t out_alias[64];
        size_t ol_alias;

        /* field domain invalid + wrong capacity → STRUCTURAL (before CAPACITY) */
        zmem(&bad_e2e, sizeof(bad_e2e));
        bad_e2e.e2e_context_id = 0u;
        bad_e2e.e2e_counter = 1u;
        mb_seal_e2e(
            "mb_prec_seal_e2e_field0_cap", rc, p, key, iv, &bad_e2e, app, 16u,
            45u, NINLIL_R7_WIRE_STRUCTURAL);

        /* length invalid + wrong capacity → LENGTH_CLASS */
        mb_seal_e2e(
            "mb_prec_seal_e2e_N0_cap", rc, p, key, iv, &e2e, app_wide, 0u, 45u,
            NINLIL_R7_WIRE_LENGTH_CLASS);

        /* visible structural + wrong capacity → STRUCTURAL (before CAPACITY) */
        (void)memcpy(bad_blob, blob, bl);
        bad_blob[0] ^= 0x01u;
        mb_open_e2e(
            "mb_prec_open_e2e_struct_cap", rc, p, key, iv, bad_blob, bl, 15u,
            NINLIL_R7_WIRE_STRUCTURAL);

        (void)memcpy(bad_frame, frame, fl);
        bad_frame[0] ^= 0x01u;
        mb_open_outer(
            "mb_prec_open_outer_struct_cap", rc, p, hkey, hiv, bad_frame, fl,
            45u, NINLIL_R7_WIRE_STRUCTURAL);

        /* length before capacity on open outer */
        mb_open_outer(
            "mb_prec_open_outer_len65_cap", rc, p, hkey, hiv, frame, 65u, 45u,
            NINLIL_R7_WIRE_LENGTH_CLASS);
        mb_open_e2e(
            "mb_prec_open_e2e_len30_cap", rc, p, key, iv, blob, 30u, 15u,
            NINLIL_R7_WIRE_LENGTH_CLASS);

        /*
         * Valid domain + wrong capacity + forced alias: capacity is checked
         * before pairwise alias → CAPACITY, callback 0.
         */
        (void)memset(out_alias, 0xA5, sizeof(out_alias));
        ol_alias = 0xBEEFu;
        {
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb_tick();
            snap_take_full(
                &before, p, key, iv, &e2e, NULL, NULL, NULL, app, 16u,
                out_alias, 45u, &ol_alias);
            reset_rec(rc);
            /* out overlaps app intentionally; capacity fails first. */
            st = ninlil_r7_wire_seal_e2e_single(
                p, key, iv, &e2e, app, 16u, app, 45u, &ol_alias);
            expect_status("mb_prec_seal_e2e_cap_before_alias", st,
                NINLIL_R7_WIRE_CAPACITY);
            mb_expect_cb0("mb_prec_seal_e2e_cap_before_alias", rc);
            snap_take_full(
                &after, p, key, iv, &e2e, NULL, NULL, NULL, app, 16u, out_alias,
                45u, &ol_alias);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb_prec_seal_e2e_cap_before_alias", "mut");
            }
        }
        {
            snap_t before, after;
            ninlil_r7_wire_status st;
            ninlil_r7_wire_e2e_single_fields eout;
            uint8_t oapp[16];

            mb_tick();
            (void)memset(oapp, 0xA5, sizeof(oapp));
            ol_alias = 0xBEEFu;
            (void)memset(&eout, 0xC3, sizeof(eout));
            snap_take_full(
                &before, p, key, iv, NULL, NULL, &eout, NULL, blob, bl, oapp,
                15u, &ol_alias);
            reset_rec(rc);
            st = ninlil_r7_wire_open_e2e_single(
                p, key, iv, blob, bl, &eout, (uint8_t *)(uintptr_t)blob, 15u,
                &ol_alias);
            expect_status("mb_prec_open_e2e_cap_before_alias", st,
                NINLIL_R7_WIRE_CAPACITY);
            mb_expect_cb0("mb_prec_open_e2e_cap_before_alias", rc);
            snap_take_full(
                &after, p, key, iv, NULL, NULL, &eout, NULL, blob, bl, oapp, 15u,
                &ol_alias);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb_prec_open_e2e_cap_before_alias", "mut");
            }
        }

        /* required pointer / provider invalid beats later length/capacity */
        mb_seal_e2e(
            "mb_prec_seal_e2e_nullkey_N191", rc, p, NULL, iv, &e2e, app_wide,
            191u, 221u, NINLIL_R7_WIRE_INVALID_ARGUMENT);

        bad_prov = *p;
        bad_prov.abi_version = 0u;
        mb_tick();
        {
            uint8_t out[64];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, &bad_prov, key, iv, &e2e, NULL, NULL, NULL, app, 16u,
                out, 45u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_e2e_single(
                &bad_prov, key, iv, &e2e, app, 16u, out, 45u, &ol);
            expect_status(
                "mb_prec_seal_e2e_badprov_cap", st,
                NINLIL_R7_WIRE_INVALID_ARGUMENT);
            mb_expect_cb0("mb_prec_seal_e2e_badprov_cap", rc);
            snap_take_full(
                &after, &bad_prov, key, iv, &e2e, NULL, NULL, NULL, app, 16u,
                out, 45u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb_prec_seal_e2e_badprov_cap", "mut");
            }
        }

        /* NULL wire input: snap with input_len 0 (no OOB); API still gets bl. */
        mb_tick();
        {
            ninlil_r7_wire_e2e_single_fields eout;
            uint8_t out[32];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            (void)memset(out, 0xA5, sizeof(out));
            (void)memset(&eout, 0xC3, sizeof(eout));
            snap_take_full(
                &before, p, key, iv, NULL, NULL, &eout, NULL, NULL, 0u, out,
                15u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_open_e2e_single(
                p, key, iv, NULL, bl, &eout, out, 15u, &ol);
            expect_status(
                "mb_prec_open_e2e_nullblob_cap", st,
                NINLIL_R7_WIRE_INVALID_ARGUMENT);
            mb_expect_cb0("mb_prec_open_e2e_nullblob_cap", rc);
            snap_take_full(
                &after, p, key, iv, NULL, NULL, &eout, NULL, NULL, 0u, out, 15u,
                &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb_prec_open_e2e_nullblob_cap", "caller mutated");
            }
        }
        mb_tick();
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, NULL, 0u, out,
                80u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, NULL, bl, out, 80u, &ol);
            expect_status(
                "mb_prec_seal_outer_nullblob_cap", st,
                NINLIL_R7_WIRE_INVALID_ARGUMENT);
            mb_expect_cb0("mb_prec_seal_outer_nullblob_cap", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, NULL, 0u, out,
                80u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb_prec_seal_outer_nullblob_cap", "caller mutated");
            }
        }

        zmem(&bad_outer, sizeof(bad_outer));
        mb_pack_outer(
            "mb_prec_pack_outer_field0_cap", &bad_outer, 18u,
            NINLIL_R7_WIRE_STRUCTURAL);
        mb_tick();
        {
            /* Caller inputs: fields=NULL, out[13] capacity canary only. */
            uint8_t out[16];
            uint8_t canary[13];
            ninlil_r7_wire_status st;
            size_t i;

            (void)memset(out, 0xA5, sizeof(out));
            (void)memset(canary, 0xA5, sizeof(canary));
            st = ninlil_r7_wire_pack_e2e_single_aad(NULL, out, 13u);
            expect_status(
                "mb_prec_pack_e2e_nullfield_cap", st,
                NINLIL_R7_WIRE_INVALID_ARGUMENT);
            if (!mem_eq(out, canary, 13u)) {
                failf("mb_prec_pack_e2e_nullfield_cap", "out[0..12] mutated");
            }
            /* Bytes beyond declared capacity are not API output surface. */
            for (i = 13u; i < sizeof(out); i++) {
                if (out[i] != 0xA5u) {
                    failf("mb_prec_pack_e2e_nullfield_cap", "stack canary");
                    break;
                }
            }
        }
    }

    if (g_mb_cases != expected_cases) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL mb_cases got=%zu want=%zu\n",
            g_mb_cases, expected_cases);
        g_failures++;
    } else {
        fprintf(stderr,
            "nrw1_t1_wire_portable mandatory_boundaries part1 cases=%zu OK\n",
            g_mb_cases);
    }
}

/* ---- part 2 helpers / matrix ---- */
static size_t g_mb2_cases;

static void mb2_tick(void)
{
    g_mb2_cases++;
}

static void mb2_store_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static void mb2_store_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static void mb2_store_u64_be(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) & 0xffu);
    p[1] = (uint8_t)((v >> 48) & 0xffu);
    p[2] = (uint8_t)((v >> 40) & 0xffu);
    p[3] = (uint8_t)((v >> 32) & 0xffu);
    p[4] = (uint8_t)((v >> 24) & 0xffu);
    p[5] = (uint8_t)((v >> 16) & 0xffu);
    p[6] = (uint8_t)((v >> 8) & 0xffu);
    p[7] = (uint8_t)(v & 0xffu);
}

static void mb_parse_e2e(
    const char *name,
    const uint8_t *aad14,
    ninlil_r7_wire_status want)
{
    ninlil_r7_wire_e2e_single_fields outf;
    ninlil_r7_wire_e2e_single_fields before;
    uint8_t aad_copy[14];
    ninlil_r7_wire_status st;

    mb2_tick();
    (void)memcpy(aad_copy, aad14, 14u);
    (void)memset(&outf, 0xC3, sizeof(outf));
    before = outf;
    st = ninlil_r7_wire_parse_e2e_single_aad(aad14, 14u, &outf);
    expect_status(name, st, want);
    if (!mem_eq(aad_copy, aad14, 14u) || !mem_eq(&before, &outf, sizeof(outf))) {
        failf(name, "caller mutated");
    }
}

static void mb_parse_outer(
    const char *name,
    const uint8_t *aad19,
    ninlil_r7_wire_status want)
{
    ninlil_r7_wire_outer_data_fields outf;
    ninlil_r7_wire_outer_data_fields before;
    uint8_t aad_copy[19];
    ninlil_r7_wire_status st;

    mb2_tick();
    (void)memcpy(aad_copy, aad19, 19u);
    (void)memset(&outf, 0xC4, sizeof(outf));
    before = outf;
    st = ninlil_r7_wire_parse_outer_data_aad(aad19, 19u, &outf);
    expect_status(name, st, want);
    if (!mem_eq(aad_copy, aad19, 19u) || !mem_eq(&before, &outf, sizeof(outf))) {
        failf(name, "caller mutated");
    }
}

/*
 * Mandatory boundary matrix — part 2 (docs/32 §8 structural domains):
 * context/counter extremes, outer route closed-set mismatches, outer Seal
 * non-E2E / invalid visible E2E, open_outer post-auth structural, precedence.
 */
static void test_mandatory_boundaries_part2(
    rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_e2e_single_fields e2e;
    ninlil_r7_wire_outer_data_fields outer;
    uint8_t app[16], blob[46], frame[81];
    uint8_t key[16], iv[12], hkey[16], hiv[12];
    uint8_t aad14[14], aad19[19];
    size_t bl = 0u, fl = 0u;
    /*
     * (1) 4 extremes × 8 APIs = 32
     * (2) 6 invalid route tuples × 4 APIs (pack/parse/seal/open outer) = 24
     * (3) seal_outer non-E2E + profile/type/nibble + len30/221 = 6
     * (4) open_outer post-auth structural = 1 (callback 1)
     * (5) structural+wrong capacity precedence = 6
     */
    const size_t expected_cases = 32u + 24u + 6u + 1u + 6u;

    g_mb2_cases = 0u;
    fill_e2e(&e2e);
    fill_outer(&outer);
    fill_app(app, 16u, 0x50u);
    (void)memcpy(key, K16, 16u);
    (void)memcpy(iv, IV12, 12u);
    (void)memcpy(hkey, HK16, 16u);
    (void)memcpy(hiv, HIV12, 12u);
    reset_rec(rc);
    expect_status(
        "mb2_prep_e2e",
        ninlil_r7_wire_seal_e2e_single(
            p, key, iv, &e2e, app, 16u, blob, 46u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "mb2_prep_outer",
        ninlil_r7_wire_seal_outer_single(
            p, hkey, hiv, &outer, blob, bl, frame, 81u, &fl),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "mb2_prep_aad_e",
        ninlil_r7_wire_pack_e2e_single_aad(&e2e, aad14, 14u),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "mb2_prep_aad_o",
        ninlil_r7_wire_pack_outer_data_aad(&outer, aad19, 19u),
        NINLIL_R7_WIRE_OK);

    /* ---- (1) context 0/MAX, counter 0/MAX on all applicable APIs ---- */
    {
        struct {
            const char *tag;
            uint32_t ctx;
            uint64_t ctr;
        } extremes[] = {
            {"ctx0", 0u, 1u},
            {"ctxmax", UINT32_MAX, 1u},
            {"ctr0", 1u, 0u},
            {"ctrmax", 1u, UINT64_MAX},
        };
        size_t ei;

        for (ei = 0u; ei < 4u; ei++) {
            ninlil_r7_wire_e2e_single_fields fe;
            ninlil_r7_wire_outer_data_fields fo;
            uint8_t ae[14], ao[19], be[46], bf[81];
            char name[96];

            fill_e2e(&fe);
            fill_outer(&fo);
            fe.e2e_context_id = extremes[ei].ctx;
            fe.e2e_counter = extremes[ei].ctr;
            fo.hop_context_id = extremes[ei].ctx;
            fo.hop_counter = extremes[ei].ctr;

            (void)snprintf(
                name, sizeof(name), "mb2_pack_e2e_%s", extremes[ei].tag);
            {
                uint8_t out[14];
                ninlil_r7_wire_e2e_single_fields fcopy = fe;
                ninlil_r7_wire_status st;
                size_t i;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                st = ninlil_r7_wire_pack_e2e_single_aad(&fe, out, 14u);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                if (!mem_eq(&fcopy, &fe, sizeof(fe))) {
                    failf(name, "fields mutated");
                }
                for (i = 0u; i < 14u; i++) {
                    if (out[i] != 0xA5u) {
                        failf(name, "out mutated");
                        break;
                    }
                }
            }

            (void)memcpy(ae, aad14, 14u);
            mb2_store_u32_be(ae + 2, extremes[ei].ctx);
            mb2_store_u64_be(ae + 6, extremes[ei].ctr);
            (void)snprintf(
                name, sizeof(name), "mb2_parse_e2e_%s", extremes[ei].tag);
            mb_parse_e2e(name, ae, NINLIL_R7_WIRE_STRUCTURAL);

            (void)snprintf(
                name, sizeof(name), "mb2_pack_outer_%s", extremes[ei].tag);
            {
                uint8_t out[19];
                ninlil_r7_wire_outer_data_fields fcopy = fo;
                ninlil_r7_wire_status st;
                size_t i;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                st = ninlil_r7_wire_pack_outer_data_aad(&fo, out, 19u);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                if (!mem_eq(&fcopy, &fo, sizeof(fo))) {
                    failf(name, "fields mutated");
                }
                for (i = 0u; i < 19u; i++) {
                    if (out[i] != 0xA5u) {
                        failf(name, "out mutated");
                        break;
                    }
                }
            }

            (void)memcpy(ao, aad19, 19u);
            mb2_store_u32_be(ao + 3, extremes[ei].ctx);
            mb2_store_u64_be(ao + 7, extremes[ei].ctr);
            (void)snprintf(
                name, sizeof(name), "mb2_parse_outer_%s", extremes[ei].tag);
            mb_parse_outer(name, ao, NINLIL_R7_WIRE_STRUCTURAL);

            (void)snprintf(
                name, sizeof(name), "mb2_seal_e2e_%s", extremes[ei].tag);
            /* Use part2 tick via local path that also ticks g_mb2 */
            {
                uint8_t out[64];
                size_t ol = 0xBEEFu;
                snap_t before, after;
                ninlil_r7_wire_status st;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                snap_take_full(
                    &before, p, key, iv, &fe, NULL, NULL, NULL, app, 16u, out,
                    46u, &ol);
                reset_rec(rc);
                st = ninlil_r7_wire_seal_e2e_single(
                    p, key, iv, &fe, app, 16u, out, 46u, &ol);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                mb_expect_cb0(name, rc);
                snap_take_full(
                    &after, p, key, iv, &fe, NULL, NULL, NULL, app, 16u, out,
                    46u, &ol);
                if (!snap_eq_strict(&before, &after)) {
                    failf(name, "caller mutated");
                }
            }

            (void)memcpy(be, blob, bl);
            mb2_store_u32_be(be + 2, extremes[ei].ctx);
            mb2_store_u64_be(be + 6, extremes[ei].ctr);
            (void)snprintf(
                name, sizeof(name), "mb2_open_e2e_%s", extremes[ei].tag);
            {
                ninlil_r7_wire_e2e_single_fields eout;
                uint8_t out[16];
                size_t ol = 0xBEEFu;
                snap_t before, after;
                ninlil_r7_wire_status st;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                (void)memset(&eout, 0xC3, sizeof(eout));
                snap_take_full(
                    &before, p, key, iv, NULL, NULL, &eout, NULL, be, bl, out,
                    16u, &ol);
                reset_rec(rc);
                st = ninlil_r7_wire_open_e2e_single(
                    p, key, iv, be, bl, &eout, out, 16u, &ol);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                mb_expect_cb0(name, rc);
                snap_take_full(
                    &after, p, key, iv, NULL, NULL, &eout, NULL, be, bl, out,
                    16u, &ol);
                if (!snap_eq_strict(&before, &after)) {
                    failf(name, "caller mutated");
                }
            }

            (void)snprintf(
                name, sizeof(name), "mb2_seal_outer_%s", extremes[ei].tag);
            {
                uint8_t out[96];
                size_t ol = 0xBEEFu;
                snap_t before, after;
                ninlil_r7_wire_status st;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                snap_take_full(
                    &before, p, hkey, hiv, NULL, &fo, NULL, NULL, blob, bl, out,
                    81u, &ol);
                reset_rec(rc);
                st = ninlil_r7_wire_seal_outer_single(
                    p, hkey, hiv, &fo, blob, bl, out, 81u, &ol);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                mb_expect_cb0(name, rc);
                snap_take_full(
                    &after, p, hkey, hiv, NULL, &fo, NULL, NULL, blob, bl, out,
                    81u, &ol);
                if (!snap_eq_strict(&before, &after)) {
                    failf(name, "caller mutated");
                }
            }

            (void)memcpy(bf, frame, fl);
            mb2_store_u32_be(bf + 3, extremes[ei].ctx);
            mb2_store_u64_be(bf + 7, extremes[ei].ctr);
            (void)snprintf(
                name, sizeof(name), "mb2_open_outer_%s", extremes[ei].tag);
            {
                ninlil_r7_wire_outer_data_fields oout;
                uint8_t out[46];
                size_t ol = 0xBEEFu;
                snap_t before, after;
                ninlil_r7_wire_status st;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                (void)memset(&oout, 0xC4, sizeof(oout));
                snap_take_full(
                    &before, p, hkey, hiv, NULL, NULL, NULL, &oout, bf, fl, out,
                    46u, &ol);
                reset_rec(rc);
                st = ninlil_r7_wire_open_outer_single(
                    p, hkey, hiv, bf, fl, &oout, out, 46u, &ol);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                mb_expect_cb0(name, rc);
                snap_take_full(
                    &after, p, hkey, hiv, NULL, NULL, NULL, &oout, bf, fl, out,
                    46u, &ol);
                if (!snap_eq_strict(&before, &after)) {
                    failf(name, "caller mutated");
                }
            }
        }
    }

    /*
     * ---- (2) outer route tuple mismatches (docs/32 §3 closed set) ----
     * Valid only: (handle,gen,hop)=(0,0,0) terminal OR (nz,nz,1..255) relay.
     * All other combinations are STRUCTURAL. No max_hops/source/destination
     * semantics beyond that closed set (T1 does not know record.max_hops).
     */
    {
        struct {
            const char *tag;
            uint16_t handle;
            uint16_t gen;
            uint8_t hop;
        } bad_routes[] = {
            {"term_hop_nz", 0u, 0u, 1u},
            {"h_nz_g0_hop0", 1u, 0u, 0u},
            {"h0_g_nz_hop0", 0u, 1u, 0u},
            {"h_nz_g0_hop_nz", 1u, 0u, 1u},
            {"h0_g_nz_hop_nz", 0u, 1u, 1u},
            {"relay_hop0", 1u, 1u, 0u},
        };
        size_t ri;

        for (ri = 0u; ri < 6u; ri++) {
            ninlil_r7_wire_outer_data_fields fo;
            uint8_t ao[19], bf[81];
            char name[96];

            fill_outer(&fo);
            fo.route_handle = bad_routes[ri].handle;
            fo.route_generation = bad_routes[ri].gen;
            fo.hop_remaining = bad_routes[ri].hop;

            (void)snprintf(
                name, sizeof(name), "mb2_pack_outer_route_%s",
                bad_routes[ri].tag);
            {
                uint8_t out[19];
                ninlil_r7_wire_outer_data_fields fcopy = fo;
                ninlil_r7_wire_status st;
                size_t i;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                st = ninlil_r7_wire_pack_outer_data_aad(&fo, out, 19u);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                if (!mem_eq(&fcopy, &fo, sizeof(fo))) {
                    failf(name, "fields mutated");
                }
                for (i = 0u; i < 19u; i++) {
                    if (out[i] != 0xA5u) {
                        failf(name, "out mutated");
                        break;
                    }
                }
            }

            (void)memcpy(ao, aad19, 19u);
            ao[2] = bad_routes[ri].hop;
            mb2_store_u16_be(ao + 15, bad_routes[ri].handle);
            mb2_store_u16_be(ao + 17, bad_routes[ri].gen);
            (void)snprintf(
                name, sizeof(name), "mb2_parse_outer_route_%s",
                bad_routes[ri].tag);
            mb_parse_outer(name, ao, NINLIL_R7_WIRE_STRUCTURAL);

            (void)snprintf(
                name, sizeof(name), "mb2_seal_outer_route_%s",
                bad_routes[ri].tag);
            {
                uint8_t out[96];
                size_t ol = 0xBEEFu;
                snap_t before, after;
                ninlil_r7_wire_status st;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                snap_take_full(
                    &before, p, hkey, hiv, NULL, &fo, NULL, NULL, blob, bl, out,
                    81u, &ol);
                reset_rec(rc);
                st = ninlil_r7_wire_seal_outer_single(
                    p, hkey, hiv, &fo, blob, bl, out, 81u, &ol);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                mb_expect_cb0(name, rc);
                snap_take_full(
                    &after, p, hkey, hiv, NULL, &fo, NULL, NULL, blob, bl, out,
                    81u, &ol);
                if (!snap_eq_strict(&before, &after)) {
                    failf(name, "caller mutated");
                }
            }

            (void)memcpy(bf, frame, fl);
            bf[2] = bad_routes[ri].hop;
            mb2_store_u16_be(bf + 15, bad_routes[ri].handle);
            mb2_store_u16_be(bf + 17, bad_routes[ri].gen);
            (void)snprintf(
                name, sizeof(name), "mb2_open_outer_route_%s",
                bad_routes[ri].tag);
            {
                ninlil_r7_wire_outer_data_fields oout;
                uint8_t out[46];
                size_t ol = 0xBEEFu;
                snap_t before, after;
                ninlil_r7_wire_status st;

                mb2_tick();
                (void)memset(out, 0xA5, sizeof(out));
                (void)memset(&oout, 0xC4, sizeof(oout));
                snap_take_full(
                    &before, p, hkey, hiv, NULL, NULL, NULL, &oout, bf, fl, out,
                    46u, &ol);
                reset_rec(rc);
                st = ninlil_r7_wire_open_outer_single(
                    p, hkey, hiv, bf, fl, &oout, out, 46u, &ol);
                expect_status(name, st, NINLIL_R7_WIRE_STRUCTURAL);
                mb_expect_cb0(name, rc);
                snap_take_full(
                    &after, p, hkey, hiv, NULL, NULL, NULL, &oout, bf, fl, out,
                    46u, &ol);
                if (!snap_eq_strict(&before, &after)) {
                    failf(name, "caller mutated");
                }
            }
        }
    }

    /* ---- (3) outer Seal: length-valid non-E2E / invalid visible E2E ---- */
    {
        uint8_t junk[46];
        uint8_t vis[46];

        (void)memset(junk, 0x00, sizeof(junk));
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, junk, 46u, out,
                81u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, junk, 46u, out, 81u, &ol);
            expect_status(
                "mb2_seal_outer_non_e2e_zeros", st, NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_seal_outer_non_e2e_zeros", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, junk, 46u, out,
                81u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_seal_outer_non_e2e_zeros", "mut");
            }
        }

        (void)memcpy(vis, blob, bl);
        vis[0] ^= 0x01u; /* profile */
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, vis, bl, out,
                81u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, vis, bl, out, 81u, &ol);
            expect_status(
                "mb2_seal_outer_e2e_bad_profile", st,
                NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_seal_outer_e2e_bad_profile", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, vis, bl, out,
                81u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_seal_outer_e2e_bad_profile", "mut");
            }
        }

        (void)memcpy(vis, blob, bl);
        vis[1] = (uint8_t)(0x20u); /* type != SINGLE (1<<4) */
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, vis, bl, out,
                81u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, vis, bl, out, 81u, &ol);
            expect_status(
                "mb2_seal_outer_e2e_bad_type", st, NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_seal_outer_e2e_bad_type", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, vis, bl, out,
                81u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_seal_outer_e2e_bad_type", "mut");
            }
        }

        (void)memcpy(vis, blob, bl);
        vis[1] |= 0x01u; /* low nibble nonzero */
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, vis, bl, out,
                81u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, vis, bl, out, 81u, &ol);
            expect_status(
                "mb2_seal_outer_e2e_bad_nibble", st,
                NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_seal_outer_e2e_bad_nibble", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, vis, bl, out,
                81u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_seal_outer_e2e_bad_nibble", "mut");
            }
        }

        /* Length outside 31..220: production returns LENGTH_CLASS before structural. */
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;
            uint8_t shortb[30];

            mb2_tick();
            (void)memset(shortb, 0x11, sizeof(shortb));
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, shortb, 30u,
                out, 65u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, shortb, 30u, out, 65u, &ol);
            expect_status(
                "mb2_seal_outer_e2e_len30", st, NINLIL_R7_WIRE_LENGTH_CLASS);
            mb_expect_cb0("mb2_seal_outer_e2e_len30", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, shortb, 30u, out,
                65u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_seal_outer_e2e_len30", "mut");
            }
        }
        {
            uint8_t out[256];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;
            uint8_t longb[221];

            mb2_tick();
            (void)memset(longb, 0x11, sizeof(longb));
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, longb, 221u,
                out, 256u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, longb, 221u, out, 256u, &ol);
            expect_status(
                "mb2_seal_outer_e2e_len221", st, NINLIL_R7_WIRE_LENGTH_CLASS);
            mb_expect_cb0("mb2_seal_outer_e2e_len221", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, longb, 221u, out,
                256u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_seal_outer_e2e_len221", "mut");
            }
        }
    }

    /*
     * ---- (4) open_outer: AEAD callback 1 then post-auth E2E structural ----
     * Controlled provider forges invalid E2E plaintext after successful Open.
     */
    {
        ninlil_r7_wire_outer_data_fields oout;
        uint8_t out[46];
        size_t ol = 0xBEEFu;
        snap_t before, after;
        ninlil_r7_wire_status st;

        mb2_tick();
        (void)memset(out, 0xA5, sizeof(out));
        (void)memset(&oout, 0xC4, sizeof(oout));
        snap_take_full(
            &before, p, hkey, hiv, NULL, NULL, NULL, &oout, frame, fl, out, 46u,
            &ol);
        reset_rec(rc);
        rc->forge_invalid_e2e_pt = 1;
        st = ninlil_r7_wire_open_outer_single(
            p, hkey, hiv, frame, fl, &oout, out, 46u, &ol);
        expect_status(
            "mb2_open_outer_postauth_e2e_struct", st,
            NINLIL_R7_WIRE_STRUCTURAL);
        if (rc->open_calls != 1u || rc->seal_calls != 0u) {
            failf("mb2_open_outer_postauth_e2e_struct", "callback");
        }
        snap_take_full(
            &after, p, hkey, hiv, NULL, NULL, NULL, &oout, frame, fl, out, 46u,
            &ol);
        if (!snap_eq_strict(&before, &after)) {
            failf("mb2_open_outer_postauth_e2e_struct", "mut");
        }
        rc->forge_invalid_e2e_pt = 0;
    }

    /* ---- (5) structural invalid + wrong capacity → STRUCTURAL, cb0 ---- */
    {
        ninlil_r7_wire_e2e_single_fields fe;
        ninlil_r7_wire_outer_data_fields fo;
        uint8_t be[46], bf[81], junk[46];

        fill_e2e(&fe);
        fe.e2e_context_id = 0u;
        {
            uint8_t out[64];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, key, iv, &fe, NULL, NULL, NULL, app, 16u, out, 45u,
                &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_e2e_single(
                p, key, iv, &fe, app, 16u, out, 45u, &ol);
            expect_status(
                "mb2_prec_seal_e2e_ctx0_cap", st, NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_prec_seal_e2e_ctx0_cap", rc);
            snap_take_full(
                &after, p, key, iv, &fe, NULL, NULL, NULL, app, 16u, out, 45u,
                &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_prec_seal_e2e_ctx0_cap", "mut");
            }
        }

        fill_outer(&fo);
        fo.route_handle = 1u;
        fo.route_generation = 0u;
        fo.hop_remaining = 0u;
        {
            uint8_t out[19];
            ninlil_r7_wire_outer_data_fields fcopy = fo;
            ninlil_r7_wire_status st;
            size_t i;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            st = ninlil_r7_wire_pack_outer_data_aad(&fo, out, 18u);
            expect_status(
                "mb2_prec_pack_outer_route_cap", st, NINLIL_R7_WIRE_STRUCTURAL);
            if (!mem_eq(&fcopy, &fo, sizeof(fo))) {
                failf("mb2_prec_pack_outer_route_cap", "fields");
            }
            for (i = 0u; i < 18u; i++) {
                if (out[i] != 0xA5u) {
                    failf("mb2_prec_pack_outer_route_cap", "out");
                    break;
                }
            }
        }

        (void)memcpy(be, blob, bl);
        be[0] ^= 0x01u;
        {
            ninlil_r7_wire_e2e_single_fields eout;
            uint8_t out[16];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            (void)memset(&eout, 0xC3, sizeof(eout));
            snap_take_full(
                &before, p, key, iv, NULL, NULL, &eout, NULL, be, bl, out, 15u,
                &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_open_e2e_single(
                p, key, iv, be, bl, &eout, out, 15u, &ol);
            expect_status(
                "mb2_prec_open_e2e_struct_cap", st, NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_prec_open_e2e_struct_cap", rc);
            snap_take_full(
                &after, p, key, iv, NULL, NULL, &eout, NULL, be, bl, out, 15u,
                &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_prec_open_e2e_struct_cap", "mut");
            }
        }

        (void)memcpy(bf, frame, fl);
        bf[2] = 1u; /* hop_remaining=1 with route 0,0 → structural */
        {
            ninlil_r7_wire_outer_data_fields oout;
            uint8_t out[46];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            (void)memset(&oout, 0xC4, sizeof(oout));
            snap_take_full(
                &before, p, hkey, hiv, NULL, NULL, NULL, &oout, bf, fl, out,
                45u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_open_outer_single(
                p, hkey, hiv, bf, fl, &oout, out, 45u, &ol);
            expect_status(
                "mb2_prec_open_outer_route_cap", st,
                NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_prec_open_outer_route_cap", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, NULL, NULL, &oout, bf, fl, out, 45u,
                &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_prec_open_outer_route_cap", "mut");
            }
        }

        (void)memset(junk, 0x00, sizeof(junk));
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &outer, NULL, NULL, junk, 46u, out,
                80u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &outer, junk, 46u, out, 80u, &ol);
            expect_status(
                "mb2_prec_seal_outer_non_e2e_cap", st,
                NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_prec_seal_outer_non_e2e_cap", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &outer, NULL, NULL, junk, 46u, out,
                80u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_prec_seal_outer_non_e2e_cap", "mut");
            }
        }

        fill_outer(&fo);
        fo.hop_counter = 0u;
        {
            uint8_t out[96];
            size_t ol = 0xBEEFu;
            snap_t before, after;
            ninlil_r7_wire_status st;

            mb2_tick();
            (void)memset(out, 0xA5, sizeof(out));
            snap_take_full(
                &before, p, hkey, hiv, NULL, &fo, NULL, NULL, blob, bl, out,
                80u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_seal_outer_single(
                p, hkey, hiv, &fo, blob, bl, out, 80u, &ol);
            expect_status(
                "mb2_prec_seal_outer_ctr0_cap", st, NINLIL_R7_WIRE_STRUCTURAL);
            mb_expect_cb0("mb2_prec_seal_outer_ctr0_cap", rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, &fo, NULL, NULL, blob, bl, out, 80u,
                &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf("mb2_prec_seal_outer_ctr0_cap", "mut");
            }
        }
    }

    if (g_mb2_cases != expected_cases) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL mb2_cases got=%zu want=%zu\n",
            g_mb2_cases, expected_cases);
        g_failures++;
    } else {
        fprintf(stderr,
            "nrw1_t1_wire_portable mandatory_boundaries part2 cases=%zu OK\n",
            g_mb2_cases);
    }
}

/*
 * AAD pack/parse alias matrix (docs/32 §6 / §8): input span ↔ output span.
 * 4 APIs × 5 layouts = 20 cases.
 *
 * Typed-host design (portable C): struct fields live only as named members
 * (&host.fields). Every AAD character view starts at the enclosing host and
 * uses offsetof(..., fields); no pointer arithmetic escapes a member
 * subobject, and no byte array is cast to a struct type.
 */
static size_t g_aad_alias_cases;

/* e2e fields (16) with room for AAD (14) before/inside/after */
typedef struct {
    uint8_t prefix[32];
    ninlil_r7_wire_e2e_single_fields fields;
    uint8_t suffix[64];
} aad_host_e2e;

/* outer fields (24) with room for AAD (19) before/inside/after */
typedef struct {
    uint8_t prefix[32];
    ninlil_r7_wire_outer_data_fields fields;
    uint8_t suffix[64];
} aad_host_outer;

static void aad_alias_tick(void)
{
    g_aad_alias_cases++;
}

static void aad_alias_assert_align(
    const char *name, const void *p, size_t align)
{
    if (p == NULL || align == 0u
        || ((uintptr_t)p % (uintptr_t)align) != 0u) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s misaligned ptr=%p align=%zu\n",
            name, p, align);
        g_failures++;
    }
}

typedef enum {
    AAD_ALIAS_EXACT_START = 0,
    AAD_ALIAS_PARTIAL = 1,
    AAD_ALIAS_ADJACENT = 2
} aad_alias_layout;

static uint8_t *aad_alias_host_view(
    const char *name,
    void *host,
    size_t host_size,
    size_t field_off,
    size_t field_len,
    size_t aad_off,
    size_t aad_len,
    aad_alias_layout layout)
{
    size_t field_end;
    size_t aad_end;
    int valid;

    if (host == NULL || field_off > host_size
        || field_len > host_size - field_off || aad_off > host_size
        || aad_len > host_size - aad_off) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s host span OOB "
            "host=%zu field=%zu+%zu aad=%zu+%zu\n",
            name, host_size, field_off, field_len, aad_off, aad_len);
        g_failures++;
        return (uint8_t *)host;
    }

    field_end = field_off + field_len;
    aad_end = aad_off + aad_len;
    if (layout == AAD_ALIAS_EXACT_START) {
        valid = field_off == aad_off;
    } else if (layout == AAD_ALIAS_PARTIAL) {
        valid = field_off < aad_end && aad_off < field_end
            && field_off != aad_off;
    } else {
        valid = field_end == aad_off || aad_end == field_off;
    }
    if (!valid) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s layout=%d "
            "field=%zu+%zu aad=%zu+%zu\n",
            name, (int)layout, field_off, field_len, aad_off, aad_len);
        g_failures++;
    }
    return (uint8_t *)host + aad_off;
}

static void test_aad_alias_matrix(void)
{
    ninlil_r7_wire_e2e_single_fields e2e_gold;
    ninlil_r7_wire_outer_data_fields outer_gold;
    uint8_t aad14_base[14];
    uint8_t aad19_base[19];
    const size_t expected = 20u;
    const size_t e2e_align = _Alignof(ninlil_r7_wire_e2e_single_fields);
    const size_t outer_align = _Alignof(ninlil_r7_wire_outer_data_fields);

    g_aad_alias_cases = 0u;
    fill_e2e(&e2e_gold);
    fill_outer(&outer_gold);
    expect_status(
        "aad_alias_prep_e",
        ninlil_r7_wire_pack_e2e_single_aad(&e2e_gold, aad14_base, 14u),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "aad_alias_prep_o",
        ninlil_r7_wire_pack_outer_data_aad(&outer_gold, aad19_base, 19u),
        NINLIL_R7_WIRE_OK);

    /* ========== pack_e2e: fields ↔ AAD14 ========== */
    {
        /* (a) exact: AAD view is object representation of fields */
        {
            aad_host_e2e host;
            aad_host_e2e snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_e2e(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_e2e_exact", &host.fields, e2e_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_e2e_exact", &host, sizeof(host),
                offsetof(aad_host_e2e, fields), sizeof(host.fields),
                offsetof(aad_host_e2e, fields), 14u,
                AAD_ALIAS_EXACT_START);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_pack_e2e_single_aad(&host.fields, aad, 14u);
            expect_status("aad_alias_pack_e2e_exact", st, NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_pack_e2e_exact", "host mutated");
            }
        }
        /* (b1) partial: AAD starts inside fields (+2) */
        {
            aad_host_e2e host;
            aad_host_e2e snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_e2e(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_e2e_partial_out_in_field", &host.fields,
                e2e_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_e2e_partial_out_in_field", &host,
                sizeof(host), offsetof(aad_host_e2e, fields),
                sizeof(host.fields), offsetof(aad_host_e2e, fields) + 2u,
                14u, AAD_ALIAS_PARTIAL);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_pack_e2e_single_aad(&host.fields, aad, 14u);
            expect_status(
                "aad_alias_pack_e2e_partial_out_in_field", st,
                NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_pack_e2e_partial_out_in_field", "host mut");
            }
        }
        /* (b2) partial: fields starts inside AAD (AAD in prefix ending into fields) */
        {
            aad_host_e2e host;
            aad_host_e2e snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_e2e(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_e2e_partial_field_in_out", &host.fields,
                e2e_align);
            /* AAD starts 8 bytes before fields → overlaps first 6 of fields */
            aad = aad_alias_host_view(
                "aad_alias_pack_e2e_partial_field_in_out", &host,
                sizeof(host), offsetof(aad_host_e2e, fields),
                sizeof(host.fields), offsetof(aad_host_e2e, fields) - 8u,
                14u, AAD_ALIAS_PARTIAL);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_pack_e2e_single_aad(&host.fields, aad, 14u);
            expect_status(
                "aad_alias_pack_e2e_partial_field_in_out", st,
                NINLIL_R7_WIRE_ALIAS);
            /* Full host: field + output-only prefix covered by AAD start */
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_pack_e2e_partial_field_in_out", "host mut");
            }
        }
        /* (c1) adj field then AAD: end(fields)==begin(aad) */
        {
            aad_host_e2e host;
            ninlil_r7_wire_e2e_single_fields f_before;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_e2e(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_e2e_adj_field_aad", &host.fields, e2e_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_e2e_adj_field_aad", &host, sizeof(host),
                offsetof(aad_host_e2e, fields), sizeof(host.fields),
                offsetof(aad_host_e2e, fields) + sizeof(host.fields), 14u,
                AAD_ALIAS_ADJACENT);
            f_before = host.fields;
            (void)memset(aad, 0xA5, 14u);
            st = ninlil_r7_wire_pack_e2e_single_aad(&host.fields, aad, 14u);
            expect_status(
                "aad_alias_pack_e2e_adj_field_aad", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(&f_before, &host.fields, sizeof(f_before))) {
                failf("aad_alias_pack_e2e_adj_field_aad", "input mut");
            }
            if (!mem_eq(aad, aad14_base, 14u)) {
                failf("aad_alias_pack_e2e_adj_field_aad", "out != baseline");
            }
        }
        /* (c2) adj AAD then field: AAD immediately before &fields */
        {
            aad_host_e2e host;
            ninlil_r7_wire_e2e_single_fields f_before;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_e2e(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_e2e_adj_aad_field", &host.fields, e2e_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_e2e_adj_aad_field", &host, sizeof(host),
                offsetof(aad_host_e2e, fields), sizeof(host.fields),
                offsetof(aad_host_e2e, fields) - 14u, 14u,
                AAD_ALIAS_ADJACENT);
            f_before = host.fields;
            (void)memset(aad, 0xA5, 14u);
            st = ninlil_r7_wire_pack_e2e_single_aad(&host.fields, aad, 14u);
            expect_status(
                "aad_alias_pack_e2e_adj_aad_field", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(&f_before, &host.fields, sizeof(f_before))) {
                failf("aad_alias_pack_e2e_adj_aad_field", "input mut");
            }
            if (!mem_eq(aad, aad14_base, 14u)) {
                failf("aad_alias_pack_e2e_adj_aad_field", "out != baseline");
            }
        }
    }

    /* ========== pack_outer: fields ↔ AAD19 ========== */
    {
        {
            aad_host_outer host;
            aad_host_outer snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_outer(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_outer_exact", &host.fields, outer_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_outer_exact", &host, sizeof(host),
                offsetof(aad_host_outer, fields), sizeof(host.fields),
                offsetof(aad_host_outer, fields), 19u,
                AAD_ALIAS_EXACT_START);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_pack_outer_data_aad(&host.fields, aad, 19u);
            expect_status(
                "aad_alias_pack_outer_exact", st, NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_pack_outer_exact", "host mutated");
            }
        }
        {
            aad_host_outer host;
            aad_host_outer snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_outer(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_outer_partial_out_in_field", &host.fields,
                outer_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_outer_partial_out_in_field", &host,
                sizeof(host), offsetof(aad_host_outer, fields),
                sizeof(host.fields), offsetof(aad_host_outer, fields) + 4u,
                19u, AAD_ALIAS_PARTIAL);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_pack_outer_data_aad(&host.fields, aad, 19u);
            expect_status(
                "aad_alias_pack_outer_partial_out_in_field", st,
                NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_pack_outer_partial_out_in_field", "host mut");
            }
        }
        {
            aad_host_outer host;
            aad_host_outer snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_outer(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_outer_partial_field_in_out", &host.fields,
                outer_align);
            /* AAD overlaps the prefix and the first 11 field bytes. */
            aad = aad_alias_host_view(
                "aad_alias_pack_outer_partial_field_in_out", &host,
                sizeof(host), offsetof(aad_host_outer, fields),
                sizeof(host.fields), offsetof(aad_host_outer, fields) - 8u,
                19u, AAD_ALIAS_PARTIAL);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_pack_outer_data_aad(&host.fields, aad, 19u);
            expect_status(
                "aad_alias_pack_outer_partial_field_in_out", st,
                NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_pack_outer_partial_field_in_out", "host mut");
            }
        }
        {
            aad_host_outer host;
            ninlil_r7_wire_outer_data_fields f_before;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_outer(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_outer_adj_field_aad", &host.fields, outer_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_outer_adj_field_aad", &host, sizeof(host),
                offsetof(aad_host_outer, fields), sizeof(host.fields),
                offsetof(aad_host_outer, fields) + sizeof(host.fields), 19u,
                AAD_ALIAS_ADJACENT);
            f_before = host.fields;
            (void)memset(aad, 0xA5, 19u);
            st = ninlil_r7_wire_pack_outer_data_aad(&host.fields, aad, 19u);
            expect_status(
                "aad_alias_pack_outer_adj_field_aad", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(&f_before, &host.fields, sizeof(f_before))) {
                failf("aad_alias_pack_outer_adj_field_aad", "input mut");
            }
            if (!mem_eq(aad, aad19_base, 19u)) {
                failf("aad_alias_pack_outer_adj_field_aad", "out != baseline");
            }
        }
        {
            aad_host_outer host;
            ninlil_r7_wire_outer_data_fields f_before;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            fill_outer(&host.fields);
            aad_alias_assert_align(
                "aad_alias_pack_outer_adj_aad_field", &host.fields, outer_align);
            aad = aad_alias_host_view(
                "aad_alias_pack_outer_adj_aad_field", &host, sizeof(host),
                offsetof(aad_host_outer, fields), sizeof(host.fields),
                offsetof(aad_host_outer, fields) - 19u, 19u,
                AAD_ALIAS_ADJACENT);
            f_before = host.fields;
            (void)memset(aad, 0xA5, 19u);
            st = ninlil_r7_wire_pack_outer_data_aad(&host.fields, aad, 19u);
            expect_status(
                "aad_alias_pack_outer_adj_aad_field", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(&f_before, &host.fields, sizeof(f_before))) {
                failf("aad_alias_pack_outer_adj_aad_field", "input mut");
            }
            if (!mem_eq(aad, aad19_base, 19u)) {
                failf("aad_alias_pack_outer_adj_aad_field", "out != baseline");
            }
        }
    }

    /* ========== parse_e2e: AAD14 ↔ decoded fields ========== */
    {
        /* (a) exact: AAD and out share object representation of fields */
        {
            aad_host_e2e host;
            aad_host_e2e snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad = aad_alias_host_view(
                "aad_alias_parse_e2e_exact", &host, sizeof(host),
                offsetof(aad_host_e2e, fields), sizeof(host.fields),
                offsetof(aad_host_e2e, fields), 14u,
                AAD_ALIAS_EXACT_START);
            (void)memcpy(aad, aad14_base, 14u);
            aad_alias_assert_align(
                "aad_alias_parse_e2e_exact", &host.fields, e2e_align);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_parse_e2e_single_aad(aad, 14u, &host.fields);
            expect_status(
                "aad_alias_parse_e2e_exact", st, NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_parse_e2e_exact", "host mutated");
            }
        }
        /* (b1) partial: out fields starts inside AAD (AAD in prefix→fields) */
        {
            aad_host_e2e host;
            aad_host_e2e snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad = aad_alias_host_view(
                "aad_alias_parse_e2e_partial_field_in_aad", &host,
                sizeof(host), offsetof(aad_host_e2e, fields),
                sizeof(host.fields), offsetof(aad_host_e2e, fields) - 8u,
                14u, AAD_ALIAS_PARTIAL);
            (void)memset(&host.fields, 0xC3, sizeof(host.fields));
            (void)memcpy(aad, aad14_base, 14u);
            aad_alias_assert_align(
                "aad_alias_parse_e2e_partial_field_in_aad", &host.fields,
                e2e_align);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_parse_e2e_single_aad(aad, 14u, &host.fields);
            expect_status(
                "aad_alias_parse_e2e_partial_field_in_aad", st,
                NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_parse_e2e_partial_field_in_aad", "host mut");
            }
        }
        /* (b2) partial: AAD starts inside fields */
        {
            aad_host_e2e host;
            aad_host_e2e snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            (void)memset(&host.fields, 0xC3, sizeof(host.fields));
            aad = aad_alias_host_view(
                "aad_alias_parse_e2e_partial_aad_in_field", &host,
                sizeof(host), offsetof(aad_host_e2e, fields),
                sizeof(host.fields), offsetof(aad_host_e2e, fields) + 4u,
                14u, AAD_ALIAS_PARTIAL);
            (void)memcpy(aad, aad14_base, 14u);
            aad_alias_assert_align(
                "aad_alias_parse_e2e_partial_aad_in_field", &host.fields,
                e2e_align);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_parse_e2e_single_aad(aad, 14u, &host.fields);
            expect_status(
                "aad_alias_parse_e2e_partial_aad_in_field", st,
                NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_parse_e2e_partial_aad_in_field", "host mut");
            }
        }
        /* (c1) adj AAD then field */
        {
            aad_host_e2e host;
            ninlil_r7_wire_status st;
            uint8_t *aad;
            uint8_t aad_before[14];

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad_alias_assert_align(
                "aad_alias_parse_e2e_adj_aad_field", &host.fields, e2e_align);
            aad = aad_alias_host_view(
                "aad_alias_parse_e2e_adj_aad_field", &host, sizeof(host),
                offsetof(aad_host_e2e, fields), sizeof(host.fields),
                offsetof(aad_host_e2e, fields) - 14u, 14u,
                AAD_ALIAS_ADJACENT);
            (void)memcpy(aad, aad14_base, 14u);
            (void)memcpy(aad_before, aad14_base, 14u);
            (void)memset(&host.fields, 0xC3, sizeof(host.fields));
            st = ninlil_r7_wire_parse_e2e_single_aad(aad, 14u, &host.fields);
            expect_status(
                "aad_alias_parse_e2e_adj_aad_field", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(aad_before, aad, 14u)) {
                failf("aad_alias_parse_e2e_adj_aad_field", "input mut");
            }
            if (!mem_eq(&host.fields, &e2e_gold, sizeof(e2e_gold))) {
                failf("aad_alias_parse_e2e_adj_aad_field", "decoded != gold");
            }
        }
        /* (c2) adj field then AAD */
        {
            aad_host_e2e host;
            ninlil_r7_wire_status st;
            uint8_t *aad;
            uint8_t aad_before[14];

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad_alias_assert_align(
                "aad_alias_parse_e2e_adj_field_aad", &host.fields, e2e_align);
            aad = aad_alias_host_view(
                "aad_alias_parse_e2e_adj_field_aad", &host, sizeof(host),
                offsetof(aad_host_e2e, fields), sizeof(host.fields),
                offsetof(aad_host_e2e, fields) + sizeof(host.fields), 14u,
                AAD_ALIAS_ADJACENT);
            (void)memcpy(aad, aad14_base, 14u);
            (void)memcpy(aad_before, aad14_base, 14u);
            (void)memset(&host.fields, 0xC3, sizeof(host.fields));
            st = ninlil_r7_wire_parse_e2e_single_aad(aad, 14u, &host.fields);
            expect_status(
                "aad_alias_parse_e2e_adj_field_aad", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(aad_before, aad, 14u)) {
                failf("aad_alias_parse_e2e_adj_field_aad", "input mut");
            }
            if (!mem_eq(&host.fields, &e2e_gold, sizeof(e2e_gold))) {
                failf("aad_alias_parse_e2e_adj_field_aad", "decoded != gold");
            }
        }
    }

    /* ========== parse_outer: AAD19 ↔ decoded fields ========== */
    {
        {
            aad_host_outer host;
            aad_host_outer snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad = aad_alias_host_view(
                "aad_alias_parse_outer_exact", &host, sizeof(host),
                offsetof(aad_host_outer, fields), sizeof(host.fields),
                offsetof(aad_host_outer, fields), 19u,
                AAD_ALIAS_EXACT_START);
            (void)memcpy(aad, aad19_base, 19u);
            aad_alias_assert_align(
                "aad_alias_parse_outer_exact", &host.fields, outer_align);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_parse_outer_data_aad(aad, 19u, &host.fields);
            expect_status(
                "aad_alias_parse_outer_exact", st, NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_parse_outer_exact", "host mutated");
            }
        }
        {
            aad_host_outer host;
            aad_host_outer snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad = aad_alias_host_view(
                "aad_alias_parse_outer_partial_field_in_aad", &host,
                sizeof(host), offsetof(aad_host_outer, fields),
                sizeof(host.fields), offsetof(aad_host_outer, fields) - 8u,
                19u, AAD_ALIAS_PARTIAL);
            (void)memset(&host.fields, 0xC4, sizeof(host.fields));
            (void)memcpy(aad, aad19_base, 19u);
            aad_alias_assert_align(
                "aad_alias_parse_outer_partial_field_in_aad", &host.fields,
                outer_align);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_parse_outer_data_aad(aad, 19u, &host.fields);
            expect_status(
                "aad_alias_parse_outer_partial_field_in_aad", st,
                NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_parse_outer_partial_field_in_aad", "host mut");
            }
        }
        {
            aad_host_outer host;
            aad_host_outer snap;
            ninlil_r7_wire_status st;
            uint8_t *aad;

            aad_alias_tick();
            zmem(&host, sizeof(host));
            (void)memset(&host.fields, 0xC4, sizeof(host.fields));
            aad = aad_alias_host_view(
                "aad_alias_parse_outer_partial_aad_in_field", &host,
                sizeof(host), offsetof(aad_host_outer, fields),
                sizeof(host.fields), offsetof(aad_host_outer, fields) + 8u,
                19u, AAD_ALIAS_PARTIAL);
            (void)memcpy(aad, aad19_base, 19u);
            aad_alias_assert_align(
                "aad_alias_parse_outer_partial_aad_in_field", &host.fields,
                outer_align);
            (void)memcpy(&snap, &host, sizeof(host));
            st = ninlil_r7_wire_parse_outer_data_aad(aad, 19u, &host.fields);
            expect_status(
                "aad_alias_parse_outer_partial_aad_in_field", st,
                NINLIL_R7_WIRE_ALIAS);
            if (!mem_eq(&snap, &host, sizeof(host))) {
                failf("aad_alias_parse_outer_partial_aad_in_field", "host mut");
            }
        }
        {
            aad_host_outer host;
            ninlil_r7_wire_status st;
            uint8_t *aad;
            uint8_t aad_before[19];

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad_alias_assert_align(
                "aad_alias_parse_outer_adj_aad_field", &host.fields, outer_align);
            aad = aad_alias_host_view(
                "aad_alias_parse_outer_adj_aad_field", &host, sizeof(host),
                offsetof(aad_host_outer, fields), sizeof(host.fields),
                offsetof(aad_host_outer, fields) - 19u, 19u,
                AAD_ALIAS_ADJACENT);
            (void)memcpy(aad, aad19_base, 19u);
            (void)memcpy(aad_before, aad19_base, 19u);
            (void)memset(&host.fields, 0xC4, sizeof(host.fields));
            st = ninlil_r7_wire_parse_outer_data_aad(aad, 19u, &host.fields);
            expect_status(
                "aad_alias_parse_outer_adj_aad_field", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(aad_before, aad, 19u)) {
                failf("aad_alias_parse_outer_adj_aad_field", "input mut");
            }
            if (!mem_eq(&host.fields, &outer_gold, sizeof(outer_gold))) {
                failf("aad_alias_parse_outer_adj_aad_field", "decoded");
            }
        }
        {
            aad_host_outer host;
            ninlil_r7_wire_status st;
            uint8_t *aad;
            uint8_t aad_before[19];

            aad_alias_tick();
            zmem(&host, sizeof(host));
            aad_alias_assert_align(
                "aad_alias_parse_outer_adj_field_aad", &host.fields, outer_align);
            aad = aad_alias_host_view(
                "aad_alias_parse_outer_adj_field_aad", &host, sizeof(host),
                offsetof(aad_host_outer, fields), sizeof(host.fields),
                offsetof(aad_host_outer, fields) + sizeof(host.fields), 19u,
                AAD_ALIAS_ADJACENT);
            (void)memcpy(aad, aad19_base, 19u);
            (void)memcpy(aad_before, aad19_base, 19u);
            (void)memset(&host.fields, 0xC4, sizeof(host.fields));
            st = ninlil_r7_wire_parse_outer_data_aad(aad, 19u, &host.fields);
            expect_status(
                "aad_alias_parse_outer_adj_field_aad", st, NINLIL_R7_WIRE_OK);
            if (!mem_eq(aad_before, aad, 19u)) {
                failf("aad_alias_parse_outer_adj_field_aad", "input mut");
            }
            if (!mem_eq(&host.fields, &outer_gold, sizeof(outer_gold))) {
                failf("aad_alias_parse_outer_adj_field_aad", "decoded");
            }
        }
    }

    if (g_aad_alias_cases != expected) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL aad_alias_cases got=%zu want=%zu\n",
            g_aad_alias_cases, expected);
        g_failures++;
    } else {
        fprintf(stderr,
            "nrw1_t1_wire_portable aad_alias_matrix cases=%zu OK\n",
            g_aad_alias_cases);
    }
}

/*
 * AAD NULL / length-class / header structural matrix (docs/32 §5.2 / §5.5 / §8).
 *
 * (A) pack/parse outer/e2e required NULL × 8 → INVALID_ARGUMENT + canaries
 * (B) parse outer len 18/20, e2e len 13/15 × 4 → LENGTH_CLASS + mutation-zero
 * (C) header structural parse/open × 12 + outer pack/seal ack=2 × 2 → 14
 * Total exact 26. No crypto on (A)/(B); open/seal structural callback 0.
 */
static size_t g_nls_cases;

static void nls_tick(void)
{
    g_nls_cases++;
}

static void nls_expect_cb0(const char *name, rec_ctx *rc)
{
    if (rc->seal_calls != 0u || rc->open_calls != 0u) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL %s callback seal=%zu open=%zu want=0\n",
            name, rc->seal_calls, rc->open_calls);
        g_failures++;
    }
}

static void test_aad_null_length_structural(
    rec_ctx *rc, ninlil_r7_crypto_provider *p)
{
    ninlil_r7_wire_outer_data_fields outer, oout, outer_snap;
    ninlil_r7_wire_e2e_single_fields e2e, eout, e2e_snap;
    uint8_t aad19[19], aad14[14], out19[19], out14[14];
    uint8_t canary19[19], canary14[14];
    uint8_t in18[18], in20[20], in13[13], in15[15];
    uint8_t in18_s[18], in20_s[20], in13_s[13], in15_s[15];
    uint8_t app[16], blob[46], frame[81];
    uint8_t key[16], iv[12], hkey[16], hiv[12];
    uint8_t out[256];
    size_t bl = 0u, fl = 0u, ol = 0u;
    snap_t before, after;
    ninlil_r7_wire_status st;
    const size_t expected = 8u + 4u + 14u;

    g_nls_cases = 0u;
    fill_outer(&outer);
    fill_e2e(&e2e);
    fill_app(app, 16u, 0x60u);
    (void)memcpy(key, K16, 16u);
    (void)memcpy(iv, IV12, 12u);
    (void)memcpy(hkey, HK16, 16u);
    (void)memcpy(hiv, HIV12, 12u);
    (void)memset(canary19, 0xA5, sizeof(canary19));
    (void)memset(canary14, 0xA5, sizeof(canary14));

    /* ---- (A) required NULL × 8 → INVALID_ARGUMENT ---- */

    /* pack outer fields NULL: full capacity canary */
    nls_tick();
    (void)memcpy(out19, canary19, 19u);
    st = ninlil_r7_wire_pack_outer_data_aad(NULL, out19, 19u);
    expect_status("nls_pack_o_fields_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(out19, canary19, 19u)) {
        failf("nls_pack_o_fields_null", "out capacity canary");
    }

    /* pack outer out NULL: field input unchanged */
    nls_tick();
    outer_snap = outer;
    st = ninlil_r7_wire_pack_outer_data_aad(&outer, NULL, 19u);
    expect_status("nls_pack_o_out_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(&outer, &outer_snap, sizeof(outer))) {
        failf("nls_pack_o_out_null", "fields mutated");
    }

    /* parse outer input NULL: decoded field full canary */
    nls_tick();
    (void)memset(&oout, 0xC4, sizeof(oout));
    outer_snap = oout;
    st = ninlil_r7_wire_parse_outer_data_aad(NULL, 19u, &oout);
    expect_status("nls_parse_o_in_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(&oout, &outer_snap, sizeof(oout))) {
        failf("nls_parse_o_in_null", "decoded canary");
    }

    /* parse outer out_fields NULL: input full unchanged */
    nls_tick();
    fill_app(aad19, 19u, 0x71u);
    (void)memcpy(canary19, aad19, 19u);
    st = ninlil_r7_wire_parse_outer_data_aad(aad19, 19u, NULL);
    expect_status("nls_parse_o_out_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(aad19, canary19, 19u)) {
        failf("nls_parse_o_out_null", "input mutated");
    }

    /* pack e2e fields NULL: full capacity canary */
    nls_tick();
    (void)memset(canary14, 0xA5, sizeof(canary14));
    (void)memcpy(out14, canary14, 14u);
    st = ninlil_r7_wire_pack_e2e_single_aad(NULL, out14, 14u);
    expect_status("nls_pack_e_fields_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(out14, canary14, 14u)) {
        failf("nls_pack_e_fields_null", "out capacity canary");
    }

    /* pack e2e out NULL: field input unchanged */
    nls_tick();
    e2e_snap = e2e;
    st = ninlil_r7_wire_pack_e2e_single_aad(&e2e, NULL, 14u);
    expect_status("nls_pack_e_out_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(&e2e, &e2e_snap, sizeof(e2e))) {
        failf("nls_pack_e_out_null", "fields mutated");
    }

    /* parse e2e input NULL: decoded field full canary */
    nls_tick();
    (void)memset(&eout, 0xC3, sizeof(eout));
    e2e_snap = eout;
    st = ninlil_r7_wire_parse_e2e_single_aad(NULL, 14u, &eout);
    expect_status("nls_parse_e_in_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(&eout, &e2e_snap, sizeof(eout))) {
        failf("nls_parse_e_in_null", "decoded canary");
    }

    /* parse e2e out_fields NULL: input full unchanged */
    nls_tick();
    fill_app(aad14, 14u, 0x72u);
    (void)memcpy(canary14, aad14, 14u);
    st = ninlil_r7_wire_parse_e2e_single_aad(aad14, 14u, NULL);
    expect_status("nls_parse_e_out_null", st, NINLIL_R7_WIRE_INVALID_ARGUMENT);
    if (!mem_eq(aad14, canary14, 14u)) {
        failf("nls_parse_e_out_null", "input mutated");
    }

    /* ---- (B) parse length class × 4, actual allocated buffers ---- */

    nls_tick();
    fill_app(in18, 18u, 0x81u);
    (void)memcpy(in18_s, in18, 18u);
    (void)memset(&oout, 0xC4, sizeof(oout));
    outer_snap = oout;
    st = ninlil_r7_wire_parse_outer_data_aad(in18, 18u, &oout);
    expect_status("nls_parse_o_len18", st, NINLIL_R7_WIRE_LENGTH_CLASS);
    if (!mem_eq(in18, in18_s, 18u)) {
        failf("nls_parse_o_len18", "input mutated");
    }
    if (!mem_eq(&oout, &outer_snap, sizeof(oout))) {
        failf("nls_parse_o_len18", "decoded mutated");
    }

    nls_tick();
    fill_app(in20, 20u, 0x82u);
    (void)memcpy(in20_s, in20, 20u);
    (void)memset(&oout, 0xC4, sizeof(oout));
    outer_snap = oout;
    st = ninlil_r7_wire_parse_outer_data_aad(in20, 20u, &oout);
    expect_status("nls_parse_o_len20", st, NINLIL_R7_WIRE_LENGTH_CLASS);
    if (!mem_eq(in20, in20_s, 20u)) {
        failf("nls_parse_o_len20", "input mutated");
    }
    if (!mem_eq(&oout, &outer_snap, sizeof(oout))) {
        failf("nls_parse_o_len20", "decoded mutated");
    }

    nls_tick();
    fill_app(in13, 13u, 0x83u);
    (void)memcpy(in13_s, in13, 13u);
    (void)memset(&eout, 0xC3, sizeof(eout));
    e2e_snap = eout;
    st = ninlil_r7_wire_parse_e2e_single_aad(in13, 13u, &eout);
    expect_status("nls_parse_e_len13", st, NINLIL_R7_WIRE_LENGTH_CLASS);
    if (!mem_eq(in13, in13_s, 13u)) {
        failf("nls_parse_e_len13", "input mutated");
    }
    if (!mem_eq(&eout, &e2e_snap, sizeof(eout))) {
        failf("nls_parse_e_len13", "decoded mutated");
    }

    nls_tick();
    fill_app(in15, 15u, 0x84u);
    (void)memcpy(in15_s, in15, 15u);
    (void)memset(&eout, 0xC3, sizeof(eout));
    e2e_snap = eout;
    st = ninlil_r7_wire_parse_e2e_single_aad(in15, 15u, &eout);
    expect_status("nls_parse_e_len15", st, NINLIL_R7_WIRE_LENGTH_CLASS);
    if (!mem_eq(in15, in15_s, 15u)) {
        failf("nls_parse_e_len15", "input mutated");
    }
    if (!mem_eq(&eout, &e2e_snap, sizeof(eout))) {
        failf("nls_parse_e_len15", "decoded mutated");
    }

    /* ---- (C) structural: header parse/open + ack=2 pack/seal ---- */

    fill_outer(&outer);
    fill_e2e(&e2e);
    expect_status(
        "nls_prep_pack_o",
        ninlil_r7_wire_pack_outer_data_aad(&outer, aad19, 19u),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "nls_prep_pack_e",
        ninlil_r7_wire_pack_e2e_single_aad(&e2e, aad14, 14u),
        NINLIL_R7_WIRE_OK);

    reset_rec(rc);
    expect_status(
        "nls_prep_seal_e2e",
        ninlil_r7_wire_seal_e2e_single(
            p, key, iv, &e2e, app, 16u, blob, 46u, &bl),
        NINLIL_R7_WIRE_OK);
    expect_status(
        "nls_prep_seal_outer",
        ninlil_r7_wire_seal_outer_single(
            p, hkey, hiv, &outer, blob, bl, frame, 81u, &fl),
        NINLIL_R7_WIRE_OK);
    if (bl != 46u || fl != 81u) {
        failf("nls_prep", "lens");
        return;
    }

    /* outer parse: profile invalid */
    nls_tick();
    {
        uint8_t bad[19];
        (void)memcpy(bad, aad19, 19u);
        bad[0] = 0x00u;
        (void)memset(&oout, 0xC4, sizeof(oout));
        outer_snap = oout;
        (void)memcpy(canary19, bad, 19u);
        st = ninlil_r7_wire_parse_outer_data_aad(bad, 19u, &oout);
        expect_status("nls_parse_o_profile", st, NINLIL_R7_WIRE_STRUCTURAL);
        if (!mem_eq(bad, canary19, 19u)
            || !mem_eq(&oout, &outer_snap, sizeof(oout))) {
            failf("nls_parse_o_profile", "input/decoded mutated");
        }
    }

    /* outer parse: kind invalid (high nibble != DATA) */
    nls_tick();
    {
        uint8_t bad[19];
        (void)memcpy(bad, aad19, 19u);
        bad[1] = (uint8_t)((2u << 4) | (bad[1] & 0x0fu));
        (void)memset(&oout, 0xC4, sizeof(oout));
        outer_snap = oout;
        (void)memcpy(canary19, bad, 19u);
        st = ninlil_r7_wire_parse_outer_data_aad(bad, 19u, &oout);
        expect_status("nls_parse_o_kind", st, NINLIL_R7_WIRE_STRUCTURAL);
        if (!mem_eq(bad, canary19, 19u)
            || !mem_eq(&oout, &outer_snap, sizeof(oout))) {
            failf("nls_parse_o_kind", "input/decoded mutated");
        }
    }

    /* outer parse: reserved bits invalid (kind_flags & 0x0e) */
    nls_tick();
    {
        uint8_t bad[19];
        (void)memcpy(bad, aad19, 19u);
        bad[1] = (uint8_t)(bad[1] | 0x02u);
        (void)memset(&oout, 0xC4, sizeof(oout));
        outer_snap = oout;
        (void)memcpy(canary19, bad, 19u);
        st = ninlil_r7_wire_parse_outer_data_aad(bad, 19u, &oout);
        expect_status("nls_parse_o_reserved", st, NINLIL_R7_WIRE_STRUCTURAL);
        if (!mem_eq(bad, canary19, 19u)
            || !mem_eq(&oout, &outer_snap, sizeof(oout))) {
            failf("nls_parse_o_reserved", "input/decoded mutated");
        }
    }

    /* e2e parse: profile invalid */
    nls_tick();
    {
        uint8_t bad[14];
        (void)memcpy(bad, aad14, 14u);
        bad[0] = 0x00u;
        (void)memset(&eout, 0xC3, sizeof(eout));
        e2e_snap = eout;
        (void)memcpy(canary14, bad, 14u);
        st = ninlil_r7_wire_parse_e2e_single_aad(bad, 14u, &eout);
        expect_status("nls_parse_e_profile", st, NINLIL_R7_WIRE_STRUCTURAL);
        if (!mem_eq(bad, canary14, 14u)
            || !mem_eq(&eout, &e2e_snap, sizeof(eout))) {
            failf("nls_parse_e_profile", "input/decoded mutated");
        }
    }

    /* e2e parse: type high-nibble invalid (!= SINGLE) */
    nls_tick();
    {
        uint8_t bad[14];
        (void)memcpy(bad, aad14, 14u);
        bad[1] = (uint8_t)((2u << 4) | (bad[1] & 0x0fu));
        (void)memset(&eout, 0xC3, sizeof(eout));
        e2e_snap = eout;
        (void)memcpy(canary14, bad, 14u);
        st = ninlil_r7_wire_parse_e2e_single_aad(bad, 14u, &eout);
        expect_status("nls_parse_e_type_hi", st, NINLIL_R7_WIRE_STRUCTURAL);
        if (!mem_eq(bad, canary14, 14u)
            || !mem_eq(&eout, &e2e_snap, sizeof(eout))) {
            failf("nls_parse_e_type_hi", "input/decoded mutated");
        }
    }

    /* e2e parse: type low-nibble reserved invalid */
    nls_tick();
    {
        uint8_t bad[14];
        (void)memcpy(bad, aad14, 14u);
        bad[1] = (uint8_t)(bad[1] | 0x01u);
        (void)memset(&eout, 0xC3, sizeof(eout));
        e2e_snap = eout;
        (void)memcpy(canary14, bad, 14u);
        st = ninlil_r7_wire_parse_e2e_single_aad(bad, 14u, &eout);
        expect_status("nls_parse_e_type_lo", st, NINLIL_R7_WIRE_STRUCTURAL);
        if (!mem_eq(bad, canary14, 14u)
            || !mem_eq(&eout, &e2e_snap, sizeof(eout))) {
            failf("nls_parse_e_type_lo", "input/decoded mutated");
        }
    }

    /* outer open: profile / kind / reserved — callback 0 + full mutation-zero */
    {
        uint8_t bad[81];
        const char *names[3] = {
            "nls_open_o_profile", "nls_open_o_kind", "nls_open_o_reserved"};
        int i;

        for (i = 0; i < 3; i++) {
            nls_tick();
            (void)memcpy(bad, frame, fl);
            if (i == 0) {
                bad[0] = 0x00u;
            } else if (i == 1) {
                bad[1] = (uint8_t)((2u << 4) | (bad[1] & 0x0fu));
            } else {
                bad[1] = (uint8_t)(bad[1] | 0x02u);
            }
            (void)memset(out, 0xA5, sizeof(out));
            ol = 0xBEEFu;
            (void)memset(&oout, 0xC4, sizeof(oout));
            snap_take_full(
                &before, p, hkey, hiv, NULL, NULL, NULL, &oout, bad, fl, out,
                46u, &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_open_outer_single(
                p, hkey, hiv, bad, fl, &oout, out, 46u, &ol);
            expect_status(names[i], st, NINLIL_R7_WIRE_STRUCTURAL);
            nls_expect_cb0(names[i], rc);
            snap_take_full(
                &after, p, hkey, hiv, NULL, NULL, NULL, &oout, bad, fl, out,
                46u, &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf(names[i], "caller mutated");
            }
        }
    }

    /* e2e open: profile / type hi / type lo — callback 0 + full mutation-zero */
    {
        uint8_t bad[46];
        const char *names[3] = {
            "nls_open_e_profile", "nls_open_e_type_hi", "nls_open_e_type_lo"};
        int i;

        for (i = 0; i < 3; i++) {
            nls_tick();
            (void)memcpy(bad, blob, bl);
            if (i == 0) {
                bad[0] = 0x00u;
            } else if (i == 1) {
                bad[1] = (uint8_t)((2u << 4) | (bad[1] & 0x0fu));
            } else {
                bad[1] = (uint8_t)(bad[1] | 0x01u);
            }
            (void)memset(out, 0xA5, sizeof(out));
            ol = 0xBEEFu;
            (void)memset(&eout, 0xC3, sizeof(eout));
            snap_take_full(
                &before, p, key, iv, NULL, NULL, &eout, NULL, bad, bl, out, 16u,
                &ol);
            reset_rec(rc);
            st = ninlil_r7_wire_open_e2e_single(
                p, key, iv, bad, bl, &eout, out, 16u, &ol);
            expect_status(names[i], st, NINLIL_R7_WIRE_STRUCTURAL);
            nls_expect_cb0(names[i], rc);
            snap_take_full(
                &after, p, key, iv, NULL, NULL, &eout, NULL, bad, bl, out, 16u,
                &ol);
            if (!snap_eq_strict(&before, &after)) {
                failf(names[i], "caller mutated");
            }
        }
    }

    /* outer pack ack_requested=2 → STRUCTURAL; fields + out capacity canary */
    nls_tick();
    fill_outer(&outer);
    outer.ack_requested = 2u;
    outer_snap = outer;
    (void)memset(out19, 0xA5, 19u);
    (void)memset(canary19, 0xA5, 19u);
    st = ninlil_r7_wire_pack_outer_data_aad(&outer, out19, 19u);
    expect_status("nls_pack_o_ack2", st, NINLIL_R7_WIRE_STRUCTURAL);
    if (!mem_eq(&outer, &outer_snap, sizeof(outer))) {
        failf("nls_pack_o_ack2", "fields mutated");
    }
    if (!mem_eq(out19, canary19, 19u)) {
        failf("nls_pack_o_ack2", "out mutated");
    }

    /* outer seal ack_requested=2 → STRUCTURAL, callback 0, full mutation-zero */
    nls_tick();
    fill_outer(&outer);
    outer.ack_requested = 2u;
    (void)memset(out, 0xA5, sizeof(out));
    ol = 0xBEEFu;
    snap_take_full(
        &before, p, hkey, hiv, NULL, &outer, NULL, NULL, blob, bl, out, 81u,
        &ol);
    reset_rec(rc);
    st = ninlil_r7_wire_seal_outer_single(
        p, hkey, hiv, &outer, blob, bl, out, 81u, &ol);
    expect_status("nls_seal_o_ack2", st, NINLIL_R7_WIRE_STRUCTURAL);
    nls_expect_cb0("nls_seal_o_ack2", rc);
    snap_take_full(
        &after, p, hkey, hiv, NULL, &outer, NULL, NULL, blob, bl, out, 81u, &ol);
    if (!snap_eq_strict(&before, &after)) {
        failf("nls_seal_o_ack2", "caller mutated");
    }

    if (g_nls_cases != expected) {
        fprintf(stderr,
            "nrw1_t1_wire_portable FAIL aad_null_length_structural "
            "cases got=%zu want=%zu\n",
            g_nls_cases, expected);
        g_failures++;
    } else {
        fprintf(stderr,
            "nrw1_t1_wire_portable aad_null_length_structural cases=%zu OK\n",
            g_nls_cases);
    }
}

int main(void)
{
    rec_ctx rc;
    ninlil_r7_crypto_provider prov;

    g_failures = 0;
    make_rec(&rc, &prov);
    test_success(&rc, &prov);
    test_aad_domains();
    test_nulls_and_provider_shapes(&rc, &prov);
    test_alias_all_pairs(&rc, &prov);
    test_bitflips(&rc, &prov);
    test_faults(&rc, &prov);
    test_mandatory_boundaries(&rc, &prov);
    test_mandatory_boundaries_part2(&rc, &prov);
    test_aad_alias_matrix();
    test_aad_null_length_structural(&rc, &prov);

    if (g_failures != 0) {
        fprintf(stderr, "nrw1_t1_wire_portable FAIL failures=%d\n", g_failures);
        return 1;
    }
    printf("nrw1_t1_wire_portable OK\n");
    return 0;
}
