/*
 * R7 T1b private acceptance tests (docs/33).
 *
 * Instrumented fake T0 raw provider only — no second production crypto.
 * Standalone:
 *   clang|gcc -std=c11 -Wall -Wextra -Werror -Wvla -pedantic \
 *     -DNINLIL_R7_BINDING_TEST_BUILD -Isrc/radio \
 *     tests/radio/private/r7_t1b_binding_test.c \
 *     src/radio/r7_context_binding.c src/radio/r7_crypto_portable.c
 */

#define NINLIL_R7_BINDING_TEST_BUILD 1

#include "r7_context_binding.h"

#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Harness                                                                    */
/* -------------------------------------------------------------------------- */

static int g_failures;
static int g_tests;

static void expect_status(const char *name, int32_t got, int32_t want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: status got=%d want=%d\n",
            name, (int)got, (int)want);
        g_failures++;
    }
}

static void expect_true(const char *name, int cond)
{
    g_tests++;
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        g_failures++;
    }
}

static void expect_size(const char *name, size_t got, size_t want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: size got=%zu want=%zu\n", name, got, want);
        g_failures++;
    }
}

static void expect_mem_eq(
    const char *name, const void *a, const void *b, size_t n)
{
    g_tests++;
    if (n > 0u && memcmp(a, b, n) != 0) {
        fprintf(stderr, "FAIL %s: bytes differ\n", name);
        g_failures++;
    }
}

static void expect_calls(
    const char *name, int sha, int ex, int exp, int wsha, int wex, int wexp)
{
    char buf[160];
    snprintf(buf, sizeof(buf), "%s sha", name);
    expect_true(buf, sha == wsha);
    snprintf(buf, sizeof(buf), "%s extract", name);
    expect_true(buf, ex == wex);
    snprintf(buf, sizeof(buf), "%s expand", name);
    expect_true(buf, exp == wexp);
}

static void fill_bytes(uint8_t *p, size_t n, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_canary(uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }
}

static int is_canary(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        if (p[i] != (uint8_t)(0xA5u ^ (uint8_t)i)) {
            return 0;
        }
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Fake T0 raw provider                                                       */
/* -------------------------------------------------------------------------- */

typedef struct fake_ctx {
    int sha_calls;
    int extract_calls;
    int expand_calls;
    ninlil_r7_crypto_raw_status sha_result;
    ninlil_r7_crypto_raw_status extract_result;
    ninlil_r7_crypto_raw_status expand_result;
    int expand_fail_after;
    int expand_unknown_after;
    int expand_auth_after;
    int sha_unknown;
    int extract_unknown;
    int expand_unknown;
    uint8_t digest32[32];
    uint8_t prk32[32];
    uint8_t okm_lane[4][16];
    size_t last_msg_len;
    size_t last_info_len;
    size_t last_okm_len;
} fake_ctx;

static void fake_reset(fake_ctx *f)
{
    size_t i;
    size_t j;
    memset(f, 0, sizeof(*f));
    f->sha_result = NINLIL_R7_CRYPTO_RAW_OK;
    f->extract_result = NINLIL_R7_CRYPTO_RAW_OK;
    f->expand_result = NINLIL_R7_CRYPTO_RAW_OK;
    for (i = 0u; i < 32u; i++) {
        f->digest32[i] = (uint8_t)(0xD0u + (uint8_t)i);
        f->prk32[i] = (uint8_t)(0xB0u + (uint8_t)i);
    }
    for (i = 0u; i < 4u; i++) {
        for (j = 0u; j < 16u; j++) {
            f->okm_lane[i][j] =
                (uint8_t)(0x40u + (uint8_t)i * 0x10u + (uint8_t)j);
        }
    }
}

static ninlil_r7_crypto_raw_status fake_sha(
    void *ctx, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t i;
    (void)msg;
    f->sha_calls++;
    f->last_msg_len = msg_len;
    if (f->sha_unknown) {
        return (ninlil_r7_crypto_raw_status)99;
    }
    if (f->sha_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->sha_result;
    }
    for (i = 0u; i < 32u; i++) {
        out[i] = f->digest32[i];
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status fake_extract(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out[32])
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t i;
    (void)salt;
    (void)salt_len;
    (void)ikm;
    (void)ikm_len;
    f->extract_calls++;
    if (f->extract_unknown) {
        return (ninlil_r7_crypto_raw_status)77;
    }
    if (f->extract_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->extract_result;
    }
    for (i = 0u; i < 32u; i++) {
        out[i] = f->prk32[i];
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status fake_expand(
    void *ctx,
    const uint8_t prk[32],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len)
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t i;
    int idx;
    (void)prk;
    (void)info;
    f->expand_calls++;
    idx = f->expand_calls - 1;
    f->last_info_len = info_len;
    f->last_okm_len = okm_len;
    if (f->expand_unknown_after > 0 && f->expand_calls == f->expand_unknown_after) {
        return (ninlil_r7_crypto_raw_status)55;
    }
    if (f->expand_auth_after > 0 && f->expand_calls == f->expand_auth_after) {
        return NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
    }
    if (f->expand_fail_after > 0 && f->expand_calls == f->expand_fail_after) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    if (f->expand_unknown) {
        return (ninlil_r7_crypto_raw_status)55;
    }
    if (f->expand_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->expand_result;
    }
    if (idx < 0) {
        idx = 0;
    }
    if (idx > 3) {
        idx = 3;
    }
    for (i = 0u; i < okm_len && i < 16u; i++) {
        out_okm[i] = f->okm_lane[idx][i];
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status fake_seal(
    void *ctx,
    const uint8_t key[16],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *pt,
    size_t pt_len,
    uint8_t *out,
    size_t out_cap,
    size_t *produced)
{
    (void)ctx;
    (void)key;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)pt;
    (void)pt_len;
    (void)out;
    (void)out_cap;
    (void)produced;
    return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
}

static ninlil_r7_crypto_raw_status fake_open(
    void *ctx,
    const uint8_t key[16],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *sealed,
    size_t sealed_len,
    uint8_t *out,
    size_t out_cap,
    size_t *produced)
{
    (void)ctx;
    (void)key;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)sealed;
    (void)sealed_len;
    (void)out;
    (void)out_cap;
    (void)produced;
    return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
}

static void make_provider(ninlil_r7_crypto_provider *p, fake_ctx *f)
{
    memset(p, 0, sizeof(*p));
    p->abi_version = NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION;
    p->struct_size = (uint32_t)sizeof(ninlil_r7_crypto_provider);
    p->reserved_zero = 0u;
    p->ctx = f;
    p->sha256 = fake_sha;
    p->hkdf_extract_sha256 = fake_extract;
    p->hkdf_expand_sha256 = fake_expand;
    p->aes128_gcm_seal = fake_seal;
    p->aes128_gcm_open = fake_open;
}

/* -------------------------------------------------------------------------- */
/* Buffers / builders                                                         */
/* -------------------------------------------------------------------------- */

typedef struct hop_bufs {
    uint8_t site[16];
    uint8_t att[32];
    uint8_t init[32];
    uint8_t resp[32];
    uint8_t auth[32];
} hop_bufs;

typedef struct e2e_bufs {
    uint8_t site[16];
    uint8_t sec[32];
    uint8_t send[32];
    uint8_t recv[32];
    uint8_t auth[32];
} e2e_bufs;

static void hop_bufs_init(hop_bufs *b)
{
    fill_bytes(b->site, 16u, 0x10u);
    fill_bytes(b->att, 32u, 0x20u);
    fill_bytes(b->init, 32u, 0x30u);
    fill_bytes(b->resp, 32u, 0x40u);
    fill_bytes(b->auth, 32u, 0x50u);
}

static void e2e_bufs_init(e2e_bufs *b)
{
    fill_bytes(b->site, 16u, 0x11u);
    fill_bytes(b->sec, 32u, 0x21u);
    fill_bytes(b->send, 32u, 0x31u);
    fill_bytes(b->recv, 32u, 0x41u);
    fill_bytes(b->auth, 32u, 0x51u);
}

static void hop_fill(
    ninlil_r7_hop_binding_input *in,
    hop_bufs *b,
    uint8_t env,
    int max_lens,
    uint8_t dir,
    int no_controller)
{
    uint16_t site_len;
    uint16_t id_len;
    uint16_t auth_len;

    memset(in, 0, sizeof(*in));
    in->environment_code = env;
    in->direction_code = dir;
    in->hop_context_id = 1u;
    in->membership_epoch = 1u;
    in->attachment_epoch = 1u;

    if (env == NINLIL_R7_BINDING_ENV_FIELD) {
        site_len = 16u;
    } else {
        site_len = max_lens ? 16u : 1u;
    }
    id_len = max_lens ? 32u : 1u;

    in->site_domain.bytes = b->site;
    in->site_domain.length = site_len;
    in->attachment_id.bytes = b->att;
    in->attachment_id.length = id_len;
    in->initiator_stable_id.bytes = b->init;
    in->initiator_stable_id.length = id_len;
    in->responder_stable_id.bytes = b->resp;
    in->responder_stable_id.length = id_len;

    if (no_controller) {
        in->controller_authority_id.bytes = NULL;
        in->controller_authority_id.length = 0u;
        in->controller_term = 0u;
    } else {
        auth_len = max_lens ? 32u : 1u;
        in->controller_authority_id.bytes = b->auth;
        in->controller_authority_id.length = auth_len;
        in->controller_term = 1u;
    }
}

static void e2e_fill(
    ninlil_r7_e2e_binding_input *in,
    e2e_bufs *b,
    uint8_t env,
    int max_lens,
    uint8_t dir,
    int no_controller)
{
    uint16_t site_len;
    uint16_t id_len;
    uint16_t auth_len;

    memset(in, 0, sizeof(*in));
    in->environment_code = env;
    in->direction_code = dir;
    in->e2e_context_id = 1u;
    in->membership_epoch = 1u;
    in->e2e_security_epoch = 1u;

    if (env == NINLIL_R7_BINDING_ENV_FIELD) {
        site_len = 16u;
    } else {
        site_len = max_lens ? 16u : 1u;
    }
    id_len = max_lens ? 32u : 1u;

    in->site_domain.bytes = b->site;
    in->site_domain.length = site_len;
    in->e2e_security_id.bytes = b->sec;
    in->e2e_security_id.length = id_len;
    in->sender_stable_id.bytes = b->send;
    in->sender_stable_id.length = id_len;
    in->receiver_stable_id.bytes = b->recv;
    in->receiver_stable_id.length = id_len;

    if (no_controller) {
        in->authority_id.bytes = NULL;
        in->authority_id.length = 0u;
        in->authority_term = 0u;
    } else {
        auth_len = max_lens ? 32u : 1u;
        in->authority_id.bytes = b->auth;
        in->authority_id.length = auth_len;
        in->authority_term = 1u;
    }
}

static size_t hop_need(const ninlil_r7_hop_binding_input *in)
{
    return 63u
        + (size_t)in->site_domain.length
        + (size_t)in->attachment_id.length
        + (size_t)in->initiator_stable_id.length
        + (size_t)in->responder_stable_id.length
        + (size_t)in->controller_authority_id.length;
}

static size_t e2e_need(const ninlil_r7_e2e_binding_input *in)
{
    return 61u
        + (size_t)in->site_domain.length
        + (size_t)in->e2e_security_id.length
        + (size_t)in->sender_stable_id.length
        + (size_t)in->receiver_stable_id.length
        + (size_t)in->authority_id.length;
}

/* -------------------------------------------------------------------------- */
/* Probe helpers                                                              */
/* -------------------------------------------------------------------------- */

static void probe_clear(ninlil_r7_binding_test_secret_probe *pr, uint8_t *reg, size_t n)
{
    memset(pr, 0, sizeof(*pr));
    if (reg != NULL && n > 0u) {
        memset(reg, 0xFFu, n);
        pr->region = reg;
        pr->capacity = n;
    }
    ninlil_r7_binding_test_set_secret_probe(pr);
}

static void probe_off(void)
{
    ninlil_r7_binding_test_set_secret_probe(NULL);
}

static int probe_has_size(const ninlil_r7_binding_test_secret_probe *pr, size_t sz)
{
    size_t i;
    for (i = 0u; i < pr->log_count; i++) {
        if (pr->log_sizes[i] == sz) {
            return 1;
        }
    }
    return 0;
}

static int probe_exact_log(
    const ninlil_r7_binding_test_secret_probe *pr,
    const size_t *want,
    size_t n)
{
    size_t i;
    if (pr->log_count != n || pr->zero_calls != n) {
        return 0;
    }
    for (i = 0u; i < n; i++) {
        if (pr->log_sizes[i] != want[i]) {
            return 0;
        }
    }
    return 1;
}

/* Expected ordered zero logs (full buffer sizes from production). */
static const size_t k_hop_encode_zeros[] = { 207u };
static const size_t k_e2e_encode_zeros[] = { 205u };
static const size_t k_hop_digest_zeros[] = { 207u, 32u };
static const size_t k_e2e_digest_zeros[] = { 205u, 32u };
static const size_t k_hop_derive_zeros[] = {
    207u, 32u, 32u, 32u, 16u, 12u, 16u, 12u
};
static const size_t k_e2e_derive_zeros[] = {
    205u, 32u, 32u, 32u, 16u, 12u
};

/* -------------------------------------------------------------------------- */
/* 1. Positive encode / digest / derive matrix                                */
/* -------------------------------------------------------------------------- */

static void test_positive_matrix(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    uint8_t out[256];
    size_t out_len;
    size_t need;
    int32_t st;
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t dig[32];
    uint8_t secret[32];
    ninlil_r7_hop_key_bundle hbnd;
    ninlil_r7_e2e_key_bundle ebnd;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);
    fill_bytes(secret, 32u, 0x77u);

    struct {
        uint8_t env;
        int max_lens;
        uint8_t dir;
        int no_ctl;
        size_t want_need;
        const char *name;
    } hop_cases[] = {
        { 2, 0, 0, 0, 83u, "HOP-FIELD-D0-MIN" },
        { 2, 1, 0, 0, 207u, "HOP-FIELD-D0-MAX" },
        { 2, 0, 1, 0, 83u, "HOP-FIELD-D1-MIN" },
        { 2, 1, 1, 0, 207u, "HOP-FIELD-D1-MAX" },
        { 1, 0, 0, 0, 68u, "HOP-LAB-CTL-D0-MIN" },
        { 1, 1, 0, 0, 207u, "HOP-LAB-CTL-D0-MAX" },
        { 1, 0, 1, 0, 68u, "HOP-LAB-CTL-D1-MIN" },
        { 1, 1, 1, 0, 207u, "HOP-LAB-CTL-D1-MAX" },
        { 1, 0, 0, 1, 67u, "HOP-LAB-NC-D0-MIN" },
        { 1, 1, 0, 1, 175u, "HOP-LAB-NC-D0-MAX" },
        { 1, 0, 1, 1, 67u, "HOP-LAB-NC-D1-MIN" },
        { 1, 1, 1, 1, 175u, "HOP-LAB-NC-D1-MAX" },
    };
    struct {
        uint8_t env;
        int max_lens;
        uint8_t dir;
        int no_ctl;
        size_t want_need;
        const char *name;
    } e2e_cases[] = {
        { 2, 0, 0, 0, 81u, "E2E-FIELD-D0-MIN" },
        { 2, 1, 0, 0, 205u, "E2E-FIELD-D0-MAX" },
        { 2, 0, 1, 0, 81u, "E2E-FIELD-D1-MIN" },
        { 2, 1, 1, 0, 205u, "E2E-FIELD-D1-MAX" },
        { 1, 0, 0, 0, 66u, "E2E-LAB-CTL-D0-MIN" },
        { 1, 1, 0, 0, 205u, "E2E-LAB-CTL-D0-MAX" },
        { 1, 0, 1, 0, 66u, "E2E-LAB-CTL-D1-MIN" },
        { 1, 1, 1, 0, 205u, "E2E-LAB-CTL-D1-MAX" },
        { 1, 0, 0, 1, 65u, "E2E-LAB-NC-D0-MIN" },
        { 1, 1, 0, 1, 173u, "E2E-LAB-NC-D0-MAX" },
        { 1, 0, 1, 1, 65u, "E2E-LAB-NC-D1-MIN" },
        { 1, 1, 1, 1, 173u, "E2E-LAB-NC-D1-MAX" },
    };
    size_t i;

    for (i = 0u; i < sizeof(hop_cases) / sizeof(hop_cases[0]); i++) {
        hop_bufs_init(&hb);
        hop_fill(&hop, &hb, hop_cases[i].env, hop_cases[i].max_lens,
            hop_cases[i].dir, hop_cases[i].no_ctl);
        if (hop_cases[i].max_lens) {
            hop.membership_epoch = UINT64_MAX;
            hop.attachment_epoch = UINT64_MAX;
            if (!hop_cases[i].no_ctl) {
                hop.controller_term = UINT64_MAX;
            }
        }
        need = hop_need(&hop);
        expect_size(hop_cases[i].name, need, hop_cases[i].want_need);
        out_len = 0u;
        st = ninlil_r7_encode_hop_binding(&hop, out, need, &out_len);
        expect_status(hop_cases[i].name, st, NINLIL_R7_BINDING_OK);
        expect_size(hop_cases[i].name, out_len, need);
        expect_true(hop_cases[i].name, out[20] == 0x11u);
        expect_true(hop_cases[i].name, out[need - 2u] == 0x00u);
        expect_true(hop_cases[i].name, out[need - 1u] == 0x03u);
    }

    for (i = 0u; i < sizeof(e2e_cases) / sizeof(e2e_cases[0]); i++) {
        e2e_bufs_init(&eb);
        e2e_fill(&e2e, &eb, e2e_cases[i].env, e2e_cases[i].max_lens,
            e2e_cases[i].dir, e2e_cases[i].no_ctl);
        if (e2e_cases[i].max_lens) {
            e2e.membership_epoch = UINT64_MAX;
            e2e.e2e_security_epoch = UINT64_MAX;
            if (!e2e_cases[i].no_ctl) {
                e2e.authority_term = UINT64_MAX;
            }
        }
        need = e2e_need(&e2e);
        expect_size(e2e_cases[i].name, need, e2e_cases[i].want_need);
        out_len = 0u;
        st = ninlil_r7_encode_e2e_binding(&e2e, out, need, &out_len);
        expect_status(e2e_cases[i].name, st, NINLIL_R7_BINDING_OK);
        expect_size(e2e_cases[i].name, out_len, need);
        expect_true(e2e_cases[i].name, out[20] == 0x11u);
    }

    fake_reset(&f);
    make_provider(&p, &f);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("digest hop", st, NINLIL_R7_BINDING_OK);
    expect_calls("digest hop", f.sha_calls, f.extract_calls, f.expand_calls, 1, 0, 0);
    expect_mem_eq("digest hop bytes", dig, f.digest32, 32u);

    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, f.digest32, secret, &hbnd);
    expect_status("derive hop", st, NINLIL_R7_BINDING_OK);
    expect_calls("derive hop", f.sha_calls, f.extract_calls, f.expand_calls, 2, 1, 4);
    expect_mem_eq("hop data key", hbnd.data_key16, f.okm_lane[0], 16u);
    expect_mem_eq("hop data iv", hbnd.data_iv12, f.okm_lane[1], 12u);
    expect_mem_eq("hop ack key", hbnd.ack_key16, f.okm_lane[2], 16u);
    expect_mem_eq("hop ack iv", hbnd.ack_iv12, f.okm_lane[3], 12u);

    fake_reset(&f);
    make_provider(&p, &f);
    e2e_fill(&e2e, &eb, 2, 0, 1, 0);
    st = ninlil_r7_digest_e2e_binding(&p, &e2e, dig);
    expect_status("digest e2e", st, NINLIL_R7_BINDING_OK);
    expect_calls("digest e2e", f.sha_calls, f.extract_calls, f.expand_calls, 1, 0, 0);
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, f.digest32, secret, &ebnd);
    expect_status("derive e2e", st, NINLIL_R7_BINDING_OK);
    expect_calls("derive e2e", f.sha_calls, f.extract_calls, f.expand_calls, 2, 1, 2);
    expect_mem_eq("e2e key", ebnd.key16, f.okm_lane[0], 16u);
    expect_mem_eq("e2e iv", ebnd.iv12, f.okm_lane[1], 12u);
}

/* -------------------------------------------------------------------------- */
/* 2. Encode field sensitivity                                                */
/* -------------------------------------------------------------------------- */

static void test_encode_field_sensitivity(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input base_h, mut_h;
    ninlil_r7_e2e_binding_input base_e, mut_e;
    uint8_t out_b[256], out_m[256];
    size_t len_b, len_m;
    size_t need_b, need_m;
    int32_t st;

    hop_bufs_init(&hb);
    hop_fill(&base_h, &hb, 2, 0, 0, 0);
    need_b = hop_need(&base_h);
    st = ninlil_r7_encode_hop_binding(&base_h, out_b, need_b, &len_b);
    expect_status("sens base hop", st, NINLIL_R7_BINDING_OK);

#define HOP_MUT_INT(field, val, tag)                                           \
    do {                                                                       \
        mut_h = base_h;                                                        \
        mut_h.field = (val);                                                   \
        need_m = hop_need(&mut_h);                                             \
        st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_m, &len_m);      \
        expect_status(tag, st, NINLIL_R7_BINDING_OK);                          \
        expect_true(tag, need_m == need_b);                                    \
        expect_true(tag, memcmp(out_b, out_m, need_b) != 0);                   \
    } while (0)

    HOP_MUT_INT(environment_code, 1u, "hop mut env");
    /* LAB needs shorter site — rebuild properly */
    {
        hop_bufs hb2;
        hop_bufs_init(&hb2);
        hop_fill(&mut_h, &hb2, 1, 0, 0, 0);
        need_m = hop_need(&mut_h);
        st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_m, &len_m);
        expect_status("hop mut env LAB", st, NINLIL_R7_BINDING_OK);
        expect_true("hop mut env LAB len", need_m != need_b);
    }
    HOP_MUT_INT(membership_epoch, 2u, "hop mut mem_ep");
    HOP_MUT_INT(attachment_epoch, 9u, "hop mut att_ep");
    HOP_MUT_INT(controller_term, 7u, "hop mut term");
    HOP_MUT_INT(hop_context_id, 42u, "hop mut ctx");
    HOP_MUT_INT(direction_code, 1u, "hop mut dir");

    /* opaque body mutation (same length) */
    mut_h = base_h;
    hb.site[0] ^= 0x01u;
    need_m = hop_need(&mut_h);
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_m, &len_m);
    expect_status("hop mut site body", st, NINLIL_R7_BINDING_OK);
    expect_true("hop mut site body", memcmp(out_b, out_m, need_b) != 0);
    hb.site[0] ^= 0x01u;

    hb.att[0] ^= 0x02u;
    mut_h = base_h;
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_b, &len_m);
    expect_status("hop mut att body", st, NINLIL_R7_BINDING_OK);
    expect_true("hop mut att body", memcmp(out_b, out_m, need_b) != 0);
    hb.att[0] ^= 0x02u;

    hb.init[0] ^= 0x03u;
    mut_h = base_h;
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_b, &len_m);
    expect_true("hop mut init body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    hb.init[0] ^= 0x03u;

    hb.resp[0] ^= 0x04u;
    mut_h = base_h;
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_b, &len_m);
    expect_true("hop mut resp body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    hb.resp[0] ^= 0x04u;

    hb.auth[0] ^= 0x05u;
    mut_h = base_h;
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_b, &len_m);
    expect_true("hop mut auth body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    hb.auth[0] ^= 0x05u;

    /* opaque length mutation (FIELD site must stay 16; use attachment) */
    mut_h = base_h;
    mut_h.attachment_id.length = 2u;
    need_m = hop_need(&mut_h);
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_m, &len_m);
    expect_status("hop mut att len", st, NINLIL_R7_BINDING_OK);
    expect_true("hop mut att len", need_m == need_b + 1u);
    expect_true("hop mut att len bytes",
        need_m != need_b || memcmp(out_b, out_m, need_b) != 0);

    mut_h = base_h;
    mut_h.initiator_stable_id.length = 2u;
    need_m = hop_need(&mut_h);
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_m, &len_m);
    expect_true("hop mut init len",
        st == NINLIL_R7_BINDING_OK && need_m == need_b + 1u);

    mut_h = base_h;
    mut_h.responder_stable_id.length = 2u;
    need_m = hop_need(&mut_h);
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_m, &len_m);
    expect_true("hop mut resp len",
        st == NINLIL_R7_BINDING_OK && need_m == need_b + 1u);

    mut_h = base_h;
    mut_h.controller_authority_id.length = 2u;
    need_m = hop_need(&mut_h);
    st = ninlil_r7_encode_hop_binding(&mut_h, out_m, need_m, &len_m);
    expect_true("hop mut auth len",
        st == NINLIL_R7_BINDING_OK && need_m == need_b + 1u);

#undef HOP_MUT_INT

    /* E2E */
    e2e_bufs_init(&eb);
    e2e_fill(&base_e, &eb, 2, 0, 0, 0);
    need_b = e2e_need(&base_e);
    st = ninlil_r7_encode_e2e_binding(&base_e, out_b, need_b, &len_b);
    expect_status("sens base e2e", st, NINLIL_R7_BINDING_OK);

#define E2E_MUT_INT(field, val, tag)                                           \
    do {                                                                       \
        mut_e = base_e;                                                        \
        mut_e.field = (val);                                                   \
        need_m = e2e_need(&mut_e);                                             \
        st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_m, &len_m);      \
        expect_status(tag, st, NINLIL_R7_BINDING_OK);                          \
        expect_true(tag, need_m == need_b);                                    \
        expect_true(tag, memcmp(out_b, out_m, need_b) != 0);                   \
    } while (0)

    E2E_MUT_INT(membership_epoch, 3u, "e2e mut mem_ep");
    E2E_MUT_INT(e2e_security_epoch, 4u, "e2e mut sec_ep");
    E2E_MUT_INT(authority_term, 5u, "e2e mut term");
    E2E_MUT_INT(e2e_context_id, 99u, "e2e mut ctx");
    E2E_MUT_INT(direction_code, 1u, "e2e mut dir");

    eb.site[0] ^= 0x11u;
    mut_e = base_e;
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_b, &len_m);
    expect_true("e2e mut site body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    eb.site[0] ^= 0x11u;

    eb.sec[0] ^= 0x12u;
    mut_e = base_e;
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_b, &len_m);
    expect_true("e2e mut sec body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    eb.sec[0] ^= 0x12u;

    eb.send[0] ^= 0x13u;
    mut_e = base_e;
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_b, &len_m);
    expect_true("e2e mut send body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    eb.send[0] ^= 0x13u;

    eb.recv[0] ^= 0x14u;
    mut_e = base_e;
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_b, &len_m);
    expect_true("e2e mut recv body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    eb.recv[0] ^= 0x14u;

    eb.auth[0] ^= 0x15u;
    mut_e = base_e;
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_b, &len_m);
    expect_true("e2e mut auth body",
        st == NINLIL_R7_BINDING_OK && memcmp(out_b, out_m, need_b) != 0);
    eb.auth[0] ^= 0x15u;

    mut_e = base_e;
    mut_e.e2e_security_id.length = 2u;
    need_m = e2e_need(&mut_e);
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_m, &len_m);
    expect_true("e2e mut sec len",
        st == NINLIL_R7_BINDING_OK && need_m == need_b + 1u);

    mut_e = base_e;
    mut_e.sender_stable_id.length = 2u;
    need_m = e2e_need(&mut_e);
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_m, &len_m);
    expect_true("e2e mut send len",
        st == NINLIL_R7_BINDING_OK && need_m == need_b + 1u);

    mut_e = base_e;
    mut_e.receiver_stable_id.length = 2u;
    need_m = e2e_need(&mut_e);
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_m, &len_m);
    expect_true("e2e mut recv len",
        st == NINLIL_R7_BINDING_OK && need_m == need_b + 1u);

    mut_e = base_e;
    mut_e.authority_id.length = 2u;
    need_m = e2e_need(&mut_e);
    st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_m, &len_m);
    expect_true("e2e mut auth len",
        st == NINLIL_R7_BINDING_OK && need_m == need_b + 1u);

    /* LAB site length change */
    {
        e2e_bufs eb2;
        e2e_bufs_init(&eb2);
        e2e_fill(&mut_e, &eb2, 1, 0, 0, 0);
        need_m = e2e_need(&mut_e);
        st = ninlil_r7_encode_e2e_binding(&mut_e, out_m, need_m, &len_m);
        expect_true("e2e mut env/site len",
            st == NINLIL_R7_BINDING_OK && need_m != need_b);
    }
#undef E2E_MUT_INT
}

/* -------------------------------------------------------------------------- */
/* 3. Shape / structural / capacity tables                                    */
/* -------------------------------------------------------------------------- */

static void expect_fail_calls0(
    const char *name,
    int32_t st,
    int32_t want,
    fake_ctx *f,
    const uint8_t *out_canary,
    const uint8_t *out,
    size_t out_n,
    size_t out_len,
    size_t out_len_canary)
{
    expect_status(name, st, want);
    expect_calls(name, f->sha_calls, f->extract_calls, f->expand_calls, 0, 0, 0);
    if (out != NULL && out_canary != NULL && out_n > 0u) {
        expect_mem_eq(name, out, out_canary, out_n);
    }
    if (out_len_canary != (size_t)-1) {
        expect_true(name, out_len == out_len_canary);
    }
}

static void test_null_and_provider_shape(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t out[256];
    uint8_t dig[32];
    uint8_t secret[32];
    ninlil_r7_hop_key_bundle hbnd;
    ninlil_r7_e2e_key_bundle ebnd;
    size_t out_len = 0xDEADBEEFu;
    int32_t st;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    fill_bytes(secret, 32u, 0x55u);
    fake_reset(&f);
    make_provider(&p, &f);
    fill_canary(out, sizeof(out));
    fill_canary(dig, 32u);
    fill_canary((uint8_t *)&hbnd, sizeof(hbnd));
    fill_canary((uint8_t *)&ebnd, sizeof(ebnd));

    st = ninlil_r7_encode_hop_binding(NULL, out, 83u, &out_len);
    expect_fail_calls0("hop null in", st, NINLIL_R7_BINDING_INVALID_ARGUMENT,
        &f, out, out, sizeof(out), out_len, 0xDEADBEEFu);
    st = ninlil_r7_encode_hop_binding(&hop, NULL, 83u, &out_len);
    expect_status("hop null out", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, NULL);
    expect_status("hop null out_len", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);

    st = ninlil_r7_encode_e2e_binding(NULL, out, 81u, &out_len);
    expect_status("e2e null in", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_encode_e2e_binding(&e2e, NULL, 81u, &out_len);
    expect_status("e2e null out", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, NULL);
    expect_status("e2e null out_len", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);

    st = ninlil_r7_digest_hop_binding(NULL, &hop, dig);
    expect_status("dig hop null p", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_digest_hop_binding(&p, NULL, dig);
    expect_status("dig hop null in", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_digest_hop_binding(&p, &hop, NULL);
    expect_status("dig hop null out", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);

    st = ninlil_r7_digest_e2e_binding(NULL, &e2e, dig);
    expect_status("dig e2e null p", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_digest_e2e_binding(&p, NULL, dig);
    expect_status("dig e2e null in", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_digest_e2e_binding(&p, &e2e, NULL);
    expect_status("dig e2e null out", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);

    st = ninlil_r7_derive_hop_key_bundle_verified(
        NULL, &hop, dig, secret, &hbnd);
    expect_status("der hop null p", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, NULL, dig, secret, &hbnd);
    expect_status("der hop null in", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, NULL, secret, &hbnd);
    expect_status("der hop null exp", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, dig, NULL, &hbnd);
    expect_status("der hop null sec", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, dig, secret, NULL);
    expect_status("der hop null out", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);

    st = ninlil_r7_derive_e2e_key_bundle_verified(
        NULL, &e2e, dig, secret, &ebnd);
    expect_status("der e2e null p", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, NULL, dig, secret, &ebnd);
    expect_status("der e2e null in", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, NULL, secret, &ebnd);
    expect_status("der e2e null exp", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, dig, NULL, &ebnd);
    expect_status("der e2e null sec", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, dig, secret, NULL);
    expect_status("der e2e null out", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);

    /* bad provider shape */
    p.abi_version = 0u;
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("dig bad abi", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    expect_calls("dig bad abi", f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
    make_provider(&p, &f);
    p.sha256 = NULL;
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("dig null sha fn", st, NINLIL_R7_BINDING_INVALID_ARGUMENT);
    expect_true("dig null sha canary", is_canary(dig, 32u));
    expect_true("nulls unmut out_len", out_len == 0xDEADBEEFu);
}

static void test_opaque_shape_every_field(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t out[256];
    size_t out_len = 1u;
    int32_t st;
    size_t need;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);
    fake_reset(&f);
    make_provider(&p, &f);

    /* Hop: zero-len with non-NULL for each opaque that can be empty (auth only) */
    hop_fill(&hop, &hb, 1, 0, 0, 1);
    hop.controller_authority_id.bytes = hb.auth;
    hop.controller_authority_id.length = 0u;
    need = hop_need(&hop);
    st = ninlil_r7_encode_hop_binding(&hop, out, need, &out_len);
    expect_fail_calls0("hop auth zero+ptr", st, NINLIL_R7_BINDING_INVALID_ARGUMENT,
        &f, NULL, NULL, 0, out_len, 1u);

    /* Hop: non-zero length with NULL for each opaque */
    {
        ninlil_r7_binding_bytes *fields[5];
        const char *names[5];
        size_t i;
        hop_fill(&hop, &hb, 2, 0, 0, 0);
        fields[0] = &hop.site_domain;
        names[0] = "hop site null bytes";
        fields[1] = &hop.attachment_id;
        names[1] = "hop att null bytes";
        fields[2] = &hop.initiator_stable_id;
        names[2] = "hop init null bytes";
        fields[3] = &hop.responder_stable_id;
        names[3] = "hop resp null bytes";
        fields[4] = &hop.controller_authority_id;
        names[4] = "hop auth null bytes";
        for (i = 0u; i < 5u; i++) {
            hop_fill(&hop, &hb, 2, 0, 0, 0);
            fields[0] = &hop.site_domain;
            fields[1] = &hop.attachment_id;
            fields[2] = &hop.initiator_stable_id;
            fields[3] = &hop.responder_stable_id;
            fields[4] = &hop.controller_authority_id;
            fields[i]->bytes = NULL;
            fields[i]->length = 1u;
            fake_reset(&f);
            st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
            expect_fail_calls0(names[i], st, NINLIL_R7_BINDING_INVALID_ARGUMENT,
                &f, NULL, NULL, 0, 0, (size_t)-1);
        }
    }

    /* E2E: same for five opaques */
    {
        size_t i;
        const char *names[5] = {
            "e2e site null", "e2e sec null", "e2e send null",
            "e2e recv null", "e2e auth null"
        };
        for (i = 0u; i < 5u; i++) {
            e2e_fill(&e2e, &eb, 2, 0, 0, 0);
            if (i == 0u) {
                e2e.site_domain.bytes = NULL;
                e2e.site_domain.length = 1u;
            } else if (i == 1u) {
                e2e.e2e_security_id.bytes = NULL;
                e2e.e2e_security_id.length = 1u;
            } else if (i == 2u) {
                e2e.sender_stable_id.bytes = NULL;
                e2e.sender_stable_id.length = 1u;
            } else if (i == 3u) {
                e2e.receiver_stable_id.bytes = NULL;
                e2e.receiver_stable_id.length = 1u;
            } else {
                e2e.authority_id.bytes = NULL;
                e2e.authority_id.length = 1u;
            }
            fake_reset(&f);
            st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
            expect_fail_calls0(names[i], st, NINLIL_R7_BINDING_INVALID_ARGUMENT,
                &f, NULL, NULL, 0, 0, (size_t)-1);
        }
    }

    /* E2E auth zero+ptr */
    e2e_fill(&e2e, &eb, 1, 0, 0, 1);
    e2e.authority_id.bytes = eb.auth;
    e2e.authority_id.length = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, e2e_need(&e2e), &out_len);
    expect_fail_calls0("e2e auth zero+ptr", st, NINLIL_R7_BINDING_INVALID_ARGUMENT,
        &f, NULL, NULL, 0, 0, (size_t)-1);
}

static void test_structural_matrix(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    fake_ctx f;
    uint8_t out[256];
    size_t out_len = 7u;
    int32_t st;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);

    struct {
        const char *name;
        void (*setup)(ninlil_r7_hop_binding_input *, hop_bufs *);
    } hop_bad[] = {
        { 0 }
    };
    (void)hop_bad;

    /* env unknown */
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    hop.environment_code = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop env0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, out_len, 7u);
    hop.environment_code = 3u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop env3", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    /* FIELD site length under/over */
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    hop.site_domain.length = 15u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
    expect_fail_calls0("hop FIELD site15", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    hop.site_domain.length = 16u;
    memset(hb.site, 0, 16u);
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop FIELD site zero", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    hop_bufs_init(&hb);

    /* LAB site 0 / 17 */
    hop_fill(&hop, &hb, 1, 0, 0, 0);
    hop.site_domain.length = 0u;
    hop.site_domain.bytes = NULL;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
    expect_fail_calls0("hop LAB site0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    hop_fill(&hop, &hb, 1, 0, 0, 0);
    hop.site_domain.length = 17u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
    expect_fail_calls0("hop LAB site17", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    /* ID under/over for each relevant hop ID */
    {
        size_t i;
        for (i = 0u; i < 4u; i++) {
            hop_fill(&hop, &hb, 2, 0, 0, 0);
            if (i == 0u) {
                hop.attachment_id.length = 0u;
                hop.attachment_id.bytes = NULL;
            } else if (i == 1u) {
                hop.initiator_stable_id.length = 0u;
                hop.initiator_stable_id.bytes = NULL;
            } else if (i == 2u) {
                hop.responder_stable_id.length = 0u;
                hop.responder_stable_id.bytes = NULL;
            } else {
                hop.controller_authority_id.length = 0u;
                hop.controller_authority_id.bytes = NULL;
                hop.controller_term = 1u; /* mixed also structural via authority matrix */
            }
            fake_reset(&f);
            st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
            expect_true("hop id under", st == NINLIL_R7_BINDING_STRUCTURAL);
            expect_calls("hop id under", f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);

            hop_fill(&hop, &hb, 2, 0, 0, 0);
            if (i == 0u) {
                hop.attachment_id.length = 33u;
            } else if (i == 1u) {
                hop.initiator_stable_id.length = 33u;
            } else if (i == 2u) {
                hop.responder_stable_id.length = 33u;
            } else {
                hop.controller_authority_id.length = 33u;
            }
            fake_reset(&f);
            st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
            expect_true("hop id over", st == NINLIL_R7_BINDING_STRUCTURAL);
            expect_calls("hop id over", f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        }
    }

    /* authority/term mixed both forms LAB */
    hop_fill(&hop, &hb, 1, 0, 0, 1);
    hop.controller_term = 1u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
    expect_fail_calls0("hop mixed term", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    hop_fill(&hop, &hb, 1, 0, 0, 0);
    hop.controller_term = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
    expect_fail_calls0("hop mixed len", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    /* FIELD authority empty */
    hop_fill(&hop, &hb, 2, 0, 0, 1);
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, hop_need(&hop), &out_len);
    expect_fail_calls0("hop FIELD no auth", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    /* zero epochs */
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    hop.membership_epoch = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop mem_ep0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    hop.attachment_epoch = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop att_ep0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    /* context 0 / MAX */
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    hop.hop_context_id = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop ctx0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    hop.hop_context_id = UINT32_MAX;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop ctxMAX", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    /* direction unknown */
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    hop.direction_code = 2u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_fail_calls0("hop dir2", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    /* ---- E2E structural ---- */
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    e2e.environment_code = 9u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
    expect_fail_calls0("e2e env9", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    memset(eb.site, 0, 16u);
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
    expect_fail_calls0("e2e FIELD site0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    e2e_bufs_init(&eb);

    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    e2e.site_domain.length = 15u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, e2e_need(&e2e), &out_len);
    expect_fail_calls0("e2e FIELD site15", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    {
        size_t i;
        for (i = 0u; i < 4u; i++) {
            e2e_fill(&e2e, &eb, 2, 0, 0, 0);
            if (i == 0u) {
                e2e.e2e_security_id.length = 0u;
                e2e.e2e_security_id.bytes = NULL;
            } else if (i == 1u) {
                e2e.sender_stable_id.length = 0u;
                e2e.sender_stable_id.bytes = NULL;
            } else if (i == 2u) {
                e2e.receiver_stable_id.length = 0u;
                e2e.receiver_stable_id.bytes = NULL;
            } else {
                e2e.authority_id.length = 0u;
                e2e.authority_id.bytes = NULL;
            }
            fake_reset(&f);
            st = ninlil_r7_encode_e2e_binding(&e2e, out, e2e_need(&e2e), &out_len);
            expect_true("e2e id under", st == NINLIL_R7_BINDING_STRUCTURAL);
            expect_calls("e2e id under", f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);

            e2e_fill(&e2e, &eb, 2, 0, 0, 0);
            if (i == 0u) {
                e2e.e2e_security_id.length = 33u;
            } else if (i == 1u) {
                e2e.sender_stable_id.length = 33u;
            } else if (i == 2u) {
                e2e.receiver_stable_id.length = 33u;
            } else {
                e2e.authority_id.length = 33u;
            }
            fake_reset(&f);
            st = ninlil_r7_encode_e2e_binding(&e2e, out, e2e_need(&e2e), &out_len);
            expect_true("e2e id over", st == NINLIL_R7_BINDING_STRUCTURAL);
            expect_calls("e2e id over", f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        }
    }

    e2e_fill(&e2e, &eb, 1, 0, 0, 1);
    e2e.authority_term = 1u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, e2e_need(&e2e), &out_len);
    expect_fail_calls0("e2e mixed term", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    e2e_fill(&e2e, &eb, 1, 0, 0, 0);
    e2e.authority_term = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, e2e_need(&e2e), &out_len);
    expect_fail_calls0("e2e mixed len", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    e2e.membership_epoch = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
    expect_fail_calls0("e2e mem0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    e2e.e2e_security_epoch = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
    expect_fail_calls0("e2e sec0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    e2e.e2e_context_id = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
    expect_fail_calls0("e2e ctx0", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
    e2e.e2e_context_id = UINT32_MAX;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
    expect_fail_calls0("e2e ctxMAX", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);

    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    e2e.direction_code = 7u;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, 81u, &out_len);
    expect_fail_calls0("e2e dir7", st, NINLIL_R7_BINDING_STRUCTURAL, &f, NULL, NULL, 0, 0, (size_t)-1);
}

static void test_capacity(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    fake_ctx f;
    uint8_t out[256];
    uint8_t canary[256];
    size_t out_len = 0xABCDu;
    size_t need;
    int32_t st;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    need = hop_need(&hop);
    fill_canary(out, sizeof(out));
    memcpy(canary, out, sizeof(out));
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, need - 1u, &out_len);
    expect_fail_calls0("hop cap under", st, NINLIL_R7_BINDING_CAPACITY, &f, canary, out, sizeof(out), out_len, 0xABCDu);
    st = ninlil_r7_encode_hop_binding(&hop, out, need + 1u, &out_len);
    expect_fail_calls0("hop cap over", st, NINLIL_R7_BINDING_CAPACITY, &f, canary, out, sizeof(out), out_len, 0xABCDu);

    need = e2e_need(&e2e);
    fill_canary(out, sizeof(out));
    memcpy(canary, out, sizeof(out));
    out_len = 0xABCDu;
    fake_reset(&f);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, need - 1u, &out_len);
    expect_fail_calls0("e2e cap under", st, NINLIL_R7_BINDING_CAPACITY, &f, canary, out, sizeof(out), out_len, 0xABCDu);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, need + 1u, &out_len);
    expect_fail_calls0("e2e cap over", st, NINLIL_R7_BINDING_CAPACITY, &f, canary, out, sizeof(out), out_len, 0xABCDu);
}

/* -------------------------------------------------------------------------- */
/* 4. Callback stop points                                                    */
/* -------------------------------------------------------------------------- */

static void test_callback_stops(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t dig[32];
    uint8_t dig_c[32];
    uint8_t secret[32];
    ninlil_r7_hop_key_bundle hbnd;
    ninlil_r7_e2e_key_bundle ebnd;
    int32_t st;
    int k;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    fill_bytes(secret, 32u, 0x66u);

    /* SHA backend */
    fake_reset(&f);
    f.sha_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    make_provider(&p, &f);
    fill_canary(dig, 32u);
    memcpy(dig_c, dig, 32u);
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("sha BE hop dig", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_calls("sha BE hop dig", f.sha_calls, f.extract_calls, f.expand_calls, 1, 0, 0);
    expect_mem_eq("sha BE dig canary", dig, dig_c, 32u);

    fake_reset(&f);
    f.sha_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    make_provider(&p, &f);
    fill_canary(dig, 32u);
    st = ninlil_r7_digest_e2e_binding(&p, &e2e, dig);
    expect_status("sha BE e2e dig", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_calls("sha BE e2e dig", f.sha_calls, f.extract_calls, f.expand_calls, 1, 0, 0);

    /* SHA unknown raw → BACKEND */
    fake_reset(&f);
    f.sha_unknown = 1;
    make_provider(&p, &f);
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("sha unk", st, NINLIL_R7_BINDING_BACKEND_FAILED);

    /* SHA AUTH → INTERNAL */
    fake_reset(&f);
    f.sha_result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
    make_provider(&p, &f);
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("sha AUTH", st, NINLIL_R7_BINDING_INTERNAL_CONTRACT);
    expect_calls("sha AUTH", f.sha_calls, f.extract_calls, f.expand_calls, 1, 0, 0);

    /* mismatch hop + e2e */
    fake_reset(&f);
    make_provider(&p, &f);
    fill_canary((uint8_t *)&hbnd, sizeof(hbnd));
    {
        uint8_t wrong[32];
        fill_bytes(wrong, 32u, 0xEEu);
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, wrong, secret, &hbnd);
    }
    expect_status("mm hop", st, NINLIL_R7_BINDING_MISMATCH);
    expect_calls("mm hop", f.sha_calls, f.extract_calls, f.expand_calls, 1, 0, 0);
    expect_true("mm hop canary", is_canary((uint8_t *)&hbnd, sizeof(hbnd)));

    fake_reset(&f);
    make_provider(&p, &f);
    fill_canary((uint8_t *)&ebnd, sizeof(ebnd));
    {
        uint8_t wrong[32];
        fill_bytes(wrong, 32u, 0xEEu);
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            &p, &e2e, wrong, secret, &ebnd);
    }
    expect_status("mm e2e", st, NINLIL_R7_BINDING_MISMATCH);
    expect_calls("mm e2e", f.sha_calls, f.extract_calls, f.expand_calls, 1, 0, 0);
    expect_true("mm e2e canary", is_canary((uint8_t *)&ebnd, sizeof(ebnd)));

    /* Extract backend / unknown / AUTH for hop and e2e */
    fake_reset(&f);
    f.extract_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    make_provider(&p, &f);
    fill_canary((uint8_t *)&hbnd, sizeof(hbnd));
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, f.digest32, secret, &hbnd);
    expect_status("ex BE hop", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_calls("ex BE hop", f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, 0);
    expect_true("ex BE hop canary", is_canary((uint8_t *)&hbnd, sizeof(hbnd)));

    fake_reset(&f);
    f.extract_unknown = 1;
    make_provider(&p, &f);
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, f.digest32, secret, &hbnd);
    expect_status("ex unk hop", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_calls("ex unk hop", f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, 0);

    fake_reset(&f);
    f.extract_result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
    make_provider(&p, &f);
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, f.digest32, secret, &hbnd);
    expect_status("ex AUTH hop", st, NINLIL_R7_BINDING_INTERNAL_CONTRACT);
    expect_calls("ex AUTH hop", f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, 0);

    fake_reset(&f);
    f.extract_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    make_provider(&p, &f);
    fill_canary((uint8_t *)&ebnd, sizeof(ebnd));
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, f.digest32, secret, &ebnd);
    expect_status("ex BE e2e", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_calls("ex BE e2e", f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, 0);

    fake_reset(&f);
    f.extract_result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
    make_provider(&p, &f);
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, f.digest32, secret, &ebnd);
    expect_status("ex AUTH e2e", st, NINLIL_R7_BINDING_INTERNAL_CONTRACT);

    /* Hop Expand 1..4 backend / unknown / AUTH */
    for (k = 1; k <= 4; k++) {
        char name[48];
        fake_reset(&f);
        f.expand_fail_after = k;
        make_provider(&p, &f);
        fill_canary((uint8_t *)&hbnd, sizeof(hbnd));
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, f.digest32, secret, &hbnd);
        snprintf(name, sizeof(name), "hop exp BE@%d", k);
        expect_status(name, st, NINLIL_R7_BINDING_BACKEND_FAILED);
        expect_calls(name, f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, k);
        expect_true(name, is_canary((uint8_t *)&hbnd, sizeof(hbnd)));

        fake_reset(&f);
        f.expand_unknown_after = k;
        make_provider(&p, &f);
        fill_canary((uint8_t *)&hbnd, sizeof(hbnd));
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, f.digest32, secret, &hbnd);
        snprintf(name, sizeof(name), "hop exp UNK@%d", k);
        expect_status(name, st, NINLIL_R7_BINDING_BACKEND_FAILED);
        expect_calls(name, f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, k);

        fake_reset(&f);
        f.expand_auth_after = k;
        make_provider(&p, &f);
        fill_canary((uint8_t *)&hbnd, sizeof(hbnd));
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, f.digest32, secret, &hbnd);
        snprintf(name, sizeof(name), "hop exp AUTH@%d", k);
        expect_status(name, st, NINLIL_R7_BINDING_INTERNAL_CONTRACT);
        expect_calls(name, f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, k);
        expect_true(name, is_canary((uint8_t *)&hbnd, sizeof(hbnd)));
    }

    /* E2E Expand 1..2 */
    for (k = 1; k <= 2; k++) {
        char name[48];
        fake_reset(&f);
        f.expand_fail_after = k;
        make_provider(&p, &f);
        fill_canary((uint8_t *)&ebnd, sizeof(ebnd));
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            &p, &e2e, f.digest32, secret, &ebnd);
        snprintf(name, sizeof(name), "e2e exp BE@%d", k);
        expect_status(name, st, NINLIL_R7_BINDING_BACKEND_FAILED);
        expect_calls(name, f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, k);

        fake_reset(&f);
        f.expand_unknown_after = k;
        make_provider(&p, &f);
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            &p, &e2e, f.digest32, secret, &ebnd);
        snprintf(name, sizeof(name), "e2e exp UNK@%d", k);
        expect_status(name, st, NINLIL_R7_BINDING_BACKEND_FAILED);
        expect_calls(name, f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, k);

        fake_reset(&f);
        f.expand_auth_after = k;
        make_provider(&p, &f);
        fill_canary((uint8_t *)&ebnd, sizeof(ebnd));
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            &p, &e2e, f.digest32, secret, &ebnd);
        snprintf(name, sizeof(name), "e2e exp AUTH@%d", k);
        expect_status(name, st, NINLIL_R7_BINDING_INTERNAL_CONTRACT);
        expect_calls(name, f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, k);
        expect_true(name, is_canary((uint8_t *)&ebnd, sizeof(ebnd)));
    }
}

/* -------------------------------------------------------------------------- */
/* 5. Mutation zero on representative classes                                 */
/* -------------------------------------------------------------------------- */

static void test_mutation_zero_classes(void)
{
    hop_bufs hb, hb_snap;
    e2e_bufs eb, eb_snap;
    ninlil_r7_hop_binding_input hop, hop_snap;
    ninlil_r7_e2e_binding_input e2e, e2e_snap;
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t out[256], out_c[256];
    size_t out_len, out_len_c;
    uint8_t dig[32], dig_c[32];
    uint8_t secret[32], secret_c[32];
    uint8_t exp[32], exp_c[32];
    ninlil_r7_hop_key_bundle b, b_c;
    ninlil_r7_e2e_key_bundle ebnd, ebnd_c;
    size_t need;
    int32_t st;

    hop_bufs_init(&hb);
    hop_bufs_init(&hb_snap);
    e2e_bufs_init(&eb);
    e2e_bufs_init(&eb_snap);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    hop_fill(&hop_snap, &hb_snap, 2, 0, 0, 0);
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    e2e_fill(&e2e_snap, &eb_snap, 2, 0, 0, 0);
    need = hop_need(&hop);
    fill_bytes(secret, 32u, 0x99u);
    memcpy(secret_c, secret, 32u);
    fill_bytes(exp, 32u, 0xD0u);
    memcpy(exp_c, exp, 32u);

    /* structural */
    fill_canary(out, sizeof(out));
    memcpy(out_c, out, sizeof(out));
    out_len = out_len_c = 0x1111u;
    hop.hop_context_id = 0u;
    fake_reset(&f);
    st = ninlil_r7_encode_hop_binding(&hop, out, need, &out_len);
    expect_status("mut struct", st, NINLIL_R7_BINDING_STRUCTURAL);
    expect_mem_eq("mut struct out", out, out_c, sizeof(out));
    expect_true("mut struct len", out_len == out_len_c);
    expect_mem_eq("mut struct site", hb.site, hb_snap.site, 16u);
    hop.hop_context_id = 1u;

    /* capacity */
    st = ninlil_r7_encode_hop_binding(&hop, out, need + 1u, &out_len);
    expect_status("mut cap", st, NINLIL_R7_BINDING_CAPACITY);
    expect_mem_eq("mut cap out", out, out_c, sizeof(out));
    expect_true("mut cap len", out_len == out_len_c);

    /* alias (out overlaps site) */
    {
        uint8_t site_out[256];
        fill_bytes(site_out, 16u, 0x10u);
        hop.site_domain.bytes = site_out;
        fill_canary(site_out + 16u, 200u);
        out_len = 0x2222u;
        fake_reset(&f);
        st = ninlil_r7_encode_hop_binding(&hop, site_out, need, &out_len);
        expect_status("mut alias", st, NINLIL_R7_BINDING_ALIAS);
        expect_calls("mut alias", f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        expect_true("mut alias len", out_len == 0x2222u);
        hop.site_domain.bytes = hb.site;
    }

    /* digest backend */
    fake_reset(&f);
    f.sha_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    make_provider(&p, &f);
    fill_canary(dig, 32u);
    memcpy(dig_c, dig, 32u);
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("mut dig BE", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_mem_eq("mut dig", dig, dig_c, 32u);
    expect_mem_eq("mut dig site", hb.site, hb_snap.site, 16u);

    /* mismatch */
    fake_reset(&f);
    make_provider(&p, &f);
    fill_canary((uint8_t *)&b, sizeof(b));
    memcpy(&b_c, &b, sizeof(b));
    {
        uint8_t wrong[32];
        fill_bytes(wrong, 32u, 0x01u);
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, wrong, secret, &b);
    }
    expect_status("mut mm", st, NINLIL_R7_BINDING_MISMATCH);
    expect_mem_eq("mut mm b", &b, &b_c, sizeof(b));
    expect_mem_eq("mut mm sec", secret, secret_c, 32u);
    expect_mem_eq("mut mm exp", exp, exp_c, 32u);

    /* extract fail */
    fake_reset(&f);
    f.extract_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    make_provider(&p, &f);
    fill_canary((uint8_t *)&b, sizeof(b));
    memcpy(&b_c, &b, sizeof(b));
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, f.digest32, secret, &b);
    expect_status("mut ex", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_mem_eq("mut ex b", &b, &b_c, sizeof(b));
    expect_mem_eq("mut ex sec", secret, secret_c, 32u);

    /* e2e expand fail */
    fake_reset(&f);
    f.expand_fail_after = 1;
    make_provider(&p, &f);
    fill_canary((uint8_t *)&ebnd, sizeof(ebnd));
    memcpy(&ebnd_c, &ebnd, sizeof(ebnd));
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, f.digest32, secret, &ebnd);
    expect_status("mut e2e exp", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_mem_eq("mut e2e b", &ebnd, &ebnd_c, sizeof(ebnd));
    expect_mem_eq("mut e2e site", eb.site, eb_snap.site, 16u);
}

/* -------------------------------------------------------------------------- */
/* 6. Alias matrix                                                            */
/* -------------------------------------------------------------------------- */

static void test_alias_complete(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t secret[32];
    size_t out_len;
    size_t need;
    int32_t st;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    need = hop_need(&hop);
    fill_bytes(secret, 32u, 0x55u);
    fake_reset(&f);
    make_provider(&p, &f);

    /* encode: out overlaps top-level */
    {
        uint8_t arena[512];
        ninlil_r7_hop_binding_input *hin =
            (ninlil_r7_hop_binding_input *)(void *)arena;
        *hin = hop;
        out_len = 0u;
        fake_reset(&f);
        st = ninlil_r7_encode_hop_binding(hin, arena + 4u, need, &out_len);
        expect_fail_calls0("alias hop out/in", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }

    /* encode: out overlaps each pointed span */
    {
        const char *names[] = {
            "alias hop out/site", "alias hop out/att", "alias hop out/init",
            "alias hop out/resp", "alias hop out/auth"
        };
        size_t i;
        for (i = 0u; i < 5u; i++) {
            uint8_t buf[256];
            fill_bytes(buf, 32u, 0x20u);
            hop_fill(&hop, &hb, 2, 0, 0, 0);
            if (i == 0u) {
                hop.site_domain.bytes = buf;
            } else if (i == 1u) {
                hop.attachment_id.bytes = buf;
            } else if (i == 2u) {
                hop.initiator_stable_id.bytes = buf;
            } else if (i == 3u) {
                hop.responder_stable_id.bytes = buf;
            } else {
                hop.controller_authority_id.bytes = buf;
            }
            out_len = 0u;
            fake_reset(&f);
            st = ninlil_r7_encode_hop_binding(&hop, buf, need, &out_len);
            expect_fail_calls0(names[i], st, NINLIL_R7_BINDING_ALIAS,
                &f, NULL, NULL, 0, 0, (size_t)-1);
        }
        hop_fill(&hop, &hb, 2, 0, 0, 0);
    }

    /* encode out/out_len */
    {
        uint8_t arena[sizeof(size_t) + 256u];
        size_t *ol = (size_t *)(void *)arena;
        *ol = 0u;
        fake_reset(&f);
        st = ninlil_r7_encode_hop_binding(
            &hop, (uint8_t *)(void *)ol, need, ol);
        expect_fail_calls0("alias hop out/len", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }

    /* digest: out overlaps provider / input / each span */
    {
        uint8_t storage[sizeof(ninlil_r7_crypto_provider) + 64u];
        ninlil_r7_crypto_provider *pp =
            (ninlil_r7_crypto_provider *)(void *)storage;
        make_provider(pp, &f);
        fake_reset(&f);
        st = ninlil_r7_digest_hop_binding(pp, &hop, storage + 8u);
        expect_fail_calls0("alias dig hop/prov", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }
    {
        uint8_t arena[512];
        ninlil_r7_hop_binding_input *hin =
            (ninlil_r7_hop_binding_input *)(void *)arena;
        *hin = hop;
        fake_reset(&f);
        make_provider(&p, &f);
        st = ninlil_r7_digest_hop_binding(&p, hin, arena + 4u);
        expect_fail_calls0("alias dig hop/in", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }
    {
        size_t i;
        for (i = 0u; i < 5u; i++) {
            uint8_t buf[64];
            fill_bytes(buf, 32u, 0x30u);
            hop_fill(&hop, &hb, 2, 0, 0, 0);
            if (i == 0u) {
                hop.site_domain.bytes = buf;
            } else if (i == 1u) {
                hop.attachment_id.bytes = buf;
            } else if (i == 2u) {
                hop.initiator_stable_id.bytes = buf;
            } else if (i == 3u) {
                hop.responder_stable_id.bytes = buf;
            } else {
                hop.controller_authority_id.bytes = buf;
            }
            fake_reset(&f);
            make_provider(&p, &f);
            st = ninlil_r7_digest_hop_binding(&p, &hop, buf);
            expect_true("alias dig hop span", st == NINLIL_R7_BINDING_ALIAS);
            expect_calls("alias dig hop span",
                f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        }
        hop_fill(&hop, &hb, 2, 0, 0, 0);
    }

    /* derive hop: bundle vs provider/input/spans/expected/secret */
    {
        uint8_t storage[sizeof(ninlil_r7_crypto_provider) + 128u];
        ninlil_r7_crypto_provider *pp =
            (ninlil_r7_crypto_provider *)(void *)storage;
        ninlil_r7_hop_key_bundle *b =
            (ninlil_r7_hop_key_bundle *)(void *)(storage + 8u);
        make_provider(pp, &f);
        fake_reset(&f);
        st = ninlil_r7_derive_hop_key_bundle_verified(
            pp, &hop, f.digest32, secret, b);
        expect_fail_calls0("alias der hop/prov", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }
    {
        uint8_t storage[sizeof(ninlil_r7_hop_key_bundle) + 64u];
        ninlil_r7_hop_key_bundle *b =
            (ninlil_r7_hop_key_bundle *)(void *)storage;
        uint8_t *exp = storage + 4u;
        memcpy(exp, f.digest32, 32u);
        fill_canary((uint8_t *)b, sizeof(*b));
        fake_reset(&f);
        make_provider(&p, &f);
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, exp, secret, b);
        expect_status("alias der hop/exp", st, NINLIL_R7_BINDING_ALIAS);
        expect_true("alias der hop/exp canary",
            is_canary((uint8_t *)b, sizeof(*b)));
        expect_calls("alias der hop/exp",
            f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
    }
    {
        uint8_t storage[128];
        ninlil_r7_hop_key_bundle *b =
            (ninlil_r7_hop_key_bundle *)(void *)storage;
        uint8_t *sec = storage + 8u;
        memcpy(sec, secret, 32u);
        fake_reset(&f);
        make_provider(&p, &f);
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, f.digest32, sec, b);
        expect_fail_calls0("alias der hop/sec", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }
    {
        size_t i;
        for (i = 0u; i < 5u; i++) {
            uint8_t buf[128];
            ninlil_r7_hop_key_bundle *b =
                (ninlil_r7_hop_key_bundle *)(void *)buf;
            hop_fill(&hop, &hb, 2, 0, 0, 0);
            if (i == 0u) {
                hop.site_domain.bytes = buf + 8u;
            } else if (i == 1u) {
                hop.attachment_id.bytes = buf + 8u;
            } else if (i == 2u) {
                hop.initiator_stable_id.bytes = buf + 8u;
            } else if (i == 3u) {
                hop.responder_stable_id.bytes = buf + 8u;
            } else {
                hop.controller_authority_id.bytes = buf + 8u;
            }
            fill_bytes(buf + 8u, 32u, 0x40u);
            fake_reset(&f);
            make_provider(&p, &f);
            st = ninlil_r7_derive_hop_key_bundle_verified(
                &p, &hop, f.digest32, secret, b);
            expect_true("alias der hop span", st == NINLIL_R7_BINDING_ALIAS);
            expect_calls("alias der hop span",
                f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        }
        hop_fill(&hop, &hb, 2, 0, 0, 0);
    }

    /* E2E encode/digest/derive alias samples for each span + provider + out_len */
    need = e2e_need(&e2e);
    {
        uint8_t arena[512];
        ninlil_r7_e2e_binding_input *ein =
            (ninlil_r7_e2e_binding_input *)(void *)arena;
        *ein = e2e;
        out_len = 0u;
        fake_reset(&f);
        st = ninlil_r7_encode_e2e_binding(ein, arena + 4u, need, &out_len);
        expect_fail_calls0("alias e2e out/in", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }
    {
        size_t i;
        for (i = 0u; i < 5u; i++) {
            uint8_t buf[256];
            fill_bytes(buf, 32u, 0x21u);
            e2e_fill(&e2e, &eb, 2, 0, 0, 0);
            if (i == 0u) {
                e2e.site_domain.bytes = buf;
            } else if (i == 1u) {
                e2e.e2e_security_id.bytes = buf;
            } else if (i == 2u) {
                e2e.sender_stable_id.bytes = buf;
            } else if (i == 3u) {
                e2e.receiver_stable_id.bytes = buf;
            } else {
                e2e.authority_id.bytes = buf;
            }
            out_len = 0u;
            fake_reset(&f);
            st = ninlil_r7_encode_e2e_binding(&e2e, buf, need, &out_len);
            expect_true("alias e2e out/span", st == NINLIL_R7_BINDING_ALIAS);
            expect_calls("alias e2e out/span",
                f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        }
        e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    }
    {
        uint8_t arena[sizeof(size_t) + 256u];
        size_t *ol = (size_t *)(void *)arena;
        *ol = 0u;
        fake_reset(&f);
        st = ninlil_r7_encode_e2e_binding(
            &e2e, (uint8_t *)(void *)ol, need, ol);
        expect_fail_calls0("alias e2e out/len", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }
    {
        uint8_t storage[sizeof(ninlil_r7_crypto_provider) + 64u];
        ninlil_r7_crypto_provider *pp =
            (ninlil_r7_crypto_provider *)(void *)storage;
        make_provider(pp, &f);
        fake_reset(&f);
        st = ninlil_r7_digest_e2e_binding(pp, &e2e, storage + 8u);
        expect_fail_calls0("alias dig e2e/prov", st, NINLIL_R7_BINDING_ALIAS,
            &f, NULL, NULL, 0, 0, (size_t)-1);
    }
    {
        uint8_t storage[128];
        ninlil_r7_e2e_key_bundle *b =
            (ninlil_r7_e2e_key_bundle *)(void *)storage;
        uint8_t *exp = storage + 4u; /* overlaps b (sizeof b == 28) */
        uint8_t *sec = storage + 8u; /* also overlaps b */
        memcpy(exp, f.digest32, 32u);
        memcpy(sec, secret, 32u);
        fake_reset(&f);
        make_provider(&p, &f);
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            &p, &e2e, exp, secret, b);
        expect_status("alias der e2e/exp", st, NINLIL_R7_BINDING_ALIAS);
        expect_calls("alias der e2e/exp",
            f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        fake_reset(&f);
        make_provider(&p, &f);
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            &p, &e2e, f.digest32, sec, b);
        expect_status("alias der e2e/sec", st, NINLIL_R7_BINDING_ALIAS);
        expect_calls("alias der e2e/sec",
            f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
    }
    {
        size_t i;
        for (i = 0u; i < 5u; i++) {
            uint8_t buf[128];
            ninlil_r7_e2e_key_bundle *b =
                (ninlil_r7_e2e_key_bundle *)(void *)buf;
            e2e_fill(&e2e, &eb, 2, 0, 0, 0);
            if (i == 0u) {
                e2e.site_domain.bytes = buf + 4u;
            } else if (i == 1u) {
                e2e.e2e_security_id.bytes = buf + 4u;
            } else if (i == 2u) {
                e2e.sender_stable_id.bytes = buf + 4u;
            } else if (i == 3u) {
                e2e.receiver_stable_id.bytes = buf + 4u;
            } else {
                e2e.authority_id.bytes = buf + 4u;
            }
            fill_bytes(buf + 4u, 32u, 0x41u);
            fake_reset(&f);
            make_provider(&p, &f);
            st = ninlil_r7_derive_e2e_key_bundle_verified(
                &p, &e2e, f.digest32, secret, b);
            expect_true("alias der e2e span", st == NINLIL_R7_BINDING_ALIAS);
            expect_calls("alias der e2e span",
                f.sha_calls, f.extract_calls, f.expand_calls, 0, 0, 0);
        }
    }

    /* RO/RO allowed: expected==secret; site==att */
    {
        uint8_t both[32];
        ninlil_r7_hop_key_bundle b;
        fake_reset(&f);
        make_provider(&p, &f);
        memcpy(both, f.digest32, 32u);
        hop_fill(&hop, &hb, 2, 0, 0, 0);
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, both, both, &b);
        expect_status("ro/ro exp==sec", st, NINLIL_R7_BINDING_OK);
        expect_calls("ro/ro exp==sec", f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, 4);
    }
    {
        uint8_t shared[32];
        uint8_t out[256];
        fill_bytes(shared, 32u, 0x22u);
        hop_fill(&hop, &hb, 1, 0, 0, 0);
        hop.site_domain.bytes = shared;
        hop.site_domain.length = 1u;
        hop.attachment_id.bytes = shared;
        hop.attachment_id.length = 1u;
        hop.initiator_stable_id.bytes = shared + 2u;
        hop.responder_stable_id.bytes = shared + 3u;
        hop.controller_authority_id.bytes = shared + 4u;
        need = hop_need(&hop);
        out_len = 0u;
        st = ninlil_r7_encode_hop_binding(&hop, out, need, &out_len);
        expect_status("ro/ro site==att", st, NINLIL_R7_BINDING_OK);
    }
    {
        uint8_t both[32];
        ninlil_r7_e2e_key_bundle b;
        fake_reset(&f);
        make_provider(&p, &f);
        memcpy(both, f.digest32, 32u);
        e2e_fill(&e2e, &eb, 2, 0, 0, 0);
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            &p, &e2e, both, both, &b);
        expect_status("ro/ro e2e exp==sec", st, NINLIL_R7_BINDING_OK);
        expect_calls("ro/ro e2e", f.sha_calls, f.extract_calls, f.expand_calls, 1, 1, 2);
    }
}

/* -------------------------------------------------------------------------- */
/* 7. Pointer-end overflow via test seam (no dereference)                     */
/* -------------------------------------------------------------------------- */

static void test_pointer_end_overflow_seam(void)
{
    const void *near_end = (const void *)(uintptr_t)(UINTPTR_MAX - 3u);
    const void *base = (const void *)(uintptr_t)0x1000u;
    const void *nullp = NULL;

    expect_true("ovf end a",
        ninlil_r7_binding_test_spans_forbidden(near_end, 16u, base, 8u) == 1);
    expect_true("ovf end b",
        ninlil_r7_binding_test_spans_forbidden(base, 8u, near_end, 16u) == 1);
    expect_true("ovf huge len",
        ninlil_r7_binding_test_spans_forbidden(
            base,
            (size_t)UINTPTR_MAX,
            (const void *)(uintptr_t)0x1001u,
            1u)
            == 1);
    expect_true("null non-empty forbidden",
        ninlil_r7_binding_test_spans_forbidden(nullp, 8u, base, 8u) == 1);
    expect_true("empty ok",
        ninlil_r7_binding_test_spans_forbidden(near_end, 0u, base, 8u) == 0);
    expect_true("adjacent ok",
        ninlil_r7_binding_test_spans_forbidden(
            (const void *)(uintptr_t)0x1000u, 8u,
            (const void *)(uintptr_t)0x1008u, 8u)
            == 0);
    expect_true("overlap",
        ninlil_r7_binding_test_spans_forbidden(
            (const void *)(uintptr_t)0x1000u, 8u,
            (const void *)(uintptr_t)0x1004u, 8u)
            == 1);
}

/* -------------------------------------------------------------------------- */
/* 8. Secure-zero exact evidence                                              */
/* -------------------------------------------------------------------------- */

static void test_secure_zero_evidence(void)
{
    hop_bufs hb;
    e2e_bufs eb;
    ninlil_r7_hop_binding_input hop;
    ninlil_r7_e2e_binding_input e2e;
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t out[256];
    size_t out_len;
    uint8_t dig[32];
    uint8_t secret[32];
    ninlil_r7_hop_key_bundle hbnd;
    ninlil_r7_e2e_key_bundle ebnd;
    ninlil_r7_binding_test_secret_probe pr;
    uint8_t region[256];
    int32_t st;
    size_t need;
    size_t i;
    int allz;

    hop_bufs_init(&hb);
    e2e_bufs_init(&eb);
    hop_fill(&hop, &hb, 2, 0, 0, 0);
    e2e_fill(&e2e, &eb, 2, 0, 0, 0);
    fill_bytes(secret, 32u, 0xAAu);
    need = hop_need(&hop);

    /* encode hop success: exact {207} */
    probe_clear(&pr, region, sizeof(region));
    st = ninlil_r7_encode_hop_binding(&hop, out, need, &out_len);
    expect_status("z enc hop", st, NINLIL_R7_BINDING_OK);
    expect_true("z enc hop log",
        probe_exact_log(&pr, k_hop_encode_zeros,
            sizeof(k_hop_encode_zeros) / sizeof(k_hop_encode_zeros[0])));
    expect_size("z enc hop bytes", pr.zero_bytes, 207u);
    expect_true("z enc hop has 207", probe_has_size(&pr, 207u));

    /* encode e2e success: exact {205} */
    probe_clear(&pr, region, sizeof(region));
    need = e2e_need(&e2e);
    st = ninlil_r7_encode_e2e_binding(&e2e, out, need, &out_len);
    expect_status("z enc e2e", st, NINLIL_R7_BINDING_OK);
    expect_true("z enc e2e log",
        probe_exact_log(&pr, k_e2e_encode_zeros,
            sizeof(k_e2e_encode_zeros) / sizeof(k_e2e_encode_zeros[0])));
    expect_size("z enc e2e bytes", pr.zero_bytes, 205u);

    /* digest hop: {207,32} */
    fake_reset(&f);
    make_provider(&p, &f);
    probe_clear(&pr, region, sizeof(region));
    st = ninlil_r7_digest_hop_binding(&p, &hop, dig);
    expect_status("z dig hop", st, NINLIL_R7_BINDING_OK);
    expect_true("z dig hop log",
        probe_exact_log(&pr, k_hop_digest_zeros,
            sizeof(k_hop_digest_zeros) / sizeof(k_hop_digest_zeros[0])));
    expect_true("z dig hop 207", probe_has_size(&pr, 207u));
    expect_true("z dig hop 32", probe_has_size(&pr, 32u));

    /* digest e2e: {205,32} */
    probe_clear(&pr, region, sizeof(region));
    st = ninlil_r7_digest_e2e_binding(&p, &e2e, dig);
    expect_status("z dig e2e", st, NINLIL_R7_BINDING_OK);
    expect_true("z dig e2e log",
        probe_exact_log(&pr, k_e2e_digest_zeros,
            sizeof(k_e2e_digest_zeros) / sizeof(k_e2e_digest_zeros[0])));

    /* hop derive success: full multiset */
    fake_reset(&f);
    make_provider(&p, &f);
    probe_clear(&pr, region, sizeof(region));
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, f.digest32, secret, &hbnd);
    expect_status("z der hop", st, NINLIL_R7_BINDING_OK);
    expect_true("z der hop log",
        probe_exact_log(&pr, k_hop_derive_zeros,
            sizeof(k_hop_derive_zeros) / sizeof(k_hop_derive_zeros[0])));
    expect_true("z der hop has 207", probe_has_size(&pr, 207u));
    expect_true("z der hop has 32", probe_has_size(&pr, 32u));
    expect_true("z der hop has 16", probe_has_size(&pr, 16u));
    expect_true("z der hop has 12", probe_has_size(&pr, 12u));
    /* total bytes: 207+32+32+32+16+12+16+12 = 359 */
    expect_size("z der hop bytes", pr.zero_bytes, 359u);
    allz = 1;
    for (i = 0u; i < pr.last_len && i < pr.capacity; i++) {
        if (region[i] != 0u) {
            allz = 0;
        }
    }
    expect_true("z der hop post-zero", allz);

    /* e2e derive success */
    fake_reset(&f);
    make_provider(&p, &f);
    probe_clear(&pr, region, sizeof(region));
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, f.digest32, secret, &ebnd);
    expect_status("z der e2e", st, NINLIL_R7_BINDING_OK);
    expect_true("z der e2e log",
        probe_exact_log(&pr, k_e2e_derive_zeros,
            sizeof(k_e2e_derive_zeros) / sizeof(k_e2e_derive_zeros[0])));
    /* 205+32+32+32+16+12 = 329 */
    expect_size("z der e2e bytes", pr.zero_bytes, 329u);
    expect_true("z der e2e 205", probe_has_size(&pr, 205u));
    expect_true("z der e2e 16", probe_has_size(&pr, 16u));
    expect_true("z der e2e 12", probe_has_size(&pr, 12u));

    /* mismatch still zeros full hop set */
    fake_reset(&f);
    make_provider(&p, &f);
    probe_clear(&pr, region, sizeof(region));
    {
        uint8_t wrong[32];
        fill_bytes(wrong, 32u, 0x01u);
        st = ninlil_r7_derive_hop_key_bundle_verified(
            &p, &hop, wrong, secret, &hbnd);
    }
    expect_status("z mm hop", st, NINLIL_R7_BINDING_MISMATCH);
    expect_true("z mm hop log",
        probe_exact_log(&pr, k_hop_derive_zeros,
            sizeof(k_hop_derive_zeros) / sizeof(k_hop_derive_zeros[0])));

    /* backend expand fail still full zero set */
    fake_reset(&f);
    f.expand_fail_after = 2;
    make_provider(&p, &f);
    probe_clear(&pr, region, sizeof(region));
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &p, &hop, f.digest32, secret, &hbnd);
    expect_status("z be hop", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_true("z be hop log",
        probe_exact_log(&pr, k_hop_derive_zeros,
            sizeof(k_hop_derive_zeros) / sizeof(k_hop_derive_zeros[0])));

    fake_reset(&f);
    f.expand_fail_after = 1;
    make_provider(&p, &f);
    probe_clear(&pr, region, sizeof(region));
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &p, &e2e, f.digest32, secret, &ebnd);
    expect_status("z be e2e", st, NINLIL_R7_BINDING_BACKEND_FAILED);
    expect_true("z be e2e log",
        probe_exact_log(&pr, k_e2e_derive_zeros,
            sizeof(k_e2e_derive_zeros) / sizeof(k_e2e_derive_zeros[0])));

    /* prevalidation: zero_calls == 0 */
    probe_clear(&pr, region, sizeof(region));
    hop.membership_epoch = 0u;
    st = ninlil_r7_encode_hop_binding(&hop, out, 83u, &out_len);
    expect_status("z preval", st, NINLIL_R7_BINDING_STRUCTURAL);
    expect_true("z preval 0", pr.zero_calls == 0u);
    hop.membership_epoch = 1u;

    probe_off();
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

int main(void)
{
    test_positive_matrix();
    test_encode_field_sensitivity();
    test_null_and_provider_shape();
    test_opaque_shape_every_field();
    test_structural_matrix();
    test_capacity();
    test_callback_stops();
    test_mutation_zero_classes();
    test_alias_complete();
    test_pointer_end_overflow_seam();
    test_secure_zero_evidence();

    if (g_failures != 0) {
        fprintf(stderr, "r7_t1b_binding_test: %d failures / %d checks\n",
            g_failures, g_tests);
        return 1;
    }
    printf("r7_t1b_binding_test: OK (%d checks)\n", g_tests);
    return 0;
}
