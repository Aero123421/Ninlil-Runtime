/*
 * r7-radio-wire-v1 fixture authority (docs/30 §18):
 *   - CMake-registered host test
 *   - Production r7_frag / r7_wire codec + crypto AEAD over fixed vectors
 *   - Negative mutation cases (tag flip, ciphertext flip, truncated frame)
 * HIL remains NOT_RUN.
 */
#include "r7_radio_wire_v1_fixture.h"

#include "r7_crypto_openssl3.h"
#include "r7_crypto_provider.h"
#include "r7_frag.h"
#include "r7_wire_codec.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void expect(const char *name, int cond)
{
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        g_fail++;
    }
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

static int hex_decode(
    const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n;
    size_t i;
    if (hex == NULL || out == NULL || out_len == NULL) {
        return 1;
    }
    n = strlen(hex);
    if ((n % 2u) != 0u) {
        return 1;
    }
    n /= 2u;
    if (n > out_cap) {
        return 1;
    }
    for (i = 0u; i < n; i++) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return 1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return 0;
}

/* AEAD rows: CT||TAG sealed form via production portable wrapper or raw. */
static int aead_roundtrip_row(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_r7_radio_wire_v1_row_t *r)
{
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[256];
    uint8_t pt[512];
    uint8_t ct_exp[512];
    uint8_t tag_exp[16];
    uint8_t sealed_exp[528];
    uint8_t sealed_got[528];
    uint8_t pt_got[512];
    size_t key_len = 0u, nonce_len = 0u, aad_len = 0u, pt_len = 0u;
    size_t ct_len = 0u, tag_len = 0u, sealed_len = 0u, pt_out = 0u;
    ninlil_r7_crypto_status st;
    ninlil_r7_crypto_raw_status rst;
    int is_bad_tag;

    if (r->key_hex == NULL || r->key_hex[0] == '\0') {
        return 0;
    }
    if (hex_decode(r->key_hex, key, sizeof(key), &key_len) != 0 || key_len != 16u) {
        return 1;
    }
    if (hex_decode(r->nonce_hex, nonce, sizeof(nonce), &nonce_len) != 0
        || nonce_len != 12u) {
        return 1;
    }
    aad_len = 0u;
    if (r->aad_hex != NULL && r->aad_hex[0] != '\0') {
        if (hex_decode(r->aad_hex, aad, sizeof(aad), &aad_len) != 0) {
            return 1;
        }
    }
    pt_len = 0u;
    if (r->plaintext_hex != NULL && r->plaintext_hex[0] != '\0') {
        if (hex_decode(r->plaintext_hex, pt, sizeof(pt), &pt_len) != 0) {
            return 1;
        }
    }
    if (r->ciphertext_hex == NULL || r->tag_hex == NULL
        || r->tag_hex[0] == '\0') {
        return 1;
    }
    ct_len = 0u;
    if (r->ciphertext_hex[0] != '\0') {
        if (hex_decode(r->ciphertext_hex, ct_exp, sizeof(ct_exp), &ct_len)
            != 0) {
            return 1;
        }
    }
    if (hex_decode(r->tag_hex, tag_exp, sizeof(tag_exp), &tag_len) != 0
        || tag_len != 16u) {
        return 1;
    }
    if (ct_len + 16u > sizeof(sealed_exp)) {
        return 1;
    }
    memcpy(sealed_exp, ct_exp, ct_len);
    memcpy(sealed_exp + ct_len, tag_exp, 16u);
    sealed_len = ct_len + 16u;
    is_bad_tag = (strcmp(r->id, "gcm_nist_one_block_bad_tag") == 0);

    /* Prefer portable wrapper when domain fits R7 portable bounds. */
    if (aad_len <= NINLIL_R7_CRYPTO_AAD_MAX
        && pt_len <= NINLIL_R7_CRYPTO_BODY_MAX) {
        st = ninlil_r7_crypto_aes128_gcm_seal(
            crypto, key, nonce, aad, aad_len, pt, pt_len, sealed_got,
            pt_len + 16u, &sealed_len);
        if (st != NINLIL_R7_CRYPTO_OK) {
            return 1;
        }
        if (!is_bad_tag) {
            if (sealed_len != ct_len + 16u
                || memcmp(sealed_got, sealed_exp, sealed_len) != 0) {
                return 1;
            }
        }
        st = ninlil_r7_crypto_aes128_gcm_open(
            crypto, key, nonce, aad, aad_len, sealed_exp, sealed_len, pt_got,
            ct_len, &pt_out);
        if (is_bad_tag) {
            return (st != NINLIL_R7_CRYPTO_OK) ? 0 : 1;
        }
        if (st != NINLIL_R7_CRYPTO_OK || pt_out != pt_len) {
            return 1;
        }
        if (pt_len > 0u && memcmp(pt_got, pt, pt_len) != 0) {
            return 1;
        }
    } else {
        /* NIST vectors may exceed portable AAD max: raw provider path. */
        rst = crypto->aes128_gcm_seal(
            crypto->ctx, key, nonce, aad, aad_len, pt, pt_len, sealed_got,
            pt_len + 16u, &sealed_len);
        if (rst != NINLIL_R7_CRYPTO_RAW_OK) {
            return 1;
        }
        if (!is_bad_tag
            && (sealed_len != ct_len + 16u
                || memcmp(sealed_got, sealed_exp, sealed_len) != 0)) {
            return 1;
        }
        rst = crypto->aes128_gcm_open(
            crypto->ctx, key, nonce, aad, aad_len, sealed_exp, sealed_len,
            pt_got, ct_len, &pt_out);
        if (is_bad_tag) {
            return (rst != NINLIL_R7_CRYPTO_RAW_OK) ? 0 : 1;
        }
        if (rst != NINLIL_R7_CRYPTO_RAW_OK || pt_out != pt_len) {
            return 1;
        }
        if (pt_len > 0u && memcmp(pt_got, pt, pt_len) != 0) {
            return 1;
        }
    }

    /* Negatives: tag flip + CT flip must not authenticate. */
    {
        uint8_t bad[528];
        size_t bad_out = 0u;
        memcpy(bad, sealed_exp, sealed_len);
        bad[sealed_len - 1u] ^= 0x01u;
        st = ninlil_r7_crypto_aes128_gcm_open(
            crypto, key, nonce,
            aad_len <= NINLIL_R7_CRYPTO_AAD_MAX ? aad : NULL,
            aad_len <= NINLIL_R7_CRYPTO_AAD_MAX ? aad_len : 0u, bad, sealed_len,
            pt_got, ct_len, &bad_out);
        if (aad_len <= NINLIL_R7_CRYPTO_AAD_MAX && pt_len <= NINLIL_R7_CRYPTO_BODY_MAX
            && st == NINLIL_R7_CRYPTO_OK) {
            return 1;
        }
        if (ct_len > 0u) {
            memcpy(bad, sealed_exp, sealed_len);
            bad[0] ^= 0x01u;
            if (aad_len <= NINLIL_R7_CRYPTO_AAD_MAX
                && pt_len <= NINLIL_R7_CRYPTO_BODY_MAX) {
                st = ninlil_r7_crypto_aes128_gcm_open(
                    crypto, key, nonce, aad, aad_len, bad, sealed_len, pt_got,
                    ct_len, &bad_out);
                if (st == NINLIL_R7_CRYPTO_OK) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int frag_frame_open_row(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_r7_radio_wire_v1_row_t *r)
{
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t frame[512];
    uint8_t e2e_blob[400];
    size_t key_len = 0u, nonce_len = 0u, frame_len = 0u, e2e_len = 0u;
    ninlil_r7_frag_status fst;
    ninlil_r7_frag_outer_data_fields of;
    ninlil_r7_frag_outer_link_ack_fields lo;
    ninlil_r7_frag_link_ack_body lb;
    ninlil_r7_frag_e2e_fields ef;
    ninlil_r7_frag_ack_body ab;
    ninlil_r7_wire_e2e_single_fields wef;
    uint8_t app[256];
    size_t app_len = 0u;
    ninlil_r7_wire_status wst;

    if (r->frame_hex == NULL || r->frame_hex[0] == '\0') {
        return 0;
    }
    if (hex_decode(r->key_hex, key, sizeof(key), &key_len) != 0 || key_len != 16u) {
        return 1;
    }
    /* Production open takes static IV; derives GCM nonce from counter. */
    if (r->static_iv_hex != NULL && r->static_iv_hex[0] != '\0') {
        if (hex_decode(r->static_iv_hex, nonce, sizeof(nonce), &nonce_len) != 0
            || nonce_len != 12u) {
            return 1;
        }
    } else if (hex_decode(r->nonce_hex, nonce, sizeof(nonce), &nonce_len) != 0
        || nonce_len != 12u) {
        return 1;
    }
    if (hex_decode(r->frame_hex, frame, sizeof(frame), &frame_len) != 0) {
        return 1;
    }
    if (frame_len < 1u || frame[0] != 0x11u) {
        return 1;
    }

    if (strcmp(r->kind, "outer_link_ack") == 0) {
        fst = ninlil_r7_frag_open_outer_link_ack(
            crypto, key, nonce, frame, frame_len, &lo, &lb);
        if (fst != NINLIL_R7_FRAG_OK) {
            return 1;
        }
        if (frame_len > 1u) {
            fst = ninlil_r7_frag_open_outer_link_ack(
                crypto, key, nonce, frame, frame_len - 1u, &lo, &lb);
            if (fst == NINLIL_R7_FRAG_OK) {
                return 1;
            }
        }
        return 0;
    }
    if (strcmp(r->kind, "outer_data") == 0) {
        size_t hop_ct;
        if (frame_len < 19u + 16u + 31u) {
            return 1;
        }
        hop_ct = frame_len - 19u - 16u;
        if (hop_ct > sizeof(e2e_blob)) {
            return 1;
        }
        fst = ninlil_r7_frag_open_outer_data(
            crypto, key, nonce, frame, frame_len, &of, e2e_blob, hop_ct,
            &e2e_len);
        if (fst != NINLIL_R7_FRAG_OK || e2e_len != hop_ct) {
            return 1;
        }
        if (frame_len >= 16u) {
            uint8_t bad[512];
            memcpy(bad, frame, frame_len);
            bad[frame_len - 1u] ^= 0x01u;
            fst = ninlil_r7_frag_open_outer_data(
                crypto, key, nonce, bad, frame_len, &of, e2e_blob, hop_ct,
                &e2e_len);
            if (fst == NINLIL_R7_FRAG_OK) {
                return 1;
            }
        }
        return 0;
    }
    if (strcmp(r->kind, "e2e_single") == 0) {
        size_t need_app;
        if (frame_len < 14u + 16u + 1u) {
            return 1;
        }
        need_app = frame_len - 14u - 16u;
        if (need_app > sizeof(app)) {
            return 1;
        }
        /* Production open requires out_capacity == exact app_len. */
        wst = ninlil_r7_wire_open_e2e_single(
            crypto, key, nonce, frame, frame_len, &wef, app, need_app,
            &app_len);
        if (wst != NINLIL_R7_WIRE_OK || app_len != need_app) {
            return 1;
        }
        {
            uint8_t bad[512];
            memcpy(bad, frame, frame_len);
            bad[frame_len - 1u] ^= 0x80u;
            wst = ninlil_r7_wire_open_e2e_single(
                crypto, key, nonce, bad, frame_len, &wef, app, need_app,
                &app_len);
            if (wst == NINLIL_R7_WIRE_OK) {
                return 1;
            }
        }
        return 0;
    }
    if (strcmp(r->kind, "e2e_frag_ack") == 0) {
        fst = ninlil_r7_frag_open_e2e_ack(
            crypto, key, nonce, frame, frame_len, &ef, &ab);
        if (fst != NINLIL_R7_FRAG_OK) {
            return 1;
        }
        {
            uint8_t bad[512];
            memcpy(bad, frame, frame_len);
            bad[frame_len - 2u] ^= 0x01u;
            fst = ninlil_r7_frag_open_e2e_ack(
                crypto, key, nonce, bad, frame_len, &ef, &ab);
            if (fst == NINLIL_R7_FRAG_OK) {
                return 1;
            }
        }
        return 0;
    }
    if (strcmp(r->kind, "e2e_frag_start") == 0) {
        ninlil_r7_frag_start_body sb;
        uint8_t first[180];
        size_t flen = 0u;
        fst = ninlil_r7_frag_open_e2e_start(
            crypto, key, nonce, frame, frame_len, &ef, &sb, first, sizeof(first),
            &flen);
        return (fst == NINLIL_R7_FRAG_OK) ? 0 : 1;
    }
    if (strcmp(r->kind, "e2e_frag_cont") == 0) {
        ninlil_r7_frag_cont_body cb;
        uint8_t chunk[200];
        size_t clen = 0u;
        fst = ninlil_r7_frag_open_e2e_cont(
            crypto, key, nonce, frame, frame_len, &ef, &cb, chunk, sizeof(chunk),
            &clen);
        return (fst == NINLIL_R7_FRAG_OK) ? 0 : 1;
    }
    return 0;
}

int main(void)
{
    size_t i;
    int saw_single = 0;
    int saw_link = 0;
    int saw_frag_ack = 0;
    int aead_rows = 0;
    int codec_rows = 0;
    ninlil_r7_crypto_provider crypto;

    expect("vector count", NINLIL_R7_RADIO_WIRE_V1_VECTOR_COUNT >= 34u);
    expect("status host",
        strcmp(NINLIL_R7_RADIO_WIRE_V1_STATUS, "HOST_MATERIALIZED") == 0);
    expect("hil not run", strcmp(NINLIL_R7_RADIO_WIRE_V1_HIL, "NOT_RUN") == 0);
    expect("json sha non-empty",
        strlen(NINLIL_R7_RADIO_WIRE_V1_JSON_SHA256) == 64u);

    memset(&crypto, 0, sizeof(crypto));
    expect("openssl3 init",
        ninlil_r7_crypto_openssl3_provider_init(&crypto) == NINLIL_R7_CRYPTO_OK);
    expect("provider validate",
        ninlil_r7_crypto_provider_validate(&crypto) == NINLIL_R7_CRYPTO_OK);

    for (i = 0u; i < NINLIL_R7_RADIO_WIRE_V1_VECTOR_COUNT; i++) {
        const ninlil_r7_radio_wire_v1_row_t *r = &ninlil_r7_radio_wire_v1_rows[i];
        expect("id non-null", r->id != NULL && r->id[0] != '\0');
        expect("kind non-null", r->kind != NULL && r->kind[0] != '\0');
        if (strcmp(r->kind, "aead") == 0 && r->key_hex != NULL
            && r->key_hex[0] != '\0') {
            aead_rows++;
            expect(r->id, aead_roundtrip_row(&crypto, r) == 0);
        }
        if (r->frame_hex != NULL && r->frame_hex[0] != '\0'
            && r->key_hex != NULL && r->key_hex[0] != '\0') {
            codec_rows++;
            expect(r->id, frag_frame_open_row(&crypto, r) == 0);
        }
        if (strcmp(r->id, "single_n_1") == 0) {
            saw_single = 1;
        }
        if (strcmp(r->id, "link_ack") == 0) {
            saw_link = 1;
        }
        if (strcmp(r->id, "frag_ack_complete") == 0) {
            saw_frag_ack = 1;
        }
        if (strcmp(r->id, "R7-FRAG-FINAL-GOOD") == 0) {
            expect("policy kind", strcmp(r->kind, "state_policy") == 0);
        }
    }
    expect("single_n_1 present", saw_single);
    expect("link_ack present", saw_link);
    expect("frag_ack_complete present", saw_frag_ack);
    expect("aead rows exercised", aead_rows >= 3);
    expect("codec frame rows exercised", codec_rows >= 5);

    fprintf(stderr,
        "r7_radio_wire_v1_fixture_test: %s aead_rows=%d codec_rows=%d fails=%d\n",
        g_fail == 0 ? "OK" : "FAIL", aead_rows, codec_rows, g_fail);
    return g_fail == 0 ? 0 : 1;
}
