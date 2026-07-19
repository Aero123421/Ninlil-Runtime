/*
 * R7 T1b independent vector bridge (docs/33 §9–10).
 *
 * Executes every generated T1b binding subset vector exactly once against the
 * production private encode / digest / verified-derive APIs, linked via the
 * real ninlil_runtime_private path and the Host OpenSSL 3 provider.
 *
 * - No Python/oracle import at runtime.
 * - No reimplementation of SHA / HMAC / HKDF / AES.
 * - No T1b PRK API; PRK is checked only through the accepted T0 HKDF-Extract
 *   wrapper (salt = digest32, IKM = traffic_secret32).
 * - No heap, VLA, platform conditional skip, or public API change.
 * - Hard-pins the exact sorted 24-ID manifest; missing/extra/duplicate/order
 *   drift and partial consumption fail closed.
 */

#include "r7_context_binding.h"
#include "r7_crypto_openssl3.h"
#include "private/r7_t1b_binding_vectors.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_T1B_BRIDGE_ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT ((size_t)24u)
#define NINLIL_R7_T1B_BRIDGE_HOP_FIXED ((size_t)63u)
#define NINLIL_R7_T1B_BRIDGE_E2E_FIXED ((size_t)61u)
#define NINLIL_R7_T1B_BRIDGE_SITE_MAX ((size_t)16u)
#define NINLIL_R7_T1B_BRIDGE_ID_MAX ((size_t)32u)
#define NINLIL_R7_T1B_BRIDGE_CANON_MAX ((size_t)207u)

_Static_assert(
    NINLIL_R7_T1B_VECTOR_COUNT == 24u, "T1b vector count pin");
_Static_assert(
    NINLIL_R7_T1B_REQUIRED_VECTOR_COUNT == 24u, "T1b required count pin");
_Static_assert(
    NINLIL_R7_T1B_BRIDGE_ARRAY_COUNT(ninlil_r7_t1b_binding_vectors) == 24u,
    "T1b generated fixture row count pin");
_Static_assert(
    NINLIL_R7_BINDING_HOP_CANON_MAX == 207u, "Hop canon max pin");
_Static_assert(
    NINLIL_R7_BINDING_E2E_CANON_MAX == 205u, "E2E canon max pin");
_Static_assert(
    NINLIL_R7_BINDING_PROFILE_ID == ((uint8_t)0x11u), "profile pin");
_Static_assert(
    NINLIL_R7_BINDING_ALLOWED_KIND_MASK == ((uint16_t)0x0003u), "mask pin");

/*
 * Exact sorted 24-ID manifest (docs/33 §9 multiset; lexicographic order of the
 * generated fixture). Hard-pinned independently of the header array contents.
 */
static const char *const k_ninlil_r7_t1b_manifest[NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT] = {
    "R7-T1B-E2E-FIELD-D0-MAX",
    "R7-T1B-E2E-FIELD-D0-MIN",
    "R7-T1B-E2E-FIELD-D1-MAX",
    "R7-T1B-E2E-FIELD-D1-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-FIELD-D0-MAX",
    "R7-T1B-HOP-FIELD-D0-MIN",
    "R7-T1B-HOP-FIELD-D1-MAX",
    "R7-T1B-HOP-FIELD-D1-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MIN",
};

typedef struct ninlil_r7_t1b_bridge_counts {
    size_t hop;
    size_t e2e;
    /* Per-layer environment matrix: each must be exactly 4. */
    size_t hop_env_field;
    size_t hop_env_lab_controller;
    size_t hop_env_lab_no_controller;
    size_t e2e_env_field;
    size_t e2e_env_lab_controller;
    size_t e2e_env_lab_no_controller;
    size_t dir_d0;
    size_t dir_d1;
    size_t size_min;
    size_t size_max;
    size_t consumed;
} ninlil_r7_t1b_bridge_counts;

/* -------------------------------------------------------------------------- */
/* Fail / helpers                                                             */
/* -------------------------------------------------------------------------- */

static int ninlil_r7_t1b_bridge_fail(const char *id, const char *field)
{
    fprintf(
        stderr,
        "nrw1_t1b_vectors_bridge FAIL id=%s field=%s\n",
        id == NULL ? "(null)" : id,
        field == NULL ? "(null)" : field);
    return 0;
}

static int ninlil_r7_t1b_bridge_hex_nibble(char value, uint8_t *out)
{
    if (out == NULL) {
        return 0;
    }
    if (value >= '0' && value <= '9') {
        *out = (uint8_t)(value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *out = (uint8_t)(10 + (value - 'a'));
        return 1;
    }
    /* Uppercase and non-hex rejected fail-closed. */
    return 0;
}

/*
 * Strict lowercase hex decode with exact capacity bound.
 * Rejects: NULL, odd length, uppercase, non-hex, overflow past capacity.
 * Empty string publishes length 0 without writing. Fail-closed: no partial
 * publish on error paths that abort before the write loop.
 */
static int ninlil_r7_t1b_bridge_decode_hex(
    const char *hex,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t chars = 0u;
    size_t i;
    uint8_t high;
    uint8_t low;

    if (hex == NULL || out == NULL || out_len == NULL
        || out_capacity > (SIZE_MAX / 2u)) {
        return 0;
    }
    while (hex[chars] != '\0') {
        if (chars == SIZE_MAX || chars + 1u > out_capacity * 2u) {
            return 0;
        }
        chars++;
    }
    if ((chars & 1u) != 0u) {
        return 0;
    }
    for (i = 0u; i < chars; i++) {
        uint8_t unused;
        if (!ninlil_r7_t1b_bridge_hex_nibble(hex[i], &unused)) {
            return 0;
        }
    }
    for (i = 0u; i < chars / 2u; i++) {
        if (!ninlil_r7_t1b_bridge_hex_nibble(hex[i * 2u], &high)
            || !ninlil_r7_t1b_bridge_hex_nibble(hex[i * 2u + 1u], &low)) {
            return 0;
        }
        out[i] = (uint8_t)((uint8_t)(high << 4) | low);
    }
    *out_len = chars / 2u;
    return 1;
}

static int ninlil_r7_t1b_bridge_decode_hex_exact(
    const char *hex, uint8_t *out, size_t exact_len)
{
    size_t got = 0u;

    if (exact_len == 0u) {
        if (hex == NULL || hex[0] != '\0') {
            return 0;
        }
        return 1;
    }
    if (!ninlil_r7_t1b_bridge_decode_hex(hex, out, exact_len, &got)
        || got != exact_len) {
        return 0;
    }
    return 1;
}

static int ninlil_r7_t1b_bridge_bytes_eq(
    const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;

    if (n == 0u) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0u; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static void ninlil_r7_t1b_bridge_fill_canary(uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }
}

static int ninlil_r7_t1b_bridge_is_canary(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        if (p[i] != (uint8_t)(0xA5u ^ (uint8_t)i)) {
            return 0;
        }
    }
    return 1;
}

static int ninlil_r7_t1b_bridge_streq(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    return strcmp(a, b) == 0;
}

static int ninlil_r7_t1b_bridge_decoder_self_test(void)
{
    uint8_t out[2] = {0xa5u, 0xa5u};
    uint8_t before[2];
    char too_long[7];
    size_t out_len = (size_t)0x5a5au;

    if (!ninlil_r7_t1b_bridge_decode_hex("00ff", out, sizeof(out), &out_len)
        || out_len != 2u || out[0] != 0x00u || out[1] != 0xffu) {
        return ninlil_r7_t1b_bridge_fail("decoder", "valid_lowercase");
    }
    (void)memcpy(before, out, sizeof(out));
    out_len = (size_t)0x5a5au;
    if (ninlil_r7_t1b_bridge_decode_hex("0", out, sizeof(out), &out_len)
        || out_len != (size_t)0x5a5au
        || memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_t1b_bridge_fail("decoder", "odd_length");
    }
    if (ninlil_r7_t1b_bridge_decode_hex("0g", out, sizeof(out), &out_len)
        || memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_t1b_bridge_fail("decoder", "invalid_digit");
    }
    if (ninlil_r7_t1b_bridge_decode_hex("0A", out, sizeof(out), &out_len)
        || memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_t1b_bridge_fail("decoder", "uppercase");
    }
    (void)memcpy(too_long, "000000", sizeof(too_long));
    if (ninlil_r7_t1b_bridge_decode_hex(
            too_long, out, sizeof(out), &out_len)
        || memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_t1b_bridge_fail("decoder", "capacity_overflow");
    }
    out_len = (size_t)0x5a5au;
    if (!ninlil_r7_t1b_bridge_decode_hex("", out, sizeof(out), &out_len)
        || out_len != 0u) {
        return ninlil_r7_t1b_bridge_fail("decoder", "empty");
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Length formulas / matrix                                                   */
/* -------------------------------------------------------------------------- */

static size_t ninlil_r7_t1b_bridge_hop_need(
    size_t site, size_t att, size_t init, size_t resp, size_t auth)
{
    return NINLIL_R7_T1B_BRIDGE_HOP_FIXED + site + att + init + resp + auth;
}

static size_t ninlil_r7_t1b_bridge_e2e_need(
    size_t site, size_t sec, size_t send, size_t recv, size_t auth)
{
    return NINLIL_R7_T1B_BRIDGE_E2E_FIXED + site + sec + send + recv + auth;
}

static int ninlil_r7_t1b_bridge_expected_min_len(
    int is_hop, const char *environment, size_t *out_min)
{
    if (out_min == NULL || environment == NULL) {
        return 0;
    }
    if (is_hop) {
        if (ninlil_r7_t1b_bridge_streq(environment, "field")) {
            *out_min = 83u;
            return 1;
        }
        if (ninlil_r7_t1b_bridge_streq(environment, "lab_controller")) {
            *out_min = 68u;
            return 1;
        }
        if (ninlil_r7_t1b_bridge_streq(environment, "lab_no_controller")) {
            *out_min = 67u;
            return 1;
        }
    } else {
        if (ninlil_r7_t1b_bridge_streq(environment, "field")) {
            *out_min = 81u;
            return 1;
        }
        if (ninlil_r7_t1b_bridge_streq(environment, "lab_controller")) {
            *out_min = 66u;
            return 1;
        }
        if (ninlil_r7_t1b_bridge_streq(environment, "lab_no_controller")) {
            *out_min = 65u;
            return 1;
        }
    }
    return 0;
}

static int ninlil_r7_t1b_bridge_update_counts(
    ninlil_r7_t1b_bridge_counts *c,
    const ninlil_r7_t1b_binding_vector *v,
    int is_hop)
{
    if (c == NULL || v == NULL) {
        return 0;
    }
    if (is_hop) {
        c->hop++;
        if (ninlil_r7_t1b_bridge_streq(v->environment, "field")) {
            c->hop_env_field++;
        } else if (ninlil_r7_t1b_bridge_streq(
                       v->environment, "lab_controller")) {
            c->hop_env_lab_controller++;
        } else if (ninlil_r7_t1b_bridge_streq(
                       v->environment, "lab_no_controller")) {
            c->hop_env_lab_no_controller++;
        } else {
            return ninlil_r7_t1b_bridge_fail(v->id, "environment");
        }
    } else {
        c->e2e++;
        if (ninlil_r7_t1b_bridge_streq(v->environment, "field")) {
            c->e2e_env_field++;
        } else if (ninlil_r7_t1b_bridge_streq(
                       v->environment, "lab_controller")) {
            c->e2e_env_lab_controller++;
        } else if (ninlil_r7_t1b_bridge_streq(
                       v->environment, "lab_no_controller")) {
            c->e2e_env_lab_no_controller++;
        } else {
            return ninlil_r7_t1b_bridge_fail(v->id, "environment");
        }
    }
    if (v->direction_code == 0u) {
        c->dir_d0++;
    } else if (v->direction_code == 1u) {
        c->dir_d1++;
    } else {
        return ninlil_r7_t1b_bridge_fail(v->id, "direction_code");
    }
    if (ninlil_r7_t1b_bridge_streq(v->size_class, "min")) {
        c->size_min++;
    } else if (ninlil_r7_t1b_bridge_streq(v->size_class, "max")) {
        c->size_max++;
    } else {
        return ninlil_r7_t1b_bridge_fail(v->id, "size_class");
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* One vector                                                                 */
/* -------------------------------------------------------------------------- */

static int ninlil_r7_t1b_bridge_run_one(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_t1b_binding_vector *v,
    ninlil_r7_t1b_bridge_counts *counts)
{
    uint8_t site[NINLIL_R7_T1B_BRIDGE_SITE_MAX];
    uint8_t primary[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t left[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t right[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t auth[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t traffic[32];
    uint8_t exp_canon[NINLIL_R7_T1B_BRIDGE_CANON_MAX];
    uint8_t got_canon[NINLIL_R7_T1B_BRIDGE_CANON_MAX];
    uint8_t exp_digest[32];
    uint8_t got_digest[32];
    uint8_t exp_prk[32];
    uint8_t got_prk[32];
    uint8_t exp_data_key[16];
    uint8_t exp_data_iv[12];
    uint8_t exp_ack_key[16];
    uint8_t exp_ack_iv[12];
    uint8_t exp_e2e_key[16];
    uint8_t exp_e2e_iv[12];
    size_t site_len = 0u;
    size_t primary_len = 0u;
    size_t left_len = 0u;
    size_t right_len = 0u;
    size_t auth_len = 0u;
    size_t exp_canon_len = 0u;
    size_t got_canon_len = 0u;
    size_t need = 0u;
    size_t min_len = 0u;
    int is_hop;
    int no_controller;
    int32_t st;
    ninlil_r7_hop_binding_input hop_in;
    ninlil_r7_e2e_binding_input e2e_in;
    ninlil_r7_hop_key_bundle hop_bundle;
    ninlil_r7_e2e_key_bundle e2e_bundle;

    if (provider == NULL || v == NULL || v->id == NULL) {
        return ninlil_r7_t1b_bridge_fail("(null)", "vector_shape");
    }

    if (ninlil_r7_t1b_bridge_streq(v->layer, "hop")) {
        is_hop = 1;
    } else if (ninlil_r7_t1b_bridge_streq(v->layer, "e2e")) {
        is_hop = 0;
    } else {
        return ninlil_r7_t1b_bridge_fail(v->id, "layer");
    }

    no_controller = ninlil_r7_t1b_bridge_streq(
        v->environment, "lab_no_controller");

    if (ninlil_r7_t1b_bridge_streq(v->environment, "field")) {
        if (v->environment_code != NINLIL_R7_BINDING_ENV_FIELD) {
            return ninlil_r7_t1b_bridge_fail(v->id, "environment_code");
        }
    } else if (ninlil_r7_t1b_bridge_streq(v->environment, "lab_controller")
        || no_controller) {
        if (v->environment_code != NINLIL_R7_BINDING_ENV_LAB) {
            return ninlil_r7_t1b_bridge_fail(v->id, "environment_code");
        }
    } else {
        return ninlil_r7_t1b_bridge_fail(v->id, "environment");
    }

    if (v->direction_code != NINLIL_R7_BINDING_DIR_IR
        && v->direction_code != NINLIL_R7_BINDING_DIR_RI) {
        return ninlil_r7_t1b_bridge_fail(v->id, "direction_code");
    }

    /* Strict hex decode of all private inputs and expected outputs. */
    if (!ninlil_r7_t1b_bridge_decode_hex(
            v->site_domain, site, sizeof(site), &site_len)
        || site_len == 0u) {
        return ninlil_r7_t1b_bridge_fail(v->id, "site_domain");
    }
    if (!ninlil_r7_t1b_bridge_decode_hex(
            v->primary_id, primary, sizeof(primary), &primary_len)
        || primary_len == 0u) {
        return ninlil_r7_t1b_bridge_fail(v->id, "primary_id");
    }
    if (!ninlil_r7_t1b_bridge_decode_hex(
            v->left_stable_id, left, sizeof(left), &left_len)
        || left_len == 0u) {
        return ninlil_r7_t1b_bridge_fail(v->id, "left_stable_id");
    }
    if (!ninlil_r7_t1b_bridge_decode_hex(
            v->right_stable_id, right, sizeof(right), &right_len)
        || right_len == 0u) {
        return ninlil_r7_t1b_bridge_fail(v->id, "right_stable_id");
    }

    if (v->authority_id == NULL) {
        return ninlil_r7_t1b_bridge_fail(v->id, "authority_id");
    }
    if (v->authority_id[0] == '\0') {
        /* Empty authority shape: exact NULL + length 0 (LAB no-controller). */
        auth_len = 0u;
        if (!no_controller || v->authority_term != 0ull) {
            return ninlil_r7_t1b_bridge_fail(v->id, "authority_empty_shape");
        }
    } else {
        if (!ninlil_r7_t1b_bridge_decode_hex(
                v->authority_id, auth, sizeof(auth), &auth_len)
            || auth_len == 0u) {
            return ninlil_r7_t1b_bridge_fail(v->id, "authority_id");
        }
        if (no_controller || v->authority_term == 0ull) {
            return ninlil_r7_t1b_bridge_fail(v->id, "authority_term");
        }
    }

    if (!ninlil_r7_t1b_bridge_decode_hex_exact(
            v->traffic_secret32, traffic, 32u)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "traffic_secret32");
    }
    if (!ninlil_r7_t1b_bridge_decode_hex(
            v->canonical, exp_canon, sizeof(exp_canon), &exp_canon_len)
        || exp_canon_len != (size_t)v->canonical_len) {
        return ninlil_r7_t1b_bridge_fail(v->id, "canonical");
    }
    if (!ninlil_r7_t1b_bridge_decode_hex_exact(v->digest, exp_digest, 32u)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "digest");
    }
    if (!ninlil_r7_t1b_bridge_decode_hex_exact(v->prk, exp_prk, 32u)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "prk");
    }

    if (is_hop) {
        if (!ninlil_r7_t1b_bridge_decode_hex_exact(
                v->data_key16, exp_data_key, 16u)
            || !ninlil_r7_t1b_bridge_decode_hex_exact(
                v->data_iv12, exp_data_iv, 12u)
            || !ninlil_r7_t1b_bridge_decode_hex_exact(
                v->ack_key16, exp_ack_key, 16u)
            || !ninlil_r7_t1b_bridge_decode_hex_exact(
                v->ack_iv12, exp_ack_iv, 12u)) {
            return ninlil_r7_t1b_bridge_fail(v->id, "hop_key_lanes");
        }
        if (v->key16 == NULL || v->key16[0] != '\0'
            || v->iv12 == NULL || v->iv12[0] != '\0') {
            return ninlil_r7_t1b_bridge_fail(v->id, "hop_unused_e2e_lanes");
        }
        need = ninlil_r7_t1b_bridge_hop_need(
            site_len, primary_len, left_len, right_len, auth_len);
        if (need > NINLIL_R7_BINDING_HOP_CANON_MAX) {
            return ninlil_r7_t1b_bridge_fail(v->id, "hop_need_max");
        }
    } else {
        if (!ninlil_r7_t1b_bridge_decode_hex_exact(
                v->key16, exp_e2e_key, 16u)
            || !ninlil_r7_t1b_bridge_decode_hex_exact(
                v->iv12, exp_e2e_iv, 12u)) {
            return ninlil_r7_t1b_bridge_fail(v->id, "e2e_key_lanes");
        }
        if (v->data_key16 == NULL || v->data_key16[0] != '\0'
            || v->data_iv12 == NULL || v->data_iv12[0] != '\0'
            || v->ack_key16 == NULL || v->ack_key16[0] != '\0'
            || v->ack_iv12 == NULL || v->ack_iv12[0] != '\0') {
            return ninlil_r7_t1b_bridge_fail(v->id, "e2e_unused_hop_lanes");
        }
        need = ninlil_r7_t1b_bridge_e2e_need(
            site_len, primary_len, left_len, right_len, auth_len);
        if (need > NINLIL_R7_BINDING_E2E_CANON_MAX) {
            return ninlil_r7_t1b_bridge_fail(v->id, "e2e_need_max");
        }
    }

    if (need != (size_t)v->canonical_len || need != exp_canon_len) {
        return ninlil_r7_t1b_bridge_fail(v->id, "canonical_len_formula");
    }
    if (!ninlil_r7_t1b_bridge_expected_min_len(
            is_hop, v->environment, &min_len)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "min_len_table");
    }
    if (ninlil_r7_t1b_bridge_streq(v->size_class, "min")) {
        if (need != min_len) {
            return ninlil_r7_t1b_bridge_fail(v->id, "min_canonical_len");
        }
    } else if (ninlil_r7_t1b_bridge_streq(v->size_class, "max")) {
        /* MAX pins full site (16) and full ID lanes (32), authority 0 or 32. */
        if (site_len != NINLIL_R7_T1B_BRIDGE_SITE_MAX
            || primary_len != NINLIL_R7_T1B_BRIDGE_ID_MAX
            || left_len != NINLIL_R7_T1B_BRIDGE_ID_MAX
            || right_len != NINLIL_R7_T1B_BRIDGE_ID_MAX) {
            return ninlil_r7_t1b_bridge_fail(v->id, "max_opaque_lens");
        }
        if (no_controller) {
            if (auth_len != 0u) {
                return ninlil_r7_t1b_bridge_fail(v->id, "max_auth_empty");
            }
        } else if (auth_len != NINLIL_R7_T1B_BRIDGE_ID_MAX) {
            return ninlil_r7_t1b_bridge_fail(v->id, "max_auth_len");
        }
        if (is_hop) {
            if (need
                != (no_controller ? (size_t)175u
                                  : NINLIL_R7_BINDING_HOP_CANON_MAX)) {
                return ninlil_r7_t1b_bridge_fail(v->id, "max_canonical_len");
            }
        } else if (need
            != (no_controller ? (size_t)173u
                              : NINLIL_R7_BINDING_E2E_CANON_MAX)) {
            return ninlil_r7_t1b_bridge_fail(v->id, "max_canonical_len");
        }
    }

    /* Reconstruct private inputs (empty authority = NULL + 0). */
    (void)memset(&hop_in, 0, sizeof(hop_in));
    (void)memset(&e2e_in, 0, sizeof(e2e_in));
    if (is_hop) {
        hop_in.environment_code = v->environment_code;
        hop_in.site_domain.bytes = site;
        hop_in.site_domain.length = (uint16_t)site_len;
        hop_in.membership_epoch = v->membership_epoch;
        hop_in.attachment_id.bytes = primary;
        hop_in.attachment_id.length = (uint16_t)primary_len;
        hop_in.attachment_epoch = v->primary_epoch;
        hop_in.initiator_stable_id.bytes = left;
        hop_in.initiator_stable_id.length = (uint16_t)left_len;
        hop_in.responder_stable_id.bytes = right;
        hop_in.responder_stable_id.length = (uint16_t)right_len;
        if (auth_len == 0u) {
            hop_in.controller_authority_id.bytes = NULL;
            hop_in.controller_authority_id.length = 0u;
        } else {
            hop_in.controller_authority_id.bytes = auth;
            hop_in.controller_authority_id.length = (uint16_t)auth_len;
        }
        hop_in.controller_term = v->authority_term;
        hop_in.hop_context_id = v->context_id;
        hop_in.direction_code = v->direction_code;
    } else {
        e2e_in.environment_code = v->environment_code;
        e2e_in.site_domain.bytes = site;
        e2e_in.site_domain.length = (uint16_t)site_len;
        e2e_in.membership_epoch = v->membership_epoch;
        e2e_in.e2e_security_id.bytes = primary;
        e2e_in.e2e_security_id.length = (uint16_t)primary_len;
        e2e_in.e2e_security_epoch = v->primary_epoch;
        e2e_in.sender_stable_id.bytes = left;
        e2e_in.sender_stable_id.length = (uint16_t)left_len;
        e2e_in.receiver_stable_id.bytes = right;
        e2e_in.receiver_stable_id.length = (uint16_t)right_len;
        if (auth_len == 0u) {
            e2e_in.authority_id.bytes = NULL;
            e2e_in.authority_id.length = 0u;
        } else {
            e2e_in.authority_id.bytes = auth;
            e2e_in.authority_id.length = (uint16_t)auth_len;
        }
        e2e_in.authority_term = v->authority_term;
        e2e_in.e2e_context_id = v->context_id;
        e2e_in.direction_code = v->direction_code;
    }

    /* Encode with exact capacity; compare canonical bytes + length. */
    ninlil_r7_t1b_bridge_fill_canary(got_canon, sizeof(got_canon));
    got_canon_len = (size_t)0xDEADBEEFu;
    if (is_hop) {
        st = ninlil_r7_encode_hop_binding(
            &hop_in, got_canon, need, &got_canon_len);
    } else {
        st = ninlil_r7_encode_e2e_binding(
            &e2e_in, got_canon, need, &got_canon_len);
    }
    if (st != NINLIL_R7_BINDING_OK || got_canon_len != need
        || !ninlil_r7_t1b_bridge_bytes_eq(got_canon, exp_canon, need)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "encode_canonical");
    }

    /* Fixed profile byte and Hop kind mask (not caller-selected). */
    if (got_canon[20] != NINLIL_R7_BINDING_PROFILE_ID
        || exp_canon[20] != NINLIL_R7_BINDING_PROFILE_ID) {
        return ninlil_r7_t1b_bridge_fail(v->id, "profile_byte");
    }
    if (is_hop) {
        if (need < 2u
            || got_canon[need - 2u] != 0x00u
            || got_canon[need - 1u] != 0x03u
            || exp_canon[need - 2u] != 0x00u
            || exp_canon[need - 1u] != 0x03u) {
            return ninlil_r7_t1b_bridge_fail(v->id, "kind_mask");
        }
    }

    /* Production digest via real OpenSSL 3 provider. */
    ninlil_r7_t1b_bridge_fill_canary(got_digest, sizeof(got_digest));
    if (is_hop) {
        st = ninlil_r7_digest_hop_binding(provider, &hop_in, got_digest);
    } else {
        st = ninlil_r7_digest_e2e_binding(provider, &e2e_in, got_digest);
    }
    if (st != NINLIL_R7_BINDING_OK
        || !ninlil_r7_t1b_bridge_bytes_eq(got_digest, exp_digest, 32u)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "digest");
    }

    /*
     * PRK: accepted T0 HKDF-Extract only (digest as salt, traffic secret as
     * IKM). No T1b PRK production API.
     */
    ninlil_r7_t1b_bridge_fill_canary(got_prk, sizeof(got_prk));
    if (ninlil_r7_crypto_hkdf_extract_sha256(
            provider,
            got_digest,
            32u,
            traffic,
            32u,
            got_prk)
        != NINLIL_R7_CRYPTO_OK
        || !ninlil_r7_t1b_bridge_bytes_eq(got_prk, exp_prk, 32u)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "prk_hkdf_extract");
    }

    /* Verified derive: all typed key/IV lanes byte-for-byte. */
    if (is_hop) {
        ninlil_r7_t1b_bridge_fill_canary(
            (uint8_t *)&hop_bundle, sizeof(hop_bundle));
        st = ninlil_r7_derive_hop_key_bundle_verified(
            provider, &hop_in, exp_digest, traffic, &hop_bundle);
        if (st != NINLIL_R7_BINDING_OK
            || !ninlil_r7_t1b_bridge_bytes_eq(
                hop_bundle.data_key16, exp_data_key, 16u)
            || !ninlil_r7_t1b_bridge_bytes_eq(
                hop_bundle.data_iv12, exp_data_iv, 12u)
            || !ninlil_r7_t1b_bridge_bytes_eq(
                hop_bundle.ack_key16, exp_ack_key, 16u)
            || !ninlil_r7_t1b_bridge_bytes_eq(
                hop_bundle.ack_iv12, exp_ack_iv, 12u)) {
            return ninlil_r7_t1b_bridge_fail(v->id, "derive_hop_bundle");
        }
    } else {
        ninlil_r7_t1b_bridge_fill_canary(
            (uint8_t *)&e2e_bundle, sizeof(e2e_bundle));
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            provider, &e2e_in, exp_digest, traffic, &e2e_bundle);
        if (st != NINLIL_R7_BINDING_OK
            || !ninlil_r7_t1b_bridge_bytes_eq(
                e2e_bundle.key16, exp_e2e_key, 16u)
            || !ninlil_r7_t1b_bridge_bytes_eq(
                e2e_bundle.iv12, exp_e2e_iv, 12u)) {
            return ninlil_r7_t1b_bridge_fail(v->id, "derive_e2e_bundle");
        }
    }

    if (!ninlil_r7_t1b_bridge_update_counts(counts, v, is_hop)) {
        return 0;
    }
    counts->consumed++;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Deliberate mismatch: one per layer, canary + mutation zero                 */
/* -------------------------------------------------------------------------- */

static int ninlil_r7_t1b_bridge_mismatch_once(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_t1b_binding_vector *v)
{
    uint8_t site[NINLIL_R7_T1B_BRIDGE_SITE_MAX];
    uint8_t primary[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t left[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t right[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t auth[NINLIL_R7_T1B_BRIDGE_ID_MAX];
    uint8_t traffic[32];
    uint8_t digest[32];
    uint8_t bad_digest[32];
    size_t site_len = 0u;
    size_t primary_len = 0u;
    size_t left_len = 0u;
    size_t right_len = 0u;
    size_t auth_len = 0u;
    int is_hop;
    int32_t st;
    ninlil_r7_hop_binding_input hop_in;
    ninlil_r7_e2e_binding_input e2e_in;
    ninlil_r7_hop_key_bundle hop_bundle;
    ninlil_r7_e2e_key_bundle e2e_bundle;

    if (provider == NULL || v == NULL || v->id == NULL) {
        return ninlil_r7_t1b_bridge_fail("mismatch", "shape");
    }
    is_hop = ninlil_r7_t1b_bridge_streq(v->layer, "hop");

    if (!ninlil_r7_t1b_bridge_decode_hex(
            v->site_domain, site, sizeof(site), &site_len)
        || !ninlil_r7_t1b_bridge_decode_hex(
            v->primary_id, primary, sizeof(primary), &primary_len)
        || !ninlil_r7_t1b_bridge_decode_hex(
            v->left_stable_id, left, sizeof(left), &left_len)
        || !ninlil_r7_t1b_bridge_decode_hex(
            v->right_stable_id, right, sizeof(right), &right_len)
        || !ninlil_r7_t1b_bridge_decode_hex_exact(
            v->traffic_secret32, traffic, 32u)
        || !ninlil_r7_t1b_bridge_decode_hex_exact(v->digest, digest, 32u)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "mismatch_decode");
    }

    if (v->authority_id != NULL && v->authority_id[0] == '\0') {
        auth_len = 0u;
    } else if (!ninlil_r7_t1b_bridge_decode_hex(
                   v->authority_id, auth, sizeof(auth), &auth_len)) {
        return ninlil_r7_t1b_bridge_fail(v->id, "mismatch_authority");
    }

    (void)memcpy(bad_digest, digest, sizeof(bad_digest));
    bad_digest[0] = (uint8_t)(bad_digest[0] ^ 0x01u);

    (void)memset(&hop_in, 0, sizeof(hop_in));
    (void)memset(&e2e_in, 0, sizeof(e2e_in));
    if (is_hop) {
        hop_in.environment_code = v->environment_code;
        hop_in.site_domain.bytes = site;
        hop_in.site_domain.length = (uint16_t)site_len;
        hop_in.membership_epoch = v->membership_epoch;
        hop_in.attachment_id.bytes = primary;
        hop_in.attachment_id.length = (uint16_t)primary_len;
        hop_in.attachment_epoch = v->primary_epoch;
        hop_in.initiator_stable_id.bytes = left;
        hop_in.initiator_stable_id.length = (uint16_t)left_len;
        hop_in.responder_stable_id.bytes = right;
        hop_in.responder_stable_id.length = (uint16_t)right_len;
        if (auth_len == 0u) {
            hop_in.controller_authority_id.bytes = NULL;
            hop_in.controller_authority_id.length = 0u;
        } else {
            hop_in.controller_authority_id.bytes = auth;
            hop_in.controller_authority_id.length = (uint16_t)auth_len;
        }
        hop_in.controller_term = v->authority_term;
        hop_in.hop_context_id = v->context_id;
        hop_in.direction_code = v->direction_code;

        ninlil_r7_t1b_bridge_fill_canary(
            (uint8_t *)&hop_bundle, sizeof(hop_bundle));
        st = ninlil_r7_derive_hop_key_bundle_verified(
            provider, &hop_in, bad_digest, traffic, &hop_bundle);
        if (st != NINLIL_R7_BINDING_MISMATCH
            || !ninlil_r7_t1b_bridge_is_canary(
                (const uint8_t *)&hop_bundle, sizeof(hop_bundle))) {
            return ninlil_r7_t1b_bridge_fail(v->id, "hop_mismatch_canary");
        }
    } else {
        e2e_in.environment_code = v->environment_code;
        e2e_in.site_domain.bytes = site;
        e2e_in.site_domain.length = (uint16_t)site_len;
        e2e_in.membership_epoch = v->membership_epoch;
        e2e_in.e2e_security_id.bytes = primary;
        e2e_in.e2e_security_id.length = (uint16_t)primary_len;
        e2e_in.e2e_security_epoch = v->primary_epoch;
        e2e_in.sender_stable_id.bytes = left;
        e2e_in.sender_stable_id.length = (uint16_t)left_len;
        e2e_in.receiver_stable_id.bytes = right;
        e2e_in.receiver_stable_id.length = (uint16_t)right_len;
        if (auth_len == 0u) {
            e2e_in.authority_id.bytes = NULL;
            e2e_in.authority_id.length = 0u;
        } else {
            e2e_in.authority_id.bytes = auth;
            e2e_in.authority_id.length = (uint16_t)auth_len;
        }
        e2e_in.authority_term = v->authority_term;
        e2e_in.e2e_context_id = v->context_id;
        e2e_in.direction_code = v->direction_code;

        ninlil_r7_t1b_bridge_fill_canary(
            (uint8_t *)&e2e_bundle, sizeof(e2e_bundle));
        st = ninlil_r7_derive_e2e_key_bundle_verified(
            provider, &e2e_in, bad_digest, traffic, &e2e_bundle);
        if (st != NINLIL_R7_BINDING_MISMATCH
            || !ninlil_r7_t1b_bridge_is_canary(
                (const uint8_t *)&e2e_bundle, sizeof(e2e_bundle))) {
            return ninlil_r7_t1b_bridge_fail(v->id, "e2e_mismatch_canary");
        }
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Manifest integrity                                                         */
/* -------------------------------------------------------------------------- */

static int ninlil_r7_t1b_bridge_check_manifest_unique(void)
{
    size_t i;
    size_t j;

    for (i = 0u; i < NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT; i++) {
        if (k_ninlil_r7_t1b_manifest[i] == NULL
            || k_ninlil_r7_t1b_manifest[i][0] == '\0') {
            return ninlil_r7_t1b_bridge_fail("manifest", "empty_id");
        }
        for (j = i + 1u; j < NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT; j++) {
            if (strcmp(
                    k_ninlil_r7_t1b_manifest[i],
                    k_ninlil_r7_t1b_manifest[j])
                == 0) {
                return ninlil_r7_t1b_bridge_fail(
                    k_ninlil_r7_t1b_manifest[i], "manifest_duplicate");
            }
        }
        if (i > 0u
            && strcmp(
                   k_ninlil_r7_t1b_manifest[i - 1u],
                   k_ninlil_r7_t1b_manifest[i])
                >= 0) {
            return ninlil_r7_t1b_bridge_fail(
                k_ninlil_r7_t1b_manifest[i], "manifest_order");
        }
    }
    return 1;
}

static int ninlil_r7_t1b_bridge_check_final_counts(
    const ninlil_r7_t1b_bridge_counts *c)
{
    if (c == NULL) {
        return ninlil_r7_t1b_bridge_fail("final", "counts_null");
    }
    if (c->consumed != NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT) {
        return ninlil_r7_t1b_bridge_fail("final", "consumed");
    }
    if (c->hop != 12u || c->e2e != 12u) {
        return ninlil_r7_t1b_bridge_fail("final", "layer_counts");
    }
    /* Each environment exactly 4 per layer (docs/33 matrix). */
    if (c->hop_env_field != 4u || c->hop_env_lab_controller != 4u
        || c->hop_env_lab_no_controller != 4u || c->e2e_env_field != 4u
        || c->e2e_env_lab_controller != 4u
        || c->e2e_env_lab_no_controller != 4u) {
        return ninlil_r7_t1b_bridge_fail("final", "environment_counts");
    }
    if (c->dir_d0 != 12u || c->dir_d1 != 12u) {
        return ninlil_r7_t1b_bridge_fail("final", "direction_counts");
    }
    if (c->size_min != 12u || c->size_max != 12u) {
        return ninlil_r7_t1b_bridge_fail("final", "size_counts");
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */

int main(void)
{
    ninlil_r7_crypto_provider provider;
    ninlil_r7_t1b_bridge_counts counts;
    uint8_t consumed_slot[NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT];
    size_t i;
    const ninlil_r7_t1b_binding_vector *first_hop = NULL;
    const ninlil_r7_t1b_binding_vector *first_e2e = NULL;

    (void)memset(&counts, 0, sizeof(counts));
    (void)memset(consumed_slot, 0, sizeof(consumed_slot));
    (void)memset(&provider, 0, sizeof(provider));

    if (!ninlil_r7_t1b_bridge_decoder_self_test()) {
        return 1;
    }
    if (!ninlil_r7_t1b_bridge_check_manifest_unique()) {
        return 1;
    }

    if (ninlil_r7_crypto_openssl3_provider_init(&provider)
            != NINLIL_R7_CRYPTO_OK
        || ninlil_r7_crypto_provider_validate(&provider)
            != NINLIL_R7_CRYPTO_OK) {
        (void)ninlil_r7_t1b_bridge_fail("provider", "openssl3_init");
        return 1;
    }

    if (NINLIL_R7_T1B_BRIDGE_ARRAY_COUNT(ninlil_r7_t1b_binding_vectors)
        != NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT) {
        (void)ninlil_r7_t1b_bridge_fail("fixture", "count");
        return 1;
    }

    for (i = 0u; i < NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT; i++) {
        const ninlil_r7_t1b_binding_vector *v =
            &ninlil_r7_t1b_binding_vectors[i];
        size_t j;

        if (v->id == NULL) {
            (void)ninlil_r7_t1b_bridge_fail("(null)", "id");
            return 1;
        }
        /* Exact order: fixture row i must equal hard-pinned sorted ID i. */
        if (!ninlil_r7_t1b_bridge_streq(v->id, k_ninlil_r7_t1b_manifest[i])) {
            (void)ninlil_r7_t1b_bridge_fail(v->id, "order_drift");
            return 1;
        }
        /* Extra / duplicate relative to prior rows. */
        for (j = 0u; j < i; j++) {
            if (ninlil_r7_t1b_bridge_streq(
                    v->id, ninlil_r7_t1b_binding_vectors[j].id)) {
                (void)ninlil_r7_t1b_bridge_fail(v->id, "duplicate");
                return 1;
            }
        }
        if (consumed_slot[i] != 0u) {
            (void)ninlil_r7_t1b_bridge_fail(v->id, "slot_reentry");
            return 1;
        }

        if (!ninlil_r7_t1b_bridge_run_one(&provider, v, &counts)) {
            return 1;
        }
        consumed_slot[i] = 1u;

        if (first_hop == NULL && ninlil_r7_t1b_bridge_streq(v->layer, "hop")) {
            first_hop = v;
        }
        if (first_e2e == NULL && ninlil_r7_t1b_bridge_streq(v->layer, "e2e")) {
            first_e2e = v;
        }
    }

    /* Prove every fixture row consumed exactly once. */
    for (i = 0u; i < NINLIL_R7_T1B_BRIDGE_VECTOR_COUNT; i++) {
        if (consumed_slot[i] != 1u) {
            (void)ninlil_r7_t1b_bridge_fail(
                k_ninlil_r7_t1b_manifest[i], "not_consumed");
            return 1;
        }
    }
    if (!ninlil_r7_t1b_bridge_check_final_counts(&counts)) {
        return 1;
    }

    if (first_hop == NULL || first_e2e == NULL) {
        (void)ninlil_r7_t1b_bridge_fail("final", "layer_sample");
        return 1;
    }
    /* One deliberate digest mismatch per layer: MISMATCH + output canary. */
    if (!ninlil_r7_t1b_bridge_mismatch_once(&provider, first_e2e)
        || !ninlil_r7_t1b_bridge_mismatch_once(&provider, first_hop)) {
        return 1;
    }

    printf(
        "nrw1_t1b_vectors_bridge PASS vector_count=24 consumed=24\n");
    return 0;
}
