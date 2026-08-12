/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Deterministic FRAG/LINK target smoke vectors (heap-free, provider-injected).
 *
 * Two build modes:
 *
 * LIGHT (NINLIL_R7_FRAG_SMOKE_LIGHT or ENDPOINT production ESP):
 *   - One static ENDPOINT reasm engine only (~9 KiB BSS).
 *   - Exercises plan / admit_start / admit_cont / exact-once / reorder / restart
 *     via state engine APIs + provider SHA-256 (no session, no test durable).
 *   - Production component claim path: zero lab session BSS.
 *
 * HOST LAB (default without SMOKE_LIGHT):
 *   - Exactly one static TX/RX session pair, reused sequentially.
 *   - May embed test durable simulator for crash/restart vectors.
 *   - Not production N6; not MFDT custody completeness.
 *
 * Concurrent production instance budget (ENDPOINT): 1 reasm engine (2 slots),
 * 1 caller-owned bind pair (matrix_ws/xfer). Not multi-static session BSS.
 */

#include "r7_frag_target_smoke.h"

#include "r7_frag_state.h"

#include <string.h>

#if defined(NINLIL_R7_FRAG_SMOKE_LIGHT) && (NINLIL_R7_FRAG_SMOKE_LIGHT)
#define R7_FRAG_SMOKE_USE_LIGHT 1
#elif defined(NINLIL_R7_FRAG_PROFILE_ENDPOINT) && (NINLIL_R7_FRAG_PROFILE_ENDPOINT)
#define R7_FRAG_SMOKE_USE_LIGHT 1
#else
#define R7_FRAG_SMOKE_USE_LIGHT 0
#endif

#if R7_FRAG_SMOKE_USE_LIGHT

/* Single ENDPOINT reasm engine — production-safe BSS pin. */
static ninlil_r7_frag_state_engine g_reasm;

static int32_t light_plan_and_exact(const ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in sin;
    ninlil_r7_frag_state_cont_in cin;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[200];
    uint8_t tid[16];
    uint8_t dig[32];
    uint8_t pub[256];
    size_t pub_len = 0u;
    uint16_t i;
    ninlil_r7_frag_state_status st;
    uint32_t ctx = 0u;
    uint64_t kgen = 0u;
    uint64_t th = 0u;

    for (i = 0u; i < 200u; i++) {
        payload[i] = (uint8_t)(i * 3u);
    }
    for (i = 0u; i < 16u; i++) {
        tid[i] = (uint8_t)(0xB0u + i);
    }
    if (ninlil_r7_frag_state_plan_build(200u, &plan) != NINLIL_R7_FRAG_STATE_OK
        || plan.frag_count < 2u) {
        return 20;
    }
    if (ninlil_r7_crypto_sha256(provider, payload, 200u, dig)
        != NINLIL_R7_CRYPTO_OK) {
        return 21;
    }
    ninlil_r7_frag_state_zeroize(&g_reasm);
    ninlil_r7_frag_state_init(&g_reasm);
    ninlil_r7_frag_state_set_now(&g_reasm, 2000u);

    memset(&sin, 0, sizeof(sin));
    sin.e2e_context_id = 21u;
    sin.key_generation = 1u;
    memcpy(sin.transfer_id, tid, 16u);
    sin.transfer_handle = 7u;
    sin.total_len = 200u;
    sin.frag_count = plan.frag_count;
    sin.continuation_unit = 180u;
    memcpy(sin.content_digest, dig, 32u);
    sin.first_chunk = payload;
    sin.first_chunk_len = plan.first_chunk_len;
    /* Fingerprint = digest of transfer_id||handle for light vector (stable). */
    if (ninlil_r7_crypto_sha256(
            provider, tid, 16u, sin.fingerprint)
        != NINLIL_R7_CRYPTO_OK) {
        return 22;
    }
    memset(&intent, 0, sizeof(intent));
    st = ninlil_r7_frag_state_admit_start(&g_reasm, &sin, &intent);
    if (st != NINLIL_R7_FRAG_STATE_OK
        && st != NINLIL_R7_FRAG_STATE_EXACT_RETRY) {
        return 23;
    }
    for (i = 1u; i < plan.frag_count; i++) {
        memset(&cin, 0, sizeof(cin));
        cin.e2e_context_id = 21u;
        cin.key_generation = 1u;
        cin.transfer_handle = 7u;
        cin.frag_index = i;
        cin.chunk = payload + plan.chunks[i].offset;
        cin.chunk_len = plan.chunks[i].length;
        cin.reassembled_digest32 = NULL;
        st = ninlil_r7_frag_state_admit_cont(&g_reasm, &cin, &intent);
        if (st == NINLIL_R7_FRAG_STATE_NEED_DIGEST) {
            const uint8_t *pl = NULL;
            size_t pl_len = 0u;
            if (ninlil_r7_frag_state_peek_reassembled(
                    &g_reasm, 21u, 7u, &pl, &pl_len)
                    == NINLIL_R7_FRAG_STATE_OK
                && pl != NULL
                && ninlil_r7_crypto_sha256(provider, pl, pl_len, dig)
                    == NINLIL_R7_CRYPTO_OK) {
                st = ninlil_r7_frag_state_finalize(
                    &g_reasm, 21u, 7u, dig, &intent);
            }
        }
        if (st != NINLIL_R7_FRAG_STATE_OK
            && st != NINLIL_R7_FRAG_STATE_DUPLICATE
            && st != NINLIL_R7_FRAG_STATE_NEED_DIGEST
            && st != NINLIL_R7_FRAG_STATE_PUBLISHED) {
            return 24;
        }
    }
    st = ninlil_r7_frag_state_take_publication(
        &g_reasm, &ctx, &kgen, &th, pub, sizeof(pub), &pub_len);
    if (st != NINLIL_R7_FRAG_STATE_PUBLISHED || pub_len != 200u
        || memcmp(pub, payload, 200u) != 0 || g_reasm.publish_count != 1u) {
        return 25;
    }
    st = ninlil_r7_frag_state_take_publication(
        &g_reasm, &ctx, &kgen, &th, pub, sizeof(pub), &pub_len);
    if (st != NINLIL_R7_FRAG_STATE_NO_TRANSFER || g_reasm.publish_count != 1u) {
        return 26;
    }
    return 0;
}

static int32_t light_reorder_no_pub(const ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_cont_in cin;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[200];
    uint16_t i;
    ninlil_r7_frag_state_status st;

    (void)provider;
    for (i = 0u; i < 200u; i++) {
        payload[i] = (uint8_t)(0x40u + (i & 0x1fu));
    }
    if (ninlil_r7_frag_state_plan_build(200u, &plan) != NINLIL_R7_FRAG_STATE_OK
        || plan.frag_count < 2u) {
        return 30;
    }
    ninlil_r7_frag_state_zeroize(&g_reasm);
    ninlil_r7_frag_state_init(&g_reasm);
    ninlil_r7_frag_state_set_now(&g_reasm, 3000u);
    memset(&cin, 0, sizeof(cin));
    cin.e2e_context_id = 21u;
    cin.key_generation = 1u;
    cin.transfer_handle = 9u;
    cin.frag_index = 1u;
    cin.chunk = payload + plan.chunks[1].offset;
    cin.chunk_len = plan.chunks[1].length;
    memset(&intent, 0, sizeof(intent));
    st = ninlil_r7_frag_state_admit_cont(&g_reasm, &cin, &intent);
    if (st != NINLIL_R7_FRAG_STATE_NO_TRANSFER
        && st != NINLIL_R7_FRAG_STATE_OK
        && st != NINLIL_R7_FRAG_STATE_DUPLICATE) {
        return 32;
    }
    if (g_reasm.publish_count != 0u) {
        return 33;
    }
    return 0;
}

static int32_t light_restart_volatile(const ninlil_r7_crypto_provider *provider)
{
    (void)provider;
    ninlil_r7_frag_state_zeroize(&g_reasm);
    ninlil_r7_frag_state_init(&g_reasm);
    if (g_reasm.publish_count != 0u || g_reasm.reasm[0].in_use != 0u) {
        return 40;
    }
    return 0;
}

int32_t ninlil_r7_frag_target_smoke_run(
    const ninlil_r7_crypto_provider *provider)
{
    int32_t st;
    if (provider == NULL || provider->sha256 == NULL) {
        return 1;
    }
    st = light_plan_and_exact(provider);
    if (st != 0) {
        return st;
    }
    st = light_reorder_no_pub(provider);
    if (st != 0) {
        return st;
    }
    st = light_restart_volatile(provider);
    if (st != 0) {
        return st;
    }
    ninlil_r7_frag_state_zeroize(&g_reasm);
    return 0;
}

#else /* host lab: one session pair */

#include "r7_frag_session.h"

/* Single pair for all smoke vectors (not N×session BSS). */
static ninlil_r7_frag_sess g_tx;
static ninlil_r7_frag_sess g_rx;

static void keys_lab(ninlil_r7_frag_sess_keys *k)
{
    size_t i;
    for (i = 0u; i < 16u; i++) {
        k->e2e_key16[i] = (uint8_t)(0x10u + i);
        k->hop_data_key16[i] = (uint8_t)(0x30u + i);
        k->hop_ack_key16[i] = (uint8_t)(0x50u + i);
        k->rev_hop_ack_key16[i] = k->hop_ack_key16[i];
        k->rev_e2e_key16[i] = k->e2e_key16[i];
    }
    for (i = 0u; i < 12u; i++) {
        k->e2e_iv12[i] = (uint8_t)(0x20u + i);
        k->hop_data_iv12[i] = (uint8_t)(0x40u + i);
        k->hop_ack_iv12[i] = (uint8_t)(0x60u + i);
        k->rev_hop_ack_iv12[i] = k->hop_ack_iv12[i];
        k->rev_e2e_iv12[i] = k->e2e_iv12[i];
    }
}

static void install_pair(ninlil_r7_frag_sess *a, ninlil_r7_frag_sess *b)
{
    (void)ninlil_r7_frag_sess_install_lane(
        a, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(
        a, NINLIL_R7_FRAG_LANE_HOP_ACK, 12u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(a, NINLIL_R7_FRAG_LANE_E2E, 21u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(a, NINLIL_R7_FRAG_LANE_E2E, 22u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(
        b, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(
        b, NINLIL_R7_FRAG_LANE_HOP_ACK, 12u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(b, NINLIL_R7_FRAG_LANE_E2E, 21u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(b, NINLIL_R7_FRAG_LANE_E2E, 22u, 1u);
}

static void pair_reset(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_frag_sess_keys *k,
    uint64_t now)
{
    ninlil_r7_frag_sess_zeroize(&g_tx);
    ninlil_r7_frag_sess_zeroize(&g_rx);
    ninlil_r7_frag_sess_init(&g_tx, provider, k);
    ninlil_r7_frag_sess_init(&g_rx, provider, k);
    g_tx.now_mono = g_rx.now_mono = now;
    g_tx.ack_requested_default = 1u;
    install_pair(&g_tx, &g_rx);
}

static int32_t smoke_link_ack(const ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_frag_sess_keys k;
    uint8_t payload[80];
    uint8_t tid[16];
    uint8_t frame[255];
    size_t flen = 0u;
    uint16_t fi = 0u;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t la[64];
    size_t lalen = 0u;
    int32_t st;
    size_t i;

    keys_lab(&k);
    for (i = 0u; i < 80u; i++) {
        payload[i] = (uint8_t)i;
    }
    for (i = 0u; i < 16u; i++) {
        tid[i] = (uint8_t)(0xA0u + i);
    }
    pair_reset(provider, &k, 1000u);
    st = ninlil_r7_frag_sess_tx_begin(
        &g_tx, payload, 80u, tid, frame, sizeof(frame), &flen, &fi);
    if (st != NINLIL_R7_FRAG_SESS_OK || frame[0] != 0x11u) {
        return 10;
    }
    (void)ninlil_r7_frag_sess_tx_note_air(&g_tx, 0u, g_tx.tx.last_hop_counter[0]);
    st = ninlil_r7_frag_sess_rx_data(
        &g_rx, frame, flen, &intent, la, sizeof(la), &lalen);
    if (st != NINLIL_R7_FRAG_SESS_OK || lalen != 51u || la[0] != 0x11u) {
        return 11;
    }
    return 0;
}

static int32_t smoke_multi_frag_exact(const ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_frag_sess_keys k;
    uint8_t payload[200];
    uint8_t tid[16];
    uint8_t frames[8][255];
    size_t flens[8];
    uint16_t fi = 0u;
    uint16_t fc;
    uint16_t i;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t la[64];
    size_t lalen = 0u;
    uint8_t pub[256];
    size_t pub_len = 0u;
    int32_t st;

    keys_lab(&k);
    for (i = 0u; i < 200u; i++) {
        payload[i] = (uint8_t)(i * 3u);
    }
    for (i = 0u; i < 16u; i++) {
        tid[i] = (uint8_t)(0xB0u + i);
    }
    pair_reset(provider, &k, 2000u);
    st = ninlil_r7_frag_sess_tx_begin(
        &g_tx, payload, 200u, tid, frames[0], sizeof(frames[0]), &flens[0],
        &fi);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return 20;
    }
    fc = g_tx.tx.plan.frag_count;
    if (fc < 2u || fc > 8u) {
        return 21;
    }
    (void)ninlil_r7_frag_sess_tx_note_air(&g_tx, 0u, g_tx.tx.last_hop_counter[0]);
    for (i = 1u; i < fc; i++) {
        st = ninlil_r7_frag_sess_tx_air(
            &g_tx, i, frames[i], sizeof(frames[i]), &flens[i]);
        if (st != NINLIL_R7_FRAG_SESS_OK || frames[i][0] != 0x11u) {
            return 22;
        }
        (void)ninlil_r7_frag_sess_tx_note_air(
            &g_tx, i, g_tx.tx.last_hop_counter[i]);
    }
    for (i = 0u; i < fc; i++) {
        lalen = 0u;
        st = ninlil_r7_frag_sess_rx_data(
            &g_rx, frames[i], flens[i], &intent, la, sizeof(la), &lalen);
        if (st != NINLIL_R7_FRAG_SESS_OK && st != NINLIL_R7_FRAG_SESS_DONE
            && st != NINLIL_R7_FRAG_SESS_NO_PUB) {
            return 23;
        }
    }
    st = ninlil_r7_frag_sess_take_publication(
        &g_rx, pub, sizeof(pub), &pub_len);
    if (st != NINLIL_R7_FRAG_SESS_OK || pub_len != 200u
        || memcmp(pub, payload, 200u) != 0 || g_rx.publish_count != 1u) {
        return 24;
    }
    st = ninlil_r7_frag_sess_rx_data(
        &g_rx, frames[0], flens[0], &intent, la, sizeof(la), &lalen);
    if (st != NINLIL_R7_FRAG_SESS_REPLAY && st != NINLIL_R7_FRAG_SESS_OK
        && st != NINLIL_R7_FRAG_SESS_DONE && st != NINLIL_R7_FRAG_SESS_NO_PUB) {
        return 25;
    }
    st = ninlil_r7_frag_sess_take_publication(
        &g_rx, pub, sizeof(pub), &pub_len);
    if (st != NINLIL_R7_FRAG_SESS_NO_PUB || g_rx.publish_count != 1u) {
        return 26;
    }
    return 0;
}

static int32_t smoke_reorder_loss(const ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_frag_sess_keys k;
    uint8_t payload[200];
    uint8_t tid[16];
    uint8_t f0[255];
    uint8_t f1[255];
    size_t l0 = 0u;
    size_t l1 = 0u;
    uint16_t fi = 0u;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t la[64];
    size_t lalen = 0u;
    int32_t st;
    size_t i;

    keys_lab(&k);
    for (i = 0u; i < 200u; i++) {
        payload[i] = (uint8_t)(0x40u + (i & 0x1fu));
    }
    for (i = 0u; i < 16u; i++) {
        tid[i] = (uint8_t)(0xC0u + i);
    }
    pair_reset(provider, &k, 3000u);
    st = ninlil_r7_frag_sess_tx_begin(
        &g_tx, payload, 200u, tid, f0, sizeof(f0), &l0, &fi);
    if (st != NINLIL_R7_FRAG_SESS_OK || g_tx.tx.plan.frag_count < 2u) {
        return 30;
    }
    st = ninlil_r7_frag_sess_tx_air(&g_tx, 1u, f1, sizeof(f1), &l1);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return 31;
    }
    st = ninlil_r7_frag_sess_rx_data(
        &g_rx, f1, l1, &intent, la, sizeof(la), &lalen);
    if (st != NINLIL_R7_FRAG_SESS_NO_PUB && st != NINLIL_R7_FRAG_SESS_OK
        && st != NINLIL_R7_FRAG_SESS_REPLAY) {
        return 32;
    }
    if (g_rx.publish_count != 0u) {
        return 33;
    }
    return 0;
}

static int32_t smoke_restart_volatile(const ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_frag_sess_keys k;
    keys_lab(&k);
    pair_reset(provider, &k, 4000u);
    if (g_rx.publish_count != 0u) {
        return 40;
    }
    ninlil_r7_frag_sess_zeroize(&g_rx);
    ninlil_r7_frag_sess_init(&g_rx, provider, &k);
    if (g_rx.publish_count != 0u) {
        return 41;
    }
    return 0;
}

static int32_t smoke_fresh_hop_retry(const ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_frag_sess_keys k;
    uint8_t payload[80];
    uint8_t tid[16];
    uint8_t f0[255];
    uint8_t f1[255];
    size_t l0 = 0u;
    size_t l1 = 0u;
    uint16_t fi = 0u;
    uint64_t e2e0;
    uint64_t hop0;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t la[64];
    size_t lalen = 0u;
    int32_t st;
    size_t i;

    keys_lab(&k);
    for (i = 0u; i < 80u; i++) {
        payload[i] = (uint8_t)(0x10u + i);
    }
    for (i = 0u; i < 16u; i++) {
        tid[i] = (uint8_t)(0xD0u + i);
    }
    pair_reset(provider, &k, 5000u);
    st = ninlil_r7_frag_sess_tx_begin(
        &g_tx, payload, 80u, tid, f0, sizeof(f0), &l0, &fi);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return 50;
    }
    e2e0 = g_tx.tx.e2e_counter[0];
    hop0 = g_tx.tx.last_hop_counter[0];
    (void)ninlil_r7_frag_sess_tx_note_air(&g_tx, 0u, hop0);
    st = ninlil_r7_frag_sess_rx_data(
        &g_rx, f0, l0, &intent, la, sizeof(la), &lalen);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return 51;
    }
    g_tx.now_mono += 4000u;
    st = ninlil_r7_frag_sess_tx_air(&g_tx, 0u, f1, sizeof(f1), &l1);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return 52;
    }
    if (g_tx.tx.e2e_counter[0] != e2e0) {
        return 53;
    }
    if (g_tx.tx.last_hop_counter[0] == hop0) {
        return 54;
    }
    if (f1[0] != 0x11u) {
        return 55;
    }
    return 0;
}

int32_t ninlil_r7_frag_target_smoke_run(
    const ninlil_r7_crypto_provider *provider)
{
    int32_t st;
    if (provider == NULL || provider->sha256 == NULL
        || provider->aes128_gcm_seal == NULL
        || provider->aes128_gcm_open == NULL) {
        return 1;
    }
    st = smoke_link_ack(provider);
    if (st != 0) {
        return st;
    }
    st = smoke_multi_frag_exact(provider);
    if (st != 0) {
        return st;
    }
    st = smoke_reorder_loss(provider);
    if (st != 0) {
        return st;
    }
    st = smoke_restart_volatile(provider);
    if (st != 0) {
        return st;
    }
    st = smoke_fresh_hop_retry(provider);
    if (st != 0) {
        return st;
    }
    ninlil_r7_frag_sess_zeroize(&g_tx);
    ninlil_r7_frag_sess_zeroize(&g_rx);
    return 0;
}

#endif /* R7_FRAG_SMOKE_USE_LIGHT */
