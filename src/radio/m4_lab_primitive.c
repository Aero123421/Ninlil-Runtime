/*
 * M4 LAB Join/Attachment — C1 stateless primitives implementation.
 */

#include "m4_lab_primitive.h"

#include "domain_store_codec.h"

#include <string.h>

#define M4_LAB_FRAME_HDR_LEN  ((size_t)8u)
#define M4_LAB_FRAME_CRC_LEN  ((size_t)4u)
#define M4_LAB_FRAME_MIN_LEN  (M4_LAB_FRAME_HDR_LEN + M4_LAB_FRAME_CRC_LEN)

#define M4_LAB_REQ_BODY_LEN   ((size_t)59u)
#define M4_LAB_REQ_FRAME_LEN  (M4_LAB_FRAME_HDR_LEN + M4_LAB_REQ_BODY_LEN + M4_LAB_FRAME_CRC_LEN)

#define M4_LAB_CH_BODY_LEN    ((size_t)36u)
#define M4_LAB_CH_FRAME_LEN   (M4_LAB_FRAME_HDR_LEN + M4_LAB_CH_BODY_LEN + M4_LAB_FRAME_CRC_LEN)

#define M4_LAB_RESP_BODY_LEN  ((size_t)36u)
#define M4_LAB_RESP_FRAME_LEN (M4_LAB_FRAME_HDR_LEN + M4_LAB_RESP_BODY_LEN + M4_LAB_FRAME_CRC_LEN)

#define M4_LAB_INST_BODY_LEN  ((size_t)36u)
#define M4_LAB_INST_FRAME_LEN (M4_LAB_FRAME_HDR_LEN + M4_LAB_INST_BODY_LEN + M4_LAB_FRAME_CRC_LEN)

#define M4_LAB_REJ_BODY_LEN   ((size_t)4u)
#define M4_LAB_REJ_FRAME_LEN  (M4_LAB_FRAME_HDR_LEN + M4_LAB_REJ_BODY_LEN + M4_LAB_FRAME_CRC_LEN)

#define M4_LAB_ENV_LAB ((uint8_t)1u)

static void m4_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
}

static void m4_store_u16_be(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)((v >> 8) & 0xffu);
    out[1] = (uint8_t)(v & 0xffu);
}

static void m4_store_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static void m4_store_u64_be(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)((v >> 56) & 0xffu);
    out[1] = (uint8_t)((v >> 48) & 0xffu);
    out[2] = (uint8_t)((v >> 40) & 0xffu);
    out[3] = (uint8_t)((v >> 32) & 0xffu);
    out[4] = (uint8_t)((v >> 24) & 0xffu);
    out[5] = (uint8_t)((v >> 16) & 0xffu);
    out[6] = (uint8_t)((v >> 8) & 0xffu);
    out[7] = (uint8_t)(v & 0xffu);
}

static uint16_t m4_load_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t m4_load_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t m4_load_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

static int m4_bytes_all_zero(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int m4_stable_id_valid(uint8_t len, const uint8_t *bytes)
{
    if (len == 0u || len > NINLIL_M4_LAB_STABLE_ID_MAX) {
        return 0;
    }
    if (m4_bytes_all_zero(bytes, (size_t)len) != 0) {
        return 0;
    }
    return 1;
}

static int m4_site_domain_valid(uint8_t len, const uint8_t *bytes)
{
    if (len == 0u || len > NINLIL_M4_LAB_SITE_DOMAIN_MAX) {
        return 0;
    }
    if (m4_bytes_all_zero(bytes, (size_t)len) != 0) {
        return 0;
    }
    return 1;
}

static int m4_tail_zero(const uint8_t *p, size_t used, size_t cap)
{
    size_t i;

    for (i = used; i < cap; i++) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int m4_write_header(
    uint8_t *out,
    size_t out_capacity,
    uint8_t frame_type,
    uint16_t total_len)
{
    if (out_capacity < M4_LAB_FRAME_MIN_LEN) {
        return 0;
    }
    out[0] = NINLIL_M4_LAB_MAGIC_0;
    out[1] = NINLIL_M4_LAB_MAGIC_1;
    out[2] = NINLIL_M4_LAB_MAGIC_2;
    out[3] = NINLIL_M4_LAB_MAGIC_3;
    out[4] = NINLIL_M4_LAB_FRAME_VERSION;
    out[5] = frame_type;
    m4_store_u16_be(out + 6, total_len);
    return 1;
}

static ninlil_m4_lab_status_t m4_parse_header(
    const uint8_t *frame,
    size_t frame_len,
    uint8_t expected_type,
    uint16_t expected_total)
{
    uint16_t total;

    if (frame == NULL || frame_len < M4_LAB_FRAME_MIN_LEN) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (frame[0] != NINLIL_M4_LAB_MAGIC_0
        || frame[1] != NINLIL_M4_LAB_MAGIC_1
        || frame[2] != NINLIL_M4_LAB_MAGIC_2
        || frame[3] != NINLIL_M4_LAB_MAGIC_3) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (frame[4] != NINLIL_M4_LAB_FRAME_VERSION) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (frame[5] != expected_type) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    total = m4_load_u16_be(frame + 6);
    if (total != expected_total || frame_len != (size_t)total) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (ninlil_m4_lab_frame_verify_crc(frame, frame_len) == 0) {
        return NINLIL_M4_LAB_CRC;
    }
    return NINLIL_M4_LAB_OK;
}

static void m4_append_crc(uint8_t *frame, size_t frame_len_without_crc)
{
    uint32_t crc = ninlil_m4_lab_crc32c(frame, frame_len_without_crc);
    m4_store_u32_be(frame + frame_len_without_crc, crc);
}

static int m4_hmac_sha256(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out32[32])
{
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t key_block[64];
    uint8_t inner_hash[32];
    uint8_t inner_msg[64u + 512u];
    uint8_t outer_msg[96];
    size_t i;
    ninlil_r7_crypto_status st;

    if (provider == NULL || key == NULL || msg == NULL || out32 == NULL) {
        return 0;
    }
    if (msg_len > 512u) {
        return 0;
    }

    (void)memset(key_block, 0, sizeof(key_block));
    if (key_len > 64u) {
        st = ninlil_r7_crypto_sha256(provider, key, key_len, key_block);
        if (st != NINLIL_R7_CRYPTO_OK) {
            m4_secure_zero(key_block, sizeof(key_block));
            return 0;
        }
        key_len = 32u;
    } else {
        (void)memcpy(key_block, key, key_len);
    }

    for (i = 0u; i < 64u; i++) {
        uint8_t kb = (i < key_len) ? key_block[i] : 0u;
        ipad[i] = (uint8_t)(kb ^ 0x36u);
        opad[i] = (uint8_t)(kb ^ 0x5cu);
    }
    m4_secure_zero(key_block, sizeof(key_block));

    (void)memcpy(inner_msg, ipad, 64u);
    (void)memcpy(inner_msg + 64u, msg, msg_len);
    st = ninlil_r7_crypto_sha256(
        provider, inner_msg, 64u + msg_len, inner_hash);
    m4_secure_zero(ipad, sizeof(ipad));
    m4_secure_zero(inner_msg, sizeof(inner_msg));
    if (st != NINLIL_R7_CRYPTO_OK) {
        m4_secure_zero(inner_hash, sizeof(inner_hash));
        return 0;
    }

    (void)memcpy(outer_msg, opad, 64u);
    (void)memcpy(outer_msg + 64u, inner_hash, 32u);
    m4_secure_zero(inner_hash, sizeof(inner_hash));
    st = ninlil_r7_crypto_sha256(provider, outer_msg, 96u, out32);
    m4_secure_zero(opad, sizeof(opad));
    m4_secure_zero(outer_msg, sizeof(outer_msg));
    return (st == NINLIL_R7_CRYPTO_OK) ? 1 : 0;
}

uint32_t ninlil_m4_lab_crc32c(const uint8_t *bytes, size_t len)
{
    if (bytes == NULL || len > UINT32_MAX) {
        return 0u;
    }
    return ninlil_model_domain_crc32c(bytes, (uint32_t)len);
}

int ninlil_m4_lab_frame_verify_crc(
    const uint8_t *frame,
    size_t frame_len)
{
    uint32_t wire;
    uint32_t calc;

    if (frame == NULL || frame_len < M4_LAB_FRAME_MIN_LEN) {
        return 0;
    }
    wire = m4_load_u32_be(frame + frame_len - M4_LAB_FRAME_CRC_LEN);
    calc = ninlil_m4_lab_crc32c(frame, frame_len - M4_LAB_FRAME_CRC_LEN);
    return (wire == calc) ? 1 : 0;
}

ninlil_m4_lab_status_t ninlil_m4_lab_identity_proof_compute(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t root_key32[NINLIL_M4_LAB_ROOT_KEY_LEN],
    const uint8_t *challenge_frame,
    size_t challenge_frame_len,
    ninlil_m4_lab_bytes_t stable_id,
    uint8_t out_proof[NINLIL_M4_LAB_PROOF_LEN])
{
    uint8_t msg[512];
    size_t msg_len;

    if (provider == NULL || root_key32 == NULL || challenge_frame == NULL
        || out_proof == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (!m4_stable_id_valid(stable_id.length, stable_id.bytes)) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (challenge_frame_len < M4_LAB_FRAME_MIN_LEN
        || challenge_frame_len > sizeof(msg)) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (ninlil_m4_lab_frame_verify_crc(challenge_frame, challenge_frame_len)
        == 0) {
        return NINLIL_M4_LAB_CRC;
    }

    msg_len = challenge_frame_len - M4_LAB_FRAME_CRC_LEN;
    (void)memcpy(msg, challenge_frame, msg_len);
    (void)memcpy(msg + msg_len, stable_id.bytes, (size_t)stable_id.length);
    msg_len += (size_t)stable_id.length;

    if (m4_hmac_sha256(
            provider,
            root_key32,
            NINLIL_M4_LAB_ROOT_KEY_LEN,
            msg,
            msg_len,
            out_proof)
        == 0) {
        m4_secure_zero(msg, sizeof(msg));
        m4_secure_zero(out_proof, NINLIL_M4_LAB_PROOF_LEN);
        return NINLIL_M4_LAB_BACKEND_FAILED;
    }
    m4_secure_zero(msg, sizeof(msg));
    return NINLIL_M4_LAB_OK;
}

ninlil_m4_lab_status_t ninlil_m4_lab_identity_proof_verify(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t root_key32[NINLIL_M4_LAB_ROOT_KEY_LEN],
    const uint8_t *challenge_frame,
    size_t challenge_frame_len,
    ninlil_m4_lab_bytes_t stable_id,
    const uint8_t proof[NINLIL_M4_LAB_PROOF_LEN])
{
    uint8_t expected[NINLIL_M4_LAB_PROOF_LEN];
    ninlil_m4_lab_status_t st;
    uint8_t diff = 0u;
    size_t i;

    st = ninlil_m4_lab_identity_proof_compute(
        provider,
        root_key32,
        challenge_frame,
        challenge_frame_len,
        stable_id,
        expected);
    if (st != NINLIL_M4_LAB_OK) {
        m4_secure_zero(expected, sizeof(expected));
        return st;
    }
    for (i = 0u; i < NINLIL_M4_LAB_PROOF_LEN; i++) {
        diff = (uint8_t)(diff | (uint8_t)(expected[i] ^ proof[i]));
    }
    m4_secure_zero(expected, sizeof(expected));
    return (diff == 0u) ? NINLIL_M4_LAB_OK : NINLIL_M4_LAB_CREDENTIAL;
}

int ninlil_m4_lab_challenge_not_expired(
    uint64_t now_ms,
    uint64_t expires_ms)
{
    return (now_ms <= expires_ms) ? 1 : 0;
}

int32_t ninlil_m4_lab_encode_join_request(
    const ninlil_m4_lab_join_request_t *req,
    uint8_t *out,
    size_t out_capacity)
{
    size_t off;

    if (req == NULL || out == NULL) {
        return (int32_t)NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (req->environment_code != M4_LAB_ENV_LAB
        || !m4_site_domain_valid(req->site_domain_len, req->site_domain)
        || !m4_stable_id_valid(
            req->device_stable_id_len, req->device_stable_id)
        || req->membership_epoch == 0u) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (!m4_tail_zero(
            req->site_domain,
            (size_t)req->site_domain_len,
            NINLIL_M4_LAB_SITE_DOMAIN_MAX)
        || !m4_tail_zero(
            req->device_stable_id,
            (size_t)req->device_stable_id_len,
            NINLIL_M4_LAB_STABLE_ID_MAX)) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (out_capacity < M4_LAB_REQ_FRAME_LEN) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (m4_write_header(
            out,
            out_capacity,
            NINLIL_M4_LAB_FRAME_JOIN_REQUEST,
            (uint16_t)M4_LAB_REQ_FRAME_LEN)
        == 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    m4_store_u64_be(out + off, req->membership_epoch);
    off += 8u;
    out[off++] = req->environment_code;
    out[off++] = req->site_domain_len;
    (void)memcpy(out + off, req->site_domain, NINLIL_M4_LAB_SITE_DOMAIN_MAX);
    off += NINLIL_M4_LAB_SITE_DOMAIN_MAX;
    out[off++] = req->device_stable_id_len;
    (void)memcpy(
        out + off, req->device_stable_id, NINLIL_M4_LAB_STABLE_ID_MAX);
    off += NINLIL_M4_LAB_STABLE_ID_MAX;
    m4_append_crc(out, off);
    return (int32_t)M4_LAB_REQ_FRAME_LEN;
}

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_request(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_request_t *out)
{
    ninlil_m4_lab_status_t st;
    size_t off;

    if (out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    st = m4_parse_header(
        frame,
        frame_len,
        NINLIL_M4_LAB_FRAME_JOIN_REQUEST,
        (uint16_t)M4_LAB_REQ_FRAME_LEN);
    if (st != NINLIL_M4_LAB_OK) {
        return st;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    out->membership_epoch = m4_load_u64_be(frame + off);
    off += 8u;
    out->environment_code = frame[off++];
    out->site_domain_len = frame[off++];
    (void)memcpy(out->site_domain, frame + off, NINLIL_M4_LAB_SITE_DOMAIN_MAX);
    off += NINLIL_M4_LAB_SITE_DOMAIN_MAX;
    out->device_stable_id_len = frame[off++];
    (void)memcpy(
        out->device_stable_id, frame + off, NINLIL_M4_LAB_STABLE_ID_MAX);
    if (out->environment_code != M4_LAB_ENV_LAB
        || !m4_site_domain_valid(out->site_domain_len, out->site_domain)
        || !m4_stable_id_valid(
            out->device_stable_id_len, out->device_stable_id)
        || out->membership_epoch == 0u) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (!m4_tail_zero(
            out->site_domain,
            (size_t)out->site_domain_len,
            NINLIL_M4_LAB_SITE_DOMAIN_MAX)
        || !m4_tail_zero(
            out->device_stable_id,
            (size_t)out->device_stable_id_len,
            NINLIL_M4_LAB_STABLE_ID_MAX)) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    return NINLIL_M4_LAB_OK;
}

int32_t ninlil_m4_lab_encode_join_challenge(
    const ninlil_m4_lab_join_challenge_t *ch,
    uint8_t *out,
    size_t out_capacity)
{
    size_t off;

    if (ch == NULL || out == NULL) {
        return (int32_t)NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (ch->membership_epoch == 0u || ch->session_id == 0u
        || m4_bytes_all_zero(ch->nonce, NINLIL_M4_LAB_NONCE_LEN) != 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (out_capacity < M4_LAB_CH_FRAME_LEN) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (m4_write_header(
            out,
            out_capacity,
            NINLIL_M4_LAB_FRAME_JOIN_CHALLENGE,
            (uint16_t)M4_LAB_CH_FRAME_LEN)
        == 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    (void)memcpy(out + off, ch->nonce, NINLIL_M4_LAB_NONCE_LEN);
    off += NINLIL_M4_LAB_NONCE_LEN;
    m4_store_u64_be(out + off, ch->expires_ms);
    off += 8u;
    m4_store_u64_be(out + off, ch->membership_epoch);
    off += 8u;
    m4_store_u32_be(out + off, ch->session_id);
    off += 4u;
    m4_append_crc(out, off);
    return (int32_t)M4_LAB_CH_FRAME_LEN;
}

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_challenge(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_challenge_t *out)
{
    ninlil_m4_lab_status_t st;
    size_t off;

    if (out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    st = m4_parse_header(
        frame,
        frame_len,
        NINLIL_M4_LAB_FRAME_JOIN_CHALLENGE,
        (uint16_t)M4_LAB_CH_FRAME_LEN);
    if (st != NINLIL_M4_LAB_OK) {
        return st;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    (void)memcpy(out->nonce, frame + off, NINLIL_M4_LAB_NONCE_LEN);
    off += NINLIL_M4_LAB_NONCE_LEN;
    out->expires_ms = m4_load_u64_be(frame + off);
    off += 8u;
    out->membership_epoch = m4_load_u64_be(frame + off);
    off += 8u;
    out->session_id = m4_load_u32_be(frame + off);
    if (out->membership_epoch == 0u || out->session_id == 0u
        || m4_bytes_all_zero(out->nonce, NINLIL_M4_LAB_NONCE_LEN) != 0) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    return NINLIL_M4_LAB_OK;
}

int32_t ninlil_m4_lab_encode_join_response(
    const ninlil_m4_lab_join_response_t *resp,
    uint8_t *out,
    size_t out_capacity)
{
    size_t off;

    if (resp == NULL || out == NULL) {
        return (int32_t)NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (resp->session_id == 0u
        || m4_bytes_all_zero(resp->proof_hmac, NINLIL_M4_LAB_PROOF_LEN) != 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (out_capacity < M4_LAB_RESP_FRAME_LEN) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (m4_write_header(
            out,
            out_capacity,
            NINLIL_M4_LAB_FRAME_JOIN_RESPONSE,
            (uint16_t)M4_LAB_RESP_FRAME_LEN)
        == 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    m4_store_u32_be(out + off, resp->session_id);
    off += 4u;
    (void)memcpy(out + off, resp->proof_hmac, NINLIL_M4_LAB_PROOF_LEN);
    off += NINLIL_M4_LAB_PROOF_LEN;
    m4_append_crc(out, off);
    return (int32_t)M4_LAB_RESP_FRAME_LEN;
}

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_response(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_response_t *out)
{
    ninlil_m4_lab_status_t st;
    size_t off;

    if (out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    st = m4_parse_header(
        frame,
        frame_len,
        NINLIL_M4_LAB_FRAME_JOIN_RESPONSE,
        (uint16_t)M4_LAB_RESP_FRAME_LEN);
    if (st != NINLIL_M4_LAB_OK) {
        return st;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    out->session_id = m4_load_u32_be(frame + off);
    off += 4u;
    (void)memcpy(out->proof_hmac, frame + off, NINLIL_M4_LAB_PROOF_LEN);
    if (out->session_id == 0u
        || m4_bytes_all_zero(out->proof_hmac, NINLIL_M4_LAB_PROOF_LEN) != 0) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    return NINLIL_M4_LAB_OK;
}

int32_t ninlil_m4_lab_encode_join_install(
    const ninlil_m4_lab_join_install_t *inst,
    uint8_t *out,
    size_t out_capacity)
{
    size_t off;

    if (inst == NULL || out == NULL) {
        return (int32_t)NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (inst->session_id == 0u
        || m4_bytes_all_zero(inst->token_fingerprint, 32u) != 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (out_capacity < M4_LAB_INST_FRAME_LEN) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (m4_write_header(
            out,
            out_capacity,
            NINLIL_M4_LAB_FRAME_JOIN_INSTALL,
            (uint16_t)M4_LAB_INST_FRAME_LEN)
        == 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    m4_store_u32_be(out + off, inst->session_id);
    off += 4u;
    (void)memcpy(out + off, inst->token_fingerprint, 32u);
    off += 32u;
    m4_append_crc(out, off);
    return (int32_t)M4_LAB_INST_FRAME_LEN;
}

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_install(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_install_t *out)
{
    ninlil_m4_lab_status_t st;
    size_t off;

    if (out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    st = m4_parse_header(
        frame,
        frame_len,
        NINLIL_M4_LAB_FRAME_JOIN_INSTALL,
        (uint16_t)M4_LAB_INST_FRAME_LEN);
    if (st != NINLIL_M4_LAB_OK) {
        return st;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    out->session_id = m4_load_u32_be(frame + off);
    off += 4u;
    (void)memcpy(out->token_fingerprint, frame + off, 32u);
    if (out->session_id == 0u
        || m4_bytes_all_zero(out->token_fingerprint, 32u) != 0) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    return NINLIL_M4_LAB_OK;
}

int32_t ninlil_m4_lab_encode_join_reject(
    const ninlil_m4_lab_join_reject_t *rej,
    uint8_t *out,
    size_t out_capacity)
{
    size_t off;

    if (rej == NULL || out == NULL) {
        return (int32_t)NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (out_capacity < M4_LAB_REJ_FRAME_LEN) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    if (m4_write_header(
            out,
            out_capacity,
            NINLIL_M4_LAB_FRAME_JOIN_REJECT,
            (uint16_t)M4_LAB_REJ_FRAME_LEN)
        == 0) {
        return (int32_t)NINLIL_M4_LAB_STRUCTURAL;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    m4_store_u32_be(out + off, rej->reason);
    off += 4u;
    m4_append_crc(out, off);
    return (int32_t)M4_LAB_REJ_FRAME_LEN;
}

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_reject(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_reject_t *out)
{
    ninlil_m4_lab_status_t st;
    size_t off;

    if (out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    st = m4_parse_header(
        frame,
        frame_len,
        NINLIL_M4_LAB_FRAME_JOIN_REJECT,
        (uint16_t)M4_LAB_REJ_FRAME_LEN);
    if (st != NINLIL_M4_LAB_OK) {
        return st;
    }
    off = M4_LAB_FRAME_HDR_LEN;
    out->reason = m4_load_u32_be(frame + off);
    return NINLIL_M4_LAB_OK;
}
