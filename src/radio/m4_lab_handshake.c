/*
 * M4 LAB Join/Attachment handshake state machine.
 */

#include "m4_lab_handshake.h"

#include <string.h>

static void m4_result_clear(ninlil_m4_lab_handshake_step_result_t *out)
{
    if (out == NULL) {
        return;
    }
    (void)memset(out, 0, sizeof(*out));
    out->new_state = NINLIL_M4_LAB_ATTACHMENT_DETACHED;
}

static void m4_result_reject(
    ninlil_m4_lab_handshake_step_result_t *out,
    uint32_t reason,
    ninlil_m4_lab_attachment_state_t state)
{
    ninlil_m4_lab_join_reject_t rej;
    int32_t enc;

    m4_result_clear(out);
    out->success = 0;
    out->reject_reason = reason;
    out->new_state = state;
    out->out_frame_type = NINLIL_M4_LAB_FRAME_JOIN_REJECT;
    rej.reason = reason;
    enc = ninlil_m4_lab_encode_join_reject(
        &rej, out->out_frame, sizeof(out->out_frame));
    if (enc > 0) {
        out->out_frame_len = (size_t)enc;
    }
}

static void m4_result_success(
    ninlil_m4_lab_handshake_step_result_t *out,
    const uint8_t *frame,
    size_t frame_len,
    uint8_t frame_type,
    ninlil_m4_lab_attachment_state_t state)
{
    uint8_t scratch[NINLIL_M4_LAB_HANDSHAKE_FRAME_MAX];
    size_t copy_len = 0u;

    if (frame != NULL && frame_len > 0u
        && frame_len <= sizeof(scratch)) {
        (void)memcpy(scratch, frame, frame_len);
        copy_len = frame_len;
    }
    m4_result_clear(out);
    out->success = 1;
    out->new_state = state;
    out->out_frame_type = frame_type;
    if (copy_len > 0u) {
        (void)memcpy(out->out_frame, scratch, copy_len);
        out->out_frame_len = copy_len;
    }
}

static int m4_replay_seen(
    ninlil_m4_lab_handshake_context_t *ctx,
    uint32_t session_id)
{
    uint32_t i;

    for (i = 0u; i < ctx->replay_count; i++) {
        if (ctx->replay_ids[i] == session_id) {
            return 1;
        }
    }
    return 0;
}

static void m4_replay_record(
    ninlil_m4_lab_handshake_context_t *ctx,
    uint32_t session_id)
{
    if (ctx->replay_count < NINLIL_M4_LAB_REPLAY_WINDOW) {
        ctx->replay_ids[ctx->replay_count] = session_id;
        ctx->replay_count += 1u;
        return;
    }
    (void)memmove(
        ctx->replay_ids,
        ctx->replay_ids + 1u,
        (size_t)(NINLIL_M4_LAB_REPLAY_WINDOW - 1u) * sizeof(uint32_t));
    ctx->replay_ids[NINLIL_M4_LAB_REPLAY_WINDOW - 1u] = session_id;
}

void ninlil_m4_lab_handshake_init(
    ninlil_m4_lab_handshake_context_t *ctx,
    ninlil_m4_lab_handshake_role_t role,
    ninlil_m4_lab_membership_registry_t *membership,
    const ninlil_r7_crypto_provider *provider,
    const ninlil_m4_lab_handshake_config_t *config)
{
    if (ctx == NULL) {
        return;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->role = role;
    ctx->state = NINLIL_M4_LAB_ATTACHMENT_DETACHED;
    ctx->membership = membership;
    ctx->provider = provider;
    if (config != NULL) {
        ctx->config = *config;
    }
}

ninlil_m4_lab_status_t ninlil_m4_lab_handshake_endpoint_begin(
    ninlil_m4_lab_handshake_context_t *ctx,
    const ninlil_m4_lab_credential_t *endpoint_cred,
    ninlil_m4_lab_handshake_step_result_t *out)
{
    ninlil_m4_lab_join_request_t req;
    ninlil_m4_lab_bytes_t stable;
    int32_t enc;

    if (ctx == NULL || endpoint_cred == NULL || out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (ctx->role != NINLIL_M4_LAB_ROLE_ENDPOINT
        || ctx->state != NINLIL_M4_LAB_ATTACHMENT_DETACHED) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    stable.bytes = endpoint_cred->stable_id;
    stable.length = endpoint_cred->stable_id_len;
    if (ninlil_m4_lab_membership_confirm_active(
            ctx->membership, stable, ctx->config.membership_epoch)
        != NINLIL_M4_LAB_OK) {
        m4_result_reject(
            out,
            NINLIL_M4_LAB_REJECT_MEMBERSHIP,
            NINLIL_M4_LAB_ATTACHMENT_DETACHED);
        return NINLIL_M4_LAB_OK;
    }

    (void)memset(&req, 0, sizeof(req));
    req.membership_epoch = ctx->config.membership_epoch;
    req.environment_code = 1u;
    req.site_domain_len = ctx->config.site_domain_len;
    (void)memcpy(req.site_domain, ctx->config.site_domain, 16u);
    req.device_stable_id_len = endpoint_cred->stable_id_len;
    (void)memcpy(
        req.device_stable_id, endpoint_cred->stable_id, 32u);

    enc = ninlil_m4_lab_encode_join_request(
        &req, out->out_frame, sizeof(out->out_frame));
    if (enc <= 0) {
        m4_result_reject(
            out,
            NINLIL_M4_LAB_REJECT_STRUCTURAL,
            NINLIL_M4_LAB_ATTACHMENT_DETACHED);
        return NINLIL_M4_LAB_OK;
    }

    ctx->last_request = req;
    ctx->has_request = 1;
    ctx->state = NINLIL_M4_LAB_ATTACHMENT_DISCOVERING;
    m4_result_success(
        out,
        out->out_frame,
        (size_t)enc,
        NINLIL_M4_LAB_FRAME_JOIN_REQUEST,
        NINLIL_M4_LAB_ATTACHMENT_DISCOVERING);
    return NINLIL_M4_LAB_OK;
}

ninlil_m4_lab_status_t ninlil_m4_lab_handshake_controller_on_request(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_handshake_step_result_t *out)
{
    ninlil_m4_lab_join_request_t req;
    ninlil_m4_lab_join_challenge_t ch;
    ninlil_m4_lab_bytes_t stable;
    ninlil_m4_lab_status_t st;
    int32_t enc;
    uint8_t nonce_buf[32];

    if (ctx == NULL || frame == NULL || out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (ctx->role != NINLIL_M4_LAB_ROLE_CONTROLLER
        || ctx->provider == NULL || ctx->membership == NULL) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    st = ninlil_m4_lab_decode_join_request(frame, frame_len, &req);
    if (st == NINLIL_M4_LAB_CRC) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CRC, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (st != NINLIL_M4_LAB_OK) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_STRUCTURAL, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    stable.bytes = req.device_stable_id;
    stable.length = req.device_stable_id_len;
    if (ninlil_m4_lab_membership_confirm_active(
            ctx->membership, stable, req.membership_epoch)
        != NINLIL_M4_LAB_OK) {
        m4_result_reject(
            out,
            NINLIL_M4_LAB_REJECT_MEMBERSHIP,
            NINLIL_M4_LAB_ATTACHMENT_DETACHED);
        return NINLIL_M4_LAB_OK;
    }
    if (req.membership_epoch != ctx->config.membership_epoch) {
        m4_result_reject(
            out,
            NINLIL_M4_LAB_REJECT_MEMBERSHIP,
            NINLIL_M4_LAB_ATTACHMENT_DETACHED);
        return NINLIL_M4_LAB_OK;
    }

    ctx->last_request = req;
    ctx->has_request = 1;
    ctx->active_session_id = ctx->config.next_session_id;
    ctx->config.next_session_id += 1u;
    if (ctx->config.next_session_id == 0u) {
        ctx->config.next_session_id = 1u;
    }

    (void)memset(&ch, 0, sizeof(ch));
    ch.expires_ms = ctx->now_ms + NINLIL_M4_LAB_CHALLENGE_TTL_MS;
    ch.membership_epoch = req.membership_epoch;
    ch.session_id = ctx->active_session_id;
    (void)memset(nonce_buf, 0, sizeof(nonce_buf));
    (void)memcpy(nonce_buf, &ctx->active_session_id, sizeof(uint32_t));
    (void)memcpy(nonce_buf + 4u, &ctx->now_ms, sizeof(uint64_t));
    {
        uint8_t nonce_digest[32];
        if (ninlil_r7_crypto_sha256(
                ctx->provider, nonce_buf, sizeof(nonce_buf), nonce_digest)
            != NINLIL_R7_CRYPTO_OK) {
            m4_result_reject(
                out,
                NINLIL_M4_LAB_REJECT_STRUCTURAL,
                NINLIL_M4_LAB_ATTACHMENT_DETACHED);
            return NINLIL_M4_LAB_OK;
        }
        (void)memcpy(ch.nonce, nonce_digest, NINLIL_M4_LAB_NONCE_LEN);
    }

    enc = ninlil_m4_lab_encode_join_challenge(
        &ch, out->out_frame, sizeof(out->out_frame));
    if (enc <= 0) {
        m4_result_reject(
            out,
            NINLIL_M4_LAB_REJECT_STRUCTURAL,
            NINLIL_M4_LAB_ATTACHMENT_DETACHED);
        return NINLIL_M4_LAB_OK;
    }

    (void)memcpy(
        ctx->challenge_frame, out->out_frame, (size_t)enc);
    ctx->challenge_frame_len = (size_t)enc;
    (void)memcpy(ctx->challenge_nonce, ch.nonce, NINLIL_M4_LAB_NONCE_LEN);
    ctx->challenge_expires_ms = ch.expires_ms;
    ctx->state = NINLIL_M4_LAB_ATTACHMENT_AUTHENTICATING;
    m4_result_success(
        out,
        out->out_frame,
        (size_t)enc,
        NINLIL_M4_LAB_FRAME_JOIN_CHALLENGE,
        NINLIL_M4_LAB_ATTACHMENT_AUTHENTICATING);
    return NINLIL_M4_LAB_OK;
}

ninlil_m4_lab_status_t ninlil_m4_lab_handshake_endpoint_on_challenge(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_m4_lab_credential_t *endpoint_cred,
    ninlil_m4_lab_handshake_step_result_t *out)
{
    ninlil_m4_lab_join_challenge_t ch;
    ninlil_m4_lab_join_response_t resp;
    ninlil_m4_lab_bytes_t stable;
    ninlil_m4_lab_status_t st;
    int32_t enc;

    if (ctx == NULL || frame == NULL || endpoint_cred == NULL
        || out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (ctx->role != NINLIL_M4_LAB_ROLE_ENDPOINT
        || ctx->state != NINLIL_M4_LAB_ATTACHMENT_DISCOVERING
        || ctx->provider == NULL) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    st = ninlil_m4_lab_decode_join_challenge(frame, frame_len, &ch);
    if (st == NINLIL_M4_LAB_CRC) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CRC, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (st != NINLIL_M4_LAB_OK) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CHALLENGE, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (ninlil_m4_lab_challenge_not_expired(ctx->now_ms, ch.expires_ms) == 0) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_EXPIRED, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (m4_replay_seen(ctx, ch.session_id) != 0) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_REPLAY, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    ctx->active_session_id = ch.session_id;
    (void)memcpy(
        ctx->challenge_frame, frame, frame_len);
    ctx->challenge_frame_len = frame_len;
    (void)memcpy(ctx->challenge_nonce, ch.nonce, NINLIL_M4_LAB_NONCE_LEN);
    ctx->challenge_expires_ms = ch.expires_ms;

    stable.bytes = endpoint_cred->stable_id;
    stable.length = endpoint_cred->stable_id_len;
    st = ninlil_m4_lab_identity_proof_compute(
        ctx->provider,
        endpoint_cred->root_key32,
        frame,
        frame_len,
        stable,
        resp.proof_hmac);
    if (st == NINLIL_M4_LAB_CRC) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CRC, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (st != NINLIL_M4_LAB_OK) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CREDENTIAL, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    resp.session_id = ch.session_id;
    enc = ninlil_m4_lab_encode_join_response(
        &resp, out->out_frame, sizeof(out->out_frame));
    if (enc <= 0) {
        m4_result_reject(
            out,
            NINLIL_M4_LAB_REJECT_STRUCTURAL,
            ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    m4_replay_record(ctx, ch.session_id);
    ctx->state = NINLIL_M4_LAB_ATTACHMENT_AUTHENTICATING;
    m4_result_success(
        out,
        out->out_frame,
        (size_t)enc,
        NINLIL_M4_LAB_FRAME_JOIN_RESPONSE,
        NINLIL_M4_LAB_ATTACHMENT_AUTHENTICATING);
    return NINLIL_M4_LAB_OK;
}

ninlil_m4_lab_status_t ninlil_m4_lab_handshake_controller_on_response(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_m4_lab_credential_t *endpoint_cred,
    ninlil_m4_lab_handshake_step_result_t *out)
{
    ninlil_m4_lab_join_response_t resp;
    ninlil_m4_lab_join_install_t inst;
    ninlil_m4_lab_bytes_t stable;
    ninlil_m4_lab_install_binding_t binding;
    ninlil_m4_lab_status_t st;
    int32_t enc;

    if (ctx == NULL || frame == NULL || endpoint_cred == NULL
        || out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (ctx->role != NINLIL_M4_LAB_ROLE_CONTROLLER
        || ctx->state != NINLIL_M4_LAB_ATTACHMENT_AUTHENTICATING
        || ctx->provider == NULL || ctx->has_request == 0
        || ctx->challenge_frame_len == 0u) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (ninlil_m4_lab_challenge_not_expired(
            ctx->now_ms, ctx->challenge_expires_ms)
        == 0) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_EXPIRED, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    st = ninlil_m4_lab_decode_join_response(frame, frame_len, &resp);
    if (st == NINLIL_M4_LAB_CRC) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CRC, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (st != NINLIL_M4_LAB_OK || resp.session_id != ctx->active_session_id) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CHALLENGE, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (m4_replay_seen(ctx, resp.session_id) != 0) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_REPLAY, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    stable.bytes = endpoint_cred->stable_id;
    stable.length = endpoint_cred->stable_id_len;
    if (stable.length != ctx->last_request.device_stable_id_len
        || memcmp(
            stable.bytes,
            ctx->last_request.device_stable_id,
            (size_t)stable.length)
            != 0) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CREDENTIAL, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    st = ninlil_m4_lab_identity_proof_verify(
        ctx->provider,
        endpoint_cred->root_key32,
        ctx->challenge_frame,
        ctx->challenge_frame_len,
        stable,
        resp.proof_hmac);
    if (st == NINLIL_M4_LAB_CREDENTIAL) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CREDENTIAL, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (st != NINLIL_M4_LAB_OK) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CHALLENGE, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    (void)memset(&binding, 0, sizeof(binding));
    binding.site_domain_len = ctx->last_request.site_domain_len;
    (void)memcpy(
        binding.site_domain, ctx->last_request.site_domain, 16u);
    binding.attachment_id_len = ctx->last_request.device_stable_id_len;
    (void)memcpy(
        binding.attachment_id,
        ctx->last_request.device_stable_id,
        32u);
    binding.initiator_stable_id_len = ctx->last_request.device_stable_id_len;
    (void)memcpy(
        binding.initiator_stable_id,
        ctx->last_request.device_stable_id,
        32u);
    binding.responder_stable_id_len = ctx->config.controller_stable_id_len;
    (void)memcpy(
        binding.responder_stable_id,
        ctx->config.controller_stable_id,
        32u);
    binding.membership_epoch = ctx->last_request.membership_epoch;
    binding.attachment_epoch = ctx->config.next_hop_context_id;
    binding.hop_context_id = ctx->config.next_hop_context_id;
    ctx->config.next_hop_context_id += 1u;
    if (ctx->config.next_hop_context_id == 0u) {
        ctx->config.next_hop_context_id = 1u;
    }
    binding.session_id = ctx->active_session_id;
    binding.direction_code = NINLIL_R7_BINDING_DIR_IR;
    binding.alloc_side = 2u;

    st = ninlil_m4_lab_install_token_mint(
        ctx->provider,
        &binding,
        resp.proof_hmac,
        ctx->challenge_nonce,
        &ctx->install_token,
        &ctx->mint_result);
    if (st != NINLIL_M4_LAB_OK || ctx->mint_result.success == 0) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_STRUCTURAL, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    ctx->has_install_token = 1;

    inst.session_id = ctx->active_session_id;
    (void)memcpy(
        inst.token_fingerprint,
        ctx->mint_result.token_fingerprint,
        32u);
    enc = ninlil_m4_lab_encode_join_install(
        &inst, out->out_frame, sizeof(out->out_frame));
    if (enc <= 0) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_STRUCTURAL, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    m4_replay_record(ctx, resp.session_id);
    ctx->state = NINLIL_M4_LAB_ATTACHMENT_ATTACHED;
    m4_result_success(
        out,
        out->out_frame,
        (size_t)enc,
        NINLIL_M4_LAB_FRAME_JOIN_INSTALL,
        NINLIL_M4_LAB_ATTACHMENT_ATTACHED);
    return NINLIL_M4_LAB_OK;
}

ninlil_m4_lab_status_t ninlil_m4_lab_handshake_endpoint_on_install(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_handshake_step_result_t *out)
{
    ninlil_m4_lab_join_install_t inst;
    ninlil_m4_lab_status_t st;

    if (ctx == NULL || frame == NULL || out == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (ctx->role != NINLIL_M4_LAB_ROLE_ENDPOINT
        || ctx->state != NINLIL_M4_LAB_ATTACHMENT_AUTHENTICATING) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    st = ninlil_m4_lab_decode_join_install(frame, frame_len, &inst);
    if (st == NINLIL_M4_LAB_CRC) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CRC, ctx->state);
        return NINLIL_M4_LAB_OK;
    }
    if (st != NINLIL_M4_LAB_OK
        || inst.session_id != ctx->active_session_id) {
        m4_result_reject(
            out, NINLIL_M4_LAB_REJECT_CHALLENGE, ctx->state);
        return NINLIL_M4_LAB_OK;
    }

    ctx->state = NINLIL_M4_LAB_ATTACHMENT_ATTACHED;
    m4_result_success(out, NULL, 0u, 0u, NINLIL_M4_LAB_ATTACHMENT_ATTACHED);
    return NINLIL_M4_LAB_OK;
}
