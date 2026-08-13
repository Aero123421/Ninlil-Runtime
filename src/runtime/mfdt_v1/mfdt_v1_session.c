/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_session.h"

#include "mfdt_v1_ncl1.h"
#include "mfdt_v1_spine.h"

#include <string.h>

static const uint8_t OFFER_DOMAIN[] = "NINLIL-MFDT-OFFER-V2";
static const uint8_t ACCEPT_DOMAIN[] = "NINLIL-MFDT-ACCEPT-V2";

static int bytes_all_zero(const uint8_t *bytes, size_t length)
{
    uint8_t combined = 0u;
    size_t index;

    if (bytes == NULL) {
        return 1;
    }
    for (index = 0u; index < length; ++index) {
        combined = (uint8_t)(combined | bytes[index]);
    }
    return combined == 0u;
}

static void transcript_digest(const uint8_t *domain, size_t domain_length,
                              uint32_t request_id, const uint8_t *body,
                              size_t body_prefix_length, uint8_t out[32])
{
    uint8_t preimage[192];
    size_t offset = 0u;

    (void)memcpy(preimage + offset, domain, domain_length);
    offset += domain_length;
    ninlil_mfdt_v1_put_u32(preimage + offset, request_id);
    offset += 4u;
    (void)memcpy(preimage + offset, body, body_prefix_length);
    offset += body_prefix_length;
    ninlil_mfdt_v1_sha256(preimage, offset, out);
    ninlil_mfdt_v1_memzero(preimage, sizeof(preimage));
}

static int session_bound_and_enabled(const ninlil_mfdt_v1_session_t *session)
{
    return session != NULL &&
           session->state != NINLIL_MFDT_V1_SESSION_COLD &&
           session->state != NINLIL_MFDT_V1_SESSION_FENCED &&
           session->policy_on != 0u &&
           session->capability == NINLIL_MFDT_V1_CAP_REQUIRED &&
           (session->base_control_version == 1u ||
            session->base_control_version == 2u) &&
           session->session_generation != 0u &&
           session->session_cookie != 0ull;
}

static void fence_session(ninlil_mfdt_v1_session_t *session)
{
    if (session == NULL) {
        return;
    }
    session->state = NINLIL_MFDT_V1_SESSION_FENCED;
    session->mfdt_admission_version = 0u;
    session->negotiated = 0u;
    session->ncl1_data_carrier_ok = 0u;
    session->selected_max_active = 0u;
}

static uint8_t local_max_active(const ninlil_mfdt_v1_session_t *session)
{
    return session->host_mode != 0u ? NINLIL_MFDT_V1_HOST_ACTIVE_MAX
                                    : NINLIL_MFDT_V1_ESP_ACTIVE_MAX;
}

static int common_body_ok(const ninlil_mfdt_v1_session_t *session,
                          const uint8_t *body, uint16_t body_length,
                          uint16_t expected_length, uint8_t expected_kind)
{
    if (session == NULL || body == NULL || body_length != expected_length) {
        return 0;
    }
    if (body[0] != (uint8_t)'M' || body[1] != (uint8_t)'F' ||
        body[2] != (uint8_t)'N' || body[3] != (uint8_t)'1' ||
        body[4] != (uint8_t)NINLIL_MFDT_V1_ADMISSION_VERSION ||
        body[5] != expected_kind || ninlil_mfdt_v1_get_u16(body + 6u) != 0u) {
        return 0;
    }
    if (ninlil_mfdt_v1_get_u32(body + 8u) !=
            session->session_generation ||
        ninlil_mfdt_v1_get_u64(body + 12u) != session->session_cookie) {
        return 0;
    }
    return 1;
}

static void admit_session(ninlil_mfdt_v1_session_t *session,
                          uint8_t selected_max_active,
                          const uint8_t transcript[32])
{
    session->state = NINLIL_MFDT_V1_SESSION_ADMITTED;
    session->mfdt_admission_version =
        NINLIL_MFDT_V1_ADMISSION_VERSION;
    session->selected_max_active = selected_max_active;
    session->negotiated = 1u;
    session->ncl1_data_carrier_ok = 1u;
    (void)memcpy(session->transcript_digest, transcript, 32u);
}

void ninlil_mfdt_v1_session_init(ninlil_mfdt_v1_session_t *session,
                                 uint8_t policy_on, uint8_t capability)
{
    if (session == NULL) {
        return;
    }
    (void)memset(session, 0, sizeof(*session));
    session->policy_on = policy_on != 0u ? 1u : 0u;
    session->capability = capability;
    session->state = NINLIL_MFDT_V1_SESSION_COLD;
}

int ninlil_mfdt_v1_session_bind(
    ninlil_mfdt_v1_session_t *session, uint16_t base_control_version,
    uint32_t session_generation, uint64_t session_cookie, uint8_t host_mode,
    const uint8_t local_endpoint_id[16], const uint8_t peer_endpoint_id[16])
{
    uint8_t policy_on;
    uint8_t capability;

    if (session == NULL || local_endpoint_id == NULL ||
        peer_endpoint_id == NULL ||
        (base_control_version != 1u && base_control_version != 2u) ||
        session_generation == 0u || session_cookie == 0ull ||
        bytes_all_zero(local_endpoint_id, 16u) ||
        bytes_all_zero(peer_endpoint_id, 16u) ||
        ninlil_mfdt_v1_memeq(local_endpoint_id, peer_endpoint_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }

    policy_on = session->policy_on;
    capability = session->capability;
    (void)memset(session, 0, sizeof(*session));
    session->policy_on = policy_on;
    session->capability = capability;
    session->host_mode = host_mode != 0u ? 1u : 0u;
    session->state = NINLIL_MFDT_V1_SESSION_BOUND;
    session->base_control_version = base_control_version;
    session->session_generation = session_generation;
    session->session_cookie = session_cookie;
    (void)memcpy(session->local_endpoint_id, local_endpoint_id, 16u);
    (void)memcpy(session->peer_endpoint_id, peer_endpoint_id, 16u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_session_build_offer(
    ninlil_mfdt_v1_session_t *session, uint32_t request_id,
    const uint8_t request_nonce[16], uint8_t *wire_out, size_t wire_cap,
    size_t *wire_len_out)
{
    uint8_t body[NINLIL_MFDT_V1_NEGOTIATE_OFFER_BODY_BYTES];
    uint8_t digest[32];
    int result;

    if (!session_bound_and_enabled(session)) {
        return NINLIL_MFDT_V1_ERR_POLICY_OFF;
    }
    if (request_id == 0u || request_nonce == NULL || wire_out == NULL ||
        wire_len_out == NULL || bytes_all_zero(request_nonce, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (session->local_offer_sent != 0u &&
        (session->local_offer_request_id != request_id ||
         !ninlil_mfdt_v1_memeq(session->local_offer_nonce, request_nonce,
                               16u))) {
        fence_session(session);
        return NINLIL_MFDT_V1_ERR_STATE;
    }

    (void)memset(body, 0, sizeof(body));
    (void)memcpy(body, "MFN1", 4u);
    body[4] = (uint8_t)NINLIL_MFDT_V1_ADMISSION_VERSION;
    body[5] = 1u;
    ninlil_mfdt_v1_put_u32(body + 8u, session->session_generation);
    ninlil_mfdt_v1_put_u64(body + 12u, session->session_cookie);
    (void)memcpy(body + 20u, request_nonce, 16u);
    ninlil_mfdt_v1_put_u32(body + 36u,
                           (uint32_t)NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_put_u32(body + 40u, NINLIL_MFDT_V1_MAX_CONTENT);
    ninlil_mfdt_v1_put_u16(body + 44u, NINLIL_MFDT_V1_CHUNK_SIZE);
    body[46] = local_max_active(session);
    body[47] = NINLIL_MFDT_V1_CARRIER_NCL1_DATA;
    (void)memcpy(body + 48u, session->local_endpoint_id, 16u);
    (void)memcpy(body + 64u, session->peer_endpoint_id, 16u);
    transcript_digest(OFFER_DOMAIN, sizeof(OFFER_DOMAIN) - 1u, request_id,
                      body, 80u, digest);
    (void)memcpy(body + 80u, digest, 32u);

    result = ninlil_mfdt_v1_ncl1_encode(
        NINLIL_MFDT_V1_NEGOTIATE_OFFER, request_id,
        session->session_generation, session->session_cookie, body,
        (uint16_t)sizeof(body), wire_out, wire_cap, wire_len_out);
    if (result == NINLIL_MFDT_V1_OK) {
        session->local_offer_sent = 1u;
        session->local_offer_request_id = request_id;
        (void)memcpy(session->local_offer_nonce, request_nonce, 16u);
        (void)memcpy(session->local_offer_digest, digest, 32u);
    }
    ninlil_mfdt_v1_memzero(body, sizeof(body));
    ninlil_mfdt_v1_memzero(digest, sizeof(digest));
    return result;
}

int ninlil_mfdt_v1_session_on_offer(
    ninlil_mfdt_v1_session_t *session, const uint8_t *offer_wire,
    size_t offer_wire_len, const uint8_t responder_nonce[16],
    uint8_t *accept_wire_out, size_t accept_wire_cap,
    size_t *accept_wire_len_out)
{
    uint8_t type = 0u;
    uint32_t request_id = 0u;
    uint32_t generation = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *offer = NULL;
    uint16_t offer_length = 0u;
    uint8_t offer_digest[32];
    uint8_t accept_digest[32];
    uint8_t selected_active;
    int result;

    if (!session_bound_and_enabled(session)) {
        return NINLIL_MFDT_V1_ERR_POLICY_OFF;
    }
    if (offer_wire == NULL || accept_wire_out == NULL ||
        accept_wire_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    result = ninlil_mfdt_v1_ncl1_decode(
        offer_wire, offer_wire_len, NINLIL_MFDT_V1_NCG1_DATA, &type,
        &request_id, &generation, &cookie, &offer, &offer_length);
    if (result != NINLIL_MFDT_V1_OK ||
        type != NINLIL_MFDT_V1_NEGOTIATE_OFFER ||
        generation != session->session_generation ||
        cookie != session->session_cookie ||
        !common_body_ok(session, offer, offer_length,
                        NINLIL_MFDT_V1_NEGOTIATE_OFFER_BODY_BYTES, 1u)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }

    transcript_digest(OFFER_DOMAIN, sizeof(OFFER_DOMAIN) - 1u, request_id,
                      offer, 80u, offer_digest);
    if (!ninlil_mfdt_v1_memeq(offer_digest, offer + 80u, 32u) ||
        bytes_all_zero(offer + 20u, 16u) ||
        ninlil_mfdt_v1_get_u32(offer + 36u) !=
            (uint32_t)NINLIL_MFDT_V1_CAP_REQUIRED ||
        ninlil_mfdt_v1_get_u32(offer + 40u) !=
            NINLIL_MFDT_V1_MAX_CONTENT ||
        ninlil_mfdt_v1_get_u16(offer + 44u) !=
            NINLIL_MFDT_V1_CHUNK_SIZE ||
        (offer[46] != NINLIL_MFDT_V1_ESP_ACTIVE_MAX &&
         offer[46] != NINLIL_MFDT_V1_HOST_ACTIVE_MAX) ||
        offer[47] != NINLIL_MFDT_V1_CARRIER_NCL1_DATA ||
        !ninlil_mfdt_v1_memeq(offer + 48u,
                              session->peer_endpoint_id, 16u) ||
        !ninlil_mfdt_v1_memeq(offer + 64u,
                              session->local_endpoint_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }

    if (session->peer_offer_accepted != 0u) {
        if (session->peer_offer_request_id != request_id ||
            !ninlil_mfdt_v1_memeq(session->peer_offer_digest,
                                  offer_digest, 32u)) {
            fence_session(session);
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        return ninlil_mfdt_v1_ncl1_encode(
            NINLIL_MFDT_V1_NEGOTIATE_ACCEPT, request_id,
            session->session_generation, session->session_cookie,
            session->cached_accept_body, session->cached_accept_body_len,
            accept_wire_out, accept_wire_cap, accept_wire_len_out);
    }

    if (responder_nonce == NULL ||
        bytes_all_zero(responder_nonce, 16u) ||
        ninlil_mfdt_v1_memeq(responder_nonce, offer + 20u, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }

    selected_active = offer[46] < local_max_active(session)
                          ? offer[46]
                          : local_max_active(session);
    (void)memset(session->cached_accept_body, 0,
                 sizeof(session->cached_accept_body));
    (void)memcpy(session->cached_accept_body, "MFN1", 4u);
    session->cached_accept_body[4] =
        (uint8_t)NINLIL_MFDT_V1_ADMISSION_VERSION;
    session->cached_accept_body[5] = 2u;
    ninlil_mfdt_v1_put_u32(session->cached_accept_body + 8u,
                           session->session_generation);
    ninlil_mfdt_v1_put_u64(session->cached_accept_body + 12u,
                           session->session_cookie);
    (void)memcpy(session->cached_accept_body + 20u, offer + 20u, 16u);
    (void)memcpy(session->cached_accept_body + 36u, responder_nonce, 16u);
    ninlil_mfdt_v1_put_u32(session->cached_accept_body + 52u,
                           (uint32_t)NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_put_u32(session->cached_accept_body + 56u,
                           NINLIL_MFDT_V1_MAX_CONTENT);
    ninlil_mfdt_v1_put_u16(session->cached_accept_body + 60u,
                           NINLIL_MFDT_V1_CHUNK_SIZE);
    session->cached_accept_body[62] = selected_active;
    session->cached_accept_body[63] =
        NINLIL_MFDT_V1_CARRIER_NCL1_DATA;
    (void)memcpy(session->cached_accept_body + 64u,
                 session->peer_endpoint_id, 16u);
    (void)memcpy(session->cached_accept_body + 80u,
                 session->local_endpoint_id, 16u);
    (void)memcpy(session->cached_accept_body + 96u, offer_digest, 32u);
    transcript_digest(ACCEPT_DOMAIN, sizeof(ACCEPT_DOMAIN) - 1u, request_id,
                      session->cached_accept_body, 128u, accept_digest);
    (void)memcpy(session->cached_accept_body + 128u, accept_digest, 32u);
    session->cached_accept_body_len =
        NINLIL_MFDT_V1_NEGOTIATE_ACCEPT_BODY_BYTES;

    result = ninlil_mfdt_v1_ncl1_encode(
        NINLIL_MFDT_V1_NEGOTIATE_ACCEPT, request_id,
        session->session_generation, session->session_cookie,
        session->cached_accept_body, session->cached_accept_body_len,
        accept_wire_out, accept_wire_cap, accept_wire_len_out);
    if (result == NINLIL_MFDT_V1_OK) {
        session->peer_offer_accepted = 1u;
        session->peer_offer_request_id = request_id;
        (void)memcpy(session->peer_offer_nonce, offer + 20u, 16u);
        (void)memcpy(session->responder_nonce, responder_nonce, 16u);
        (void)memcpy(session->peer_offer_digest, offer_digest, 32u);
        admit_session(session, selected_active, accept_digest);
    }
    ninlil_mfdt_v1_memzero(offer_digest, sizeof(offer_digest));
    ninlil_mfdt_v1_memzero(accept_digest, sizeof(accept_digest));
    return result;
}

int ninlil_mfdt_v1_session_on_accept(
    ninlil_mfdt_v1_session_t *session, const uint8_t *accept_wire,
    size_t accept_wire_len)
{
    uint8_t type = 0u;
    uint32_t request_id = 0u;
    uint32_t generation = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *accept = NULL;
    uint16_t accept_length = 0u;
    uint8_t accept_digest[32];
    int result;

    if (!session_bound_and_enabled(session) ||
        session->local_offer_sent == 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    result = ninlil_mfdt_v1_ncl1_decode(
        accept_wire, accept_wire_len, NINLIL_MFDT_V1_NCG1_DATA, &type,
        &request_id, &generation, &cookie, &accept, &accept_length);
    if (result != NINLIL_MFDT_V1_OK ||
        type != NINLIL_MFDT_V1_NEGOTIATE_ACCEPT ||
        generation != session->session_generation ||
        cookie != session->session_cookie ||
        request_id != session->local_offer_request_id ||
        !common_body_ok(session, accept, accept_length,
                        NINLIL_MFDT_V1_NEGOTIATE_ACCEPT_BODY_BYTES, 2u)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }

    transcript_digest(ACCEPT_DOMAIN, sizeof(ACCEPT_DOMAIN) - 1u, request_id,
                      accept, 128u, accept_digest);
    if (!ninlil_mfdt_v1_memeq(accept + 20u,
                              session->local_offer_nonce, 16u) ||
        bytes_all_zero(accept + 36u, 16u) ||
        ninlil_mfdt_v1_memeq(accept + 20u, accept + 36u, 16u) ||
        ninlil_mfdt_v1_get_u32(accept + 52u) !=
            (uint32_t)NINLIL_MFDT_V1_CAP_REQUIRED ||
        ninlil_mfdt_v1_get_u32(accept + 56u) !=
            NINLIL_MFDT_V1_MAX_CONTENT ||
        ninlil_mfdt_v1_get_u16(accept + 60u) !=
            NINLIL_MFDT_V1_CHUNK_SIZE ||
        accept[62] == 0u || accept[62] > local_max_active(session) ||
        accept[63] != NINLIL_MFDT_V1_CARRIER_NCL1_DATA ||
        !ninlil_mfdt_v1_memeq(accept + 64u,
                              session->local_endpoint_id, 16u) ||
        !ninlil_mfdt_v1_memeq(accept + 80u,
                              session->peer_endpoint_id, 16u) ||
        !ninlil_mfdt_v1_memeq(accept + 96u,
                              session->local_offer_digest, 32u) ||
        !ninlil_mfdt_v1_memeq(accept + 128u, accept_digest, 32u)) {
        fence_session(session);
        ninlil_mfdt_v1_memzero(accept_digest, sizeof(accept_digest));
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }

    (void)memcpy(session->responder_nonce, accept + 36u, 16u);
    admit_session(session, accept[62], accept_digest);
    ninlil_mfdt_v1_memzero(accept_digest, sizeof(accept_digest));
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_session_carrier_ncl1_data_ok(
    const ninlil_mfdt_v1_session_t *session)
{
    return session != NULL &&
           session->state == NINLIL_MFDT_V1_SESSION_ADMITTED &&
           session->mfdt_admission_version ==
               NINLIL_MFDT_V1_ADMISSION_VERSION &&
           session->negotiated != 0u &&
           session->ncl1_data_carrier_ok != 0u;
}

int ninlil_mfdt_v1_session_on_ncg1_data(
    const ninlil_mfdt_v1_session_t *session,
    ninlil_mfdt_v1_spine_ctx_t *spine,
    const uint8_t *payload, size_t length)
{
    uint8_t message_type = 0u;
    uint32_t request_id = 0u;
    uint32_t generation = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *body = NULL;
    uint16_t body_length = 0u;
    int result;

    if (session == NULL || spine == NULL || payload == NULL || length == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!ninlil_mfdt_v1_session_carrier_ncl1_data_ok(session)) {
        return 0;
    }
    result = ninlil_mfdt_v1_ncl1_decode(
        payload, length, NINLIL_MFDT_V1_NCG1_DATA, &message_type,
        &request_id, &generation, &cookie, &body, &body_length);
    if (result != NINLIL_MFDT_V1_OK ||
        !ninlil_mfdt_v1_ncl1_is_transfer_type(message_type)) {
        return 0;
    }
    if (generation != session->session_generation ||
        cookie != session->session_cookie) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    result = ninlil_mfdt_v1_spine_on_ncl1_data(spine, payload, length);
    return result == NINLIL_MFDT_V1_OK ? 1 : result;
}

int ninlil_mfdt_v1_session_apply_to_spine(
    const ninlil_mfdt_v1_session_t *session,
    ninlil_mfdt_v1_spine_ctx_t *spine)
{
    ninlil_mfdt_v1_seam_config_t config;

    if (session == NULL || spine == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    (void)memset(&config, 0, sizeof(config));
    config.policy_on = session->policy_on;
    config.capability = session->capability;
    config.mfdt_admission_version = session->mfdt_admission_version;
    config.host_mode = session->host_mode;
    config.session_generation = session->session_generation;
    config.session_cookie = session->session_cookie;
    return ninlil_mfdt_v1_spine_set_config(spine, &config);
}
