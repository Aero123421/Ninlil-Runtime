/*
 * Test/support only wire seam for host completion integrated E2E.
 */
#include "host_completion_wire.h"

#include "fabric_private_select.h"
#include "wifi_nwb1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

/*
 * Structural NFL1: header 584 + payload.
 * Payload layout: TAG[4] + u16 ncl1_len + ncl1 + zero pad to satisfy total>=587.
 */
static int build_nfl1_with_body(
    const uint8_t tag[4],
    const uint8_t *body,
    size_t body_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    size_t payload_len;
    size_t total;
    uint32_t crc;
    size_t i;

    if (tag == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (body_len > 0u && body == NULL) {
        return -1;
    }
    /* payload = 4 tag + 2 len + body */
    payload_len = 6u + body_len;
    if (payload_len < 3u) {
        payload_len = 3u;
    }
    total = (size_t)NINLIL_WIFI_NFL1_HEADER_BYTES + payload_len;
    if (total < 587u) {
        payload_len = 587u - (size_t)NINLIL_WIFI_NFL1_HEADER_BYTES;
        total = 587u;
    }
    if (total > 1925u || total > out_cap) {
        return -1;
    }
    (void)memset(out, 0, total);
    out[0] = (uint8_t)'N';
    out[1] = (uint8_t)'F';
    out[2] = (uint8_t)'L';
    out[3] = (uint8_t)'1';
    wr16(out + 4, 1u);
    wr16(out + 6, (uint16_t)NINLIL_WIFI_NFL1_HEADER_BYTES);
    wr32(out + 8, (uint32_t)total);
    wr32(out + 12, 0u);
    wr16(out + 570, 0u);
    wr16(out + 572, 0u);
    wr16(out + 574, 0u);
    wr32(out + 576, (uint32_t)payload_len);
    wr32(out + 580, 0u);
    out[584] = tag[0];
    out[585] = tag[1];
    out[586] = tag[2];
    out[587] = tag[3];
    wr16(out + 588, (uint16_t)body_len);
    if (body_len > 0u) {
        (void)memcpy(out + 590, body, body_len);
    }
    crc = ninlil_wifi_crc32c(out, total);
    wr32(out + 12, crc);
    if (!ninlil_wifi_nfl1_structural_ok(out, total)) {
        return -1;
    }
    *out_len = total;
    (void)i;
    return 0;
}

static int extract_body_from_nfl1(
    const uint8_t *nfl1,
    size_t nfl1_len,
    const uint8_t expect_tag[4],
    uint8_t *body_out,
    size_t body_cap,
    size_t *body_len_out)
{
    uint32_t payload_len;
    uint16_t blen;
    if (nfl1 == NULL || body_out == NULL || body_len_out == NULL) {
        return -1;
    }
    if (!ninlil_wifi_nfl1_structural_ok(nfl1, nfl1_len)) {
        return -1;
    }
    payload_len = rd32(nfl1 + 576);
    if (payload_len < 6u
        || (size_t)NINLIL_WIFI_NFL1_HEADER_BYTES + (size_t)payload_len != nfl1_len) {
        return -1;
    }
    if (nfl1[584] != expect_tag[0] || nfl1[585] != expect_tag[1]
        || nfl1[586] != expect_tag[2] || nfl1[587] != expect_tag[3]) {
        return -1;
    }
    blen = rd16(nfl1 + 588);
    if ((size_t)blen + 6u > (size_t)payload_len || (size_t)blen > body_cap) {
        return -1;
    }
    if (blen > 0u) {
        (void)memcpy(body_out, nfl1 + 590, blen);
    }
    *body_len_out = (size_t)blen;
    return 0;
}

int host_completion_ncl1_to_nwb1(
    const uint8_t *ncl1,
    size_t ncl1_len,
    const uint8_t session_id[16],
    uint32_t sequence,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t nfl1[HOST_COMPLETION_NFL1_MAX];
    size_t nfl1_len = 0u;
    uint8_t tag[4];
    ninlil_wifi_status_t st;

    if (ncl1 == NULL || ncl1_len == 0u || ncl1_len > HOST_COMPLETION_NCL1_MAX
        || session_id == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    tag[0] = HOST_COMPLETION_NFL1_TAG0;
    tag[1] = HOST_COMPLETION_NFL1_TAG1;
    tag[2] = HOST_COMPLETION_NFL1_TAG2;
    tag[3] = HOST_COMPLETION_NFL1_TAG3;
    if (build_nfl1_with_body(tag, ncl1, ncl1_len, nfl1, sizeof(nfl1), &nfl1_len)
        != 0) {
        return -1;
    }
    st = ninlil_wifi_nwb1_encode(
        session_id, sequence, nfl1, (uint32_t)nfl1_len, out, out_cap, out_len);
    return (st == NINLIL_WIFI_OK) ? 0 : -1;
}

int host_completion_nwb1_to_ncl1(
    const uint8_t *nwb1,
    size_t nwb1_len,
    uint8_t *ncl1_out,
    size_t ncl1_cap,
    size_t *ncl1_len_out,
    uint32_t *sequence_out)
{
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0u;
    uint32_t seq = 0u;
    ninlil_wifi_status_t st;
    uint8_t tag[4];

    if (nwb1 == NULL || ncl1_out == NULL || ncl1_len_out == NULL) {
        return -1;
    }
    st = ninlil_wifi_nwb1_classify(
        nwb1, nwb1_len, NULL, 0, 0u, &payload, &payload_len, &seq);
    if (st != NINLIL_WIFI_OK || payload == NULL) {
        return -1;
    }
    tag[0] = HOST_COMPLETION_NFL1_TAG0;
    tag[1] = HOST_COMPLETION_NFL1_TAG1;
    tag[2] = HOST_COMPLETION_NFL1_TAG2;
    tag[3] = HOST_COMPLETION_NFL1_TAG3;
    if (extract_body_from_nfl1(
            payload, payload_len, tag, ncl1_out, ncl1_cap, ncl1_len_out)
        != 0) {
        return -1;
    }
    if (sequence_out != NULL) {
        *sequence_out = seq;
    }
    return 0;
}

int host_completion_hop_to_nwb1(
    const ninlil_rrmp_outbound_packet_t *pkt,
    const uint8_t session_id[16],
    uint32_t sequence,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    uint8_t body[128];
    uint8_t nfl1[HOST_COMPLETION_NFL1_MAX];
    size_t nfl1_len = 0u;
    uint8_t tag[4];
    size_t body_len;
    ninlil_wifi_status_t st;

    if (pkt == NULL || session_id == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    /* body: e2e_len u16 + e2e_body + route_handle u16 + gen u16 + hop_remaining */
    body[0] = (uint8_t)(pkt->e2e_len >> 8);
    body[1] = (uint8_t)pkt->e2e_len;
    if (pkt->e2e_len > 96u) {
        return -1;
    }
    (void)memcpy(body + 2, pkt->e2e_body, pkt->e2e_len);
    body_len = 2u + (size_t)pkt->e2e_len;
    body[body_len++] = (uint8_t)(pkt->route_handle >> 8);
    body[body_len++] = (uint8_t)pkt->route_handle;
    body[body_len++] = (uint8_t)(pkt->route_generation >> 8);
    body[body_len++] = (uint8_t)pkt->route_generation;
    body[body_len++] = pkt->hop_remaining_out;
    tag[0] = HOST_COMPLETION_HOP_TAG0;
    tag[1] = HOST_COMPLETION_HOP_TAG1;
    tag[2] = HOST_COMPLETION_HOP_TAG2;
    tag[3] = HOST_COMPLETION_HOP_TAG3;
    if (build_nfl1_with_body(tag, body, body_len, nfl1, sizeof(nfl1), &nfl1_len)
        != 0) {
        return -1;
    }
    st = ninlil_wifi_nwb1_encode(
        session_id, sequence, nfl1, (uint32_t)nfl1_len, out, out_cap, out_len);
    return (st == NINLIL_WIFI_OK) ? 0 : -1;
}

int host_completion_nwb1_is_hop(
    const uint8_t *nwb1, size_t nwb1_len, ninlil_rrmp_outbound_packet_t *pkt_out)
{
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0u;
    uint32_t seq = 0u;
    uint8_t body[128];
    size_t body_len = 0u;
    uint8_t tag[4];
    ninlil_wifi_status_t st;

    if (nwb1 == NULL) {
        return 0;
    }
    st = ninlil_wifi_nwb1_classify(
        nwb1, nwb1_len, NULL, 0, 0u, &payload, &payload_len, &seq);
    if (st != NINLIL_WIFI_OK || payload == NULL) {
        return 0;
    }
    tag[0] = HOST_COMPLETION_HOP_TAG0;
    tag[1] = HOST_COMPLETION_HOP_TAG1;
    tag[2] = HOST_COMPLETION_HOP_TAG2;
    tag[3] = HOST_COMPLETION_HOP_TAG3;
    if (extract_body_from_nfl1(
            payload, payload_len, tag, body, sizeof(body), &body_len)
        != 0) {
        return 0;
    }
    if (pkt_out != NULL && body_len >= 7u) {
        uint16_t elen = (uint16_t)(((uint16_t)body[0] << 8) | body[1]);
        (void)memset(pkt_out, 0, sizeof(*pkt_out));
        if (elen > 96u || (size_t)elen + 7u > body_len) {
            return 0;
        }
        pkt_out->e2e_len = elen;
        (void)memcpy(pkt_out->e2e_body, body + 2, elen);
        pkt_out->route_handle =
            (uint16_t)(((uint16_t)body[2u + elen] << 8) | body[3u + elen]);
        pkt_out->route_generation =
            (uint16_t)(((uint16_t)body[4u + elen] << 8) | body[5u + elen]);
        pkt_out->hop_remaining_out = body[6u + elen];
    }
    (void)seq;
    return 1;
}

void host_completion_outbound_init(
    host_completion_outbound_ctx_t *ctx, ninlil_wifi_session_t *session)
{
    if (ctx == NULL) {
        return;
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->session = session;
}

uint32_t host_completion_rrmp_outbound_submit(
    void *user, const ninlil_rrmp_outbound_packet_t *pkt)
{
    host_completion_outbound_ctx_t *ctx = (host_completion_outbound_ctx_t *)user;
    uint8_t nfl1[HOST_COMPLETION_NFL1_MAX];
    size_t nfl1_len = 0u;
    ninlil_wifi_status_t st;
    uint32_t spins;
    uint32_t send_bytes = 0u;

    if (ctx == NULL || pkt == NULL || ctx->session == NULL) {
        return NINLIL_RRMP_OUTBOUND_NO_PROVIDER;
    }
    if (ctx->session->phase != NINLIL_WIFI_PHASE_ATTACHED) {
        return NINLIL_RRMP_OUTBOUND_DENIED;
    }
    ctx->last_pkt = *pkt;
    ctx->has_last = 1u;

    /*
     * Production seam: application carrier (NCL1) is emitted as MFDT NFL1
     * body over the WiFi session — same bytes RRMP hop accepted. No separate
     * host_completion_session_send_ncl1 bypass on the forward path.
     * Custody-only hops (carrier_len == 0) keep RRMP hop-tag frames.
     */
    if (pkt->carrier_len > 0u) {
        uint8_t tag[4];
        if (pkt->carrier_len > HOST_COMPLETION_NCL1_MAX) {
            ctx->last_status = NINLIL_RRMP_OUTBOUND_DENIED;
            return NINLIL_RRMP_OUTBOUND_DENIED;
        }
        tag[0] = HOST_COMPLETION_NFL1_TAG0;
        tag[1] = HOST_COMPLETION_NFL1_TAG1;
        tag[2] = HOST_COMPLETION_NFL1_TAG2;
        tag[3] = HOST_COMPLETION_NFL1_TAG3;
        if (build_nfl1_with_body(
                tag, pkt->carrier, (size_t)pkt->carrier_len, nfl1, sizeof(nfl1),
                &nfl1_len)
            != 0) {
            ctx->last_status = NINLIL_RRMP_OUTBOUND_DENIED;
            return NINLIL_RRMP_OUTBOUND_DENIED;
        }
        st = ninlil_wifi_session_send_payload(
            ctx->session, nfl1, (uint32_t)nfl1_len);
        send_bytes = (uint32_t)nfl1_len;
    } else {
        uint8_t rec[HOST_COMPLETION_NWB1_MAX];
        size_t rec_len = 0u;
        const uint8_t *pl = NULL;
        uint32_t pl_len = 0u;
        uint32_t seq = 0u;
        if (host_completion_hop_to_nwb1(
                pkt,
                ctx->session->ids.attached_session_id,
                ctx->sequence,
                rec,
                sizeof(rec),
                &rec_len)
            != 0) {
            ctx->last_status = NINLIL_RRMP_OUTBOUND_DENIED;
            return NINLIL_RRMP_OUTBOUND_DENIED;
        }
        if (ninlil_wifi_nwb1_classify(
                rec, rec_len, NULL, 0, 0u, &pl, &pl_len, &seq)
            != NINLIL_WIFI_OK) {
            ctx->last_status = NINLIL_RRMP_OUTBOUND_DENIED;
            return NINLIL_RRMP_OUTBOUND_DENIED;
        }
        st = ninlil_wifi_session_send_payload(ctx->session, pl, pl_len);
        send_bytes = pl_len;
        ctx->sequence += 1u;
    }

    if (st == NINLIL_WIFI_BACKPRESSURE || st == NINLIL_WIFI_WOULD_BLOCK) {
        ctx->last_status = NINLIL_RRMP_OUTBOUND_WOULD_BLOCK;
        return NINLIL_RRMP_OUTBOUND_WOULD_BLOCK;
    }
    if (st != NINLIL_WIFI_OK) {
        ctx->last_status = NINLIL_RRMP_OUTBOUND_DENIED;
        return NINLIL_RRMP_OUTBOUND_DENIED;
    }
    ctx->submit_count += 1u;
    ctx->bytes_submitted += (uint64_t)send_bytes;
    for (spins = 0u; spins < 5000u; ++spins) {
        if (ninlil_wifi_queue_is_empty(&ctx->session->txq)
            && ctx->session->tx_partial_len == 0u) {
            break;
        }
        (void)ninlil_wifi_session_poll(ctx->session);
        usleep(100);
    }
    ctx->last_status = NINLIL_RRMP_OUTBOUND_ACCEPTED;
    return NINLIL_RRMP_OUTBOUND_ACCEPTED;
}

int host_completion_session_drain(ninlil_wifi_session_t *session, uint32_t timeout_ms)
{
    uint32_t spins = 0u;
    uint32_t max_spins = timeout_ms * 10u + 1u;
    if (session == NULL) {
        return -1;
    }
    while (spins < max_spins) {
        (void)ninlil_wifi_session_poll(session);
        if (ninlil_wifi_queue_is_empty(&session->txq)
            && session->tx_partial_len == 0u) {
            return 0;
        }
        usleep(100);
        spins += 1u;
    }
    return -1;
}

int host_completion_session_send_ncl1(
    ninlil_wifi_session_t *session, const uint8_t *ncl1, size_t ncl1_len)
{
    uint8_t nfl1[HOST_COMPLETION_NFL1_MAX];
    size_t nfl1_len = 0u;
    uint8_t tag[4];
    ninlil_wifi_status_t st;
    uint32_t spins;

    if (session == NULL || ncl1 == NULL || ncl1_len == 0u) {
        return -1;
    }
    tag[0] = HOST_COMPLETION_NFL1_TAG0;
    tag[1] = HOST_COMPLETION_NFL1_TAG1;
    tag[2] = HOST_COMPLETION_NFL1_TAG2;
    tag[3] = HOST_COMPLETION_NFL1_TAG3;
    if (build_nfl1_with_body(tag, ncl1, ncl1_len, nfl1, sizeof(nfl1), &nfl1_len)
        != 0) {
        return -1;
    }
    for (spins = 0u; spins < 20000u; ++spins) {
        st = ninlil_wifi_session_send_payload(session, nfl1, (uint32_t)nfl1_len);
        if (st == NINLIL_WIFI_OK) {
            return host_completion_session_drain(session, 5000u);
        }
        if (st != NINLIL_WIFI_BACKPRESSURE && st != NINLIL_WIFI_WOULD_BLOCK) {
            return -1;
        }
        (void)ninlil_wifi_session_poll(session);
        usleep(100);
    }
    return -1;
}

int host_completion_session_recv_ncl1(
    ninlil_wifi_session_t *session,
    uint8_t *ncl1_out,
    size_t ncl1_cap,
    size_t *ncl1_len_out,
    uint32_t *seq_out,
    uint32_t timeout_ms)
{
    uint32_t spins = 0u;
    uint32_t max_spins = timeout_ms * 10u + 1u;
    if (session == NULL || ncl1_out == NULL || ncl1_len_out == NULL) {
        return -1;
    }
    while (spins < max_spins) {
        uint8_t rec[HOST_COMPLETION_NWB1_MAX];
        size_t rec_len = 0u;
        uint32_t seq = 0u;
        ninlil_wifi_status_t st;

        (void)ninlil_wifi_session_poll(session);
        st = ninlil_wifi_session_recv_record(
            session, rec, sizeof(rec), &rec_len, &seq);
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            usleep(100);
            spins += 1u;
            continue;
        }
        if (st != NINLIL_WIFI_OK) {
            return -1;
        }
        /* Hop frames are not MFDT NCL1 — skip for MFDT path. */
        if (host_completion_nwb1_is_hop(rec, rec_len, NULL)) {
            if (seq_out != NULL) {
                *seq_out = seq;
            }
            /* Report hop as special: ncl1_len 0 and return 1 */
            *ncl1_len_out = 0u;
            return 1;
        }
        if (host_completion_nwb1_to_ncl1(
                rec, rec_len, ncl1_out, ncl1_cap, ncl1_len_out, seq_out)
            != 0) {
            return -1;
        }
        return 0;
    }
    return -2; /* timeout */
}

static void fill_pat(uint8_t *dst, uint8_t seed, size_t n)
{
    size_t i;
    for (i = 0u; i < n; ++i) {
        dst[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

int host_completion_fabric_select_parent(
    const uint8_t parent_a[16],
    const uint8_t parent_b[16],
    int a_available,
    int b_available,
    uint64_t now_ms,
    uint8_t selected_out[16],
    uint32_t *has_selection_out)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;
    ninlil_fabric_private_select_registry_row_t *r0;
    ninlil_fabric_private_select_registry_row_t *r1;
    ninlil_fabric_private_select_policy_t *p;
    ninlil_fabric_private_select_authority_row_t *a;
    uint8_t i;

    if (parent_a == NULL || parent_b == NULL || selected_out == NULL
        || has_selection_out == NULL) {
        return -1;
    }
    (void)memset(&snap, 0, sizeof(snap));
    (void)memset(&res, 0, sizeof(res));
    snap.outer_available = 1u;
    fill_pat(snap.query.service_identity_digest, 0x11u, 32u);
    snap.query.family = 2u;
    snap.query.direction = 1u;
    snap.query.traffic_class = 1u;
    fill_pat(snap.query.source_runtime_id, 0x30u, 16u);
    fill_pat(snap.query.target_runtime_id, 0x80u, 16u);
    fill_pat(snap.query.target_application_id, 0x90u, 16u);
    snap.query.packet_bytes = 587u;
    snap.query.transfer_bytes = 587u;
    snap.query.now_ms = now_ms != 0u ? now_ms : 170000u;
    snap.query.deadline_ms = snap.query.now_ms + 30000u;
    fill_pat(snap.query.deadline_clock_epoch_id, 0xA1u, 16u);
    fill_pat(snap.query.admission_clock_epoch_id, 0xA1u, 16u);
    fill_pat(snap.query.availability_clock_epoch_id, 0xA1u, 16u);
    fill_pat(snap.query.attestation_clock_epoch_id, 0xA1u, 16u);
    fill_pat(snap.query.authority_clock_epoch_id, 0xD1u, 16u);
    fill_pat(snap.query.authenticated_peer_runtime_id, 0x31u, 16u);
    fill_pat(snap.query.attachment_authority_id, 0x41u, 16u);
    fill_pat(snap.query.attachment_binding_digest, 0x51u, 32u);
    snap.query.requires_custody = 0u;

    snap.policy_count = 1u;
    p = &snap.policies[0];
    fill_pat(p->policy_id, 0x71u, 16u);
    p->revision = 3u;
    fill_pat(p->canonical_digest, 0x22u, 32u);
    fill_pat(p->service_identity_digest, 0x11u, 32u);
    p->family = 2u;
    p->direction = 1u;
    p->traffic_class = 1u;
    p->scope_selector = 2u;
    p->required_capability_flags = 0x02u;
    p->required_security_flags = 0x0Fu;
    p->maximum_latency_class = 50u;
    p->maximum_cost_class = 50u;
    p->minimum_packet_bytes = 587u;
    p->authority_mode = 1u;
    p->deadline_guard_ms = 100u;
    p->candidate_count = 2u;
    for (i = 0u; i < 16u; ++i) {
        p->candidates[0].instance_id[i] = parent_a[i];
        p->candidates[1].instance_id[i] = parent_b[i];
    }
    p->candidates[0].rank = 10u;
    p->candidates[0].reservation_units = 1u;
    p->candidates[1].rank = 20u;
    p->candidates[1].reservation_units = 1u;
    p->revision_chain_len = 3u;
    p->revision_chain[0] = 1u;
    p->revision_chain[1] = 2u;
    p->revision_chain[2] = 3u;

    snap.registry_count = 2u;
    r0 = &snap.registry[0];
    for (i = 0u; i < 16u; ++i) {
        r0->instance_id[i] = parent_a[i];
    }
    r0->link_kind = 2u;
    r0->direction_mask = 3u;
    r0->capability_flags = 0x4Fu;
    r0->security_capability_flags = 0x0Fu;
    r0->maximum_packet_bytes = 1925u;
    r0->maximum_transfer_bytes = 1925u;
    r0->latency_class = 10u;
    r0->cost_class = 20u;
    r0->reservation_capacity = 8u;
    r0->lifecycle = a_available ? 1u : 0u;
    r0->peer_nfl1_version = 1u;
    r0->peer_fabric_capability_flags = 1u;
    fill_pat(r0->authenticated_peer_runtime_id, 0x31u, 16u);
    fill_pat(r0->attachment_authority_id, 0x41u, 16u);
    fill_pat(r0->attachment_binding_digest, 0x51u, 32u);
    fill_pat(r0->attestation_clock_epoch_id, 0xA1u, 16u);
    r0->attestation_expires_at_ms = snap.query.now_ms + 100000u;
    fill_pat(r0->availability_clock_epoch_id, 0xA1u, 16u);
    r0->availability_state = a_available ? 1u : 0u;
    r0->availability_expires_at_ms = snap.query.now_ms + 80000u;

    r1 = &snap.registry[1];
    *r1 = *r0;
    for (i = 0u; i < 16u; ++i) {
        r1->instance_id[i] = parent_b[i];
    }
    r1->lifecycle = b_available ? 1u : 0u;
    r1->availability_state = b_available ? 1u : 0u;
    r1->latency_class = 15u;

    snap.authority_count = 1u;
    a = &snap.authorities[0];
    fill_pat(a->service_identity_digest, 0x11u, 32u);
    a->family = 2u;
    a->direction = 1u;
    a->traffic_class = 1u;
    a->scope_selector = 2u;
    fill_pat(a->endpoint_runtime_id, 0x80u, 16u);
    fill_pat(a->target_runtime_id, 0x80u, 16u);
    fill_pat(a->target_application_id, 0x90u, 16u);
    fill_pat(a->policy_id, 0x71u, 16u);
    a->policy_revision = 3u;
    fill_pat(a->policy_digest, 0x22u, 32u);
    a->authority_state = 1u;
    fill_pat(a->authority_clock_epoch_id, 0xD1u, 16u);
    a->lease_expires_at_ms = snap.query.now_ms + 100000u;

    ninlil_fabric_private_select(&snap, &res);
    *has_selection_out = res.has_selection;
    if (res.has_selection != 0u
        && res.resolution == NINLIL_FABRIC_PRIVATE_SEL_SELECTED) {
        for (i = 0u; i < 16u; ++i) {
            selected_out[i] = res.selected_instance_id[i];
        }
        return 0;
    }
    return -1;
}

/* Magic: "MFST" + u32 version=1 + rows of {key[20], u32 vlen, value}. */
int host_completion_mfdt_store_export_path(
    const ninlil_mfdt_v1_lab_store_t *store, const char *path, size_t *bytes_out)
{
    FILE *f;
    size_t i;
    size_t total = 0u;
    uint32_t ver = 1u;
    uint32_t nrows = 0u;
    if (store == NULL || path == NULL) {
        return -1;
    }
    for (i = 0u; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        if (store->rows[i].occupied) {
            nrows += 1u;
        }
    }
    f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    if (fwrite("MFST", 1u, 4u, f) != 4u || fwrite(&ver, 1u, 4u, f) != 4u
        || fwrite(&nrows, 1u, 4u, f) != 4u) {
        (void)fclose(f);
        return -1;
    }
    total = 12u;
    for (i = 0u; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        uint32_t vlen;
        if (!store->rows[i].occupied) {
            continue;
        }
        vlen = store->rows[i].value_len;
        if (fwrite(store->rows[i].key, 1u, 20u, f) != 20u
            || fwrite(&vlen, 1u, 4u, f) != 4u) {
            (void)fclose(f);
            return -1;
        }
        if (vlen > 0u) {
            if (store->rows[i].value == NULL
                || fwrite(store->rows[i].value, 1u, vlen, f) != vlen) {
                (void)fclose(f);
                return -1;
            }
        }
        total += 24u + (size_t)vlen;
    }
    if (fclose(f) != 0) {
        return -1;
    }
    if (bytes_out != NULL) {
        *bytes_out = total;
    }
    return 0;
}

int host_completion_mfdt_store_import_path(
    ninlil_mfdt_v1_lab_store_t *store, const char *path, size_t *bytes_out)
{
    FILE *f;
    char mag[4];
    uint32_t ver = 0u;
    uint32_t nrows = 0u;
    uint32_t ri;
    size_t total = 0u;
    if (store == NULL || path == NULL) {
        return -1;
    }
    ninlil_mfdt_v1_lab_store_init(store);
    f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    if (fread(mag, 1u, 4u, f) != 4u || fread(&ver, 1u, 4u, f) != 4u
        || fread(&nrows, 1u, 4u, f) != 4u) {
        (void)fclose(f);
        return -1;
    }
    if (mag[0] != 'M' || mag[1] != 'F' || mag[2] != 'S' || mag[3] != 'T'
        || ver != 1u || nrows > (uint32_t)NINLIL_MFDT_V1_LAB_MAX_ROWS) {
        (void)fclose(f);
        return -1;
    }
    total = 12u;
    for (ri = 0u; ri < nrows; ++ri) {
        uint8_t key[20];
        uint32_t vlen = 0u;
        uint8_t *tmp = NULL;
        if (fread(key, 1u, 20u, f) != 20u || fread(&vlen, 1u, 4u, f) != 4u) {
            (void)fclose(f);
            return -1;
        }
        if (vlen > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) {
            (void)fclose(f);
            return -1;
        }
        if (vlen > 0u) {
            tmp = (uint8_t *)malloc((size_t)vlen);
            if (tmp == NULL || fread(tmp, 1u, vlen, f) != vlen) {
                free(tmp);
                (void)fclose(f);
                return -1;
            }
        }
        if (ninlil_mfdt_v1_lab_full_begin(store) != NINLIL_MFDT_V1_OK
            || ninlil_mfdt_v1_lab_put(store, key, tmp, vlen) != NINLIL_MFDT_V1_OK
            || ninlil_mfdt_v1_lab_full_commit(store) != NINLIL_MFDT_V1_OK) {
            free(tmp);
            (void)fclose(f);
            return -1;
        }
        free(tmp);
        total += 24u + (size_t)vlen;
    }
    if (fclose(f) != 0) {
        return -1;
    }
    if (bytes_out != NULL) {
        *bytes_out = total;
    }
    return 0;
}
