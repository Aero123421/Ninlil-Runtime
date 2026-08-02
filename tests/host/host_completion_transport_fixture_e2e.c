/*
 * Host test-only transport fixture E2E (private, non-installed).
 * Roles: --role parent|relay|endpoint
 *
 * This fixture uses host_completion_wire test mapping. It is fail-closed
 * transport/restart evidence, not canonical Foundation owner-plane completion
 * and not a Domain/Wi-Fi/R7 FRAG/RRMP/MFDT cross-feature E2E claim.
 *
 * Fail-closed requirements (no false-green):
 *  (1) Real reconnect: multi-accept relay + only "endpoint: RECONNECTED"
 *  (2) MFDT full reassembly + digest match + publication exactly once + sender complete
 *  (3) Cold recover from real durable storage bytes → fresh owner/engine, LIVE continues
 *  (4) Duplicate: parent pub count=1, RRMP hop custody count does not increase
 *  (5) P1 loss→P2 exact parent B + subsequent completion (no soft/OR)
 *
 * Flow: parents attach → relay hop on P1 → SWITCH_TO_P2 → hop on P2 →
 *       durable cold recover → accept E → bidirectional MFDT bridge on P2 only.
 */
#include "host_completion_wire.h"

#include "fabric_rrmp_select_hook.h"
#include "in_memory_storage.h"
#include "mfdt_v1.h"
#include "mfdt_v1_pipeline.h"
#include "ninlil/platform.h"
#include "rrmp_abi.h"
#include "rrmp_codec.h"
#include "rrmp_seam.h"
#include "rrmp_util.h"
#include "wifi_attachment_m4.h"
#include "wifi_session.h"

/*
 * Reuse the exact v2 authority-transition fixture builders. Rename its
 * generic ID helper so this translation unit can retain its local helper.
 */
#define rrmp_fill_id rrmp_test_common_fill_id
#include "../runtime/route_relay_v1/rrmp_test_common.h"
#undef rrmp_fill_id

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { RRMP_WS_MAX = 512 * 1024 };
enum { CONTENT_BYTES = 2000u }; /* > 896 → multi-chunk MFDT */
enum { SESSION_COOKIE = 0x4d464454ull };

/*
 * Test-control record carried over the same authenticated NWB1/NFL1 session.
 * It is never forwarded through RRMP or exposed as ApplicationData.  Its only
 * purpose is to make every multi-process fixture role finish explicitly so the
 * shell gate can collect authoritative exit statuses instead of killing
 * long-lived roles after observing partial log markers.
 */
static const uint8_t k_host_completion_shutdown[] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'H', 'C', '-', 'S', 'H', 'U', 'T',
    'D', 'O', 'W', 'N', '-', 'V', '1', 0xa5, 0x5a, 0x3c};
static const uint8_t k_host_completion_shutdown_ack[] = {
    'N', 'I', 'N', 'L', 'I', 'L', '-', 'H', 'C', '-', 'S', 'H', 'U', 'T',
    'D', 'O', 'W', 'N', '-', 'A', 'C', 'K', '-', 'V', '1', 0x5a, 0xa5, 0xc3};

_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_rrmp_ws[RRMP_WS_MAX];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_rrmp_ws2[RRMP_WS_MAX];
static uint8_t g_rrmp_storage_value[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];

static int host_completion_is_shutdown(const uint8_t *bytes, size_t length)
{
    return bytes != NULL
        && length == sizeof(k_host_completion_shutdown)
        && memcmp(bytes, k_host_completion_shutdown, length) == 0;
}

static int host_completion_is_shutdown_ack(const uint8_t *bytes, size_t length)
{
    return bytes != NULL
        && length == sizeof(k_host_completion_shutdown_ack)
        && memcmp(bytes, k_host_completion_shutdown_ack, length) == 0;
}

static uint64_t mono_ms(void *user)
{
    struct timespec ts;
    (void)user;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void fill_endpoint(ninlil_wifi_endpoint_t *ep, uint16_t port)
{
    (void)memset(ep, 0, sizeof(*ep));
    ep->address_kind = 1u;
    ep->port = port;
    ep->address[0] = 127u;
    ep->address[1] = 0u;
    ep->address[2] = 0u;
    ep->address[3] = 1u;
}

static const uint8_t k_fabric_desc[32] = {
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
    0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0
};
static const uint8_t k_cred_digest[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11
};

static int accept_m4(ninlil_wifi_session_t *session)
{
    ninlil_wifi_m4_full_evidence_t ev;
    ninlil_wifi_m4_membership_lease_t lease;
    ninlil_wifi_m4_fabric_registry_t reg;
    /* Process-static owner: wait_attached may retry; do not mint unbounded slots. */
    static ninlil_wifi_m4_owner_t m4_owner;
    static int m4_owner_ready = 0;
    ninlil_test_storage_t *store = NULL;
    ninlil_test_storage_config_t cfg;
    const ninlil_storage_ops_t *ops;
    uint8_t peer[16];
    uint8_t att[16];
    uint8_t epoch[16];
    ninlil_wifi_status_t st;
    uint64_t now = mono_ms(NULL);
    int rc = -1;

    if (ninlil_wifi_session_get_session_ids(session, peer, att) != NINLIL_WIFI_OK) {
        return -1;
    }
    if (!m4_owner_ready) {
        ninlil_wifi_m4_owner_init(&m4_owner);
        m4_owner_ready = 1;
    }
    if (ninlil_wifi_m4_evidence_reset(&m4_owner, &ev) != NINLIL_WIFI_OK) {
        (void)ninlil_wifi_m4_owner_restart(&m4_owner);
        if (ninlil_wifi_m4_evidence_reset(&m4_owner, &ev) != NINLIL_WIFI_OK) {
            return -1;
        }
    }
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 8u;
    cfg.max_entries_per_namespace = 64u;
    cfg.max_bytes_per_namespace = 65536u;
    store = ninlil_test_storage_create(&cfg);
    if (store == NULL) {
        return -1;
    }
    ops = ninlil_test_storage_ops(store);
    (void)memset(&lease, 0, sizeof(lease));
    (void)memcpy(lease.member_runtime_id, peer, 16u);
    lease.lease_not_before_ms = now > 1000u ? now - 1000u : 0u;
    lease.lease_not_after_ms = now + 600000u;
    (void)memset(lease.authority_id, 0xd0, 16u);
    lease.authority_id[15] = 0xdf;
    (void)memset(lease.binding_digest, 0xb1, 32u);
    if (ninlil_wifi_m4_membership_store_full(ops, store, "hc-m4", &lease)
        != NINLIL_WIFI_OK) {
        goto out;
    }
    if (ninlil_wifi_m4_membership_load_classify(
            &m4_owner, ops, store, "hc-m4", now, &ev)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_membership_live(&ev) == 0) {
        goto out;
    }
    if (ninlil_wifi_m4_credential_store_full(
            ops, store, "hc-m4", k_cred_digest, 1u)
        != NINLIL_WIFI_OK) {
        goto out;
    }
    if (ninlil_wifi_m4_credential_load_classify(
            &m4_owner, ops, store, "hc-m4", &ev)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_class_credential(&ev)
            != NINLIL_WIFI_M4_CLASS_FULL) {
        goto out;
    }
    if (ninlil_wifi_m4_attachment_store_full(
            ops,
            store,
            "hc-m4",
            peer,
            lease.authority_id,
            lease.binding_digest,
            k_cred_digest,
            k_fabric_desc)
        != NINLIL_WIFI_OK) {
        goto out;
    }
    if (ninlil_wifi_m4_attachment_load_classify(
            &m4_owner, ops, store, "hc-m4", peer, &ev)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_class_attachment(&ev)
            != NINLIL_WIFI_M4_CLASS_FULL) {
        goto out;
    }
    (void)memset(epoch, 0xe1, sizeof(epoch));
    st = ninlil_wifi_m4_fabric_registry_bind(
        &reg, k_fabric_desc, lease.authority_id, epoch);
    if (st != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_apply_fabric_registry(&ev, &reg)
            != NINLIL_WIFI_OK) {
        goto out;
    }
    /* Session-authority mint required for ready_for_attach (no free assert). */
    if (ninlil_wifi_m4_evidence_mark_session_authority(&ev) != NINLIL_WIFI_OK) {
        goto out;
    }
    if (ninlil_wifi_session_accept_m4_full_evidence(session, &ev)
        != NINLIL_WIFI_OK) {
        goto out;
    }
    if (session->phase != NINLIL_WIFI_PHASE_ATTACHED) {
        goto out;
    }
    rc = 0;
out:
    /* Free slot on failure so retries do not hit CAPACITY. */
    if (rc != 0) {
        ninlil_wifi_m4_evidence_consume(&ev);
    }
    ninlil_test_storage_destroy(store);
    return rc;
}

static void fill_peer_inputs(ninlil_wifi_peer_context_inputs_t *in)
{
    uint8_t i;
    (void)memset(in, 0, sizeof(*in));
    (void)memset(in->authority_id, 0xd0, 16u);
    in->authority_id[15] = 0xdf;
    in->authority_term = 7u;
    in->assignment_epoch = 11u;
    for (i = 0u; i < 16u; ++i) {
        in->tls_client_runtime_id[i] = (uint8_t)(0x31u + i);
        in->tls_server_runtime_id[i] = (uint8_t)(0x32u + i);
    }
}

static int wait_attached_budget(ninlil_wifi_session_t *session, uint32_t max_spins)
{
    uint32_t spins = 0u;
    while (spins < max_spins) {
        ninlil_wifi_status_t st = ninlil_wifi_session_poll(session);
        if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
            && st != NINLIL_WIFI_BACKPRESSURE
            && st != NINLIL_WIFI_INVALID_STATE) {
            (void)fprintf(stderr, "poll fail %u phase=%u\n", (unsigned)st,
                (unsigned)session->phase);
            return -1;
        }
        if (session->phase == NINLIL_WIFI_PHASE_PEER_SESSION
            || session->phase == NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING
            || session->phase == NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED) {
            if (session->phase != NINLIL_WIFI_PHASE_ATTACHED) {
                (void)accept_m4(session);
            }
        }
        if (session->phase == NINLIL_WIFI_PHASE_ATTACHED) {
            return 0;
        }
        if (session->phase == NINLIL_WIFI_PHASE_FENCED
            || session->phase == NINLIL_WIFI_PHASE_CLOSED) {
            (void)fprintf(stderr, "fenced/closed phase=%u\n",
                (unsigned)session->phase);
            return -1;
        }
        usleep(1000);
        spins += 1u;
    }
    (void)fprintf(stderr, "attach timeout phase=%u\n",
        (unsigned)session->phase);
    return -1;
}

static int wait_attached(ninlil_wifi_session_t *session)
{
    return wait_attached_budget(session, 60000u);
}

static int connect_wait_budget(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_endpoint_t *ep,
    uint32_t max_spins)
{
    ninlil_wifi_status_t st;
    uint32_t spins = 0u;
    if (ninlil_wifi_session_set_fabric_descriptor(session, k_fabric_desc)
        != NINLIL_WIFI_OK) {
        return -1;
    }
    st = ninlil_wifi_session_connect(session, ep);
    while (st == NINLIL_WIFI_WOULD_BLOCK && spins < max_spins) {
        usleep(1000);
        spins += 1u;
        st = ninlil_wifi_session_poll(session);
        if (session->phase == NINLIL_WIFI_PHASE_CONNECTING
            || session->phase == NINLIL_WIFI_PHASE_HANDSHAKING) {
            st = NINLIL_WIFI_WOULD_BLOCK;
        } else if (
            session->phase == NINLIL_WIFI_PHASE_PEER_SESSION
            || session->phase == NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING
            || session->phase == NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED
            || session->phase == NINLIL_WIFI_PHASE_ATTACHED) {
            st = NINLIL_WIFI_OK;
        } else if (
            session->phase == NINLIL_WIFI_PHASE_FENCED
            || session->phase == NINLIL_WIFI_PHASE_CLOSED) {
            return -1;
        }
    }
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        return -1;
    }
    return wait_attached_budget(session, max_spins);
}

static int connect_wait(
    ninlil_wifi_session_t *session, const ninlil_wifi_endpoint_t *ep)
{
    return connect_wait_budget(session, ep, 60000u);
}

static int configure_tls_paths(
    ninlil_wifi_session_t *session, const char *certs, int is_server)
{
    ninlil_wifi_tls_paths_t paths;
    char ca[512];
    char cert[512];
    char key[512];
    (void)memset(&paths, 0, sizeof(paths));
    (void)snprintf(ca, sizeof(ca), "%s/ca.cert.pem", certs);
    if (is_server) {
        (void)snprintf(cert, sizeof(cert), "%s/server.cert.pem", certs);
        (void)snprintf(key, sizeof(key), "%s/server.key.pem", certs);
    } else {
        (void)snprintf(cert, sizeof(cert), "%s/client.cert.pem", certs);
        (void)snprintf(key, sizeof(key), "%s/client.key.pem", certs);
    }
    paths.ca_pem_path = ca;
    paths.cert_pem_path = cert;
    paths.key_pem_path = key;
    return ninlil_wifi_session_configure_tls(session, is_server, &paths)
            == NINLIL_WIFI_OK
        ? 0
        : -1;
}

/* ---- RRMP helpers ------------------------------------------------------- */

static void rrmp_fill_id(uint8_t id[16], uint8_t seed)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        id[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void rrmp_scope_ctx_default(ninlil_rrmp_scope_derivation_ctx_t *ctx)
{
    ninlil_rrmp_memzero(ctx, sizeof(*ctx));
    rrmp_fill_id(ctx->endpoint_runtime_id, 0x10u);
    ctx->direction = 0u;
    ctx->traffic_class = 1u;
    ctx->namespace_len = 4u;
    ctx->service_len = 3u;
    (void)memcpy(ctx->namespace, "nspc", 4u);
    (void)memcpy(ctx->service, "svc", 3u);
}

static int rrmp_install_route(ninlil_rrmp_owner_t *o, uint16_t h)
{
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_activate_req_v1_t act;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_nrm1_fields_t f;
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];

    ninlil_rrmp_owner_bind(o);
    ninlil_rrmp_memzero(&install, sizeof(install));
    install.preamble.api_version = 1u;
    install.preamble.struct_size = 312u;
    rrmp_fill_id(install.authority_id, 0xA0u);
    install.controller_term = 5u;
    install.batch_id = 1u;
    install.entry_count = 1u;
    ninlil_rrmp_memzero(&f, sizeof(f));
    rrmp_fill_id(f.authority_id.bytes, 0xA0u);
    f.controller_term = 5u;
    f.route_revision = 1u;
    f.lease_epoch = 1u;
    rrmp_fill_id(f.authority_clock_epoch_id.bytes, 0x50u);
    f.lease_expiry_ms = 5000000u;
    f.ingress_hop_context_id = 0x1000u + h;
    f.route_handle = h;
    f.route_generation = 1u;
    rrmp_fill_id(f.egress_peer_id.bytes, 0x60u);
    f.egress_hop_context_id = 0x2000u + h;
    f.egress_route_handle = 0u;
    f.egress_route_generation = 0u;
    rrmp_fill_id(f.grant_id.bytes, 0x70u);
    f.queue_quota_entries = 8u;
    f.queue_quota_bytes = 2048u;
    f.max_hops = 1u;
    f.ack_policy = 1u;
    f.terminal_flag = 1u;
    rrmp_fill_id(f.path_policy_id.bytes, 0x80u);
    f.path_policy_revision = 1u;
    if (!ninlil_rrmp_encode_nrm1(&f, raw)) {
        return -1;
    }
    (void)memcpy(install.entries, raw, sizeof(raw));
    if (ninlil_route_install_batch(&install, &out) != NINLIL_ROUTE_OK) {
        return -1;
    }
    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = 64u;
    act.ingress_hop_context_id = 0x1000u + h;
    act.route_handle = h;
    act.route_generation = 1u;
    act.now_ms = 1000000u;
    if (ninlil_route_activate(&act, &out) != NINLIL_ROUTE_OK) {
        return -1;
    }
    return 0;
}

/* Install 2-parent set under derived owner_scope for path_policy 0x80. */
static int rrmp_install_two_parents(
    ninlil_rrmp_owner_t *o, uint8_t scope_out[16], uint8_t path_policy_out[16])
{
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[2];
    ninlil_rrmp_digest32_t dig;
    ninlil_rrmp_scope_derivation_ctx_t ctx;

    ninlil_rrmp_owner_bind(o);
    rrmp_scope_ctx_default(&ctx);
    ninlil_rrmp_owner_set_scope_derivation(o, &ctx);
    rrmp_fill_id(path_policy_out, 0x80u);
    if (!ninlil_rrmp_derive_owner_scope_id(
            ctx.endpoint_runtime_id,
            ctx.direction,
            ctx.namespace,
            ctx.namespace_len,
            ctx.service,
            ctx.service_len,
            ctx.traffic_class,
            path_policy_out,
            scope_out)) {
        return -1;
    }
    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    (void)memcpy(set.owner_scope_id, scope_out, 16u);
    set.parent_set_count = 2u;
    (void)memcpy(set.path_policy_id, path_policy_out, 16u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x30u);
    rrmp_fill_id(ids[1].bytes, 0x40u);
    (void)memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    (void)memcpy(set.parent_runtime_id[1], ids[1].bytes, 16u);
    if (!ninlil_rrmp_parent_set_digest(ids, 2u, &dig)) {
        return -1;
    }
    (void)memcpy(set.parent_set_digest32, dig.bytes, 32u);
    if (ninlil_parent_set_install(&set, &out) != NINLIL_PARENT_OK) {
        return -1;
    }
    return 0;
}

/*
 * Production hop seam: admit + hop_forward with optional app carrier (NCL1).
 * Carrier bytes go to RRMP outbound provider → Fabric/WiFi. No external
 * host_completion_session_send_ncl1 for the forward path.
 */
static int rrmp_hop_with_outbound(
    ninlil_rrmp_owner_t *o,
    const uint8_t e2e_digest[32],
    uint64_t token,
    const uint8_t *carrier,
    uint16_t carrier_len,
    ninlil_rrmp_hop_tx_view_t *tx_out)
{
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_hop_tx_view_t tx;
    ninlil_rrmp_link_ack_evidence_t ev;
    ninlil_route_forward_complete_req_v1_t comp;
    size_t i;

    ninlil_rrmp_owner_bind(o);
    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = token;
    admit.outer_rx_counter = 100u + token;
    (void)memcpy(admit.e2e_header_digest32, e2e_digest, 32u);
    {
        ninlil_route_status_u32 ast;
        ninlil_route_status_u32 hst;
        ast = ninlil_route_forward_admit(&admit, &out);
        if (ast != NINLIL_ROUTE_OK) {
            (void)fprintf(stderr, "hop admit st=%u\n", (unsigned)ast);
            return -1;
        }
        hst = ninlil_rrmp_core_hop_forward_execute(
            o, out.opaque_local_handle, carrier, carrier_len, 1u, &tx);
        if (hst != NINLIL_ROUTE_OK) {
            (void)fprintf(stderr, "hop exec st=%u\n", (unsigned)hst);
            return -1;
        }
        if (carrier_len != 0u) {
            if (tx.carrier_set != 1u || tx.payload_len != carrier_len
                || memcmp(tx.payload, carrier, carrier_len) != 0) {
                (void)fprintf(stderr, "hop carrier bytes mismatch\n");
                return -1;
            }
        }
    }
    {
        uint64_t oh = out.opaque_local_handle;
        ninlil_rrmp_memzero(&ev, sizeof(ev));
        ev.opaque_local_handle = oh;
        ev.auth_ok = 1u;
        ev.ack_ok = 1u;
        ev.outer_tx_counter = tx.outer_tx_counter;
        /*
         * Exact installed route egress peer.  LINK_ACK authority compares
         * this identity with the queue's durable expected_peer_id.
         */
        rrmp_fill_id(ev.peer_runtime_id, 0x60u);
        for (i = 0u; i < 32u; ++i) {
            ev.auth_proof32[i] = (uint8_t)(0xA1u + i);
        }
        {
            ninlil_route_status_u32 ack_st =
                ninlil_rrmp_core_link_ack_from_evidence(o, &ev, &out);
            if (ack_st != NINLIL_ROUTE_OK) {
                (void)fprintf(
                    stderr,
                    "hop link_ack st=%u out=%u\n",
                    (unsigned)ack_st,
                    (unsigned)out.status);
                return -1;
            }
        }
        ninlil_rrmp_memzero(&comp, sizeof(comp));
        comp.preamble.api_version = 1u;
        comp.preamble.struct_size = 64u;
        comp.opaque_local_handle = oh;
        comp.outcome = 1u;
        comp.completion_now_ms = 1000001u;
        {
            ninlil_route_status_u32 complete_st =
                ninlil_route_forward_complete(&comp, &out);
            if (complete_st != NINLIL_ROUTE_OK) {
                (void)fprintf(
                    stderr,
                    "hop complete st=%u out=%u\n",
                    (unsigned)complete_st,
                    (unsigned)out.status);
                return -1;
            }
        }
    }
    if (tx_out != NULL) {
        *tx_out = tx;
    }
    return 0;
}

static int digest_hex32(const uint8_t dig[32], char out[65])
{
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        if (snprintf(out + i * 2u, 3, "%02x", dig[i]) != 2) {
            return -1;
        }
    }
    out[64] = '\0';
    return 0;
}

/*
 * Durable logical publication count: number of NM3R rows with publication_state
 * non-zero and a non-zero publication_token (record bytes [248..263]).
 * Not eng.publication_ready (volatile). Not a log-line counter.
 */
static uint32_t durable_nm3r_publication_count(
    const ninlil_mfdt_v1_lab_store_t *store)
{
    size_t ri;
    uint32_t n = 0u;
    uint8_t rec[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];
    uint32_t rlen = 0u;
    uint8_t owner_side = 0u, state_code = 0u, tid[16];
    uint32_t revision = 0u;
    uint8_t man[32];
    const uint8_t *ob = NULL, *ent = NULL, *content = NULL;
    uint16_t ol = 0u, el = 0u;
    uint32_t clen = 0u;
    uint64_t rgen = 0u;
    uint8_t pbm = 0u, rtry = 0u, pstate = 0u, hstate = 0u;
    uint64_t cbm = 0u;
    size_t zi;

    if (store == NULL) {
        return 0u;
    }
    for (ri = 0u; ri < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++ri) {
        if (!store->rows[ri].occupied || store->rows[ri].key_len < 4u) {
            continue;
        }
        if (store->rows[ri].key[0] != (uint8_t)'N'
            || store->rows[ri].key[1] != (uint8_t)'M'
            || store->rows[ri].key[2] != (uint8_t)'3'
            || store->rows[ri].key[3] != (uint8_t)'R') {
            continue;
        }
        if (ninlil_mfdt_v1_lab_get(
                store, store->rows[ri].key, rec, sizeof(rec), &rlen)
            != 0) {
            continue;
        }
        if (ninlil_mfdt_v1_record_unpack(
                rec, rlen, &owner_side, &state_code, tid, &revision, man, &ob,
                &ol, &ent, &el, &content, &clen, &rgen, &pbm, &cbm, &rtry,
                &pstate, &hstate)
            != 0) {
            continue;
        }
        if (pstate == 0u || rlen < 264u) {
            continue;
        }
        {
            int tok_nz = 0;
            for (zi = 0u; zi < 16u; ++zi) {
                if (rec[248u + zi] != 0u) {
                    tok_nz = 1;
                    break;
                }
            }
            if (tok_nz) {
                n += 1u;
            }
        }
    }
    return n;
}

static int parent_publication_digest(
    ninlil_mfdt_v1_lab_store_t *store, uint8_t dig_out[32])
{
    size_t ri;
    uint8_t rec[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];
    uint32_t rlen = 0u;
    const uint8_t *content = NULL;
    uint32_t clen = 0u;
    uint8_t owner_side = 0u, state_code = 0u, tid[16];
    uint32_t revision = 0u;
    uint8_t man[32];
    const uint8_t *ob = NULL, *ent = NULL;
    uint16_t ol = 0u, el = 0u;
    uint64_t rgen = 0u;
    uint8_t pbm = 0u, rtry = 0u, pstate = 0u, hstate = 0u;
    uint64_t cbm = 0u;

    for (ri = 0u; ri < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++ri) {
        if (!store->rows[ri].occupied) {
            continue;
        }
        if (store->rows[ri].key_len >= 4u
            && store->rows[ri].key[0] == (uint8_t)'N'
            && store->rows[ri].key[1] == (uint8_t)'M'
            && store->rows[ri].key[2] == (uint8_t)'3'
            && store->rows[ri].key[3] == (uint8_t)'R') {
            if (ninlil_mfdt_v1_lab_get(
                    store, store->rows[ri].key, rec, sizeof(rec), &rlen)
                != 0) {
                continue;
            }
            if (ninlil_mfdt_v1_record_unpack(
                    rec, rlen, &owner_side, &state_code, tid, &revision, man,
                    &ob, &ol, &ent, &el, &content, &clen, &rgen, &pbm, &cbm,
                    &rtry, &pstate, &hstate)
                != 0) {
                continue;
            }
            if (content != NULL && clen > 0u && pstate != 0u) {
                ninlil_mfdt_v1_sha256(content, clen, dig_out);
                return 0;
            }
        }
    }
    return -1;
}

/*
 * Serialize the exact committed platform rows, preserving the manifest/chunk
 * boundary and every value-size limit. This is the cold-process authority;
 * the logical namespace export is deliberately not used as a storage value.
 */
static int rrmp_storage_export_physical(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    uint8_t *out,
    size_t cap,
    size_t *len_out)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t sst;
    static const uint8_t k_magic[8] = {
        'H', 'C', 'R', 'R', 'P', 'H', '1', '\0'};
    static const uint8_t k_prefix[5] = {'R', 'R', 'M', 'P', '/'};
    uint8_t key_bytes[255];
    uint32_t count = 0u;
    size_t off = 12u;

    if (ops == NULL || handle == NULL || out == NULL || len_out == NULL
        || cap < off) {
        return -1;
    }
    *len_out = 0u;
    sst = ops->begin(ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn);
    if (sst != NINLIL_STORAGE_OK || txn == NULL) {
        return -1;
    }
    sst = ops->iter_open(
        ops->user,
        txn,
        (ninlil_bytes_view_t){k_prefix, (uint32_t)sizeof(k_prefix)},
        &iter);
    if (sst != NINLIL_STORAGE_OK || iter == NULL) {
        (void)ops->rollback(ops->user, txn);
        return -1;
    }
    (void)memcpy(out, k_magic, sizeof(k_magic));
    for (;;) {
        ninlil_mut_bytes_t key;
        ninlil_mut_bytes_t value;
        key.data = key_bytes;
        key.length = 0u;
        key.capacity = (uint32_t)sizeof(key_bytes);
        value.data = g_rrmp_storage_value;
        value.length = 0u;
        value.capacity = (uint32_t)sizeof(g_rrmp_storage_value);
        sst = ops->iter_next(ops->user, iter, &key, &value);
        if (sst == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (sst != NINLIL_STORAGE_OK || count >= 6u || key.length == 0u
            || value.length > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES
            || off > cap || cap - off < 8u + key.length + value.length) {
            ops->iter_close(ops->user, iter);
            (void)ops->rollback(ops->user, txn);
            return -1;
        }
        ninlil_rrmp_put_u32_be(out + off, key.length);
        ninlil_rrmp_put_u32_be(out + off + 4u, value.length);
        off += 8u;
        (void)memcpy(out + off, key.data, key.length);
        off += key.length;
        (void)memcpy(out + off, value.data, value.length);
        off += value.length;
        count += 1u;
    }
    ops->iter_close(ops->user, iter);
    if (count == 0u
        || ops->rollback(ops->user, txn) != NINLIL_STORAGE_OK) {
        return -1;
    }
    ninlil_rrmp_put_u32_be(out + 8u, count);
    *len_out = off;
    return 0;
}

static int rrmp_storage_import_physical(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    const uint8_t *bytes,
    size_t len)
{
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t k_magic[8] = {
        'H', 'C', 'R', 'R', 'P', 'H', '1', '\0'};
    uint32_t count;
    uint32_t row;
    const uint8_t *previous_key = NULL;
    uint32_t previous_key_len = 0u;
    size_t off = 12u;

    if (ops == NULL || handle == NULL || bytes == NULL || len < off
        || memcmp(bytes, k_magic, sizeof(k_magic)) != 0) {
        return -1;
    }
    count = ninlil_rrmp_get_u32_be(bytes + 8u);
    if (count == 0u || count > 6u
        || ops->begin(
               ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            != NINLIL_STORAGE_OK
        || txn == NULL) {
        return -1;
    }
    for (row = 0u; row < count; ++row) {
        uint32_t key_len;
        uint32_t value_len;
        ninlil_bytes_view_t key;
        ninlil_bytes_view_t value;
        if (off > len || len - off < 8u) {
            (void)ops->rollback(ops->user, txn);
            return -1;
        }
        key_len = ninlil_rrmp_get_u32_be(bytes + off);
        value_len = ninlil_rrmp_get_u32_be(bytes + off + 4u);
        off += 8u;
        if (key_len != 7u
            || value_len > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES
            || off > len || len - off < (size_t)key_len + value_len
            || memcmp(bytes + off, "RRMP/", 5u) != 0
            || (previous_key != NULL
                && (previous_key_len != key_len
                    || memcmp(previous_key, bytes + off, key_len) >= 0))) {
            (void)ops->rollback(ops->user, txn);
            return -1;
        }
        key.data = bytes + off;
        key.length = key_len;
        previous_key = key.data;
        previous_key_len = key_len;
        off += key_len;
        value.data = bytes + off;
        value.length = value_len;
        off += value_len;
        if (ops->put(ops->user, txn, key, value) != NINLIL_STORAGE_OK) {
            (void)ops->rollback(ops->user, txn);
            return -1;
        }
    }
    if (off != len
        || ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        return -1;
    }
    return 0;
}

static int rrmp_storage_current_witness(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    ninlil_rrmp_bundle_witness_v2_t *out)
{
    static const uint8_t k_manifest_key[7] = {
        'R', 'R', 'M', 'P', '/', 'M', '1'};
    ninlil_storage_txn_t txn = NULL;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t st;

    if (ops == NULL || handle == NULL || out == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    st = ops->begin(
        ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK || txn == NULL) {
        return 0;
    }
    value.data = out->manifest_rrm1;
    value.length = 0u;
    value.capacity = NINLIL_RRMP_RRM1_BYTES;
    st = ops->get(
        ops->user,
        txn,
        (ninlil_bytes_view_t){
            k_manifest_key, (uint32_t)sizeof(k_manifest_key)},
        &value);
    if (ops->rollback(ops->user, txn) != NINLIL_STORAGE_OK
        || st != NINLIL_STORAGE_OK
        || value.length != NINLIL_RRMP_RRM1_BYTES
        || memcmp(out->manifest_rrm1, "RRM1", 4u) != 0) {
        ninlil_rrmp_memzero(out, sizeof(*out));
        return 0;
    }
    out->logical_length =
        ninlil_rrmp_get_u32_be(out->manifest_rrm1 + 16u);
    if (out->logical_length == 0u
        || out->logical_length > NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX) {
        ninlil_rrmp_memzero(out, sizeof(*out));
        return 0;
    }
    out->present = 1u;
    (void)memcpy(
        out->logical_sha256, out->manifest_rrm1 + 24u, 32u);
    return 1;
}

/*
 * Bootstrap a live parent authority through the real S1/S3/S4 entrypoints
 * while platform storage is already bound. No scope is made seal-capable by
 * a fixture flag; every transition is closed by its production FULL writepoint.
 */
static int rrmp_bootstrap_assignment_durable(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    const uint8_t owner_scope_id[16],
    const uint8_t path_policy_id[16],
    const uint8_t parent_set_digest32[32],
    uint8_t parent_set_count,
    const uint8_t token32[32])
{
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_activate_req_v1_t activate;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    ninlil_rrmp_bundle_witness_v2_t expected_bundle;
    uint8_t proof[32];
    uint8_t commit_digest[32];

    if (ops == NULL || handle == NULL || owner_scope_id == NULL
        || path_policy_id == NULL || parent_set_digest32 == NULL
        || parent_set_count == 0u || token32 == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(&noa, sizeof(noa));
    (void)memcpy(noa.owner_scope_id.bytes, owner_scope_id, 16u);
    rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
    noa.controller_term = 5u;
    noa.assignment_epoch = 1u;
    noa.assignment_revision = 1u;
    rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
    rrmp_fill_id(noa.owner_cell_id.bytes, 0xB1u);
    noa.direction = 1u;
    noa.e2e_context_id = 1u;
    noa.key_generation = 1u;
    rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
    noa.e2e_security_epoch = 1u;
    (void)memset(noa.e2e_binding_digest.bytes, 0xE1, 32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    (void)memcpy(noa.handoff_token_digest.bytes, token32, 32u);
    (void)memcpy(
        noa.parent_set_digest.bytes, parent_set_digest32, 32u);
    noa.parent_set_count = parent_set_count;
    (void)memcpy(noa.parent_set_id.bytes, path_policy_id, 16u);

    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = (uint32_t)sizeof(prep);
    (void)memcpy(prep.owner_scope_id, owner_scope_id, 16u);
    if (!ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1)) {
        return 0;
    }
    (void)memcpy(prep.handoff_token_digest32, token32, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    if (rrmp_test_owner_prepare_v2(
            &prep, &old_tuple, 1u, &new_tuple, &out)
            != NINLIL_PARENT_OK
        || rrmp_test_owner_fence_v2(
            owner_scope_id, token32, &old_tuple, proof, &out)
            != NINLIL_PARENT_OK
        || !rrmp_storage_current_witness(
            ops, handle, &expected_bundle)
        || rrmp_test_authority_commit_v2(
            owner_scope_id,
            &old_tuple,
            &new_tuple,
            token32,
            proof,
            &expected_bundle,
            0u,
            commit_digest,
            &out) != NINLIL_PARENT_OK) {
        return 0;
    }
    ninlil_rrmp_memzero(&activate, sizeof(activate));
    activate.preamble.api_version = 1u;
    activate.preamble.struct_size = (uint32_t)sizeof(activate);
    (void)memcpy(activate.owner_scope_id, owner_scope_id, 16u);
    (void)memcpy(
        activate.commit_receipt_digest32, commit_digest, 32u);
    activate.now_ms = 1000000u;
    return ninlil_parent_owner_activate(&activate, &out)
        == NINLIL_PARENT_OK;
}

/* ---- roles -------------------------------------------------------------- */

static int role_parent(uint16_t port, const char *certs, const char *log_tag)
{
    ninlil_wifi_session_t session;
    ninlil_wifi_tcp_t listen_tcp;
    ninlil_wifi_tcp_t accepted_tcp;
    ninlil_wifi_peer_context_inputs_t pin;
    ninlil_mfdt_v1_engine_t eng;
    ninlil_mfdt_v1_workspace_t ws;
    ninlil_mfdt_v1_lab_store_t store;
    ninlil_mfdt_v1_pipeline_t pipe;
    ninlil_mfdt_v1_config_t cfg;
    uint32_t ncl1_count = 0u;
    uint32_t hop_count = 0u;
    uint32_t durable_pub_count = 0u;
    uint32_t durable_pub_at_first = 0u;
    uint8_t first_pub_token[16];
    int have_first_pub_token = 0;
    uint64_t bytes_rx = 0u;
    int accepted_ok = 0;
    uint32_t post_pub_frames = 0u;
    uint16_t bound_port = 0u;
    int shutdown_received = 0;

    (void)memset(first_pub_token, 0, sizeof(first_pub_token));

    ninlil_wifi_session_init(&session);
    ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
    ninlil_wifi_tcp_init(&listen_tcp);
    ninlil_wifi_tcp_init(&accepted_tcp);
    fill_peer_inputs(&pin);
    if (configure_tls_paths(&session, certs, 1) != 0) {
        (void)fprintf(stderr, "%s: tls paths\n", log_tag);
        return 1;
    }
    (void)ninlil_wifi_session_set_peer_context_inputs(&session, &pin);
    (void)ninlil_wifi_session_set_fabric_descriptor(&session, k_fabric_desc);
    if (ninlil_wifi_tcp_listen_loopback(&listen_tcp, port, &bound_port)
        != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "%s: listen %u failed\n", log_tag, (unsigned)port);
        return 1;
    }
    if (bound_port == 0u) {
        (void)fprintf(stderr, "%s: listener returned zero port\n", log_tag);
        return 1;
    }
    (void)printf("%s: listening port=%u\n", log_tag, (unsigned)bound_port);
    (void)fflush(stdout);

    {
        uint32_t spins = 0u;
        while (spins < 90000u) {
            ninlil_wifi_status_t st =
                ninlil_wifi_tcp_accept(&listen_tcp, &accepted_tcp);
            if (st == NINLIL_WIFI_OK) {
                accepted_ok = 1;
                break;
            }
            usleep(1000);
            spins += 1u;
        }
        if (!accepted_ok) {
            (void)fprintf(stderr, "%s: accept timeout\n", log_tag);
            return 1;
        }
    }
    if (ninlil_wifi_session_accept_fd(&session, accepted_tcp.fd)
        != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "%s: accept_fd fail\n", log_tag);
        return 1;
    }
    accepted_tcp.fd = -1;
    if (wait_attached(&session) != 0) {
        (void)fprintf(stderr, "%s: attach fail\n", log_tag);
        return 1;
    }
    (void)printf("%s: ATTACHED\n", log_tag);
    (void)fflush(stdout);

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.now_ms = mono_ms(NULL);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    (void)memset(cfg.local_clock_epoch.bytes, 0xe1, 16u);
    ninlil_mfdt_v1_lab_store_init(&store);
    if (ninlil_mfdt_v1_engine_init(&eng, &ws, &store, &cfg) != NINLIL_MFDT_V1_OK) {
        return 1;
    }
    ninlil_mfdt_v1_pipeline_init(
        &pipe, NULL, &eng, NULL, NULL, 1u, SESSION_COOKIE);

    for (;;) {
        uint8_t ncl1[HOST_COMPLETION_NCL1_MAX];
        size_t nlen = 0u;
        uint32_t seq = 0u;
        int rr = host_completion_session_recv_ncl1(
            &session, ncl1, sizeof(ncl1), &nlen, &seq, 30000u);
        if (rr == -2) {
            (void)fprintf(stderr,
                "%s: explicit shutdown timeout durable_pub=%u hop=%u\n",
                log_tag,
                durable_pub_count,
                hop_count);
            return 1;
        }
        if (rr == 1) {
            hop_count += 1u;
            (void)printf("%s: hop_frame seq=%u hops=%u\n", log_tag, seq, hop_count);
            (void)printf(
                "%s: VERIFIED_HOP_FRAME seq=%u count=%u\n",
                log_tag,
                seq,
                hop_count);
            (void)fflush(stdout);
            continue;
        }
        if (rr != 0) {
            if (durable_pub_count == 1u) {
                break;
            }
            return 1;
        }
        if (host_completion_is_shutdown(ncl1, nlen)) {
            shutdown_received = 1;
            (void)printf(
                "%s: SHUTDOWN_RECEIVED hop=%u ncl1=%u durable_pub=%u\n",
                log_tag,
                hop_count,
                ncl1_count,
                durable_pub_count);
            (void)fflush(stdout);
            break;
        }
        ncl1_count += 1u;
        bytes_rx += (uint64_t)nlen;
        (void)ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pipe, ncl1, nlen);
        if (ninlil_mfdt_v1_pipeline_outbox_pending(&pipe)) {
            uint8_t outf[HOST_COMPLETION_NCL1_MAX];
            size_t on = 0u;
            while (ninlil_mfdt_v1_pipeline_take_outbound(
                       &pipe, outf, sizeof(outf), &on)
                    == 0
                && on > 0u) {
                if (host_completion_session_send_ncl1(&session, outf, on) != 0) {
                    (void)fprintf(stderr, "%s: reply send fail\n", log_tag);
                    return 1;
                }
            }
        }
        /* Process-local durable publication audit after every ingress. */
        durable_pub_count = durable_nm3r_publication_count(&store);
        (void)printf(
            "%s: ncl1_frame n=%u len=%u eng_pub=%u durable_pub=%u\n",
            log_tag,
            ncl1_count,
            (unsigned)nlen,
            (unsigned)eng.publication_ready,
            durable_pub_count);
        (void)fflush(stdout);

        if (durable_pub_count > 1u) {
            (void)fprintf(stderr,
                "%s: FAIL durable publication count=%u (exactly-once violated)\n",
                log_tag, durable_pub_count);
            ninlil_wifi_session_close(&session);
            ninlil_wifi_tcp_close(&listen_tcp);
            return 1;
        }
        if (eng.publication_ready && durable_pub_count != 1u) {
            (void)fprintf(stderr,
                "%s: FAIL eng.publication_ready but durable_pub=%u\n",
                log_tag, durable_pub_count);
            return 1;
        }
        if (durable_pub_count == 1u && !have_first_pub_token) {
            uint8_t dig[32];
            char dighex[65];
            size_t ti;
            if (parent_publication_digest(&store, dig) != 0
                || digest_hex32(dig, dighex) != 0) {
                (void)fprintf(stderr, "%s: FAIL digest extract\n", log_tag);
                return 1;
            }
            /* Capture durable publication_token from first NM3R with pstate. */
            {
                size_t ri;
                uint8_t rec[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];
                uint32_t rlen = 0u;
                for (ri = 0u; ri < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++ri) {
                    if (!store.rows[ri].occupied || store.rows[ri].key_len < 4u) {
                        continue;
                    }
                    if (store.rows[ri].key[0] != (uint8_t)'N'
                        || store.rows[ri].key[1] != (uint8_t)'M'
                        || store.rows[ri].key[2] != (uint8_t)'3'
                        || store.rows[ri].key[3] != (uint8_t)'R') {
                        continue;
                    }
                    if (ninlil_mfdt_v1_lab_get(
                            &store, store.rows[ri].key, rec, sizeof(rec), &rlen)
                            == 0
                        && rlen >= 264u && rec[107] != 0u) {
                        (void)memcpy(first_pub_token, rec + 248, 16u);
                        have_first_pub_token = 1;
                        break;
                    }
                }
            }
            if (!have_first_pub_token) {
                (void)fprintf(stderr, "%s: FAIL no durable publication_token\n",
                    log_tag);
                return 1;
            }
            durable_pub_at_first = 1u;
            (void)printf(
                "%s: PUBLICATION_ONCE count=1 digest=%s durable_pub=1\n",
                log_tag,
                dighex);
            (void)fflush(stdout);
            (void)ti;
            continue;
        }
        if (durable_pub_count == 1u && have_first_pub_token) {
            /* Duplicate / re-ingress must leave durable publication invariant. */
            size_t ri;
            uint8_t rec[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];
            uint32_t rlen = 0u;
            int tok_match = 0;
            post_pub_frames += 1u;
            if (durable_pub_count != durable_pub_at_first) {
                (void)fprintf(stderr,
                    "%s: FAIL durable_pub changed after first publication "
                    "now=%u was=%u\n",
                    log_tag, durable_pub_count, durable_pub_at_first);
                return 1;
            }
            for (ri = 0u; ri < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++ri) {
                if (!store.rows[ri].occupied || store.rows[ri].key_len < 4u) {
                    continue;
                }
                if (store.rows[ri].key[0] != (uint8_t)'N'
                    || store.rows[ri].key[1] != (uint8_t)'M'
                    || store.rows[ri].key[2] != (uint8_t)'3'
                    || store.rows[ri].key[3] != (uint8_t)'R') {
                    continue;
                }
                if (ninlil_mfdt_v1_lab_get(
                        &store, store.rows[ri].key, rec, sizeof(rec), &rlen)
                        == 0
                    && rlen >= 264u && rec[107] != 0u) {
                    if (memcmp(first_pub_token, rec + 248, 16u) == 0) {
                        tok_match = 1;
                    } else {
                        (void)fprintf(stderr,
                            "%s: FAIL publication_token mutated after first pub\n",
                            log_tag);
                        return 1;
                    }
                }
            }
            if (!tok_match) {
                (void)fprintf(stderr,
                    "%s: FAIL durable publication_token missing after ingress\n",
                    log_tag);
                return 1;
            }
            continue;
        }
    }

    if (!shutdown_received) {
        (void)fprintf(stderr, "%s: FAIL missing explicit shutdown\n", log_tag);
        return 1;
    }
    if (ncl1_count == 0u && hop_count > 0u) {
        if (durable_nm3r_publication_count(&store) != 0u
            || have_first_pub_token) {
            (void)fprintf(stderr,
                "%s: FAIL hop-only shutdown durable_pub=%u have_token=%d\n",
                log_tag,
                durable_nm3r_publication_count(&store),
                have_first_pub_token);
            return 1;
        }
        (void)printf(
            "%s: DONE hop_only hops=%u durable_pub=0 explicit_shutdown=1\n",
            log_tag,
            hop_count);
        (void)fflush(stdout);
        ninlil_wifi_session_close(&session);
        ninlil_wifi_tcp_close(&listen_tcp);
        ninlil_wifi_tcp_close(&accepted_tcp);
        return 0;
    }
    if (durable_nm3r_publication_count(&store) != 1u || !have_first_pub_token) {
        (void)fprintf(stderr,
            "%s: FAIL final durable_pub=%u have_token=%d ncl1=%u\n",
            log_tag,
            durable_nm3r_publication_count(&store),
            have_first_pub_token,
            ncl1_count);
        ninlil_wifi_session_close(&session);
        ninlil_wifi_tcp_close(&listen_tcp);
        return 1;
    }
    (void)printf(
        "%s: DONE ncl1=%u hop=%u bytes_rx=%llu durable_pub=1 "
        "post_pub_frames=%u explicit_shutdown=1\n",
        log_tag,
        ncl1_count,
        hop_count,
        (unsigned long long)bytes_rx,
        post_pub_frames);
    (void)fflush(stdout);
    ninlil_wifi_session_close(&session);
    ninlil_wifi_tcp_close(&listen_tcp);
    ninlil_wifi_tcp_close(&accepted_tcp);
    return 0;
}

static int accept_endpoint_session(
    ninlil_wifi_session_t *sess_e,
    ninlil_wifi_tcp_t *listen_tcp,
    ninlil_wifi_tcp_t *accepted_tcp,
    const char *certs,
    const char *tag)
{
    ninlil_wifi_peer_context_inputs_t pin;
    uint32_t spins = 0u;
    int accepted_ok = 0;

    ninlil_wifi_session_close(sess_e);
    ninlil_wifi_session_init(sess_e);
    ninlil_wifi_session_set_mono_clock(sess_e, mono_ms, NULL);
    fill_peer_inputs(&pin);
    if (configure_tls_paths(sess_e, certs, 1) != 0
        || ninlil_wifi_session_set_peer_context_inputs(sess_e, &pin)
            != NINLIL_WIFI_OK
        || ninlil_wifi_session_set_fabric_descriptor(sess_e, k_fabric_desc)
            != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "relay: %s cfg fail\n", tag);
        return -1;
    }
    ninlil_wifi_tcp_init(accepted_tcp);
    while (spins < 30000u) {
        if (ninlil_wifi_tcp_accept(listen_tcp, accepted_tcp) == NINLIL_WIFI_OK) {
            accepted_ok = 1;
            break;
        }
        usleep(1000);
        spins += 1u;
    }
    if (!accepted_ok
        || ninlil_wifi_session_accept_fd(sess_e, accepted_tcp->fd)
            != NINLIL_WIFI_OK
        || wait_attached_budget(sess_e, 30000u) != 0) {
        (void)fprintf(stderr, "relay: %s accept/attach fail\n", tag);
        return -1;
    }
    accepted_tcp->fd = -1;
    return 0;
}

/* 0 ok, -1 hard fail, -2 endpoint session dead (caller should reaccept). */
static int bridge_reverse(
    ninlil_wifi_session_t *from_parent, ninlil_wifi_session_t *to_e, uint32_t budget_ms)
{
    uint32_t steps;
    uint32_t max_steps = budget_ms / 10u + 1u;
    if (to_e == NULL
        || to_e->phase == NINLIL_WIFI_PHASE_CLOSED
        || to_e->phase == NINLIL_WIFI_PHASE_FENCED) {
        return -2;
    }
    for (steps = 0u; steps < max_steps; ++steps) {
        uint8_t rn[HOST_COMPLETION_NCL1_MAX];
        size_t rlen = 0u;
        uint32_t rseq = 0u;
        int r2;
        (void)ninlil_wifi_session_poll(to_e);
        if (to_e->phase == NINLIL_WIFI_PHASE_CLOSED
            || to_e->phase == NINLIL_WIFI_PHASE_FENCED) {
            return -2;
        }
        r2 = host_completion_session_recv_ncl1(
            from_parent, rn, sizeof(rn), &rlen, &rseq, 20u);
        if (r2 == 1) {
            continue; /* hop frame noise */
        }
        if (r2 != 0 || rlen == 0u) {
            break;
        }
        if (host_completion_session_send_ncl1(to_e, rn, rlen) != 0) {
            (void)ninlil_wifi_session_poll(to_e);
            if (to_e->phase != NINLIL_WIFI_PHASE_ATTACHED) {
                return -2;
            }
            return -1;
        }
    }
    return 0;
}

static int role_relay(
    uint16_t listen_port,
    uint16_t port_p1,
    uint16_t port_p2,
    const char *certs,
    int switch_after,
    int cold_restart)
{
    ninlil_wifi_session_t sess_e;
    ninlil_wifi_session_t sess_p1;
    ninlil_wifi_session_t sess_p2;
    ninlil_wifi_tcp_t listen_tcp;
    ninlil_wifi_tcp_t accepted_tcp;
    ninlil_wifi_peer_context_inputs_t pin;
    ninlil_wifi_endpoint_t ep;
    host_completion_outbound_ctx_t ob_p1;
    host_completion_outbound_ctx_t ob_p2;
    host_completion_outbound_ctx_t *ob_active;
    ninlil_rrmp_owner_t *owner = NULL;
    ninlil_rrmp_outbound_provider_t provider;
    ninlil_rrmp_scope_derivation_ctx_t sctx;
    ninlil_test_storage_t *durable = NULL;
    ninlil_test_storage_config_t scfg;
    ninlil_storage_handle_t shandle = NULL;
    const ninlil_storage_ops_t *sops = NULL;
    uint8_t scope[16];
    uint8_t path_policy[16];
    uint8_t parent_a[16];
    uint8_t parent_b[16];
    uint8_t bootstrap_token[32];
    ninlil_rrmp_id16_t parent_ids[2];
    ninlil_rrmp_digest32_t parent_digest;
    uint8_t selected[16];
    uint32_t has_sel = 0u;
    int a_avail = 1;
    int b_avail = 1;
    uint32_t fwd = 0u;
    uint32_t hop_custody_count = 0u;
    uint32_t hop_token = 1u;
    size_t need;
    uint8_t seen_e2e[64][32];
    uint32_t seen_n = 0u;
    uint32_t idle_rounds = 0u;
    const char *wd = getenv("HOST_COMPLETION_WORKDIR");
    uint16_t bound_listen_port = 0u;
    int shutdown_propagated = 0;

    rrmp_fill_id(parent_a, 0x30u);
    rrmp_fill_id(parent_b, 0x40u);

    ninlil_wifi_session_init(&sess_e);
    ninlil_wifi_session_init(&sess_p1);
    ninlil_wifi_session_init(&sess_p2);
    ninlil_wifi_session_set_mono_clock(&sess_e, mono_ms, NULL);
    ninlil_wifi_session_set_mono_clock(&sess_p1, mono_ms, NULL);
    ninlil_wifi_session_set_mono_clock(&sess_p2, mono_ms, NULL);
    ninlil_wifi_tcp_init(&accepted_tcp);
    fill_peer_inputs(&pin);
    if (configure_tls_paths(&sess_e, certs, 1) != 0
        || configure_tls_paths(&sess_p1, certs, 0) != 0
        || configure_tls_paths(&sess_p2, certs, 0) != 0) {
        return 1;
    }
    (void)ninlil_wifi_session_set_peer_context_inputs(&sess_e, &pin);
    (void)ninlil_wifi_session_set_peer_context_inputs(&sess_p1, &pin);
    (void)ninlil_wifi_session_set_peer_context_inputs(&sess_p2, &pin);

    fill_endpoint(&ep, port_p1);
    if (ninlil_wifi_session_add_endpoint(&sess_p1, &ep) != NINLIL_WIFI_OK
        || connect_wait(&sess_p1, &ep) != 0) {
        (void)fprintf(stderr, "relay: P1 connect fail\n");
        return 1;
    }
    fill_endpoint(&ep, port_p2);
    if (ninlil_wifi_session_add_endpoint(&sess_p2, &ep) != NINLIL_WIFI_OK
        || connect_wait(&sess_p2, &ep) != 0) {
        (void)fprintf(stderr, "relay: P2 connect fail\n");
        return 1;
    }
    (void)printf("relay: parents ATTACHED\n");
    (void)fflush(stdout);

    host_completion_outbound_init(&ob_p1, &sess_p1);
    host_completion_outbound_init(&ob_p2, &sess_p2);
    ob_active = &ob_p1;

    (void)memset(&scfg, 0, sizeof(scfg));
    scfg.max_namespaces = 4u;
    scfg.max_entries_per_namespace = 256u;
    scfg.max_bytes_per_namespace = 512u * 1024u;
    durable = ninlil_test_storage_create(&scfg);
    if (durable == NULL) {
        return 1;
    }
    sops = ninlil_test_storage_ops(durable);
    if (sops->open(sops->user,
            (ninlil_bytes_view_t){ (const uint8_t *)"rrmp", 4u }, 1u, &shandle)
        != NINLIL_STORAGE_OK) {
        (void)fprintf(stderr, "relay: durable open fail\n");
        return 1;
    }

    need = ninlil_rrmp_owner_workspace_bytes();
    if (need == 0u || need > RRMP_WS_MAX) {
        return 1;
    }
    {
        ninlil_rrmp_owner_config_v1_t cfg;
        ninlil_rrmp_memzero(&cfg, sizeof(cfg));
        cfg.preamble.api_version = 1u;
        cfg.preamble.struct_size = (uint32_t)sizeof(cfg);
        rrmp_fill_id(cfg.local_runtime_id, 0x10u);
        rrmp_fill_id(cfg.authority_id, 0xA0u);
        cfg.controller_term = 5u;
        rrmp_fill_id(cfg.authority_clock_epoch_id, 0x50u);
        cfg.feature_route_relay = 1u;
        cfg.feature_multi_parent = 1u;
        cfg.max_hops_profile = 3u;
        cfg.now_ms = 1000000u;
        owner = ninlil_rrmp_owner_init(g_rrmp_ws, need, &cfg);
    }
    if (owner == NULL) {
        return 1;
    }
    ninlil_rrmp_owner_bind(owner);
    rrmp_scope_ctx_default(&sctx);
    ninlil_rrmp_owner_set_scope_derivation(owner, &sctx);
    if (!ninlil_rrmp_owner_bind_storage(owner, sops, shandle)) {
        (void)fprintf(stderr, "relay: bind_storage fail\n");
        return 1;
    }
    ninlil_rrmp_memzero(&provider, sizeof(provider));
    provider.user = ob_active;
    provider.submit = host_completion_rrmp_outbound_submit;
    ninlil_rrmp_owner_set_outbound_provider(owner, &provider);

    if (rrmp_install_route(owner, 1u) != 0
        || rrmp_install_two_parents(owner, scope, path_policy) != 0) {
        (void)fprintf(stderr, "relay: rrmp install fail\n");
        return 1;
    }
    rrmp_fill_id(parent_ids[0].bytes, 0x30u);
    rrmp_fill_id(parent_ids[1].bytes, 0x40u);
    (void)memset(bootstrap_token, 0x5bu, sizeof(bootstrap_token));
    if (!ninlil_rrmp_parent_set_digest(parent_ids, 2u, &parent_digest)
        || !rrmp_bootstrap_assignment_durable(
            sops,
            shandle,
            scope,
            path_policy,
            parent_digest.bytes,
            2u,
            bootstrap_token)) {
        (void)fprintf(stderr, "relay: rrmp authority bootstrap fail\n");
        return 1;
    }

    if (host_completion_fabric_select_parent(
            parent_a, parent_b, a_avail, b_avail, mono_ms(NULL), selected, &has_sel)
        != 0 || has_sel == 0u) {
        (void)fprintf(stderr, "relay: fabric select fail\n");
        return 1;
    }
    ninlil_fabric_rrmp_on_path_selected(
        owner, selected, has_sel, 1u, 1u, mono_ms(NULL));
    (void)printf("relay: fabric_selected P1 first has=%u\n", has_sel);
    (void)fflush(stdout);

    /* --- Pre-E: hop on P1, P1 loss→P2 exact B, hop on P2, cold recover --- */
    {
        uint8_t e2e[32];
        size_t i;
        for (i = 0u; i < 32u; ++i) {
            e2e[i] = (uint8_t)(0xA0u + i);
        }
        if (rrmp_hop_with_outbound(owner, e2e, hop_token++, NULL, 0u, NULL) != 0) {
            (void)fprintf(stderr, "relay: hop P1 fail\n");
            return 1;
        }
        hop_custody_count += 1u;
        (void)printf(
            "relay: hop_ok sub=%u bytes=%llu hop_custody_count=%u\n",
            ob_p1.submit_count,
            (unsigned long long)ob_p1.bytes_submitted,
            hop_custody_count);
        (void)fflush(stdout);
    }

    if (switch_after > 0) {
        uint8_t att1[16], att2[16], sel2[16];
        ninlil_parent_result_v1_t pout;
        uint32_t has2 = 0u;
        size_t i;
        /*
         * Multiparent failover is attempt-ordinal based (not parent_loss first).
         * parent_loss seals the scope; further selects become SPLIT_BRAIN.
         * Attempt1 → A, attempt2 → B (exact expected parent B).
         */
        ninlil_rrmp_memzero(att1, 16u);
        ninlil_rrmp_put_u16_be(att1 + 14, 1u);
        ninlil_rrmp_memzero(att2, 16u);
        ninlil_rrmp_put_u16_be(att2 + 14, 2u);
        if (ninlil_rrmp_core_parent_select_for_attempt(
                owner, scope, att1, selected, &pout)
            != NINLIL_PARENT_OK) {
            (void)fprintf(stderr, "relay: select attempt1 fail st=%u\n",
                (unsigned)pout.status);
            return 1;
        }
        for (i = 0u; i < 16u; ++i) {
            if (selected[i] != parent_a[i]) {
                (void)fprintf(stderr, "relay: attempt1 not parent A\n");
                return 1;
            }
        }
        if (ninlil_rrmp_core_parent_select_for_attempt(
                owner, scope, att2, selected, &pout)
            != NINLIL_PARENT_OK) {
            (void)fprintf(stderr, "relay: select attempt2 fail st=%u\n",
                (unsigned)pout.status);
            return 1;
        }
        for (i = 0u; i < 16u; ++i) {
            if (selected[i] != parent_b[i]) {
                (void)fprintf(stderr, "relay: parent_select not B\n");
                return 1;
            }
        }
        a_avail = 0;
        if (host_completion_fabric_select_parent(
                parent_a, parent_b, a_avail, b_avail, mono_ms(NULL), sel2, &has2)
            != 0 || has2 == 0u) {
            (void)fprintf(stderr, "relay: fabric reselect fail\n");
            return 1;
        }
        for (i = 0u; i < 16u; ++i) {
            if (sel2[i] != parent_b[i]) {
                (void)fprintf(stderr, "relay: fabric selected not parent B\n");
                return 1;
            }
        }
        ninlil_fabric_rrmp_on_path_selected(
            owner, sel2, has2, 1u, 2u, mono_ms(NULL));
        ob_active = &ob_p2;
        provider.user = ob_active;
        ninlil_rrmp_owner_set_outbound_provider(owner, &provider);
        (void)printf(
            "relay: SWITCH_TO_P2 exact_parent_b="
            "404142434445464748494a4b4c4d4e4f\n");
        (void)fflush(stdout);

        {
            uint8_t e2e2[32];
            for (i = 0u; i < 32u; ++i) {
                e2e2[i] = (uint8_t)(0xB0u + i);
            }
            if (rrmp_hop_with_outbound(owner, e2e2, hop_token++, NULL, 0u, NULL) != 0) {
                (void)fprintf(stderr, "relay: hop P2 fail\n");
                return 1;
            }
            hop_custody_count += 1u;
            (void)printf(
                "relay: hop_ok sub=%u bytes=%llu hop_custody_count=%u\n",
                ob_p2.submit_count,
                (unsigned long long)ob_p2.bytes_submitted,
                hop_custody_count);
            (void)fflush(stdout);
        }
        /*
         * Do not parent_loss here: loss seals the scope and fences further hop
         * admit (DRAIN_FENCED). P1→P2 is proven by attempt2 exact B + fabric
         * reselect + hop on P2 + MFDT completion on P2.
         */
    }

    if (cold_restart) {
        uint8_t export_buf[256 * 1024];
        uint8_t file_buf[256 * 1024];
        size_t elen = 0u;
        size_t flen = 0u;
        char path[512];
        ninlil_rrmp_owner_config_v1_t cfg;
        ninlil_route_query_req_v1_t rq;
        ninlil_route_result_v1_t rout;
        ninlil_parent_result_v1_t pout;
        uint8_t att1[16];
        uint8_t selx[16];
        uint8_t e2e_live[32];
        size_t i;
        ninlil_test_storage_t *durable_fresh = NULL;
        ninlil_storage_handle_t shandle_fresh = NULL;
        const ninlil_storage_ops_t *sops_fresh = NULL;
        FILE *df;

        if (!ninlil_rrmp_owner_storage_commit_full(owner)) {
            (void)fprintf(stderr, "relay: storage_commit_full fail\n");
            return 1;
        }
        if (rrmp_storage_export_physical(
                sops, shandle, export_buf, sizeof(export_buf), &elen)
                != 0
            || elen == 0u) {
            (void)fprintf(stderr, "relay: physical storage export fail\n");
            return 1;
        }
        (void)snprintf(
            path,
            sizeof(path),
            "%s/rrmp_durable.bin",
            (wd != NULL && wd[0] != '\0') ? wd : "/tmp");
        df = fopen(path, "wb");
        if (df == NULL || fwrite(export_buf, 1u, elen, df) != elen
            || fclose(df) != 0) {
            (void)fprintf(stderr, "relay: durable file write fail\n");
            return 1;
        }

        /* Tear down owner + original storage completely (no shandle reuse). */
        ninlil_rrmp_owner_fini(owner);
        owner = NULL;
        if (shandle != NULL && sops != NULL && sops->close != NULL) {
            sops->close(sops->user, shandle);
        }
        shandle = NULL;
        sops = NULL;
        ninlil_test_storage_destroy(durable);
        durable = NULL;
        (void)memset(g_rrmp_ws, 0, sizeof(g_rrmp_ws));
        (void)memset(g_rrmp_ws2, 0, sizeof(g_rrmp_ws2));

        /* Read file bytes only — sole recovery authority. */
        df = fopen(path, "rb");
        if (df == NULL) {
            (void)fprintf(stderr, "relay: durable file reopen fail\n");
            return 1;
        }
        flen = fread(file_buf, 1u, sizeof(file_buf), df);
        (void)fclose(df);
        if (flen == 0u || flen != elen
            || memcmp(file_buf, export_buf, elen) != 0) {
            (void)fprintf(stderr,
                "relay: durable file bytes mismatch elen=%u flen=%u\n",
                (unsigned)elen, (unsigned)flen);
            return 1;
        }

        /* Fresh storage instance ← file bytes. */
        durable_fresh = ninlil_test_storage_create(&scfg);
        if (durable_fresh == NULL) {
            return 1;
        }
        sops_fresh = ninlil_test_storage_ops(durable_fresh);
        if (sops_fresh->open(
                sops_fresh->user,
                (ninlil_bytes_view_t){ (const uint8_t *)"rrmp", 4u },
                1u,
                &shandle_fresh)
            != NINLIL_STORAGE_OK) {
            (void)fprintf(stderr, "relay: fresh storage open fail\n");
            ninlil_test_storage_destroy(durable_fresh);
            return 1;
        }
        if (rrmp_storage_import_physical(
                sops_fresh, shandle_fresh, file_buf, flen)
            != 0) {
            (void)fprintf(stderr, "relay: fresh physical storage import fail\n");
            ninlil_test_storage_destroy(durable_fresh);
            return 1;
        }

        ninlil_rrmp_memzero(&cfg, sizeof(cfg));
        cfg.preamble.api_version = 1u;
        cfg.preamble.struct_size = (uint32_t)sizeof(cfg);
        rrmp_fill_id(cfg.local_runtime_id, 0x10u);
        rrmp_fill_id(cfg.authority_id, 0xA0u);
        cfg.controller_term = 5u;
        rrmp_fill_id(cfg.authority_clock_epoch_id, 0x50u);
        cfg.feature_route_relay = 1u;
        cfg.feature_multi_parent = 1u;
        cfg.max_hops_profile = 3u;
        cfg.now_ms = 1000000u;
        owner = ninlil_rrmp_owner_init(g_rrmp_ws2, need, &cfg);
        if (owner == NULL) {
            (void)fprintf(stderr, "relay: fresh owner init fail\n");
            ninlil_test_storage_destroy(durable_fresh);
            return 1;
        }
        ninlil_rrmp_owner_bind(owner);
        rrmp_scope_ctx_default(&sctx);
        ninlil_rrmp_owner_set_scope_derivation(owner, &sctx);
        if (!ninlil_rrmp_owner_bind_storage(owner, sops_fresh, shandle_fresh)
            || !ninlil_rrmp_owner_storage_recover(owner)) {
            (void)fprintf(stderr,
                "relay: fresh storage_recover from file bytes fail\n");
            ninlil_rrmp_owner_fini(owner);
            owner = NULL;
            ninlil_test_storage_destroy(durable_fresh);
            return 1;
        }
        /* Adopt fresh storage as the live durable for remaining relay life. */
        durable = durable_fresh;
        sops = sops_fresh;
        shandle = shandle_fresh;
        provider.user = ob_active;
        provider.submit = host_completion_rrmp_outbound_submit;
        ninlil_rrmp_owner_set_outbound_provider(owner, &provider);

        ninlil_rrmp_memzero(&rq, sizeof(rq));
        rq.preamble.api_version = 1u;
        rq.preamble.struct_size = 48u;
        rq.ingress_hop_context_id = 0x1001u;
        rq.route_handle = 1u;
        rq.route_generation = 1u;
        if (ninlil_route_query(&rq, &rout) != NINLIL_ROUTE_OK
            || rout.lifecycle_state != NINLIL_RRMP_LIFE_ACTIVE) {
            (void)fprintf(stderr, "relay: LIVE route missing after recover\n");
            return 1;
        }
        /* Last pre-crash select was attempt2 → fence continues on att2 only. */
        ninlil_rrmp_memzero(att1, 16u);
        ninlil_rrmp_put_u16_be(att1 + 14, 2u);
        if (ninlil_rrmp_core_parent_select_for_attempt(
                owner, scope, att1, selx, &pout)
            != NINLIL_PARENT_SAME_ATTEMPT_RESELECT) {
            (void)fprintf(stderr,
                "relay: LIVE attempt fence missing after recover st=%u\n",
                (unsigned)pout.status);
            return 1;
        }
        for (i = 0u; i < 32u; ++i) {
            e2e_live[i] = (uint8_t)(0xC0u + i);
        }
        if (rrmp_hop_with_outbound(
                owner, e2e_live, hop_token++, NULL, 0u, NULL)
            != 0) {
            (void)fprintf(stderr, "relay: hop after cold recover fail\n");
            return 1;
        }
        hop_custody_count += 1u;
        (void)printf(
            "relay: COLD_RECOVER durable_bytes=%u live_route=1 live_attempt=1 "
            "fresh_storage=1 file_import=1 hop_custody_count=%u\n",
            (unsigned)flen,
            hop_custody_count);
        (void)fflush(stdout);
    }

    ninlil_wifi_tcp_init(&listen_tcp);
    if (ninlil_wifi_tcp_listen_loopback(
            &listen_tcp, listen_port, &bound_listen_port)
        != NINLIL_WIFI_OK) {
        return 1;
    }
    if (bound_listen_port == 0u) {
        (void)fprintf(stderr, "relay: listener returned zero port\n");
        return 1;
    }
    (void)printf(
        "relay: listening for E port=%u\n", (unsigned)bound_listen_port);
    (void)fflush(stdout);

    if (accept_endpoint_session(
            &sess_e, &listen_tcp, &accepted_tcp, certs, "E first")
        != 0) {
        return 1;
    }
    (void)printf("relay: E ATTACHED\n");
    (void)fflush(stdout);

    /* Bidirectional MFDT bridge on active parent (P2 after switch). */
    for (;;) {
        uint8_t ncl1[HOST_COMPLETION_NCL1_MAX];
        size_t nlen = 0u;
        uint32_t seq = 0u;
        uint8_t e2e[32];
        ninlil_wifi_status_t pst;
        int rr;
        int is_dup = 0;
        uint32_t si;
        int need_reaccept = 0;

        /* Always poll E; also non-block accept probe while dead. */
        pst = ninlil_wifi_session_poll(&sess_e);
        if (sess_e.phase == NINLIL_WIFI_PHASE_CLOSED
            || sess_e.phase == NINLIL_WIFI_PHASE_FENCED
            || sess_e.phase == NINLIL_WIFI_PHASE_RECONNECT_WAIT
            || (pst != NINLIL_WIFI_OK && pst != NINLIL_WIFI_WOULD_BLOCK
                && pst != NINLIL_WIFI_BACKPRESSURE
                && pst != NINLIL_WIFI_INVALID_STATE)) {
            need_reaccept = 1;
        }
        if (need_reaccept) {
            (void)printf("relay: E_SESSION_DEAD phase=%u — reaccept\n",
                (unsigned)sess_e.phase);
            (void)fflush(stdout);
            if (accept_endpoint_session(
                    &sess_e, &listen_tcp, &accepted_tcp, certs, "E reaccept")
                != 0) {
                return 1;
            }
            (void)printf("relay: E REATTACHED\n");
            (void)fflush(stdout);
        }

        /* Reverse bridge first so sender can leave WAIT_* phases. */
        {
            int br = bridge_reverse(ob_active->session, &sess_e, 80u);
            if (br == -2) {
                continue; /* top-of-loop reaccept */
            }
            if (br != 0) {
                (void)fprintf(stderr, "relay: reverse bridge fail\n");
                return 1;
            }
        }

        rr = host_completion_session_recv_ncl1(
            &sess_e, ncl1, sizeof(ncl1), &nlen, &seq, 100u);
        if (rr == -2) {
            idle_rounds += 1u;
            if (fwd >= 6u && idle_rounds >= 80u) {
                break;
            }
            continue;
        }
        if (rr != 0) {
            /* Endpoint may have closed mid-transfer — reaccept on next loop. */
            (void)ninlil_wifi_session_poll(&sess_e);
            continue;
        }
        idle_rounds = 0u;
        if (host_completion_is_shutdown(ncl1, nlen)) {
            if (fwd < 6u
                || host_completion_session_send_ncl1(
                       &sess_e,
                       k_host_completion_shutdown_ack,
                       sizeof(k_host_completion_shutdown_ack))
                    != 0
                || host_completion_session_send_ncl1(
                       &sess_p1,
                       k_host_completion_shutdown,
                       sizeof(k_host_completion_shutdown))
                    != 0
                || host_completion_session_send_ncl1(
                       &sess_p2,
                       k_host_completion_shutdown,
                       sizeof(k_host_completion_shutdown))
                    != 0
                || host_completion_session_drain(&sess_e, 5000u) != 0
                || host_completion_session_drain(&sess_p1, 5000u) != 0
                || host_completion_session_drain(&sess_p2, 5000u) != 0) {
                (void)fprintf(stderr,
                    "relay: explicit shutdown propagation failed fwd=%u\n",
                    fwd);
                return 1;
            }
            shutdown_propagated = 1;
            (void)printf(
                "relay: SHUTDOWN_PROPAGATED endpoint_ack=1 p1=1 p2=1 fwd=%u\n",
                fwd);
            (void)fflush(stdout);
            break;
        }
        ninlil_mfdt_v1_sha256(ncl1, nlen, e2e);
        for (si = 0u; si < seen_n; ++si) {
            if (memcmp(seen_e2e[si], e2e, 32u) == 0) {
                is_dup = 1;
                break;
            }
        }
        if (!is_dup) {
            uint32_t sub_before = ob_active->submit_count;
            if (seen_n < 64u) {
                (void)memcpy(seen_e2e[seen_n], e2e, 32u);
                seen_n += 1u;
            }
            /*
             * Real NCL1 carrier through RRMP hop → outbound provider → WiFi.
             * Prohibits separate host_completion_session_send_ncl1 forward.
             */
            if (nlen == 0u || nlen > NINLIL_RRMP_OUTBOUND_CARRIER_MAX
                || rrmp_hop_with_outbound(
                       owner, e2e, hop_token++, ncl1, (uint16_t)nlen, NULL)
                    != 0) {
                (void)fprintf(stderr,
                    "relay: hop+carrier fail at fwd=%u nlen=%u\n", fwd,
                    (unsigned)nlen);
                return 1;
            }
            if (ob_active->submit_count != sub_before + 1u
                || !ob_active->has_last
                || ob_active->last_pkt.carrier_len != (uint16_t)nlen
                || memcmp(ob_active->last_pkt.carrier, ncl1, nlen) != 0) {
                (void)fprintf(stderr,
                    "relay: outbound carrier bytes not on production seam\n");
                return 1;
            }
            hop_custody_count += 1u;
            (void)printf(
                "relay: hop_ok carrier_len=%u sub=%u bytes=%llu "
                "hop_custody_count=%u\n",
                (unsigned)nlen,
                ob_active->submit_count,
                (unsigned long long)ob_active->bytes_submitted,
                hop_custody_count);
            (void)fflush(stdout);
        } else {
            (void)printf(
                "relay: DUPLICATE_NO_NEW_CUSTODY hop_custody_count=%u\n",
                hop_custody_count);
            (void)fflush(stdout);
        }
        {
            int br = bridge_reverse(ob_active->session, &sess_e, 300u);
            if (br == -2) {
                /* Parent reply held until E reattaches; continue reaccept. */
                continue;
            }
            if (br != 0) {
                (void)fprintf(stderr, "relay: reverse after forward fail\n");
                return 1;
            }
        }
        fwd += 1u;
        (void)printf(
            "relay: fwd=%u ncl1_len=%u bytes_p1=%llu bytes_p2=%llu "
            "p1_sub=%u p2_sub=%u hop_custody_count=%u\n",
            fwd,
            (unsigned)nlen,
            (unsigned long long)ob_p1.bytes_submitted,
            (unsigned long long)ob_p2.bytes_submitted,
            ob_p1.submit_count,
            ob_p2.submit_count,
            hop_custody_count);
        (void)fflush(stdout);
    }

    (void)printf(
        "relay: DONE fwd=%u p1_bytes=%llu p2_bytes=%llu p1_sub=%u p2_sub=%u "
        "hop_custody_count=%u\n",
        fwd,
        (unsigned long long)ob_p1.bytes_submitted,
        (unsigned long long)ob_p2.bytes_submitted,
        ob_p1.submit_count,
        ob_p2.submit_count,
        hop_custody_count);
    (void)fflush(stdout);
    if (owner != NULL) {
        ninlil_rrmp_owner_fini(owner);
    }
    ninlil_wifi_session_close(&sess_e);
    ninlil_wifi_session_close(&sess_p1);
    ninlil_wifi_session_close(&sess_p2);
    ninlil_wifi_tcp_close(&listen_tcp);
    ninlil_wifi_tcp_close(&accepted_tcp);
    if (durable != NULL) {
        ninlil_test_storage_destroy(durable);
    }
    if (!shutdown_propagated) {
        (void)fprintf(stderr, "relay: missing explicit shutdown\n");
        return 1;
    }
    if (fwd == 0u) {
        return 1;
    }
    if (switch_after > 0
        && (ob_p2.submit_count == 0u || ob_p2.bytes_submitted == 0u)) {
        (void)fprintf(stderr, "relay: P2 never received after switch\n");
        return 1;
    }
    return 0;
}

static int role_endpoint(
    uint16_t relay_port,
    const char *certs,
    int disconnect_after,
    int send_duplicate,
    int cold_restart)
{
    ninlil_wifi_session_t session;
    ninlil_wifi_peer_context_inputs_t pin;
    ninlil_wifi_endpoint_t ep;
    ninlil_mfdt_v1_engine_t eng;
    ninlil_mfdt_v1_workspace_t ws;
    ninlil_mfdt_v1_lab_store_t store;
    ninlil_mfdt_v1_pipeline_t pipe;
    ninlil_mfdt_v1_engine_t eng_cold;
    ninlil_mfdt_v1_workspace_t ws_cold;
    ninlil_mfdt_v1_lab_store_t store_cold;
    ninlil_mfdt_v1_pipeline_t pipe_cold;
    ninlil_mfdt_v1_engine_t *eng_live = &eng;
    ninlil_mfdt_v1_workspace_t *ws_live = &ws;
    ninlil_mfdt_v1_lab_store_t *store_live = &store;
    ninlil_mfdt_v1_pipeline_t *pipe_live = &pipe;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t content[CONTENT_BYTES];
    uint8_t tid[16];
    uint8_t digest_expect[32];
    uint32_t i;
    uint32_t sent = 0u;
    int did_disconnect = 0;
    int did_duplicate = 0;
    int did_cold = 0;
    int reconnected = 0;
    int sender_begin_rc;
    const char *wd = getenv("HOST_COMPLETION_WORKDIR");
    char store_path[512];

    for (i = 0u; i < CONTENT_BYTES; ++i) {
        content[i] = (uint8_t)(0x40u + (i % 200u));
    }
    (void)memset(tid, 0x5a, sizeof(tid));
    ninlil_mfdt_v1_sha256(content, CONTENT_BYTES, digest_expect);
    (void)snprintf(
        store_path,
        sizeof(store_path),
        "%s/mfdt_sender_durable.bin",
        (wd != NULL && wd[0] != '\0') ? wd : "/tmp");

    ninlil_wifi_session_init(&session);
    ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
    fill_peer_inputs(&pin);
    if (configure_tls_paths(&session, certs, 0) != 0) {
        return 1;
    }
    (void)ninlil_wifi_session_set_peer_context_inputs(&session, &pin);
    fill_endpoint(&ep, relay_port);
    if (ninlil_wifi_session_add_endpoint(&session, &ep) != NINLIL_WIFI_OK
        || connect_wait(&session, &ep) != 0) {
        (void)fprintf(stderr, "endpoint: connect/attach fail\n");
        return 1;
    }
    (void)printf("endpoint: ATTACHED to relay\n");
    (void)fflush(stdout);

    /*
     * Real reconnect before MFDT transfer body: multi-accept on relay is
     * required. Mid-body disconnect races reverse bridge; prove RECONNECTED
     * on a fresh attached session, then complete MFDT with duplicate+cold.
     * Brief dwell so relay leaves accept/attach and enters reaccept loop.
     */
    if (disconnect_after > 0 && !did_disconnect) {
        usleep(300000);
        ninlil_wifi_session_close(&session);
        (void)printf("endpoint: DISCONNECT mid-transfer\n");
        (void)fflush(stdout);
        usleep(200000);
        {
            int tries;
            int ok = 0;
            for (tries = 0; tries < 150; ++tries) {
                ninlil_wifi_session_init(&session);
                ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
                fill_peer_inputs(&pin);
                if (configure_tls_paths(&session, certs, 0) != 0
                    || ninlil_wifi_session_set_peer_context_inputs(
                           &session, &pin)
                        != NINLIL_WIFI_OK) {
                    (void)fprintf(stderr, "endpoint: reconnect tls cfg fail\n");
                    return 1;
                }
                fill_endpoint(&ep, relay_port);
                if (ninlil_wifi_session_add_endpoint(&session, &ep)
                        == NINLIL_WIFI_OK
                    && connect_wait_budget(&session, &ep, 8000u) == 0) {
                    ok = 1;
                    break;
                }
                ninlil_wifi_session_close(&session);
                usleep(50000);
            }
            if (!ok) {
                (void)fprintf(stderr, "endpoint: RECONNECT_FAILED\n");
                return 1;
            }
        }
        did_disconnect = 1;
        reconnected = 1;
        (void)printf("endpoint: RECONNECTED\n");
        (void)fflush(stdout);
    }

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.now_ms = mono_ms(NULL);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    (void)memset(cfg.local_clock_epoch.bytes, 0xe2, 16u);
    ninlil_mfdt_v1_lab_store_init(&store);
    if (ninlil_mfdt_v1_engine_init(eng_live, ws_live, store_live, &cfg)
        != NINLIL_MFDT_V1_OK) {
        return 1;
    }
    ninlil_mfdt_v1_pipeline_init(
        pipe_live, eng_live, NULL, NULL, NULL, 1u, SESSION_COOKIE);
    sender_begin_rc = ninlil_mfdt_v1_pipeline_sender_begin(
        pipe_live, tid, content, CONTENT_BYTES);
    if (sender_begin_rc != NINLIL_MFDT_V1_OK) {
        (void)fprintf(
            stderr,
            "endpoint: sender_begin fail rc=%d fulls=%u txn=%u active=%u "
            "phase=%u outbox=%u\n",
            sender_begin_rc,
            (unsigned)store_live->full_count,
            (unsigned)store_live->txn_open,
            (unsigned)eng_live->active_count,
            (unsigned)pipe_live->phase,
            (unsigned)pipe_live->outbox_valid);
        return 1;
    }

    while (!pipe_live->complete && sent < 256u) {
        uint8_t frame[HOST_COMPLETION_NCL1_MAX];
        size_t flen = 0u;
        uint8_t last_frame[HOST_COMPLETION_NCL1_MAX];
        size_t last_flen = 0u;

        (void)ninlil_mfdt_v1_pipeline_sender_pump(pipe_live);
        if (ninlil_mfdt_v1_pipeline_outbox_pending(pipe_live)) {
            if (ninlil_mfdt_v1_pipeline_take_outbound(
                    pipe_live, frame, sizeof(frame), &flen)
                    != 0
                || flen == 0u) {
                /* keep receiving */
            } else {
                if (host_completion_session_send_ncl1(&session, frame, flen)
                    != 0) {
                    (void)fprintf(stderr, "endpoint: send ncl1 fail\n");
                    return 1;
                }
                sent += 1u;
                (void)memcpy(last_frame, frame, flen);
                last_flen = flen;
                (void)printf(
                    "endpoint: sent_frame=%u len=%u\n", sent, (unsigned)flen);
                (void)fflush(stdout);

                if (send_duplicate && !did_duplicate && sent == 2u) {
                    if (host_completion_session_send_ncl1(
                            &session, last_frame, last_flen)
                        != 0) {
                        return 1;
                    }
                    did_duplicate = 1;
                    (void)printf(
                        "endpoint: DUPLICATE_RETRANSMIT len=%u\n",
                        (unsigned)last_flen);
                    (void)fflush(stdout);
                }

                if (cold_restart && !did_cold && sent == 4u) {
                    size_t dbytes = 0u;
                    ninlil_mfdt_v1_active_snapshot_t snap;
                    ninlil_mfdt_v1_config_t cfg_cold;
                    /*
                     * Cold-process restart (fail-closed):
                     *  1) export durable lab rows to file only
                     *  2) zero old eng/pipe/ws/store (no field salvage)
                     *  3) import file into a NEW store object
                     *  4) new engine_init + restart_scan_transfer(tid, sender)
                     *  5) pipeline_sender_rehydrate from engine snapshot only
                     * Zero copy of phase/next_page/next_chunk/geo/request_id
                     * from the pre-crash pipeline image.
                    */
                    if (host_completion_mfdt_store_export_path(
                            store_live, store_path, &dbytes)
                        != 0 || dbytes == 0u) {
                        (void)fprintf(stderr, "endpoint: mfdt export fail\n");
                        return 1;
                    }
                    /* Obliterate pre-crash process image. */
                    (void)memset(eng_live, 0, sizeof(*eng_live));
                    (void)memset(pipe_live, 0, sizeof(*pipe_live));
                    (void)memset(ws_live, 0, sizeof(*ws_live));
                    (void)memset(store_live, 0, sizeof(*store_live));
                    (void)memset(&store_cold, 0, sizeof(store_cold));
                    (void)memset(&eng_cold, 0, sizeof(eng_cold));
                    (void)memset(&ws_cold, 0, sizeof(ws_cold));
                    (void)memset(&pipe_cold, 0, sizeof(pipe_cold));
                    ninlil_mfdt_v1_lab_store_init(&store_cold);
                    if (host_completion_mfdt_store_import_path(
                            &store_cold, store_path, &dbytes)
                        != 0) {
                        (void)fprintf(stderr, "endpoint: mfdt import fail\n");
                        return 1;
                    }
                    (void)memset(&cfg_cold, 0, sizeof(cfg_cold));
                    cfg_cold.policy = NINLIL_MFDT_V1_POLICY_ON;
                    cfg_cold.mfdt_admission_version =
                        NINLIL_MFDT_V1_ADMISSION_VERSION;
                    cfg_cold.session_generation = 1;
                    cfg_cold.mfdt_capability = 2;
                    cfg_cold.host_mode = 1;
                    cfg_cold.now_ms = mono_ms(NULL);
                    cfg_cold.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
                    (void)memset(
                        cfg_cold.local_clock_epoch.bytes, 0xe2, 16u);
                    if (ninlil_mfdt_v1_engine_init(
                            &eng_cold, &ws_cold, &store_cold, &cfg_cold)
                        != NINLIL_MFDT_V1_OK) {
                        return 1;
                    }
                    {
                        const int restart_rc =
                            ninlil_mfdt_v1_restart_scan_transfer(
                                &eng_cold, tid, 1u);
                        if (restart_rc != NINLIL_MFDT_V1_OK) {
                            (void)fprintf(
                                stderr,
                                "endpoint: restart_scan_transfer fail rc=%d\n",
                                restart_rc);
                            return 1;
                        }
                    }
                    if (ninlil_mfdt_v1_pipeline_sender_rehydrate(
                            &pipe_cold, &eng_cold, tid, 1u, SESSION_COOKIE)
                        != NINLIL_MFDT_V1_OK) {
                        (void)fprintf(stderr,
                            "endpoint: pipeline rehydrate fail\n");
                        return 1;
                    }
                    if (ninlil_mfdt_v1_engine_active_snapshot(&eng_cold, &snap)
                        != NINLIL_MFDT_V1_OK
                        || snap.role != 1u
                        || memcmp(snap.transfer_id, tid, 16u) != 0) {
                        (void)fprintf(stderr,
                            "endpoint: durable snapshot missing after recover\n");
                        return 1;
                    }
                    /* Rehydrate must not leave pipeline IDLE with empty geo. */
                    if (pipe_cold.phase == NINLIL_MFDT_V1_PHASE_IDLE
                        || pipe_cold.geo.chunk_count == 0u) {
                        (void)fprintf(stderr,
                            "endpoint: rehydrate left empty/idle pipeline\n");
                        return 1;
                    }
                    /*
                     * Install the independently reconstructed process image.
                     * These objects live for the whole role_endpoint call:
                     * never shallow-copy the lab store because its row values
                     * are self-relative pointers into store_cold.value_pool.
                     */
                    eng_live = &eng_cold;
                    ws_live = &ws_cold;
                    store_live = &store_cold;
                    pipe_live = &pipe_cold;
                    did_cold = 1;
                    (void)printf(
                        "endpoint: COLD_RECOVER durable_bytes=%u phase=%u "
                        "next_page=%u next_chunk=%u via_restart_scan_only=1\n",
                        (unsigned)dbytes,
                        (unsigned)pipe_live->phase,
                        (unsigned)pipe_live->next_page,
                        (unsigned)pipe_live->next_chunk);
                    (void)fflush(stdout);
                }
            }
        }

        {
            uint8_t rn[HOST_COMPLETION_NCL1_MAX];
            size_t rlen = 0u;
            uint32_t rseq = 0u;
            int r2 = host_completion_session_recv_ncl1(
                &session, rn, sizeof(rn), &rlen, &rseq, 100u);
            if (r2 == 0 && rlen > 0u) {
                (void)ninlil_mfdt_v1_pipeline_on_ncl1_ingress(
                    pipe_live, rn, rlen);
            }
        }
        usleep(500);
    }

    (void)printf(
        "endpoint: DONE sent=%u complete=%u reconnected=%d\n",
        sent,
        (unsigned)pipe_live->complete,
        reconnected);
    (void)fflush(stdout);

    if (disconnect_after > 0 && !reconnected) {
        (void)fprintf(stderr, "endpoint: FAIL missing real RECONNECTED\n");
        ninlil_wifi_session_close(&session);
        return 1;
    }
    if (sent < 4u || !pipe_live->complete) {
        (void)fprintf(stderr,
            "endpoint: FAIL sent=%u complete=%u (need multi-frame complete=1)\n",
            sent, (unsigned)pipe_live->complete);
        ninlil_wifi_session_close(&session);
        return 1;
    }
    {
        char dighex[65];
        if (digest_hex32(digest_expect, dighex) != 0) {
            ninlil_wifi_session_close(&session);
            return 1;
        }
        (void)printf("endpoint: COMPLETE digest=%s\n", dighex);
        (void)fflush(stdout);
    }
    if (host_completion_session_send_ncl1(
            &session,
            k_host_completion_shutdown,
            sizeof(k_host_completion_shutdown))
            != 0
        || host_completion_session_drain(&session, 5000u) != 0) {
        (void)fprintf(stderr, "endpoint: explicit shutdown send failed\n");
        ninlil_wifi_session_close(&session);
        return 1;
    }
    (void)printf("endpoint: SHUTDOWN_SENT\n");
    (void)fflush(stdout);
    {
        uint8_t ack[HOST_COMPLETION_NCL1_MAX];
        size_t ack_len = 0u;
        uint32_t ack_seq = 0u;
        int ack_result = host_completion_session_recv_ncl1(
            &session, ack, sizeof(ack), &ack_len, &ack_seq, 10000u);
        if (ack_result != 0
            || !host_completion_is_shutdown_ack(ack, ack_len)) {
            (void)fprintf(stderr,
                "endpoint: shutdown ACK missing result=%d len=%u\n",
                ack_result,
                (unsigned)ack_len);
            ninlil_wifi_session_close(&session);
            return 1;
        }
        (void)printf("endpoint: SHUTDOWN_ACK_RECEIVED seq=%u\n", ack_seq);
        (void)fflush(stdout);
    }
    ninlil_wifi_session_close(&session);
    return 0;
}

static void usage(void)
{
    (void)fprintf(
        stderr,
        "usage:\n"
        "  host_completion_transport_fixture_e2e --role parent --port N --certs DIR "
        "[--tag NAME]\n"
        "  host_completion_transport_fixture_e2e --role relay --listen N --p1 N --p2 N "
        "--certs DIR [--switch-after K] [--cold-restart]\n"
        "  host_completion_transport_fixture_e2e --role endpoint --relay N --certs DIR "
        "[--disconnect-after K] [--duplicate] [--cold-restart]\n");
}

static int parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;
    if (s == NULL || out == NULL) {
        return -1;
    }
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > 0xfffffffful) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    const char *role = NULL;
    const char *certs = NULL;
    const char *tag = "parent";
    uint32_t port = 0u;
    uint32_t listen_port = 0u;
    uint32_t p1 = 0u;
    uint32_t p2 = 0u;
    uint32_t relay = 0u;
    int switch_after = 0;
    int disconnect_after = 0;
    int duplicate = 0;
    int cold = 0;
    int i;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            role = argv[++i];
        } else if (strcmp(argv[i], "--certs") == 0 && i + 1 < argc) {
            certs = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], &port) != 0) {
                return 2;
            }
        } else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], &listen_port) != 0) {
                return 2;
            }
        } else if (strcmp(argv[i], "--p1") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], &p1) != 0) {
                return 2;
            }
        } else if (strcmp(argv[i], "--p2") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], &p2) != 0) {
                return 2;
            }
        } else if (strcmp(argv[i], "--relay") == 0 && i + 1 < argc) {
            if (parse_u32(argv[++i], &relay) != 0) {
                return 2;
            }
        } else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc) {
            tag = argv[++i];
        } else if (strcmp(argv[i], "--switch-after") == 0 && i + 1 < argc) {
            switch_after = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--disconnect-after") == 0 && i + 1 < argc) {
            disconnect_after = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duplicate") == 0) {
            duplicate = 1;
        } else if (strcmp(argv[i], "--cold-restart") == 0) {
            cold = 1;
        } else {
            usage();
            return 2;
        }
    }

    if (role == NULL || certs == NULL) {
        usage();
        return 2;
    }
    if (strcmp(role, "parent") == 0) {
        if (port > 65535u) {
            usage();
            return 2;
        }
        return role_parent((uint16_t)port, certs, tag);
    }
    if (strcmp(role, "relay") == 0) {
        if (listen_port > 65535u || p1 == 0u || p1 > 65535u
            || p2 == 0u || p2 > 65535u) {
            usage();
            return 2;
        }
        return role_relay(
            (uint16_t)listen_port,
            (uint16_t)p1,
            (uint16_t)p2,
            certs,
            switch_after,
            cold);
    }
    if (strcmp(role, "endpoint") == 0) {
        if (relay == 0u) {
            usage();
            return 2;
        }
        return role_endpoint(
            (uint16_t)relay, certs, disconnect_after, duplicate, cold);
    }
    usage();
    return 2;
}
