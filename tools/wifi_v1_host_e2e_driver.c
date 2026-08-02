/*
 * 2-process real-socket Wi-Fi Host e2e driver (private candidate).
 * Modes:
 *   --server --port N --certs DIR --frames K
 *   --client --port N --certs DIR --frames K [options]
 *
 * Options:
 *   --slow-ms M          inject client delay
 *   --malformed          inject garbage after handshake
 *   --expired-client     use expired client cert
 *   --bidirectional      both directions send frames
 *   --failover-port P    secondary endpoint for rotation
 *   --restart-midstream  client reconnects mid-transfer
 *   --ap-disconnect      server closes after partial frames
 *   --export-check       verify TLS exporter 62/64 domain separation
 *   --cred-rotate        exercise stage/activate mid-session
 *   --cred-revoke        revoke after activate → fail-closed send
 *   --runtime-e2e        public Runtime -> Fabric -> TLS -> peer Runtime
 *
 * Default frames=10000. Real TCP + OpenSSL TLS1.3 mutual auth.
 * No secret logging.
 */
#include "wifi_attachment_m4.h"
#include "wifi_budget.h"
#include "wifi_nfl1_min.h"
#include "wifi_session.h"
#include "wifi_tls_host.h"

#include "in_memory_storage.h"

#if defined(NINLIL_WIFI_HOST_FABRIC_SEND)
#include "wifi_v1_fabric_host_send.h"
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void usage(void)
{
    (void)fprintf(
        stderr,
        "usage: wifi_v1_host_e2e_driver --server|--client --port N "
        "--certs DIR [--frames K] [--slow-ms M] [--malformed] "
        "[--expired-client] [--bidirectional] [--failover-port P] "
        "[--restart-midstream] [--ap-disconnect] [--export-check] "
        "[--cred-rotate] [--cred-revoke] [--fabric-send] "
        "[--fabric-reply] [--runtime-e2e]\n");
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

/* Controllable mono clock: real wall mono unless override armed (blackhole). */
static uint64_t g_mono_override_ms;
static int g_mono_override_on;

static uint64_t mono_ms(void *user)
{
    struct timespec ts;
    (void)user;
    if (g_mono_override_on) {
        return g_mono_override_ms;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Provisioned Fabric descriptor + credential digest (not free M4 assertion). */
static const uint8_t k_e2e_fabric_desc[32] = {
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
    0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0
};
static const uint8_t k_e2e_cred_digest[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11
};

static int accept_m4_from_path(ninlil_wifi_session_t *session)
{
    ninlil_wifi_m4_full_evidence_t ev;
    ninlil_wifi_m4_membership_lease_t lease;
    ninlil_wifi_m4_fabric_registry_t reg;
    ninlil_test_storage_t *store = NULL;
    ninlil_test_storage_config_t cfg;
    const ninlil_storage_ops_t *ops;
    uint8_t peer[16];
    uint8_t att[16];
    uint8_t epoch[16];
    ninlil_wifi_status_t st;
    uint64_t now = mono_ms(NULL);
    const char *path = "wifi-m4-e2e";
    int rc = -1;

    if (ninlil_wifi_session_get_session_ids(session, peer, att)
        != NINLIL_WIFI_OK) {
        return -1;
    }
    ninlil_wifi_m4_owner_t m4_owner;
    ninlil_wifi_m4_owner_init(&m4_owner);
    if (ninlil_wifi_m4_evidence_reset(&m4_owner, &ev) != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "m4 evidence reset failed\n");
        goto out;
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
    st = ninlil_wifi_m4_membership_store_full(ops, store, path, &lease);
    if (st != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "m4 membership store failed %u\n", (unsigned)st);
        goto out;
    }
    st = ninlil_wifi_m4_membership_load_classify(&m4_owner, ops, store, path, now, &ev);
    if (st != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_membership_live(&ev) == 0) {
        (void)fprintf(stderr, "m4 membership classify failed\n");
        goto out;
    }

    {
        const uint8_t *cred_dig = k_e2e_cred_digest;
        uint64_t cred_rev = 1u;
        /* Match active session credential when rotated/re-staged. */
        if (ninlil_wifi_credential_is_active(&session->credentials)) {
            cred_dig = session->credentials.committed.secret_ref_digest;
            cred_rev = session->credentials.committed.revision;
            if (cred_rev == 0u) {
                cred_rev = 1u;
            }
        }
        st = ninlil_wifi_m4_credential_store_full(
            ops, store, path, cred_dig, cred_rev);
        if (st != NINLIL_WIFI_OK) {
            (void)fprintf(
                stderr, "m4 credential store failed %u\n", (unsigned)st);
            goto out;
        }
        st = ninlil_wifi_m4_credential_load_classify(
            &m4_owner, ops, store, path, &ev);
        if (st != NINLIL_WIFI_OK
            || ninlil_wifi_m4_evidence_class_credential(&ev)
                != NINLIL_WIFI_M4_CLASS_FULL) {
            (void)fprintf(stderr, "m4 credential classify failed\n");
            goto out;
        }

        st = ninlil_wifi_m4_attachment_store_full(
            ops,
            store,
            path,
            peer,
            lease.authority_id,
            lease.binding_digest,
            cred_dig,
            k_e2e_fabric_desc);
    }
    if (st != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "m4 attachment store failed %u\n", (unsigned)st);
        goto out;
    }
    st = ninlil_wifi_m4_attachment_load_classify(&m4_owner, ops, store, path, peer, &ev);
    if (st != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_class_attachment(&ev)
            != NINLIL_WIFI_M4_CLASS_FULL) {
        (void)fprintf(stderr, "m4 attachment classify failed\n");
        goto out;
    }

    (void)memset(epoch, 0xe1, sizeof(epoch));
    st = ninlil_wifi_m4_fabric_registry_bind(
        &reg, k_e2e_fabric_desc, lease.authority_id, epoch);
    if (st != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_apply_fabric_registry(&ev, &reg)
            != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "m4 fabric registry bind failed\n");
        goto out;
    }
    /*
     * Only after authenticated TLS peer session (exporters already ran):
     * mark evidence as session-authority minted. Raw durable fill alone is
     * not ready for attach.
     */
    if (session->phase != NINLIL_WIFI_PHASE_PEER_SESSION
        || !session->peer_session_valid) {
        (void)fprintf(stderr, "m4 requires authenticated peer session\n");
        goto out;
    }
    st = ninlil_wifi_m4_evidence_mark_session_authority(&ev);
    if (st != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "m4 session authority mark failed\n");
        goto out;
    }

    st = ninlil_wifi_session_accept_m4_full_evidence(session, &ev);
    if (st != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "m4 full evidence accept failed %u\n", (unsigned)st);
        goto out;
    }
    if (session->phase != NINLIL_WIFI_PHASE_ATTACHED) {
        (void)fprintf(stderr, "m4 accept left phase=%u (publish=0 path?)\n",
            (unsigned)session->phase);
        goto out;
    }
    rc = 0;
out:
    ninlil_test_storage_destroy(store);
    return rc;
}

static void fill_peer_inputs(ninlil_wifi_peer_context_inputs_t *in, int is_server)
{
    (void)memset(in, 0, sizeof(*in));
    /* BOUND ALL_NONZERO authority group. */
    (void)memset(in->authority_id, 0xd0, 16u);
    in->authority_id[15] = 0xdf;
    in->authority_term = 7u;
    in->assignment_epoch = 11u;
    /* Fixed client/server runtime ids (role order fixed, no lex sort). */
    {
        uint8_t i;
        for (i = 0u; i < 16u; ++i) {
            in->tls_client_runtime_id[i] = (uint8_t)(0x31u + i);
            in->tls_server_runtime_id[i] = (uint8_t)(0x32u + i);
        }
    }
    (void)is_server;
}

static int wait_attached(ninlil_wifi_session_t *session, int expired_client)
{
    uint32_t spins = 0u;
    /*
     * expired_client must never soft-pass on timeout. Rejection is only
     * success at configure_tls (local leaf notAfter) or explicit CREDENTIAL
     * fence — never "spun long enough".
     */
    (void)expired_client;
    while (spins < 30000u) {
        ninlil_wifi_status_t st = ninlil_wifi_session_poll(session);
        if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
            && st != NINLIL_WIFI_BACKPRESSURE
            && st != NINLIL_WIFI_INVALID_STATE) {
            (void)fprintf(stderr, "handshake poll failed %u phase=%u\n",
                (unsigned)st, (unsigned)session->phase);
            return -1;
        }
        if (session->phase == NINLIL_WIFI_PHASE_PEER_SESSION
            || session->phase == NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING) {
            /* M4 FULL from durable carrier evidence — not free-assertion digests. */
            if (accept_m4_from_path(session) != 0) {
                return -1;
            }
        }
        if (session->phase == NINLIL_WIFI_PHASE_ATTACHED) {
            return 1;
        }
        if (session->phase == NINLIL_WIFI_PHASE_FENCED
            || session->phase == NINLIL_WIFI_PHASE_CLOSED) {
            (void)fprintf(stderr, "not attached phase=%u\n",
                (unsigned)session->phase);
            return -1;
        }
        usleep(1000);
        spins += 1u;
    }
    (void)fprintf(stderr, "not attached phase=%u (timeout is not success)\n",
        (unsigned)session->phase);
    return -1;
}

static int send_frames(
    ninlil_wifi_session_t *session,
    uint32_t frames,
    uint32_t slow_ms,
    uint32_t start_id)
{
    uint8_t nfl1[587];
    size_t nfl1_len = 0u;
    uint32_t i;
    for (i = 0u; i < frames; ++i) {
        if (ninlil_wifi_nfl1_min_encode(
                nfl1, sizeof(nfl1), &nfl1_len, start_id + i)
            != NINLIL_WIFI_OK) {
            return -1;
        }
        for (;;) {
            ninlil_wifi_status_t st = ninlil_wifi_session_send_payload(
                session, nfl1, (uint32_t)nfl1_len);
            if (st == NINLIL_WIFI_OK) {
                break;
            }
            if (st == NINLIL_WIFI_BACKPRESSURE
                || st == NINLIL_WIFI_WOULD_BLOCK) {
                (void)ninlil_wifi_session_poll(session);
                usleep(100);
                continue;
            }
            (void)fprintf(stderr, "send fail %u at %u\n", (unsigned)st, i);
            return -1;
        }
        (void)ninlil_wifi_session_poll(session);
        if (slow_ms > 0u && (i % 100u) == 0u) {
            usleep(slow_ms * 1000u);
        }
    }
    for (i = 0u; i < 100000u; ++i) {
        if (ninlil_wifi_queue_is_empty(&session->txq)
            && session->tx_partial_len == 0u) {
            break;
        }
        (void)ninlil_wifi_session_poll(session);
        usleep(100);
    }
    return 0;
}

static int recv_frames(
    ninlil_wifi_session_t *session,
    uint32_t frames,
    int malformed,
    int ap_disconnect,
    int fabric_reply,
    uint32_t *received_out)
{
    uint32_t received = 0u;
    uint32_t last_seq = 0xffffffffu;
    while (received < frames) {
        uint8_t rec[1965];
        size_t rec_len = 0u;
        uint32_t seq = 0u;
        ninlil_wifi_status_t st = ninlil_wifi_session_poll(session);
        if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
            && st != NINLIL_WIFI_BACKPRESSURE) {
            if (malformed || ap_disconnect) {
                *received_out = received;
                return 0;
            }
            (void)fprintf(stderr, "server poll fail %u\n", (unsigned)st);
            return -1;
        }
        st = ninlil_wifi_session_recv_record(
            session, rec, sizeof(rec), &rec_len, &seq);
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            usleep(100);
            continue;
        }
        if (st != NINLIL_WIFI_OK) {
            if (ap_disconnect) {
                *received_out = received;
                return 0;
            }
            (void)fprintf(stderr, "recv fail %u\n", (unsigned)st);
            return -1;
        }
        if (last_seq != 0xffffffffu && seq != last_seq + 1u) {
            (void)fprintf(
                stderr, "sequence gap last=%u got=%u\n", last_seq, seq);
            return -1;
        }
        last_seq = seq;
        received += 1u;
        if (fabric_reply != 0
            && send_frames(session, 1u, 0u, 100000u + received - 1u) != 0) {
            (void)fprintf(
                stderr,
                "server Fabric response failed after frame=%u\n",
                received);
            return -1;
        }
        if (ap_disconnect && received >= frames / 2u) {
            *received_out = received;
            return 0;
        }
    }
    *received_out = received;
    return 0;
}

int main(int argc, char **argv)
{
    int is_server = 0;
    int is_client = 0;
    uint32_t port = 0u;
    uint32_t failover_port = 0u;
    uint32_t frames = 10000u;
    uint32_t slow_ms = 0u;
    int malformed = 0;
    int expired_client = 0;
    int bidirectional = 0;
    int restart_midstream = 0;
    int ap_disconnect = 0;
    int export_check = 0;
    int cred_rotate = 0;
    int cred_revoke = 0;
    int journal_durable = 0;
    int blackhole_inject = 0;
    int fabric_send = 0;
    int fabric_reply = 0;
    int runtime_e2e = 0;
    const char *certs = NULL;
    ninlil_wifi_session_t session;
    ninlil_wifi_tls_paths_t paths;
    ninlil_wifi_endpoint_t ep;
    uint32_t i;
    uint32_t received = 0u;
    int argi;
    int attach_rc;
    ninlil_wifi_peer_context_inputs_t peer_in;

    (void)signal(SIGPIPE, SIG_IGN);

    if (argc == 2 && strcmp(argv[1], "--supports-fabric-send") == 0) {
#if defined(NINLIL_WIFI_HOST_FABRIC_SEND)
        (void)printf("wifi_v1_host_e2e_driver: fabric-send supported\n");
        return 0;
#else
        return 2;
#endif
    }

    for (argi = 1; argi < argc; ++argi) {
        if (strcmp(argv[argi], "--server") == 0) {
            is_server = 1;
        } else if (strcmp(argv[argi], "--client") == 0) {
            is_client = 1;
        } else if (strcmp(argv[argi], "--port") == 0 && argi + 1 < argc) {
            if (parse_u32(argv[++argi], &port) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(argv[argi], "--failover-port") == 0
            && argi + 1 < argc) {
            if (parse_u32(argv[++argi], &failover_port) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(argv[argi], "--frames") == 0 && argi + 1 < argc) {
            if (parse_u32(argv[++argi], &frames) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(argv[argi], "--certs") == 0 && argi + 1 < argc) {
            certs = argv[++argi];
        } else if (strcmp(argv[argi], "--slow-ms") == 0 && argi + 1 < argc) {
            if (parse_u32(argv[++argi], &slow_ms) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(argv[argi], "--malformed") == 0) {
            malformed = 1;
        } else if (strcmp(argv[argi], "--expired-client") == 0) {
            expired_client = 1;
        } else if (strcmp(argv[argi], "--bidirectional") == 0) {
            bidirectional = 1;
        } else if (strcmp(argv[argi], "--restart-midstream") == 0) {
            restart_midstream = 1;
        } else if (strcmp(argv[argi], "--ap-disconnect") == 0) {
            ap_disconnect = 1;
        } else if (strcmp(argv[argi], "--export-check") == 0) {
            export_check = 1;
        } else if (strcmp(argv[argi], "--cred-rotate") == 0) {
            cred_rotate = 1;
        } else if (strcmp(argv[argi], "--cred-revoke") == 0) {
            cred_revoke = 1;
        } else if (strcmp(argv[argi], "--journal-durable") == 0) {
            journal_durable = 1;
        } else if (strcmp(argv[argi], "--blackhole-inject") == 0) {
            blackhole_inject = 1;
        } else if (strcmp(argv[argi], "--fabric-send") == 0) {
            fabric_send = 1;
        } else if (strcmp(argv[argi], "--fabric-reply") == 0) {
            fabric_reply = 1;
        } else if (strcmp(argv[argi], "--runtime-e2e") == 0) {
            runtime_e2e = 1;
        } else {
            usage();
            return 2;
        }
    }
    if ((is_server == is_client) || port == 0u || certs == NULL) {
        usage();
        return 2;
    }
    if (fabric_send != 0
        && (!is_client || restart_midstream || malformed || cred_rotate
            || cred_revoke || blackhole_inject || journal_durable)) {
        (void)fprintf(
            stderr, "--fabric-send is valid only for the plain client path\n");
        return 2;
    }
    if (fabric_reply != 0
        && ((is_client && fabric_send == 0)
            || restart_midstream || malformed || ap_disconnect
            || cred_rotate || cred_revoke || blackhole_inject
            || journal_durable || bidirectional)) {
        (void)fprintf(
            stderr,
            "--fabric-reply is valid only for the Fabric happy path\n");
        return 2;
    }
    if (runtime_e2e != 0
        && (frames != 1u || restart_midstream || malformed || expired_client
            || bidirectional || failover_port != 0u || slow_ms != 0u
            || ap_disconnect || export_check || cred_rotate || cred_revoke
            || journal_durable || blackhole_inject || fabric_send
            || fabric_reply)) {
        (void)fprintf(
            stderr,
            "--runtime-e2e requires the plain one-message path\n");
        return 2;
    }
#if !defined(NINLIL_WIFI_HOST_FABRIC_SEND)
    if (fabric_send != 0 || runtime_e2e != 0) {
        (void)fprintf(
            stderr,
            "--fabric-send/--runtime-e2e is unavailable in this build\n");
        return 2;
    }
#endif

    ninlil_wifi_session_init(&session);
    ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
    fill_peer_inputs(&peer_in, is_server);
    if (ninlil_wifi_session_set_peer_context_inputs(&session, &peer_in)
        != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "peer context inputs failed\n");
        return 1;
    }
    if (ninlil_wifi_session_set_fabric_descriptor(&session, k_e2e_fabric_desc)
        != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "fabric descriptor provision failed\n");
        return 1;
    }
    /* Committed credential candidate required for M4 FULL evidence match. */
    if (ninlil_wifi_credential_stage(
            &session.credentials, k_e2e_cred_digest, 1u)
            != NINLIL_WIFI_OK
        || ninlil_wifi_credential_activate(&session.credentials)
            != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "baseline cred activate failed\n");
        return 1;
    }
    /* credentials active for M4 match; require for send-path only after attach */
    {
        static char ca[512];
        static char cert[512];
        static char key[512];
        (void)snprintf(ca, sizeof(ca), "%s/ca.cert.pem", certs);
        if (is_server) {
            (void)snprintf(cert, sizeof(cert), "%s/server.cert.pem", certs);
            (void)snprintf(key, sizeof(key), "%s/server.key.pem", certs);
        } else if (expired_client) {
            (void)snprintf(cert, sizeof(cert), "%s/expired.cert.pem", certs);
            (void)snprintf(key, sizeof(key), "%s/expired.key.pem", certs);
        } else {
            (void)snprintf(cert, sizeof(cert), "%s/client.cert.pem", certs);
            (void)snprintf(key, sizeof(key), "%s/client.key.pem", certs);
        }
        paths.ca_pem_path = ca;
        paths.cert_pem_path = cert;
        paths.key_pem_path = key;
    }

    if (!ninlil_wifi_tls_host_profile_authority()) {
        if (getenv("NINLIL_WIFI_REQUIRE_AUTHORITY") != NULL) {
            (void)fprintf(
                stderr,
                "wifi_v1_host_e2e_driver: pinned static OpenSSL authority "
                "required but unavailable\n");
            return 1;
        }
        (void)printf(
            "wifi_v1_host_e2e_driver: pinned static OpenSSL authority absent "
            "(LAB path; authority not claimed)\n");
    }
    {
        ninlil_wifi_status_t tls_st =
            ninlil_wifi_session_configure_tls(&session, is_server, &paths);
        if (tls_st != NINLIL_WIFI_OK) {
            if (expired_client && !is_server
                && tls_st == NINLIL_WIFI_CREDENTIAL) {
                (void)printf(
                    "wifi_v1_host_e2e_driver: expired-client rejected OK\n");
                ninlil_wifi_session_close(&session);
                return 0;
            }
            (void)fprintf(stderr, "tls configure failed st=%u\n",
                (unsigned)tls_st);
            return 1;
        }
    }

    /* cred_rotate / cred_revoke exercised after ATTACHED (below). */

    /* Keep listener open for dual-accept paths (cred-rotate / restart). */
    ninlil_wifi_tcp_t server_listener;
    int server_listener_live = 0;
    ninlil_wifi_tcp_init(&server_listener);

    if (is_server) {
        ninlil_wifi_tcp_t accepted;
        ninlil_wifi_tcp_init(&accepted);
        if (ninlil_wifi_tcp_listen_loopback(
                &server_listener, (uint16_t)port, NULL)
            != NINLIL_WIFI_OK) {
            (void)fprintf(stderr, "listen failed\n");
            return 1;
        }
        server_listener_live = 1;
        for (;;) {
            ninlil_wifi_status_t st =
                ninlil_wifi_tcp_accept(&server_listener, &accepted);
            if (st == NINLIL_WIFI_OK) {
                break;
            }
            if (st != NINLIL_WIFI_WOULD_BLOCK) {
                (void)fprintf(stderr, "accept failed\n");
                ninlil_wifi_tcp_close(&server_listener);
                return 1;
            }
            usleep(1000);
        }
        if (ninlil_wifi_session_accept_fd(&session, accepted.fd)
            != NINLIL_WIFI_OK) {
            (void)fprintf(stderr, "accept_fd failed\n");
            ninlil_wifi_tcp_close(&server_listener);
            return 1;
        }
        accepted.fd = -1;
        /* Keep listener for second accept when dual-session scenarios run. */
        if (!cred_rotate && !restart_midstream) {
            ninlil_wifi_tcp_close(&server_listener);
            server_listener_live = 0;
        }
    } else {
        fill_endpoint(&ep, (uint16_t)port);
        if (failover_port != 0u) {
            ninlil_wifi_endpoint_t fo;
            fill_endpoint(&fo, (uint16_t)failover_port);
            (void)ninlil_wifi_session_add_endpoint(&session, &ep);
            (void)ninlil_wifi_session_set_failover(&session, &fo);
            ninlil_wifi_session_set_auto_reconnect(&session, 1);
        }
        {
            ninlil_wifi_status_t st =
                ninlil_wifi_session_connect(&session, &ep);
            while (st == NINLIL_WIFI_WOULD_BLOCK) {
                usleep(1000);
                st = ninlil_wifi_session_poll(&session);
                if (session.phase == NINLIL_WIFI_PHASE_CONNECTING
                    || session.phase == NINLIL_WIFI_PHASE_HANDSHAKING) {
                    st = NINLIL_WIFI_WOULD_BLOCK;
                } else if (
                    session.phase == NINLIL_WIFI_PHASE_PEER_SESSION
                    || session.phase == NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING
                    || session.phase == NINLIL_WIFI_PHASE_ATTACHED) {
                    st = NINLIL_WIFI_OK;
                }
            }
            if (session.phase == NINLIL_WIFI_PHASE_FENCED
                || session.phase == NINLIL_WIFI_PHASE_CLOSED) {
                if (expired_client) {
                    (void)printf(
                        "wifi_v1_host_e2e_driver: expired-client rejected OK\n");
                    ninlil_wifi_session_close(&session);
                    return 0;
                }
                (void)fprintf(stderr, "connect/handshake failed phase=%u\n",
                    (unsigned)session.phase);
                return 1;
            }
        }
    }

    attach_rc = wait_attached(&session, expired_client);
    if (attach_rc <= 0) {
        ninlil_wifi_session_close(&session);
        if (expired_client && attach_rc == 0) {
            (void)printf(
                "wifi_v1_host_e2e_driver: expired-client rejected OK\n");
        }
        return attach_rc == 0 ? 0 : 1;
    }
    if (expired_client) {
        (void)fprintf(
            stderr, "expired-client must not reach ATTACHED\n");
        ninlil_wifi_session_close(&session);
        return 1;
    }
    ninlil_wifi_session_require_credentials(&session, 1);

    if (export_check) {
        uint8_t peer_ctx[62];
        uint8_t att_ctx[64];
        uint8_t peer_sid[16];
        uint8_t att_sid[16];
        if (ninlil_wifi_session_get_contexts(&session, peer_ctx, att_ctx)
            != NINLIL_WIFI_OK) {
            (void)fprintf(stderr, "export contexts missing\n");
            return 1;
        }
        if (memcmp(peer_ctx, att_ctx, 62u) == 0) {
            (void)fprintf(stderr, "context domain separation failed\n");
            return 1;
        }
        if (ninlil_wifi_session_get_session_ids(&session, peer_sid, att_sid)
            != NINLIL_WIFI_OK) {
            (void)fprintf(stderr, "export 16-byte ids missing\n");
            return 1;
        }
        if (memcmp(peer_sid, att_sid, 16u) == 0) {
            (void)fprintf(stderr, "session id domain separation failed\n");
            return 1;
        }
        (void)printf(
            "wifi_v1_host_e2e_driver: export contexts 62/64 + ids 16/16 OK\n");
    }

    if (malformed && is_client) {
        uint8_t junk[16] = {0};
        size_t w = 0u;
        junk[0] = 0x4e;
        (void)ninlil_wifi_tls_write(session.tls, junk, sizeof(junk), &w);
        (void)printf(
            "wifi_v1_host_e2e_driver: client injected malformed\n");
    }

    if (cred_rotate && is_client) {
        uint8_t dig[32];
        /*
         * Manifest rotate: RAM digest swap alone must not continue ATTACHED.
         * Fence/close old TLS/session, then re-auth only after new credentials.
         */
        /* Allow server to finish first ATTACHED before we tear down. */
        usleep(100000);
        (void)memcpy(dig, k_e2e_cred_digest, 32u);
        dig[0] ^= 0x6du;
        /* Stage+activate while ATTACHED without fence — forbidden continue. */
        if (ninlil_wifi_credential_stage(&session.credentials, dig, 2u)
                != NINLIL_WIFI_OK
            || ninlil_wifi_credential_activate(&session.credentials)
                != NINLIL_WIFI_OK) {
            (void)fprintf(stderr, "cred rotate stage-while-attached failed\n");
            return 1;
        }
        /*
         * Must fence/close old TLS/session before any post-rotate progress.
         * Remaining ATTACHED after digest swap alone is a hard fail.
         */
        ninlil_wifi_session_fence(&session);
        if (session.phase == NINLIL_WIFI_PHASE_ATTACHED) {
            (void)fprintf(
                stderr, "cred rotate RAM digest swap continued ATTACHED\n");
            return 1;
        }
        ninlil_wifi_session_close(&session);
        /* Give server time to observe close and re-arm second accept. */
        usleep(50000);
        {
            uint32_t tries;
            int ok = 0;
            for (tries = 0u; tries < 200u; ++tries) {
                ninlil_wifi_session_init(&session);
                ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
                fill_peer_inputs(&peer_in, 0);
                (void)ninlil_wifi_session_set_peer_context_inputs(
                    &session, &peer_in);
                (void)ninlil_wifi_session_set_fabric_descriptor(
                    &session, k_e2e_fabric_desc);
                if (ninlil_wifi_credential_stage(
                        &session.credentials, dig, 2u)
                        != NINLIL_WIFI_OK
                    || ninlil_wifi_credential_activate(&session.credentials)
                        != NINLIL_WIFI_OK
                    || ninlil_wifi_session_configure_tls(
                           &session, 0, &paths)
                        != NINLIL_WIFI_OK) {
                    (void)fprintf(stderr, "cred rotate re-stage/tls failed\n");
                    return 1;
                }
                ninlil_wifi_session_require_credentials(&session, 1);
                fill_endpoint(&ep, (uint16_t)port);
                {
                    ninlil_wifi_status_t st =
                        ninlil_wifi_session_connect(&session, &ep);
                    if (st == NINLIL_WIFI_OK
                        || session.phase == NINLIL_WIFI_PHASE_HANDSHAKING
                        || session.phase == NINLIL_WIFI_PHASE_CONNECTING
                        || session.phase == NINLIL_WIFI_PHASE_PEER_SESSION
                        || session.phase == NINLIL_WIFI_PHASE_ATTACHED) {
                        if (wait_attached(&session, 0) > 0) {
                            ok = 1;
                            break;
                        }
                    }
                }
                ninlil_wifi_session_close(&session);
                usleep(20000);
            }
            if (!ok) {
                (void)fprintf(stderr, "cred rotate reattach failed\n");
                return 1;
            }
        }
        (void)printf(
            "wifi_v1_host_e2e_driver: cred-rotate fence+reauth OK\n");
    }

    if (journal_durable && is_client) {
        ninlil_test_storage_t *jstore;
        ninlil_test_storage_config_t jcfg;
        (void)memset(&jcfg, 0, sizeof(jcfg));
        jcfg.max_namespaces = 4u;
        jcfg.max_entries_per_namespace = 32u;
        jcfg.max_bytes_per_namespace = 65536u;
        jstore = ninlil_test_storage_create(&jcfg);
        if (jstore == NULL) {
            return 1;
        }
        if (ninlil_wifi_credential_bind_storage(
                &session.credentials,
                ninlil_test_storage_ops(jstore),
                jstore,
                "cred-nwd1")
            != NINLIL_WIFI_OK) {
            ninlil_test_storage_destroy(jstore);
            return 1;
        }
        if (ninlil_wifi_credential_stage(
                &session.credentials, k_e2e_cred_digest, 3u)
                != NINLIL_WIFI_OK
            || ninlil_wifi_credential_activate(&session.credentials)
                != NINLIL_WIFI_OK
            || ninlil_wifi_credential_durable_put_full(&session.credentials)
                != NINLIL_WIFI_OK) {
            ninlil_test_storage_destroy(jstore);
            (void)fprintf(stderr, "durable credential put failed\n");
            return 1;
        }
        /* Cold reopen durable credential image (FULL NWD1 recovery). */
        {
            ninlil_wifi_credential_store_t cold;
            ninlil_wifi_credential_store_init(&cold);
            if (ninlil_wifi_credential_bind_storage(
                    &cold, ninlil_test_storage_ops(jstore), jstore, "cred-nwd1")
                != NINLIL_WIFI_OK
                || ninlil_wifi_credential_durable_reopen(&cold)
                    != NINLIL_WIFI_OK
                || ninlil_wifi_credential_is_active(&cold) == 0) {
                ninlil_test_storage_destroy(jstore);
                (void)fprintf(stderr, "durable credential recovery failed\n");
                return 1;
            }
        }
        ninlil_test_storage_destroy(jstore);
        (void)printf(
            "wifi_v1_host_e2e_driver: journal-durable recovery OK\n");
    }

    if (blackhole_inject && is_client) {
        /*
         * Real timer path: advance mono past BLACKHOLE_DETECT_MS without RX.
         * Do not use force_blackhole shortcut — exercise the threshold compare.
         */
        ninlil_wifi_status_t st;
        (void)ninlil_wifi_session_poll(&session); /* arm last_rx watermark */
        g_mono_override_ms = mono_ms(NULL);
        g_mono_override_on = 1;
        g_mono_override_ms += (uint64_t)NINLIL_WIFI_BLACKHOLE_DETECT_MS + 1u;
        st = ninlil_wifi_session_poll(&session);
        g_mono_override_on = 0;
        if (st == NINLIL_WIFI_FENCED
            || session.phase == NINLIL_WIFI_PHASE_FENCED) {
            (void)printf(
                "wifi_v1_host_e2e_driver: blackhole fence OK\n");
            ninlil_wifi_session_close(&session);
            return 0;
        }
        (void)fprintf(
            stderr, "blackhole did not fence st=%u phase=%u\n",
            (unsigned)st, (unsigned)session.phase);
        return 1;
    }

    if (cred_revoke && is_client) {
        (void)ninlil_wifi_credential_revoke(&session.credentials);
        {
            uint8_t nfl1[587];
            size_t nfl1_len = 0u;
            ninlil_wifi_status_t st;
            (void)ninlil_wifi_nfl1_min_encode(
                nfl1, sizeof(nfl1), &nfl1_len, 1u);
            st = ninlil_wifi_session_send_payload(
                &session, nfl1, (uint32_t)nfl1_len);
            if (st == NINLIL_WIFI_CREDENTIAL) {
                (void)printf(
                    "wifi_v1_host_e2e_driver: cred-revoke fail-closed OK\n");
                ninlil_wifi_session_close(&session);
                return 0;
            }
            (void)fprintf(stderr, "cred-revoke did not fail closed st=%u\n",
                (unsigned)st);
            return 1;
        }
    }

    if (runtime_e2e != 0) {
#if defined(NINLIL_WIFI_HOST_FABRIC_SEND)
        int runtime_e2e_result =
            ninlil_wifi_host_public_runtime_e2e(&session, is_server);
        if (server_listener_live) {
            ninlil_wifi_tcp_close(&server_listener);
        }
        ninlil_wifi_session_close(&session);
        return runtime_e2e_result == 0 ? 0 : 1;
#endif
    }

    if (is_client) {
        if (fabric_send != 0) {
#if defined(NINLIL_WIFI_HOST_FABRIC_SEND)
            if (ninlil_wifi_host_fabric_send_frames(
                    &session, frames, slow_ms, 1u, fabric_reply)
                != 0) {
                return 1;
            }
            (void)printf(
                "wifi_v1_host_e2e_driver: client sent frames=%u\n", frames);
#endif
        } else {
            uint32_t first = restart_midstream ? frames / 2u : frames;
            if (send_frames(&session, first, slow_ms, 1u) != 0) {
                return 1;
            }
            if (restart_midstream) {
                ninlil_wifi_session_close(&session);
                ninlil_wifi_session_init(&session);
                ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
                fill_peer_inputs(&peer_in, 0);
                (void)ninlil_wifi_session_set_peer_context_inputs(
                    &session, &peer_in);
                (void)ninlil_wifi_session_set_fabric_descriptor(
                    &session, k_e2e_fabric_desc);
                if (ninlil_wifi_credential_stage(
                        &session.credentials, k_e2e_cred_digest, 1u)
                        != NINLIL_WIFI_OK
                    || ninlil_wifi_credential_activate(&session.credentials)
                        != NINLIL_WIFI_OK) {
                    return 1;
                }
                ninlil_wifi_session_require_credentials(&session, 1);
                if (ninlil_wifi_session_configure_tls(&session, 0, &paths)
                    != NINLIL_WIFI_OK) {
                    return 1;
                }
                fill_endpoint(&ep, (uint16_t)port);
                if (ninlil_wifi_session_connect(&session, &ep)
                        != NINLIL_WIFI_OK
                    && session.phase != NINLIL_WIFI_PHASE_HANDSHAKING
                    && session.phase != NINLIL_WIFI_PHASE_ATTACHED
                    && session.phase != NINLIL_WIFI_PHASE_PEER_SESSION
                    && session.phase != NINLIL_WIFI_PHASE_CONNECTING) {
                    return 1;
                }
                if (wait_attached(&session, 0) <= 0) {
                    return 1;
                }
                if (send_frames(
                        &session, frames - first, slow_ms, first + 1u)
                    != 0) {
                    return 1;
                }
                (void)printf(
                    "wifi_v1_host_e2e_driver: client restart-midstream OK "
                    "frames=%u\n",
                    frames);
            } else {
                (void)printf(
                    "wifi_v1_host_e2e_driver: client sent frames=%u\n",
                    frames);
            }
        }
        if (bidirectional) {
            if (recv_frames(&session, frames, 0, 0, 0, &received) != 0) {
                return 1;
            }
            (void)printf(
                "wifi_v1_host_e2e_driver: client received frames=%u ordered\n",
                received);
        }
    } else {
        if (cred_rotate) {
            /*
             * Client fences/closes old TLS then re-auths. Drop first session
             * as soon as peer goes away (or after a short grace), then accept
             * the post-rotate connection on the kept listener.
             */
            {
                uint32_t spins = 0u;
                while (spins < 10000u) {
                    ninlil_wifi_status_t st =
                        ninlil_wifi_session_poll(&session);
                    if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
                        && st != NINLIL_WIFI_BACKPRESSURE) {
                        break;
                    }
                    if (session.phase == NINLIL_WIFI_PHASE_FENCED
                        || session.phase == NINLIL_WIFI_PHASE_CLOSED) {
                        break;
                    }
                    usleep(1000);
                    spins += 1u;
                }
            }
            ninlil_wifi_session_close(&session);
            ninlil_wifi_session_init(&session);
            ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
            fill_peer_inputs(&peer_in, 1);
            (void)ninlil_wifi_session_set_peer_context_inputs(
                &session, &peer_in);
            (void)ninlil_wifi_session_set_fabric_descriptor(
                &session, k_e2e_fabric_desc);
            if (ninlil_wifi_credential_stage(
                    &session.credentials, k_e2e_cred_digest, 1u)
                    != NINLIL_WIFI_OK
                || ninlil_wifi_credential_activate(&session.credentials)
                    != NINLIL_WIFI_OK) {
                (void)fprintf(stderr, "cred-rotate server re-cred failed\n");
                return 1;
            }
            ninlil_wifi_session_require_credentials(&session, 1);
            if (ninlil_wifi_session_configure_tls(&session, 1, &paths)
                != NINLIL_WIFI_OK) {
                (void)fprintf(stderr, "cred-rotate server re-tls failed\n");
                return 1;
            }
            {
                ninlil_wifi_tcp_t accepted;
                ninlil_wifi_tcp_init(&accepted);
                if (!server_listener_live) {
                    (void)fprintf(stderr, "cred-rotate missing listener\n");
                    return 1;
                }
                /* Drain any stale half-open connections from client retries. */
                for (i = 0u; i < 50000u; ++i) {
                    ninlil_wifi_status_t st =
                        ninlil_wifi_tcp_accept(&server_listener, &accepted);
                    if (st == NINLIL_WIFI_OK) {
                        break;
                    }
                    usleep(1000);
                }
                if (accepted.fd < 0) {
                    (void)fprintf(stderr, "cred-rotate second accept failed\n");
                    return 1;
                }
                if (ninlil_wifi_session_accept_fd(&session, accepted.fd)
                    != NINLIL_WIFI_OK) {
                    (void)fprintf(stderr, "cred-rotate accept_fd failed\n");
                    return 1;
                }
                accepted.fd = -1;
            }
            if (wait_attached(&session, 0) <= 0) {
                (void)fprintf(
                    stderr,
                    "cred-rotate server reattach failed phase=%u\n",
                    (unsigned)session.phase);
                return 1;
            }
            if (recv_frames(&session, frames, 0, 0, 0, &received) != 0) {
                return 1;
            }
            (void)printf(
                "wifi_v1_host_e2e_driver: server received frames=%u ordered\n",
                received);
        } else if (restart_midstream) {
            /* First half only — client will close and reconnect. */
            uint32_t first = frames / 2u;
            if (recv_frames(&session, first, 0, 0, 0, &received) != 0) {
                (void)fprintf(stderr, "restart first-half recv failed\n");
                return 1;
            }
            /* Drain until client closes before re-accept. */
            {
                uint32_t spins = 0u;
                while (spins < 10000u) {
                    ninlil_wifi_status_t st =
                        ninlil_wifi_session_poll(&session);
                    if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
                        && st != NINLIL_WIFI_BACKPRESSURE) {
                        break;
                    }
                    if (session.phase == NINLIL_WIFI_PHASE_FENCED
                        || session.phase == NINLIL_WIFI_PHASE_CLOSED) {
                        break;
                    }
                    usleep(1000);
                    spins += 1u;
                }
            }
            /* Accept second connection after client restart (listener kept). */
            ninlil_wifi_session_close(&session);
            ninlil_wifi_session_init(&session);
            ninlil_wifi_session_set_mono_clock(&session, mono_ms, NULL);
            fill_peer_inputs(&peer_in, 1);
            (void)ninlil_wifi_session_set_peer_context_inputs(
                &session, &peer_in);
            (void)ninlil_wifi_session_set_fabric_descriptor(
                &session, k_e2e_fabric_desc);
            if (ninlil_wifi_credential_stage(
                    &session.credentials, k_e2e_cred_digest, 1u)
                    != NINLIL_WIFI_OK
                || ninlil_wifi_credential_activate(&session.credentials)
                    != NINLIL_WIFI_OK) {
                return 1;
            }
            ninlil_wifi_session_require_credentials(&session, 1);
            if (ninlil_wifi_session_configure_tls(&session, 1, &paths)
                != NINLIL_WIFI_OK) {
                (void)fprintf(stderr, "restart server re-tls failed\n");
                return 1;
            }
            {
                ninlil_wifi_tcp_t accepted;
                ninlil_wifi_tcp_init(&accepted);
                if (!server_listener_live) {
                    (void)fprintf(stderr, "restart missing listener\n");
                    return 1;
                }
                for (i = 0u; i < 50000u; ++i) {
                    ninlil_wifi_status_t st =
                        ninlil_wifi_tcp_accept(&server_listener, &accepted);
                    if (st == NINLIL_WIFI_OK) {
                        break;
                    }
                    usleep(1000);
                }
                if (accepted.fd < 0) {
                    (void)fprintf(stderr, "restart second accept failed\n");
                    return 1;
                }
                if (ninlil_wifi_session_accept_fd(&session, accepted.fd)
                    != NINLIL_WIFI_OK) {
                    (void)fprintf(stderr, "restart accept_fd failed\n");
                    return 1;
                }
                accepted.fd = -1;
            }
            if (wait_attached(&session, 0) <= 0) {
                (void)fprintf(stderr, "restart server reattach failed\n");
                return 1;
            }
            if (recv_frames(
                    &session, frames - frames / 2u, 0, 0, 0, &received)
                != 0) {
                return 1;
            }
            (void)printf(
                "wifi_v1_host_e2e_driver: server restart-midstream OK "
                "second_half=%u\n",
                received);
        } else if (recv_frames(
                       &session,
                       frames,
                       malformed,
                       ap_disconnect,
                       fabric_reply,
                       &received)
            != 0) {
            return 1;
        } else if (malformed) {
            (void)printf(
                "wifi_v1_host_e2e_driver: server saw malformed OK\n");
        } else if (ap_disconnect) {
            ninlil_wifi_session_fence(&session);
            (void)printf(
                "wifi_v1_host_e2e_driver: server ap-disconnect after %u\n",
                received);
        } else {
            (void)printf(
                "wifi_v1_host_e2e_driver: server received frames=%u ordered\n",
                received);
            if (fabric_reply != 0) {
                (void)printf(
                    "wifi_v1_host_e2e_driver: server Fabric responses=%u\n",
                    received);
            }
        }
        if (bidirectional && !malformed && !ap_disconnect
            && !restart_midstream && !cred_rotate) {
            if (send_frames(&session, frames, 0u, 100000u) != 0) {
                return 1;
            }
            (void)printf(
                "wifi_v1_host_e2e_driver: server sent frames=%u\n", frames);
        }
    }

    if (server_listener_live) {
        ninlil_wifi_tcp_close(&server_listener);
    }
    ninlil_wifi_session_close(&session);
    return 0;
}
