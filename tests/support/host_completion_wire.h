/*
 * Test/support only: Host completion integrated E2E wire seam.
 * Not public ABI. Not installed. Wraps existing private codecs/ops.
 */
#ifndef NINLIL_TESTS_SUPPORT_HOST_COMPLETION_WIRE_H
#define NINLIL_TESTS_SUPPORT_HOST_COMPLETION_WIRE_H

#include "mfdt_v1.h"
#include "rrmp_abi.h"
#include "wifi_session.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic tag embedded in structural NFL1 for MFDT NCL1 carrier (after header). */
#define HOST_COMPLETION_NFL1_TAG0 ((uint8_t)'M')
#define HOST_COMPLETION_NFL1_TAG1 ((uint8_t)'F')
#define HOST_COMPLETION_NFL1_TAG2 ((uint8_t)'D')
#define HOST_COMPLETION_NFL1_TAG3 ((uint8_t)'T')

/* Hop outbound carrier tag (RRMP e2e body over TLS). */
#define HOST_COMPLETION_HOP_TAG0 ((uint8_t)'R')
#define HOST_COMPLETION_HOP_TAG1 ((uint8_t)'R')
#define HOST_COMPLETION_HOP_TAG2 ((uint8_t)'M')
#define HOST_COMPLETION_HOP_TAG3 ((uint8_t)'P')

enum {
    HOST_COMPLETION_NCL1_MAX = 1024,
    HOST_COMPLETION_NFL1_MAX = 1925,
    HOST_COMPLETION_NWB1_MAX = 1965
};

/*
 * Build structural NFL1 that carries NCL1 body (tag + len + ncl1 + pad).
 * Then NWB1-encode for session_send_payload.
 */
int host_completion_ncl1_to_nwb1(
    const uint8_t *ncl1,
    size_t ncl1_len,
    const uint8_t session_id[16],
    uint32_t sequence,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);

/* Inverse: NWB1 record → NCL1 bytes. Returns 0 on success. */
int host_completion_nwb1_to_ncl1(
    const uint8_t *nwb1,
    size_t nwb1_len,
    uint8_t *ncl1_out,
    size_t ncl1_cap,
    size_t *ncl1_len_out,
    uint32_t *sequence_out);

/* Pack RRMP outbound hop e2e body into NWB1 for real TLS. */
int host_completion_hop_to_nwb1(
    const ninlil_rrmp_outbound_packet_t *pkt,
    const uint8_t session_id[16],
    uint32_t sequence,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);

int host_completion_nwb1_is_hop(
    const uint8_t *nwb1, size_t nwb1_len, ninlil_rrmp_outbound_packet_t *pkt_out);

/*
 * Real-TLS RRMP outbound provider (production seam test double).
 * When pkt->carrier_len > 0, submits those exact NCL1 bytes as MFDT NFL1 over
 * the attached WiFi session (no separate session_send_ncl1 bypass).
 */
typedef struct host_completion_outbound_ctx {
    ninlil_wifi_session_t *session; /* active parent TLS session */
    uint64_t bytes_submitted;
    uint32_t submit_count;
    uint32_t last_status;
    ninlil_rrmp_outbound_packet_t last_pkt;
    uint8_t has_last;
    uint32_t sequence; /* NWB1 seq for custody-only hop frames */
} host_completion_outbound_ctx_t;

void host_completion_outbound_init(
    host_completion_outbound_ctx_t *ctx, ninlil_wifi_session_t *session);

/* Install as ninlil_rrmp_outbound_provider_t.submit */
uint32_t host_completion_rrmp_outbound_submit(
    void *user, const ninlil_rrmp_outbound_packet_t *pkt);

/* Drain session TX queue over real TLS (poll until empty or timeout_ms). */
int host_completion_session_drain(ninlil_wifi_session_t *session, uint32_t timeout_ms);

/* Send one NCL1 over attached session as NWB1 (increments session sequences). */
int host_completion_session_send_ncl1(
    ninlil_wifi_session_t *session, const uint8_t *ncl1, size_t ncl1_len);

/* Recv one NCL1 from attached session (poll with timeout). */
int host_completion_session_recv_ncl1(
    ninlil_wifi_session_t *session,
    uint8_t *ncl1_out,
    size_t ncl1_cap,
    size_t *ncl1_len_out,
    uint32_t *seq_out,
    uint32_t timeout_ms);

/* Fabric private select among 2 candidate instance ids (existing select API). */
int host_completion_fabric_select_parent(
    const uint8_t parent_a[16],
    const uint8_t parent_b[16],
    int a_available,
    int b_available,
    uint64_t now_ms,
    uint8_t selected_out[16],
    uint32_t *has_selection_out);

/*
 * MFDT lab store durable snapshot (key+value rows → file).
 * Not a struct memcpy: serializes occupied rows as real storage bytes.
 */
int host_completion_mfdt_store_export_path(
    const ninlil_mfdt_v1_lab_store_t *store, const char *path, size_t *bytes_out);

int host_completion_mfdt_store_import_path(
    ninlil_mfdt_v1_lab_store_t *store, const char *path, size_t *bytes_out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TESTS_SUPPORT_HOST_COMPLETION_WIRE_H */
