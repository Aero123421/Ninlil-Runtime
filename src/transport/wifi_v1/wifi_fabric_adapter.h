#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_FABRIC_ADAPTER_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_FABRIC_ADAPTER_H

/*
 * Fabric packet-link provider seam for private Wi-Fi (ADR-0018 / ADR-0017).
 *
 * Host packet-link state machine (ops authority — wifi_fabric_link_ops.c):
 *   open  : second_open while open → DENIED; live unreleased slots → WOULD_BLOCK
 *   start : TxPermit atomic consume (null/mismatch/expired/reused → DENIED, TX0)
 *   cancel: terminal + drop session TX by NWB1 sequence
 *   close : terminal-all + cancel TX; keep slots until release; record closed_generation
 *   release: open gen OR closed_generation handle; wipe slot after terminal only
 *
 * Permit authority:
 *   - Fabric's FBA1 co-locates the durable one-shot permit claim.
 *   - This provider keeps only live/unreleased permits and rejects a duplicate
 *     while transport ownership is retained.
 *   - trusted clock binding is mandatory; no zero-time expiry bypass exists.
 */
#include "wifi_budget.h"
#include "wifi_fabric_call_authority.h"
#include "wifi_private_types.h"

#include <ninlil/platform.h>

#if !defined(ESP_PLATFORM)
#include "wifi_session.h"
#else
/* ESP: opaque session type; authority surface may keep session NULL. */
typedef struct ninlil_wifi_session ninlil_wifi_session_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_fabric_link {
    ninlil_wifi_session_t *session;
    uint32_t maximum_packet_bytes;
    uint32_t link_kind;
} ninlil_wifi_fabric_link_t;

typedef struct ninlil_wifi_fabric_send_slot {
    uint8_t in_use;
    uint8_t terminal;
    uint8_t cancelled;
    uint8_t permit_ledger_slot; /* index into permit ledger while in-flight */
    uint32_t completion_kind;
    uint32_t generation;
    uint32_t sequence_at_accept;
    uint8_t permit_id[16];
} ninlil_wifi_fabric_send_slot_t;

#if !defined(ESP_PLATFORM)

/*
 * Bounded ownership ledger:
 *   LIVE    — accepted and not terminal
 *   RETIRED — terminal but caller has not released its token
 *
 * release reclaims RETIRED entries only when durable_outer_permit_authority is
 * asserted. Durable replay authority belongs to the owning Fabric FBA1 while
 * the issuer's TxGate never reissues an {epoch, permit_id} pair.
 */
#define NINLIL_WIFI_FABRIC_PERMIT_LEDGER 16u
#define NINLIL_WIFI_FABRIC_PERMIT_CONSUME_MAX NINLIL_WIFI_FABRIC_PERMIT_LEDGER
#define NINLIL_WIFI_FABRIC_PERMIT_ST_EMPTY 0u
#define NINLIL_WIFI_FABRIC_PERMIT_ST_LIVE 1u
#define NINLIL_WIFI_FABRIC_PERMIT_ST_RETIRED 2u

typedef struct ninlil_wifi_fabric_permit_entry {
    uint8_t permit_id[16];
    uint8_t clock_epoch_id[16];
    uint64_t expires_at_ms;
    uint8_t state;
    uint8_t reserved[7];
} ninlil_wifi_fabric_permit_entry_t;

typedef struct ninlil_wifi_fabric_link_user {
    uint32_t provider_magic;
    ninlil_wifi_session_t *session;
    uint64_t availability_epoch_seen;

    /* Trusted clock snapshot. Bind through the helper below before any send. */
    uint64_t permit_now_ms;
    uint8_t permit_clock_epoch_id[16];
    uint8_t permit_clock_epoch_set;
    /*
     * Required for sends. The caller promises Fabric's co-located FBA1
     * one-shot gate wraps this provider. Direct standalone use is fail-closed.
     */
    uint8_t durable_outer_permit_authority;
    uint8_t reserved_clk[6];

    /*
     * Production authority.  durable_outer_permit_authority is retained only
     * for explicit low-level test seams; adapter-created ops use this exact
     * Fabric-cookie/generation binding.
     */
    ninlil_wifi_fabric_call_authority_v1_t call_authority;

    uint32_t open_generation;
    /* Last successful close generation; release-after-close accepts this handle. */
    uint32_t closed_generation;
    uint8_t open;
    uint8_t reserved0[3];

    ninlil_wifi_fabric_send_slot_t send_slots[NINLIL_WIFI_TX_QUEUE_DEPTH];
    uint32_t next_token_generation;
    /* Monotonic test/diagnostic count: provider RETAINED accepts only. */
    uint64_t accepted_send_count;
    /*
     * Monotonic ingress transcript. NWB1's ordered stream classifier rejects
     * duplicates/gaps before these fields advance; the digest covers the
     * exact NFL1 payload accepted from the peer.
     */
    uint64_t accepted_receive_count;
    uint32_t last_receive_sequence;
    uint32_t last_receive_length;
    uint8_t last_receive_digest[32];

    uint8_t rx_loan_active;
    uint8_t reserved1[3];
    uint32_t next_rx_loan_generation;
    uint32_t active_rx_loan_generation;
    uint8_t rx_record[NINLIL_WIFI_NWB1_TOTAL_MAX];
    uint32_t rx_record_len;

    ninlil_wifi_fabric_permit_entry_t permit_ledger[NINLIL_WIFI_FABRIC_PERMIT_LEDGER];
    uint32_t permit_live_count; /* LIVE entries only (capacity) */
} ninlil_wifi_fabric_link_user_t;

#endif /* !ESP_PLATFORM */

void ninlil_wifi_fabric_link_init(
    ninlil_wifi_fabric_link_t *link,
    ninlil_wifi_session_t *session);

#if !defined(ESP_PLATFORM)
ninlil_wifi_status_t ninlil_wifi_fabric_link_send(
    ninlil_wifi_fabric_link_t *link,
    const uint8_t *nfl1,
    uint32_t nfl1_len);

ninlil_wifi_status_t ninlil_wifi_fabric_link_recv(
    ninlil_wifi_fabric_link_t *link,
    uint8_t *record_out,
    size_t record_cap,
    size_t *record_len_out);

#if defined(NINLIL_POSIX_TLS_V1_BUILD)
#include <ninlil/fabric_v1.h>
#elif defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1
#include "fabric_private_api.h"
#endif

#if (defined(NINLIL_POSIX_TLS_V1_BUILD)) \
    || (defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) \
        && NINLIL_ENABLE_PRIVATE_FABRIC_V1)
void ninlil_wifi_fabric_packet_link_ops_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_fabric_link_user_t *user);

/*
 * Production adapter seam.  A scoped table is valid only while the exact
 * cookie remains bound at the captured generation.
 */
void ninlil_wifi_fabric_packet_link_ops_scoped_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_fabric_link_user_t *user,
    ninlil_wifi_fabric_call_scope_v1_t *scope,
    const void *fabric_cookie);

int ninlil_wifi_fabric_packet_link_authority_prepare(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie);

int ninlil_wifi_fabric_packet_link_authority_activate(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie);

int ninlil_wifi_fabric_packet_link_authority_drain(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie);

int ninlil_wifi_fabric_packet_link_authority_unbind(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie);

/*
 * Bind a trusted, monotonic sample. Epoch change or time regression is denied
 * so an already-expired permit cannot be made valid again.
 */
ninlil_wifi_status_t ninlil_wifi_fabric_bind_trusted_clock(
    ninlil_wifi_fabric_link_user_t *user,
    const ninlil_time_sample_t *sample);
#endif
#endif /* !ESP_PLATFORM */

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_FABRIC_ADAPTER_H */
