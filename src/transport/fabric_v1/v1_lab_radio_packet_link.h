#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_RADIO_PACKET_LINK_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_RADIO_PACKET_LINK_H

/* Private V1 LAB Fabric -> NRA1 -> R7 SINGLE -> SX1262 packet-link. */

#include "v1_lab_radio_mapping.h"

#include "ninlil/fabric_v1.h"

#include "ninlil_sx1262_phy.h"
#include "r7_frag/r7_frag_prod_orch.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_RADIO_LINK_PATH_MAX ((uint8_t)4u)
#define NINLIL_V1_LAB_RADIO_LINK_RX_TIMEOUT_MS ((uint32_t)5000u)

typedef uint32_t ninlil_v1_lab_radio_link_status_t;
#define NINLIL_V1_LAB_RADIO_LINK_OK \
    ((ninlil_v1_lab_radio_link_status_t)0u)
#define NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT \
    ((ninlil_v1_lab_radio_link_status_t)1u)
#define NINLIL_V1_LAB_RADIO_LINK_BINDING \
    ((ninlil_v1_lab_radio_link_status_t)2u)
#define NINLIL_V1_LAB_RADIO_LINK_CAPACITY \
    ((ninlil_v1_lab_radio_link_status_t)3u)
#define NINLIL_V1_LAB_RADIO_LINK_CONFLICT \
    ((ninlil_v1_lab_radio_link_status_t)4u)
#define NINLIL_V1_LAB_RADIO_LINK_PHY \
    ((ninlil_v1_lab_radio_link_status_t)5u)
#define NINLIL_V1_LAB_RADIO_LINK_CORRUPT \
    ((ninlil_v1_lab_radio_link_status_t)6u)
#define NINLIL_V1_LAB_RADIO_LINK_FENCED \
    ((ninlil_v1_lab_radio_link_status_t)7u)

struct ninlil_v1_lab_radio_packet_link;

typedef struct ninlil_v1_lab_radio_path_port {
    uint8_t active;
    uint8_t open;
    uint8_t pair_slot;
    uint8_t original_flow;
    uint8_t path_id[16];
    ninlil_fabric_link_state_v1_t state;
    struct ninlil_v1_lab_radio_packet_link *owner;
    ninlil_fabric_packet_link_ops_v1_t ops;
} ninlil_v1_lab_radio_path_port_t;

typedef struct ninlil_v1_lab_radio_route {
    uint8_t active;
    uint8_t pair_slot;
    uint8_t flow;
    uint8_t receive;
    uint32_t hop_context_id;
    uint32_t e2e_context_id;
    ninlil_r7_frag_prod_bind_t *r7;
} ninlil_v1_lab_radio_route_t;

typedef struct ninlil_v1_lab_radio_link_tx {
    uint8_t active;
    uint8_t terminal;
    uint8_t port_index;
    uint8_t completion_kind;
    uint8_t r7_held;
    uint8_t r7_route_index;
    uint8_t reserved_zero[2];
    uint32_t generation;
    uint64_t candidate_token;
    uint8_t permit_id[16];
    uint8_t permit_clock_epoch_id[16];
    uint64_t tx_ok_before;
    uint64_t tx_timeout_before;
} ninlil_v1_lab_radio_link_tx_t;

typedef struct ninlil_v1_lab_radio_link_rx {
    uint8_t active;
    uint8_t loaned;
    uint8_t port_index;
    uint8_t reserved_zero;
    uint32_t generation;
    uint32_t mapper_receipt_token;
    uint32_t nfl1_length;
    uint8_t nfl1[NINLIL_V1_LAB_RADIO_NFL1_MAX];
} ninlil_v1_lab_radio_link_rx_t;

typedef struct ninlil_v1_lab_radio_packet_link {
    uint32_t magic;
    uint8_t closed;
    uint8_t route_count;
    uint8_t port_count;
    uint8_t reserved_zero;
    uint64_t owner_token;
    uint64_t next_candidate_token;
    uint32_t next_tx_generation;
    uint32_t next_rx_generation;
    ninlil_clock_ops_t clock;
    ninlil_sx1262_phy_t *phy;
    ninlil_v1_lab_radio_mapper_t mapper;
    ninlil_v1_lab_radio_route_t routes[NINLIL_V1_LAB_RADIO_LINK_PATH_MAX];
    ninlil_v1_lab_radio_path_port_t
        ports[NINLIL_V1_LAB_RADIO_LINK_PATH_MAX];
    ninlil_v1_lab_radio_link_tx_t tx;
    ninlil_v1_lab_radio_link_rx_t rx;
} ninlil_v1_lab_radio_packet_link_t;

ninlil_v1_lab_radio_link_status_t ninlil_v1_lab_radio_packet_link_init(
    ninlil_v1_lab_radio_packet_link_t *link,
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t local_runtime_id[16],
    const ninlil_clock_ops_t *clock,
    ninlil_sx1262_phy_t *phy);

/*
 * The two R7 binds are already configured by the board owner with the exact
 * directional N6 handles, shared R2/R1/R9 authorities and trusted time.
 */
ninlil_v1_lab_radio_link_status_t
ninlil_v1_lab_radio_packet_link_install_pair(
    ninlil_v1_lab_radio_packet_link_t *link,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    ninlil_r7_frag_prod_bind_t *a_to_b,
    ninlil_r7_frag_prod_bind_t *b_to_a,
    uint8_t *out_pair_slot);

/* Returns the exact private Fabric provider for one original Application flow. */
ninlil_v1_lab_radio_link_status_t
ninlil_v1_lab_radio_packet_link_path(
    ninlil_v1_lab_radio_packet_link_t *link,
    uint8_t pair_slot,
    uint8_t original_flow,
    const uint8_t **out_path_id,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops);

/* One bounded owner-task progress unit: PHY poll, one RX admit, or RX arm. */
ninlil_v1_lab_radio_link_status_t ninlil_v1_lab_radio_packet_link_step(
    ninlil_v1_lab_radio_packet_link_t *link);

void ninlil_v1_lab_radio_packet_link_clear(
    ninlil_v1_lab_radio_packet_link_t *link);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_RADIO_PACKET_LINK_H */
