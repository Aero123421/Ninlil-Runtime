#ifndef NINLIL_RADIO_HIL_MESH_LAB_H
#define NINLIL_RADIO_HIL_MESH_LAB_H

#include <stddef.h>
#include <stdint.h>

#define NINLIL_MESH_LAB_FRAME_MAX 128u
#define NINLIL_MESH_LAB_PAYLOAD_MAX 64u
#define NINLIL_MESH_LAB_NODE_ID_BYTES 8u
#define NINLIL_MESH_LAB_TURNAROUND_GUARD_MS 225u
#define NINLIL_MESH_LAB_DATA_AFTER_PARENT_GUARD_MS 500u
#define NINLIL_MESH_LAB_RESPONSE_DWELL_MS 1500u
#define NINLIL_MESH_LAB_DATA_ACK_WAIT_MS 3000u
#define NINLIL_MESH_LAB_DATA_ACK_RETRY_JITTER_MS 701u
#define NINLIL_MESH_LAB_RELAY_BEACON_DELAY_MS 500u
#define NINLIL_MESH_LAB_TOPOLOGY_MAX 8u
#define NINLIL_MESH_LAB_TOPOLOGY_STALE_MS 60000u
#define NINLIL_MESH_LAB_ROUTE_TTL_MS 60000u
#define NINLIL_MESH_LAB_TOPOLOGY_HEARTBEAT_MAX_MS 20700u

typedef enum ninlil_mesh_lab_event_kind {
    NINLIL_MESH_LAB_EVENT_NONE = 0,
    NINLIL_MESH_LAB_EVENT_JOINED = 1,
    NINLIL_MESH_LAB_EVENT_ROUTE_CHANGED = 2,
    NINLIL_MESH_LAB_EVENT_DATA = 3,
    NINLIL_MESH_LAB_EVENT_ACK = 4,
    NINLIL_MESH_LAB_EVENT_LEFT = 5
} ninlil_mesh_lab_event_kind_t;

typedef struct ninlil_mesh_lab_tx {
    uint8_t bytes[NINLIL_MESH_LAB_FRAME_MAX];
    uint16_t length;
} ninlil_mesh_lab_tx_t;

typedef struct ninlil_mesh_lab_event {
    ninlil_mesh_lab_event_kind_t kind;
    uint8_t source[NINLIL_MESH_LAB_NODE_ID_BYTES];
    uint8_t payload[NINLIL_MESH_LAB_PAYLOAD_MAX];
    uint8_t payload_length;
} ninlil_mesh_lab_event_t;

typedef struct ninlil_mesh_lab_candidate {
    uint8_t active;
    uint8_t node_id[8];
    uint8_t controller_id[8];
    uint8_t site_id[8];
    uint32_t site_epoch;
    uint16_t score;
    uint8_t advertised_hops;
    uint8_t observations;
    int8_t rssi_dbm;
    int8_t snr_db;
    uint64_t last_seen_ms;
} ninlil_mesh_lab_candidate_t;

typedef struct ninlil_mesh_lab_route {
    uint8_t active;
    uint8_t destination[8];
    uint8_t next_hop[8];
    uint64_t last_seen_ms;
} ninlil_mesh_lab_route_t;

typedef struct ninlil_mesh_lab_seen {
    uint8_t active;
    uint8_t kind;
    uint8_t origin[8];
    uint32_t sequence;
} ninlil_mesh_lab_seen_t;

typedef struct ninlil_mesh_lab_topology {
    uint8_t active;
    uint8_t node_id[8];
    uint8_t parent_id[8];
    uint8_t hops;
    int8_t link_rssi_dbm;
    int8_t link_snr_db;
    uint64_t last_seen_ms;
} ninlil_mesh_lab_topology_t;

typedef struct ninlil_mesh_lab {
    uint8_t node_id[8];
    uint8_t site_id[8];
    uint8_t controller_id[8];
    uint8_t parent_id[8];
    uint8_t penalty_parent[8];
    uint32_t site_epoch;
    uint32_t next_sequence;
    uint8_t controller;
    uint8_t joined;
    uint8_t joining;
    uint8_t hops;
    uint8_t penalty;
    uint8_t seen_cursor;
    uint8_t route_cursor;
    uint16_t parent_score;
    uint64_t parent_last_seen_ms;
    uint64_t lease_until_ms;
    uint64_t next_beacon_ms;
    uint64_t next_join_ms;
    uint64_t next_topology_ms;
    int8_t parent_rssi_dbm;
    int8_t parent_snr_db;
    uint32_t tx_count;
    uint32_t rx_count;
    uint32_t relay_count;
    uint32_t duplicate_count;
    uint32_t route_change_count;
    ninlil_mesh_lab_candidate_t candidates[6];
    ninlil_mesh_lab_route_t routes[8];
    ninlil_mesh_lab_seen_t seen[12];
    ninlil_mesh_lab_topology_t topology[NINLIL_MESH_LAB_TOPOLOGY_MAX];
} ninlil_mesh_lab_t;

typedef struct ninlil_mesh_lab_snapshot {
    uint8_t node_id[8];
    uint8_t site_id[8];
    uint8_t controller_id[8];
    uint8_t parent_id[8];
    uint32_t site_epoch;
    uint8_t controller;
    uint8_t joined;
    uint8_t joining;
    uint8_t hops;
    uint64_t lease_until_ms;
    uint32_t tx_count;
    uint32_t rx_count;
    uint32_t relay_count;
    uint32_t duplicate_count;
    uint32_t route_change_count;
} ninlil_mesh_lab_snapshot_t;

void ninlil_mesh_lab_init(ninlil_mesh_lab_t *mesh, const uint8_t node_id[8]);
int ninlil_mesh_lab_become_controller(ninlil_mesh_lab_t *mesh,
    const uint8_t site_id[8], uint32_t site_epoch, uint64_t now_ms);
void ninlil_mesh_lab_become_node(ninlil_mesh_lab_t *mesh);
void ninlil_mesh_lab_leave(ninlil_mesh_lab_t *mesh);
void ninlil_mesh_lab_maintain(ninlil_mesh_lab_t *mesh, uint64_t now_ms);
int ninlil_mesh_lab_set_test_penalty(ninlil_mesh_lab_t *mesh,
    const uint8_t parent_id[8], uint8_t penalty);
int ninlil_mesh_lab_tick(ninlil_mesh_lab_t *mesh, uint64_t now_ms,
    ninlil_mesh_lab_tx_t *out);
int ninlil_mesh_lab_receive(ninlil_mesh_lab_t *mesh,
    const uint8_t *frame, size_t frame_length, int16_t rssi_dbm,
    int8_t snr_db, uint64_t now_ms, ninlil_mesh_lab_tx_t *out,
    ninlil_mesh_lab_event_t *event);
int ninlil_mesh_lab_send_data(ninlil_mesh_lab_t *mesh,
    const uint8_t destination[8], const uint8_t *payload,
    uint8_t payload_length, uint64_t now_ms, ninlil_mesh_lab_tx_t *out);
int ninlil_mesh_lab_tx_requires_ack(const ninlil_mesh_lab_t *mesh,
    const ninlil_mesh_lab_tx_t *tx);
int ninlil_mesh_lab_ack_matches_tx(const ninlil_mesh_lab_tx_t *tx,
    const ninlil_mesh_lab_event_t *event);
int ninlil_mesh_lab_retry_data(ninlil_mesh_lab_t *mesh,
    const ninlil_mesh_lab_tx_t *previous, uint64_t now_ms,
    ninlil_mesh_lab_tx_t *out);
int ninlil_mesh_lab_selected_parent_beacon(const ninlil_mesh_lab_t *mesh,
    const uint8_t *frame, size_t frame_length);
uint64_t ninlil_mesh_lab_data_ack_retry_at(
    const uint8_t node_id[NINLIL_MESH_LAB_NODE_ID_BYTES], uint32_t sequence,
    uint8_t attempt, uint64_t sent_at_ms);
uint64_t ninlil_mesh_lab_response_not_before(uint64_t received_at_ms);
uint64_t ninlil_mesh_lab_data_after_parent_not_before(
    uint64_t parent_beacon_received_at_ms);
int ninlil_mesh_lab_tx_due(uint64_t now_ms, uint64_t not_before_ms);
uint64_t ninlil_mesh_lab_response_dwell_until(
    const ninlil_mesh_lab_tx_t *tx, uint64_t sent_at_ms);
int ninlil_mesh_lab_periodic_tx_due(uint64_t now_ms, uint64_t dwell_until_ms);
uint32_t ninlil_mesh_lab_beacon_interval_ms(
    const uint8_t node_id[NINLIL_MESH_LAB_NODE_ID_BYTES], uint32_t sequence);
size_t ninlil_mesh_lab_topology_snapshot(const ninlil_mesh_lab_t *mesh,
    uint64_t now_ms, ninlil_mesh_lab_topology_t *out, size_t out_count);
void ninlil_mesh_lab_snapshot(const ninlil_mesh_lab_t *mesh,
    ninlil_mesh_lab_snapshot_t *out);

#endif
