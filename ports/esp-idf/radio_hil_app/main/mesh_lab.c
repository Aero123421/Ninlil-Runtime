#include "mesh_lab.h"

#include <limits.h>
#include <string.h>

enum {
    NJM1_BEACON = 1,
    NJM1_JOIN_REQUEST = 2,
    NJM1_JOIN_ACCEPT = 3,
    NJM1_DATA = 4,
    NJM1_ACK = 5,
    NJM1_HEADER_BYTES = 60,
    NJM1_CRC_BYTES = 4,
    NJM1_MAX_HOPS = 3,
    NJM1_BEACON_MS = 2000,
    NJM1_BEACON_JITTER_MS = 701,
    NJM1_CANDIDATE_MS = 12000,
    NJM1_ROUTE_MS = 30000,
    NJM1_LEASE_MS = 20000,
    NJM1_DISCOVERY_MS = 10000,
    NJM1_JOIN_RETRY_MS = 3000,
    NJM1_JOIN_RETRY_JITTER_MS = 701,
    NJM1_HYSTERESIS = 12,
    NJM1_TEST_EXCLUDE_PENALTY = 200
};

typedef struct njm1_view {
    uint8_t kind;
    uint8_t hops;
    uint8_t site[8];
    uint32_t epoch;
    uint32_t sequence;
    uint8_t origin[8];
    uint8_t sender[8];
    uint8_t next[8];
    uint8_t destination[8];
    const uint8_t *payload;
    uint8_t payload_length;
    uint8_t load;
} njm1_view_t;

static int id_zero(const uint8_t id[8])
{
    size_t i;
    uint8_t v = 0u;
    for (i = 0u; i < 8u; ++i) {
        v |= id[i];
    }
    return v == 0u;
}

static int id_equal(const uint8_t a[8], const uint8_t b[8])
{
    return memcmp(a, b, 8u) == 0;
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t crc32c(const uint8_t *bytes, size_t length)
{
    uint32_t crc = UINT32_MAX;
    size_t i;
    for (i = 0u; i < length; ++i) {
        uint8_t bit;
        crc ^= bytes[i];
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0x82f63b78u : 0u);
        }
    }
    return ~crc;
}

static uint32_t next_sequence(ninlil_mesh_lab_t *mesh)
{
    mesh->next_sequence += 1u;
    if (mesh->next_sequence == 0u) {
        mesh->next_sequence = 1u;
    }
    return mesh->next_sequence;
}

static uint32_t join_retry_delay_ms(const ninlil_mesh_lab_t *mesh,
    uint32_t sequence)
{
    uint32_t mix;

    /* Bounded deterministic dephasing prevents simultaneously booted nodes
     * from repeatedly colliding with the controller's beacon cadence. */
    mix = ((uint32_t)mesh->node_id[0] << 24)
        | ((uint32_t)mesh->node_id[1] << 16)
        | ((uint32_t)mesh->node_id[2] << 8)
        | (uint32_t)mesh->node_id[3];
    mix ^= sequence * 0x9e3779b9u;
    mix ^= mix >> 16;
    return NJM1_JOIN_RETRY_MS + (mix % NJM1_JOIN_RETRY_JITTER_MS);
}

uint32_t ninlil_mesh_lab_beacon_interval_ms(const uint8_t node_id[8],
    uint32_t sequence)
{
    uint32_t mix = 0u;
    size_t i;
    if (node_id == NULL) {
        return NJM1_BEACON_MS;
    }
    for (i = 0u; i < 8u; ++i) {
        mix = mix * 33u + node_id[i];
    }
    mix ^= sequence * 0x9e3779b9u;
    mix ^= mix >> 16;
    return NJM1_BEACON_MS + (mix % NJM1_BEACON_JITTER_MS);
}

static int encode(ninlil_mesh_lab_t *mesh, uint8_t kind, uint8_t hops,
    const uint8_t origin[8], const uint8_t sender[8], const uint8_t next[8],
    const uint8_t destination[8], uint32_t sequence, const uint8_t *payload,
    uint8_t payload_length, uint8_t load, ninlil_mesh_lab_tx_t *out)
{
    size_t length;
    if (mesh == NULL || out == NULL || kind < NJM1_BEACON || kind > NJM1_ACK
        || payload_length > NINLIL_MESH_LAB_PAYLOAD_MAX
        || (payload_length != 0u && payload == NULL)) {
        return 0;
    }
    length = NJM1_HEADER_BYTES + payload_length + NJM1_CRC_BYTES;
    memset(out, 0, sizeof(*out));
    memcpy(out->bytes, "NJM1", 4u);
    out->bytes[4] = 1u;
    out->bytes[5] = kind;
    out->bytes[7] = hops;
    memcpy(out->bytes + 8u, mesh->site_id, 8u);
    put_u32(out->bytes + 16u, mesh->site_epoch);
    put_u32(out->bytes + 20u, sequence);
    memcpy(out->bytes + 24u, origin, 8u);
    memcpy(out->bytes + 32u, sender, 8u);
    memcpy(out->bytes + 40u, next, 8u);
    memcpy(out->bytes + 48u, destination, 8u);
    out->bytes[56] = payload_length;
    out->bytes[57] = load;
    if (payload_length != 0u) {
        memcpy(out->bytes + NJM1_HEADER_BYTES, payload, payload_length);
    }
    put_u32(out->bytes + length - NJM1_CRC_BYTES,
        crc32c(out->bytes, length - NJM1_CRC_BYTES));
    out->length = (uint16_t)length;
    mesh->tx_count += 1u;
    return 1;
}

static int decode(const uint8_t *frame, size_t length, njm1_view_t *view)
{
    uint8_t payload_length;
    if (frame == NULL || view == NULL || length < 64u
        || length > NINLIL_MESH_LAB_FRAME_MAX
        || memcmp(frame, "NJM1", 4u) != 0 || frame[4] != 1u
        || frame[5] < NJM1_BEACON || frame[5] > NJM1_ACK
        || frame[6] != 0u || frame[58] != 0u || frame[59] != 0u) {
        return 0;
    }
    payload_length = frame[56];
    if (payload_length > NINLIL_MESH_LAB_PAYLOAD_MAX
        || length != NJM1_HEADER_BYTES + payload_length + NJM1_CRC_BYTES
        || get_u32(frame + length - NJM1_CRC_BYTES)
            != crc32c(frame, length - NJM1_CRC_BYTES)) {
        return 0;
    }
    memset(view, 0, sizeof(*view));
    view->kind = frame[5];
    view->hops = frame[7];
    memcpy(view->site, frame + 8u, 8u);
    view->epoch = get_u32(frame + 16u);
    view->sequence = get_u32(frame + 20u);
    memcpy(view->origin, frame + 24u, 8u);
    memcpy(view->sender, frame + 32u, 8u);
    memcpy(view->next, frame + 40u, 8u);
    memcpy(view->destination, frame + 48u, 8u);
    view->payload_length = payload_length;
    view->load = frame[57];
    view->payload = frame + NJM1_HEADER_BYTES;
    if (id_zero(view->site) || view->epoch == 0u || view->sequence == 0u
        || id_zero(view->origin) || id_zero(view->sender)) {
        return 0;
    }
    if (view->kind == NJM1_BEACON) {
        return view->hops < NJM1_MAX_HOPS && id_zero(view->next)
            && id_zero(view->destination) && view->payload_length == 8u
            && !id_zero(view->payload);
    }
    return view->hops > 0u && view->hops <= NJM1_MAX_HOPS
        && !id_zero(view->next) && !id_zero(view->destination);
}

static void clear_membership(ninlil_mesh_lab_t *mesh)
{
    memset(mesh->site_id, 0, 8u);
    memset(mesh->controller_id, 0, 8u);
    memset(mesh->parent_id, 0, 8u);
    memset(mesh->candidates, 0, sizeof(mesh->candidates));
    memset(mesh->routes, 0, sizeof(mesh->routes));
    memset(mesh->seen, 0, sizeof(mesh->seen));
    mesh->route_cursor = 0u;
    mesh->seen_cursor = 0u;
    mesh->site_epoch = 0u;
    mesh->joined = 0u;
    mesh->joining = 0u;
    mesh->hops = 0u;
    mesh->parent_score = UINT16_MAX;
    mesh->parent_last_seen_ms = 0u;
    mesh->lease_until_ms = 0u;
    mesh->next_beacon_ms = 0u;
    mesh->next_join_ms = 0u;
}

void ninlil_mesh_lab_init(ninlil_mesh_lab_t *mesh, const uint8_t node_id[8])
{
    if (mesh == NULL || node_id == NULL || id_zero(node_id)) {
        return;
    }
    memset(mesh, 0, sizeof(*mesh));
    memcpy(mesh->node_id, node_id, 8u);
    mesh->next_sequence = get_u32(node_id + 4u);
    mesh->parent_score = UINT16_MAX;
}

int ninlil_mesh_lab_become_controller(ninlil_mesh_lab_t *mesh,
    const uint8_t site_id[8], uint32_t site_epoch, uint64_t now_ms)
{
    if (mesh == NULL || id_zero(mesh->node_id) || site_id == NULL
        || id_zero(site_id) || site_epoch == 0u) {
        return 0;
    }
    clear_membership(mesh);
    mesh->controller = 1u;
    mesh->joined = 1u;
    memcpy(mesh->site_id, site_id, 8u);
    memcpy(mesh->controller_id, mesh->node_id, 8u);
    mesh->site_epoch = site_epoch;
    mesh->next_beacon_ms = now_ms;
    mesh->lease_until_ms = UINT64_MAX;
    return 1;
}

void ninlil_mesh_lab_become_node(ninlil_mesh_lab_t *mesh)
{
    if (mesh == NULL) {
        return;
    }
    mesh->controller = 0u;
    clear_membership(mesh);
}

void ninlil_mesh_lab_leave(ninlil_mesh_lab_t *mesh)
{
    if (mesh != NULL && mesh->controller == 0u) {
        clear_membership(mesh);
    }
}

void ninlil_mesh_lab_maintain(ninlil_mesh_lab_t *mesh, uint64_t now_ms)
{
    if (mesh == NULL || mesh->controller) {
        return;
    }
    if (!id_zero(mesh->site_id) && now_ms >= mesh->lease_until_ms
        && mesh->lease_until_ms != 0u) {
        clear_membership(mesh);
    }
    if (mesh->joined && now_ms - mesh->parent_last_seen_ms > NJM1_CANDIDATE_MS) {
        mesh->joined = 0u;
        mesh->joining = 0u;
    }
}

int ninlil_mesh_lab_set_test_penalty(ninlil_mesh_lab_t *mesh,
    const uint8_t parent_id[8], uint8_t penalty)
{
    if (mesh == NULL || parent_id == NULL || id_zero(parent_id)) {
        return 0;
    }
    memcpy(mesh->penalty_parent, parent_id, 8u);
    mesh->penalty = penalty;
    return 1;
}

static void learn_route(ninlil_mesh_lab_t *mesh, const uint8_t destination[8],
    const uint8_t next_hop[8], uint64_t now_ms)
{
    size_t i;
    size_t slot = sizeof(mesh->routes) / sizeof(mesh->routes[0]);
    for (i = 0u; i < sizeof(mesh->routes) / sizeof(mesh->routes[0]); ++i) {
        if (mesh->routes[i].active && id_equal(mesh->routes[i].destination, destination)) {
            slot = i;
            break;
        }
        if (!mesh->routes[i].active && slot == sizeof(mesh->routes) / sizeof(mesh->routes[0])) {
            slot = i;
        }
    }
    if (slot == sizeof(mesh->routes) / sizeof(mesh->routes[0])) {
        slot = mesh->route_cursor++ % (sizeof(mesh->routes) / sizeof(mesh->routes[0]));
    }
    mesh->routes[slot].active = 1u;
    memcpy(mesh->routes[slot].destination, destination, 8u);
    memcpy(mesh->routes[slot].next_hop, next_hop, 8u);
    mesh->routes[slot].last_seen_ms = now_ms;
}

static int route_to(const ninlil_mesh_lab_t *mesh, const uint8_t destination[8],
    uint64_t now_ms, uint8_t next_hop[8])
{
    size_t i;
    if (!mesh->controller && id_equal(destination, mesh->controller_id)
        && !id_zero(mesh->parent_id)) {
        memcpy(next_hop, mesh->parent_id, 8u);
        return 1;
    }
    for (i = 0u; i < sizeof(mesh->routes) / sizeof(mesh->routes[0]); ++i) {
        if (mesh->routes[i].active
            && now_ms - mesh->routes[i].last_seen_ms <= NJM1_ROUTE_MS
            && id_equal(mesh->routes[i].destination, destination)) {
            memcpy(next_hop, mesh->routes[i].next_hop, 8u);
            return 1;
        }
    }
    return 0;
}

static int seen_before(ninlil_mesh_lab_t *mesh, const njm1_view_t *view)
{
    size_t i;
    size_t slot;
    for (i = 0u; i < sizeof(mesh->seen) / sizeof(mesh->seen[0]); ++i) {
        if (mesh->seen[i].active && mesh->seen[i].kind == view->kind
            && mesh->seen[i].sequence == view->sequence
            && id_equal(mesh->seen[i].origin, view->origin)) {
            mesh->duplicate_count += 1u;
            return 1;
        }
    }
    slot = mesh->seen_cursor++ % (sizeof(mesh->seen) / sizeof(mesh->seen[0]));
    mesh->seen[slot].active = 1u;
    mesh->seen[slot].kind = view->kind;
    mesh->seen[slot].sequence = view->sequence;
    memcpy(mesh->seen[slot].origin, view->origin, 8u);
    return 0;
}

static uint16_t candidate_score(const ninlil_mesh_lab_t *mesh,
    const uint8_t parent[8], uint8_t advertised_hops, int16_t rssi, int8_t snr,
    uint8_t load)
{
    int32_t penalty = -rssi - 40;
    uint32_t score;
    if (penalty < 0) {
        penalty = 0;
    }
    if (penalty > 120) {
        penalty = 120;
    }
    if (snr < 0) {
        penalty += -(int32_t)snr * 2;
    }
    score = (uint32_t)(advertised_hops + 1u) * 32u + (uint32_t)penalty
        + (load > 100u ? 100u : load);
    if (mesh->penalty != 0u && mesh->penalty < NJM1_TEST_EXCLUDE_PENALTY
        && id_equal(parent, mesh->penalty_parent)) {
        score += mesh->penalty;
    }
    return score > UINT16_MAX ? UINT16_MAX : (uint16_t)score;
}

static ninlil_mesh_lab_candidate_t *candidate_update(ninlil_mesh_lab_t *mesh,
    const njm1_view_t *view, int16_t rssi, int8_t snr, uint64_t now_ms)
{
    size_t i;
    size_t slot = sizeof(mesh->candidates) / sizeof(mesh->candidates[0]);
    for (i = 0u; i < sizeof(mesh->candidates) / sizeof(mesh->candidates[0]); ++i) {
        if (mesh->candidates[i].active
            && id_equal(mesh->candidates[i].node_id, view->sender)) {
            slot = i;
            break;
        }
        if (!mesh->candidates[i].active
            && slot == sizeof(mesh->candidates) / sizeof(mesh->candidates[0])) {
            slot = i;
        }
    }
    if (slot == sizeof(mesh->candidates) / sizeof(mesh->candidates[0])) {
        return NULL;
    }
    mesh->candidates[slot].active = 1u;
    memcpy(mesh->candidates[slot].node_id, view->sender, 8u);
    memcpy(mesh->candidates[slot].controller_id, view->payload, 8u);
    memcpy(mesh->candidates[slot].site_id, view->site, 8u);
    mesh->candidates[slot].site_epoch = view->epoch;
    mesh->candidates[slot].score = candidate_score(
        mesh, view->sender, view->hops, rssi, snr, view->load);
    mesh->candidates[slot].advertised_hops = view->hops;
    if (mesh->candidates[slot].observations < UINT8_MAX) {
        mesh->candidates[slot].observations += 1u;
    }
    mesh->candidates[slot].last_seen_ms = now_ms;
    return &mesh->candidates[slot];
}

static ninlil_mesh_lab_candidate_t *best_candidate(ninlil_mesh_lab_t *mesh,
    uint64_t now_ms)
{
    size_t i;
    ninlil_mesh_lab_candidate_t *best = NULL;
    for (i = 0u; i < sizeof(mesh->candidates) / sizeof(mesh->candidates[0]); ++i) {
        ninlil_mesh_lab_candidate_t *candidate = &mesh->candidates[i];
        if (!candidate->active || candidate->observations < 2u
            || now_ms - candidate->last_seen_ms > NJM1_CANDIDATE_MS
            || candidate->advertised_hops + 1u > NJM1_MAX_HOPS) {
            continue;
        }
        if (mesh->penalty == NJM1_TEST_EXCLUDE_PENALTY
            && id_equal(candidate->node_id, mesh->penalty_parent)) {
            continue; /* Explicit desk-HIL topology exclusion. */
        }
        if (!id_zero(mesh->site_id)
            && (!id_equal(mesh->site_id, candidate->site_id)
                || mesh->site_epoch != candidate->site_epoch)) {
            continue;
        }
        /* A same-site parent must be upstream in the controller tree. Keep
         * this invariant even after a parent is lost, until lease expiry
         * clears the old hop depth. */
        if (mesh->hops != 0u
            && candidate->advertised_hops >= mesh->hops) {
            continue;
        }
        if (best == NULL || candidate->score < best->score) {
            best = candidate;
        }
    }
    return best;
}

static int join_via(ninlil_mesh_lab_t *mesh,
    const ninlil_mesh_lab_candidate_t *candidate, uint64_t now_ms,
    ninlil_mesh_lab_tx_t *out)
{
    uint8_t old_parent[8];
    uint32_t sequence;
    memcpy(old_parent, mesh->parent_id, 8u);
    memcpy(mesh->site_id, candidate->site_id, 8u);
    memcpy(mesh->controller_id, candidate->controller_id, 8u);
    memcpy(mesh->parent_id, candidate->node_id, 8u);
    mesh->site_epoch = candidate->site_epoch;
    mesh->hops = (uint8_t)(candidate->advertised_hops + 1u);
    mesh->parent_score = candidate->score;
    mesh->parent_last_seen_ms = now_ms;
    mesh->joining = 1u;
    mesh->next_beacon_ms = 0u;
    sequence = next_sequence(mesh);
    mesh->next_join_ms = now_ms + join_retry_delay_ms(mesh, sequence);
    if (!id_equal(old_parent, mesh->parent_id)) {
        mesh->route_change_count += 1u;
    }
    return encode(mesh, NJM1_JOIN_REQUEST, NJM1_MAX_HOPS, mesh->node_id,
        mesh->node_id, mesh->parent_id, mesh->controller_id,
        sequence, NULL, 0u, 0u, out);
}

int ninlil_mesh_lab_tick(ninlil_mesh_lab_t *mesh, uint64_t now_ms,
    ninlil_mesh_lab_tx_t *out)
{
    ninlil_mesh_lab_candidate_t *best;
    uint8_t zero[8] = {0};
    if (mesh == NULL || out == NULL || id_zero(mesh->node_id)) {
        return 0;
    }
    out->length = 0u;
    ninlil_mesh_lab_maintain(mesh, now_ms);
    if (!mesh->controller && (!mesh->joined || mesh->joining)
        && now_ms >= mesh->next_join_ms) {
        best = best_candidate(mesh, now_ms);
        if (best != NULL) {
            return join_via(mesh, best, now_ms, out);
        }
    }
    if (mesh->controller && now_ms >= mesh->next_beacon_ms) {
        uint32_t sequence = next_sequence(mesh);
        mesh->next_beacon_ms = now_ms
            + ninlil_mesh_lab_beacon_interval_ms(mesh->node_id, sequence);
        return encode(mesh, NJM1_BEACON, mesh->hops, mesh->node_id,
            mesh->node_id, zero, zero, sequence,
            mesh->controller_id, 8u, 0u, out);
    }
    if (!mesh->controller && mesh->joined && mesh->next_beacon_ms != 0u
        && now_ms >= mesh->next_beacon_ms) {
        uint32_t sequence = next_sequence(mesh);
        mesh->next_beacon_ms = 0u;
        return encode(mesh, NJM1_BEACON, mesh->hops, mesh->node_id,
            mesh->node_id, zero, zero, sequence,
            mesh->controller_id, 8u, 0u, out);
    }
    return 0;
}

static int forward(ninlil_mesh_lab_t *mesh, const njm1_view_t *view,
    const uint8_t next_hop[8], ninlil_mesh_lab_tx_t *out)
{
    if (view->hops <= 1u) {
        return 0;
    }
    mesh->relay_count += 1u;
    return encode(mesh, view->kind, (uint8_t)(view->hops - 1u),
        view->origin, mesh->node_id, next_hop, view->destination,
        view->sequence, view->payload, view->payload_length, 0u, out);
}

int ninlil_mesh_lab_receive(ninlil_mesh_lab_t *mesh,
    const uint8_t *frame, size_t frame_length, int16_t rssi_dbm,
    int8_t snr_db, uint64_t now_ms, ninlil_mesh_lab_tx_t *out,
    ninlil_mesh_lab_event_t *event)
{
    njm1_view_t view;
    uint8_t next_hop[8];
    if (mesh == NULL || out == NULL || event == NULL
        || !decode(frame, frame_length, &view) || id_equal(view.sender, mesh->node_id)) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    memset(event, 0, sizeof(*event));
    mesh->rx_count += 1u;
    if (view.kind == NJM1_BEACON) {
        ninlil_mesh_lab_candidate_t *candidate;
        if (mesh->controller
            || (!id_zero(mesh->site_id)
                && (!id_equal(mesh->site_id, view.site)
                    || mesh->site_epoch != view.epoch))) {
            return 1;
        }
        candidate = candidate_update(mesh, &view, rssi_dbm, snr_db, now_ms);
        /* At first discovery, collect a bounded set of valid candidates
         * before committing to the first one that reaches two observations. */
        if (!mesh->joined && id_zero(mesh->site_id)
            && mesh->next_join_ms == 0u) {
            mesh->next_join_ms = now_ms + NJM1_DISCOVERY_MS;
        }
        if (candidate != NULL && id_equal(candidate->node_id, mesh->parent_id)) {
            mesh->parent_last_seen_ms = now_ms;
            mesh->parent_score = candidate->score;
            /* A valid beacon from the selected parent proves the current
             * site remains reachable; keep its Join lease alive. */
            if (mesh->joined) {
                mesh->lease_until_ms = now_ms + NJM1_LEASE_MS;
                mesh->next_beacon_ms = now_ms
                    + NINLIL_MESH_LAB_RELAY_BEACON_DELAY_MS;
            }
        }
        if (!mesh->joined && now_ms >= mesh->next_join_ms) {
            ninlil_mesh_lab_candidate_t *best = best_candidate(mesh, now_ms);
            if (best != NULL) {
                return join_via(mesh, best, now_ms, out);
            }
        }
        if (mesh->joined && candidate != NULL && candidate->observations >= 2u
            && !(mesh->penalty == NJM1_TEST_EXCLUDE_PENALTY
                && id_equal(candidate->node_id, mesh->penalty_parent))
            && candidate->advertised_hops < mesh->hops
            && candidate->score + NJM1_HYSTERESIS < mesh->parent_score) {
            event->kind = NINLIL_MESH_LAB_EVENT_ROUTE_CHANGED;
            return join_via(mesh, candidate, now_ms, out);
        }
        return 1;
    }
    if (!id_equal(view.next, mesh->node_id)
        || !id_equal(view.site, mesh->site_id) || view.epoch != mesh->site_epoch
        || seen_before(mesh, &view)) {
        return 0;
    }
    learn_route(mesh, view.origin, view.sender, now_ms);
    if (id_equal(view.sender, mesh->parent_id)) {
        mesh->parent_last_seen_ms = now_ms;
    }
    if (!id_equal(view.destination, mesh->node_id)) {
        if (!route_to(mesh, view.destination, now_ms, next_hop)) {
            return 0;
        }
        return forward(mesh, &view, next_hop, out);
    }
    memcpy(event->source, view.origin, 8u);
    if (view.kind == NJM1_JOIN_REQUEST && mesh->controller) {
        uint8_t lease[2] = {0u, 20u};
        if (!route_to(mesh, view.origin, now_ms, next_hop)) {
            return 0;
        }
        return encode(mesh, NJM1_JOIN_ACCEPT, NJM1_MAX_HOPS, mesh->node_id,
            mesh->node_id, next_hop, view.origin, next_sequence(mesh),
            lease, 2u, 0u, out);
    }
    if (view.kind == NJM1_JOIN_ACCEPT && !mesh->controller
        && view.payload_length == 2u) {
        uint16_t seconds = (uint16_t)(((uint16_t)view.payload[0] << 8)
            | view.payload[1]);
        if (seconds == 0u) {
            return 0;
        }
        mesh->joined = 1u;
        mesh->joining = 0u;
        mesh->lease_until_ms = now_ms + (uint64_t)seconds * 1000u;
        mesh->next_beacon_ms = now_ms + NINLIL_MESH_LAB_RELAY_BEACON_DELAY_MS;
        event->kind = NINLIL_MESH_LAB_EVENT_JOINED;
        return 1;
    }
    if (view.kind == NJM1_DATA) {
        uint8_t ack[4];
        event->kind = NINLIL_MESH_LAB_EVENT_DATA;
        event->payload_length = view.payload_length;
        memcpy(event->payload, view.payload, view.payload_length);
        if (!route_to(mesh, view.origin, now_ms, next_hop)) {
            return 1;
        }
        put_u32(ack, view.sequence);
        (void)encode(mesh, NJM1_ACK, NJM1_MAX_HOPS, mesh->node_id,
            mesh->node_id, next_hop, view.origin, next_sequence(mesh),
            ack, 4u, 0u, out);
        return 1;
    }
    if (view.kind == NJM1_ACK && view.payload_length == 4u) {
        event->kind = NINLIL_MESH_LAB_EVENT_ACK;
        memcpy(event->payload, view.payload, 4u);
        event->payload_length = 4u;
        return 1;
    }
    return 0;
}

int ninlil_mesh_lab_send_data(ninlil_mesh_lab_t *mesh,
    const uint8_t destination[8], const uint8_t *payload,
    uint8_t payload_length, uint64_t now_ms, ninlil_mesh_lab_tx_t *out)
{
    uint8_t next_hop[8];
    if (mesh == NULL || destination == NULL || id_zero(destination)
        || payload == NULL || payload_length == 0u
        || payload_length > NINLIL_MESH_LAB_PAYLOAD_MAX
        || (!mesh->controller && !mesh->joined)
        || !route_to(mesh, destination, now_ms, next_hop)) {
        return 0;
    }
    return encode(mesh, NJM1_DATA, NJM1_MAX_HOPS, mesh->node_id,
        mesh->node_id, next_hop, destination, next_sequence(mesh),
        payload, payload_length, 0u, out);
}

int ninlil_mesh_lab_tx_requires_ack(const ninlil_mesh_lab_t *mesh,
    const ninlil_mesh_lab_tx_t *tx)
{
    return mesh != NULL && tx != NULL && tx->length >= 64u
        && tx->bytes[5] == NJM1_DATA
        && id_equal(tx->bytes + 24u, mesh->node_id);
}

int ninlil_mesh_lab_ack_matches_tx(const ninlil_mesh_lab_tx_t *tx,
    const ninlil_mesh_lab_event_t *event)
{
    return tx != NULL && event != NULL && tx->length >= 64u
        && tx->bytes[5] == NJM1_DATA
        && event->kind == NINLIL_MESH_LAB_EVENT_ACK
        && event->payload_length == 4u
        && memcmp(tx->bytes + 20u, event->payload, 4u) == 0;
}

int ninlil_mesh_lab_retry_data(ninlil_mesh_lab_t *mesh,
    const ninlil_mesh_lab_tx_t *previous, uint64_t now_ms,
    ninlil_mesh_lab_tx_t *out)
{
    if (!ninlil_mesh_lab_tx_requires_ack(mesh, previous)) {
        return 0;
    }
    return ninlil_mesh_lab_send_data(mesh, previous->bytes + 48u,
        previous->bytes + NJM1_HEADER_BYTES, previous->bytes[56], now_ms, out);
}

int ninlil_mesh_lab_selected_parent_beacon(const ninlil_mesh_lab_t *mesh,
    const uint8_t *frame, size_t frame_length)
{
    njm1_view_t view;

    return mesh != NULL && mesh->joined && !mesh->controller
        && decode(frame, frame_length, &view) && view.kind == NJM1_BEACON
        && id_equal(view.sender, mesh->parent_id)
        && id_equal(view.site, mesh->site_id) && view.epoch == mesh->site_epoch;
}

uint64_t ninlil_mesh_lab_data_ack_retry_at(const uint8_t node_id[8],
    uint32_t sequence, uint8_t attempt, uint64_t sent_at_ms)
{
    uint32_t mix = sequence ^ ((uint32_t)attempt * 0x9e3779b9u);
    size_t i;

    if (node_id != NULL) {
        for (i = 0u; i < 8u; ++i) {
            mix = mix * 33u + node_id[i];
        }
    }
    mix ^= mix >> 16;
    return sent_at_ms + NINLIL_MESH_LAB_DATA_ACK_WAIT_MS
        + (mix % NINLIL_MESH_LAB_DATA_ACK_RETRY_JITTER_MS);
}

uint64_t ninlil_mesh_lab_response_not_before(uint64_t received_at_ms)
{
    return received_at_ms + NINLIL_MESH_LAB_TURNAROUND_GUARD_MS;
}

uint64_t ninlil_mesh_lab_data_after_parent_not_before(
    uint64_t parent_beacon_received_at_ms)
{
    return parent_beacon_received_at_ms
        + NINLIL_MESH_LAB_DATA_AFTER_PARENT_GUARD_MS;
}

int ninlil_mesh_lab_tx_due(uint64_t now_ms, uint64_t not_before_ms)
{
    return now_ms >= not_before_ms;
}

uint64_t ninlil_mesh_lab_response_dwell_until(
    const ninlil_mesh_lab_tx_t *tx, uint64_t sent_at_ms)
{
    if (tx != NULL && tx->length > 5u && tx->bytes[5] >= NJM1_JOIN_REQUEST
        && tx->bytes[5] <= NJM1_ACK) {
        return sent_at_ms + NINLIL_MESH_LAB_RESPONSE_DWELL_MS;
    }
    return sent_at_ms;
}

int ninlil_mesh_lab_periodic_tx_due(uint64_t now_ms, uint64_t dwell_until_ms)
{
    return now_ms >= dwell_until_ms;
}

void ninlil_mesh_lab_snapshot(const ninlil_mesh_lab_t *mesh,
    ninlil_mesh_lab_snapshot_t *out)
{
    if (mesh == NULL || out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->node_id, mesh->node_id, 8u);
    memcpy(out->site_id, mesh->site_id, 8u);
    memcpy(out->controller_id, mesh->controller_id, 8u);
    memcpy(out->parent_id, mesh->parent_id, 8u);
    out->site_epoch = mesh->site_epoch;
    out->controller = mesh->controller;
    out->joined = mesh->joined;
    out->joining = mesh->joining;
    out->hops = mesh->hops;
    out->lease_until_ms = mesh->lease_until_ms;
    out->tx_count = mesh->tx_count;
    out->rx_count = mesh->rx_count;
    out->relay_count = mesh->relay_count;
    out->duplicate_count = mesh->duplicate_count;
    out->route_change_count = mesh->route_change_count;
}
