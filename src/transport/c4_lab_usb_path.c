#include "c4_lab_usb_path.h"

#include <string.h>

#define NINLIL_C4_LAB_USB_MAGIC ((uint32_t)0x42554C34u) /* '4LUB' LE */

#define C4_WIRE_HDR_BYTES 16u
#define C4_WIRE_TYPE_CUSTODY_OFFER 1u
#define C4_WIRE_TYPE_CUSTODY_ACCEPT 2u

struct ninlil_c4_lab_usb {
    uint32_t magic;
    uint32_t lifecycle;
    ninlil_logical_session_object_t session_obj;
    ninlil_logical_session_t *session;
    ninlil_logical_session_role_t role;
    uint32_t owner_token;
    ninlil_byte_stream_t *stream;
    ninlil_c4_lab_usb_t *peer;
    ninlil_c4_lab_usb_link_state_t link_state;
    uint16_t control_version;
    uint32_t assignment_epoch;
    uint32_t pending_token;
    uint32_t pending_len;
    uint8_t pending_payload[NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES];
    uint8_t held_payload[NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES];
    uint32_t held_len;
    uint32_t held_token;
    uint8_t held_valid;
    uint8_t rx_buf[2048];
    uint32_t rx_len;
    ninlil_c4_lab_usb_diag_t diag;
};

_Static_assert(
    sizeof(ninlil_c4_lab_usb_t) <= NINLIL_C4_LAB_USB_OBJECT_BYTES,
    "c4_lab_usb object exceeds OBJECT_BYTES ceiling");

static uint32_t crc32_fold(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    uint32_t i;
    uint32_t bit;

    for (i = 0u; i < len; ++i) {
        crc ^= (uint32_t)data[i];
        for (bit = 0u; bit < 8u; ++bit) {
            if ((crc & 1u) != 0u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static void store_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xFFu);
    out[1] = (uint8_t)((v >> 16) & 0xFFu);
    out[2] = (uint8_t)((v >> 8) & 0xFFu);
    out[3] = (uint8_t)(v & 0xFFu);
}

static void store_u16_be(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)((v >> 8) & 0xFFu);
    out[1] = (uint8_t)(v & 0xFFu);
}

static uint32_t load_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint16_t load_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static void update_link_state(ninlil_c4_lab_usb_t *path)
{
    ninlil_logical_session_state_t st;

    if (path == NULL) {
        return;
    }
    if (path->stream == NULL) {
        path->link_state = NINLIL_C4_LAB_USB_LINK_DISCONNECTED;
        return;
    }
    st = ninlil_logical_session_state(path->session);
    if (st == NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED) {
        path->link_state = NINLIL_C4_LAB_USB_LINK_DISCONNECTED;
        return;
    }
    if (st != NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
        path->link_state = NINLIL_C4_LAB_USB_LINK_UP;
        return;
    }
    if (path->control_version >= 2u && path->assignment_epoch != 0u) {
        path->link_state = NINLIL_C4_LAB_USB_CUSTODY_READY;
        return;
    }
    path->link_state = NINLIL_C4_LAB_USB_SESSION_ACTIVE;
}

static int deliver_custody_offer(
    ninlil_c4_lab_usb_t *receiver,
    uint32_t token,
    const uint8_t *payload,
    uint32_t payload_len)
{
    if (receiver == NULL) {
        return 0;
    }
    if (receiver->held_valid != 0u) {
        receiver->diag.ownership_violation += 1u;
        return 0;
    }
    if (payload_len > NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES) {
        return 0;
    }
    if (payload_len > 0u && payload != NULL) {
        (void)memcpy(receiver->held_payload, payload, payload_len);
    }
    receiver->held_len = payload_len;
    receiver->held_token = token;
    receiver->held_valid = 1u;
    receiver->diag.custody_payload += 1u;
    return 1;
}

static ninlil_c4_lab_usb_status_t write_wire(
    ninlil_c4_lab_usb_t *path,
    uint8_t msg_type,
    uint32_t token,
    const uint8_t *payload,
    uint16_t payload_len)
{
    uint8_t frame[C4_WIRE_HDR_BYTES + NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES];
    uint32_t total;
    uint32_t crc;
    ninlil_byte_stream_status_t st;
    uint32_t accepted = 0u;

    if (path == NULL || path->stream == NULL || path->stream->ops == NULL
        || path->stream->ops->write == NULL) {
        return NINLIL_C4_LAB_USB_INVALID_STATE;
    }
    if (payload_len > NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES) {
        return NINLIL_C4_LAB_USB_CAPACITY;
    }
    if (payload_len > 0u && payload == NULL) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    frame[0] = NINLIL_C4_LAB_USB_WIRE_MAGIC0;
    frame[1] = NINLIL_C4_LAB_USB_WIRE_MAGIC1;
    frame[2] = NINLIL_C4_LAB_USB_WIRE_MAGIC2;
    frame[3] = NINLIL_C4_LAB_USB_WIRE_MAGIC3;
    frame[4] = 1u;
    frame[5] = msg_type;
    store_u32_be(frame + 6, token);
    store_u16_be(frame + 10, payload_len);
    frame[12] = 0u;
    frame[13] = 0u;
    frame[14] = 0u;
    frame[15] = 0u;
    if (payload_len > 0u) {
        (void)memcpy(frame + C4_WIRE_HDR_BYTES, payload, payload_len);
    }
    total = C4_WIRE_HDR_BYTES + (uint32_t)payload_len;
    crc = crc32_fold(frame, total);
    store_u32_be(frame + 12, crc);
    st = path->stream->ops->write(
        path->stream, frame, total, &accepted, NULL);
    if (st == NINLIL_BYTE_STREAM_WOULD_BLOCK) {
        return NINLIL_C4_LAB_USB_WOULD_BLOCK;
    }
    if (st != NINLIL_BYTE_STREAM_OK || accepted != total) {
        return NINLIL_C4_LAB_USB_IO_ERROR;
    }
    return NINLIL_C4_LAB_USB_OK;
}

static ninlil_c4_lab_usb_status_t parse_wire(
    ninlil_c4_lab_usb_t *path,
    uint8_t *out_type,
    uint32_t *out_token,
    uint8_t *out_payload,
    uint32_t out_cap,
    uint32_t *out_len)
{
    const uint8_t *frame = path->rx_buf;
    uint32_t total;
    uint16_t plen;
    uint32_t crc_expect;
    uint32_t crc_actual;

    if (path->rx_len < C4_WIRE_HDR_BYTES) {
        return NINLIL_C4_LAB_USB_BAD_FRAME;
    }
    if (frame[0] != NINLIL_C4_LAB_USB_WIRE_MAGIC0
        || frame[1] != NINLIL_C4_LAB_USB_WIRE_MAGIC1
        || frame[2] != NINLIL_C4_LAB_USB_WIRE_MAGIC2
        || frame[3] != NINLIL_C4_LAB_USB_WIRE_MAGIC3) {
        path->diag.bad_frame += 1u;
        return NINLIL_C4_LAB_USB_BAD_FRAME;
    }
    if (frame[4] != 1u) {
        path->diag.bad_frame += 1u;
        return NINLIL_C4_LAB_USB_BAD_FRAME;
    }
    plen = load_u16_be(frame + 10);
    total = C4_WIRE_HDR_BYTES + (uint32_t)plen;
    if (total > path->rx_len || plen > NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES) {
        path->diag.bad_frame += 1u;
        return NINLIL_C4_LAB_USB_BAD_FRAME;
    }
    crc_expect = load_u32_be(frame + 12);
    crc_actual = crc32_fold(frame, total);
    if (crc_expect != crc_actual) {
        path->diag.bad_frame += 1u;
        return NINLIL_C4_LAB_USB_BAD_FRAME;
    }
    *out_type = frame[5];
    *out_token = load_u32_be(frame + 6);
    if (plen > out_cap) {
        return NINLIL_C4_LAB_USB_CAPACITY;
    }
    if (plen > 0u) {
        (void)memcpy(out_payload, frame + C4_WIRE_HDR_BYTES, plen);
    }
    *out_len = (uint32_t)plen;
    return NINLIL_C4_LAB_USB_OK;
}

static void drain_rx(ninlil_c4_lab_usb_t *path)
{
    uint8_t chunk[256];
    uint32_t n;
    ninlil_byte_stream_status_t st;

    if (path == NULL || path->stream == NULL || path->stream->ops == NULL
        || path->stream->ops->read == NULL) {
        return;
    }
    for (;;) {
        n = 0u;
        st = path->stream->ops->read(
            path->stream, chunk, sizeof(chunk), &n, NULL);
        if (st != NINLIL_BYTE_STREAM_OK || n == 0u) {
            break;
        }
        if (path->rx_len + n > sizeof(path->rx_buf)) {
            path->rx_len = 0u;
            path->diag.bad_frame += 1u;
            break;
        }
        (void)memcpy(path->rx_buf + path->rx_len, chunk, n);
        path->rx_len += n;
    }
}

static void process_custody_rx(ninlil_c4_lab_usb_t *path)
{
    uint8_t msg_type;
    uint32_t token;
    uint32_t plen;
    uint8_t payload[NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES];
    ninlil_c4_lab_usb_status_t st;

    while (path->rx_len >= C4_WIRE_HDR_BYTES) {
        st = parse_wire(path, &msg_type, &token, payload, sizeof(payload), &plen);
        if (st != NINLIL_C4_LAB_USB_OK) {
            if (st == NINLIL_C4_LAB_USB_BAD_FRAME) {
                path->rx_len = 0u;
            }
            return;
        }
        if (msg_type == C4_WIRE_TYPE_CUSTODY_OFFER) {
            if (path->held_valid != 0u) {
                path->diag.ownership_violation += 1u;
                (void)write_wire(path, C4_WIRE_TYPE_CUSTODY_ACCEPT, token, NULL, 0u);
                path->rx_len = 0u;
                return;
            }
            (void)deliver_custody_offer(path, token, payload, plen);
            (void)write_wire(path, C4_WIRE_TYPE_CUSTODY_ACCEPT, token, NULL, 0u);
        } else if (msg_type == C4_WIRE_TYPE_CUSTODY_ACCEPT) {
            if (path->pending_len > 0u && path->pending_token == token) {
                path->pending_len = 0u;
                path->diag.custody_accept += 1u;
            }
        }
        path->rx_len = 0u;
    }
}

size_t ninlil_c4_lab_usb_object_size(void)
{
    return sizeof(ninlil_c4_lab_usb_t);
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_init_object(
    ninlil_c4_lab_usb_object_t *object,
    const ninlil_c4_lab_usb_config_t *config,
    ninlil_c4_lab_usb_t **out_path)
{
    ninlil_c4_lab_usb_t *path;
    ninlil_logical_session_config_t sess_cfg;
    ninlil_logical_session_status_t st;

    if (object == NULL || config == NULL || out_path == NULL) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    if (sizeof(ninlil_c4_lab_usb_t) > sizeof(object->storage)) {
        return NINLIL_C4_LAB_USB_INVALID_STATE;
    }
    path = (ninlil_c4_lab_usb_t *)(void *)object->storage;
    (void)memset(path, 0, sizeof(*path));
    path->magic = NINLIL_C4_LAB_USB_MAGIC;
    path->lifecycle = 1u;
    path->role = config->role;
    path->owner_token = config->owner_token;
    (void)memset(&sess_cfg, 0, sizeof(sess_cfg));
    sess_cfg.role = config->role;
    sess_cfg.cookie_rng = config->cookie_rng;
    sess_cfg.cookie_rng_ctx = config->cookie_rng_ctx;
    sess_cfg.jitter_fn = config->jitter_fn;
    sess_cfg.jitter_ctx = config->jitter_ctx;
    st = ninlil_logical_session_init_object(
        &path->session_obj, &sess_cfg, &path->session);
    if (st != NINLIL_LOGICAL_SESSION_OK) {
        return NINLIL_C4_LAB_USB_INVALID_STATE;
    }
    path->link_state = NINLIL_C4_LAB_USB_LINK_DISCONNECTED;
    path->control_version = 2u;
    path->assignment_epoch = 1u;
    path->diag.control_version = 2u;
    path->diag.assignment_epoch = 1u;
    *out_path = path;
    return NINLIL_C4_LAB_USB_OK;
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_bind(
    ninlil_c4_lab_usb_t *path,
    ninlil_byte_stream_t *stream)
{
    ninlil_logical_session_status_t st;

    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC || stream == NULL) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    st = ninlil_logical_session_bind(path->session, stream);
    if (st != NINLIL_LOGICAL_SESSION_OK) {
        return NINLIL_C4_LAB_USB_INVALID_STATE;
    }
    path->stream = stream;
    update_link_state(path);
    return NINLIL_C4_LAB_USB_OK;
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_bind_peer(
    ninlil_c4_lab_usb_t *path,
    ninlil_c4_lab_usb_t *peer)
{
    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    path->peer = peer;
    return NINLIL_C4_LAB_USB_OK;
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_step(
    ninlil_c4_lab_usb_t *path,
    uint64_t now_monotonic_ms,
    uint32_t timeout_ms)
{
    ninlil_logical_session_state_t prev_state;
    ninlil_logical_session_status_t st;
    ninlil_logical_session_snapshot_t snap;

    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    prev_state = ninlil_logical_session_state(path->session);
    st = ninlil_logical_session_step(path->session, now_monotonic_ms, timeout_ms);
    drain_rx(path);
    process_custody_rx(path);
    ninlil_logical_session_snapshot(path->session, &snap);
    path->diag.hello_sent = snap.counters.tx_actions_submitted;
    if (prev_state != NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE
        && snap.state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
        path->diag.hello_ack_ok += 1u;
    }
    update_link_state(path);
    if (st == NINLIL_LOGICAL_SESSION_OK
        || st == NINLIL_LOGICAL_SESSION_WOULD_BLOCK) {
        return NINLIL_C4_LAB_USB_OK;
    }
    return NINLIL_C4_LAB_USB_IO_ERROR;
}

ninlil_c4_lab_usb_link_state_t ninlil_c4_lab_usb_link_state(
    const ninlil_c4_lab_usb_t *path)
{
    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC) {
        return NINLIL_C4_LAB_USB_LINK_DISCONNECTED;
    }
    return path->link_state;
}

int ninlil_c4_lab_usb_session_active(const ninlil_c4_lab_usb_t *path)
{
    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC) {
        return 0;
    }
    return path->link_state >= NINLIL_C4_LAB_USB_SESSION_ACTIVE ? 1 : 0;
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_custody_offer(
    ninlil_c4_lab_usb_t *path,
    uint32_t ownership_token,
    const uint8_t *payload,
    uint32_t payload_len)
{
    ninlil_c4_lab_usb_status_t st;

    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    if (path->link_state < NINLIL_C4_LAB_USB_CUSTODY_READY) {
        return NINLIL_C4_LAB_USB_INVALID_STATE;
    }
    if (payload_len == 0u || payload_len > NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES) {
        return NINLIL_C4_LAB_USB_CAPACITY;
    }
    if (payload == NULL) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    if (path->pending_len != 0u) {
        path->diag.ownership_violation += 1u;
        return NINLIL_C4_LAB_USB_OWNERSHIP;
    }
    path->pending_token = ownership_token;
    path->pending_len = payload_len;
    (void)memcpy(path->pending_payload, payload, payload_len);
    if (path->peer != NULL) {
        if (deliver_custody_offer(path->peer, ownership_token, payload, payload_len)
            == 0) {
            path->diag.ownership_violation += 1u;
            path->pending_len = 0u;
            return NINLIL_C4_LAB_USB_OWNERSHIP;
        }
        path->diag.custody_offer += 1u;
        path->diag.custody_accept += 1u;
        path->pending_len = 0u;
        return NINLIL_C4_LAB_USB_OK;
    }
    st = write_wire(path, C4_WIRE_TYPE_CUSTODY_OFFER, ownership_token, payload, (uint16_t)payload_len);
    if (st == NINLIL_C4_LAB_USB_OK) {
        path->diag.custody_offer += 1u;
    }
    return st;
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_custody_accept(
    ninlil_c4_lab_usb_t *path,
    uint32_t ownership_token,
    uint8_t *out_payload,
    uint32_t out_capacity,
    uint32_t *out_payload_len)
{
    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC
        || out_payload == NULL || out_payload_len == NULL) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    if (path->held_valid == 0u || path->held_token != ownership_token) {
        path->diag.ownership_violation += 1u;
        return NINLIL_C4_LAB_USB_OWNERSHIP;
    }
    if (path->held_len > out_capacity) {
        return NINLIL_C4_LAB_USB_CAPACITY;
    }
    (void)memcpy(out_payload, path->held_payload, path->held_len);
    *out_payload_len = path->held_len;
    path->held_valid = 0u;
    path->held_len = 0u;
    path->held_token = 0u;
    return NINLIL_C4_LAB_USB_OK;
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_recover_hello(
    ninlil_c4_lab_usb_t *path)
{
    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    if (path->role != NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
        return NINLIL_C4_LAB_USB_INVALID_STATE;
    }
#if defined(NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM)
    ninlil_logical_session_test_force_state(
        path->session, NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION);
    ninlil_logical_session_test_controller_request_hello_now(path->session);
    path->diag.hello_recovery += 1u;
    update_link_state(path);
    return NINLIL_C4_LAB_USB_OK;
#else
    return NINLIL_C4_LAB_USB_INVALID_STATE;
#endif
}

void ninlil_c4_lab_usb_diag_snapshot(
    const ninlil_c4_lab_usb_t *path,
    ninlil_c4_lab_usb_diag_t *out_diag)
{
    if (path == NULL || out_diag == NULL) {
        return;
    }
    *out_diag = path->diag;
}

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_inject_wire_rx(
    ninlil_c4_lab_usb_t *path,
    const uint8_t *data,
    uint32_t length)
{
    if (path == NULL || path->magic != NINLIL_C4_LAB_USB_MAGIC) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    if (length == 0u || data == NULL) {
        return NINLIL_C4_LAB_USB_INVALID_ARGUMENT;
    }
    if (length > sizeof(path->rx_buf)) {
        return NINLIL_C4_LAB_USB_CAPACITY;
    }
    (void)memcpy(path->rx_buf, data, length);
    path->rx_len = length;
    process_custody_rx(path);
    return NINLIL_C4_LAB_USB_OK;
}
