/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_usb_bridge.h"

#include "in_memory_storage.h"
#include "n6_crypto_provider.h"
#include "r7_crypto_openssl3.h"
#include "v1_lab_binding.h"

#include "ninlil/fabric_v1.h"
#include "ninlil/posix_usb_serial_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <util.h>
#elif defined(__linux__)
#include <pty.h>
#else
#error "V1 USB bridge PTY test supports Linux and macOS"
#endif

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            goto cleanup;                                                      \
        }                                                                      \
    } while (0)

typedef struct master_stream {
    ninlil_byte_stream_t view;
    int fd;
    uint64_t generation;
    ninlil_byte_stream_link_t link;
} master_stream_t;

typedef struct test_n6 {
    uint8_t object[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    uint8_t pool_bytes[4096u];
    ninlil_n6_t *n6;
} test_n6_t;

typedef struct installed_state {
    uint32_t calls;
    uint32_t board_info_calls;
    size_t binding_length;
    ninlil_v1_lab_n6_handles_t handles;
    uint32_t fabric_calls;
    uint8_t last_packet_first;
    ninlil_nvb1_board_info_t board_info;
} installed_state_t;

static ninlil_byte_stream_status_t master_write(
    ninlil_byte_stream_t *stream,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error)
{
    master_stream_t *master = (master_stream_t *)stream->self;
    ssize_t written;

    (void)out_error;
    *out_accepted = 0u;
    if (master->link != NINLIL_BYTE_STREAM_LINK_UP) {
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    written = write(master->fd, data, length);
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    if (written != (ssize_t)length) {
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
    *out_accepted = length;
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_status_t master_read(
    ninlil_byte_stream_t *stream,
    uint8_t *out,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error)
{
    master_stream_t *master = (master_stream_t *)stream->self;
    ssize_t length;

    (void)out_error;
    *out_length = 0u;
    if (master->link != NINLIL_BYTE_STREAM_LINK_UP) {
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    length = read(master->fd, out, capacity);
    if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return NINLIL_BYTE_STREAM_OK;
    }
    if (length <= 0) {
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
    *out_length = (uint32_t)length;
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_status_t master_poll(
    ninlil_byte_stream_t *stream,
    uint32_t timeout_ms,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error)
{
    master_stream_t *master = (master_stream_t *)stream->self;
    struct pollfd fd;
    int result;

    (void)out_error;
    *out_events = NINLIL_BYTE_STREAM_EVENT_NONE;
    if (master->link != NINLIL_BYTE_STREAM_LINK_UP) {
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    fd.fd = master->fd;
    fd.events = POLLIN | POLLOUT;
    fd.revents = 0;
    result = poll(&fd, 1, (int)timeout_ms);
    if (result < 0 && errno == EINTR) {
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    if (result < 0 || (fd.revents & (POLLERR | POLLNVAL)) != 0) {
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
    if ((fd.revents & POLLHUP) != 0) {
        master->link = NINLIL_BYTE_STREAM_LINK_DOWN;
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    if ((fd.revents & POLLIN) != 0) {
        *out_events |= NINLIL_BYTE_STREAM_EVENT_READABLE;
    }
    if ((fd.revents & POLLOUT) != 0) {
        *out_events |= NINLIL_BYTE_STREAM_EVENT_WRITABLE;
    }
    if (result == 0) {
        *out_events |= NINLIL_BYTE_STREAM_EVENT_TIMEOUT;
    }
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_link_t master_link(
    const ninlil_byte_stream_t *stream)
{
    return ((const master_stream_t *)stream->self)->link;
}

static uint64_t master_generation(const ninlil_byte_stream_t *stream)
{
    return ((const master_stream_t *)stream->self)->generation;
}

static const ninlil_byte_stream_ops_t k_master_ops = {
    NULL, NULL, master_write, master_read, master_poll,
    master_link, master_generation, NULL, NULL};

static void master_attach(master_stream_t *master, int fd)
{
    master->fd = fd;
    master->generation += 1u;
    master->link = NINLIL_BYTE_STREAM_LINK_UP;
    master->view.ops = &k_master_ops;
    master->view.self = master;
}

static int pty_open(int *out_master, char out_path[256])
{
    int slave = -1;
    int flags;

    *out_master = -1;
    out_path[0] = '\0';
    if (openpty(out_master, &slave, out_path, NULL, NULL) != 0) {
        return 0;
    }
    flags = fcntl(*out_master, F_GETFL, 0);
    if (out_path[0] != '/' || flags < 0
        || fcntl(*out_master, F_SETFL, flags | O_NONBLOCK) != 0
        || close(slave) != 0) {
        (void)close(*out_master);
        *out_master = -1;
        return 0;
    }
    return 1;
}

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_endpoint(ninlil_v1_lab_endpoint_t *endpoint, uint8_t seed)
{
    (void)memset(endpoint, 0, sizeof(*endpoint));
    fill_bytes(endpoint->runtime_id, 16u, seed);
    fill_bytes(endpoint->application_id, 16u, (uint8_t)(seed + 0x10u));
    fill_bytes(endpoint->device_id, 16u, (uint8_t)(seed + 0x20u));
    fill_bytes(endpoint->site_id, 16u, 0x70u);
    endpoint->binding_epoch = 1u;
    endpoint->membership_epoch = 1u;
    endpoint->identity_flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    fill_bytes(endpoint->clock_epoch_id, 16u, seed);
    endpoint->clock_trust = NINLIL_CLOCK_TRUSTED;
}

static void make_binding(ninlil_v1_lab_binding_t *binding)
{
    ninlil_v1_lab_service_row_t *row;

    (void)memset(binding, 0, sizeof(*binding));
    binding->service_count = 1u;
    binding->pair_generation = 1u;
    fill_endpoint(&binding->endpoint_a, 0x10u);
    fill_endpoint(&binding->endpoint_b, 0x30u);
    (void)memcpy(
        binding->endpoint_b.clock_epoch_id,
        binding->endpoint_a.clock_epoch_id,
        16u);
    fill_bytes(binding->radio_site_domain_id, 16u, 0x90u);
    binding->radio_membership_epoch = 10u;
    binding->a_to_b_hop_context_id = 1u;
    binding->a_to_b_e2e_context_id = 1u;
    binding->b_to_a_hop_context_id = 1u;
    binding->b_to_a_e2e_context_id = 1u;
    fill_bytes(binding->a_to_b_hop_secret, 32u, 0x11u);
    fill_bytes(binding->a_to_b_e2e_secret, 32u, 0x31u);
    fill_bytes(binding->b_to_a_hop_secret, 32u, 0x51u);
    fill_bytes(binding->b_to_a_e2e_secret, 32u, 0x71u);
    row = &binding->services[0];
    row->slot = 1u;
    row->flow = NINLIL_V1_LAB_FLOW_A_TO_B;
    row->namespace_length = 3u;
    row->service_length = 3u;
    row->schema_length = 3u;
    row->descriptor_revision = 1u;
    fill_bytes(row->descriptor_digest, 32u, 0x30u);
    row->schema_major = 1u;
    row->family = NINLIL_FAMILY_DESIRED_STATE;
    row->direction = NINLIL_DIRECTION_DOWNLINK;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    row->evidence_grace_ms = 1000u;
    (void)memcpy(row->namespace_id, "lab", 3u);
    (void)memcpy(row->service_id, "svc", 3u);
    (void)memcpy(row->schema_id, "bin", 3u);
}

static int init_n6(test_n6_t *test)
{
    ninlil_n6_context_pool_t pool;

    (void)memset(test, 0, sizeof(*test));
    (void)memset(&pool, 0, sizeof(pool));
    pool.max_slots = 8u;
    pool.bytes = test->pool_bytes;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    return pool.bytes_size <= sizeof(test->pool_bytes)
        && ninlil_n6_init(test->object, sizeof(test->object),
               &pool, &test->n6) == NINLIL_N6_OK;
}

static void pair_installed(void *user, const uint8_t *binding,
    size_t length, const ninlil_v1_lab_n6_handles_t *handles)
{
    installed_state_t *state = (installed_state_t *)user;

    state->calls += 1u;
    state->binding_length = length;
    state->handles = *handles;
    state->last_packet_first = binding[0];
}

static uint32_t fabric_handoff(void *user, const uint8_t *packet, size_t length)
{
    installed_state_t *state = (installed_state_t *)user;

    (void)length;
    state->fabric_calls += 1u;
    state->last_packet_first = packet[0];
    return NINLIL_NVB1_STATUS_ACCEPTED_LOCAL;
}

static ninlil_v1_usb_bridge_status_t board_info_handoff(
    void *user, const ninlil_nvb1_board_info_t *info)
{
    installed_state_t *state = (installed_state_t *)user;

    state->board_info_calls += 1u;
    state->board_info = *info;
    return NINLIL_V1_USB_BRIDGE_OK;
}

static int pump_until_board_info(
    ninlil_v1_usb_bridge_t *host,
    ninlil_v1_usb_bridge_t *board,
    installed_state_t *state,
    uint32_t expected_calls,
    uint64_t now)
{
    unsigned int i;

    for (i = 0u; i < 256u; ++i) {
        ninlil_v1_usb_bridge_status_t board_status =
            ninlil_v1_usb_bridge_step(board, now + i, 1u);
        ninlil_v1_usb_bridge_status_t host_status =
            ninlil_v1_usb_bridge_step(host, now + i, 1u);
        if ((board_status != NINLIL_V1_USB_BRIDGE_OK
                && board_status != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK)
            || (host_status != NINLIL_V1_USB_BRIDGE_OK
                && host_status != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK)) {
            return 0;
        }
        if (state->board_info_calls == expected_calls) {
            return 1;
        }
    }
    return 0;
}

static int pump_until_complete(
    ninlil_v1_usb_bridge_t *owner,
    ninlil_v1_usb_bridge_t *other,
    ninlil_v1_usb_bridge_handle_t handle,
    uint64_t now,
    ninlil_v1_usb_bridge_completion_t *out)
{
    unsigned int i;

    for (i = 0u; i < 256u; ++i) {
        ninlil_v1_usb_bridge_status_t a =
            ninlil_v1_usb_bridge_step(owner, now + i, 1u);
        ninlil_v1_usb_bridge_status_t b =
            ninlil_v1_usb_bridge_step(other, now + i, 1u);
        ninlil_v1_usb_bridge_status_t taken;
        if ((a != NINLIL_V1_USB_BRIDGE_OK
                && a != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK)
            || (b != NINLIL_V1_USB_BRIDGE_OK
                && b != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK)) {
            return 0;
        }
        taken = ninlil_v1_usb_bridge_take_completion(owner, handle, out);
        if (taken == NINLIL_V1_USB_BRIDGE_OK) {
            return 1;
        }
        if (taken != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
            return 0;
        }
    }
    return 0;
}

static int run_test(void)
{
    int passed = 0;
    int master_fd = -1;
    char slave_path[256];
    master_stream_t master;
    ninlil_posix_usb_serial_object_t host_object;
    ninlil_byte_stream_t host_stream;
    ninlil_byte_stream_error_t stream_error;
    ninlil_v1_usb_bridge_t host_bridge;
    ninlil_v1_usb_bridge_t board_bridge;
    ninlil_v1_usb_bridge_config_t bridge_config;
    ninlil_v1_usb_bridge_handle_t handle;
    ninlil_v1_usb_bridge_completion_t completion;
    ninlil_r7_crypto_provider crypto;
    ninlil_v1_lab_binding_t binding;
    ninlil_r2_authority_clock_result_t clock_sample;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_test_storage_config_t storage_config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = NULL;
    installed_state_t callbacks;
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];

    (void)memset(&master, 0, sizeof(master));
    master.fd = -1;
    (void)memset(&host_object, 0, sizeof(host_object));
    (void)memset(&host_stream, 0, sizeof(host_stream));
    (void)memset(&host_bridge, 0, sizeof(host_bridge));
    (void)memset(&board_bridge, 0, sizeof(board_bridge));
    (void)memset(&n6, 0, sizeof(n6));
    (void)memset(&binding, 0, sizeof(binding));
    (void)memset(&provisioner, 0, sizeof(provisioner));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    REQUIRE(pty_open(&master_fd, slave_path));
    master_attach(&master, master_fd);
    REQUIRE(ninlil_posix_usb_serial_init_object(&host_object, &host_stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_posix_usb_serial_open(
        &host_stream, slave_path, &stream_error) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&crypto)
        == NINLIL_R7_CRYPTO_OK);
    make_binding(&binding);
    REQUIRE(ninlil_v1_lab_binding_finalize(&crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    storage = ninlil_test_storage_create(&storage_config);
    REQUIRE(storage != NULL);
    REQUIRE(init_n6(&n6));
    (void)memset(&clock_sample, 0, sizeof(clock_sample));
    clock_sample.typed_class = NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH;
    clock_sample.sample_fields_valid = 1u;
    clock_sample.sample_trust = NINLIL_CLOCK_TRUSTED;
    clock_sample.result_catalog = NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP;
    clock_sample.exact_status = NINLIL_PCP_OK;
    (void)memcpy(clock_sample.sample_epoch_id,
        binding.endpoint_a.clock_epoch_id, 16u);
    clock_sample.sample_now_ms = 1000u;
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
        ninlil_test_storage_ops(storage), ninlil_n6_crypto_host_ops(),
        &crypto, binding.endpoint_a.runtime_id, &clock_sample)
        == NINLIL_V1_LAB_PROVISION_OK);

    (void)memset(&bridge_config, 0, sizeof(bridge_config));
    bridge_config.role = NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER;
    bridge_config.stream = &host_stream;
    bridge_config.fabric_handoff = fabric_handoff;
    bridge_config.board_info = board_info_handoff;
    bridge_config.callback_user = &callbacks;
    REQUIRE(ninlil_v1_usb_bridge_init(&host_bridge, &bridge_config)
        == NINLIL_V1_USB_BRIDGE_OK);
    bridge_config.role = NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD;
    bridge_config.stream = &master.view;
    bridge_config.provisioner = &provisioner;
    bridge_config.pair_installed = pair_installed;
    bridge_config.board_info = NULL;
    REQUIRE(ninlil_v1_usb_bridge_init(&board_bridge, &bridge_config)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, 1u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&board_bridge, 1u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);

    {
        ninlil_nvb1_board_info_t info;
        (void)memset(&info, 0, sizeof(info));
        (void)memcpy(info.clock_epoch_id,
            clock_sample.sample_epoch_id, sizeof(info.clock_epoch_id));
        info.clock_now_ms = clock_sample.sample_now_ms;
        info.clock_trust = clock_sample.sample_trust;
        REQUIRE(ninlil_v1_usb_bridge_submit_board_info(&board_bridge, &info)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(pump_until_board_info(&host_bridge, &board_bridge,
            &callbacks, 1u, 2u));
        REQUIRE(memcmp(callbacks.board_info.clock_epoch_id,
            binding.endpoint_a.clock_epoch_id, 16u) == 0);
    }

    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&host_bridge,
        binding.raw, binding.raw_length, 1000u, &handle)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(pump_until_complete(&host_bridge, &board_bridge,
        handle, 2u, &completion));
    REQUIRE(completion.reason
        == NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS);
    REQUIRE(completion.remote_status_code == NINLIL_NVB1_STATUS_INSTALLED);
    REQUIRE(completion.pair_generation == 1u);
    REQUIRE(callbacks.calls == 1u);
    REQUIRE(callbacks.binding_length == binding.raw_length);
    REQUIRE(callbacks.handles.a_to_b_hop != 0u);
    REQUIRE(callbacks.handles.b_to_a_e2e != 0u);

    (void)memset(packet, 0xa1, sizeof(packet));
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&host_bridge,
        packet, sizeof(packet), 2000u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(pump_until_complete(&host_bridge, &board_bridge,
        handle, 300u, &completion));
    REQUIRE(completion.remote_status_code
        == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL);
    REQUIRE(callbacks.fabric_calls == 1u);
    packet[0] = 0xb2u;
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&board_bridge,
        packet, sizeof(packet), 3000u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(pump_until_complete(&board_bridge, &host_bridge,
        handle, 600u, &completion));
    REQUIRE(completion.remote_status_code
        == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL);
    REQUIRE(callbacks.fabric_calls == 2u);
    REQUIRE(callbacks.last_packet_first == 0xb2u);

    /* Explicit A1 close/reopen creates a fresh physical generation. */
    packet[0] = 0xc3u;
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&host_bridge,
        packet, sizeof(packet), 4000u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_posix_usb_serial_close(&host_stream, &stream_error)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(close(master_fd) == 0);
    master_fd = -1;
    master.fd = -1;
    master.link = NINLIL_BYTE_STREAM_LINK_DOWN;
    REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, 900u, 0u)
        == NINLIL_V1_USB_BRIDGE_LINK_DOWN);
    REQUIRE(ninlil_v1_usb_bridge_take_completion(
        &host_bridge, handle, &completion) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(completion.reason
        == NINLIL_V1_USB_BRIDGE_COMPLETION_LINK_FENCED);
    REQUIRE(ninlil_v1_usb_bridge_step(&board_bridge, 900u, 0u)
        == NINLIL_V1_USB_BRIDGE_LINK_DOWN);

    REQUIRE(pty_open(&master_fd, slave_path));
    master_attach(&master, master_fd);
    REQUIRE(ninlil_posix_usb_serial_open(
        &host_stream, slave_path, &stream_error) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, 901u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&board_bridge, 901u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    {
        ninlil_nvb1_board_info_t info;
        (void)memset(&info, 0, sizeof(info));
        (void)memcpy(info.clock_epoch_id,
            clock_sample.sample_epoch_id, sizeof(info.clock_epoch_id));
        info.clock_now_ms = clock_sample.sample_now_ms;
        info.clock_trust = clock_sample.sample_trust;
        REQUIRE(ninlil_v1_usb_bridge_submit_board_info(&board_bridge, &info)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(pump_until_board_info(&host_bridge, &board_bridge,
            &callbacks, 2u, 902u));
    }
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&host_bridge,
        packet, sizeof(packet), 5000u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(handle.operation_id == 1u);
    REQUIRE(pump_until_complete(&host_bridge, &board_bridge,
        handle, 1200u, &completion));
    REQUIRE(completion.remote_status_code
        == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL);
    REQUIRE(callbacks.fabric_calls == 3u);
    REQUIRE(callbacks.last_packet_first == 0xc3u);
    passed = 1;

cleanup:
    ninlil_v1_usb_bridge_clear(&host_bridge);
    ninlil_v1_usb_bridge_clear(&board_bridge);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&binding);
    if (host_stream.ops != NULL) {
        (void)ninlil_posix_usb_serial_close(&host_stream, &stream_error);
    }
    if (master_fd >= 0) {
        (void)close(master_fd);
    }
    if (storage != NULL) {
        ninlil_test_storage_destroy(storage);
    }
    return passed;
}

int main(void)
{
    if (!run_test()) {
        return 1;
    }
    (void)printf(
        "v1_usb_bridge_pty_test OK binding=1 bidirectional=1 reopen=1 installed_port=1\n");
    return 0;
}
