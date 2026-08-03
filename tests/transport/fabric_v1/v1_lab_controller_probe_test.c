#include "v1_usb_bridge.h"

#include "in_memory_storage.h"
#include "n6_crypto_provider.h"
#include "nfl1_codec.h"
#include "r7_crypto_openssl3.h"
#include "v1_lab_binding.h"
#include "v1_lab_fabric.h"

#include "ninlil/fabric_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <util.h>
#elif defined(__linux__)
#include <pty.h>
#else
#error "V1 Controller probe test supports Linux and macOS"
#endif

#define TEST_TIMEOUT_MS UINT64_C(10000)

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
    uint64_t pair_generation;
    uint32_t fabric_calls;
    uint32_t packet_length;
    uint8_t packet[NINLIL_V1_LAB_FABRIC_PACKET_MAX];
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
    if (written < 0 && (errno == EIO || errno == ENXIO)) {
        master->link = NINLIL_BYTE_STREAM_LINK_DOWN;
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
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
    if (length == 0 || (length < 0 && errno == EIO)) {
        master->link = NINLIL_BYTE_STREAM_LINK_DOWN;
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    if (length < 0) {
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
    struct pollfd descriptor;
    int result;

    (void)out_error;
    *out_events = NINLIL_BYTE_STREAM_EVENT_NONE;
    descriptor.fd = master->fd;
    descriptor.events = POLLIN | POLLOUT;
    descriptor.revents = 0;
    result = poll(&descriptor, 1, (int)timeout_ms);
    if (result < 0 && errno == EINTR) {
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    if (result < 0 || (descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
    if ((descriptor.revents & POLLHUP) != 0
        && (descriptor.revents & POLLIN) == 0) {
        master->link = NINLIL_BYTE_STREAM_LINK_DOWN;
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    if ((descriptor.revents & POLLIN) != 0) {
        *out_events |= NINLIL_BYTE_STREAM_EVENT_READABLE;
    }
    if ((descriptor.revents & POLLOUT) != 0) {
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

static int monotonic_ms(uint64_t *out_ms)
{
    struct timespec value;

    if (out_ms == NULL || clock_gettime(CLOCK_MONOTONIC, &value) != 0
        || value.tv_sec < 0 || value.tv_nsec < 0
        || value.tv_nsec >= 1000000000L) {
        return 0;
    }
    *out_ms = (uint64_t)value.tv_sec * UINT64_C(1000)
        + (uint64_t)value.tv_nsec / UINT64_C(1000000);
    return 1;
}

static int wait_for_raw_mode(int descriptor, uint64_t timeout_ms)
{
    struct timespec pause = {0, 1000000L};
    uint64_t start;

    if (!monotonic_ms(&start)) {
        return 0;
    }
    for (;;) {
        struct termios attributes;
        uint64_t now;

        if (tcgetattr(descriptor, &attributes) == 0
            && (attributes.c_lflag & (tcflag_t)(ICANON | ECHO)) == 0u) {
            return 1;
        }
        if (!monotonic_ms(&now) || now < start || now - start > timeout_ms) {
            return 0;
        }
        (void)nanosleep(&pause, NULL);
    }
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

static int write_exact(int descriptor, const uint8_t *data, size_t length)
{
    size_t used = 0u;

    while (used < length) {
        ssize_t amount = write(descriptor, data + used, length - used);
        if (amount > 0) {
            used += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static void pair_installed(void *user, const uint8_t *binding,
    size_t length, const ninlil_v1_lab_n6_handles_t *handles)
{
    installed_state_t *state = (installed_state_t *)user;

    (void)binding;
    (void)length;
    (void)handles;
    state->calls += 1u;
    state->pair_generation = 1u;
}

static uint32_t fabric_handoff(void *user, const uint8_t *packet, size_t length)
{
    installed_state_t *state = (installed_state_t *)user;

    if (state == NULL || packet == NULL || length == 0u
        || length > sizeof(state->packet) || state->fabric_calls != 0u) {
        return NINLIL_NVB1_STATUS_BUSY;
    }
    (void)memcpy(state->packet, packet, length);
    state->packet_length = (uint32_t)length;
    state->fabric_calls = 1u;
    return NINLIL_NVB1_STATUS_ACCEPTED_LOCAL;
}

static const ninlil_v1_lab_endpoint_t *test_controller_endpoint(
    const ninlil_v1_lab_binding_t *binding)
{
    if (binding == NULL) {
        return NULL;
    }
    return binding->controller_side == NINLIL_V1_LAB_SIDE_A
        ? &binding->endpoint_a
        : &binding->endpoint_b;
}

static const ninlil_v1_lab_endpoint_t *test_peer_endpoint(
    const ninlil_v1_lab_binding_t *binding)
{
    if (binding == NULL) {
        return NULL;
    }
    return binding->controller_side == NINLIL_V1_LAB_SIDE_A
        ? &binding->endpoint_b
        : &binding->endpoint_a;
}

static void set_receipt_source(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->source_runtime_id.bytes,
        endpoint->runtime_id, 16u);
    (void)memcpy(envelope->source_application_id.bytes,
        endpoint->application_id, 16u);
    (void)memcpy(envelope->source_device_id.bytes,
        endpoint->device_id, 16u);
    (void)memcpy(envelope->source_installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(envelope->source_site_id.bytes, endpoint->site_id, 16u);
    envelope->source_binding_epoch = endpoint->binding_epoch;
    envelope->source_membership_epoch = endpoint->membership_epoch;
    envelope->source_flags = endpoint->identity_flags;
}

static void set_receipt_target(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->target_runtime_id.bytes,
        endpoint->runtime_id, 16u);
    (void)memcpy(envelope->target_application_id.bytes,
        endpoint->application_id, 16u);
    (void)memcpy(envelope->target_device_id.bytes,
        endpoint->device_id, 16u);
    (void)memcpy(envelope->target_installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(envelope->target_site_id.bytes, endpoint->site_id, 16u);
    envelope->target_binding_epoch = endpoint->binding_epoch;
    envelope->target_membership_epoch = endpoint->membership_epoch;
    envelope->target_flags = endpoint->identity_flags;
}

static int make_verified_receipt(
    const ninlil_v1_lab_binding_t *binding,
    const installed_state_t *state,
    uint8_t out[NINLIL_V1_LAB_FABRIC_PACKET_MAX],
    uint32_t *out_length)
{
    static const uint8_t expected_payload[] = {0x01u, 0x02u, 0x03u, 0x04u};
    const ninlil_v1_lab_endpoint_t *controller =
        test_controller_endpoint(binding);
    const ninlil_v1_lab_endpoint_t *peer = test_peer_endpoint(binding);
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    if (binding == NULL || state == NULL || out == NULL || out_length == NULL
        || controller == NULL || peer == NULL || state->fabric_calls != 1u
        || ninlil_fabric_private_nfl1_decode(state->packet,
               state->packet_length, &workspace, &envelope, &required)
            != NINLIL_FABRIC_PRIVATE_NFL1_OK
        || envelope.message_kind != NINLIL_BEARER_MESSAGE_APPLICATION
        || envelope.family != NINLIL_FAMILY_DESIRED_STATE
        || memcmp(envelope.source_runtime_id.bytes,
               controller->runtime_id, 16u)
            != 0
        || memcmp(envelope.target_runtime_id.bytes,
               peer->runtime_id, 16u)
            != 0
        || envelope.payload.length != sizeof(expected_payload)
        || memcmp(envelope.payload.bytes, expected_payload,
               sizeof(expected_payload))
            != 0
        || envelope.path_selection_epoch == UINT64_MAX) {
        return 0;
    }
    envelope.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    set_receipt_source(&envelope, peer);
    set_receipt_target(&envelope, controller);
    envelope.receipt_stage = NINLIL_EVIDENCE_VERIFIED;
    envelope.payload.bytes = NULL;
    envelope.payload.length = 0u;
    envelope.evidence.bytes = NULL;
    envelope.evidence.length = 0u;
    (void)memcpy(envelope.evidence_time_clock_epoch_id.bytes,
        peer->clock_epoch_id, 16u);
    envelope.evidence_time_now_ms = 71200u;
    envelope.evidence_time_trust = NINLIL_CLOCK_TRUSTED;
    envelope.path_selection_epoch += 1u;
    return ninlil_fabric_private_nfl1_encode(&envelope, out,
               NINLIL_V1_LAB_FABRIC_PACKET_MAX, out_length)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK;
}

static void remove_database_files(const char *path)
{
    char sidecar[256];

    if (path == NULL || path[0] == '\0') {
        return;
    }
    (void)unlink(path);
    {
        int written = snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
        if (written > 0 && (size_t)written < sizeof(sidecar)) {
            (void)unlink(sidecar);
        }
    }
    {
        int written = snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
        if (written > 0 && (size_t)written < sizeof(sidecar)) {
            (void)unlink(sidecar);
        }
    }
}

static int run_test(const char *controller_path, int send_mode)
{
    int passed = 0;
    int master_fd = -1;
    int slave_fd = -1;
    int binding_fd = -1;
    int database_fd = -1;
    int child_status = 0;
    pid_t child = -1;
    char slave_path[256];
    char binding_path[] = "/tmp/ninlil-binding-XXXXXX";
    char database_path[] = "/tmp/ninlil-controller-XXXXXX";
    master_stream_t master;
    ninlil_v1_usb_bridge_t board_bridge;
    ninlil_v1_usb_bridge_config_t bridge_config;
    ninlil_r7_crypto_provider crypto;
    ninlil_v1_lab_binding_t binding;
    ninlil_r2_authority_clock_result_t clock_sample;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_test_storage_config_t storage_config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = NULL;
    installed_state_t installed;
    ninlil_v1_usb_bridge_handle_t receipt_handle;
    ninlil_v1_usb_bridge_completion_t receipt_completion;
    uint8_t receipt[NINLIL_V1_LAB_FABRIC_PACKET_MAX];
    uint32_t receipt_length = 0u;
    int receipt_submitted = 0;
    int receipt_completed = 0;
    uint64_t start;

    (void)memset(&master, 0, sizeof(master));
    (void)memset(&board_bridge, 0, sizeof(board_bridge));
    (void)memset(&binding, 0, sizeof(binding));
    (void)memset(&provisioner, 0, sizeof(provisioner));
    (void)memset(&installed, 0, sizeof(installed));
    (void)memset(&receipt_handle, 0, sizeof(receipt_handle));
    (void)memset(&receipt_completion, 0, sizeof(receipt_completion));
    (void)memset(receipt, 0, sizeof(receipt));
    REQUIRE(controller_path != NULL && controller_path[0] == '/');
    REQUIRE(openpty(&master_fd, &slave_fd, slave_path, NULL, NULL) == 0);
    REQUIRE(fcntl(master_fd, F_SETFL,
        fcntl(master_fd, F_GETFL, 0) | O_NONBLOCK) == 0);
    master.fd = master_fd;
    master.generation = 1u;
    master.link = NINLIL_BYTE_STREAM_LINK_UP;
    master.view.ops = &k_master_ops;
    master.view.self = &master;
    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&crypto)
        == NINLIL_R7_CRYPTO_OK);
    make_binding(&binding);
    REQUIRE(ninlil_v1_lab_binding_finalize(&crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    binding_fd = mkstemp(binding_path);
    REQUIRE(binding_fd >= 0);
    REQUIRE(write_exact(binding_fd, binding.raw, binding.raw_length));
    REQUIRE(close(binding_fd) == 0);
    binding_fd = -1;
    database_fd = mkstemp(database_path);
    REQUIRE(database_fd >= 0);
    REQUIRE(close(database_fd) == 0);
    database_fd = -1;
    REQUIRE(unlink(database_path) == 0);
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
    clock_sample.sample_now_ms = 70000u;
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
        ninlil_test_storage_ops(storage), ninlil_n6_crypto_host_ops(),
        &crypto, binding.endpoint_a.runtime_id, &clock_sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    (void)memset(&bridge_config, 0, sizeof(bridge_config));
    bridge_config.role = NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD;
    bridge_config.stream = &master.view;
    bridge_config.provisioner = &provisioner;
    bridge_config.pair_installed = pair_installed;
    bridge_config.fabric_handoff = fabric_handoff;
    bridge_config.callback_user = &installed;
    REQUIRE(ninlil_v1_usb_bridge_init(&board_bridge, &bridge_config)
        == NINLIL_V1_USB_BRIDGE_OK);

    child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        (void)close(master_fd);
        (void)close(slave_fd);
        if (send_mode != 0) {
            (void)execl(controller_path, controller_path,
                "--usb", slave_path,
                "--database", database_path,
                "--binding", binding_path,
                "--timeout-ms", "5000",
                "--send-binding", "1",
                "--send-service", "1",
                "--payload-hex", "01020304", (char *)NULL);
        } else {
            (void)execl(controller_path, controller_path,
                "--usb", slave_path,
                "--database", database_path,
                "--binding", binding_path,
                "--timeout-ms", "5000", (char *)NULL);
        }
        _exit(127);
    }
    REQUIRE(wait_for_raw_mode(slave_fd, UINT64_C(5000)));
    REQUIRE(close(slave_fd) == 0);
    slave_fd = -1;
    {
        ninlil_nvb1_board_info_t info;

        (void)memset(&info, 0, sizeof(info));
        (void)memcpy(info.clock_epoch_id,
            clock_sample.sample_epoch_id, sizeof(info.clock_epoch_id));
        info.clock_now_ms = clock_sample.sample_now_ms;
        info.clock_trust = clock_sample.sample_trust;
        REQUIRE(ninlil_v1_usb_bridge_step(&board_bridge, 1u, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(ninlil_v1_usb_bridge_submit_board_info(&board_bridge, &info)
            == NINLIL_V1_USB_BRIDGE_OK);
    }
    REQUIRE(monotonic_ms(&start));
    for (;;) {
        uint64_t now;
        pid_t waited;
        ninlil_v1_usb_bridge_status_t status;

        REQUIRE(monotonic_ms(&now) && now >= start
            && now - start <= TEST_TIMEOUT_MS);
        status = ninlil_v1_usb_bridge_step(&board_bridge, now, 2u);
        REQUIRE(status == NINLIL_V1_USB_BRIDGE_OK
            || status == NINLIL_V1_USB_BRIDGE_WOULD_BLOCK
            || (installed.calls == 1u
                && status == NINLIL_V1_USB_BRIDGE_LINK_DOWN));
        if (send_mode != 0 && installed.fabric_calls == 1u
            && receipt_submitted == 0) {
            ninlil_v1_usb_bridge_status_t submit_status;

            REQUIRE(make_verified_receipt(
                &binding, &installed, receipt, &receipt_length));
            REQUIRE(now <= UINT64_MAX - TEST_TIMEOUT_MS);
            submit_status = ninlil_v1_usb_bridge_submit_fabric(
                &board_bridge, receipt, receipt_length,
                now + TEST_TIMEOUT_MS, &receipt_handle);
            REQUIRE(submit_status == NINLIL_V1_USB_BRIDGE_OK
                || submit_status == NINLIL_V1_USB_BRIDGE_BUSY);
            if (submit_status == NINLIL_V1_USB_BRIDGE_OK) {
                receipt_submitted = 1;
            }
        }
        if (receipt_submitted != 0 && receipt_completed == 0) {
            ninlil_v1_usb_bridge_status_t completion_status =
                ninlil_v1_usb_bridge_take_completion(&board_bridge,
                    receipt_handle, &receipt_completion);
            if (completion_status == NINLIL_V1_USB_BRIDGE_OK) {
                REQUIRE(receipt_completion.reason
                        == NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS
                    && receipt_completion.remote_status_code
                        == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL);
                receipt_completed = 1;
            } else {
                REQUIRE(completion_status == NINLIL_V1_USB_BRIDGE_WOULD_BLOCK);
            }
        }
        waited = waitpid(child, &child_status, WNOHANG);
        REQUIRE(waited >= 0);
        if (waited == child) {
            child = -1;
            break;
        }
    }
    REQUIRE(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    REQUIRE(installed.calls == 1u && installed.pair_generation == 1u);
    REQUIRE((send_mode == 0 && installed.fabric_calls == 0u)
        || (send_mode != 0 && installed.fabric_calls == 1u
            && receipt_submitted != 0 && receipt_completed == 1));
    passed = 1;

cleanup:
    if (child > 0) {
        (void)kill(child, SIGTERM);
        (void)waitpid(child, &child_status, 0);
    }
    ninlil_v1_usb_bridge_clear(&board_bridge);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&binding);
    if (binding_fd >= 0) {
        (void)close(binding_fd);
    }
    if (database_fd >= 0) {
        (void)close(database_fd);
    }
    if (master_fd >= 0) {
        (void)close(master_fd);
    }
    if (slave_fd >= 0) {
        (void)close(slave_fd);
    }
    if (storage != NULL) {
        ninlil_test_storage_destroy(storage);
    }
    (void)unlink(binding_path);
    remove_database_files(database_path);
    return passed;
}

int main(int argc, char **argv)
{
    if (argc != 2 || !run_test(argv[1], 0) || !run_test(argv[1], 1)) {
        return 1;
    }
    (void)printf(
        "v1_lab_controller_probe_test OK usb=pty binding=installed "
        "runtime_submit=verified\n");
    return 0;
}
