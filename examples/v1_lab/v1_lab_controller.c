#include "v1_lab_controller_platform.h"

#include "fabric_private_api.h"
#include "r7_crypto_openssl3.h"
#include "v1_lab_binding.h"
#include "v1_lab_fabric.h"
#include "v1_usb_bridge.h"
#include "v1_usb_fabric_link.h"

#include "ninlil/composition_v1.h"
#include "ninlil/posix_usb_serial_v1.h"
#include "ninlil/runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CONTROLLER_BINDING_MAX ((uint8_t)2u)
#define CONTROLLER_PATH_MAX ((uint8_t)4u)
#define CONTROLLER_STEP_LIMIT ((uint32_t)512u)
#define CONTROLLER_POLL_MS ((uint32_t)20u)
#define CONTROLLER_TIMEOUT_DEFAULT_MS ((uint32_t)5000u)
#define CONTROLLER_PAYLOAD_MAX ((uint32_t)128u)
#define CONTROLLER_IDEMPOTENCY_BYTES ((uint32_t)16u)

typedef struct controller_options {
    const char *usb_path;
    const char *database_path;
    const char *binding_paths[CONTROLLER_BINDING_MAX];
    uint8_t binding_count;
    uint8_t send_enabled;
    uint8_t send_binding;
    uint8_t send_service;
    uint8_t payload[CONTROLLER_PAYLOAD_MAX];
    uint32_t payload_length;
    uint32_t timeout_ms;
} controller_options_t;

typedef struct controller_submission_summary {
    ninlil_outcome_t outcome;
    ninlil_evidence_stage_t latest_evidence;
    ninlil_reason_t reason;
    ninlil_reason_t target_reason;
    uint64_t attempts;
} controller_submission_summary_t;

typedef struct controller_context {
    ninlil_r7_crypto_provider crypto;
    ninlil_posix_usb_serial_object_t usb_object;
    ninlil_byte_stream_t stream;
    ninlil_v1_usb_fabric_link_t link;
    ninlil_v1_usb_bridge_t bridge;
    ninlil_v1_lab_controller_platform_t *platform;
    void *composition_workspace;
    uint32_t composition_workspace_bytes;
    ninlil_composition_v1_t *composition;
    ninlil_runtime_t *runtime;
    ninlil_fabric_v1_t *fabric;
    ninlil_service_t *submission_service;
    ninlil_fabric_link_registration_v1_t
        *registrations[CONTROLLER_PATH_MAX];
    uint8_t registration_count;
    uint8_t stream_open;
    uint8_t link_prepared;
    uint8_t bridge_initialized;
} controller_context_t;

static void secure_clear(void *pointer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;

    if (pointer == NULL) {
        return;
    }
    while (length > 0u) {
        *bytes = 0u;
        ++bytes;
        --length;
    }
}

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t i;

    if (bytes == NULL) {
        return 0;
    }
    for (i = 0u; i < length; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any != 0u;
}

static int monotonic_ms(uint64_t *out_ms)
{
    struct timespec value;
    uint64_t seconds;

    if (out_ms == NULL || clock_gettime(CLOCK_MONOTONIC, &value) != 0
        || value.tv_sec < 0 || value.tv_nsec < 0
        || value.tv_nsec >= 1000000000L) {
        return 0;
    }
    seconds = (uint64_t)value.tv_sec;
    if (seconds > UINT64_MAX / UINT64_C(1000)) {
        return 0;
    }
    *out_ms = seconds * UINT64_C(1000)
        + (uint64_t)value.tv_nsec / UINT64_C(1000000);
    return 1;
}

static void usage(FILE *stream, const char *program)
{
    (void)fprintf(stream,
        "Usage: %s --usb DEVICE --database PATH "
        "--binding FILE [--binding FILE] [--timeout-ms 100..60000] "
        "[--send-binding 1|2 --send-service SLOT --payload-hex HEX]\n",
        program);
}

static int parse_u32(const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || out == NULL || text[0] == '\0') {
        return 0;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

static int hex_nibble(char value, uint8_t *out)
{
    if (out == NULL) {
        return 0;
    }
    if (value >= '0' && value <= '9') {
        *out = (uint8_t)(value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *out = (uint8_t)(value - 'a' + 10);
        return 1;
    }
    if (value >= 'A' && value <= 'F') {
        *out = (uint8_t)(value - 'A' + 10);
        return 1;
    }
    return 0;
}

static int parse_payload_hex(
    const char *text,
    uint8_t out[CONTROLLER_PAYLOAD_MAX],
    uint32_t *out_length)
{
    size_t text_length;
    size_t index;

    if (text == NULL || out == NULL || out_length == NULL) {
        return 0;
    }
    text_length = strlen(text);
    if (text_length < 2u || text_length > CONTROLLER_PAYLOAD_MAX * 2u
        || (text_length & 1u) != 0u) {
        return 0;
    }
    for (index = 0u; index < text_length / 2u; ++index) {
        uint8_t high;
        uint8_t low;
        if (!hex_nibble(text[index * 2u], &high)
            || !hex_nibble(text[index * 2u + 1u], &low)) {
            secure_clear(out, CONTROLLER_PAYLOAD_MAX);
            return 0;
        }
        out[index] = (uint8_t)((high << 4u) | low);
    }
    *out_length = (uint32_t)(text_length / 2u);
    return 1;
}

static int parse_options(
    int argc, char **argv, controller_options_t *out_options)
{
    controller_options_t options;
    uint8_t send_options = 0u;
    int i;

    if (argv == NULL || out_options == NULL) {
        return 0;
    }
    (void)memset(&options, 0, sizeof(options));
    options.timeout_ms = CONTROLLER_TIMEOUT_DEFAULT_MS;
    for (i = 1; i < argc; ++i) {
        const char *argument = argv[i];

        if (strcmp(argument, "--usb") == 0 && i + 1 < argc
            && options.usb_path == NULL) {
            options.usb_path = argv[++i];
        } else if (strcmp(argument, "--database") == 0 && i + 1 < argc
            && options.database_path == NULL) {
            options.database_path = argv[++i];
        } else if (strcmp(argument, "--binding") == 0 && i + 1 < argc
            && options.binding_count < CONTROLLER_BINDING_MAX) {
            options.binding_paths[options.binding_count++] = argv[++i];
        } else if (strcmp(argument, "--timeout-ms") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &options.timeout_ms)) {
                return 0;
            }
        } else if (strcmp(argument, "--send-binding") == 0 && i + 1 < argc
            && (send_options & 1u) == 0u) {
            uint32_t value;
            if (!parse_u32(argv[++i], &value) || value == 0u
                || value > CONTROLLER_BINDING_MAX) {
                return 0;
            }
            options.send_binding = (uint8_t)value;
            send_options |= 1u;
        } else if (strcmp(argument, "--send-service") == 0 && i + 1 < argc
            && (send_options & 2u) == 0u) {
            uint32_t value;
            if (!parse_u32(argv[++i], &value) || value == 0u
                || value > UINT8_MAX) {
                return 0;
            }
            options.send_service = (uint8_t)value;
            send_options |= 2u;
        } else if (strcmp(argument, "--payload-hex") == 0 && i + 1 < argc
            && (send_options & 4u) == 0u) {
            if (!parse_payload_hex(argv[++i], options.payload,
                    &options.payload_length)) {
                return 0;
            }
            send_options |= 4u;
        } else {
            return 0;
        }
    }
    if (options.usb_path == NULL || options.usb_path[0] != '/'
        || options.database_path == NULL || options.database_path[0] == '\0'
        || options.binding_count == 0u || options.timeout_ms < 100u
        || options.timeout_ms > 60000u
        || (send_options != 0u && send_options != 7u)
        || (send_options == 7u
            && options.send_binding > options.binding_count)) {
        return 0;
    }
    options.send_enabled = send_options == 7u ? 1u : 0u;
    *out_options = options;
    return 1;
}

static int read_binding_file(
    const char *path,
    uint8_t out[NINLIL_V1_LAB_BINDING_MAX_BYTES],
    size_t *out_length)
{
    struct stat status;
    size_t used = 0u;
    int descriptor;

    if (path == NULL || out == NULL || out_length == NULL) {
        return 0;
    }
    *out_length = 0u;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &status) != 0
        || !S_ISREG(status.st_mode) || status.st_nlink != 1
        || status.st_uid != geteuid()
        || (status.st_mode & (mode_t)(S_IRWXG | S_IRWXO)) != 0
        || status.st_size < (off_t)NINLIL_V1_LAB_BINDING_MIN_BYTES
        || status.st_size > (off_t)NINLIL_V1_LAB_BINDING_MAX_BYTES) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return 0;
    }
    while (used < (size_t)status.st_size) {
        ssize_t amount = read(descriptor, out + used,
            (size_t)status.st_size - used);
        if (amount > 0) {
            used += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            secure_clear(out, NINLIL_V1_LAB_BINDING_MAX_BYTES);
            (void)close(descriptor);
            return 0;
        }
    }
    if (close(descriptor) != 0) {
        secure_clear(out, NINLIL_V1_LAB_BINDING_MAX_BYTES);
        return 0;
    }
    *out_length = used;
    return 1;
}

static const ninlil_v1_lab_endpoint_t *controller_endpoint(
    const ninlil_v1_lab_binding_t *binding)
{
    if (binding == NULL) {
        return NULL;
    }
    if (binding->controller_side == NINLIL_V1_LAB_SIDE_A) {
        return &binding->endpoint_a;
    }
    if (binding->controller_side == NINLIL_V1_LAB_SIDE_B) {
        return &binding->endpoint_b;
    }
    return NULL;
}

static const ninlil_v1_lab_endpoint_t *peer_endpoint(
    const ninlil_v1_lab_binding_t *binding)
{
    if (binding == NULL) {
        return NULL;
    }
    if (binding->controller_side == NINLIL_V1_LAB_SIDE_A) {
        return &binding->endpoint_b;
    }
    if (binding->controller_side == NINLIL_V1_LAB_SIDE_B) {
        return &binding->endpoint_a;
    }
    return NULL;
}

static int controller_flow_matches(
    const ninlil_v1_lab_binding_t *binding,
    uint8_t flow)
{
    return binding != NULL
        && ((binding->controller_side == NINLIL_V1_LAB_SIDE_A
                && flow == NINLIL_V1_LAB_FLOW_A_TO_B)
            || (binding->controller_side == NINLIL_V1_LAB_SIDE_B
                && flow == NINLIL_V1_LAB_FLOW_B_TO_A));
}

static const ninlil_v1_lab_service_row_t *find_send_row(
    const ninlil_v1_lab_binding_t *binding,
    uint8_t slot,
    uint8_t *out_index)
{
    uint8_t index;

    if (binding == NULL || out_index == NULL) {
        return NULL;
    }
    for (index = 0u; index < binding->service_count; ++index) {
        const ninlil_v1_lab_service_row_t *row = &binding->services[index];
        if (row->slot == slot
            && row->family == NINLIL_FAMILY_DESIRED_STATE
            && row->direction == NINLIL_DIRECTION_DOWNLINK
            && controller_flow_matches(binding, row->flow)) {
            *out_index = index;
            return row;
        }
    }
    return NULL;
}

static int bindings_share_controller(
    const ninlil_v1_lab_binding_t *bindings, uint8_t count)
{
    const ninlil_v1_lab_endpoint_t *first;
    uint8_t i;

    if (bindings == NULL || count == 0u || count > CONTROLLER_BINDING_MAX) {
        return 0;
    }
    first = controller_endpoint(&bindings[0]);
    if (first == NULL) {
        return 0;
    }
    for (i = 1u; i < count; ++i) {
        const ninlil_v1_lab_endpoint_t *next =
            controller_endpoint(&bindings[i]);
        if (next == NULL
            || memcmp(first->runtime_id, next->runtime_id, 16u) != 0
            || memcmp(first->application_id, next->application_id, 16u) != 0
            || memcmp(first->device_id, next->device_id, 16u) != 0
            || memcmp(first->installation_id, next->installation_id, 16u) != 0
            || memcmp(first->site_id, next->site_id, 16u) != 0
            || first->binding_epoch != next->binding_epoch
            || first->membership_epoch != next->membership_epoch
            || first->identity_flags != next->identity_flags
            || memcmp(first->clock_epoch_id, next->clock_epoch_id, 16u) != 0
            || first->clock_trust != next->clock_trust) {
            return 0;
        }
    }
    return count != CONTROLLER_BINDING_MAX
        || memcmp(bindings[0].pair_id, bindings[1].pair_id, 32u) != 0;
}

static int wait_for_board_info(
    controller_context_t *context, uint32_t timeout_ms)
{
    uint64_t start;

    if (context == NULL || !monotonic_ms(&start)) {
        return 0;
    }
    for (;;) {
        ninlil_nvb1_board_info_t info;
        uint64_t now;
        ninlil_v1_usb_bridge_status_t status;

        if (!monotonic_ms(&now) || now < start || now - start > timeout_ms) {
            return 0;
        }
        status = ninlil_v1_usb_bridge_step(
            &context->bridge, now, CONTROLLER_POLL_MS);
        if (status != NINLIL_V1_USB_BRIDGE_OK
            && status != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
            return 0;
        }
        (void)memset(&info, 0, sizeof(info));
        if (ninlil_v1_usb_fabric_link_board_info(&context->link, &info)
            == NINLIL_V1_USB_FABRIC_LINK_OK) {
            secure_clear(&info, sizeof(info));
            return 1;
        }
    }
}

static int wait_for_completion(
    controller_context_t *context,
    ninlil_v1_usb_bridge_handle_t handle,
    uint32_t timeout_ms,
    ninlil_v1_usb_bridge_completion_t *out_completion)
{
    uint64_t start;

    if (context == NULL || out_completion == NULL || !monotonic_ms(&start)) {
        return 0;
    }
    (void)memset(out_completion, 0, sizeof(*out_completion));
    for (;;) {
        uint64_t now;
        ninlil_v1_usb_bridge_status_t status;

        if (!monotonic_ms(&now) || now < start || now - start > timeout_ms) {
            return 0;
        }
        status = ninlil_v1_usb_bridge_step(
            &context->bridge, now, CONTROLLER_POLL_MS);
        if (status != NINLIL_V1_USB_BRIDGE_OK
            && status != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
            return 0;
        }
        status = ninlil_v1_usb_bridge_take_completion(
            &context->bridge, handle, out_completion);
        if (status == NINLIL_V1_USB_BRIDGE_OK) {
            return 1;
        }
        if (status != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
            return 0;
        }
    }
}

static ninlil_runtime_config_t runtime_config(
    const ninlil_v1_lab_endpoint_t *endpoint,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_LAB;
    (void)memcpy(config.runtime_id.bytes, endpoint->runtime_id, 16u);
    config.local_identity.abi_version = NINLIL_ABI_VERSION;
    config.local_identity.struct_size =
        (uint16_t)sizeof(config.local_identity);
    config.local_identity.flags = endpoint->identity_flags;
    (void)memcpy(config.local_identity.device_id.bytes,
        endpoint->device_id, 16u);
    (void)memcpy(config.local_identity.installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(config.local_identity.site_domain_id.bytes,
        endpoint->site_id, 16u);
    config.local_identity.binding_epoch = endpoint->binding_epoch;
    config.local_identity.membership_epoch = endpoint->membership_epoch;
    config.storage_namespace.data = storage_namespace;
    config.storage_namespace.length = storage_namespace_length;
    config.limits.abi_version = NINLIL_ABI_VERSION;
    config.limits.struct_size = (uint16_t)sizeof(config.limits);
    config.limits.max_services = 6u;
    config.limits.max_nonterminal_transactions = 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 128u;
    config.limits.max_durable_outbox_payload_bytes = 8192u;
    config.limits.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 16u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_result_cache_entries = 16u;
    config.limits.max_retained_dispositions = 16u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 60000u;
    config.result_cache_retention_ms = 60000u;
    config.observation_retention_ms = 60000u;
    return config;
}

static int create_composition(
    controller_context_t *context,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    static const uint8_t namespace_prefix[4] = {'N', 'L', 'C', '1'};
    uint8_t storage_namespace[20];
    ninlil_runtime_config_t config;
    const ninlil_platform_ops_t *platform_ops;
    uint32_t bytes = 0u;
    uint32_t alignment = 0u;

    if (context == NULL || endpoint == NULL || context->platform == NULL) {
        return 0;
    }
    (void)memcpy(storage_namespace, namespace_prefix, sizeof(namespace_prefix));
    (void)memcpy(storage_namespace + sizeof(namespace_prefix),
        endpoint->runtime_id, 16u);
    config = runtime_config(
        endpoint, storage_namespace, (uint32_t)sizeof(storage_namespace));
    platform_ops = ninlil_v1_lab_controller_platform_ops(context->platform);
    if (platform_ops == NULL
        || ninlil_composition_v1_workspace_required(
               NINLIL_COMPOSITION_PROFILE_1, &bytes, &alignment)
            != NINLIL_OK
        || bytes == 0u || alignment == 0u
        || posix_memalign(&context->composition_workspace,
               alignment < sizeof(void *) ? sizeof(void *) : alignment,
               bytes)
            != 0) {
        return 0;
    }
    context->composition_workspace_bytes = bytes;
    if (ninlil_composition_v1_create(NINLIL_COMPOSITION_PROFILE_1,
            &config, platform_ops, context->composition_workspace,
            bytes, &context->composition) != NINLIL_OK
        || ninlil_composition_v1_runtime(
               context->composition, &context->runtime)
            != NINLIL_OK
        || ninlil_composition_v1_fabric(
               context->composition, &context->fabric)
            != NINLIL_OK) {
        return 0;
    }
    secure_clear(storage_namespace, sizeof(storage_namespace));
    return 1;
}

static int path_seen(
    const uint8_t paths[CONTROLLER_PATH_MAX][16],
    uint8_t count,
    const uint8_t path_id[16])
{
    uint8_t i;

    for (i = 0u; i < count; ++i) {
        if (memcmp(paths[i], path_id, 16u) == 0) {
            return 1;
        }
    }
    return 0;
}

static int register_bindings(
    controller_context_t *context,
    const ninlil_v1_lab_binding_t *bindings,
    uint8_t binding_count,
    const uint8_t local_runtime_id[16],
    uint8_t *out_service_rows)
{
    uint8_t paths[CONTROLLER_PATH_MAX][16];
    uint8_t path_count = 0u;
    uint8_t service_rows = 0u;
    uint8_t pair_index;

    (void)memset(paths, 0, sizeof(paths));
    for (pair_index = 0u; pair_index < binding_count; ++pair_index) {
        const ninlil_v1_lab_binding_t *binding = &bindings[pair_index];
        uint8_t row_index;

        for (row_index = 0u; row_index < binding->service_count; ++row_index) {
            const ninlil_v1_lab_service_row_t *row =
                &binding->services[row_index];
            ninlil_fabric_path_policy_v1_t policy;
            ninlil_fabric_authority_binding_v1_t authority;

            if (!path_seen(paths, path_count, row->selected_path_id)) {
                const ninlil_fabric_link_descriptor_v1_t *descriptor = NULL;
                const ninlil_fabric_packet_link_ops_v1_t *ops = NULL;

                if (path_count >= CONTROLLER_PATH_MAX
                    || ninlil_v1_usb_fabric_link_path(&context->link,
                           row->selected_path_id, &descriptor, &ops)
                        != NINLIL_V1_USB_FABRIC_LINK_OK
                    || ninlil_fabric_v1_register_link(context->fabric,
                           descriptor, ops,
                           &context->registrations[context->registration_count])
                        != NINLIL_FABRIC_OK) {
                    secure_clear(paths, sizeof(paths));
                    return 0;
                }
                context->registration_count += 1u;
                if (ninlil_fabric_private_rf_mapping_approve_v1(
                        context->fabric,
                        context->registrations[
                            context->registration_count - 1u])
                    != NINLIL_FABRIC_OK) {
                    secure_clear(paths, sizeof(paths));
                    return 0;
                }
                (void)memcpy(paths[path_count], row->selected_path_id, 16u);
                path_count += 1u;
            }
            (void)memset(&policy, 0, sizeof(policy));
            (void)memset(&authority, 0, sizeof(authority));
            if (ninlil_v1_lab_fabric_build_service(&context->crypto,
                    binding, local_runtime_id, row_index,
                    &policy, &authority) != NINLIL_V1_LAB_FABRIC_OK
                || ninlil_fabric_v1_policy_put(context->fabric, &policy)
                    != NINLIL_FABRIC_OK
                || ninlil_fabric_v1_authority_put(context->fabric, &authority)
                    != NINLIL_FABRIC_OK) {
                secure_clear(&policy, sizeof(policy));
                secure_clear(&authority, sizeof(authority));
                secure_clear(paths, sizeof(paths));
                return 0;
            }
            secure_clear(&policy, sizeof(policy));
            secure_clear(&authority, sizeof(authority));
            service_rows += 1u;
        }
    }
    secure_clear(paths, sizeof(paths));
    *out_service_rows = service_rows;
    return 1;
}

static int register_submission_service(
    controller_context_t *context,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t local_runtime_id[16],
    uint8_t row_index)
{
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;

    if (context == NULL || context->runtime == NULL || binding == NULL
        || local_runtime_id == NULL || row_index >= binding->service_count) {
        return 0;
    }
    (void)memset(&descriptor, 0, sizeof(descriptor));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    callbacks.abi_version = NINLIL_ABI_VERSION;
    callbacks.struct_size = (uint16_t)sizeof(callbacks);
    return ninlil_v1_lab_fabric_build_descriptor(binding,
               local_runtime_id, row_index, &descriptor)
                == NINLIL_V1_LAB_FABRIC_OK
        && ninlil_service_register(context->runtime, &descriptor,
               &callbacks, &context->submission_service)
            == NINLIL_OK;
}

static int composition_step_once(
    controller_context_t *context,
    uint32_t runtime_work)
{
    ninlil_composition_step_budget_v1_t budget;
    ninlil_composition_step_result_v1_t result;

    if (context == NULL || context->composition == NULL) {
        return 0;
    }
    (void)memset(&budget, 0, sizeof(budget));
    budget.api_version = NINLIL_COMPOSITION_API_VERSION;
    budget.struct_size = (uint16_t)sizeof(budget);
    budget.runtime.abi_version = NINLIL_ABI_VERSION;
    budget.runtime.struct_size = (uint16_t)sizeof(budget.runtime);
    if (runtime_work != 0u) {
        budget.runtime.max_ingress_messages = 8u;
        budget.runtime.max_callbacks = 8u;
        budget.runtime.max_state_transitions = 16u;
        budget.runtime.max_bearer_sends = 8u;
    }
    budget.fabric_work = 64u;
    (void)memset(&result, 0, sizeof(result));
    result.api_version = NINLIL_COMPOSITION_API_VERSION;
    result.struct_size = (uint16_t)sizeof(result);
    return ninlil_composition_v1_step(
               context->composition, &budget, &result)
        == NINLIL_OK;
}

static void fill_target(
    ninlil_concrete_target_t *target,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memset(target, 0, sizeof(*target));
    target->abi_version = NINLIL_ABI_VERSION;
    target->struct_size = (uint16_t)sizeof(*target);
    (void)memcpy(target->target_runtime_id.bytes,
        endpoint->runtime_id, 16u);
    (void)memcpy(target->target_application_instance_id.bytes,
        endpoint->application_id, 16u);
    (void)memcpy(target->device_id.bytes, endpoint->device_id, 16u);
    (void)memcpy(target->installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(target->site_domain_id.bytes, endpoint->site_id, 16u);
    target->binding_epoch = endpoint->binding_epoch;
    target->membership_epoch = endpoint->membership_epoch;
    target->flags = endpoint->identity_flags;
}

static int drain_terminal_usb_status(
    controller_context_t *context,
    const ninlil_clock_ops_t *clock,
    uint32_t timeout_ms)
{
    uint64_t start;

    if (context == NULL || clock == NULL || clock->now == NULL
        || context->stream.ops == NULL || context->stream.ops->stats == NULL
        || !monotonic_ms(&start)) {
        return 0;
    }
    for (;;) {
        ninlil_byte_stream_stats_t stats;
        ninlil_time_sample_t sample;
        ninlil_v1_usb_bridge_status_t status;
        uint64_t now;

        (void)memset(&sample, 0, sizeof(sample));
        if (clock->now(clock->user, &sample) != NINLIL_PORT_OK
            || sample.trust != NINLIL_CLOCK_TRUSTED) {
            return 0;
        }
        status = ninlil_v1_usb_fabric_link_step(
            &context->link, sample.now_ms, CONTROLLER_POLL_MS);
        if (status != NINLIL_V1_USB_BRIDGE_OK
            && status != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
            return 0;
        }
        (void)memset(&stats, 0, sizeof(stats));
        context->stream.ops->stats(&context->stream, &stats);
        if (context->bridge.tx_wire_length == 0u
            && stats.tx_ring_bytes == 0u) {
            return 1;
        }
        if (!monotonic_ms(&now) || now < start
            || now - start > timeout_ms) {
            return 0;
        }
    }
}

static int run_submission(
    controller_context_t *context,
    const controller_options_t *options,
    const ninlil_v1_lab_binding_t *binding,
    const ninlil_v1_lab_service_row_t *row,
    controller_submission_summary_t *out_summary)
{
    const ninlil_v1_lab_endpoint_t *peer = peer_endpoint(binding);
    const ninlil_platform_ops_t *platform_ops;
    ninlil_concrete_target_t target;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target_snapshot;
    ninlil_time_sample_t clock_sample;
    uint8_t idempotency_key[CONTROLLER_IDEMPOTENCY_BYTES];
    uint64_t start;

    if (context == NULL || options == NULL || binding == NULL || row == NULL
        || out_summary == NULL || peer == NULL || context->runtime == NULL
        || context->submission_service == NULL || context->platform == NULL
        || options->payload_length == 0u
        || options->payload_length > CONTROLLER_PAYLOAD_MAX) {
        return 0;
    }
    platform_ops = ninlil_v1_lab_controller_platform_ops(context->platform);
    if (platform_ops == NULL || platform_ops->clock == NULL
        || platform_ops->entropy == NULL) {
        return 0;
    }
    (void)memset(&clock_sample, 0, sizeof(clock_sample));
    if (platform_ops->clock->now(
            platform_ops->clock->user, &clock_sample)
            != NINLIL_PORT_OK
        || clock_sample.trust != NINLIL_CLOCK_TRUSTED) {
        return 0;
    }
    (void)memset(idempotency_key, 0, sizeof(idempotency_key));
    if (platform_ops->entropy->fill(platform_ops->entropy->user,
            idempotency_key, sizeof(idempotency_key))
            != NINLIL_PORT_OK
        || !bytes_nonzero(idempotency_key, sizeof(idempotency_key))) {
        secure_clear(idempotency_key, sizeof(idempotency_key));
        return 0;
    }
    fill_target(&target, peer);
    (void)memset(&submission, 0, sizeof(submission));
    submission.abi_version = NINLIL_ABI_VERSION;
    submission.struct_size = (uint16_t)sizeof(submission);
    submission.schema_major = row->schema_major;
    submission.schema_minor = row->schema_minor;
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_VERIFIED;
    submission.effect_deadline_ms = options->timeout_ms;
    submission.evidence_grace_ms = row->evidence_grace_ms;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length = sizeof(idempotency_key);
    submission.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    submission.generation = 1u;
    submission.payload.data = options->payload;
    submission.payload.length = options->payload_length;
    if (ninlil_r7_crypto_sha256(&context->crypto, options->payload,
            options->payload_length, submission.content_digest.bytes)
            != NINLIL_R7_CRYPTO_OK) {
        secure_clear(idempotency_key, sizeof(idempotency_key));
        return 0;
    }
    (void)memset(&submit_result, 0, sizeof(submit_result));
    submit_result.abi_version = NINLIL_ABI_VERSION;
    submit_result.struct_size = (uint16_t)sizeof(submit_result);
    if (ninlil_submit(context->submission_service, &submission,
            &submit_result) != NINLIL_OK
        || submit_result.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
        secure_clear(idempotency_key, sizeof(idempotency_key));
        return 0;
    }
    secure_clear(idempotency_key, sizeof(idempotency_key));
    if (!monotonic_ms(&start)) {
        return 0;
    }
    for (;;) {
        ninlil_v1_usb_bridge_status_t bridge_status;
        ninlil_status_t query_status;
        uint64_t now;

        if (!monotonic_ms(&now) || now < start
            || now - start > options->timeout_ms) {
            (void)fprintf(stderr,
                "controller: submission wait exceeded its local timeout\n");
            return 0;
        }
        (void)memset(&clock_sample, 0, sizeof(clock_sample));
        if (platform_ops->clock->now(
                platform_ops->clock->user, &clock_sample)
                != NINLIL_PORT_OK
            || clock_sample.trust != NINLIL_CLOCK_TRUSTED) {
            (void)fprintf(stderr,
                "controller: trusted clock unavailable while awaiting "
                "evidence\n");
            return 0;
        }
        bridge_status = ninlil_v1_usb_fabric_link_step(
            &context->link, clock_sample.now_ms, CONTROLLER_POLL_MS);
        if (bridge_status != NINLIL_V1_USB_BRIDGE_OK
            && bridge_status != NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
            (void)fprintf(stderr,
                "controller: USB bridge failed while awaiting evidence "
                "(status=%u)\n", (unsigned)bridge_status);
            return 0;
        }
        if (!composition_step_once(context, 1u)) {
            (void)fprintf(stderr,
                "controller: Composition step failed while awaiting "
                "evidence\n");
            return 0;
        }
        (void)memset(&target_snapshot, 0, sizeof(target_snapshot));
        target_snapshot.abi_version = NINLIL_ABI_VERSION;
        target_snapshot.struct_size = (uint16_t)sizeof(target_snapshot);
        (void)memset(&snapshot, 0, sizeof(snapshot));
        snapshot.abi_version = NINLIL_ABI_VERSION;
        snapshot.struct_size = (uint16_t)sizeof(snapshot);
        snapshot.targets = &target_snapshot;
        snapshot.target_capacity = 1u;
        query_status = ninlil_transaction_query(context->runtime,
            &submit_result.transaction_id, &snapshot);
        if (query_status != NINLIL_OK) {
            (void)fprintf(stderr,
                "controller: transaction query failed while awaiting "
                "evidence (status=%u)\n", (unsigned)query_status);
            return 0;
        }
        if (snapshot.state == NINLIL_TXN_TERMINAL) {
            int satisfied;

            out_summary->outcome = snapshot.outcome;
            out_summary->latest_evidence = snapshot.latest_evidence;
            out_summary->reason = snapshot.reason;
            out_summary->target_reason = target_snapshot.reason;
            out_summary->attempts = target_snapshot.cumulative_attempts;
            satisfied = snapshot.outcome == NINLIL_OUTCOME_SATISFIED
                && snapshot.latest_evidence >= NINLIL_EVIDENCE_VERIFIED;
            if (satisfied
                && !drain_terminal_usb_status(context,
                    platform_ops->clock, options->timeout_ms)) {
                (void)fprintf(stderr,
                    "controller: could not flush the terminal USB status\n");
                return 0;
            }
            return satisfied;
        }
    }
}

static int cleanup_context(controller_context_t *context)
{
    uint32_t step;
    uint8_t i;

    if (context == NULL) {
        return 0;
    }
    if (context->fabric != NULL) {
        for (i = 0u; i < context->registration_count; ++i) {
            if (context->registrations[i] != NULL) {
                if (ninlil_fabric_v1_unregister_begin(
                        context->fabric, context->registrations[i])
                    != NINLIL_FABRIC_OK) {
                    return 0;
                }
            }
        }
        for (step = 0u; step < CONTROLLER_STEP_LIMIT; ++step) {
            uint32_t all_done = 1u;
            for (i = 0u; i < context->registration_count; ++i) {
                uint32_t done = 0u;
                if (context->registrations[i] != NULL) {
                    if (ninlil_fabric_v1_unregister_poll(context->fabric,
                            context->registrations[i], &done)
                        != NINLIL_FABRIC_OK) {
                        return 0;
                    }
                    if (done != 0u) {
                        context->registrations[i] = NULL;
                    }
                }
                if (context->registrations[i] != NULL) {
                    all_done = 0u;
                }
            }
            if (all_done != 0u) {
                break;
            }
            if (!composition_step_once(context, 0u)) {
                return 0;
            }
        }
        for (i = 0u; i < context->registration_count; ++i) {
            if (context->registrations[i] != NULL) {
                return 0;
            }
        }
    }
    if (context->composition != NULL) {
        uint32_t done = 0u;
        if (ninlil_composition_v1_close_begin(context->composition)
            != NINLIL_OK) {
            return 0;
        }
        for (step = 0u; step < CONTROLLER_STEP_LIMIT && done == 0u; ++step) {
            if (ninlil_composition_v1_close_poll(
                    context->composition, 64u, &done)
                != NINLIL_OK) {
                return 0;
            }
        }
        if (done == 0u
            || ninlil_composition_v1_destroy(context->composition)
                != NINLIL_OK) {
            return 0;
        }
        context->composition = NULL;
        context->runtime = NULL;
        context->fabric = NULL;
    }
    free(context->composition_workspace);
    context->composition_workspace = NULL;
    context->composition_workspace_bytes = 0u;
    if (context->link_prepared != 0u) {
        ninlil_v1_usb_fabric_link_clear(&context->link);
    }
    if (context->bridge_initialized != 0u) {
        ninlil_v1_usb_bridge_clear(&context->bridge);
    }
    if (context->platform != NULL) {
        ninlil_v1_lab_controller_platform_destroy(context->platform);
        context->platform = NULL;
    }
    if (context->stream_open != 0u) {
        ninlil_byte_stream_error_t error;
        (void)memset(&error, 0, sizeof(error));
        if (ninlil_posix_usb_serial_close(&context->stream, &error)
            != NINLIL_BYTE_STREAM_OK) {
            return 0;
        }
        context->stream_open = 0u;
    }
    secure_clear(context, sizeof(*context));
    return 1;
}

static int run_controller_probe(const controller_options_t *options)
{
    controller_context_t context;
    ninlil_v1_lab_binding_t bindings[CONTROLLER_BINDING_MAX];
    uint8_t encoded[CONTROLLER_BINDING_MAX]
        [NINLIL_V1_LAB_BINDING_MAX_BYTES];
    size_t encoded_lengths[CONTROLLER_BINDING_MAX];
    const ninlil_v1_lab_endpoint_t *controller;
    ninlil_nvb1_board_info_t board_info;
    ninlil_v1_lab_controller_platform_config_t platform_config;
    ninlil_v1_usb_bridge_config_t bridge_config;
    ninlil_byte_stream_error_t stream_error;
    controller_submission_summary_t submission_summary;
    const ninlil_v1_lab_service_row_t *send_row = NULL;
    uint8_t send_row_index = 0u;
    uint8_t service_rows = 0u;
    uint8_t registered_paths = 0u;
    uint8_t i;
    int ok = 0;

    (void)memset(&context, 0, sizeof(context));
    (void)memset(bindings, 0, sizeof(bindings));
    (void)memset(encoded, 0, sizeof(encoded));
    (void)memset(encoded_lengths, 0, sizeof(encoded_lengths));
    (void)memset(&submission_summary, 0, sizeof(submission_summary));
    if (ninlil_r7_crypto_openssl3_provider_init(&context.crypto)
        != NINLIL_R7_CRYPTO_OK) {
        (void)fprintf(stderr, "controller: OpenSSL provider unavailable\n");
        goto done;
    }
    for (i = 0u; i < options->binding_count; ++i) {
        if (!read_binding_file(options->binding_paths[i],
                encoded[i], &encoded_lengths[i])
            || ninlil_v1_lab_binding_decode(&context.crypto,
                   encoded[i], encoded_lengths[i], &bindings[i])
                != NINLIL_V1_LAB_BINDING_OK) {
            (void)fprintf(stderr,
                "controller: binding %u is unreadable or invalid\n",
                (unsigned)(i + 1u));
            goto done;
        }
    }
    if (!bindings_share_controller(bindings, options->binding_count)) {
        (void)fprintf(stderr,
            "controller: bindings do not name distinct pairs for one exact "
            "Controller endpoint\n");
        goto done;
    }
    controller = controller_endpoint(&bindings[0]);
    if (controller == NULL || !bytes_nonzero(controller->runtime_id, 16u)) {
        goto done;
    }
    if (options->send_enabled != 0u) {
        send_row = find_send_row(
            &bindings[options->send_binding - 1u],
            options->send_service,
            &send_row_index);
        if (send_row == NULL) {
            (void)fprintf(stderr,
                "controller: selected Service is not an outbound "
                "DesiredState row\n");
            goto done;
        }
    }

    if (ninlil_posix_usb_serial_init_object(
            &context.usb_object, &context.stream)
        != NINLIL_BYTE_STREAM_OK) {
        (void)fprintf(stderr, "controller: USB serial initialization failed\n");
        goto done;
    }
    (void)memset(&stream_error, 0, sizeof(stream_error));
    if (ninlil_posix_usb_serial_open(
            &context.stream, options->usb_path, &stream_error)
        != NINLIL_BYTE_STREAM_OK) {
        (void)fprintf(stderr, "controller: cannot open USB device\n");
        goto done;
    }
    context.stream_open = 1u;
    if (ninlil_v1_usb_fabric_link_prepare(&context.link)
        != NINLIL_V1_USB_FABRIC_LINK_OK) {
        goto done;
    }
    context.link_prepared = 1u;
    (void)memset(&bridge_config, 0, sizeof(bridge_config));
    bridge_config.role = NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER;
    bridge_config.stream = &context.stream;
    bridge_config.fabric_handoff = ninlil_v1_usb_fabric_link_handoff;
    bridge_config.board_info = ninlil_v1_usb_fabric_link_board_info_handoff;
    bridge_config.callback_user = &context.link;
    if (ninlil_v1_usb_bridge_init(&context.bridge, &bridge_config)
        != NINLIL_V1_USB_BRIDGE_OK) {
        goto done;
    }
    context.bridge_initialized = 1u;
    if (!wait_for_board_info(&context, options->timeout_ms)) {
        (void)fprintf(stderr,
            "controller: timed out waiting for BOARD_INFO\n");
        goto done;
    }
    (void)memset(&board_info, 0, sizeof(board_info));
    if (ninlil_v1_usb_fabric_link_board_info(&context.link, &board_info)
            != NINLIL_V1_USB_FABRIC_LINK_OK
        || memcmp(board_info.clock_epoch_id,
               controller->clock_epoch_id, 16u)
            != 0) {
        (void)fprintf(stderr,
            "controller: binding clock does not match this parent boot\n");
        goto done;
    }
    (void)memset(&platform_config, 0, sizeof(platform_config));
    platform_config.database_path = options->database_path;
    (void)memcpy(platform_config.clock_epoch_id,
        board_info.clock_epoch_id, 16u);
    platform_config.clock_anchor_ms = board_info.clock_now_ms;
    context.platform =
        ninlil_v1_lab_controller_platform_create(&platform_config);
    if (context.platform == NULL) {
        (void)fprintf(stderr,
            "controller: cannot create Host providers or SQLite store\n");
        goto done;
    }
    for (i = 0u; i < options->binding_count; ++i) {
        ninlil_v1_usb_bridge_handle_t handle;
        ninlil_v1_usb_bridge_completion_t completion;
        const ninlil_platform_ops_t *platform_ops =
            ninlil_v1_lab_controller_platform_ops(context.platform);
        uint64_t bridge_now;

        if (platform_ops == NULL
            || !monotonic_ms(&bridge_now)
            || bridge_now > UINT64_MAX - options->timeout_ms
            || ninlil_v1_usb_bridge_submit_binding(&context.bridge,
                   encoded[i], encoded_lengths[i],
                   bridge_now + options->timeout_ms, &handle)
                != NINLIL_V1_USB_BRIDGE_OK
            || !wait_for_completion(
                   &context, handle, options->timeout_ms, &completion)
            || completion.reason
                != NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS
            || completion.remote_status_code != NINLIL_NVB1_STATUS_INSTALLED
            || completion.pair_generation != bindings[i].pair_generation
            || ninlil_v1_usb_fabric_link_activate(&context.link,
                   &context.bridge, &context.crypto, platform_ops->clock,
                   controller->runtime_id, encoded[i], encoded_lengths[i],
                   completion.pair_generation)
                != NINLIL_V1_USB_FABRIC_LINK_OK) {
            (void)fprintf(stderr,
                "controller: parent rejected binding %u\n",
                (unsigned)(i + 1u));
            goto done;
        }
    }
    if (!create_composition(&context, controller)) {
        (void)fprintf(stderr,
            "controller: Composition creation failed\n");
        goto done;
    }
    if (!register_bindings(&context, bindings, options->binding_count,
            controller->runtime_id, &service_rows)) {
        (void)fprintf(stderr, "controller: Fabric registration failed\n");
        goto done;
    }
    if (options->send_enabled != 0u
        && !register_submission_service(&context,
            &bindings[options->send_binding - 1u],
            controller->runtime_id, send_row_index)) {
        (void)fprintf(stderr,
            "controller: Runtime Service registration failed\n");
        goto done;
    }
    if (!composition_step_once(&context, options->send_enabled)) {
        (void)fprintf(stderr, "controller: initial Composition step failed\n");
        goto done;
    }
    registered_paths = context.registration_count;
    if (options->send_enabled != 0u
        && !run_submission(&context, options,
            &bindings[options->send_binding - 1u], send_row,
            &submission_summary)) {
        (void)fprintf(stderr,
            "controller: ApplicationData did not reach VERIFIED success "
            "(outcome=%u reason=%u target_reason=%u evidence=%u "
            "attempts=%llu)\n",
            (unsigned)submission_summary.outcome,
            (unsigned)submission_summary.reason,
            (unsigned)submission_summary.target_reason,
            (unsigned)submission_summary.latest_evidence,
            (unsigned long long)submission_summary.attempts);
        goto done;
    }
    ok = 1;

done:
    if (!cleanup_context(&context)) {
        (void)fprintf(stderr,
            "controller: cleanup did not reach a quiescent state\n");
        ok = 0;
    }
    for (i = 0u; i < CONTROLLER_BINDING_MAX; ++i) {
        ninlil_v1_lab_binding_clear(&bindings[i]);
    }
    secure_clear(encoded, sizeof(encoded));
    secure_clear(encoded_lengths, sizeof(encoded_lengths));
    secure_clear(&board_info, sizeof(board_info));
    secure_clear(&platform_config, sizeof(platform_config));
    if (ok != 0) {
        if (options->send_enabled != 0u) {
            (void)printf(
                "ninlil_v1_lab_controller SATISFIED pair=%u service=%u "
                "evidence=%u attempts=%llu\n",
                (unsigned)options->send_binding,
                (unsigned)options->send_service,
                (unsigned)submission_summary.latest_evidence,
                (unsigned long long)submission_summary.attempts);
        } else {
            (void)printf(
                "ninlil_v1_lab_controller READY pairs=%u paths=%u "
                "service_rows=%u\n",
                (unsigned)options->binding_count,
                (unsigned)registered_paths,
                (unsigned)service_rows);
        }
    }
    return ok;
}

int main(int argc, char **argv)
{
    controller_options_t options;
    int result;

    if (!parse_options(argc, argv, &options)) {
        usage(stderr, argc > 0 && argv != NULL ? argv[0]
                                               : "ninlil_v1_lab_controller");
        return 2;
    }
    result = run_controller_probe(&options) ? 0 : 1;
    secure_clear(&options, sizeof(options));
    return result;
}
