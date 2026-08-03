#include "ninlil/composition_v1.h"

#include "domain_store_codec.h"
#include "fabric_private_api.h"
#include "runtime_lifecycle_model.h"
#include "runtime_terminal_owner_projection.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define COMPOSITION_MAGIC UINT32_C(0x4e435331)
#define COMPOSITION_LIVE UINT32_C(1)
#define COMPOSITION_CLOSING UINT32_C(2)
#define COMPOSITION_CLOSED UINT32_C(3)
#define COMPOSITION_BASE_NAMESPACE_MAX UINT32_C(255)
#define COMPOSITION_FABRIC_WORK_MAX UINT32_C(64)
#define COMPOSITION_RELIABILITY_WORK_MAX UINT32_C(64)

static const uint8_t g_fabric_open_namespace[] = {
    'n', 'i', 'n', 'l', 'i', 'l', '.', 'f', 'a', 'b', 'r', 'i', 'c', '.',
    'v', '1'
};

struct ninlil_composition_v1 {
    uint32_t magic;
    uint32_t lifecycle;
    uint32_t workspace_bytes;
    uint32_t fabric_offset;
    uint32_t in_call;
    uint32_t terminal_owner_cursor;
    uint32_t terminal_owner_wrap_pending;
    uint32_t pending_terminal_owner_valid;
    uint32_t pending_terminal_projection_more;
    ninlil_status_t close_terminal_status;
    uint64_t owner_context_id;
    ninlil_rt_private_terminal_owner_v1_t pending_terminal_owner;
    ninlil_runtime_config_t runtime_config;
    uint8_t base_namespace[COMPOSITION_BASE_NAMESPACE_MAX];
    uint8_t fabric_namespace[32];
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_storage_ops_t underlying_storage;
    ninlil_storage_ops_t fabric_storage;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin_authorization;
    ninlil_platform_ops_t runtime_platform;
    ninlil_runtime_t *runtime;
    ninlil_fabric_v1_t *fabric;
};

static int bytes_equal(
    const uint8_t *left, const uint8_t *right, uint32_t length)
{
    return length == 0u || memcmp(left, right, length) == 0;
}

static int align_up_u32(
    uint32_t value, uint32_t alignment, uint32_t *out_value)
{
    uint64_t rounded;

    if (out_value == NULL || alignment == 0u
        || (alignment & (alignment - 1u)) != 0u) {
        return 0;
    }
    rounded = ((uint64_t)value + (uint64_t)alignment - 1u)
        & ~((uint64_t)alignment - 1u);
    if (rounded > UINT32_MAX) {
        return 0;
    }
    *out_value = (uint32_t)rounded;
    return 1;
}

static ninlil_status_t map_fabric_status(ninlil_fabric_status_t status)
{
    switch (status) {
    case NINLIL_FABRIC_OK:
        return NINLIL_OK;
    case NINLIL_FABRIC_INVALID_ARGUMENT:
        return NINLIL_E_INVALID_ARGUMENT;
    case NINLIL_FABRIC_WRONG_THREAD:
        return NINLIL_E_WRONG_THREAD;
    case NINLIL_FABRIC_REENTRANT:
        return NINLIL_E_REENTRANT;
    case NINLIL_FABRIC_CLOSED:
        return NINLIL_E_INVALID_STATE;
    case NINLIL_FABRIC_CONFLICT:
        return NINLIL_E_CONFLICT;
    case NINLIL_FABRIC_UNSUPPORTED:
        return NINLIL_E_UNSUPPORTED;
    case NINLIL_FABRIC_CORRUPT:
    case NINLIL_FABRIC_DENIED:
        return NINLIL_E_DEGRADED;
    case NINLIL_FABRIC_COMMIT_UNKNOWN:
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_FABRIC_UNAVAILABLE:
    case NINLIL_FABRIC_WOULD_BLOCK:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_FABRIC_CAPACITY:
        return NINLIL_E_CAPACITY_EXHAUSTED;
    default:
        return NINLIL_E_INVALID_STATE;
    }
}

static ninlil_bearer_status_t validation_bearer_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    (void)user;
    (void)runtime_id;
    (void)role;
    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    return NINLIL_BEARER_UNAVAILABLE;
}

static void validation_bearer_close(
    void *user, ninlil_bearer_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_bearer_status_t validation_bearer_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    (void)user;
    (void)handle;
    (void)permit;
    (void)message;
    (void)out_result;
    return NINLIL_BEARER_UNAVAILABLE;
}

static ninlil_bearer_status_t validation_bearer_receive_next(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    (void)user;
    (void)handle;
    (void)out_message;
    return NINLIL_BEARER_EMPTY;
}

static void validation_bearer_release_received(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    (void)user;
    (void)handle;
    (void)message;
}

static ninlil_bearer_status_t validation_bearer_state(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state)
{
    (void)user;
    (void)handle;
    (void)out_state;
    return NINLIL_BEARER_UNAVAILABLE;
}

static void init_validation_bearer(ninlil_bearer_ops_t *bearer)
{
    (void)memset(bearer, 0, sizeof(*bearer));
    bearer->abi_version = NINLIL_ABI_VERSION;
    bearer->struct_size = (uint16_t)sizeof(*bearer);
    bearer->open = validation_bearer_open;
    bearer->close = validation_bearer_close;
    bearer->send = validation_bearer_send;
    bearer->receive_next = validation_bearer_receive_next;
    bearer->release_received = validation_bearer_release_received;
    bearer->state = validation_bearer_state;
}

static ninlil_storage_status_t fabric_storage_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    ninlil_bytes_view_t derived;

    if (composition == NULL || out_handle == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    *out_handle = NULL;
    if (expected_schema != 1u
        || storage_namespace.length != sizeof(g_fabric_open_namespace)
        || storage_namespace.data == NULL
        || !bytes_equal(
            storage_namespace.data,
            g_fabric_open_namespace,
            (uint32_t)sizeof(g_fabric_open_namespace))) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    derived.data = composition->fabric_namespace;
    derived.length = (uint32_t)sizeof(composition->fabric_namespace);
    return composition->underlying_storage.open(
        composition->underlying_storage.user,
        derived,
        expected_schema,
        out_handle);
}

static void fabric_storage_close(void *user, ninlil_storage_handle_t handle)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    composition->underlying_storage.close(
        composition->underlying_storage.user, handle);
}

static ninlil_storage_status_t fabric_storage_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.begin(
        composition->underlying_storage.user, handle, mode, out_txn);
}

static ninlil_storage_status_t fabric_storage_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.get(
        composition->underlying_storage.user, txn, key, inout_value);
}

static ninlil_storage_status_t fabric_storage_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.put(
        composition->underlying_storage.user, txn, key, value);
}

static ninlil_storage_status_t fabric_storage_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.erase(
        composition->underlying_storage.user, txn, key);
}

static ninlil_storage_status_t fabric_storage_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.iter_open(
        composition->underlying_storage.user, txn, prefix, out_iter);
}

static ninlil_storage_status_t fabric_storage_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.iter_next(
        composition->underlying_storage.user,
        iter,
        inout_key,
        inout_value);
}

static void fabric_storage_iter_close(
    void *user, ninlil_storage_iter_t iter)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    composition->underlying_storage.iter_close(
        composition->underlying_storage.user, iter);
}

static ninlil_storage_status_t fabric_storage_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.capacity(
        composition->underlying_storage.user, handle, out_capacity);
}

static ninlil_storage_status_t fabric_storage_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.commit(
        composition->underlying_storage.user, txn, durability);
}

static ninlil_storage_status_t fabric_storage_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    ninlil_composition_v1_t *composition =
        (ninlil_composition_v1_t *)user;
    return composition->underlying_storage.rollback(
        composition->underlying_storage.user, txn);
}

static void init_fabric_storage(ninlil_composition_v1_t *composition)
{
    ninlil_storage_ops_t *storage = &composition->fabric_storage;

    (void)memset(storage, 0, sizeof(*storage));
    storage->abi_version = NINLIL_ABI_VERSION;
    storage->struct_size = (uint16_t)sizeof(*storage);
    storage->user = composition;
    storage->open = fabric_storage_open;
    storage->close = fabric_storage_close;
    storage->begin = fabric_storage_begin;
    storage->get = fabric_storage_get;
    storage->put = fabric_storage_put;
    storage->erase = fabric_storage_erase;
    storage->iter_open = fabric_storage_iter_open;
    storage->iter_next = fabric_storage_iter_next;
    storage->iter_close = fabric_storage_iter_close;
    storage->capacity = fabric_storage_capacity;
    storage->commit = fabric_storage_commit;
    storage->rollback = fabric_storage_rollback;
}

static ninlil_status_t derive_fabric_namespace(
    const ninlil_runtime_config_t *config, uint8_t out_namespace[32])
{
    static const uint8_t prefix[8] = {
        'N', 'C', 'S', '1', 1u, 0u, 0u, 0u
    };
    ninlil_model_domain_sha256_ctx_t context;
    ninlil_model_domain_digest_t digest;
    uint8_t length_be[4];
    ninlil_status_t status;

    length_be[0] = (uint8_t)(config->storage_namespace.length >> 24u);
    length_be[1] = (uint8_t)(config->storage_namespace.length >> 16u);
    length_be[2] = (uint8_t)(config->storage_namespace.length >> 8u);
    length_be[3] = (uint8_t)config->storage_namespace.length;
    ninlil_model_domain_sha256_init(&context);
    status = ninlil_model_domain_sha256_update(
        &context, prefix, (uint32_t)sizeof(prefix));
    if (status == NINLIL_OK) {
        status = ninlil_model_domain_sha256_update(
            &context, config->runtime_id.bytes, 16u);
    }
    if (status == NINLIL_OK) {
        status = ninlil_model_domain_sha256_update(
            &context, length_be, (uint32_t)sizeof(length_be));
    }
    if (status == NINLIL_OK) {
        status = ninlil_model_domain_sha256_update(
            &context,
            config->storage_namespace.data,
            config->storage_namespace.length);
    }
    if (status == NINLIL_OK) {
        status = ninlil_model_domain_sha256_final(&context, &digest);
    }
    if (status != NINLIL_OK) {
        (void)memset(out_namespace, 0, 32u);
        return status;
    }
    (void)memcpy(out_namespace, digest.bytes, 32u);
    return NINLIL_OK;
}

static ninlil_status_t composition_base_check(
    ninlil_composition_v1_t *composition)
{
    uint64_t context_id;

    if (composition == NULL || composition->magic != COMPOSITION_MAGIC) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (composition->execution.current_context_id == NULL) {
        return NINLIL_E_INVALID_STATE;
    }
    context_id = composition->execution.current_context_id(
        composition->execution.user);
    if (context_id == 0u) {
        return NINLIL_E_DEGRADED;
    }
    if (context_id != composition->owner_context_id) {
        return NINLIL_E_WRONG_THREAD;
    }
    return composition->in_call == 0u
        ? NINLIL_OK : NINLIL_E_REENTRANT;
}

static ninlil_status_t composition_owner_check(
    ninlil_composition_v1_t *composition)
{
    ninlil_status_t status = composition_base_check(composition);

    if (status != NINLIL_OK) {
        return status;
    }
    return composition->lifecycle == COMPOSITION_LIVE
        ? NINLIL_OK : NINLIL_E_INVALID_STATE;
}

static int composition_header_ok(
    uint16_t api_version,
    uint16_t struct_size,
    uint16_t expected_version,
    size_t expected_size)
{
    return api_version == expected_version
        && (size_t)struct_size >= expected_size;
}

static void composition_prepare_step_result(
    ninlil_composition_step_result_v1_t *result)
{
    uint16_t api_version = result->api_version;
    uint16_t struct_size = result->struct_size;

    (void)memset(result, 0, sizeof(*result));
    result->api_version = api_version;
    result->struct_size = struct_size;
    result->runtime.abi_version = NINLIL_ABI_VERSION;
    result->runtime.struct_size = (uint16_t)sizeof(result->runtime);
    result->runtime.health = NINLIL_HEALTH_OK;
}

static int composition_runtime_budget_is_zero(
    const ninlil_step_budget_t *budget)
{
    return budget->max_ingress_messages == 0u
        && budget->max_callbacks == 0u
        && budget->max_state_transitions == 0u
        && budget->max_bearer_sends == 0u;
}

static int composition_runtime_budget_within_limit(
    const ninlil_composition_v1_t *composition,
    const ninlil_step_budget_t *budget)
{
    return budget->max_ingress_messages
            <= composition->runtime_config.limits.max_ingress_per_step
        && budget->max_callbacks
            <= composition->runtime_config.limits.max_callbacks_per_step
        && budget->max_state_transitions
            <= composition->runtime_config.limits.max_state_transitions_per_step
        && budget->max_bearer_sends
            <= composition->runtime_config.limits.max_bearer_sends_per_step;
}

static void composition_unwind_fabric(ninlil_composition_v1_t *composition)
{
    uint32_t done = 0u;

    if (composition == NULL || composition->fabric == NULL) {
        return;
    }
    (void)ninlil_fabric_v1_close_begin(composition->fabric);
    (void)ninlil_fabric_v1_close_poll(composition->fabric, &done);
    if (done != 0u) {
        (void)ninlil_fabric_v1_destroy(composition->fabric);
    }
    composition->fabric = NULL;
}

ninlil_status_t ninlil_composition_v1_workspace_required(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment)
{
    uint32_t fabric_bytes = 0u;
    uint32_t fabric_alignment = 0u;
    uint32_t offset = 0u;
    uint64_t total;
    ninlil_fabric_status_t fabric_status;

    if (out_bytes == NULL || out_alignment == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_bytes = 0u;
    *out_alignment = 0u;
    if (profile_id != NINLIL_COMPOSITION_PROFILE_1) {
        return NINLIL_E_UNSUPPORTED;
    }
    fabric_status = ninlil_fabric_v1_workspace_required(
        NINLIL_FABRIC_PROFILE_1, &fabric_bytes, &fabric_alignment);
    if (fabric_status != NINLIL_FABRIC_OK) {
        return map_fabric_status(fabric_status);
    }
    if (fabric_alignment < (uint32_t)_Alignof(max_align_t)) {
        fabric_alignment = (uint32_t)_Alignof(max_align_t);
    }
    if (!align_up_u32(
            (uint32_t)sizeof(ninlil_composition_v1_t),
            fabric_alignment,
            &offset)) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    total = (uint64_t)offset + fabric_bytes;
    if (total > UINT32_MAX) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    *out_bytes = (uint32_t)total;
    *out_alignment = fabric_alignment;
    return NINLIL_OK;
}

ninlil_status_t ninlil_composition_v1_create(
    uint32_t profile_id,
    const ninlil_runtime_config_t *runtime_config,
    const ninlil_platform_ops_t *platform_template,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_composition_v1_t **out_composition)
{
    ninlil_model_runtime_validation_result_t validation;
    ninlil_platform_ops_t validation_platform;
    ninlil_bearer_ops_t validation_bearer;
    ninlil_runtime_config_t config_copy;
    ninlil_allocator_ops_t allocator_copy;
    ninlil_execution_ops_t execution_copy;
    ninlil_clock_ops_t clock_copy;
    ninlil_entropy_ops_t entropy_copy;
    ninlil_storage_ops_t storage_copy;
    ninlil_tx_gate_ops_t tx_gate_copy;
    ninlil_origin_authorization_ops_t origin_copy;
    uint8_t namespace_copy[COMPOSITION_BASE_NAMESPACE_MAX];
    ninlil_composition_v1_t *composition;
    ninlil_fabric_config_v1_t fabric_config;
    const ninlil_bearer_ops_t *fabric_bearer = NULL;
    uint32_t required_bytes = 0u;
    uint32_t required_alignment = 0u;
    uint32_t fabric_bytes = 0u;
    uint32_t fabric_alignment = 0u;
    uint32_t fabric_offset = 0u;
    uint64_t owner_context_id;
    ninlil_fabric_status_t fabric_status;
    ninlil_status_t status;

    if (out_composition == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_composition = NULL;
    if (profile_id != NINLIL_COMPOSITION_PROFILE_1) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (runtime_config == NULL || platform_template == NULL
        || workspace == NULL || platform_template->bearer != NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    validation_platform = *platform_template;
    init_validation_bearer(&validation_bearer);
    validation_platform.bearer = &validation_bearer;
    status = ninlil_model_runtime_validate_and_derive(
        runtime_config, &validation_platform, &validation);
    if (status != NINLIL_OK) {
        return validation.status;
    }
    status = ninlil_composition_v1_workspace_required(
        profile_id, &required_bytes, &required_alignment);
    if (status != NINLIL_OK) {
        return status;
    }
    if (workspace_bytes < required_bytes
        || ((uintptr_t)workspace % required_alignment) != 0u) {
        return workspace_bytes < required_bytes
            ? NINLIL_E_CAPACITY_EXHAUSTED
            : NINLIL_E_INVALID_ARGUMENT;
    }
    owner_context_id = platform_template->execution->current_context_id(
        platform_template->execution->user);
    if (owner_context_id == 0u) {
        return NINLIL_E_DEGRADED;
    }

    config_copy = *runtime_config;
    allocator_copy = *platform_template->allocator;
    execution_copy = *platform_template->execution;
    clock_copy = *platform_template->clock;
    entropy_copy = *platform_template->entropy;
    storage_copy = *platform_template->storage;
    tx_gate_copy = *platform_template->tx_gate;
    origin_copy = *platform_template->origin_authorization;
    (void)memcpy(
        namespace_copy,
        runtime_config->storage_namespace.data,
        runtime_config->storage_namespace.length);

    fabric_status = ninlil_fabric_v1_workspace_required(
        NINLIL_FABRIC_PROFILE_1, &fabric_bytes, &fabric_alignment);
    if (fabric_status != NINLIL_FABRIC_OK
        || !align_up_u32(
            (uint32_t)sizeof(*composition),
            required_alignment,
            &fabric_offset)) {
        return fabric_status == NINLIL_FABRIC_OK
            ? NINLIL_E_CAPACITY_EXHAUSTED
            : map_fabric_status(fabric_status);
    }
    (void)fabric_alignment;

    (void)memset(workspace, 0, required_bytes);
    composition = (ninlil_composition_v1_t *)workspace;
    composition->magic = COMPOSITION_MAGIC;
    composition->lifecycle = COMPOSITION_LIVE;
    composition->workspace_bytes = required_bytes;
    composition->fabric_offset = fabric_offset;
    composition->owner_context_id = owner_context_id;
    composition->runtime_config = config_copy;
    (void)memcpy(
        composition->base_namespace,
        namespace_copy,
        runtime_config->storage_namespace.length);
    composition->runtime_config.storage_namespace.data =
        composition->base_namespace;
    composition->allocator = allocator_copy;
    composition->execution = execution_copy;
    composition->clock = clock_copy;
    composition->entropy = entropy_copy;
    composition->underlying_storage = storage_copy;
    composition->tx_gate = tx_gate_copy;
    composition->origin_authorization = origin_copy;
    status = derive_fabric_namespace(
        &composition->runtime_config, composition->fabric_namespace);
    if (status != NINLIL_OK) {
        (void)memset(workspace, 0, required_bytes);
        return status;
    }
    init_fabric_storage(composition);

    (void)memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = &composition->fabric_storage;
    fabric_config.clock = &composition->clock;
    fabric_config.execution = &composition->execution;
    fabric_status = ninlil_fabric_v1_create(
        &fabric_config,
        (uint8_t *)workspace + fabric_offset,
        fabric_bytes,
        &composition->fabric);
    if (fabric_status != NINLIL_FABRIC_OK) {
        status = map_fabric_status(fabric_status);
        (void)memset(workspace, 0, required_bytes);
        return status;
    }
    fabric_status = ninlil_fabric_v1_bearer_ops(
        composition->fabric, &fabric_bearer);
    if (fabric_status != NINLIL_FABRIC_OK || fabric_bearer == NULL) {
        status = fabric_status == NINLIL_FABRIC_OK
            ? NINLIL_E_INVALID_STATE : map_fabric_status(fabric_status);
        composition_unwind_fabric(composition);
        (void)memset(workspace, 0, required_bytes);
        return status;
    }

    (void)memset(&composition->runtime_platform, 0,
        sizeof(composition->runtime_platform));
    composition->runtime_platform.abi_version = NINLIL_ABI_VERSION;
    composition->runtime_platform.struct_size =
        (uint16_t)sizeof(composition->runtime_platform);
    composition->runtime_platform.allocator = &composition->allocator;
    composition->runtime_platform.execution = &composition->execution;
    composition->runtime_platform.clock = &composition->clock;
    composition->runtime_platform.entropy = &composition->entropy;
    composition->runtime_platform.storage = &composition->underlying_storage;
    composition->runtime_platform.bearer = fabric_bearer;
    composition->runtime_platform.tx_gate = &composition->tx_gate;
    composition->runtime_platform.origin_authorization =
        &composition->origin_authorization;
    status = ninlil_runtime_create(
        &composition->runtime_config,
        &composition->runtime_platform,
        &composition->runtime);
    if (status != NINLIL_OK) {
        composition_unwind_fabric(composition);
        (void)memset(workspace, 0, required_bytes);
        return status;
    }

    *out_composition = composition;
    return NINLIL_OK;
}

ninlil_status_t ninlil_composition_v1_runtime(
    ninlil_composition_v1_t *composition,
    ninlil_runtime_t **out_runtime)
{
    ninlil_status_t status;

    if (out_runtime == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_runtime = NULL;
    status = composition_owner_check(composition);
    if (status != NINLIL_OK) {
        return status;
    }
    if (composition->runtime == NULL) {
        return NINLIL_E_INVALID_STATE;
    }
    *out_runtime = composition->runtime;
    return NINLIL_OK;
}

ninlil_status_t ninlil_composition_v1_fabric(
    ninlil_composition_v1_t *composition,
    ninlil_fabric_v1_t **out_fabric)
{
    ninlil_status_t status;

    if (out_fabric == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_fabric = NULL;
    status = composition_owner_check(composition);
    if (status != NINLIL_OK) {
        return status;
    }
    if (composition->fabric == NULL) {
        return NINLIL_E_INVALID_STATE;
    }
    *out_fabric = composition->fabric;
    return NINLIL_OK;
}

ninlil_status_t ninlil_composition_v1_step(
    ninlil_composition_v1_t *composition,
    const ninlil_composition_step_budget_v1_t *budget,
    ninlil_composition_step_result_v1_t *out_result)
{
    ninlil_status_t status;
    ninlil_fabric_status_t fabric_status;
    uint32_t runtime_skipped;
    uint32_t remaining_fabric_work;
    uint32_t release_work = 0u;
    uint32_t release_more = 0u;
    uint32_t projection_present = 0u;
    uint32_t projection_more = 0u;
    uint32_t fabric_step_work = 0u;
    uint32_t fabric_pending = 0u;
    uint32_t runtime_pending = 0u;

    if (budget == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!composition_header_ok(
            budget->api_version,
            budget->struct_size,
            NINLIL_COMPOSITION_API_VERSION,
            sizeof(*budget))
        || !composition_header_ok(
            budget->runtime.abi_version,
            budget->runtime.struct_size,
            NINLIL_ABI_VERSION,
            sizeof(budget->runtime))
        || !composition_header_ok(
            out_result->api_version,
            out_result->struct_size,
            NINLIL_COMPOSITION_API_VERSION,
            sizeof(*out_result))) {
        return NINLIL_E_ABI_MISMATCH;
    }
    composition_prepare_step_result(out_result);
    runtime_skipped = (uint32_t)composition_runtime_budget_is_zero(
        &budget->runtime);
    if (budget->fabric_work > COMPOSITION_FABRIC_WORK_MAX
        || budget->reliability_work > COMPOSITION_RELIABILITY_WORK_MAX
        || (runtime_skipped != 0u && budget->fabric_work == 0u
            && budget->reliability_work == 0u)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = composition_owner_check(composition);
    if (status != NINLIL_OK) {
        return status;
    }
    if (!composition_runtime_budget_within_limit(
            composition, &budget->runtime)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    composition->in_call = 1u;
    if (runtime_skipped == 0u) {
        status = ninlil_runtime_step(
            composition->runtime, &budget->runtime, &out_result->runtime);
        if (out_result->runtime.transactions_terminalized != 0u
            && composition->terminal_owner_cursor != 0u) {
            composition->terminal_owner_wrap_pending = 1u;
        }
        if (status != NINLIL_OK) {
            out_result->more_work = 1u;
            composition->in_call = 0u;
            return status;
        }
        if (out_result->runtime.more_work != 0u) {
            out_result->more_work = 1u;
        }
        if (composition->terminal_owner_wrap_pending != 0u) {
            out_result->more_work = 1u;
        }
    } else {
        status = ninlil_rt_private_has_pending_work_v1(
            composition->runtime, &runtime_pending);
        if (status != NINLIL_OK) {
            out_result->more_work = 1u;
            composition->in_call = 0u;
            return status;
        }
        if (runtime_pending != 0u) {
            out_result->more_work = 1u;
        }
    }

    /* Profile 1 reliability engines remain inactive until durable state exists. */
    out_result->reliability_work_done = 0u;
    remaining_fabric_work = budget->fabric_work;
    if (composition->pending_terminal_owner_valid == 0u) {
        status = ninlil_rt_private_terminal_owner_next_v1(
            composition->runtime,
            &composition->terminal_owner_cursor,
            &composition->terminal_owner_wrap_pending,
            &composition->pending_terminal_owner,
            &projection_present,
            &projection_more);
        if (status != NINLIL_OK) {
            out_result->more_work = 1u;
            composition->in_call = 0u;
            return status;
        }
        if (projection_present != 0u) {
            composition->pending_terminal_owner_valid = 1u;
            composition->pending_terminal_projection_more = projection_more;
        } else {
            composition->pending_terminal_projection_more = 0u;
            if (projection_more != 0u) {
                out_result->more_work = 1u;
            } else {
                composition->terminal_owner_cursor = 0u;
            }
        }
    }
    if (remaining_fabric_work != 0u
        && composition->pending_terminal_owner_valid != 0u) {
        fabric_status = ninlil_fabric_private_terminal_release_v1(
            composition->fabric,
            &composition->pending_terminal_owner.transaction_id,
            composition->pending_terminal_owner.release_token,
            &release_work,
            &release_more);
        if (release_work > 1u || release_work > remaining_fabric_work) {
            out_result->more_work = 1u;
            composition->in_call = 0u;
            return NINLIL_E_DEGRADED;
        }
        out_result->fabric_work_done += release_work;
        remaining_fabric_work -= release_work;
        if (fabric_status == NINLIL_FABRIC_OK && release_more == 0u) {
            composition->pending_terminal_owner_valid = 0u;
            (void)memset(
                &composition->pending_terminal_owner,
                0,
                sizeof(composition->pending_terminal_owner));
        }
        if (composition->pending_terminal_owner_valid != 0u
            || composition->pending_terminal_projection_more != 0u) {
            out_result->more_work = 1u;
        }
        if (fabric_status != NINLIL_FABRIC_OK) {
            composition->in_call = 0u;
            return map_fabric_status(fabric_status);
        }
        if (composition->pending_terminal_owner_valid == 0u) {
            composition->pending_terminal_projection_more = 0u;
        }
    }
    if (remaining_fabric_work != 0u) {
        fabric_status = ninlil_fabric_v1_step(
            composition->fabric,
            remaining_fabric_work,
            &fabric_step_work);
        if (fabric_step_work > remaining_fabric_work) {
            out_result->more_work = 1u;
            composition->in_call = 0u;
            return NINLIL_E_DEGRADED;
        }
        out_result->fabric_work_done += fabric_step_work;
        if (fabric_status != NINLIL_FABRIC_OK) {
            out_result->more_work = 1u;
            composition->in_call = 0u;
            return map_fabric_status(fabric_status);
        }
    }
    fabric_status = ninlil_fabric_private_has_pending_work_v1(
        composition->fabric, &fabric_pending);
    if (fabric_status != NINLIL_FABRIC_OK) {
        out_result->more_work = 1u;
        composition->in_call = 0u;
        return map_fabric_status(fabric_status);
    }
    if (fabric_pending != 0u
        || composition->pending_terminal_owner_valid != 0u
        || composition->terminal_owner_wrap_pending != 0u) {
        out_result->more_work = 1u;
    }
    composition->in_call = 0u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_composition_v1_close_begin(
    ninlil_composition_v1_t *composition)
{
    ninlil_status_t status;
    ninlil_fabric_status_t fabric_status;
    uint32_t registrations_present = 0u;

    status = composition_base_check(composition);
    if (status != NINLIL_OK) {
        return status;
    }
    if (composition->lifecycle == COMPOSITION_CLOSING) {
        return NINLIL_OK;
    }
    if (composition->lifecycle != COMPOSITION_LIVE) {
        return NINLIL_E_INVALID_STATE;
    }
    composition->in_call = 1u;
    fabric_status = ninlil_fabric_private_has_link_registrations_v1(
        composition->fabric, &registrations_present);
    if (fabric_status != NINLIL_FABRIC_OK) {
        composition->in_call = 0u;
        return map_fabric_status(fabric_status);
    }
    if (registrations_present != 0u) {
        composition->in_call = 0u;
        return NINLIL_E_CONFLICT;
    }

    status = ninlil_runtime_destroy(composition->runtime);
    if (status == NINLIL_E_INVALID_ARGUMENT
        || status == NINLIL_E_INVALID_STATE
        || status == NINLIL_E_WRONG_THREAD
        || status == NINLIL_E_REENTRANT) {
        composition->in_call = 0u;
        return status;
    }
    composition->runtime = NULL;
    if (status != NINLIL_OK) {
        composition->close_terminal_status = status;
    }
    fabric_status = ninlil_fabric_v1_close_begin(composition->fabric);
    if (fabric_status != NINLIL_FABRIC_OK) {
        composition->lifecycle = COMPOSITION_CLOSING;
        composition->in_call = 0u;
        return map_fabric_status(fabric_status);
    }
    composition->lifecycle = COMPOSITION_CLOSING;
    composition->in_call = 0u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_composition_v1_close_poll(
    ninlil_composition_v1_t *composition,
    uint32_t work_budget,
    uint32_t *out_done)
{
    ninlil_status_t status;
    ninlil_fabric_status_t fabric_status;
    uint32_t work_done = 0u;
    uint32_t fabric_done = 0u;

    if (out_done == NULL || work_budget == 0u
        || work_budget > COMPOSITION_FABRIC_WORK_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_done = 0u;
    status = composition_base_check(composition);
    if (status != NINLIL_OK) {
        return status;
    }
    if (composition->lifecycle == COMPOSITION_CLOSED) {
        *out_done = 1u;
        return composition->close_terminal_status;
    }
    if (composition->lifecycle != COMPOSITION_CLOSING) {
        return NINLIL_E_INVALID_STATE;
    }

    composition->in_call = 1u;
    fabric_status = ninlil_fabric_v1_step(
        composition->fabric, work_budget, &work_done);
    if (fabric_status != NINLIL_FABRIC_OK) {
        composition->in_call = 0u;
        return map_fabric_status(fabric_status);
    }
    fabric_status = ninlil_fabric_v1_close_poll(
        composition->fabric, &fabric_done);
    if (fabric_status != NINLIL_FABRIC_OK) {
        composition->in_call = 0u;
        return map_fabric_status(fabric_status);
    }
    if (fabric_done != 0u) {
        composition->lifecycle = COMPOSITION_CLOSED;
        *out_done = 1u;
        status = composition->close_terminal_status;
    } else {
        status = NINLIL_OK;
    }
    composition->in_call = 0u;
    return status;
}

ninlil_status_t ninlil_composition_v1_destroy(
    ninlil_composition_v1_t *composition)
{
    ninlil_status_t status;
    ninlil_fabric_status_t fabric_status;
    uint32_t workspace_bytes;

    status = composition_base_check(composition);
    if (status != NINLIL_OK) {
        return status;
    }
    if (composition->lifecycle != COMPOSITION_CLOSED) {
        return NINLIL_E_WOULD_BLOCK;
    }
    composition->in_call = 1u;
    fabric_status = ninlil_fabric_v1_destroy(composition->fabric);
    if (fabric_status != NINLIL_FABRIC_OK) {
        composition->in_call = 0u;
        return map_fabric_status(fabric_status);
    }
    workspace_bytes = composition->workspace_bytes;
    (void)memset(composition, 0, workspace_bytes);
    return NINLIL_OK;
}
