/*
 * Private Stage 5 empty-domain metadata-init orchestrator tests.
 *
 * Non-claims: public runtime_create, Stage 5 complete, COMMIT_UNKNOWN
 * convergence, D3/D4, Command/Event E2E.
 *
 * D2-S6 seam outcome contract is unchanged after metadata write.
 */

#include "stage5_empty_metadata.h"

#include "runtime_lifecycle_model.h"
#include "runtime_store_stage5_seam.h"
#include "domain_store_codec.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"

#include <stdio.h>
#include <string.h>

/*
 * Minimal platform shell for production ninlil_model_runtime_validate_and_derive
 * only (pointer/header/function presence). Port bodies are unused by that path.
 */
typedef struct validation_platform {
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_storage_ops_t storage;
    ninlil_bearer_ops_t bearer;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
} validation_platform_t;

static void *vp_allocate(void *user, uint64_t size, uint32_t alignment)
{
    (void)user;
    (void)size;
    (void)alignment;
    return NULL;
}

static void vp_deallocate(
    void *user, void *ptr, uint64_t size, uint32_t alignment)
{
    (void)user;
    (void)ptr;
    (void)size;
    (void)alignment;
}

static uint64_t vp_context(void *user)
{
    (void)user;
    return 1u;
}

static ninlil_port_status_t vp_clock(void *user, ninlil_time_sample_t *out)
{
    (void)user;
    (void)out;
    return NINLIL_PORT_PERMANENT_FAILURE;
}

static ninlil_port_status_t vp_entropy(
    void *user, uint8_t *out, uint32_t length)
{
    (void)user;
    (void)out;
    (void)length;
    return NINLIL_PORT_PERMANENT_FAILURE;
}

static ninlil_storage_status_t vp_storage_open(
    void *user,
    ninlil_bytes_view_t ns,
    uint32_t schema,
    ninlil_storage_handle_t *out_handle)
{
    (void)user;
    (void)ns;
    (void)schema;
    (void)out_handle;
    return NINLIL_STORAGE_IO_ERROR;
}

static void vp_storage_close(void *user, ninlil_storage_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_storage_status_t vp_storage_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    (void)user;
    (void)handle;
    (void)mode;
    (void)out_txn;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *value)
{
    (void)user;
    (void)txn;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    (void)user;
    (void)txn;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    (void)user;
    (void)txn;
    (void)key;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    (void)user;
    (void)txn;
    (void)prefix;
    (void)out_iter;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *value)
{
    (void)user;
    (void)iter;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static void vp_storage_iter_close(void *user, ninlil_storage_iter_t iter)
{
    (void)user;
    (void)iter;
}

static ninlil_storage_status_t vp_storage_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *capacity)
{
    (void)user;
    (void)handle;
    (void)capacity;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t durability)
{
    (void)user;
    (void)txn;
    (void)durability;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    (void)user;
    (void)txn;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_bearer_status_t vp_bearer_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    (void)user;
    (void)runtime_id;
    (void)role;
    (void)out_handle;
    return NINLIL_BEARER_UNAVAILABLE;
}

static void vp_bearer_close(void *user, ninlil_bearer_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_bearer_status_t vp_bearer_send(
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

static ninlil_bearer_status_t vp_bearer_receive(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    (void)user;
    (void)handle;
    (void)out_message;
    return NINLIL_BEARER_EMPTY;
}

static void vp_bearer_release(
    void *user, ninlil_bearer_handle_t handle, ninlil_bearer_message_t *message)
{
    (void)user;
    (void)handle;
    (void)message;
}

static ninlil_bearer_status_t vp_bearer_state(
    void *user, ninlil_bearer_handle_t handle, ninlil_bearer_state_t *out_state)
{
    (void)user;
    (void)handle;
    (void)out_state;
    return NINLIL_BEARER_UNAVAILABLE;
}

static ninlil_tx_gate_status_t vp_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    (void)user;
    (void)request;
    (void)now;
    (void)out_permit;
    return NINLIL_TX_GATE_TEMPORARY;
}

static void vp_tx_release(void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t vp_origin(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)request;
    (void)decision;
    return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
}

static void validation_platform_init(validation_platform_t *vp)
{
    (void)memset(vp, 0, sizeof(*vp));
#define HDR(obj)                                                               \
    do {                                                                       \
        (obj).abi_version = NINLIL_ABI_VERSION;                                \
        (obj).struct_size = (uint16_t)sizeof(obj);                             \
    } while (0)
    HDR(vp->allocator);
    vp->allocator.allocate = vp_allocate;
    vp->allocator.deallocate = vp_deallocate;
    HDR(vp->execution);
    vp->execution.current_context_id = vp_context;
    HDR(vp->clock);
    vp->clock.now = vp_clock;
    HDR(vp->entropy);
    vp->entropy.fill = vp_entropy;
    HDR(vp->storage);
    vp->storage.open = vp_storage_open;
    vp->storage.close = vp_storage_close;
    vp->storage.begin = vp_storage_begin;
    vp->storage.get = vp_storage_get;
    vp->storage.put = vp_storage_put;
    vp->storage.erase = vp_storage_erase;
    vp->storage.iter_open = vp_storage_iter_open;
    vp->storage.iter_next = vp_storage_iter_next;
    vp->storage.iter_close = vp_storage_iter_close;
    vp->storage.capacity = vp_storage_capacity;
    vp->storage.commit = vp_storage_commit;
    vp->storage.rollback = vp_storage_rollback;
    HDR(vp->bearer);
    vp->bearer.open = vp_bearer_open;
    vp->bearer.close = vp_bearer_close;
    vp->bearer.send = vp_bearer_send;
    vp->bearer.receive_next = vp_bearer_receive;
    vp->bearer.release_received = vp_bearer_release;
    vp->bearer.state = vp_bearer_state;
    HDR(vp->tx_gate);
    vp->tx_gate.acquire = vp_tx_acquire;
    vp->tx_gate.release_unused = vp_tx_release;
    HDR(vp->origin);
    vp->origin.evaluate = vp_origin;
    HDR(vp->platform);
    vp->platform.allocator = &vp->allocator;
    vp->platform.execution = &vp->execution;
    vp->platform.clock = &vp->clock;
    vp->platform.entropy = &vp->entropy;
    vp->platform.storage = &vp->storage;
    vp->platform.bearer = &vp->bearer;
    vp->platform.tx_gate = &vp->tx_gate;
    vp->platform.origin_authorization = &vp->origin;
#undef HDR
}

/* Production validate_and_derive path (not handmade status=OK). */
static int validation_from_config(
    const ninlil_runtime_config_t *config,
    ninlil_model_runtime_validation_result_t *out)
{
    validation_platform_t vp;
    ninlil_status_t st;

    if (config == NULL || out == NULL) {
        return 0;
    }
    validation_platform_init(&vp);
    st = ninlil_model_runtime_validate_and_derive(config, &vp.platform, out);
    return st == NINLIL_OK && out->status == NINLIL_OK
        && out->failure_field == NINLIL_MODEL_RUNTIME_VALIDATION_NONE;
}

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t TEST_NAMESPACE[] = "stage5-empty-metadata-v1";

typedef struct test_context {
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_allocator_t *allocator_fixture;
    const ninlil_storage_ops_t *storage;
    ninlil_storage_handle_t handle;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_runtime_store_stage5_workspace_t stage5_workspace;
    ninlil_runtime_store_stage5_result_t stage5_result;
    ninlil_stage5_empty_metadata_workspace_t empty_workspace;
    ninlil_stage5_empty_metadata_result_t empty_result;
} test_context_t;

/* Malicious Port wrapper for get/put/iter adversarial shape tests. */
typedef enum mut_attack {
    MUT_ATTACK_NONE = 0,
    MUT_ATTACK_DATA_PTR,
    MUT_ATTACK_CAPACITY,
    MUT_ATTACK_LENGTH_GT_CAP,
    MUT_ATTACK_GET_UNKNOWN_POISON_LEN,
    MUT_ATTACK_GET_COMMIT_UNKNOWN_POISON_LEN,
    MUT_ATTACK_GET_IO_POISON_LEN,
    MUT_ATTACK_GET_NOT_FOUND_POISON_LEN,
    MUT_ATTACK_GET_BTS_NATURAL,
    MUT_ATTACK_GET_BTS_REWRITE_DATA,
    MUT_ATTACK_ITER_OPEN_OK_NULL,
    MUT_ATTACK_ITER_OPEN_ERR_NONNULL,
    MUT_ATTACK_ITER_OPEN_UNKNOWN_NONNULL,
    MUT_ATTACK_ITER_NEXT_KEY_DATA,
    MUT_ATTACK_ITER_NEXT_KEY_CAP,
    MUT_ATTACK_ITER_NEXT_VAL_DATA,
    MUT_ATTACK_ITER_NEXT_VAL_CAP,
    MUT_ATTACK_ITER_NEXT_VAL_LEN_GT,
    MUT_ATTACK_ITER_NEXT_BTS_NATURAL,
    MUT_ATTACK_ITER_NEXT_BTS_REWRITE_VAL,
    MUT_ATTACK_ITER_NEXT_NOT_FOUND_POISON,
    MUT_ATTACK_ITER_NEXT_IO_POISON,
    MUT_ATTACK_ITER_NEXT_UNKNOWN,
    MUT_ATTACK_ITER_NEXT_DUP_KEY,
    MUT_ATTACK_ITER_NEXT_OOO_KEY,
    MUT_ATTACK_PUT_NTH_IO,
    MUT_ATTACK_PUT_UNKNOWN,
    MUT_ATTACK_BEGIN_UNKNOWN,
    MUT_ATTACK_BEGIN_COMMIT_UNKNOWN,
    MUT_ATTACK_BEGIN_FAIL_NONNULL
} mut_attack_t;

typedef struct mut_wrap {
    const ninlil_storage_ops_t *inner;
    ninlil_storage_ops_t ops;
    mut_attack_t attack;
    uint32_t get_hits_left;
    uint32_t put_hits_left;
    uint32_t begin_hits_left;
    uint32_t iter_open_hits_left;
    uint32_t iter_next_hits_left;
    uint8_t alt_buf[256];
    uint8_t fake_iter_token;
    uint8_t prev_key_snap[255];
    uint32_t prev_key_len;
} mut_wrap_t;

static ninlil_storage_status_t mut_open(
    void *user,
    ninlil_bytes_view_t name,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    return w->inner->open(w->inner->user, name, expected_schema, out_handle);
}

static void mut_close(void *user, ninlil_storage_handle_t handle)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    w->inner->close(w->inner->user, handle);
}

static ninlil_storage_status_t mut_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    if ((w->attack == MUT_ATTACK_BEGIN_UNKNOWN
            || w->attack == MUT_ATTACK_BEGIN_COMMIT_UNKNOWN)
        && w->begin_hits_left > 0u) {
        w->begin_hits_left -= 1u;
        if (w->begin_hits_left == 0u) {
            if (out_txn != NULL) {
                *out_txn = NULL;
            }
            return w->attack == MUT_ATTACK_BEGIN_COMMIT_UNKNOWN
                ? NINLIL_STORAGE_COMMIT_UNKNOWN
                : (ninlil_storage_status_t)211;
        }
    }
    if (w->attack == MUT_ATTACK_BEGIN_FAIL_NONNULL
        && w->begin_hits_left > 0u) {
        ninlil_storage_status_t st;
        w->begin_hits_left -= 1u;
        if (w->begin_hits_left == 0u) {
            /* Publish a live txn then return non-OK (shape violation). */
            st = w->inner->begin(w->inner->user, handle, mode, out_txn);
            if (st != NINLIL_STORAGE_OK) {
                return st;
            }
            return NINLIL_STORAGE_IO_ERROR;
        }
    }
    return w->inner->begin(w->inner->user, handle, mode, out_txn);
}

static ninlil_storage_status_t mut_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    ninlil_storage_status_t st;

    st = w->inner->get(w->inner->user, txn, key, inout_value);
    if (w->attack == MUT_ATTACK_NONE || w->get_hits_left == 0u) {
        return st;
    }
    w->get_hits_left -= 1u;
    if (w->get_hits_left != 0u) {
        return st;
    }
    if (inout_value == NULL) {
        return st;
    }
    if (w->attack == MUT_ATTACK_DATA_PTR && st == NINLIL_STORAGE_OK) {
        inout_value->data = w->alt_buf;
        return st;
    }
    if (w->attack == MUT_ATTACK_CAPACITY && st == NINLIL_STORAGE_OK) {
        inout_value->capacity = inout_value->capacity + 1u;
        return st;
    }
    if (w->attack == MUT_ATTACK_LENGTH_GT_CAP && st == NINLIL_STORAGE_OK) {
        inout_value->length = inout_value->capacity + 1u;
        return st;
    }
    if (w->attack == MUT_ATTACK_GET_UNKNOWN_POISON_LEN) {
        inout_value->length = 1u;
        return (ninlil_storage_status_t)199;
    }
    if (w->attack == MUT_ATTACK_GET_COMMIT_UNKNOWN_POISON_LEN) {
        inout_value->length = 1u;
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    if (w->attack == MUT_ATTACK_GET_IO_POISON_LEN) {
        inout_value->length = 1u;
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (w->attack == MUT_ATTACK_GET_NOT_FOUND_POISON_LEN) {
        inout_value->length = 1u;
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (w->attack == MUT_ATTACK_GET_BTS_NATURAL) {
        /* MB3 natural: data/capacity unchanged, required length > capacity. */
        inout_value->length = inout_value->capacity + 1u;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (w->attack == MUT_ATTACK_GET_BTS_REWRITE_DATA) {
        inout_value->data = w->alt_buf;
        inout_value->length = inout_value->capacity + 1u;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    return st;
}

static ninlil_storage_status_t mut_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    if (w->attack == MUT_ATTACK_PUT_NTH_IO && w->put_hits_left > 0u) {
        w->put_hits_left -= 1u;
        if (w->put_hits_left == 0u) {
            return NINLIL_STORAGE_IO_ERROR;
        }
    }
    if (w->attack == MUT_ATTACK_PUT_UNKNOWN && w->put_hits_left > 0u) {
        w->put_hits_left -= 1u;
        if (w->put_hits_left == 0u) {
            return (ninlil_storage_status_t)198;
        }
    }
    return w->inner->put(w->inner->user, txn, key, value);
}

static ninlil_storage_status_t mut_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    return w->inner->erase(w->inner->user, txn, key);
}

static ninlil_storage_status_t mut_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    ninlil_storage_status_t st;

    if (w->attack == MUT_ATTACK_ITER_OPEN_OK_NULL
        && w->iter_open_hits_left > 0u) {
        w->iter_open_hits_left -= 1u;
        if (w->iter_open_hits_left == 0u) {
            if (out_iter != NULL) {
                *out_iter = NULL;
            }
            return NINLIL_STORAGE_OK;
        }
    }
    if (w->attack == MUT_ATTACK_ITER_OPEN_ERR_NONNULL
        && w->iter_open_hits_left > 0u) {
        w->iter_open_hits_left -= 1u;
        if (w->iter_open_hits_left == 0u) {
            if (out_iter != NULL) {
                *out_iter = (ninlil_storage_iter_t)&w->fake_iter_token;
            }
            return NINLIL_STORAGE_IO_ERROR;
        }
    }
    if (w->attack == MUT_ATTACK_ITER_OPEN_UNKNOWN_NONNULL
        && w->iter_open_hits_left > 0u) {
        w->iter_open_hits_left -= 1u;
        if (w->iter_open_hits_left == 0u) {
            if (out_iter != NULL) {
                *out_iter = (ninlil_storage_iter_t)&w->fake_iter_token;
            }
            return (ninlil_storage_status_t)197;
        }
    }
    st = w->inner->iter_open(w->inner->user, txn, prefix, out_iter);
    return st;
}

static ninlil_storage_status_t mut_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    ninlil_storage_status_t st;

    st = w->inner->iter_next(w->inner->user, iter, inout_key, inout_value);
    /* Snapshot natural key before adversarial rewrite (for DUP). */
    if (st == NINLIL_STORAGE_OK && inout_key != NULL && inout_key->length > 0u
        && inout_key->length <= sizeof(w->prev_key_snap)
        && w->iter_next_hits_left > 1u) {
        (void)memcpy(w->prev_key_snap, inout_key->data, inout_key->length);
        w->prev_key_len = inout_key->length;
    }
    if (w->iter_next_hits_left == 0u) {
        return st;
    }
    w->iter_next_hits_left -= 1u;
    if (w->iter_next_hits_left != 0u) {
        return st;
    }
    if (w->attack == MUT_ATTACK_ITER_NEXT_KEY_DATA && inout_key != NULL) {
        inout_key->data = w->alt_buf;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_KEY_CAP && inout_key != NULL) {
        inout_key->capacity = inout_key->capacity + 1u;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_VAL_DATA
        && inout_value != NULL) {
        inout_value->data = w->alt_buf;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_VAL_CAP
        && inout_value != NULL) {
        inout_value->capacity = inout_value->capacity + 1u;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_VAL_LEN_GT
        && inout_value != NULL && st == NINLIL_STORAGE_OK) {
        inout_value->length = inout_value->capacity + 1u;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_BTS_NATURAL
        && inout_key != NULL && inout_value != NULL) {
        /* MB7 natural: required lengths may exceed capacity; data/cap fixed. */
        inout_key->length = inout_key->capacity + 1u;
        inout_value->length = inout_value->capacity + 1u;
        st = NINLIL_STORAGE_BUFFER_TOO_SMALL;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_BTS_REWRITE_VAL
        && inout_value != NULL) {
        inout_value->data = w->alt_buf;
        inout_value->length = inout_value->capacity + 1u;
        st = NINLIL_STORAGE_BUFFER_TOO_SMALL;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_NOT_FOUND_POISON) {
        st = NINLIL_STORAGE_NOT_FOUND;
        if (inout_key != NULL) {
            inout_key->length = 1u;
        }
        if (inout_value != NULL) {
            inout_value->length = 1u;
        }
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_IO_POISON) {
        st = NINLIL_STORAGE_IO_ERROR;
        if (inout_key != NULL) {
            inout_key->length = 1u;
        }
        if (inout_value != NULL) {
            inout_value->length = 1u;
        }
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_UNKNOWN) {
        st = (ninlil_storage_status_t)196;
        if (inout_key != NULL) {
            inout_key->length = 0u;
        }
        if (inout_value != NULL) {
            inout_value->length = 0u;
        }
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_DUP_KEY
        && inout_key != NULL && st == NINLIL_STORAGE_OK
        && w->prev_key_len > 0u && inout_key->capacity >= w->prev_key_len) {
        (void)memcpy(inout_key->data, w->prev_key_snap, w->prev_key_len);
        inout_key->length = w->prev_key_len;
    } else if (w->attack == MUT_ATTACK_ITER_NEXT_OOO_KEY
        && inout_key != NULL && st == NINLIL_STORAGE_OK
        && inout_key->length > 0u) {
        /* Force lexicographically smaller key than previous. */
        inout_key->data[0] = 0u;
        inout_key->length = 1u;
    }
    return st;
}

static void mut_iter_close(void *user, ninlil_storage_iter_t iter)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    if (iter == (ninlil_storage_iter_t)&w->fake_iter_token) {
        return;
    }
    w->inner->iter_close(w->inner->user, iter);
}

static ninlil_storage_status_t mut_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    return w->inner->capacity(w->inner->user, handle, out_capacity);
}

static ninlil_storage_status_t mut_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t durability)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    return w->inner->commit(w->inner->user, txn, durability);
}

static ninlil_storage_status_t mut_rollback(void *user, ninlil_storage_txn_t txn)
{
    mut_wrap_t *w = (mut_wrap_t *)user;
    return w->inner->rollback(w->inner->user, txn);
}

static void mut_wrap_init(
    mut_wrap_t *w,
    const ninlil_storage_ops_t *inner,
    mut_attack_t attack,
    uint32_t on_get_call)
{
    (void)memset(w, 0, sizeof(*w));
    w->inner = inner;
    w->attack = attack;
    w->get_hits_left = on_get_call;
    w->put_hits_left = 0u;
    w->begin_hits_left = 0u;
    w->iter_open_hits_left = 0u;
    w->iter_next_hits_left = 0u;
    w->ops.abi_version = inner->abi_version;
    w->ops.struct_size = inner->struct_size;
    w->ops.user = w;
    w->ops.open = mut_open;
    w->ops.close = mut_close;
    w->ops.begin = mut_begin;
    w->ops.get = mut_get;
    w->ops.put = mut_put;
    w->ops.erase = mut_erase;
    w->ops.iter_open = mut_iter_open;
    w->ops.iter_next = mut_iter_next;
    w->ops.iter_close = mut_iter_close;
    w->ops.capacity = mut_capacity;
    w->ops.commit = mut_commit;
    w->ops.rollback = mut_rollback;
}

static void mut_wrap_put_nth(mut_wrap_t *w, const ninlil_storage_ops_t *inner,
    uint32_t nth_put)
{
    mut_wrap_init(w, inner, MUT_ATTACK_PUT_NTH_IO, 0u);
    w->put_hits_left = nth_put;
}

static void mut_wrap_iter_open(mut_wrap_t *w, const ninlil_storage_ops_t *inner,
    mut_attack_t attack)
{
    mut_wrap_init(w, inner, attack, 0u);
    w->iter_open_hits_left = 1u;
}

static void mut_wrap_iter_next(mut_wrap_t *w, const ninlil_storage_ops_t *inner,
    mut_attack_t attack, uint32_t on_call)
{
    mut_wrap_init(w, inner, attack, 0u);
    w->iter_next_hits_left = on_call;
}

static int reopen_namespace(test_context_t *ctx)
{
    ninlil_bytes_view_t storage_namespace;
    storage_namespace.data = TEST_NAMESPACE;
    storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    ctx->handle = NULL;
    return ctx->storage->open(ctx->storage->user, storage_namespace,
               NINLIL_STORAGE_SCHEMA_M1A, &ctx->handle)
        == NINLIL_STORAGE_OK;
}

static const ninlil_model_runtime_store_key_id_t TEST_MEMBER_KEYS[15] = {
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ASSIGNED_OWNER,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TRANSACTION,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TARGET,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_OUTBOX_BYTES,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_COUNT,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_BYTES,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_RESULT_CACHE,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVIDENCE,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_INGRESS,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN
};

static int build_expected_meta_key(
    uint32_t index,
    ninlil_model_domain_key_t *out_key)
{
    ninlil_model_runtime_store_key_t member_key;
    ninlil_model_domain_digest_t mkd;
    ninlil_model_domain_digest_t composite;
    ninlil_bytes_view_t member_view;
    ninlil_bytes_view_t components;
    ninlil_bytes_view_t identity;

    if (index >= 16u || out_key == NULL) {
        return 0;
    }
    if (index == 15u) {
        identity.data = NULL;
        identity.length = 0u;
        return ninlil_model_domain_build_key(
                   NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                   NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE,
                   NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON,
                   identity,
                   out_key)
            == NINLIL_OK;
    }
    if (ninlil_model_runtime_store_build_key(TEST_MEMBER_KEYS[index], &member_key)
        != NINLIL_OK) {
        return 0;
    }
    member_view.data = member_key.bytes;
    member_view.length = member_key.length;
    if (ninlil_model_domain_key_digest(member_view, &mkd) != NINLIL_OK) {
        return 0;
    }
    components.data = mkd.bytes;
    components.length = 32u;
    if (ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
            components,
            &composite)
        != NINLIL_OK) {
        return 0;
    }
    return ninlil_model_domain_build_key(
               NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
               NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
               NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
               (ninlil_bytes_view_t){composite.bytes, 32u},
               out_key)
        == NINLIL_OK;
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static ninlil_runtime_config_t config_fixture(void)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x10u);
    config.local_identity.abi_version = NINLIL_ABI_VERSION;
    config.local_identity.struct_size =
        (uint16_t)sizeof(config.local_identity);
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x20u);
    set_id(&config.local_identity.installation_id, 0x40u);
    set_id(&config.local_identity.site_domain_id, 0x60u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = TEST_NAMESPACE;
    config.storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    config.limits.abi_version = NINLIL_ABI_VERSION;
    config.limits.struct_size = (uint16_t)sizeof(config.limits);
    config.limits.max_services = 11u;
    config.limits.max_nonterminal_transactions = 27u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 5000u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 30u;
    /* Cross-field: deferred ≤ deliveries ≤ nonterminal (lifecycle model). */
    config.limits.max_nonterminal_deliveries = 19u;
    config.limits.max_result_cache_entries = 13u;
    config.limits.max_retained_dispositions = 14u;
    config.limits.max_ingress_per_step = 15u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 17u;
    config.limits.max_bearer_sends_per_step = 18u;
    config.limits.max_deferred_tokens = 12u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 900u;
    config.observation_retention_ms = 800u;
    return config;
}

static int context_init(test_context_t *context)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_runtime_config_t config = config_fixture();
    ninlil_bytes_view_t storage_namespace;

    (void)memset(context, 0, sizeof(*context));
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 2u;
    storage_config.max_entries_per_namespace = 128u;
    storage_config.max_bytes_per_namespace = 400000u;
    context->storage_fixture = ninlil_test_storage_create(&storage_config);
    context->allocator_fixture = ninlil_test_allocator_create();
    if (context->storage_fixture == NULL
        || context->allocator_fixture == NULL) {
        return 0;
    }
    context->storage = ninlil_test_storage_ops(context->storage_fixture);
    /* Authority A: production validate_and_derive (not handmade status=OK). */
    if (!validation_from_config(&config, &context->validation)) {
        return 0;
    }
    storage_namespace.data = TEST_NAMESPACE;
    storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    return context->storage->open(context->storage->user,
        storage_namespace, NINLIL_STORAGE_SCHEMA_M1A,
        &context->handle) == NINLIL_STORAGE_OK;
}

static int context_destroy(test_context_t *context)
{
    int clean = 1;

    if (context->handle != NULL && context->storage != NULL) {
        context->storage->close(context->storage->user, context->handle);
        context->handle = NULL;
    }
    if (context->storage_fixture != NULL) {
        if (ninlil_test_storage_live_handles(context->storage_fixture) != 0u
            || ninlil_test_storage_live_transactions(context->storage_fixture)
                != 0u
            || ninlil_test_storage_live_iterators(context->storage_fixture)
                != 0u) {
            clean = 0;
        }
        ninlil_test_storage_destroy(context->storage_fixture);
        context->storage_fixture = NULL;
    }
    if (context->allocator_fixture != NULL) {
        if (ninlil_test_allocator_destroy(context->allocator_fixture) != 0u) {
            clean = 0;
        }
        context->allocator_fixture = NULL;
    }
    return clean;
}

static int bootstrap_via_seam(test_context_t *ctx)
{
    ninlil_status_t st;

    (void)memset(&ctx->stage5_workspace, 0, sizeof(ctx->stage5_workspace));
    (void)memset(&ctx->stage5_result, 0, sizeof(ctx->stage5_result));
    st = ninlil_runtime_store_stage5_private_hookup(
        ctx->storage,
        &ctx->handle,
        &ctx->validation,
        NULL,
        &ctx->stage5_workspace,
        &ctx->stage5_result);
    if (st != NINLIL_OK) {
        return 0;
    }
    if (ctx->stage5_result.outcome
            != NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING
        || ctx->stage5_result.storage_recovery_complete != 0u
        || ctx->stage5_result.scan_ran != 0u) {
        return 0;
    }
    return 1;
}

static ninlil_time_sample_t make_trusted_sample(uint8_t epoch_seed, uint64_t now)
{
    ninlil_time_sample_t sample;
    (void)memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    set_id(&sample.clock_epoch_id, epoch_seed);
    sample.now_ms = now;
    sample.trust = NINLIL_CLOCK_TRUSTED;
    sample.reserved_zero = 0u;
    return sample;
}

static int raw_put(
    test_context_t *ctx,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_storage_txn_t txn = NULL;
    if (ctx->storage->begin(ctx->storage->user, ctx->handle,
            NINLIL_STORAGE_READ_WRITE, &txn) != NINLIL_STORAGE_OK) {
        return 0;
    }
    if (ctx->storage->put(ctx->storage->user, txn, key, value)
        != NINLIL_STORAGE_OK) {
        (void)ctx->storage->rollback(ctx->storage->user, txn);
        return 0;
    }
    return ctx->storage->commit(
               ctx->storage->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK;
}

static int raw_erase(test_context_t *ctx, ninlil_bytes_view_t key)
{
    ninlil_storage_txn_t txn = NULL;
    if (ctx->storage->begin(ctx->storage->user, ctx->handle,
            NINLIL_STORAGE_READ_WRITE, &txn) != NINLIL_STORAGE_OK) {
        return 0;
    }
    if (ctx->storage->erase(ctx->storage->user, txn, key)
        != NINLIL_STORAGE_OK) {
        (void)ctx->storage->rollback(ctx->storage->user, txn);
        return 0;
    }
    return ctx->storage->commit(
               ctx->storage->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK;
}

static int test_workspace_bounds(void)
{
    /* Arena-owned; includes same-txn scan buffers (not ESP stack). */
    REQUIRE(sizeof(ninlil_stage5_empty_metadata_workspace_t) <= NINLIL_STAGE5_EMPTY_METADATA_WORKSPACE_CEILING_BYTES);
    REQUIRE(NINLIL_STAGE5_EMPTY_METADATA_RECORD_COUNT == 16u);
    return 0;
}

static int test_null_and_fail_out_zero(void)
{
    ninlil_stage5_empty_metadata_workspace_t ws;
    ninlil_stage5_empty_metadata_result_t result;
    ninlil_storage_handle_t handle = (ninlil_storage_handle_t)1;

    (void)memset(&ws, 0xA5, sizeof(ws));
    (void)memset(&result, 0x5A, sizeof(result));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            NULL, &handle, NULL, &ws, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    /* Prevalidation failure: out_result must not be wiped. */
    REQUIRE(((const uint8_t *)&result)[0] == 0x5Au);
    (void)memset(&result, 0x5A, sizeof(result));
    REQUIRE(ninlil_stage5_empty_metadata_validate(
            NULL, &handle, NULL, &ws, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result.clock_trusted == 0x5A5A5A5Au
        || ((const uint8_t *)&result)[0] == 0x5Au);
    return 0;
}

static int test_commit_0_16_exact_and_noop(void)
{
    test_context_t ctx;
    uint64_t put_before;
    uint64_t put_after;
    uint64_t commit_before;
    uint64_t commit_after;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));

    put_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ctx.empty_result.wrote_metadata == 1u);
    REQUIRE(ctx.empty_result.reopen_required == 0u);
    put_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(put_after == put_before + 16u);
    REQUIRE(commit_after == commit_before + 1u);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);

    /* 16/16 no-op: no put/commit; TRUSTED never forced. */
    put_before = put_after;
    commit_before = commit_after;
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ctx.empty_result.wrote_metadata == 0u);
    put_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(put_after == put_before);
    REQUIRE(commit_after == commit_before);

    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_partial_1_15_all_counts(void)
{
    uint32_t present;
    for (present = 1u; present <= 15u; ++present) {
        test_context_t ctx;
        uint32_t erase_index;
        uint64_t put_before;
        uint64_t commit_before;
        uint64_t put_after;
        uint64_t commit_after;

        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_OK);
        /* Leave exactly `present` of 16 expected keys (erase the rest). */
        for (erase_index = present; erase_index < 16u; ++erase_index) {
            ninlil_model_domain_key_t dk;
            ninlil_bytes_view_t kv;
            REQUIRE(build_expected_meta_key(erase_index, &dk));
            kv.data = dk.bytes;
            kv.length = dk.length;
            REQUIRE(raw_erase(&ctx, kv));
        }
        put_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        commit_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        put_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        commit_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        REQUIRE(put_after == put_before);
        REQUIRE(commit_after == commit_before);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);
        REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
            == 0u);
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static int test_surplus_row_corrupt(void)
{
    test_context_t ctx;
    uint8_t surplus_key[] = {
        'n', 'i', 'n', 'l', 'i', 'l', 0u, 0u, /* root padding-ish */
        0x05u, 0x50u, 0x01u, 0x01u, 0x00u /* fake family5 non-expected */
    };
    uint8_t surplus_val[4] = {1u, 2u, 3u, 4u};
    ninlil_bytes_view_t k;
    ninlil_bytes_view_t v;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    /* Inject non-catalog / non-expected key after bootstrap. */
    k.data = surplus_key;
    k.length = (uint32_t)sizeof(surplus_key);
    v.data = surplus_val;
    v.length = (uint32_t)sizeof(surplus_val);
    REQUIRE(raw_put(&ctx, k, v));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ctx.empty_result.wrote_metadata == 0u);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);
    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_no_trusted_downgrade(void)
{
    test_context_t ctx;
    ninlil_time_sample_t sample = make_trusted_sample(0xA0u, 42u);

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            &ctx.validation,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ninlil_stage5_empty_metadata_validate(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ctx.empty_result.clock_trusted == 1u);
    /* Second metadata commit must not rewrite TRUSTED → UNINITIALIZED. */
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ctx.empty_result.wrote_metadata == 0u);
    REQUIRE(ninlil_stage5_empty_metadata_validate(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ctx.empty_result.clock_trusted == 1u);
    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_commit_failure_no_post_commit_rollback(void)
{
    test_context_t ctx;
    uint64_t rb_before;
    uint64_t rb_after;
    uint64_t commit_before;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));

    rb_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_test_storage_fault_next(
        ctx.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_IO_ERROR));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(rb_after == rb_before);
    REQUIRE(ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before + 1u);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);

    rb_before = rb_after;
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_test_storage_fault_enqueue(
        ctx.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        0));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(rb_after == rb_before);
    REQUIRE(ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before + 1u);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);
    /* COMMIT_UNKNOWN fences; no convergence claim. */
    REQUIRE(ctx.empty_result.reopen_required == 1u);
    REQUIRE(ctx.handle == NULL);

    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_pre_commit_failure_rollback_exactly_one(void)
{
    test_context_t ctx;
    uint64_t rb_before;
    uint64_t rb_after;
    uint64_t commit_before;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));

    rb_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_test_storage_fault_next(
        ctx.storage_fixture,
        NINLIL_TEST_STORAGE_OP_BEGIN,
        NINLIL_STORAGE_IO_ERROR));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(rb_after == rb_before);
    REQUIRE(ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);

    rb_before = rb_after;
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_test_storage_fault_next(
        ctx.storage_fixture,
        NINLIL_TEST_STORAGE_OP_GET,
        NINLIL_STORAGE_IO_ERROR));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(rb_after == rb_before + 1u);
    REQUIRE(ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);

    rb_before = rb_after;
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_test_storage_fault_next(
        ctx.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT,
        NINLIL_STORAGE_IO_ERROR));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(rb_after == rb_before + 1u);
    REQUIRE(ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);

    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_pre_commit_rollback_failure_keeps_primary(void)
{
    test_context_t ctx;
    uint64_t rb_before;
    uint64_t rb_after;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));

    rb_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(ninlil_test_storage_fault_next(
        ctx.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT,
        NINLIL_STORAGE_IO_ERROR));
    REQUIRE(ninlil_test_storage_fault_next(
        ctx.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ROLLBACK,
        NINLIL_STORAGE_IO_ERROR));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(rb_after == rb_before + 1u);
    REQUIRE(ctx.empty_result.reopen_required == 1u);
    REQUIRE(ctx.handle == NULL);
    REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture) == 0u);

    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_validate_ro_rollback_failure_not_success(void)
{
    test_context_t ctx;
    static const ninlil_storage_status_t faults[] = {
        NINLIL_STORAGE_BUSY,
        NINLIL_STORAGE_IO_ERROR,
        NINLIL_STORAGE_CORRUPT,
        (ninlil_storage_status_t)250
    };
    size_t i;

    for (i = 0u; i < sizeof(faults) / sizeof(faults[0]); ++i) {
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_OK);

        REQUIRE(ninlil_test_storage_fault_next(
            ctx.storage_fixture,
            NINLIL_TEST_STORAGE_OP_ROLLBACK,
            faults[i]));
        REQUIRE(ninlil_stage5_empty_metadata_validate(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            != NINLIL_OK);
        REQUIRE(ctx.empty_result.clock_trusted == 0u);
        REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
            == 0u);
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static int test_get_shape_mutations_fail_closed(void)
{
    test_context_t ctx;
    mut_wrap_t wrap;
    mut_attack_t attacks[] = {
        MUT_ATTACK_DATA_PTR,
        MUT_ATTACK_CAPACITY,
        MUT_ATTACK_LENGTH_GT_CAP
    };
    size_t i;

    for (i = 0u; i < sizeof(attacks) / sizeof(attacks[0]); ++i) {
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        /* Seed 16 keys so subsequent classify gets return OK (shape attack). */
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_OK);
        mut_wrap_init(&wrap, ctx.storage, attacks[i], 1u);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                &wrap.ops,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);
        REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
            == 0u);
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static int test_seam_contract_unchanged_after_metadata(void)
{
    test_context_t ctx;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);

    (void)memset(&ctx.stage5_workspace, 0, sizeof(ctx.stage5_workspace));
    (void)memset(&ctx.stage5_result, 0, sizeof(ctx.stage5_result));
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
            ctx.storage,
            &ctx.handle,
            &ctx.validation,
            NULL,
            &ctx.stage5_workspace,
            &ctx.stage5_result)
        == NINLIL_OK);
    REQUIRE(ctx.stage5_result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING);
    REQUIRE(ctx.stage5_result.storage_recovery_complete == 0u);
    REQUIRE(ctx.stage5_result.scan_adopted == 1u);
    REQUIRE(ctx.stage5_result.current_domain_key_count == 16u);
    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_clock_sample_and_second_call(void)
{
    test_context_t ctx;
    ninlil_time_sample_t sample = make_trusted_sample(0xC0u, 9u);
    ninlil_time_sample_t bad = sample;
    uint64_t put_before;
    uint64_t put_after;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);

    bad.trust = NINLIL_CLOCK_UNCERTAIN;
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &bad,
            &ctx.validation,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            &ctx.validation,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_OK);
    put_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    /* Same epoch+now: idempotent retry OK / mutation 0. */
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            &ctx.validation,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_OK);
    put_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    REQUIRE(put_after == put_before);
    REQUIRE(context_destroy(&ctx));
    return 0;
}

/*
 * Already-TRUSTED table: only exact same epoch+now is OK/mutation0.
 * Different epoch / now advance / now regression → CONFLICT / mutation0.
 * First-transition MAX gen/rev → DEGRADED / mutation0 (separate row setup).
 */
static int test_clock_trusted_sample_matrix(void)
{
    typedef struct {
        const char *name;
        uint8_t epoch_seed;
        uint64_t now_ms;
        ninlil_status_t expect;
    } row_t;
    static const row_t rows[] = {
        { "same_epoch_same_now", 0xC1u, 100u, NINLIL_OK },
        { "same_epoch_now_advance", 0xC1u, 101u, NINLIL_E_CONFLICT },
        { "same_epoch_now_regress", 0xC1u, 99u, NINLIL_E_CONFLICT },
        { "different_epoch_same_now", 0xC2u, 100u, NINLIL_E_CONFLICT },
        { "different_epoch_higher_now", 0xC2u, 200u, NINLIL_E_CONFLICT },
        { "different_epoch_lower_now", 0xC2u, 1u, NINLIL_E_CONFLICT }
    };
    size_t i;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        test_context_t ctx;
        ninlil_time_sample_t first = make_trusted_sample(0xC1u, 100u);
        ninlil_time_sample_t retry = make_trusted_sample(
            rows[i].epoch_seed, rows[i].now_ms);
        uint64_t put_before;
        uint64_t put_after;
        uint64_t commit_before;
        uint64_t commit_after;

        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_OK);
        REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
                ctx.storage,
                &ctx.handle,
                &first,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_OK);

        put_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        commit_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
                ctx.storage,
                &ctx.handle,
                &retry,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == rows[i].expect);
        put_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        commit_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        REQUIRE(put_after == put_before);
        REQUIRE(commit_after == commit_before);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);
        (void)rows[i].name;
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static int test_sample_abi_exact_storage_call_zero(void)
{
    test_context_t ctx;
    ninlil_time_sample_t sample;
    ninlil_time_sample_t bad;
    uint64_t begin_before;
    uint64_t begin_after;
    size_t i;
    struct {
        const char *name;
        int (*mutate)(ninlil_time_sample_t *);
        ninlil_status_t expect;
    } cases[6];

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);
    sample = make_trusted_sample(0xD0u, 1u);

    cases[0].name = "abi";
    cases[0].expect = NINLIL_E_ABI_MISMATCH;
    cases[1].name = "size_small";
    cases[1].expect = NINLIL_E_ABI_MISMATCH;
    cases[2].name = "size_large";
    cases[2].expect = NINLIL_E_ABI_MISMATCH;
    cases[3].name = "reserved";
    cases[3].expect = NINLIL_E_INVALID_ARGUMENT;
    cases[4].name = "trust";
    cases[4].expect = NINLIL_E_INVALID_ARGUMENT;
    cases[5].name = "zero_epoch";
    cases[5].expect = NINLIL_E_INVALID_ARGUMENT;

    for (i = 0u; i < 6u; ++i) {
        bad = sample;
        if (i == 0u) {
            bad.abi_version = (uint16_t)(NINLIL_ABI_VERSION + 1u);
        } else if (i == 1u) {
            bad.struct_size = (uint16_t)(sizeof(bad) - 1u);
        } else if (i == 2u) {
            bad.struct_size = (uint16_t)(sizeof(bad) + 1u);
        } else if (i == 3u) {
            bad.reserved_zero = 1u;
        } else if (i == 4u) {
            bad.trust = NINLIL_CLOCK_UNCERTAIN;
        } else {
            (void)memset(bad.clock_epoch_id.bytes, 0, 16u);
        }
        begin_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN);
        REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
                ctx.storage,
                &ctx.handle,
                &bad,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == cases[i].expect);
        begin_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN);
        REQUIRE(begin_after == begin_before);
        (void)cases[i].name;
    }
    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_alias_precondition_no_result_init(void)
{
    test_context_t ctx;
    ninlil_stage5_empty_metadata_result_t *aliased;
    uint8_t poison = 0xABu;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    /* Alias out_result into workspace → INVALID; do not wipe aliased bytes. */
    (void)memset(&ctx.empty_workspace, poison, sizeof(ctx.empty_workspace));
    aliased = (ninlil_stage5_empty_metadata_result_t *)&ctx.empty_workspace;
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage,
            &ctx.handle,
            &ctx.validation,
            &ctx.empty_workspace,
            aliased)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(((const uint8_t *)aliased)[0] == poison);
    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_iter_adversarial(void)
{
    static const mut_attack_t open_attacks[] = {
        MUT_ATTACK_ITER_OPEN_OK_NULL,
        MUT_ATTACK_ITER_OPEN_ERR_NONNULL
    };
    static const mut_attack_t next_attacks[] = {
        MUT_ATTACK_ITER_NEXT_KEY_DATA,
        MUT_ATTACK_ITER_NEXT_KEY_CAP,
        MUT_ATTACK_ITER_NEXT_VAL_DATA,
        MUT_ATTACK_ITER_NEXT_VAL_CAP,
        MUT_ATTACK_ITER_NEXT_VAL_LEN_GT,
        MUT_ATTACK_ITER_NEXT_NOT_FOUND_POISON,
        MUT_ATTACK_ITER_NEXT_DUP_KEY,
        MUT_ATTACK_ITER_NEXT_OOO_KEY
    };
    size_t i;

    for (i = 0u; i < sizeof(open_attacks) / sizeof(open_attacks[0]); ++i) {
        test_context_t ctx;
        mut_wrap_t wrap;
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        mut_wrap_iter_open(&wrap, ctx.storage, open_attacks[i]);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                &wrap.ops,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
            == 0u);
        REQUIRE(ninlil_test_storage_live_iterators(ctx.storage_fixture) == 0u);
        REQUIRE(context_destroy(&ctx));
    }

    for (i = 0u; i < sizeof(next_attacks) / sizeof(next_attacks[0]); ++i) {
        test_context_t ctx;
        mut_wrap_t wrap;
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        /* Attack on second next (after at least one prior key) for order/dup. */
        mut_wrap_iter_next(&wrap, ctx.storage, next_attacks[i],
            (next_attacks[i] == MUT_ATTACK_ITER_NEXT_DUP_KEY
                    || next_attacks[i] == MUT_ATTACK_ITER_NEXT_OOO_KEY)
                ? 2u
                : 1u);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                &wrap.ops,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
            == 0u);
        REQUIRE(ninlil_test_storage_live_iterators(ctx.storage_fixture) == 0u);
        REQUIRE(context_destroy(&ctx));
    }

    /* BUFFER_TOO_SMALL / known / unknown iter_next status. */
    {
        test_context_t ctx;
        static const ninlil_storage_status_t sts[] = {
            NINLIL_STORAGE_BUFFER_TOO_SMALL,
            NINLIL_STORAGE_IO_ERROR,
            NINLIL_STORAGE_BUSY,
            (ninlil_storage_status_t)200
        };
        size_t s;
        for (s = 0u; s < sizeof(sts) / sizeof(sts[0]); ++s) {
            REQUIRE(context_init(&ctx));
            REQUIRE(bootstrap_via_seam(&ctx));
            (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
            if (sts[s] == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
                /* Natural MB7 BTS: required length > capacity, no fence. */
                mut_wrap_t wrap;
                uint64_t close_before = ninlil_test_storage_call_count(
                    ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);
                mut_wrap_iter_next(
                    &wrap, ctx.storage, MUT_ATTACK_ITER_NEXT_BTS_NATURAL, 1u);
                REQUIRE(ninlil_stage5_empty_metadata_commit(
                        &wrap.ops,
                        &ctx.handle,
                        &ctx.validation,
                        &ctx.empty_workspace,
                        &ctx.empty_result)
                    == NINLIL_E_STORAGE_CORRUPT);
                REQUIRE(ctx.empty_result.reopen_required == 0u);
                REQUIRE(ctx.handle != NULL);
                REQUIRE(ninlil_test_storage_call_count(
                        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE)
                    == close_before);
            } else {
                REQUIRE(ninlil_test_storage_fault_next(
                    ctx.storage_fixture,
                    NINLIL_TEST_STORAGE_OP_ITER_NEXT,
                    sts[s]));
                REQUIRE(ninlil_stage5_empty_metadata_commit(
                        ctx.storage,
                        &ctx.handle,
                        &ctx.validation,
                        &ctx.empty_workspace,
                        &ctx.empty_result)
                    != NINLIL_OK);
            }
            REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
                == 0u);
            REQUIRE(ninlil_test_storage_live_iterators(ctx.storage_fixture)
                == 0u);
            REQUIRE(context_destroy(&ctx));
        }
    }
    return 0;
}

static int test_surplus_kinds(void)
{
    /* current domain non-expected, future-ish, unknown/malformed, business. */
    struct {
        uint8_t key[48];
        uint32_t key_len;
        uint8_t val[8];
    } rows[4];
    size_t i;

    /* 0: current domain BEARER_STATE (not in expected 16). */
    {
        ninlil_model_domain_key_t k;
        ninlil_bytes_view_t id;
        id.data = NULL;
        id.length = 0u;
        REQUIRE(ninlil_model_domain_build_key(
                    NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                    NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE,
                    NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON,
                    id,
                    &k)
            == NINLIL_OK);
        (void)memcpy(rows[0].key, k.bytes, k.length);
        rows[0].key_len = k.length;
    }
    /* 1: business TRANSACTION_STATE (ID128). */
    {
        ninlil_model_domain_key_t k;
        uint8_t raw[16];
        ninlil_bytes_view_t id;
        (void)memset(raw, 0x77, sizeof(raw));
        id.data = raw;
        id.length = 16u;
        REQUIRE(ninlil_model_domain_build_key(
                    NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                    NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE,
                    NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
                    id,
                    &k)
            == NINLIL_OK);
        (void)memcpy(rows[1].key, k.bytes, k.length);
        rows[1].key_len = k.length;
    }
    /* 2: health INTERNAL_INVARIANT (ID128). */
    {
        ninlil_model_domain_key_t k;
        uint8_t raw[16];
        ninlil_bytes_view_t id;
        (void)memset(raw, 0x55, sizeof(raw));
        id.data = raw;
        id.length = 16u;
        REQUIRE(ninlil_model_domain_build_key(
                    NINLIL_MODEL_DOMAIN_FAMILY_HEALTH,
                    NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT,
                    NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
                    id,
                    &k)
            == NINLIL_OK);
        (void)memcpy(rows[2].key, k.bytes, k.length);
        rows[2].key_len = k.length;
    }
    /* 3: future-looking key without valid NLR1 framing → MALFORMED/CORRUPT. */
    {
        static const uint8_t ROOT_V1[8] = {
            'n', 'i', 'n', 'l', 'i', 'l', 0x00u, 0x01u
        };
        (void)memcpy(rows[3].key, ROOT_V1, 8u);
        rows[3].key[7] = 0x02u; /* future root byte without complete predicate */
        rows[3].key[8] = 0x10u;
        rows[3].key[9] = 0x20u;
        rows[3].key[10] = 0x01u;
        rows[3].key[11] = 0x01u;
        rows[3].key[12] = 0x00u;
        rows[3].key_len = 13u;
    }

    for (i = 0u; i < 4u; ++i) {
        test_context_t ctx;
        ninlil_bytes_view_t k;
        ninlil_bytes_view_t v;
        (void)memset(rows[i].val, (int)(0x10u + i), sizeof(rows[i].val));
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        k.data = rows[i].key;
        k.length = rows[i].key_len;
        v.data = rows[i].val;
        v.length = (uint32_t)sizeof(rows[i].val);
        REQUIRE(raw_put(&ctx, k, v));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static void write_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void write_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint32_t build_nlr1_for_test(
    uint8_t *out,
    uint32_t capacity,
    uint16_t record_type,
    uint16_t record_version,
    const uint8_t *payload,
    uint32_t payload_length)
{
    uint32_t total;
    uint32_t crc;

    total = 16u + payload_length;
    if (total > capacity) {
        return 0u;
    }
    out[0] = (uint8_t)'N';
    out[1] = (uint8_t)'L';
    out[2] = (uint8_t)'R';
    out[3] = (uint8_t)'1';
    write_u16_be(&out[4], record_type);
    write_u16_be(&out[6], record_version);
    write_u32_be(&out[8], payload_length);
    if (payload_length != 0u) {
        (void)memcpy(&out[12], payload, payload_length);
    }
    crc = ninlil_model_domain_crc32c(out, 12u + payload_length);
    write_u32_be(&out[12u + payload_length], crc);
    return total;
}

static int make_recognizable_future_row(
    uint8_t *key_out,
    uint32_t *key_len,
    uint8_t *val_out,
    uint32_t *val_len)
{
    static const uint8_t ROOT_V1[8] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
    };
    uint8_t payload[4] = {0x01u, 0x02u, 0x03u, 0x04u};
    uint32_t n;

    (void)memcpy(key_out, ROOT_V1, 8u);
    key_out[7] = 0x02u;
    key_out[8] = 0x10u;
    key_out[9] = 0x20u;
    key_out[10] = 0x01u;
    key_out[11] = 0x01u;
    key_out[12] = 0x00u;
    *key_len = 13u;
    n = build_nlr1_for_test(
        val_out, 64u, 6u, 2u, payload, 4u);
    if (n == 0u) {
        return 0;
    }
    *val_len = n;
    return 1;
}

static int test_future_only_unsupported_and_mixed_precedence(void)
{
    test_context_t ctx;
    uint8_t fkey[32];
    uint8_t fval[64];
    uint32_t fkey_len = 0u;
    uint32_t fval_len = 0u;
    ninlil_bytes_view_t k;
    ninlil_bytes_view_t v;
    uint64_t put_before;
    uint64_t commit_before;
    ninlil_model_domain_key_t business;
    uint8_t raw_id[16];
    ninlil_bytes_view_t id;

    REQUIRE(make_recognizable_future_row(fkey, &fkey_len, fval, &fval_len));

    /* Future-only (plus family1-4 bootstrap): UNSUPPORTED, mutation 0. */
    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    k.data = fkey;
    k.length = fkey_len;
    v.data = fval;
    v.length = fval_len;
    REQUIRE(raw_put(&ctx, k, v));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    put_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == put_before);
    REQUIRE(ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);
    REQUIRE(ctx.empty_result.wrote_metadata == 0u);
    REQUIRE(context_destroy(&ctx));

    /* Future + current business surplus: CORRUPT outranks future. */
    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    REQUIRE(raw_put(&ctx, k, v));
    (void)memset(raw_id, 0x66, sizeof(raw_id));
    id.data = raw_id;
    id.length = 16u;
    REQUIRE(ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE,
                NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
                id,
                &business)
        == NINLIL_OK);
    {
        ninlil_bytes_view_t bk;
        ninlil_bytes_view_t bv;
        uint8_t junk[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
        bk.data = business.bytes;
        bk.length = business.length;
        bv.data = junk;
        bv.length = 8u;
        REQUIRE(raw_put(&ctx, bk, bv));
    }
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ctx.empty_result.wrote_metadata == 0u);
    REQUIRE(context_destroy(&ctx));

    /* Framing future on current-root key (record_version>1, valid NLR1). */
    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    {
        ninlil_model_domain_key_t bearer;
        ninlil_bytes_view_t empty_id;
        uint8_t payload[4] = {0xAAu, 0xBBu, 0xCCu, 0xDDu};
        uint8_t env[64];
        uint32_t env_len;
        ninlil_bytes_view_t bk;
        ninlil_bytes_view_t bv;
        empty_id.data = NULL;
        empty_id.length = 0u;
        REQUIRE(ninlil_model_domain_build_key(
                    NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                    NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE,
                    NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON,
                    empty_id,
                    &bearer)
            == NINLIL_OK);
        env_len = build_nlr1_for_test(
            env,
            (uint32_t)sizeof(env),
            NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
            2u,
            payload,
            4u);
        REQUIRE(env_len != 0u);
        bk.data = bearer.bytes;
        bk.length = bearer.length;
        bv.data = env;
        bv.length = env_len;
        REQUIRE(raw_put(&ctx, bk, bv));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        put_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_UNSUPPORTED);
        REQUIRE(ninlil_test_storage_call_count(
                ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
            == put_before);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);
    }
    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_commit_unknown_both_truths_metadata_and_clock(void)
{
    int truth;
    for (truth = 0; truth <= 1; ++truth) {
        test_context_t ctx;
        uint64_t rb_before;
        uint64_t rb_after;

        /* Metadata path. */
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        rb_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
        REQUIRE(ninlil_test_storage_fault_enqueue(
            ctx.storage_fixture,
            NINLIL_TEST_STORAGE_OP_COMMIT,
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            1u,
            1,
            truth));
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        rb_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
        REQUIRE(rb_after == rb_before);
        REQUIRE(ctx.empty_result.reopen_required == 1u);
        REQUIRE(ctx.handle == NULL);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);
        REQUIRE(reopen_namespace(&ctx));
        if (truth != 0) {
            /* Committed truth: validate may succeed (helper did not claim OK). */
            (void)ninlil_stage5_empty_metadata_validate(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result);
        } else {
            /* Not committed: 0/16 still writable. */
            REQUIRE(ninlil_stage5_empty_metadata_commit(
                    ctx.storage,
                    &ctx.handle,
                    &ctx.validation,
                    &ctx.empty_workspace,
                    &ctx.empty_result)
                == NINLIL_OK);
            REQUIRE(ctx.empty_result.wrote_metadata == 1u);
        }
        REQUIRE(context_destroy(&ctx));

        /* Clock path: need metadata present first. */
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_OK);
        {
            ninlil_time_sample_t sample = make_trusted_sample(0xB1u, 3u);
            rb_before = ninlil_test_storage_call_count(
                ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
            REQUIRE(ninlil_test_storage_fault_enqueue(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                truth));
            REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
                    ctx.storage,
                    &ctx.handle,
                    &sample,
                    &ctx.validation,
                    &ctx.empty_workspace,
                    &ctx.empty_result)
                == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            rb_after = ninlil_test_storage_call_count(
                ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
            REQUIRE(rb_after == rb_before);
            REQUIRE(ctx.empty_result.reopen_required == 1u);
            REQUIRE(ctx.handle == NULL);
            REQUIRE(reopen_namespace(&ctx));
            REQUIRE(ninlil_stage5_empty_metadata_validate(
                    ctx.storage,
                    &ctx.handle,
                    &ctx.validation,
                    &ctx.empty_workspace,
                    &ctx.empty_result)
                == NINLIL_OK);
            if (truth != 0) {
                REQUIRE(ctx.empty_result.clock_trusted == 1u);
            } else {
                REQUIRE(ctx.empty_result.clock_trusted == 0u);
            }
        }
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static int test_all_16_put_fault_positions(void)
{
    uint32_t nth;
    for (nth = 1u; nth <= 16u; ++nth) {
        test_context_t ctx;
        mut_wrap_t wrap;
        uint64_t commit_before;
        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        mut_wrap_put_nth(&wrap, ctx.storage, nth);
        commit_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                &wrap.ops,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE);
        REQUIRE(ninlil_test_storage_call_count(
                ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_before);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);
        REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
            == 0u);
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static int test_clock_old_record_mutations(void)
{
    test_context_t ctx;
    ninlil_time_sample_t sample = make_trusted_sample(0xE2u, 11u);
    ninlil_model_domain_key_t clock_key;
    ninlil_bytes_view_t ck;
    ninlil_bytes_view_t identity;
    uint8_t value_buf[512];
    uint32_t value_len = 0u;
    ninlil_storage_txn_t txn = NULL;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_OK);

    identity.data = NULL;
    identity.length = 0u;
    REQUIRE(ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE,
                NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON,
                identity,
                &clock_key)
        == NINLIL_OK);
    ck.data = clock_key.bytes;
    ck.length = clock_key.length;

    /* Corrupt digest/bytes of old clock value. */
    REQUIRE(ctx.storage->begin(ctx.storage->user, ctx.handle,
                NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    {
        ninlil_mut_bytes_t mv;
        mv.data = value_buf;
        mv.capacity = (uint32_t)sizeof(value_buf);
        mv.length = 0u;
        REQUIRE(ctx.storage->get(ctx.storage->user, txn, ck, &mv)
            == NINLIL_STORAGE_OK);
        value_len = mv.length;
        REQUIRE(value_len > 8u);
        value_buf[value_len / 2u] ^= 0xFFu;
        REQUIRE(ctx.storage->put(ctx.storage->user, txn, ck,
                    (ninlil_bytes_view_t){value_buf, value_len})
            == NINLIL_STORAGE_OK);
        REQUIRE(ctx.storage->commit(
                    ctx.storage->user, txn, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
        txn = NULL;
    }
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            &ctx.validation,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* Missing clock → CORRUPT. */
    REQUIRE(raw_erase(&ctx, ck));
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            &ctx.validation,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);

    REQUIRE(context_destroy(&ctx));
    return 0;
}

/*
 * Table-driven fence: status × poison/shape for Port ops used by the
 * orchestrator. On fence: close +1, handle NULL, reopen_required=1, live txn 0.
 */
static int expect_fenced_commit_fail(
    test_context_t *ctx,
    const ninlil_storage_ops_t *ops,
    uint64_t close_before)
{
    uint64_t close_after;

    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ops,
            &ctx->handle,
            &ctx->validation,
            &ctx->empty_workspace,
            &ctx->empty_result)
        != NINLIL_OK);
    REQUIRE(ctx->empty_result.reopen_required == 1u);
    REQUIRE(ctx->handle == NULL);
    REQUIRE(ctx->empty_result.wrote_metadata == 0u);
    close_after = ninlil_test_storage_call_count(
        ctx->storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);
    REQUIRE(close_after == close_before + 1u);
    REQUIRE(ninlil_test_storage_live_transactions(ctx->storage_fixture) == 0u);
    REQUIRE(ninlil_test_storage_live_iterators(ctx->storage_fixture) == 0u);
    return 0;
}

static int test_port_fence_status_shape_table(void)
{
    typedef struct {
        const char *name;
        mut_attack_t attack;
        uint32_t get_n;
        uint32_t put_n;
        uint32_t begin_n;
        uint32_t iter_open_n;
        uint32_t iter_next_n;
        int need_metadata_seed; /* 1: write metadata first so put path is idle */
        int use_fixture_get_cu; /* fixture COMMIT_UNKNOWN get (len 0) */
        int use_fixture_put_cu;
        int use_fixture_begin_io;
        int use_fixture_commit_cu;
        int use_fixture_rb_io_after_put;
        int expect_fence;
    } row_t;

    /* expect_fence=1 for unknown/COMMIT_UNKNOWN/poison/shape; 0 for natural IO. */
    static const row_t rows[] = {
        { "begin_unknown", MUT_ATTACK_BEGIN_UNKNOWN, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "begin_commit_unknown", MUT_ATTACK_BEGIN_COMMIT_UNKNOWN, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_unknown_poison_len", MUT_ATTACK_GET_UNKNOWN_POISON_LEN, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_cu_poison_len", MUT_ATTACK_GET_COMMIT_UNKNOWN_POISON_LEN, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_io_poison_len", MUT_ATTACK_GET_IO_POISON_LEN, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_nf_poison_len", MUT_ATTACK_GET_NOT_FOUND_POISON_LEN, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_data_ptr", MUT_ATTACK_DATA_PTR, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_cap", MUT_ATTACK_CAPACITY, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_len_gt", MUT_ATTACK_LENGTH_GT_CAP, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "get_cu_clean", MUT_ATTACK_NONE, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1 },
        { "put_unknown", MUT_ATTACK_PUT_UNKNOWN, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "put_cu_clean", MUT_ATTACK_NONE, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1 },
        { "iter_open_ok_null", MUT_ATTACK_ITER_OPEN_OK_NULL, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_open_err_nonnull", MUT_ATTACK_ITER_OPEN_ERR_NONNULL, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_open_unknown_nonnull", MUT_ATTACK_ITER_OPEN_UNKNOWN_NONNULL, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_next_key_data", MUT_ATTACK_ITER_NEXT_KEY_DATA, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_next_nf_poison", MUT_ATTACK_ITER_NEXT_NOT_FOUND_POISON, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_next_io_poison", MUT_ATTACK_ITER_NEXT_IO_POISON, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_next_unknown", MUT_ATTACK_ITER_NEXT_UNKNOWN, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_next_val_len_gt", MUT_ATTACK_ITER_NEXT_VAL_LEN_GT, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 },
        { "iter_next_bts_rewrite", MUT_ATTACK_ITER_NEXT_BTS_REWRITE_VAL, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1 },
        { "get_bts_rewrite", MUT_ATTACK_GET_BTS_REWRITE_DATA, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        { "commit_cu", MUT_ATTACK_NONE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 },
        /* Natural definite put IO: rollback keeps primary; no status fence. */
        { "put_io_no_fence", MUT_ATTACK_PUT_NTH_IO, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        /* Natural BTS (MB3/MB7): CORRUPT, no fence. */
        { "get_bts_natural_no_fence", MUT_ATTACK_GET_BTS_NATURAL, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        { "iter_next_bts_natural_no_fence", MUT_ATTACK_ITER_NEXT_BTS_NATURAL, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 }
    };
    size_t i;

    for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); ++i) {
        test_context_t ctx;
        mut_wrap_t wrap;
        uint64_t close_before;
        const ninlil_storage_ops_t *ops;

        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));

        if (rows[i].need_metadata_seed != 0) {
            REQUIRE(ninlil_stage5_empty_metadata_commit(
                    ctx.storage,
                    &ctx.handle,
                    &ctx.validation,
                    &ctx.empty_workspace,
                    &ctx.empty_result)
                == NINLIL_OK);
        }

        mut_wrap_init(&wrap, ctx.storage, rows[i].attack, rows[i].get_n);
        wrap.put_hits_left = rows[i].put_n;
        wrap.begin_hits_left = rows[i].begin_n;
        wrap.iter_open_hits_left = rows[i].iter_open_n;
        wrap.iter_next_hits_left = rows[i].iter_next_n;
        ops = &wrap.ops;

        if (rows[i].use_fixture_get_cu != 0) {
            ops = ctx.storage;
            REQUIRE(ninlil_test_storage_fault_enqueue(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_GET,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                0,
                0));
        }
        if (rows[i].use_fixture_put_cu != 0) {
            ops = ctx.storage;
            REQUIRE(ninlil_test_storage_fault_enqueue(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_PUT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                0,
                0));
        }
        if (rows[i].use_fixture_begin_io != 0) {
            ops = ctx.storage;
            REQUIRE(ninlil_test_storage_fault_next(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_BEGIN,
                NINLIL_STORAGE_IO_ERROR));
        }
        if (rows[i].use_fixture_commit_cu != 0) {
            ops = ctx.storage;
            REQUIRE(ninlil_test_storage_fault_enqueue(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                0));
        }
        if (rows[i].use_fixture_rb_io_after_put != 0) {
            ops = ctx.storage;
            REQUIRE(ninlil_test_storage_fault_next(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_PUT,
                NINLIL_STORAGE_IO_ERROR));
            REQUIRE(ninlil_test_storage_fault_next(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_ROLLBACK,
                NINLIL_STORAGE_IO_ERROR));
        }

        close_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);

        if (rows[i].expect_fence != 0) {
            if (expect_fenced_commit_fail(&ctx, ops, close_before) != 0) {
                (void)fprintf(stderr, "fence row failed: %s\n", rows[i].name);
                return 1;
            }
        } else {
            /* Definite known failure without fence (e.g. put IO). */
            REQUIRE(ninlil_stage5_empty_metadata_commit(
                    ops, &ctx.handle, &ctx.validation,
                    &ctx.empty_workspace, &ctx.empty_result)
                != NINLIL_OK);
            REQUIRE(ctx.empty_result.reopen_required == 0u);
            REQUIRE(ctx.handle != NULL);
            REQUIRE(ninlil_test_storage_call_count(
                    ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE)
                == close_before);
            REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
                == 0u);
        }
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

static int test_partial_bootstrap_no_metadata_puts(void)
{
    test_context_t ctx;
    ninlil_model_runtime_store_key_t key;
    ninlil_bytes_view_t kv;
    uint64_t put_before;
    uint64_t put_after;

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    /* Erase one family 1–4 catalog key → bootstrap not exact-17. */
    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN, &key)
        == NINLIL_OK);
    kv.data = key.bytes;
    kv.length = key.length;
    REQUIRE(raw_erase(&ctx, kv));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    put_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage, &ctx.handle, &ctx.validation,
            &ctx.empty_workspace, &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);
    put_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    REQUIRE(put_after == put_before);
    REQUIRE(ctx.empty_result.wrote_metadata == 0u);
    REQUIRE(context_destroy(&ctx));
    return 0;
}

/*
 * Malformed/corrupt case: flip a stored bootstrap byte (may not remain a
 * fully valid alternate authority). Authority proof must still fail closed.
 */
static int test_bootstrap_authority_mismatch_fields(void)
{
    typedef enum {
        MUT_BINDING_BYTE = 0,
        MUT_IDENTITY_BYTE,
        MUT_COUNTER_BYTE,
        MUT_CAPACITY_LIMIT_BYTE
    } mut_kind_t;
    static const mut_kind_t kinds[] = {
        MUT_BINDING_BYTE,
        MUT_IDENTITY_BYTE,
        MUT_COUNTER_BYTE,
        MUT_CAPACITY_LIMIT_BYTE
    };
    static const ninlil_model_runtime_store_key_id_t key_ids[] = {
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE
    };
    size_t i;

    for (i = 0u; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
        test_context_t ctx;
        ninlil_model_runtime_store_key_t key;
        ninlil_bytes_view_t kv;
        ninlil_storage_txn_t txn = NULL;
        uint8_t buf[256];
        ninlil_mut_bytes_t mv;
        uint64_t put_before;
        uint64_t commit_before;
        uint64_t rb_before;
        uint64_t put_after;
        uint64_t commit_after;
        uint64_t rb_after;

        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        REQUIRE(ninlil_model_runtime_store_build_key(key_ids[i], &key)
            == NINLIL_OK);
        kv.data = key.bytes;
        kv.length = key.length;
        REQUIRE(ctx.storage->begin(
                ctx.storage->user, ctx.handle, NINLIL_STORAGE_READ_WRITE, &txn)
            == NINLIL_STORAGE_OK);
        mv.data = buf;
        mv.capacity = (uint32_t)sizeof(buf);
        mv.length = 0u;
        REQUIRE(ctx.storage->get(ctx.storage->user, txn, kv, &mv)
            == NINLIL_STORAGE_OK);
        REQUIRE(mv.length > 4u);
        /* Flip a payload byte so stored remains framed but authority differs. */
        buf[mv.length / 2u] ^= 0x5Au;
        REQUIRE(ctx.storage->put(
                ctx.storage->user,
                txn,
                kv,
                (ninlil_bytes_view_t){buf, mv.length})
            == NINLIL_STORAGE_OK);
        REQUIRE(ctx.storage->commit(
                ctx.storage->user, txn, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
        txn = NULL;

        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        put_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        commit_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        rb_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        put_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        commit_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        rb_after = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
        REQUIRE(put_after == put_before);
        REQUIRE(commit_after == commit_before);
        REQUIRE(rb_after == rb_before + 1u);
        REQUIRE(ctx.empty_result.wrote_metadata == 0u);

        /* Same mismatch on validate + clock: mutation 0. */
        REQUIRE(ninlil_stage5_empty_metadata_validate(
                ctx.storage,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        {
            ninlil_time_sample_t sample = make_trusted_sample(0x11u, 1u);
            put_before = ninlil_test_storage_call_count(
                ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
            REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
                    ctx.storage,
                    &ctx.handle,
                    &sample,
                    &ctx.validation,
                    &ctx.empty_workspace,
                    &ctx.empty_result)
                == NINLIL_E_STORAGE_CORRUPT);
            put_after = ninlil_test_storage_call_count(
                ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
            REQUIRE(put_after == put_before);
        }
        (void)kinds[i];
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

/*
 * P0 dead-end avoidance: replace stored bootstrap with a fully valid alternate
 * authority B (plan+validate_snapshot success). accepted_validation=A must
 * CORRUPT with put/commit 0 and no extra fence; B must pass authority proof.
 */
static int test_bootstrap_valid_authority_b_replacement(void)
{
    test_context_t ctx;
    ninlil_runtime_config_t config_b;
    ninlil_model_runtime_validation_result_t validation_a;
    ninlil_model_runtime_validation_result_t validation_b;
    ninlil_model_runtime_store_bootstrap_plan_t plan_b;
    ninlil_model_runtime_store_bootstrap_record_t rec;
    ninlil_model_runtime_store_encoded_snapshot_t encoded;
    ninlil_model_runtime_store_validated_snapshot_t validated;
    uint8_t packed[NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_VALUE_BYTES];
    ninlil_storage_txn_t txn = NULL;
    uint32_t index;
    uint64_t put_before;
    uint64_t commit_before;
    uint64_t rb_before;
    uint64_t close_before;
    uint64_t put_after;
    uint64_t commit_after;
    uint64_t rb_after;
    uint64_t close_after;
    ninlil_time_sample_t sample = make_trusted_sample(0x33u, 7u);
    static const uint16_t caps[17] = {
        183u, 84u, 32u, 32u, 32u, 32u, 68u, 68u, 68u, 68u, 68u, 68u, 68u, 68u,
        68u, 68u, 68u
    };
    static const uint16_t offs[17] = {
        0u, 183u, 267u, 299u, 331u, 363u, 395u, 463u, 531u, 599u, 667u, 735u,
        803u, 871u, 939u, 1007u, 1075u
    };

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    /* Authority A already came from production validate_and_derive. */
    validation_a = ctx.validation;
    REQUIRE(validation_a.status == NINLIL_OK);

    /*
     * Fully valid alternate authority B via production validate_and_derive.
     * Differs in runtime_id / device / installation / max_services while
     * satisfying lifecycle cross-field + profile upper bounds (services ≤16).
     */
    config_b = config_fixture();
    set_id(&config_b.runtime_id, 0x91u);
    set_id(&config_b.local_identity.device_id, 0x92u);
    set_id(&config_b.local_identity.installation_id, 0x93u);
    config_b.limits.max_services = 12u;
    /* Cross-field + profile upper: deferred ≤ deliveries ≤ nonterminal ≤256. */
    config_b.limits.max_nonterminal_transactions = 40u;
    config_b.limits.max_nonterminal_deliveries = 20u;
    config_b.limits.max_deferred_tokens = 16u;
    config_b.limits.max_event_spool_count = 0u;
    config_b.limits.max_event_spool_bytes = 0u;
    REQUIRE(validation_from_config(&config_b, &validation_b));
    REQUIRE(validation_b.status == NINLIL_OK);
    REQUIRE(memcmp(
                validation_a.accepted_config.runtime_id.bytes,
                validation_b.accepted_config.runtime_id.bytes,
                16u)
        != 0);
    REQUIRE(validation_a.accepted_config.limits.max_services
        != validation_b.accepted_config.limits.max_services);

    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
            &validation_b, &plan_b)
        == NINLIL_OK);

    /* Replace entire bootstrap-17 with canonical B records. */
    REQUIRE(ctx.storage->begin(
            ctx.storage->user, ctx.handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    for (index = 0u; index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_bytes_view_t k;
        ninlil_bytes_view_t v;
        REQUIRE(ninlil_model_runtime_store_bootstrap_record_at(
                &plan_b, index, &rec)
            == NINLIL_OK);
        k.data = rec.key.bytes;
        k.length = rec.key.length;
        v.data = rec.value;
        v.length = rec.value_length;
        REQUIRE(ctx.storage->put(ctx.storage->user, txn, k, v)
            == NINLIL_STORAGE_OK);
    }
    REQUIRE(ctx.storage->commit(
            ctx.storage->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Prove stored B is structurally valid exact-17 (self-consistent authority). */
    (void)memset(&encoded, 0, sizeof(encoded));
    (void)memset(packed, 0, sizeof(packed));
    REQUIRE(ctx.storage->begin(
            ctx.storage->user, ctx.handle, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    for (index = 0u; index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_model_runtime_store_key_t key;
        ninlil_bytes_view_t key_view;
        ninlil_mut_bytes_t mv;
        REQUIRE(ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)(index + 1u), &key)
            == NINLIL_OK);
        key_view.data = key.bytes;
        key_view.length = key.length;
        mv.data = &packed[offs[index]];
        mv.capacity = caps[index];
        mv.length = 0u;
        REQUIRE(ctx.storage->get(ctx.storage->user, txn, key_view, &mv)
            == NINLIL_STORAGE_OK);
        encoded.values[index].data = mv.data;
        encoded.values[index].length = mv.length;
    }
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(&encoded, &validated)
        == NINLIL_OK);
    REQUIRE(ctx.storage->rollback(ctx.storage->user, txn) == NINLIL_STORAGE_OK);
    txn = NULL;

    /* accepted_validation=A against stored B: all 3 APIs CORRUPT, no write, no fence. */
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    put_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    rb_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    close_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);

    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage,
            &ctx.handle,
            &validation_a,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);
    put_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    close_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);
    REQUIRE(put_after == put_before);
    REQUIRE(commit_after == commit_before);
    REQUIRE(rb_after == rb_before + 1u);
    REQUIRE(close_after == close_before);
    REQUIRE(ctx.empty_result.reopen_required == 0u);
    REQUIRE(ctx.handle != NULL);
    REQUIRE(ctx.empty_result.wrote_metadata == 0u);

    REQUIRE(ninlil_stage5_empty_metadata_validate(
            ctx.storage,
            &ctx.handle,
            &validation_a,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ctx.empty_result.reopen_required == 0u);
    REQUIRE(ctx.handle != NULL);

    put_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    rb_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            &validation_a,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);
    put_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    rb_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_ROLLBACK);
    REQUIRE(put_after == put_before);
    REQUIRE(rb_after == rb_before + 1u);
    REQUIRE(ctx.empty_result.reopen_required == 0u);
    REQUIRE(ctx.handle != NULL);

    /* Control: accepted_validation=B passes authority; domain still 0/16 → write OK. */
    put_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage,
            &ctx.handle,
            &validation_b,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_OK);
    put_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    REQUIRE(ctx.empty_result.wrote_metadata == 1u);
    REQUIRE(put_after == put_before + 16u);
    REQUIRE(ctx.empty_result.reopen_required == 0u);
    REQUIRE(ctx.handle != NULL);

    /* Validate with B succeeds; clock first TRUSTED with B succeeds. */
    REQUIRE(ninlil_stage5_empty_metadata_validate(
            ctx.storage,
            &ctx.handle,
            &validation_b,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ctx.empty_result.clock_trusted == 0u);
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            &validation_b,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ninlil_stage5_empty_metadata_validate(
            ctx.storage,
            &ctx.handle,
            &validation_b,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_OK);
    REQUIRE(ctx.empty_result.clock_trusted == 1u);

    /* A still rejects after B-valid metadata/clock (authority mismatch). */
    REQUIRE(ninlil_stage5_empty_metadata_validate(
            ctx.storage,
            &ctx.handle,
            &validation_a,
            &ctx.empty_workspace,
            &ctx.empty_result)
        == NINLIL_E_STORAGE_CORRUPT);

    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_validation_precondition_port0(void)
{
    test_context_t ctx;
    ninlil_stage5_empty_metadata_result_t result;
    ninlil_model_runtime_validation_result_t bad;
    uint64_t begin_before;
    uint64_t begin_after;
    ninlil_time_sample_t sample = make_trusted_sample(0x22u, 2u);

    REQUIRE(context_init(&ctx));
    REQUIRE(bootstrap_via_seam(&ctx));
    (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
    (void)memset(&result, 0xA5, sizeof(result));
    begin_before = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN);

    /* NULL validation */
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage,
            &ctx.handle,
            NULL,
            &ctx.empty_workspace,
            &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(((const uint8_t *)&result)[0] == 0xA5u);

    /* status non-OK */
    bad = ctx.validation;
    bad.status = NINLIL_E_INVALID_ARGUMENT;
    (void)memset(&result, 0xA5, sizeof(result));
    REQUIRE(ninlil_stage5_empty_metadata_validate(
            ctx.storage,
            &ctx.handle,
            &bad,
            &ctx.empty_workspace,
            &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(((const uint8_t *)&result)[0] == 0xA5u);

    /* alias validation with workspace */
    (void)memset(&result, 0xA5, sizeof(result));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
            ctx.storage,
            &ctx.handle,
            (const ninlil_model_runtime_validation_result_t *)
                &ctx.empty_workspace,
            &ctx.empty_workspace,
            &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(((const uint8_t *)&result)[0] == 0xA5u);

    (void)memset(&result, 0xA5, sizeof(result));
    REQUIRE(ninlil_stage5_clock_baseline_commit_trusted(
            ctx.storage,
            &ctx.handle,
            &sample,
            NULL,
            &ctx.empty_workspace,
            &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(((const uint8_t *)&result)[0] == 0xA5u);

    begin_after = ninlil_test_storage_call_count(
        ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN);
    REQUIRE(begin_after == begin_before);
    REQUIRE(context_destroy(&ctx));
    return 0;
}

static int test_begin_shape_nonnull_txn_cleanup(void)
{
    /* rollback after shape: OK / IO / unknown */
    static const ninlil_storage_status_t rb_faults[] = {
        NINLIL_STORAGE_OK, /* natural path: no fault */
        NINLIL_STORAGE_IO_ERROR,
        (ninlil_storage_status_t)212
    };
    size_t i;

    for (i = 0u; i < sizeof(rb_faults) / sizeof(rb_faults[0]); ++i) {
        test_context_t ctx;
        mut_wrap_t wrap;
        uint64_t close_before;

        REQUIRE(context_init(&ctx));
        REQUIRE(bootstrap_via_seam(&ctx));
        (void)memset(&ctx.empty_workspace, 0, sizeof(ctx.empty_workspace));
        mut_wrap_init(&wrap, ctx.storage, MUT_ATTACK_BEGIN_FAIL_NONNULL, 0u);
        wrap.begin_hits_left = 1u;
        if (rb_faults[i] != NINLIL_STORAGE_OK) {
            REQUIRE(ninlil_test_storage_fault_next(
                ctx.storage_fixture,
                NINLIL_TEST_STORAGE_OP_ROLLBACK,
                rb_faults[i]));
        }
        close_before = ninlil_test_storage_call_count(
            ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);
        REQUIRE(ninlil_stage5_empty_metadata_commit(
                &wrap.ops,
                &ctx.handle,
                &ctx.validation,
                &ctx.empty_workspace,
                &ctx.empty_result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ctx.empty_result.reopen_required == 1u);
        REQUIRE(ctx.handle == NULL);
        REQUIRE(ninlil_test_storage_call_count(
                ctx.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE)
            == close_before + 1u);
        REQUIRE(ninlil_test_storage_live_transactions(ctx.storage_fixture)
            == 0u);
        if (rb_faults[i] != NINLIL_STORAGE_OK) {
            REQUIRE(ctx.empty_result.cleanup_status == rb_faults[i]);
        }
        REQUIRE(context_destroy(&ctx));
    }
    return 0;
}

int main(void)
{
    if (test_workspace_bounds() != 0) {
        return 1;
    }
    if (test_null_and_fail_out_zero() != 0) {
        return 1;
    }
    if (test_validation_precondition_port0() != 0) {
        return 1;
    }
    if (test_alias_precondition_no_result_init() != 0) {
        return 1;
    }
    if (test_bootstrap_authority_mismatch_fields() != 0) {
        return 1;
    }
    if (test_bootstrap_valid_authority_b_replacement() != 0) {
        return 1;
    }
    if (test_begin_shape_nonnull_txn_cleanup() != 0) {
        return 1;
    }
    if (test_port_fence_status_shape_table() != 0) {
        return 1;
    }
    if (test_partial_bootstrap_no_metadata_puts() != 0) {
        return 1;
    }
    if (test_commit_0_16_exact_and_noop() != 0) {
        return 1;
    }
    if (test_partial_1_15_all_counts() != 0) {
        return 1;
    }
    if (test_surplus_row_corrupt() != 0) {
        return 1;
    }
    if (test_surplus_kinds() != 0) {
        return 1;
    }
    if (test_future_only_unsupported_and_mixed_precedence() != 0) {
        return 1;
    }
    if (test_no_trusted_downgrade() != 0) {
        return 1;
    }
    if (test_commit_failure_no_post_commit_rollback() != 0) {
        return 1;
    }
    if (test_pre_commit_failure_rollback_exactly_one() != 0) {
        return 1;
    }
    if (test_pre_commit_rollback_failure_keeps_primary() != 0) {
        return 1;
    }
    if (test_validate_ro_rollback_failure_not_success() != 0) {
        return 1;
    }
    if (test_get_shape_mutations_fail_closed() != 0) {
        return 1;
    }
    if (test_iter_adversarial() != 0) {
        return 1;
    }
    if (test_commit_unknown_both_truths_metadata_and_clock() != 0) {
        return 1;
    }
    if (test_all_16_put_fault_positions() != 0) {
        return 1;
    }
    if (test_sample_abi_exact_storage_call_zero() != 0) {
        return 1;
    }
    if (test_clock_old_record_mutations() != 0) {
        return 1;
    }
    if (test_clock_sample_and_second_call() != 0) {
        return 1;
    }
    if (test_clock_trusted_sample_matrix() != 0) {
        return 1;
    }
    if (test_seam_contract_unchanged_after_metadata() != 0) {
        return 1;
    }
    (void)printf("stage5_empty_metadata_test ok\n");
    return 0;
}
