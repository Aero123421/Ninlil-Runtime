#include "typed_simulated_bearer.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct bearer_message_copy bearer_message_copy_t;
typedef struct bearer_handle bearer_handle_t;

typedef struct bearer_endpoint {
    int bound;
    int active;
    ninlil_id128_t runtime_id;
    ninlil_role_t role;
    bearer_handle_t *active_handle;
} bearer_endpoint_t;

typedef struct bearer_direction {
    bearer_message_copy_t *head;
    bearer_message_copy_t *tail;
    uint64_t queued_entries;
    uint64_t queued_bytes;
    uint64_t availability_epoch;
    uint64_t blocked_entries;
    uint64_t blocked_bytes;
    int path_up;
    int fatal;
} bearer_direction_t;

struct bearer_message_copy {
    ninlil_bearer_message_t message;
    uint8_t *payload;
    uint8_t *evidence;
    uint64_t logical_bytes;
    bearer_message_copy_t *next;
};

struct bearer_handle {
    uint64_t id;
    struct ninlil_test_bearer *owner;
    size_t endpoint_index;
    int live;
    int cleanup_only;
    bearer_message_copy_t *loan;
    ninlil_bearer_message_t *loan_object;
    bearer_handle_t *next;
};

typedef enum permit_state {
    PERMIT_LIVE = 0,
    PERMIT_CONSUMED = 1,
    PERMIT_RELEASED = 2,
    PERMIT_EXPIRED = 3,
    PERMIT_FENCED = 4
} permit_state_t;

typedef struct permit_record {
    ninlil_tx_permit_t permit;
    ninlil_id128_t transaction_id;
    ninlil_bearer_message_kind_t message_kind;
    uint32_t logical_bytes;
    ninlil_digest256_t content_digest;
    ninlil_digest256_t request_digest;
    permit_state_t state;
} permit_record_t;

typedef struct raw_open_entry {
    ninlil_bearer_status_t status;
    uint32_t remaining;
    int return_handle;
} raw_open_entry_t;

typedef struct raw_send_entry {
    ninlil_bearer_status_t status;
    uint32_t remaining;
    ninlil_bearer_send_result_t result;
} raw_send_entry_t;

typedef struct raw_receive_entry {
    ninlil_bearer_status_t status;
    uint32_t remaining;
    bearer_message_copy_t *prototype;
    int exact_unsafe;
} raw_receive_entry_t;

typedef struct raw_state_entry {
    ninlil_bearer_status_t status;
    uint32_t remaining;
    ninlil_bearer_state_t state;
} raw_state_entry_t;

typedef struct raw_open_queue {
    raw_open_entry_t entries[NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY];
    size_t head;
    size_t count;
} raw_open_queue_t;

typedef struct raw_send_queue {
    raw_send_entry_t entries[NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY];
    size_t head;
    size_t count;
} raw_send_queue_t;

typedef struct raw_receive_queue {
    raw_receive_entry_t entries[NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY];
    size_t head;
    size_t count;
} raw_receive_queue_t;

typedef struct raw_state_queue {
    raw_state_entry_t entries[NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY];
    size_t head;
    size_t count;
} raw_state_queue_t;

struct ninlil_test_bearer {
    ninlil_bearer_ops_t bearer_ops;
    ninlil_tx_gate_ops_t tx_gate_ops;
    ninlil_test_bearer_config_t config;
    bearer_endpoint_t endpoints[2];
    bearer_direction_t directions[2];
    bearer_handle_t *handles;
    bearer_message_copy_t *orphan_loans;
    bearer_message_copy_t *raw_retired;
    permit_record_t *permits;
    raw_open_queue_t raw_open;
    raw_send_queue_t raw_send;
    raw_receive_queue_t raw_receive;
    raw_state_queue_t raw_state;
    ninlil_id128_t current_clock_epoch_id;
    uint64_t current_time_ms;
    uint64_t next_handle_id;
    uint64_t next_permit_sequence;
    uint64_t next_trace_sequence;
    uint64_t call_counts[NINLIL_TEST_BEARER_OP_COUNT];
    ninlil_test_bearer_trace_record_t
        trace[NINLIL_TEST_BEARER_TRACE_CAPACITY];
    size_t trace_count;
    int trace_overflowed;
    uint64_t live_handles;
    uint64_t tombstoned_handles;
    uint64_t live_loan_count;
    uint64_t live_loan_bytes;
    uint64_t orphan_loan_count;
    uint64_t orphan_loan_bytes;
    uint64_t permit_live_count;
    uint64_t permit_consumed_count;
    uint64_t permit_released_count;
    uint64_t permit_expired_count;
    uint64_t permit_fenced_count;
    uint64_t violation_count;
    uint32_t fail_next_copy_allocations;
};

typedef struct sha256_context {
    uint32_t state[8];
    uint64_t total_bytes;
    uint8_t buffer[64];
    size_t buffer_length;
} sha256_context_t;

static const uint32_t sha256_constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static ninlil_bearer_status_t fixture_open(
    void *user, const ninlil_id128_t *runtime_id, ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle);
static void fixture_close(void *user, ninlil_bearer_handle_t handle);
static ninlil_bearer_status_t fixture_send(
    void *user, ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result);
static ninlil_bearer_status_t fixture_receive_next(
    void *user, ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message);
static void fixture_release_received(
    void *user, ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message);
static ninlil_bearer_status_t fixture_state(
    void *user, ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state);
static ninlil_tx_gate_status_t fixture_tx_acquire(
    void *user, const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now, ninlil_tx_permit_t *out_permit);
static void fixture_tx_release_unused(
    void *user, const ninlil_tx_permit_t *permit);

static uint32_t rotate_right(uint32_t value, uint32_t bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static uint32_t load_be32(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24u)
        | ((uint32_t)input[1] << 16u)
        | ((uint32_t)input[2] << 8u)
        | (uint32_t)input[3];
}

static void store_be32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24u);
    output[1] = (uint8_t)(value >> 16u);
    output[2] = (uint8_t)(value >> 8u);
    output[3] = (uint8_t)value;
}

static void store_be64(uint8_t output[8], uint64_t value)
{
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        output[7u - index] = (uint8_t)(value >> (index * 8u));
    }
}

static void sha256_transform(sha256_context_t *context, const uint8_t block[64])
{
    uint32_t words[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    size_t index;

    for (index = 0u; index < 16u; ++index) {
        words[index] = load_be32(&block[index * 4u]);
    }
    for (index = 16u; index < 64u; ++index) {
        uint32_t s0 = rotate_right(words[index - 15u], 7u)
            ^ rotate_right(words[index - 15u], 18u)
            ^ (words[index - 15u] >> 3u);
        uint32_t s1 = rotate_right(words[index - 2u], 17u)
            ^ rotate_right(words[index - 2u], 19u)
            ^ (words[index - 2u] >> 10u);
        words[index] = words[index - 16u] + s0
            + words[index - 7u] + s1;
    }
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];
    for (index = 0u; index < 64u; ++index) {
        uint32_t sum1 = rotate_right(e, 6u) ^ rotate_right(e, 11u)
            ^ rotate_right(e, 25u);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sum1 + choice
            + sha256_constants[index] + words[index];
        uint32_t sum0 = rotate_right(a, 2u) ^ rotate_right(a, 13u)
            ^ rotate_right(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void sha256_init(sha256_context_t *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    (void)memset(context, 0, sizeof(*context));
    (void)memcpy(context->state, initial, sizeof(initial));
}

static void sha256_update(
    sha256_context_t *context, const uint8_t *data, size_t length)
{
    size_t consumed = 0u;
    context->total_bytes += (uint64_t)length;
    while (consumed < length) {
        size_t available = 64u - context->buffer_length;
        size_t take = length - consumed < available
            ? length - consumed : available;
        (void)memcpy(&context->buffer[context->buffer_length],
            &data[consumed], take);
        context->buffer_length += take;
        consumed += take;
        if (context->buffer_length == 64u) {
            sha256_transform(context, context->buffer);
            context->buffer_length = 0u;
        }
    }
}

static void sha256_final(sha256_context_t *context, uint8_t output[32])
{
    uint8_t padding[64] = {0x80u};
    uint8_t length_bytes[8];
    uint64_t bit_length = context->total_bytes * 8u;
    size_t padding_length = context->buffer_length < 56u
        ? 56u - context->buffer_length : 120u - context->buffer_length;
    size_t index;
    store_be64(length_bytes, bit_length);
    sha256_update(context, padding, padding_length);
    sha256_update(context, length_bytes, sizeof(length_bytes));
    for (index = 0u; index < 8u; ++index) {
        store_be32(&output[index * 4u], context->state[index]);
    }
}

static int id_is_zero(const ninlil_id128_t *id)
{
    static const ninlil_id128_t zero = {{0u}};
    return id == NULL || memcmp(id, &zero, sizeof(zero)) == 0;
}

static int id_equal(const ninlil_id128_t *left, const ninlil_id128_t *right)
{
    return left != NULL && right != NULL
        && memcmp(left, right, sizeof(*left)) == 0;
}

static int digest_equal(
    const ninlil_digest256_t *left, const ninlil_digest256_t *right)
{
    return left != NULL && right != NULL
        && memcmp(left, right, sizeof(*left)) == 0;
}

static int abi_header_is_valid(
    uint16_t version, uint16_t size, size_t required)
{
    return version == NINLIL_ABI_VERSION && (size_t)size >= required;
}

static int checked_increment(uint64_t *value)
{
    if (*value == UINT64_MAX) {
        return 0;
    }
    *value += 1u;
    return 1;
}

static uint64_t next_nonzero(uint64_t *value)
{
    uint64_t result = *value == 0u ? 1u : *value;
    *value = result == UINT64_MAX ? UINT64_MAX : result + 1u;
    return result;
}

static void record_trace(
    ninlil_test_bearer_t *bearer,
    ninlil_test_bearer_operation_t operation,
    ninlil_bearer_status_t bearer_status,
    ninlil_tx_gate_status_t tx_gate_status,
    const bearer_handle_t *handle,
    const ninlil_id128_t *peer,
    const ninlil_bearer_message_t *message,
    uint64_t logical_bytes,
    size_t direction_index,
    uint32_t raw_consumed,
    uint32_t violation)
{
    ninlil_test_bearer_trace_record_t *record;
    const bearer_handle_t *known_handle = NULL;
    const bearer_handle_t *cursor;
    if ((size_t)operation < (size_t)NINLIL_TEST_BEARER_OP_COUNT
        && bearer->call_counts[operation] != UINT64_MAX) {
        bearer->call_counts[operation] += 1u;
    }
    if (bearer->trace_count >= NINLIL_TEST_BEARER_TRACE_CAPACITY) {
        bearer->trace_overflowed = 1;
        return;
    }
    record = &bearer->trace[bearer->trace_count++];
    (void)memset(record, 0, sizeof(*record));
    record->sequence = next_nonzero(&bearer->next_trace_sequence);
    record->operation = operation;
    record->bearer_status = bearer_status;
    record->tx_gate_status = tx_gate_status;
    record->logical_bytes = logical_bytes;
    record->raw_consumed = raw_consumed;
    record->violation = violation;
    for (cursor = bearer->handles; cursor != NULL; cursor = cursor->next) {
        if (cursor == handle) {
            known_handle = cursor;
            break;
        }
    }
    if (known_handle != NULL) {
        record->handle_id = known_handle->id;
        if (known_handle->endpoint_index < 2u) {
            record->runtime_id =
                bearer->endpoints[known_handle->endpoint_index].runtime_id;
        }
    }
    if (peer != NULL) {
        record->peer_runtime_id = *peer;
    }
    if (message != NULL) {
        record->transaction_id = message->transaction_id;
        record->attempt_id = message->attempt_id;
    }
    if (direction_index < 2u) {
        record->queued_entries = bearer->directions[direction_index].queued_entries;
        record->queued_bytes = bearer->directions[direction_index].queued_bytes;
        record->availability_epoch =
            bearer->directions[direction_index].availability_epoch;
    }
}

static void note_violation(ninlil_test_bearer_t *bearer)
{
    if (bearer->violation_count != UINT64_MAX) {
        bearer->violation_count += 1u;
    }
}

static int message_shape_is_safe(const ninlil_bearer_message_t *message)
{
    if (message == NULL
        || !abi_header_is_valid(message->abi_version,
            message->struct_size, sizeof(*message))
        || !abi_header_is_valid(message->source.abi_version,
            message->source.struct_size, sizeof(message->source))
        || !abi_header_is_valid(message->source.local_identity.abi_version,
            message->source.local_identity.struct_size,
            sizeof(message->source.local_identity))
        || !abi_header_is_valid(message->target.abi_version,
            message->target.struct_size, sizeof(message->target))
        || !abi_header_is_valid(message->service.abi_version,
            message->service.struct_size, sizeof(message->service))) {
        return 0;
    }
    if (message->service.namespace_id.length > NINLIL_MAX_TEXT_ID_BYTES
        || message->service.service_id.length > NINLIL_MAX_TEXT_ID_BYTES
        || message->service.schema_id.length > NINLIL_MAX_TEXT_ID_BYTES) {
        return 0;
    }
    if ((message->payload.length == 0u && message->payload.data != NULL)
        || (message->payload.length > 0u && message->payload.data == NULL)
        || (message->evidence.length == 0u && message->evidence.data != NULL)
        || (message->evidence.length > 0u && message->evidence.data == NULL)) {
        return 0;
    }
    return 1;
}

int ninlil_test_bearer_logical_bytes(
    const ninlil_bearer_message_t *message, uint64_t *out_bytes)
{
    uint64_t total = 455u;
    uint64_t additions[5];
    size_t index;
    if (out_bytes == NULL || !message_shape_is_safe(message)) {
        return 0;
    }
    additions[0] = message->service.namespace_id.length;
    additions[1] = message->service.service_id.length;
    additions[2] = message->service.schema_id.length;
    additions[3] = message->payload.length;
    additions[4] = message->evidence.length;
    for (index = 0u; index < 5u; ++index) {
        if (UINT64_MAX - total < additions[index]) {
            return 0;
        }
        total += additions[index];
    }
    if (total > UINT32_MAX) {
        return 0;
    }
    *out_bytes = total;
    return 1;
}

static void free_message_copy(bearer_message_copy_t *copy)
{
    if (copy != NULL) {
        free(copy->payload);
        free(copy->evidence);
        free(copy);
    }
}

static bearer_message_copy_t *clone_message(
    ninlil_test_bearer_t *bearer,
    const ninlil_bearer_message_t *message,
    uint64_t logical_bytes,
    int use_failure_script)
{
    bearer_message_copy_t *copy;
    if (use_failure_script && bearer->fail_next_copy_allocations > 0u) {
        bearer->fail_next_copy_allocations -= 1u;
        return NULL;
    }
    copy = (bearer_message_copy_t *)calloc(1u, sizeof(*copy));
    if (copy == NULL) {
        return NULL;
    }
    copy->message = *message;
    copy->logical_bytes = logical_bytes;
    if (message->payload.length > 0u) {
        copy->payload = (uint8_t *)malloc(message->payload.length);
        if (copy->payload == NULL) {
            free_message_copy(copy);
            return NULL;
        }
        (void)memcpy(copy->payload, message->payload.data,
            message->payload.length);
        copy->message.payload.data = copy->payload;
    } else {
        copy->message.payload.data = NULL;
    }
    if (message->evidence.length > 0u) {
        copy->evidence = (uint8_t *)malloc(message->evidence.length);
        if (copy->evidence == NULL) {
            free_message_copy(copy);
            return NULL;
        }
        (void)memcpy(copy->evidence, message->evidence.data,
            message->evidence.length);
        copy->message.evidence.data = copy->evidence;
    } else {
        copy->message.evidence.data = NULL;
    }
    return copy;
}

static int find_endpoint(
    const ninlil_test_bearer_t *bearer, const ninlil_id128_t *runtime_id)
{
    size_t index;
    for (index = 0u; index < 2u; ++index) {
        if (bearer->endpoints[index].bound
            && id_equal(&bearer->endpoints[index].runtime_id, runtime_id)) {
            return (int)index;
        }
    }
    return -1;
}

static int free_endpoint_slot(const ninlil_test_bearer_t *bearer)
{
    if (!bearer->endpoints[0].bound) {
        return 0;
    }
    if (!bearer->endpoints[1].bound) {
        return 1;
    }
    return -1;
}

static size_t direction_for_source(size_t source_endpoint)
{
    return source_endpoint;
}

static int path_available(
    const ninlil_test_bearer_t *bearer, size_t direction_index)
{
    size_t peer = 1u - direction_index;
    const bearer_direction_t *direction = &bearer->directions[direction_index];
    return !direction->fatal && direction->path_up
        && bearer->endpoints[direction_index].active
        && bearer->endpoints[peer].active;
}

static int increment_availability(
    ninlil_test_bearer_t *bearer, size_t direction_index)
{
    bearer_direction_t *direction = &bearer->directions[direction_index];
    if (!checked_increment(&direction->availability_epoch)) {
        direction->fatal = 1;
        return 0;
    }
    return 1;
}

static void maybe_record_block_improvement(
    ninlil_test_bearer_t *bearer, size_t direction_index)
{
    bearer_direction_t *direction = &bearer->directions[direction_index];
    if (direction->blocked_entries == 0u) {
        return;
    }
    if (direction->queued_entries <= bearer->config.max_entries_per_direction
        && direction->blocked_entries
            <= bearer->config.max_entries_per_direction
                - direction->queued_entries
        && direction->queued_bytes <= bearer->config.max_bytes_per_direction
        && direction->blocked_bytes
            <= bearer->config.max_bytes_per_direction
                - direction->queued_bytes
        && bearer->endpoints[1u - direction_index].active
        && direction->path_up && !direction->fatal) {
        direction->blocked_entries = 0u;
        direction->blocked_bytes = 0u;
        (void)increment_availability(bearer, direction_index);
    }
}

static bearer_handle_t *find_known_handle(
    const ninlil_test_bearer_t *bearer, const bearer_handle_t *handle)
{
    bearer_handle_t *cursor;
    if (handle == NULL) {
        return NULL;
    }
    for (cursor = bearer->handles; cursor != NULL; cursor = cursor->next) {
        if (cursor == handle) {
            return cursor;
        }
    }
    return NULL;
}

static int handle_is_live(
    const ninlil_test_bearer_t *bearer, const bearer_handle_t *handle)
{
    bearer_handle_t *known = find_known_handle(bearer, handle);
    return known != NULL && known->owner == bearer && known->live
        && !known->cleanup_only
        && known->endpoint_index < 2u
        && bearer->endpoints[known->endpoint_index].active_handle == known;
}

static bearer_handle_t *allocate_handle(
    ninlil_test_bearer_t *bearer, size_t endpoint_index, int live)
{
    bearer_handle_t *handle = (bearer_handle_t *)calloc(1u, sizeof(*handle));
    if (handle == NULL) {
        return NULL;
    }
    handle->id = next_nonzero(&bearer->next_handle_id);
    handle->owner = bearer;
    handle->endpoint_index = endpoint_index;
    handle->live = live;
    handle->next = bearer->handles;
    bearer->handles = handle;
    if (live) {
        bearer->live_handles += 1u;
    } else {
        bearer->tombstoned_handles += 1u;
    }
    return handle;
}

static void initialize_send_result(
    ninlil_bearer_send_result_t *result, uint64_t epoch)
{
    (void)memset(result, 0, sizeof(*result));
    result->abi_version = NINLIL_ABI_VERSION;
    result->struct_size = (uint16_t)sizeof(*result);
    result->availability_epoch = epoch;
}

static int send_result_pointer_is_valid(
    const ninlil_bearer_send_result_t *result)
{
    return result != NULL;
}

static int tx_permit_pointer_is_valid(const ninlil_tx_permit_t *permit)
{
    return permit != NULL && abi_header_is_valid(
        permit->abi_version, permit->struct_size, sizeof(*permit));
}

static int tx_request_is_valid(const ninlil_tx_request_t *request)
{
    return request != NULL
        && abi_header_is_valid(request->abi_version,
            request->struct_size, sizeof(*request))
        && !id_is_zero(&request->transaction_id)
        && !id_is_zero(&request->attempt_id)
        && request->message_kind >= NINLIL_BEARER_MESSAGE_APPLICATION
        && request->message_kind <= NINLIL_BEARER_MESSAGE_CANCEL_RESULT
        && request->logical_bytes > 0u
        && request->content_digest.algorithm == NINLIL_DIGEST_SHA256
        && request->content_digest.reserved_zero == 0u;
}

static int time_sample_is_valid(const ninlil_time_sample_t *now)
{
    return now != NULL
        && abi_header_is_valid(now->abi_version, now->struct_size, sizeof(*now))
        && !id_is_zero(&now->clock_epoch_id)
        && (now->trust == NINLIL_CLOCK_TRUSTED
            || now->trust == NINLIL_CLOCK_UNCERTAIN)
        && now->reserved_zero == 0u;
}

static void calculate_request_digest(
    const ninlil_tx_request_t *request, ninlil_digest256_t *out)
{
    static const uint8_t label[] = "ninlil-tx-request-v1";
    uint8_t scalar[4];
    uint8_t algorithm[2];
    sha256_context_t context;
    sha256_init(&context);
    sha256_update(&context, label, sizeof(label) - 1u);
    sha256_update(&context, request->transaction_id.bytes, 16u);
    sha256_update(&context, request->attempt_id.bytes, 16u);
    store_be32(scalar, request->message_kind);
    sha256_update(&context, scalar, sizeof(scalar));
    store_be32(scalar, request->logical_bytes);
    sha256_update(&context, scalar, sizeof(scalar));
    algorithm[0] = (uint8_t)(request->content_digest.algorithm >> 8u);
    algorithm[1] = (uint8_t)request->content_digest.algorithm;
    sha256_update(&context, algorithm, sizeof(algorithm));
    sha256_update(&context, request->content_digest.bytes, 32u);
    out->algorithm = NINLIL_DIGEST_SHA256;
    out->reserved_zero = 0u;
    sha256_final(&context, out->bytes);
}

static void calculate_permit_id(
    const ninlil_test_bearer_t *bearer,
    const ninlil_tx_request_t *request,
    const ninlil_digest256_t *request_digest,
    const ninlil_id128_t *clock_epoch_id,
    uint64_t expires_at_ms,
    uint64_t sequence,
    ninlil_id128_t *out)
{
    static const uint8_t label[] = "ninlil-virtual-permit-v1";
    uint8_t scalar[8];
    uint8_t digest[32];
    sha256_context_t context;
    sha256_init(&context);
    sha256_update(&context, label, sizeof(label) - 1u);
    sha256_update(&context, bearer->config.permit_issuer_id.bytes, 16u);
    sha256_update(&context, request->attempt_id.bytes, 16u);
    sha256_update(&context, request_digest->bytes, 32u);
    sha256_update(&context, clock_epoch_id->bytes, 16u);
    store_be64(scalar, expires_at_ms);
    sha256_update(&context, scalar, sizeof(scalar));
    store_be64(scalar, sequence);
    sha256_update(&context, scalar, sizeof(scalar));
    sha256_final(&context, digest);
    (void)memcpy(out->bytes, digest, 16u);
}

static permit_record_t *find_permit_record(
    ninlil_test_bearer_t *bearer, const ninlil_tx_permit_t *permit)
{
    uint32_t index;
    if (!tx_permit_pointer_is_valid(permit)) {
        return NULL;
    }
    for (index = 0u; index < bearer->config.max_permits; ++index) {
        permit_record_t *record = &bearer->permits[index];
        if (!id_is_zero(&record->permit.permit_id)
            && id_equal(&record->permit.permit_id, &permit->permit_id)) {
            return record;
        }
    }
    return NULL;
}

static int public_permit_equal(
    const ninlil_tx_permit_t *left, const ninlil_tx_permit_t *right)
{
    return left->abi_version == right->abi_version
        && left->struct_size == right->struct_size
        && id_equal(&left->permit_id, &right->permit_id)
        && id_equal(&left->attempt_id, &right->attempt_id)
        && id_equal(&left->clock_epoch_id, &right->clock_epoch_id)
        && left->expires_at_ms == right->expires_at_ms;
}

static int validate_permit_for_message(
    ninlil_test_bearer_t *bearer,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    uint64_t logical_bytes,
    permit_record_t **out_record)
{
    permit_record_t *record = find_permit_record(bearer, permit);
    *out_record = NULL;
    if (record == NULL || record->state != PERMIT_LIVE
        || !public_permit_equal(&record->permit, permit)
        || !id_equal(&record->transaction_id, &message->transaction_id)
        || !id_equal(&record->permit.attempt_id, &message->attempt_id)
        || record->message_kind != message->kind
        || record->logical_bytes != logical_bytes
        || !digest_equal(&record->content_digest, &message->content_digest)
        || !id_equal(&record->permit.clock_epoch_id,
            &bearer->current_clock_epoch_id)
        || bearer->current_time_ms >= record->permit.expires_at_ms) {
        if (record != NULL && record->state == PERMIT_LIVE
            && bearer->current_time_ms >= record->permit.expires_at_ms) {
            record->state = PERMIT_EXPIRED;
            if (bearer->permit_live_count > 0u) {
                bearer->permit_live_count -= 1u;
            }
            bearer->permit_expired_count += 1u;
        }
        return 0;
    }
    *out_record = record;
    return 1;
}

static int raw_open_pop(ninlil_test_bearer_t *bearer, raw_open_entry_t *out)
{
    raw_open_entry_t *entry;
    if (bearer->raw_open.count == 0u) {
        return 0;
    }
    entry = &bearer->raw_open.entries[bearer->raw_open.head];
    *out = *entry;
    entry->remaining -= 1u;
    if (entry->remaining == 0u) {
        bearer->raw_open.head = (bearer->raw_open.head + 1u)
            % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
        bearer->raw_open.count -= 1u;
    }
    return 1;
}

static int raw_send_pop(ninlil_test_bearer_t *bearer, raw_send_entry_t *out)
{
    raw_send_entry_t *entry;
    if (bearer->raw_send.count == 0u) {
        return 0;
    }
    entry = &bearer->raw_send.entries[bearer->raw_send.head];
    *out = *entry;
    entry->remaining -= 1u;
    if (entry->remaining == 0u) {
        bearer->raw_send.head = (bearer->raw_send.head + 1u)
            % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
        bearer->raw_send.count -= 1u;
    }
    return 1;
}

static int raw_receive_pop(
    ninlil_test_bearer_t *bearer, raw_receive_entry_t *out)
{
    raw_receive_entry_t *entry;
    if (bearer->raw_receive.count == 0u) {
        return 0;
    }
    entry = &bearer->raw_receive.entries[bearer->raw_receive.head];
    *out = *entry;
    entry->remaining -= 1u;
    if (entry->remaining == 0u) {
        entry->prototype = NULL;
        bearer->raw_receive.head = (bearer->raw_receive.head + 1u)
            % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
        bearer->raw_receive.count -= 1u;
    }
    return 1;
}

static int raw_state_pop(ninlil_test_bearer_t *bearer, raw_state_entry_t *out)
{
    raw_state_entry_t *entry;
    if (bearer->raw_state.count == 0u) {
        return 0;
    }
    entry = &bearer->raw_state.entries[bearer->raw_state.head];
    *out = *entry;
    entry->remaining -= 1u;
    if (entry->remaining == 0u) {
        bearer->raw_state.head = (bearer->raw_state.head + 1u)
            % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
        bearer->raw_state.count -= 1u;
    }
    return 1;
}

static void update_peer_transition(
    ninlil_test_bearer_t *bearer,
    size_t changed_endpoint,
    int old_available)
{
    size_t peer_lane = 1u - changed_endpoint;
    bearer_direction_t *direction = &bearer->directions[peer_lane];
    if (!bearer->endpoints[peer_lane].bound || direction->fatal) {
        return;
    }
    if (old_available != path_available(bearer, peer_lane)) {
        (void)increment_availability(bearer, peer_lane);
    }
}

static ninlil_bearer_status_t fixture_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    raw_open_entry_t raw;
    bearer_handle_t *handle;
    int endpoint_index;
    int was_unpaired;
    int peer_old_available = 0;
    int new_binding = 0;
    uint32_t raw_consumed = 0u;
    if (bearer == NULL || out_handle == NULL || runtime_id == NULL) {
        if (bearer != NULL) {
            record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
                NINLIL_BEARER_DENIED, 0u, NULL, NULL, NULL,
                0u, 2u, 0u, 0u);
        }
        return NINLIL_BEARER_DENIED;
    }
    *out_handle = NULL;
    if (id_is_zero(runtime_id)
        || (role != NINLIL_ROLE_CONTROLLER && role != NINLIL_ROLE_ENDPOINT)) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
            NINLIL_BEARER_DENIED, 0u, NULL, NULL, NULL,
            0u, 2u, 0u, 0u);
        return NINLIL_BEARER_DENIED;
    }
    endpoint_index = find_endpoint(bearer, runtime_id);
    if (endpoint_index >= 0) {
        bearer_endpoint_t *endpoint = &bearer->endpoints[endpoint_index];
        if (endpoint->role != role) {
            record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
                NINLIL_BEARER_DENIED, 0u, NULL, NULL, NULL,
                0u, 2u, 0u, 0u);
            return NINLIL_BEARER_DENIED;
        }
        if (endpoint->active) {
            record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
                NINLIL_BEARER_WOULD_BLOCK, 0u, NULL, NULL, NULL,
                0u, (size_t)endpoint_index, 0u, 0u);
            return NINLIL_BEARER_WOULD_BLOCK;
        }
    } else {
        endpoint_index = free_endpoint_slot(bearer);
        if (endpoint_index < 0) {
            record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
                NINLIL_BEARER_DENIED, 0u, NULL, NULL, NULL,
                0u, 2u, 0u, 0u);
            return NINLIL_BEARER_DENIED;
        }
        new_binding = 1;
    }
    if (new_binding && bearer->endpoints[1 - endpoint_index].bound
        && (bearer->directions[0].availability_epoch == UINT64_MAX
            || bearer->directions[1].availability_epoch == UINT64_MAX)) {
        bearer->directions[0].fatal = 1;
        bearer->directions[1].fatal = 1;
        record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
            NINLIL_BEARER_CORRUPT, 0u, NULL, NULL, NULL,
            0u, (size_t)endpoint_index, 0u, 0u);
        return NINLIL_BEARER_CORRUPT;
    }
    if (raw_open_pop(bearer, &raw)) {
        raw_consumed = 1u;
        if (raw.status == NINLIL_BEARER_OK && raw.return_handle) {
            /* Valid raw OK follows the natural binding/lane transition. */
        } else {
            if (raw.return_handle) {
                handle = allocate_handle(bearer, 2u, 1);
                if (handle != NULL) {
                    handle->cleanup_only = 1;
                    *out_handle = (ninlil_bearer_handle_t)handle;
                }
            }
            record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
                raw.status, 0u, (bearer_handle_t *)*out_handle, NULL, NULL,
                0u, (size_t)endpoint_index, 1u, 0u);
            return raw.status;
        }
    }
    handle = allocate_handle(bearer, (size_t)endpoint_index, 1);
    if (handle == NULL) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
            NINLIL_BEARER_WOULD_BLOCK, 0u, NULL, NULL, NULL,
            0u, (size_t)endpoint_index, 0u, 0u);
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    was_unpaired = !(bearer->endpoints[0].bound && bearer->endpoints[1].bound);
    if (!was_unpaired) {
        peer_old_available = path_available(bearer,
            1u - (size_t)endpoint_index);
    }
    if (!bearer->endpoints[endpoint_index].bound) {
        bearer->endpoints[endpoint_index].bound = 1;
        bearer->endpoints[endpoint_index].runtime_id = *runtime_id;
        bearer->endpoints[endpoint_index].role = role;
    }
    bearer->endpoints[endpoint_index].active = 1;
    bearer->endpoints[endpoint_index].active_handle = handle;
    if (was_unpaired && bearer->endpoints[0].bound
        && bearer->endpoints[1].bound) {
        (void)increment_availability(bearer, 0u);
        (void)increment_availability(bearer, 1u);
    } else if (!was_unpaired) {
        update_peer_transition(bearer, (size_t)endpoint_index,
            peer_old_available);
        if (path_available(bearer, (size_t)endpoint_index)
            && bearer->directions[endpoint_index].fatal == 0) {
            /* Local/source reopen changes its lane only if peer state differs. */
        }
    }
    *out_handle = (ninlil_bearer_handle_t)handle;
    record_trace(bearer, NINLIL_TEST_BEARER_OP_OPEN,
        NINLIL_BEARER_OK, 0u, handle, NULL, NULL,
        0u, (size_t)endpoint_index, raw_consumed, 0u);
    return NINLIL_BEARER_OK;
}

static void fixture_close(void *user, ninlil_bearer_handle_t opaque_handle)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    bearer_handle_t *handle = (bearer_handle_t *)opaque_handle;
    uint32_t violation = 0u;
    int peer_old_available;
    if (bearer == NULL) {
        return;
    }
    handle = find_known_handle(bearer, handle);
    if (handle != NULL && handle->owner == bearer && handle->live
        && handle->cleanup_only) {
        handle->live = 0;
        bearer->live_handles -= 1u;
        bearer->tombstoned_handles += 1u;
        record_trace(bearer, NINLIL_TEST_BEARER_OP_CLOSE,
            0u, 0u, handle, NULL, NULL, 0u, 2u, 0u, 0u);
        return;
    }
    if (handle == NULL || !handle_is_live(bearer, handle)) {
        note_violation(bearer);
        violation = 1u;
        record_trace(bearer, NINLIL_TEST_BEARER_OP_CLOSE,
            0u, 0u, handle, NULL, NULL, 0u, 2u, 0u, violation);
        return;
    }
    if (handle->loan != NULL) {
        handle->loan->next = bearer->orphan_loans;
        bearer->orphan_loans = handle->loan;
        bearer->orphan_loan_count += 1u;
        bearer->orphan_loan_bytes += handle->loan->logical_bytes;
        if (bearer->live_loan_count > 0u) {
            bearer->live_loan_count -= 1u;
        }
        if (bearer->live_loan_bytes >= handle->loan->logical_bytes) {
            bearer->live_loan_bytes -= handle->loan->logical_bytes;
        }
        handle->loan = NULL;
        handle->loan_object = NULL;
        note_violation(bearer);
        violation = 1u;
    }
    peer_old_available = path_available(bearer,
        1u - handle->endpoint_index);
    bearer->endpoints[handle->endpoint_index].active = 0;
    bearer->endpoints[handle->endpoint_index].active_handle = NULL;
    handle->live = 0;
    if (bearer->live_handles > 0u) {
        bearer->live_handles -= 1u;
    }
    bearer->tombstoned_handles += 1u;
    update_peer_transition(bearer, handle->endpoint_index,
        peer_old_available);
    record_trace(bearer, NINLIL_TEST_BEARER_OP_CLOSE,
        0u, 0u, handle, NULL, NULL, 0u,
        handle->endpoint_index, 0u, violation);
}

static void enqueue_copy(
    bearer_direction_t *direction, bearer_message_copy_t *copy)
{
    copy->next = NULL;
    if (direction->tail == NULL) {
        direction->head = copy;
    } else {
        direction->tail->next = copy;
    }
    direction->tail = copy;
    direction->queued_entries += 1u;
    direction->queued_bytes += copy->logical_bytes;
}

static void mark_permit_consumed(
    ninlil_test_bearer_t *bearer, permit_record_t *record)
{
    record->state = PERMIT_CONSUMED;
    if (bearer->permit_live_count > 0u) {
        bearer->permit_live_count -= 1u;
    }
    bearer->permit_consumed_count += 1u;
}

static void mark_permit_fenced(
    ninlil_test_bearer_t *bearer, permit_record_t *record)
{
    record->state = PERMIT_FENCED;
    if (bearer->permit_live_count > 0u) {
        bearer->permit_live_count -= 1u;
    }
    bearer->permit_fenced_count += 1u;
}

static int raw_send_is_valid_accept(
    const raw_send_entry_t *raw, uint64_t current_epoch)
{
    return raw->status == NINLIL_BEARER_OK
        && raw->result.abi_version == NINLIL_ABI_VERSION
        && raw->result.struct_size >= sizeof(raw->result)
        && (raw->result.kind == NINLIL_BEARER_SEND_ACCEPTED
            || raw->result.kind == NINLIL_BEARER_SEND_DURABLE_CUSTODY)
        && raw->result.reserved_zero == 0u
        && raw->result.availability_epoch == current_epoch;
}

static int raw_send_is_definite_no_send(
    const raw_send_entry_t *raw, uint64_t current_epoch)
{
    return (raw->status == NINLIL_BEARER_WOULD_BLOCK
            || raw->status == NINLIL_BEARER_UNAVAILABLE
            || raw->status == NINLIL_BEARER_DENIED)
        && raw->result.abi_version == NINLIL_ABI_VERSION
        && raw->result.struct_size >= sizeof(raw->result)
        && raw->result.kind == 0u
        && raw->result.reserved_zero == 0u
        && raw->result.availability_epoch == current_epoch;
}

static ninlil_bearer_status_t fixture_send(
    void *user,
    ninlil_bearer_handle_t opaque_handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    bearer_handle_t *handle = (bearer_handle_t *)opaque_handle;
    bearer_direction_t *direction;
    permit_record_t *permit_record = NULL;
    bearer_message_copy_t *copy = NULL;
    raw_send_entry_t raw;
    uint64_t logical_bytes;
    size_t direction_index;
    size_t peer_index;
    uint64_t return_epoch;
    int last_alloc_failure = 0;
    if (bearer == NULL || !handle_is_live(bearer, handle)
        || !send_result_pointer_is_valid(out_result)) {
        if (bearer != NULL) {
            record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
                NINLIL_BEARER_CORRUPT, 0u, handle, NULL, message,
                0u, 2u, 0u, 0u);
        }
        return NINLIL_BEARER_CORRUPT;
    }
    direction_index = direction_for_source(handle->endpoint_index);
    peer_index = 1u - handle->endpoint_index;
    direction = &bearer->directions[direction_index];
    return_epoch = direction->availability_epoch;
    initialize_send_result(out_result, return_epoch);
    if (!ninlil_test_bearer_logical_bytes(message, &logical_bytes)) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
            NINLIL_BEARER_CORRUPT, 0u, handle, NULL, message,
            0u, direction_index, 0u, 0u);
        return NINLIL_BEARER_CORRUPT;
    }
    if (!validate_permit_for_message(bearer, permit, message,
            logical_bytes, &permit_record)) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
            NINLIL_BEARER_DENIED, 0u, handle, NULL, message,
            logical_bytes, direction_index, 0u, 0u);
        return NINLIL_BEARER_DENIED;
    }
    if (!bearer->endpoints[peer_index].bound
        || !id_equal(&bearer->endpoints[peer_index].runtime_id,
            &message->target.target_runtime_id)) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
            NINLIL_BEARER_DENIED, 0u, handle, NULL, message,
            logical_bytes, direction_index, 0u, 0u);
        return NINLIL_BEARER_DENIED;
    }
    if (!path_available(bearer, direction_index)) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
            NINLIL_BEARER_UNAVAILABLE, 0u, handle,
            &bearer->endpoints[peer_index].runtime_id, message,
            logical_bytes, direction_index, 0u, 0u);
        return NINLIL_BEARER_UNAVAILABLE;
    }
    if (direction->queued_entries >= bearer->config.max_entries_per_direction
        || logical_bytes > bearer->config.max_bytes_per_direction
            - direction->queued_bytes) {
        if (direction->blocked_entries == 0u
            || 1u < direction->blocked_entries) {
            direction->blocked_entries = 1u;
        }
        if (direction->blocked_bytes == 0u
            || logical_bytes < direction->blocked_bytes) {
            direction->blocked_bytes = logical_bytes;
        }
        record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
            NINLIL_BEARER_WOULD_BLOCK, 0u, handle,
            &bearer->endpoints[peer_index].runtime_id, message,
            logical_bytes, direction_index, 0u, 0u);
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    if (bearer->raw_send.count > 0u) {
        (void)raw_send_pop(bearer, &raw);
        *out_result = raw.result;
        if (raw_send_is_valid_accept(&raw, return_epoch)) {
            copy = clone_message(bearer, message, logical_bytes, 0);
            if (copy == NULL) {
                initialize_send_result(out_result, return_epoch);
                record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
                    NINLIL_BEARER_WOULD_BLOCK, 0u, handle,
                    &bearer->endpoints[peer_index].runtime_id, message,
                    logical_bytes, direction_index, 1u, 0u);
                return NINLIL_BEARER_WOULD_BLOCK;
            }
            enqueue_copy(direction, copy);
            mark_permit_consumed(bearer, permit_record);
        } else if (!raw_send_is_definite_no_send(&raw, return_epoch)) {
            mark_permit_fenced(bearer, permit_record);
        }
        record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
            raw.status, 0u, handle,
            &bearer->endpoints[peer_index].runtime_id, message,
            logical_bytes, direction_index, 1u, 0u);
        return raw.status;
    }
    if (bearer->fail_next_copy_allocations == 1u) {
        last_alloc_failure = 1;
    }
    copy = clone_message(bearer, message, logical_bytes, 1);
    if (copy == NULL) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
            NINLIL_BEARER_WOULD_BLOCK, 0u, handle,
            &bearer->endpoints[peer_index].runtime_id, message,
            logical_bytes, direction_index, 0u, 0u);
        if (last_alloc_failure) {
            (void)increment_availability(bearer, direction_index);
        }
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    enqueue_copy(direction, copy);
    mark_permit_consumed(bearer, permit_record);
    out_result->kind = NINLIL_BEARER_SEND_ACCEPTED;
    record_trace(bearer, NINLIL_TEST_BEARER_OP_SEND,
        NINLIL_BEARER_OK, 0u, handle,
        &bearer->endpoints[peer_index].runtime_id, message,
        logical_bytes, direction_index, 0u, 0u);
    return NINLIL_BEARER_OK;
}

static ninlil_bearer_status_t fixture_receive_next(
    void *user,
    ninlil_bearer_handle_t opaque_handle,
    ninlil_bearer_message_t *out_message)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    bearer_handle_t *handle = (bearer_handle_t *)opaque_handle;
    raw_receive_entry_t raw;
    bearer_message_copy_t *copy;
    size_t incoming_direction;
    if (bearer == NULL || !handle_is_live(bearer, handle)
        || out_message == NULL) {
        if (bearer != NULL) {
            record_trace(bearer, NINLIL_TEST_BEARER_OP_RECEIVE,
                NINLIL_BEARER_CORRUPT, 0u, handle, NULL, NULL,
                0u, 2u, 0u, 0u);
        }
        return NINLIL_BEARER_CORRUPT;
    }
    (void)memset(out_message, 0, sizeof(*out_message));
    incoming_direction = 1u - handle->endpoint_index;
    if (handle->loan != NULL) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_RECEIVE,
            NINLIL_BEARER_WOULD_BLOCK, 0u, handle, NULL, NULL,
            0u, incoming_direction, 0u, 0u);
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    if (bearer->raw_receive.count > 0u) {
        raw_receive_entry_t *peek =
            &bearer->raw_receive.entries[bearer->raw_receive.head];
        copy = NULL;
        if (peek->status == NINLIL_BEARER_OK) {
            if (peek->prototype == NULL) {
                copy = (bearer_message_copy_t *)calloc(1u, sizeof(*copy));
            } else if (peek->exact_unsafe) {
                copy = (bearer_message_copy_t *)calloc(1u, sizeof(*copy));
                if (copy != NULL) {
                    copy->message = peek->prototype->message;
                }
            } else {
                copy = clone_message(bearer, &peek->prototype->message,
                    peek->prototype->logical_bytes, 0);
            }
            if (copy == NULL) {
                record_trace(bearer, NINLIL_TEST_BEARER_OP_RECEIVE,
                    NINLIL_BEARER_WOULD_BLOCK, 0u, handle, NULL, NULL,
                    0u, incoming_direction, 0u, 0u);
                return NINLIL_BEARER_WOULD_BLOCK;
            }
        }
        (void)raw_receive_pop(bearer, &raw);
        if (raw.status == NINLIL_BEARER_OK) {
            *out_message = copy->message;
            handle->loan = copy;
            handle->loan_object = out_message;
            bearer->live_loan_count += 1u;
            bearer->live_loan_bytes += copy->logical_bytes;
        } else if (raw.prototype != NULL) {
            *out_message = raw.prototype->message;
        }
        record_trace(bearer, NINLIL_TEST_BEARER_OP_RECEIVE,
            raw.status, 0u, handle, NULL,
            raw.prototype == NULL ? NULL : &raw.prototype->message,
            raw.prototype == NULL ? 0u : raw.prototype->logical_bytes,
            incoming_direction, 1u, 0u);
        if (raw.remaining == 1u && raw.prototype != NULL) {
            raw.prototype->next = bearer->raw_retired;
            bearer->raw_retired = raw.prototype;
        }
        return raw.status;
    }
    copy = bearer->directions[incoming_direction].head;
    if (copy == NULL) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_RECEIVE,
            NINLIL_BEARER_EMPTY, 0u, handle, NULL, NULL,
            0u, incoming_direction, 0u, 0u);
        return NINLIL_BEARER_EMPTY;
    }
    bearer->directions[incoming_direction].head = copy->next;
    if (bearer->directions[incoming_direction].head == NULL) {
        bearer->directions[incoming_direction].tail = NULL;
    }
    bearer->directions[incoming_direction].queued_entries -= 1u;
    bearer->directions[incoming_direction].queued_bytes -= copy->logical_bytes;
    copy->next = NULL;
    *out_message = copy->message;
    handle->loan = copy;
    handle->loan_object = out_message;
    bearer->live_loan_count += 1u;
    bearer->live_loan_bytes += copy->logical_bytes;
    maybe_record_block_improvement(bearer, incoming_direction);
    record_trace(bearer, NINLIL_TEST_BEARER_OP_RECEIVE,
        NINLIL_BEARER_OK, 0u, handle, NULL, &copy->message,
        copy->logical_bytes, incoming_direction, 0u, 0u);
    return NINLIL_BEARER_OK;
}

static void fixture_release_received(
    void *user,
    ninlil_bearer_handle_t opaque_handle,
    ninlil_bearer_message_t *message)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    bearer_handle_t *handle = (bearer_handle_t *)opaque_handle;
    bearer_message_copy_t *loan;
    uint32_t violation = 0u;
    if (bearer == NULL) {
        return;
    }
    if (!handle_is_live(bearer, handle) || handle->loan == NULL
        || handle->loan_object != message) {
        note_violation(bearer);
        violation = 1u;
        record_trace(bearer, NINLIL_TEST_BEARER_OP_RELEASE,
            0u, 0u, handle, NULL, NULL, 0u, 2u, 0u, violation);
        return;
    }
    loan = handle->loan;
    handle->loan = NULL;
    handle->loan_object = NULL;
    bearer->live_loan_count -= 1u;
    bearer->live_loan_bytes -= loan->logical_bytes;
    (void)memset(message, 0, sizeof(*message));
    record_trace(bearer, NINLIL_TEST_BEARER_OP_RELEASE,
        0u, 0u, handle, NULL, &loan->message, loan->logical_bytes,
        2u, 0u, 0u);
    free_message_copy(loan);
}

static ninlil_bearer_status_t fixture_state(
    void *user,
    ninlil_bearer_handle_t opaque_handle,
    ninlil_bearer_state_t *out_state)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    bearer_handle_t *handle = (bearer_handle_t *)opaque_handle;
    raw_state_entry_t raw;
    size_t direction_index;
    if (bearer == NULL || !handle_is_live(bearer, handle)
        || out_state == NULL) {
        if (bearer != NULL) {
            record_trace(bearer, NINLIL_TEST_BEARER_OP_STATE,
                NINLIL_BEARER_CORRUPT, 0u, handle, NULL, NULL,
                0u, 2u, 0u, 0u);
        }
        return NINLIL_BEARER_CORRUPT;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    direction_index = handle->endpoint_index;
    if (bearer->raw_state.count > 0u) {
        (void)raw_state_pop(bearer, &raw);
        *out_state = raw.state;
        record_trace(bearer, NINLIL_TEST_BEARER_OP_STATE,
            raw.status, 0u, handle, NULL, NULL, 0u,
            direction_index, 1u, 0u);
        return raw.status;
    }
    if (bearer->directions[direction_index].fatal) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_STATE,
            NINLIL_BEARER_CORRUPT, 0u, handle, NULL, NULL, 0u,
            direction_index, 0u, 0u);
        return NINLIL_BEARER_CORRUPT;
    }
    if (!bearer->endpoints[1u - handle->endpoint_index].bound) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_STATE,
            NINLIL_BEARER_OK, 0u, handle, NULL, NULL, 0u,
            direction_index, 0u, 0u);
        out_state->abi_version = NINLIL_ABI_VERSION;
        out_state->struct_size = (uint16_t)sizeof(*out_state);
        out_state->availability_epoch =
            bearer->directions[direction_index].availability_epoch;
        out_state->available = 0u;
        return NINLIL_BEARER_OK;
    }
    out_state->abi_version = NINLIL_ABI_VERSION;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->availability_epoch =
        bearer->directions[direction_index].availability_epoch;
    out_state->available = path_available(bearer, direction_index) ? 1u : 0u;
    record_trace(bearer, NINLIL_TEST_BEARER_OP_STATE,
        NINLIL_BEARER_OK, 0u, handle, NULL, NULL, 0u,
        direction_index, 0u, 0u);
    return NINLIL_BEARER_OK;
}

static ninlil_tx_gate_status_t fixture_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    permit_record_t *record = NULL;
    ninlil_digest256_t request_digest;
    uint64_t sequence;
    uint64_t expires;
    uint32_t index;
    if (bearer == NULL || out_permit == NULL) {
        return NINLIL_TX_GATE_DENIED;
    }
    (void)memset(out_permit, 0, sizeof(*out_permit));
    if (!tx_request_is_valid(request) || !time_sample_is_valid(now)
        || !id_equal(&now->clock_epoch_id, &bearer->current_clock_epoch_id)
        || now->now_ms != bearer->current_time_ms
        || now->trust != NINLIL_CLOCK_TRUSTED
        || UINT64_MAX - now->now_ms < 1000u
        || bearer->next_permit_sequence == UINT64_MAX) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_TX_ACQUIRE,
            0u, NINLIL_TX_GATE_DENIED, NULL, NULL, NULL,
            0u, 2u, 0u, 0u);
        return NINLIL_TX_GATE_DENIED;
    }
    for (index = 0u; index < bearer->config.max_permits; ++index) {
        if (id_is_zero(&bearer->permits[index].permit.permit_id)
            || bearer->permits[index].state != PERMIT_LIVE) {
            record = &bearer->permits[index];
            break;
        }
    }
    if (record == NULL) {
        record_trace(bearer, NINLIL_TEST_BEARER_OP_TX_ACQUIRE,
            0u, NINLIL_TX_GATE_TEMPORARY, NULL, NULL, NULL,
            0u, 2u, 0u, 0u);
        return NINLIL_TX_GATE_TEMPORARY;
    }
    sequence = bearer->next_permit_sequence;
    bearer->next_permit_sequence += 1u;
    expires = now->now_ms + 1000u;
    calculate_request_digest(request, &request_digest);
    (void)memset(record, 0, sizeof(*record));
    record->permit.abi_version = NINLIL_ABI_VERSION;
    record->permit.struct_size = (uint16_t)sizeof(record->permit);
    calculate_permit_id(bearer, request, &request_digest,
        &now->clock_epoch_id, expires, sequence, &record->permit.permit_id);
    record->permit.attempt_id = request->attempt_id;
    record->permit.clock_epoch_id = now->clock_epoch_id;
    record->permit.expires_at_ms = expires;
    record->transaction_id = request->transaction_id;
    record->message_kind = request->message_kind;
    record->logical_bytes = request->logical_bytes;
    record->content_digest = request->content_digest;
    record->request_digest = request_digest;
    record->state = PERMIT_LIVE;
    bearer->permit_live_count += 1u;
    *out_permit = record->permit;
    record_trace(bearer, NINLIL_TEST_BEARER_OP_TX_ACQUIRE,
        0u, NINLIL_TX_GATE_OK, NULL, NULL, NULL,
        request->logical_bytes, 2u, 0u, 0u);
    return NINLIL_TX_GATE_OK;
}

static void fixture_tx_release_unused(
    void *user, const ninlil_tx_permit_t *permit)
{
    ninlil_test_bearer_t *bearer = (ninlil_test_bearer_t *)user;
    permit_record_t *record;
    uint32_t violation = 0u;
    if (bearer == NULL) {
        return;
    }
    record = find_permit_record(bearer, permit);
    if (record == NULL || record->state != PERMIT_LIVE
        || !public_permit_equal(&record->permit, permit)) {
        note_violation(bearer);
        violation = 1u;
    } else {
        record->state = PERMIT_RELEASED;
        bearer->permit_live_count -= 1u;
        bearer->permit_released_count += 1u;
    }
    record_trace(bearer, NINLIL_TEST_BEARER_OP_TX_RELEASE,
        0u, 0u, NULL, NULL, NULL, 0u, 2u, 0u, violation);
}

ninlil_test_bearer_t *ninlil_test_bearer_create(
    const ninlil_test_bearer_config_t *input_config)
{
    ninlil_test_bearer_t *bearer;
    ninlil_test_bearer_config_t config;
    if (input_config == NULL) {
        return NULL;
    }
    config = *input_config;
    if (config.reserved_zero != 0u
        || id_is_zero(&config.permit_issuer_id)
        || id_is_zero(&config.initial_clock_epoch_id)
        || config.max_entries_per_direction == UINT64_MAX
        || config.max_bytes_per_direction == UINT64_MAX) {
        return NULL;
    }
    if (config.max_entries_per_direction == 0u) {
        config.max_entries_per_direction =
            NINLIL_TEST_BEARER_DEFAULT_QUEUE_ENTRIES;
    }
    if (config.max_bytes_per_direction == 0u) {
        config.max_bytes_per_direction =
            NINLIL_TEST_BEARER_DEFAULT_QUEUE_BYTES;
    }
    if (config.max_permits == 0u) {
        config.max_permits = NINLIL_TEST_BEARER_DEFAULT_MAX_PERMITS;
    }
#if SIZE_MAX <= UINT32_MAX
    if (config.max_permits
        > (uint32_t)(SIZE_MAX / sizeof(permit_record_t))) {
        return NULL;
    }
#endif
    bearer = (ninlil_test_bearer_t *)calloc(1u, sizeof(*bearer));
    if (bearer == NULL) {
        return NULL;
    }
    bearer->permits = (permit_record_t *)calloc(
        config.max_permits, sizeof(*bearer->permits));
    if (bearer->permits == NULL) {
        free(bearer);
        return NULL;
    }
    bearer->config = config;
    bearer->current_clock_epoch_id = config.initial_clock_epoch_id;
    bearer->current_time_ms = config.initial_time_ms;
    bearer->next_handle_id = 1u;
    bearer->next_permit_sequence = 1u;
    bearer->next_trace_sequence = 1u;
    bearer->directions[0].availability_epoch = 1u;
    bearer->directions[1].availability_epoch = 1u;
    bearer->directions[0].path_up = 1;
    bearer->directions[1].path_up = 1;
    bearer->bearer_ops.abi_version = NINLIL_ABI_VERSION;
    bearer->bearer_ops.struct_size = (uint16_t)sizeof(bearer->bearer_ops);
    bearer->bearer_ops.user = bearer;
    bearer->bearer_ops.open = fixture_open;
    bearer->bearer_ops.close = fixture_close;
    bearer->bearer_ops.send = fixture_send;
    bearer->bearer_ops.receive_next = fixture_receive_next;
    bearer->bearer_ops.release_received = fixture_release_received;
    bearer->bearer_ops.state = fixture_state;
    bearer->tx_gate_ops.abi_version = NINLIL_ABI_VERSION;
    bearer->tx_gate_ops.struct_size = (uint16_t)sizeof(bearer->tx_gate_ops);
    bearer->tx_gate_ops.user = bearer;
    bearer->tx_gate_ops.acquire = fixture_tx_acquire;
    bearer->tx_gate_ops.release_unused = fixture_tx_release_unused;
    return bearer;
}

void ninlil_test_bearer_destroy(ninlil_test_bearer_t *bearer)
{
    bearer_handle_t *handle;
    bearer_message_copy_t *copy;
    size_t direction_index;
    size_t raw_index;
    if (bearer == NULL) {
        return;
    }
    for (direction_index = 0u; direction_index < 2u; ++direction_index) {
        copy = bearer->directions[direction_index].head;
        while (copy != NULL) {
            bearer_message_copy_t *next = copy->next;
            free_message_copy(copy);
            copy = next;
        }
    }
    copy = bearer->orphan_loans;
    while (copy != NULL) {
        bearer_message_copy_t *next = copy->next;
        free_message_copy(copy);
        copy = next;
    }
    copy = bearer->raw_retired;
    while (copy != NULL) {
        bearer_message_copy_t *next = copy->next;
        free_message_copy(copy);
        copy = next;
    }
    for (handle = bearer->handles; handle != NULL;) {
        bearer_handle_t *next = handle->next;
        if (handle->loan != NULL) {
            free_message_copy(handle->loan);
        }
        free(handle);
        handle = next;
    }
    for (raw_index = 0u; raw_index < bearer->raw_receive.count; ++raw_index) {
        size_t index = (bearer->raw_receive.head + raw_index)
            % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
        free_message_copy(bearer->raw_receive.entries[index].prototype);
    }
    free(bearer->permits);
    free(bearer);
}

const ninlil_bearer_ops_t *ninlil_test_bearer_ops(
    ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? NULL : &bearer->bearer_ops;
}

const ninlil_tx_gate_ops_t *ninlil_test_bearer_tx_gate_ops(
    ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? NULL : &bearer->tx_gate_ops;
}

int ninlil_test_bearer_set_time(
    ninlil_test_bearer_t *bearer,
    ninlil_id128_t clock_epoch_id,
    uint64_t now_ms)
{
    if (bearer == NULL || id_is_zero(&clock_epoch_id)) {
        return 0;
    }
    if (id_equal(&clock_epoch_id, &bearer->current_clock_epoch_id)
        && now_ms < bearer->current_time_ms) {
        return 0;
    }
    bearer->current_clock_epoch_id = clock_epoch_id;
    bearer->current_time_ms = now_ms;
    return 1;
}

int ninlil_test_bearer_set_path_up(
    ninlil_test_bearer_t *bearer,
    const ninlil_id128_t *from_runtime_id,
    int up)
{
    int endpoint_index;
    bearer_direction_t *direction;
    int normalized;
    if (bearer == NULL || from_runtime_id == NULL || (up != 0 && up != 1)) {
        return 0;
    }
    endpoint_index = find_endpoint(bearer, from_runtime_id);
    if (endpoint_index < 0) {
        return 0;
    }
    direction = &bearer->directions[endpoint_index];
    normalized = up != 0;
    if (direction->path_up == normalized) {
        return 1;
    }
    if (!increment_availability(bearer, (size_t)endpoint_index)) {
        return 0;
    }
    direction->path_up = normalized;
    return 1;
}

int ninlil_test_bearer_set_path_epoch_for_test(
    ninlil_test_bearer_t *bearer,
    const ninlil_id128_t *from_runtime_id,
    uint64_t epoch)
{
    int endpoint_index;
    if (bearer == NULL || from_runtime_id == NULL || epoch == 0u) {
        return 0;
    }
    endpoint_index = find_endpoint(bearer, from_runtime_id);
    if (endpoint_index < 0) {
        return 0;
    }
    bearer->directions[endpoint_index].availability_epoch = epoch;
    bearer->directions[endpoint_index].fatal = 0;
    return 1;
}

int ninlil_test_bearer_fail_next_copy_allocations(
    ninlil_test_bearer_t *bearer, uint32_t count)
{
    if (bearer == NULL || count == 0u
        || UINT32_MAX - bearer->fail_next_copy_allocations < count) {
        return 0;
    }
    bearer->fail_next_copy_allocations += count;
    return 1;
}

int ninlil_test_bearer_raw_open_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    int return_handle,
    uint32_t count)
{
    size_t index;
    raw_open_entry_t *entry;
    if (bearer == NULL || count == 0u
        || (return_handle != 0 && return_handle != 1)
        || bearer->raw_open.count >= NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY) {
        return 0;
    }
    index = (bearer->raw_open.head + bearer->raw_open.count)
        % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
    entry = &bearer->raw_open.entries[index];
    entry->status = status;
    entry->return_handle = return_handle;
    entry->remaining = count;
    bearer->raw_open.count += 1u;
    return 1;
}

int ninlil_test_bearer_raw_send_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    const ninlil_bearer_send_result_t *result,
    uint32_t count)
{
    size_t index;
    raw_send_entry_t *entry;
    if (bearer == NULL || result == NULL || count == 0u
        || bearer->raw_send.count >= NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY) {
        return 0;
    }
    index = (bearer->raw_send.head + bearer->raw_send.count)
        % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
    entry = &bearer->raw_send.entries[index];
    entry->status = status;
    entry->result = *result;
    entry->remaining = count;
    bearer->raw_send.count += 1u;
    return 1;
}

int ninlil_test_bearer_raw_receive_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    const ninlil_bearer_message_t *message,
    uint32_t count)
{
    size_t index;
    raw_receive_entry_t *entry;
    bearer_message_copy_t *prototype = NULL;
    uint64_t logical_bytes = 0u;
    int safe;
    if (bearer == NULL || count == 0u
        || bearer->raw_receive.count
            >= NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY) {
        return 0;
    }
    safe = message != NULL
        && ninlil_test_bearer_logical_bytes(message, &logical_bytes);
    if (message != NULL) {
        if (safe) {
            prototype = clone_message(bearer, message, logical_bytes, 0);
        } else {
            prototype = (bearer_message_copy_t *)calloc(1u, sizeof(*prototype));
            if (prototype != NULL) {
                prototype->message = *message;
            }
        }
        if (prototype == NULL) {
            return 0;
        }
    }
    index = (bearer->raw_receive.head + bearer->raw_receive.count)
        % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
    entry = &bearer->raw_receive.entries[index];
    entry->status = status;
    entry->remaining = count;
    entry->prototype = prototype;
    entry->exact_unsafe = message != NULL && !safe;
    bearer->raw_receive.count += 1u;
    return 1;
}

int ninlil_test_bearer_raw_state_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    const ninlil_bearer_state_t *state,
    uint32_t count)
{
    size_t index;
    raw_state_entry_t *entry;
    if (bearer == NULL || state == NULL || count == 0u
        || bearer->raw_state.count >= NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY) {
        return 0;
    }
    index = (bearer->raw_state.head + bearer->raw_state.count)
        % NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY;
    entry = &bearer->raw_state.entries[index];
    entry->status = status;
    entry->state = *state;
    entry->remaining = count;
    bearer->raw_state.count += 1u;
    return 1;
}

int ninlil_test_bearer_direction_accounting(
    const ninlil_test_bearer_t *bearer,
    const ninlil_id128_t *from_runtime_id,
    uint64_t *out_entries,
    uint64_t *out_bytes)
{
    int endpoint_index;
    if (bearer == NULL || from_runtime_id == NULL
        || out_entries == NULL || out_bytes == NULL) {
        return 0;
    }
    endpoint_index = find_endpoint(bearer, from_runtime_id);
    if (endpoint_index < 0) {
        return 0;
    }
    *out_entries = bearer->directions[endpoint_index].queued_entries;
    *out_bytes = bearer->directions[endpoint_index].queued_bytes;
    return 1;
}

uint64_t ninlil_test_bearer_live_loan_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->live_loan_count;
}

uint64_t ninlil_test_bearer_live_loan_bytes(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->live_loan_bytes;
}

uint64_t ninlil_test_bearer_orphan_loan_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->orphan_loan_count;
}

uint64_t ninlil_test_bearer_orphan_loan_bytes(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->orphan_loan_bytes;
}

uint64_t ninlil_test_bearer_live_handle_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->live_handles;
}

uint64_t ninlil_test_bearer_tombstoned_handle_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->tombstoned_handles;
}

uint64_t ninlil_test_bearer_violation_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->violation_count;
}

uint64_t ninlil_test_bearer_call_count(
    const ninlil_test_bearer_t *bearer,
    ninlil_test_bearer_operation_t operation)
{
    if (bearer == NULL || operation < NINLIL_TEST_BEARER_OP_OPEN
        || operation >= NINLIL_TEST_BEARER_OP_COUNT) {
        return 0u;
    }
    return bearer->call_counts[operation];
}

uint64_t ninlil_test_bearer_permit_live_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->permit_live_count;
}

uint64_t ninlil_test_bearer_permit_consumed_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->permit_consumed_count;
}

uint64_t ninlil_test_bearer_permit_released_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->permit_released_count;
}

uint64_t ninlil_test_bearer_permit_expired_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->permit_expired_count;
}

uint64_t ninlil_test_bearer_permit_fenced_count(
    const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->permit_fenced_count;
}

size_t ninlil_test_bearer_trace_count(const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0u : bearer->trace_count;
}

int ninlil_test_bearer_trace_overflowed(const ninlil_test_bearer_t *bearer)
{
    return bearer == NULL ? 0 : bearer->trace_overflowed;
}

const ninlil_test_bearer_trace_record_t *ninlil_test_bearer_trace_at(
    const ninlil_test_bearer_t *bearer, size_t index)
{
    if (bearer == NULL || index >= bearer->trace_count) {
        return NULL;
    }
    return &bearer->trace[index];
}
