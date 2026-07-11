#include "deterministic_entropy.h"

#include <stdlib.h>
#include <string.h>

typedef struct sha256_context {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_length;
} sha256_context_t;

typedef struct entropy_action {
    ninlil_test_entropy_action_kind_t kind;
    uint32_t partial_prefix_length;
    uint32_t remaining_count;
} entropy_action_t;

struct ninlil_test_entropy {
    ninlil_entropy_ops_t ops;
    uint64_t seed;
    uint32_t stream_id;
    uint64_t counter;
    int exhausted;
    entropy_action_t actions[NINLIL_TEST_ENTROPY_ACTION_CAPACITY];
    size_t action_head;
    size_t action_count;
    ninlil_test_entropy_trace_record_t
        trace[NINLIL_TEST_ENTROPY_TRACE_CAPACITY];
    size_t trace_count;
    uint64_t next_sequence;
    uint64_t call_count;
    uint64_t script_error_count;
    uint64_t invalid_call_count;
    uint64_t restart_count;
    int trace_overflowed;
};

static const uint32_t sha256_constants[64] = {
    UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf),
    UINT32_C(0xe9b5dba5), UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
    UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5), UINT32_C(0xd807aa98),
    UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7),
    UINT32_C(0xc19bf174), UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
    UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc), UINT32_C(0x2de92c6f),
    UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
    UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8),
    UINT32_C(0xbf597fc7), UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
    UINT32_C(0x06ca6351), UINT32_C(0x14292967), UINT32_C(0x27b70a85),
    UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
    UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e),
    UINT32_C(0x92722c85), UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
    UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3), UINT32_C(0xd192e819),
    UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c),
    UINT32_C(0x34b0bcb5), UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
    UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3), UINT32_C(0x748f82ee),
    UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7),
    UINT32_C(0xc67178f2)
};

static uint32_t rotate_right(uint32_t value, uint32_t count)
{
    return (value >> count) | (value << (32u - count));
}

static uint32_t load_u32_be(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24u)
        | ((uint32_t)bytes[1] << 16u)
        | ((uint32_t)bytes[2] << 8u)
        | (uint32_t)bytes[3];
}

static void store_u32_be(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
}

static void store_u64_be(uint8_t *bytes, uint64_t value)
{
    bytes[0] = (uint8_t)(value >> 56u);
    bytes[1] = (uint8_t)(value >> 48u);
    bytes[2] = (uint8_t)(value >> 40u);
    bytes[3] = (uint8_t)(value >> 32u);
    bytes[4] = (uint8_t)(value >> 24u);
    bytes[5] = (uint8_t)(value >> 16u);
    bytes[6] = (uint8_t)(value >> 8u);
    bytes[7] = (uint8_t)value;
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
        words[index] = load_u32_be(&block[index * 4u]);
    }
    for (index = 16u; index < 64u; ++index) {
        uint32_t left = words[index - 15u];
        uint32_t right = words[index - 2u];
        uint32_t small0 = rotate_right(left, 7u)
            ^ rotate_right(left, 18u) ^ (left >> 3u);
        uint32_t small1 = rotate_right(right, 17u)
            ^ rotate_right(right, 19u) ^ (right >> 10u);
        words[index] = words[index - 16u] + small0
            + words[index - 7u] + small1;
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
        uint32_t big1 = rotate_right(e, 6u)
            ^ rotate_right(e, 11u) ^ rotate_right(e, 25u);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + big1 + choose
            + sha256_constants[index] + words[index];
        uint32_t big0 = rotate_right(a, 2u)
            ^ rotate_right(a, 13u) ^ rotate_right(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = big0 + majority;
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
    static const uint32_t initial_state[8] = {
        UINT32_C(0x6a09e667), UINT32_C(0xbb67ae85),
        UINT32_C(0x3c6ef372), UINT32_C(0xa54ff53a),
        UINT32_C(0x510e527f), UINT32_C(0x9b05688c),
        UINT32_C(0x1f83d9ab), UINT32_C(0x5be0cd19)
    };
    (void)memset(context, 0, sizeof(*context));
    (void)memcpy(context->state, initial_state, sizeof(initial_state));
}

static void sha256_update(
    sha256_context_t *context,
    const uint8_t *data,
    size_t length)
{
    size_t consumed = 0u;

    context->bit_count += (uint64_t)length * 8u;
    while (consumed < length) {
        size_t available = 64u - context->buffer_length;
        size_t remaining = length - consumed;
        size_t amount = remaining < available ? remaining : available;
        (void)memcpy(&context->buffer[context->buffer_length],
            &data[consumed], amount);
        context->buffer_length += amount;
        consumed += amount;
        if (context->buffer_length == 64u) {
            sha256_transform(context, context->buffer);
            context->buffer_length = 0u;
        }
    }
}

static void sha256_final(sha256_context_t *context, uint8_t output[32])
{
    uint8_t length_bytes[8];
    uint8_t padding[64];
    size_t padding_length;
    size_t index;

    (void)memset(padding, 0, sizeof(padding));
    padding[0] = 0x80u;
    store_u64_be(length_bytes, context->bit_count);
    padding_length = context->buffer_length < 56u
        ? 56u - context->buffer_length
        : 120u - context->buffer_length;
    sha256_update(context, padding, padding_length);
    sha256_update(context, length_bytes, sizeof(length_bytes));
    for (index = 0u; index < 8u; ++index) {
        store_u32_be(&output[index * 4u], context->state[index]);
    }
}

static void entropy_block(
    const ninlil_test_entropy_t *entropy,
    uint64_t counter,
    uint8_t output[32])
{
    static const uint8_t label[] = "ninlil-sim-entropy-v1";
    uint8_t suffix[20];
    sha256_context_t context;

    store_u64_be(&suffix[0], entropy->seed);
    store_u32_be(&suffix[8], entropy->stream_id);
    store_u64_be(&suffix[12], counter);
    sha256_init(&context);
    sha256_update(&context, label, sizeof(label) - 1u);
    sha256_update(&context, suffix, sizeof(suffix));
    sha256_final(&context, output);
}

static uint64_t increment_saturating(uint64_t value)
{
    return value == UINT64_MAX ? UINT64_MAX : value + 1u;
}

static uint64_t required_blocks(uint32_t length)
{
    return ((uint64_t)length + 31u) / 32u;
}

static int counter_range_is_available(
    const ninlil_test_entropy_t *entropy,
    uint64_t blocks)
{
    return !entropy->exhausted && blocks != 0u
        && blocks - 1u <= UINT64_MAX - entropy->counter;
}

static void generate_bytes(
    const ninlil_test_entropy_t *entropy,
    uint8_t *output,
    uint32_t length)
{
    uint64_t block_offset = 0u;
    uint32_t written = 0u;

    while (written < length) {
        uint8_t block[32];
        uint32_t remaining = length - written;
        uint32_t amount = remaining < 32u ? remaining : 32u;
        entropy_block(entropy, entropy->counter + block_offset, block);
        (void)memcpy(&output[written], block, amount);
        written += amount;
        block_offset += 1u;
    }
}

static void advance_counter(ninlil_test_entropy_t *entropy, uint64_t blocks)
{
    uint64_t last = entropy->counter + blocks - 1u;
    if (last == UINT64_MAX) {
        entropy->counter = UINT64_MAX;
        entropy->exhausted = 1;
    } else {
        entropy->counter = last + 1u;
    }
}

static int take_action(
    ninlil_test_entropy_t *entropy,
    entropy_action_t *out)
{
    entropy_action_t *action;
    if (entropy->action_count == 0u) {
        return 0;
    }
    action = &entropy->actions[entropy->action_head];
    *out = *action;
    action->remaining_count -= 1u;
    if (action->remaining_count == 0u) {
        entropy->action_head = (entropy->action_head + 1u)
            % NINLIL_TEST_ENTROPY_ACTION_CAPACITY;
        entropy->action_count -= 1u;
    }
    return 1;
}

static void entropy_trace(
    ninlil_test_entropy_t *entropy,
    ninlil_test_entropy_action_kind_t action,
    ninlil_port_status_t status,
    uint32_t requested_length,
    uint32_t bytes_written,
    uint64_t counter_before,
    int exhausted_before,
    int configuration_error)
{
    ninlil_test_entropy_trace_record_t *record;
    if (entropy->trace_count >= NINLIL_TEST_ENTROPY_TRACE_CAPACITY) {
        entropy->trace_overflowed = 1;
        return;
    }
    record = &entropy->trace[entropy->trace_count];
    entropy->trace_count += 1u;
    record->sequence = entropy->next_sequence;
    entropy->next_sequence = increment_saturating(entropy->next_sequence);
    record->action = action;
    record->status = status;
    record->requested_length = requested_length;
    record->bytes_written = bytes_written;
    record->counter_before = counter_before;
    record->counter_after = entropy->counter;
    record->exhausted_before = exhausted_before != 0;
    record->exhausted_after = entropy->exhausted != 0;
    record->script_configuration_error = configuration_error != 0;
}

static ninlil_port_status_t entropy_fill(
    void *user,
    uint8_t *output,
    uint32_t length)
{
    ninlil_test_entropy_t *entropy = (ninlil_test_entropy_t *)user;
    entropy_action_t action;
    ninlil_test_entropy_action_kind_t action_kind =
        NINLIL_TEST_ENTROPY_ACTION_NONE;
    ninlil_port_status_t status;
    uint64_t blocks;
    uint64_t counter_before;
    int exhausted_before;
    uint32_t bytes_written = 0u;
    int configuration_error = 0;

    if (entropy == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    entropy->call_count = increment_saturating(entropy->call_count);
    counter_before = entropy->counter;
    exhausted_before = entropy->exhausted;
    if (length == 0u) {
        status = NINLIL_PORT_OK;
        entropy_trace(entropy, action_kind, status, length, 0u,
            counter_before, exhausted_before, 0);
        return status;
    }
    if (output == NULL) {
        status = NINLIL_PORT_PERMANENT_FAILURE;
        entropy_trace(entropy, action_kind, status, length, 0u,
            counter_before, exhausted_before, 0);
        entropy->invalid_call_count = increment_saturating(
            entropy->invalid_call_count);
        return status;
    }
    blocks = required_blocks(length);
    if (!counter_range_is_available(entropy, blocks)) {
        status = NINLIL_PORT_PERMANENT_FAILURE;
        entropy_trace(entropy, action_kind, status, length, 0u,
            counter_before, exhausted_before, 0);
        return status;
    }
    if (take_action(entropy, &action)) {
        action_kind = action.kind;
        switch (action.kind) {
        case NINLIL_TEST_ENTROPY_ACTION_TEMPORARY:
            status = NINLIL_PORT_TEMPORARY_FAILURE;
            break;
        case NINLIL_TEST_ENTROPY_ACTION_PERMANENT:
            status = NINLIL_PORT_PERMANENT_FAILURE;
            break;
        case NINLIL_TEST_ENTROPY_ACTION_PARTIAL:
            if (action.partial_prefix_length == 0u
                || action.partial_prefix_length >= length) {
                status = NINLIL_PORT_PERMANENT_FAILURE;
                configuration_error = 1;
                entropy->script_error_count = increment_saturating(
                    entropy->script_error_count);
            } else {
                generate_bytes(entropy, output, action.partial_prefix_length);
                bytes_written = action.partial_prefix_length;
                status = NINLIL_PORT_TEMPORARY_FAILURE;
            }
            break;
        case NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO:
            (void)memset(output, 0, length);
            bytes_written = length;
            advance_counter(entropy, blocks);
            status = NINLIL_PORT_OK;
            break;
        default:
            status = NINLIL_PORT_PERMANENT_FAILURE;
            configuration_error = 1;
            entropy->script_error_count = increment_saturating(
                entropy->script_error_count);
            break;
        }
    } else {
        generate_bytes(entropy, output, length);
        bytes_written = length;
        advance_counter(entropy, blocks);
        status = NINLIL_PORT_OK;
    }
    entropy_trace(entropy, action_kind, status, length, bytes_written,
        counter_before, exhausted_before, configuration_error);
    return status;
}

ninlil_test_entropy_t *ninlil_test_entropy_create(
    uint64_t seed,
    uint32_t stream_id)
{
    ninlil_test_entropy_t *entropy =
        (ninlil_test_entropy_t *)calloc(1u, sizeof(*entropy));
    if (entropy == NULL) {
        return NULL;
    }
    entropy->seed = seed;
    entropy->stream_id = stream_id;
    entropy->next_sequence = 1u;
    entropy->ops.abi_version = NINLIL_ABI_VERSION;
    entropy->ops.struct_size = (uint16_t)sizeof(entropy->ops);
    entropy->ops.user = entropy;
    entropy->ops.fill = entropy_fill;
    return entropy;
}

const ninlil_entropy_ops_t *ninlil_test_entropy_ops(
    ninlil_test_entropy_t *entropy)
{
    return entropy == NULL ? NULL : &entropy->ops;
}

int ninlil_test_entropy_script(
    ninlil_test_entropy_t *entropy,
    ninlil_test_entropy_action_kind_t action,
    uint32_t partial_prefix_length,
    uint32_t remaining_count)
{
    entropy_action_t *entry;
    size_t tail;
    int is_partial = action == NINLIL_TEST_ENTROPY_ACTION_PARTIAL;

    if (entropy == NULL || remaining_count == 0u
        || action < NINLIL_TEST_ENTROPY_ACTION_TEMPORARY
        || action > NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO
        || (is_partial && partial_prefix_length == 0u)
        || (!is_partial && partial_prefix_length != 0u)
        || entropy->action_count >= NINLIL_TEST_ENTROPY_ACTION_CAPACITY) {
        return 0;
    }
    tail = (entropy->action_head + entropy->action_count)
        % NINLIL_TEST_ENTROPY_ACTION_CAPACITY;
    entry = &entropy->actions[tail];
    entry->kind = action;
    entry->partial_prefix_length = partial_prefix_length;
    entry->remaining_count = remaining_count;
    entropy->action_count += 1u;
    return 1;
}

uint64_t ninlil_test_entropy_counter(const ninlil_test_entropy_t *entropy)
{
    return entropy == NULL ? 0u : entropy->counter;
}

int ninlil_test_entropy_exhausted(const ninlil_test_entropy_t *entropy)
{
    return entropy != NULL && entropy->exhausted;
}

uint64_t ninlil_test_entropy_call_count(const ninlil_test_entropy_t *entropy)
{
    return entropy == NULL ? 0u : entropy->call_count;
}

uint64_t ninlil_test_entropy_script_error_count(
    const ninlil_test_entropy_t *entropy)
{
    return entropy == NULL ? 0u : entropy->script_error_count;
}

uint64_t ninlil_test_entropy_invalid_call_count(
    const ninlil_test_entropy_t *entropy)
{
    return entropy == NULL ? 0u : entropy->invalid_call_count;
}

int ninlil_test_entropy_trace_overflowed(
    const ninlil_test_entropy_t *entropy)
{
    return entropy != NULL && entropy->trace_overflowed;
}

uint64_t ninlil_test_entropy_restart_count(
    const ninlil_test_entropy_t *entropy)
{
    return entropy == NULL ? 0u : entropy->restart_count;
}

size_t ninlil_test_entropy_trace_count(const ninlil_test_entropy_t *entropy)
{
    return entropy == NULL ? 0u : entropy->trace_count;
}

const ninlil_test_entropy_trace_record_t *ninlil_test_entropy_trace_at(
    const ninlil_test_entropy_t *entropy,
    size_t index)
{
    if (entropy == NULL || index >= entropy->trace_count) {
        return NULL;
    }
    return &entropy->trace[index];
}

void ninlil_test_entropy_simulate_restart(ninlil_test_entropy_t *entropy)
{
    if (entropy != NULL) {
        entropy->restart_count = increment_saturating(entropy->restart_count);
    }
}

void ninlil_test_entropy_scenario_reset(
    ninlil_test_entropy_t *entropy,
    uint64_t seed,
    uint32_t stream_id)
{
    if (entropy == NULL) {
        return;
    }
    entropy->seed = seed;
    entropy->stream_id = stream_id;
    entropy->counter = 0u;
    entropy->exhausted = 0;
    entropy->action_head = 0u;
    entropy->action_count = 0u;
    entropy->trace_count = 0u;
    entropy->next_sequence = 1u;
    entropy->call_count = 0u;
    entropy->script_error_count = 0u;
    entropy->invalid_call_count = 0u;
    entropy->restart_count = 0u;
    entropy->trace_overflowed = 0;
}

int ninlil_test_entropy_set_counter_for_test(
    ninlil_test_entropy_t *entropy,
    uint64_t counter,
    int exhausted)
{
    if (entropy == NULL || (exhausted != 0 && exhausted != 1)
        || (exhausted != 0 && counter != UINT64_MAX)) {
        return 0;
    }
    entropy->counter = counter;
    entropy->exhausted = exhausted;
    return 1;
}

void ninlil_test_entropy_destroy(ninlil_test_entropy_t *entropy)
{
    free(entropy);
}
