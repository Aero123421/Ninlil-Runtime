#include "typed_simulated_bearer.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",       \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct test_context {
    ninlil_test_bearer_t *bearer;
    const ninlil_bearer_ops_t *ops;
    const ninlil_tx_gate_ops_t *tx;
    ninlil_id128_t a_id;
    ninlil_id128_t b_id;
    ninlil_id128_t clock_epoch;
    ninlil_bearer_handle_t a;
    ninlil_bearer_handle_t b;
} test_context_t;

static ninlil_id128_t marked_id(uint8_t first, uint8_t last)
{
    ninlil_id128_t id = {{0u}};
    id.bytes[0] = first;
    id.bytes[15] = last;
    return id;
}

static int hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    return -1;
}

static int decode_hex(const char *hex, uint8_t *output, size_t length)
{
    size_t index;
    for (index = 0u; index < length; ++index) {
        int high = hex_value(hex[index * 2u]);
        int low = hex_value(hex[index * 2u + 1u]);
        if (high < 0 || low < 0) {
            return 0;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    return hex[length * 2u] == '\0';
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static void set_text(ninlil_text_id_t *text, const char *value)
{
    size_t length = strlen(value);
    (void)memset(text, 0, sizeof(*text));
    text->length = (uint8_t)length;
    (void)memcpy(text->bytes, value, length);
}

static ninlil_bearer_message_t make_message(
    const test_context_t *context,
    int from_a,
    ninlil_bearer_message_kind_t kind,
    uint8_t marker,
    uint8_t *payload,
    uint32_t payload_length,
    uint8_t *evidence,
    uint32_t evidence_length)
{
    ninlil_bearer_message_t message;
    const ninlil_id128_t *source = from_a ? &context->a_id : &context->b_id;
    const ninlil_id128_t *target = from_a ? &context->b_id : &context->a_id;
    (void)memset(&message, 0, sizeof(message));
    set_header(&message.abi_version, &message.struct_size, sizeof(message));
    message.kind = kind;
    message.transaction_id = marked_id(0x70u, marker);
    message.attempt_id = marked_id(0x71u, marker);
    if (kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
        message.generation = 1u;
    }
    set_header(&message.source.abi_version, &message.source.struct_size,
        sizeof(message.source));
    message.source.runtime_id = *source;
    message.source.application_instance_id = marked_id(0x30u, marker);
    set_header(&message.source.local_identity.abi_version,
        &message.source.local_identity.struct_size,
        sizeof(message.source.local_identity));
    message.source.local_identity.device_id = marked_id(0x20u, marker);
    message.source.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE;
    message.source.local_identity.binding_epoch = 1u;
    set_header(&message.target.abi_version, &message.target.struct_size,
        sizeof(message.target));
    message.target.target_runtime_id = *target;
    message.target.target_application_instance_id = marked_id(0x60u, marker);
    message.target.device_id = marked_id(0x40u, marker);
    message.target.flags = NINLIL_TARGET_HAS_DEVICE;
    message.target.binding_epoch = 1u;
    set_header(&message.service.abi_version, &message.service.struct_size,
        sizeof(message.service));
    set_text(&message.service.namespace_id, "org.ninlil.examples");
    set_text(&message.service.service_id, "absolute-state");
    set_text(&message.service.schema_id, "absolute-state");
    message.service.descriptor_revision = 1u;
    message.service.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    message.service.descriptor_digest.bytes[0] = marker;
    message.service.schema_major = 1u;
    message.service.family = NINLIL_FAMILY_DESIRED_STATE;
    message.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    message.content_digest.bytes[0] = marker;
    message.required_evidence = NINLIL_EVIDENCE_APPLIED;
    message.payload.data = payload_length == 0u ? NULL : payload;
    message.payload.length = payload_length;
    message.evidence.data = evidence_length == 0u ? NULL : evidence;
    message.evidence.length = evidence_length;
    return message;
}

static test_context_t make_context(uint64_t entries, uint64_t bytes)
{
    test_context_t context;
    ninlil_test_bearer_config_t config;
    (void)memset(&context, 0, sizeof(context));
    context.a_id = marked_id(0x21u, 1u);
    context.b_id = marked_id(0x41u, 1u);
    context.clock_epoch = marked_id(0xa0u, 1u);
    (void)memset(&config, 0, sizeof(config));
    config.max_entries_per_direction = entries;
    config.max_bytes_per_direction = bytes;
    config.max_permits = 128u;
    config.permit_issuer_id = marked_id(0x80u, 1u);
    config.initial_clock_epoch_id = context.clock_epoch;
    context.bearer = ninlil_test_bearer_create(&config);
    if (context.bearer == NULL) {
        return context;
    }
    context.ops = ninlil_test_bearer_ops(context.bearer);
    context.tx = ninlil_test_bearer_tx_gate_ops(context.bearer);
    if (context.ops->open(context.ops->user, &context.a_id,
            NINLIL_ROLE_CONTROLLER, &context.a) != NINLIL_BEARER_OK
        || context.ops->open(context.ops->user, &context.b_id,
            NINLIL_ROLE_ENDPOINT, &context.b) != NINLIL_BEARER_OK) {
        ninlil_test_bearer_destroy(context.bearer);
        (void)memset(&context, 0, sizeof(context));
    }
    return context;
}

static void destroy_context(test_context_t *context)
{
    if (context->a != NULL) {
        context->ops->close(context->ops->user, context->a);
    }
    if (context->b != NULL) {
        context->ops->close(context->ops->user, context->b);
    }
    ninlil_test_bearer_destroy(context->bearer);
    (void)memset(context, 0, sizeof(*context));
}

static ninlil_tx_permit_t acquire_permit(
    test_context_t *context,
    const ninlil_bearer_message_t *message)
{
    ninlil_tx_request_t request;
    ninlil_time_sample_t now;
    ninlil_tx_permit_t permit;
    uint64_t logical_bytes = 0u;
    (void)memset(&request, 0, sizeof(request));
    (void)memset(&now, 0, sizeof(now));
    (void)memset(&permit, 0, sizeof(permit));
    if (!ninlil_test_bearer_logical_bytes(message, &logical_bytes)
        || logical_bytes > UINT32_MAX) {
        return permit;
    }
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    request.transaction_id = message->transaction_id;
    request.attempt_id = message->attempt_id;
    request.message_kind = message->kind;
    request.logical_bytes = (uint32_t)logical_bytes;
    request.content_digest = message->content_digest;
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    now.clock_epoch_id = context->clock_epoch;
    now.now_ms = 0u;
    now.trust = NINLIL_CLOCK_TRUSTED;
    if (context->tx->acquire(context->tx->user, &request, &now, &permit)
        != NINLIL_TX_GATE_OK) {
        (void)memset(&permit, 0, sizeof(permit));
    }
    return permit;
}

static ninlil_bearer_status_t send_message(
    test_context_t *context,
    ninlil_bearer_handle_t handle,
    const ninlil_bearer_message_t *message,
    ninlil_tx_permit_t *permit,
    ninlil_bearer_send_result_t *result)
{
    (void)memset(result, 0, sizeof(*result));
    return context->ops->send(context->ops->user, handle,
        permit, message, result);
}

static int receive_and_release(
    test_context_t *context,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    if (context->ops->receive_next(context->ops->user, handle, message)
        != NINLIL_BEARER_OK) {
        return 0;
    }
    context->ops->release_received(context->ops->user, handle, message);
    return 1;
}

static int test_tb1_accounting_and_tb2_deep_copy(void)
{
    test_context_t context = make_context(2u, 1021u);
    uint8_t payload[10] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u};
    uint8_t evidence[3] = {0xa1u, 0xa2u, 0xa3u};
    ninlil_bearer_message_t c1;
    ninlil_bearer_message_t e1;
    ninlil_bearer_message_t received;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint64_t logical_bytes;
    uint64_t entries;
    uint64_t bytes;
    uint32_t kind;
    REQUIRE(context.bearer != NULL);
    c1 = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        1u, payload, 9u, NULL, 0u);
    REQUIRE(ninlil_test_bearer_logical_bytes(&c1, &logical_bytes));
    REQUIRE(logical_bytes == 511u);
    e1 = c1;
    set_text(&e1.service.service_id, "durable-event");
    set_text(&e1.service.schema_id, "durable-event");
    e1.payload.length = 10u;
    REQUIRE(ninlil_test_bearer_logical_bytes(&e1, &logical_bytes));
    REQUIRE(logical_bytes == 510u);
    permit = acquire_permit(&context, &c1);
    REQUIRE(send_message(&context, context.a, &c1, &permit, &result)
        == NINLIL_BEARER_OK);
    permit = acquire_permit(&context, &e1);
    REQUIRE(send_message(&context, context.a, &e1, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(ninlil_test_bearer_direction_accounting(context.bearer,
        &context.a_id, &entries, &bytes));
    REQUIRE(entries == 2u && bytes == 1021u);
    permit = acquire_permit(&context, &c1);
    REQUIRE(send_message(&context, context.a, &c1, &permit, &result)
        == NINLIL_BEARER_WOULD_BLOCK);
    REQUIRE(ninlil_test_bearer_permit_live_count(context.bearer) == 1u);
    context.tx->release_unused(context.tx->user, &permit);
    REQUIRE(receive_and_release(&context, context.b, &received));
    REQUIRE(receive_and_release(&context, context.b, &received));

    for (kind = NINLIL_BEARER_MESSAGE_APPLICATION;
         kind <= NINLIL_BEARER_MESSAGE_CANCEL_RESULT; ++kind) {
        ninlil_bearer_message_t message = make_message(&context, 1,
            kind, (uint8_t)(kind + 10u), payload, sizeof(payload),
            evidence, sizeof(evidence));
        ninlil_bearer_message_t snapshot = message;
        uint8_t payload_snapshot[sizeof(payload)];
        uint8_t evidence_snapshot[sizeof(evidence)];
        (void)memcpy(payload_snapshot, payload, sizeof(payload));
        (void)memcpy(evidence_snapshot, evidence, sizeof(evidence));
        permit = acquire_permit(&context, &message);
        REQUIRE(send_message(&context, context.a, &message, &permit, &result)
            == NINLIL_BEARER_OK);
        (void)memset(&message, 0xa5, sizeof(message));
        (void)memset(payload, 0x5a, sizeof(payload));
        (void)memset(evidence, 0x6b, sizeof(evidence));
        REQUIRE(context.ops->receive_next(context.ops->user, context.b,
            &received) == NINLIL_BEARER_OK);
        REQUIRE(received.kind == snapshot.kind);
        REQUIRE(received.transaction_id.bytes[15]
            == snapshot.transaction_id.bytes[15]);
        REQUIRE(received.payload.data != payload);
        REQUIRE(received.evidence.data != evidence);
        REQUIRE(memcmp(received.payload.data, payload_snapshot,
            sizeof(payload_snapshot)) == 0);
        REQUIRE(memcmp(received.evidence.data, evidence_snapshot,
            sizeof(evidence_snapshot)) == 0);
        context.ops->release_received(context.ops->user, context.b, &received);
        (void)memcpy(payload, payload_snapshot, sizeof(payload));
        (void)memcpy(evidence, evidence_snapshot, sizeof(evidence));
    }
    destroy_context(&context);
    return 0;
}

static int test_tb3_fifo_and_tb6_loan(void)
{
    test_context_t context = make_context(4u, 4096u);
    uint8_t payload = 1u;
    ninlil_bearer_message_t a1;
    ninlil_bearer_message_t a2;
    ninlil_bearer_message_t b1;
    ninlil_bearer_message_t b2;
    ninlil_bearer_message_t received;
    ninlil_bearer_message_t wrong_object;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint64_t violations;
    REQUIRE(context.bearer != NULL);
    a1 = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        1u, &payload, 1u, NULL, 0u);
    a2 = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        2u, &payload, 1u, NULL, 0u);
    b1 = make_message(&context, 0, NINLIL_BEARER_MESSAGE_APPLICATION,
        3u, &payload, 1u, NULL, 0u);
    b2 = make_message(&context, 0, NINLIL_BEARER_MESSAGE_APPLICATION,
        4u, &payload, 1u, NULL, 0u);
    permit = acquire_permit(&context, &a1);
    REQUIRE(send_message(&context, context.a, &a1, &permit, &result)
        == NINLIL_BEARER_OK);
    permit = acquire_permit(&context, &b1);
    REQUIRE(send_message(&context, context.b, &b1, &permit, &result)
        == NINLIL_BEARER_OK);
    permit = acquire_permit(&context, &a2);
    REQUIRE(send_message(&context, context.a, &a2, &permit, &result)
        == NINLIL_BEARER_OK);
    permit = acquire_permit(&context, &b2);
    REQUIRE(send_message(&context, context.b, &b2, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.transaction_id.bytes[15] == 1u);
    (void)memset(&wrong_object, 0, sizeof(wrong_object));
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &wrong_object) == NINLIL_BEARER_WOULD_BLOCK);
    REQUIRE(memcmp(&wrong_object, &(ninlil_bearer_message_t){0},
        sizeof(wrong_object)) == 0);
    violations = ninlil_test_bearer_violation_count(context.bearer);
    context.ops->release_received(context.ops->user, context.a, &received);
    REQUIRE(ninlil_test_bearer_violation_count(context.bearer)
        == violations + 1u);
    wrong_object = received;
    context.ops->release_received(context.ops->user, context.b, &wrong_object);
    REQUIRE(ninlil_test_bearer_live_loan_count(context.bearer) == 1u);
    context.ops->release_received(context.ops->user, context.b, &received);
    REQUIRE(ninlil_test_bearer_live_loan_count(context.bearer) == 0u);
    REQUIRE(memcmp(&received, &(ninlil_bearer_message_t){0},
        sizeof(received)) == 0);
    context.ops->release_received(context.ops->user, context.b, &received);
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.transaction_id.bytes[15] == 2u);
    context.ops->release_received(context.ops->user, context.b, &received);
    REQUIRE(context.ops->receive_next(context.ops->user, context.a,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.transaction_id.bytes[15] == 3u);
    context.ops->release_received(context.ops->user, context.a, &received);
    REQUIRE(context.ops->receive_next(context.ops->user, context.a,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.transaction_id.bytes[15] == 4u);
    context.ops->release_received(context.ops->user, context.a, &received);
    destroy_context(&context);
    return 0;
}

static int test_tb4_handles_and_retention(void)
{
    test_context_t context = make_context(4u, 4096u);
    ninlil_bearer_handle_t duplicate = (ninlil_bearer_handle_t)(uintptr_t)1u;
    ninlil_bearer_handle_t reopened = NULL;
    ninlil_bearer_handle_t third = NULL;
    ninlil_id128_t third_id = marked_id(0x51u, 1u);
    uint8_t payload = 9u;
    ninlil_bearer_message_t message;
    ninlil_bearer_message_t received;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint64_t violations;
    REQUIRE(context.bearer != NULL);
    REQUIRE(context.ops->open(context.ops->user, &context.a_id,
        NINLIL_ROLE_CONTROLLER, &duplicate) == NINLIL_BEARER_WOULD_BLOCK);
    REQUIRE(duplicate == NULL);
    REQUIRE(context.ops->open(context.ops->user, &context.a_id,
        NINLIL_ROLE_ENDPOINT, &duplicate) == NINLIL_BEARER_DENIED);
    REQUIRE(context.ops->open(context.ops->user, &third_id,
        NINLIL_ROLE_ENDPOINT, &third) == NINLIL_BEARER_DENIED);
    message = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        8u, &payload, 1u, NULL, 0u);
    permit = acquire_permit(&context, &message);
    REQUIRE(send_message(&context, context.a, &message, &permit, &result)
        == NINLIL_BEARER_OK);
    context.ops->close(context.ops->user, context.b);
    violations = ninlil_test_bearer_violation_count(context.bearer);
    context.ops->close(context.ops->user, context.b);
    REQUIRE(ninlil_test_bearer_violation_count(context.bearer)
        == violations + 1u);
    REQUIRE(context.ops->open(context.ops->user, &context.b_id,
        NINLIL_ROLE_ENDPOINT, &reopened) == NINLIL_BEARER_OK);
    REQUIRE(reopened != context.b);
    context.b = reopened;
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    context.ops->release_received(context.ops->user, context.b, &received);
    destroy_context(&context);
    return 0;
}

static int test_tb5_permit_binding(void)
{
    test_context_t context = make_context(1u, 4096u);
    uint8_t payload = 7u;
    ninlil_bearer_message_t message;
    ninlil_bearer_message_t changed;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    ninlil_tx_permit_t poisoned;
    ninlil_bearer_message_t received;
    REQUIRE(context.bearer != NULL);
    message = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        1u, &payload, 1u, NULL, 0u);
    permit = acquire_permit(&context, &message);
    changed = message;
    changed.transaction_id.bytes[1] ^= 1u;
    REQUIRE(send_message(&context, context.a, &changed, &permit, &result)
        == NINLIL_BEARER_DENIED);
    changed = message;
    changed.content_digest.bytes[1] ^= 1u;
    REQUIRE(send_message(&context, context.a, &changed, &permit, &result)
        == NINLIL_BEARER_DENIED);
    changed = message;
    changed.kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    REQUIRE(send_message(&context, context.a, &changed, &permit, &result)
        == NINLIL_BEARER_DENIED);
    changed = message;
    changed.payload.length = 2u;
    REQUIRE(send_message(&context, context.a, &changed, &permit, &result)
        == NINLIL_BEARER_DENIED);
    poisoned = permit;
    poisoned.attempt_id.bytes[1] ^= 1u;
    REQUIRE(send_message(&context, context.a, &message, &poisoned, &result)
        == NINLIL_BEARER_DENIED);
    REQUIRE(ninlil_test_bearer_set_time(context.bearer,
        marked_id(0xa0u, 2u), 0u));
    REQUIRE(send_message(&context, context.a, &message, &permit, &result)
        == NINLIL_BEARER_DENIED);
    REQUIRE(ninlil_test_bearer_set_time(context.bearer,
        context.clock_epoch, 0u));
    REQUIRE(ninlil_test_bearer_set_time(context.bearer,
        context.clock_epoch, 999u));
    REQUIRE(send_message(&context, context.a, &message, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(send_message(&context, context.a, &message, &permit, &result)
        == NINLIL_BEARER_DENIED);
    REQUIRE(ninlil_test_bearer_permit_consumed_count(context.bearer) == 1u);
    REQUIRE(receive_and_release(&context, context.b, &received));
    REQUIRE(ninlil_test_bearer_set_time(context.bearer,
        context.clock_epoch, 1000u));
    message.attempt_id.bytes[15] = 2u;
    message.transaction_id.bytes[15] = 2u;
    /* acquire uses the current time, so this new permit expires at 2000. */
    {
        ninlil_tx_request_t request;
        ninlil_time_sample_t now;
        uint64_t logical_bytes;
        (void)memset(&request, 0, sizeof(request));
        (void)memset(&now, 0, sizeof(now));
        set_header(&request.abi_version, &request.struct_size, sizeof(request));
        REQUIRE(ninlil_test_bearer_logical_bytes(&message, &logical_bytes));
        request.transaction_id = message.transaction_id;
        request.attempt_id = message.attempt_id;
        request.message_kind = message.kind;
        request.logical_bytes = (uint32_t)logical_bytes;
        request.content_digest = message.content_digest;
        set_header(&now.abi_version, &now.struct_size, sizeof(now));
        now.clock_epoch_id = context.clock_epoch;
        now.now_ms = 1000u;
        now.trust = NINLIL_CLOCK_TRUSTED;
        REQUIRE(context.tx->acquire(context.tx->user, &request, &now, &permit)
            == NINLIL_TX_GATE_OK);
    }
    REQUIRE(ninlil_test_bearer_set_time(context.bearer,
        context.clock_epoch, 2000u));
    REQUIRE(send_message(&context, context.a, &message, &permit, &result)
        == NINLIL_BEARER_DENIED);
    REQUIRE(ninlil_test_bearer_permit_expired_count(context.bearer) == 1u);
    destroy_context(&context);
    return 0;
}

static int test_tb7_tb8_tb9(void)
{
    test_context_t context = make_context(1u, 4096u);
    uint8_t payload = 5u;
    ninlil_bearer_message_t message;
    ninlil_bearer_message_t received;
    ninlil_bearer_send_result_t result;
    ninlil_bearer_send_result_t raw_result;
    ninlil_bearer_state_t state;
    ninlil_bearer_state_t raw_state;
    ninlil_tx_permit_t permit;
    uint64_t epoch;
    REQUIRE(context.bearer != NULL);
    (void)memset(&state, 0, sizeof(state));
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    REQUIRE(state.availability_epoch == 2u && state.available == 1u);
    epoch = state.availability_epoch;
    REQUIRE(ninlil_test_bearer_set_path_up(context.bearer, &context.a_id, 0));
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    REQUIRE(state.availability_epoch == epoch + 1u && state.available == 0u);
    REQUIRE(ninlil_test_bearer_set_path_up(context.bearer, &context.a_id, 0));
    REQUIRE(ninlil_test_bearer_set_path_up(context.bearer, &context.a_id, 1));
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK && state.available == 1u);

    message = make_message(&context, 1, 99u, 9u,
        &payload, 1u, NULL, 0u);
    /* Unknown kind is safe transport data, but Tx Gate only issues known kinds. */
    message.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    permit = acquire_permit(&context, &message);
    message.flags = 0x80000000u;
    REQUIRE(send_message(&context, context.a, &message, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.flags == 0x80000000u);
    context.ops->release_received(context.ops->user, context.b, &received);

    message = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        10u, &payload, 1u, NULL, 0u);
    message.service.namespace_id.length = 64u;
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(context.ops->send(context.ops->user, context.a,
        NULL, &message, &result) == NINLIL_BEARER_CORRUPT);

    (void)memset(&raw_state, 0xa5, sizeof(raw_state));
    REQUIRE(ninlil_test_bearer_raw_state_enqueue(context.bearer,
        (ninlil_bearer_status_t)99u, &raw_state, 1u));
    (void)memset(&state, 0, sizeof(state));
    REQUIRE(context.ops->state(context.ops->user, context.a, &state) == 99u);
    REQUIRE(memcmp(&state, &raw_state, sizeof(state)) == 0);

    message = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        11u, &payload, 1u, NULL, 0u);
    permit = acquire_permit(&context, &message);
    (void)memset(&raw_result, 0, sizeof(raw_result));
    raw_result.abi_version = NINLIL_ABI_VERSION;
    raw_result.struct_size = (uint16_t)sizeof(raw_result);
    raw_result.kind = 99u;
    raw_result.availability_epoch = 2u;
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(context.bearer,
        NINLIL_BEARER_OK, &raw_result, 1u));
    REQUIRE(send_message(&context, context.a, &message, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(ninlil_test_bearer_permit_fenced_count(context.bearer) == 1u);

    REQUIRE(ninlil_test_bearer_set_path_epoch_for_test(context.bearer,
        &context.a_id, UINT64_MAX));
    REQUIRE(!ninlil_test_bearer_set_path_up(context.bearer, &context.a_id, 0));
    (void)memset(&state, 0xa5, sizeof(state));
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_CORRUPT);
    REQUIRE(memcmp(&state, &(ninlil_bearer_state_t){0}, sizeof(state)) == 0);
    destroy_context(&context);
    return 0;
}

static int test_c1_permit_golden(void)
{
    test_context_t context = make_context(4u, 4096u);
    uint8_t payload[9];
    ninlil_bearer_message_t message;
    ninlil_tx_permit_t permit;
    static const char *payload_hex = "010100000000000000";
    static const char *content_hex =
        "46f8ec5a439c92e1df8299e1a4432a7ee172d8496b5e33e0a35a7b67163371b5";
    static const char *transaction_hex = "0d5382f07b9c59639f7c1957ae22fea7";
    static const char *attempt_hex = "5dd9578bd99d35ff819efba06edcb33e";
    static const char *permit_hex = "a82ca19b607f15a81ab5984de23aec7a";
    REQUIRE(context.bearer != NULL);
    REQUIRE(decode_hex(payload_hex, payload, sizeof(payload)));
    message = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        1u, payload, sizeof(payload), NULL, 0u);
    REQUIRE(decode_hex(transaction_hex, message.transaction_id.bytes, 16u));
    REQUIRE(decode_hex(attempt_hex, message.attempt_id.bytes, 16u));
    REQUIRE(decode_hex(content_hex, message.content_digest.bytes, 32u));
    permit = acquire_permit(&context, &message);
    {
        uint8_t expected[16];
        REQUIRE(decode_hex(permit_hex, expected, sizeof(expected)));
        REQUIRE(memcmp(permit.permit_id.bytes, expected, sizeof(expected)) == 0);
    }
    destroy_context(&context);
    return 0;
}

static int test_review_regressions(void)
{
    test_context_t context = make_context(1u, 4096u);
    uint8_t payload[2] = {1u, 2u};
    ninlil_bearer_message_t first;
    ninlil_bearer_message_t second;
    ninlil_bearer_message_t received;
    ninlil_bearer_message_t wrong;
    ninlil_bearer_send_result_t result;
    ninlil_bearer_send_result_t raw_result;
    ninlil_bearer_state_t state;
    ninlil_tx_permit_t permit;
    uint64_t epoch;
    uint64_t violations;
    REQUIRE(context.bearer != NULL);

    first = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        21u, payload, 1u, NULL, 0u);
    second = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        22u, payload, 2u, NULL, 0u);
    permit = acquire_permit(&context, &first);
    REQUIRE(send_message(&context, context.a, &first, &permit, &result)
        == NINLIL_BEARER_OK);
    permit = acquire_permit(&context, &second);
    REQUIRE(send_message(&context, context.a, &second, &permit, &result)
        == NINLIL_BEARER_WOULD_BLOCK);
    context.tx->release_unused(context.tx->user, &permit);
    (void)memset(&state, 0, sizeof(state));
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    epoch = state.availability_epoch;
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    REQUIRE(state.availability_epoch == epoch + 1u);
    context.ops->release_received(context.ops->user, context.b, &received);

    permit = acquire_permit(&context, &first);
    REQUIRE(ninlil_test_bearer_fail_next_copy_allocations(
        context.bearer, 1u));
    epoch = state.availability_epoch;
    REQUIRE(send_message(&context, context.a, &first, &permit, &result)
        == NINLIL_BEARER_WOULD_BLOCK);
    REQUIRE(result.availability_epoch == epoch);
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    REQUIRE(state.availability_epoch == epoch + 1u);
    context.tx->release_unused(context.tx->user, &permit);

    epoch = state.availability_epoch;
    context.ops->close(context.ops->user, context.b);
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    REQUIRE(state.available == 0u && state.availability_epoch == epoch + 1u);
    context.b = NULL;
    REQUIRE(context.ops->open(context.ops->user, &context.b_id,
        NINLIL_ROLE_ENDPOINT, &context.b) == NINLIL_BEARER_OK);
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    REQUIRE(state.available == 1u && state.availability_epoch == epoch + 2u);

    first = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        23u, NULL, 0u, NULL, 0u);
    permit = acquire_permit(&context, &first);
    REQUIRE(send_message(&context, context.a, &first, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.payload.data == NULL && received.evidence.data == NULL);
    wrong = received;
    violations = ninlil_test_bearer_violation_count(context.bearer);
    context.ops->release_received(context.ops->user, context.b, &wrong);
    REQUIRE(ninlil_test_bearer_violation_count(context.bearer)
        == violations + 1u);
    context.ops->release_received(context.ops->user, context.b, &received);

    permit = acquire_permit(&context, &first);
    REQUIRE(send_message(&context, context.a, &first, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    context.ops->close(context.ops->user, context.b);
    context.b = NULL;
    REQUIRE(ninlil_test_bearer_orphan_loan_count(context.bearer) == 1u);
    REQUIRE(ninlil_test_bearer_live_loan_count(context.bearer) == 0u);
    REQUIRE(context.ops->open(context.ops->user, &context.b_id,
        NINLIL_ROLE_ENDPOINT, &context.b) == NINLIL_BEARER_OK);

    REQUIRE(ninlil_test_bearer_raw_receive_enqueue(context.bearer,
        NINLIL_BEARER_OK, NULL, 1u));
    (void)memset(&received, 0xa5, sizeof(received));
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(memcmp(&received, &(ninlil_bearer_message_t){0},
        sizeof(received)) == 0);
    REQUIRE(ninlil_test_bearer_live_loan_count(context.bearer) == 1u);
    context.ops->release_received(context.ops->user, context.b, &received);

    first = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        24u, payload, 1u, NULL, 0u);
    first.abi_version = 0u;
    REQUIRE(ninlil_test_bearer_raw_receive_enqueue(context.bearer,
        NINLIL_BEARER_OK, &first, 1u));
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.abi_version == 0u);
    context.ops->release_received(context.ops->user, context.b, &received);

    first = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        26u, payload, 1u, NULL, 0u);
    first.flags = 0x5a5a5a5au;
    REQUIRE(ninlil_test_bearer_raw_receive_enqueue(context.bearer,
        NINLIL_BEARER_WOULD_BLOCK, &first, 1u));
    (void)memset(&received, 0, sizeof(received));
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_WOULD_BLOCK);
    REQUIRE(received.flags == 0x5a5a5a5au);
    REQUIRE(ninlil_test_bearer_live_loan_count(context.bearer) == 0u);

    first = make_message(&context, 1, NINLIL_BEARER_MESSAGE_APPLICATION,
        25u, payload, 1u, NULL, 0u);
    permit = acquire_permit(&context, &first);
    (void)memset(&raw_result, 0, sizeof(raw_result));
    raw_result.abi_version = NINLIL_ABI_VERSION;
    raw_result.struct_size = (uint16_t)sizeof(raw_result);
    raw_result.availability_epoch = state.availability_epoch;
    raw_result.kind = 77u;
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(context.bearer,
        NINLIL_BEARER_WOULD_BLOCK, &raw_result, 1u));
    REQUIRE(send_message(&context, context.a, &first, &permit, &result)
        == NINLIL_BEARER_WOULD_BLOCK);
    REQUIRE(ninlil_test_bearer_permit_fenced_count(context.bearer) >= 1u);

    permit = acquire_permit(&context, &first);
    (void)memset(&raw_result, 0, sizeof(raw_result));
    raw_result.abi_version = NINLIL_ABI_VERSION;
    raw_result.struct_size = (uint16_t)sizeof(raw_result);
    raw_result.kind = NINLIL_BEARER_SEND_ACCEPTED;
    raw_result.availability_epoch = state.availability_epoch - 1u;
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(context.bearer,
        NINLIL_BEARER_OK, &raw_result, 1u));
    REQUIRE(send_message(&context, context.a, &first, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(ninlil_test_bearer_permit_fenced_count(context.bearer) >= 2u);

    first.attempt_id.bytes[15] = 27u;
    first.transaction_id.bytes[15] = 27u;
    permit = acquire_permit(&context, &first);
    REQUIRE(context.ops->state(context.ops->user, context.a, &state)
        == NINLIL_BEARER_OK);
    (void)memset(&raw_result, 0, sizeof(raw_result));
    raw_result.abi_version = NINLIL_ABI_VERSION;
    raw_result.struct_size = (uint16_t)sizeof(raw_result);
    raw_result.kind = NINLIL_BEARER_SEND_ACCEPTED;
    raw_result.availability_epoch = state.availability_epoch;
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(context.bearer,
        NINLIL_BEARER_OK, &raw_result, 1u));
    REQUIRE(send_message(&context, context.a, &first, &permit, &result)
        == NINLIL_BEARER_OK);
    REQUIRE(context.ops->receive_next(context.ops->user, context.b,
        &received) == NINLIL_BEARER_OK);
    REQUIRE(received.transaction_id.bytes[15] == 27u);
    context.ops->release_received(context.ops->user, context.b, &received);

    violations = ninlil_test_bearer_violation_count(context.bearer);
    context.ops->close(context.ops->user,
        (ninlil_bearer_handle_t)(uintptr_t)0x12345u);
    REQUIRE(ninlil_test_bearer_violation_count(context.bearer)
        == violations + 1u);
    destroy_context(&context);
    return 0;
}

static int test_open_raw_and_pair_max(void)
{
    ninlil_test_bearer_config_t config;
    ninlil_test_bearer_t *bearer;
    const ninlil_bearer_ops_t *ops;
    ninlil_id128_t a_id = marked_id(0x21u, 1u);
    ninlil_id128_t b_id = marked_id(0x41u, 1u);
    ninlil_bearer_handle_t a = NULL;
    ninlil_bearer_handle_t b = NULL;
    ninlil_bearer_state_t state;
    (void)memset(&config, 0, sizeof(config));
    config.max_entries_per_direction = 4u;
    config.max_bytes_per_direction = 4096u;
    config.max_permits = 8u;
    config.permit_issuer_id = marked_id(0x80u, 1u);
    config.initial_clock_epoch_id = marked_id(0xa0u, 1u);
    bearer = ninlil_test_bearer_create(&config);
    REQUIRE(bearer != NULL);
    ops = ninlil_test_bearer_ops(bearer);
    REQUIRE(ninlil_test_bearer_raw_open_enqueue(bearer,
        NINLIL_BEARER_OK, 1, 1u));
    REQUIRE(ops->open(ops->user, &a_id, NINLIL_ROLE_CONTROLLER, &a)
        == NINLIL_BEARER_OK);
    REQUIRE(a != NULL);
    (void)memset(&state, 0, sizeof(state));
    REQUIRE(ops->state(ops->user, a, &state) == NINLIL_BEARER_OK);
    REQUIRE(state.availability_epoch == 1u && state.available == 0u);
    REQUIRE(ninlil_test_bearer_set_path_epoch_for_test(
        bearer, &a_id, UINT64_MAX));
    REQUIRE(ops->open(ops->user, &b_id, NINLIL_ROLE_ENDPOINT, &b)
        == NINLIL_BEARER_CORRUPT);
    REQUIRE(b == NULL);
    (void)memset(&state, 0xa5, sizeof(state));
    REQUIRE(ops->state(ops->user, a, &state) == NINLIL_BEARER_CORRUPT);
    REQUIRE(memcmp(&state, &(ninlil_bearer_state_t){0}, sizeof(state)) == 0);
    ops->close(ops->user, a);
    ninlil_test_bearer_destroy(bearer);

    bearer = ninlil_test_bearer_create(&config);
    REQUIRE(bearer != NULL);
    ops = ninlil_test_bearer_ops(bearer);
    REQUIRE(ninlil_test_bearer_raw_open_enqueue(bearer,
        NINLIL_BEARER_DENIED, 1, 1u));
    REQUIRE(ops->open(ops->user, &a_id, NINLIL_ROLE_CONTROLLER, &a)
        == NINLIL_BEARER_DENIED);
    REQUIRE(a != NULL);
    (void)memset(&state, 0, sizeof(state));
    REQUIRE(ops->state(ops->user, a, &state) == NINLIL_BEARER_CORRUPT);
    ops->close(ops->user, a);
    ninlil_test_bearer_destroy(bearer);
    return 0;
}

int main(void)
{
    if (test_tb1_accounting_and_tb2_deep_copy() != 0
        || test_tb3_fifo_and_tb6_loan() != 0
        || test_tb4_handles_and_retention() != 0
        || test_tb5_permit_binding() != 0
        || test_tb7_tb8_tb9() != 0
        || test_c1_permit_golden() != 0
        || test_review_regressions() != 0
        || test_open_raw_and_pair_max() != 0) {
        return 1;
    }
    return 0;
}
