#include "resource_ledger_batch.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                        \
                "%s:%d: requirement failed: %s\n",                           \
                __FILE__,                                                      \
                __LINE__,                                                      \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EXPECTED_KIND_MASK ((uint32_t)0x7ffu)

static ninlil_model_resource_ledger_t make_ledger(uint64_t limit)
{
    ninlil_model_capacity_limits_t limits;
    ninlil_model_resource_ledger_t ledger;
    size_t index;

    (void)memset(&limits, 0, sizeof(limits));
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        limits.values[index] = limit;
    }
    (void)memset(&ledger, 0, sizeof(ledger));
    (void)ninlil_model_resource_ledger_init(&limits, &ledger);
    return ledger;
}

static ninlil_model_capacity_batch_input_t make_three_request_input(
    ninlil_model_capacity_batch_operation_t operation,
    uint64_t amount)
{
    static const ninlil_resource_kind_t kinds[] = {
        NINLIL_RESOURCE_TRANSACTION,
        NINLIL_RESOURCE_DELIVERY,
        NINLIL_RESOURCE_EVIDENCE
    };
    ninlil_model_capacity_batch_input_t input;
    size_t index;

    (void)memset(&input, 0, sizeof(input));
    input.current = make_ledger(10u);
    input.operation = operation;
    input.request_count = 3u;
    for (index = 0u; index < 3u; ++index) {
        input.requests[index].kind = kinds[index];
        if (operation == NINLIL_MODEL_CAPACITY_BATCH_RELEASE) {
            input.requests[index].used_release = amount;
        } else {
            input.requests[index].amount = amount;
        }
    }
    return input;
}

static int entry_equals(
    const ninlil_model_capacity_entry_t *left,
    const ninlil_model_capacity_entry_t *right)
{
    return left->kind == right->kind
        && left->limit == right->limit
        && left->used == right->used
        && left->reserved == right->reserved
        && left->high_water == right->high_water
        && left->capacity_epoch == right->capacity_epoch
        && left->blocked == right->blocked
        && left->counter_exhausted_marker
            == right->counter_exhausted_marker;
}

static int ledger_equals(
    const ninlil_model_resource_ledger_t *left,
    const ninlil_model_resource_ledger_t *right)
{
    size_t index;

    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        if (!entry_equals(&left->entries[index], &right->entries[index])) {
            return 0;
        }
    }
    return 1;
}

static int result_is_zero(
    const ninlil_model_capacity_batch_result_t *result)
{
    ninlil_model_capacity_batch_result_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(result, &zero, sizeof(zero)) == 0;
}

static int expect_error(
    ninlil_status_t expected,
    const ninlil_model_capacity_batch_input_t *input)
{
    ninlil_model_capacity_batch_result_t result;

    (void)memset(&result, 0xa5, sizeof(result));
    return ninlil_model_capacity_batch_transition(input, &result) == expected
        && result_is_zero(&result);
}

static uint32_t kind_mask(ninlil_resource_kind_t kind)
{
    return (uint32_t)1u << (kind - 1u);
}

static int test_reserve_failure_at_each_position(void)
{
    size_t failure_index;

    for (failure_index = 0u; failure_index < 3u; ++failure_index) {
        ninlil_model_capacity_batch_input_t input = make_three_request_input(
            NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
            2u);
        ninlil_model_capacity_batch_result_t result;
        ninlil_resource_kind_t failing_kind =
            input.requests[failure_index].kind;
        size_t entry_index = (size_t)(failing_kind - 1u);
        size_t index;

        input.current.entries[entry_index].limit = 1u;
        REQUIRE(ninlil_model_capacity_batch_transition(&input, &result)
            == NINLIL_OK);
        REQUIRE(result.action
            == NINLIL_MODEL_CAPACITY_BATCH_BLOCK_SET_REQUIRED);
        REQUIRE(result.mutation_required == 1u);
        REQUIRE(result.changed_kind_mask == kind_mask(failing_kind));
        REQUIRE(result.failing_request_ordinal
            == (uint32_t)(failure_index + 1u));
        REQUIRE(result.failing_kind == failing_kind);
        REQUIRE(result.failing_entry_action
            == NINLIL_MODEL_CAPACITY_BLOCK_SET_REQUIRED);
        REQUIRE(result.rolled_back_count == (uint32_t)failure_index);
        REQUIRE(result.next.entries[entry_index].blocked == 1u);
        REQUIRE(result.next.entries[entry_index].used == 0u);
        REQUIRE(result.next.entries[entry_index].reserved == 0u);
        REQUIRE(result.next.entries[entry_index].high_water == 0u);

        for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
            if (index == entry_index) {
                ninlil_model_capacity_entry_t expected =
                    input.current.entries[index];

                expected.blocked = 1u;
                REQUIRE(entry_equals(&result.next.entries[index], &expected));
            } else {
                REQUIRE(entry_equals(
                    &result.next.entries[index],
                    &input.current.entries[index]));
            }
        }
    }
    return 0;
}

static int test_reserve_semantic_failures(void)
{
    ninlil_model_capacity_batch_input_t input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        2u);
    ninlil_model_capacity_batch_result_t result;
    size_t failure_entry =
        (size_t)(input.requests[1].kind - 1u);

    input.current.entries[failure_entry].limit = 1u;
    input.current.entries[failure_entry].blocked = 1u;
    REQUIRE(ninlil_model_capacity_batch_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BATCH_ALREADY_BLOCKED);
    REQUIRE(result.mutation_required == 0u);
    REQUIRE(result.changed_kind_mask == 0u);
    REQUIRE(result.rolled_back_count == 1u);
    REQUIRE(result.failing_request_ordinal == 2u);
    REQUIRE(result.failing_entry_action
        == NINLIL_MODEL_CAPACITY_ALREADY_BLOCKED);
    REQUIRE(ledger_equals(&result.next, &input.current));

    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        2u);
    failure_entry = (size_t)(input.requests[2].kind - 1u);
    input.current.entries[failure_entry].capacity_epoch = UINT64_MAX;
    input.current.entries[failure_entry].counter_exhausted_marker = 1u;
    REQUIRE(ninlil_model_capacity_batch_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_CAPACITY_BATCH_COUNTER_EXHAUSTED);
    REQUIRE(result.mutation_required == 0u);
    REQUIRE(result.changed_kind_mask == 0u);
    REQUIRE(result.rolled_back_count == 2u);
    REQUIRE(result.failing_request_ordinal == 3u);
    REQUIRE(result.failing_entry_action
        == NINLIL_MODEL_CAPACITY_COUNTER_EXHAUSTED);
    REQUIRE(ledger_equals(&result.next, &input.current));
    return 0;
}

static int test_reserve_success_and_determinism(void)
{
    ninlil_model_capacity_batch_input_t input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        2u);
    ninlil_model_capacity_batch_result_t first;
    ninlil_model_capacity_batch_result_t second;
    uint32_t expected_mask = kind_mask(input.requests[0].kind)
        | kind_mask(input.requests[1].kind)
        | kind_mask(input.requests[2].kind);
    size_t index;

    input.requests[1].amount = 3u;
    input.requests[2].amount = 4u;
    REQUIRE(ninlil_model_capacity_batch_transition(&input, &first)
        == NINLIL_OK);
    REQUIRE(ninlil_model_capacity_batch_transition(&input, &second)
        == NINLIL_OK);
    REQUIRE(memcmp(&first, &second, sizeof(first)) == 0);
    REQUIRE(first.action == NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED);
    REQUIRE(first.mutation_required == 1u);
    REQUIRE(first.changed_kind_mask == expected_mask);
    REQUIRE(first.unblocked_kind_mask == 0u);
    REQUIRE(first.counter_marker_newly_set_mask == 0u);
    REQUIRE(first.failing_request_ordinal == 0u);
    REQUIRE(first.rolled_back_count == 0u);
    for (index = 0u; index < 3u; ++index) {
        size_t entry_index = (size_t)(input.requests[index].kind - 1u);

        REQUIRE(first.next.entries[entry_index].reserved
            == input.requests[index].amount);
        REQUIRE(first.next.entries[entry_index].high_water
            == input.requests[index].amount);
    }
    return 0;
}

static int test_commit_all_or_none(void)
{
    ninlil_model_capacity_batch_input_t input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED,
        2u);
    ninlil_model_capacity_batch_result_t result;
    ninlil_model_resource_ledger_t before;
    size_t index;

    for (index = 0u; index < 3u; ++index) {
        size_t entry_index = (size_t)(input.requests[index].kind - 1u);

        input.current.entries[entry_index].reserved = 2u;
        input.current.entries[entry_index].high_water = 2u;
    }
    before = input.current;
    REQUIRE(ninlil_model_capacity_batch_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED);
    REQUIRE(result.mutation_required == 1u);
    for (index = 0u; index < 3u; ++index) {
        size_t entry_index = (size_t)(input.requests[index].kind - 1u);

        REQUIRE(result.next.entries[entry_index].used == 2u);
        REQUIRE(result.next.entries[entry_index].reserved == 0u);
        REQUIRE(result.next.entries[entry_index].high_water == 2u);
    }
    REQUIRE(ledger_equals(&input.current, &before));

    input.current = before;
    input.current.entries[input.requests[1].kind - 1u].reserved = 1u;
    input.current.entries[input.requests[1].kind - 1u].high_water = 1u;
    before = input.current;
    REQUIRE(expect_error(NINLIL_E_STORAGE_CORRUPT, &input));
    REQUIRE(ledger_equals(&input.current, &before));
    return 0;
}

static int test_release_all_or_none_and_masks(void)
{
    ninlil_model_capacity_batch_input_t input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RELEASE,
        1u);
    ninlil_model_capacity_batch_result_t result;
    ninlil_model_resource_ledger_t before;
    size_t first_entry = (size_t)(input.requests[0].kind - 1u);
    size_t second_entry = (size_t)(input.requests[1].kind - 1u);
    size_t third_entry = (size_t)(input.requests[2].kind - 1u);
    uint32_t expected_changed = kind_mask(input.requests[0].kind)
        | kind_mask(input.requests[1].kind)
        | kind_mask(input.requests[2].kind);

    input.current.entries[first_entry].used = 2u;
    input.current.entries[first_entry].high_water = 2u;
    input.current.entries[first_entry].blocked = 1u;
    input.requests[0].reopens_blocked_class = 1u;
    input.current.entries[second_entry].used = 2u;
    input.current.entries[second_entry].high_water = 2u;
    input.current.entries[second_entry].blocked = 1u;
    input.current.entries[second_entry].capacity_epoch = UINT64_MAX;
    input.requests[1].reopens_blocked_class = 1u;
    input.current.entries[third_entry].used = 2u;
    input.current.entries[third_entry].high_water = 2u;
    before = input.current;

    REQUIRE(ninlil_model_capacity_batch_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BATCH_ALL_RELEASED);
    REQUIRE(result.mutation_required == 1u);
    REQUIRE(result.changed_kind_mask == expected_changed);
    REQUIRE(result.unblocked_kind_mask
        == (kind_mask(input.requests[0].kind)
            | kind_mask(input.requests[1].kind)));
    REQUIRE(result.counter_marker_newly_set_mask
        == kind_mask(input.requests[1].kind));
    REQUIRE((result.changed_kind_mask & ~EXPECTED_KIND_MASK) == 0u);
    REQUIRE((result.unblocked_kind_mask & ~EXPECTED_KIND_MASK) == 0u);
    REQUIRE((result.counter_marker_newly_set_mask & ~EXPECTED_KIND_MASK)
        == 0u);
    REQUIRE(result.next.entries[first_entry].used == 1u);
    REQUIRE(result.next.entries[first_entry].capacity_epoch == 2u);
    REQUIRE(result.next.entries[first_entry].blocked == 0u);
    REQUIRE(result.next.entries[second_entry].used == 1u);
    REQUIRE(result.next.entries[second_entry].capacity_epoch == UINT64_MAX);
    REQUIRE(result.next.entries[second_entry].blocked == 0u);
    REQUIRE(result.next.entries[second_entry].counter_exhausted_marker == 1u);
    REQUIRE(result.next.entries[third_entry].used == 1u);
    REQUIRE(ledger_equals(&input.current, &before));

    input.current = before;
    input.current.entries[third_entry].used = 0u;
    input.current.entries[third_entry].high_water = 0u;
    before = input.current;
    REQUIRE(expect_error(NINLIL_E_STORAGE_CORRUPT, &input));
    REQUIRE(ledger_equals(&input.current, &before));
    return 0;
}

static int test_count_eleven(void)
{
    ninlil_model_capacity_batch_input_t input;
    ninlil_model_capacity_batch_result_t result;
    size_t index;

    (void)memset(&input, 0, sizeof(input));
    input.current = make_ledger(1u);
    input.operation = NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK;
    input.request_count = NINLIL_MODEL_RESOURCE_KIND_COUNT;
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        input.requests[index].kind = (ninlil_resource_kind_t)(index + 1u);
        input.requests[index].amount = 1u;
    }
    REQUIRE(ninlil_model_capacity_batch_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED);
    REQUIRE(result.changed_kind_mask == EXPECTED_KIND_MASK);

    (void)memset(&input, 0, sizeof(input));
    input.current = make_ledger(1u);
    input.operation = NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK;
    input.request_count = 1u;
    input.requests[0].kind = NINLIL_RESOURCE_SERVICE;
    input.requests[0].amount = 1u;
    REQUIRE(ninlil_model_capacity_batch_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED);
    REQUIRE(result.changed_kind_mask == kind_mask(NINLIL_RESOURCE_SERVICE));
    return 0;
}

static int test_fail_closed_shapes(void)
{
    ninlil_model_capacity_batch_input_t input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    ninlil_model_capacity_batch_result_t result;

    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, NULL));
    REQUIRE(ninlil_model_capacity_batch_transition(&input, NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    input.operation = (ninlil_model_capacity_batch_operation_t)0;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.request_count = 0u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input.request_count = 12u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));

    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.requests[1].kind = input.requests[0].kind;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input.requests[1].kind = NINLIL_RESOURCE_SERVICE;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input.requests[1].kind = (ninlil_resource_kind_t)12u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));

    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.requests[3].amount = 1u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.requests[3].kind = NINLIL_RESOURCE_SERVICE;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.requests[3].reopens_blocked_class = 1u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.requests[3].used_release = 1u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.requests[3].reserved_release = 1u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.requests[0].used_release = 1u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));

    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RELEASE,
        1u);
    input.requests[0].reopens_blocked_class = 2u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RELEASE,
        1u);
    input.requests[0].amount = 1u;
    REQUIRE(expect_error(NINLIL_E_INVALID_ARGUMENT, &input));

    input = make_three_request_input(
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK,
        1u);
    input.current.entries[0].capacity_epoch = 0u;
    REQUIRE(expect_error(NINLIL_E_STORAGE_CORRUPT, &input));

    (void)memset(&result, 0xa5, sizeof(result));
    REQUIRE(ninlil_model_capacity_batch_transition(NULL, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result_is_zero(&result));
    return 0;
}

int main(void)
{
    REQUIRE(test_reserve_failure_at_each_position() == 0);
    REQUIRE(test_reserve_semantic_failures() == 0);
    REQUIRE(test_reserve_success_and_determinism() == 0);
    REQUIRE(test_commit_all_or_none() == 0);
    REQUIRE(test_release_all_or_none_and_masks() == 0);
    REQUIRE(test_count_eleven() == 0);
    REQUIRE(test_fail_closed_shapes() == 0);
    return 0;
}
