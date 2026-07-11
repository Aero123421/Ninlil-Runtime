#include "resource_ledger.h"

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

static ninlil_model_capacity_entry_t make_entry(
    ninlil_resource_kind_t kind,
    uint64_t limit)
{
    ninlil_model_capacity_entry_t entry;

    (void)memset(&entry, 0, sizeof(entry));
    entry.kind = kind;
    entry.limit = limit;
    entry.capacity_epoch = 1u;
    return entry;
}

static ninlil_model_capacity_transition_input_t make_operation(
    const ninlil_model_capacity_entry_t *current,
    ninlil_model_capacity_operation_t operation)
{
    ninlil_model_capacity_transition_input_t input;

    (void)memset(&input, 0, sizeof(input));
    input.current = *current;
    input.operation = operation;
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

static int transition_result_is_zero(
    const ninlil_model_capacity_transition_result_t *result)
{
    ninlil_model_capacity_transition_result_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(result, &zero, sizeof(zero)) == 0;
}

static int ledger_is_zero(const ninlil_model_resource_ledger_t *ledger)
{
    ninlil_model_resource_ledger_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(ledger, &zero, sizeof(zero)) == 0;
}

static int snapshot_is_zero(
    const ninlil_model_capacity_snapshot_view_t *snapshot)
{
    ninlil_model_capacity_snapshot_view_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(snapshot, &zero, sizeof(zero)) == 0;
}

static int expect_transition_error(
    ninlil_status_t expected,
    const ninlil_model_capacity_transition_input_t *input)
{
    ninlil_model_capacity_transition_result_t result;

    (void)memset(&result, 0xa5, sizeof(result));
    return ninlil_model_capacity_entry_transition(input, &result) == expected
        && transition_result_is_zero(&result);
}

static int apply_amount(
    ninlil_model_capacity_entry_t *entry,
    ninlil_model_capacity_operation_t operation,
    uint64_t amount,
    ninlil_model_capacity_action_t expected_action)
{
    ninlil_model_capacity_transition_input_t input =
        make_operation(entry, operation);
    ninlil_model_capacity_transition_result_t result;

    input.amount = amount;
    if (ninlil_model_capacity_entry_transition(&input, &result) != NINLIL_OK
        || result.action != expected_action) {
        return 0;
    }
    *entry = result.next;
    return 1;
}

static int apply_release(
    ninlil_model_capacity_entry_t *entry,
    uint64_t used_release,
    uint64_t reserved_release,
    uint32_t reopens,
    ninlil_model_capacity_action_t expected_action)
{
    ninlil_model_capacity_transition_input_t input = make_operation(
        entry,
        NINLIL_MODEL_CAPACITY_RELEASE);
    ninlil_model_capacity_transition_result_t result;

    input.used_release = used_release;
    input.reserved_release = reserved_release;
    input.reopens_blocked_class = reopens;
    if (ninlil_model_capacity_entry_transition(&input, &result) != NINLIL_OK
        || result.action != expected_action) {
        return 0;
    }
    *entry = result.next;
    return 1;
}

static int test_eleven_entry_init_and_projection(void)
{
    ninlil_model_capacity_limits_t limits;
    ninlil_model_resource_ledger_t ledger;
    ninlil_model_capacity_snapshot_view_t snapshot;
    size_t index;

    (void)memset(&limits, 0, sizeof(limits));
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        limits.values[index] = index == 3u ? 0u : (uint64_t)(index + 1u) * 10u;
    }

    REQUIRE(ninlil_model_resource_ledger_init(&limits, &ledger) == NINLIL_OK);
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        REQUIRE(ledger.entries[index].kind
            == (ninlil_resource_kind_t)(index + 1u));
        REQUIRE(ledger.entries[index].limit == limits.values[index]);
        REQUIRE(ledger.entries[index].used == 0u);
        REQUIRE(ledger.entries[index].reserved == 0u);
        REQUIRE(ledger.entries[index].high_water == 0u);
        REQUIRE(ledger.entries[index].capacity_epoch == 1u);
        REQUIRE(ledger.entries[index].blocked == 0u);
        REQUIRE(ledger.entries[index].counter_exhausted_marker == 0u);
    }
    REQUIRE(ledger.entries[3].limit == 0u);
    REQUIRE(ledger.entries[3].capacity_epoch == 1u);

    REQUIRE(ninlil_model_resource_ledger_project(&ledger, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.entry_count == NINLIL_MODEL_RESOURCE_KIND_COUNT);
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        REQUIRE(snapshot.entries[index].kind == ledger.entries[index].kind);
        REQUIRE(snapshot.entries[index].limit == ledger.entries[index].limit);
        REQUIRE(snapshot.entries[index].used == ledger.entries[index].used);
        REQUIRE(snapshot.entries[index].reserved
            == ledger.entries[index].reserved);
        REQUIRE(snapshot.entries[index].high_water
            == ledger.entries[index].high_water);
        REQUIRE(snapshot.entries[index].capacity_epoch
            == ledger.entries[index].capacity_epoch);
    }

    (void)memset(&ledger, 0xa5, sizeof(ledger));
    REQUIRE(ninlil_model_resource_ledger_init(NULL, &ledger)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ledger_is_zero(&ledger));
    REQUIRE(ninlil_model_resource_ledger_init(&limits, NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(ninlil_model_resource_ledger_init(&limits, &ledger) == NINLIL_OK);
    ledger.entries[4].kind = NINLIL_RESOURCE_SERVICE;
    (void)memset(&snapshot, 0xa5, sizeof(snapshot));
    REQUIRE(ninlil_model_resource_ledger_project(&ledger, &snapshot)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(snapshot_is_zero(&snapshot));
    REQUIRE(ninlil_model_resource_ledger_project(NULL, &snapshot)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(snapshot_is_zero(&snapshot));
    REQUIRE(ninlil_model_resource_ledger_project(&ledger, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_reserve_commit_release_and_epoch(void)
{
    ninlil_model_capacity_entry_t entry =
        make_entry(NINLIL_RESOURCE_DEFERRED_TOKEN, 10u);
    ninlil_model_capacity_transition_input_t input;
    ninlil_model_capacity_transition_result_t result;
    ninlil_model_capacity_entry_t before;

    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK,
        4u,
        NINLIL_MODEL_CAPACITY_RESERVED));
    REQUIRE(entry.used == 0u && entry.reserved == 4u);
    REQUIRE(entry.high_water == 4u && entry.capacity_epoch == 1u);

    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        3u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(entry.used == 3u && entry.reserved == 1u);
    REQUIRE(entry.high_water == 4u);

    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK,
        6u,
        NINLIL_MODEL_CAPACITY_RESERVED));
    REQUIRE(entry.used == 3u && entry.reserved == 7u);
    REQUIRE(entry.high_water == 10u);

    before = entry;
    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK);
    input.amount = 1u;
    REQUIRE(ninlil_model_capacity_entry_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BLOCK_SET_REQUIRED);
    REQUIRE(result.next.used == before.used);
    REQUIRE(result.next.reserved == before.reserved);
    REQUIRE(result.next.high_water == before.high_water);
    REQUIRE(result.next.capacity_epoch == before.capacity_epoch);
    REQUIRE(result.next.blocked == 1u);
    entry = result.next;

    input.current = entry;
    REQUIRE(ninlil_model_capacity_entry_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_ALREADY_BLOCKED);
    REQUIRE(entry_equals(&result.next, &entry));

    REQUIRE(apply_release(
        &entry,
        1u,
        0u,
        0u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(entry.used == 2u && entry.reserved == 7u);
    REQUIRE(entry.blocked == 1u && entry.capacity_epoch == 1u);
    REQUIRE(entry.high_water == 10u);

    REQUIRE(apply_release(
        &entry,
        0u,
        1u,
        1u,
        NINLIL_MODEL_CAPACITY_RELEASED_AND_UNBLOCKED));
    REQUIRE(entry.used == 2u && entry.reserved == 6u);
    REQUIRE(entry.blocked == 0u && entry.capacity_epoch == 2u);
    REQUIRE(entry.high_water == 10u);

    REQUIRE(apply_release(
        &entry,
        1u,
        0u,
        1u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(entry.capacity_epoch == 2u);
    REQUIRE(entry.high_water == 10u);
    return 0;
}

static int test_epoch_max_marker(void)
{
    ninlil_model_capacity_entry_t entry =
        make_entry(NINLIL_RESOURCE_EVIDENCE, 2u);
    ninlil_model_capacity_transition_input_t input;
    ninlil_model_capacity_transition_result_t result;
    ninlil_model_capacity_entry_t before;

    entry.used = 1u;
    entry.reserved = 1u;
    entry.high_water = 2u;
    entry.capacity_epoch = UINT64_MAX;
    entry.blocked = 1u;

    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RELEASE);
    input.used_release = 1u;
    input.reopens_blocked_class = 1u;
    REQUIRE(ninlil_model_capacity_entry_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_CAPACITY_RELEASED_EPOCH_EXHAUSTED);
    REQUIRE(result.next.used == 0u && result.next.reserved == 1u);
    REQUIRE(result.next.blocked == 0u);
    REQUIRE(result.next.capacity_epoch == UINT64_MAX);
    REQUIRE(result.next.counter_exhausted_marker == 1u);
    REQUIRE(result.counter_exhausted_marker_newly_set == 1u);
    entry = result.next;

    before = entry;
    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK);
    input.amount = 1u;
    REQUIRE(ninlil_model_capacity_entry_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_COUNTER_EXHAUSTED);
    REQUIRE(entry_equals(&result.next, &before));

    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        1u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(entry.used == 1u && entry.reserved == 0u);
    REQUIRE(entry.counter_exhausted_marker == 1u);
    REQUIRE(apply_release(
        &entry,
        1u,
        0u,
        1u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(entry.used == 0u && entry.capacity_epoch == UINT64_MAX);
    REQUIRE(entry.counter_exhausted_marker == 1u);
    return 0;
}

static int test_deferred_token_improvement_epoch(void)
{
    ninlil_model_capacity_entry_t entry =
        make_entry(NINLIL_RESOURCE_DEFERRED_TOKEN, 32u);
    ninlil_model_capacity_transition_input_t input;
    ninlil_model_capacity_transition_result_t result;

    entry.used = 32u;
    entry.high_water = 32u;
    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK);
    input.amount = 1u;
    REQUIRE(ninlil_model_capacity_entry_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BLOCK_SET_REQUIRED);
    REQUIRE(result.next.blocked == 1u);
    entry = result.next;

    REQUIRE(apply_release(
        &entry,
        1u,
        0u,
        1u,
        NINLIL_MODEL_CAPACITY_RELEASED_AND_UNBLOCKED));
    REQUIRE(entry.used == 31u);
    REQUIRE(entry.capacity_epoch == 2u && entry.blocked == 0u);
    REQUIRE(entry.high_water == 32u);

    REQUIRE(apply_release(
        &entry,
        1u,
        0u,
        1u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(entry.used == 30u && entry.capacity_epoch == 2u);
    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK,
        2u,
        NINLIL_MODEL_CAPACITY_RESERVED));
    REQUIRE(entry.used == 30u && entry.reserved == 2u);

    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK);
    input.amount = 1u;
    REQUIRE(ninlil_model_capacity_entry_transition(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_CAPACITY_BLOCK_SET_REQUIRED);
    entry = result.next;
    REQUIRE(apply_release(
        &entry,
        0u,
        1u,
        1u,
        NINLIL_MODEL_CAPACITY_RELEASED_AND_UNBLOCKED));
    REQUIRE(entry.capacity_epoch == 3u && entry.blocked == 0u);
    return 0;
}

static int test_fail_closed(void)
{
    ninlil_model_capacity_entry_t entry =
        make_entry(NINLIL_RESOURCE_TRANSACTION, 10u);
    ninlil_model_capacity_transition_input_t input;
    ninlil_model_capacity_transition_result_t result;

    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK);
    input.amount = 1u;
    REQUIRE(expect_transition_error(NINLIL_E_INVALID_ARGUMENT, NULL));
    REQUIRE(ninlil_model_capacity_entry_transition(&input, NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    input.operation = (ninlil_model_capacity_operation_t)0;
    REQUIRE(expect_transition_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input.operation = (ninlil_model_capacity_operation_t)4;
    REQUIRE(expect_transition_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK);
    REQUIRE(expect_transition_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input.amount = 1u;
    input.used_release = 1u;
    REQUIRE(expect_transition_error(NINLIL_E_INVALID_ARGUMENT, &input));

    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RELEASE);
    REQUIRE(expect_transition_error(NINLIL_E_INVALID_ARGUMENT, &input));
    input.used_release = 1u;
    input.reopens_blocked_class = 2u;
    REQUIRE(expect_transition_error(NINLIL_E_INVALID_ARGUMENT, &input));

    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_COMMIT_RESERVED);
    input.amount = 1u;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));
    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RELEASE);
    input.used_release = 1u;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));

    entry.kind = (ninlil_resource_kind_t)0u;
    input = make_operation(&entry, NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK);
    input.amount = 1u;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));

    entry = make_entry(NINLIL_RESOURCE_TRANSACTION, 10u);
    entry.used = 8u;
    entry.reserved = 3u;
    entry.high_water = 10u;
    input.current = entry;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));
    entry.reserved = 2u;
    entry.high_water = 9u;
    input.current = entry;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));
    entry.high_water = 11u;
    input.current = entry;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));
    entry.high_water = 10u;
    entry.capacity_epoch = 0u;
    input.current = entry;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));

    entry = make_entry(NINLIL_RESOURCE_TRANSACTION, 10u);
    entry.counter_exhausted_marker = 1u;
    input.current = entry;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));
    entry.capacity_epoch = UINT64_MAX;
    entry.blocked = 1u;
    input.current = entry;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));

    entry = make_entry(NINLIL_RESOURCE_TRANSACTION, UINT64_MAX);
    entry.used = UINT64_MAX;
    entry.reserved = 1u;
    entry.high_water = UINT64_MAX;
    input.current = entry;
    REQUIRE(expect_transition_error(NINLIL_E_STORAGE_CORRUPT, &input));

    (void)memset(&result, 0xa5, sizeof(result));
    REQUIRE(ninlil_model_capacity_entry_transition(NULL, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(transition_result_is_zero(&result));
    return 0;
}

static int test_uint64_boundary(void)
{
    ninlil_model_capacity_entry_t entry =
        make_entry(NINLIL_RESOURCE_OUTBOX_BYTES, UINT64_MAX);

    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK,
        UINT64_MAX,
        NINLIL_MODEL_CAPACITY_RESERVED));
    REQUIRE(entry.reserved == UINT64_MAX);
    REQUIRE(entry.high_water == UINT64_MAX);
    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        UINT64_MAX,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(entry.used == UINT64_MAX && entry.reserved == 0u);
    REQUIRE(apply_release(
        &entry,
        UINT64_MAX,
        0u,
        0u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(entry.used == 0u && entry.high_water == UINT64_MAX);
    return 0;
}

static int test_event_spool_portable_lifecycle(void)
{
    ninlil_model_capacity_entry_t receipt_entry =
        make_entry(NINLIL_RESOURCE_EVENT_SPOOL_BYTES, 3000u);
    ninlil_model_capacity_entry_t discard_entry;

    REQUIRE(apply_amount(
        &receipt_entry,
        NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK,
        2570u,
        NINLIL_MODEL_CAPACITY_RESERVED));
    REQUIRE(apply_amount(
        &receipt_entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        10u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(receipt_entry.used == 10u && receipt_entry.reserved == 2560u);
    REQUIRE(apply_amount(
        &receipt_entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        256u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(apply_amount(
        &receipt_entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        256u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(receipt_entry.used == 522u && receipt_entry.reserved == 2048u);
    REQUIRE(receipt_entry.high_water == 2570u);

    discard_entry = receipt_entry;
    REQUIRE(apply_release(
        &receipt_entry,
        10u,
        2048u,
        0u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(receipt_entry.used == 512u && receipt_entry.reserved == 0u);
    REQUIRE(receipt_entry.high_water == 2570u);
    REQUIRE(apply_release(
        &receipt_entry,
        512u,
        0u,
        0u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(receipt_entry.used == 0u && receipt_entry.reserved == 0u);

    REQUIRE(apply_amount(
        &discard_entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        512u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(apply_release(
        &discard_entry,
        10u,
        1536u,
        0u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(discard_entry.used == 1024u && discard_entry.reserved == 0u);
    REQUIRE(discard_entry.high_water == 2570u);
    return 0;
}

static int test_evidence_lifecycle(void)
{
    ninlil_model_capacity_entry_t entry =
        make_entry(NINLIL_RESOURCE_EVIDENCE, 9u);
    ninlil_model_capacity_entry_t terminal;

    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK,
        9u,
        NINLIL_MODEL_CAPACITY_RESERVED));
    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        1u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(entry.used == 1u && entry.reserved == 8u);
    REQUIRE(apply_amount(
        &entry,
        NINLIL_MODEL_CAPACITY_COMMIT_RESERVED,
        3u,
        NINLIL_MODEL_CAPACITY_COMMITTED));
    REQUIRE(entry.used == 4u && entry.reserved == 5u);
    terminal = entry;
    REQUIRE(entry_equals(&terminal, &entry));
    REQUIRE(apply_release(
        &terminal,
        4u,
        5u,
        0u,
        NINLIL_MODEL_CAPACITY_RELEASED));
    REQUIRE(terminal.used == 0u && terminal.reserved == 0u);
    REQUIRE(terminal.high_water == 9u);
    return 0;
}

int main(void)
{
    REQUIRE(test_eleven_entry_init_and_projection() == 0);
    REQUIRE(test_reserve_commit_release_and_epoch() == 0);
    REQUIRE(test_epoch_max_marker() == 0);
    REQUIRE(test_deferred_token_improvement_epoch() == 0);
    REQUIRE(test_fail_closed() == 0);
    REQUIRE(test_uint64_boundary() == 0);
    REQUIRE(test_event_spool_portable_lifecycle() == 0);
    REQUIRE(test_evidence_lifecycle() == 0);
    return 0;
}
