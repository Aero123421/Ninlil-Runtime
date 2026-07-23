#include "runtime_v1_target_resolver.h"

#include <string.h>

static int target_less(
    const ninlil_concrete_target_t *left,
    const ninlil_concrete_target_t *right)
{
    uint8_t left_buf[100];
    uint8_t right_buf[100];
    uint32_t index;

    (void)memset(left_buf, 0, sizeof(left_buf));
    (void)memset(right_buf, 0, sizeof(right_buf));
    (void)memcpy(left_buf, left->target_runtime_id.bytes, 16u);
    (void)memcpy(left_buf + 16u, left->target_application_instance_id.bytes, 16u);
    (void)memcpy(right_buf, right->target_runtime_id.bytes, 16u);
    (void)memcpy(right_buf + 16u, right->target_application_instance_id.bytes, 16u);
    for (index = 32u; index < 100u; ++index) {
        left_buf[index] = 0u;
        right_buf[index] = 0u;
    }
    return memcmp(left_buf, right_buf, 100u);
}

ninlil_status_t ninlil_rt_v1_resolve_submission_targets(
    const ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_submission_t *submission,
    ninlil_rt_target_resolve_result_t *out_result)
{
    uint32_t max_targets;
    uint32_t index;
    uint32_t out_count = 0u;

    if (runtime == NULL || descriptor == NULL || submission == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (submission->target_count == 0u || submission->targets == NULL) {
        out_result->reject_reason = NINLIL_REASON_TARGET_COUNT_UNSUPPORTED;
        return NINLIL_OK;
    }

    max_targets = descriptor->target_limit;
    if (max_targets > runtime->config.limits.max_targets_per_transaction) {
        max_targets = runtime->config.limits.max_targets_per_transaction;
    }
    if (max_targets > NINLIL_RT_V1_MAX_TARGETS_PER_TXN) {
        max_targets = NINLIL_RT_V1_MAX_TARGETS_PER_TXN;
    }
    if (submission->target_count > max_targets) {
        out_result->reject_reason = NINLIL_REASON_TARGET_COUNT_UNSUPPORTED;
        return NINLIL_OK;
    }

    for (index = 0u; index < submission->target_count; ++index) {
        uint32_t scan;
        for (scan = 0u; scan < out_count; ++scan) {
            if (target_less(
                    &submission->targets[index],
                    &out_result->targets[scan].target)
                == 0) {
                out_result->reject_reason = NINLIL_REASON_TARGET_COUNT_UNSUPPORTED;
                return NINLIL_OK;
            }
        }
        out_result->targets[out_count].in_use = 1u;
        out_result->targets[out_count].pending_dispatch = 1u;
        out_result->targets[out_count].target = submission->targets[index];
        out_result->targets[out_count].outcome = NINLIL_OUTCOME_NONE;
        out_result->targets[out_count].reason = NINLIL_REASON_NONE;
        out_count += 1u;
    }

    for (index = 0u; index < out_count; ++index) {
        uint32_t best = index;
        uint32_t scan;
        for (scan = index + 1u; scan < out_count; ++scan) {
            if (target_less(
                    &out_result->targets[scan].target,
                    &out_result->targets[best].target)
                < 0) {
                best = scan;
            }
        }
        if (best != index) {
            ninlil_rt_target_slot_t tmp = out_result->targets[index];
            out_result->targets[index] = out_result->targets[best];
            out_result->targets[best] = tmp;
        }
    }

    out_result->target_count = out_count;
    return NINLIL_OK;
}

void ninlil_rt_v1_aggregate_target_outcomes(
    ninlil_rt_transaction_slot_t *txn,
    ninlil_outcome_t *out_outcome,
    ninlil_reason_t *out_reason)
{
    uint32_t index;
    uint32_t satisfied = 0u;
    uint32_t failed = 0u;
    uint32_t active = 0u;

    if (out_outcome != NULL) {
        *out_outcome = NINLIL_OUTCOME_NONE;
    }
    if (out_reason != NULL) {
        *out_reason = NINLIL_REASON_NONE;
    }
    if (txn == NULL || txn->bound_target_count == 0u) {
        return;
    }

    for (index = 0u; index < txn->bound_target_count; ++index) {
        const ninlil_rt_target_slot_t *slot = &txn->bound_targets[index];
        if (slot->in_use == 0u) {
            continue;
        }
        if (slot->outcome == NINLIL_OUTCOME_SATISFIED) {
            satisfied += 1u;
        } else if (slot->outcome == NINLIL_OUTCOME_FAILED_DEFINITIVE
            || slot->outcome == NINLIL_OUTCOME_EXPIRED) {
            failed += 1u;
        } else {
            active += 1u;
        }
    }

    if (active != 0u) {
        return;
    }
    if (satisfied == txn->bound_target_count) {
        if (out_outcome != NULL) {
            *out_outcome = NINLIL_OUTCOME_SATISFIED;
        }
        return;
    }
    if (failed != 0u || satisfied != txn->bound_target_count) {
        *out_outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
    }
    if (out_reason != NULL) {
        *out_reason = NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT;
    }
}

int ninlil_rt_v1_all_targets_evidence_recorded(
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    if (txn == NULL || txn->bound_target_count == 0u) {
        return 0;
    }
    for (index = 0u; index < txn->bound_target_count; ++index) {
        if (txn->bound_targets[index].in_use == 0u) {
            continue;
        }
        if (txn->bound_targets[index].evidence_recorded == 0u) {
            return 0;
        }
    }
    return 1;
}
