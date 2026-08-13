/* SPDX-License-Identifier: Apache-2.0 */
#include "runtime_v1_target_resolver.h"

#include <stdint.h>
#include <string.h>

static int id_equal(
    const ninlil_id128_t *left,
    const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int target_is_terminal(const ninlil_rt_target_slot_t *target)
{
    return target->terminal != 0u
        && target->outcome != NINLIL_OUTCOME_NONE;
}

static int target_timer_due(
    const ninlil_rt_target_slot_t *target,
    const ninlil_time_sample_t *clock_sample)
{
    return target->next_retry_ms == 0u
        || (clock_sample != NULL
            && id_equal(
                &target->next_retry_clock_epoch_id,
                &clock_sample->clock_epoch_id)
            && clock_sample->now_ms >= target->next_retry_ms);
}

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
    left_buf[32] = (uint8_t)(left->flags >> 24);
    left_buf[33] = (uint8_t)(left->flags >> 16);
    left_buf[34] = (uint8_t)(left->flags >> 8);
    left_buf[35] = (uint8_t)left->flags;
    (void)memcpy(left_buf + 36u, left->device_id.bytes, 16u);
    (void)memcpy(left_buf + 52u, left->installation_id.bytes, 16u);
    (void)memcpy(left_buf + 68u, left->site_domain_id.bytes, 16u);
    (void)memcpy(right_buf, right->target_runtime_id.bytes, 16u);
    (void)memcpy(right_buf + 16u, right->target_application_instance_id.bytes, 16u);
    right_buf[32] = (uint8_t)(right->flags >> 24);
    right_buf[33] = (uint8_t)(right->flags >> 16);
    right_buf[34] = (uint8_t)(right->flags >> 8);
    right_buf[35] = (uint8_t)right->flags;
    (void)memcpy(right_buf + 36u, right->device_id.bytes, 16u);
    (void)memcpy(right_buf + 52u, right->installation_id.bytes, 16u);
    (void)memcpy(right_buf + 68u, right->site_domain_id.bytes, 16u);
    for (index = 0u; index < 8u; ++index) {
        left_buf[84u + index] =
            (uint8_t)(left->binding_epoch >> (56u - index * 8u));
        left_buf[92u + index] =
            (uint8_t)(left->membership_epoch >> (56u - index * 8u));
        right_buf[84u + index] =
            (uint8_t)(right->binding_epoch >> (56u - index * 8u));
        right_buf[92u + index] =
            (uint8_t)(right->membership_epoch >> (56u - index * 8u));
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
        ninlil_rt_v1_initialize_target_state(
            &out_result->targets[out_count],
            descriptor->family);
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
    uint32_t active = 0u;
    uint32_t failed = 0u;
    uint32_t expired = 0u;
    uint32_t cancelled = 0u;
    uint32_t superseded = 0u;
    uint32_t unknown = 0u;
    ninlil_reason_t first_failed_reason = NINLIL_REASON_NONE;
    ninlil_reason_t first_expired_reason = NINLIL_REASON_NONE;
    ninlil_reason_t first_cancelled_reason = NINLIL_REASON_NONE;

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
        if (!target_is_terminal(slot)) {
            active += 1u;
        } else if (slot->outcome == NINLIL_OUTCOME_SATISFIED) {
            satisfied += 1u;
        } else if (slot->outcome == NINLIL_OUTCOME_UNKNOWN) {
            unknown += 1u;
        } else if (slot->outcome == NINLIL_OUTCOME_FAILED_DEFINITIVE) {
            failed += 1u;
            if (first_failed_reason == NINLIL_REASON_NONE) {
                first_failed_reason = slot->reason;
            }
        } else if (slot->outcome == NINLIL_OUTCOME_EXPIRED) {
            expired += 1u;
            if (first_expired_reason == NINLIL_REASON_NONE) {
                first_expired_reason = slot->reason;
            }
        } else if (slot->outcome
            == NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT) {
            cancelled += 1u;
            if (first_cancelled_reason == NINLIL_REASON_NONE) {
                first_cancelled_reason = slot->reason;
            }
        } else if (slot->outcome
            == NINLIL_OUTCOME_SUPERSEDED_RESERVED) {
            superseded += 1u;
        } else {
            unknown += 1u;
        }
    }

    if (active != 0u) {
        return;
    }
    if (satisfied == txn->bound_target_count) {
        if (out_outcome != NULL) {
            *out_outcome = NINLIL_OUTCOME_SATISFIED;
        }
        if (out_reason != NULL) {
            *out_reason = NINLIL_REASON_REQUIRED_EVIDENCE_MET;
        }
        return;
    }
    if (unknown != 0u) {
        if (out_outcome != NULL) {
            *out_outcome = NINLIL_OUTCOME_UNKNOWN;
        }
        if (out_reason != NULL) {
            *out_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        }
        return;
    }
    if (failed != 0u) {
        if (out_outcome != NULL) {
            *out_outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
        }
        if (out_reason != NULL) {
            *out_reason =
                failed == txn->bound_target_count
                ? first_failed_reason
                : NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT;
        }
        return;
    }
    if (expired != 0u) {
        if (out_outcome != NULL) {
            *out_outcome = NINLIL_OUTCOME_EXPIRED;
        }
        if (out_reason != NULL) {
            *out_reason =
                expired == txn->bound_target_count
                ? first_expired_reason
                : NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT;
        }
        return;
    }
    if (cancelled == txn->bound_target_count) {
        if (out_outcome != NULL) {
            *out_outcome = NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT;
        }
        if (out_reason != NULL) {
            *out_reason = first_cancelled_reason;
        }
        return;
    }
    if (superseded == txn->bound_target_count) {
        if (out_outcome != NULL) {
            *out_outcome = NINLIL_OUTCOME_SUPERSEDED_RESERVED;
        }
        if (out_reason != NULL) {
            *out_reason =
                NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION;
        }
        return;
    }
    if (out_outcome != NULL) {
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

void ninlil_rt_v1_initialize_target_state(
    ninlil_rt_target_slot_t *target,
    ninlil_family_t family)
{
    ninlil_concrete_target_t concrete;
    uint8_t in_use;

    if (target == NULL) {
        return;
    }
    concrete = target->target;
    in_use = target->in_use;
    (void)memset(target, 0, sizeof(*target));
    target->in_use = in_use;
    target->pending_dispatch = in_use != 0u ? 1u : 0u;
    target->delivery_phase =
        in_use != 0u
        ? NINLIL_RT_DELIVERY_QUEUED
        : NINLIL_RT_DELIVERY_NONE;
    target->target = concrete;
    target->latest_evidence = NINLIL_EVIDENCE_NONE;
    target->deadline_verdict =
        family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_DEADLINE_NOT_APPLICABLE
        : NINLIL_DEADLINE_PENDING;
    target->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
}

int ninlil_rt_v1_active_target(
    const ninlil_rt_transaction_slot_t *txn,
    uint32_t *out_index)
{
    uint32_t index;

    if (txn == NULL
        || txn->active_target_index >= txn->bound_target_count
        || txn->active_target_index
            >= NINLIL_RT_V1_MAX_TARGETS_PER_TXN) {
        return 0;
    }
    index = txn->active_target_index;
    if (txn->bound_targets[index].in_use == 0u
        || target_is_terminal(&txn->bound_targets[index])) {
        return 0;
    }
    if (out_index != NULL) {
        *out_index = index;
    }
    return 1;
}

void ninlil_rt_v1_activate_target(
    ninlil_rt_transaction_slot_t *txn,
    uint32_t target_index)
{
    ninlil_rt_target_slot_t *target;

    if (txn == NULL || target_index >= txn->bound_target_count
        || target_index >= NINLIL_RT_V1_MAX_TARGETS_PER_TXN
        || txn->bound_targets[target_index].in_use == 0u
        || target_is_terminal(&txn->bound_targets[target_index])) {
        return;
    }
    target = &txn->bound_targets[target_index];
    txn->active_target_index = target_index;
    txn->attempt_prepared = target->attempt_prepared;
    txn->attempt_id = target->active_attempt_id;
    txn->retry_budget = target->retry_budget;
    txn->next_retry_ms = target->next_retry_ms;
    txn->next_retry_clock_epoch_id =
        target->next_retry_clock_epoch_id;
    txn->send_observation_closed =
        target->send_observation_closed;
    txn->send_observed_at_ms = target->send_observed_at_ms;
    txn->send_observed_clock_epoch_id =
        target->send_observed_clock_epoch_id;
    txn->delivery_phase = target->delivery_phase;
    txn->pending_dispatch = target->pending_dispatch;
}

int ninlil_rt_v1_select_dispatch_target(
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *out_index)
{
    uint32_t index;
    uint32_t current;

    if (txn == NULL || txn->family != NINLIL_FAMILY_DESIRED_STATE) {
        return 0;
    }
    if (ninlil_rt_v1_active_target(txn, &current)
        && (txn->bound_targets[current].attempt_prepared != 0u
            || txn->bound_targets[current].send_observation_closed != 0u
            || txn->receipt_pending != 0u)) {
        if (out_index != NULL) {
            *out_index = current;
        }
        return 1;
    }
    for (index = 0u; index < txn->bound_target_count; ++index) {
        ninlil_rt_target_slot_t *target = &txn->bound_targets[index];

        if (target->in_use == 0u || target_is_terminal(target)
            || target->pending_dispatch == 0u
            || !target_timer_due(target, clock_sample)) {
            continue;
        }
        ninlil_rt_v1_activate_target(txn, index);
        if (out_index != NULL) {
            *out_index = index;
        }
        return 1;
    }
    return 0;
}

void ninlil_rt_v1_refresh_target_aggregate(
    ninlil_rt_transaction_slot_t *txn)
{
    ninlil_outcome_t aggregate_outcome = NINLIL_OUTCOME_NONE;
    ninlil_reason_t aggregate_reason = NINLIL_REASON_NONE;
    ninlil_evidence_stage_t latest = NINLIL_EVIDENCE_NONE;
    uint32_t index;
    uint32_t pending = 0u;
    uint32_t has_late_evidence = 0u;

    if (txn == NULL || txn->family != NINLIL_FAMILY_DESIRED_STATE
        || txn->origin_admission == 0u) {
        return;
    }
    for (index = 0u; index < txn->bound_target_count; ++index) {
        const ninlil_rt_target_slot_t *target =
            &txn->bound_targets[index];

        if (target->in_use == 0u) {
            continue;
        }
        if (target->latest_evidence > latest) {
            latest = target->latest_evidence;
        }
        if (target->has_late_evidence != 0u) {
            has_late_evidence = 1u;
        }
        if (!target_is_terminal(target)
            && target->pending_dispatch != 0u) {
            pending = 1u;
        }
    }
    txn->latest_evidence = latest;
    txn->has_late_evidence = has_late_evidence;
    txn->evidence_recorded =
        ninlil_rt_v1_all_targets_evidence_recorded(txn) ? 1u : 0u;
    ninlil_rt_v1_aggregate_target_outcomes(
        txn, &aggregate_outcome, &aggregate_reason);
    if (aggregate_outcome != NINLIL_OUTCOME_NONE) {
        txn->terminal = 1u;
        txn->outcome_recorded = 1u;
        txn->outcome = aggregate_outcome;
        txn->reason = aggregate_reason;
        txn->pending_dispatch = 0u;
        txn->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        txn->active_target_index = NINLIL_RT_V1_NO_ACTIVE_TARGET;
        txn->attempt_prepared = 0u;
        (void)memset(&txn->attempt_id, 0, sizeof(txn->attempt_id));
        txn->next_retry_ms = 0u;
        (void)memset(
            &txn->next_retry_clock_epoch_id,
            0,
            sizeof(txn->next_retry_clock_epoch_id));
        txn->send_observation_closed = 0u;
        txn->send_observed_at_ms = 0u;
        (void)memset(
            &txn->send_observed_clock_epoch_id,
            0,
            sizeof(txn->send_observed_clock_epoch_id));
        return;
    }
    txn->terminal = 0u;
    txn->outcome_recorded = 0u;
    txn->outcome = NINLIL_OUTCOME_NONE;
    txn->reason = NINLIL_REASON_NONE;
    if (!ninlil_rt_v1_active_target(txn, NULL)) {
        txn->active_target_index = NINLIL_RT_V1_NO_ACTIVE_TARGET;
        txn->attempt_prepared = 0u;
        (void)memset(&txn->attempt_id, 0, sizeof(txn->attempt_id));
        txn->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
        txn->pending_dispatch = pending;
    }
}
