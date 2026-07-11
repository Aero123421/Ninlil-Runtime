#ifndef NINLIL_MODEL_DESIRED_TARGET_SNAPSHOT_H
#define NINLIL_MODEL_DESIRED_TARGET_SNAPSHOT_H

#include <ninlil/version.h>

typedef enum ninlil_model_desired_target_state {
    NINLIL_MODEL_DESIRED_TARGET_READY = 1,
    NINLIL_MODEL_DESIRED_TARGET_ATTEMPT_PREPARED = 2,
    NINLIL_MODEL_DESIRED_TARGET_AWAITING_EVIDENCE = 3,
    NINLIL_MODEL_DESIRED_TARGET_RETRY_WAIT = 4,
    NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE = 5,
    NINLIL_MODEL_DESIRED_TARGET_SATISFIED = 6,
    NINLIL_MODEL_DESIRED_TARGET_EXPIRED = 7,
    NINLIL_MODEL_DESIRED_TARGET_CANCELLED_BEFORE_EFFECT = 8,
    NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE = 9,
    NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN = 10
} ninlil_model_desired_target_state_t;

typedef struct ninlil_model_desired_target_snapshot {
    ninlil_model_desired_target_state_t state;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    ninlil_deadline_verdict_t deadline_verdict;
    ninlil_effect_certainty_t effect_certainty;
} ninlil_model_desired_target_snapshot_t;

#endif
