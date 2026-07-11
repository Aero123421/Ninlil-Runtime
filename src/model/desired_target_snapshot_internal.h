#ifndef NINLIL_MODEL_DESIRED_TARGET_SNAPSHOT_INTERNAL_H
#define NINLIL_MODEL_DESIRED_TARGET_SNAPSHOT_INTERNAL_H

#include "desired_target_snapshot.h"

int ninlil_model_desired_target_state_is_active(
    ninlil_model_desired_target_state_t state);

int ninlil_model_desired_target_state_is_terminal(
    ninlil_model_desired_target_state_t state);

int ninlil_model_desired_target_snapshot_is_valid(
    const ninlil_model_desired_target_snapshot_t *current);

void ninlil_model_desired_target_snapshot_copy(
    ninlil_model_desired_target_snapshot_t *destination,
    const ninlil_model_desired_target_snapshot_t *source);

#endif
