#ifndef NINLIL_FAMILY_CAPABILITY_MODEL_H
#define NINLIL_FAMILY_CAPABILITY_MODEL_H

/*
 * V1-LAB B5: shared family classification for model/runtime layers.
 * Not public ABI.
 */

#include <ninlil/version.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int ninlil_model_family_is_uplink(ninlil_family_t family)
{
    return family == NINLIL_FAMILY_EVENT_FACT
        || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED;
}

static inline int ninlil_model_family_is_downlink(ninlil_family_t family)
{
    return family == NINLIL_FAMILY_DESIRED_STATE
        || family == NINLIL_FAMILY_TRANSFER_RESERVED
        || family == NINLIL_FAMILY_CONFIG_RESERVED;
}

static inline int ninlil_model_family_is_b5_lab(ninlil_family_t family)
{
    return family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED
        || family == NINLIL_FAMILY_TRANSFER_RESERVED
        || family == NINLIL_FAMILY_CONFIG_RESERVED;
}

static inline int ninlil_model_family_is_admit_supported(ninlil_family_t family)
{
    return ninlil_model_family_is_uplink(family)
        || ninlil_model_family_is_downlink(family);
}

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_FAMILY_CAPABILITY_MODEL_H */
