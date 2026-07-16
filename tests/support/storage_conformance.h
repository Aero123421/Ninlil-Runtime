#ifndef NINLIL_TEST_STORAGE_CONFORMANCE_H
#define NINLIL_TEST_STORAGE_CONFORMANCE_H

#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Provider-neutral, success-path subset of the normative Storage Port
 * contract. The provider owns ops/user for the duration of this call and the
 * supplied namespace must be unused in that provider instance.
 */
int ninlil_test_storage_conformance_run(
    const ninlil_storage_ops_t *ops,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    uint32_t expected_schema);

#ifdef __cplusplus
}
#endif

#endif
