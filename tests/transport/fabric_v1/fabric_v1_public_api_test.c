/* SPDX-License-Identifier: Apache-2.0 */
#include <ninlil/fabric_v1.h>

#include <stdio.h>

#define REQUIRE_EQ(actual, expected)                                           \
    do {                                                                       \
        const uint32_t actual_value = (uint32_t)(actual);                      \
        const uint32_t expected_value = (uint32_t)(expected);                  \
        if (actual_value != expected_value) {                                  \
            (void)fprintf(                                                     \
                stderr,                                                        \
                "%s:%d got %u, expected %u\n",                               \
                __FILE__,                                                      \
                __LINE__,                                                      \
                (unsigned)actual_value,                                        \
                (unsigned)expected_value);                                     \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int verify_catalog_and_allowlist(void)
{
    uint32_t bytes = 0u;
    uint32_t alignment = 0u;

    _Static_assert(NINLIL_FABRIC_OK == 0u, "status catalog");
    _Static_assert(NINLIL_FABRIC_WOULD_BLOCK == 12u, "status catalog");
    _Static_assert(NINLIL_FABRIC_LINK_CORRUPT == 7u, "link catalog");
    _Static_assert(
        NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN == 4u,
        "completion catalog");
    _Static_assert(
        NINLIL_FABRIC_REGISTRY_MAX == 16u,
        "link bound");
    _Static_assert(NINLIL_FABRIC_POLICY_MAX == 64u, "policy bound");
    _Static_assert(
        NINLIL_FABRIC_AUTHORITY_MAX == 64u,
        "authority bound");
    _Static_assert(
        NINLIL_FABRIC_ATTEMPT_MAX == 64u,
        "attempt bound");
    _Static_assert(
        NINLIL_FABRIC_POLICY_CANDIDATES_MAX == 8u,
        "candidate bound");

    REQUIRE_EQ(
        ninlil_fabric_v1_workspace_required(
            NINLIL_FABRIC_PROFILE_1, &bytes, &alignment),
        NINLIL_FABRIC_OK);
    REQUIRE_EQ(bytes, NINLIL_FABRIC_WORKSPACE_BYTES);
    if (alignment < 8u) {
        return 1;
    }
    REQUIRE_EQ(
        ninlil_fabric_v1_workspace_required(0u, &bytes, &alignment),
        NINLIL_FABRIC_UNSUPPORTED);

    /* Every public wrapper is linked and preserves the private null result. */
    REQUIRE_EQ(ninlil_fabric_v1_create(NULL, NULL, 0u, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_bearer_ops(NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_register_link(NULL, NULL, NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_unregister_begin(NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_unregister_poll(NULL, NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_policy_put(NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_policy_remove(NULL, NULL, 0u),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_policy_snapshot(NULL, NULL, 0u, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_authority_put(NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_authority_remove(NULL, NULL, 0u),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_authority_snapshot(NULL, NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_link_snapshot(NULL, NULL, NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_link_availability_update(NULL, NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_metrics_snapshot(NULL, NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_step(NULL, 0u, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_close_begin(NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_close_poll(NULL, NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    REQUIRE_EQ(ninlil_fabric_v1_destroy(NULL),
               NINLIL_FABRIC_INVALID_ARGUMENT);
    return 0;
}

int main(void)
{
    const int result = verify_catalog_and_allowlist();
    if (result == 0) {
        (void)printf("fabric_v1_public_api_test: PASS\n");
    }
    return result;
}
