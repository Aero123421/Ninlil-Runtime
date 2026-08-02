#include "composition_v1_test_fixture.h"

#include <stdio.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__,       \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int bytes_are_zero(const void *bytes, uint32_t length)
{
    const uint8_t *value = (const uint8_t *)bytes;
    uint32_t index;

    for (index = 0u; index < length; ++index) {
        if (value[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    static const uint8_t storage_namespace[] = "composition-create";
    composition_test_fixture_t fixture;
    ninlil_composition_v1_t *composition = NULL;
    ninlil_runtime_t *runtime = NULL;
    ninlil_fabric_v1_t *fabric = NULL;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t invalid_config;
    ninlil_bearer_ops_t caller_bearer;
    uint32_t required_bytes = 7u;
    uint32_t required_alignment = 9u;
    uint64_t opens_before;

    REQUIRE(ninlil_composition_v1_workspace_required(
                99u, &required_bytes, &required_alignment)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(required_bytes == 0u && required_alignment == 0u);
    REQUIRE(ninlil_composition_v1_workspace_required(
                NINLIL_COMPOSITION_PROFILE_1, NULL, &required_alignment)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_composition_v1_workspace_required(
                NINLIL_COMPOSITION_PROFILE_1,
                &required_bytes,
                &required_alignment)
        == NINLIL_OK);
    REQUIRE(required_bytes > NINLIL_FABRIC_WORKSPACE_BYTES);
    REQUIRE(required_alignment >= _Alignof(max_align_t));

    REQUIRE(composition_test_fixture_init(
        &fixture,
        NULL,
        0x10u,
        storage_namespace,
        (uint32_t)sizeof(storage_namespace) - 1u));
    opens_before = ninlil_test_storage_call_count(
        fixture.storage, NINLIL_TEST_STORAGE_OP_OPEN);

    composition = (ninlil_composition_v1_t *)fixture.workspace;
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes,
                NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_composition_v1_create(
                99u,
                &fixture.config,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(composition == NULL);
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                NULL,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                NULL,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &fixture.platform,
                NULL,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_INVALID_ARGUMENT);

    platform = fixture.platform;
    (void)memset(&caller_bearer, 0, sizeof(caller_bearer));
    platform.bearer = &caller_bearer;
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &platform,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes - 1u,
                &composition)
        == NINLIL_E_CAPACITY_EXHAUSTED);
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &fixture.platform,
                (uint8_t *)fixture.workspace + 1u,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_INVALID_ARGUMENT);

    invalid_config = fixture.config;
    invalid_config.reserved_zero = 1u;
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &invalid_config,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_test_storage_call_count(
                fixture.storage, NINLIL_TEST_STORAGE_OP_OPEN)
        == opens_before);

    /* Fabric opens first; a Runtime allocation failure must unwind it. */
    ninlil_test_allocator_fail_next(fixture.allocator, 1u);
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_E_CAPACITY_EXHAUSTED);
    REQUIRE(composition == NULL);
    REQUIRE(ninlil_test_storage_live_handles(fixture.storage) == 0u);
    REQUIRE(bytes_are_zero(fixture.workspace, fixture.workspace_bytes));

    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_OK);
    REQUIRE(composition != NULL);
    REQUIRE(ninlil_composition_v1_runtime(composition, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_composition_v1_fabric(composition, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_composition_v1_runtime(composition, &runtime) == NINLIL_OK);
    REQUIRE(ninlil_composition_v1_fabric(composition, &fabric) == NINLIL_OK);
    REQUIRE(runtime != NULL && fabric != NULL);

    ninlil_test_execution_set_context_id(fixture.execution, 2u);
    runtime = (ninlil_runtime_t *)fixture.workspace;
    fabric = (ninlil_fabric_v1_t *)fixture.workspace;
    REQUIRE(ninlil_composition_v1_runtime(composition, &runtime)
        == NINLIL_E_WRONG_THREAD);
    REQUIRE(runtime == NULL);
    REQUIRE(ninlil_composition_v1_fabric(composition, &fabric)
        == NINLIL_E_WRONG_THREAD);
    REQUIRE(fabric == NULL);
    ninlil_test_execution_set_context_id(fixture.execution, 1u);

    REQUIRE(composition_test_fixture_release_composition(
        &fixture, composition));
    composition_test_fixture_destroy(&fixture);
    (void)printf("composition_v1_create_test: PASS\n");
    return 0;
}
