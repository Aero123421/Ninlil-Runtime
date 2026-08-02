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

int main(void)
{
    static const uint8_t namespace_a[] = "composition-a";
    static const uint8_t namespace_b[] = "composition-b";
    /* Independent SHA-256 KATs for ADR-0032 NCS1/domain=1 material. */
    static const uint8_t derived_a[32] = {
        0xcau, 0x40u, 0x7eu, 0xaeu, 0xcbu, 0x95u, 0x05u, 0xe5u,
        0xc3u, 0x62u, 0x87u, 0x59u, 0x47u, 0xc8u, 0x15u, 0x72u,
        0xceu, 0x82u, 0x9du, 0x39u, 0x6au, 0x1fu, 0xe9u, 0x17u,
        0x45u, 0xb2u, 0x72u, 0x21u, 0x7bu, 0x2au, 0x95u, 0xeeu
    };
    static const uint8_t derived_b[32] = {
        0x04u, 0x7du, 0x5fu, 0x7fu, 0x09u, 0x93u, 0xdau, 0x97u,
        0x9bu, 0xacu, 0xa5u, 0x21u, 0xa1u, 0x57u, 0x02u, 0x5au,
        0x06u, 0x60u, 0x6cu, 0xffu, 0xa2u, 0xafu, 0x1cu, 0xf5u,
        0x2eu, 0x99u, 0xc3u, 0xfeu, 0xccu, 0xddu, 0x24u, 0xbbu
    };
    ninlil_test_storage_config_t storage_config;
    ninlil_test_storage_t *shared_storage;
    composition_test_fixture_t fixture_a;
    composition_test_fixture_t fixture_b;
    ninlil_composition_v1_t *composition_a = NULL;
    ninlil_composition_v1_t *composition_b = NULL;
    ninlil_bytes_view_t view_a;
    ninlil_bytes_view_t view_b;
    ninlil_bytes_view_t base_a;
    ninlil_bytes_view_t base_b;

    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 32u;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = UINT64_C(1048576);
    shared_storage = ninlil_test_storage_create(&storage_config);
    REQUIRE(shared_storage != NULL);
    REQUIRE(composition_test_fixture_init(
        &fixture_a,
        shared_storage,
        0x30u,
        namespace_a,
        (uint32_t)sizeof(namespace_a) - 1u));
    REQUIRE(composition_test_fixture_init(
        &fixture_b,
        shared_storage,
        0x50u,
        namespace_b,
        (uint32_t)sizeof(namespace_b) - 1u));
    REQUIRE(fixture_a.platform.storage == fixture_b.platform.storage);
    REQUIRE(fixture_a.platform.storage->user
        == fixture_b.platform.storage->user);

    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture_a.config,
                &fixture_a.platform,
                fixture_a.workspace,
                fixture_a.workspace_bytes,
                &composition_a)
        == NINLIL_OK);
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture_b.config,
                &fixture_b.platform,
                fixture_b.workspace,
                fixture_b.workspace_bytes,
                &composition_b)
        == NINLIL_OK);

    view_a.data = derived_a;
    view_a.length = (uint32_t)sizeof(derived_a);
    view_b.data = derived_b;
    view_b.length = (uint32_t)sizeof(derived_b);
    base_a.data = namespace_a;
    base_a.length = (uint32_t)sizeof(namespace_a) - 1u;
    base_b.data = namespace_b;
    base_b.length = (uint32_t)sizeof(namespace_b) - 1u;

    /* Fabric metadata exists only in each exact derived binary namespace. */
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                shared_storage, view_a, (uint8_t)'F', (uint8_t)'B')
        == 1u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                shared_storage, view_b, (uint8_t)'F', (uint8_t)'B')
        == 1u);
    REQUIRE(memcmp(derived_a, derived_b, sizeof(derived_a)) != 0);

    /* Foundation bootstrap keys remain in the caller's original namespace. */
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                shared_storage, base_a, 0x4eu, 0x49u)
        > 0u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                shared_storage, base_b, 0x4eu, 0x49u)
        > 0u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                shared_storage, base_a, (uint8_t)'F', (uint8_t)'B')
        == 0u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                shared_storage, view_a, 0x4eu, 0x49u)
        == 0u);

    REQUIRE(composition_test_fixture_release_composition(
        &fixture_a, composition_a));
    REQUIRE(composition_test_fixture_release_composition(
        &fixture_b, composition_b));
    composition_test_fixture_destroy(&fixture_a);
    composition_test_fixture_destroy(&fixture_b);
    REQUIRE(ninlil_test_storage_live_handles(shared_storage) == 0u);
    ninlil_test_storage_destroy(shared_storage);
    (void)printf("composition_v1_namespace_test: PASS\n");
    return 0;
}
