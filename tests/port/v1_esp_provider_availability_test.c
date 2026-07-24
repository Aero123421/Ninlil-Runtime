/* V1-LAB unit 1c: ESP platform provider catalog + LAB unavailable admission. */

#include "ninlil_esp_idf/platform_availability.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const ninlil_allocator_ops_t g_stub_allocator = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_allocator_ops_t),
};
static const ninlil_bearer_ops_t g_stub_bearer = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_bearer_ops_t),
};
static const ninlil_origin_authorization_ops_t g_stub_origin = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_origin_authorization_ops_t),
};
static const ninlil_execution_ops_t g_stub_execution = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_execution_ops_t),
};
static const ninlil_clock_ops_t g_stub_clock = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_clock_ops_t),
};
static const ninlil_entropy_ops_t g_stub_entropy = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_entropy_ops_t),
};
static const ninlil_storage_ops_t g_stub_storage = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_storage_ops_t),
};
static const ninlil_tx_gate_ops_t g_stub_tx_gate = {
    .abi_version = NINLIL_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_tx_gate_ops_t),
};

static int test_lab_unavailable_explicit_reject(void)
{
    REQUIRE(ninlil_esp_idf_provider_catalog_status(
                NINLIL_ESP_IDF_PROVIDER_BEARER)
        == NINLIL_ESP_IDF_PROVIDER_STATUS_LAB_UNAVAILABLE);
    REQUIRE(ninlil_esp_idf_provider_catalog_status(
                NINLIL_ESP_IDF_PROVIDER_ALLOCATOR)
        == NINLIL_ESP_IDF_PROVIDER_STATUS_LAB_UNAVAILABLE);
    REQUIRE(ninlil_esp_idf_provider_catalog_status(
                NINLIL_ESP_IDF_PROVIDER_ORIGIN_AUTHORIZATION)
        == NINLIL_ESP_IDF_PROVIDER_STATUS_LAB_UNAVAILABLE);

    REQUIRE(ninlil_esp_idf_provider_admission_request(
                NINLIL_ESP_IDF_PROVIDER_BEARER, &g_stub_bearer)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_esp_idf_provider_admission_request(
                NINLIL_ESP_IDF_PROVIDER_ALLOCATOR, &g_stub_allocator)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_esp_idf_provider_admission_request(
                NINLIL_ESP_IDF_PROVIDER_ORIGIN_AUTHORIZATION, &g_stub_origin)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_esp_idf_provider_admission_request(
                NINLIL_ESP_IDF_PROVIDER_BEARER, NULL)
        == NINLIL_PORT_PERMANENT_FAILURE);
    return 0;
}

static int test_implemented_requires_ops(void)
{
    REQUIRE(ninlil_esp_idf_provider_catalog_status(
                NINLIL_ESP_IDF_PROVIDER_CLOCK)
        == NINLIL_ESP_IDF_PROVIDER_STATUS_IMPLEMENTED);
    REQUIRE(ninlil_esp_idf_provider_admission_request(
                NINLIL_ESP_IDF_PROVIDER_CLOCK, NULL)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_esp_idf_provider_admission_request(
                NINLIL_ESP_IDF_PROVIDER_CLOCK, &g_stub_clock)
        == NINLIL_PORT_OK);
    return 0;
}

static int test_platform_ops_admit_rejects_stub_wiring(void)
{
    ninlil_platform_ops_t valid;
    ninlil_platform_ops_t stub_bearer;

    (void)memset(&valid, 0, sizeof(valid));
    valid.abi_version = NINLIL_ABI_VERSION;
    valid.struct_size = (uint16_t)sizeof(valid);
    valid.execution = &g_stub_execution;
    valid.clock = &g_stub_clock;
    valid.entropy = &g_stub_entropy;
    valid.storage = &g_stub_storage;
    valid.tx_gate = &g_stub_tx_gate;
    REQUIRE(ninlil_esp_idf_platform_ops_admit(&valid) == 0);

    stub_bearer = valid;
    stub_bearer.bearer = &g_stub_bearer;
    REQUIRE(ninlil_esp_idf_platform_ops_admit(&stub_bearer) != 0);

  {
    ninlil_platform_ops_t missing_storage = valid;
    missing_storage.storage = NULL;
    REQUIRE(ninlil_esp_idf_platform_ops_admit(&missing_storage) != 0);
  }
    return 0;
}

int main(void)
{
    REQUIRE(test_lab_unavailable_explicit_reject() == 0);
    REQUIRE(test_implemented_requires_ops() == 0);
    REQUIRE(test_platform_ops_admit_rejects_stub_wiring() == 0);
    return 0;
}
