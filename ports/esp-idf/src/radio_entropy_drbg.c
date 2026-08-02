#include "radio_entropy_drbg.h"

#include "mbedtls/entropy.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int storage_is_zero(
    const ninlil_esp_idf_radio_drbg_t *state)
{
    const uint8_t *bytes = (const uint8_t *)state;
    size_t index;

    for (index = 0u; index < sizeof(*state); ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int seed_feed(void *user, unsigned char *out, size_t length)
{
    ninlil_esp_idf_radio_drbg_t *state =
        (ninlil_esp_idf_radio_drbg_t *)user;
    uint32_t remaining;

    if (state == NULL || out == NULL || state->seed_active == 0u
        || state->seed_cursor > NINLIL_ESP_IDF_RADIO_DRBG_SEED_BYTES
        || length > UINT32_MAX) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    remaining = NINLIL_ESP_IDF_RADIO_DRBG_SEED_BYTES - state->seed_cursor;
    if ((uint32_t)length > remaining) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    (void)memcpy(out, state->seed_bytes + state->seed_cursor, length);
    state->seed_cursor += (uint32_t)length;
    return 0;
}

static void radio_drbg_retire(ninlil_esp_idf_radio_drbg_t *state)
{
    state->ready = 0u;
    mbedtls_ctr_drbg_free(&state->context);
    (void)memset(&state->context, 0, sizeof(state->context));
    state->seed_active = 0u;
    state->seed_cursor = 0u;
    (void)memset(state->seed_bytes, 0, sizeof(state->seed_bytes));
}

static ninlil_port_status_t radio_drbg_fill(
    void *user,
    uint8_t *out,
    uint32_t length)
{
    ninlil_esp_idf_radio_drbg_t *state =
        (ninlil_esp_idf_radio_drbg_t *)user;
    int result;

    if (state == NULL || xPortInIsrContext() != 0) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (state->self != state || state->ready == 0u
        || state->owner_task != xTaskGetCurrentTaskHandle()
        || length > NINLIL_ESP_IDF_RADIO_DRBG_MAX_DRAW_BYTES) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (length == 0u) {
        return NINLIL_PORT_OK;
    }
    if (out == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (state->request_count >= NINLIL_ESP_IDF_RADIO_DRBG_MAX_REQUESTS) {
        radio_drbg_retire(state);
        return NINLIL_PORT_PERMANENT_FAILURE;
    }

    result = mbedtls_ctr_drbg_random(&state->context, out, (size_t)length);
    if (result != 0) {
        radio_drbg_retire(state);
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    state->request_count += 1u;
    return NINLIL_PORT_OK;
}

int ninlil_esp_idf_radio_drbg_init(
    ninlil_esp_idf_radio_drbg_t *state,
    const ninlil_entropy_ops_t *seed_source,
    const uint8_t personalization_digest[32])
{
    static const uint8_t domain[] = "ninlil-radio-runtime-v1";
    uint8_t personalization[sizeof(domain) - 1u + 32u];
    ninlil_port_status_t seed_status;
    uint32_t seed_bytes_consumed;
    int result;

    if (state == NULL || seed_source == NULL
        || personalization_digest == NULL || xPortInIsrContext() != 0
        || !storage_is_zero(state)
        || seed_source->abi_version != NINLIL_ABI_VERSION
        || seed_source->struct_size != (uint16_t)sizeof(*seed_source)
        || seed_source->fill == NULL
        || !bytes_nonzero(personalization_digest, 32u)) {
        return 1;
    }

    seed_status = seed_source->fill(
        seed_source->user,
        state->seed_bytes,
        NINLIL_ESP_IDF_RADIO_DRBG_SEED_BYTES);
    if (seed_status != NINLIL_PORT_OK) {
        (void)memset(state, 0, sizeof(*state));
        return 1;
    }

    (void)memcpy(personalization, domain, sizeof(domain) - 1u);
    (void)memcpy(
        personalization + sizeof(domain) - 1u,
        personalization_digest,
        32u);
    state->seed_active = 1u;
    mbedtls_ctr_drbg_init(&state->context);
    mbedtls_ctr_drbg_set_entropy_len(&state->context, 48u);
    mbedtls_ctr_drbg_set_prediction_resistance(
        &state->context, MBEDTLS_CTR_DRBG_PR_OFF);
    result = mbedtls_ctr_drbg_seed(
        &state->context,
        seed_feed,
        state,
        personalization,
        sizeof(personalization));
    seed_bytes_consumed = state->seed_cursor;
    (void)memset(personalization, 0, sizeof(personalization));
    state->seed_active = 0u;
    state->seed_cursor = 0u;
    (void)memset(state->seed_bytes, 0, sizeof(state->seed_bytes));
    if (result != 0 || seed_bytes_consumed != 48u) {
        mbedtls_ctr_drbg_free(&state->context);
        (void)memset(state, 0, sizeof(*state));
        return 1;
    }

    mbedtls_ctr_drbg_set_reseed_interval(&state->context, INT_MAX);
    state->ops.abi_version = NINLIL_ABI_VERSION;
    state->ops.struct_size = (uint16_t)sizeof(state->ops);
    state->ops.user = state;
    state->ops.fill = radio_drbg_fill;
    state->self = state;
    state->owner_task = xTaskGetCurrentTaskHandle();
    state->ready = 1u;
    return 0;
}

const ninlil_entropy_ops_t *ninlil_esp_idf_radio_drbg_ops(
    ninlil_esp_idf_radio_drbg_t *state)
{
    if (state == NULL || xPortInIsrContext() != 0 || state->self != state
        || state->ready == 0u
        || state->owner_task != xTaskGetCurrentTaskHandle()) {
        return NULL;
    }
    return &state->ops;
}

void ninlil_esp_idf_radio_drbg_close(
    ninlil_esp_idf_radio_drbg_t *state)
{
    if (state == NULL || xPortInIsrContext() != 0 || state->self != state
        || state->owner_task != xTaskGetCurrentTaskHandle()) {
        return;
    }
    state->ready = 0u;
    mbedtls_ctr_drbg_free(&state->context);
    (void)memset(state, 0, sizeof(*state));
}
