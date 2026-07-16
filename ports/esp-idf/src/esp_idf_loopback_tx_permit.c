#include "ninlil_esp_idf/loopback_tx_permit.h"

#include "loopback_tx_permit_logic.h"

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static portMUX_TYPE s_loopback_mux = portMUX_INITIALIZER_UNLOCKED;

static ninlil_tx_gate_status_t loopback_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    ninlil_tx_gate_status_t st;

    if (xPortInIsrContext() != 0) {
        return NINLIL_TX_GATE_DENIED;
    }
    portENTER_CRITICAL(&s_loopback_mux);
    st = ninlil_esp_idf_loopback_tx_permit_acquire_pure(
        (ninlil_esp_idf_loopback_tx_permit_t *)user, request, now, out_permit);
    portEXIT_CRITICAL(&s_loopback_mux);
    return st;
}

static void loopback_release_unused(
    void *user,
    const ninlil_tx_permit_t *permit)
{
    if (xPortInIsrContext() != 0) {
        return;
    }
    portENTER_CRITICAL(&s_loopback_mux);
    ninlil_esp_idf_loopback_tx_permit_release_unused_pure(
        (ninlil_esp_idf_loopback_tx_permit_t *)user, permit);
    portEXIT_CRITICAL(&s_loopback_mux);
}

int ninlil_esp_idf_loopback_tx_permit_init(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_esp_idf_loopback_tx_permit_config_t *config)
{
    int rc;

    if (xPortInIsrContext() != 0) {
        return 1;
    }
    portENTER_CRITICAL(&s_loopback_mux);
    rc = ninlil_esp_idf_loopback_tx_permit_init_pure(
        gate, config, loopback_acquire, loopback_release_unused);
    portEXIT_CRITICAL(&s_loopback_mux);
    return rc;
}

int ninlil_esp_idf_loopback_tx_permit_shutdown(
    ninlil_esp_idf_loopback_tx_permit_t *gate)
{
    if (gate == NULL || xPortInIsrContext() != 0) {
        return 1;
    }
    portENTER_CRITICAL(&s_loopback_mux);
    if (gate->lifecycle != 1u) {
        portEXIT_CRITICAL(&s_loopback_mux);
        return 1;
    }
    /* Closed contract: live permits must be released before shutdown. */
    if (gate->live_count > 0u) {
        portEXIT_CRITICAL(&s_loopback_mux);
        return 1;
    }
    ninlil_esp_idf_loopback_tx_permit_shutdown_pure(gate);
    portEXIT_CRITICAL(&s_loopback_mux);
    return 0;
}

const ninlil_tx_gate_ops_t *ninlil_esp_idf_loopback_tx_permit_ops(
    ninlil_esp_idf_loopback_tx_permit_t *gate)
{
    const ninlil_tx_gate_ops_t *ops = NULL;

    if (gate == NULL || xPortInIsrContext() != 0) {
        return NULL;
    }
    portENTER_CRITICAL(&s_loopback_mux);
    if (gate->lifecycle == 1u) {
        ops = &gate->ops;
    }
    portEXIT_CRITICAL(&s_loopback_mux);
    return ops;
}
