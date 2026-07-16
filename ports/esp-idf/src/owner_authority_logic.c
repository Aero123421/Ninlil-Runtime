#include "owner_authority_logic.h"

#include <string.h>

void ninlil_esp_idf_owner_authority_init(ninlil_esp_idf_owner_authority_t *a)
{
    if (a == NULL) {
        return;
    }
    (void)memset(a, 0, sizeof(*a));
    a->api_lifecycle = 1u;
    a->published_lifecycle = NINLIL_ESP_IDF_OWNER_LC_STOPPED;
    a->next_claim = 1u;
}

int ninlil_esp_idf_owner_authority_try_claim(
    ninlil_esp_idf_owner_authority_t *a,
    uint32_t *out_token)
{
    if (a == NULL || out_token == NULL || a->api_lifecycle != 1u) {
        return 0;
    }
    if (a->op_claim != 0u) {
        return 0;
    }
    if (a->next_claim == 0u) {
        a->next_claim = 1u;
    }
    a->op_claim = a->next_claim;
    *out_token = a->op_claim;
    a->next_claim += 1u;
    return 1;
}

void ninlil_esp_idf_owner_authority_release_claim(
    ninlil_esp_idf_owner_authority_t *a,
    uint32_t token)
{
    if (a != NULL && a->op_claim == token) {
        a->op_claim = 0u;
    }
}

int ninlil_esp_idf_owner_authority_admit_post(
    ninlil_esp_idf_owner_authority_t *a)
{
    if (a == NULL || a->api_lifecycle != 1u) {
        return 0;
    }
    if (a->accepting == 0u || a->handle_live == 0u || a->reclaim_closed != 0u) {
        return 0;
    }
    if (a->published_lifecycle != NINLIL_ESP_IDF_OWNER_LC_RUNNING) {
        return 0;
    }
    a->inflight += 1u;
    return 1;
}

void ninlil_esp_idf_owner_authority_complete_post(
    ninlil_esp_idf_owner_authority_t *a)
{
    if (a != NULL && a->inflight > 0u) {
        a->inflight -= 1u;
    }
}

int ninlil_esp_idf_owner_authority_begin_stop(
    ninlil_esp_idf_owner_authority_t *a)
{
    if (a == NULL) {
        return 0;
    }
    if (a->published_lifecycle == NINLIL_ESP_IDF_OWNER_LC_STOPPED
        || a->published_lifecycle == NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        return 0;
    }
    a->accepting = 0u;
    a->reclaim_closed = 1u;
    a->published_lifecycle = NINLIL_ESP_IDF_OWNER_LC_STOPPING;
    return 1;
}

int ninlil_esp_idf_owner_authority_can_reclaim(
    const ninlil_esp_idf_owner_authority_t *a)
{
    return a != NULL && a->reclaim_closed != 0u && a->inflight == 0u
        && a->will_suspend != 0u;
}

void ninlil_esp_idf_owner_authority_mark_suspended(
    ninlil_esp_idf_owner_authority_t *a)
{
    if (a != NULL) {
        a->will_suspend = 1u;
        if (a->inflight == 0u) {
            a->published_lifecycle = NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK;
        }
    }
}

void ninlil_esp_idf_owner_authority_finish_join(
    ninlil_esp_idf_owner_authority_t *a)
{
    if (a == NULL) {
        return;
    }
    a->handle_live = 0u;
    a->will_suspend = 0u;
    a->reclaim_closed = 0u;
    a->accepting = 0u;
    a->start_gate = 0u;
    a->published_lifecycle = NINLIL_ESP_IDF_OWNER_LC_STOPPED;
}

void ninlil_esp_idf_owner_authority_timeout_failed_live(
    ninlil_esp_idf_owner_authority_t *a)
{
    if (a != NULL) {
        a->accepting = 0u;
        a->reclaim_closed = 1u;
        a->published_lifecycle = NINLIL_ESP_IDF_OWNER_LC_FAILED_LIVE;
    }
}

int ninlil_esp_idf_owner_authority_may_retire(
    const ninlil_esp_idf_owner_authority_t *a)
{
    return a != NULL && a->api_lifecycle == 1u && a->handle_live == 0u
        && a->inflight == 0u
        && (a->published_lifecycle == NINLIL_ESP_IDF_OWNER_LC_STOPPED
            || a->published_lifecycle
                == NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED);
}

int ninlil_esp_idf_owner_authority_may_swap_tx(
    const ninlil_esp_idf_owner_authority_t *a)
{
    return ninlil_esp_idf_owner_authority_may_retire(a);
}
