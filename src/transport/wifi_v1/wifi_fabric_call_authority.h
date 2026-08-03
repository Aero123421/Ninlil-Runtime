#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_FABRIC_CALL_AUTHORITY_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_FABRIC_CALL_AUTHORITY_H

/*
 * Private, non-installed call authority shared by the Host and ESP packet-link
 * providers.  The cookie is the exact owning Fabric object.  A scope captures
 * one binding generation, so an ops table retained across unregister/rebind
 * cannot become authoritative again.
 */

#include <stdint.h>
#include <string.h>

#define NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC UINT32_C(0x57464341) /* WFCA */
#define NINLIL_WIFI_FABRIC_CALL_SCOPE_MAGIC UINT32_C(0x57464353) /* WFCS */

#define NINLIL_WIFI_FABRIC_CALL_UNBOUND 0u
#define NINLIL_WIFI_FABRIC_CALL_PREPARED 1u
#define NINLIL_WIFI_FABRIC_CALL_ACTIVE 2u
#define NINLIL_WIFI_FABRIC_CALL_DRAINING 3u

/*
 * Registration scopes are immutable capabilities once handed to Fabric.
 * Adapters never reuse a slot; bounded exhaustion requires adapter recreation
 * instead of letting an old copied ops table regain authority.
 */
#define NINLIL_WIFI_FABRIC_REGISTRATION_SCOPE_MAX 8u

typedef struct ninlil_wifi_fabric_call_authority_v1 {
    uint32_t magic;
    uint32_t phase;
    uint64_t generation;
    const void *fabric_cookie;
    uint8_t exhausted;
    uint8_t reserved[7];
} ninlil_wifi_fabric_call_authority_v1_t;

typedef struct ninlil_wifi_fabric_call_scope_v1 {
    uint32_t magic;
    uint32_t reserved_zero;
    void *provider_user;
    const ninlil_wifi_fabric_call_authority_v1_t *authority;
    const void *fabric_cookie;
    uint64_t generation;
} ninlil_wifi_fabric_call_scope_v1_t;

static inline void ninlil_wifi_fabric_call_authority_init(
    ninlil_wifi_fabric_call_authority_v1_t *authority)
{
    if (authority == NULL) {
        return;
    }
    (void)memset(authority, 0, sizeof(*authority));
    authority->magic = NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC;
}

static inline int ninlil_wifi_fabric_call_authority_prepare(
    ninlil_wifi_fabric_call_authority_v1_t *authority,
    const void *fabric_cookie)
{
    if (authority == NULL || fabric_cookie == NULL
        || authority->magic != NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC
        || authority->phase != NINLIL_WIFI_FABRIC_CALL_UNBOUND
        || authority->exhausted != 0u
        || authority->generation == UINT64_MAX) {
        return 0;
    }
    authority->generation += 1u;
    if (authority->generation == 0u) {
        authority->exhausted = 1u;
        return 0;
    }
    authority->fabric_cookie = fabric_cookie;
    authority->phase = NINLIL_WIFI_FABRIC_CALL_PREPARED;
    return 1;
}

static inline int ninlil_wifi_fabric_call_authority_activate(
    ninlil_wifi_fabric_call_authority_v1_t *authority,
    const void *fabric_cookie)
{
    if (authority == NULL || fabric_cookie == NULL
        || authority->magic != NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC
        || authority->phase != NINLIL_WIFI_FABRIC_CALL_PREPARED
        || authority->fabric_cookie != fabric_cookie) {
        return 0;
    }
    authority->phase = NINLIL_WIFI_FABRIC_CALL_ACTIVE;
    return 1;
}

static inline int ninlil_wifi_fabric_call_authority_drain(
    ninlil_wifi_fabric_call_authority_v1_t *authority,
    const void *fabric_cookie)
{
    if (authority == NULL || fabric_cookie == NULL
        || authority->magic != NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC
        || authority->phase != NINLIL_WIFI_FABRIC_CALL_ACTIVE
        || authority->fabric_cookie != fabric_cookie) {
        return 0;
    }
    authority->phase = NINLIL_WIFI_FABRIC_CALL_DRAINING;
    return 1;
}

static inline int ninlil_wifi_fabric_call_authority_unbind(
    ninlil_wifi_fabric_call_authority_v1_t *authority,
    const void *fabric_cookie)
{
    if (authority == NULL || fabric_cookie == NULL
        || authority->magic != NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC
        || authority->phase == NINLIL_WIFI_FABRIC_CALL_UNBOUND
        || authority->fabric_cookie != fabric_cookie) {
        return 0;
    }
    authority->fabric_cookie = NULL;
    authority->phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    /*
     * generation is deliberately retained.  Every later prepare advances it,
     * invalidating all previously copied ops/user scopes, including same
     * address Fabric re-registration.
     */
    return 1;
}

static inline void ninlil_wifi_fabric_call_scope_init(
    ninlil_wifi_fabric_call_scope_v1_t *scope,
    void *provider_user,
    const ninlil_wifi_fabric_call_authority_v1_t *authority,
    const void *fabric_cookie)
{
    if (scope == NULL) {
        return;
    }
    (void)memset(scope, 0, sizeof(*scope));
    scope->magic = NINLIL_WIFI_FABRIC_CALL_SCOPE_MAGIC;
    scope->provider_user = provider_user;
    scope->authority = authority;
    scope->fabric_cookie = fabric_cookie;
    if (authority != NULL) {
        scope->generation = authority->generation;
    }
}

static inline int ninlil_wifi_fabric_call_scope_valid(
    const ninlil_wifi_fabric_call_scope_v1_t *scope)
{
    const ninlil_wifi_fabric_call_authority_v1_t *authority;
    if (scope == NULL || scope->magic != NINLIL_WIFI_FABRIC_CALL_SCOPE_MAGIC
        || scope->reserved_zero != 0u || scope->provider_user == NULL
        || scope->authority == NULL || scope->fabric_cookie == NULL) {
        return 0;
    }
    authority = scope->authority;
    return authority->magic == NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC
        && authority->phase != NINLIL_WIFI_FABRIC_CALL_UNBOUND
        && authority->exhausted == 0u
        && authority->fabric_cookie == scope->fabric_cookie
        && authority->generation == scope->generation;
}

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_FABRIC_CALL_AUTHORITY_H */
