/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_test_common.h"

enum {
    RRMP_SERIAL_WS_MAX = NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES,
    RRMP_SERIAL_EXPORT_MAX = NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX
};

_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_ws_a[RRMP_SERIAL_WS_MAX];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_ws_b[RRMP_SERIAL_WS_MAX];
static uint8_t g_export[RRMP_SERIAL_EXPORT_MAX];

typedef struct auth_context {
    uint8_t accept;
    uint32_t calls;
} auth_context_t;

static int authorize(
    void *user,
    const ninlil_rrmp_caller_auth_v1_t *auth,
    const uint8_t local_runtime_id[16],
    const uint8_t authority_id[16])
{
    auth_context_t *ctx = (auth_context_t *)user;
    if (ctx != NULL) {
        ctx->calls += 1u;
    }
    return ctx != NULL && ctx->accept && auth != NULL &&
        local_runtime_id != NULL && authority_id != NULL &&
        auth->authorization_epoch == 7u && auth->proof32[0] == 0xA5u;
}

static void fill_auth(ninlil_rrmp_caller_auth_v1_t *auth, uint32_t caps)
{
    ninlil_rrmp_memzero(auth, sizeof(*auth));
    rrmp_fill_id(auth->principal_id, 0x22u);
    auth->capability_mask = caps;
    auth->authorization_epoch = 7u;
    auth->proof32[0] = 0xA5u;
}

static ninlil_rrmp_owner_t *make_owner(
    uint8_t *workspace, uint8_t authority_seed, uint8_t authorization_required)
{
    ninlil_rrmp_owner_config_v1_t cfg;
    rrmp_cfg_fill(&cfg, 1u, 1u);
    rrmp_fill_id(cfg.local_runtime_id, (uint8_t)(authority_seed - 0x10u));
    rrmp_fill_id(cfg.authority_id, authority_seed);
    cfg.authorization_required = authorization_required;
    return ninlil_rrmp_owner_init(
        workspace, ninlil_rrmp_owner_workspace_bytes(), &cfg);
}

static int fill_install(
    ninlil_route_install_batch_req_v1_t *req,
    uint8_t authority_seed,
    uint16_t handle)
{
    ninlil_rrmp_nrm1_fields_t fields;
    ninlil_rrmp_memzero(req, sizeof(*req));
    req->preamble.api_version = 1u;
    req->preamble.struct_size = 312u;
    rrmp_fill_id(req->authority_id, authority_seed);
    req->controller_term = 5u;
    req->batch_id = handle;
    req->entry_count = 1u;
    rrmp_fill_nrm1(&fields, handle, 1u, 1u);
    rrmp_fill_id(fields.authority_id.bytes, authority_seed);
    return ninlil_rrmp_encode_nrm1(&fields, req->entries);
}

static void fill_query(ninlil_route_query_req_v1_t *req, uint16_t handle)
{
    ninlil_rrmp_memzero(req, sizeof(*req));
    req->preamble.api_version = 1u;
    req->preamble.struct_size = 48u;
    req->ingress_hop_context_id = 0x1000u + handle;
    req->route_handle = handle;
    req->route_generation = 1u;
}

static int snapshot(
    const ninlil_rrmp_owner_t *owner, uint8_t digest[32], size_t *length)
{
    size_t needed = 0u;
    if (!ninlil_rrmp_owner_export_namespace(owner, NULL, 0u, &needed) ||
        needed > sizeof(g_export) ||
        !ninlil_rrmp_owner_export_namespace(
            owner, g_export, sizeof(g_export), &needed)) {
        return 0;
    }
    ninlil_rrmp_sha256(g_export, needed, digest);
    *length = needed;
    return 1;
}

static int bytes_all_zero(const uint8_t *bytes, size_t length)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    ninlil_rrmp_owner_t *a;
    ninlil_rrmp_owner_t *b;
    ninlil_rrmp_caller_auth_v1_t auth;
    ninlil_rrmp_authorizer_v1_t authorizer;
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_query_req_v1_t query;
    ninlil_route_result_v1_t out;
    ninlil_parent_owner_prepare_req_v1_t legacy_parent;
    ninlil_parent_result_v1_t parent_out;
    auth_context_t auth_ctx = {1u, 0u};
    uint8_t before_a[32];
    uint8_t before_b[32];
    uint8_t after_a[32];
    uint8_t after_b[32];
    size_t before_a_len;
    size_t before_b_len;
    size_t after_a_len;
    size_t after_b_len;
    size_t workspace_bytes = ninlil_rrmp_owner_workspace_bytes();

    RRMP_CHECK(workspace_bytes <= RRMP_SERIAL_WS_MAX);
    a = make_owner(g_ws_a, 0xA0u, 1u);
    b = make_owner(g_ws_b, 0xB0u, 0u);
    RRMP_CHECK(a != NULL && b != NULL);

    ninlil_rrmp_memzero(&authorizer, sizeof(authorizer));
    authorizer.user = &auth_ctx;
    authorizer.authorize = authorize;
    fill_auth(&auth, NINLIL_RRMP_AUTH_ALL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_authorized(a, &auth, &authorizer));
    RRMP_CHECK(ninlil_rrmp_owner_bind(b));

    RRMP_CHECK(fill_install(&install, 0xA0u, 1u));
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(a, &install, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK(fill_install(&install, 0xB0u, 101u));
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(b, &install, &out), NINLIL_ROUTE_OK);
    fill_query(&query, 1u);
    RRMP_CHECK_EQ(ninlil_route_query(a, &query, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(
        ninlil_route_query(b, &query, &out), NINLIL_ROUTE_NOT_ACTIVE);
    fill_query(&query, 101u);
    RRMP_CHECK_EQ(ninlil_route_query(b, &query, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(
        ninlil_route_query(a, &query, &out), NINLIL_ROUTE_NOT_ACTIVE);

    /* A request carrying B's authority cannot mutate either serial domain. */
    RRMP_CHECK(snapshot(a, before_a, &before_a_len));
    RRMP_CHECK(snapshot(b, before_b, &before_b_len));
    RRMP_CHECK(fill_install(&install, 0xB0u, 102u));
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(a, &install, &out),
        NINLIL_ROUTE_AUTHORITY_CONFLICT);
    install.preamble.api_version = 99u;
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(a, &install, &out),
        NINLIL_ROUTE_UNSUPPORTED_API);
    RRMP_CHECK(snapshot(a, after_a, &after_a_len));
    RRMP_CHECK(snapshot(b, after_b, &after_b_len));
    RRMP_CHECK_EQ(before_a_len, after_a_len);
    RRMP_CHECK_EQ(before_b_len, after_b_len);
    RRMP_CHECK(memcmp(before_a, after_a, 32u) == 0);
    RRMP_CHECK(memcmp(before_b, after_b, 32u) == 0);

    /* B lifecycle operations cannot clear A's live authorization. */
    ninlil_rrmp_owner_unbind(b);
    fill_query(&query, 101u);
    RRMP_CHECK_EQ(
        ninlil_route_query(b, &query, &out), NINLIL_ROUTE_INVALID_ARGUMENT);
    fill_query(&query, 1u);
    RRMP_CHECK_EQ(ninlil_route_query(a, &query, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK(ninlil_rrmp_owner_bind(b));
    fill_query(&query, 101u);
    RRMP_CHECK_EQ(ninlil_route_query(b, &query, &out), NINLIL_ROUTE_OK);

    RRMP_CHECK_EQ(
        ninlil_route_query(NULL, &query, &out), NINLIL_ROUTE_INVALID_ARGUMENT);
    ninlil_rrmp_memzero(&legacy_parent, sizeof(legacy_parent));
    legacy_parent.preamble.api_version = 1u;
    legacy_parent.preamble.struct_size = (uint32_t)sizeof(legacy_parent);
    RRMP_CHECK_EQ(
        ninlil_parent_owner_prepare(NULL, &legacy_parent, &parent_out),
        NINLIL_PARENT_INVALID_ARGUMENT);

    /* Failed authorization and unbind both clear the prior auth domain. */
    auth_ctx.accept = 0u;
    RRMP_CHECK(!ninlil_rrmp_owner_bind_authorized(a, &auth, &authorizer));
    fill_query(&query, 1u);
    RRMP_CHECK_EQ(
        ninlil_route_query(a, &query, &out), NINLIL_ROUTE_INVALID_ARGUMENT);
    auth_ctx.accept = 1u;
    fill_auth(&auth, NINLIL_RRMP_AUTH_ROUTE_ADMIN);
    RRMP_CHECK(ninlil_rrmp_owner_bind_authorized(a, &auth, &authorizer));
    RRMP_CHECK_EQ(
        ninlil_route_query(a, &query, &out),
        NINLIL_ROUTE_AUTHORITY_CONFLICT);
    ninlil_rrmp_owner_unbind(a);
    RRMP_CHECK_EQ(
        ninlil_route_query(a, &query, &out), NINLIL_ROUTE_INVALID_ARGUMENT);

    ninlil_rrmp_owner_fini(a);
    ninlil_rrmp_owner_fini(b);
    RRMP_CHECK(bytes_all_zero(g_ws_a, workspace_bytes));
    RRMP_CHECK(bytes_all_zero(g_ws_b, workspace_bytes));
    RRMP_CHECK(auth_ctx.calls == 3u);
    printf("rrmp_serial_owner_state_test OK\n");
    return 0;
}
