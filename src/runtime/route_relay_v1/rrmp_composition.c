/*
 * Production composition: platform storage bind + recover only.
 * No synthetic store/provider, no large BSS lifecycle fixtures.
 */
#include "rrmp_composition.h"

int ninlil_rrmp_composition_bind(
    ninlil_rrmp_owner_t *owner,
    const ninlil_storage_ops_t *storage_ops,
    ninlil_storage_handle_t storage_handle,
    const ninlil_rrmp_outbound_provider_t *outbound,
    const ninlil_rrmp_scope_derivation_ctx_t *scope_ctx)
{
    if (owner == NULL || storage_ops == NULL || storage_handle == NULL) {
        return 0;
    }
    if (!ninlil_rrmp_owner_bind_storage(owner, storage_ops, storage_handle)) {
        return 0;
    }
    if (outbound != NULL) {
        ninlil_rrmp_owner_set_outbound_provider(owner, outbound);
    }
    if (scope_ctx != NULL) {
        ninlil_rrmp_owner_set_scope_derivation(owner, scope_ctx);
    }
    return 1;
}

int ninlil_rrmp_composition_recover(ninlil_rrmp_owner_t *owner)
{
    return ninlil_rrmp_owner_storage_recover(owner);
}
