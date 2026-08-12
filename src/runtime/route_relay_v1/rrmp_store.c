/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_store.h"
#include "rrmp_codec.h"
#include "rrmp_util.h"

#include <string.h>

static int8_t arena_alloc(uint8_t *used, uint8_t n)
{
    uint8_t i;
    for (i = 0u; i < n; ++i) {
        if (!used[i]) {
            used[i] = 1u;
            return (int8_t)i;
        }
    }
    return -1;
}

static void arena_free(uint8_t *used, int8_t idx)
{
    if (idx >= 0) {
        used[(uint8_t)idx] = 0u;
    }
}

void ninlil_rrmp_route_ns_init(ninlil_rrmp_route_ns_t *ns)
{
    size_t i;
    if (ns == NULL) {
        return;
    }
    ninlil_rrmp_memzero(ns, sizeof(*ns));
    ns->cu_class = NINLIL_RRMP_CU_ABSENT;
    for (i = 0u; i < NINLIL_RRMP_PHYSICAL_KEY_COUNT; ++i) {
        ns->keys[i].active = 0xFFu;
        ns->keys[i].page_idx[0] = -1;
        ns->keys[i].page_idx[1] = -1;
    }
}

void ninlil_rrmp_parent_ns_init(ninlil_rrmp_parent_ns_t *ns)
{
    size_t i;
    if (ns == NULL) {
        return;
    }
    ninlil_rrmp_memzero(ns, sizeof(*ns));
    ns->cu_class = NINLIL_RRMP_CU_ABSENT;
    for (i = 0u; i < NINLIL_RRMP_PKEY_COUNT; ++i) {
        ns->keys[i].active = 0xFFu;
        ns->keys[i].page_idx[0] = -1;
        ns->keys[i].page_idx[1] = -1;
    }
}

static uint8_t inactive_of(const ninlil_rrmp_dual_meta_t *b)
{
    if (b->active == 0xFFu) {
        return 0u;
    }
    return (uint8_t)(1u - b->active);
}

/*
 * Exact dual OLD/NEW retention: after NEW commit, previous complete page stays
 * present as OLD (lower generation). Next begin_write reclaims inactive/OLD.
 * Arena pressure: reclaim any dual-OLD when alloc fails.
 */
static int reclaim_one_route_old(ninlil_rrmp_route_ns_t *ns)
{
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_PHYSICAL_KEY_COUNT; ++i) {
        ninlil_rrmp_dual_meta_t *b = &ns->keys[i];
        uint8_t other;
        if (b->active == 0xFFu || !b->present[0] || !b->present[1]) {
            continue;
        }
        other = (uint8_t)(1u - b->active);
        if (b->page_idx[other] < 0 || !b->present[other]) {
            continue;
        }
        arena_free(ns->arena_used, b->page_idx[other]);
        b->page_idx[other] = -1;
        b->present[other] = 0u;
        b->generation[other] = 0u;
        b->length[other] = 0u;
        return 1;
    }
    return 0;
}

static int reclaim_one_parent_old(ninlil_rrmp_parent_ns_t *ns)
{
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_PKEY_COUNT; ++i) {
        ninlil_rrmp_dual_meta_t *b = &ns->keys[i];
        uint8_t other;
        if (b->active == 0xFFu || !b->present[0] || !b->present[1]) {
            continue;
        }
        other = (uint8_t)(1u - b->active);
        if (b->page_idx[other] < 0 || !b->present[other]) {
            continue;
        }
        arena_free(ns->arena_used, b->page_idx[other]);
        b->page_idx[other] = -1;
        b->present[other] = 0u;
        b->generation[other] = 0u;
        b->length[other] = 0u;
        return 1;
    }
    return 0;
}

int ninlil_rrmp_route_dual_begin_write(
    ninlil_rrmp_route_ns_t *ns,
    uint8_t key_id,
    uint8_t **out_buf,
    size_t *out_cap,
    uint64_t *out_gen)
{
    ninlil_rrmp_dual_meta_t *b;
    uint8_t slot;
    uint64_t gen;
    int8_t pi;
    if (ns == NULL || ns->fenced ||
        key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT || out_buf == NULL ||
        out_cap == NULL) {
        return 0;
    }
    b = &ns->keys[key_id];
    slot = inactive_of(b);
    /* Reclaim this key's inactive/OLD page for the new write buffer. */
    if (b->page_idx[slot] >= 0) {
        arena_free(ns->arena_used, b->page_idx[slot]);
        b->page_idx[slot] = -1;
        b->present[slot] = 0u;
        b->generation[slot] = 0u;
        b->length[slot] = 0u;
    }
    pi = arena_alloc(ns->arena_used, NINLIL_RRMP_ROUTE_ARENA_PAGES);
    if (pi < 0 && reclaim_one_route_old(ns)) {
        pi = arena_alloc(ns->arena_used, NINLIL_RRMP_ROUTE_ARENA_PAGES);
    }
    if (pi < 0) {
        return 0;
    }
    gen = 1u;
    if (b->active != 0xFFu) {
        gen = b->generation[b->active] + 1u;
        if (gen == 0u) {
            gen = 1u;
        }
    }
    b->page_idx[slot] = pi;
    b->present[slot] = 0u;
    b->generation[slot] = gen;
    b->length[slot] = 0u;
    ninlil_rrmp_memzero(ns->arena[(uint8_t)pi], 4096u);
    *out_buf = ns->arena[(uint8_t)pi];
    *out_cap = 4096u;
    if (out_gen != NULL) {
        *out_gen = gen;
    }
    return 1;
}

int ninlil_rrmp_route_dual_commit(
    ninlil_rrmp_route_ns_t *ns, uint8_t key_id, uint32_t length)
{
    ninlil_rrmp_dual_meta_t *b;
    uint8_t slot;
    if (ns == NULL || ns->fenced ||
        key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT || length > 4096u) {
        return 0;
    }
    b = &ns->keys[key_id];
    slot = inactive_of(b);
    if (b->page_idx[slot] < 0) {
        return 0;
    }
    b->length[slot] = length;
    b->present[slot] = 1u;
    /* Retain previous active as OLD (exact dual). Do not free. */
    b->active = slot;
    return 1;
}

int ninlil_rrmp_route_dual_read_active(
    const ninlil_rrmp_route_ns_t *ns,
    uint8_t key_id,
    const uint8_t **out,
    uint32_t *len,
    uint64_t *gen)
{
    const ninlil_rrmp_dual_meta_t *b;
    if (ns == NULL || key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT || out == NULL ||
        len == NULL) {
        return 0;
    }
    b = &ns->keys[key_id];
    if (b->active == 0xFFu || !b->present[b->active] || b->page_idx[b->active] < 0) {
        return 0;
    }
    *out = ns->arena[(uint8_t)b->page_idx[b->active]];
    *len = b->length[b->active];
    if (gen != NULL) {
        *gen = b->generation[b->active];
    }
    return 1;
}

int ninlil_rrmp_route_dual_read_retained_old(
    const ninlil_rrmp_route_ns_t *ns,
    uint8_t key_id,
    const uint8_t **out,
    uint32_t *len,
    uint64_t *gen)
{
    const ninlil_rrmp_dual_meta_t *b;
    uint8_t other;
    if (ns == NULL || key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT || out == NULL ||
        len == NULL) {
        return 0;
    }
    b = &ns->keys[key_id];
    if (b->active == 0xFFu || !b->present[0] || !b->present[1]) {
        return 0;
    }
    other = (uint8_t)(1u - b->active);
    if (!b->present[other] || b->page_idx[other] < 0) {
        return 0;
    }
    if (b->generation[other] >= b->generation[b->active]) {
        return 0; /* not OLD */
    }
    *out = ns->arena[(uint8_t)b->page_idx[other]];
    *len = b->length[other];
    if (gen != NULL) {
        *gen = b->generation[other];
    }
    return 1;
}

int ninlil_rrmp_parent_dual_begin_write(
    ninlil_rrmp_parent_ns_t *ns,
    uint8_t key_id,
    uint8_t **out_buf,
    size_t *out_cap,
    uint64_t *out_gen)
{
    ninlil_rrmp_dual_meta_t *b;
    uint8_t slot;
    uint64_t gen;
    int8_t pi;
    if (ns == NULL || ns->fenced ||
        key_id >= NINLIL_RRMP_PKEY_COUNT || out_buf == NULL ||
        out_cap == NULL) {
        return 0;
    }
    b = &ns->keys[key_id];
    slot = inactive_of(b);
    if (b->page_idx[slot] >= 0) {
        arena_free(ns->arena_used, b->page_idx[slot]);
        b->page_idx[slot] = -1;
        b->present[slot] = 0u;
        b->generation[slot] = 0u;
        b->length[slot] = 0u;
    }
    pi = arena_alloc(ns->arena_used, NINLIL_RRMP_PARENT_ARENA_PAGES);
    if (pi < 0 && reclaim_one_parent_old(ns)) {
        pi = arena_alloc(ns->arena_used, NINLIL_RRMP_PARENT_ARENA_PAGES);
    }
    if (pi < 0) {
        return 0;
    }
    gen = 1u;
    if (b->active != 0xFFu) {
        gen = b->generation[b->active] + 1u;
        if (gen == 0u) {
            gen = 1u;
        }
    }
    b->page_idx[slot] = pi;
    b->present[slot] = 0u;
    b->generation[slot] = gen;
    b->length[slot] = 0u;
    ninlil_rrmp_memzero(ns->arena[(uint8_t)pi], 4096u);
    *out_buf = ns->arena[(uint8_t)pi];
    *out_cap = 4096u;
    if (out_gen != NULL) {
        *out_gen = gen;
    }
    return 1;
}

int ninlil_rrmp_parent_dual_commit(
    ninlil_rrmp_parent_ns_t *ns, uint8_t key_id, uint32_t length)
{
    ninlil_rrmp_dual_meta_t *b;
    uint8_t slot;
    if (ns == NULL || ns->fenced ||
        key_id >= NINLIL_RRMP_PKEY_COUNT || length > 4096u) {
        return 0;
    }
    b = &ns->keys[key_id];
    slot = inactive_of(b);
    if (b->page_idx[slot] < 0) {
        return 0;
    }
    b->length[slot] = length;
    b->present[slot] = 1u;
    /* Retain previous active as OLD (exact dual). Do not free. */
    b->active = slot;
    return 1;
}

int ninlil_rrmp_parent_dual_read_active(
    const ninlil_rrmp_parent_ns_t *ns,
    uint8_t key_id,
    const uint8_t **out,
    uint32_t *len,
    uint64_t *gen)
{
    const ninlil_rrmp_dual_meta_t *b;
    if (ns == NULL || key_id >= NINLIL_RRMP_PKEY_COUNT || out == NULL || len == NULL) {
        return 0;
    }
    b = &ns->keys[key_id];
    if (b->active == 0xFFu || !b->present[b->active] || b->page_idx[b->active] < 0) {
        return 0;
    }
    *out = ns->arena[(uint8_t)b->page_idx[b->active]];
    *len = b->length[b->active];
    if (gen != NULL) {
        *gen = b->generation[b->active];
    }
    return 1;
}

int ninlil_rrmp_route_full_commit(
    ninlil_rrmp_route_ns_t *ns, const uint8_t *key_ids, uint8_t n)
{
    uint8_t i;
    if (ns == NULL || ns->fenced || key_ids == NULL || n == 0u) {
        return 0;
    }
    for (i = 0u; i < n; ++i) {
        uint8_t kid = key_ids[i];
        if (kid >= NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
            return 0;
        }
        if (ns->keys[kid].active == 0xFFu ||
            !ns->keys[kid].present[ns->keys[kid].active]) {
            return 0;
        }
    }
    ns->cu_class = NINLIL_RRMP_CU_NEW;
    ns->corrupt = 0u;
    ns->fenced = 0u;
    return 1;
}

int ninlil_rrmp_parent_full_commit(
    ninlil_rrmp_parent_ns_t *ns, const uint8_t *key_ids, uint8_t n)
{
    uint8_t i;
    if (ns == NULL || ns->fenced || key_ids == NULL || n == 0u) {
        return 0;
    }
    for (i = 0u; i < n; ++i) {
        uint8_t kid = key_ids[i];
        if (kid >= NINLIL_RRMP_PKEY_COUNT) {
            return 0;
        }
        if (ns->keys[kid].active == 0xFFu ||
            !ns->keys[kid].present[ns->keys[kid].active]) {
            return 0;
        }
    }
    ns->cu_class = NINLIL_RRMP_CU_NEW;
    ns->corrupt = 0u;
    ns->fenced = 0u;
    return 1;
}

static uint32_t classify_meta(const ninlil_rrmp_dual_meta_t *b, int *any)
{
    int a = b->present[0] ? 1 : 0;
    int bb = b->present[1] ? 1 : 0;
    if (any != NULL && (a || bb)) {
        *any = 1;
    }
    if (b->extra_mark) {
        return NINLIL_RRMP_CU_EXTRA;
    }
    if (!a && !bb) {
        return NINLIL_RRMP_CU_ABSENT;
    }
    if (a && bb && b->generation[0] == b->generation[1] &&
        b->generation[0] != 0u) {
        return NINLIL_RRMP_CU_THIRD;
    }
    if (a && bb && b->active == 0xFFu) {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    if ((a || bb) && b->active == 0xFFu) {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    if (a && bb && b->active != 0xFFu) {
        uint8_t other = (uint8_t)(1u - b->active);
        /* Active is older than the other complete slot → CU OLD */
        if (b->present[other] &&
            b->generation[b->active] < b->generation[other]) {
            return NINLIL_RRMP_CU_OLD;
        }
        if (b->generation[other] < b->generation[b->active]) {
            return NINLIL_RRMP_CU_NEW; /* NEW active + OLD retained */
        }
    }
    return NINLIL_RRMP_CU_NEW;
}

uint32_t ninlil_rrmp_route_classify_cu(const ninlil_rrmp_route_ns_t *ns)
{
    size_t i;
    int any = 0;
    int partial = 0;
    int third = 0;
    int extra = 0;
    int old = 0;
    if (ns == NULL) {
        return NINLIL_RRMP_CU_ABSENT;
    }
    if (ns->fenced &&
        (ns->cu_class == NINLIL_RRMP_CU_PARTIAL ||
         ns->cu_class == NINLIL_RRMP_CU_EXTRA ||
         ns->cu_class == NINLIL_RRMP_CU_THIRD)) {
        return ns->cu_class;
    }
    if (ns->corrupt) {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    for (i = 0u; i < NINLIL_RRMP_PHYSICAL_KEY_COUNT; ++i) {
        uint32_t c = classify_meta(&ns->keys[i], &any);
        if (c == NINLIL_RRMP_CU_PARTIAL) {
            partial = 1;
        }
        if (c == NINLIL_RRMP_CU_THIRD) {
            third = 1;
        }
        if (c == NINLIL_RRMP_CU_EXTRA || ns->keys[i].extra_mark) {
            extra = 1;
        }
        if (ns->keys[i].present[0] && ns->keys[i].present[1] &&
            ns->keys[i].active != 0xFFu) {
            uint8_t other = (uint8_t)(1u - ns->keys[i].active);
            if (ns->keys[i].generation[other] <
                    ns->keys[i].generation[ns->keys[i].active] &&
                ns->keys[i].generation[other] != 0u) {
                old = 1;
            }
        }
    }
    if (third) {
        return NINLIL_RRMP_CU_THIRD;
    }
    if (extra) {
        return NINLIL_RRMP_CU_EXTRA;
    }
    if (partial) {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    if (!any) {
        return NINLIL_RRMP_CU_ABSENT;
    }
    {
        size_t j;
        for (j = 0u; j < NINLIL_RRMP_PHYSICAL_KEY_COUNT; ++j) {
            if (classify_meta(&ns->keys[j], NULL) == NINLIL_RRMP_CU_OLD) {
                return NINLIL_RRMP_CU_OLD;
            }
        }
    }
    (void)old;
    return NINLIL_RRMP_CU_NEW;
}

uint32_t ninlil_rrmp_parent_classify_cu(const ninlil_rrmp_parent_ns_t *ns)
{
    size_t i;
    int any = 0;
    int partial = 0;
    int third = 0;
    int extra = 0;
    if (ns == NULL) {
        return NINLIL_RRMP_CU_ABSENT;
    }
    if (ns->fenced &&
        (ns->cu_class == NINLIL_RRMP_CU_PARTIAL ||
         ns->cu_class == NINLIL_RRMP_CU_EXTRA ||
         ns->cu_class == NINLIL_RRMP_CU_THIRD)) {
        return ns->cu_class;
    }
    if (ns->corrupt) {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    for (i = 0u; i < NINLIL_RRMP_PKEY_COUNT; ++i) {
        uint32_t c = classify_meta(&ns->keys[i], &any);
        if (c == NINLIL_RRMP_CU_PARTIAL) {
            partial = 1;
        }
        if (c == NINLIL_RRMP_CU_THIRD) {
            third = 1;
        }
        if (c == NINLIL_RRMP_CU_EXTRA || ns->keys[i].extra_mark) {
            extra = 1;
        }
    }
    if (third) {
        return NINLIL_RRMP_CU_THIRD;
    }
    if (extra) {
        return NINLIL_RRMP_CU_EXTRA;
    }
    if (partial) {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    if (!any) {
        return NINLIL_RRMP_CU_ABSENT;
    }
    for (i = 0u; i < NINLIL_RRMP_PKEY_COUNT; ++i) {
        if (classify_meta(&ns->keys[i], NULL) == NINLIL_RRMP_CU_OLD) {
            return NINLIL_RRMP_CU_OLD;
        }
    }
    return NINLIL_RRMP_CU_NEW;
}

void ninlil_rrmp_route_inject_partial(ninlil_rrmp_route_ns_t *ns, uint8_t key_id)
{
    ninlil_rrmp_dual_meta_t *b;
    uint8_t slot;
    if (ns == NULL || key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
        return;
    }
    b = &ns->keys[key_id];
    slot = inactive_of(b);
    b->present[slot] = 0u;
    b->generation[slot] =
        (b->active == 0xFFu) ? 1u : (b->generation[b->active] + 1u);
    b->length[slot] = 0u;
}

void ninlil_rrmp_route_inject_extra(ninlil_rrmp_route_ns_t *ns, uint8_t key_id)
{
    uint8_t *buf;
    size_t cap;
    uint64_t gen;
    if (ns == NULL) {
        return;
    }
    if (!ninlil_rrmp_route_dual_begin_write(ns, key_id, &buf, &cap, &gen)) {
        /* Fail-closed: cannot prove image shape → fence as EXTRA-class. */
        ns->cu_class = NINLIL_RRMP_CU_EXTRA;
        ns->fenced = 1u;
        return;
    }
    buf[0] = 0xEEu;
    ns->keys[key_id].extra_mark = 1u;
    (void)ninlil_rrmp_route_dual_commit(ns, key_id, 1u);
    ns->cu_class = NINLIL_RRMP_CU_EXTRA;
    ns->fenced = 1u;
}

void ninlil_rrmp_route_inject_third(ninlil_rrmp_route_ns_t *ns, uint8_t key_id)
{
    ninlil_rrmp_dual_meta_t *b;
    int8_t p0;
    int8_t p1;
    if (ns == NULL || key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
        return;
    }
    b = &ns->keys[key_id];
    p0 = arena_alloc(ns->arena_used, NINLIL_RRMP_ROUTE_ARENA_PAGES);
    p1 = arena_alloc(ns->arena_used, NINLIL_RRMP_ROUTE_ARENA_PAGES);
    if (p0 < 0 || p1 < 0) {
        /* Fail-closed: third-image inject must not leave ns operable. */
        ns->cu_class = NINLIL_RRMP_CU_THIRD;
        ns->fenced = 1u;
        ns->corrupt = 1u;
        return;
    }
    b->page_idx[0] = p0;
    b->page_idx[1] = p1;
    b->present[0] = 1u;
    b->present[1] = 1u;
    b->generation[0] = 7u;
    b->generation[1] = 7u;
    b->length[0] = 8u;
    b->length[1] = 8u;
    b->active = 0u;
    ns->cu_class = NINLIL_RRMP_CU_THIRD;
    ns->fenced = 1u;
}

void ninlil_rrmp_route_inject_corrupt_active(
    ninlil_rrmp_route_ns_t *ns, uint8_t key_id)
{
    ninlil_rrmp_dual_meta_t *b;
    if (ns == NULL || key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
        return;
    }
    b = &ns->keys[key_id];
    if (b->active == 0xFFu || b->page_idx[b->active] < 0) {
        ns->corrupt = 1u;
        ns->fenced = 1u;
        ns->cu_class = NINLIL_RRMP_CU_PARTIAL;
        return;
    }
    ns->arena[(uint8_t)b->page_idx[b->active]][0] ^= 0xFFu;
    ns->corrupt = 1u;
    ns->fenced = 1u;
    ns->cu_class = NINLIL_RRMP_CU_PARTIAL;
}

static size_t dual_key_export_bytes(const ninlil_rrmp_dual_meta_t *b)
{
    size_t n = 0u;
    uint8_t s;
    for (s = 0u; s < 2u; ++s) {
        if (b->present[s] && b->page_idx[s] >= 0) {
            n += 1u + 8u + 4u + b->length[s];
        }
    }
    return n;
}

static uint8_t dual_key_export_count(const ninlil_rrmp_dual_meta_t *b)
{
    uint8_t c = 0u;
    uint8_t s;
    for (s = 0u; s < 2u; ++s) {
        if (b->present[s] && b->page_idx[s] >= 0) {
            ++c;
        }
    }
    return c;
}

/* Emit lower generation first so import end-state has NEW active + OLD retained. */
static size_t dual_key_export_write(
    const ninlil_rrmp_dual_meta_t *b,
    const uint8_t arena[][4096],
    uint8_t key_id,
    uint8_t *out,
    size_t off)
{
    uint8_t order[2];
    uint8_t n = 0u;
    uint8_t s;
    uint8_t i;
    for (s = 0u; s < 2u; ++s) {
        if (b->present[s] && b->page_idx[s] >= 0) {
            order[n++] = s;
        }
    }
    if (n == 2u && b->generation[order[0]] > b->generation[order[1]]) {
        uint8_t t = order[0];
        order[0] = order[1];
        order[1] = t;
    }
    for (i = 0u; i < n; ++i) {
        uint8_t slot = order[i];
        uint32_t L = b->length[slot];
        int8_t pi = b->page_idx[slot];
        out[off++] = key_id;
        ninlil_rrmp_put_u64_be(out + off, b->generation[slot]);
        off += 8u;
        ninlil_rrmp_put_u32_be(out + off, L);
        off += 4u;
        if (pi >= 0) {
            memcpy(out + off, arena[(uint8_t)pi], L);
        }
        off += L;
    }
    return off;
}

size_t ninlil_rrmp_route_ns_export_size(const ninlil_rrmp_route_ns_t *ns)
{
    size_t n = 8u;
    size_t i;
    if (ns == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_RRMP_PHYSICAL_KEY_COUNT; ++i) {
        n += dual_key_export_bytes(&ns->keys[i]);
    }
    return n;
}

int ninlil_rrmp_route_ns_export(
    const ninlil_rrmp_route_ns_t *ns, uint8_t *out, size_t cap, size_t *len)
{
    size_t need;
    size_t off = 0u;
    size_t i;
    uint8_t count = 0u;
    if (ns == NULL || len == NULL) {
        return 0;
    }
    need = ninlil_rrmp_route_ns_export_size(ns);
    *len = need;
    if (out == NULL || cap < need) {
        return out == NULL ? 1 : 0;
    }
    out[0] = 'R';
    out[1] = 'N';
    out[2] = 'S';
    out[3] = '1';
    for (i = 0u; i < NINLIL_RRMP_PHYSICAL_KEY_COUNT; ++i) {
        count = (uint8_t)(count + dual_key_export_count(&ns->keys[i]));
    }
    out[4] = count;
    out[5] = 0u;
    out[6] = 0u;
    out[7] = 0u;
    off = 8u;
    for (i = 0u; i < NINLIL_RRMP_PHYSICAL_KEY_COUNT; ++i) {
        off = dual_key_export_write(
            &ns->keys[i], ns->arena, (uint8_t)i, out, off);
    }
    return 1;
}

static void route_import_fence(
    ninlil_rrmp_route_ns_t *ns, uint32_t cu_class)
{
    ninlil_rrmp_route_ns_init(ns);
    ns->cu_class = cu_class;
    ns->corrupt = 1u;
    ns->fenced = 1u;
}

static int import_bytes_zero(const uint8_t *bytes, size_t length)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int import_bytes_nonzero(const uint8_t *bytes, size_t length)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int route_directory_semantic_valid(const uint8_t *record)
{
    uint16_t route_bits = 0u;
    uint16_t evidence_bits = 0u;
    size_t i;
    if (!import_bytes_nonzero(record + 16u, 16u) ||
        ninlil_rrmp_get_u64_be(record + 32u) == 0u ||
        ninlil_rrmp_get_u64_be(record + 32u) == UINT64_MAX ||
        !import_bytes_zero(record + 124u, 128u)) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_PAGE_COUNT; ++i) {
        uint32_t generation =
            ninlil_rrmp_get_u32_be(record + 44u + i * 4u);
        if (generation == UINT32_MAX) {
            return 0;
        }
        if (generation != 0u) {
            route_bits =
                (uint16_t)(route_bits | (uint16_t)(1u << i));
        }
    }
    for (i = 0u; i < NINLIL_RRMP_NEP1_PAGE_COUNT; ++i) {
        uint32_t generation =
            ninlil_rrmp_get_u32_be(record + 108u + i * 4u);
        if (generation == UINT32_MAX) {
            return 0;
        }
        if (generation != 0u) {
            evidence_bits =
                (uint16_t)(evidence_bits | (uint16_t)(1u << i));
        }
    }
    return route_bits == ninlil_rrmp_get_u16_be(record + 40u) &&
                   evidence_bits == ninlil_rrmp_get_u16_be(record + 42u)
               ? 1
               : 0;
}

static int route_slot_import_valid(const uint8_t *slot)
{
    ninlil_rrmp_nrm1_fields_t fields;
    uint8_t exact[NINLIL_RRMP_EXACT_BODY_BYTES];
    uint8_t state = 0u;
    uint64_t next_admission_seq = 0u;
    size_t i;
    if (slot[0] < NINLIL_RRMP_ROUTE_STATE_INSTALLED ||
        slot[0] > NINLIL_RRMP_ROUTE_STATE_RETIRED ||
        !import_bytes_zero(slot + 1u, 3u) ||
        !import_bytes_zero(slot + 464u, 44u) ||
        !ninlil_rrmp_decode_slot_state(
            slot, &state, &fields, &next_admission_seq) ||
        !ninlil_rrmp_materialize_exact(&fields, exact) ||
        memcmp(exact, slot + 268u, NINLIL_RRMP_EXACT_BODY_BYTES) != 0 ||
        ninlil_rrmp_get_u32_be(slot + 4u) !=
            fields.ingress_hop_context_id ||
        ninlil_rrmp_get_u16_be(slot + 8u) != fields.route_handle ||
        ninlil_rrmp_get_u16_be(slot + 10u) != fields.route_generation ||
        !import_bytes_nonzero(slot + 364u, 16u) ||
        ninlil_rrmp_get_u64_be(slot + 380u) == 0u ||
        ninlil_rrmp_get_u64_be(slot + 380u) == UINT64_MAX) {
        return 0;
    }
    if (state >= NINLIL_RRMP_ROUTE_STATE_INSTALLED &&
        state <= NINLIL_RRMP_ROUTE_STATE_DRAINING &&
        (next_admission_seq == 0u || next_admission_seq == UINT64_MAX)) {
        return 0;
    }
    if (state == NINLIL_RRMP_ROUTE_STATE_DRAINING) {
        for (i = 0u; i < 4u; ++i) {
            uint64_t value =
                ninlil_rrmp_get_u64_be(slot + 388u + i * 8u);
            if (value == 0u || value == UINT64_MAX) {
                return 0;
            }
        }
    }
    return 1;
}

static int route_page_semantic_valid(const uint8_t *record)
{
    uint16_t bitmap = ninlil_rrmp_get_u16_be(record + 12u);
    size_t i;
    if ((bitmap & 0xff00u) != 0u ||
        ninlil_rrmp_get_u16_be(record + 14u) != 0u ||
        !import_bytes_zero(
            record + NINLIL_RRMP_NRP1_HEADER_BYTES +
                NINLIL_RRMP_SLOTS_PER_PAGE * NINLIL_RRMP_SLOT_BYTES,
            NINLIL_RRMP_NRP1_PAD_BYTES)) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_SLOTS_PER_PAGE; ++i) {
        const uint8_t *slot =
            record + NINLIL_RRMP_NRP1_HEADER_BYTES +
            i * NINLIL_RRMP_SLOT_BYTES;
        if ((bitmap & (uint16_t)(1u << i)) != 0u) {
            if (!route_slot_import_valid(slot)) {
                return 0;
            }
        } else if (!import_bytes_zero(slot, NINLIL_RRMP_SLOT_BYTES)) {
            return 0;
        }
    }
    return 1;
}

static int evidence_page_semantic_valid(const uint8_t *record)
{
    uint32_t count = ninlil_rrmp_get_u32_be(record + 12u);
    size_t i;
    if (ninlil_rrmp_get_u32_be(record + 16u) != 0u ||
        !import_bytes_zero(
            record + NINLIL_RRMP_NEP1_HEADER_BYTES +
                NINLIL_RRMP_NEP1_SLOTS * NINLIL_RRMP_NEV1_BYTES,
            NINLIL_RRMP_NEP1_PAD_BYTES)) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_NEP1_SLOTS; ++i) {
        const uint8_t *slot =
            record + NINLIL_RRMP_NEP1_HEADER_BYTES +
            i * NINLIL_RRMP_NEV1_BYTES;
        if (i < count) {
            if (slot[87] != 0u || !ninlil_rrmp_validate_nev1(slot)) {
                return 0;
            }
        } else if (!import_bytes_zero(slot, NINLIL_RRMP_NEV1_BYTES)) {
            return 0;
        }
    }
    return 1;
}

static uint32_t route_import_record_class(
    uint8_t kid, uint64_t gen, const uint8_t *record, uint32_t length)
{
    uint16_t page_index;
    uint32_t page_generation;
    if (kid == NINLIL_RRMP_KEY_NRD1) {
        if (length != NINLIL_RRMP_DIR_BYTES ||
            gen == 0u || gen == UINT64_MAX ||
            !ninlil_rrmp_validate_nrd1(record) ||
            ninlil_rrmp_get_u64_be(record + 8u) != gen ||
            !route_directory_semantic_valid(record)) {
            return NINLIL_RRMP_CU_THIRD;
        }
        return NINLIL_RRMP_CU_NONE;
    }
    if (gen == 0u || gen >= UINT32_MAX || length != 4096u) {
        return NINLIL_RRMP_CU_THIRD;
    }
    page_index = ninlil_rrmp_get_u16_be(record + 6u);
    page_generation = ninlil_rrmp_get_u32_be(record + 8u);
    if (page_generation != (uint32_t)gen) {
        return NINLIL_RRMP_CU_THIRD;
    }
    if (kid >= NINLIL_RRMP_KEY_NRP1_BASE &&
        kid < NINLIL_RRMP_KEY_NEP1_BASE) {
        if (page_index !=
                (uint16_t)(kid - NINLIL_RRMP_KEY_NRP1_BASE) ||
            !ninlil_rrmp_validate_nrp1(record) ||
            !route_page_semantic_valid(record)) {
            return NINLIL_RRMP_CU_THIRD;
        }
        return NINLIL_RRMP_CU_NONE;
    }
    if (kid >= NINLIL_RRMP_KEY_NEP1_BASE &&
        kid < NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
        if (page_index !=
                (uint16_t)(kid - NINLIL_RRMP_KEY_NEP1_BASE) ||
            !ninlil_rrmp_validate_nep1(record) ||
            !evidence_page_semantic_valid(record)) {
            return NINLIL_RRMP_CU_THIRD;
        }
        return NINLIL_RRMP_CU_NONE;
    }
    return NINLIL_RRMP_CU_EXTRA;
}

static uint32_t route_import_preflight(const uint8_t *in, size_t len)
{
    uint8_t seen[NINLIL_RRMP_PHYSICAL_KEY_COUNT];
    size_t off = 8u;
    uint8_t count;
    uint8_t i;
    uint8_t previous_kid = 0u;
    uint64_t previous_gen = 0u;
    int have_previous = 0;
    if (in == NULL || len < 8u ||
        in[0] != 'R' || in[1] != 'N' || in[2] != 'S' || in[3] != '1') {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    if (in[5] != 0u || in[6] != 0u || in[7] != 0u) {
        return NINLIL_RRMP_CU_THIRD;
    }
    count = in[4];
    if (count > 2u * NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
        return NINLIL_RRMP_CU_THIRD;
    }
    ninlil_rrmp_memzero(seen, sizeof(seen));
    for (i = 0u; i < count; ++i) {
        uint8_t kid;
        uint64_t gen;
        uint32_t length;
        uint32_t record_class;
        if (off > len || len - off < 13u) {
            return NINLIL_RRMP_CU_PARTIAL;
        }
        kid = in[off++];
        gen = ninlil_rrmp_get_u64_be(in + off);
        off += 8u;
        length = ninlil_rrmp_get_u32_be(in + off);
        off += 4u;
        if (kid >= NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
            return NINLIL_RRMP_CU_EXTRA;
        }
        if ((have_previous &&
             (kid < previous_kid ||
              (kid == previous_kid && gen <= previous_gen))) ||
            ++seen[kid] > 2u) {
            return NINLIL_RRMP_CU_THIRD;
        }
        if (off > len || (size_t)length > len - off) {
            return NINLIL_RRMP_CU_PARTIAL;
        }
        record_class =
            route_import_record_class(kid, gen, in + off, length);
        if (record_class != NINLIL_RRMP_CU_NONE) {
            return record_class;
        }
        off += length;
        previous_kid = kid;
        previous_gen = gen;
        have_previous = 1;
    }
    return off == len ? NINLIL_RRMP_CU_NONE : NINLIL_RRMP_CU_EXTRA;
}

int ninlil_rrmp_route_ns_import(
    ninlil_rrmp_route_ns_t *ns, const uint8_t *in, size_t len)
{
    size_t off = 8u;
    uint32_t preflight;
    uint8_t count;
    uint8_t i;
    if (ns == NULL) {
        return 0;
    }
    if (ns->fenced) {
        return 0;
    }
    preflight = route_import_preflight(in, len);
    if (preflight != NINLIL_RRMP_CU_NONE) {
        route_import_fence(ns, preflight);
        return 0;
    }
    ninlil_rrmp_route_ns_init(ns);
    count = in[4];
    for (i = 0u; i < count; ++i) {
        uint8_t kid;
        uint64_t gen;
        uint32_t L;
        uint8_t *buf;
        size_t cap;
        uint64_t g2;
        kid = in[off++];
        gen = ninlil_rrmp_get_u64_be(in + off);
        off += 8u;
        L = ninlil_rrmp_get_u32_be(in + off);
        off += 4u;
        if (!ninlil_rrmp_route_dual_begin_write(ns, kid, &buf, &cap, &g2)) {
            route_import_fence(ns, NINLIL_RRMP_CU_PARTIAL);
            return 0;
        }
        memcpy(buf, in + off, L);
        off += L;
        if (!ninlil_rrmp_route_dual_commit(ns, kid, L)) {
            route_import_fence(ns, NINLIL_RRMP_CU_PARTIAL);
            return 0;
        }
        ns->keys[kid].generation[ns->keys[kid].active] = gen;
    }
    ns->cu_class = ninlil_rrmp_route_classify_cu(ns);
    return 1;
}

size_t ninlil_rrmp_parent_ns_export_size(const ninlil_rrmp_parent_ns_t *ns)
{
    size_t n = 8u;
    size_t i;
    if (ns == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_RRMP_PKEY_COUNT; ++i) {
        n += dual_key_export_bytes(&ns->keys[i]);
    }
    return n;
}

int ninlil_rrmp_parent_ns_export(
    const ninlil_rrmp_parent_ns_t *ns, uint8_t *out, size_t cap, size_t *len)
{
    size_t need;
    size_t off = 0u;
    size_t i;
    uint8_t count = 0u;
    if (ns == NULL || len == NULL) {
        return 0;
    }
    need = ninlil_rrmp_parent_ns_export_size(ns);
    *len = need;
    if (out == NULL || cap < need) {
        return out == NULL ? 1 : 0;
    }
    out[0] = 'P';
    out[1] = 'N';
    out[2] = 'S';
    out[3] = '1';
    for (i = 0u; i < NINLIL_RRMP_PKEY_COUNT; ++i) {
        count = (uint8_t)(count + dual_key_export_count(&ns->keys[i]));
    }
    out[4] = count;
    out[5] = out[6] = out[7] = 0u;
    off = 8u;
    for (i = 0u; i < NINLIL_RRMP_PKEY_COUNT; ++i) {
        off = dual_key_export_write(
            &ns->keys[i], ns->arena, (uint8_t)i, out, off);
    }
    return 1;
}

static void parent_import_fence(
    ninlil_rrmp_parent_ns_t *ns, uint32_t cu_class)
{
    ninlil_rrmp_parent_ns_init(ns);
    ns->cu_class = cu_class;
    ns->corrupt = 1u;
    ns->fenced = 1u;
}

static uint32_t parent_import_record_class(
    uint8_t kid, uint64_t gen, const uint8_t *record, uint32_t length)
{
    uint16_t page_index;
    uint32_t page_generation;
    if (kid == NINLIL_RRMP_PKEY_NPH1) {
        if (length != NINLIL_RRMP_NPH1_BYTES ||
            gen == 0u || gen == UINT64_MAX ||
            !ninlil_rrmp_validate_nph1(record) ||
            ninlil_rrmp_get_u64_be(record + 112u) != gen) {
            return NINLIL_RRMP_CU_THIRD;
        }
        return NINLIL_RRMP_CU_NONE;
    }
    if (gen == 0u || gen >= UINT32_MAX || length != 4096u) {
        return NINLIL_RRMP_CU_THIRD;
    }
    page_index = ninlil_rrmp_get_u16_be(record + 6u);
    page_generation = ninlil_rrmp_get_u32_be(record + 8u);
    if (page_generation != (uint32_t)gen) {
        return NINLIL_RRMP_CU_THIRD;
    }
    if (kid >= NINLIL_RRMP_PKEY_NPP1_BASE &&
        kid < NINLIL_RRMP_PKEY_NPA1_BASE) {
        if (page_index !=
                (uint16_t)(kid - NINLIL_RRMP_PKEY_NPP1_BASE) ||
            !ninlil_rrmp_validate_npp1(record)) {
            return NINLIL_RRMP_CU_THIRD;
        }
        return NINLIL_RRMP_CU_NONE;
    }
    if (kid >= NINLIL_RRMP_PKEY_NPA1_BASE &&
        kid < NINLIL_RRMP_PKEY_NPT1_BASE) {
        if (page_index !=
                (uint16_t)(kid - NINLIL_RRMP_PKEY_NPA1_BASE) ||
            !ninlil_rrmp_validate_npa1(record)) {
            return NINLIL_RRMP_CU_THIRD;
        }
        return NINLIL_RRMP_CU_NONE;
    }
    if (kid >= NINLIL_RRMP_PKEY_NPT1_BASE &&
        kid < NINLIL_RRMP_PKEY_COUNT) {
        if (page_index !=
                (uint16_t)(kid - NINLIL_RRMP_PKEY_NPT1_BASE) ||
            !ninlil_rrmp_validate_npt1(record)) {
            return NINLIL_RRMP_CU_THIRD;
        }
        return NINLIL_RRMP_CU_NONE;
    }
    return NINLIL_RRMP_CU_EXTRA;
}

static uint32_t parent_import_preflight(const uint8_t *in, size_t len)
{
    uint8_t seen[NINLIL_RRMP_PKEY_COUNT];
    size_t off = 8u;
    uint8_t count;
    uint8_t i;
    uint8_t previous_kid = 0u;
    uint64_t previous_gen = 0u;
    int have_previous = 0;
    if (in == NULL || len < 8u ||
        in[0] != 'P' || in[1] != 'N' || in[2] != 'S' || in[3] != '1') {
        return NINLIL_RRMP_CU_PARTIAL;
    }
    if (in[5] != 0u || in[6] != 0u || in[7] != 0u) {
        return NINLIL_RRMP_CU_THIRD;
    }
    count = in[4];
    if (count > 2u * NINLIL_RRMP_PKEY_COUNT) {
        return NINLIL_RRMP_CU_THIRD;
    }
    ninlil_rrmp_memzero(seen, sizeof(seen));
    for (i = 0u; i < count; ++i) {
        uint8_t kid;
        uint64_t gen;
        uint32_t length;
        uint32_t record_class;
        if (off > len || len - off < 13u) {
            return NINLIL_RRMP_CU_PARTIAL;
        }
        kid = in[off++];
        gen = ninlil_rrmp_get_u64_be(in + off);
        off += 8u;
        length = ninlil_rrmp_get_u32_be(in + off);
        off += 4u;
        if (kid >= NINLIL_RRMP_PKEY_COUNT) {
            return NINLIL_RRMP_CU_EXTRA;
        }
        if ((have_previous &&
             (kid < previous_kid ||
              (kid == previous_kid && gen <= previous_gen))) ||
            ++seen[kid] > 2u) {
            return NINLIL_RRMP_CU_THIRD;
        }
        if (off > len || (size_t)length > len - off) {
            return NINLIL_RRMP_CU_PARTIAL;
        }
        record_class =
            parent_import_record_class(kid, gen, in + off, length);
        if (record_class != NINLIL_RRMP_CU_NONE) {
            return record_class;
        }
        off += length;
        previous_kid = kid;
        previous_gen = gen;
        have_previous = 1;
    }
    return off == len ? NINLIL_RRMP_CU_NONE : NINLIL_RRMP_CU_EXTRA;
}

int ninlil_rrmp_parent_ns_import(
    ninlil_rrmp_parent_ns_t *ns, const uint8_t *in, size_t len)
{
    size_t off = 8u;
    uint32_t preflight;
    uint8_t count;
    uint8_t i;
    if (ns == NULL) {
        return 0;
    }
    if (ns->fenced) {
        return 0;
    }
    preflight = parent_import_preflight(in, len);
    if (preflight != NINLIL_RRMP_CU_NONE) {
        parent_import_fence(ns, preflight);
        return 0;
    }
    ninlil_rrmp_parent_ns_init(ns);
    count = in[4];
    for (i = 0u; i < count; ++i) {
        uint8_t kid;
        uint64_t gen;
        uint32_t L;
        uint8_t *buf;
        size_t cap;
        uint64_t g2;
        kid = in[off++];
        gen = ninlil_rrmp_get_u64_be(in + off);
        off += 8u;
        L = ninlil_rrmp_get_u32_be(in + off);
        off += 4u;
        if (!ninlil_rrmp_parent_dual_begin_write(ns, kid, &buf, &cap, &g2)) {
            parent_import_fence(ns, NINLIL_RRMP_CU_PARTIAL);
            return 0;
        }
        memcpy(buf, in + off, L);
        off += L;
        if (!ninlil_rrmp_parent_dual_commit(ns, kid, L)) {
            parent_import_fence(ns, NINLIL_RRMP_CU_PARTIAL);
            return 0;
        }
        ns->keys[kid].generation[ns->keys[kid].active] = gen;
    }
    ns->cu_class = ninlil_rrmp_parent_classify_cu(ns);
    return 1;
}

void ninlil_rrmp_route_inject_cu_old(ninlil_rrmp_route_ns_t *ns, uint8_t key_id)
{
    ninlil_rrmp_dual_meta_t *b;
    int8_t p0;
    int8_t p1;
    if (ns == NULL || key_id >= NINLIL_RRMP_PHYSICAL_KEY_COUNT) {
        return;
    }
    b = &ns->keys[key_id];
    p0 = arena_alloc(ns->arena_used, NINLIL_RRMP_ROUTE_ARENA_PAGES);
    p1 = arena_alloc(ns->arena_used, NINLIL_RRMP_ROUTE_ARENA_PAGES);
    if (p0 < 0 || p1 < 0) {
        return;
    }
    b->page_idx[0] = p0;
    b->page_idx[1] = p1;
    b->present[0] = 1u;
    b->present[1] = 1u;
    b->generation[0] = 1u; /* older active */
    b->generation[1] = 2u; /* newer retained */
    b->length[0] = 8u;
    b->length[1] = 8u;
    b->active = 0u;
}

void ninlil_rrmp_parent_inject_cu_old(ninlil_rrmp_parent_ns_t *ns, uint8_t key_id)
{
    ninlil_rrmp_dual_meta_t *b;
    int8_t p0;
    int8_t p1;
    if (ns == NULL || key_id >= NINLIL_RRMP_PKEY_COUNT) {
        return;
    }
    b = &ns->keys[key_id];
    p0 = arena_alloc(ns->arena_used, NINLIL_RRMP_PARENT_ARENA_PAGES);
    p1 = arena_alloc(ns->arena_used, NINLIL_RRMP_PARENT_ARENA_PAGES);
    if (p0 < 0 || p1 < 0) {
        return;
    }
    b->page_idx[0] = p0;
    b->page_idx[1] = p1;
    b->present[0] = 1u;
    b->present[1] = 1u;
    b->generation[0] = 1u;
    b->generation[1] = 2u;
    b->length[0] = 8u;
    b->length[1] = 8u;
    b->active = 0u;
}
