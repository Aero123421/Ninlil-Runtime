/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Fixed-length dual-slot durable provider with shared page arena
 * (ESP-budget: no per-key 2x4096 embedding).
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_STORE_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_STORE_H

#include "rrmp_types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RRMP_KEY_NRD1 0u
#define NINLIL_RRMP_KEY_NRP1_BASE 1u
#define NINLIL_RRMP_KEY_NEP1_BASE 17u
/* Parent namespace keys (ADR-0020 §12.1 exact budget 22): NPH1 + 5 NPP1 + 8 NPA1 + 8 NPT1 */
#define NINLIL_RRMP_PKEY_NPH1 0u
#define NINLIL_RRMP_PKEY_NPP1_BASE 1u  /* 1..5 */
#define NINLIL_RRMP_PKEY_NPA1_BASE 6u  /* 6..13 */
#define NINLIL_RRMP_PKEY_NPT1_BASE 14u /* 14..21 */
#define NINLIL_RRMP_PKEY_COUNT 22u
#define NINLIL_RRMP_DUAL 2u

/*
 * Shared page arenas.  The namespace must be able to retain every canonical
 * key at once plus one inactive page while a dual-slot update is staged.
 * Smaller arenas make the advertised 128-route / 64-scope capacities
 * unreachable even though the in-memory tables still have free entries.
 */
#define NINLIL_RRMP_ROUTE_ARENA_PAGES \
    (NINLIL_RRMP_PHYSICAL_KEY_COUNT + 1u)
#define NINLIL_RRMP_PARENT_ARENA_PAGES (NINLIL_RRMP_PKEY_COUNT + 1u)

typedef struct ninlil_rrmp_dual_meta {
    uint8_t present[NINLIL_RRMP_DUAL];
    uint64_t generation[NINLIL_RRMP_DUAL];
    uint32_t length[NINLIL_RRMP_DUAL];
    int8_t page_idx[NINLIL_RRMP_DUAL]; /* -1 = none; else arena index */
    uint8_t active;                     /* 0/1 or 0xFF none */
    uint8_t extra_mark;                 /* EXTRA injection */
} ninlil_rrmp_dual_meta_t;

typedef struct ninlil_rrmp_route_ns {
    ninlil_rrmp_dual_meta_t keys[NINLIL_RRMP_PHYSICAL_KEY_COUNT];
    uint8_t arena[NINLIL_RRMP_ROUTE_ARENA_PAGES][4096];
    uint8_t arena_used[NINLIL_RRMP_ROUTE_ARENA_PAGES];
    uint32_t cu_class;
    uint8_t corrupt;
    uint8_t fenced;
} ninlil_rrmp_route_ns_t;

typedef struct ninlil_rrmp_parent_ns {
    ninlil_rrmp_dual_meta_t keys[NINLIL_RRMP_PKEY_COUNT];
    uint8_t arena[NINLIL_RRMP_PARENT_ARENA_PAGES][4096];
    uint8_t arena_used[NINLIL_RRMP_PARENT_ARENA_PAGES];
    uint32_t cu_class;
    uint8_t corrupt;
    uint8_t fenced;
    uint64_t writer_generation;
    uint8_t sole_writer_id[16];
    uint8_t sole_writer_set;
} ninlil_rrmp_parent_ns_t;

void ninlil_rrmp_route_ns_init(ninlil_rrmp_route_ns_t *ns);
void ninlil_rrmp_parent_ns_init(ninlil_rrmp_parent_ns_t *ns);

int ninlil_rrmp_route_dual_begin_write(
    ninlil_rrmp_route_ns_t *ns,
    uint8_t key_id,
    uint8_t **out_buf,
    size_t *out_cap,
    uint64_t *out_gen);
int ninlil_rrmp_route_dual_commit(
    ninlil_rrmp_route_ns_t *ns, uint8_t key_id, uint32_t length);
int ninlil_rrmp_route_dual_read_active(
    const ninlil_rrmp_route_ns_t *ns,
    uint8_t key_id,
    const uint8_t **out,
    uint32_t *len,
    uint64_t *gen);
/* Non-active complete page when dual OLD retained (gen lower than active). */
int ninlil_rrmp_route_dual_read_retained_old(
    const ninlil_rrmp_route_ns_t *ns,
    uint8_t key_id,
    const uint8_t **out,
    uint32_t *len,
    uint64_t *gen);

int ninlil_rrmp_parent_dual_begin_write(
    ninlil_rrmp_parent_ns_t *ns,
    uint8_t key_id,
    uint8_t **out_buf,
    size_t *out_cap,
    uint64_t *out_gen);
int ninlil_rrmp_parent_dual_commit(
    ninlil_rrmp_parent_ns_t *ns, uint8_t key_id, uint32_t length);
int ninlil_rrmp_parent_dual_read_active(
    const ninlil_rrmp_parent_ns_t *ns,
    uint8_t key_id,
    const uint8_t **out,
    uint32_t *len,
    uint64_t *gen);

int ninlil_rrmp_route_full_commit(
    ninlil_rrmp_route_ns_t *ns, const uint8_t *key_ids, uint8_t n);
int ninlil_rrmp_parent_full_commit(
    ninlil_rrmp_parent_ns_t *ns, const uint8_t *key_ids, uint8_t n);

uint32_t ninlil_rrmp_route_classify_cu(const ninlil_rrmp_route_ns_t *ns);
uint32_t ninlil_rrmp_parent_classify_cu(const ninlil_rrmp_parent_ns_t *ns);

void ninlil_rrmp_route_inject_partial(ninlil_rrmp_route_ns_t *ns, uint8_t key_id);
void ninlil_rrmp_route_inject_extra(ninlil_rrmp_route_ns_t *ns, uint8_t key_id);
void ninlil_rrmp_route_inject_third(ninlil_rrmp_route_ns_t *ns, uint8_t key_id);
void ninlil_rrmp_route_inject_corrupt_active(
    ninlil_rrmp_route_ns_t *ns, uint8_t key_id);
/* Force active=older, other=newer complete → CU_OLD for fault-injection tests. */
void ninlil_rrmp_route_inject_cu_old(ninlil_rrmp_route_ns_t *ns, uint8_t key_id);
void ninlil_rrmp_parent_inject_cu_old(ninlil_rrmp_parent_ns_t *ns, uint8_t key_id);

size_t ninlil_rrmp_route_ns_export_size(const ninlil_rrmp_route_ns_t *ns);
int ninlil_rrmp_route_ns_export(
    const ninlil_rrmp_route_ns_t *ns, uint8_t *out, size_t cap, size_t *len);
int ninlil_rrmp_route_ns_import(
    ninlil_rrmp_route_ns_t *ns, const uint8_t *in, size_t len);

size_t ninlil_rrmp_parent_ns_export_size(const ninlil_rrmp_parent_ns_t *ns);
int ninlil_rrmp_parent_ns_export(
    const ninlil_rrmp_parent_ns_t *ns, uint8_t *out, size_t cap, size_t *len);
int ninlil_rrmp_parent_ns_import(
    ninlil_rrmp_parent_ns_t *ns, const uint8_t *in, size_t len);

#ifdef __cplusplus
}
#endif

#endif
