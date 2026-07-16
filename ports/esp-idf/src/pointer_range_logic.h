/*
 * Overflow-safe pure address-range helpers (docs/22).
 * uintptr_t only — no pointer relational operators (< > <= >=).
 * Pointee contents are never read (address + size only).
 */

#ifndef NINLIL_ESP_IDF_POINTER_RANGE_LOGIC_H
#define NINLIL_ESP_IDF_POINTER_RANGE_LOGIC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 1 if representable: size==0 always; size>0 requires non-NULL and no start+size overflow. */
int ninlil_esp_idf_pointer_range_representable(const void *p, size_t size);

/*
 * 1 = ranges overlap, or either range is unrepresentable (fail-closed).
 * 0 = disjoint, or either size is 0 (vacuous non-overlap).
 * Never compares pointers with relational operators.
 * Address-only: does not read pointee contents (safe for not-yet-written outs).
 */
int ninlil_esp_idf_pointer_ranges_overlap(
    const void *a,
    size_t a_size,
    const void *b,
    size_t b_size);

/*
 * 1 if inner is fully contained in outer (integer ends only).
 * 0 if either unrepresentable, empty, or not contained.
 */
int ninlil_esp_idf_pointer_range_contains(
    const void *outer,
    size_t outer_size,
    const void *inner,
    size_t inner_size);

#ifdef __cplusplus
}
#endif

#endif
