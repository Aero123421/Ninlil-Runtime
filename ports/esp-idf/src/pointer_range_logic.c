#include "pointer_range_logic.h"

#include <stdint.h>

int ninlil_esp_idf_pointer_range_representable(const void *p, size_t size)
{
    uintptr_t start;

    if (size == 0u) {
        return 1;
    }
    if (p == NULL) {
        return 0;
    }
    start = (uintptr_t)p;
    /* Checked start+size: size > UINTPTR_MAX - start ⇒ overflow. */
    if (size > (size_t)(UINTPTR_MAX - start)) {
        return 0;
    }
    return 1;
}

int ninlil_esp_idf_pointer_ranges_overlap(
    const void *a,
    size_t a_size,
    const void *b,
    size_t b_size)
{
    uintptr_t a_start;
    uintptr_t b_start;
    uintptr_t a_end;
    uintptr_t b_end;

    if (a_size == 0u || b_size == 0u) {
        return 0;
    }
    if (!ninlil_esp_idf_pointer_range_representable(a, a_size)
        || !ninlil_esp_idf_pointer_range_representable(b, b_size)) {
        return 1;
    }

    a_start = (uintptr_t)a;
    b_start = (uintptr_t)b;
    a_end = a_start + (uintptr_t)a_size;
    b_end = b_start + (uintptr_t)b_size;

    /* Integer end compares only (not pointer relational ops). */
    if (a_end <= b_start || b_end <= a_start) {
        return 0;
    }
    return 1;
}

int ninlil_esp_idf_pointer_range_contains(
    const void *outer,
    size_t outer_size,
    const void *inner,
    size_t inner_size)
{
    uintptr_t o_start;
    uintptr_t i_start;
    uintptr_t o_end;
    uintptr_t i_end;

    if (outer_size == 0u || inner_size == 0u) {
        return 0;
    }
    if (!ninlil_esp_idf_pointer_range_representable(outer, outer_size)
        || !ninlil_esp_idf_pointer_range_representable(inner, inner_size)) {
        return 0;
    }
    o_start = (uintptr_t)outer;
    i_start = (uintptr_t)inner;
    o_end = o_start + (uintptr_t)outer_size;
    i_end = i_start + (uintptr_t)inner_size;
    return (o_start <= i_start && i_end <= o_end) ? 1 : 0;
}
