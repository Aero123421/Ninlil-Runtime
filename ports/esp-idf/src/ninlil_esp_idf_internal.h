/*
 * Portable internal-linkage / non-default visibility for private port helpers.
 * Not a public API. Not installed. Does not make symbols public.
 *
 * GCC/Clang: STV_HIDDEN (not GLOBAL DEFAULT in final ELF).
 * Other compilers: no attribute (link still private via non-install headers).
 */

#ifndef NINLIL_ESP_IDF_INTERNAL_H
#define NINLIL_ESP_IDF_INTERNAL_H

#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_ESP_IDF_INTERNAL __attribute__((visibility("hidden")))
#else
#define NINLIL_ESP_IDF_INTERNAL
#endif

#endif
