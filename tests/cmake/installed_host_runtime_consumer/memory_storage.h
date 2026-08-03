#ifndef NINLIL_INSTALLED_CONSUMER_MEMORY_STORAGE_H
#define NINLIL_INSTALLED_CONSUMER_MEMORY_STORAGE_H

#include <stdint.h>

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct consumer_memory_storage consumer_memory_storage_t;

/*
 * A deliberately bounded, process-local provider used by the installed
 * package smoke. It is consumer-owned code and uses only Ninlil's installed
 * public storage ABI.
 */
consumer_memory_storage_t *consumer_memory_storage_create(void);
void consumer_memory_storage_destroy(consumer_memory_storage_t *storage);

const ninlil_storage_ops_t *consumer_memory_storage_ops(
    consumer_memory_storage_t *storage);

uint64_t consumer_memory_storage_live_handles(
    const consumer_memory_storage_t *storage);
uint64_t consumer_memory_storage_live_transactions(
    const consumer_memory_storage_t *storage);
uint64_t consumer_memory_storage_live_iterators(
    const consumer_memory_storage_t *storage);

#ifdef __cplusplus
}
#endif

#endif
