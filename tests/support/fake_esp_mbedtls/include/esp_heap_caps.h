/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TEST_FAKE_ESP_HEAP_CAPS_H
#define NINLIL_TEST_FAKE_ESP_HEAP_CAPS_H

#include <stddef.h>
#include <stdint.h>

#define MALLOC_CAP_INTERNAL UINT32_C(0x01)
#define MALLOC_CAP_SPIRAM UINT32_C(0x02)
#define MALLOC_CAP_8BIT UINT32_C(0x04)

void *heap_caps_calloc(size_t count, size_t size, uint32_t caps);
void heap_caps_free(void *pointer);
size_t heap_caps_get_free_size(uint32_t caps);
size_t heap_caps_get_largest_free_block(uint32_t caps);

#endif
