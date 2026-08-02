/*
 * Private Fabric v1 utilities — not installed, not public ABI.
 * Authority: docs/adr/0017-bearer-registry-path-selection.md,
 *            docs/34-v2-runtime-fabric-completion.md §5.
 *
 * Symbol prefix: ninlil_fabric_private_
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_UTIL_H
#define NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ninlil/fabric_v1.h"

/* Canonical NFL1 sizes live in nfl1_codec.h (single authority). */
#include "nfl1_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_FABRIC_PRIVATE_API_VERSION NINLIL_FABRIC_API_VERSION
#define NINLIL_FABRIC_STORAGE_SCHEMA_1 ((uint32_t)1u)

#ifndef NINLIL_FABRIC_NFL1_HEADER_BYTES
#define NINLIL_FABRIC_NFL1_HEADER_BYTES NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES
#define NINLIL_FABRIC_NFL1_CODEC_CEILING NINLIL_FABRIC_PRIVATE_NFL1_CODEC_CEILING
#define NINLIL_FABRIC_NFL1_STRUCTURAL_MIN NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
#define NINLIL_FABRIC_NFL1_STRUCTURAL_MAX NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MAX
#define NINLIL_FABRIC_NFL1_SEMANTIC_MAX NINLIL_FABRIC_PRIVATE_NFL1_SEMANTIC_MAX
#define NINLIL_FABRIC_NFL1_PAYLOAD_MAX NINLIL_FABRIC_PRIVATE_NFL1_PAYLOAD_MAX
#define NINLIL_FABRIC_NFL1_EVIDENCE_MAX NINLIL_FABRIC_PRIVATE_NFL1_EVIDENCE_MAX
#define NINLIL_FABRIC_NFL1_TEXT_ID_MAX NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX
#define NINLIL_FABRIC_NFL1_VERSION NINLIL_FABRIC_PRIVATE_NFL1_VERSION
#endif

#define NINLIL_FABRIC_TRIGGER_MAX ((uint32_t)64u)
#define NINLIL_FABRIC_SHARED_QUEUE_MAX ((uint32_t)32u)
#define NINLIL_FABRIC_PER_LINK_RETAINED_MAX ((uint32_t)8u)
#define NINLIL_FABRIC_TIMERS_MAX ((uint32_t)64u)
#define NINLIL_FABRIC_RETRY_LIFETIME_MS ((uint64_t)30000u)

#define NINLIL_FABRIC_RECORD_ENVELOPE_BYTES ((uint32_t)24u)
#define NINLIL_FABRIC_FBM1_PAYLOAD_BYTES ((uint32_t)40u)
#define NINLIL_FABRIC_FBM1_VALUE_BYTES ((uint32_t)64u)
#define NINLIL_FABRIC_FBR1_PAYLOAD_BYTES ((uint32_t)348u)
#define NINLIL_FABRIC_FBR1_VALUE_BYTES ((uint32_t)372u)
#define NINLIL_FABRIC_FBP1_PAYLOAD_BYTES ((uint32_t)328u)
#define NINLIL_FABRIC_FBP1_VALUE_BYTES ((uint32_t)352u)
#define NINLIL_FABRIC_FBC1_PAYLOAD_BYTES ((uint32_t)488u)
#define NINLIL_FABRIC_FBC1_VALUE_BYTES ((uint32_t)512u)
#define NINLIL_FABRIC_FBA1_PAYLOAD_BYTES ((uint32_t)688u)
#define NINLIL_FABRIC_FBA1_VALUE_BYTES ((uint32_t)712u)
#define NINLIL_FABRIC_FBT1_PAYLOAD_BYTES ((uint32_t)224u)
#define NINLIL_FABRIC_FBT1_VALUE_BYTES ((uint32_t)248u)
#define NINLIL_FABRIC_OWNER_TUPLE_BYTES ((uint32_t)200u)
#define NINLIL_FABRIC_VALUE_CEILING ((uint32_t)712u)

#define NINLIL_FABRIC_FBA1_KEY_BYTES ((uint32_t)76u)
#define NINLIL_FABRIC_FBT1_KEY_BYTES ((uint32_t)40u)
#define NINLIL_FABRIC_FBR1_KEY_BYTES ((uint32_t)20u)
#define NINLIL_FABRIC_FBP1_KEY_BYTES ((uint32_t)28u)
#define NINLIL_FABRIC_FBC1_KEY_BYTES ((uint32_t)20u)
#define NINLIL_FABRIC_FBM1_KEY_BYTES ((uint32_t)4u)

void ninlil_fabric_private_put_u16_be(uint8_t *out, uint16_t value);
void ninlil_fabric_private_put_u32_be(uint8_t *out, uint32_t value);
void ninlil_fabric_private_put_u64_be(uint8_t *out, uint64_t value);
uint16_t ninlil_fabric_private_get_u16_be(const uint8_t *in);
uint32_t ninlil_fabric_private_get_u32_be(const uint8_t *in);
uint64_t ninlil_fabric_private_get_u64_be(const uint8_t *in);

void ninlil_fabric_private_memzero(void *dst, size_t length);
int ninlil_fabric_private_memeq(
    const void *a, const void *b, size_t length);
int ninlil_fabric_private_is_zero(const uint8_t *bytes, size_t length);
int ninlil_fabric_private_id_is_zero(const uint8_t id[16]);
void ninlil_fabric_private_id_copy(uint8_t dst[16], const uint8_t src[16]);
int ninlil_fabric_private_id_cmp(const uint8_t a[16], const uint8_t b[16]);

uint32_t ninlil_fabric_private_crc32c(
    const uint8_t *data, size_t length);
void ninlil_fabric_private_sha256(
    const uint8_t *data, size_t length, uint8_t out[32]);
void ninlil_fabric_private_tagged_sha256(
    const char *tag_ascii,
    const uint8_t *value,
    size_t value_len,
    uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_UTIL_H */
