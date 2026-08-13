/* SPDX-License-Identifier: Apache-2.0 */
/* Cross-compiled, machine-readable ABI layout authority for ILP32 little-endian. */
#include <ninlil/runtime.h>
#include <ninlil/fabric_v1.h>
#include <ninlil/composition_v1.h>
#include <ninlil/posix_tls_v1.h>
#include <ninlil/byte_stream.h>
#include <ninlil/posix_usb_serial_v1.h>

#include <stddef.h>
#include <stdint.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "ILP32 ABI authority requires a little-endian compiler target"
#endif

_Static_assert(sizeof(void *) == 4u, "authority requires ILP32 pointers");
_Static_assert(sizeof(long) == 4u, "authority requires ILP32 long");
_Static_assert(sizeof(int) == 4u, "authority requires 32-bit int");
_Static_assert(sizeof(size_t) == 4u, "authority requires 32-bit size_t");

struct __attribute__((packed)) abi_manifest_authority_record {
    unsigned char kind;
    char name[127];
    uint64_t value;
};

#define ABI_AUTHORITY_RECORD(kind_, name_, value_) { kind_, name_, (uint64_t)(value_) }
#define MANIFEST_CONST(name) ABI_AUTHORITY_RECORD('C', #name, name),
#define MANIFEST_STRUCT_BEGIN(type) ABI_AUTHORITY_RECORD('S', #type, sizeof(type)),
#define MANIFEST_STRUCT_ALIGN(type) ABI_AUTHORITY_RECORD('A', #type, _Alignof(type)),
#define MANIFEST_FIELD(type, field) ABI_AUTHORITY_RECORD('F', #field, offsetof(type, field)),
#define MANIFEST_STRUCT_END(type)

const struct abi_manifest_authority_record ninlil_abi_manifest_ilp32_authority[]
    __attribute__((used, section(".ninlil_abi_authority"))) = {
        ABI_AUTHORITY_RECORD('V', "format_version", 1u),
        ABI_AUTHORITY_RECORD('V', "abi_version", NINLIL_ABI_VERSION),
        ABI_AUTHORITY_RECORD('V', "target.pointer_bits", sizeof(void *) * 8u),
        ABI_AUTHORITY_RECORD('V', "target.long_bits", sizeof(long) * 8u),
        ABI_AUTHORITY_RECORD('V', "target.int_bits", sizeof(int) * 8u),
        ABI_AUTHORITY_RECORD('V', "target.size_t_bits", sizeof(size_t) * 8u),
#include "abi_manifest_constants.inc"
#include "abi_manifest_structs.inc"
        ABI_AUTHORITY_RECORD('Z', "", 0u),
    };
