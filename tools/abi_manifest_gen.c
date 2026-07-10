#include <ninlil/runtime.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MANIFEST_FORMAT_VERSION 1u
#define NINLIL_ABI_MANIFEST_EXPECTED_CONSTANTS 278u
#define NINLIL_ABI_MANIFEST_EXPECTED_STRUCTS 53u
#define NINLIL_ABI_MANIFEST_EXPECTED_FIELDS 526u

static size_t g_manifest_constant_count;
static size_t g_manifest_struct_count;
static size_t g_manifest_field_count;

static int is_little_endian(void)
{
    const uint32_t probe = 0x01020304u;
    return *((const uint8_t *)&probe) == 0x04u;
}

static const char *int_model_name(void)
{
    if (sizeof(void *) == 4u && sizeof(long) == 4u) {
        return "ILP32";
    }
    if (sizeof(void *) == 8u && sizeof(long) == 8u) {
        return "LP64";
    }
    if (sizeof(void *) == 8u && sizeof(long) == 4u) {
        return "LLP64";
    }
    return "UNKNOWN";
}

static void emit_target_id(FILE *out)
{
    const char *endianness = is_little_endian() ? "little" : "big";
    const char *model = int_model_name();
    unsigned pointer_bits = (unsigned)(sizeof(void *) * 8u);

    fprintf(out, "target.pointer_bits=%u\n", pointer_bits);
    fprintf(out, "target.long_bits=%zu\n", sizeof(long) * 8u);
    fprintf(out, "target.int_bits=%zu\n", sizeof(int) * 8u);
    fprintf(out, "target.size_t_bits=%zu\n", sizeof(size_t) * 8u);
    fprintf(out, "target.int_model=%s\n", model);
    fprintf(out, "target.endian=%s\n", endianness);
    fprintf(
        out,
        "target.id=%s-%s-%u\n",
        model,
        is_little_endian() ? "le" : "be",
        pointer_bits);
}

static void emit_u64_hex(FILE *out, uint64_t value)
{
    fprintf(out, "0x%016" PRIx64, value);
}

static void emit_constant(FILE *out, const char *name, uint64_t value)
{
    fprintf(out, "constant %s ", name);
    emit_u64_hex(out, value);
    fputc('\n', out);
}

#define MANIFEST_CONST(name) \
    do { \
        emit_constant(out, #name, (uint64_t)(name)); \
        ++g_manifest_constant_count; \
    } while (0);

#define MANIFEST_FIELD(type, field) \
    do { \
        fprintf( \
            out, \
            "field %s offset=%zu\n", \
            #field, \
            offsetof(type, field)); \
        ++g_manifest_field_count; \
    } while (0);

#define MANIFEST_STRUCT_BEGIN(type) \
    do { \
        fprintf(out, "struct %s size=%zu\n", #type, sizeof(type)); \
        ++g_manifest_struct_count; \
    } while (0);

#define MANIFEST_STRUCT_END(type) ((void)0);

static int emit_manifest(FILE *out)
{
    g_manifest_constant_count = 0u;
    g_manifest_struct_count = 0u;
    g_manifest_field_count = 0u;

    fprintf(out, "format_version=%u\n", MANIFEST_FORMAT_VERSION);
    fprintf(out, "abi_version=0x%04x\n", (unsigned)NINLIL_ABI_VERSION);
    emit_target_id(out);
    fputs("\n[constants]\n", out);
#include "abi_manifest_constants.inc"
    fputs("\n[structs]\n", out);
#include "abi_manifest_structs.inc"
    fputs("\n[coverage]\n", out);
    fprintf(out, "coverage.constants=%zu\n", g_manifest_constant_count);
    fprintf(out, "coverage.structs=%zu\n", g_manifest_struct_count);
    fprintf(out, "coverage.fields=%zu\n", g_manifest_field_count);
    return ferror(out) ? 1 : 0;
}

int main(void)
{
    if (emit_manifest(stdout) != 0) {
        return 1;
    }
    return 0;
}
