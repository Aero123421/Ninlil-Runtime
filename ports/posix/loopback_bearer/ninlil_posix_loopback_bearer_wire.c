#include "ninlil_posix_loopback_bearer_wire.h"

#include <stdlib.h>
#include <string.h>

static int append_bytes(uint8_t **cursor, uint8_t *end, const void *src, size_t n)
{
    if (n == 0u) {
        return 1;
    }
    if (*cursor + n > end) {
        return 0;
    }
    (void)memcpy(*cursor, src, n);
    *cursor += n;
    return 1;
}

static int read_bytes(
    const uint8_t **cursor,
    const uint8_t *end,
    void *dst,
    size_t n)
{
    if (*cursor + n > end) {
        return 0;
    }
    if (n > 0u) {
        (void)memcpy(dst, *cursor, n);
        *cursor += n;
    }
    return 1;
}

static uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
        | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

static void write_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

void ninlil_posix_loopback_wire_message_init(
    ninlil_posix_loopback_wire_message_t *wire)
{
    if (wire != NULL) {
        (void)memset(wire, 0, sizeof(*wire));
    }
}

void ninlil_posix_loopback_wire_message_clear(
    ninlil_posix_loopback_wire_message_t *wire)
{
    if (wire == NULL) {
        return;
    }
    free(wire->owned_payload);
    free(wire->owned_evidence);
    free(wire->owned_namespace_id);
    free(wire->owned_service_id);
    free(wire->owned_schema_id);
    (void)memset(wire, 0, sizeof(*wire));
}

int ninlil_posix_loopback_wire_encode(
    const ninlil_bearer_message_t *message,
    uint8_t **out_bytes,
    size_t *out_length)
{
    size_t total;
    uint8_t *buf;
    uint8_t *cursor;
    uint8_t *end;
    uint32_t ns_len;
    uint32_t svc_len;
    uint32_t sch_len;
    uint32_t pay_len;
    uint32_t ev_len;

    if (message == NULL || out_bytes == NULL || out_length == NULL) {
        return 0;
    }
    ns_len = message->service.namespace_id.length;
    svc_len = message->service.service_id.length;
    sch_len = message->service.schema_id.length;
    pay_len = message->payload.length;
    ev_len = message->evidence.length;
    if (ns_len > NINLIL_MAX_TEXT_ID_BYTES
        || svc_len > NINLIL_MAX_TEXT_ID_BYTES
        || sch_len > NINLIL_MAX_TEXT_ID_BYTES) {
        return 0;
    }
    total = sizeof(*message) + 20u + ns_len + svc_len + sch_len + pay_len + ev_len;
    buf = (uint8_t *)malloc(total);
    if (buf == NULL) {
        return 0;
    }
    cursor = buf;
    end = buf + total;
    if (!append_bytes(&cursor, end, message, sizeof(*message))) {
        free(buf);
        return 0;
    }
    write_u32_be(cursor, ns_len);
    cursor += 4u;
    write_u32_be(cursor, svc_len);
    cursor += 4u;
    write_u32_be(cursor, sch_len);
    cursor += 4u;
    write_u32_be(cursor, pay_len);
    cursor += 4u;
    write_u32_be(cursor, ev_len);
    cursor += 4u;
    if (!append_bytes(&cursor, end, message->service.namespace_id.bytes, ns_len)
        || !append_bytes(&cursor, end, message->service.service_id.bytes, svc_len)
        || !append_bytes(&cursor, end, message->service.schema_id.bytes, sch_len)
        || !append_bytes(&cursor, end, message->payload.data, pay_len)
        || !append_bytes(&cursor, end, message->evidence.data, ev_len)) {
        free(buf);
        return 0;
    }
    *out_bytes = buf;
    *out_length = total;
    return 1;
}

static uint8_t *dup_slice(const uint8_t *src, uint32_t len)
{
    uint8_t *out;

    if (len == 0u) {
        return NULL;
    }
    out = (uint8_t *)malloc(len);
    if (out == NULL) {
        return NULL;
    }
    (void)memcpy(out, src, len);
    return out;
}

int ninlil_posix_loopback_wire_decode(
    const uint8_t *bytes,
    size_t length,
    ninlil_posix_loopback_wire_message_t *out_wire)
{
    const uint8_t *cursor;
    const uint8_t *end;
    uint32_t ns_len;
    uint32_t svc_len;
    uint32_t sch_len;
    uint32_t pay_len;
    uint32_t ev_len;

    if (bytes == NULL || out_wire == NULL || length < sizeof(ninlil_bearer_message_t) + 20u) {
        return 0;
    }
    ninlil_posix_loopback_wire_message_clear(out_wire);
    cursor = bytes;
    end = bytes + length;
    (void)memcpy(&out_wire->message, cursor, sizeof(out_wire->message));
    cursor += sizeof(out_wire->message);
    if (!read_bytes(&cursor, end, &ns_len, 4u)) {
        ninlil_posix_loopback_wire_message_clear(out_wire);
        return 0;
    }
    ns_len = read_u32_be((const uint8_t *)&ns_len);
    if (!read_bytes(&cursor, end, &svc_len, 4u)) {
        ninlil_posix_loopback_wire_message_clear(out_wire);
        return 0;
    }
    svc_len = read_u32_be((const uint8_t *)&svc_len);
    if (!read_bytes(&cursor, end, &sch_len, 4u)) {
        ninlil_posix_loopback_wire_message_clear(out_wire);
        return 0;
    }
    sch_len = read_u32_be((const uint8_t *)&sch_len);
    if (!read_bytes(&cursor, end, &pay_len, 4u)) {
        ninlil_posix_loopback_wire_message_clear(out_wire);
        return 0;
    }
    pay_len = read_u32_be((const uint8_t *)&pay_len);
    if (!read_bytes(&cursor, end, &ev_len, 4u)) {
        ninlil_posix_loopback_wire_message_clear(out_wire);
        return 0;
    }
    ev_len = read_u32_be((const uint8_t *)&ev_len);
    if (ns_len > NINLIL_MAX_TEXT_ID_BYTES
        || svc_len > NINLIL_MAX_TEXT_ID_BYTES
        || sch_len > NINLIL_MAX_TEXT_ID_BYTES
        || cursor + ns_len + svc_len + sch_len + pay_len + ev_len > end) {
        ninlil_posix_loopback_wire_message_clear(out_wire);
        return 0;
    }
    out_wire->owned_namespace_id = dup_slice(cursor, ns_len);
    cursor += ns_len;
    out_wire->owned_service_id = dup_slice(cursor, svc_len);
    cursor += svc_len;
    out_wire->owned_schema_id = dup_slice(cursor, sch_len);
    cursor += sch_len;
    out_wire->owned_payload = dup_slice(cursor, pay_len);
    cursor += pay_len;
    out_wire->owned_evidence = dup_slice(cursor, ev_len);
    if ((ns_len > 0u && out_wire->owned_namespace_id == NULL)
        || (svc_len > 0u && out_wire->owned_service_id == NULL)
        || (sch_len > 0u && out_wire->owned_schema_id == NULL)
        || (pay_len > 0u && out_wire->owned_payload == NULL)
        || (ev_len > 0u && out_wire->owned_evidence == NULL)) {
        ninlil_posix_loopback_wire_message_clear(out_wire);
        return 0;
    }
    out_wire->message.service.namespace_id.length = (uint8_t)ns_len;
    if (ns_len > 0u) {
        (void)memcpy(
            out_wire->message.service.namespace_id.bytes,
            out_wire->owned_namespace_id,
            ns_len);
    }
    out_wire->message.service.service_id.length = (uint8_t)svc_len;
    if (svc_len > 0u) {
        (void)memcpy(
            out_wire->message.service.service_id.bytes,
            out_wire->owned_service_id,
            svc_len);
    }
    out_wire->message.service.schema_id.length = (uint8_t)sch_len;
    if (sch_len > 0u) {
        (void)memcpy(
            out_wire->message.service.schema_id.bytes,
            out_wire->owned_schema_id,
            sch_len);
    }
    out_wire->message.payload.data = out_wire->owned_payload;
    out_wire->message.payload.length = pay_len;
    out_wire->message.evidence.data = out_wire->owned_evidence;
    out_wire->message.evidence.length = ev_len;
    return 1;
}
