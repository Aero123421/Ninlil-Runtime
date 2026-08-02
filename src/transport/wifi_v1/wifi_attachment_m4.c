#include "wifi_attachment_m4.h"

#include "wifi_sha256.h"
#include "wifi_storage_cu.h"

#include <string.h>

#if defined(ESP_PLATFORM)
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>
#elif defined(_WIN32)
/* Host private wifi_v1 is POSIX+OpenSSL; Windows not a support target. */
#error "wifi_v1 M4 requires platform entropy (POSIX/OpenSSL or ESP)"
#else
#include <openssl/rand.h>
#include <pthread.h>
#endif

/*
 * Subsystem-owned linear capability registry.
 *
 * Authority = live slot state under instance-scoped owner (+ mutex).
 * Public evidence = alias handle (slot/generation/epoch/cap_id).
 * cap_id is 128-bit owner-minted from platform entropy/DRBG — not a
 * compile-time secret and not caller-provided authority.
 */

enum {
    M4_HANDLE_MAGIC = 0x4d34484cu, /* 'M4HL' — cosmetic only, not authority */
    M4_BIT_MEMBERSHIP = 1u,
    M4_BIT_ATTACHMENT = 2u,
    M4_BIT_CREDENTIAL = 4u,
    M4_BIT_FABRIC = 8u
};

#define M4_SLOT_COUNT NINLIL_WIFI_M4_OWNER_SLOT_COUNT
#define M4_CAP_ID_BYTES 16u

typedef struct m4_handle {
    uint32_t magic;
    uint32_t slot;
    uint64_t generation;
    uint64_t owner_epoch;
    uint8_t cap_id[M4_CAP_ID_BYTES];
    uintptr_t owner_addr; /* instance binding; not caller-forgeable truth alone */
} m4_handle_t;

_Static_assert(
    sizeof(m4_handle_t) <= NINLIL_WIFI_M4_EVIDENCE_OPAQUE_BYTES,
    "m4 handle larger than opaque");

typedef struct m4_slot {
    uint64_t generation; /* non-zero when live */
    uint8_t live;
    uint8_t membership_live;
    uint8_t fabric_registry_bound;
    uint8_t session_authority_mint; /* 1 only via authenticated session mint */
    uint32_t source_bits;
    /*
     * Per-component load operation tokens. Each load_classify start bumps the
     * component token; after storage I/O, results apply only if the token
     * still matches. Prevents logical stale completion when concurrent loads
     * A/B finish out of order on the same evidence handle.
     */
    uint64_t membership_load_op;
    uint64_t attachment_load_op;
    uint64_t credential_load_op;
    uint8_t cap_id[M4_CAP_ID_BYTES];
    ninlil_wifi_m4_record_class_t membership_class;
    ninlil_wifi_m4_record_class_t attachment_class;
    ninlil_wifi_m4_record_class_t credential_class;
    uint8_t member_runtime_id[16];
    uint8_t membership_authority_id[16];
    uint8_t membership_binding_digest[32];
    uint8_t membership_wire_digest[32];
    uint8_t peer_session_id[16];
    uint8_t attachment_authority_id[16];
    uint8_t active_attachment_binding_digest[32];
    uint8_t attachment_credential_digest[32];
    uint8_t attachment_fabric_descriptor[32];
    uint8_t attachment_wire_digest[32];
    uint8_t durable_image[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint8_t credential_candidate_digest[32];
    uint8_t credential_wire_digest[32];
    uint8_t fabric_descriptor[32];
    uint8_t fabric_authority_id[16];
    uint8_t fabric_epoch_id[16];
} m4_slot_t;

typedef struct m4_owner {
    uint64_t owner_epoch; /* non-zero after first use; never wraps */
    uint64_t next_generation; /* monotonic, never 0; never wraps */
    uint8_t exhausted; /* 1 => permanent fail-closed (counter/entropy) */
    uint8_t initialized;
    uint8_t reserved[6];
    m4_slot_t slots[M4_SLOT_COUNT];
#if !defined(ESP_PLATFORM)
    pthread_mutex_t mutex;
#endif
} m4_owner_t;

_Static_assert(
    sizeof(m4_owner_t) <= NINLIL_WIFI_M4_OWNER_STORAGE_BYTES,
    "m4 owner storage too small");

static m4_owner_t *owner_impl(ninlil_wifi_m4_owner_t *owner)
{
    if (owner == NULL) {
        return NULL;
    }
    return (m4_owner_t *)(void *)owner->opaque;
}

/*
 * Process-local registry of live owner *instances* only (not shared slots).
 * Forged owner_addr must not be dereferenced unless registered here.
 */
enum { M4_OWNER_REG_MAX = 16u };
static m4_owner_t *g_m4_owner_reg[M4_OWNER_REG_MAX];
static uint32_t g_m4_owner_reg_count;

static int owner_register(m4_owner_t *o)
{
    uint32_t i;
    if (o == NULL) {
        return -1;
    }
    for (i = 0u; i < g_m4_owner_reg_count; ++i) {
        if (g_m4_owner_reg[i] == o) {
            return 0;
        }
    }
    if (g_m4_owner_reg_count >= M4_OWNER_REG_MAX) {
        return -1;
    }
    g_m4_owner_reg[g_m4_owner_reg_count++] = o;
    return 0;
}

static int owner_is_registered(const m4_owner_t *o)
{
    uint32_t i;
    if (o == NULL) {
        return 0;
    }
    for (i = 0u; i < g_m4_owner_reg_count; ++i) {
        if (g_m4_owner_reg[i] == o) {
            return 1;
        }
    }
    return 0;
}

#if defined(ESP_PLATFORM)
static portMUX_TYPE g_m4_esp_mux = portMUX_INITIALIZER_UNLOCKED;
static void m4_lock(m4_owner_t *o)
{
    (void)o;
    portENTER_CRITICAL(&g_m4_esp_mux);
}
static void m4_unlock(m4_owner_t *o)
{
    (void)o;
    portEXIT_CRITICAL(&g_m4_esp_mux);
}
#else
static void m4_lock(m4_owner_t *o)
{
    if (o != NULL) {
        (void)pthread_mutex_lock(&o->mutex);
    }
}
static void m4_unlock(m4_owner_t *o)
{
    if (o != NULL) {
        (void)pthread_mutex_unlock(&o->mutex);
    }
}
#endif

#if defined(NINLIL_WIFI_M4_TEST_HOOKS)
static ninlil_wifi_m4_storage_io_hook_fn g_m4_io_hook;
static void *g_m4_io_hook_user;

void ninlil_wifi_m4_test_set_storage_io_hook(
    ninlil_wifi_m4_storage_io_hook_fn fn,
    void *user)
{
    g_m4_io_hook = fn;
    g_m4_io_hook_user = user;
}

static void m4_invoke_io_hook(void)
{
    ninlil_wifi_m4_storage_io_hook_fn fn = g_m4_io_hook;
    void *user = g_m4_io_hook_user;
    if (fn != NULL) {
        fn(user);
    }
}
#else
static void m4_invoke_io_hook(void)
{
}
#endif

/* ---- LE / util ---- */

static void le_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void le_u64(uint8_t *p, uint64_t v)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xffu);
    }
}

static uint16_t rd_le_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint64_t rd_le_u64(const uint8_t *p)
{
    uint64_t v = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        v |= ((uint64_t)p[i]) << (8u * i);
    }
    return v;
}

static int is_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static ninlil_bytes_view_t bv(const void *data, uint32_t length)
{
    ninlil_bytes_view_t v;
    v.data = (const uint8_t *)data;
    v.length = length;
    return v;
}

static ninlil_wifi_status_t map_st(ninlil_storage_status_t st)
{
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_WIFI_OK;
    }
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN;
    }
    if (st == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (st == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_WIFI_CAPACITY;
    }
    if (st == NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
        return NINLIL_WIFI_UNSUPPORTED;
    }
    return NINLIL_WIFI_IO_ERROR;
}

/*
 * Owner-minted unpredictable 128-bit identity from platform entropy/DRBG.
 * Not a fixed secret; not caller-supplied. All-zero output rejected.
 */
static int m4_fill_cap_id(uint8_t out[M4_CAP_ID_BYTES])
{
#if defined(ESP_PLATFORM)
    esp_fill_random(out, (size_t)M4_CAP_ID_BYTES);
    if (is_all_zero(out, M4_CAP_ID_BYTES)) {
        return -1;
    }
    return 0;
#else
    if (RAND_bytes(out, (int)M4_CAP_ID_BYTES) != 1) {
        return -1;
    }
    if (is_all_zero(out, M4_CAP_ID_BYTES)) {
        return -1;
    }
    return 0;
#endif
}

static void owner_ensure_epoch_unlocked(m4_owner_t *o)
{
    if (o == NULL || o->exhausted != 0u) {
        return;
    }
    if (o->owner_epoch == 0u) {
        o->owner_epoch = 1u;
    }
    if (o->next_generation == 0u) {
        o->next_generation = 1u;
    }
}

/* Returns 0 on success and writes gen; -1 fail-closed (no wrap). */
static int owner_alloc_generation_unlocked(m4_owner_t *o, uint64_t *out_gen)
{
    uint64_t g;
    if (o == NULL || out_gen == NULL) {
        return -1;
    }
    owner_ensure_epoch_unlocked(o);
    if (o->exhausted != 0u) {
        return -1;
    }
    if (o->next_generation == 0u || o->next_generation == UINT64_MAX) {
        o->exhausted = 1u;
        return -1;
    }
    g = o->next_generation;
    o->next_generation += 1u;
    if (g == 0u) {
        o->exhausted = 1u;
        return -1;
    }
    *out_gen = g;
    return 0;
}

static void slot_clear(m4_slot_t *s)
{
    if (s != NULL) {
        (void)memset(s, 0, sizeof(*s));
    }
}

/* Bump component op token; -1 on fail-closed (exhaustion). */
static int bump_load_op_unlocked(uint64_t *op_field, uint64_t *out_token)
{
    if (op_field == NULL || out_token == NULL) {
        return -1;
    }
    if (*op_field == UINT64_MAX) {
        return -1;
    }
    *op_field += 1u;
    if (*op_field == 0u) {
        return -1;
    }
    *out_token = *op_field;
    return 0;
}

static m4_handle_t *handle_mut(ninlil_wifi_m4_full_evidence_t *ev)
{
    if (ev == NULL) {
        return NULL;
    }
    return (m4_handle_t *)(void *)ev->opaque;
}

static const m4_handle_t *handle_const(const ninlil_wifi_m4_full_evidence_t *ev)
{
    if (ev == NULL) {
        return NULL;
    }
    return (const m4_handle_t *)(const void *)ev->opaque;
}

static void handle_clear(ninlil_wifi_m4_full_evidence_t *ev)
{
    if (ev != NULL) {
        (void)memset(ev, 0, sizeof(*ev));
    }
}

static void handle_write(
    m4_owner_t *o,
    ninlil_wifi_m4_full_evidence_t *ev,
    uint32_t slot,
    uint64_t generation,
    const uint8_t cap_id[M4_CAP_ID_BYTES])
{
    m4_handle_t *h = handle_mut(ev);
    if (h == NULL || o == NULL) {
        return;
    }
    (void)memset(ev, 0, sizeof(*ev));
    h->magic = M4_HANDLE_MAGIC;
    h->slot = slot;
    h->generation = generation;
    h->owner_epoch = o->owner_epoch;
    (void)memcpy(h->cap_id, cap_id, M4_CAP_ID_BYTES);
    h->owner_addr = (uintptr_t)(void *)o;
}

/* Resolve live slot for handle; NULL if stale/forged. Caller holds lock. */
static m4_owner_t *owner_from_handle_unlocked(const m4_handle_t *h)
{
    m4_owner_t *o;
    if (h == NULL || h->owner_addr == 0u) {
        return NULL;
    }
    o = (m4_owner_t *)(void *)h->owner_addr;
    if (!owner_is_registered(o) || o->initialized == 0u) {
        return NULL;
    }
    return o;
}

static m4_slot_t *slot_resolve_mut_unlocked(ninlil_wifi_m4_full_evidence_t *ev)
{
    m4_handle_t *h = handle_mut(ev);
    m4_owner_t *o;
    m4_slot_t *s;
    if (h == NULL) {
        return NULL;
    }
    o = owner_from_handle_unlocked(h);
    if (o == NULL || o->exhausted != 0u) {
        return NULL;
    }
    owner_ensure_epoch_unlocked(o);
    if (h->magic != M4_HANDLE_MAGIC || h->generation == 0u
        || h->slot >= M4_SLOT_COUNT
        || h->owner_epoch != o->owner_epoch
        || is_all_zero(h->cap_id, M4_CAP_ID_BYTES)) {
        return NULL;
    }
    s = &o->slots[h->slot];
    if (s->live == 0u || s->generation != h->generation
        || memcmp(s->cap_id, h->cap_id, M4_CAP_ID_BYTES) != 0) {
        return NULL;
    }
    return s;
}

static const m4_slot_t *slot_resolve_const_unlocked(
    const ninlil_wifi_m4_full_evidence_t *ev)
{
    const m4_handle_t *h = handle_const(ev);
    m4_owner_t *o;
    const m4_slot_t *s;
    if (h == NULL) {
        return NULL;
    }
    o = owner_from_handle_unlocked(h);
    if (o == NULL || o->exhausted != 0u) {
        return NULL;
    }
    owner_ensure_epoch_unlocked(o);
    if (h->magic != M4_HANDLE_MAGIC || h->generation == 0u
        || h->slot >= M4_SLOT_COUNT
        || h->owner_epoch != o->owner_epoch
        || is_all_zero(h->cap_id, M4_CAP_ID_BYTES)) {
        return NULL;
    }
    s = &o->slots[h->slot];
    if (s->live == 0u || s->generation != h->generation
        || memcmp(s->cap_id, h->cap_id, M4_CAP_ID_BYTES) != 0) {
        return NULL;
    }
    return s;
}

/*
 * After I/O: handle must still resolve and component op must still match.
 * Mismatch => logical stale completion (do not apply wire result).
 * out_slot receives the resolved live slot when current.
 */
static int membership_op_current_unlocked(
    ninlil_wifi_m4_full_evidence_t *ev,
    uint64_t expected_op,
    m4_slot_t **out_slot)
{
    m4_slot_t *s = slot_resolve_mut_unlocked(ev);
    if (s == NULL || expected_op == 0u || s->membership_load_op != expected_op) {
        return 0;
    }
    if (out_slot != NULL) {
        *out_slot = s;
    }
    return 1;
}

static int attachment_op_current_unlocked(
    ninlil_wifi_m4_full_evidence_t *ev,
    uint64_t expected_op,
    m4_slot_t **out_slot)
{
    m4_slot_t *s = slot_resolve_mut_unlocked(ev);
    if (s == NULL || expected_op == 0u || s->attachment_load_op != expected_op) {
        return 0;
    }
    if (out_slot != NULL) {
        *out_slot = s;
    }
    return 1;
}

static int credential_op_current_unlocked(
    ninlil_wifi_m4_full_evidence_t *ev,
    uint64_t expected_op,
    m4_slot_t **out_slot)
{
    m4_slot_t *s = slot_resolve_mut_unlocked(ev);
    if (s == NULL || expected_op == 0u || s->credential_load_op != expected_op) {
        return 0;
    }
    if (out_slot != NULL) {
        *out_slot = s;
    }
    return 1;
}

static void handle_invalidate_slot_unlocked(ninlil_wifi_m4_full_evidence_t *ev)
{
    m4_handle_t *h = handle_mut(ev);
    m4_owner_t *o;
    m4_slot_t *s;
    if (h == NULL) {
        return;
    }
    o = owner_from_handle_unlocked(h);
    if (o == NULL) {
        return;
    }
    if (h->magic != M4_HANDLE_MAGIC || h->generation == 0u
        || h->slot >= M4_SLOT_COUNT || is_all_zero(h->cap_id, M4_CAP_ID_BYTES)) {
        return;
    }
    s = &o->slots[h->slot];
    if (s->live != 0u && s->generation == h->generation
        && memcmp(s->cap_id, h->cap_id, M4_CAP_ID_BYTES) == 0) {
        slot_clear(s);
    }
}

/*
 * Allocate free slot into out on the given owner instance.
 * Does not evict live slots of this owner (or any other).
 */
static ninlil_wifi_status_t slot_alloc_empty_unlocked(
    m4_owner_t *o,
    ninlil_wifi_m4_full_evidence_t *ev)
{
    uint32_t i;
    uint64_t gen;
    uint8_t cap[M4_CAP_ID_BYTES];
    if (o == NULL || ev == NULL || o->initialized == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (o->exhausted != 0u) {
        handle_clear(ev);
        return NINLIL_WIFI_DENIED;
    }
    handle_invalidate_slot_unlocked(ev);
    owner_ensure_epoch_unlocked(o);
    for (i = 0u; i < M4_SLOT_COUNT; ++i) {
        if (o->slots[i].live == 0u) {
            if (owner_alloc_generation_unlocked(o, &gen) != 0) {
                handle_clear(ev);
                return NINLIL_WIFI_DENIED;
            }
            if (m4_fill_cap_id(cap) != 0) {
                o->exhausted = 1u;
                handle_clear(ev);
                return NINLIL_WIFI_CORRUPT;
            }
            slot_clear(&o->slots[i]);
            o->slots[i].live = 1u;
            o->slots[i].generation = gen;
            (void)memcpy(o->slots[i].cap_id, cap, M4_CAP_ID_BYTES);
            o->slots[i].membership_class = NINLIL_WIFI_M4_CLASS_MISSING;
            o->slots[i].attachment_class = NINLIL_WIFI_M4_CLASS_MISSING;
            o->slots[i].credential_class = NINLIL_WIFI_M4_CLASS_MISSING;
            handle_write(o, ev, i, gen, cap);
            return NINLIL_WIFI_OK;
        }
    }
    handle_clear(ev);
    return NINLIL_WIFI_CAPACITY;
}

static ninlil_wifi_status_t slot_acquire_for_unlocked(
    m4_owner_t *o,
    ninlil_wifi_m4_full_evidence_t *ev,
    m4_slot_t **out_slot)
{
    m4_slot_t *s;
    ninlil_wifi_status_t st;
    m4_handle_t *h;
    if (o == NULL || ev == NULL || out_slot == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    h = handle_mut(ev);
    if (h != NULL && h->owner_addr != 0u
        && h->owner_addr != (uintptr_t)(void *)o) {
        /* Handle bound to a different owner instance. */
        return NINLIL_WIFI_DENIED;
    }
    s = slot_resolve_mut_unlocked(ev);
    if (s != NULL) {
        *out_slot = s;
        return NINLIL_WIFI_OK;
    }
    /*
     * Non-empty forged/stale/random handle must not silently re-mint.
     * load_classify only allocates when the evidence is fully empty
     * (caller must evidence_reset for a fresh capability).
     */
    if (h != NULL
        && (h->magic != 0u || h->generation != 0u || h->owner_epoch != 0u
            || h->owner_addr != 0u || h->slot != 0u
            || !is_all_zero(h->cap_id, M4_CAP_ID_BYTES))) {
        return NINLIL_WIFI_DENIED;
    }
    st = slot_alloc_empty_unlocked(o, ev);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    s = slot_resolve_mut_unlocked(ev);
    if (s == NULL) {
        return NINLIL_WIFI_CORRUPT;
    }
    *out_slot = s;
    return NINLIL_WIFI_OK;
}

static int slot_is_ready(const m4_slot_t *s)
{
    if (s == NULL || s->live == 0u) {
        return 0;
    }
    /* Self-issued durable fill without session authority mint is not ready. */
    if (s->session_authority_mint == 0u) {
        return 0;
    }
    if ((s->source_bits
            & (M4_BIT_MEMBERSHIP | M4_BIT_ATTACHMENT | M4_BIT_CREDENTIAL
                | M4_BIT_FABRIC))
        != (M4_BIT_MEMBERSHIP | M4_BIT_ATTACHMENT | M4_BIT_CREDENTIAL
            | M4_BIT_FABRIC)) {
        return 0;
    }
    if (s->membership_class != NINLIL_WIFI_M4_CLASS_FULL
        || s->membership_live == 0u
        || s->attachment_class != NINLIL_WIFI_M4_CLASS_FULL
        || s->credential_class != NINLIL_WIFI_M4_CLASS_FULL
        || s->fabric_registry_bound == 0u) {
        return 0;
    }
    if (is_all_zero(s->membership_authority_id, 16u)
        || is_all_zero(s->membership_binding_digest, 32u)
        || is_all_zero(s->member_runtime_id, 16u)
        || is_all_zero(s->attachment_authority_id, 16u)
        || is_all_zero(s->active_attachment_binding_digest, 32u)
        || is_all_zero(s->attachment_credential_digest, 32u)
        || is_all_zero(s->attachment_fabric_descriptor, 32u)
        || is_all_zero(s->credential_candidate_digest, 32u)
        || is_all_zero(s->fabric_descriptor, 32u)
        || is_all_zero(s->fabric_authority_id, 16u)
        || is_all_zero(s->peer_session_id, 16u)
        || is_all_zero(s->membership_wire_digest, 32u)
        || is_all_zero(s->attachment_wire_digest, 32u)
        || is_all_zero(s->credential_wire_digest, 32u)
        || is_all_zero(s->cap_id, M4_CAP_ID_BYTES)) {
        return 0;
    }
    if (memcmp(s->membership_authority_id, s->attachment_authority_id, 16u)
            != 0
        || memcmp(s->membership_authority_id, s->fabric_authority_id, 16u) != 0
        || memcmp(
               s->membership_binding_digest,
               s->active_attachment_binding_digest,
               32u)
            != 0
        || memcmp(
               s->attachment_credential_digest,
               s->credential_candidate_digest,
               32u)
            != 0
        || memcmp(s->attachment_fabric_descriptor, s->fabric_descriptor, 32u)
            != 0
        || memcmp(s->member_runtime_id, s->peer_session_id, 16u) != 0) {
        return 0;
    }
    return 1;
}

static ninlil_wifi_status_t cu_put_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const char *key_utf8,
    const uint8_t *wire,
    uint32_t wire_len,
    ninlil_wifi_cu_class_t *out_class)
{
    return ninlil_wifi_storage_cu_put_full(
        storage,
        storage_user,
        path_utf8,
        key_utf8,
        wire,
        wire_len,
        out_class);
}

static ninlil_wifi_status_t cu_get(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const char *key_utf8,
    uint8_t *wire,
    uint32_t wire_cap,
    uint32_t *out_len)
{
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t ns;
    ninlil_bytes_view_t key;
    ninlil_mut_bytes_t value;
    if (storage == NULL || path_utf8 == NULL || key_utf8 == NULL || wire == NULL
        || out_len == NULL || storage->open == NULL || storage->begin == NULL
        || storage->get == NULL || storage->close == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ns = bv(path_utf8, (uint32_t)strlen(path_utf8));
    st = storage->open(storage_user, ns, NINLIL_STORAGE_SCHEMA_M1A, &h);
    if (st != NINLIL_STORAGE_OK) {
        return map_st(st);
    }
    st = storage->begin(storage_user, h, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        storage->close(storage_user, h);
        return map_st(st);
    }
    key = bv(key_utf8, (uint32_t)strlen(key_utf8));
    value.data = wire;
    value.capacity = wire_cap;
    value.length = 0u;
    st = storage->get(storage_user, txn, key, &value);
    if (storage->rollback != NULL) {
        (void)storage->rollback(storage_user, txn);
    } else if (storage->commit != NULL) {
        ninlil_storage_status_t cst =
            storage->commit(storage_user, txn, NINLIL_DURABILITY_FULL);
        if (cst == NINLIL_STORAGE_COMMIT_UNKNOWN
            || cst == NINLIL_STORAGE_CORRUPT) {
            storage->close(storage_user, h);
            return NINLIL_WIFI_CORRUPT;
        }
        if (cst != NINLIL_STORAGE_OK && st == NINLIL_STORAGE_OK) {
            storage->close(storage_user, h);
            return map_st(cst);
        }
    }
    storage->close(storage_user, h);
    if (st != NINLIL_STORAGE_OK) {
        return map_st(st);
    }
    *out_len = value.length;
    return NINLIL_WIFI_OK;
}

/* ---- public ownership APIs ---- */

void ninlil_wifi_m4_owner_init(ninlil_wifi_m4_owner_t *owner)
{
    m4_owner_t *o = owner_impl(owner);
    if (o == NULL) {
        return;
    }
    (void)memset(o, 0, sizeof(*o));
#if !defined(ESP_PLATFORM)
    (void)pthread_mutex_init(&o->mutex, NULL);
#endif
    o->owner_epoch = 1u;
    o->next_generation = 1u;
    o->initialized = 1u;
    (void)owner_register(o);
}

ninlil_wifi_status_t ninlil_wifi_m4_owner_restart(ninlil_wifi_m4_owner_t *owner)
{
    m4_owner_t *o = owner_impl(owner);
    uint32_t i;
    uint64_t next_epoch;
    ninlil_wifi_status_t st = NINLIL_WIFI_OK;
    if (o == NULL || o->initialized == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    m4_lock(o);
    owner_ensure_epoch_unlocked(o);
    if (o->exhausted != 0u) {
        st = NINLIL_WIFI_DENIED;
        goto out;
    }
    if (o->owner_epoch == UINT64_MAX) {
        o->exhausted = 1u;
        for (i = 0u; i < M4_SLOT_COUNT; ++i) {
            slot_clear(&o->slots[i]);
        }
        st = NINLIL_WIFI_DENIED;
        goto out;
    }
    next_epoch = o->owner_epoch + 1u;
    if (next_epoch == 0u) {
        o->exhausted = 1u;
        for (i = 0u; i < M4_SLOT_COUNT; ++i) {
            slot_clear(&o->slots[i]);
        }
        st = NINLIL_WIFI_DENIED;
        goto out;
    }
    for (i = 0u; i < M4_SLOT_COUNT; ++i) {
        slot_clear(&o->slots[i]);
    }
    o->owner_epoch = next_epoch;
    if (o->next_generation == 0u) {
        o->next_generation = 1u;
    }
out:
    m4_unlock(o);
    return st;
}

ninlil_wifi_status_t ninlil_wifi_m4_evidence_reset(
    ninlil_wifi_m4_owner_t *owner,
    ninlil_wifi_m4_full_evidence_t *out)
{
    m4_owner_t *o = owner_impl(owner);
    ninlil_wifi_status_t st;
    if (o == NULL || o->initialized == 0u || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    m4_lock(o);
    st = slot_alloc_empty_unlocked(o, out);
    m4_unlock(o);
    return st;
}

void ninlil_wifi_m4_evidence_consume(ninlil_wifi_m4_full_evidence_t *ev)
{
    m4_handle_t *h;
    m4_owner_t *o;
    if (ev == NULL) {
        return;
    }
    h = handle_mut(ev);
    o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o != NULL) {
        m4_lock(o);
        handle_invalidate_slot_unlocked(ev);
        m4_unlock(o);
    }
    handle_clear(ev);
}

ninlil_wifi_status_t ninlil_wifi_m4_evidence_mark_session_authority(
    ninlil_wifi_m4_full_evidence_t *ev)
{
    m4_handle_t *h = handle_mut(ev);
    m4_owner_t *o;
    m4_slot_t *s;
    ninlil_wifi_status_t st = NINLIL_WIFI_DENIED;
    if (h == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    o = owner_from_handle_unlocked(h);
    if (o == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    m4_lock(o);
    s = slot_resolve_mut_unlocked(ev);
    if (s != NULL && s->live != 0u) {
        s->session_authority_mint = 1u;
        st = NINLIL_WIFI_OK;
    }
    m4_unlock(o);
    return st;
}

/* ---- durable store / load ---- */

ninlil_wifi_status_t ninlil_wifi_m4_membership_store_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const ninlil_wifi_m4_membership_lease_t *lease_in)
{
    ninlil_wifi_cu_class_t observed = NINLIL_WIFI_CU_NONE;
    return ninlil_wifi_m4_membership_store_full_reconciled(
        storage, storage_user, path_utf8, lease_in, &observed);
}

ninlil_wifi_status_t ninlil_wifi_m4_membership_store_full_reconciled(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const ninlil_wifi_m4_membership_lease_t *lease_in,
    ninlil_wifi_cu_class_t *out_class)
{
    uint8_t wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint8_t dig[32];
    if (lease_in == NULL || out_class == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_WIFI_CU_NONE;
    (void)memset(wire, 0, sizeof(wire));
    wire[0] = (uint8_t)'M';
    wire[1] = (uint8_t)'4';
    wire[2] = (uint8_t)'M';
    wire[3] = (uint8_t)'1';
    le_u16(wire + 4, 1u);
    le_u16(wire + 6, 0u);
    (void)memcpy(wire + 8, lease_in->member_runtime_id, 16u);
    le_u64(wire + 24, lease_in->lease_not_before_ms);
    le_u64(wire + 32, lease_in->lease_not_after_ms);
    (void)memcpy(wire + 40, lease_in->authority_id, 16u);
    (void)memcpy(wire + 56, lease_in->binding_digest, 32u);
    ninlil_wifi_sha256(wire, 88u, dig);
    (void)memcpy(wire + 88, dig, 32u);
    return cu_put_full(
        storage, storage_user, path_utf8, NINLIL_WIFI_M4_KEY_MEMBERSHIP, wire,
        (uint32_t)sizeof(wire), out_class);
}

ninlil_wifi_status_t ninlil_wifi_m4_membership_load_classify(
    ninlil_wifi_m4_owner_t *owner,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    uint64_t mono_now_ms,
    ninlil_wifi_m4_full_evidence_t *ev)
{
    m4_owner_t *o = owner_impl(owner);
    m4_slot_t *s;
    uint8_t wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint32_t len = 0u;
    ninlil_wifi_status_t st;
    uint8_t expect[32];
    uint64_t nb;
    uint64_t na;
    uint64_t my_op = 0u;
    if (o == NULL || o->initialized == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    m4_lock(o);
    st = slot_acquire_for_unlocked(o, ev, &s);
    if (st != NINLIL_WIFI_OK) {
        m4_unlock(o);
        return st;
    }
    if (bump_load_op_unlocked(&s->membership_load_op, &my_op) != 0) {
        m4_unlock(o);
        return NINLIL_WIFI_DENIED;
    }
    s->membership_class = NINLIL_WIFI_M4_CLASS_MISSING;
    s->membership_live = 0u;
    s->source_bits &= (uint32_t)~M4_BIT_MEMBERSHIP;
    /* Release lock around storage I/O to avoid blocking concurrent ready. */
    m4_unlock(o);
    m4_invoke_io_hook();
    st = cu_get(
        storage, storage_user, path_utf8, NINLIL_WIFI_M4_KEY_MEMBERSHIP, wire,
        (uint32_t)sizeof(wire), &len);
    m4_lock(o);
    /*
     * Apply only if this load is still the current membership op.
     * Stale completions (older A finishing after newer B) → DENIED, no write.
     */
    if (!membership_op_current_unlocked(ev, my_op, &s)) {
        m4_unlock(o);
        return NINLIL_WIFI_DENIED;
    }
    if (st == NINLIL_WIFI_UNAVAILABLE) {
        /* Start cleared to MISSING; keep if still current. */
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if (st != NINLIL_WIFI_OK) {
        s->membership_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return st;
    }
    if (len != sizeof(wire) || wire[0] != (uint8_t)'M' || wire[1] != (uint8_t)'4'
        || wire[2] != (uint8_t)'M' || wire[3] != (uint8_t)'1'
        || rd_le_u16(wire + 4) != 1u) {
        s->membership_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    ninlil_wifi_sha256(wire, 88u, expect);
    if (memcmp(expect, wire + 88, 32u) != 0) {
        s->membership_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    nb = rd_le_u64(wire + 24);
    na = rd_le_u64(wire + 32);
    if (mono_now_ms < nb || mono_now_ms > na) {
        s->membership_class = NINLIL_WIFI_M4_CLASS_STALE;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if ((s->source_bits & M4_BIT_ATTACHMENT) != 0u) {
        if (memcmp(s->attachment_authority_id, wire + 40, 16u) != 0
            || memcmp(s->active_attachment_binding_digest, wire + 56, 32u) != 0
            || memcmp(s->peer_session_id, wire + 8, 16u) != 0) {
            s->membership_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
            m4_unlock(o);
            return NINLIL_WIFI_OK;
        }
    }
    if ((s->source_bits & M4_BIT_FABRIC) != 0u) {
        if (memcmp(s->fabric_authority_id, wire + 40, 16u) != 0) {
            s->membership_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
            m4_unlock(o);
            return NINLIL_WIFI_OK;
        }
    }
    s->membership_class = NINLIL_WIFI_M4_CLASS_FULL;
    s->membership_live = 1u;
    s->source_bits |= M4_BIT_MEMBERSHIP;
    (void)memcpy(s->member_runtime_id, wire + 8, 16u);
    (void)memcpy(s->membership_authority_id, wire + 40, 16u);
    (void)memcpy(s->membership_binding_digest, wire + 56, 32u);
    (void)memcpy(s->membership_wire_digest, wire + 88, 32u);
    m4_unlock(o);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_m4_attachment_store_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t peer_session_id[16],
    const uint8_t authority_id[16],
    const uint8_t binding_digest[32],
    const uint8_t credential_digest[32],
    const uint8_t fabric_descriptor[32])
{
    ninlil_wifi_cu_class_t observed = NINLIL_WIFI_CU_NONE;
    return ninlil_wifi_m4_attachment_store_full_reconciled(
        storage,
        storage_user,
        path_utf8,
        peer_session_id,
        authority_id,
        binding_digest,
        credential_digest,
        fabric_descriptor,
        &observed);
}

ninlil_wifi_status_t ninlil_wifi_m4_attachment_store_full_reconciled(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t peer_session_id[16],
    const uint8_t authority_id[16],
    const uint8_t binding_digest[32],
    const uint8_t credential_digest[32],
    const uint8_t fabric_descriptor[32],
    ninlil_wifi_cu_class_t *out_class)
{
    uint8_t wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint8_t dig[32];
    if (peer_session_id == NULL || authority_id == NULL || binding_digest == NULL
        || credential_digest == NULL || fabric_descriptor == NULL
        || out_class == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_WIFI_CU_NONE;
    if (is_all_zero(peer_session_id, 16u) || is_all_zero(authority_id, 16u)
        || is_all_zero(binding_digest, 32u)
        || is_all_zero(credential_digest, 32u)
        || is_all_zero(fabric_descriptor, 32u)) {
        return NINLIL_WIFI_DENIED;
    }
    (void)memset(wire, 0, sizeof(wire));
    wire[0] = (uint8_t)'M';
    wire[1] = (uint8_t)'4';
    wire[2] = (uint8_t)'A';
    wire[3] = (uint8_t)'1';
    le_u16(wire + 4, 1u);
    le_u16(wire + 6, 1u);
    (void)memcpy(wire + 8, peer_session_id, 16u);
    (void)memcpy(wire + 24, authority_id, 16u);
    (void)memcpy(wire + 40, binding_digest, 32u);
    (void)memcpy(wire + 72, credential_digest, 32u);
    (void)memcpy(wire + 104, fabric_descriptor, 32u);
    ninlil_wifi_sha256(wire, 136u, dig);
    (void)memcpy(wire + 136, dig, 24u);
    return cu_put_full(
        storage, storage_user, path_utf8, NINLIL_WIFI_M4_KEY_ATTACHMENT, wire,
        (uint32_t)sizeof(wire), out_class);
}

ninlil_wifi_status_t ninlil_wifi_m4_attachment_load_classify(
    ninlil_wifi_m4_owner_t *owner,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t peer_session_id[16],
    ninlil_wifi_m4_full_evidence_t *ev)
{
    m4_owner_t *o = owner_impl(owner);
    m4_slot_t *s;
    uint8_t wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint32_t len = 0u;
    ninlil_wifi_status_t st;
    uint8_t dig[32];
    uint64_t my_op = 0u;
    if (o == NULL || o->initialized == 0u || peer_session_id == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    m4_lock(o);
    st = slot_acquire_for_unlocked(o, ev, &s);
    if (st != NINLIL_WIFI_OK) {
        m4_unlock(o);
        return st;
    }
    if (bump_load_op_unlocked(&s->attachment_load_op, &my_op) != 0) {
        m4_unlock(o);
        return NINLIL_WIFI_DENIED;
    }
    s->attachment_class = NINLIL_WIFI_M4_CLASS_MISSING;
    s->source_bits &= (uint32_t)~M4_BIT_ATTACHMENT;
    m4_unlock(o);
    m4_invoke_io_hook();
    st = cu_get(
        storage, storage_user, path_utf8, NINLIL_WIFI_M4_KEY_ATTACHMENT, wire,
        (uint32_t)sizeof(wire), &len);
    m4_lock(o);
    if (!attachment_op_current_unlocked(ev, my_op, &s)) {
        m4_unlock(o);
        return NINLIL_WIFI_DENIED;
    }
    if (st == NINLIL_WIFI_UNAVAILABLE) {
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if (st != NINLIL_WIFI_OK) {
        s->attachment_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return st;
    }
    if (len != sizeof(wire) || wire[0] != (uint8_t)'M' || wire[1] != (uint8_t)'4'
        || wire[2] != (uint8_t)'A' || wire[3] != (uint8_t)'1'
        || rd_le_u16(wire + 4) != 1u) {
        s->attachment_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    ninlil_wifi_sha256(wire, 136u, dig);
    if (memcmp(dig, wire + 136, 24u) != 0) {
        s->attachment_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if (memcmp(wire + 8, peer_session_id, 16u) != 0) {
        s->attachment_class = NINLIL_WIFI_M4_CLASS_STALE;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if (rd_le_u16(wire + 6) != 1u) {
        s->attachment_class = NINLIL_WIFI_M4_CLASS_STALE;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if ((s->source_bits & M4_BIT_MEMBERSHIP) != 0u) {
        if (memcmp(s->membership_authority_id, wire + 24, 16u) != 0
            || memcmp(s->membership_binding_digest, wire + 40, 32u) != 0
            || memcmp(s->member_runtime_id, wire + 8, 16u) != 0) {
            s->attachment_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
            m4_unlock(o);
            return NINLIL_WIFI_OK;
        }
    }
    if ((s->source_bits & M4_BIT_CREDENTIAL) != 0u) {
        if (memcmp(s->credential_candidate_digest, wire + 72, 32u) != 0) {
            s->attachment_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
            m4_unlock(o);
            return NINLIL_WIFI_OK;
        }
    }
    if ((s->source_bits & M4_BIT_FABRIC) != 0u) {
        if (memcmp(s->fabric_descriptor, wire + 104, 32u) != 0
            || memcmp(s->fabric_authority_id, wire + 24, 16u) != 0) {
            s->attachment_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
            m4_unlock(o);
            return NINLIL_WIFI_OK;
        }
    }
    s->attachment_class = NINLIL_WIFI_M4_CLASS_FULL;
    s->source_bits |= M4_BIT_ATTACHMENT;
    (void)memcpy(s->peer_session_id, wire + 8, 16u);
    (void)memcpy(s->attachment_authority_id, wire + 24, 16u);
    (void)memcpy(s->active_attachment_binding_digest, wire + 40, 32u);
    (void)memcpy(s->attachment_credential_digest, wire + 72, 32u);
    (void)memcpy(s->attachment_fabric_descriptor, wire + 104, 32u);
    (void)memcpy(s->attachment_wire_digest, dig, 32u);
    (void)memcpy(s->durable_image, wire, sizeof(wire));
    m4_unlock(o);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_m4_credential_store_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t secret_ref_digest[32],
    uint64_t revision)
{
    ninlil_wifi_cu_class_t observed = NINLIL_WIFI_CU_NONE;
    return ninlil_wifi_m4_credential_store_full_reconciled(
        storage,
        storage_user,
        path_utf8,
        secret_ref_digest,
        revision,
        &observed);
}

ninlil_wifi_status_t ninlil_wifi_m4_credential_store_full_reconciled(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t secret_ref_digest[32],
    uint64_t revision,
    ninlil_wifi_cu_class_t *out_class)
{
    uint8_t wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint8_t dig[32];
    if (secret_ref_digest == NULL || is_all_zero(secret_ref_digest, 32u)
        || revision == 0u || out_class == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    *out_class = NINLIL_WIFI_CU_NONE;
    (void)memset(wire, 0, sizeof(wire));
    wire[0] = (uint8_t)'M';
    wire[1] = (uint8_t)'4';
    wire[2] = (uint8_t)'C';
    wire[3] = (uint8_t)'1';
    le_u16(wire + 4, 1u);
    le_u16(wire + 6, 1u);
    le_u64(wire + 8, revision);
    (void)memcpy(wire + 16, secret_ref_digest, 32u);
    ninlil_wifi_sha256(wire, 48u, dig);
    (void)memcpy(wire + 48, dig, 32u);
    return cu_put_full(
        storage, storage_user, path_utf8, NINLIL_WIFI_M4_KEY_CREDENTIAL, wire,
        (uint32_t)sizeof(wire), out_class);
}

ninlil_wifi_status_t ninlil_wifi_m4_credential_load_classify(
    ninlil_wifi_m4_owner_t *owner,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    ninlil_wifi_m4_full_evidence_t *ev)
{
    m4_owner_t *o = owner_impl(owner);
    m4_slot_t *s;
    uint8_t wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint32_t len = 0u;
    ninlil_wifi_status_t st;
    uint8_t dig[32];
    uint64_t my_op = 0u;
    if (o == NULL || o->initialized == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    m4_lock(o);
    st = slot_acquire_for_unlocked(o, ev, &s);
    if (st != NINLIL_WIFI_OK) {
        m4_unlock(o);
        return st;
    }
    if (bump_load_op_unlocked(&s->credential_load_op, &my_op) != 0) {
        m4_unlock(o);
        return NINLIL_WIFI_DENIED;
    }
    s->credential_class = NINLIL_WIFI_M4_CLASS_MISSING;
    s->source_bits &= (uint32_t)~M4_BIT_CREDENTIAL;
    m4_unlock(o);
    m4_invoke_io_hook();
    st = cu_get(
        storage, storage_user, path_utf8, NINLIL_WIFI_M4_KEY_CREDENTIAL, wire,
        (uint32_t)sizeof(wire), &len);
    m4_lock(o);
    if (!credential_op_current_unlocked(ev, my_op, &s)) {
        m4_unlock(o);
        return NINLIL_WIFI_DENIED;
    }
    if (st == NINLIL_WIFI_UNAVAILABLE) {
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if (st != NINLIL_WIFI_OK) {
        s->credential_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return st;
    }
    if (len != sizeof(wire) || wire[0] != (uint8_t)'M' || wire[1] != (uint8_t)'4'
        || wire[2] != (uint8_t)'C' || wire[3] != (uint8_t)'1'
        || rd_le_u16(wire + 4) != 1u || rd_le_u16(wire + 6) != 1u) {
        s->credential_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    ninlil_wifi_sha256(wire, 48u, dig);
    if (memcmp(dig, wire + 48, 32u) != 0) {
        s->credential_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if (rd_le_u64(wire + 8) == 0u || is_all_zero(wire + 16, 32u)) {
        s->credential_class = NINLIL_WIFI_M4_CLASS_STALE;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    if ((s->source_bits & M4_BIT_ATTACHMENT) != 0u
        && memcmp(s->attachment_credential_digest, wire + 16, 32u) != 0) {
        s->credential_class = NINLIL_WIFI_M4_CLASS_CORRUPT;
        m4_unlock(o);
        return NINLIL_WIFI_OK;
    }
    s->credential_class = NINLIL_WIFI_M4_CLASS_FULL;
    s->source_bits |= M4_BIT_CREDENTIAL;
    (void)memcpy(s->credential_candidate_digest, wire + 16, 32u);
    (void)memcpy(s->credential_wire_digest, dig, 32u);
    m4_unlock(o);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_m4_fabric_registry_bind(
    ninlil_wifi_m4_fabric_registry_t *reg,
    const uint8_t fabric_descriptor[32],
    const uint8_t authority_id[16],
    const uint8_t registry_epoch_id[16])
{
    if (reg == NULL || fabric_descriptor == NULL || authority_id == NULL
        || registry_epoch_id == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (is_all_zero(fabric_descriptor, 32u) || is_all_zero(authority_id, 16u)
        || is_all_zero(registry_epoch_id, 16u)) {
        return NINLIL_WIFI_DENIED;
    }
    (void)memset(reg, 0, sizeof(*reg));
    (void)memcpy(reg->fabric_descriptor, fabric_descriptor, 32u);
    (void)memcpy(reg->authority_id, authority_id, 16u);
    (void)memcpy(reg->registry_epoch_id, registry_epoch_id, 16u);
    reg->bound = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_m4_evidence_apply_fabric_registry(
    ninlil_wifi_m4_full_evidence_t *ev,
    const ninlil_wifi_m4_fabric_registry_t *reg)
{
    m4_handle_t *h = handle_mut(ev);
    m4_owner_t *o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    m4_slot_t *s;
    ninlil_wifi_status_t st = NINLIL_WIFI_OK;
    m4_lock(o);
    s = slot_resolve_mut_unlocked(ev);
    if (s == NULL || reg == NULL || !reg->bound) {
        st = NINLIL_WIFI_DENIED;
        goto out;
    }
    if ((s->source_bits & M4_BIT_ATTACHMENT) != 0u) {
        if (memcmp(s->attachment_authority_id, reg->authority_id, 16u) != 0
            || memcmp(
                   s->attachment_fabric_descriptor, reg->fabric_descriptor, 32u)
                != 0) {
            s->fabric_registry_bound = 0u;
            s->source_bits &= (uint32_t)~M4_BIT_FABRIC;
            st = NINLIL_WIFI_DENIED;
            goto out;
        }
    }
    if ((s->source_bits & M4_BIT_MEMBERSHIP) != 0u) {
        if (memcmp(s->membership_authority_id, reg->authority_id, 16u) != 0) {
            s->fabric_registry_bound = 0u;
            s->source_bits &= (uint32_t)~M4_BIT_FABRIC;
            st = NINLIL_WIFI_DENIED;
            goto out;
        }
    }
    (void)memcpy(s->fabric_descriptor, reg->fabric_descriptor, 32u);
    (void)memcpy(s->fabric_authority_id, reg->authority_id, 16u);
    (void)memcpy(s->fabric_epoch_id, reg->registry_epoch_id, 16u);
    s->fabric_registry_bound = 1u;
    s->source_bits |= M4_BIT_FABRIC;
out:
    m4_unlock(o);
    return st;
}

ninlil_wifi_status_t ninlil_wifi_m4_evidence_ready_for_attach(
    const ninlil_wifi_m4_full_evidence_t *ev)
{
    const m4_handle_t *h = handle_const(ev);
    m4_owner_t *o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    const m4_slot_t *s;
    ninlil_wifi_status_t st;
    if (ev == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    m4_lock(o);
    s = slot_resolve_const_unlocked(ev);
    st = (s != NULL && slot_is_ready(s)) ? NINLIL_WIFI_OK : NINLIL_WIFI_DENIED;
    m4_unlock(o);
    return st;
}

ninlil_wifi_status_t ninlil_wifi_m4_evidence_export_attach_material(
    const ninlil_wifi_m4_full_evidence_t *ev,
    ninlil_wifi_m4_attach_material_t *out)
{
    const m4_handle_t *h = handle_const(ev);
    m4_owner_t *o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o == NULL) {
        if (out != NULL) { (void)memset(out, 0, sizeof(*out)); }
        return NINLIL_WIFI_DENIED;
    }
    const m4_slot_t *s;
    ninlil_wifi_status_t st = NINLIL_WIFI_DENIED;
    if (out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    m4_lock(o);
    s = slot_resolve_const_unlocked(ev);
    if (s != NULL && slot_is_ready(s)) {
        (void)memcpy(out->peer_session_id, s->peer_session_id, 16u);
        (void)memcpy(
            out->attachment_authority_id, s->attachment_authority_id, 16u);
        (void)memcpy(
            out->active_attachment_binding_digest,
            s->active_attachment_binding_digest,
            32u);
        (void)memcpy(
            out->credential_candidate_digest,
            s->credential_candidate_digest,
            32u);
        (void)memcpy(out->fabric_descriptor, s->fabric_descriptor, 32u);
        st = NINLIL_WIFI_OK;
    }
    m4_unlock(o);
    return st;
}

ninlil_wifi_m4_record_class_t ninlil_wifi_m4_evidence_class_membership(
    const ninlil_wifi_m4_full_evidence_t *ev)
{
    const m4_handle_t *h = handle_const(ev);
    m4_owner_t *o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o == NULL) {
        return NINLIL_WIFI_M4_CLASS_MISSING;
    }
    const m4_slot_t *s;
    ninlil_wifi_m4_record_class_t c = NINLIL_WIFI_M4_CLASS_MISSING;
    m4_lock(o);
    s = slot_resolve_const_unlocked(ev);
    if (s != NULL) {
        c = s->membership_class;
    }
    m4_unlock(o);
    return c;
}

ninlil_wifi_m4_record_class_t ninlil_wifi_m4_evidence_class_attachment(
    const ninlil_wifi_m4_full_evidence_t *ev)
{
    const m4_handle_t *h = handle_const(ev);
    m4_owner_t *o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o == NULL) {
        return NINLIL_WIFI_M4_CLASS_MISSING;
    }
    const m4_slot_t *s;
    ninlil_wifi_m4_record_class_t c = NINLIL_WIFI_M4_CLASS_MISSING;
    m4_lock(o);
    s = slot_resolve_const_unlocked(ev);
    if (s != NULL) {
        c = s->attachment_class;
    }
    m4_unlock(o);
    return c;
}

ninlil_wifi_m4_record_class_t ninlil_wifi_m4_evidence_class_credential(
    const ninlil_wifi_m4_full_evidence_t *ev)
{
    const m4_handle_t *h = handle_const(ev);
    m4_owner_t *o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o == NULL) {
        return NINLIL_WIFI_M4_CLASS_MISSING;
    }
    const m4_slot_t *s;
    ninlil_wifi_m4_record_class_t c = NINLIL_WIFI_M4_CLASS_MISSING;
    m4_lock(o);
    s = slot_resolve_const_unlocked(ev);
    if (s != NULL) {
        c = s->credential_class;
    }
    m4_unlock(o);
    return c;
}

int ninlil_wifi_m4_evidence_membership_live(
    const ninlil_wifi_m4_full_evidence_t *ev)
{
    const m4_handle_t *h = handle_const(ev);
    m4_owner_t *o = (h != NULL) ? owner_from_handle_unlocked(h) : NULL;
    if (o == NULL) {
        return 0;
    }
    const m4_slot_t *s;
    int live = 0;
    m4_lock(o);
    s = slot_resolve_const_unlocked(ev);
    if (s != NULL && s->membership_live != 0u) {
        live = 1;
    }
    m4_unlock(o);
    return live;
}
