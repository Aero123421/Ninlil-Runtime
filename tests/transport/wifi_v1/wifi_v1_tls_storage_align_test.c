/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Regression: host session TLS storage must be max_align_t-aligned so that
 * casting tls_storage to ninlil_wifi_tls_t* (OpenSSL SSL / SSL_CTX pointers)
 * is defined. Unaligned uint8_t storage is silent under normal builds and
 * loud under UBSan.
 */
#include "wifi_session.h"
#include "wifi_tls_host.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            (void)fprintf(                                                      \
                stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);          \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

static int test_compile_time_surface(void)
{
    CHECK(sizeof(((ninlil_wifi_session_t *)0)->tls_storage)
        == NINLIL_WIFI_TLS_STORAGE_BYTES);
    CHECK(
        (offsetof(ninlil_wifi_session_t, tls_storage) % _Alignof(max_align_t))
        == 0u);
    CHECK(_Alignof(ninlil_wifi_session_t) >= _Alignof(max_align_t));
    CHECK(NINLIL_WIFI_TLS_STORAGE_BYTES >= ninlil_wifi_tls_sizeof());
    return failures == 0 ? 0 : 1;
}

static int test_session_init_tls_pointer_aligned(void)
{
    ninlil_wifi_session_t session;
    uintptr_t storage_addr;
    uintptr_t tls_addr;

    (void)memset(&session, 0xA5, sizeof(session));
    ninlil_wifi_session_init(&session);
    CHECK(session.tls != NULL);
    storage_addr = (uintptr_t)(void *)&session.tls_storage[0];
    tls_addr = (uintptr_t)(void *)session.tls;
    CHECK((storage_addr % (uintptr_t)_Alignof(max_align_t)) == 0u);
    CHECK((tls_addr % (uintptr_t)_Alignof(max_align_t)) == 0u);
    CHECK(tls_addr == storage_addr);
    CHECK(ninlil_wifi_tls_sizeof() <= sizeof(session.tls_storage));
    ninlil_wifi_session_close(&session);
    return failures == 0 ? 0 : 1;
}

/*
 * Misaligned regression detector: a deliberate +1 offset is NOT max_align_t
 * aligned. If product code ever reintroduces plain unaligned storage casts,
 * this fixture documents the bad address class that UBSan catches.
 */
static int test_misaligned_buffer_is_detectable(void)
{
    _Alignas(max_align_t) uint8_t raw[NINLIL_WIFI_TLS_STORAGE_BYTES + 16u];
    uint8_t *misaligned;
    uintptr_t bad;
    uintptr_t good;

    good = (uintptr_t)(void *)&raw[0];
    CHECK((good % (uintptr_t)_Alignof(max_align_t)) == 0u);

    misaligned = &raw[1];
    bad = (uintptr_t)(void *)misaligned;
    CHECK((bad % (uintptr_t)_Alignof(max_align_t)) != 0u);
    /* Product path must never use this class of pointer for ninlil_wifi_tls_t. */
    CHECK(bad != (uintptr_t)(void *)&raw[0]);
    return failures == 0 ? 0 : 1;
}

/*
 * Array of sessions: each object's tls_storage remains aligned (struct alignas).
 */
static int test_array_of_sessions_keeps_alignment(void)
{
    ninlil_wifi_session_t sessions[3];
    size_t i;

    for (i = 0u; i < 3u; ++i) {
        uintptr_t addr;
        ninlil_wifi_session_init(&sessions[i]);
        addr = (uintptr_t)(void *)sessions[i].tls;
        CHECK(sessions[i].tls != NULL);
        CHECK((addr % (uintptr_t)_Alignof(max_align_t)) == 0u);
        ninlil_wifi_session_close(&sessions[i]);
    }
    return failures == 0 ? 0 : 1;
}

int main(void)
{
    failures = 0;
    (void)test_compile_time_surface();
    (void)test_session_init_tls_pointer_aligned();
    (void)test_misaligned_buffer_is_detectable();
    (void)test_array_of_sessions_keeps_alignment();
    if (failures != 0) {
        (void)fprintf(stderr, "wifi_v1_tls_storage_align_test FAIL count=%d\n",
            failures);
        return 1;
    }
    (void)printf("wifi_v1_tls_storage_align_test PASS\n");
    return 0;
}
