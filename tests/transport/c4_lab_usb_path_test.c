/*
 * V1-LAB item 9: C4-LAB USB Controller/Cell Agent software path tests.
 */

#include "c4_lab_usb_path.h"
#include "fake_byte_stream.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(                                                     \
                stderr, "REQUIRE fail %s:%d: %s\n", __FILE__, __LINE__, #c);   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct cookie_rng_ctx {
    uint64_t seq;
} cookie_rng_ctx_t;

static int cookie_rng_cb(void *ctx, uint64_t *out)
{
    cookie_rng_ctx_t *c = (cookie_rng_ctx_t *)ctx;
    if (c == NULL || out == NULL) {
        return -1;
    }
    c->seq += 0x1111111111111111ull;
    *out = c->seq;
    return 0;
}

static void pump_pair(
    ninlil_fake_byte_stream_t *a,
    ninlil_fake_byte_stream_t *b)
{
    uint8_t buf[2048];
    uint32_t n;

    n = ninlil_fake_byte_stream_take_tx(a, buf, sizeof(buf));
    if (n > 0u) {
        (void)ninlil_fake_byte_stream_inject_rx(b, buf, n);
    }
    n = ninlil_fake_byte_stream_take_tx(b, buf, sizeof(buf));
    if (n > 0u) {
        (void)ninlil_fake_byte_stream_inject_rx(a, buf, n);
    }
}

static int bring_up_session(
    ninlil_c4_lab_usb_t *ctrl,
    ninlil_c4_lab_usb_t *cell,
    ninlil_fake_byte_stream_t *ctrl_fake,
    ninlil_fake_byte_stream_t *cell_fake,
    uint64_t *now_ms)
{
    uint32_t i;

    for (i = 0u; i < 200u; ++i) {
        REQUIRE(
            ninlil_c4_lab_usb_step(ctrl, *now_ms, 50u)
            == NINLIL_C4_LAB_USB_OK);
        REQUIRE(
            ninlil_c4_lab_usb_step(cell, *now_ms, 50u)
            == NINLIL_C4_LAB_USB_OK);
        pump_pair(ctrl_fake, cell_fake);
        if (ninlil_c4_lab_usb_session_active(ctrl) != 0
            && ninlil_c4_lab_usb_session_active(cell) != 0) {
            return 0;
        }
        *now_ms += 10u;
    }
    return 1;
}

static int test_happy_custody(void)
{
    ninlil_c4_lab_usb_object_t ctrl_obj = NINLIL_C4_LAB_USB_OBJECT_INIT;
    ninlil_c4_lab_usb_object_t cell_obj = NINLIL_C4_LAB_USB_OBJECT_INIT;
    ninlil_c4_lab_usb_t *ctrl;
    ninlil_c4_lab_usb_t *cell;
    ninlil_c4_lab_usb_config_t cfg;
    ninlil_fake_byte_stream_t ctrl_fake;
    ninlil_fake_byte_stream_t cell_fake;
    cookie_rng_ctx_t rng = {0x42u};
    uint64_t now_ms = 1000u;
    const uint8_t payload[] = "v1-lab-u6-custody";
    uint8_t recv[64];
    uint32_t recv_len = 0u;

    ninlil_fake_byte_stream_init(&ctrl_fake);
    ninlil_fake_byte_stream_init(&cell_fake);
    ninlil_fake_byte_stream_open_up(&ctrl_fake, 1u);
    ninlil_fake_byte_stream_open_up(&cell_fake, 2u);
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER;
    cfg.owner_token = 1u;
    REQUIRE(
        ninlil_c4_lab_usb_init_object(&ctrl_obj, &cfg, &ctrl)
        == NINLIL_C4_LAB_USB_OK);
    cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CELL;
    cfg.owner_token = 2u;
    cfg.cookie_rng = cookie_rng_cb;
    cfg.cookie_rng_ctx = &rng;
    REQUIRE(
        ninlil_c4_lab_usb_init_object(&cell_obj, &cfg, &cell)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(
        ninlil_c4_lab_usb_bind(ctrl, &ctrl_fake.view) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(
        ninlil_c4_lab_usb_bind(cell, &cell_fake.view) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_bind_peer(ctrl, cell) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(bring_up_session(ctrl, cell, &ctrl_fake, &cell_fake, &now_ms) == 0);
    REQUIRE(
        ninlil_c4_lab_usb_link_state(ctrl)
        == NINLIL_C4_LAB_USB_CUSTODY_READY);
    REQUIRE(
        ninlil_c4_lab_usb_custody_offer(
            ctrl, 0xA5A5u, payload, (uint32_t)sizeof(payload) - 1u)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(
        ninlil_c4_lab_usb_custody_accept(
            cell, 0xA5A5u, recv, sizeof(recv), &recv_len)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(recv_len == sizeof(payload) - 1u);
    REQUIRE(memcmp(recv, payload, recv_len) == 0);
    (void)fprintf(stderr, "PASS happy_custody\n");
    return 0;
}

static int test_bad_frame(void)
{
    ninlil_c4_lab_usb_object_t cell_obj = NINLIL_C4_LAB_USB_OBJECT_INIT;
    ninlil_c4_lab_usb_t *cell;
    ninlil_c4_lab_usb_config_t cfg;
    cookie_rng_ctx_t rng = {0x99u};
    const uint8_t garbage[] = {
        NINLIL_C4_LAB_USB_WIRE_MAGIC0,
        NINLIL_C4_LAB_USB_WIRE_MAGIC1,
        NINLIL_C4_LAB_USB_WIRE_MAGIC2,
        NINLIL_C4_LAB_USB_WIRE_MAGIC3,
        1u,
        1u,
        0u,
        0u,
        0u,
        0u,
        0u,
        0u,
        0xFFu,
        0xFFu,
        0xFFu,
        0xFFu
    };
    ninlil_c4_lab_usb_diag_t diag;

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CELL;
    cfg.cookie_rng = cookie_rng_cb;
    cfg.cookie_rng_ctx = &rng;
    REQUIRE(
        ninlil_c4_lab_usb_init_object(&cell_obj, &cfg, &cell)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(
        ninlil_c4_lab_usb_inject_wire_rx(
            cell, garbage, (uint32_t)sizeof(garbage))
        == NINLIL_C4_LAB_USB_OK);
    ninlil_c4_lab_usb_diag_snapshot(cell, &diag);
    REQUIRE(diag.bad_frame >= 1u);
    (void)fprintf(stderr, "PASS bad_frame\n");
    return 0;
}

static int test_ownership_violation(void)
{
    ninlil_c4_lab_usb_object_t cell_obj = NINLIL_C4_LAB_USB_OBJECT_INIT;
    ninlil_c4_lab_usb_t *cell;
    ninlil_c4_lab_usb_config_t cfg;
    cookie_rng_ctx_t rng = {0x55u};
    uint8_t recv[32];
    uint32_t recv_len = 0u;

    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CELL;
    cfg.cookie_rng = cookie_rng_cb;
    cfg.cookie_rng_ctx = &rng;
    REQUIRE(
        ninlil_c4_lab_usb_init_object(&cell_obj, &cfg, &cell)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(
        ninlil_c4_lab_usb_custody_accept(cell, 0xBEEFu, recv, sizeof(recv), &recv_len)
        == NINLIL_C4_LAB_USB_OWNERSHIP);
    (void)fprintf(stderr, "PASS ownership_violation\n");
    return 0;
}

static int test_hello_recovery(void)
{
    ninlil_c4_lab_usb_object_t ctrl_obj = NINLIL_C4_LAB_USB_OBJECT_INIT;
    ninlil_c4_lab_usb_t *ctrl;
    ninlil_c4_lab_usb_config_t cfg;
    ninlil_fake_byte_stream_t ctrl_fake;
    ninlil_c4_lab_usb_diag_t diag;

    ninlil_fake_byte_stream_init(&ctrl_fake);
    ninlil_fake_byte_stream_open_up(&ctrl_fake, 1u);
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER;
    REQUIRE(
        ninlil_c4_lab_usb_init_object(&ctrl_obj, &cfg, &ctrl)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(
        ninlil_c4_lab_usb_bind(ctrl, &ctrl_fake.view) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_recover_hello(ctrl) == NINLIL_C4_LAB_USB_OK);
    ninlil_c4_lab_usb_diag_snapshot(ctrl, &diag);
    REQUIRE(diag.hello_recovery >= 1u);
    (void)fprintf(stderr, "PASS hello_recovery\n");
    return 0;
}

int main(void)
{
    REQUIRE(test_happy_custody() == 0);
    REQUIRE(test_bad_frame() == 0);
    REQUIRE(test_ownership_violation() == 0);
    REQUIRE(test_hello_recovery() == 0);
    (void)fprintf(stderr, "c4_lab_usb_path_test: all passed\n");
    return 0;
}
