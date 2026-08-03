/* SPDX-License-Identifier: Apache-2.0
 * Fault / transactional FULL / expiry / adversarial geometry tests.
 */
#include "mfdt_v1.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
static void expect(int c, const char *m) {
  if (!c) { fprintf(stderr, "FAIL: %s\n", m); g_fail = 1; }
}

static void test_txn_crash_not_visible(void) {
  ninlil_mfdt_v1_lab_store_t st;
  uint8_t key[20];
  uint8_t val[32];
  uint8_t out[32];
  uint32_t len = 0;
  memset(key, 0xab, sizeof(key));
  memset(val, 0xcd, sizeof(val));
  ninlil_mfdt_v1_lab_store_init(&st);
  st.crash_after_fulls = 0; /* fail first commit */
  st.crash_after_fulls = 0;
  /* begin, put staging, crash commit => get must miss */
  expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "begin");
  expect(ninlil_mfdt_v1_lab_put(&st, key, val, 32) == 0, "stage put");
  /* staged not visible */
  expect(ninlil_mfdt_v1_lab_get(&st, key, out, 32, &len) != 0, "not visible pre-commit");
  st.crash_after_fulls = 0; /* allow? wait: full_count+1 > crash_after when crash_after is 0 means no inject */
  /* set crash on next commit */
  st.crash_after_fulls = 0;
  st.full_count = 0;
  st.crash_after_fulls = 0; /* 0 = disabled */
  /* Force inject: crash_after_fulls = 0 disables; use 1 and full_count=1 so next fails?
     code: full_count+1 > crash_after_fulls => if crash_after=1 and full_count=0, 1>1 false; full_count=1, 2>1 true */
  st.crash_after_fulls = 1;
  st.full_count = 1;
  expect(ninlil_mfdt_v1_lab_full_commit(&st) == NINLIL_MFDT_V1_ERR_STORAGE, "crash commit");
  expect(st.crash_armed == 1, "armed");
  expect(ninlil_mfdt_v1_lab_get(&st, key, out, 32, &len) != 0, "still absent after failed commit");
  /* successful path */
  ninlil_mfdt_v1_lab_store_init(&st);
  expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "begin2");
  expect(ninlil_mfdt_v1_lab_put(&st, key, val, 32) == 0, "put2");
  expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "commit2");
  expect(ninlil_mfdt_v1_lab_get(&st, key, out, 32, &len) == 0 && len == 32, "visible after commit");
  expect(ninlil_mfdt_v1_memeq(out, val, 32), "value match");
}

static void test_entry_layout_and_overflow(void) {
  uint8_t entry[40];
  uint8_t dig[32];
  uint8_t chunk[4] = {1,2,3,4};
  ninlil_mfdt_v1_chunk_entry(chunk, 4, 0, 0, entry);
  expect(ninlil_mfdt_v1_get_u16(entry+0) == 0, "index0");
  expect(ninlil_mfdt_v1_get_u16(entry+2) == 4, "len");
  expect(ninlil_mfdt_v1_get_u32(entry+4) == 0, "off");
  ninlil_mfdt_v1_sha256(chunk, 4, dig);
  expect(ninlil_mfdt_v1_memeq(entry+8, dig, 32), "dig");
  /* overflow index */
  ninlil_mfdt_v1_chunk_entry(chunk, 4, 0, 99, entry);
  expect(ninlil_mfdt_v1_get_u16(entry+0) == 0 && ninlil_mfdt_v1_get_u16(entry+2) == 0, "overflow zero");
  /* manifest with chunk_count>37 must not stack-overflow (returns closed digest) */
  {
    uint8_t out[32];
    uint8_t head[202];
    memset(head, 0, sizeof(head));
    ninlil_mfdt_v1_manifest_digest(
        head, NULL, NULL, 0u, NULL, 99u, out);
    /* closed overflow digest is non-zero domain hash of overflow tag */
    expect(!(out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == 0 &&
             out[28] == 0 && out[29] == 0 && out[30] == 0 && out[31] == 0),
           "manifest overflow safe non-zero");
  }
}

static void test_cu_on_real_bytes(void) {
  uint8_t oldb[8] = {1,2,3,4,5,6,7,8};
  uint8_t newb[8] = {1,2,3,4,5,6,7,9};
  ninlil_mfdt_v1_cu_class_t c;
  c = ninlil_mfdt_v1_classify_cu_bytes(oldb, 8, 1, oldb, 8, 1, newb, 8, 1);
  expect(c == NINLIL_MFDT_V1_CU_OLD, "cu old");
  c = ninlil_mfdt_v1_classify_cu_bytes(newb, 8, 1, oldb, 8, 1, newb, 8, 1);
  expect(c == NINLIL_MFDT_V1_CU_NEW, "cu new");
  c = ninlil_mfdt_v1_classify_cu_bytes(NULL, 0, 0, oldb, 8, 1, newb, 8, 1);
  expect(c == NINLIL_MFDT_V1_CU_ABSENT, "cu absent");
  c = ninlil_mfdt_v1_classify_cu_bytes(oldb, 4, 1, oldb, 8, 1, newb, 8, 1);
  expect(c == NINLIL_MFDT_V1_CU_PARTIAL || c == NINLIL_MFDT_V1_CU_THIRD, "cu partial/third");
}

static void test_retry_budget_and_resume_bounds(void) {
  ninlil_mfdt_v1_engine_t eng;
  ninlil_mfdt_v1_workspace_t ws;
  ninlil_mfdt_v1_lab_store_t st;
  ninlil_mfdt_v1_config_t cfg;
  uint8_t tid[16];
  uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
  uint16_t olen = 0;
  ninlil_mfdt_v1_response_t resp;
  uint8_t q[64];
  memset(&cfg, 0, sizeof(cfg));
  cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
  cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 1u;
    cfg.session_generation = 1u;
  cfg.host_mode = 1;
  cfg.now_ms = 1;
  memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
  cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
  memset(tid, 3, 16);
  tid[0] = 1;
  ninlil_mfdt_v1_lab_store_init(&st);
  expect(ninlil_mfdt_v1_engine_init(&eng, &ws, &st, &cfg) == 0, "init");
  expect(ninlil_mfdt_v1_sender_open(&eng, tid, NULL, 0, open, &olen, 1) == 0, "sopen");
  /* receiver path */
  {
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == 0, "rxinit");
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, olen, 1, &resp) == 0, "ropen");
    /* resume gen 0 reject */
    memset(q, 0, sizeof(q));
    ninlil_mfdt_v1_bind52(tid, ninlil_mfdt_v1_get_u32(open + 16),
                          open + 202, q);
    ninlil_mfdt_v1_put_u32(q + 52, 0);
    expect(ninlil_mfdt_v1_receiver_on_resume(
               &rx, q, 60, 9, &resp) == NINLIL_MFDT_V1_OK,
           "resume0 transport");
    expect(resp.message_type == NINLIL_MFDT_V1_MSG_REJECT &&
               resp.reject_code == NINLIL_MFDT_V1_REJ_STATE &&
               resp.state_mutation == 1u && resp.full_count == 1u,
           "resume0 exact reject");
    /* gap >1 reject */
    ninlil_mfdt_v1_put_u32(q + 52, 3);
    expect(ninlil_mfdt_v1_receiver_on_resume(
               &rx, q, 60, 10, &resp) == NINLIL_MFDT_V1_OK,
           "resume gap transport");
    expect(resp.message_type == NINLIL_MFDT_V1_MSG_REJECT &&
               resp.reject_code == NINLIL_MFDT_V1_REJ_STATE &&
               resp.state_mutation == 1u && resp.full_count == 1u,
           "resume gap exact reject");
    /* gen 9 >8 reject */
    ninlil_mfdt_v1_put_u32(q + 52, 9);
    expect(ninlil_mfdt_v1_receiver_on_resume(
               &rx, q, 60, 11, &resp) == NINLIL_MFDT_V1_OK,
           "resume>8 transport");
    expect(resp.message_type == NINLIL_MFDT_V1_MSG_REJECT &&
               resp.reject_code == NINLIL_MFDT_V1_REJ_STATE &&
               resp.state_mutation == 1u && resp.full_count == 1u,
           "resume>8 exact reject");
    /* gen 1 ok */
    ninlil_mfdt_v1_put_u32(q + 52, 1);
    expect(ninlil_mfdt_v1_receiver_on_resume(&rx, q, 60, 12, &resp) == 0, "resume1");
  }
}

static void test_expiry_frees_slot(void) {
  ninlil_mfdt_v1_engine_t tx;
  ninlil_mfdt_v1_engine_t rx;
  ninlil_mfdt_v1_engine_t tx2;
  ninlil_mfdt_v1_workspace_t txws;
  ninlil_mfdt_v1_workspace_t rxws;
  ninlil_mfdt_v1_workspace_t txws2;
  ninlil_mfdt_v1_lab_store_t txst;
  ninlil_mfdt_v1_lab_store_t rxst;
  ninlil_mfdt_v1_lab_store_t txst2;
  ninlil_mfdt_v1_config_t cfg;
  uint8_t tid[16];
  uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
  uint8_t content = 0x5au;
  uint16_t olen = 0;
  ninlil_mfdt_v1_response_t resp;
  memset(&cfg, 0, sizeof(cfg));
  cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
  cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 1u;
    cfg.session_generation = 1u;
  cfg.host_mode = 1;
  cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
  cfg.now_ms = 1;
  memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
  memset(tid, 9, 16);
  ninlil_mfdt_v1_lab_store_init(&txst);
  ninlil_mfdt_v1_lab_store_init(&rxst);
  expect(ninlil_mfdt_v1_engine_init(&tx, &txws, &txst, &cfg) == 0, "tx init");
  expect(ninlil_mfdt_v1_engine_init(&rx, &rxws, &rxst, &cfg) == 0, "rx init");
  expect(ninlil_mfdt_v1_sender_open(&tx, tid, &content, 1u, open, &olen, 1) == 0,
         "open");
  expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, olen, 1, &resp) == 0,
         "reserve");
  expect(rx.active_count == 1, "active1");
  rx.cfg.now_ms = 1u + NINLIL_MFDT_V1_RESERVATION_MS;
  expect(ninlil_mfdt_v1_on_reservation_expired(&rx) == 0, "expiry");
  expect(rx.active_count == 0, "active0");
  /* A terminalized receiver slot is reusable by a new transfer. */
  tid[0] = 10;
  ninlil_mfdt_v1_lab_store_init(&txst2);
  expect(ninlil_mfdt_v1_engine_init(&tx2, &txws2, &txst2, &cfg) == 0,
         "tx2 init");
  expect(ninlil_mfdt_v1_sender_open(&tx2, tid, &content, 1u, open, &olen, 2) == 0,
         "open2");
  expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, olen, 2, &resp) == 0,
         "reuse open");
}

static void test_budget_pins(void) {
  expect(ninlil_mfdt_v1_receiver_fulls_max() == 77u, "rx77");
  expect(ninlil_mfdt_v1_sender_fulls_max() == 67u, "tx67");
}

static void test_retry_exhaustion_and_session(void) {
  ninlil_mfdt_v1_engine_t eng;
  ninlil_mfdt_v1_engine_t rx;
  ninlil_mfdt_v1_workspace_t ws;
  ninlil_mfdt_v1_workspace_t rws;
  ninlil_mfdt_v1_lab_store_t st;
  ninlil_mfdt_v1_lab_store_t rst;
  ninlil_mfdt_v1_config_t cfg;
  ninlil_mfdt_v1_response_t response;
  uint8_t tid[16];
  uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
  uint16_t olen = 0;
  int i;
  memset(&cfg, 0, sizeof(cfg));
  cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
  cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 1u;
    cfg.session_generation = 1u;
  cfg.host_mode = 1;
  cfg.mfdt_capability = 1;
  cfg.session_generation = 1;
  cfg.now_ms = 1;
  memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
  cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
  memset(tid, 4, 16); tid[0] = 1;
  ninlil_mfdt_v1_lab_store_init(&st);
  ninlil_mfdt_v1_lab_store_init(&rst);
  expect(ninlil_mfdt_v1_admission_check(&cfg) == 0, "admission");
  cfg.mfdt_capability = 0;
  expect(ninlil_mfdt_v1_admission_check(&cfg) != 0, "admission cap");
  cfg.mfdt_capability = 1;
  expect(ninlil_mfdt_v1_engine_init(&eng, &ws, &st, &cfg) == 0, "init");
  expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == 0, "rx init");
  expect(ninlil_mfdt_v1_sender_open(&eng, tid, NULL, 0, open, &olen, 1) == 0, "open");
  expect(ninlil_mfdt_v1_receiver_on_open(
             &rx, open, olen, 1, &response) == 0,
         "receiver open anchor");
  expect(ninlil_mfdt_v1_retry_budget_remaining(&eng) == 8u, "rb8");
  for (i = 0; i < 8; ++i) {
    expect(ninlil_mfdt_v1_owner_timeout_retry_charge(&eng) == 0, "charge");
  }
  expect(ninlil_mfdt_v1_retry_budget_remaining(&eng) == 0u, "rb0");
  expect(ninlil_mfdt_v1_owner_timeout_retry_charge(&eng) == NINLIL_MFDT_V1_ERR_CAPACITY,
         "exhausted");
  /* Distinct session generations advance once (1->2), then stop at two. */
  expect(ninlil_mfdt_v1_advance_session_generation(&rx) == 0, "sess2");
  expect(ninlil_mfdt_v1_advance_session_generation(&rx) != 0, "sess max");
}

static void test_restart_rehydrates_durable(void) {
  ninlil_mfdt_v1_engine_t eng;
  ninlil_mfdt_v1_workspace_t ws;
  ninlil_mfdt_v1_lab_store_t st;
  ninlil_mfdt_v1_config_t cfg;
  uint8_t tid[16];
  uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
  uint16_t olen = 0;
  uint8_t content[4] = {1,2,3,4};
  memset(&cfg, 0, sizeof(cfg));
  cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
  cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 1u;
    cfg.session_generation = 1u;
  cfg.host_mode = 1;
  cfg.now_ms = 50;
  memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
  cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
  memset(tid, 5, 16); tid[0] = 2;
  ninlil_mfdt_v1_lab_store_init(&st);
  expect(ninlil_mfdt_v1_engine_init(&eng, &ws, &st, &cfg) == 0, "init");
  expect(ninlil_mfdt_v1_sender_open(&eng, tid, content, 4, open, &olen, 1) == 0, "open");
  expect(eng.active_count == 1, "active");
  /* wipe RAM meta except we keep store; re-init engine workspace */
  expect(ninlil_mfdt_v1_engine_init(&eng, &ws, &st, &cfg) == 0, "reinit");
  /* restore tid/role into meta then scan */
  {
    /* After full reinit, meta is zero — restart_scan needs tid. Lab path:
     * re-open is capacity unless we seed meta from store by scanning keys.
     * Seed occupied meta with tid+role then restart_scan. */
    uint8_t *bytes = ws.bytes;
    memset(bytes, 0, 512);
    memcpy(bytes, tid, 16);
    bytes[16] = 1; /* occupied */
    bytes[17] = 1; /* role sender */
  }
  /* A fresh engine must recover the durable transfer without reopening it. */
  {
    ninlil_mfdt_v1_engine_t e2;
    ninlil_mfdt_v1_workspace_t w2;
    uint8_t key[20];
    uint8_t rec[4096];
    uint32_t len = 0;
    ninlil_mfdt_v1_engine_init(&e2, &w2, &st, &cfg);
    memcpy(key, "NM3S", 4);
    memcpy(key + 4, tid, 16);
    expect(ninlil_mfdt_v1_lab_get(&st, key, rec, sizeof(rec), &len) == 0 && len > 308,
           "durable NM3S present");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&e2, tid, 1u) == 0, "restart");
    expect(e2.active_count == 1, "rehydrated active");
    expect(ninlil_mfdt_v1_retry_budget_remaining(&e2) == 8u, "rb restored");
  }
}

static void test_cu_after_full_boundary(void) {
  ninlil_mfdt_v1_lab_store_t st;
  uint8_t key[20];
  uint8_t oldv[8] = {1,1,1,1,1,1,1,1};
  uint8_t newv[8] = {2,2,2,2,2,2,2,2};
  ninlil_mfdt_v1_cu_class_t c;
  memset(key, 0xab, 20);
  ninlil_mfdt_v1_lab_store_init(&st);
  expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b");
  expect(ninlil_mfdt_v1_lab_put(&st, key, oldv, 8) == 0, "p");
  expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c");
  c = ninlil_mfdt_v1_cu_observe_key(&st, key, oldv, 8, 1, newv, 8, 1);
  expect(c == NINLIL_MFDT_V1_CU_OLD, "old image");
  expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b2");
  expect(ninlil_mfdt_v1_lab_put(&st, key, newv, 8) == 0, "p2");
  expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c2");
  c = ninlil_mfdt_v1_cu_observe_key(&st, key, oldv, 8, 1, newv, 8, 1);
  expect(c == NINLIL_MFDT_V1_CU_NEW, "new image");
}

int main(void) {
  g_fail = 0;
  test_budget_pins();
  test_entry_layout_and_overflow();
  test_txn_crash_not_visible();
  test_expiry_frees_slot();
  test_cu_on_real_bytes();
  test_retry_budget_and_resume_bounds();
  test_retry_exhaustion_and_session();
  test_restart_rehydrates_durable();
  test_cu_after_full_boundary();
  if (g_fail) { fprintf(stderr, "mfdt_v1_fault_test FAILED\n"); return 1; }
  printf("mfdt_v1_fault_test OK\n");
  return 0;
}
