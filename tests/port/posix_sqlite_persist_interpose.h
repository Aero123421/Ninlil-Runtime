#ifndef NINLIL_POSIX_SQLITE_PERSIST_INTERPOSE_H
#define NINLIL_POSIX_SQLITE_PERSIST_INTERPOSE_H

/*
 * Test-target-only private seam. Linked solely into
 * ninlil_posix_sqlite_storage_test. Production library and installed package
 * must not contain these symbols. Implementation intercepts sqlite3_exec /
 * sqlite3_prepare_v2 / sqlite3_get_autocommit at link time.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_test_persist_point {
    NINLIL_TEST_PERSIST_POINT_NONE = 0,
    NINLIL_TEST_PERSIST_POINT_BEFORE_BEGIN = 1,
    NINLIL_TEST_PERSIST_POINT_AFTER_BEGIN = 2,
    NINLIL_TEST_PERSIST_POINT_BEFORE_MUTATION = 3,
    NINLIL_TEST_PERSIST_POINT_BEFORE_COMMIT = 4,
    NINLIL_TEST_PERSIST_POINT_AFTER_COMMIT = 5
} ninlil_test_persist_point_t;

typedef void (*ninlil_test_persist_point_fn)(
    ninlil_test_persist_point_t point,
    void *user);

void ninlil_test_persist_interpose_set(
    ninlil_test_persist_point_t arm,
    ninlil_test_persist_point_fn fn,
    void *user);

void ninlil_test_persist_interpose_clear(void);

/*
 * One-shot sqlite3_exec result injection for COMMIT / ROLLBACK statements.
 * call_real=0 skips the real SQLite call and returns forced_rc.
 * call_real=1 runs the real call (forced_rc ignored).
 * Each inject is consumed once when a matching statement is observed.
 */
void ninlil_test_sqlite_inject_commit(int call_real, int forced_rc);
void ninlil_test_sqlite_inject_rollback(int call_real, int forced_rc);

/*
 * One-shot: next sqlite3_get_autocommit returns 0 (lie open-txn) then clears.
 * Used to force post-COMMIT COMMIT_UNKNOWN after a real successful COMMIT.
 */
void ninlil_test_sqlite_force_autocommit_zero_once(void);

void ninlil_test_sqlite_inject_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_SQLITE_PERSIST_INTERPOSE_H */
