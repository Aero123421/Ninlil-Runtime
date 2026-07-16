/*
 * Test-target-only SQLite interposition for deterministic persist tests.
 * Not part of the production library or install package.
 *
 * Backends (selected by CMake; never mixed):
 *   NINLIL_TEST_SQLITE_INTERPOSE_WRAP  — GNU/Clang -Wl,--wrap on Linux static
 *   NINLIL_TEST_SQLITE_INTERPOSE_DLSYM — RTLD_NEXT for shared libsqlite3
 *
 * Strict C11 for the dlsym backend: void* + size assert + memcpy, no direct
 * void*→function-pointer cast.
 */

#include "posix_sqlite_persist_interpose.h"

#include <sqlite3.h>
#include <stddef.h>
#include <string.h>

#if defined(NINLIL_TEST_SQLITE_INTERPOSE_WRAP)
/* Linker provides __real_* when --wrap is used. */
extern int __real_sqlite3_exec(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void *, int, char **, char **),
    void *arg,
    char **errmsg);
extern int __real_sqlite3_prepare_v2(
    sqlite3 *db,
    const char *sql,
    int n_byte,
    sqlite3_stmt **stmt,
    const char **tail);
extern int __real_sqlite3_get_autocommit(sqlite3 *db);
#elif defined(NINLIL_TEST_SQLITE_INTERPOSE_DLSYM)
#include <dlfcn.h>
#else
#error "posix_sqlite_persist_interpose.c requires WRAP or DLSYM backend define"
#endif

typedef int (*sqlite3_exec_fn)(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void *, int, char **, char **),
    void *arg,
    char **errmsg);

typedef int (*sqlite3_prepare_v2_fn)(
    sqlite3 *db,
    const char *sql,
    int n_byte,
    sqlite3_stmt **stmt,
    const char **tail);

typedef int (*sqlite3_get_autocommit_fn)(sqlite3 *db);

#if defined(NINLIL_TEST_SQLITE_INTERPOSE_DLSYM)
static sqlite3_exec_fn real_sqlite3_exec;
static sqlite3_prepare_v2_fn real_sqlite3_prepare_v2;
static sqlite3_get_autocommit_fn real_sqlite3_get_autocommit;

_Static_assert(
    sizeof(sqlite3_exec_fn) == sizeof(void *),
    "sqlite3_exec_fn size must match void* for dlsym bridge");
_Static_assert(
    sizeof(sqlite3_prepare_v2_fn) == sizeof(void *),
    "sqlite3_prepare_v2_fn size must match void* for dlsym bridge");
_Static_assert(
    sizeof(sqlite3_get_autocommit_fn) == sizeof(void *),
    "sqlite3_get_autocommit_fn size must match void* for dlsym bridge");

static void load_fn_ptr(void *fn_out, size_t fn_size, const char *name)
{
    void *sym;

    if (fn_out == NULL || fn_size != sizeof(void *) || name == NULL) {
        return;
    }
    sym = dlsym(RTLD_NEXT, name);
    if (sym == NULL) {
        return;
    }
    (void)memcpy(fn_out, &sym, fn_size);
}

static void resolve_real(void)
{
    if (real_sqlite3_exec == NULL) {
        load_fn_ptr(&real_sqlite3_exec, sizeof(real_sqlite3_exec), "sqlite3_exec");
    }
    if (real_sqlite3_prepare_v2 == NULL) {
        load_fn_ptr(
            &real_sqlite3_prepare_v2,
            sizeof(real_sqlite3_prepare_v2),
            "sqlite3_prepare_v2");
    }
    if (real_sqlite3_get_autocommit == NULL) {
        load_fn_ptr(
            &real_sqlite3_get_autocommit,
            sizeof(real_sqlite3_get_autocommit),
            "sqlite3_get_autocommit");
    }
}

static int call_real_exec(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void *, int, char **, char **),
    void *arg,
    char **errmsg)
{
    resolve_real();
    if (real_sqlite3_exec == NULL) {
        return SQLITE_ERROR;
    }
    return real_sqlite3_exec(db, sql, callback, arg, errmsg);
}

static int call_real_prepare_v2(
    sqlite3 *db,
    const char *sql,
    int n_byte,
    sqlite3_stmt **stmt,
    const char **tail)
{
    resolve_real();
    if (real_sqlite3_prepare_v2 == NULL) {
        return SQLITE_ERROR;
    }
    return real_sqlite3_prepare_v2(db, sql, n_byte, stmt, tail);
}

static int call_real_get_autocommit(sqlite3 *db)
{
    resolve_real();
    if (real_sqlite3_get_autocommit == NULL) {
        return 1;
    }
    return real_sqlite3_get_autocommit(db);
}
#else /* WRAP */
static int call_real_exec(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void *, int, char **, char **),
    void *arg,
    char **errmsg)
{
    return __real_sqlite3_exec(db, sql, callback, arg, errmsg);
}

static int call_real_prepare_v2(
    sqlite3 *db,
    const char *sql,
    int n_byte,
    sqlite3_stmt **stmt,
    const char **tail)
{
    return __real_sqlite3_prepare_v2(db, sql, n_byte, stmt, tail);
}

static int call_real_get_autocommit(sqlite3 *db)
{
    return __real_sqlite3_get_autocommit(db);
}
#endif

static ninlil_test_persist_point_t armed_point =
    NINLIL_TEST_PERSIST_POINT_NONE;
static ninlil_test_persist_point_fn armed_fn;
static void *armed_user;
static int interpose_depth;

static int commit_inject_armed;
static int commit_inject_call_real;
static int commit_inject_rc;
static int rollback_inject_armed;
static int rollback_inject_call_real;
static int rollback_inject_rc;
static int force_autocommit_zero_once;

static int sql_is_begin_immediate(const char *sql)
{
    return sql != NULL && strncmp(sql, "BEGIN IMMEDIATE", 15) == 0;
}

static int sql_is_commit(const char *sql)
{
    return sql != NULL && strncmp(sql, "COMMIT", 6) == 0;
}

static int sql_is_rollback(const char *sql)
{
    return sql != NULL && strncmp(sql, "ROLLBACK", 8) == 0;
}

static int sql_is_namespace_delete(const char *sql)
{
    return sql != NULL
        && strncmp(sql, "DELETE FROM ninlil_kv WHERE namespace", 36) == 0;
}

static void fire_if_armed(ninlil_test_persist_point_t point)
{
    ninlil_test_persist_point_fn fn;
    void *user;

    if (armed_point != point || armed_fn == NULL) {
        return;
    }
    fn = armed_fn;
    user = armed_user;
    armed_point = NINLIL_TEST_PERSIST_POINT_NONE;
    armed_fn = NULL;
    armed_user = NULL;
    fn(point, user);
}

void ninlil_test_persist_interpose_set(
    ninlil_test_persist_point_t arm,
    ninlil_test_persist_point_fn fn,
    void *user)
{
    armed_point = arm;
    armed_fn = fn;
    armed_user = user;
}

void ninlil_test_persist_interpose_clear(void)
{
    armed_point = NINLIL_TEST_PERSIST_POINT_NONE;
    armed_fn = NULL;
    armed_user = NULL;
}

void ninlil_test_sqlite_inject_commit(int call_real, int forced_rc)
{
    commit_inject_armed = 1;
    commit_inject_call_real = call_real != 0 ? 1 : 0;
    commit_inject_rc = forced_rc;
}

void ninlil_test_sqlite_inject_rollback(int call_real, int forced_rc)
{
    rollback_inject_armed = 1;
    rollback_inject_call_real = call_real != 0 ? 1 : 0;
    rollback_inject_rc = forced_rc;
}

void ninlil_test_sqlite_force_autocommit_zero_once(void)
{
    force_autocommit_zero_once = 1;
}

void ninlil_test_sqlite_inject_clear(void)
{
    commit_inject_armed = 0;
    rollback_inject_armed = 0;
    force_autocommit_zero_once = 0;
}

static int interposed_exec(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void *, int, char **, char **),
    void *arg,
    char **errmsg)
{
    int rc;

    if (interpose_depth > 0) {
        return call_real_exec(db, sql, callback, arg, errmsg);
    }

    interpose_depth += 1;
    if (sql_is_begin_immediate(sql)) {
        fire_if_armed(NINLIL_TEST_PERSIST_POINT_BEFORE_BEGIN);
        rc = call_real_exec(db, sql, callback, arg, errmsg);
        if (rc == SQLITE_OK) {
            fire_if_armed(NINLIL_TEST_PERSIST_POINT_AFTER_BEGIN);
        }
        interpose_depth -= 1;
        return rc;
    }
    if (sql_is_commit(sql)) {
        fire_if_armed(NINLIL_TEST_PERSIST_POINT_BEFORE_COMMIT);
        if (commit_inject_armed != 0) {
            commit_inject_armed = 0;
            if (commit_inject_call_real != 0) {
                rc = call_real_exec(db, sql, callback, arg, errmsg);
            } else {
                rc = commit_inject_rc;
            }
        } else {
            rc = call_real_exec(db, sql, callback, arg, errmsg);
        }
        if (rc == SQLITE_OK) {
            fire_if_armed(NINLIL_TEST_PERSIST_POINT_AFTER_COMMIT);
        }
        interpose_depth -= 1;
        return rc;
    }
    if (sql_is_rollback(sql)) {
        if (rollback_inject_armed != 0) {
            rollback_inject_armed = 0;
            if (rollback_inject_call_real != 0) {
                rc = call_real_exec(db, sql, callback, arg, errmsg);
            } else {
                rc = rollback_inject_rc;
            }
            interpose_depth -= 1;
            return rc;
        }
        rc = call_real_exec(db, sql, callback, arg, errmsg);
        interpose_depth -= 1;
        return rc;
    }
    rc = call_real_exec(db, sql, callback, arg, errmsg);
    interpose_depth -= 1;
    return rc;
}

static int interposed_prepare_v2(
    sqlite3 *db,
    const char *sql,
    int n_byte,
    sqlite3_stmt **stmt,
    const char **tail)
{
    int rc;

    if (interpose_depth > 0) {
        return call_real_prepare_v2(db, sql, n_byte, stmt, tail);
    }

    interpose_depth += 1;
    if (sql_is_namespace_delete(sql)) {
        fire_if_armed(NINLIL_TEST_PERSIST_POINT_BEFORE_MUTATION);
    }
    rc = call_real_prepare_v2(db, sql, n_byte, stmt, tail);
    interpose_depth -= 1;
    return rc;
}

static int interposed_get_autocommit(sqlite3 *db)
{
    if (interpose_depth > 0) {
        return call_real_get_autocommit(db);
    }
    if (force_autocommit_zero_once != 0) {
        force_autocommit_zero_once = 0;
        return 0;
    }
    return call_real_get_autocommit(db);
}

#if defined(NINLIL_TEST_SQLITE_INTERPOSE_WRAP)

int __wrap_sqlite3_exec(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void *, int, char **, char **),
    void *arg,
    char **errmsg)
{
    return interposed_exec(db, sql, callback, arg, errmsg);
}

int __wrap_sqlite3_prepare_v2(
    sqlite3 *db,
    const char *sql,
    int n_byte,
    sqlite3_stmt **stmt,
    const char **tail)
{
    return interposed_prepare_v2(db, sql, n_byte, stmt, tail);
}

int __wrap_sqlite3_get_autocommit(sqlite3 *db)
{
    return interposed_get_autocommit(db);
}

#else /* DLSYM: strong definitions override the shared library imports */

int sqlite3_exec(
    sqlite3 *db,
    const char *sql,
    int (*callback)(void *, int, char **, char **),
    void *arg,
    char **errmsg)
{
    return interposed_exec(db, sql, callback, arg, errmsg);
}

int sqlite3_prepare_v2(
    sqlite3 *db,
    const char *sql,
    int n_byte,
    sqlite3_stmt **stmt,
    const char **tail)
{
    return interposed_prepare_v2(db, sql, n_byte, stmt, tail);
}

int sqlite3_get_autocommit(sqlite3 *db)
{
    return interposed_get_autocommit(db);
}

#endif
