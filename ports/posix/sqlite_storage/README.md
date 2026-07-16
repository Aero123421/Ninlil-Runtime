# POSIX SQLite storage port

Host (Linux / macOS) production-candidate implementation of `ninlil_storage_ops_t`.

This port is **not** public Runtime complete, **not** M1a field-ready, and does **not** claim Stage 5 / domain recovery completion. ESP-IDF / NVS / USB / radio / Join / security are out of scope.

## Layout

| Path | Role |
| --- | --- |
| `ports/posix/include/ninlil_posix_sqlite_storage.h` | Port-owned factory (not under `include/ninlil/`) |
| `ports/posix/sqlite_storage/ninlil_posix_sqlite_storage.c` | SQLite provider |
| `ports/posix/examples/sqlite_storage_minimal.c` | Minimal host example |
| `tests/port/posix_sqlite_storage_test.c` | Host conformance tests |

## Factory configuration

Callers set finite pools and logical capacity:

- `database_path` — host filesystem path of **one** SQLite file (not a namespace)
- `busy_timeout_ms` — bounded SQLite busy timeout (default 1000 ms)
- `max_entries_per_namespace` / `max_bytes_per_namespace` — logical capacity (docs/14 units)
- `max_handles` / `max_transactions` / `max_iterators` — finite pools (1..32 for txn/iter)

Opaque storage namespace bytes (`1..255`) are stored as a BLOB column and are **never** interpreted as a path string.

## SQLite settings and durability claim

On open the port applies:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
```

**FULL commit success** means the atomic namespace mutation group crossed the SQLite durability boundary under those pragmas. The claim does **not** cover a filesystem or device that acknowledges flush falsely.

### Fault model (port status mapping)

| Condition | Status |
| --- | --- |
| Exclusive namespace lease or RW held | `BUSY` |
| Lock busy after timeout | `BUSY` |
| Logical capacity / single-value > 65536 / SQLITE_FULL | `NO_SPACE` |
| Integrity / contract shape | `CORRUPT` |
| Definite I/O before durable boundary | `IO_ERROR` |
| Commit outcome not classifiable | `COMMIT_UNKNOWN` |
| `schema_version != 1` | create fails / open path `UNSUPPORTED_SCHEMA` |

Migration of unknown future schema versions is **rejected** (no auto-upgrade).

## Semantics closed by this port

- Open lease: one live handle per exact namespace bytes per backend
- Multiple `READ_ONLY` snapshots + at most one `READ_WRITE` per handle
- Read-your-writes on the RW transaction only
- Stable unsigned-byte lexicographic key order (SQLite BLOB / memcmp)
- `get` / `iter_next` `BUFFER_TOO_SMALL` does not mutate buffers or advance the iterator
- `capacity()` reports **committed** usage only
- `commit(FULL)` is atomic; non-FULL durability is `CORRUPT` and consumes the txn
- Handle / txn / iterator consume on close/commit/rollback (including implicit iterator close)

## Build

CMake option `NINLIL_BUILD_POSIX_SQLITE_STORAGE` (default ON). The target is built only when `find_package(SQLite3)` succeeds; missing SQLite does not break the portable core build.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build -R posix_sqlite --output-on-failure
```

## Explicit non-claims

- Public Runtime body / `runtime_create` integration
- M1a complete / field-ready / production SLO
- Domain Store D3/D4 recovery writer composition
- Multi-process dead-owner fencing beyond process-local lease + SQLite locking
- KGuard vocabulary (absent by design)
