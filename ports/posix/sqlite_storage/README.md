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

## Exclusive open lease (crash-safe)

docs/12 requires one active open lease per exact namespace, with dead-owner confirmation before reopen.

SQLite WAL/SHM files derive from the opened pathname. A direct main-file
`flock` conflicts with SQLite's own locks on macOS, so this port uses a
**DB-wide inode-keyed adjacent authority sidecar**, acquired before SQLite open:

| Property | Behavior |
| --- | --- |
| Identity | main file opened with `O_NOFOLLOW|O_CLOEXEC`; sidecar name derives from main `st_dev/st_ino` |
| Live exclusion | A second provider for the inode, including hardlink aliases, fails before SQLite open |
| Sidecar | `O_NOFOLLOW|O_CLOEXEC`, regular/link-count checks, **effective UID ownership + exact `0600`**, nonblocking `flock`, post-lock and every later authority-boundary path↔fd/owner/mode recheck |
| Symlink/rename | final DB symlink/hardlink is rejected; DB and sidecar path↔fd `dev`/`ino`/`nlink` and lock authority are rechecked after SQLite open and at every durable-persist revalidation point (see below) |
| Clean close | provider destroy unlocks/closes but does not unlink the sidecar; handle close retires only its logical namespace token |
| Process death | Kernel releases the flock; reopen succeeds without cooperative cleanup |
| Stale writer fence | RW `commit` re-checks handle generation + lease token before the SQLite durable write |
| Dead schema | Legacy `ninlil_lease` is unsupported and rejected without mutation |

PID-based lease rows and per-namespace lease files are intentionally rejected.

Opaque handle / transaction / iterator values are addresses in a 16 TiB
`PROT_NONE` virtual token arena reserved at provider create on 64-bit
Linux/macOS. They are never dereferenced or reissued during the provider
lifetime. Validation checks arena range and active slot identity, so fabricated
and stale values fail closed without per-operation heap growth. 32-bit hosts or
failed arena reservation are unsupported and create fails closed.

**No wrap:** 64-bit generation and lease-token sequences never restart at 1 after their max (`UINT64_MAX` fixed domain in production). A handle/txn/iterator slot that has issued its max generation is **permanently retired**; further allocation that needs a free slot fails with `NO_SPACE`. Lease-token exhaustion **fences the storage instance** (no further open) without migration/reinitialize reuse. The pure advance helpers live in a private (non-installed) module and are unit-tested with explicit max arguments; production storage does not expose runtime ceiling injection.

Without a custom SQLite VFS, external rename/unlink/chmod/chown of the live DB
or sidecar is an unsupported adversarial operation. The port **detects** path
replacement at public open and at the durable-persist revalidation points
below; it does **not** claim atomic prevention of uncooperative OS rename
between those points or after a successful return has already linearized. The
supported profile is a local POSIX volume whose operator does not mutate those
live paths.

Durable namespace persist revalidation points (docs/08):

1. acquire `BEGIN IMMEDIATE` (write lock first)
2. revalidate closed schema definition **inside that transaction**
3. revalidate path/fd/`nlink`/lock authority
4. DELETE/INSERT mutation
5. revalidate identity immediately before `COMMIT`
6. after `COMMIT` success and autocommit confirmation, revalidate identity
   again; only then may the provider return `OK`

Replacement observed at a **pre-COMMIT** revalidation yields rollback (when
autocommit confirms non-commit) + connection fence + `CORRUPT` (or
`COMMIT_UNKNOWN` when the outcome cannot be classified). Replacement that
occurs **after the last pre-COMMIT revalidation and before `COMMIT` returns**,
or **after `COMMIT` success**, is observed only at the post-COMMIT identity
check and yields `COMMIT_UNKNOWN` + connection fence — **never** `OK`. Windows
between revalidation points are not closed atomically; a successful `OK` is
only claimed when the post-COMMIT identity check still matches. Changes after
that return are outside the claim.

The authority sidecar is private control state. Existing sidecars are accepted
only when owned by the process's current effective UID with exact mode `0600`;
group/other read, write, or execute permission is rejected rather than repaired.
The database parent directory must therefore permit that UID to create/open this
private file. World/group-writable shared directories remain outside the threat
claim unless the operator also guarantees that untrusted users cannot rename,
unlink, chmod, chown, or replace the live DB and authority paths. A sticky bit
alone does not extend the guarantee.

All application access to the database must go through the provider while it
is live. Raw external SQLite access is unsupported; the busy-timeout test's
second connection is a lock-injection oracle only and does **not** authorize
raw concurrent writers as a FULL OK success path. A child process that needs
the provider must `exec`/spawn a fresh process image; using SQLite in the child
side of `fork()` before `exec` is unsupported by SQLite/platform libraries on
macOS.

## SQLite settings and durability claim

On open the port applies:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
```

**FULL commit success** means the atomic namespace mutation group crossed the
SQLite durability boundary under those pragmas **and** the post-commit identity
revalidation still matched the pinned path/fd/lock authority. The claim does
**not** cover a filesystem or device that acknowledges flush falsely, nor path
replacement after that linearization point.

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
Schema v1 has a closed `sqlite_master` object set: exactly the `ninlil_meta` and
`ninlil_kv` STRICT, WITHOUT ROWID tables, with no autoindexes required by that
layout. Triggers, views, explicit indexes, `sqlite_stat*`/`sqlite_sequence`
residue, legacy lease tables, extra tables, columns, or meta rows are rejected
without drop, repair, or migration. On every durable namespace persist the
provider takes `BEGIN IMMEDIATE` **first**, revalidates that closed shape in the
same transaction, then mutates. Schema corruption before mutation rolls back,
returns `CORRUPT`, and fences the connection so an injected trigger cannot
observe or rewrite DELETE/INSERT.

## Semantics closed by this port

- Open lease: one provider per database inode (DB-wide OS flock); one live handle per exact namespace within it
- Multiple `READ_ONLY` snapshots + at most one `READ_WRITE` per handle
- Read-your-writes on the RW transaction only
- Stable unsigned-byte lexicographic key order (SQLite BLOB / memcmp)
- `get` / `iter_next` `BUFFER_TOO_SMALL` does not mutate buffers or advance the iterator
- `capacity()` reports **committed** usage only
- `commit(FULL)` is atomic; non-FULL durability is `CORRUPT` and consumes the txn
- Handle / txn / iterator consume on close/commit/rollback (including implicit iterator close)
- Stale opaque tokens after close/consume/reuse are fail-closed

## Build

CMake option `NINLIL_BUILD_POSIX_SQLITE_STORAGE` (default ON). The target is built only when `find_package(SQLite3)` succeeds; missing SQLite does not break the portable core build.

`NINLIL_SQLITE_LINKAGE` is a **closed set**: exactly `AUTO`, `STATIC`, or `SHARED`
(any other value is configure **FATAL**). It controls which libsqlite3 is preferred
and how private system deps / test interpose backends are selected.

- **AUTO**: requires a classifiable path suffix (`.a`/`.lib` or `.so`/`.dylib`/`.tbd`/`.dll`). Unclassifiable/opaque paths are **FATAL** — AUTO never guesses shared.
- **STATIC**: prefers `.a`; may accept an operator-forced opaque existing regular file via `SQLite3_LIBRARY` only when that path is not a shared-library name.
- **SHARED**: requires a classifiable shared path.
- BOGUS values (`BOGUS`, typos) → configure **FATAL** immediately.

```bash
# Default / dynamic (macOS + Linux)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DNINLIL_SQLITE_LINKAGE=SHARED
cmake --build build --parallel
ctest --test-dir build -R posix_sqlite --output-on-failure

# Linux static archive (production + --wrap host tests)
cmake -S . -B build-static -DNINLIL_SQLITE_LINKAGE=STATIC
cmake --build build-static --parallel
ctest --test-dir build-static --output-on-failure
```

### Production vs test linkage matrix

| Platform | Production | Installed consumer | Host tests |
| --- | --- | --- | --- |
| Linux shared | supported | supported | dlsym interpose |
| Linux static | supported; export propagates Threads, `dl`, `m`, and ZLIB when required | supported via `NinlilConfig` `find_dependency` | GNU/Clang `-Wl,--wrap` interpose |
| macOS shared/dylib | supported | supported | dlsym interpose |
| macOS static | **unsupported** | **unsupported** | **unsupported** (`tests-on` configure fail-fast) |

Unsupported combinations fail at **configure** time rather than with multiple-definition link errors.

### Debug archive path hygiene (ship artifacts)

Installed `libninlil_posix_sqlite_storage.a` for **non-sanitizer production**
must not embed absolute source or build roots even for **Debug** builds (no
reliance on Release strip):

| Compiler | Path hygiene (non-sanitizer ship) |
| --- | --- |
| GNU GCC | feature-checked `-gdwarf-4` (PRIVATE) + prefix-map group + `-gno-record-gcc-switches` |
| Clang / AppleClang | prefix-map + `-gno-record-gcc-switches` + `-fdebug-compilation-dir=.` |

GNU GCC 13 default DWARF5 `.debug_line_str` can retain absolute compile cwd
under prefix-map alone; feature-checked DWARF4 closes that leak for **GNU
only**. Clang/AppleClang non-sanitizer builds rely on prefix-map +
`-fdebug-compilation-dir=.` (no unconditional `-gdwarf-4` for all compilers,
no relpath compile launcher).

**Sanitizer builds are not ship artifacts.** Builds with explicit
`NINLIL_ENABLE_SANITIZERS=ON`, or with a supported
`NINLIL_ENABLE_POINTER_COMPARE_SANITIZER=ON`, keep their sanitizer coverage
full. Installed consumer smoke still exercises package/install/
`find_package`/link/run. Only the
archive/object absolute-path hygiene scan is skipped, because ASan global
descriptors embed absolute `-c` paths that prefix-map cannot rewrite. Skip is
driven solely by those explicit, toolchain-validated CMake options (no compiler guessing, no inspection
deletion, no ASan-globals disable). Ship hygiene is guaranteed by separate
non-sanitizer gates: Ubuntu GCC (existing), Ubuntu Clang non-sanitizer
(`strings` / `ar x` / `readelf` inventory), and macOS AppleClang (`strings` /
`ar` within standard tools).

Installable SDK consumers use the exported CMake package and target:

```cmake
find_package(Ninlil CONFIG REQUIRED)
target_link_libraries(my_host_app PRIVATE
    Ninlil::ninlil_posix_sqlite_storage)
```

`cmake --install build --prefix <prefix>` installs the portable public headers,
the POSIX SQLite factory header/library when enabled, and `NinlilConfig.cmake`.
The installed package re-finds SQLite3 and, for Linux static builds, Threads
(and ZLIB when the selected archive needs it). Consumers do not include
source-tree paths; the install smoke gate rejects absolute source paths in the
exported package.

**Imported configuration mapping:** single-config `install(EXPORT)` ships only
one `NinlilTargets-<config>.cmake` (`DEBUG` / `RELEASE` / `NOCONFIG`), so
`IMPORTED_LOCATION` exists for that producer configuration alone.
`NinlilConfig.cmake` then (1) sets a config-agnostic `IMPORTED_LOCATION` and
`MAP_IMPORTED_CONFIG_<CFG>` on `Ninlil::ninlil_posix_sqlite_storage`, and
(2) additively copies FindSQLite3's config-less `IMPORTED_LOCATION` onto
standard imported configuration names when missing (no `INTERFACE_*` / link-line
rewrite; ALIAS targets untouched). Installed consumers configure/build with
empty `CMAKE_BUILD_TYPE`, `Debug`, `Release`, multi-config generators, and
strict identity `CMAKE_MAP_IMPORTED_CONFIG_*` maps. The install-consumer smoke
matrix covers match / no-build-type / Debug↔Release / strict-map after one
install.

## Explicit non-claims

- Public Runtime body / `runtime_create` integration
- M1a complete / field-ready / production SLO
- Domain Store D3/D4 recovery writer composition
- NFS / remote-filesystem flock semantics (local POSIX volumes only)
- KGuard vocabulary (absent by design)

### Supported host diagnostics

Callable on the same thread that owns the storage instance (no internal
locking). Not Core public ABI; port-owned.

| API | Lifetime / side effect |
| --- | --- |
| `live_handles` / `live_transactions` / `live_iterators` | Snapshot counts of live opaque tokens; 0 if storage is NULL |
| `connection_fenced` | 1 after unclassifiable durable outcome or identity failure; further durable use fail-closed |
| `lease_tokens_fenced` | 1 after lease-token domain exhaustion; further `open` fail-closed |
| `simulate_crash` | Drops live handles/leases without unlinking files or reversing commits; caller-held tokens go stale |

Host conformance covers same-process/spawned-process exclusion with explicit
flock-contention diagnosis, SIGKILL dead-owner reopen, hardlink/symlink/rename,
sidecar owner/mode drift, closed schema object/trigger fail-closed behavior,
deterministic interleaving and COMMIT/ROLLBACK result injection via a
**test-target-only** SQLite link-time interposition unit (not installed; not in
the production archive), pure generation/token advance unit tests, external
SQLite lock timing, strict schema negatives, namespace isolation, opaque ABA,
parallel unique-path examples, installed-consumer build, and a package-surface
negative gate (`nm` + public header) forbidding barrier/hook/interpose/
commit_fault/test_ceilings symbols and `test-only` wording on the install
surface.
