#!/usr/bin/env python3
"""Offline, read-only V1-LAB namespace export and artifact verification.

This tool implements the exact ``NLEXP001`` artifact in ADR-0022.  It is not
an importer and never converts LAB rows into Domain Store rows.

The POSIX SQLite source must be offline.  Export acquires the provider's
inode-keyed authority sidecar with a non-blocking exclusive flock before
opening SQLite in ``mode=ro``.  All source validation, row counting, and row
emission happen inside one READ_ONLY SQLite transaction.  The completed
artifact is installed without overwriting an existing path.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import struct
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO, Iterator, NoReturn


EXPORT_MAGIC = b"NLEXP001"
COMPLETION_MAGIC = b"NLEXDONE"
EXPORT_CONTENT_DOMAIN = b"NINLIL-LAB-EXPORT-V1"
EXPORT_ROW_DOMAIN = b"NINLIL-LAB-EXPORT-ROW-V1"
EXPORT_PROVIDER_DOMAIN = b"NINLIL-LAB-EXPORT-PROVIDER-V1"

FORMAT_VERSION = 1
SOURCE_PROFILE_V1_LAB = 1
FLAGS_NONE = 0

# Integration-fixed identity for ports/posix/sqlite_storage schema v1.
PROVIDER_KIND_POSIX_SQLITE = 1
PROVIDER_SCHEMA_POSIX_SQLITE_V1 = 1

MAX_NAMESPACE_BYTES = 255
MAX_KEY_BYTES = 255
MAX_VALUE_BYTES = 65536
MAX_PROVIDER_CONFIG_BYTES = 65535
COPY_CHUNK_BYTES = 65536


class ExportError(Exception):
    """Closed failure with a machine-readable category and reason."""

    def __init__(self, category: str, reason: str):
        super().__init__(f"{category}: {reason}")
        self.category = category
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class VerificationResult:
    namespace_hex: str
    record_count: int
    provider_kind: int
    provider_schema: int
    content_digest_hex: str
    artifact_sha256_hex: str


def _fail(category: str, reason: str) -> NoReturn:
    raise ExportError(category, reason)


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _provider_digest(kind: int, schema: int, config: bytes) -> bytes:
    if not 1 <= kind <= 0xFFFF:
        _fail("CORRUPT", "ZERO_OR_RANGE_PROVIDER_KIND")
    if not 1 <= schema <= 0xFFFF:
        _fail("CORRUPT", "ZERO_OR_RANGE_PROVIDER_SCHEMA")
    if len(config) > MAX_PROVIDER_CONFIG_BYTES:
        _fail("CORRUPT", "PROVIDER_CONFIG_LENGTH")
    return hashlib.sha256(
        EXPORT_PROVIDER_DOMAIN
        + _u16(kind)
        + _u16(schema)
        + _u16(len(config))
        + config
    ).digest()


def _validate_provider_fields(kind: int, schema: int) -> None:
    if kind == 0:
        _fail("CORRUPT", "ZERO_PROVIDER_KIND")
    if schema == 0:
        _fail("CORRUPT", "ZERO_PROVIDER_SCHEMA")
    if kind > 0xFFFF:
        _fail("CORRUPT", "RANGE_PROVIDER_KIND")
    if schema > 0xFFFF:
        _fail("CORRUPT", "RANGE_PROVIDER_SCHEMA")


def _validate_namespace(namespace: bytes) -> None:
    if not 1 <= len(namespace) <= MAX_NAMESPACE_BYTES:
        _fail("CORRUPT", "NAMESPACE_LENGTH")


def _lexicographic_after(previous: bytes | None, current: bytes) -> None:
    if previous is not None and current == previous:
        _fail("CORRUPT", "DUPLICATE_KEY")
    if previous is not None and current < previous:
        _fail("CORRUPT", "ROW_ORDER")


def _validate_row(key: object, value: object, previous: bytes | None) -> tuple[bytes, bytes]:
    if not isinstance(key, bytes) or not isinstance(value, bytes):
        _fail("CORRUPT", "NON_BLOB_ROW")
    if not 1 <= len(key) <= MAX_KEY_BYTES:
        _fail("CORRUPT", "KEY_LENGTH")
    if not 1 <= len(value) <= MAX_VALUE_BYTES:
        _fail("CORRUPT", "VALUE_LENGTH")
    _lexicographic_after(previous, key)
    return key, value


def _sqlite_uri(path: Path) -> str:
    # Path.as_uri() performs correct percent escaping. SQLite URI uses file:.
    return f"{path.resolve().as_uri()}?mode=ro"


def _schema_objects_are_exact(connection: sqlite3.Connection) -> bool:
    rows = connection.execute(
        "SELECT type, name, tbl_name FROM sqlite_master "
        "ORDER BY type, name, tbl_name"
    ).fetchall()
    return rows == [
        ("table", "ninlil_kv", "ninlil_kv"),
        ("table", "ninlil_meta", "ninlil_meta"),
    ]


def _table_shape(
    connection: sqlite3.Connection, table: str
) -> tuple[list[tuple[object, ...]], tuple[int, int] | None]:
    columns = connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
    table_list = connection.execute("PRAGMA table_list").fetchall()
    flags: tuple[int, int] | None = None
    for row in table_list:
        # schema, name, type, ncol, wr, strict
        if len(row) >= 6 and row[1] == table:
            flags = (int(row[4]), int(row[5]))
    return columns, flags


def _validate_sqlite_schema(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA query_only").fetchone() != (1,):
        _fail("CORRUPT", "QUERY_ONLY_NOT_ACTIVE")
    quick = connection.execute("PRAGMA quick_check").fetchall()
    if quick != [("ok",)]:
        _fail("CORRUPT", "SQLITE_QUICK_CHECK")
    if not _schema_objects_are_exact(connection):
        _fail("UNSUPPORTED", "SQLITE_OBJECT_SET")

    meta_columns, meta_flags = _table_shape(connection, "ninlil_meta")
    kv_columns, kv_flags = _table_shape(connection, "ninlil_kv")
    # cid, name, type, notnull, default, pk, hidden
    meta_projection = [
        (row[1], row[2], row[3], row[4], row[5], row[6])
        for row in meta_columns
    ]
    kv_projection = [
        (row[1], row[2], row[3], row[4], row[5], row[6])
        for row in kv_columns
    ]
    if meta_projection != [
        ("key", "TEXT", 1, None, 1, 0),
        ("value", "INTEGER", 1, None, 0, 0),
    ] or meta_flags != (1, 1):
        _fail("UNSUPPORTED", "SQLITE_META_SHAPE")
    if kv_projection != [
        ("namespace", "BLOB", 1, None, 1, 0),
        ("key", "BLOB", 1, None, 2, 0),
        ("value", "BLOB", 1, None, 0, 0),
    ] or kv_flags != (1, 1):
        _fail("UNSUPPORTED", "SQLITE_KV_SHAPE")

    meta = connection.execute(
        "SELECT key, value, typeof(value) FROM ninlil_meta ORDER BY key"
    ).fetchall()
    if meta != [
        ("migration_state", 0, "integer"),
        ("schema_version", 1, "integer"),
    ]:
        _fail("UNSUPPORTED", "SQLITE_META_ROWS")

    invalid = connection.execute(
        "SELECT 1 FROM ninlil_kv WHERE "
        "typeof(namespace) != 'blob' OR typeof(key) != 'blob' "
        "OR typeof(value) != 'blob' "
        "OR length(namespace) NOT BETWEEN 1 AND 255 "
        "OR length(key) NOT BETWEEN 1 AND 255 "
        "OR length(value) NOT BETWEEN 1 AND 65536 LIMIT 1"
    ).fetchone()
    if invalid is not None:
        _fail("CORRUPT", "SQLITE_ROW_SHAPE")


def _authority_sidecar_path(database_path: Path, db_stat: os.stat_result) -> Path:
    canonical = database_path.resolve(strict=True)
    return canonical.parent / (
        f".ninlil-sqlite-{db_stat.st_dev:x}-{db_stat.st_ino:x}.lock"
    )


@contextlib.contextmanager
def _offline_database_authority(database_path: Path) -> Iterator[Path]:
    """Acquire the same DB-wide sidecar authority as the POSIX provider."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    try:
        db_fd = os.open(database_path, os.O_RDONLY | nofollow | cloexec)
    except OSError as exc:
        _fail("IO", f"DATABASE_OPEN:{exc.errno}")
    lock_fd = -1
    try:
        db_stat = os.fstat(db_fd)
        path_stat = os.lstat(database_path)
        if (
            not stat.S_ISREG(db_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or db_stat.st_dev != path_stat.st_dev
            or db_stat.st_ino != path_stat.st_ino
            or db_stat.st_nlink != 1
            or path_stat.st_nlink != 1
        ):
            _fail("CORRUPT", "DATABASE_IDENTITY")
        lock_path = _authority_sidecar_path(database_path, db_stat)
        try:
            lock_fd = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | nofollow | cloexec,
                0o600,
            )
        except OSError as exc:
            _fail("IO", f"AUTHORITY_OPEN:{exc.errno}")
        lock_stat = os.fstat(lock_fd)
        lock_path_stat = os.lstat(lock_path)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or not stat.S_ISREG(lock_path_stat.st_mode)
            or lock_stat.st_nlink != 1
            or lock_path_stat.st_nlink != 1
            or lock_stat.st_uid != os.geteuid()
            or lock_path_stat.st_uid != os.geteuid()
            or stat.S_IMODE(lock_stat.st_mode) != 0o600
            or stat.S_IMODE(lock_path_stat.st_mode) != 0o600
            or lock_stat.st_dev != lock_path_stat.st_dev
            or lock_stat.st_ino != lock_path_stat.st_ino
        ):
            _fail("CORRUPT", "AUTHORITY_IDENTITY")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail("BUSY", "SOURCE_PROVIDER_ACTIVE")
        after_db = os.fstat(db_fd)
        after_path = os.lstat(database_path)
        if (
            after_db.st_dev != db_stat.st_dev
            or after_db.st_ino != db_stat.st_ino
            or after_path.st_dev != db_stat.st_dev
            or after_path.st_ino != db_stat.st_ino
        ):
            _fail("CORRUPT", "DATABASE_IDENTITY_DRIFT")
        yield lock_path
    finally:
        if lock_fd >= 0:
            with contextlib.suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        os.close(db_fd)


@contextlib.contextmanager
def _read_only_snapshot(database_path: Path) -> Iterator[sqlite3.Connection]:
    try:
        connection = sqlite3.connect(
            _sqlite_uri(database_path),
            uri=True,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        _fail("IO", f"SQLITE_OPEN:{exc.sqlite_errorname}")
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        _validate_sqlite_schema(connection)
        yield connection
        connection.execute("ROLLBACK")
    except ExportError:
        with contextlib.suppress(sqlite3.Error):
            connection.execute("ROLLBACK")
        raise
    except sqlite3.Error as exc:
        with contextlib.suppress(sqlite3.Error):
            connection.execute("ROLLBACK")
        _fail("IO", f"SQLITE_READ:{exc.sqlite_errorname}")
    finally:
        connection.close()


def _iter_namespace_rows(
    connection: sqlite3.Connection, namespace: bytes
) -> Iterator[tuple[bytes, bytes]]:
    previous: bytes | None = None
    cursor = connection.execute(
        "SELECT key, value FROM ninlil_kv "
        "WHERE namespace = ? ORDER BY key ASC",
        (sqlite3.Binary(namespace),),
    )
    try:
        for raw_key, raw_value in cursor:
            key, value = _validate_row(raw_key, raw_value, previous)
            previous = key
            yield key, value
    finally:
        cursor.close()


def _count_rows(connection: sqlite3.Connection, namespace: bytes) -> int:
    count = 0
    for _key, _value in _iter_namespace_rows(connection, namespace):
        if count == 0xFFFFFFFF:
            _fail("CORRUPT", "RECORD_COUNT_OVERFLOW")
        count += 1
    return count


class _ArtifactWriter:
    def __init__(self, output: BinaryIO):
        self.output = output
        self.content = hashlib.sha256(EXPORT_CONTENT_DOMAIN)

    def write_content(self, value: bytes) -> None:
        self.output.write(value)
        self.content.update(value)

    def finish(self) -> tuple[bytes, bytes]:
        content_digest = self.content.digest()
        self.output.write(content_digest)
        self.output.write(COMPLETION_MAGIC)
        return content_digest, COMPLETION_MAGIC


def _artifact_temp_path(output_path: Path) -> tuple[int, Path]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".incomplete",
        dir=output_path.parent,
    )
    os.fchmod(fd, 0o600)
    return fd, Path(raw_path)


def _install_without_overwrite(temp_path: Path, output_path: Path) -> None:
    try:
        os.link(temp_path, output_path)
    except FileExistsError:
        _fail("IO", "OUTPUT_EXISTS")
    except OSError as exc:
        _fail("IO", f"OUTPUT_INSTALL:{exc.errno}")
    os.unlink(temp_path)
    dir_fd = os.open(
        output_path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def export_sqlite_namespace(
    database_path: Path,
    namespace: bytes,
    provider_config: bytes,
    output_path: Path,
) -> VerificationResult:
    """Export one namespace without mutating source or overwriting output."""

    _validate_namespace(namespace)
    _validate_provider_fields(
        PROVIDER_KIND_POSIX_SQLITE, PROVIDER_SCHEMA_POSIX_SQLITE_V1
    )
    provider_identity = _provider_digest(
        PROVIDER_KIND_POSIX_SQLITE,
        PROVIDER_SCHEMA_POSIX_SQLITE_V1,
        provider_config,
    )
    fd = -1
    temp_path: Path | None = None
    content_digest = b""
    record_count = 0
    try:
        with _offline_database_authority(database_path):
            with _read_only_snapshot(database_path) as connection:
                record_count = _count_rows(connection, namespace)
                fd, temp_path = _artifact_temp_path(output_path)
                with os.fdopen(fd, "wb", closefd=True) as stream:
                    fd = -1
                    writer = _ArtifactWriter(stream)
                    header = struct.pack(
                        ">8sHHIHH32sH",
                        EXPORT_MAGIC,
                        FORMAT_VERSION,
                        SOURCE_PROFILE_V1_LAB,
                        FLAGS_NONE,
                        PROVIDER_KIND_POSIX_SQLITE,
                        PROVIDER_SCHEMA_POSIX_SQLITE_V1,
                        provider_identity,
                        len(namespace),
                    )
                    writer.write_content(header)
                    writer.write_content(namespace)
                    writer.write_content(_u32(record_count))
                    emitted = 0
                    for key, value in _iter_namespace_rows(connection, namespace):
                        row_header = (
                            _u16(len(key))
                            + _u16(0)
                            + _u32(len(value))
                        )
                        row_digest = hashlib.sha256(
                            EXPORT_ROW_DOMAIN
                            + _u16(len(key))
                            + key
                            + _u32(len(value))
                            + value
                        ).digest()
                        writer.write_content(row_header)
                        writer.write_content(key)
                        writer.write_content(value)
                        writer.write_content(row_digest)
                        emitted += 1
                    if emitted != record_count:
                        _fail("CORRUPT", "SNAPSHOT_ROW_COUNT_DRIFT")
                    content_digest, _ = writer.finish()
                    stream.flush()
                    os.fsync(stream.fileno())
                _install_without_overwrite(temp_path, output_path)
                temp_path = None
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_path is not None:
            with contextlib.suppress(OSError):
                temp_path.unlink()
    verified = verify_artifact(
        output_path,
        PROVIDER_KIND_POSIX_SQLITE,
        PROVIDER_SCHEMA_POSIX_SQLITE_V1,
        provider_config,
    )
    if (
        verified.record_count != record_count
        or verified.namespace_hex != namespace.hex()
        or verified.content_digest_hex != content_digest.hex()
    ):
        _fail("CORRUPT", "POST_INSTALL_VERIFY")
    return verified


class _DigestingReader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.artifact = hashlib.sha256()
        self.content = hashlib.sha256(EXPORT_CONTENT_DOMAIN)

    def read_exact(self, length: int, *, content: bool = True) -> bytes:
        value = self.stream.read(length)
        if len(value) != length:
            _fail("CORRUPT", "TRUNCATED")
        self.artifact.update(value)
        if content:
            self.content.update(value)
        return value

    def read_to_row_hash(
        self,
        length: int,
        row_hash: "hashlib._Hash",
    ) -> None:
        remaining = length
        while remaining:
            chunk = self.read_exact(min(remaining, COPY_CHUNK_BYTES))
            row_hash.update(chunk)
            remaining -= len(chunk)


def verify_artifact(
    artifact_path: Path,
    known_provider_kind: int,
    known_provider_schema: int,
    known_provider_config: bytes,
) -> VerificationResult:
    """Streaming fail-closed verifier for the exact export artifact."""

    _validate_provider_fields(known_provider_kind, known_provider_schema)
    expected_provider_digest = _provider_digest(
        known_provider_kind,
        known_provider_schema,
        known_provider_config,
    )
    try:
        stream = artifact_path.open("rb")
    except OSError as exc:
        _fail("IO", f"ARTIFACT_OPEN:{exc.errno}")
    with stream:
        reader = _DigestingReader(stream)
        header = reader.read_exact(54)
        (
            magic,
            format_version,
            source_profile,
            flags,
            provider_kind,
            provider_schema,
            provider_digest,
            namespace_length,
        ) = struct.unpack(">8sHHIHH32sH", header)
        if magic != EXPORT_MAGIC:
            _fail("CORRUPT", "MAGIC")
        if format_version != FORMAT_VERSION:
            _fail("UNSUPPORTED", "FORMAT_VERSION")
        if source_profile != SOURCE_PROFILE_V1_LAB:
            _fail("UNSUPPORTED", "SOURCE_PROFILE")
        if flags != FLAGS_NONE:
            _fail("UNSUPPORTED", "FLAGS")
        _validate_provider_fields(provider_kind, provider_schema)
        if provider_kind != known_provider_kind:
            _fail("UNSUPPORTED", "UNKNOWN_PROVIDER_KIND")
        if provider_schema != known_provider_schema:
            _fail("UNSUPPORTED", "UNKNOWN_PROVIDER_SCHEMA")
        if provider_digest == bytes(32):
            _fail("CORRUPT", "ZERO_PROVIDER_IDENTITY_DIGEST")
        if provider_digest != expected_provider_digest:
            _fail("CORRUPT", "PROVIDER_IDENTITY_DIGEST")
        if not 1 <= namespace_length <= MAX_NAMESPACE_BYTES:
            _fail("CORRUPT", "NAMESPACE_LENGTH")
        namespace = reader.read_exact(namespace_length)
        record_count = struct.unpack(">I", reader.read_exact(4))[0]
        previous: bytes | None = None
        for _ in range(record_count):
            row_header = reader.read_exact(8)
            key_length, reserved, value_length = struct.unpack(
                ">HHI", row_header
            )
            if not 1 <= key_length <= MAX_KEY_BYTES:
                _fail("CORRUPT", "KEY_LENGTH")
            if reserved != 0:
                _fail("CORRUPT", "ROW_RESERVED")
            if not 1 <= value_length <= MAX_VALUE_BYTES:
                _fail("CORRUPT", "VALUE_LENGTH")
            key = reader.read_exact(key_length)
            _lexicographic_after(previous, key)
            previous = key
            row_hash = hashlib.sha256(
                EXPORT_ROW_DOMAIN
                + _u16(key_length)
                + key
                + _u32(value_length)
            )
            reader.read_to_row_hash(value_length, row_hash)
            actual_row_digest = reader.read_exact(32)
            if actual_row_digest != row_hash.digest():
                _fail("CORRUPT", "ROW_DIGEST")
        actual_content_digest = reader.read_exact(32, content=False)
        if actual_content_digest != reader.content.digest():
            _fail("CORRUPT", "CONTENT_DIGEST")
        completion = reader.read_exact(8, content=False)
        if completion != COMPLETION_MAGIC:
            _fail("CORRUPT", "COMPLETION_MAGIC")
        if stream.read(1) != b"":
            _fail("CORRUPT", "TRAILING_BYTES")
        # The EOF probe is empty and therefore does not affect the hash.
        return VerificationResult(
            namespace_hex=namespace.hex(),
            record_count=record_count,
            provider_kind=provider_kind,
            provider_schema=provider_schema,
            content_digest_hex=actual_content_digest.hex(),
            artifact_sha256_hex=reader.artifact.hexdigest(),
        )


def _create_self_test_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            "CREATE TABLE ninlil_meta ("
            " key TEXT PRIMARY KEY NOT NULL,"
            " value INTEGER NOT NULL"
            ") STRICT, WITHOUT ROWID;"
            "CREATE TABLE ninlil_kv ("
            " namespace BLOB NOT NULL CHECK(typeof(namespace) = 'blob'),"
            " key BLOB NOT NULL CHECK(typeof(key) = 'blob'),"
            " value BLOB NOT NULL CHECK(typeof(value) = 'blob'),"
            " PRIMARY KEY (namespace, key)"
            ") STRICT, WITHOUT ROWID;"
            "INSERT INTO ninlil_meta VALUES('schema_version', 1);"
            "INSERT INTO ninlil_meta VALUES('migration_state', 0);"
        )
        connection.executemany(
            "INSERT INTO ninlil_kv(namespace, key, value) VALUES(?, ?, ?)",
            [
                (b"lab", b"a", b"one"),
                (b"lab", b"b", b"two"),
                (b"other", b"x", b"excluded"),
            ],
        )
        connection.commit()
    finally:
        connection.close()


def _run_self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="ninlil-lab-export-test-") as raw:
        root = Path(raw)
        database = root / "store.sqlite3"
        artifact = root / "lab.nlexp"
        _create_self_test_database(database)
        before = database.read_bytes()
        result = export_sqlite_namespace(database, b"lab", b"test", artifact)
        assert result.record_count == 2
        assert result.namespace_hex == b"lab".hex()
        assert database.read_bytes() == before
        assert not list(root.glob("*.incomplete"))

        verified = verify_artifact(
            artifact,
            PROVIDER_KIND_POSIX_SQLITE,
            PROVIDER_SCHEMA_POSIX_SQLITE_V1,
            b"test",
        )
        assert verified == result

        try:
            export_sqlite_namespace(database, b"lab", b"test", artifact)
        except ExportError as exc:
            assert exc.reason == "OUTPUT_EXISTS"
        else:
            raise AssertionError("existing artifact was overwritten")

        tampered = root / "tampered.nlexp"
        damaged = bytearray(artifact.read_bytes())
        damaged[-9] ^= 0x01
        tampered.write_bytes(damaged)
        try:
            verify_artifact(
                tampered,
                PROVIDER_KIND_POSIX_SQLITE,
                PROVIDER_SCHEMA_POSIX_SQLITE_V1,
                b"test",
            )
        except ExportError as exc:
            assert exc.reason == "CONTENT_DIGEST"
        else:
            raise AssertionError("tampered artifact was accepted")

        db_stat = database.stat()
        lock_path = _authority_sidecar_path(database, db_stat)
        lock_fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                export_sqlite_namespace(
                    database, b"lab", b"test", root / "busy.nlexp"
                )
            except ExportError as exc:
                assert exc.category == "BUSY"
            else:
                raise AssertionError("active provider authority was ignored")
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    vector_path = (
        Path(__file__).resolve().parents[1]
        / "spec/vectors/domain-store-schema1-runtime-binding-v1.json"
    )
    authority = json.loads(vector_path.read_text(encoding="utf-8"))
    vectors = authority["export_artifact_v1"]["exact_vectors"]["vectors"]
    with tempfile.TemporaryDirectory(
        prefix="ninlil-lab-export-vectors-"
    ) as raw_vectors:
        vector_root = Path(raw_vectors)
        for index, vector in enumerate(vectors):
            path = vector_root / f"{index:02d}.nlexp"
            path.write_bytes(bytes.fromhex(vector["artifact_hex"]))
            known = vector["known_provider"]
            try:
                checked = verify_artifact(
                    path,
                    int(known["kind"]),
                    int(known["schema"]),
                    bytes.fromhex(known["config_hex"]),
                )
                status = "NINLIL_OK"
            except ExportError as exc:
                checked = None
                status = (
                    "NINLIL_E_UNSUPPORTED"
                    if exc.category == "UNSUPPORTED"
                    else "NINLIL_E_STORAGE_CORRUPT"
                )
            if status != vector["expected_status"]:
                raise AssertionError(
                    f"{vector['id']}: {status} != {vector['expected_status']}"
                )
            if checked is not None:
                if checked.artifact_sha256_hex != vector["artifact_sha256"]:
                    raise AssertionError(
                        f"{vector['id']}: artifact digest mismatch"
                    )
                if checked.content_digest_hex != vector["computed"][
                    "content_digest"
                ]:
                    raise AssertionError(
                        f"{vector['id']}: content digest mismatch"
                    )

    print(
        "ninlil_lab_export self-test OK "
        f"read-only/snapshot/digest/busy/no-overwrite/vectors={len(vectors)}"
    )


def _hex_bytes(value: str, label: str) -> bytes:
    try:
        result = bytes.fromhex(value)
    except ValueError:
        _fail("CORRUPT", f"{label}_HEX")
    return result


def _result_json(result: VerificationResult) -> str:
    return json.dumps(
        dataclasses.asdict(result),
        sort_keys=True,
        separators=(",", ":"),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export", help="export an offline SQLite namespace")
    export.add_argument("--database", type=Path, required=True)
    export.add_argument("--namespace-hex", required=True)
    export.add_argument("--provider-config-hex", default="")
    export.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify", help="verify a completed artifact")
    verify.add_argument("--artifact", type=Path, required=True)
    verify.add_argument(
        "--provider-kind", type=int, default=PROVIDER_KIND_POSIX_SQLITE
    )
    verify.add_argument(
        "--provider-schema", type=int, default=PROVIDER_SCHEMA_POSIX_SQLITE_V1
    )
    verify.add_argument("--provider-config-hex", default="")
    sub.add_parser("--self-test", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Preserve the convenient historical spelling used by CTest.
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv == ["--self-test"]:
        _run_self_test()
        return 0
    args = _parser().parse_args(raw_argv)
    try:
        if args.command == "export":
            result = export_sqlite_namespace(
                args.database,
                _hex_bytes(args.namespace_hex, "NAMESPACE"),
                _hex_bytes(args.provider_config_hex, "PROVIDER_CONFIG"),
                args.output,
            )
        elif args.command == "verify":
            result = verify_artifact(
                args.artifact,
                args.provider_kind,
                args.provider_schema,
                _hex_bytes(args.provider_config_hex, "PROVIDER_CONFIG"),
            )
        else:
            _fail("CORRUPT", "COMMAND")
        print(_result_json(result))
        return 0
    except ExportError as exc:
        print(
            json.dumps(
                {"status": exc.category, "reason": exc.reason},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
