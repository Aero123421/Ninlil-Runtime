#!/usr/bin/env python3
"""Fail closed if ESP storage FULL/media/workspace bypasses become public.

Archive inspection requires explicit --archive-kind host|target (no default):
  host   : CTest dual-slot host library may export host-only test seams
           (host_media_* family, private_simulate_*). Public construction
           bypass names and public-looking simulate_* aliases are always
           forbidden. Consumer public headers never expose seams.
  target : official ESP archive; host-only seams are strictly forbidden
           (exact private_simulate_* + any ninlil_port_esp_storage_host_media_
           prefix) in addition to always-forbidden public bypass names.

nm parsing distinguishes defined/exported (T/D/u/...) from undefined (U/w/v).
Required flash_bind/unbind pass only when defined; forbidden symbols fail
only when defined/exported. Native macOS host names normalize exactly one
Mach-O leading underscore; ESP/Linux target ELF names are never normalized.

Target visibility (docs/21): official ELF/archive is inspected with
xtensa readelf actual output — not source-string claims alone.

  GLOBAL HIDDEN  : private_set_hil_observer, flash_set_hil_observer
  GLOBAL DEFAULT : flash_bind, flash_unbind

This gate is independent of tools/esp_idf_private_symbol_gate.py (owner/cell
on main). After rebase the two may be composed; they must not share state.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
PUBLIC_HEADERS = (
    REPO / "ports/esp-idf/storage/include/ninlil_port/esp_storage.h",
    REPO / "ports/esp-idf/storage/include/ninlil_port/esp_storage_flash.h",
)
MODEL_SOURCE = REPO / "ports/esp-idf/storage/model/esp_storage_model.c"
PRIVATE_HEADER = REPO / "ports/esp-idf/storage/private/esp_storage_private.h"
FORBIDDEN_HEADER_TOKENS = (
    "FULL_HOST_MODEL",
    "FULL_ESP_UNPROVEN",
    "FULL_ESP_HIL_ATTESTED",
    "storage_private_init",
    "storage_private_media_ops",
    "storage_workspace",
    "host_media",
    # HIL observer vocabulary must stay out of consumer-visible headers.
    "hil_event",
    "hil_observer",
    "HIL_DIRECTORY",
    "HIL_DATA_",
    "set_hil_observer",
    "HIL_BEFORE",
    "HIL_AFTER",
)

# Always forbidden in any archive (host CTest or official ESP target).
# These are public-looking construction / HIL / media-table / simulate-alias
# bypass names that must never export. Distinct from intentional host-only
# private_* test seams (those are target-only forbidden below).
ALWAYS_FORBIDDEN_ARCHIVE_SYMBOLS = (
    # Generic public construction must not exist; only private_* + flash_bind.
    "ninlil_port_esp_storage_init",
    "ninlil_port_esp_storage_deinit",
    "ninlil_port_esp_storage_ops",
    # Public-name HIL setter (must not exist; private/flash forms are HIDDEN).
    "ninlil_port_esp_storage_set_hil_observer",
    # Flash media ops table is static internal; must not be a public export.
    "ninlil_port_esp_storage_flash_media_ops",
    # Public-looking simulate aliases: ALWAYS forbidden on host and target.
    # Host may export only private_simulate_* (see TARGET_ONLY below).
    "ninlil_port_esp_storage_simulate_full_reinit",
    "ninlil_port_esp_storage_simulate_crash",
)

# Target-only forbidden exact symbols: intentional host private test seams.
# Host CTest archive (libninlil_port_esp_storage.a without ESP_PLATFORM) may
# export these for dual-slot conformance / reinit simulation. Official ESP
# target archive must not ship them (docs/21: host media / reinit are host-only).
# Definitions are compile-excluded under ESP_PLATFORM; this list is the
# archive-level backstop if a future edit reintroduces them on target.
TARGET_ONLY_FORBIDDEN_ARCHIVE_SYMBOLS = (
    "ninlil_port_esp_storage_private_simulate_full_reinit",
    "ninlil_port_esp_storage_private_simulate_crash",
    # Also reject the unsuffixed stem; the prefix rule below covers helpers.
    "ninlil_port_esp_storage_host_media",
)

# Complete host-media seam family on target: any defined export with this
# prefix is forbidden (ops, fault_write, init, counters, ...). Prefer prefix
# so new host_media_* helpers cannot silently ship on ESP.
TARGET_ONLY_FORBIDDEN_SYMBOL_PREFIXES = (
    "ninlil_port_esp_storage_host_media_",
)

# Intentional host dual-slot seams used by conformance tests. Host archive
# checks accept these; target rejects them via exact list + host_media_ prefix.
HOST_ONLY_ALLOWED_SEAM_SYMBOLS = (
    "ninlil_port_esp_storage_private_simulate_full_reinit",
    "ninlil_port_esp_storage_private_simulate_crash",
    "ninlil_port_esp_storage_host_media_ops",
    "ninlil_port_esp_storage_host_media_fault_write",
    "ninlil_port_esp_storage_host_media_init",
    "ninlil_port_esp_storage_host_media_deinit",
)

REQUIRED_ARCHIVE_SYMBOLS = (
    "ninlil_port_esp_storage_flash_bind",
    "ninlil_port_esp_storage_flash_unbind",
)

ARCHIVE_KINDS = ("host", "target")
# Single-letter nm type column (GNU nm / llvm-nm / Apple nm).
_NM_TYPE_RE = re.compile(r"^[A-Za-z]$")
# Defense-in-depth for host-only runs without ELF. Target CI must still pass
# readelf on official artifacts; source markers alone are not target green.
HIDDEN_HIL_SOURCE_MARKERS = (
    (
        REPO / "ports/esp-idf/storage/model/esp_storage_model.c",
        "ninlil_port_esp_storage_private_set_hil_observer",
    ),
    (
        REPO / "ports/esp-idf/storage/esp/esp_storage_flash_media.c",
        "ninlil_port_esp_storage_flash_set_hil_observer",
    ),
)

# Official binary contract (readelf -Ws).
HIDDEN_HIL_SYMBOLS = (
    "ninlil_port_esp_storage_private_set_hil_observer",
    "ninlil_port_esp_storage_flash_set_hil_observer",
)
DEFAULT_PUBLIC_SYMBOLS = (
    "ninlil_port_esp_storage_flash_bind",
    "ninlil_port_esp_storage_flash_unbind",
)

# readelf -Ws line sample (GNU binutils / xtensa-*-readelf):
#   123: 4200a3fc   64 FUNC    GLOBAL DEFAULT   12 ninlil_port_esp_storage_flash_bind
#   124: 4200ab84   48 FUNC    GLOBAL HIDDEN    12 ninlil_port_esp_storage_flash_set_hil_observer
SYM_LINE_RE = re.compile(
    r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+\w+\s+(\w+)\s+(\w+)\s+\S+\s+(\S+)\s*$"
)


def fail(msg: str) -> None:
    print(f"esp_storage_public_api_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def normalize_nm_symbol(name: str, *, strip_macho_prefix: bool) -> str:
    """Normalize nm symbol names across Linux ELF and macOS Mach-O.

    macOS / Apple llvm-nm prefixes C symbols with a single leading underscore;
    Linux/ESP ELF nm does not. When `strip_macho_prefix` is true, strip exactly
    one leading '_' so native macOS host archives compare correctly. Never use
    this normalization for ESP target archives, and never strip twice.
    """
    if strip_macho_prefix and name.startswith("_"):
        return name[1:]
    return name


def parse_nm_global_symbols(
    stdout: str,
    *,
    strip_macho_prefix: bool = False,
) -> tuple[set[str], set[str]]:
    """Parse `nm -g` archive output into (defined, undefined) C names.

    Distinguishes defined/exported symbols (T/D/B/R/u/...) from undefined
    references (U/w/v). A name that appears as U in one member and T in another
    is treated as defined. Required flash_bind/unbind pass only when defined;
    forbidden symbols fail only when defined/exported, not merely referenced.

    Handles GNU binutils nm, llvm-nm, and Apple llvm-nm archive layouts:
      esp_storage_host_media.c.o:
      0000000000000114 T _ninlil_port_esp_storage_host_media_ops
                       U _ninlil_port_esp_storage_media_total_bytes
    """
    defined: set[str] = set()
    undefined: set[str] = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Archive member banners: "esp_storage_host_media.c.o:" or
        # "lib.a(member.o):" — single token ending in colon, no spaces.
        if stripped.endswith(":") and not any(ch.isspace() for ch in stripped):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        # Standard rows: "ADDR TYPE NAME" or "TYPE NAME" (U undefined).
        type_token: str | None = None
        if len(parts) >= 3 and _NM_TYPE_RE.match(parts[-2]):
            type_token = parts[-2]
        elif len(parts) == 2 and _NM_TYPE_RE.match(parts[0]):
            type_token = parts[0]
        else:
            continue
        name = parts[-1]
        if name.endswith(":"):
            continue
        norm = normalize_nm_symbol(
            name,
            strip_macho_prefix=strip_macho_prefix,
        )
        if not norm:
            continue
        # GNU/LLVM nm: U is undefined; lowercase w/v are undefined weak
        # function/object references. Lowercase u is a defined GNU-unique
        # symbol and therefore deliberately falls through to `defined`.
        if type_token in ("U", "w", "v"):
            if norm not in defined:
                undefined.add(norm)
            continue
        # Any other nm type letter is a definition for -g purposes.
        defined.add(norm)
        undefined.discard(norm)
    return defined, undefined


def check_archive_symbols(defined: set[str], kind: str) -> list[str]:
    """Return violations for *defined* nm symbols only (testable).

    Undefined (U) references never satisfy required symbols and never count
    as forbidden exports — only actual definitions/exports do.
    """
    if kind not in ARCHIVE_KINDS:
        fail(f"unknown archive kind {kind!r} (expected host|target)")
    violations: list[str] = []
    for symbol in ALWAYS_FORBIDDEN_ARCHIVE_SYMBOLS:
        if symbol in defined:
            violations.append(f"always-forbidden symbol exported: {symbol}")
    if kind == "target":
        for symbol in TARGET_ONLY_FORBIDDEN_ARCHIVE_SYMBOLS:
            if symbol in defined:
                violations.append(
                    f"target-only-forbidden host seam exported: {symbol}"
                )
        for symbol in sorted(defined):
            for prefix in TARGET_ONLY_FORBIDDEN_SYMBOL_PREFIXES:
                if symbol.startswith(prefix):
                    violations.append(
                        f"target-only-forbidden host_media seam exported: "
                        f"{symbol}"
                    )
                    break
    for symbol in REQUIRED_ARCHIVE_SYMBOLS:
        if symbol not in defined:
            violations.append(
                f"required opaque symbol missing from archive: {symbol}"
            )
    return violations


def check_headers() -> None:
    for header in PUBLIC_HEADERS:
        text = header.read_text(encoding="utf-8")
        for token in FORBIDDEN_HEADER_TOKENS:
            if token in text:
                fail(f"public ESP storage bypass token {token!r}: {header}")
    removed_workspace = (
        REPO
        / "ports/esp-idf/storage/include/ninlil_port/esp_storage_workspace.h"
    )
    if removed_workspace.exists():
        fail(f"concrete workspace remains publicly packaged: {removed_workspace}")
    private = PRIVATE_HEADER.read_text(encoding="utf-8")
    if "#if !defined(ESP_PLATFORM)\n    NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL" not in private:
        fail("HOST_MODEL is not compile-excluded from ESP target")
    # Host-only private simulate seams must not be visible under ESP_PLATFORM.
    if (
        "#if !defined(ESP_PLATFORM)\n"
        "/* Host dual-slot conformance only"
    ) not in private and (
        "#if !defined(ESP_PLATFORM)\n"
        "void ninlil_port_esp_storage_private_simulate_crash"
    ) not in private:
        fail("private_simulate_* is not compile-excluded from ESP target")
    workspace_hdr = (
        REPO / "ports/esp-idf/storage/private/esp_storage_workspace.h"
    )
    if not workspace_hdr.is_file():
        fail(f"missing private workspace header: {workspace_hdr}")
    workspace_text = workspace_hdr.read_text(encoding="utf-8")
    # Concrete host-media RAM workspace must not exist under ESP preprocessing.
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"(?:/\*[\s\S]*?\*/\s*\n)?"
        r"struct\s+ninlil_port_esp_storage_host_media\s*\{",
        workspace_text,
    ):
        fail(
            "host_media workspace struct is not compile-excluded from ESP target"
        )
    model = MODEL_SOURCE.read_text(encoding="utf-8")
    target_tail = """\
#if defined(ESP_PLATFORM)
    /* There is deliberately no unattested ESP target branch to FULL OK. */
    return NINLIL_STORAGE_COMMIT_UNKNOWN;
#else
"""
    if target_tail not in model:
        fail("ESP FULL target fail-closed branch is missing")
    # private_simulate definitions must be host-only in model source too.
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"void\s+ninlil_port_esp_storage_private_simulate_crash\s*\(",
        model,
    ):
        fail(
            "private_simulate_crash definition is not compile-excluded "
            "from ESP target in model source"
        )
    for path, symbol in HIDDEN_HIL_SOURCE_MARKERS:
        text = path.read_text(encoding="utf-8")
        # Host-only defense: visibility(hidden) immediately before setter.
        pattern = (
            r'__attribute__\s*\(\s*\(\s*visibility\s*\(\s*"hidden"\s*\)\s*\)\s*\)'
            r"[\s\S]{0,120}" + re.escape(symbol)
        )
        if re.search(pattern, text) is None:
            fail(
                f"private HIL symbol {symbol} missing visibility(hidden) in {path}"
            )


def check_archive(archive: pathlib.Path, nm: str, kind: str) -> None:
    if kind not in ARCHIVE_KINDS:
        fail(f"unknown --archive-kind {kind!r} (expected host|target)")
    if not archive.is_file():
        fail(f"missing archive: {archive}")
    try:
        completed = subprocess.run(
            [nm, "-g", str(archive)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        fail(f"nm executable missing: {nm}")
    except subprocess.CalledProcessError as exc:
        fail(f"nm failed ({exc.returncode}): {(exc.stdout or '')[:500]}")
    # Host archives are native: Apple nm adds the Mach-O C ABI underscore.
    # ESP target archives are ELF even when this script is launched on macOS,
    # so target inspection must never normalize an invalid leading underscore.
    strip_macho_prefix = kind == "host" and sys.platform == "darwin"
    defined, undefined = parse_nm_global_symbols(
        completed.stdout,
        strip_macho_prefix=strip_macho_prefix,
    )
    for violation in check_archive_symbols(defined, kind):
        fail(violation)
    print(
        f"esp_storage_public_api_gate archive OK: kind={kind} "
        f"archive={archive.name} defined={len(defined)} "
        f"undefined={len(undefined)} "
        f"always_forbidden={len(ALWAYS_FORBIDDEN_ARCHIVE_SYMBOLS)} "
        f"target_only_exact="
        f"{0 if kind == 'host' else len(TARGET_ONLY_FORBIDDEN_ARCHIVE_SYMBOLS)} "
        f"target_only_prefixes="
        f"{0 if kind == 'host' else len(TARGET_ONLY_FORBIDDEN_SYMBOL_PREFIXES)}"
    )


def resolve_readelf(explicit: str | None) -> str:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    candidates.extend(
        [
            "xtensa-esp32s3-elf-readelf",
            "xtensa-esp-elf-readelf",
            "readelf",
            "llvm-readelf",
        ]
    )
    for name in candidates:
        if pathlib.Path(name).exists():
            return name
        found = shutil.which(name)
        if found:
            return found
    fail(
        "readelf not found (need xtensa-esp32s3-elf-readelf or readelf; "
        "refusing false-green on visibility)"
    )
    raise AssertionError("unreachable")


def parse_readelf_symbols(stdout: str) -> list[tuple[str, str, str]]:
    """Parse readelf -Ws lines into (name, bind, vis)."""
    out: list[tuple[str, str, str]] = []
    for line in stdout.splitlines():
        m = SYM_LINE_RE.match(line)
        if m:
            bind, vis, name = m.group(1), m.group(2), m.group(3)
            out.append((name, bind, vis))
            continue
        # llvm-readelf / archive member banners: fall back to token search.
        if "ninlil_port_esp_storage_" not in line:
            continue
        tokens = line.split()
        if len(tokens) < 8:
            continue
        name = tokens[-1]
        bind = vis = None
        for t in tokens:
            if t in ("GLOBAL", "LOCAL", "WEAK"):
                bind = t
            if t in ("DEFAULT", "HIDDEN", "INTERNAL", "PROTECTED"):
                vis = t
        if bind and vis and name:
            out.append((name, bind, vis))
    return out


def run_readelf_ws(readelf: str, path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing binary for readelf: {path}")
    try:
        proc = subprocess.run(
            [readelf, "-Ws", str(path)],
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except FileNotFoundError:
        fail(f"readelf executable missing: {readelf}")
    except subprocess.CalledProcessError as exc:
        fail(f"readelf failed ({exc.returncode}): {(exc.stderr or '')[:500]}")
    return proc.stdout


def check_visibility_contract(
    binary: pathlib.Path,
    readelf: str,
    *,
    require_hil_setters: bool,
) -> None:
    """Fail closed on GLOBAL DEFAULT HIL setters or non-DEFAULT public bind/unbind."""
    re_bin = resolve_readelf(readelf)
    stdout = run_readelf_ws(re_bin, binary)
    if not stdout.strip():
        fail(f"readelf produced empty output for {binary}")
    by_name: dict[str, list[tuple[str, str]]] = {}
    for name, bind, vis in parse_readelf_symbols(stdout):
        by_name.setdefault(name, []).append((bind, vis))

    for name in DEFAULT_PUBLIC_SYMBOLS:
        entries = by_name.get(name)
        if not entries:
            fail(f"{name} missing from readelf -Ws of {binary.name}")
        for bind, vis in entries:
            if bind != "GLOBAL" or vis != "DEFAULT":
                fail(
                    f"{name} must be GLOBAL DEFAULT in {binary.name}, "
                    f"readelf saw {bind} {vis}"
                )

    for name in HIDDEN_HIL_SYMBOLS:
        entries = by_name.get(name)
        if not entries:
            if require_hil_setters:
                fail(
                    f"{name} missing from readelf -Ws of {binary.name} "
                    f"(expected GLOBAL HIDDEN; refuse GC-away false-green)"
                )
            continue
        for bind, vis in entries:
            if bind == "GLOBAL" and vis == "DEFAULT":
                fail(
                    f"{name} is GLOBAL DEFAULT in {binary.name} "
                    f"(must be GLOBAL HIDDEN)"
                )
            if bind == "GLOBAL" and vis not in (
                "HIDDEN",
                "INTERNAL",
                "PROTECTED",
            ):
                fail(
                    f"{name} GLOBAL with non-private visibility {vis} "
                    f"in {binary.name}"
                )
            if bind == "GLOBAL" and vis == "HIDDEN":
                continue
            if bind == "LOCAL":
                # Accept LOCAL as private enough, but prefer HIDDEN GLOBAL.
                continue
            if bind not in ("GLOBAL", "LOCAL", "WEAK"):
                fail(f"{name} unexpected bind {bind} in {binary.name}")

    # When HIL setters are required, at least one entry per name must be
    # GLOBAL HIDDEN (not merely LOCAL after aggressive stripping).
    if require_hil_setters:
        for name in HIDDEN_HIL_SYMBOLS:
            entries = by_name[name]
            if not any(bind == "GLOBAL" and vis == "HIDDEN" for bind, vis in entries):
                fail(
                    f"{name} must appear as GLOBAL HIDDEN in readelf -Ws of "
                    f"{binary.name}, saw {entries}"
                )

    print(
        f"esp_storage_public_api_gate readelf OK: binary={binary.name} "
        f"hidden={list(HIDDEN_HIL_SYMBOLS)} default={list(DEFAULT_PUBLIC_SYMBOLS)} "
        f"readelf={re_bin}"
    )


def _run_negative_compile(
    argv: list[str],
    original: str,
    directory: str | None,
    source: str,
    expected_tokens: tuple[str, ...],
    label: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="ninlil-public-negative-") as td:
        td_path = pathlib.Path(td)
        negative = td_path / "esp_storage_public_bypass_negative.c"
        output = td_path / "negative.o"
        negative.write_text(source, encoding="utf-8")
        replaced: list[str] = []
        skip_output = False
        for arg in argv:
            if skip_output:
                replaced.append(str(output))
                skip_output = False
            elif arg == "-o":
                replaced.append(arg)
                skip_output = True
            elif arg == original or arg.endswith("smoke_app/main/main.c"):
                replaced.append(str(negative))
            else:
                replaced.append(arg)
        completed = subprocess.run(
            replaced,
            cwd=directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if completed.returncode == 0:
            fail(f"{label} compiled against public headers")
        if not any(token in completed.stdout for token in expected_tokens):
            fail(f"{label} failed for an unrelated reason:\n" + completed.stdout)


def compile_negative(compile_commands: pathlib.Path) -> None:
    commands = json.loads(compile_commands.read_text(encoding="utf-8"))
    entry = next(
        (
            item
            for item in commands
            if item.get("file", "").endswith("smoke_app/main/main.c")
        ),
        None,
    )
    if entry is None:
        fail("smoke main compile command not found")
    argv = entry.get("arguments")
    if argv is None:
        argv = shlex.split(entry["command"])
    original = entry["file"]
    directory = entry.get("directory")
    _run_negative_compile(
        argv,
        original,
        directory,
        """\
#include "ninlil_port/esp_storage.h"
#include "ninlil_port/esp_storage_flash.h"
int forbidden_policy = NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL;
int forbidden_workspace = sizeof(ninlil_port_esp_storage_flash_binding_t);
void *forbidden_init = (void *)&ninlil_port_esp_storage_private_init;
""",
        (
            "PRIVATE_FULL_HOST_MODEL",
            "flash_binding_t",
            "private_init",
        ),
        "public HOST_MODEL/workspace/generic-init bypass",
    )
    _run_negative_compile(
        argv,
        original,
        directory,
        """\
#include "ninlil_port/esp_storage.h"
#include "ninlil_port/esp_storage_flash.h"
static int hil_cb(void *user, ninlil_port_esp_storage_hil_event_t event)
{
    (void)user;
    (void)event;
    return 0;
}
void *forbidden_hil_setter = (void *)&ninlil_port_esp_storage_flash_set_hil_observer;
int forbidden_event = NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE;
void *forbidden_cb = (void *)&hil_cb;
""",
        (
            "hil_event",
            "hil_observer",
            "set_hil_observer",
            "HIL_DATA_BEFORE_ERASE",
            "HIL_DIRECTORY",
        ),
        "public HIL observer/event/setter remix",
    )


def self_test_headers() -> None:
    """Negative self-test: headers, nm kinds, readelf parse, missing-kind."""
    check_headers()
    for header in PUBLIC_HEADERS:
        text = header.read_text(encoding="utf-8")
        for token in (
            "hil_event",
            "hil_observer",
            "set_hil_observer",
            "HIL_DIRECTORY",
            "HIL_DATA_",
        ):
            if token in text:
                fail(f"self-test: public header still contains {token!r}: {header}")
    private_hil = (
        REPO / "ports/esp-idf/storage/private/esp_storage_hil_observer.h"
    )
    if not private_hil.is_file():
        fail("self-test: private HIL observer header missing")
    private_text = private_hil.read_text(encoding="utf-8")
    if "ninlil_port_esp_storage_hil_event_t" not in private_text:
        fail("self-test: private HIL enum missing")

    # --- nm parser: Linux ELF + Apple/GNU llvm-nm macOS archive shapes ---
    # Realistic host archive sample (defined seams + inter-member U refs).
    linux_nm = (
        "esp_storage_flash_media.c.o:\n"
        "0000000000000000 T ninlil_port_esp_storage_flash_bind\n"
        "0000000000000050 T ninlil_port_esp_storage_flash_unbind\n"
        "esp_storage_host_media.c.o:\n"
        "0000000000000114 T ninlil_port_esp_storage_host_media_ops\n"
        "0000000000000120 T ninlil_port_esp_storage_host_media_fault_write\n"
        "0000000000000000 T ninlil_port_esp_storage_host_media_init\n"
        "0000000000000040 T ninlil_port_esp_storage_host_media_deinit\n"
        "                 U ninlil_port_esp_storage_media_total_bytes\n"
        "esp_storage_model.c.o:\n"
        "000000000000258c T ninlil_port_esp_storage_private_simulate_full_reinit\n"
        "00000000000027e8 T ninlil_port_esp_storage_private_simulate_crash\n"
        "                 U ninlil_port_esp_storage_flash_bind\n"
    )
    # Apple llvm-nm -g: single Mach-O leading underscore + padded U columns.
    mac_nm = (
        "esp_storage_flash_media.c.o:\n"
        "0000000000000000 T _ninlil_port_esp_storage_flash_bind\n"
        "0000000000000050 T _ninlil_port_esp_storage_flash_unbind\n"
        "esp_storage_host_media.c.o:\n"
        "0000000000000114 T _ninlil_port_esp_storage_host_media_ops\n"
        "0000000000000120 T _ninlil_port_esp_storage_host_media_fault_write\n"
        "0000000000000000 T _ninlil_port_esp_storage_host_media_init\n"
        "0000000000000040 T _ninlil_port_esp_storage_host_media_deinit\n"
        "                 U _ninlil_port_esp_storage_media_total_bytes\n"
        "esp_storage_model.c.o:\n"
        "000000000000258c T _ninlil_port_esp_storage_private_simulate_full_reinit\n"
        "00000000000027e8 T _ninlil_port_esp_storage_private_simulate_crash\n"
        "                 U _ninlil_port_esp_storage_flash_bind\n"
    )
    linux_defined, linux_undefined = parse_nm_global_symbols(linux_nm)
    mac_defined, mac_undefined = parse_nm_global_symbols(
        mac_nm,
        strip_macho_prefix=True,
    )
    if linux_defined != mac_defined or linux_undefined != mac_undefined:
        fail(
            f"self-test: linux/mac nm parse diverge: "
            f"linux_def={sorted(linux_defined)} mac_def={sorted(mac_defined)} "
            f"linux_undef={sorted(linux_undefined)} "
            f"mac_undef={sorted(mac_undefined)}"
        )

    # ESP/Linux ELF must not accept Mach-O-prefixed required names. This is
    # the target false-green regression case that format-aware parsing closes.
    prefixed_elf_defined, _ = parse_nm_global_symbols(
        "00000000 T _ninlil_port_esp_storage_flash_bind\n"
        "00000020 T _ninlil_port_esp_storage_flash_unbind\n"
    )
    prefixed_elf_violations = check_archive_symbols(
        prefixed_elf_defined,
        "target",
    )
    for required in REQUIRED_ARCHIVE_SYMBOLS:
        if not any(required in v for v in prefixed_elf_violations):
            fail(
                f"self-test: target ELF must reject Mach-O-prefixed "
                f"required name {required}: {prefixed_elf_violations}"
            )
    for required in (
        "ninlil_port_esp_storage_host_media_ops",
        "ninlil_port_esp_storage_host_media_fault_write",
        "ninlil_port_esp_storage_host_media_init",
        "ninlil_port_esp_storage_host_media_deinit",
        "ninlil_port_esp_storage_flash_bind",
        "ninlil_port_esp_storage_flash_unbind",
        "ninlil_port_esp_storage_private_simulate_full_reinit",
        "ninlil_port_esp_storage_private_simulate_crash",
    ):
        if required not in linux_defined:
            fail(f"self-test: nm parser missed defined {required}")
    # U-only inter-member refs must stay undefined (not promoted unless T seen).
    if "ninlil_port_esp_storage_media_total_bytes" not in linux_undefined:
        fail("self-test: U-only media_total_bytes must be undefined")
    # flash_bind appears as T in one member and U in another → defined wins.
    if "ninlil_port_esp_storage_flash_bind" in linux_undefined:
        fail("self-test: defined+U flash_bind must not remain undefined")
    # Exactly one Mach-O underscore: __foo → _foo (do not strip twice).
    double_us = parse_nm_global_symbols(
        "00000000 T __double_underscored\n",
        strip_macho_prefix=True,
    )[0]
    if "__double_underscored" in double_us or "double_underscored" in double_us:
        fail("self-test: must strip exactly one leading underscore")
    if "_double_underscored" not in double_us:
        fail(f"self-test: expected _double_underscored, got {double_us}")

    # GNU nm type semantics: u is a definition; U/w/v are undefined refs.
    type_defined, type_undefined = parse_nm_global_symbols(
        "00000000 u _gnu_unique_definition\n"
        "         U _strong_undefined\n"
        "         w _weak_function_undefined\n"
        "         v _weak_object_undefined\n",
        strip_macho_prefix=True,
    )
    if "gnu_unique_definition" not in type_defined:
        fail(f"self-test: lowercase u must be defined, got {type_defined}")
    for weak_or_undefined in (
        "strong_undefined",
        "weak_function_undefined",
        "weak_object_undefined",
    ):
        if weak_or_undefined not in type_undefined:
            fail(
                f"self-test: {weak_or_undefined} must be undefined, "
                f"got {type_undefined}"
            )

    # Host must accept intentional private host seams (not public aliases).
    host_violations = check_archive_symbols(linux_defined, "host")
    if host_violations:
        fail(f"self-test: host must accept host seams, got {host_violations}")
    for seam in HOST_ONLY_ALLOWED_SEAM_SYMBOLS:
        if seam not in linux_defined:
            fail(f"self-test: host sample missing intentional seam {seam}")

    # Target must reject host_media family (prefix) + private_simulate exact.
    target_violations = check_archive_symbols(linux_defined, "target")
    for host_media_seam in (
        "host_media_ops",
        "host_media_fault_write",
        "host_media_init",
        "host_media_deinit",
    ):
        if not any(host_media_seam in v for v in target_violations):
            fail(
                f"self-test: target must reject {host_media_seam} via prefix, "
                f"got {target_violations}"
            )
    if not any("private_simulate_full_reinit" in v for v in target_violations):
        fail(
            "self-test: target must reject private_simulate_full_reinit, "
            f"got {target_violations}"
        )
    if not any("private_simulate_crash" in v for v in target_violations):
        fail(
            "self-test: target must reject private_simulate_crash, "
            f"got {target_violations}"
        )

    # Inject every always-forbidden exact symbol: host and target must reject.
    base_ok = set(linux_defined)
    for symbol in ALWAYS_FORBIDDEN_ARCHIVE_SYMBOLS:
        host_hit = check_archive_symbols(base_ok | {symbol}, "host")
        target_hit = check_archive_symbols(base_ok | {symbol}, "target")
        if not any(symbol in v for v in host_hit):
            fail(
                f"self-test: host must reject always-forbidden {symbol}: "
                f"{host_hit}"
            )
        if not any(symbol in v for v in target_hit):
            fail(
                f"self-test: target must reject always-forbidden {symbol}: "
                f"{target_hit}"
            )

    # Public simulate aliases are always-forbidden (not host-only private).
    for alias in (
        "ninlil_port_esp_storage_simulate_full_reinit",
        "ninlil_port_esp_storage_simulate_crash",
    ):
        if alias not in ALWAYS_FORBIDDEN_ARCHIVE_SYMBOLS:
            fail(f"self-test: {alias} must be ALWAYS_FORBIDDEN")
        if alias in TARGET_ONLY_FORBIDDEN_ARCHIVE_SYMBOLS:
            fail(f"self-test: {alias} must not be target-only (always)")

    # Inject every target-only exact symbol: host accepts, target rejects.
    for symbol in TARGET_ONLY_FORBIDDEN_ARCHIVE_SYMBOLS:
        host_ok = check_archive_symbols(base_ok | {symbol}, "host")
        if any(symbol in v for v in host_ok):
            fail(
                f"self-test: host must accept private host seam {symbol}: "
                f"{host_ok}"
            )
        target_hit = check_archive_symbols(base_ok | {symbol}, "target")
        if not any(symbol in v for v in target_hit):
            fail(
                f"self-test: target must reject {symbol}: {target_hit}"
            )

    # Prefix case: novel host_media_* helper is target-forbidden, host-ok.
    novel = "ninlil_port_esp_storage_host_media_fault_novel_helper"
    host_novel = check_archive_symbols(base_ok | {novel}, "host")
    if any(novel in v for v in host_novel):
        fail(f"self-test: host must accept host_media prefix seam: {host_novel}")
    target_novel = check_archive_symbols(base_ok | {novel}, "target")
    if not any(novel in v for v in target_novel):
        fail(
            f"self-test: target must reject novel host_media_ prefix: "
            f"{target_novel}"
        )

    # U-only required symbols must fail (not defined/exported).
    u_only_required_nm = (
        "esp_storage_other.c.o:\n"
        "                 U ninlil_port_esp_storage_flash_bind\n"
        "                 U ninlil_port_esp_storage_flash_unbind\n"
        "                 U _ninlil_port_esp_storage_flash_bind\n"
    )
    u_defined, u_undefined = parse_nm_global_symbols(u_only_required_nm)
    if u_defined:
        fail(f"self-test: U-only sample must have empty defined, got {u_defined}")
    if "ninlil_port_esp_storage_flash_bind" not in u_undefined:
        fail("self-test: U-only flash_bind must be classified undefined")
    u_req = check_archive_symbols(u_defined, "host")
    if not any("flash_bind" in v for v in u_req):
        fail(f"self-test: U-only required flash_bind must fail: {u_req}")
    if not any("flash_unbind" in v for v in u_req):
        fail(f"self-test: U-only required flash_unbind must fail: {u_req}")

    # U-only forbidden must NOT fail (reference ≠ export).
    u_forbidden_nm = (
        "esp_storage_flash_media.c.o:\n"
        "0000000000000000 T ninlil_port_esp_storage_flash_bind\n"
        "0000000000000050 T ninlil_port_esp_storage_flash_unbind\n"
        "esp_storage_other.c.o:\n"
        "                 U ninlil_port_esp_storage_init\n"
        "                 U ninlil_port_esp_storage_simulate_crash\n"
        "                 U ninlil_port_esp_storage_host_media_ops\n"
    )
    uf_defined, uf_undefined = parse_nm_global_symbols(u_forbidden_nm)
    for mere_ref in (
        "ninlil_port_esp_storage_init",
        "ninlil_port_esp_storage_simulate_crash",
        "ninlil_port_esp_storage_host_media_ops",
    ):
        if mere_ref in uf_defined:
            fail(f"self-test: U-only {mere_ref} must not be defined")
        if mere_ref not in uf_undefined:
            fail(f"self-test: U-only {mere_ref} must be undefined")
    uf_host = check_archive_symbols(uf_defined, "host")
    if uf_host:
        fail(
            f"self-test: U-only forbidden refs must not fail host: {uf_host}"
        )
    uf_target = check_archive_symbols(uf_defined, "target")
    if uf_target:
        fail(
            f"self-test: U-only forbidden refs must not fail target: "
            f"{uf_target}"
        )

    # Missing required opaque symbols fail both kinds.
    incomplete = {
        "ninlil_port_esp_storage_flash_bind",
        # unbind intentionally missing
    }
    if not any(
        "flash_unbind" in v for v in check_archive_symbols(incomplete, "host")
    ):
        fail("self-test: missing flash_unbind must fail")

    # --- readelf line parse (existing contract) ---
    sample_ok = (
        "   123: 4200a3fc    64 FUNC    GLOBAL DEFAULT   12 "
        "ninlil_port_esp_storage_flash_bind\n"
        "   124: 4200a4e0    32 FUNC    GLOBAL DEFAULT   12 "
        "ninlil_port_esp_storage_flash_unbind\n"
        "   125: 4200ab84    48 FUNC    GLOBAL HIDDEN    12 "
        "ninlil_port_esp_storage_flash_set_hil_observer\n"
        "   126: 4201836c    40 FUNC    GLOBAL HIDDEN    12 "
        "ninlil_port_esp_storage_private_set_hil_observer\n"
    )
    parsed = parse_readelf_symbols(sample_ok)
    by_name = {name: (bind, vis) for name, bind, vis in parsed}
    for name in DEFAULT_PUBLIC_SYMBOLS:
        if by_name.get(name) != ("GLOBAL", "DEFAULT"):
            fail(f"self-test: expected GLOBAL DEFAULT for {name}, got {by_name.get(name)}")
    for name in HIDDEN_HIL_SYMBOLS:
        if by_name.get(name) != ("GLOBAL", "HIDDEN"):
            fail(f"self-test: expected GLOBAL HIDDEN for {name}, got {by_name.get(name)}")

    sample_bad = (
        "   200: 4200ab84    48 FUNC    GLOBAL DEFAULT   12 "
        "ninlil_port_esp_storage_flash_set_hil_observer\n"
    )
    bad = parse_readelf_symbols(sample_bad)
    if not bad or bad[0][1:] != ("GLOBAL", "DEFAULT"):
        fail("self-test: bad visibility sample parse")

    # --- missing-kind / kind-without-archive negatives (CLI) ---
    try:
        main(
            [
                "--archive",
                str(REPO / "tools" / "esp_storage_public_api_gate.py"),
            ]
        )
        fail("self-test: --archive without --archive-kind must fail")
    except SystemExit as exc:
        if exc.code in (0, None):
            fail("self-test: --archive without --archive-kind must non-zero exit")

    try:
        main(["--archive-kind", "host"])
        fail("self-test: --archive-kind without --archive must fail")
    except SystemExit as exc:
        if exc.code in (0, None):
            fail("self-test: --archive-kind without --archive must non-zero exit")

    print("esp_storage_public_api_gate self-test OK")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1 and argv[0] == "self-test":
        self_test_headers()
        return 0
    parser = argparse.ArgumentParser(
        description=(
            "ESP storage public API gate. When inspecting an archive, "
            "--archive-kind host|target is mandatory (no default)."
        )
    )
    parser.add_argument("--archive", type=pathlib.Path)
    parser.add_argument(
        "--archive-kind",
        choices=ARCHIVE_KINDS,
        default=None,
        help="required with --archive: host CTest archive vs official ESP target",
    )
    parser.add_argument("--elf", type=pathlib.Path, help="official linked ELF for readelf")
    parser.add_argument("--nm", default="nm")
    parser.add_argument(
        "--readelf",
        default=None,
        help="xtensa-esp32s3-elf-readelf (required with --elf)",
    )
    parser.add_argument("--compile-commands", type=pathlib.Path)
    args = parser.parse_args(argv)

    if args.archive is not None and args.archive_kind is None:
        fail("--archive requires --archive-kind host|target (no default; refuse false-green)")
    if args.archive is None and args.archive_kind is not None:
        fail("--archive-kind requires --archive")

    check_headers()
    if args.archive is not None:
        assert args.archive_kind is not None
        check_archive(args.archive, args.nm, args.archive_kind)
        # Optional archive readelf: when --readelf is given without --elf,
        # still refuse false-green if HIL setters appear as GLOBAL DEFAULT.
        if args.readelf is not None and args.elf is None:
            check_visibility_contract(
                args.archive,
                args.readelf,
                require_hil_setters=True,
            )
    if args.elf is not None:
        if args.readelf is None:
            # Prefer explicit tool; resolve_readelf will still search PATH.
            args.readelf = "xtensa-esp32s3-elf-readelf"
        # HIL ELF is the preferred artifact: it keeps both HIL setters live.
        check_visibility_contract(
            args.elf,
            args.readelf,
            require_hil_setters=True,
        )
    if args.compile_commands is not None:
        compile_negative(args.compile_commands)
    print("ESP storage public API gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
