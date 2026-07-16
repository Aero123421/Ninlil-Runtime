#!/usr/bin/env python3
"""Fail closed if ESP storage FULL/media/workspace bypasses become public.

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
FORBIDDEN_ARCHIVE_SYMBOLS = (
    "ninlil_port_esp_storage_init",
    "ninlil_port_esp_storage_deinit",
    "ninlil_port_esp_storage_ops",
    # Public-name HIL setter (must not exist; private/flash forms are HIDDEN).
    "ninlil_port_esp_storage_set_hil_observer",
    "ninlil_port_esp_storage_simulate_full_reinit",
    "ninlil_port_esp_storage_flash_media_ops",
    "ninlil_port_esp_storage_host_media_ops",
)
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
    model = MODEL_SOURCE.read_text(encoding="utf-8")
    target_tail = """\
#if defined(ESP_PLATFORM)
    /* There is deliberately no unattested ESP target branch to FULL OK. */
    return NINLIL_STORAGE_COMMIT_UNKNOWN;
#else
"""
    if target_tail not in model:
        fail("ESP FULL target fail-closed branch is missing")
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


def check_archive(archive: pathlib.Path, nm: str) -> None:
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
    symbols = completed.stdout
    for symbol in FORBIDDEN_ARCHIVE_SYMBOLS:
        if any(line.split()[-1:] == [symbol] for line in symbols.splitlines()):
            fail(f"forbidden target archive symbol exported: {symbol}")
    if "ninlil_port_esp_storage_flash_bind" not in symbols:
        fail("opaque flash binder missing from archive")
    if "ninlil_port_esp_storage_flash_unbind" not in symbols:
        fail("opaque flash unbind missing from archive")


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
    """Negative self-test: public headers + synthetic readelf line parse."""
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

    print("esp_storage_public_api_gate self-test OK")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 1 and argv[0] == "self-test":
        self_test_headers()
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=pathlib.Path)
    parser.add_argument("--elf", type=pathlib.Path, help="official linked ELF for readelf")
    parser.add_argument("--nm", default="nm")
    parser.add_argument(
        "--readelf",
        default=None,
        help="xtensa-esp32s3-elf-readelf (required with --elf)",
    )
    parser.add_argument("--compile-commands", type=pathlib.Path)
    args = parser.parse_args(argv)
    check_headers()
    if args.archive is not None:
        check_archive(args.archive, args.nm)
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
