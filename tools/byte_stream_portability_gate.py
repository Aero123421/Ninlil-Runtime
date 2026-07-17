#!/usr/bin/env python3
"""Source gate: portable C1 byte-stream contract must not include POSIX headers.

Locks docs/23 + ADR-0003 rule that C1 is platform-type free. Does not claim
U1 complete or physical HIL.

self-test mutates temporary copies of the real C1 header and proves each
mutation fails the real checker (mutation coverage, not soft token smoke).
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import tempfile
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
C1_HEADER = REPO_ROOT / "src" / "transport" / "byte_stream.h"

BANNED_INCLUDE_NAMES = (
    "termios.h",
    "unistd.h",
    "fcntl.h",
    "poll.h",
    "pthread.h",
    "sys/ioctl.h",
    "sys/types.h",
    "sys/stat.h",
    "sys/socket.h",
    "windows.h",
    "tinyusb.h",
    "tusb.h",
)
INCLUDE_LINE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')
BANNED_TYPE_TOKEN = re.compile(
    r"\b(?:fd_set|termios|pthread_t|pid_t|nfds_t|pollfd|HANDLE|SOCKET)\b"
)

# Production code (comments/strings stripped): bare fd identifiers / decls.
FD_DECL = re.compile(
    r"\b(?:int|unsigned|signed|long|short|size_t|ssize_t)\s+fd\b"
)
FD_FIELD = re.compile(r"\bfd\s*;")
FD_PARAM = re.compile(r"\([^;{}]*\bfd\b[^;{}]*\)")

# Real ops vtable member declarations (function pointers), not comment tokens.
OPS_MEMBERS = (
    "open",
    "close",
    "read",
    "write",
    "poll",
    "link",
    "link_generation",
)

REQUIRED_TOKENS = (
    "ninlil_byte_stream_ops_t",
    "WOULD_BLOCK",
    "RX_OVERFLOW",
    "ERR_LINK_DOWN",
    "endpoint_token",
    "LINK_LISTENING",
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def strip_c_comments_and_strings(text: str) -> str:
    """Remove // and /* */ comments and "..." / '...' string literals."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            if j < 0:
                break
            out.append("\n")
            i = j + 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                break
            # Preserve newlines so line-oriented tools still work.
            chunk = text[i : j + 2]
            out.append("\n" * chunk.count("\n"))
            i = j + 2
            continue
        if text[i] in "\"'":
            quote = text[i]
            out.append(" ")
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def check_text(text: str, where: str = "C1 header") -> None:
    if "ninlil_byte_stream_ops_t" not in text:
        fail(f"{where} missing ops vtable type")
    for required in REQUIRED_TOKENS:
        if required not in text:
            fail(f"{where} missing required contract token: {required}")

    for line in text.splitlines():
        m = INCLUDE_LINE.match(line)
        if not m:
            continue
        name = m.group(1).strip()
        lower = name.lower()
        banned = False
        for ban in BANNED_INCLUDE_NAMES:
            if lower == ban or lower.endswith("/" + ban):
                banned = True
                break
        if lower.startswith("netinet/") or lower.startswith("arpa/"):
            banned = True
        if lower.startswith("freertos/") or lower.startswith("esp_"):
            banned = True
        if lower.startswith("winsock"):
            banned = True
        if banned:
            fail(f"{where} must not include platform header: {line!r}")

    code = strip_c_comments_and_strings(text)

    for m in BANNED_TYPE_TOKEN.finditer(code):
        line_start = code.rfind("\n", 0, m.start()) + 1
        line_end = code.find("\n", m.start())
        if line_end < 0:
            line_end = len(code)
        line = code[line_start:line_end]
        fail(f"{where} must not expose platform type {m.group(0)!r} in: {line!r}")

    # Platform identifier `fd` must not appear as a production declaration.
    for rx, label in (
        (FD_DECL, "typed fd declaration"),
        (FD_FIELD, "fd field"),
        (FD_PARAM, "fd parameter list"),
    ):
        m = rx.search(code)
        if m:
            line_start = code.rfind("\n", 0, m.start()) + 1
            line_end = code.find("\n", m.start())
            if line_end < 0:
                line_end = len(code)
            line = code[line_start:line_end].strip()
            fail(f"{where} must not contain {label}: {line!r}")

    # Ops vtable members must be real function-pointer declarations.
    for member in OPS_MEMBERS:
        # Match: (*open)(  or  (* open )(
        pat = re.compile(rf"\(\s*\*\s*{re.escape(member)}\s*\)\s*\(")
        if not pat.search(code):
            fail(
                f"{where} missing real ops vtable member declaration for "
                f"{member!r} (function pointer)"
            )


def check_path(path: pathlib.Path) -> None:
    if not path.is_file():
        fail(f"missing C1 header: {path}")
    check_text(path.read_text(encoding="utf-8"), str(path))


def check() -> None:
    check_path(C1_HEADER)
    print(
        "byte_stream_portability_gate ok: "
        f"{C1_HEADER.relative_to(REPO_ROOT)} platform-clean"
    )


def _expect_fail(label: str, mutator: Callable[[pathlib.Path], None]) -> None:
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        dst = root / "byte_stream.h"
        shutil.copy2(C1_HEADER, dst)
        mutator(dst)
        try:
            check_path(dst)
        except GateFailure as e:
            print(f"  self-test mutation {label!r} correctly failed: {e}")
            return
        fail(f"self-test mutation {label!r} did not fail the checker (false green)")


def _mut_drop_token(token: str) -> Callable[[pathlib.Path], None]:
    def mut(path: pathlib.Path) -> None:
        text = path.read_text(encoding="utf-8")
        if token not in text:
            fail(f"mutator setup: token {token!r} missing")
        path.write_text(text.replace(token, "XREMOVEDX"), encoding="utf-8")

    return mut


def _mut_add_include(header: str) -> Callable[[pathlib.Path], None]:
    def mut(path: pathlib.Path) -> None:
        text = path.read_text(encoding="utf-8")
        path.write_text(f'#include <{header}>\n' + text, encoding="utf-8")

    return mut


def _mut_add_type(type_name: str) -> Callable[[pathlib.Path], None]:
    def mut(path: pathlib.Path) -> None:
        text = path.read_text(encoding="utf-8")
        path.write_text(
            text + f"\ntypedef struct {{ int x; }} {type_name};\n",
            encoding="utf-8",
        )

    return mut


def _mut_add_fd_decl(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    # Production-looking field; comments already stripped by checker.
    path.write_text(text + "\nint fd;\n", encoding="utf-8")


def _mut_drop_ops_member(member: str) -> Callable[[pathlib.Path], None]:
    def mut(path: pathlib.Path) -> None:
        text = path.read_text(encoding="utf-8")
        # Break the real function-pointer declaration for this member.
        pat = re.compile(rf"\(\s*\*\s*{re.escape(member)}\s*\)")
        if not pat.search(text):
            fail(f"mutator setup: ops member {member!r} declaration missing")
        path.write_text(pat.sub(f"(*X{member}X)", text), encoding="utf-8")

    return mut


def self_test() -> None:
    if not C1_HEADER.is_file():
        fail(f"missing C1 header for self-test: {C1_HEADER}")

    check_path(C1_HEADER)

    mutations: list[tuple[str, Callable[[pathlib.Path], None]]] = [
        ("drop_ops_type", _mut_drop_token("ninlil_byte_stream_ops_t")),
        ("drop_WOULD_BLOCK", _mut_drop_token("WOULD_BLOCK")),
        ("drop_RX_OVERFLOW", _mut_drop_token("RX_OVERFLOW")),
        ("drop_link_generation", _mut_drop_ops_member("link_generation")),
        ("drop_ERR_LINK_DOWN", _mut_drop_token("ERR_LINK_DOWN")),
        ("drop_endpoint_token", _mut_drop_token("endpoint_token")),
        ("drop_LINK_LISTENING", _mut_drop_token("LINK_LISTENING")),
        ("include_termios", _mut_add_include("termios.h")),
        ("include_poll", _mut_add_include("poll.h")),
        ("include_pthread", _mut_add_include("pthread.h")),
        ("include_fcntl", _mut_add_include("fcntl.h")),
        ("type_pthread_t", _mut_add_type("pthread_t")),
        ("type_pollfd", _mut_add_type("pollfd")),
        ("type_termios", _mut_add_type("termios")),
        ("decl_int_fd", _mut_add_fd_decl),
        ("drop_ops_open", _mut_drop_ops_member("open")),
    ]
    for label, mut in mutations:
        _expect_fail(label, mut)

    print(
        f"byte_stream_portability_gate self-test ok: mutations={len(mutations)}"
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: byte_stream_portability_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    try:
        if argv[1] == "self-test":
            self_test()
        else:
            check()
    except GateFailure as e:
        print(f"byte_stream_portability_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
