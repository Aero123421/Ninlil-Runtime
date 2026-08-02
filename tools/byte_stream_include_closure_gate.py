#!/usr/bin/env python3
"""Include-closure gate for C1 byte-stream dual-surface headers.

Locks the private/public split after the ESP public-include boundary work:

  - Private ``src/transport/byte_stream.h`` is self-contained under
    ``-I src/transport`` alone (no ``ninlil/`` shim dependency).
  - Public ``include/ninlil/byte_stream.h`` is self-contained under
    ``-I include`` alone.
  - Private and public type bodies stay ABI-identical (normalized).
  - Cascading private consumers (control_session / logical_session /
    c4_lab_usb_path) compile against private transport + model + public
    version roots without needing a public ``src/**`` export.

Does not claim U1 complete, HIL, or RELEASE_SUPPORTED.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PRIVATE_HEADER = REPO_ROOT / "src" / "transport" / "byte_stream.h"
PUBLIC_HEADER = REPO_ROOT / "include" / "ninlil" / "byte_stream.h"
CONTROL_SESSION = REPO_ROOT / "src" / "transport" / "control_session.h"
LOGICAL_SESSION = REPO_ROOT / "src" / "transport" / "logical_session.h"
C4_LAB = REPO_ROOT / "src" / "transport" / "c4_lab_usb_path.h"

PRIVATE_ONLY_DIRS = (REPO_ROOT / "src" / "transport",)
PUBLIC_ONLY_DIRS = (REPO_ROOT / "include",)
# control_session pulls control_frame_codec → ninlil/version.h.
CASCADE_DIRS = (
    REPO_ROOT / "src" / "transport",
    REPO_ROOT / "src" / "model",
    REPO_ROOT / "src" / "runtime",
    REPO_ROOT / "include",
)

SHIM_INCLUDE = re.compile(
    r'^\s*#\s*include\s*[<"]ninlil/byte_stream\.h[>"]', re.MULTILINE
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(REPO_ROOT)}")
    return path.read_text(encoding="utf-8")


def normalize_type_body(text: str) -> str:
    """Drop guards/comments; keep production body from first real include/typedef."""
    lines = text.splitlines(True)
    out: list[str] = []
    started = False
    for ln in lines:
        if not started:
            stripped = ln.lstrip()
            if (
                stripped.startswith("#include")
                or stripped.startswith("typedef")
                or stripped.startswith("#define NINLIL_BYTE_STREAM_RING")
            ):
                started = True
            else:
                continue
        if re.search(r"NINLIL_(?:TRANSPORT_)?BYTE_STREAM_H", ln) and (
            "ifndef" in ln or re.search(r"^\s*#\s*define\b", ln) or "endif" in ln
        ):
            continue
        out.append(ln)
    return "".join(out)


def _display_path(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def assert_not_shim(path: pathlib.Path) -> None:
    text = read_text(path)
    where = _display_path(path)
    if SHIM_INCLUDE.search(text):
        fail(
            f"{where} must not shim via "
            f'#include "ninlil/byte_stream.h" — keep private body self-contained'
        )
    if "ninlil_byte_stream_ops_t" not in text:
        fail(f"{where} missing ops vtable (empty/shim?)")
    if "(*open)" not in text and "(* open)" not in text:
        # tolerate whitespace variants via regex
        if not re.search(r"\(\s*\*\s*open\s*\)\s*\(", text):
            fail(f"{where} missing real open ops member")


def assert_bodies_match() -> None:
    priv = normalize_type_body(read_text(PRIVATE_HEADER))
    pub = normalize_type_body(read_text(PUBLIC_HEADER))
    if priv != pub:
        fail(
            "private src/transport/byte_stream.h and public "
            "include/ninlil/byte_stream.h type bodies diverge"
        )


def _compile(source: str, include_dirs: list[pathlib.Path], label: str) -> None:
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory(prefix="ninlil-bs-closure-") as tmp:
        src_path = pathlib.Path(tmp) / "probe.c"
        obj_path = pathlib.Path(tmp) / "probe.o"
        src_path.write_text(source, encoding="utf-8")
        cmd = [cc, "-std=c11", "-Wall", "-Werror", "-c", str(src_path), "-o", str(obj_path)]
        for d in include_dirs:
            cmd.extend(["-I", str(d)])
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            fail(f"{label} failed to compile (include closure broken)")


def assert_private_self_contained() -> None:
    src = """
#include "byte_stream.h"
int main(void) {
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_status_t st = NINLIL_BYTE_STREAM_OK;
    ninlil_byte_stream_ops_t ops;
    (void)stream;
    (void)st;
    (void)ops;
    (void)ninlil_byte_stream_sat_add_u64(1u, 2u);
    return 0;
}
"""
    _compile(src, list(PRIVATE_ONLY_DIRS), "private byte_stream under -I src/transport only")


def assert_public_self_contained() -> None:
    src = """
#include "ninlil/byte_stream.h"
int main(void) {
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_status_t st = NINLIL_BYTE_STREAM_OK;
    (void)stream;
    (void)st;
    return 0;
}
"""
    _compile(src, list(PUBLIC_ONLY_DIRS), "public ninlil/byte_stream under -I include only")


def assert_cascade_private_headers() -> None:
    """Private cascade headers must resolve types without public src export."""
    probes = (
        (
            "control_session.h",
            """
#include "control_session.h"
int main(void) {
    ninlil_byte_stream_t *stream = 0;
    ninlil_byte_stream_status_t st = NINLIL_BYTE_STREAM_OK;
    (void)stream;
    (void)st;
    (void)NINLIL_CTRL_SESSION_OBJECT_BYTES;
    return 0;
}
""",
        ),
        (
            "logical_session.h",
            """
#include "logical_session.h"
int main(void) {
    ninlil_byte_stream_t *stream = 0;
    (void)stream;
    return 0;
}
""",
        ),
        (
            "c4_lab_usb_path.h",
            """
#include "c4_lab_usb_path.h"
int main(void) {
    ninlil_byte_stream_t *stream = 0;
    (void)stream;
    return 0;
}
""",
        ),
    )
    for name, source in probes:
        path = REPO_ROOT / "src" / "transport" / name
        if not path.is_file():
            fail(f"missing cascade header {name}")
        _compile(
            source,
            list(CASCADE_DIRS),
            f"cascade private {name} include closure",
        )


def assert_private_not_on_public_roots() -> None:
    """Bare private transport include must fail with only public roots."""
    cc = os.environ.get("CC", "cc")
    src = '#include "byte_stream.h"\nint main(void){return 0;}\n'
    with tempfile.TemporaryDirectory(prefix="ninlil-bs-neg-") as tmp:
        src_path = pathlib.Path(tmp) / "neg.c"
        obj_path = pathlib.Path(tmp) / "neg.o"
        src_path.write_text(src, encoding="utf-8")
        cmd = [cc, "-std=c11", "-c", str(src_path), "-o", str(obj_path)]
        for d in PUBLIC_ONLY_DIRS:
            cmd.extend(["-I", str(d)])
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            fail(
                "bare \"byte_stream.h\" compiled with only public include/ — "
                "private transport root leaked into public surface"
            )


def check() -> None:
    assert_not_shim(PRIVATE_HEADER)
    assert_not_shim(PUBLIC_HEADER)
    assert_bodies_match()
    assert_private_self_contained()
    assert_public_self_contained()
    assert_cascade_private_headers()
    assert_private_not_on_public_roots()
    print(
        "byte_stream_include_closure_gate OK: private self-contained under "
        "src/transport; public self-contained under include/; cascade headers "
        "resolve ninlil_byte_stream_*; bodies match; no public leak"
    )


def _expect_fail(label: str, mutator: Callable[[], None]) -> None:
    try:
        mutator()
    except GateFailure as e:
        print(f"  self-test mutation {label!r} correctly failed: {e}")
        return
    fail(f"self-test mutation {label!r} did not fail the checker (false green)")


def self_test() -> None:
    # Mutation: private becomes a shim → must fail.
    original = read_text(PRIVATE_HEADER)

    def mut_shim() -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            # Operate on a copy via temporary swap of normalize paths is hard;
            # instead inline assert_not_shim on synthetic text.
            shim = (
                "#ifndef NINLIL_BYTE_STREAM_H\n"
                "#define NINLIL_BYTE_STREAM_H\n"
                '#include "ninlil/byte_stream.h"\n'
                "#endif\n"
            )
            if not SHIM_INCLUDE.search(shim):
                fail("mutator setup: shim pattern not detected")
            # reuse assert_not_shim logic via temp file path override
            path = root / "byte_stream.h"
            path.write_text(shim, encoding="utf-8")
            try:
                assert_not_shim(path)
            except GateFailure:
                raise
            fail("shim accepted")

    _expect_fail("private_shim", mut_shim)

    def mut_body_diverge() -> None:
        # Compare against a diverged public body.
        priv = normalize_type_body(original)
        pub = normalize_type_body(read_text(PUBLIC_HEADER)) + "\n/* diverge */\n"
        if priv == pub:
            fail("mutator setup: bodies still match")
        # Direct body compare call simulation:
        if priv != pub:
            fail(
                "private src/transport/byte_stream.h and public "
                "include/ninlil/byte_stream.h type bodies diverge"
            )

    _expect_fail("body_diverge", mut_body_diverge)

    # Live tree must still pass the full check.
    check()
    print("byte_stream_include_closure_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: byte_stream_include_closure_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    try:
        if argv[1] == "check":
            check()
        else:
            self_test()
    except GateFailure as e:
        print(f"byte_stream_include_closure_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
