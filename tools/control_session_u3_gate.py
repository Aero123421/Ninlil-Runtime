#!/usr/bin/env python3
"""U3 structural gate: C3 control session + C4 pump + private source authority.

Mutation self-test invokes the real checker on temporary trees (not soft
substring smoke). Does not claim U3 USB series complete, HELLO/NCL1, or HIL.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

SESSION_H = REPO_ROOT / "src" / "transport" / "control_session.h"
SESSION_C = REPO_ROOT / "src" / "transport" / "control_session.c"
C1_H = REPO_ROOT / "src" / "transport" / "byte_stream.h"
CODEC_H = REPO_ROOT / "src" / "model" / "control_frame_codec.h"
PRIVATE_AUTH = REPO_ROOT / "cmake" / "ninlil_runtime_private_sources.cmake"
CMAKE_LISTS = REPO_ROOT / "CMakeLists.txt"
DOC23 = REPO_ROOT / "docs" / "23-usb-radio-boundary.md"
DOC07 = REPO_ROOT / "docs" / "07-testing-and-quality.md"
PUBLIC_INCLUDE = REPO_ROOT / "include" / "ninlil"

BANNED_INCLUDES = (
    "termios.h",
    "unistd.h",
    "fcntl.h",
    "pthread.h",
    "tinyusb.h",
    "tusb.h",
    "freertos/",
    "esp_",
)
INCLUDE_LINE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')

REQUIRED_HEADER_TOKENS = (
    "ninlil_ctrl_session_bind",
    "ninlil_ctrl_session_pump",
    "ninlil_ctrl_session_submit_tx",
    "ninlil_ctrl_session_take_rx",
    "NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES",
    "NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP",
    "NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES",
    "NINLIL_CTRL_SESSION_TX_INTENT_BYTE_CAP",
    "NINLIL_CTRL_SESSION_CONTINUITY_LOST",
    "NINLIL_CTRL_SESSION_GENERATION_MISMATCH",
    "NINLIL_CTRL_SESSION_RX_OVERFLOW",
    "all-or-none",
    "copy-out",
    "Not HELLO",
    "NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM",
)

REQUIRED_SOURCE_TOKENS = (
    "ninlil_ctrl_session_pump",
    "ninlil_model_control_frame_parser_feed",
    "ninlil_model_control_frame_encode",
    "link_generation",
    "RX_OVERFLOW",
    "WRONG_OWNER",
    "ingress",
    "tx_wire",
    "sat_add",
    "validate_link_generation_ticket",
    "set_error_out_only",
    "commit_parser_stats_and_reset",
    "partial OK",
    "read OK length > capacity",
    "read WOULD_BLOCK with length!=0",
    "feed guard residual not consumed",
    "g1/link/g2",
)

SEAM_SYMBOL = "ninlil_ctrl_session_test_force_committed_framing_stats"


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def strip_c_comments_and_strings(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i : i + 2] == "//":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text[i : i + 2] == "/*":
            i += 2
            while i + 1 < n and text[i : i + 2] != "*/":
                i += 1
            i = min(i + 2, n)
            continue
        if text[i] == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('""')
            continue
        if text[i] == "'":
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "'":
                    i += 1
                    break
                i += 1
            out.append("''")
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def check_includes(path: pathlib.Path) -> None:
    text = read_text(path)
    for line in text.splitlines():
        m = INCLUDE_LINE.match(line)
        if not m:
            continue
        inc = m.group(1)
        for banned in BANNED_INCLUDES:
            if banned in inc:
                fail(f"{path}: banned include {inc}")


def check_no_heap_vla(path: pathlib.Path) -> None:
    code = strip_c_comments_and_strings(read_text(path))
    for token in ("malloc(", "calloc(", "realloc(", "free(", "alloca("):
        if token in code:
            fail(f"{path}: heap/alloca token {token}")
    if path.suffix == ".c":
        if re.search(
            r"\b(?:uint8_t|char|int|unsigned|size_t)\s+\w+\s*\[\s*[a-z_][a-z0-9_]*\s*\]",
            code,
        ):
            fail(f"{path}: possible VLA declaration")


def check_public_abi_clean() -> None:
    for p in PUBLIC_INCLUDE.glob("*.h"):
        text = read_text(p)
        if "ctrl_session" in text or "control_session" in text:
            fail(f"public header must not mention control_session: {p}")


def check_authority() -> None:
    text = read_text(PRIVATE_AUTH)
    if "src/transport/control_session.c" not in text:
        fail("control_session.c missing from ninlil_runtime_private_sources.cmake")
    if "control_session.c" not in text.split("NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES")[-1]:
        fail("control_session.c missing from VLA source list")


def check_cmake_test_seam_define() -> None:
    text = read_text(CMAKE_LISTS)
    if "NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM=1" not in text:
        fail("CMake must define NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM for tests")
    # Must be under NINLIL_BUILD_TESTS for private lib, not always-on.
    if not re.search(
        r"if\s*\(\s*NINLIL_BUILD_TESTS\s*\).*NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM",
        text,
        re.DOTALL,
    ):
        fail("TEST_SEAM define must be gated by NINLIL_BUILD_TESTS on runtime_private")


def check_docs_nonclaims() -> None:
    text = read_text(DOC23)
    head = "\n".join(text.splitlines()[:8])
    if re.search(r"\bU3 complete\b", head) and "ではない" not in head and "not" not in head.lower():
        fail("docs/23 head claims U3 complete")
    if "U3" not in text or "C3" not in text:
        fail("docs/23 must retain U3/C3 catalog")
    if "all-or-none" not in text and "all-or-none" not in read_text(DOC07):
        fail("docs must describe C1 all-or-none TX contract for U3")
    d7 = read_text(DOC07)
    if "partial TX" in d7 and "all-or-none" not in d7:
        fail("docs/07 still says partial TX without all-or-none")


def check_header_api() -> None:
    text = read_text(SESSION_H)
    for tok in REQUIRED_HEADER_TOKENS:
        if tok not in text:
            fail(f"control_session.h missing required token: {tok}")
    if "8192" not in text:
        fail("ingress/tx byte cap 8192 missing from header")
    check_includes(SESSION_H)
    if "byte_stream.h" not in text:
        fail("control_session.h must include C1 byte_stream.h")
    if "control_frame_codec.h" not in text:
        fail("control_session.h must include C2 control_frame_codec.h")


def check_source() -> None:
    text = read_text(SESSION_C)
    for tok in REQUIRED_SOURCE_TOKENS:
        if tok not in text:
            fail(f"control_session.c missing required token: {tok}")
    check_includes(SESSION_C)
    check_no_heap_vla(SESSION_C)
    code = strip_c_comments_and_strings(text)
    if "bound_generation" not in code:
        fail("bound_generation missing from production code")
    if "GENERATION_MISMATCH" not in code:
        fail("GENERATION_MISMATCH path missing from production code")
    if "RX_OVERFLOW" not in code:
        fail("RX_OVERFLOW fence path missing from production code")
    if "WRONG_OWNER" not in code:
        fail("WRONG_OWNER path missing from production code")
    if re.search(r"\bHELLO_OK\b|\bNCL1\b|\bsession_cookie\b", code):
        fail("U3 production source must not implement HELLO/NCL1/cookie")
    # Test seam definition must be under #if defined(SEAM)
    if not re.search(
        r"#\s*if\s+defined\s*\(\s*NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM\s*\)[\s\S]*?"
        + re.escape(SEAM_SYMBOL),
        text,
    ):
        fail("test seam definition must be under NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM")
    # Double-generation ticket
    if "g1" not in code or "g2" not in code:
        fail("generation ticket must use g1/g2 double snapshot")


def check_tests_off_seam_absent() -> None:
    """Build tests-OFF private archive and prove seam symbol is absent."""
    with tempfile.TemporaryDirectory(prefix="u3-seam-absent-") as td:
        build = pathlib.Path(td) / "build"
        cfg = subprocess.run(
            [
                "cmake",
                "-S",
                str(REPO_ROOT),
                "-B",
                str(build),
                "-DCMAKE_BUILD_TYPE=Release",
                "-DNINLIL_BUILD_TESTS=OFF",
            ],
            capture_output=True,
            text=True,
        )
        if cfg.returncode != 0:
            fail(f"tests-OFF configure failed:\n{cfg.stdout}\n{cfg.stderr}")
        bld = subprocess.run(
            ["cmake", "--build", str(build), "--target", "ninlil_runtime_private", "--parallel"],
            capture_output=True,
            text=True,
        )
        if bld.returncode != 0:
            fail(f"tests-OFF private build failed:\n{bld.stdout}\n{bld.stderr}")
        archives = list(build.rglob("libninlil_runtime_private.a"))
        if not archives:
            fail("tests-OFF private archive not found")
        nm = subprocess.run(
            ["nm", "-g", str(archives[0])],
            capture_output=True,
            text=True,
        )
        if nm.returncode != 0:
            fail(f"nm failed: {nm.stderr}")
        if SEAM_SYMBOL in nm.stdout or SEAM_SYMBOL in nm.stderr:
            fail(f"test seam symbol present in tests-OFF archive: {SEAM_SYMBOL}")
        if "ninlil_ctrl_session_pump" not in nm.stdout and "ninlil_ctrl_session_pump" not in nm.stderr:
            # Apple nm prefixes with _
            if "_ninlil_ctrl_session_pump" not in nm.stdout:
                fail("ctrl_session_pump missing from tests-OFF archive")


def check(root: pathlib.Path | None = None, *, run_archive_probe: bool = True) -> None:
    global SESSION_H, SESSION_C, C1_H, CODEC_H, PRIVATE_AUTH, CMAKE_LISTS, DOC23, DOC07, PUBLIC_INCLUDE
    if root is not None:
        SESSION_H = root / "src" / "transport" / "control_session.h"
        SESSION_C = root / "src" / "transport" / "control_session.c"
        C1_H = root / "src" / "transport" / "byte_stream.h"
        CODEC_H = root / "src" / "model" / "control_frame_codec.h"
        PRIVATE_AUTH = root / "cmake" / "ninlil_runtime_private_sources.cmake"
        CMAKE_LISTS = root / "CMakeLists.txt"
        DOC23 = root / "docs" / "23-usb-radio-boundary.md"
        DOC07 = root / "docs" / "07-testing-and-quality.md"
        PUBLIC_INCLUDE = root / "include" / "ninlil"

    if not C1_H.is_file():
        fail("C1 byte_stream.h missing")
    if not CODEC_H.is_file():
        fail("C2 control_frame_codec.h missing")
    check_header_api()
    check_source()
    check_authority()
    check_cmake_test_seam_define()
    check_public_abi_clean()
    check_docs_nonclaims()
    if run_archive_probe and root is None:
        check_tests_off_seam_absent()
    print("control_session_u3_gate: OK")


def _copy_tree(dst: pathlib.Path) -> None:
    for rel in (
        "src/transport/control_session.h",
        "src/transport/control_session.c",
        "src/transport/byte_stream.h",
        "src/model/control_frame_codec.h",
        "cmake/ninlil_runtime_private_sources.cmake",
        "CMakeLists.txt",
        "docs/23-usb-radio-boundary.md",
        "docs/07-testing-and-quality.md",
    ):
        src = REPO_ROOT / rel
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
    pub = dst / "include" / "ninlil"
    pub.mkdir(parents=True, exist_ok=True)
    for p in (REPO_ROOT / "include" / "ninlil").glob("*.h"):
        shutil.copy2(p, pub / p.name)


def self_test() -> None:
    def mut_drop_pump(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("ninlil_ctrl_session_pump", "ninlil_ctrl_session_Xpump"), encoding="utf-8")

    def mut_drop_authority(root: pathlib.Path) -> None:
        p = root / "cmake" / "ninlil_runtime_private_sources.cmake"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("src/transport/control_session.c\n", ""), encoding="utf-8")

    def mut_drop_gen_fence(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("GENERATION_MISMATCH", "GEN_X_MISMATCH"), encoding="utf-8")

    def mut_heap(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\nvoid *bad(void){return malloc(1);}\n", encoding="utf-8")

    def mut_public_leak(root: pathlib.Path) -> None:
        p = root / "include" / "ninlil" / "runtime.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\n/* control_session leak */\n", encoding="utf-8")

    def mut_hello_in_u3(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\nstatic int HELLO_OK = 1;\n", encoding="utf-8")

    def mut_drop_ingress_cap(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP", "NINLIL_CTRL_SESSION_INGRESS_BYTE_X"),
            encoding="utf-8",
        )

    def mut_ungate_seam(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace(
                "#if defined(NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM)",
                "#if 1 /* mutated unguarded seam */",
            ),
            encoding="utf-8",
        )

    def mut_drop_g1g2(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("g1/link/g2", "gen-ticket"), encoding="utf-8")

    def mut_drop_read_over_cap(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("read OK length > capacity", "read length bad"),
            encoding="utf-8",
        )

    def mut_drop_feed_residual(root: pathlib.Path) -> None:
        p = root / "src" / "transport" / "control_session.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("feed guard residual not consumed", "feed residual ok"),
            encoding="utf-8",
        )

    def mut_drop_cmake_seam(root: pathlib.Path) -> None:
        p = root / "CMakeLists.txt"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM=1", "NINLIL_CTRL_SESSION_SEAM_OFF=1"),
            encoding="utf-8",
        )

    mutations = [
        ("drop pump API token", mut_drop_pump),
        ("drop private authority entry", mut_drop_authority),
        ("drop generation fence path", mut_drop_gen_fence),
        ("inject malloc", mut_heap),
        ("public header control_session mention", mut_public_leak),
        ("HELLO_OK in U3 production", mut_hello_in_u3),
        ("drop ingress byte cap token", mut_drop_ingress_cap),
        ("unguard test seam definition", mut_ungate_seam),
        ("drop g1/g2 ticket hint", mut_drop_g1g2),
        ("drop read over-capacity fence token", mut_drop_read_over_cap),
        ("drop feed residual fence token", mut_drop_feed_residual),
        ("drop cmake TEST_SEAM define", mut_drop_cmake_seam),
    ]

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td) / "clean"
        root.mkdir()
        _copy_tree(root)
        check(root, run_archive_probe=False)

    for name, mut in mutations:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "mut"
            root.mkdir()
            _copy_tree(root)
            mut(root)
            try:
                check(root, run_archive_probe=False)
            except GateFailure:
                print(f"mutation caught: {name}")
                continue
            raise SystemExit(f"mutation NOT caught: {name}")

    print(f"control_session_u3_gate self-test: {len(mutations)} mutations caught")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print("usage: control_session_u3_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "check":
            check()
        else:
            self_test()
    except GateFailure as e:
        print(f"control_session_u3_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
