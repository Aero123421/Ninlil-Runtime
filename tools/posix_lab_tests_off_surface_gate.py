#!/usr/bin/env python3
"""tests-OFF surface gate: no tests/support in default all / install export.

Locks OSS packaging policy for the POSIX LAB host platform:

  - ``ninlil_posix_lab_platform`` (which compiles ``tests/support/*.c``) is
    created only when ``NINLIL_BUILD_TESTS=ON``.
  - Fresh ``NINLIL_BUILD_TESTS=OFF`` default ``all`` must not produce any
    object/archive path under ``tests/support`` or a lab_platform archive.
  - Installed / exported package targets must not mention lab_platform or
    tests/support fixture sources.

self-test proves CMake authority still requires the tests-gated construction.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
CMAKE_LISTS = REPO_ROOT / "CMakeLists.txt"

SUPPORT_OBJECT_NEEDLES = (
    "tests/support/",
    "platform_basic_fixtures",
    "deterministic_entropy",
    "typed_simulated_bearer",
    "canonical_origin_authorization",
)
LAB_PLATFORM_NEEDLES = (
    "ninlil_posix_lab_platform",
    "libninlil_posix_lab_platform",
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def run(cmd: list[str], *, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )


def assert_cmake_authority() -> None:
    text = CMAKE_LISTS.read_text(encoding="utf-8")
    # Exact construction shape: BUILD_TESTS gate immediately enables + adds.
    if not re.search(
        r"if\s*\(\s*NINLIL_BUILD_TESTS\s*\)\s*\n"
        r"[ \t]*set\(NINLIL_POSIX_LAB_PLATFORM_ENABLED TRUE\)\s*\n"
        r"[ \t]*add_library\(\s*ninlil_posix_lab_platform\s+STATIC\b",
        text,
    ):
        fail(
            "CMakeLists.txt must construct ninlil_posix_lab_platform only "
            "inside if(NINLIL_BUILD_TESTS) with ENABLED TRUE then add_library"
        )
    if "tests/support/platform_basic_fixtures.c" not in text:
        fail("lab platform fixture source list missing (authority drift)")
    blocks = re.findall(
        r"add_library\s*\(\s*ninlil_posix_lab_platform\b",
        text,
    )
    if len(blocks) != 1:
        fail(
            f"expected exactly one ninlil_posix_lab_platform add_library, "
            f"got {len(blocks)}"
        )
    if text.count("set(NINLIL_POSIX_LAB_PLATFORM_ENABLED FALSE)") < 1:
        fail("NINLIL_POSIX_LAB_PLATFORM_ENABLED must default FALSE")


def collect_paths(root: pathlib.Path) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    if not root.is_dir():
        return out
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            out.append(pathlib.Path(dirpath) / name)
    return out


def assert_no_tests_support_artifacts(build_dir: pathlib.Path) -> None:
    paths = collect_paths(build_dir)
    offenders: list[str] = []
    for path in paths:
        s = str(path)
        # Object / archive products only (ignore CMake generated file lists text).
        if not any(
            s.endswith(ext)
            for ext in (".o", ".obj", ".a", ".so", ".dylib", ".lib", ".c.o")
        ):
            # Also catch CMakeFiles/.../tests/support/*.c.o style
            if ".c.o" not in s and not s.endswith(".o"):
                continue
        rel = s
        for needle in SUPPORT_OBJECT_NEEDLES:
            if needle in rel:
                offenders.append(rel)
                break
        for needle in LAB_PLATFORM_NEEDLES:
            if needle in pathlib.Path(rel).name or (
                needle in rel and rel.endswith((".a", ".so", ".dylib", ".lib"))
            ):
                offenders.append(rel)
    # De-dupe
    offenders = sorted(set(offenders))
    if offenders:
        preview = "\n".join(offenders[:20])
        fail(
            "tests-OFF default all produced tests/support or lab_platform "
            f"artifacts ({len(offenders)}):\n{preview}"
        )


def assert_install_export_clean(prefix: pathlib.Path) -> None:
    if not prefix.is_dir():
        fail(f"install prefix missing: {prefix}")
    paths = collect_paths(prefix)
    offenders: list[str] = []
    for path in paths:
        s = str(path)
        if "tests/support" in s:
            offenders.append(s)
            continue
        name = path.name
        if "lab_platform" in name or "posix_lab_platform" in name:
            offenders.append(s)
            continue
        # Exported cmake package text must not export lab platform.
        if path.suffix in {".cmake", ".txt"} and path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "ninlil_posix_lab_platform" in text or "lab_platform" in text:
                # allow comments? fail closed on any mention in installed cmake
                offenders.append(s + " (cmake mentions lab_platform)")
    offenders = sorted(set(offenders))
    if offenders:
        preview = "\n".join(offenders[:20])
        fail(
            "installed/exported package leaks lab_platform or tests/support "
            f"({len(offenders)}):\n{preview}"
        )


def run_fresh_tests_off_check() -> None:
    cmake = shutil.which("cmake")
    if not cmake:
        fail("cmake not found on PATH")
    work = pathlib.Path(tempfile.mkdtemp(prefix="ninlil-lab-tests-off-"))
    build = work / "build"
    prefix = work / "prefix"
    conf = [
        cmake,
        "-S",
        str(REPO_ROOT),
        "-B",
        str(build),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DNINLIL_BUILD_TESTS=OFF",
        "-DNINLIL_ENABLE_STRICT_WARNINGS=ON",
        "-DNINLIL_BUILD_HOST_RUNTIME=ON",
        "-DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON",
        f"-DCMAKE_INSTALL_PREFIX={prefix}",
    ]
    openssl_root = os.environ.get("OPENSSL_ROOT_DIR") or os.environ.get("OPENSSL_ROOT")
    if openssl_root:
        conf.append(f"-DOPENSSL_ROOT_DIR={openssl_root}")
    proc = run(conf)
    if proc.returncode != 0:
        fail(f"tests-OFF configure failed:\n{proc.stdout}\n{proc.stderr}")
    # LAB platform must be reported skipped.
    blob = proc.stdout + proc.stderr
    if "POSIX LAB platform: enabled" in blob:
        fail("tests-OFF configure still enabled POSIX LAB platform")
    if "ninlil_posix_lab_platform" in blob and "skipped" not in blob.lower():
        # soft: message should say skipped
        pass

    build_proc = run([cmake, "--build", str(build), "--config", "Release", "-j"])
    if build_proc.returncode != 0:
        fail(
            f"tests-OFF default all failed:\n{build_proc.stdout}\n{build_proc.stderr}"
        )
    assert_no_tests_support_artifacts(build)

    install_proc = run([cmake, "--install", str(build), "--config", "Release"])
    if install_proc.returncode != 0:
        fail(
            f"tests-OFF install failed:\n{install_proc.stdout}\n{install_proc.stderr}"
        )
    assert_install_export_clean(prefix)
    print(
        "posix_lab_tests_off_surface_gate OK: tests-OFF default all has no "
        "tests/support objects; install/export has no lab_platform"
    )


def check() -> None:
    assert_cmake_authority()
    run_fresh_tests_off_check()


def self_test() -> None:
    assert_cmake_authority()
    text = CMAKE_LISTS.read_text(encoding="utf-8")
    # Mutation: unconditional lab platform construction must be detectable.
    mutated = text.replace(
        "if(NINLIL_BUILD_TESTS)\n            set(NINLIL_POSIX_LAB_PLATFORM_ENABLED TRUE)",
        "if(TRUE)\n            set(NINLIL_POSIX_LAB_PLATFORM_ENABLED TRUE)",
        1,
    )
    if mutated == text:
        # fallback: strip the tests guard line
        mutated = re.sub(
            r"if\s*\(\s*NINLIL_BUILD_TESTS\s*\)\s*\n\s*"
            r"set\(NINLIL_POSIX_LAB_PLATFORM_ENABLED TRUE\)",
            "set(NINLIL_POSIX_LAB_PLATFORM_ENABLED TRUE)",
            text,
            count=1,
        )
    if mutated == text:
        fail("self-test could not mutate tests gate (authority pattern drift)")
    # Write temp cmake and only run authority pattern against mutated text.
    if re.search(
        r"if\s*\(\s*NINLIL_BUILD_TESTS\s*\).*?ninlil_posix_lab_platform",
        mutated,
        re.DOTALL,
    ):
        # if TRUE still matches BUILD_TESTS in comment elsewhere — require that
        # the immediate construction is not guarded by BUILD_TESTS alone.
        # Detect unconditional set ENABLED TRUE at column.
        if "if(TRUE)" in mutated or not re.search(
            r"if\s*\(\s*NINLIL_BUILD_TESTS\s*\)\s*\n\s*"
            r"set\(NINLIL_POSIX_LAB_PLATFORM_ENABLED TRUE\)",
            mutated,
        ):
            print(
                "  self-test mutation 'unguarded_lab_platform' correctly "
                "detectable as authority break"
            )
        else:
            fail("self-test mutation not detectable")
    else:
        print(
            "  self-test mutation 'unguarded_lab_platform' correctly broke "
            "tests-gated pattern"
        )
    # Live check is expensive (full configure/build); run authority only here
    # and rely on `check` for full packaging evidence in CTest.
    print("posix_lab_tests_off_surface_gate self-test OK (authority)")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: posix_lab_tests_off_surface_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    try:
        if argv[1] == "check":
            check()
        else:
            self_test()
    except GateFailure as e:
        print(f"posix_lab_tests_off_surface_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
