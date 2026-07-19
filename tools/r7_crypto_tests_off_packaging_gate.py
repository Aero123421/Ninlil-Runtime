#!/usr/bin/env python3
"""R7 T0 tests-OFF Release packaging gate (docs/31 §10–11 / ADR-0011).

Fresh isolated OFF Release subbuild (never reuses a parent tests-ON tree):
  1. configure NINLIL_BUILD_TESTS=OFF + CMAKE_BUILD_TYPE=Release + strict
  2. prove ctest -N reports zero tests
  3. bare `all` → private archive path-count exact 0
  4. explicit --target ninlil_runtime_private → path-count exact 1
  5. ar members: r7 portable/nonce/openssl3 exact once each;
     mbedtls / test / oracle / generated / test-seam basenames = 0
  6. nm on that fresh OFF private archive: no TEST_BUILD seam /
     test / oracle / fixture defined symbols (tests-ON may contain seams;
     never reuse a tests-ON archive as evidence)
  7. temp install: path bans + nm every installed static/shared library for
     public leakage of ninlil_r7_crypto_ / ninlil_r7_mbedtls_ / provider
     factory / private seam symbols (platform nm failure = fail closed)

Self-test mutations (must go red, not configure-fail alone as catch for
inspection mutations):
  - multi-line install(FILES private header...) structural detection
  - missing / duplicate archive members
  - seam / test / oracle / generated member contamination
  - injected nm symbol list for TEST_BUILD seam in OFF archive
  - public installed library nm private-symbol contamination
  - Host/ESP adapter swap in production set
  - ambiguous private archive (0 or 2+ paths after explicit)
  - CI macOS OpenSSL must use shell $OPENSSL_ROOT (not ${{ env.* }})

PASS ≠ product GO / R7 complete / ESP HIL / T0 accepted.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Iterable

REPO = Path(__file__).resolve().parents[1]

R7_REQUIRED_MEMBERS = (
    "r7_crypto_portable.c.o",
    "r7_crypto_nonce.c.o",
    "r7_crypto_openssl3.c.o",
)

# Basename substrings / exact basenames that must never appear in the
# production private archive under tests-OFF.
BANNED_MEMBER_NEEDLES = (
    "mbedtls",
    "r7_crypto_mbedtls",
    "fixture",
    "oracle",
    "spy",
    "testbuild",
    "generated",
    ".gen.",
    "r7_crypto_vectors",
    "r7_crypto_portable_test",
    "r7_crypto_openssl3_test",
    "r7_crypto_vectors_bridge",
    "test_spans_forbidden",
)

# Exact defined symbols forbidden in tests-OFF private archive (TEST_BUILD
# seams and other non-production inspection hooks). tests-ON may define these.
BANNED_OFF_ARCHIVE_SYMBOLS = frozenset(
    {
        "ninlil_r7_crypto_test_spans_forbidden",
    }
)

# Substring needles on defined symbol names for tests-OFF private archive.
# Catches renamed seams / oracle / fixture / spy symbols that still leak.
BANNED_OFF_ARCHIVE_SYMBOL_NEEDLES = (
    "test_spans_forbidden",
    "testbuild",
    "test_build",
    "fixture",
    "oracle",
    "spy",
    "vectors_bridge",
    "r7_crypto_portable_test",
    "r7_crypto_openssl3_test",
)

# Defined symbols / prefixes that must never appear in public installed libs.
# Private production symbols live only in ninlil_runtime_private (not installed).
BANNED_PUBLIC_LIB_SYMBOL_PREFIXES = (
    "ninlil_r7_crypto_",
    "ninlil_r7_mbedtls_",
)

BANNED_PUBLIC_LIB_SYMBOLS = frozenset(
    {
        "ninlil_r7_crypto_test_spans_forbidden",
        "ninlil_r7_crypto_openssl3_provider_init",
        "ninlil_r7_crypto_mbedtls_provider_init",
        "ninlil_r7_crypto_provider_validate",
    }
)

# Paths/tokens that must not land in the public install tree.
BANNED_INSTALL_NEEDLES = (
    "r7_crypto",
    "r7_crypto_provider.h",
    "r7_crypto_openssl3.h",
    "r7_crypto_mbedtls",
    "r7_crypto_vectors",
    "tests/radio/private",
    "libninlil_runtime_private",
    "ninlil_runtime_private",
)

PRIVATE_ARCHIVE_RE = re.compile(r"libninlil_runtime_private\.(a|lib)$")
INSTALLED_LIB_RE = re.compile(
    r".*\.(a|lib|so|dylib)$|.*\.so\.\d+(\.\d+)*$"
)
_NM_TYPE_RE = re.compile(r"^[A-Za-z]$")
# GITHUB expression that freezes env before GITHUB_ENV is visible in the shell.
_CI_OPENSSL_ENV_EXPR = re.compile(
    r"\$\{\{\s*env\.OPENSSL_ROOT(_DIR)?\s*\}\}"
)


def fail(msg: str) -> None:
    print(f"r7_crypto_tests_off_packaging_gate FAIL: {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"r7_crypto_tests_off_packaging_gate: {msg}")


def collect_private_archives(root: Path) -> list[Path]:
    """Exact path-count policy (no realpath collapse). Each GLOB path counts."""
    found: list[Path] = []
    if not root.is_dir():
        return found
    for path in root.rglob("*ninlil_runtime_private*"):
        if PRIVATE_ARCHIVE_RE.search(path.name):
            found.append(path)
    return sorted(found)


def ar_members(archive: Path) -> list[str]:
    out = subprocess.check_output(["ar", "t", str(archive)], stderr=subprocess.STDOUT)
    return [line for line in out.decode("utf-8", errors="replace").splitlines() if line]


def member_basename(member: str) -> str:
    return Path(member).name


def inspect_archive_members(members: Iterable[str]) -> list[str]:
    """Validate production R7 members: exact once portable/nonce/openssl3."""
    errors: list[str] = []
    basenames = [member_basename(m) for m in members]
    for required in R7_REQUIRED_MEMBERS:
        count = basenames.count(required)
        if count != 1:
            errors.append(
                f"archive member {required}: expected exact once, got {count}"
            )
    for base in basenames:
        lower = base.lower()
        for needle in BANNED_MEMBER_NEEDLES:
            if needle.lower() in lower:
                errors.append(f"banned archive member basename: {base} ({needle})")
                break
    # Host/ESP split: mbedTLS object must never appear on Host production archive.
    for base in basenames:
        if "mbedtls" in base.lower() or base == "r7_crypto_mbedtls.c.o":
            if f"banned archive member basename: {base}" not in "\n".join(errors):
                errors.append(f"ESP mbedTLS adapter in Host archive: {base}")
    return errors


def normalize_nm_symbol(name: str) -> str:
    """Strip exactly one Mach-O leading underscore when present (fail-closed)."""
    n = name.strip()
    if n.startswith("_"):
        return n[1:]
    return n


def parse_nm_defined_symbols(stdout: str) -> set[str]:
    """Parse `nm -g` (or `nm`) output into defined C symbol names.

    Platform layouts (GNU / Apple llvm-nm) are accepted. Undefined U/w/v are
    ignored for ban checks. Member banners are skipped. Fail-closed callers
    must treat empty parse + nm failure separately.
    """
    defined: set[str] = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and not any(ch.isspace() for ch in stripped):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
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
        if type_token in ("U", "w", "v"):
            continue
        norm = normalize_nm_symbol(name)
        if norm:
            defined.add(norm)
    return defined


def run_nm_defined(path: Path) -> tuple[set[str] | None, list[str]]:
    """Run nm -g on archive/object/lib. Returns (defined, errors).

    Missing nm or nonzero exit is fail-closed (defined=None + error list).
    """
    nm = shutil.which("nm")
    if not nm:
        return None, ["nm executable missing (fail closed)"]
    try:
        proc = subprocess.run(
            [nm, "-g", str(path)],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        return None, [f"nm launch failed on {path}: {exc}"]
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        return None, [f"nm -g nonzero exit {proc.returncode} on {path}: {err}"]
    text = (proc.stdout or b"").decode("utf-8", errors="replace")
    return parse_nm_defined_symbols(text), []


def inspect_off_archive_symbols(defined: Iterable[str]) -> list[str]:
    """tests-OFF private archive must not define TEST_BUILD/seam/test/oracle."""
    errors: list[str] = []
    names = set(defined)
    for sym in sorted(BANNED_OFF_ARCHIVE_SYMBOLS):
        if sym in names:
            errors.append(
                f"tests-OFF private archive defines forbidden TEST_BUILD seam: {sym}"
            )
    for sym in sorted(names):
        lower = sym.lower()
        for needle in BANNED_OFF_ARCHIVE_SYMBOL_NEEDLES:
            if needle.lower() in lower:
                # Avoid double-reporting exact-set hits.
                if sym in BANNED_OFF_ARCHIVE_SYMBOLS:
                    break
                errors.append(
                    f"tests-OFF private archive defines banned symbol "
                    f"{sym} (needle={needle})"
                )
                break
    return errors


def inspect_public_lib_symbols(defined: Iterable[str], *, lib_label: str) -> list[str]:
    """Installed public static/shared libs must not export private R7 symbols."""
    errors: list[str] = []
    names = set(defined)
    for sym in sorted(names):
        if sym in BANNED_PUBLIC_LIB_SYMBOLS:
            errors.append(
                f"installed public library {lib_label} defines private R7 "
                f"symbol: {sym}"
            )
            continue
        for prefix in BANNED_PUBLIC_LIB_SYMBOL_PREFIXES:
            if sym.startswith(prefix):
                errors.append(
                    f"installed public library {lib_label} defines private R7 "
                    f"prefix {prefix!r}: {sym}"
                )
                break
    return errors


def collect_installed_libraries(prefix: Path) -> list[Path]:
    """All installed static/shared libraries under install prefix."""
    found: list[Path] = []
    if not prefix.is_dir():
        return found
    for path in prefix.rglob("*"):
        if not path.is_file() and not path.is_symlink():
            continue
        # Skip private archive identity (also path-banned separately).
        name = path.name
        if PRIVATE_ARCHIVE_RE.search(name):
            continue
        # Match common library suffixes; reject bare non-lib files.
        if INSTALLED_LIB_RE.fullmatch(name) or name.endswith(
            (".a", ".lib", ".so", ".dylib")
        ):
            found.append(path)
            continue
        # libfoo.so.1.2.3 style without matching fullmatch edge cases
        if re.search(r"\.so(\.\d+)+$", name):
            found.append(path)
    return sorted(found)


def inspect_install_tree(prefix: Path) -> list[str]:
    errors: list[str] = []
    if not prefix.is_dir():
        return [f"install prefix missing: {prefix}"]
    for path in prefix.rglob("*"):
        if not path.is_file() and not path.is_symlink():
            # Still scan directory names for private archive dirs etc.
            rel = str(path.relative_to(prefix)).replace("\\", "/")
            for needle in BANNED_INSTALL_NEEDLES:
                if needle in rel:
                    errors.append(f"install path contains private R7 token {needle}: {rel}")
                    break
            continue
        rel = str(path.relative_to(prefix)).replace("\\", "/")
        lower = rel.lower()
        for needle in BANNED_INSTALL_NEEDLES:
            if needle.lower() in lower:
                errors.append(f"install tree private R7 leak {needle}: {rel}")
                break
        # Extra: private headers by basename even if relocated oddly.
        name = path.name.lower()
        if name in {
            "r7_crypto_provider.h",
            "r7_crypto_openssl3.h",
            "r7_crypto_mbedtls.h",
            "r7_crypto_vectors.json",
            "r7_crypto_vectors.gen.h",
            "r7_crypto_portable.c",
            "r7_crypto_nonce.c",
            "r7_crypto_openssl3.c",
            "r7_crypto_mbedtls.c",
            "libninlil_runtime_private.a",
            "libninlil_runtime_private.lib",
        }:
            errors.append(f"install tree private R7 basename: {rel}")

    # Symbol inspection of every installed static/shared library (path-clean
    # public libninlil.a that still carries private R7 text is a false-green
    # if only paths are checked).
    for lib in collect_installed_libraries(prefix):
        rel = str(lib.relative_to(prefix)).replace("\\", "/")
        defined, nm_errs = run_nm_defined(lib)
        if nm_errs or defined is None:
            for e in nm_errs or ["nm produced no result"]:
                errors.append(f"install lib nm fail-closed {rel}: {e}")
            continue
        errors.extend(inspect_public_lib_symbols(defined, lib_label=rel))
    return errors


def _ci_code_without_comments(ci_text: str) -> str:
    """Drop full-line '#' comments so structural bans ignore documentation."""
    lines: list[str] = []
    for line in ci_text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def inspect_ci_openssl_structure(ci_text: str) -> list[str]:
    """macOS jobs must forward GITHUB_ENV OPENSSL via shell, not ${{ env }}."""
    errors: list[str] = []
    code = _ci_code_without_comments(ci_text)
    if _CI_OPENSSL_ENV_EXPR.search(code):
        errors.append(
            "ci.yml uses ${{ env.OPENSSL_ROOT }} (or _DIR); macOS jobs must "
            "pass shell \"$OPENSSL_ROOT\" from GITHUB_ENV into cmake"
        )
    # Positive evidence: shell form present when OPENSSL_ROOT is written.
    if "OPENSSL_ROOT=" in code and 'OPENSSL_ROOT_DIR="$OPENSSL_ROOT"' not in code:
        # Allow OPENSSL_ROOT_DIR=$OPENSSL_ROOT without quotes only if shell form.
        if "-DOPENSSL_ROOT_DIR=$OPENSSL_ROOT" not in code and (
            '-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT"' not in code
        ):
            errors.append(
                "ci.yml sets OPENSSL_ROOT but cmake lacks "
                '-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" shell form'
            )
    return errors


def cmake_install_call_bodies(text: str) -> list[str]:
    bodies: list[str] = []
    for match in re.finditer(r"\binstall\s*\(", text, re.IGNORECASE):
        start = match.end()
        depth = 1
        i = start
        n = len(text)
        while i < n and depth > 0:
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth == 0:
            bodies.append(text[start : i - 1])
    return bodies


def inspect_cmake_install_rules(cmake_text: str) -> list[str]:
    """Multi-line install(FILES private...) detection (false-green fix)."""
    errors: list[str] = []
    needles = (
        "r7_crypto",
        "tests/radio/private",
        "r7_crypto_vectors",
        "r7_crypto_provider.h",
        "r7_crypto_openssl3.h",
        "r7_crypto_mbedtls",
        "libninlil_runtime_private",
    )
    for index, body in enumerate(cmake_install_call_bodies(cmake_text), 1):
        lower = body.lower()
        for needle in needles:
            if needle.lower() in lower:
                errors.append(
                    f"CMake install() call #{index} ships private R7 token: {needle}"
                )
                break
    return errors


def parse_ctest_total(text: str) -> int | None:
    m = re.search(r"Total Tests:\s*([0-9]+)", text)
    if m:
        return int(m.group(1))
    if "No tests were found" in text:
        return 0
    return None


def run_cmd(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def which_cmake() -> str:
    cmake = shutil.which("cmake")
    if not cmake:
        raise RuntimeError("cmake not found on PATH")
    return cmake


def which_ctest() -> str:
    ctest = shutil.which("ctest")
    if not ctest:
        raise RuntimeError("ctest not found on PATH")
    return ctest


def run_fresh_packaging_check(
    src_root: Path,
    *,
    generator: str | None = None,
    keep_work: bool = False,
) -> int:
    """Full fresh OFF Release evidence. Returns process exit code."""
    cmake = which_cmake()
    ctest = which_ctest()
    work = Path(tempfile.mkdtemp(prefix="r7-tests-off-packaging-"))
    build = work / "build"
    prefix = work / "install"
    try:
        gen = generator or os.environ.get("CMAKE_GENERATOR") or "Unix Makefiles"
        ok(f"fresh OFF Release under {work} (generator={gen})")
        conf_argv = [
            cmake,
            "-S",
            str(src_root),
            "-B",
            str(build),
            "-G",
            gen,
            "-DCMAKE_BUILD_TYPE=Release",
            "-DNINLIL_BUILD_TESTS=OFF",
            "-DNINLIL_ENABLE_STRICT_WARNINGS=ON",
            "-DNINLIL_ENABLE_SANITIZERS=OFF",
        ]
        # macOS Homebrew OpenSSL 3 is not on the default search path; CI exports
        # OPENSSL_ROOT / OPENSSL_ROOT_DIR. Forward so the nested OFF configure
        # fails closed for the same reason as the parent job, not by discovery.
        openssl_root = os.environ.get("OPENSSL_ROOT_DIR") or os.environ.get(
            "OPENSSL_ROOT"
        )
        if openssl_root:
            conf_argv.append(f"-DOPENSSL_ROOT_DIR={openssl_root}")
        conf = run_cmd(conf_argv)
        if conf.returncode != 0:
            fail(
                "configure failed:\n"
                f"{conf.stdout}\n{conf.stderr}"
            )
            return 1

        # Host CMake install rules must not ship private R7 (multi-line aware).
        cmake_lists = (src_root / "CMakeLists.txt").read_text(encoding="utf-8")
        install_errs = inspect_cmake_install_rules(cmake_lists)
        if install_errs:
            for e in install_errs:
                fail(e)
            return 1

        # Source authority: Host production must carry openssl3 not mbedtls.
        authority = (
            src_root / "cmake" / "ninlil_r7_crypto_sources.cmake"
        ).read_text(encoding="utf-8")
        if "src/radio/r7_crypto_openssl3.c" not in authority:
            fail("authority missing Host OpenSSL adapter source")
            return 1
        if "ports/esp-idf/src/r7_crypto_mbedtls.c" not in authority:
            fail("authority missing ESP mbedTLS adapter source (split proof)")
            return 1

        listing = run_cmd([ctest, "-N"], cwd=build)
        if listing.returncode != 0:
            fail(f"ctest -N failed:\n{listing.stdout}\n{listing.stderr}")
            return 1
        total = parse_ctest_total(listing.stdout + listing.stderr)
        if total is None:
            fail(
                "cannot parse ctest -N output "
                f"(need Total Tests: 0 or No tests were found):\n"
                f"{listing.stdout}\n{listing.stderr}"
            )
            return 1
        if total != 0:
            fail(f"ctest -N reported Total Tests: {total} (expected 0 under OFF)")
            return 1

        all_build = run_cmd(
            [cmake, "--build", str(build), "--config", "Release"]
        )
        if all_build.returncode != 0:
            fail(f"default all build failed:\n{all_build.stdout}\n{all_build.stderr}")
            return 1
        after_all = collect_private_archives(build)
        if len(after_all) != 0:
            fail(
                "EXCLUDE_FROM_ALL broken — after bare all, "
                f"libninlil_runtime_private path count must be 0, got "
                f"{len(after_all)}: {after_all}"
            )
            return 1

        priv_build = run_cmd(
            [
                cmake,
                "--build",
                str(build),
                "--config",
                "Release",
                "--target",
                "ninlil_runtime_private",
            ]
        )
        if priv_build.returncode != 0:
            fail(
                "explicit ninlil_runtime_private build failed:\n"
                f"{priv_build.stdout}\n{priv_build.stderr}"
            )
            return 1
        after_explicit = collect_private_archives(build)
        if len(after_explicit) != 1:
            fail(
                "after explicit --target ninlil_runtime_private, "
                "libninlil_runtime_private path count must be exactly 1, got "
                f"{len(after_explicit)}: {after_explicit} "
                "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)"
            )
            return 1
        archive = after_explicit[0]
        try:
            members = ar_members(archive)
        except (OSError, subprocess.CalledProcessError) as exc:
            fail(f"ar t failed on {archive}: {exc}")
            return 1
        member_errs = inspect_archive_members(members)
        if member_errs:
            for e in member_errs:
                fail(e)
            return 1

        # nm on this fresh OFF archive only — never a parent tests-ON archive.
        defined, nm_errs = run_nm_defined(archive)
        if nm_errs or defined is None:
            for e in nm_errs or ["nm produced no result"]:
                fail(f"private archive nm fail-closed: {e}")
            return 1
        sym_errs = inspect_off_archive_symbols(defined)
        if sym_errs:
            for e in sym_errs:
                fail(e)
            return 1

        # CI structural: GITHUB_ENV OpenSSL must not use ${{ env.OPENSSL_* }}.
        ci_yml = src_root / ".github" / "workflows" / "ci.yml"
        if ci_yml.is_file():
            ci_errs = inspect_ci_openssl_structure(
                ci_yml.read_text(encoding="utf-8")
            )
            if ci_errs:
                for e in ci_errs:
                    fail(e)
                return 1

        prefix.mkdir(parents=True, exist_ok=True)
        inst = run_cmd(
            [
                cmake,
                "--install",
                str(build),
                "--prefix",
                str(prefix),
                "--config",
                "Release",
            ]
        )
        if inst.returncode != 0:
            fail(f"install failed:\n{inst.stdout}\n{inst.stderr}")
            return 1
        install_errs = inspect_install_tree(prefix)
        if install_errs:
            for e in install_errs:
                fail(e)
            return 1

        ok(
            "PASS (fresh OFF Release; ctest-N=0; bare-all archive=0; "
            "explicit path-count=1; R7 members portable/nonce/openssl3 exact once; "
            "nm: no TEST_BUILD/seam/oracle/fixture; install public-only + nm clean)"
        )
        return 0
    finally:
        if keep_work:
            ok(f"kept work tree at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


def _mutation(
    name: str,
    fn: Callable[[], list[str]],
    *,
    expect_errors: bool,
) -> str | None:
    try:
        errs = fn()
    except Exception as exc:  # noqa: BLE001 — self-test harness
        return f"{name}: raised {exc!r}"
    if expect_errors and not errs:
        return f"{name}: expected RED, got GREEN"
    if not expect_errors and errs:
        return f"{name}: expected GREEN, got RED: {errs}"
    return None


def run_self_test(src_root: Path) -> int:
    failures: list[str] = []

    # --- baseline pure inspections must be GREEN on real tree ---
    cmake_text = (src_root / "CMakeLists.txt").read_text(encoding="utf-8")
    failures.append(
        _mutation(
            "baseline_install_rules",
            lambda: inspect_cmake_install_rules(cmake_text),
            expect_errors=False,
        )
    )

    # Multi-line install(FILES private header...) — known false-green if only
    # lines containing "install" are scanned.
    multi_line = (
        "install(TARGETS ninlil EXPORT NinlilTargets)\n"
        "install(FILES\n"
        "    src/radio/r7_crypto_provider.h\n"
        "    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})\n"
        "install(FILES LICENSE DESTINATION share)\n"
    )
    failures.append(
        _mutation(
            "multiline_install_private_header",
            lambda: inspect_cmake_install_rules(multi_line),
            expect_errors=True,
        )
    )
    # Same private path on a single-line install — also red.
    single_line = 'install(FILES src/radio/r7_crypto_openssl3.h DESTINATION include)\n'
    failures.append(
        _mutation(
            "single_line_install_private_header",
            lambda: inspect_cmake_install_rules(single_line),
            expect_errors=True,
        )
    )
    # Benign public install remains green.
    public_only = (
        "install(TARGETS ninlil EXPORT NinlilTargets)\n"
        "install(DIRECTORY include/ninlil DESTINATION include)\n"
        "install(FILES LICENSE DESTINATION share/licenses/ninlil)\n"
    )
    failures.append(
        _mutation(
            "public_install_green",
            lambda: inspect_cmake_install_rules(public_only),
            expect_errors=False,
        )
    )

    # --- archive member mutations ---
    good_members = [
        "control_frame_codec.c.o",
        "r7_crypto_portable.c.o",
        "r7_crypto_nonce.c.o",
        "r7_crypto_openssl3.c.o",
        "n6_record_codec.c.o",
    ]
    failures.append(
        _mutation(
            "archive_baseline",
            lambda: inspect_archive_members(good_members),
            expect_errors=False,
        )
    )
    missing = [m for m in good_members if m != "r7_crypto_nonce.c.o"]
    failures.append(
        _mutation(
            "archive_member_missing",
            lambda: inspect_archive_members(missing),
            expect_errors=True,
        )
    )
    dup = list(good_members) + ["r7_crypto_portable.c.o"]
    failures.append(
        _mutation(
            "archive_member_duplicate",
            lambda: inspect_archive_members(dup),
            expect_errors=True,
        )
    )
    with_mbedtls = list(good_members) + ["r7_crypto_mbedtls.c.o"]
    failures.append(
        _mutation(
            "archive_host_esp_swap_mbedtls",
            lambda: inspect_archive_members(with_mbedtls),
            expect_errors=True,
        )
    )
    with_test = list(good_members) + ["r7_crypto_portable_test.c.o"]
    failures.append(
        _mutation(
            "archive_test_member",
            lambda: inspect_archive_members(with_test),
            expect_errors=True,
        )
    )
    with_oracle = list(good_members) + ["r7_radio_wire_oracle.c.o"]
    failures.append(
        _mutation(
            "archive_oracle_member",
            lambda: inspect_archive_members(with_oracle),
            expect_errors=True,
        )
    )
    with_gen = list(good_members) + ["r7_crypto_vectors.gen.h.o"]
    failures.append(
        _mutation(
            "archive_generated_member",
            lambda: inspect_archive_members(with_gen),
            expect_errors=True,
        )
    )
    with_seam = list(good_members) + ["r7_crypto_test_spans_forbidden.c.o"]
    failures.append(
        _mutation(
            "archive_test_seam_member",
            lambda: inspect_archive_members(with_seam),
            expect_errors=True,
        )
    )

    # --- nm symbol mutations (pure function; member name alone is insufficient) ---
    clean_prod = {
        "ninlil_r7_crypto_provider_validate",
        "ninlil_r7_crypto_sha256",
        "ninlil_r7_crypto_nonce_from_counter",
        "ninlil_r7_crypto_openssl3_provider_init",
    }
    failures.append(
        _mutation(
            "off_archive_symbols_baseline",
            lambda: inspect_off_archive_symbols(clean_prod),
            expect_errors=False,
        )
    )
    with_seam_sym = set(clean_prod) | {"ninlil_r7_crypto_test_spans_forbidden"}
    failures.append(
        _mutation(
            "off_archive_seam_symbol_injected",
            lambda: inspect_off_archive_symbols(with_seam_sym),
            expect_errors=True,
        )
    )
    with_oracle_sym = set(clean_prod) | {"ninlil_r7_radio_wire_oracle_verify_helper"}
    failures.append(
        _mutation(
            "off_archive_oracle_symbol_injected",
            lambda: inspect_off_archive_symbols(with_oracle_sym),
            expect_errors=True,
        )
    )
    with_fixture_sym = set(clean_prod) | {"ninlil_r7_crypto_fixture_stamp"}
    failures.append(
        _mutation(
            "off_archive_fixture_symbol_injected",
            lambda: inspect_off_archive_symbols(with_fixture_sym),
            expect_errors=True,
        )
    )
    # Mach-O underscore normalization: banned after strip.
    mac_nm = (
        "r7_crypto_portable.c.o:\n"
        "0000000000000000 T _ninlil_r7_crypto_test_spans_forbidden\n"
        "                 U _memcpy\n"
    )
    parsed_mac = parse_nm_defined_symbols(mac_nm)
    if "ninlil_r7_crypto_test_spans_forbidden" not in parsed_mac:
        failures.append("nm macho underscore parse missed test_spans_forbidden")
    failures.append(
        _mutation(
            "off_archive_macho_seam_parsed",
            lambda: inspect_off_archive_symbols(parsed_mac),
            expect_errors=True,
        )
    )
    linux_nm = (
        "r7_crypto_portable.c.o:\n"
        "0000000000000000 T ninlil_r7_crypto_sha256\n"
        "                 U memcpy\n"
    )
    parsed_linux = parse_nm_defined_symbols(linux_nm)
    failures.append(
        _mutation(
            "off_archive_linux_clean_parsed",
            lambda: inspect_off_archive_symbols(parsed_linux),
            expect_errors=False,
        )
    )

    # Public installed lib must not carry any ninlil_r7_crypto_* definitions.
    failures.append(
        _mutation(
            "public_lib_symbols_baseline",
            lambda: inspect_public_lib_symbols(
                {"ninlil_runtime_open", "sqlite3_open"},
                lib_label="lib/libninlil.a",
            ),
            expect_errors=False,
        )
    )
    failures.append(
        _mutation(
            "public_lib_private_prefix",
            lambda: inspect_public_lib_symbols(
                {"ninlil_runtime_open", "ninlil_r7_crypto_sha256"},
                lib_label="lib/libninlil.a",
            ),
            expect_errors=True,
        )
    )
    failures.append(
        _mutation(
            "public_lib_provider_factory",
            lambda: inspect_public_lib_symbols(
                {"ninlil_r7_crypto_openssl3_provider_init"},
                lib_label="lib/libninlil.a",
            ),
            expect_errors=True,
        )
    )
    failures.append(
        _mutation(
            "public_lib_mbedtls_prefix",
            lambda: inspect_public_lib_symbols(
                {"ninlil_r7_mbedtls_provider_init"},
                lib_label="lib/libfoo.so",
            ),
            expect_errors=True,
        )
    )

    # Synthetic archive mutation: real ar + object carrying banned symbol must
    # be red via nm path (proves tooling, not only pure inspect lists).
    with tempfile.TemporaryDirectory(prefix="r7-nm-arch-mut-") as td:
        root = Path(td)
        src = root / "seam.c"
        src.write_text(
            "int ninlil_r7_crypto_test_spans_forbidden(void) { return 0; }\n",
            encoding="utf-8",
        )
        obj = root / "seam.c.o"
        archive = root / "libfake_public.a"
        cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        ar = shutil.which("ar")
        if cc and ar:
            c1 = run_cmd([cc, "-c", str(src), "-o", str(obj)])
            c2 = run_cmd([ar, "rcs", str(archive), str(obj)])
            if c1.returncode == 0 and c2.returncode == 0:
                defined, nm_errs = run_nm_defined(archive)
                if nm_errs or defined is None:
                    failures.append(f"synthetic archive nm failed: {nm_errs}")
                else:
                    failures.append(
                        _mutation(
                            "synthetic_public_archive_seam_nm",
                            lambda d=defined: inspect_public_lib_symbols(
                                d, lib_label=str(archive.name)
                            ),
                            expect_errors=True,
                        )
                    )
                    failures.append(
                        _mutation(
                            "synthetic_off_archive_seam_nm",
                            lambda d=defined: inspect_off_archive_symbols(d),
                            expect_errors=True,
                        )
                    )
            else:
                failures.append(
                    "synthetic archive build failed "
                    f"(cc={c1.returncode}, ar={c2.returncode})"
                )
        else:
            failures.append("cc/ar missing for synthetic archive mutation")

    # --- install tree mutations ---
    with tempfile.TemporaryDirectory(prefix="r7-install-mut-") as td:
        root = Path(td)
        (root / "include" / "ninlil").mkdir(parents=True)
        (root / "include" / "ninlil" / "runtime.h").write_text("ok\n", encoding="utf-8")
        (root / "lib").mkdir()
        # Path-only baseline without a real library file (empty install libs).
        failures.append(
            _mutation(
                "install_tree_baseline_paths",
                lambda: [
                    e
                    for e in inspect_install_tree(root)
                    if "nm" not in e and "symbol" not in e
                ],
                expect_errors=False,
            )
        )
        # Clean public archive (no private symbols) is green for symbols.
        clean_src = root / "clean.c"
        clean_src.write_text("int ninlil_public_only(void) { return 1; }\n", encoding="utf-8")
        clean_obj = root / "clean.c.o"
        clean_a = root / "lib" / "libninlil.a"
        cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        ar = shutil.which("ar")
        if cc and ar:
            if (
                run_cmd([cc, "-c", str(clean_src), "-o", str(clean_obj)]).returncode
                == 0
                and run_cmd([ar, "rcs", str(clean_a), str(clean_obj)]).returncode
                == 0
            ):
                failures.append(
                    _mutation(
                        "install_tree_clean_public_lib",
                        lambda: inspect_install_tree(root),
                        expect_errors=False,
                    )
                )
            else:
                failures.append("install clean public lib build failed")
        else:
            failures.append("cc/ar missing for install public lib mutation")
        leak_h = root / "include" / "r7_crypto_provider.h"
        leak_h.write_text("private\n", encoding="utf-8")
        failures.append(
            _mutation(
                "install_tree_private_header",
                lambda: inspect_install_tree(root),
                expect_errors=True,
            )
        )
        leak_h.unlink()
        leak_json = root / "share" / "r7_crypto_vectors.json"
        leak_json.parent.mkdir(parents=True, exist_ok=True)
        leak_json.write_text("{}\n", encoding="utf-8")
        failures.append(
            _mutation(
                "install_tree_vector_json",
                lambda: inspect_install_tree(root),
                expect_errors=True,
            )
        )
        leak_json.unlink()
        leak_a = root / "lib" / "libninlil_runtime_private.a"
        leak_a.write_bytes(b"!\n")
        failures.append(
            _mutation(
                "install_tree_private_archive",
                lambda: inspect_install_tree(root),
                expect_errors=True,
            )
        )
        leak_a.unlink()
        # Contaminated public archive: path looks public, symbols private → red.
        if cc and ar and clean_a.is_file():
            seam_src = root / "pub_seam.c"
            seam_src.write_text(
                "int ninlil_r7_crypto_sha256(void) { return 0; }\n",
                encoding="utf-8",
            )
            seam_obj = root / "pub_seam.c.o"
            if (
                run_cmd([cc, "-c", str(seam_src), "-o", str(seam_obj)]).returncode
                == 0
                and run_cmd([ar, "rcs", str(clean_a), str(seam_obj)]).returncode
                == 0
            ):
                failures.append(
                    _mutation(
                        "install_tree_public_lib_private_symbol",
                        lambda: inspect_install_tree(root),
                        expect_errors=True,
                    )
                )
            else:
                failures.append("install contaminated public lib build failed")

    # --- CI OpenSSL structure ---
    bad_ci = (
        "echo \"OPENSSL_ROOT=$(brew --prefix openssl@3)\" >> \"$GITHUB_ENV\"\n"
        "cmake -S . -B build -DOPENSSL_ROOT_DIR=${{ env.OPENSSL_ROOT }}\n"
    )
    failures.append(
        _mutation(
            "ci_openssl_env_expr_red",
            lambda: inspect_ci_openssl_structure(bad_ci),
            expect_errors=True,
        )
    )
    good_ci = (
        "echo \"OPENSSL_ROOT=$(brew --prefix openssl@3)\" >> \"$GITHUB_ENV\"\n"
        'cmake -S . -B build -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT"\n'
    )
    failures.append(
        _mutation(
            "ci_openssl_shell_form_green",
            lambda: inspect_ci_openssl_structure(good_ci),
            expect_errors=False,
        )
    )
    real_ci = src_root / ".github" / "workflows" / "ci.yml"
    if real_ci.is_file():
        # After fix, real tree must be green; if still red, surface as failure.
        real_errs = inspect_ci_openssl_structure(
            real_ci.read_text(encoding="utf-8")
        )
        # Note: during mid-edit this may still be red; self-test records it.
        # The subsequent ci.yml fix must make this green before final verify.
        if real_errs:
            # Keep as mutation expectation: will fail self-test until ci fixed.
            failures.append(
                "ci.yml OPENSSL structure still red: " + "; ".join(real_errs)
            )

    # --- archive path-count (ambiguity) mutations ---
    with tempfile.TemporaryDirectory(prefix="r7-arch-count-") as td:
        root = Path(td)
        # empty → 0 archives
        if len(collect_private_archives(root)) != 0:
            failures.append("archive_count_empty: expected 0")
        (root / "libninlil_runtime_private.a").write_bytes(b"!\n")
        if len(collect_private_archives(root)) != 1:
            failures.append("archive_count_one: expected 1")
        sub = root / "extra"
        sub.mkdir()
        (sub / "libninlil_runtime_private.a").write_bytes(b"!\n")
        count = len(collect_private_archives(root))
        if count < 2:
            failures.append(
                f"archive_ambiguity_two: expected >=2 paths, got {count}"
            )
        # Gate policy: check rejects != 1 after explicit.
        if count == 1:
            failures.append("archive_ambiguity_two: still exact 1 (mutation failed)")

    # Host/ESP source authority swap detection via authority text probe used
    # in check (openssl present, mbedtls named as ESP-only).
    auth_path = src_root / "cmake" / "ninlil_r7_crypto_sources.cmake"
    auth = auth_path.read_text(encoding="utf-8")
    if "src/radio/r7_crypto_openssl3.c" not in auth:
        failures.append("authority baseline missing openssl3")
    swapped = auth.replace(
        "src/radio/r7_crypto_openssl3.c",
        "ports/esp-idf/src/r7_crypto_mbedtls.c",
    )
    # After swap, Host set would contain mbedtls twice / no openssl — the
    # packaging check's archive inspect would catch mbedtls member; also
    # structural: HOST list must not equal ESP path alone.
    if "src/radio/r7_crypto_openssl3.c" in swapped:
        failures.append("host_esp_swap mutation setup failed")
    # Simulated archive after ESP-into-Host contamination:
    failures.append(
        _mutation(
            "host_esp_swap_archive",
            lambda: inspect_archive_members(
                [
                    "r7_crypto_portable.c.o",
                    "r7_crypto_nonce.c.o",
                    "r7_crypto_mbedtls.c.o",  # wrong platform
                ]
            ),
            expect_errors=True,
        )
    )

    real_failures = [f for f in failures if f is not None]
    if real_failures:
        for f in real_failures:
            print(
                f"r7_crypto_tests_off_packaging_gate self-test FAIL: {f}",
                file=sys.stderr,
            )
        return 1
    ok(
        "self-test PASS "
        "(multiline install, member miss/dup, seam/test/oracle/generated, "
        "nm TEST_BUILD seam, public lib private symbols, Host/ESP swap, "
        "archive ambiguity, install path+nm leaks, CI OPENSSL shell form)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("check", "self-test"),
        help="check = fresh OFF Release packaging; self-test = mutation suite",
    )
    parser.add_argument(
        "--src-root",
        type=Path,
        default=REPO,
        help="repository root (default: inferred from this script)",
    )
    parser.add_argument(
        "--generator",
        default=None,
        help="CMake generator for fresh subbuild (default: Unix Makefiles)",
    )
    parser.add_argument(
        "--keep-work",
        action="store_true",
        help="retain temporary work tree after check (debug only)",
    )
    args = parser.parse_args(argv)
    src_root = args.src_root.resolve()
    if args.command == "self-test":
        return run_self_test(src_root)
    return run_fresh_packaging_check(
        src_root,
        generator=args.generator,
        keep_work=args.keep_work,
    )


if __name__ == "__main__":
    raise SystemExit(main())
