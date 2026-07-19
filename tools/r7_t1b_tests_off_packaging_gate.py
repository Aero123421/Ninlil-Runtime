#!/usr/bin/env python3
"""R7 T1b tests-OFF packaging gate (docs/33 §10).

Fresh OFF Release subbuild:
  - ctest -N = 0
  - private archive path-count exact 1 after explicit target build
  - ar member r7_context_binding.c.o exact once
  - nm: exact six production APIs; zero test symbols
  - install tree and public export surface: no T1b private artifact leakage

Self-test uses controlled fixtures (no full-repo configure required).

PASS ≠ T1b Accepted / R7 full / HIL / ESP final-link.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BINDING_MEMBER = "r7_context_binding.c.o"
EXACT_BINDING_DEFINED_APIS = frozenset(
    {
        "ninlil_r7_encode_hop_binding",
        "ninlil_r7_encode_e2e_binding",
        "ninlil_r7_digest_hop_binding",
        "ninlil_r7_digest_e2e_binding",
        "ninlil_r7_derive_hop_key_bundle_verified",
        "ninlil_r7_derive_e2e_key_bundle_verified",
    }
)
BANNED_MEMBER_NEEDLES = (
    "r7_t1b_binding_test",
    "r7_t1b_vectors",
    "r7_t1b_binding_vectors",
    "r7_t1b_oracle",
    "r7_t1b_fixture",
    "r7_t1b_generated",
)
BANNED_OFF_SYMBOL_NEEDLES = (
    "r7_binding_test",
    "r7_t1b_vectors",
    "r7_t1b_fixture",
    "r7_t1b_oracle",
    "binding_test_spans",
    "binding_test_set_secret",
    "ninlil_r7_binding_test_",
)
BANNED_PUBLIC_PREFIXES = (
    "ninlil_r7_encode_",
    "ninlil_r7_digest_",
    "ninlil_r7_derive_",
    "ninlil_r7_binding_",
)
BANNED_PUBLIC_MEMBER_NEEDLES = (
    "r7_context_binding",
    "r7_t1b",
    "nrw1_t1b",
)
PRIVATE_T1B_ARTIFACT_PATHS = frozenset(
    {
        "src/radio/r7_context_binding.c",
        "src/radio/r7_context_binding.h",
        "cmake/ninlil_nrw1_t1b_ctest.cmake",
        "tests/radio/private/r7_t1b_binding_test.c",
        "tests/radio/private/r7_t1b_binding_vectors.h",
        "tests/radio/r7_t1b_binding_vectors_bridge_test.c",
        "spec/vectors/r7-t1b-binding-subset.json",
        "tools/r7_t1b_binding_oracle.py",
        "tools/r7_t1b_ctest_gate.py",
        "tools/r7_t1b_kat_pin.py",
        "tools/r7_t1b_platform_split_gate.py",
        "tools/r7_t1b_stack_gate.py",
        "tools/r7_t1b_tests_off_packaging_gate.py",
    }
)
PRIVATE_T1B_ARTIFACT_BASENAMES = frozenset(
    Path(path).name for path in PRIVATE_T1B_ARTIFACT_PATHS
)
# Path-substring bans for install trees. Keep these specific enough that a
# deliberately benign name like ``r7_t1b_stack_gate.py-not-private`` stays green
# (exact catalog basenames + byte-identity catch real leakage).
LEGACY_BANNED_INSTALL_NEEDLES = (
    "tests/radio/private",
    "libninlil_runtime_private",
    "include/ninlil/r7_context_binding",
)
PRIVATE_ARCHIVE_RE = re.compile(r"libninlil_runtime_private\.(a|lib)$")
INSTALLED_LIB_RE = re.compile(r".*\.(a|lib|so|dylib)$|.*\.so\.\d+(\.\d+)*$")
_NM_TYPE_RE = re.compile(r"^[A-Za-z]$")
PrivateArtifactAuthority = dict[str, tuple[int, str]]


def fail(msg: str) -> None:
    print(f"r7_t1b_tests_off_packaging_gate FAIL: {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"r7_t1b_tests_off_packaging_gate: {msg}")


def collect_private_archives(root: Path) -> list[Path]:
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


def normalize_nm_symbol(name: str) -> str:
    n = name.strip()
    return n[1:] if n.startswith("_") else n


def parse_nm_defined_symbols(stdout: str) -> set[str]:
    defined: set[str] = set()
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or (stripped.endswith(":") and not any(ch.isspace() for ch in stripped)):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        type_token = None
        if len(parts) >= 3 and _NM_TYPE_RE.match(parts[-2]):
            type_token = parts[-2]
        elif len(parts) == 2 and _NM_TYPE_RE.match(parts[0]):
            type_token = parts[0]
        else:
            continue
        name = parts[-1]
        if type_token in ("U", "w", "v") or name.endswith(":"):
            continue
        norm = normalize_nm_symbol(name)
        if norm:
            defined.add(norm)
    return defined


def run_nm_defined(path: Path) -> tuple[set[str] | None, list[str]]:
    nm = shutil.which("nm")
    if not nm:
        return None, ["nm missing"]
    proc = subprocess.run([nm, "-g", str(path)], capture_output=True, check=False)
    if proc.returncode != 0:
        return None, [f"nm failed on {path}"]
    text = (proc.stdout or b"").decode("utf-8", errors="replace")
    return parse_nm_defined_symbols(text), []


def inspect_members(members: list[str]) -> list[str]:
    errors: list[str] = []
    bases = [Path(m).name for m in members]
    if bases.count(BINDING_MEMBER) != 1:
        errors.append(
            f"{BINDING_MEMBER}: expected once, got {bases.count(BINDING_MEMBER)}"
        )
    for base in bases:
        lower = base.lower()
        for needle in BANNED_MEMBER_NEEDLES:
            if needle in lower:
                errors.append(f"banned member {base} ({needle})")
                break
    return errors


def binding_defined_apis(defined: set[str]) -> set[str]:
    return {s for s in defined if s in EXACT_BINDING_DEFINED_APIS or (
        s.startswith("ninlil_r7_")
        and (
            s.startswith("ninlil_r7_encode_")
            or s.startswith("ninlil_r7_digest_")
            or s.startswith("ninlil_r7_derive_")
            or s.startswith("ninlil_r7_binding_")
        )
    )}


def inspect_off_symbols(defined: set[str]) -> list[str]:
    errors: list[str] = []
    for sym in defined:
        lower = sym.lower()
        for needle in BANNED_OFF_SYMBOL_NEEDLES:
            if needle in lower:
                errors.append(f"banned OFF symbol {sym} ({needle})")
                break
    # Exact set of production binding APIs among ninlil_r7_{encode,digest,derive,binding}_*
    binding_syms = binding_defined_apis(defined)
    # Allow only the exact six production APIs (no test seams).
    if binding_syms != EXACT_BINDING_DEFINED_APIS:
        missing = sorted(EXACT_BINDING_DEFINED_APIS - binding_syms)
        extra = sorted(binding_syms - EXACT_BINDING_DEFINED_APIS)
        if missing:
            errors.append(f"missing exact binding API symbols: {missing}")
        if extra:
            errors.append(
                f"unexpected binding-family defined symbols (test/extra): {extra}"
            )
    return errors


def inspect_binding_member_symbols(defined: set[str]) -> list[str]:
    errors: list[str] = []
    if defined != EXACT_BINDING_DEFINED_APIS:
        missing = sorted(EXACT_BINDING_DEFINED_APIS - defined)
        extra = sorted(defined - EXACT_BINDING_DEFINED_APIS)
        if missing:
            errors.append(f"binding member missing exact APIs: {missing}")
        if extra:
            errors.append(f"binding member has unexpected external APIs: {extra}")
    return errors


def inspect_private_binding_member_symbols(
    archive: Path, members: list[str]
) -> list[str]:
    exact_members = [
        member for member in members if Path(member).name == BINDING_MEMBER
    ]
    if len(exact_members) != 1:
        return [
            f"{BINDING_MEMBER}: cannot extract for exact API check; "
            f"member count={len(exact_members)}"
        ]
    member = exact_members[0]
    with tempfile.TemporaryDirectory(prefix="r7-t1b-member-") as td:
        extract_dir = Path(td)
        try:
            subprocess.check_call(["ar", "x", str(archive), member], cwd=extract_dir)
        except subprocess.CalledProcessError as exc:
            return [f"ar extract failed for {BINDING_MEMBER}: {exc}"]
        extracted = extract_dir / Path(member).name
        if not extracted.is_file():
            return [f"ar extract did not create {BINDING_MEMBER}"]
        defined, nm_errs = run_nm_defined(extracted)
        if defined is None:
            return nm_errs
        # Restrict to binding-family symbols only for member exact-set.
        family = binding_defined_apis(defined)
        return inspect_binding_member_symbols(family)


def inspect_public_symbols(defined: set[str]) -> list[str]:
    errors: list[str] = []
    for sym in defined:
        for prefix in BANNED_PUBLIC_PREFIXES:
            if sym.startswith(prefix):
                errors.append(f"public lib leaks {sym}")
                break
    return errors


def private_artifact_member_tokens() -> frozenset[str]:
    tokens: set[str] = set()
    for artifact in PRIVATE_T1B_ARTIFACT_PATHS:
        basename = Path(artifact).name.lower()
        tokens.add(basename)
        tokens.add(basename.split(".", 1)[0])
    return frozenset(tokens)


PRIVATE_ARTIFACT_MEMBER_TOKENS = private_artifact_member_tokens()


def inspect_public_members(members: list[str]) -> list[str]:
    errors: list[str] = []
    for member in members:
        base = Path(member).name
        lower = base.lower()
        for needle in BANNED_PUBLIC_MEMBER_NEEDLES:
            if needle in lower:
                errors.append(f"public archive has banned member {base} ({needle})")
                break
        for token in PRIVATE_ARTIFACT_MEMBER_TOKENS:
            if token in lower:
                errors.append(
                    f"public archive has private T1b catalog member {base} ({token})"
                )
                break
    return errors


def catalog_matches(value: str) -> list[str]:
    normalized = value.replace("\\", "/").lower()
    matches = [
        path for path in PRIVATE_T1B_ARTIFACT_PATHS if path.lower() in normalized
    ]
    basename = Path(normalized).name
    for artifact in PRIVATE_T1B_ARTIFACT_BASENAMES:
        if basename == artifact.lower() and artifact not in matches:
            matches.append(artifact)
    return sorted(matches)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_private_artifact_authority(
    src_root: Path,
) -> tuple[PrivateArtifactAuthority, list[str]]:
    authority: PrivateArtifactAuthority = {}
    errors: list[str] = []
    for artifact in sorted(PRIVATE_T1B_ARTIFACT_PATHS):
        path = src_root / artifact
        if not path.is_file():
            errors.append(f"private artifact authority missing regular file: {artifact}")
            continue
        try:
            authority[artifact] = (path.stat().st_size, sha256_file(path))
        except OSError as exc:
            errors.append(f"cannot fingerprint private artifact {artifact}: {exc}")
    return authority, errors


def private_artifact_hash_matches(
    path: Path, authority: PrivateArtifactAuthority
) -> tuple[str, ...]:
    try:
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError:
        return ()
    return tuple(
        artifact
        for artifact, (expected_size, expected_digest) in authority.items()
        if size == expected_size and digest == expected_digest
    )


def inspect_public_surface_text(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"cannot read public surface {path}: {exc}"]
    lower = text.replace("\\", "/").lower()
    errors: list[str] = []
    for needle in (
        "ninlil_r7_encode_",
        "ninlil_r7_digest_",
        "ninlil_r7_derive_",
        "ninlil_r7_binding_",
        "r7_context_binding",
        "nrw1_t1b",
    ):
        if needle in lower:
            errors.append(f"public surface exposes private binding token {needle}: {path}")
    for artifact in sorted(PRIVATE_T1B_ARTIFACT_PATHS):
        basename = Path(artifact).name.lower()
        if artifact.lower() in lower or basename in lower:
            errors.append(f"public surface references private artifact {artifact}: {path}")
    return errors


def cmake_install_blocks(cmake_text: str) -> list[str]:
    without_comments = re.sub(r"(?m)#.*$", "", cmake_text)
    return re.findall(r"\binstall\s*\((.*?)\)", without_comments, re.DOTALL | re.IGNORECASE)


def inspect_cmake_install_rules(cmake_path: Path) -> list[str]:
    try:
        text = cmake_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"cannot read CMake install authority {cmake_path}: {exc}"]
    errors: list[str] = []
    for block in cmake_install_blocks(text):
        lower = block.replace("\\", "/").lower()
        if not re.search(
            r"\b(FILES|DIRECTORY|PROGRAMS|SCRIPT|CODE)\b",
            lower,
            re.IGNORECASE,
        ):
            continue
        for artifact in sorted(PRIVATE_T1B_ARTIFACT_PATHS):
            basename = Path(artifact).name.lower()
            if artifact.lower() in lower or basename in lower:
                errors.append(
                    f"CMake install rule leaks private artifact {artifact}: {cmake_path}"
                )
    return errors


def inspect_source_install_rules(src_root: Path) -> list[str]:
    cmake_paths = [src_root / "CMakeLists.txt"]
    cmake_dir = src_root / "cmake"
    if cmake_dir.is_dir():
        cmake_paths.extend(sorted(cmake_dir.rglob("*.cmake")))
    errors: list[str] = []
    for path in cmake_paths:
        if path.is_file():
            errors.extend(inspect_cmake_install_rules(path))
    return errors


def inspect_install_tree(
    install_root: Path, private_authority: PrivateArtifactAuthority
) -> list[str]:
    errors: list[str] = []
    for path in install_root.rglob("*"):
        rel = str(path.relative_to(install_root)).replace("\\", "/")
        lower = rel.lower()
        for artifact in catalog_matches(rel):
            errors.append(f"private T1b artifact installed: {rel} ({artifact})")
        for needle in LEGACY_BANNED_INSTALL_NEEDLES:
            if needle.lower() in lower:
                errors.append(f"banned install path: {rel} ({needle})")
                break
        if path.is_file():
            for artifact in private_artifact_hash_matches(path, private_authority):
                errors.append(
                    f"private T1b artifact bytes installed: {rel} ({artifact}, sha256)"
                )
        if path.is_file() and INSTALLED_LIB_RE.match(path.name):
            if path.suffix.lower() in {".a", ".lib"}:
                try:
                    member_errors = inspect_public_members(ar_members(path))
                except subprocess.CalledProcessError as exc:
                    member_errors = [f"ar failed on public archive {path}: {exc}"]
                errors.extend(member_errors)
            defined, nm_errs = run_nm_defined(path)
            if defined is None:
                errors.extend(nm_errs)
            else:
                errors.extend(inspect_public_symbols(defined))
        if path.is_file() and path.suffix.lower() in {".cmake", ".h", ".hpp", ".pc"}:
            errors.extend(inspect_public_surface_text(path))
    return errors


def configure_off(src: Path, build: Path, generator: str) -> None:
    cmd = [
        "cmake",
        "-S",
        str(src),
        "-B",
        str(build),
        "-G",
        generator,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DNINLIL_BUILD_TESTS=OFF",
        "-DNINLIL_ENABLE_STRICT_WARNINGS=ON",
        "-DNINLIL_ENABLE_SANITIZERS=OFF",
        "-DNINLIL_SQLITE_LINKAGE=SHARED",
    ]
    for prefix in (
        os.environ.get("OPENSSL_ROOT_DIR"),
        os.environ.get("OPENSSL_ROOT"),
        "/opt/homebrew/opt/openssl@3",
        "/usr/local/opt/openssl@3",
    ):
        if prefix and Path(prefix).is_dir():
            cmd.append(f"-DOPENSSL_ROOT_DIR={prefix}")
            break
    subprocess.check_call(cmd)


def run_check(src_root: Path, generator: str) -> int:
    source_install_errs = inspect_source_install_rules(src_root)
    private_authority, authority_errs = build_private_artifact_authority(src_root)
    if source_install_errs or authority_errs:
        for e in source_install_errs + authority_errs:
            fail(e)
        return 1
    with tempfile.TemporaryDirectory(prefix="r7-t1b-off-") as td:
        root = Path(td)
        build = root / "build"
        install = root / "install"
        try:
            configure_off(src_root, build, generator)
        except subprocess.CalledProcessError as exc:
            fail(f"configure failed: {exc}")
            return 1

        listing = subprocess.check_output(
            ["ctest", "--test-dir", str(build), "-N"], text=True
        )
        if "Test #" in listing:
            fail("tests-OFF registered tests non-zero")
            return 1
        if re.search(r"Total Tests:\s*0\b", listing) is None and (
            "No tests were found" not in listing
        ):
            if re.search(r"Total Tests:\s*[1-9]", listing):
                fail("tests-OFF ctest -N is not empty")
                return 1

        subprocess.check_call(
            ["cmake", "--build", str(build), "--config", "Release", "--parallel"]
        )
        after_all = collect_private_archives(build)
        if len(after_all) != 0:
            fail(
                f"EXCLUDE_FROM_ALL broken — after bare all, "
                f"private archive path-count={len(after_all)} want 0"
            )
            return 1

        subprocess.check_call(
            [
                "cmake",
                "--build",
                str(build),
                "--config",
                "Release",
                "--target",
                "ninlil_runtime_private",
                "--parallel",
            ]
        )
        archives = collect_private_archives(build)
        if len(archives) != 1:
            fail(f"private archive path-count={len(archives)} want 1")
            return 1
        archive = archives[0]
        members = ar_members(archive)
        mem_errs = inspect_members(members)
        if mem_errs:
            for e in mem_errs:
                fail(e)
            return 1
        member_symbol_errs = inspect_private_binding_member_symbols(archive, members)
        if member_symbol_errs:
            for e in member_symbol_errs:
                fail(e)
            return 1
        defined, nm_errs = run_nm_defined(archive)
        if defined is None:
            for e in nm_errs:
                fail(e)
            return 1
        # Archive has many unrelated symbols; only binding-family exact-set.
        sym_errs = inspect_off_symbols(defined)
        if sym_errs:
            for e in sym_errs:
                fail(e)
            return 1

        subprocess.check_call(
            ["cmake", "--install", str(build), "--prefix", str(install)]
        )
        inst_errs = inspect_install_tree(install, private_authority)
        if inst_errs:
            for e in inst_errs:
                fail(e)
            return 1
        ok(
            f"PASS member={BINDING_MEMBER} once; apis=6; bare-all archive=0; "
            f"install public-only; binding symbols private-only"
        )
        return 0


def run_self_test(src_root: Path) -> int:
    failures: list[str] = []
    private_authority, authority_errs = build_private_artifact_authority(src_root)
    if authority_errs:
        failures.extend(f"authority baseline red: {err}" for err in authority_errs)
    auth = (src_root / "cmake/ninlil_nrw1_t1b_ctest.cmake").read_text(encoding="utf-8")
    if "src/radio/r7_context_binding.c" not in auth:
        failures.append("authority missing binding source")
    if not inspect_members(["r7_crypto_portable.c.o"]):
        failures.append("missing binding member did not go red")
    if not inspect_members([BINDING_MEMBER, BINDING_MEMBER]):
        failures.append("duplicate binding member did not go red")
    if not inspect_members([BINDING_MEMBER, "r7_t1b_vectors_bridge.c.o"]):
        failures.append("banned member did not go red")
    if inspect_members(
        [
            BINDING_MEMBER,
            "public_model.gen.c.o",
            "fixture_runtime.c.o",
        ]
    ):
        failures.append("unrelated private-archive member false-positive")

    defined_ok = set(EXACT_BINDING_DEFINED_APIS)
    if inspect_off_symbols(defined_ok):
        failures.append(f"baseline symbols red: {inspect_off_symbols(defined_ok)}")
    with_test = set(defined_ok) | {"ninlil_r7_binding_test_spans_forbidden"}
    if not inspect_off_symbols(with_test):
        failures.append("test seam symbol did not go red")
    with_extra = set(defined_ok) | {"ninlil_r7_derive_generic"}
    if not inspect_off_symbols(with_extra):
        failures.append("extra derive API did not go red")
    incomplete = set(defined_ok) - {"ninlil_r7_encode_hop_binding"}
    if not inspect_off_symbols(incomplete):
        failures.append("missing exact API did not go red")
    if not inspect_public_symbols({"ninlil_r7_encode_hop_binding"}):
        failures.append("public leak did not go red")

    with tempfile.TemporaryDirectory(prefix="r7-t1b-member-api-mut-") as td:
        root = Path(td)

        def build_binding_member_archive(
            label: str, functions: set[str], extra_global: str | None = None
        ) -> list[str] | None:
            case = root / label
            case.mkdir()
            source = case / "r7_context_binding.c"
            lines = ["extern void unresolved_backend(void);"]
            for index, function in enumerate(sorted(functions)):
                body = "unresolved_backend();" if index == 0 else ""
                lines.append(f"void {function}(void) {{ {body} }}")
            lines.append("static void binding_static_helper(void) { }")
            if extra_global is not None:
                lines.append(f"void {extra_global}(void) {{ }}")
            source.write_text("\n".join(lines) + "\n", encoding="utf-8")
            member = case / BINDING_MEMBER
            archive = case / "libninlil_runtime_private.a"
            try:
                subprocess.check_call(["cc", "-c", str(source), "-o", str(member)])
                subprocess.check_call(["ar", "rcs", str(archive), str(member)])
                members = ar_members(archive)
                if inspect_members(members):
                    return [f"fixture member shape red: {inspect_members(members)}"]
                return inspect_private_binding_member_symbols(archive, members)
            except subprocess.CalledProcessError as exc:
                failures.append(f"binding member API mutation could not run: {exc}")
                return None

        baseline_member_errors = build_binding_member_archive(
            "baseline", set(EXACT_BINDING_DEFINED_APIS)
        )
        if baseline_member_errors:
            failures.append(
                f"exact6 binding member baseline red: {baseline_member_errors}"
            )
        extra_member_errors = build_binding_member_archive(
            "extra",
            set(EXACT_BINDING_DEFINED_APIS),
            "ninlil_r7_binding_test_spans_forbidden",
        )
        if not extra_member_errors or not any(
            "ninlil_r7_binding_test_spans_forbidden" in err
            for err in extra_member_errors
        ):
            failures.append("test seam API escaped binding member check")
        missing_member_errors = build_binding_member_archive(
            "missing",
            set(EXACT_BINDING_DEFINED_APIS)
            - {"ninlil_r7_derive_e2e_key_bundle_verified"},
        )
        if not missing_member_errors or not any(
            "ninlil_r7_derive_e2e_key_bundle_verified" in err
            for err in missing_member_errors
        ):
            failures.append("missing exact binding API escaped member check")

    with tempfile.TemporaryDirectory(prefix="r7-t1b-install-mut-") as td:
        install = Path(td) / "install"
        install.mkdir()
        benign = install / "share/ninlil/r7_t1b_stack_gate.py-not-private"
        benign.parent.mkdir(parents=True)
        benign.write_text("benign", encoding="utf-8")
        if inspect_install_tree(install, private_authority):
            failures.append("exact-basename false-positive guard went red")
        for artifact in sorted(PRIVATE_T1B_ARTIFACT_PATHS):
            leaked = install / "share/ninlil" / Path(artifact).name
            leaked.write_text("private", encoding="utf-8")
            errs = inspect_install_tree(install, private_authority)
            if not any(Path(artifact).name in err for err in errs):
                failures.append(f"install mutation escaped: {artifact}")
            leaked.unlink()

        public_header = install / "include/ninlil/new_api.h"
        public_header.parent.mkdir(parents=True, exist_ok=True)
        public_header.write_text(
            "int ninlil_r7_encode_hop_binding(void);\n",
            encoding="utf-8",
        )
        if not any(
            "ninlil_r7_encode_" in err
            for err in inspect_install_tree(install, private_authority)
        ):
            failures.append("public header binding-token mutation escaped")
        public_header.unlink()

        renamed_copy = install / "share/ninlil/ninlil-gate-copy"
        shutil.copyfile(src_root / "tools/r7_t1b_stack_gate.py", renamed_copy)
        if not any(
            "r7_t1b_stack_gate.py" in err and "sha256" in err
            for err in inspect_install_tree(install, private_authority)
        ):
            failures.append("renamed byte-identical stack gate escaped hash check")
        renamed_copy.unlink()

    # Source list duplication / missing markers in authority file.
    auth_text = auth
    if auth_text.count("src/radio/r7_context_binding.c") < 1:
        failures.append("source authority missing binding path")
    # Duplicate path in set() body would be caught by platform gate; packaging
    # self-test ensures catalog completeness and member exact-once.

    # CMake install injection of private tool must red.
    with tempfile.TemporaryDirectory(prefix="r7-t1b-cmake-mut-") as td:
        cmake_path = Path(td) / "CMakeLists.txt"
        cmake_path.write_text(
            "install(FILES tools/r7_t1b_stack_gate.py DESTINATION share/ninlil)\n",
            encoding="utf-8",
        )
        if not any(
            "r7_t1b_stack_gate.py" in err
            for err in inspect_cmake_install_rules(cmake_path)
        ):
            failures.append("CMake stack-gate install injection escaped")

    false_positive_cmake = (
        "add_test(NAME t COMMAND tools/r7_t1b_stack_gate.py self-test)\n"
    )
    with tempfile.TemporaryDirectory(prefix="r7-t1b-cmake-fp-") as td:
        cmake_path = Path(td) / "CMakeLists.txt"
        cmake_path.write_text(false_positive_cmake, encoding="utf-8")
        if inspect_cmake_install_rules(cmake_path):
            failures.append("non-install CMake reference false-positive")

    if failures:
        for f in failures:
            fail(f"self-test: {f}")
        return 1
    ok("self-test PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    parser.add_argument("--src-root", type=Path, default=REPO)
    parser.add_argument("--generator", default="Ninja")
    args = parser.parse_args(argv)
    src = args.src_root.resolve()
    if args.command == "self-test":
        return run_self_test(src)
    return run_check(src, args.generator)


if __name__ == "__main__":
    raise SystemExit(main())
