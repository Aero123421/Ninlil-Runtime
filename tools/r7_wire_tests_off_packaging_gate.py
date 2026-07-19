#!/usr/bin/env python3
"""R7 T1 tests-OFF packaging gate (docs/32 §9.4–5).

Fresh OFF Release subbuild:
  - ctest -N = 0
  - private archive path-count exact 1 after explicit target build
  - ar member r7_wire_codec.c.o exact once
  - nm: no test/oracle/fixture wire symbols in OFF archive
  - install tree and public export surface: no T1 private artifact leakage
  - installed public libs: no ninlil_r7_wire_* defined symbols

PASS ≠ T1 Accepted / R7 full / HIL.
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
WIRE_MEMBER = "r7_wire_codec.c.o"
# docs/32 §4 exact production external API set (no composite / no extras).
EXACT_WIRE_DEFINED_APIS = frozenset(
    {
        "ninlil_r7_wire_pack_outer_data_aad",
        "ninlil_r7_wire_parse_outer_data_aad",
        "ninlil_r7_wire_pack_e2e_single_aad",
        "ninlil_r7_wire_parse_e2e_single_aad",
        "ninlil_r7_wire_seal_e2e_single",
        "ninlil_r7_wire_open_e2e_single",
        "ninlil_r7_wire_seal_outer_single",
        "ninlil_r7_wire_open_outer_single",
    }
)
BANNED_MEMBER_NEEDLES = (
    "r7_wire_vectors",
    "r7_wire_portable_test",
    "r7_wire_single_t1",
    "r7_wire_fixture",
    "r7_wire_oracle",
    "r7_wire_generated",
)
BANNED_OFF_SYMBOL_NEEDLES = (
    "r7_wire_vectors_bridge",
    "r7_wire_fixture",
    "r7_wire_oracle",
    "r7_wire_testbuild",
    "r7_wire_portable_test",
)
BANNED_PUBLIC_PREFIXES = ("ninlil_r7_wire_",)
BANNED_PUBLIC_MEMBER_NEEDLES = (
    "r7_wire_codec",
    "r7_wire_vectors",
    "r7_wire_portable_test",
    "r7_wire_fixture",
    "r7_wire_oracle",
    "r7_wire_generated",
    "nrw1_t1",
)
# docs/32 §9.5: this is the complete, exact T1 private-artifact catalog.
#
# An installed file can legitimately have a different directory than the source
# tree (for example, share/ninlil/r7_wire_stack_gate.py).  Therefore both the
# source-relative paths and their exact basenames are authorities.  Do not
# replace this with a broad "r7_wire" substring: that produces false positives
# while still failing to document every artifact that must remain private.
PRIVATE_T1_ARTIFACT_PATHS = frozenset(
    {
        "src/radio/r7_wire_codec.c",
        "src/radio/r7_wire_codec.h",
        "cmake/ninlil_r7_wire_sources.cmake",
        "cmake/ninlil_r7_wire_ctest.cmake",
        "tests/radio/r7_wire_portable_test.c",
        "tests/radio/r7_wire_vectors_bridge_test.c",
        "tests/radio/private/r7_wire_single_t1_vectors.json",
        "tests/radio/private/r7_wire_single_t1_vectors.gen.h",
        "tools/nrw1_t1_ctest_gate.py",
        "tools/r7_wire_kat_pin.py",
        "tools/r7_wire_platform_split_gate.py",
        "tools/r7_wire_single_oracle.py",
        "tools/r7_wire_stack_gate.py",
        "tools/r7_wire_tests_off_packaging_gate.py",
    }
)
PRIVATE_T1_ARTIFACT_BASENAMES = frozenset(
    Path(path).name for path in PRIVATE_T1_ARTIFACT_PATHS
)
LEGACY_BANNED_INSTALL_NEEDLES = (
    "nrw1_t1",
    "tests/radio/private",
    "libninlil_runtime_private",
)
PRIVATE_ARCHIVE_RE = re.compile(r"libninlil_runtime_private\.(a|lib)$")
INSTALLED_LIB_RE = re.compile(r".*\.(a|lib|so|dylib)$|.*\.so\.\d+(\.\d+)*$")
_NM_TYPE_RE = re.compile(r"^[A-Za-z]$")
PrivateArtifactAuthority = dict[str, tuple[int, str]]


def fail(msg: str) -> None:
    print(f"r7_wire_tests_off_packaging_gate FAIL: {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"r7_wire_tests_off_packaging_gate: {msg}")


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
    if bases.count(WIRE_MEMBER) != 1:
        errors.append(f"{WIRE_MEMBER}: expected once, got {bases.count(WIRE_MEMBER)}")
    for base in bases:
        lower = base.lower()
        for needle in BANNED_MEMBER_NEEDLES:
            if needle in lower:
                errors.append(f"banned member {base} ({needle})")
                break
    return errors


def wire_defined_apis(defined: set[str]) -> set[str]:
    """External defined symbols with ninlil_r7_wire_ prefix only."""
    return {s for s in defined if s.startswith("ninlil_r7_wire_")}


def inspect_off_symbols(defined: set[str]) -> list[str]:
    errors: list[str] = []
    for sym in defined:
        lower = sym.lower()
        for needle in BANNED_OFF_SYMBOL_NEEDLES:
            if needle in lower:
                errors.append(f"banned OFF symbol {sym} ({needle})")
                break
    # Exact set: every ninlil_r7_wire_* defined symbol is one of the 8 APIs.
    wire_syms = wire_defined_apis(defined)
    if wire_syms != EXACT_WIRE_DEFINED_APIS:
        missing = sorted(EXACT_WIRE_DEFINED_APIS - wire_syms)
        extra = sorted(wire_syms - EXACT_WIRE_DEFINED_APIS)
        if missing:
            errors.append(f"missing exact wire API symbols: {missing}")
        if extra:
            errors.append(
                f"unexpected ninlil_r7_wire_* defined symbols (composite/extra): "
                f"{extra}"
            )
    return errors


def inspect_wire_codec_member_symbols(defined: set[str]) -> list[str]:
    """The codec object itself may export exactly the eight private APIs."""
    errors: list[str] = []
    if defined != EXACT_WIRE_DEFINED_APIS:
        missing = sorted(EXACT_WIRE_DEFINED_APIS - defined)
        extra = sorted(defined - EXACT_WIRE_DEFINED_APIS)
        if missing:
            errors.append(f"wire codec member missing exact APIs: {missing}")
        if extra:
            errors.append(f"wire codec member has unexpected external APIs: {extra}")
    return errors


def inspect_private_wire_member_symbols(
    archive: Path, members: list[str]
) -> list[str]:
    """Extract exact codec member and inspect only its external definitions."""
    exact_members = [member for member in members if Path(member).name == WIRE_MEMBER]
    if len(exact_members) != 1:
        return [
            f"{WIRE_MEMBER}: cannot extract for exact API check; "
            f"member count={len(exact_members)}"
        ]
    member = exact_members[0]
    with tempfile.TemporaryDirectory(prefix="r7-t1-wire-member-") as td:
        extract_dir = Path(td)
        try:
            subprocess.check_call(["ar", "x", str(archive), member], cwd=extract_dir)
        except subprocess.CalledProcessError as exc:
            return [f"ar extract failed for {WIRE_MEMBER}: {exc}"]
        extracted = extract_dir / Path(member).name
        if not extracted.is_file():
            return [f"ar extract did not create {WIRE_MEMBER}"]
        defined, nm_errs = run_nm_defined(extracted)
        if defined is None:
            return nm_errs
        return inspect_wire_codec_member_symbols(defined)


def inspect_public_symbols(defined: set[str]) -> list[str]:
    errors: list[str] = []
    for sym in defined:
        for prefix in BANNED_PUBLIC_PREFIXES:
            if sym.startswith(prefix):
                errors.append(f"public lib leaks {sym}")
                break
    return errors


def private_artifact_member_tokens() -> frozenset[str]:
    """Names/stems that must never occur in an installed public archive."""
    tokens: set[str] = set()
    for artifact in PRIVATE_T1_ARTIFACT_PATHS:
        basename = Path(artifact).name.lower()
        tokens.add(basename)
        # ar members normally end in .o, so reject both foo.c.o and foo.o for
        # every catalogued source/tool/test/vector/CMake artifact.
        tokens.add(basename.split(".", 1)[0])
    return frozenset(tokens)


PRIVATE_ARTIFACT_MEMBER_TOKENS = private_artifact_member_tokens()


def inspect_public_members(members: list[str]) -> list[str]:
    """Public archive members must contain no T1 production/test artifacts."""
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
                    f"public archive has private T1 catalog member {base} ({token})"
                )
                break
    return errors


def catalog_matches(value: str) -> list[str]:
    """Return exact T1 catalog entries represented by a normalized path/text."""
    normalized = value.replace("\\", "/").lower()
    matches = [
        path for path in PRIVATE_T1_ARTIFACT_PATHS if path.lower() in normalized
    ]
    basename = Path(normalized).name
    for artifact in PRIVATE_T1_ARTIFACT_BASENAMES:
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
    """Return exact size+SHA-256 identities for all catalogued private files."""
    authority: PrivateArtifactAuthority = {}
    errors: list[str] = []
    for artifact in sorted(PRIVATE_T1_ARTIFACT_PATHS):
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
    """Identify byte-identical private artifacts, regardless of installed name."""
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
    """Reject private T1 names in installed public headers/config exports."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"cannot read public surface {path}: {exc}"]
    lower = text.replace("\\", "/").lower()
    errors: list[str] = []
    if "ninlil_r7_wire_" in lower:
        errors.append(f"public surface exposes private wire token ninlil_r7_wire_: {path}")
    for artifact in sorted(PRIVATE_T1_ARTIFACT_PATHS):
        basename = Path(artifact).name.lower()
        if artifact.lower() in lower or basename in lower:
            errors.append(f"public surface references private artifact {artifact}: {path}")
    return errors


def cmake_install_blocks(cmake_text: str) -> list[str]:
    """Extract simple install(...) blocks after dropping line comments.

    T1 install rules in this project do not nest parenthesized generator
    expressions.  A deliberately narrow parser avoids treating an add_test
    command or an explanatory comment as an install rule.
    """
    without_comments = re.sub(r"(?m)#.*$", "", cmake_text)
    return re.findall(r"\binstall\s*\((.*?)\)", without_comments, re.DOTALL | re.IGNORECASE)


def inspect_cmake_install_rules(cmake_path: Path) -> list[str]:
    """Reject direct installation of a catalogued private artifact."""
    try:
        text = cmake_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"cannot read CMake install authority {cmake_path}: {exc}"]
    errors: list[str] = []
    for block in cmake_install_blocks(text):
        lower = block.replace("\\", "/").lower()
        # PROGRAMS can rename a private tool, which defeats a post-install
        # basename scan.  SCRIPT/CODE may likewise copy or generate an
        # artifact under an unrelated name, so any catalog token in those
        # install forms is fail-closed.  TARGETS has no source-artifact token
        # and remains covered by the installed-library symbol inspection.
        if not re.search(
            r"\b(FILES|DIRECTORY|PROGRAMS|SCRIPT|CODE)\b",
            lower,
            re.IGNORECASE,
        ):
            continue
        for artifact in sorted(PRIVATE_T1_ARTIFACT_PATHS):
            basename = Path(artifact).name.lower()
            if artifact.lower() in lower or basename in lower:
                errors.append(
                    f"CMake install rule leaks private artifact {artifact}: {cmake_path}"
                )
    return errors


def inspect_source_install_rules(src_root: Path) -> list[str]:
    """Check Host/package CMake authorities before creating an install tree."""
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
            errors.append(f"private T1 artifact installed: {rel} ({artifact})")
        for needle in LEGACY_BANNED_INSTALL_NEEDLES:
            if needle.lower() in lower:
                errors.append(f"banned install path: {rel} ({needle})")
                break
        if path.is_file():
            for artifact in private_artifact_hash_matches(path, private_authority):
                errors.append(
                    f"private T1 artifact bytes installed: {rel} ({artifact}, sha256)"
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
    # OpenSSL on macOS
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
    with tempfile.TemporaryDirectory(prefix="r7-t1-off-") as td:
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
            # Accept either form of empty CTest listing.
            if re.search(r"Total Tests:\s*[1-9]", listing):
                fail("tests-OFF ctest -N is not empty")
                return 1

        # bare all: installable public targets only; private archive path-count 0
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

        # explicit private target
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
        member_symbol_errs = inspect_private_wire_member_symbols(archive, members)
        if member_symbol_errs:
            for e in member_symbol_errs:
                fail(e)
            return 1
        defined, nm_errs = run_nm_defined(archive)
        if defined is None:
            for e in nm_errs:
                fail(e)
            return 1
        sym_errs = inspect_off_symbols(defined)
        if sym_errs:
            for e in sym_errs:
                fail(e)
            return 1

        # Install public tree (all-build already produced installable libs).
        subprocess.check_call(
            ["cmake", "--install", str(build), "--prefix", str(install)]
        )
        inst_errs = inspect_install_tree(install, private_authority)
        if inst_errs:
            for e in inst_errs:
                fail(e)
            return 1
        ok(
            f"PASS member={WIRE_MEMBER} once; bare-all archive=0; "
            f"install public-only; wire symbols private-only"
        )
        return 0


def run_self_test(src_root: Path) -> int:
    failures: list[str] = []
    private_authority, authority_errs = build_private_artifact_authority(src_root)
    if authority_errs:
        failures.extend(f"authority baseline red: {err}" for err in authority_errs)
    auth = (src_root / "cmake/ninlil_r7_wire_sources.cmake").read_text(encoding="utf-8")
    if "src/radio/r7_wire_codec.c" not in auth:
        failures.append("authority missing wire source")
    # Member inspection mutations
    if not inspect_members(["r7_crypto_portable.c.o"]):
        failures.append("missing wire member did not go red")
    if not inspect_members([WIRE_MEMBER, WIRE_MEMBER]):
        failures.append("duplicate wire member did not go red")
    if not inspect_members([WIRE_MEMBER, "r7_wire_vectors_bridge.c.o"]):
        failures.append("banned member did not go red")
    if inspect_members(
        [
            WIRE_MEMBER,
            "public_model.gen.c.o",
            "fixture_runtime.c.o",
            "public_oracle_client.c.o",
        ]
    ):
        failures.append("unrelated private-archive member false-positive")
    defined_ok = set(EXACT_WIRE_DEFINED_APIS)
    if inspect_off_symbols(defined_ok):
        failures.append(f"baseline symbols red: {inspect_off_symbols(defined_ok)}")
    unrelated_symbols = defined_ok | {
        "public_fixture_runtime",
        "public_oracle_client",
        "public_testbuild_model",
    }
    if inspect_off_symbols(unrelated_symbols):
        failures.append("unrelated OFF symbol false-positive")
    # Alias composite API must red under exact-set authority.
    with_composite = set(defined_ok) | {"ninlil_r7_wire_seal_full"}
    if not inspect_off_symbols(with_composite):
        failures.append("alias composite seal_full did not go red")
    with_open_full = set(defined_ok) | {"ninlil_r7_wire_open_full"}
    if not inspect_off_symbols(with_open_full):
        failures.append("alias composite open_full did not go red")
    incomplete = set(defined_ok) - {"ninlil_r7_wire_pack_outer_data_aad"}
    if not inspect_off_symbols(incomplete):
        failures.append("missing exact API did not go red")
    if not inspect_public_symbols({"ninlil_r7_wire_seal_e2e_single"}):
        failures.append("public leak did not go red")
    if inspect_public_members(["public_core.c.o"]):
        failures.append("benign public archive member false-positive")
    for benign_member in (
        "public_generated_codec.c.o",
        "public_model.gen.c.o",
        "public_oracle_client.c.o",
        "fixture_runtime.c.o",
    ):
        if inspect_public_members([benign_member]):
            failures.append(
                f"unrelated public member false-positive: {benign_member}"
            )

    # Build real static archives.  Member names are a separate public-surface
    # boundary: nm alone cannot see a test-only object with harmless symbols.
    with tempfile.TemporaryDirectory(prefix="r7-t1-public-archive-mut-") as td:
        root = Path(td)
        archive = root / "libpublic.a"
        for member_name, should_red in (
            ("public_core.c.o", False),
            ("r7_wire_vectors_bridge.c.o", True),
            ("r7_wire_codec.c.o", True),
        ):
            member = root / member_name
            source = root / member_name.removesuffix(".o")
            source.write_text("int public_archive_member(void) { return 0; }\n", encoding="utf-8")
            try:
                subprocess.check_call(["cc", "-c", str(source), "-o", str(member)])
                subprocess.check_call(["ar", "rcs", str(archive), str(member)])
                member_errors = inspect_public_members(ar_members(archive))
            except subprocess.CalledProcessError as exc:
                failures.append(f"public archive member mutation could not run: {exc}")
                break
            if should_red and not any(member_name in err for err in member_errors):
                failures.append(f"public archive member mutation escaped: {member_name}")
            if not should_red and member_errors:
                failures.append(f"benign archive mutation red: {member_errors}")
            archive.unlink(missing_ok=True)

    # Materialize the codec object boundary itself.  The whole private archive
    # contains unrelated globals, so only r7_wire_codec.c.o may be compared to
    # the exact eight API set.  An unresolved reference is deliberately present
    # to prove nm's undefined entries are excluded; a static helper proves
    # nm -g does not contaminate the external API set.
    with tempfile.TemporaryDirectory(prefix="r7-t1-wire-member-api-mut-") as td:
        root = Path(td)

        def build_wire_member_archive(
            label: str, functions: set[str], extra_global: str | None = None
        ) -> list[str] | None:
            case = root / label
            case.mkdir()
            source = case / "r7_wire_codec.c"
            lines = ["extern void unresolved_backend(void);"]
            for index, function in enumerate(sorted(functions)):
                body = "unresolved_backend();" if index == 0 else ""
                lines.append(f"void {function}(void) {{ {body} }}")
            lines.append("static void wire_static_helper(void) { }")
            if extra_global is not None:
                lines.append(f"void {extra_global}(void) {{ }}")
            source.write_text("\n".join(lines) + "\n", encoding="utf-8")
            member = case / WIRE_MEMBER
            archive = case / "libninlil_runtime_private.a"
            try:
                subprocess.check_call(["cc", "-c", str(source), "-o", str(member)])
                subprocess.check_call(["ar", "rcs", str(archive), str(member)])
                members = ar_members(archive)
                if inspect_members(members):
                    return [f"fixture member shape red: {inspect_members(members)}"]
                return inspect_private_wire_member_symbols(archive, members)
            except subprocess.CalledProcessError as exc:
                failures.append(f"wire member API mutation could not run: {exc}")
                return None

        baseline_member_errors = build_wire_member_archive(
            "baseline", set(EXACT_WIRE_DEFINED_APIS)
        )
        if baseline_member_errors:
            failures.append(f"exact8 codec member baseline red: {baseline_member_errors}")
        extra_member_errors = build_wire_member_archive(
            "extra", set(EXACT_WIRE_DEFINED_APIS), "ninlil_r7_seal_full"
        )
        if not extra_member_errors or not any(
            "ninlil_r7_seal_full" in err for err in extra_member_errors
        ):
            failures.append("non-prefix composite API escaped codec member check")
        missing_member_errors = build_wire_member_archive(
            "missing",
            set(EXACT_WIRE_DEFINED_APIS)
            - {"ninlil_r7_wire_open_outer_single"},
        )
        if not missing_member_errors or not any(
            "ninlil_r7_wire_open_outer_single" in err
            for err in missing_member_errors
        ):
            failures.append("missing exact codec API escaped member check")

    # Every exact source/header/test/vector/tool/CMake artifact must be rejected
    # even when an installer relocates it under an otherwise innocuous path.
    with tempfile.TemporaryDirectory(prefix="r7-t1-install-mut-") as td:
        install = Path(td) / "install"
        install.mkdir()
        benign = install / "share/ninlil/r7_wire_stack_gate.py-not-private"
        benign.parent.mkdir(parents=True)
        benign.write_text("benign", encoding="utf-8")
        if inspect_install_tree(install, private_authority):
            failures.append("exact-basename false-positive guard went red")
        for artifact in sorted(PRIVATE_T1_ARTIFACT_PATHS):
            leaked = install / "share/ninlil" / Path(artifact).name
            leaked.write_text("private", encoding="utf-8")
            errs = inspect_install_tree(install, private_authority)
            if not any(Path(artifact).name in err for err in errs):
                failures.append(f"install mutation escaped: {artifact}")
            leaked.unlink()

        # Concrete acceptance regression: the previously missed stack gate.
        reproduced = install / "share/ninlil/r7_wire_stack_gate.py"
        reproduced.write_text("private", encoding="utf-8")
        if not any(
            "r7_wire_stack_gate.py" in err
            for err in inspect_install_tree(install, private_authority)
        ):
            failures.append("share/ninlil/r7_wire_stack_gate.py escaped")
        reproduced.unlink()

        public_header = install / "include/ninlil/new_api.h"
        public_header.parent.mkdir(parents=True, exist_ok=True)
        public_header.write_text(
            "int ninlil_r7_wire_seal_full(void);\n"
            "#define NINLIL_R7_WIRE_FOO 1\n",
            encoding="utf-8",
        )
        if not any(
            "ninlil_r7_wire_" in err
            for err in inspect_install_tree(install, private_authority)
        ):
            failures.append("public header wire-token mutation escaped")
        public_header.unlink()

        benign_header = install / "include/ninlil/application_wire.h"
        benign_header.write_text(
            "int ninlil_application_wire_send(void);\n",
            encoding="utf-8",
        )
        if inspect_install_tree(install, private_authority):
            failures.append("unrelated public wire API false-positive")
        benign_header.unlink()

        renamed_copy = install / "share/ninlil/ninlil-gate-copy"
        shutil.copyfile(src_root / "tools/r7_wire_stack_gate.py", renamed_copy)
        if not any(
            "r7_wire_stack_gate.py" in err and "sha256" in err
            for err in inspect_install_tree(install, private_authority)
        ):
            failures.append("renamed byte-identical stack gate escaped hash check")
        renamed_copy.unlink()

    # Host CMake injection must fail before a build can create a false-green
    # install.  Materialize the exact regression through CMake install, rather
    # than relying on a synthetic path or parser-only assertion.
    with tempfile.TemporaryDirectory(prefix="r7-t1-cmake-mut-") as td:
        source = Path(td) / "source"
        tool = source / "tools/r7_wire_stack_gate.py"
        tool.parent.mkdir(parents=True)
        shutil.copyfile(src_root / "tools/r7_wire_stack_gate.py", tool)
        cmake_path = source / "CMakeLists.txt"
        cmake_path.write_text(
            "cmake_minimum_required(VERSION 3.24)\n"
            "project(r7_t1_install_mutation NONE)\n"
            "install(FILES tools/r7_wire_stack_gate.py DESTINATION share/ninlil)\n",
            encoding="utf-8",
        )
        if not any(
            "r7_wire_stack_gate.py" in err
            for err in inspect_cmake_install_rules(cmake_path)
        ):
            failures.append("Host CMake stack-gate install injection escaped")
        build = Path(td) / "build"
        install = Path(td) / "install"
        try:
            subprocess.check_call(["cmake", "-S", str(source), "-B", str(build)])
            subprocess.check_call(
                ["cmake", "--install", str(build), "--prefix", str(install)]
            )
        except subprocess.CalledProcessError as exc:
            failures.append(f"Host CMake install mutation could not run: {exc}")
        else:
            if not any(
                "r7_wire_stack_gate.py" in err
                for err in inspect_install_tree(install, private_authority)
            ):
                failures.append("Host CMake installed stack gate escaped")

    # Variable-indirected PROGRAMS permits a RENAME, so neither the source
    # install rule nor installed filename contains the catalog basename.  The
    # actual install must still go red by byte identity.
    with tempfile.TemporaryDirectory(prefix="r7-t1-programs-rename-mut-") as td:
        source = Path(td) / "source"
        tool = source / "tools/r7_wire_stack_gate.py"
        tool.parent.mkdir(parents=True)
        shutil.copyfile(src_root / "tools/r7_wire_stack_gate.py", tool)
        cmake_path = source / "CMakeLists.txt"
        cmake_path.write_text(
            "cmake_minimum_required(VERSION 3.24)\n"
            "project(r7_t1_programs_rename_mutation NONE)\n"
            "set(PRIVATE_TOOL \"${CMAKE_CURRENT_SOURCE_DIR}/tools/"
            "r7_wire_stack_gate.py\")\n"
            "install(PROGRAMS \"${PRIVATE_TOOL}\" DESTINATION bin "
            "RENAME ninlil-gate)\n",
            encoding="utf-8",
        )
        build = Path(td) / "build"
        install = Path(td) / "install"
        try:
            subprocess.check_call(["cmake", "-S", str(source), "-B", str(build)])
            subprocess.check_call(
                ["cmake", "--install", str(build), "--prefix", str(install)]
            )
        except subprocess.CalledProcessError as exc:
            failures.append(f"PROGRAMS RENAME mutation could not run: {exc}")
        else:
            if not (install / "bin/ninlil-gate").is_file():
                failures.append("PROGRAMS RENAME mutation did not install renamed tool")
            if not any(
                "r7_wire_stack_gate.py" in err and "sha256" in err
                for err in inspect_install_tree(install, private_authority)
            ):
                failures.append("variable PROGRAMS RENAME escaped hash check")

    # FILES has the same variable/RENAME bypass shape and must rely on the
    # installed-byte authority when the CMake source has no literal catalog
    # token in its install() block.
    with tempfile.TemporaryDirectory(prefix="r7-t1-files-rename-mut-") as td:
        source = Path(td) / "source"
        tool = source / "tools/r7_wire_stack_gate.py"
        tool.parent.mkdir(parents=True)
        shutil.copyfile(src_root / "tools/r7_wire_stack_gate.py", tool)
        cmake_path = source / "CMakeLists.txt"
        cmake_path.write_text(
            "cmake_minimum_required(VERSION 3.24)\n"
            "project(r7_t1_files_rename_mutation NONE)\n"
            "set(PRIVATE_TOOL \"${CMAKE_CURRENT_SOURCE_DIR}/tools/"
            "r7_wire_stack_gate.py\")\n"
            "install(FILES \"${PRIVATE_TOOL}\" DESTINATION share/ninlil "
            "RENAME ninlil-gate-file)\n",
            encoding="utf-8",
        )
        build = Path(td) / "build"
        install = Path(td) / "install"
        try:
            subprocess.check_call(["cmake", "-S", str(source), "-B", str(build)])
            subprocess.check_call(
                ["cmake", "--install", str(build), "--prefix", str(install)]
            )
        except subprocess.CalledProcessError as exc:
            failures.append(f"FILES RENAME mutation could not run: {exc}")
        else:
            if not (install / "share/ninlil/ninlil-gate-file").is_file():
                failures.append("FILES RENAME mutation did not install renamed tool")
            if not any(
                "r7_wire_stack_gate.py" in err and "sha256" in err
                for err in inspect_install_tree(install, private_authority)
            ):
                failures.append("variable FILES RENAME escaped hash check")

    # SCRIPT and CODE can hide both the source variable and the final name.
    # Their concrete byte-identical copies are caught by the post-install hash
    # authority even when source rule parsing sees no private artifact token.
    with tempfile.TemporaryDirectory(prefix="r7-t1-script-code-hash-mut-") as td:
        source = Path(td) / "source"
        tools_dir = source / "tools"
        tools_dir.mkdir(parents=True)
        build = Path(td) / "build"
        install = Path(td) / "install"
        shutil.copyfile(
            src_root / "tools/r7_wire_stack_gate.py",
            tools_dir / "r7_wire_stack_gate.py",
        )
        (tools_dir / "copy_private.cmake").write_text(
            f"file(MAKE_DIRECTORY \"{install}/bin\")\n"
            "file(COPY_FILE \"${CMAKE_CURRENT_LIST_DIR}/r7_wire_stack_gate.py\" "
            f"\"{install}/bin/ninlil-gate-script\")\n",
            encoding="utf-8",
        )
        cmake_path = source / "CMakeLists.txt"
        cmake_path.write_text(
            "cmake_minimum_required(VERSION 3.24)\n"
            "project(r7_t1_script_code_hash_mutation NONE)\n"
            "set(PRIVATE_TOOL \"${CMAKE_CURRENT_SOURCE_DIR}/tools/"
            "r7_wire_stack_gate.py\")\n"
            "install(SCRIPT tools/copy_private.cmake)\n"
            f"install(CODE \"file(MAKE_DIRECTORY \\\"{install}/bin\\\")\\n"
            "file(COPY_FILE \\\"${PRIVATE_TOOL}\\\" "
            f"\\\"{install}/bin/ninlil-gate-code\\\")\")\n",
            encoding="utf-8",
        )
        try:
            subprocess.check_call(["cmake", "-S", str(source), "-B", str(build)])
            subprocess.check_call(
                ["cmake", "--install", str(build), "--prefix", str(install)]
            )
        except subprocess.CalledProcessError as exc:
            failures.append(f"SCRIPT/CODE hash mutation could not run: {exc}")
        else:
            for renamed in ("ninlil-gate-script", "ninlil-gate-code"):
                if not (install / "bin" / renamed).is_file():
                    failures.append(f"SCRIPT/CODE mutation missing installed {renamed}")
            hash_errors = inspect_install_tree(install, private_authority)
            for renamed in ("ninlil-gate-script", "ninlil-gate-code"):
                if not any(
                    renamed in err and "r7_wire_stack_gate.py" in err and "sha256" in err
                    for err in hash_errors
                ):
                    failures.append(f"{renamed} escaped post-install hash check")

    # SCRIPT and CODE can conceal copy/install behavior behind arbitrary
    # filenames.  Their private artifact tokens must be rejected at parse time.
    parser_mutations = {
        "SCRIPT": "install(SCRIPT tools/r7_wire_stack_gate.py)\n",
        "CODE": (
            "install(CODE \"file(INSTALL FILES "
            "tools/r7_wire_stack_gate.py DESTINATION share/ninlil)\")\n"
        ),
    }
    with tempfile.TemporaryDirectory(prefix="r7-t1-install-parser-mut-") as td:
        for form, mutation in parser_mutations.items():
            cmake_path = Path(td) / f"{form}.cmake"
            cmake_path.write_text(mutation, encoding="utf-8")
            if not any(
                "r7_wire_stack_gate.py" in err
                for err in inspect_cmake_install_rules(cmake_path)
            ):
                failures.append(f"install({form}) private-token mutation escaped")

    # Existing CMake references in add_test must stay allowed; only install()
    # blocks are relevant to this packaging guard.
    false_positive_cmake = "add_test(NAME r7 COMMAND tools/r7_wire_stack_gate.py self-test)\n"
    with tempfile.TemporaryDirectory(prefix="r7-t1-cmake-fp-") as td:
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
