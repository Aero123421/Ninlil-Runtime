#!/usr/bin/env python3
"""Offline integrity gate for the private PA-S1a EDHOC candidate."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "third_party/production_attachment_edhoc.allowlist"
VENDOR = ROOT / "third_party/production_attachment_edhoc"
SOURCES = ROOT / "cmake/ninlil_pa_s1_edhoc_sources.cmake"
CMAKE = ROOT / "CMakeLists.txt"
EXPECTED_LIBEDHOC = "008ce0584e6cfa41aa6319f530b6c254c8abfc3e"
EXPECTED_ZCBOR = "d3093b5684f62268c7f27f8a5079f166772619de"
PUBLIC_FORBIDDEN_PREFIXES = (
    "edhoc_", "zcbor_", "cbor_encode_", "cbor_decode_",
    "ninlil_pa_s1_edhoc_", "ninlil_pa_s2_edhoc_",
)


class GateError(RuntimeError):
    pass


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def upstream_path(path: pathlib.Path) -> str:
    """Return the exact pinned upstream path for one flattened vendor file."""
    relative = path.relative_to(VENDOR)
    component, name = relative.parts
    if component == "zcbor":
        if name == "LICENSE":
            return "zcbor:LICENSE"
        if path.suffix == ".c":
            return f"zcbor:src/{name}"
        return f"zcbor:include/{name}"
    if component != "libedhoc":
        raise GateError(f"unknown vendor component: {path.relative_to(ROOT)}")
    if name == "LICENSE":
        return "libedhoc:LICENSE"
    if name in {"edhoc_backend_memory.h", "edhoc_backend_log.h"}:
        backend = "memory" if name.endswith("memory.h") else "log"
        return f"libedhoc:backends/{backend}/include/{name}"
    if name.startswith("backend_cbor_"):
        location = "src" if path.suffix == ".c" else "include"
        return f"libedhoc:backends/cbor/{location}/{name}"
    if path.suffix == ".c":
        return f"libedhoc:library/{name}"
    return f"libedhoc:include/{name}"


def entries() -> dict[pathlib.Path, tuple[str, str]]:
    text = ALLOWLIST.read_text(encoding="utf-8")
    if EXPECTED_LIBEDHOC not in text or EXPECTED_ZCBOR not in text:
        raise GateError("upstream commit pins are absent")
    result: dict[pathlib.Path, tuple[str, str]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (third_party/production_attachment_edhoc/.+)", line)
        if match is None:
            raise GateError(f"invalid allow-list line: {line!r}")
        path = ROOT / match.group(2)
        if path in result:
            raise GateError(f"duplicate allow-list path: {path}")
        result[path] = (match.group(1), upstream_path(path))
    if len(result) != 99:
        raise GateError(f"allow-list count drift: {len(result)} != 99")
    return result


def vendor_tree_hash(component: str) -> str:
    root = VENDOR / component
    digest = hashlib.sha256()
    for path in sorted(path for path in root.rglob("*") if path.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def validate_blobs(listed: dict[pathlib.Path, tuple[str, str]]) -> None:
    actual = {path for path in VENDOR.rglob("*") if path.is_file()}
    if actual != set(listed):
        raise GateError("vendored file set differs from exact allow-list")
    upstream_paths = [upstream for _, upstream in listed.values()]
    if len(upstream_paths) != len(set(upstream_paths)):
        raise GateError("upstream path mapping is not one-to-one")
    for path, (expected, _) in listed.items():
        if sha256(path) != expected:
            raise GateError(f"blob SHA-256 drift: {path.relative_to(ROOT)}")
    expected_components = {
        "libedhoc": "75e49a0f740fd619b89727ef10325cfb7be71b43f256dfedd1e2fed5e4b6e980",
        "zcbor": "c57f5db29b9dcfcf8b3dae0503496d83066a920160e65c6118aa059655b4efce",
    }
    # The local tree hashes bind the shipped archive; each mapped upstream
    # path then binds its exact blob without requiring network access.
    for component, expected in expected_components.items():
        if not any(upstream.startswith(f"{component}:") for _, upstream in listed.values()):
            raise GateError(f"missing upstream component mapping: {component}")
        if vendor_tree_hash(component) != expected:
            raise GateError(f"component tree hash drift: {component}")


def symbols(archive: pathlib.Path) -> str:
    try:
        return subprocess.check_output(["nm", "-g", str(archive)], text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"cannot inspect archive symbols: {archive}: {exc}") from exc


def defined_symbols(output: str) -> list[str]:
    result: list[str] = []
    for line in output.splitlines():
        match = re.search(r"(?:^|\s)([A-Za-z])\s+_?([A-Za-z][A-Za-z0-9_]*)$", line)
        if match is not None and match.group(1).upper() != "U":
            result.append(match.group(2))
    return result


def reject_public_symbol_leaks(output: str) -> None:
    if any(symbol.startswith(PUBLIC_FORBIDDEN_PREFIXES)
           for symbol in defined_symbols(output)):
        raise GateError("private Production Attachment symbols leaked into installed Runtime archive")


def reject_archive_overlap(private_output: str, public_output: str) -> None:
    overlap = set(defined_symbols(private_output)) & set(defined_symbols(public_output))
    if overlap:
        raise GateError("private PA-S1 symbols leaked into installed Runtime archive")


def validate(private_archive: pathlib.Path | None = None,
             public_archive: pathlib.Path | None = None) -> None:
    listed = entries()
    validate_blobs(listed)
    actual = set(listed)
    source_text = SOURCES.read_text(encoding="utf-8")
    source_paths = set(re.findall(
        r"(third_party/production_attachment_edhoc/(?:libedhoc|zcbor)/[^\s)]+\.c)",
        source_text,
    ))
    actual_c = {path.relative_to(ROOT).as_posix() for path in actual if path.suffix == ".c"}
    if source_paths != actual_c or len(source_paths) != 43:
        raise GateError("translation-unit allow-list drift")
    cmake = CMAKE.read_text(encoding="utf-8")
    if cmake.count("add_library(ninlil_pa_s1_edhoc_private STATIC EXCLUDE_FROM_ALL") != 1:
        raise GateError("PA-S1 archive must be exactly one private EXCLUDE_FROM_ALL target")
    if "install(TARGETS ninlil_pa_s1_edhoc_private" in cmake:
        raise GateError("PA-S1 private archive must not be installed")
    public_headers = ROOT / "include/ninlil"
    if any("edhoc" in path.read_text(encoding="utf-8", errors="ignore").lower()
           for path in public_headers.rglob("*.[ch]")):
        raise GateError("EDHOC leaked into installed public headers")
    private_output = symbols(private_archive) if private_archive is not None else None
    if private_output is not None:
        private_symbols = defined_symbols(private_output)
        if private_symbols.count("edhoc_context_init") != 1:
            raise GateError("private candidate archive lacks exact EDHOC core symbol")
        if {"edhoc_mem_alloc", "edhoc_mem_free"} & set(private_symbols):
            raise GateError("context-free custom hook leaked from test adapter into candidate")
    if public_archive is not None:
        public_output = symbols(public_archive)
        reject_public_symbol_leaks(public_output)
        if private_output is not None:
            reject_archive_overlap(private_output, public_output)


def self_test() -> None:
    validate()
    if defined_symbols("0000 T _edhoc_context_init\n         U _edhoc_mem_alloc\n"
                       "0000 T edhoc_context_init\n") != [
                           "edhoc_context_init", "edhoc_context_init"]:
        raise GateError("portable nm defined-symbol parsing drift")
    reject_public_symbol_leaks("0000 T _ninlil_runtime_create\n"
                               "         U _ninlil_pa_s1_edhoc_alloc\n"
                               "         U cbor_encode_message_1\n")
    try:
        reject_public_symbol_leaks("0000 T ninlil_pa_s1_edhoc_allocator_v1_begin\n")
    except GateError:
        pass
    else:
        raise GateError("private PA-S1 symbol leak was accepted")
    try:
        reject_public_symbol_leaks(
            "0000 T ninlil_pa_s2_edhoc_crypto_owner_v1_begin\n")
    except GateError:
        pass
    else:
        raise GateError("private PA-S2 symbol leak was accepted")
    try:
        reject_public_symbol_leaks("0000 T _cbor_decode_message_1\n")
    except GateError:
        pass
    else:
        raise GateError("generated CBOR symbol leak was accepted")
    reject_archive_overlap("0000 T _private_only\n", "0000 T _public_only\n")
    try:
        reject_archive_overlap("0000 T _shared_private\n", "0000 T shared_private\n")
    except GateError:
        pass
    else:
        raise GateError("private/public defined-symbol overlap was accepted")
    mutated = entries()
    path = next(iter(mutated))
    _, upstream = mutated[path]
    mutated[path] = ("0" * 64, upstream)
    try:
        validate_blobs(mutated)
    except GateError:
        return
    raise GateError("blob mutation was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    parser.add_argument("--private-archive", type=pathlib.Path)
    parser.add_argument("--public-archive", type=pathlib.Path)
    args = parser.parse_args()
    try:
        if args.command == "check":
            validate(args.private_archive, args.public_archive)
        else:
            self_test()
    except (GateError, OSError, UnicodeError) as exc:
        print(f"production attachment EDHOC vendor gate: {exc}", file=sys.stderr)
        return 1
    print("production attachment EDHOC vendor gate: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
