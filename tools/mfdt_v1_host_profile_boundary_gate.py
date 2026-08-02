#!/usr/bin/env python3
"""Fail-closed Host-four-slot versus ESP-one-slot MFDT package boundary."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


STORE_PORT_SOURCE = "src/runtime/mfdt_v1/mfdt_v1_store_port.c"
HOST_STORE_SOURCE = "src/runtime/mfdt_v1/mfdt_v1_host_store.c"
HOST_COORDINATOR_SOURCE = (
    "src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c"
)
HOST_HEADER = "src/runtime/mfdt_v1/mfdt_v1_host_coordinator.h"
HOST_SYMBOL = "ninlil_mfdt_v1_host_owner_init"
MFDT_SYMBOL_PREFIX = "ninlil_mfdt_v1_"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--build-dir", type=Path)
    check.add_argument("--esp-archive", type=Path)
    subparsers.add_parser("self-test")
    return parser.parse_args()


def strip_cmake_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def set_body(text: str, variable: str) -> str | None:
    match = re.search(
        rf"set\s*\(\s*{re.escape(variable)}\b(?P<body>.*?)\)",
        strip_cmake_comments(text),
        flags=re.DOTALL,
    )
    return match.group("body") if match is not None else None


def source_tokens(body: str | None) -> set[str]:
    if body is None:
        return set()
    return set(
        re.findall(
            r"(?:src|ports)/[A-Za-z0-9_./-]+\.c",
            body,
        )
    )


def check_authority(
    source_cmake: str,
    component_cmake: str,
    root_cmake: str,
    coordinator_source: str,
) -> list[str]:
    failures: list[str] = []
    production_body = set_body(
        source_cmake,
        "NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES",
    )
    host_body = set_body(
        source_cmake,
        "NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES",
    )
    portable_body = set_body(
        source_cmake,
        "NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES",
    )
    production = source_tokens(production_body)
    host = source_tokens(host_body)

    if STORE_PORT_SOURCE not in production:
        failures.append("generic store-port must be in ESP/Host production set")
    for source in (HOST_STORE_SOURCE, HOST_COORDINATOR_SOURCE):
        if source not in host:
            failures.append(f"Host-only source missing from Host set: {source}")
        if source in production:
            failures.append(f"Host-only source leaked into production set: {source}")
    if portable_body is None or (
        "${NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES}" not in portable_body
    ):
        failures.append("portable Host set must expand exact Host source authority")

    component_code = strip_cmake_comments(component_cmake)
    if "NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES" not in component_code:
        failures.append("ESP component must consume production source authority")
    if (
        "NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES" in component_code
        or HOST_COORDINATOR_SOURCE in component_code
        or HOST_STORE_SOURCE in component_code
    ):
        failures.append("ESP component references a Host-only MFDT source")

    root_code = strip_cmake_comments(root_cmake)
    if (
        "NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES" not in root_code
        or "target_sources(ninlil_runtime_private" not in root_code
    ):
        failures.append("Host private archive does not consume portable MFDT set")
    if re.search(
        r"install\s*\([^)]*(?:ninlil_mfdt|runtime_private)",
        root_code,
        flags=re.DOTALL,
    ):
        failures.append("private MFDT/runtime target appears in install()")

    coordinator_code = strip_c_comments(coordinator_source)
    if re.search(
        r"\b(?:malloc|calloc|realloc|free|"
        r"ninlil_mfdt_v1_target_zalloc|"
        r"ninlil_mfdt_v1_target_free)\s*\(",
        coordinator_code,
    ):
        failures.append("Host coordinator performs dynamic allocation")
    required_layout_tokens = (
        "_Static_assert(sizeof(ninlil_mfdt_v1_host_owner_t) ==",
        "_Static_assert(_Alignof(ninlil_mfdt_v1_host_owner_t) >=",
        "_Static_assert(offsetof(mfdt_host_owner_layout_t, arenas) ==",
        "_Static_assert(sizeof(mfdt_host_owner_layout_t) ==",
    )
    for token in required_layout_tokens:
        if token not in coordinator_source:
            failures.append(f"coordinator lacks compile-time layout gate: {token}")
    return failures


def nm_output(path: Path) -> tuple[str, str | None]:
    if not path.is_file():
        return "", f"archive missing: {path}"
    completed = subprocess.run(
        ["nm", "-g", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return "", f"nm failed for {path}: {completed.stderr.strip()}"
    return completed.stdout + completed.stderr, None


def check_archive(
    path: Path,
    *,
    require_host: bool,
    forbid_all_mfdt: bool,
) -> list[str]:
    output, error = nm_output(path)
    if error is not None:
        return [error]
    failures: list[str] = []
    if require_host and HOST_SYMBOL not in output:
        failures.append(f"{path.name} lacks Host coordinator symbol")
    if not require_host and HOST_SYMBOL in output:
        failures.append(f"{path.name} contains forbidden Host coordinator symbol")
    if forbid_all_mfdt and MFDT_SYMBOL_PREFIX in output:
        failures.append(f"{path.name} contains private MFDT symbols")
    return failures


def read_required(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file():
        raise FileNotFoundError(relative)
    return path.read_text(encoding="utf-8")


def run_check(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    failures: list[str] = []
    try:
        source_cmake = read_required(
            root,
            "cmake/ninlil_mfdt_v1_sources.cmake",
        )
        component_cmake = read_required(
            root,
            "ports/esp-idf/components/ninlil/CMakeLists.txt",
        )
        root_cmake = read_required(root, "CMakeLists.txt")
        coordinator_source = read_required(root, HOST_COORDINATOR_SOURCE)
        read_required(root, HOST_HEADER)
    except (OSError, UnicodeError) as error:
        print(f"mfdt Host profile boundary FAIL: {error}", file=sys.stderr)
        return 1

    failures.extend(
        check_authority(
            source_cmake,
            component_cmake,
            root_cmake,
            coordinator_source,
        )
    )
    for public_root in (root / "include", root / "ports/esp-idf/include"):
        for path in public_root.rglob("*mfdt*"):
            if path.is_file():
                failures.append(
                    f"private MFDT header leaked into public include tree: "
                    f"{path.relative_to(root)}"
                )

    if args.build_dir is not None:
        build_dir = args.build_dir.resolve()
        public_archive = build_dir / "libninlil_runtime.a"
        private_archive = build_dir / "libninlil_runtime_private.a"
        if public_archive.is_file():
            failures.extend(
                check_archive(
                    public_archive,
                    require_host=False,
                    forbid_all_mfdt=True,
                )
            )
        failures.extend(
            check_archive(
                private_archive,
                require_host=True,
                forbid_all_mfdt=False,
            )
        )
    if args.esp_archive is not None:
        failures.extend(
            check_archive(
                args.esp_archive.resolve(),
                require_host=False,
                forbid_all_mfdt=False,
            )
        )

    if failures:
        for failure in failures:
            print(f"mfdt Host profile boundary FAIL: {failure}", file=sys.stderr)
        return 1
    print(
        "mfdt Host profile boundary OK: "
        "Host=4 source-private; ESP=1; install ABI unchanged"
    )
    return 0


def run_self_test() -> int:
    source = f"""
set(NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES
    {STORE_PORT_SOURCE}
)
set(NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES
    {HOST_STORE_SOURCE}
    {HOST_COORDINATOR_SOURCE}
)
set(NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES
    ${{NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES}}
    ${{NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES}}
)
"""
    component = """
foreach(_rel IN LISTS NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES)
  list(APPEND NINLIL_COMPONENT_SRCS "${_rel}")
endforeach()
"""
    root = """
target_sources(ninlil_runtime_private PRIVATE
  ${NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES})
"""
    coordinator = """
_Static_assert(sizeof(ninlil_mfdt_v1_host_owner_t) == 280064u, "owner");
_Static_assert(_Alignof(ninlil_mfdt_v1_host_owner_t) >= 8u, "align");
_Static_assert(offsetof(mfdt_host_owner_layout_t, arenas) == 17920u, "off");
_Static_assert(sizeof(mfdt_host_owner_layout_t) == 280064u, "layout");
"""
    if check_authority(source, component, root, coordinator):
        print("self-test valid fixture rejected", file=sys.stderr)
        return 1
    mutations = (
        source.replace(
            f"    {HOST_COORDINATOR_SOURCE}\n",
            "",
        ),
        source.replace(
            f"set(NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES\n",
            "set(NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES\n"
            f"    {STORE_PORT_SOURCE}\n",
        ).replace(
            f"set(NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES\n",
            "set(NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES\n"
            f"    {HOST_COORDINATOR_SOURCE}\n",
        ),
        source.replace(
            "    ${NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES}\n",
            "",
        ),
    )
    for index, mutation in enumerate(mutations):
        if not check_authority(mutation, component, root, coordinator):
            print(
                f"self-test authority mutation {index} survived",
                file=sys.stderr,
            )
            return 1
    if not check_authority(
        source,
        component + f"\n{HOST_COORDINATOR_SOURCE}\n",
        root,
        coordinator,
    ):
        print("self-test ESP leak survived", file=sys.stderr)
        return 1
    if not check_authority(
        source,
        component,
        root,
        coordinator + "\nvoid f(void) { (void)calloc(1, 1); }\n",
    ):
        print("self-test allocator mutation survived", file=sys.stderr)
        return 1
    print("mfdt Host profile boundary self-test OK")
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "self-test":
        return run_self_test()
    return run_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
