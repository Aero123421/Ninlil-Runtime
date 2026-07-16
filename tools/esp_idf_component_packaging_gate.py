#!/usr/bin/env python3
"""ESP-IDF packaging + M3-basic port authority gate."""

from __future__ import annotations

import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PORTABLE_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_runtime_private_sources.cmake"
PORT_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_esp_idf_port_sources.cmake"
HOST_CMAKE = REPO_ROOT / "CMakeLists.txt"
COMPONENT_CMAKE = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
)
COMPONENT_YML = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "idf_component.yml"
)
VERSION_FILE = REPO_ROOT / "ports" / "esp-idf" / "ESP_IDF_VERSION"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "esp-idf.yml"
DOCS_PIN = REPO_ROOT / "docs" / "18-m3-prep-esp-idf-component.md"
DOCS_BASIC = REPO_ROOT / "docs" / "20-m3-basic-esp-idf-platform-adapters.md"
SMOKE_APP = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "CMakeLists.txt"
SMOKE_MAIN = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "main" / "main.c"
PIN_MIRRORS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "CHANGELOG.md",
    REPO_ROOT / "docs" / "06-versioning-and-compatibility.md",
    REPO_ROOT / "docs" / "09-roadmap.md",
    REPO_ROOT / "ports" / "esp-idf" / "README.md",
)
PORT_HEADERS = (
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "clock.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "entropy.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "execution.h",
)

VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\s*$")
SOURCE_LINE_RE = re.compile(r"^\s*((?:src|ports)/[A-Za-z0-9_./-]+\.c)\s*$")
GLOB_RE = re.compile(r"file\s*\(\s*GLOB", re.IGNORECASE)
ESP_INCLUDE_RE = re.compile(r'#\s*include\s*[<"]esp_')
FREERTOS_INCLUDE_RE = re.compile(r'#\s*include\s*[<"]freertos/')


def fail(msg: str) -> None:
    print(f"esp_idf_component_packaging_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(REPO_ROOT)}")
    return path.read_text(encoding="utf-8")


def read_pin() -> str:
    raw = read_text(VERSION_FILE).strip()
    if not VERSION_RE.match(raw):
        fail(f"ESP_IDF_VERSION must be concrete vX.Y.Z, got {raw!r}")
    return raw


def pin_numeric(pin: str) -> str:
    m = VERSION_RE.match(pin)
    assert m is not None
    return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"


def authority_sources(text: str) -> list[str]:
    sources: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        code = line.split("#", 1)[0].strip().rstrip(")")
        m = SOURCE_LINE_RE.match(code)
        if m:
            rel = m.group(1)
            if rel not in seen:
                seen.add(rel)
                sources.append(rel)
    return sources


def list_sources_in_var(text: str, var_name: str) -> list[str]:
    pattern = re.compile(
        rf"set\(\s*{re.escape(var_name)}\s*(.*?)^\s*\)",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(text)
    if not m:
        return []
    return authority_sources(m.group(1))


def assert_no_esp_freertos(rel: str, text: str) -> None:
    if ESP_INCLUDE_RE.search(text):
        fail(f"source must not include ESP-IDF header: {rel}")
    if FREERTOS_INCLUDE_RE.search(text):
        fail(f"source must not include FreeRTOS header: {rel}")


def check() -> None:
    pin = read_pin()
    numeric = pin_numeric(pin)

    host = read_text(HOST_CMAKE)
    if "ninlil_runtime_private_sources.cmake" not in host:
        fail("host CMakeLists missing private authority")
    if "ninlil_esp_idf_port_sources.cmake" not in host:
        fail("host CMakeLists missing ESP-IDF port authority")
    if "esp_idf_port_logic" not in host:
        fail("host missing esp_idf_port_logic test")

    component = read_text(COMPONENT_CMAKE)
    if "ninlil_esp_idf_port_sources.cmake" not in component:
        fail("component missing port authority")
    if "NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES" not in component:
        fail("component must consume port ALL sources")
    component_code = "\n".join(
        line.split("#", 1)[0] for line in component.splitlines()
    )
    if GLOB_RE.search(component_code):
        fail("component must not GLOB")
    for req in ("esp_timer", "esp_hw_support", "bootloader_support", "freertos"):
        if req not in component:
            fail(f"component should PRIV_REQUIRES {req}")

    portable_text = read_text(PORTABLE_AUTHORITY)
    portable_sources = authority_sources(portable_text)
    for rel in portable_sources:
        if rel.startswith("ports/"):
            fail(f"portable authority must not list {rel}")
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        assert_no_esp_freertos(rel, text)

    port_text = read_text(PORT_AUTHORITY)
    pure_sources = list_sources_in_var(
        port_text, "NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES"
    )
    backend_sources = list_sources_in_var(
        port_text, "NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES"
    )
    if not pure_sources or not backend_sources:
        fail("port authority pure/backend empty")
    for rel in pure_sources:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        assert_no_esp_freertos(rel, text)
    for rel in backend_sources:
        if not (REPO_ROOT / rel).is_file():
            fail(f"missing backend {rel}")

    required = {
        "ports/esp-idf/src/entropy_lifecycle_logic.c",
        "ports/esp-idf/src/entropy_publish_logic.c",
        "ports/esp-idf/src/execution_init_logic.c",
        "ports/esp-idf/src/esp_idf_clock.c",
        "ports/esp-idf/src/esp_idf_entropy.c",
        "ports/esp-idf/src/esp_idf_execution.c",
    }
    all_port = set(pure_sources) | set(backend_sources)
    if not required.issubset(all_port):
        fail(f"port sources missing {required - all_port}")

    for header in PORT_HEADERS:
        h = read_text(header)
        if ESP_INCLUDE_RE.search(h) or FREERTOS_INCLUDE_RE.search(h):
            fail(f"port header must not include ESP/FreeRTOS: {header.name}")
        if "ninlil/platform.h" not in h:
            fail(f"port header must include platform.h: {header.name}")

    yml = read_text(COMPONENT_YML)
    if f"=={numeric}" not in yml or "esp32s3" not in yml:
        fail("idf_component.yml pin/target mismatch")

    ci = read_text(CI_WORKFLOW)
    if pin not in ci or "esp32s3" not in ci or "espressif/idf:" not in ci:
        fail("esp-idf.yml pin/target/image mismatch")
    if re.search(r"\bctest\b", ci):
        fail("esp-idf.yml must not run host ctest")

    docs = read_text(DOCS_PIN)
    if pin not in docs or "M3-prep" not in docs:
        fail("docs/18 pin/M3-prep missing")

    docs19 = read_text(DOCS_BASIC)
    for needle in (
        "one-shot",
        "immutable",
        "DISABLING",
        "ACQUIRING cancel",
        "NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX",
        "RETIRED",
        "TaskHandle",
        "owner-task",
        "esp_timer",
        "BOOTLOADER_RNG",
        "compile/link",
        "M3 incomplete",
    ):
        if needle not in docs19:
            fail(f"docs/20 must document {needle!r}")

    for mirror in PIN_MIRRORS:
        if pin not in read_text(mirror):
            fail(f"{mirror.relative_to(REPO_ROOT)} missing pin {pin}")

    smoke = read_text(SMOKE_APP)
    if "EXTRA_COMPONENT_DIRS" not in smoke:
        fail("smoke_app missing EXTRA_COMPONENT_DIRS")
    smoke_main = read_text(SMOKE_MAIN)
    for needle in (
        "ninlil_esp_idf/clock.h",
        "ninlil_esp_idf/entropy.h",
        "ninlil_esp_idf/execution.h",
        "NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG",
        "ninlil_esp_idf_entropy_shutdown",
        "ninlil_esp_idf_clock_shutdown",
    ):
        if needle not in smoke_main:
            fail(f"smoke_app must include/use {needle!r}")

    print(
        "esp_idf_component_packaging_gate OK: "
        f"pin={pin} pure={len(pure_sources)} backend={len(backend_sources)}"
    )


def self_test() -> None:
    if not VERSION_RE.match("v5.5.3") or VERSION_RE.match("release-v5.1"):
        fail("self-test VERSION_RE")
    sample = "    ports/esp-idf/src/clock_logic.c\n"
    if authority_sources(sample) != ["ports/esp-idf/src/clock_logic.c"]:
        fail("self-test source parse")
    print("esp_idf_component_packaging_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print("usage: esp_idf_component_packaging_gate.py check|self-test", file=sys.stderr)
        return 2
    if argv[1] == "check":
        check()
    else:
        self_test()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
