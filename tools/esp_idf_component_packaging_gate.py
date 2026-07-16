#!/usr/bin/env python3
"""M3-prep ESP-IDF packaging consistency gate.

Checks:
1. Host CMakeLists includes the single private-source authority.
2. ESP-IDF component CMakeLists includes the same authority (no local glob).
3. ports/esp-idf/ESP_IDF_VERSION is a concrete vX.Y.Z pin.
4. Docs, CI workflow, and idf_component.yml use the same pin.
5. Component packaging does not compile tests/generated/tools sources.

Does not claim ESP-IDF port complete, M3 complete, or hardware verification.
"""

from __future__ import annotations

import pathlib
import re
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
AUTHORITY = REPO_ROOT / "cmake" / "ninlil_runtime_private_sources.cmake"
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
SMOKE_APP = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "CMakeLists.txt"
PIN_MIRRORS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "CHANGELOG.md",
    REPO_ROOT / "docs" / "06-versioning-and-compatibility.md",
    REPO_ROOT / "docs" / "09-roadmap.md",
    REPO_ROOT / "ports" / "esp-idf" / "README.md",
)

VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\s*$")
SOURCE_LINE_RE = re.compile(r"^\s*(src/[A-Za-z0-9_./]+\.c)\s*$")
GLOB_RE = re.compile(r"file\s*\(\s*GLOB", re.IGNORECASE)


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
    """Return unique src/*.c entries from the authority file (stable order)."""
    sources: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        # Strip CMake comments.
        code = line.split("#", 1)[0].strip().rstrip(")")
        m = SOURCE_LINE_RE.match(code)
        if m:
            rel = m.group(1)
            if rel not in seen:
                seen.add(rel)
                sources.append(rel)
    return sources


def check() -> None:
    pin = read_pin()
    numeric = pin_numeric(pin)

    host = read_text(HOST_CMAKE)
    if "ninlil_runtime_private_sources.cmake" not in host:
        fail("host CMakeLists.txt does not include private source authority")
    if "NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES" not in host:
        fail(
            "host CMakeLists.txt does not consume "
            "NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES"
        )

    component = read_text(COMPONENT_CMAKE)
    if "ninlil_runtime_private_sources.cmake" not in component:
        fail(
            "ESP-IDF component CMakeLists.txt does not include "
            "private source authority"
        )
    if "idf_component_register" not in component:
        fail("ESP-IDF component CMakeLists.txt missing idf_component_register")
    component_code = "\n".join(
        line.split("#", 1)[0] for line in component.splitlines()
    )
    if GLOB_RE.search(component_code):
        fail("ESP-IDF component CMakeLists.txt must not use file(GLOB)")
    if "NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN" in component_code:
        fail("ESP-IDF component must not enable TEST transport begin")

    authority = read_text(AUTHORITY)
    authority_code = "\n".join(
        line.split("#", 1)[0] for line in authority.splitlines()
    )
    if GLOB_RE.search(authority_code):
        fail("private source authority must not use file(GLOB)")
    sources = authority_sources(authority)
    if not sources:
        fail("private source authority lists no src/*.c entries")
    for rel in sources:
        if rel.startswith(("tests/", "generated/", "tools/")):
            fail(f"private source authority must not list {rel}")
        src = REPO_ROOT / rel
        if not src.is_file():
            fail(f"authority lists missing source: {rel}")
        text = src.read_text(encoding="utf-8", errors="replace")
        if re.search(r'#\s*include\s*[<"]esp_', text):
            fail(f"portable source includes ESP-IDF header: {rel}")
        if re.search(r'#\s*include\s*[<"]freertos/', text):
            fail(f"portable source includes FreeRTOS header: {rel}")

    yml = read_text(COMPONENT_YML)
    if f"=={numeric}" not in yml:
        fail(
            "idf_component.yml idf dependency pin does not match "
            f"ESP_IDF_VERSION ({pin} / =={numeric})"
        )
    if "esp32s3" not in yml:
        fail("idf_component.yml must declare esp32s3 target")

    ci = read_text(CI_WORKFLOW)
    if "ESP_IDF_VERSION" not in ci:
        fail("esp-idf.yml must read ports/esp-idf/ESP_IDF_VERSION")
    if pin not in ci:
        fail(
            f"esp-idf.yml must mention current pin {pin} "
            "(comment and/or image tag; keep docs/CI/version file aligned)"
        )
    if "espressif/idf:" not in ci:
        fail("esp-idf.yml must use official espressif/idf Docker image")
    if "esp32s3" not in ci:
        fail("esp-idf.yml must build target esp32s3")
    if re.search(r"\bctest\b", ci):
        fail("esp-idf.yml must stay separate from host ctest")

    docs = read_text(DOCS_PIN)
    if pin not in docs:
        fail(f"docs/18-m3-prep-esp-idf-component.md does not document pin {pin}")
    if "M3-prep" not in docs:
        fail("docs must label the pin as M3-prep")
    # Affirmative completion claims only (negated "does not claim ..." is OK).
    affirmative = (
        re.compile(r"(?<![Nn]ot claim )(?<![Dd]oes not claim )M3 complete"),
        re.compile(r"(?<![Nn]ot claim )ESP-IDF port complete"),
        re.compile(r"\bhardware verified\b"),
        re.compile(r"\bV1 complete\b"),
        re.compile(r"M3 milestone の完了を達成"),
    )
    for pat in affirmative:
        if pat.search(docs):
            fail(f"docs must not affirmatively claim completion ({pat.pattern})")

    for mirror in PIN_MIRRORS:
        mirror_text = read_text(mirror)
        if pin not in mirror_text:
            fail(
                f"{mirror.relative_to(REPO_ROOT)} does not mirror current pin {pin}"
            )

    smoke = read_text(SMOKE_APP)
    if "EXTRA_COMPONENT_DIRS" not in smoke:
        fail("smoke_app must set EXTRA_COMPONENT_DIRS")
    if "components" not in smoke:
        fail("smoke_app must reference ports/esp-idf/components")

    print(
        "esp_idf_component_packaging_gate OK: "
        f"pin={pin} sources={len(sources)} component=present ci=esp32s3"
    )


def self_test() -> None:
    """Negative self-tests for detectors used by check()."""
    pin = read_pin()

    if VERSION_RE.match("release-v5.1"):
        fail("self-test: floating release branch must not match VERSION_RE")
    if not VERSION_RE.match("v5.5.3"):
        fail("self-test: concrete pin must match VERSION_RE")
    if pin_numeric("v5.5.3") != "5.5.3":
        fail("self-test: pin_numeric broken")
    if pin_numeric(pin) != pin[1:]:
        fail("self-test: live pin numeric mismatch")

    if not GLOB_RE.search("file(GLOB SRCS *.c)"):
        fail("self-test: GLOB detector broken")
    if GLOB_RE.search("set(SRCS a.c b.c)"):
        fail("self-test: GLOB detector false positive")

    sample = (
        "# comment tests/ tools/\n"
        "set(NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\n"
        "    src/runtime/domain_store_scanner.c\n"
        "    src/runtime/runtime_store_stage5_seam.c\n"
        ")\n"
    )
    parsed = authority_sources(sample)
    if parsed != [
        "src/runtime/domain_store_scanner.c",
        "src/runtime/runtime_store_stage5_seam.c",
    ]:
        fail(f"self-test: authority_sources parse broken: {parsed}")

    authority = read_text(AUTHORITY)
    for required in (
        "src/runtime/domain_store_scanner.c",
        "src/runtime/runtime_store_stage5_seam.c",
        "src/model/runtime_store_codec.c",
    ):
        if required not in authority_sources(authority):
            fail(f"self-test: authority missing {required}")

    print("esp_idf_component_packaging_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: esp_idf_component_packaging_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    if argv[1] == "check":
        check()
    else:
        self_test()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
