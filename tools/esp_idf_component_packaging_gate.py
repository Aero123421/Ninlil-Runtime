#!/usr/bin/env python3
"""ESP-IDF packaging + M3-basic + owner/cell + durable-storage authority gate."""

from __future__ import annotations

import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PORTABLE_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_runtime_private_sources.cmake"
PORT_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_esp_idf_port_sources.cmake"
STORAGE_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_esp_storage_sources.cmake"
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
DOCS_STORAGE = REPO_ROOT / "docs" / "21-m3-esp-idf-durable-storage.md"
DOCS_OWNER = REPO_ROOT / "docs" / "22-m3-owner-cell-agent-skeleton.md"
SMOKE_APP = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "CMakeLists.txt"
SMOKE_MAIN = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "main" / "main.c"
SMOKE_SDKCONFIG = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "sdkconfig.defaults"
PARTITION_CSV = REPO_ROOT / "ports" / "esp-idf" / "partitions" / "ninlil_storage.csv"
HIL_MAIN = REPO_ROOT / "ports" / "esp-idf" / "hil_app" / "main" / "main.c"
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
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "owner_task.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "cell_agent.h",
    REPO_ROOT
    / "ports"
    / "esp-idf"
    / "include"
    / "ninlil_esp_idf"
    / "loopback_tx_permit.h",
)

VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\s*$")
SOURCE_LINE_RE = re.compile(r"^\s*((?:src|ports)/[A-Za-z0-9_./-]+\.c)\s*$")
SOURCE_TOKEN_RE = re.compile(
    r"\$\{(?P<var>[A-Za-z0-9_]+)\}"
    r"|(?P<source>(?:src|ports)/[A-Za-z0-9_./-]+\.c)"
)
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
    """Expand a CMake set() list, including nested ${VAR} references."""
    pattern = re.compile(
        r"set\(\s*(?P<name>[A-Za-z0-9_]+)\s*(?P<body>.*?)^\s*\)",
        re.MULTILINE | re.DOTALL,
    )
    bodies = {m.group("name"): m.group("body") for m in pattern.finditer(text)}

    def expand(name: str, active: tuple[str, ...]) -> list[str]:
        if name in active:
            fail(f"recursive CMake source variable: {' -> '.join(active + (name,))}")
        body = bodies.get(name)
        if body is None:
            fail(f"undefined CMake source variable {name}")
        code = "\n".join(line.split("#", 1)[0] for line in body.splitlines())
        expanded: list[str] = []
        for token in SOURCE_TOKEN_RE.finditer(code):
            nested = token.group("var")
            source = token.group("source")
            if nested is not None:
                expanded.extend(expand(nested, active + (name,)))
            elif source is not None:
                expanded.append(source)
        return expanded

    result: list[str] = []
    seen: set[str] = set()
    for source in expand(var_name, ()):
        if source in seen:
            fail(f"duplicate source after CMake expansion in {var_name}: {source}")
        seen.add(source)
        result.append(source)
    return result


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
    if "ninlil_esp_storage_sources.cmake" not in host:
        fail("host CMakeLists missing storage authority")
    if "esp_idf_port_logic" not in host:
        fail("host missing esp_idf_port_logic test")

    component = read_text(COMPONENT_CMAKE)
    if "ninlil_esp_idf_port_sources.cmake" not in component:
        fail("component missing port authority")
    if "NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES" not in component:
        fail("component must consume port ALL sources")
    if "ninlil_esp_storage_sources.cmake" not in component:
        fail("component missing durable-storage authority")
    if "NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES" not in component:
        fail("component must consume storage TARGET sources")
    component_code = "\n".join(
        line.split("#", 1)[0] for line in component.splitlines()
    )
    if GLOB_RE.search(component_code):
        fail("component must not GLOB")
    for req in (
        "esp_timer",
        "esp_hw_support",
        "bootloader_support",
        "freertos",
        "spi_flash",
        "esp_partition",
        "wear_levelling",
    ):
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
        "ports/esp-idf/src/owner_mailbox_logic.c",
        "ports/esp-idf/src/owner_lifecycle_logic.c",
        "ports/esp-idf/src/owner_publish_logic.c",
        "ports/esp-idf/src/owner_authority_logic.c",
        "ports/esp-idf/src/cell_assignment_logic.c",
        "ports/esp-idf/src/control_boundary_logic.c",
        "ports/esp-idf/src/loopback_tx_permit_logic.c",
        "ports/esp-idf/src/tx_gate_validate.c",
        "ports/esp-idf/src/pointer_range_logic.c",
        "ports/esp-idf/src/abi_header_stage_logic.c",
        "ports/esp-idf/src/owner_config_stage_logic.c",
        "ports/esp-idf/src/tx_gate_lease_logic.c",
        "ports/esp-idf/src/esp_idf_clock.c",
        "ports/esp-idf/src/esp_idf_entropy.c",
        "ports/esp-idf/src/esp_idf_execution.c",
        "ports/esp-idf/src/esp_idf_owner_task.c",
        "ports/esp-idf/src/esp_idf_cell_agent.c",
        "ports/esp-idf/src/esp_idf_loopback_tx_permit.c",
    }
    all_port = set(pure_sources) | set(backend_sources)
    if not required.issubset(all_port):
        fail(f"port sources missing {required - all_port}")

    storage_text = read_text(STORAGE_AUTHORITY)
    storage_target = list_sources_in_var(
        storage_text, "NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES"
    )
    exact_storage_target = [
        "ports/esp-idf/storage/model/esp_storage_codec.c",
        "ports/esp-idf/storage/model/esp_storage_model.c",
        "ports/esp-idf/storage/esp/esp_storage_flash_media.c",
    ]
    if storage_target != exact_storage_target:
        fail(
            "target storage source set must be exactly model2+flash1, got "
            f"{storage_target}"
        )
    for required_storage in exact_storage_target:
        if required_storage not in storage_text:
            fail(f"storage authority missing {required_storage}")
        if not (REPO_ROOT / required_storage).is_file():
            fail(f"missing storage source {required_storage}")
    if "ports/esp-idf/storage/host/esp_storage_host_media.c" in storage_target:
        fail("target storage authority must exclude host media")

    # Host-media concrete workspace + private_simulate seams must stay
    # compile-excluded under ESP_PLATFORM (docs/21 host-only dual-slot).
    workspace_hdr = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "storage"
        / "private"
        / "esp_storage_workspace.h"
    )
    workspace_text = read_text(workspace_hdr)
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"(?:/\*[\s\S]*?\*/\s*\n)?"
        r"struct\s+ninlil_port_esp_storage_host_media\s*\{",
        workspace_text,
    ):
        fail(
            "esp_storage_workspace.h host_media struct must be "
            "compile-excluded under ESP_PLATFORM"
        )
    private_hdr = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "storage"
        / "private"
        / "esp_storage_private.h"
    )
    private_text = read_text(private_hdr)
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"(?:/\*[\s\S]*?\*/\s*\n)?"
        r"void\s+ninlil_port_esp_storage_private_simulate_crash\s*\(",
        private_text,
    ):
        fail(
            "esp_storage_private.h private_simulate_crash must be "
            "compile-excluded under ESP_PLATFORM"
        )
    model_src = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "storage"
        / "model"
        / "esp_storage_model.c"
    )
    model_text = read_text(model_src)
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"void\s+ninlil_port_esp_storage_private_simulate_crash\s*\(",
        model_text,
    ):
        fail(
            "esp_storage_model.c private_simulate_crash definition must be "
            "compile-excluded under ESP_PLATFORM"
        )

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
    for needle in (
        "ports/esp-idf/hil_app",
        "esp_storage_map_gate.py",
        "esp_storage_stack_gate.py",
        "esp_storage_public_api_gate.py",
        "xtensa-esp32s3-elf-readelf",
        "ninlil_m3_combined_smoke.map",
        "ninlil_storage_powercut_hil.map",
        "ninlil_storage_powercut_hil.elf",
    ):
        if needle not in ci:
            fail(f"esp-idf.yml missing storage target gate {needle!r}")
    # Official target archive inspection must declare --archive-kind target
    # (host CTest uses host kind; refuse silent default / inverted wiring).
    if "--archive-kind target" not in ci:
        fail(
            "esp-idf.yml public_api_gate must pass --archive-kind target "
            "(host CTest uses --archive-kind host)"
        )
    if "--archive-kind host" in ci:
        fail(
            "esp-idf.yml must not pass --archive-kind host "
            "(target workflow inspects the official ESP archive)"
        )
    # Both official maps must be required (not smoke-only).
    if ci.count("esp_storage_map_gate.py") < 2:
        fail("esp-idf.yml must run esp_storage_map_gate.py on smoke and HIL maps")

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

    docs21 = read_text(DOCS_STORAGE)
    for needle in (
        "PSRAM",
        "ESP_UNPROVEN",
        "COMMIT_UNKNOWN",
        "iterator",
        "final-net",
        "HIL 未実行",
    ):
        if needle not in docs21:
            fail(f"docs/21 must document {needle!r}")

    docs22 = read_text(DOCS_OWNER)
    for needle in (
        "inflight",
        "FAILED_LIVE",
        "FAILED_JOINED",
        "JOIN_ACK",
        "vTaskDelete",
        "prvDeleteTCB",
        "start_gate",
        "4096",
        "StackType_t",
        "experimental",
        "logical_bytes",
        "lease",
        "MAX_TX_GATE_LEASES",
        "mux_ready",
        "M3 incomplete",
        "self-stop",
        "single-use",
        "non-overlap",
        "uintptr_t",
        "pointer-compare",
        "detect_invalid_pointer_pairs",
        "tx_gate_lease_registry.h",
        "ABI header staging",
        "declared struct_size",
        "detail/",
        "Target smoke",
        "trusted initial publish",
        "exact",
        "struct_size` 除外",
        "post-write reread",
        "owner_config_stage",
    ):
        if needle not in docs22:
            fail(f"docs/22 must document {needle!r}")

    owner_backend = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "esp_idf_owner_task.c"
    )
    if "ninlil_esp_idf_owner_config_stage" not in owner_backend:
        fail("owner_task_init path must call owner_config_stage helper")
    host_test = read_text(
        REPO_ROOT / "tests" / "port" / "owner_cell_agent_logic_test.c"
    )
    if "ninlil_esp_idf_owner_config_stage" not in host_test:
        fail("host owner test must exercise owner_config_stage (not generic only)")
    if "|| (declared - known)" in host_test or "|| declared - known" in host_test:
        fail("owner logic test has vacuous OR geometry assertion")

    host = read_text(HOST_CMAKE)
    if "owner_cell_agent_logic" not in host:
        fail("host CMakeLists missing owner_cell_agent_logic test")
    if "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER" not in host:
        fail("host CMakeLists missing pointer-compare sanitizer option")
    if "esp_storage_dual_slot_conformance" not in host:
        fail("host CMakeLists missing esp_storage_dual_slot_conformance test")
    if "esp_storage_stack_gate" not in host:
        fail("host CMakeLists missing esp_storage_stack_gate test")
    if "esp_storage_wear_gate" not in host:
        fail("host CMakeLists missing esp_storage_wear_gate test")
    if "esp_storage_budget_gate" not in host:
        fail("host CMakeLists missing esp_storage_budget_gate test")
    if "esp_storage_public_api_gate.py" not in host:
        fail("host CMakeLists missing esp_storage_public_api_gate test")
    # Host CTest archive is the dual-slot host library (includes host media
    # test seams). Kind must be host; target kind here would false-fail on
    # intentional ninlil_port_esp_storage_host_media_ops.
    if "--archive-kind host" not in host:
        fail(
            "host CMakeLists public_api_gate must pass --archive-kind host "
            "(refuse missing kind / silent target rules on host archive)"
        )
    if "--archive-kind target" in host:
        fail(
            "host CMakeLists must not pass --archive-kind target "
            "(official ESP archive is gated in esp-idf.yml)"
        )

    ci_host = read_text(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    if "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER" not in ci_host:
        fail("host ci.yml missing pointer-compare sanitizer job")
    if "detect_invalid_pointer_pairs=2" not in ci_host:
        fail("host ci.yml missing detect_invalid_pointer_pairs=2")

    owner_api = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "owner_task.h"
    )
    if "tx_gate_lease_registry_t" in owner_api or "tx_gate_lease_slot_t" in owner_api:
        fail("public owner_task.h must not expose registry/slot internal types")
    if "ABI staging" not in owner_api:
        fail("public owner_task.h must document ABI staging")

    old_reg = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "include"
        / "ninlil_esp_idf"
        / "tx_gate_lease_registry.h"
    )
    if old_reg.is_file():
        fail("registry layout must not remain outside detail/")
    reg_hdr = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "include"
        / "ninlil_esp_idf"
        / "detail"
        / "tx_gate_lease_registry.h"
    )
    if not reg_hdr.is_file():
        fail("missing detail/tx_gate_lease_registry.h unstable layout header")
    if "Unstable concrete storage detail" not in read_text(reg_hdr):
        fail("detail registry header must declare unstable storage detail")

    # Trusted/nested helpers must not ship as default global ELF symbols.
    # Prefer static inline (local / absent in nm), not merely -fvisibility=hidden.
    if "cell_config_stage_logic.c" in pure_sources:
        fail("cell_config_stage_nested_owner must not be a pure .c TU (use static inline)")
    lease_c = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "tx_gate_lease_logic.c")
    if re.search(
        r"(?m)^(?!\s*static\s).*set_ops_trusted\s*\(", lease_c
    ) or "set_ops_trusted" in lease_c:
        fail("set_ops_trusted must not be defined in tx_gate_lease_logic.c")
    owner_c = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "esp_idf_owner_task.c")
    if "publish_tx_gate_trusted" in owner_c:
        fail("publish_tx_gate_trusted must not be defined in esp_idf_owner_task.c")
    lease_h = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "tx_gate_lease_logic.h")
    if "static inline" not in lease_h or "set_ops_trusted" not in lease_h:
        fail("set_ops_trusted must be static inline in private header")
    trusted_h = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "owner_tx_gate_trusted.h")
    if "static inline" not in trusted_h or "publish_tx_gate_trusted" not in trusted_h:
        fail("publish_tx_gate_trusted must be static inline in private header")
    cell_stage_h = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "cell_config_stage_logic.h"
    )
    if "static inline" not in cell_stage_h or "cell_config_stage_nested_owner" not in cell_stage_h:
        fail("cell_config_stage_nested_owner must be static inline in private header")
    if (REPO_ROOT / "ports" / "esp-idf" / "src" / "cell_config_stage_logic.c").is_file():
        fail("cell_config_stage_logic.c must be removed (header-only static inline)")
    # Failure atomicity: stage to temps, commit only on success (no out poison).
    if "outer_tmp" not in cell_stage_h or "owner_tmp" not in cell_stage_h:
        fail("cell_config_stage must stage into temps before commit")
    if "*out_outer_local = outer_tmp" not in cell_stage_h:
        fail("cell_config_stage must commit outer_tmp only after validation")
    owner_stage_c = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "owner_config_stage_logic.c"
    )
    owner_stage_h = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "owner_config_stage_logic.h"
    )
    if "NINLIL_ESP_IDF_INTERNAL" not in owner_stage_h:
        fail("owner_config_stage must use NINLIL_ESP_IDF_INTERNAL (non-DEFAULT export)")
    if "local_tmp" not in owner_stage_c or "hdr_tmp" not in owner_stage_c:
        fail("owner_config_stage must stage into temps before commit")
    if "(owner_storage == NULL) != (owner_storage_size == 0u)" not in owner_stage_c:
        fail("owner_config_stage must closed-reject NULL/size storage contradictions")
    if "pointer_ranges_overlap" not in owner_stage_c:
        fail("owner_config_stage must reject out/storage alias via pointer_range helper")
    internal_h = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "ninlil_esp_idf_internal.h"
    )
    if "visibility" not in internal_h or "hidden" not in internal_h:
        fail("ninlil_esp_idf_internal.h must define portable hidden visibility")
    # Official ELF gates must be wired into esp-idf.yml (objdump frame + readelf).
    if "esp_idf_app_main_frame_gate.py" not in ci:
        fail("esp-idf.yml must run app_main frame gate")
    if "xtensa-esp32s3-elf-objdump" not in ci:
        fail("esp-idf.yml frame gate must use xtensa-esp32s3-elf-objdump explicitly")
    if "esp_idf_private_symbol_gate.py" not in ci:
        fail("esp-idf.yml must run private symbol / readelf gate")
    if "xtensa-esp32s3-elf-readelf" not in ci:
        fail("esp-idf.yml symbol gate must use xtensa-esp32s3-elf-readelf explicitly")
    frame_gate = read_text(REPO_ROOT / "tools" / "esp_idf_app_main_frame_gate.py")
    if "false-green" not in frame_gate and "false_green" not in frame_gate:
        fail("frame gate must refuse false-green when objdump missing")
    if "SAFE_MARGIN_BYTES" not in frame_gate:
        fail("frame gate must assert a safety margin")
    sym_gate = read_text(REPO_ROOT / "tools" / "esp_idf_private_symbol_gate.py")
    if "GLOBAL" not in sym_gate or "DEFAULT" not in sym_gate:
        fail("private symbol gate must reject GLOBAL DEFAULT")
    if "owner_config_stage" not in sym_gate:
        fail("private symbol gate must cover owner_config_stage")

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
        "ninlil_esp_idf/owner_task_storage.h",
        "ninlil_esp_idf/cell_agent_storage.h",
        "ninlil_esp_idf/loopback_tx_permit.h",
        "NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG",
        "ninlil_esp_idf_entropy_shutdown",
        "ninlil_esp_idf_clock_shutdown",
        "ninlil_esp_idf_loopback_tx_permit",
        "SELFTEST",
        "producer_task",
        "post_tick_from_isr",
        "DOUBLE_STOP",
        "stack_hwm_bytes",
        "ESP_TIMER_ISR",
        "acquire_tx_gate_lease",
        "LEASE_STALE",
        "max_leases",
        "event_group_null",
        "double_release_not_stale",
        "snapshot_borrowers_not_2",
        "shutdown_not_busy_two_leases",
        "forged_release_not_stale",
        "tx_gate_borrowers",
        "owner_init_forward_ext",
        "retired s_standalone_owner",
        "ninlil_port/esp_storage.h",
        "ninlil_port/esp_storage_flash.h",
        "ninlil_port_esp_storage_flash_bind",
        "ninlil_port_esp_storage_flash_unbind",
        "NINLIL_STORAGE_COMMIT_UNKNOWN",
        "smoke_storage_commit_unknown",
    ):
        if needle not in smoke_main:
            fail(f"smoke_app must include/use {needle!r}")
    # Post-shutdown full memset of retired standalone owner is forbidden
    # (destroys lifecycle evidence). Pre-init zero remains allowed.
    post_shutdown_wipe = re.search(
        r"owner_task_shutdown\(&s_standalone_owner\).*?"
        r"memset\(&s_standalone_owner",
        smoke_main,
        re.DOTALL,
    )
    if post_shutdown_wipe:
        fail("smoke must not memset retired s_standalone_owner after shutdown")

    # Host tests must assert failure-path output immutability for both helpers.
    if "outer_poison" not in host_test or "local_poison" not in host_test:
        fail("owner_cell_agent_logic_test must poison outs for atomicity checks")
    if "closed reject" not in host_test:
        fail("host owner/cell tests must cover storage NULL/size closed reject")
    if "failure atomicity" not in host_test and "Failure-path output" not in host_test:
        fail("host tests must document/cover failure atomicity for stage helpers")

    sdkconfig = read_text(SMOKE_SDKCONFIG)
    for needle in (
        "CONFIG_SPIRAM=y",
        'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="../partitions/ninlil_storage.csv"',
        "CONFIG_WL_SECTOR_SIZE_4096=y",
        "CONFIG_FREERTOS_UNICORE=n",
        "CONFIG_FREERTOS_CHECK_PORT_CRITICAL_COMPLIANCE=y",
        "CONFIG_ESP_TIMER_SUPPORTS_ISR_DISPATCH_METHOD=y",
    ):
        if needle not in sdkconfig:
            fail(f"smoke sdkconfig missing {needle!r}")
    read_text(PARTITION_CSV)
    read_text(HIL_MAIN)

    print(
        "esp_idf_component_packaging_gate OK: "
        f"pin={pin} pure={len(pure_sources)} backend={len(backend_sources)} "
        f"storage_target={len(storage_target)}"
    )


def self_test() -> None:
    if not VERSION_RE.match("v5.5.3") or VERSION_RE.match("release-v5.1"):
        fail("self-test VERSION_RE")
    sample = "    ports/esp-idf/src/clock_logic.c\n"
    if authority_sources(sample) != ["ports/esp-idf/src/clock_logic.c"]:
        fail("self-test source parse")
    recursive = """set(MODEL
    ports/esp-idf/storage/model/a.c
    ports/esp-idf/storage/model/b.c
)
set(TARGET
    ${MODEL}
    ports/esp-idf/storage/esp/media.c
)
"""
    if list_sources_in_var(recursive, "TARGET") != [
        "ports/esp-idf/storage/model/a.c",
        "ports/esp-idf/storage/model/b.c",
        "ports/esp-idf/storage/esp/media.c",
    ]:
        fail("self-test recursive source expansion")
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
