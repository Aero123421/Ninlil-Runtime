#!/usr/bin/env python3
"""Private NRW1 LINK/FRAG ESP packaging gate (default-OFF).

Proves:
  - single source authority cmake/ninlil_r7_frag_sources.cmake
  - ESP component includes authority and gates sources on Kconfig
  - Kconfig default n; sdkconfig.defaults does not enable
  - public installed headers do not declare FRAG APIs
  - host ctest registration expands the same authority list
  - disabled default: no FRAG in default smoke path references unless gated

Does not claim RF/HIL/legal/software gap=0 alone.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
AUTHORITY = REPO_ROOT / "cmake" / "ninlil_r7_frag_sources.cmake"
CTEST = REPO_ROOT / "cmake" / "ninlil_r7_frag_ctest.cmake"
COMPONENT = REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
KCONFIG = REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "Kconfig"
SMOKE_DEFAULTS = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "sdkconfig.defaults"
SMOKE_ON = (
    REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "sdkconfig.defaults.r7_frag_on"
)
SMOKE_MAIN = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "main" / "main.c"
HOST_CMAKE = REPO_ROOT / "CMakeLists.txt"
PUBLIC_HEADERS = (
    REPO_ROOT / "include" / "ninlil" / "platform.h",
    REPO_ROOT / "include" / "ninlil" / "runtime.h",
    REPO_ROOT / "include" / "ninlil" / "service.h",
    REPO_ROOT / "include" / "ninlil" / "transaction.h",
    REPO_ROOT / "include" / "ninlil" / "version.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "clock.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "entropy.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "execution.h",
)

SOURCE_LINE_RE = re.compile(
    r"^\s*(src/radio/r7_frag/[A-Za-z0-9_.-]+\.c)\s*$"
)


def fail(msg: str) -> None:
    print(f"esp_idf_r7_frag_packaging_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read(p: pathlib.Path) -> str:
    return p.read_text(encoding="utf-8")


def authority_sources(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        m = SOURCE_LINE_RE.match(line)
        if m:
            out.append(m.group(1))
    return out


def check() -> None:
    if not AUTHORITY.is_file():
        fail("missing cmake/ninlil_r7_frag_sources.cmake single authority")
    auth = read(AUTHORITY)
    if "NINLIL_R7_FRAG_PORTABLE_RELATIVE_SOURCES" not in auth:
        fail("authority missing PORTABLE list")
    if "NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES" not in auth:
        fail("authority missing PRODUCTION list (ESP claim path)")
    if "NINLIL_R7_FRAG_LAB_RELATIVE_SOURCES" not in auth:
        fail("authority missing LAB list (host-only session/durable)")
    if re.search(r"^\s*file\s*\(\s*GLOB", auth, re.MULTILINE | re.IGNORECASE):
        fail("authority must not GLOB")
    srcs = authority_sources(auth)
    if len(srcs) < 9:
        fail(f"authority portable set too small ({len(srcs)})")
    required = {
        "src/radio/r7_frag/r7_frag_state.c",
        "src/radio/r7_frag/r7_frag_session.c",
        "src/radio/r7_frag/r7_frag_wire.c",
        "src/radio/r7_frag/r7_frag_target_smoke.c",
        "src/radio/r7_frag/r7_frag_prod_orch.c",
        "src/radio/r7_frag/r7_frag_adapters.c",
        "src/radio/r7_frag/r7_frag_durable.c",
        "src/radio/r7_frag/r7_frag_core.c",
        "src/radio/r7_frag/r7_frag_ack_ledger.c",
        "src/radio/r7_frag/r7_r2_authority_clock.c",
    }
    missing = required - set(srcs)
    if missing:
        fail(f"authority missing required TUs: {sorted(missing)}")
    # Production list must not contain lab session/durable.
    prod_block = auth.split("NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES", 1)[1]
    prod_block = prod_block.split(")", 1)[0]
    if "r7_frag_session.c" in prod_block or "r7_frag_durable.c" in prod_block:
        fail("PRODUCTION list must not include session/durable lab TUs")

    ctest = read(CTEST)
    if "ninlil_r7_frag_sources.cmake" not in ctest:
        fail("ctest cmake must include single source authority")
    if "NINLIL_R7_FRAG_PORTABLE_RELATIVE_SOURCES" not in ctest:
        fail("ctest must expand PORTABLE authority list")
    # Wire fixture must link production crypto archives — never recompile
    # r7_crypto_portable/nonce (r7_crypto_stack_gate duplicate-owner RED).
    if "ninlil_r7_radio_wire_v1_fixture_test" in ctest:
        m = re.search(
            r"add_executable\s*\(\s*ninlil_r7_radio_wire_v1_fixture_test\b(.*?)\)",
            ctest,
            re.DOTALL,
        )
        if m is None:
            fail("wire fixture executable block missing")
        fixture_srcs = m.group(1)
        for ban in (
            "r7_crypto_portable.c",
            "r7_crypto_nonce.c",
            "r7_crypto_openssl3.c",
            "r7_wire_codec.c",
            "r7_frag_wire.c",
            "r7_frag_core.c",
        ):
            if ban in fixture_srcs:
                fail(
                    f"wire fixture must not recompile production TU {ban} "
                    "(link ninlil_runtime_private / ninlil_r7_frag_private)"
                )
        if "ninlil_runtime_private" not in ctest:
            fail("wire fixture must link ninlil_runtime_private")
        if "ninlil_r7_frag_private" not in ctest:
            fail("wire fixture must link ninlil_r7_frag_private")
    # ctest must not re-list the portable set as a second authority.
    if re.search(
        r"set\s*\(\s*NINLIL_R7_FRAG_PRIVATE_SOURCES",
        ctest,
    ):
        fail("ctest must not redefine a second source list")

    comp = read(COMPONENT)
    if "ninlil_r7_frag_sources.cmake" not in comp:
        fail("ESP component must include FRAG source authority")
    if "CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE" not in comp:
        fail("ESP component must gate FRAG sources on Kconfig")
    if "NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES" not in comp:
        fail("ESP component must expand PRODUCTION list (not full PORTABLE)")
    if re.search(
        r"foreach\s*\(\s*_rel\s+IN\s+LISTS\s+NINLIL_R7_FRAG_PORTABLE_RELATIVE_SOURCES\s*\)",
        comp,
    ):
        fail("ESP component must not expand full PORTABLE (lab would enter DRAM)")
    if "NINLIL_R7_FRAG_SMOKE_LIGHT" not in comp:
        fail("ESP component must define SMOKE_LIGHT for production BSS pin")
    # Public INCLUDE_DIRS must not expose r7_frag.
    if re.search(
        r"INCLUDE_DIRS[\s\S]*?r7_frag",
        comp,
    ) and "PRIV_INCLUDE" not in comp:
        fail("r7_frag must not be public INCLUDE_DIRS")
    # Ensure r7_frag only under PRIV when present.
    if '"${NINLIL_REPO_ROOT}/src/radio/r7_frag"' in comp:
        # Must be in NINLIL_R7_FRAG_PRIV_INCLUDES path, not bare public.
        if "NINLIL_R7_FRAG_PRIV_INCLUDES" not in comp:
            fail("r7_frag include must be private gated list")

    kcfg = read(KCONFIG)
    if "NINLIL_ENABLE_R7_FRAG_PRIVATE" not in kcfg:
        fail("Kconfig missing NINLIL_ENABLE_R7_FRAG_PRIVATE")
    if not re.search(
        r"config\s+NINLIL_ENABLE_R7_FRAG_PRIVATE[\s\S]*?default\s+n",
        kcfg,
    ):
        fail("Kconfig must default n (OFF)")

    defaults = read(SMOKE_DEFAULTS)
    if "CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE=y" in defaults:
        fail("default smoke sdkconfig must not enable FRAG")
    if not SMOKE_ON.is_file():
        fail("missing sdkconfig.defaults.r7_frag_on enable overlay")
    on_txt = read(SMOKE_ON)
    if "CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE=y" not in on_txt:
        fail("enable overlay must set CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE=y")

    smoke = read(SMOKE_MAIN)
    if "ninlil_r7_frag_target_smoke_run" not in smoke:
        fail("smoke main must reference target smoke when enabled")
    if "CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE" not in smoke:
        fail("smoke main FRAG path must be Kconfig-gated")

    host = read(HOST_CMAKE)
    if "NINLIL_ENABLE_R7_FRAG_PRIVATE" not in host:
        fail("host CMake missing NINLIL_ENABLE_R7_FRAG_PRIVATE option")
    if "ninlil_r7_frag_ctest.cmake" not in host:
        fail("host CMake must include r7_frag ctest when option set")

    for hdr in PUBLIC_HEADERS:
        text = read(hdr)
        if "r7_frag" in text or "R7_FRAG" in text:
            fail(f"public header must not mention FRAG: {hdr.relative_to(REPO_ROOT)}")

    print(
        "esp_idf_r7_frag_packaging_gate OK: "
        f"authority_sources={len(srcs)} default=OFF public=0"
    )


def self_test() -> None:
    check()
    # Mutation: authority without smoke TU must fail.
    original = read(AUTHORITY)
    try:
        AUTHORITY.write_text(
            original.replace(
                "src/radio/r7_frag/r7_frag_target_smoke.c\n", ""
            ),
            encoding="utf-8",
        )
        try:
            check()
            fail("self-test accepted authority without target_smoke")
        except SystemExit:
            pass
    finally:
        AUTHORITY.write_text(original, encoding="utf-8")
    check()
    print("esp_idf_r7_frag_packaging_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: esp_idf_r7_frag_packaging_gate.py check|self-test",
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
