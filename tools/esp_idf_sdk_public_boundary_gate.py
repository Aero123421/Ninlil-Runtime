#!/usr/bin/env python3
"""ESP-IDF component public include-boundary gate.

Fails closed when:
  - component public INCLUDE_DIRS export any src/** root
  - private target-smoke headers are placed under a public include root
  - public headers under ports/esp-idf/include include private path forms
    (\"byte_stream.h\" without ninlil/, control_session.h, src/ relative)
  - external consumer can compile against private transport roots
  - external consumer cannot compile against public ninlil + ninlil_esp_idf

Does not require a full ESP-IDF install: host CC simulates the include graph
exported by idf_component_register(INCLUDE_DIRS / PRIV_INCLUDE_DIRS).
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPONENT_CMAKE = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
)
PUBLIC_INCLUDE_ROOTS = (
    REPO_ROOT / "include",
    REPO_ROOT / "ports" / "esp-idf" / "include",
    REPO_ROOT / "ports" / "esp-idf" / "storage" / "include",
)
USB_CDC_PUBLIC = (
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "usb_cdc.h"
)
BYTE_STREAM_PUBLIC = REPO_ROOT / "include" / "ninlil" / "byte_stream.h"


def fail(msg: str) -> None:
    print(f"esp_idf_sdk_public_boundary_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(REPO_ROOT)}")
    return path.read_text(encoding="utf-8")


def assert_public_header_path_allowed(path: pathlib.Path) -> None:
    """Reject test/smoke implementation contracts from public include roots."""
    if "target_smoke" in path.name.lower():
        try:
            display = path.relative_to(REPO_ROOT)
        except ValueError:
            display = path
        fail(f"private target-smoke header leaked into public include tree: {display}")


def extract_idf_include_dirs(cmake_text: str) -> tuple[list[str], list[str]]:
    """Parse INCLUDE_DIRS / PRIV_INCLUDE_DIRS blocks from idf_component_register."""
    match = re.search(
        r"idf_component_register\s*\((?P<body>.*)\)\s*\n",
        cmake_text,
        re.DOTALL,
    )
    if match is None:
        fail("idf_component_register(...) not found in component CMakeLists")
    body = match.group("body")

    def collect(key: str) -> list[str]:
        # Stop at the next idf_component_register keyword (exact tokens).
        key_m = re.search(
            rf"(?m)^[ \t]*{key}[ \t]*\n(?P<dirs>.*?)"
            rf"(?=^[ \t]*(?:INCLUDE_DIRS|PRIV_INCLUDE_DIRS|SRCS|REQUIRES|"
            rf"PRIV_REQUIRES|EMBED_FILES|EMBED_TXTFILES)\b|\Z)",
            body,
            re.DOTALL | re.MULTILINE,
        )
        if key_m is None:
            return []
        dirs_blob = key_m.group("dirs")
        # Capture "${NINLIL_REPO_ROOT}/..." and bare quoted paths / vars.
        found = re.findall(
            r'"\$\{NINLIL_REPO_ROOT\}/([^"]+)"|"([^"]+)"|(\$\{[A-Za-z0-9_]+\})',
            dirs_blob,
        )
        out: list[str] = []
        for a, b, c in found:
            if a:
                out.append(a)
            elif b and not b.startswith("${"):
                out.append(b)
            elif c:
                out.append(c)
        return out

    # Match public INCLUDE_DIRS only (not PRIV_INCLUDE_DIRS): use line-anchored key.
    public = collect("INCLUDE_DIRS")
    # collect("INCLUDE_DIRS") may also hit PRIV_INCLUDE_DIRS if unanchored — use
    # explicit line start without PRIV_ prefix.
    public_m = re.search(
        r"(?m)^[ \t]*INCLUDE_DIRS[ \t]*\n(?P<dirs>.*?)"
        r"(?=^[ \t]*(?:PRIV_INCLUDE_DIRS|SRCS|REQUIRES|PRIV_REQUIRES)\b|\Z)",
        body,
        re.DOTALL | re.MULTILINE,
    )
    if public_m is None:
        fail("INCLUDE_DIRS block not found")
    public_blob = public_m.group("dirs")
    public = [
        a or b or c
        for a, b, c in re.findall(
            r'"\$\{NINLIL_REPO_ROOT\}/([^"]+)"|"([^"]+)"|(\$\{[A-Za-z0-9_]+\})',
            public_blob,
        )
        if a or b or c
    ]
    priv = collect("PRIV_INCLUDE_DIRS")
    return public, priv


def assert_public_include_closure(cmake_text: str) -> None:
    public_dirs, priv_dirs = extract_idf_include_dirs(cmake_text)
    if not public_dirs:
        fail("component public INCLUDE_DIRS empty")
    forbidden_public = []
    for d in public_dirs:
        if d.startswith("src/") or d == "src" or "/src/" in d:
            forbidden_public.append(d)
        if d.startswith("drivers/") or d.startswith("ports/esp-idf/src"):
            forbidden_public.append(d)
    if forbidden_public:
        fail(
            "public INCLUDE_DIRS must not export private source roots: "
            f"{forbidden_public}"
        )
    # Required public roots.
    for required in (
        "include",
        "ports/esp-idf/include",
        "ports/esp-idf/storage/include",
    ):
        if required not in public_dirs:
            fail(f"public INCLUDE_DIRS missing required root {required!r}")
    # transport must remain private-only.
    if "src/transport" in public_dirs:
        fail("src/transport must not appear in public INCLUDE_DIRS")
    if "src/transport" not in priv_dirs and "${NINLIL_R7_FRAG_PRIV_INCLUDES}" not in (
        " ".join(priv_dirs)
    ):
        # priv may list src/transport explicitly
        if not any(d == "src/transport" or d.endswith("/src/transport") for d in priv_dirs):
            # allow variable-only priv blocks as long as literal src/transport present
            if "src/transport" not in "\n".join(priv_dirs):
                # re-check with raw file
                if 'PRIV_INCLUDE_DIRS' in cmake_text and "src/transport" in cmake_text:
                    pass
                else:
                    fail("src/transport must remain in PRIV_INCLUDE_DIRS")
    if "src/transport" not in cmake_text.split("PRIV_INCLUDE_DIRS", 1)[-1].split(
        "PRIV_REQUIRES", 1
    )[0]:
        fail("PRIV_INCLUDE_DIRS must list src/transport for private TUs")


def assert_public_headers_do_not_pull_private() -> None:
    if not BYTE_STREAM_PUBLIC.is_file():
        fail("missing formal public header include/ninlil/byte_stream.h")
    for public_root in PUBLIC_INCLUDE_ROOTS:
        for path in public_root.rglob("*.h"):
            assert_public_header_path_allowed(path)
    usb = read_text(USB_CDC_PUBLIC)
    if '#include "byte_stream.h"' in usb:
        fail(
            "usb_cdc.h must not include private \"byte_stream.h\"; "
            "use \"ninlil/byte_stream.h\""
        )
    if '#include "ninlil/byte_stream.h"' not in usb and "#include <ninlil/byte_stream.h>" not in usb:
        fail("usb_cdc.h must include formal ninlil/byte_stream.h")
    # Public port headers must not reference bare private transport filenames.
    pub_root = REPO_ROOT / "ports" / "esp-idf" / "include"
    private_names = (
        "control_session.h",
        "logical_session.h",
        "usb_cdc_orch_logic.h",
        "usb_cdc_state_logic.h",
        "runtime_internal.h",
    )
    for path in pub_root.rglob("*.h"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in private_names:
            if f'"{name}"' in text or f"<{name}>" in text:
                fail(
                    f"public header {path.relative_to(REPO_ROOT)} must not "
                    f"include private {name}"
                )
        # bare byte_stream without ninlil/
        if re.search(r'#\s*include\s*["<]byte_stream\.h[">]', text):
            fail(
                f"public header {path.relative_to(REPO_ROOT)} includes bare "
                f"byte_stream.h (use ninlil/byte_stream.h)"
            )


def _compile(source: str, include_dirs: list[pathlib.Path], label: str) -> int:
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory(prefix="ninlil-esp-boundary-") as tmp:
        src_path = pathlib.Path(tmp) / "consumer.c"
        obj_path = pathlib.Path(tmp) / "consumer.o"
        src_path.write_text(source, encoding="utf-8")
        cmd = [cc, "-std=c11", "-c", str(src_path), "-o", str(obj_path)]
        for d in include_dirs:
            cmd.extend(["-I", str(d)])
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 and label.startswith("positive"):
            print(proc.stderr, file=sys.stderr)
        return proc.returncode


def assert_external_consumer_compile() -> None:
    public_dirs = list(PUBLIC_INCLUDE_ROOTS)
    positive = """
#include "ninlil/byte_stream.h"
#include "ninlil_esp_idf/usb_cdc.h"
#include "ninlil/version.h"
int main(void) {
    ninlil_esp_idf_usb_cdc_object_t obj;
    ninlil_byte_stream_t stream;
    (void)ninlil_esp_idf_usb_cdc_object_size();
    (void)ninlil_esp_idf_usb_cdc_init_object(&obj, &stream);
    (void)NINLIL_BYTE_STREAM_OK;
    return 0;
}
"""
    rc = _compile(positive, public_dirs, "positive public consumer")
    if rc != 0:
        fail("positive external ESP public consumer failed to compile")

    # Negative: bare private transport include must fail with only public roots.
    negative_bare = """
#include "byte_stream.h"
int main(void) { return 0; }
"""
    rc = _compile(negative_bare, public_dirs, "negative bare byte_stream")
    if rc == 0:
        fail(
            "negative consumer compiled bare \"byte_stream.h\" with only public "
            "INCLUDE_DIRS — private root still exported"
        )

    negative_private = """
#include "control_session.h"
int main(void) { return 0; }
"""
    rc = _compile(negative_private, public_dirs, "negative control_session")
    if rc == 0:
        fail(
            "negative consumer compiled private control_session.h with only "
            "public INCLUDE_DIRS"
        )

    negative_src = """
#include "usb_cdc_state_logic.h"
int main(void) { return 0; }
"""
    rc = _compile(negative_src, public_dirs, "negative port private logic")
    if rc == 0:
        fail(
            "negative consumer compiled ports private usb_cdc_state_logic.h "
            "with only public INCLUDE_DIRS"
        )


def check() -> None:
    cmake = read_text(COMPONENT_CMAKE)
    assert_public_include_closure(cmake)
    assert_public_headers_do_not_pull_private()
    assert_external_consumer_compile()
    print(
        "esp_idf_sdk_public_boundary_gate OK: "
        "public INCLUDE_DIRS closed; usb_cdc uses ninlil/byte_stream.h; "
        "external positive/negative consumers OK"
    )


def self_test() -> None:
    cmake = read_text(COMPONENT_CMAKE)
    public_dirs, priv_dirs = extract_idf_include_dirs(cmake)
    if "src/transport" in public_dirs:
        fail("self-test: src/transport still public")
    if "include" not in public_dirs:
        fail("self-test: public include root missing")
    # Mutation: inject public src/transport must be detectable.
    mutated = cmake.replace(
        'INCLUDE_DIRS\n        "${NINLIL_REPO_ROOT}/include"',
        'INCLUDE_DIRS\n        "${NINLIL_REPO_ROOT}/src/transport"\n'
        '        "${NINLIL_REPO_ROOT}/include"',
        1,
    )
    if mutated == cmake:
        # fallback inject
        mutated = cmake.replace(
            "INCLUDE_DIRS",
            'INCLUDE_DIRS\n        "${NINLIL_REPO_ROOT}/src/transport"',
            1,
        )
    try:
        assert_public_include_closure(mutated)
    except SystemExit:
        pass
    else:
        fail("self-test accepted public src/transport injection")
    try:
        assert_public_header_path_allowed(
            REPO_ROOT
            / "ports"
            / "esp-idf"
            / "include"
            / "ninlil_esp_idf"
            / "private_target_smoke.h"
        )
    except SystemExit:
        pass
    else:
        fail("self-test accepted private target-smoke header in public include")
    check()
    print("esp_idf_sdk_public_boundary_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: esp_idf_sdk_public_boundary_gate.py check|self-test",
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
