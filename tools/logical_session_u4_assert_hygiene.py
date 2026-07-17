#!/usr/bin/env python3
"""U4 bridge hygiene + portable fixture mutation evidence.

mutation mode requires explicit paths from CMake/CTest:
  --build-dir   current binary dir (for rebuild)
  --exe         path to ninlil_logical_session_u4_test
  --fixture     path to generated logical_session_u4_vector_fixture.h

Does not hardcode build-u4-full or search other trees.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
TEST = REPO / "tests" / "transport" / "logical_session_u4_test.c"
VEC = REPO / "spec" / "vectors" / "logical-session-u4-v1.json"
GEN = REPO / "tools" / "logical_session_u4_vector_gen.py"


def fail(msg: str) -> None:
    print(f"logical_session_u4_assert_hygiene FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def check_source(text: str) -> None:
    if "run_all_scenarios" not in text or "check_expect_on_peer" not in text:
        fail("bridge must run scenarios with per-action expect checks")
    if "tx_hex" not in text and "EF_TX_HEX" not in text and "tx_blob" not in text:
        # Runner must compare full expected wire bytes.
        if "memcmp" not in text or "tx_" not in text:
            fail("bridge must memcmp full expected TX wire bytes")
    if re.search(r"\bg_pass_marks\b", text):
        fail("g_pass_marks forbidden")
    if re.search(r"==\s*0\s*\|\|\s*1\b", text):
        fail("always-true OR forbidden")
    if "build-u4-full" in text:
        fail("test source must not hardcode build-u4-full")


def rebuild(build_dir: pathlib.Path) -> None:
    r = subprocess.run(
        [
            "cmake",
            "--build",
            str(build_dir),
            "--target",
            "ninlil_logical_session_u4_test",
            "-j8",
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"build failed: {(r.stderr or r.stdout)[-800:]}")


def run_exe(exe: pathlib.Path) -> tuple[int, str]:
    if not exe.is_file():
        fail(f"missing executable: {exe}")
    r = subprocess.run([str(exe)], capture_output=True, text=True)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def wipe_test_artifacts(build_dir: pathlib.Path, exe: pathlib.Path) -> None:
    if exe.is_file():
        exe.unlink()
    for obj in build_dir.rglob("logical_session_u4_test.c.o"):
        try:
            obj.unlink()
        except OSError:
            pass
    for obj in build_dir.rglob("logical_session_u4_test.c.obj"):
        try:
            obj.unlink()
        except OSError:
            pass


def reemit_clean(fixture: pathlib.Path) -> None:
    r = subprocess.run(
        [sys.executable, str(GEN), "emit-c-fixture", str(VEC), str(fixture)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"re-emit clean fixture failed: {r.stderr or r.stdout}")


def mutation_evidence(
    build_dir: pathlib.Path,
    exe: pathlib.Path,
    fixture: pathlib.Path,
) -> None:
    check_source(TEST.read_text(encoding="utf-8"))
    if not build_dir.is_dir():
        fail(f"build-dir missing: {build_dir}")
    if not fixture.is_file():
        fail(f"fixture missing: {fixture}")
    if "build-u4-full" in str(build_dir) and not build_dir.exists():
        fail("must not require build-u4-full")

    clean_vec = VEC.read_text(encoding="utf-8")
    rebuild(build_dir)
    code, out = run_exe(exe)
    if code != 0:
        fail(f"clean bridge not green: {out[-600:]}")

    def mut_and_run(label: str, mutator, *, allow_emit_hard_fail: bool = False) -> None:
        doc = json.loads(clean_vec)
        target = next(v for v in doc["vectors"] if v.get("id") == "U4-G-HELLO-OK")
        mutator(target)
        tmp = pathlib.Path(tempfile.mkdtemp()) / f"mut_{label}.json"
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(GEN), "emit-c-fixture", str(tmp), str(fixture)],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            if allow_emit_hard_fail:
                print(f"mutation evidence OK (emit hard-fail): {label}")
                reemit_clean(fixture)
                wipe_test_artifacts(build_dir, exe)
                rebuild(build_dir)
                return
            fail(f"emit fail {label}: {r.stderr}")
        wipe_test_artifacts(build_dir, exe)
        rebuild(build_dir)
        c2, _o2 = run_exe(exe)
        reemit_clean(fixture)
        wipe_test_artifacts(build_dir, exe)
        rebuild(build_dir)
        if c2 == 0:
            fail(f"mutation {label} did not fail bridge")
        print(f"mutation evidence OK: {label}")

    try:
        mut_and_run(
            "status",
            lambda t: t["actions"][0]["expect"].__setitem__("status", 9),
        )
        mut_and_run(
            "state",
            lambda t: t["expect_final"][0].__setitem__("state", 0),
        )
        mut_and_run(
            "counter",
            lambda t: t["expect_final"][1].setdefault("counters", {}).__setitem__(
                "raw_accepts", 999
            ),
        )
        mut_and_run(
            "commit",
            lambda t: t["expect_final"][1].__setitem__("last_tx_commit", 0),
        )
        mut_and_run(
            "seq",
            lambda t: t["actions"][0]["expect"].__setitem__("next_tx_seq", 99),
        )
        mut_and_run(
            "gen",
            lambda t: t["expect_final"][0].__setitem__("active_generation", 7),
        )
        mut_and_run(
            "cookie",
            lambda t: t["expect_final"][0].__setitem__("active_cookie", 1),
        )
        def mut_tx_len(t: dict) -> None:
            e0 = t["actions"][0]["expect"]
            hx = e0.get("tx_hex")
            if not hx or len(hx) < 4:
                fail("HELLO-OK action0 missing tx_hex for tx_len mutation")
            # Truncate wire by one byte so length check fails independently.
            e0["tx_hex"] = hx[:-2]
            e0["tx_len"] = (len(hx) // 2) - 1

        # Truncating/flipping hex without updating the semantic descriptor must
        # hard-fail at emit (rebuild-identical oracle) — never resynthesize.
        mut_and_run("tx_len", mut_tx_len, allow_emit_hard_fail=True)

        def flip_tx_byte(t: dict) -> None:
            e0 = t["actions"][0]["expect"]
            hx = e0.get("tx_hex")
            if not hx or len(hx) < 2:
                fail("HELLO-OK action0 missing tx_hex for wire mutation")
            # Flip first wire byte deterministically (not a length-only change).
            b0 = int(hx[0:2], 16) ^ 0x01
            e0["tx_hex"] = f"{b0:02x}" + hx[2:]

        mut_and_run("tx_bytes", flip_tx_byte, allow_emit_hard_fail=True)

        def drop_tx_request_id(t: dict) -> None:
            e0 = t["actions"][0]["expect"]
            if "tx" not in e0 or "request_id" not in e0["tx"]:
                fail("HELLO-OK action0 missing tx.request_id for descriptor mutation")
            del e0["tx"]["request_id"]

        mut_and_run("tx_desc_field", drop_tx_request_id, allow_emit_hard_fail=True)

        def corrupt_tx_message_type(t: dict) -> None:
            e0 = t["actions"][0]["expect"]
            if "tx" not in e0:
                fail("HELLO-OK action0 missing tx for message_type mutation")
            e0["tx"]["message_type"] = 0x99

        mut_and_run(
            "tx_unknown_message_type",
            corrupt_tx_message_type,
            allow_emit_hard_fail=True,
        )
    finally:
        reemit_clean(fixture)
        wipe_test_artifacts(build_dir, exe)
        rebuild(build_dir)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=("check", "mutation"))
    ap.add_argument("--build-dir", type=pathlib.Path, default=None)
    ap.add_argument("--exe", type=pathlib.Path, default=None)
    ap.add_argument("--fixture", type=pathlib.Path, default=None)
    ns = ap.parse_args(argv)

    if ns.command == "check":
        check_source(TEST.read_text(encoding="utf-8"))
        # Hygiene source itself must not hardcode a build tree name.
        self_src = pathlib.Path(__file__).read_text(encoding="utf-8")
        if re.search(r'BUILD\s*=\s*REPO\s*/\s*["\']build-u4-full["\']', self_src):
            fail("hygiene must not assign BUILD from hardcoded build-u4-full")
        print("logical_session_u4_assert_hygiene check OK")
        return 0

    if ns.command == "mutation":
        if ns.build_dir is None or ns.exe is None or ns.fixture is None:
            fail(
                "mutation requires --build-dir --exe --fixture "
                "(from CMake/CTest; no implicit build-u4-full)"
            )
        mutation_evidence(
            ns.build_dir.resolve(),
            ns.exe.resolve(),
            ns.fixture.resolve(),
        )
        print("logical_session_u4_assert_hygiene mutation OK")
        return 0

    fail(f"unknown {ns.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
