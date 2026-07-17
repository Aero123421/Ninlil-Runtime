#!/usr/bin/env python3
"""R3 airtime gate formula_version 1 + danger mutations."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
DOC27 = "docs/27-r3-airtime-calculator.md"
ADR7 = "docs/adr/0007-r3-airtime-calculator.md"
DOC07 = "docs/07-testing-and-quality.md"
HDR = "src/radio/airtime_calculator.h"
SRC = "src/radio/airtime_calculator.c"
PRIVATE = "cmake/ninlil_runtime_private_sources.cmake"
ORACLE = "tools/airtime_r3_oracle.py"
PUBLIC_RUNTIME = "include/ninlil/runtime.h"
VECTORS_JSON = "tests/radio/airtime_r3_vectors.json"
VECTORS_H = "tests/radio/airtime_r3_vectors.gen.h"

OFFICIAL_BW = (7812, 10417, 15625, 20833, 31250, 41667, 62500, 125000, 250000, 500000)
OLD_APPROX_BW = (7810, 10420, 15630, 20830, 41670)

class GateFailure(Exception):
    pass

def fail(msg: str) -> None:
    raise GateFailure(msg)

def read(root: pathlib.Path, rel: str) -> str:
    p = root / rel
    if not p.is_file():
        fail(f"missing {rel}")
    return p.read_text(encoding="utf-8")

def check_docs(root: pathlib.Path) -> None:
    doc = read(root, DOC27)
    adr = read(root, ADR7)
    need = [
        "SEMANTIC: R3_HOST_CANDIDATE_ONLY",
        "9636dc4660ada4eeddf91eb7b3f7f241000bf202",
        "v2.3.2",
        "DS.SX1261-2.W.APP",
        "Rev 2.2",
        "§6.1.4",
        "p41",
        "16.38",
        "LDRO_AUTO_GE_16P38_MS",
        "SF56_LDRO_ON_ACCEPTED",
        "n_payload_symbols",
        "34581760",
        "494718",
        "CR_LONG_INTERLEAVE_5_7_REJECT",
        "7812",
        "10417",
        "Japan",
        "re-review GO",
        "uint64",
        "VECTORS_FRESH_DETERMINISTIC",
    ]
    for tok in need:
        if tok not in doc and tok not in adr:
            fail(f"docs missing {tok}")
    if "Accepted" not in adr:
        fail("ADR must be Accepted")
    if "16.38" not in doc:
        fail("docs must pin 16.38 ms LDRO threshold")
    if "((uint32_t)1u)" not in read(root, HDR):
        fail("formula_version must be 1 for first freeze")
    if re.search(r"formula_version\s*\*\*3\*\*|公開済みv[12]", doc + adr):
        fail("must not claim published multi-version history")
    # docs/07 must name freshness gate (when present in tree)
    doc07_path = root / DOC07
    if doc07_path.is_file():
        d7 = doc07_path.read_text(encoding="utf-8")
        if "airtime_r3" not in d7 or "fresh" not in d7.lower():
            fail("docs/07 must document airtime_r3 vector freshness gate")

def check_source(root: pathlib.Path) -> None:
    h = read(root, HDR)
    c = read(root, SRC)
    if "NINLIL_AIRTIME_FORMULA_VERSION ((uint32_t)1u)" not in h:
        fail("formula version must be 1")
    if "9636dc4660ada4eeddf91eb7b3f7f241000bf202" not in c and (
        "9636dc4660ada4eeddf91eb7b3f7f241000bf202" not in h
    ):
        fail("must pin driver commit")
    if re.search(r"\b(float|double)\b", c):
        fail("no float/double")
    for tok in (
        "DRIVER_NUMERATOR_V232",
        "SF56_EXPLICIT_PLUS20_IMPLICIT_PLUS0",
        "SF56_EXTRA_PLUS2_SYMBOLS",
        "SF7_PLUS_NUM_PLUS8",
        "LDRO_AUTO_GE_16P38_MS",
        "SF56_LDRO_ON_ACCEPTED_DE_UNUSED_IN_ALGEBRA",
        "TOA_NUMERATOR_UINT64_EXACT",
        "CR_LONG_INTERLEAVE_5_7_REJECT",
        "AIRTIME_US_CEIL_1E6_NUM_OVER_BW",
    ):
        if tok not in c and tok not in h:
            fail(f"missing anchor {tok}")

    if re.search(
        r"if\s*\(\s*sf\s*<=\s*6u\s*\)\s*\{\s*return\s+NINLIL_AIRTIME_UNSUPPORTED",
        c,
    ):
        fail("SF5/6 LDRO_ON must not be UNSUPPORTED")
    if not re.search(r"header_implicit\s*!=\s*0u\s*\?\s*0\s*:\s*20", c):
        fail("explicit +20 / implicit 0 required")
    if not re.search(
        r"if\s*\(\s*sf\s*<=\s*6u\s*\)\s*\{[^}]*intermed\s*\+=\s*2\s*;",
        c,
        re.S,
    ):
        fail("SF<=6 intermed += 2 required")
    if not re.search(r"^\s*ceil_numerator\s*\+=\s*8\s*;", c, re.M):
        fail("SF>=7 ceil_numerator += 8 required")
    if re.search(
        r"if\s*\(\s*sf\s*<=\s*6u\s*\)\s*\{[^}]*ceil_numerator\s*\+=\s*8",
        c,
        re.S,
    ):
        fail("SF<=6 must not apply +8")
    # SF5/6 denominator must not use de (wrong mix-up)
    if re.search(
        r"if\s*\(\s*sf\s*<=\s*6u\s*\)\s*\{[^}]{0,200}?"
        r"ceil_denominator\s*=\s*4\s*\*\s*\(\s*\(\s*int32_t\s*\)\s*sf\s*-\s*2",
        c,
        re.S,
    ) or re.search(
        r"if\s*\(\s*sf\s*<=\s*6u\s*\)\s*\{[^}]{0,200}?de\s*!=\s*0",
        c,
        re.S,
    ):
        fail("SF<=6 must not apply DE to denominator")

    # LDRO >= 16.38 rational (not > 16ms)
    if "NINLIL_AIRTIME_LDRO_AUTO_NUM" not in h:
        fail("LDRO auto num macro missing")
    if not re.search(
        r"NINLIL_AIRTIME_LDRO_AUTO_NUM\s*\(\(uint32_t\)100000u\)",
        h,
    ):
        fail("LDRO AUTO num must be 100000u")
    if not re.search(
        r"NINLIL_AIRTIME_LDRO_AUTO_DEN_MS_X100\s*\(\(uint32_t\)1638u\)",
        h,
    ):
        fail("LDRO AUTO den must be 1638u (16.38 ms)")
    if not re.search(r"left\s*>=\s*right", c):
        fail("LDRO AUTO must use >= (equality included)")
    if re.search(r"return\s*\(\s*left\s*>\s*right\s*\)", c):
        fail("LDRO AUTO must not use strict-only greater-than")
    # obsolete 16ms form in executable LDRO path
    if re.search(
        r"bw_hz\s*\*\s*16u|bw_hz\)\s*\*\s*16u",
        c,
    ):
        fail("obsolete *16 LDRO threshold in source")

    for bw in OFFICIAL_BW:
        if f"{bw}u" not in h:
            fail(f"missing bw {bw}")
    for bw in OLD_APPROX_BW:
        if re.search(rf"\b{bw}u\b", h) or re.search(rf"\b{bw}u\b", c):
            fail(f"old bw {bw} forbidden")

    if "uint32_t toa_numerator;" in h:
        fail("toa_numerator must be uint64 split lo/hi")
    if "toa_numerator_lo" not in h:
        fail("need toa_numerator_lo")

    if "airtime_calculator" in read(root, PUBLIC_RUNTIME):
        fail("public leak")

def check_private_packaging(root: pathlib.Path) -> None:
    priv = read(root, PRIVATE)
    if "src/radio/airtime_calculator.c" not in priv:
        fail("private sources missing airtime")
    if "airtime_r3_oracle" in priv:
        fail("oracle in private")
    if "airtime_r3_vectors" in priv or "airtime_r3_bridge" in priv:
        fail("vector/bridge must not be in private sources")


def _run_oracle_emit(oracle: pathlib.Path, cmd: str, out: pathlib.Path) -> None:
    r = subprocess.run(
        [sys.executable, str(oracle), cmd, "--out", str(out)],
        cwd=str(oracle.parent.parent),  # repo-ish root; oracle is self-contained
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"oracle {cmd} failed: {r.stderr or r.stdout}")
    if not out.is_file():
        fail(f"oracle {cmd} did not write {out}")


def check_vector_freshness(root: pathlib.Path) -> None:
    """Regenerate JSON+header twice in independent temp dirs.

    Require run1==run2 (deterministic) and each matches committed artifacts
    byte-for-byte. Must not write into the source tree.
    SEMANTIC: VECTORS_FRESH_DETERMINISTIC
    """
    oracle = root / ORACLE
    committed_json = root / VECTORS_JSON
    committed_h = root / VECTORS_H
    if not oracle.is_file():
        fail(f"missing {ORACLE}")
    if not committed_json.is_file():
        fail(f"missing committed {VECTORS_JSON}")
    if not committed_h.is_file():
        fail(f"missing committed {VECTORS_H}")

    committed_json_b = committed_json.read_bytes()
    committed_h_b = committed_h.read_bytes()
    runs: list[tuple[bytes, bytes]] = []

    for _ in range(2):
        with tempfile.TemporaryDirectory(prefix="airtime_r3_fresh_") as td:
            td_path = pathlib.Path(td)
            j_out = td_path / "vectors.json"
            h_out = td_path / "vectors.gen.h"
            # Guard: outputs must stay under temp, never under root source
            if root.resolve() in j_out.resolve().parents:
                fail("freshness emit must not target source tree")
            _run_oracle_emit(oracle, "emit-json", j_out)
            _run_oracle_emit(oracle, "emit-c", h_out)
            runs.append((j_out.read_bytes(), h_out.read_bytes()))

    j1, h1 = runs[0]
    j2, h2 = runs[1]
    if j1 != j2:
        fail("oracle emit-json non-deterministic (run1 != run2)")
    if h1 != h2:
        fail("oracle emit-c non-deterministic (run1 != run2)")
    if j1 != committed_json_b:
        fail(
            f"{VECTORS_JSON} stale vs oracle (byte mismatch; "
            "re-run: python3 tools/airtime_r3_oracle.py emit-json --out "
            f"{VECTORS_JSON})"
        )
    if h1 != committed_h_b:
        fail(
            f"{VECTORS_H} stale vs oracle (byte mismatch; "
            "re-run: python3 tools/airtime_r3_oracle.py emit-c --out "
            f"{VECTORS_H})"
        )


def check_oracle(root: pathlib.Path) -> None:
    r = subprocess.run(
        [sys.executable, str(root / ORACLE), "self-check"],
        cwd=str(root),
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        fail(f"oracle self-check: {r.stderr or r.stdout}")
    o = read(root, ORACLE)
    if "FORMULA_VERSION = 1" not in o:
        fail("oracle version must be 1")
    if "34581760" not in o:
        fail("oracle must pin max ceil-ms")
    if "494718" not in o:
        fail("oracle must name forbidden wrapper value")
    if "1638" not in o:
        fail("oracle LDRO 16.38 rational")
    # Real SF5 LDRO_ON vector (not OFF masquerading as de1)
    if "hv_sf5_p16_pre12_de1_on" not in o:
        fail("oracle missing hv_sf5_p16_pre12_de1_on")
    if not re.search(
        r'hv_sf5_p16_pre12_de1_on".*LDRO_ON',
        o,
        re.S,
    ) and not re.search(
        r"hv_sf5_p16_pre12_de1_on\",\s*Input\(5,\s*1,\s*0,\s*1,\s*LDRO_ON",
        o,
    ):
        fail("de1_on vector must pass LDRO_ON")
    if re.search(
        r'hv_sf5_p16_pre12_de1_on",\s*Input\(5,\s*1,\s*0,\s*1,\s*LDRO_OFF',
        o,
    ):
        fail("de1_on must not be LDRO_OFF")

def run_check(root: pathlib.Path | None = None) -> None:
    root = root or REPO
    check_docs(root)
    check_source(root)
    check_private_packaging(root)
    check_oracle(root)
    check_vector_freshness(root)

def _mut(path: pathlib.Path, old: str, new: str, all_occ: bool = False) -> None:
    t = path.read_text(encoding="utf-8")
    if old not in t:
        raise RuntimeError(f"anchor missing: {old[:100]!r}")
    path.write_text(
        t.replace(old, new) if all_occ else t.replace(old, new, 1),
        encoding="utf-8",
    )

def run_self_test() -> None:
    mutations: list[tuple[str, str, str, str, bool]] = [
        (
            "M_sf56_plus20_to_plus8",
            SRC,
            "header_implicit != 0u ? 0 : 20",
            "header_implicit != 0u ? 0 : 8",
            False,
        ),
        (
            "M_implicit_always_plus20",
            SRC,
            "header_implicit != 0u ? 0 : 20",
            "header_implicit != 0u ? 20 : 20",
            False,
        ),
        (
            "M_sf56_drop_extra_plus2",
            SRC,
            "        intermed += 2;\n",
            "        /* +2 removed */\n",
            False,
        ),
        (
            "M_bw_old_7810",
            HDR,
            "#define NINLIL_AIRTIME_BW_HZ_0 ((uint32_t)7812u)",
            "#define NINLIL_AIRTIME_BW_HZ_0 ((uint32_t)7810u)",
            False,
        ),
        (
            "M_bw_old_10420",
            HDR,
            "#define NINLIL_AIRTIME_BW_HZ_1 ((uint32_t)10417u)",
            "#define NINLIL_AIRTIME_BW_HZ_1 ((uint32_t)10420u)",
            False,
        ),
        (
            "M_bw_old_15630",
            HDR,
            "#define NINLIL_AIRTIME_BW_HZ_2 ((uint32_t)15625u)",
            "#define NINLIL_AIRTIME_BW_HZ_2 ((uint32_t)15630u)",
            False,
        ),
        (
            "M_bw_old_20830",
            HDR,
            "#define NINLIL_AIRTIME_BW_HZ_3 ((uint32_t)20833u)",
            "#define NINLIL_AIRTIME_BW_HZ_3 ((uint32_t)20830u)",
            False,
        ),
        (
            "M_bw_old_41670",
            HDR,
            "#define NINLIL_AIRTIME_BW_HZ_5 ((uint32_t)41667u)",
            "#define NINLIL_AIRTIME_BW_HZ_5 ((uint32_t)41670u)",
            False,
        ),
        (
            "M_sf7_drop_plus8",
            SRC,
            "        ceil_numerator += 8;\n",
            "        /* SF7 addend removed */\n",
            False,
        ),
        (
            "M_sf56_wrong_plus8",
            SRC,
            "    if (sf <= 6u) {\n"
            "        /* SF5/6: DE unused in denominator (driver algebra). */\n"
            "        (void)de;\n"
            "        ceil_denominator = 4 * (int32_t)sf;\n"
            "    } else {\n"
            "        ceil_numerator += 8;\n",
            "    if (sf <= 6u) {\n"
            "        ceil_numerator += 8;\n"
            "        (void)de;\n"
            "        ceil_denominator = 4 * (int32_t)sf;\n"
            "    } else {\n"
            "        ceil_numerator += 8;\n",
            False,
        ),
        # LDRO: collapse >= to > (drop equality)
        (
            "M_ldro_drop_equality",
            SRC,
            "return (left >= right) ? 1 : 0;",
            "return (left > right) ? 1 : 0;",
            False,
        ),
        # LDRO: revert to obsolete 16ms strict
        (
            "M_ldro_old_16ms",
            SRC,
            "    const uint64_t left =\n"
            "        ((uint64_t)1u << (unsigned)sf) * (uint64_t)NINLIL_AIRTIME_LDRO_AUTO_NUM;\n"
            "    const uint64_t right =\n"
            "        (uint64_t)bw_hz * (uint64_t)NINLIL_AIRTIME_LDRO_AUTO_DEN_MS_X100;\n"
            "\n"
            "    return (left >= right) ? 1 : 0;",
            "    const uint64_t left = ((uint64_t)1u << (unsigned)sf) * 1000u;\n"
            "    const uint64_t right = (uint64_t)bw_hz * 16u;\n"
            "    return (left > right) ? 1 : 0;",
            False,
        ),
        (
            "M_ldro_macro_1638_to_1600",
            HDR,
            "#define NINLIL_AIRTIME_LDRO_AUTO_DEN_MS_X100 ((uint32_t)1638u)",
            "#define NINLIL_AIRTIME_LDRO_AUTO_DEN_MS_X100 ((uint32_t)1600u)",
            False,
        ),
        # SF5/6 LDRO_ON rejected (false policy)
        (
            "M_sf56_ldro_on_unsupported",
            SRC,
            "    if (ldro == NINLIL_AIRTIME_LDRO_ON) {\n"
            "        /* SF5/6: accept ON; effective=1; numerator path still ignores de. */\n"
            "        *out_de = 1u;\n"
            "        return NINLIL_AIRTIME_OK;\n"
            "    }",
            "    if (ldro == NINLIL_AIRTIME_LDRO_ON) {\n"
            "        if (sf <= 6u) {\n"
            "            return NINLIL_AIRTIME_UNSUPPORTED;\n"
            "        }\n"
            "        *out_de = 1u;\n"
            "        return NINLIL_AIRTIME_OK;\n"
            "    }",
            False,
        ),
        # ON vector replaced with OFF (false test greenwash)
        (
            "M_sf56_on_vector_to_off",
            ORACLE,
            '("hv_sf5_p16_pre12_de1_on", Input(5, 1, 0, 1, LDRO_ON, 16, 12, 125000), 17),',
            '("hv_sf5_p16_pre12_de1_on", Input(5, 1, 0, 1, LDRO_OFF, 16, 12, 125000), 17),',
            False,
        ),
        # SF5/6 algebra wrongly applies DE to denominator
        (
            "M_sf56_apply_de_to_den",
            SRC,
            "    if (sf <= 6u) {\n"
            "        /* SF5/6: DE unused in denominator (driver algebra). */\n"
            "        (void)de;\n"
            "        ceil_denominator = 4 * (int32_t)sf;\n"
            "    } else {\n",
            "    if (sf <= 6u) {\n"
            "        /* wrong: apply DE on SF5/6 */\n"
            "        if (de != 0u) {\n"
            "            ceil_denominator = 4 * ((int32_t)sf - 2);\n"
            "        } else {\n"
            "            ceil_denominator = 4 * (int32_t)sf;\n"
            "        }\n"
            "    } else {\n",
            False,
        ),
        (
            "M_remove_private_source",
            PRIVATE,
            "    src/radio/airtime_calculator.c\n",
            "",
            True,
        ),
        (
            "M_docs_drop_host_marker",
            DOC27,
            "SEMANTIC: R3_HOST_CANDIDATE_ONLY",
            "SEMANTIC: R3_COMPLETE_CLAIM",
            False,
        ),
        (
            "M_source_float",
            SRC,
            "static int ceil_div_u64(uint64_t a, uint64_t b, uint64_t *out)",
            "static double ceil_div_bad(uint64_t a, uint64_t b, uint64_t *out)",
            False,
        ),
        (
            "M_formula_version_bump_fake",
            HDR,
            "#define NINLIL_AIRTIME_FORMULA_VERSION ((uint32_t)1u)",
            "#define NINLIL_AIRTIME_FORMULA_VERSION ((uint32_t)2u)",
            False,
        ),
        # --- vector freshness / determinism ---
        (
            "M_stale_vectors_json",
            VECTORS_JSON,
            '"formula_version": 1',
            '"formula_version": 0',
            False,
        ),
        (
            "M_stale_vectors_header",
            VECTORS_H,
            "#define NINLIL_AIRTIME_R3_ORACLE_FORMULA_VERSION (1u)",
            "#define NINLIL_AIRTIME_R3_ORACLE_FORMULA_VERSION (0u)",
            False,
        ),
        (
            "M_oracle_nondeterministic_json",
            ORACLE,
            "        text = json.dumps(\n"
            '            {"formula_version": FORMULA_VERSION, "vectors": boundary_vectors()},\n'
            "            indent=2,\n"
            "            sort_keys=True,\n"
            "        )\n"
            "        if args.out:\n"
            '            open(args.out, "w", encoding="utf-8").write(text + "\\n")',
            "        text = json.dumps(\n"
            '            {"formula_version": FORMULA_VERSION, "vectors": boundary_vectors()},\n'
            "            indent=2,\n"
            "            sort_keys=True,\n"
            "        ) + str(__import__('time').time_ns())\n"
            "        if args.out:\n"
            '            open(args.out, "w", encoding="utf-8").write(text + "\\n")',
            False,
        ),
        (
            "M_stale_json_only_header_ok",
            VECTORS_JSON,
            '"formula_version": 1,',
            '"formula_version": 1, "stale": true,',
            False,
        ),
    ]
    copies = [
        DOC27,
        ADR7,
        DOC07,
        HDR,
        SRC,
        PRIVATE,
        ORACLE,
        PUBLIC_RUNTIME,
        VECTORS_JSON,
        VECTORS_H,
    ]
    for name, rel, old, new, allo in mutations:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            for p in copies:
                s = REPO / p
                d = root / p
                d.parent.mkdir(parents=True, exist_ok=True)
                if s.is_file():
                    shutil.copy2(s, d)
            try:
                _mut(root / rel, old, new, allo)
            except RuntimeError as e:
                fail(f"self-test {name}: {e}")
            try:
                run_check(root)
            except GateFailure:
                print(f"self-test {name}: fail as expected")
                continue
            fail(f"self-test {name}: unexpectedly passed (false-green)")

def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print("usage: airtime_r3_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "check":
            run_check()
            print(
                "airtime_r3_gate ok: formula_v1 + vectors fresh/deterministic"
            )
        else:
            run_self_test()
            print("airtime_r3_gate self-test ok")
        return 0
    except GateFailure as e:
        print(f"airtime_r3_gate FAIL: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # pragma: no cover
        print(f"airtime_r3_gate ERROR: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))
