#!/usr/bin/env python3
"""Independent R3 LoRa airtime oracle — uint64 exact rational (not driver ms wrapper).

Pins:
  Algebra: Lora-net/sx126x_driver v2.3.2 commit 9636dc4… src/sx126x.c numerator/BW
  Policy: DS.SX1261-2.W.APP Rev 2.2 — LDRO recommend Ts>=16.38ms; CR helper 1..4 only

DO NOT copy sx126x_get_lora_time_on_air_in_ms uint32 results (legal max wrong).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from fractions import Fraction
from typing import Any

FORMULA_VERSION = 1

BW_CLOSED = (
    7812,
    10417,
    15625,
    20833,
    31250,
    41667,
    62500,
    125000,
    250000,
    500000,
)

OK = 0
INVALID_ARGUMENT = 1
UNSUPPORTED = 2
OVERFLOW = 3
STRUCT = 4

LDRO_OFF = 0
LDRO_ON = 1
LDRO_AUTO = 2

# Tsym >= 16.38 ms  <=>  2^SF * 100000 >= BW * 1638
LDRO_AUTO_NUM = 100_000
LDRO_AUTO_DEN = 1638

@dataclass(frozen=True)
class Input:
    sf: int
    cr: int
    header_implicit: int
    crc_on: int
    ldro: int
    payload_len_bytes: int
    preamble_len_symbols: int
    bw_hz: int
    reserved_zero: int = 0

@dataclass(frozen=True)
class Result:
    status: int
    airtime_us: int = 0
    n_payload_symbols: int = 0
    tsym_us_ceil: int = 0
    toa_numerator: int = 0  # full uint64 value
    airtime_ms_ceil: int = 0  # independent ceil-ms (uint64); not driver wrapper
    ldro_effective: int = 0

def resolve_de(sf: int, bw_hz: int, ldro: int) -> tuple[int | None, int]:
    if ldro == LDRO_OFF:
        return 0, OK
    if ldro == LDRO_ON:
        # SF5/6: accept ON (effective=1); algebra ignores DE for SF<=6.
        return 1, OK
    if ldro == LDRO_AUTO:
        # Fraction path: Tsym >= 16.38/1000 (all SF, including 5/6)
        tsym = Fraction(1 << sf, bw_hz)
        de = 1 if tsym >= Fraction(1638, 100_000) else 0
        de2 = (
            1
            if ((1 << sf) * LDRO_AUTO_NUM) >= (bw_hz * LDRO_AUTO_DEN)
            else 0
        )
        if de != de2:
            raise RuntimeError("LDRO rational mismatch")
        return de, OK
    return None, INVALID_ARGUMENT

def toa_numerator_u64(
    sf: int,
    pl: int,
    crc: int,
    implicit: int,
    de: int,
    cr: int,
    preamble: int,
) -> tuple[int, int]:
    """Independent uint64 U + n_payload (driver algebra, different expression order)."""
    explicit_bonus = 0 if implicit else 20
    num = (pl * 8) + (16 if crc else 0) - (4 * sf) + explicit_bonus
    if sf <= 6:
        den = 4 * sf
    else:
        num += 8
        den = 4 * (sf - 2) if de else 4 * sf
    if den <= 0:
        raise OverflowError("den")
    if num < 0:
        num = 0
    ceil_term = (num + den - 1) // den
    cr_denom = cr + 4
    n_pay = 8 + ceil_term * cr_denom
    intermed = ceil_term * cr_denom + preamble + 12
    if sf <= 6:
        intermed += 2
    u = (4 * intermed + 1) * (1 << (sf - 2))
    if u < 0:
        raise OverflowError("u")
    return int(u), int(n_pay)

def compute(inp: Input) -> Result:
    if inp.reserved_zero != 0:
        return Result(status=STRUCT)
    if not (5 <= inp.sf <= 12):
        return Result(status=INVALID_ARGUMENT)
    # CR 5..7 (long interleave raw) explicit reject — no extrapolate
    if not (1 <= inp.cr <= 4):
        return Result(status=INVALID_ARGUMENT)
    if inp.header_implicit not in (0, 1):
        return Result(status=INVALID_ARGUMENT)
    if inp.crc_on not in (0, 1):
        return Result(status=INVALID_ARGUMENT)
    if not (6 <= inp.preamble_len_symbols <= 65535):
        return Result(status=INVALID_ARGUMENT)
    if not (0 <= inp.payload_len_bytes <= 255):
        return Result(status=INVALID_ARGUMENT)
    if inp.bw_hz not in BW_CLOSED:
        return Result(status=UNSUPPORTED)

    de, st = resolve_de(inp.sf, inp.bw_hz, inp.ldro)
    if st != OK or de is None:
        return Result(status=st)

    try:
        u, n_pay = toa_numerator_u64(
            inp.sf,
            inp.payload_len_bytes,
            inp.crc_on,
            inp.header_implicit,
            de,
            inp.cr,
            inp.preamble_len_symbols,
        )
    except OverflowError:
        return Result(status=OVERFLOW)

    # Independent uint64 ceil-ms and ceil-us (NOT uint32 1000*U wrapper)
    ms = math.ceil(Fraction(u * 1000, inp.bw_hz))
    us = math.ceil(Fraction(u * 1_000_000, inp.bw_hz))
    tsym_us = math.ceil(Fraction(1 << inp.sf, inp.bw_hz) * 1_000_000)

    if us < 0 or us > 0xFFFFFFFF:
        # Still report diagnostic numerator/ms for max-vector self-check
        return Result(
            status=OVERFLOW,
            toa_numerator=u,
            airtime_ms_ceil=int(ms) if 0 <= ms <= 2**63 else 0,
            ldro_effective=de,
        )

    return Result(
        status=OK,
        airtime_us=int(us),
        n_payload_symbols=int(n_pay),
        tsym_us_ceil=int(tsym_us),
        toa_numerator=int(u),
        airtime_ms_ceil=int(ms),
        ldro_effective=int(de),
    )

def high_value_ms_vectors() -> list[tuple[str, Input, int]]:
    """(id, input, expect_ceil_ms) from independent audit."""
    return [
        ("hv_sf7_p0", Input(7, 1, 0, 0, 0, 0, 8, 125000), 21),
        ("hv_sf7_p3", Input(7, 1, 0, 0, 0, 3, 8, 125000), 26),
        ("hv_sf7_p4", Input(7, 1, 0, 0, 0, 4, 8, 125000), 31),
        ("hv_sf7_p5_explicit", Input(7, 1, 0, 0, 0, 5, 8, 125000), 31),
        ("hv_sf7_p5_implicit", Input(7, 1, 1, 0, 0, 5, 8, 125000), 26),
        ("hv_sf5_p16_pre12_de0", Input(5, 1, 0, 1, LDRO_OFF, 16, 12, 125000), 17),
        # SF5 LDRO_ON: accepted, effective=1, same ToA as DE0 (algebra ignores DE)
        ("hv_sf5_p16_pre12_de1_on", Input(5, 1, 0, 1, LDRO_ON, 16, 12, 125000), 17),
        ("hv_sf6_p16_pre12_cr4_impl", Input(6, 4, 1, 0, 0, 16, 12, 125000), 34),
        ("hv_sf11_de0", Input(11, 1, 0, 1, LDRO_OFF, 16, 8, 125000), 578),
        ("hv_sf11_de1", Input(11, 1, 0, 1, LDRO_ON, 16, 8, 125000), 660),
        ("hv_sf12_bw250_de1", Input(12, 1, 0, 1, LDRO_ON, 16, 8, 250000), 660),
    ]

def boundary_vectors() -> list[dict[str, Any]]:
    cases: list[Input] = []

    def add(**kwargs: Any) -> None:
        base = dict(
            sf=7,
            cr=1,
            header_implicit=0,
            crc_on=1,
            ldro=LDRO_OFF,
            payload_len_bytes=16,
            preamble_len_symbols=8,
            bw_hz=125000,
            reserved_zero=0,
        )
        base.update(kwargs)
        cases.append(Input(**base))

    add(sf=5)
    add(sf=6)
    add(sf=12, ldro=LDRO_AUTO)
    for bw in BW_CLOSED:
        add(bw_hz=bw, sf=7)
        add(bw_hz=bw, sf=5, payload_len_bytes=8)
    add(cr=1)
    add(cr=4)
    for sf in (5, 7):
        for ih in (0, 1):
            for crc in (0, 1):
                add(sf=sf, header_implicit=ih, crc_on=crc, payload_len_bytes=0)
                add(sf=sf, header_implicit=ih, crc_on=crc, payload_len_bytes=255)
    add(preamble_len_symbols=6)
    add(preamble_len_symbols=12)  # DS recommend for SF5/6 — math only
    add(preamble_len_symbols=64)
    add(preamble_len_symbols=65535, sf=7, bw_hz=500000, payload_len_bytes=1)
    add(sf=10, bw_hz=125000, ldro=LDRO_AUTO)
    add(sf=11, bw_hz=125000, ldro=LDRO_AUTO)
    add(sf=12, bw_hz=125000, ldro=LDRO_OFF)
    add(sf=12, bw_hz=125000, ldro=LDRO_ON)
    add(sf=12, bw_hz=250000, ldro=LDRO_AUTO)
    add(sf=11, bw_hz=250000, ldro=LDRO_AUTO)
    add(sf=5, ldro=LDRO_AUTO)

    # Legal max → OVERFLOW for u32 us; ms cross-check in self-check
    add(
        sf=12,
        cr=4,
        header_implicit=0,
        crc_on=1,
        ldro=LDRO_ON,
        payload_len_bytes=255,
        preamble_len_symbols=65535,
        bw_hz=7812,
    )
    add(
        sf=12,
        cr=4,
        payload_len_bytes=255,
        preamble_len_symbols=65535,
        bw_hz=500000,
        ldro=LDRO_ON,
    )

    neg: list[tuple[str, Input]] = [
        ("sf_low", Input(4, 1, 0, 1, 0, 16, 8, 125000)),
        ("sf_high", Input(13, 1, 0, 1, 0, 16, 8, 125000)),
        ("cr_0", Input(7, 0, 0, 1, 0, 16, 8, 125000)),
        ("cr_5_long_il", Input(7, 5, 0, 1, 0, 16, 8, 125000)),
        ("cr_6_long_il", Input(7, 6, 0, 1, 0, 16, 8, 125000)),
        ("cr_7_long_il", Input(7, 7, 0, 1, 0, 16, 8, 125000)),
        ("preamble_low", Input(7, 1, 0, 1, 0, 16, 5, 125000)),
        ("bw_old_7810", Input(7, 1, 0, 1, 0, 16, 8, 7810)),
        ("bw_old_10420", Input(7, 1, 0, 1, 0, 16, 8, 10420)),
        # SF6 LDRO_ON is valid (not a negative); covered by high-value / boundary
        ("reserved", Input(7, 1, 0, 1, 0, 16, 8, 125000, reserved_zero=1)),
        ("header_bad", Input(7, 1, 2, 1, 0, 16, 8, 125000)),
        ("crc_bad", Input(7, 1, 0, 2, 0, 16, 8, 125000)),
        ("ldro_bad", Input(7, 1, 0, 1, 9, 16, 8, 125000)),
    ]

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, c in enumerate(cases):
        r = compute(c)
        key = f"ok_{i}_sf{c.sf}_bw{c.bw_hz}_pl{c.payload_len_bytes}"
        if key in seen:
            key = f"{key}_{i}"
        seen.add(key)
        exp = asdict(r)
        out.append({"id": key, "input": asdict(c), "expect": exp})

    for name, c in neg:
        r = compute(c)
        out.append({"id": f"neg_{name}", "input": asdict(c), "expect": asdict(r)})

    for name, c, exp_ms in high_value_ms_vectors():
        r = compute(c)
        d = asdict(r)
        d["expect_airtime_ms_ceil"] = exp_ms
        if r.status == OK and r.airtime_ms_ceil != exp_ms:
            raise RuntimeError(f"{name} ms {r.airtime_ms_ceil} != {exp_ms}")
        out.append({"id": name, "input": asdict(c), "expect": d})

    # Max legal: expect OVERFLOW for u32 us + pin ms 34581760 / U
    cmax = Input(12, 4, 0, 1, LDRO_ON, 255, 65535, 7812)
    rmax = compute(cmax)
    dmax = asdict(rmax)
    dmax["expect_airtime_ms_ceil"] = 34581760
    dmax["expect_toa_numerator"] = 270152704
    dmax["forbid_driver_ms_wrapper"] = 494718
    out.append({"id": "max_sf12_bw7812_overflow_us", "input": asdict(cmax), "expect": dmax})

    return out

def emit_c_header(vectors: list[dict[str, Any]], path: str) -> None:
    lines = [
        "/* AUTO-GENERATED by tools/airtime_r3_oracle.py — do not hand-edit */",
        "#ifndef NINLIL_AIRTIME_R3_VECTORS_GEN_H",
        "#define NINLIL_AIRTIME_R3_VECTORS_GEN_H",
        "#include <stdint.h>",
        f"#define NINLIL_AIRTIME_R3_VECTOR_COUNT ({len(vectors)}u)",
        f"#define NINLIL_AIRTIME_R3_ORACLE_FORMULA_VERSION ({FORMULA_VERSION}u)",
        "typedef struct ninlil_airtime_r3_vector {",
        "  const char *id;",
        "  uint8_t sf, cr, header_implicit, crc_on, ldro, payload_len_bytes;",
        "  uint16_t preamble_len_symbols;",
        "  uint32_t bw_hz;",
        "  uint32_t reserved_zero;",
        "  uint32_t expect_status;",
        "  uint32_t expect_airtime_us;",
        "  uint32_t expect_n_payload_symbols;",
        "  uint32_t expect_tsym_us_ceil;",
        "  uint32_t expect_toa_numerator_lo;",
        "  uint32_t expect_toa_numerator_hi;",
        "  uint8_t expect_ldro_effective;",
        "} ninlil_airtime_r3_vector_t;",
        "static const ninlil_airtime_r3_vector_t",
        "ninlil_airtime_r3_vectors[NINLIL_AIRTIME_R3_VECTOR_COUNT] = {",
    ]
    for v in vectors:
        inp = v["input"]
        exp = v["expect"]
        u = int(exp.get("toa_numerator", 0))
        lo = u & 0xFFFFFFFF
        hi = (u >> 32) & 0xFFFFFFFF
        # OVERFLOW vectors still carry numerator for diagnostics in C when status OK only
        air = int(exp.get("airtime_us", 0))
        npay = int(exp.get("n_payload_symbols", 0))
        tsym = int(exp.get("tsym_us_ceil", 0))
        ldro_e = int(exp.get("ldro_effective", 0))
        lines.append(
            "  { "
            f"\"{v['id']}\", "
            f"{inp['sf']}u, {inp['cr']}u, {inp['header_implicit']}u, "
            f"{inp['crc_on']}u, {inp['ldro']}u, {inp['payload_len_bytes']}u, "
            f"{inp['preamble_len_symbols']}u, {inp['bw_hz']}u, "
            f"{inp['reserved_zero']}u, "
            f"{exp['status']}u, {air}u, {npay}u, {tsym}u, "
            f"{lo}u, {hi}u, {ldro_e}u "
            "},"
        )
    lines += ["};", "#endif", ""]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("self-check", "emit-json", "emit-c", "eval"))
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv[1:])

    if args.cmd == "self-check":
        # SF7 hand us
        r = compute(Input(7, 1, 0, 1, 0, 16, 8, 125000))
        if r.status != OK or r.airtime_us != 51456:
            print(f"sf7 fail {r}", file=sys.stderr)
            return 1
        # high-value ms
        for name, inp, exp_ms in high_value_ms_vectors():
            rr = compute(inp)
            if rr.status != OK or rr.airtime_ms_ceil != exp_ms:
                print(f"{name} fail {rr} exp_ms={exp_ms}", file=sys.stderr)
                return 1
            if name == "hv_sf5_p16_pre12_de0" and rr.ldro_effective != 0:
                print(f"{name} effective {rr.ldro_effective}", file=sys.stderr)
                return 1
            if name == "hv_sf5_p16_pre12_de1_on" and rr.ldro_effective != 1:
                print(f"{name} effective {rr.ldro_effective}", file=sys.stderr)
                return 1
        # max: us OVERFLOW, ms exact, NOT driver wrapper
        rm = compute(Input(12, 4, 0, 1, LDRO_ON, 255, 65535, 7812))
        if rm.status != OVERFLOW:
            print(f"max must OVERFLOW us: {rm}", file=sys.stderr)
            return 1
        if rm.airtime_ms_ceil != 34581760:
            print(f"max ms {rm.airtime_ms_ceil} != 34581760", file=sys.stderr)
            return 1
        if rm.toa_numerator != 270152704:
            print(f"max U {rm.toa_numerator}", file=sys.stderr)
            return 1
        if rm.airtime_ms_ceil == 494718:
            print("must not equal driver wrapper garbage", file=sys.stderr)
            return 1
        # LDRO AUTO 16.38
        r11 = compute(Input(11, 1, 0, 1, LDRO_AUTO, 16, 8, 125000))
        if r11.ldro_effective != 1:
            print(f"sf11 auto {r11}", file=sys.stderr)
            return 1
        r10 = compute(Input(10, 1, 0, 1, LDRO_AUTO, 16, 8, 125000))
        if r10.ldro_effective != 0:
            print(f"sf10 auto {r10}", file=sys.stderr)
            return 1
        # SF5 LDRO_ON accepted; same ms as OFF; effective differs
        r5off = compute(Input(5, 1, 0, 1, LDRO_OFF, 16, 12, 125000))
        r5on = compute(Input(5, 1, 0, 1, LDRO_ON, 16, 12, 125000))
        if r5off.status != OK or r5on.status != OK:
            print(f"sf5 ldro off/on status {r5off} {r5on}", file=sys.stderr)
            return 1
        if r5off.airtime_ms_ceil != 17 or r5on.airtime_ms_ceil != 17:
            print(f"sf5 ms {r5off.airtime_ms_ceil} {r5on.airtime_ms_ceil}", file=sys.stderr)
            return 1
        if r5off.airtime_us != r5on.airtime_us:
            print("sf5 DE must not change ToA", file=sys.stderr)
            return 1
        if r5off.ldro_effective != 0 or r5on.ldro_effective != 1:
            print(f"sf5 effective {r5off.ldro_effective} {r5on.ldro_effective}", file=sys.stderr)
            return 1
        # SF6 LDRO_ON accepted
        r6on = compute(Input(6, 1, 0, 1, LDRO_ON, 16, 8, 125000))
        if r6on.status != OK or r6on.ldro_effective != 1:
            print(f"sf6 ldro on fail {r6on}", file=sys.stderr)
            return 1
        # CR 5..7 reject
        for cr in (5, 6, 7):
            if compute(Input(7, cr, 0, 1, 0, 16, 8, 125000)).status != INVALID_ARGUMENT:
                print(f"cr {cr} must INVALID", file=sys.stderr)
                return 1
        vecs = boundary_vectors()
        print(f"airtime_r3_oracle self-check ok vectors={len(vecs)}")
        return 0

    if args.cmd == "emit-json":
        text = json.dumps(
            {"formula_version": FORMULA_VERSION, "vectors": boundary_vectors()},
            indent=2,
            sort_keys=True,
        )
        if args.out:
            open(args.out, "w", encoding="utf-8").write(text + "\n")
        else:
            print(text)
        return 0

    if args.cmd == "emit-c":
        if not args.out:
            return 2
        emit_c_header(boundary_vectors(), args.out)
        print(f"emitted {args.out}")
        return 0

    if args.cmd == "eval":
        print(json.dumps(asdict(compute(Input(**json.load(sys.stdin)))), sort_keys=True))
        return 0
    return 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
