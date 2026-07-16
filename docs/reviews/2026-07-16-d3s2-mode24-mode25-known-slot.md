# D3-S2 Mode24/25 known-slot legality review

Date: 2026-07-16  
Scope: `docs/17` §18.13.15 case 3 residual for Modes 24 and 25

## Decision

GO for this append-only slice. It does not claim D3-S2 overall complete.

Rows with REVERSE_REPLY `reply_kind` outside 1..4, RETRY CUMULATIVE slot other than 0, or RETRY RECENT slot outside 0..3 are already rejected by D1 same-record validation. They are therefore not constructible as D3-S2 formal inputs and were not fabricated.

The four appended vectors use D1-valid cross-row population failures instead:

- Mode24: `reply_count=1` with no REVERSE_REPLY.
- Mode24: `reply_count=1` with RECEIPT and DISPOSITION.
- Mode25: cumulative total 1 with no RECENT row.
- Mode25: cumulative total 1 with valid cycle 1/slot 0 and cycle 2/slot 1 rows.

The production evaluator already rejects all four during the known-kind/known-slot FOCUS close, before BIND. No production source change was required.

## Independent verification

- Existing 139 vector objects are exactly unchanged; four vectors are appended for a total of 143.
- Generator check: pass, 94 D3-S1 prefix + 49 D3-S2 suffix.
- Generator mutation self-test: pass.
- Clean Debug build and CTest: 86/86 pass.
- AppleClang ASan/UBSan build and CTest: 86/86 pass with halt-on-error.
- Tests-OFF build plus private/release/DSR2 gates: pass.
- `git diff --check`: pass.

## Non-claims

This review does not establish DSD1 composition, the remaining D3-S2 audit items, D3-S3 through S12, Stage 5, D4, public Runtime, ESP-IDF, USB, LoRa, or hardware readiness.
