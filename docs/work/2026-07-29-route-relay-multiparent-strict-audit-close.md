# RRMP strict audit close — 2026-07-29 (additional exact)

> Historical snapshot. Current capacity evidence supersedes the workspace
> number below: **353480 B ≤ 384 KiB**, with 22/23-page route/parent arenas.

## Status

- Spec/ADR: **Proposed** (not Accepted)
- Physical RF HIL: **NOT_RUN**
- ESP IDF compile/map: **NOT_RUN** (no IDF in session)
- Workspace: **255728 B** ≤ 256 KiB

## Exact items addressed

| Item | Change |
|------|--------|
| 22 keys | NPH1×1 + NPP1×5 + NPA1×8 + NPT1×8; rehydrate all pages |
| Scope cap | **64** live scopes (not 75) |
| Queue 64 | full fields: e2e body, rev, deadline, F/R, prio, seq, opaque; fairness + byte quota |
| Parent select | path-policy ordered walk (primary→backup); **not** attempt%count; loss/reinstall clears attempt |
| old_owner_seal | **0** after OLD_RETIRED (ADR S6) |
| Lifecycle | STAGED→ACTIVE only; lease→durable **EXPIRED** slot state 4; fence=`next_admission_seq` |
| Slot map | LIFE_* ↔ ROUTE_STATE_* exact; EXPIRED=4 RETIRED=5; rehydrate skips RETIRED tombstones |
| Batch/retire | install none-or-all prealloc + page FULL; retire durable RETIRED then free; persist fail reverts |
| Drain | F≤13 R≤3; nonzero **A/T/W/I/G**; airtime **F×A** only |
| SHA | OpenSSL/mbedTLS only + NIST empty/`abc` KAT selftest fail-closed (no portable fallback) |
| 10k sim | **exact** install=activate=admit=complete=retire=**10000**; every `out.status==return==OK` |
| OFF archive | does **not** require compiling impl probe; proxy zero symbols |
| A→B→C | independent owners; per-node materialize rewrap; hop 3→2→1; CU OLD fault on A; B/C query OK |
| Codecs | semantic KAT: reserved zeros, all-zero reject, slot kinds, NPP1 all pages, NPA1/NPT1 LIVE/TOMBSTONE |

## Verify

```text
build-rrmp-strict:      codec/sm/crash/sim → OK; 10k exact 10000×5
build-rrmp-strict-asan: same under ASan → OK
build-rrmp-strict-off:  prod_off_proxy + archive → pass; no impl probe required
```

## Residuals (honest non-claims)

- Host multi-node is software owners, not RF
- Dual OLD retained only via inject (production frees previous active after NEW commit)
- Physical RF multi-hop / multiparent air / NOR powercut HIL: **NOT_RUN**
- ESP-IDF ELF/map with RRMP-on: **NOT_RUN**
