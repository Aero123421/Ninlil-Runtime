# RRMP P0 close (independent snapshot NO-GO) — 2026-07-29

> Superseded implementation note: the final capacity repair uses 22 route
> arena pages, 23 parent arena pages, a 353480-byte owner workspace under a
> 384 KiB ceiling, and `RRMPQST3` scope seal flags. The earlier
> `NPS1[255]`/256 KiB mechanism below is retained only as audit history and is
> not the current format.

## Status

- Spec/ADR: still **Proposed** (no Accepted).
- Feature default-OFF; private symbols only when ON; public ABI unchanged.
- Physical RF HIL: **NOT_RUN**.

## P0 groups closed

| # | Requirement | Implementation |
|---|-------------|----------------|
| 1 | recover-CU ABI + reserved/precedence | `parent_recover_cu_req`: owner_scope@16, observed_assignment@32, class@64, now@72; reserved must 0; preamble precedence |
| 2 | 22 parent keys + NPH1/NPA1/NPT1 + FULL + rehydrate | keys 0+1..5+6..13+14..21; NPP1×5/NPA1×8/NPT1×8 rehydrate; FULL commit re-classifies CU |
| 3 | first-admit durable before queue; complete ownership | LIVE NEP1 FULL before queue; persist fail → no admit; complete matches `opaque_handle` + local ownership |
| 4 | E2E payload from NRM1 materialize; multi-node hops | admit stores materialize body; TX inject rejected; 2/3-hop = independent owners |
| 5 | SB/parent-loss mandatory bind + old_seal + durable | Historical implementation used NPS1[255]; superseded by canonical NPS1 reserved-zero plus `RRMPQST3` scope seal flags |
| 6 | SHA fail-closed | OpenSSL or mbedTLS only; **no portable fallback** (`#error`) |

## Workspace

- `ws_bytes=219496` (≤256KiB). Live scopes 24; queue 48; parent arena 16 pages.

## Verify (fresh)

```text
# ON focused
build-rrmp-p0:        ctest -R 'ninlil_rrmp_|rrmp_private' → 7/7
# ASan+UBSan
build-rrmp-p0-asan:   ctest -R 'ninlil_rrmp_' → 4/4
# OFF (prod archive must lack rrmp)
build-rrmp-p0-off:    ctest -R 'ninlil_rrmp_|rrmp_private' → 7/7
```

## ESP

- Host private path green. Official ESP compile/link/map proof: **not run in this host session** (no IDF invocation recorded). Component sources remain Kconfig default-OFF.

## Residuals (honest)

- Physical RF HIL NOT_RUN.
- Spec remains Proposed.
- Live RAM scope capacity 24 (NPP1 theoretical 75); extra scopes beyond 24 not rehydrated into RAM.
- Multi-node hop uses independent owners + shared e2e digest; not over-air.
