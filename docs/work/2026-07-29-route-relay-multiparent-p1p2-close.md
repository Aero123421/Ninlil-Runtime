# RRMP P1/P2 close (post NO-GO repair) — 2026-07-29

> Historical snapshot. Current capacity evidence supersedes the workspace and
> arena numbers below: **353480 B ≤ 384 KiB**, 22 route arena pages and 23
> parent arena pages.

## Scope

Closes independent audit P1/P2 items (not SPEC_ACCEPTED). Proposed ADRs unchanged.

## Semantic fixes (evidence lines → behavior)

| Item | Fix |
|------|-----|
| route lookup | `(ingress_hop_context_id, handle, gen)` required |
| lease | `now >= lease_expiry` → `LEASE_EXPIRED` |
| hop | `hop_remaining > max_hops/profile/absolute` → `HOP_EXHAUSTED` |
| clock epoch | NRM1 epoch must match owner cfg → `CLOCK_EPOCH_MISMATCH` |
| stale generation | `controller_term < cfg` → `STALE_GENERATION` |
| self-egress | egress_peer == local → `LOOP` |
| DRAINING order | only ACTIVE→DRAINING |
| drain formula | `remaining_attempts` multiplies work; 0 attempts ineligible |
| queue full | capacity checked **before** LIVE durable; BACKPRESSURE leaves no LIVE |
| parent IDs | nonzero, unique, trailing zero, revision mono-inc |
| fence proof | nonzero + digest(scope‖token‖old_rev) bind |
| authority CAS | exact `cas_expected_generation` + term/revision match; store commit dig |
| activate receipt | must equal **commit digest**, not token |
| split-brain / parent loss | **scope-local** seal only; other scopes continue |
| workspace | **no calloc**; `ninlil_rrmp_owner_init(ws, bytes, cfg)`; arena dual-slot |

## Budget

- `ninlil_rrmp_owner_workspace_bytes()` measured **218208** (≈213 KiB) ≤ **256 KiB**
  host ESP-candidate gate.
- Dual pages use shared arenas (12 route / 8 parent pages), not 21×2×4096 embedding.
- No `calloc`/`malloc` in production owner path; caller-owned `owner_init(ws,n,cfg)`.

## Tests

- Queue actually filled to BACKPRESSURE; all statuses asserted (`out.status == return`).
- 10k lifecycle: INVALID_ARGUMENT never counted as success.
- Symbol archive: **20 catalog ops** required; feature-OFF production **proxy** always built (no absent skip).
- Spec gate still 114/114 Proposed.

## Honest residuals

- Physical multi-hop / multi-parent RF HIL: unexecuted.
- Real flash power-cut dual-slot HIL: unexecuted.
- Board esp32s3 ELF/map campaign: recipe only.

## Claims

**Implementation candidate only.** Not Accepted. No over-claim of production readiness or HIL.
