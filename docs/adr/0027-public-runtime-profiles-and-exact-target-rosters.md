# ADR-0027: Public Runtime profiles and exact target rosters

- Status: **Proposed — implementation candidate; independent review pending**
- Date: 2026-07-30
- Scope: public Foundation Runtime C API

## Context

The public ABI already carries three Runtime roles, four deployment
environments, a target array, target capacity, and per-target snapshots.
The implementation nevertheless rejected `CELL_AGENT`, every environment
except `TEST`, and every submission whose target count was not exactly one.
That made the public boundary narrower than its durable and bounded data
model, and encouraged application-specific wrappers to invent incompatible
role and fan-out semantics.

## Decision

1. `CONTROLLER`, `CELL_AGENT`, and `ENDPOINT` are valid values for
   `ninlil_runtime_create()`.
2. `TEST`, `LAB`, `FIELD`, and `PRODUCTION` are valid environments. Unknown
   values remain invalid. The environment is forwarded to policy/identity
   boundaries; Core does not weaken validation or durability by environment.
3. Foundation application services remain owned by `CONTROLLER` and
   `ENDPOINT`. `CELL_AGENT` creation is valid, while
   `ninlil_service_register()` fails closed with `NINLIL_E_UNSUPPORTED`.
4. A Controller downlink submission may contain 1 through 4 explicitly
   enumerated concrete targets, further bounded by both Runtime
   `max_targets_per_transaction` and Service `target_limit`.
5. Admission canonicalizes the exact roster, rejects duplicate target
   records, commits the complete roster and resource reservation in one FULL
   transaction, and includes the roster in the idempotency digest.
6. Completion is `ALL_TARGETS`: each target has independent durable retry
   budget/counters, active attempt ID and canonical-target binding, timer/send
   observation, dispatch/evidence/terminal state, Outcome and reason. A
   timeout, exhaustion, availability failure, stale/duplicate Receipt, or
   wrong-target Receipt for one target cannot mutate or stop another target.
   The transaction becomes `SATISFIED` only after every target reaches
   required evidence; mixed terminal Outcomes use the deterministic
   precedence in Normative docs/13. Each public target snapshot also exposes
   its own late-evidence flag and saturating valid/duplicate/raw-overflow/late
   counters. A valid terminal Receipt updates only the matched target's late
   evidence and never reverses its or the aggregate Outcome.
7. Query returns every target in canonical order and reports required
   capacity without partial projection. List remains a transaction-summary
   API; callers use query for the roster.
8. Selector resolution, named groups, `ANY_TARGET`, quorum, and best-effort
   broadcast are explicitly unsupported. No target is inferred from a name,
   topology, or current membership.
9. Origin-authorized uplink `EventFact` remains exactly one target because
   its authorization Port evaluates one exact target per grant. Expanding
   that authority requires a separate ADR and Port revision.
10. The LAB-private NTS3 durable row changes from schema 1.0 to 1.1. Schema
    1.0 has no target-local attempt binding and is rejected fail-closed; it is
    never interpreted as 1.1. This pre-release namespace gets no implicit
    migration. The 1.1 maximum (4 targets × 8 attempts plus maximum V1
    payload/evidence) must fit the existing 4,096-byte record ceiling. NTS3
    stores logical and inline payload lengths separately: single-frame routes
    require equality up to 926 bytes, while MFDT stores 927..32768 logical
    bytes with zero inline bytes because NM3S owns content custody.

The implementation maximum of four is a profile bound, not an ABI promise
that future profiles can never raise the limit.

## Consequences

- One durable transaction can safely express small exact fan-out without an
  application-side transaction aggregator.
- Resource accounting scales target and evidence reservations by roster size.
- Restart, retry and dedup operate on the same durable roster.
- `CELL_AGENT` can host transport/fabric adapters without pretending to be an
  application admission authority.
- Deployment environment selection no longer requires a private Runtime fork.

## Acceptance

- Runtime creation matrix covers all 3 roles × 4 environments, plus unknown
  role/environment rejection.
- A 2-target Controller submission proves admission, idempotent replay,
  conflicting replay, FULL restart recovery from A-complete/B-retrying,
  retry/exhaustion isolation, attempt+source target binding, per-target dedup,
  query capacity/full roster, mixed aggregate, list visibility, and
  A-high/B-lower/terminal-late/exact-duplicate evidence classification before
  and after restart.
- A 4-target maximum proves canonical deep-copy, TARGET=4 and EVIDENCE=36
  atomic accounting, release/restart/query, NTS3 maximum size, and corruption
  rejection.
- Zero, duplicate, over-Service-limit, over-Runtime-limit, and over-profile
  rosters fail closed.
- MFDT logical length 927 and 32768 round-trip with zero inline bytes;
  route/length mismatch, inline overflow, and old 1.0 rows fail closed.
- Until the public Runtime owns an MFDT scheduler/ingress path, an admitted
  MFDT-shaped transaction remains durable `ADMITTED_READY` pending work:
  normal APPLICATION/U6 send, Tx permit, attempt/retry consumption, record
  mutation, and false terminalization are all zero before and after restart.
  A single-frame logical=inline negative control still uses the ordinary
  bearer path. This fail-closed fence does not complete public MFDT delivery.
- Normal and ASan/UBSan runs pass. Host simulation is not physical HIL.

The target-local NTS3 summary is not a substitute for the Normative
`EVIDENCE_CELL` raw-detail contract. Accepted Foundation promotion still
requires the docs/13 and docs/17 admission materialization, raw `L` cells,
summary replacement headroom, and ordered-ingress atomicity evidence. This
ADR must not be promoted on the NTS3 summary tests alone.

Promotion to **Accepted** requires an independent review of this specification,
the public API boundary, durable record/resource accounting, retry/dedup
behavior, and the normal plus sanitizer evidence. The implementation author
does not self-promote this ADR.
