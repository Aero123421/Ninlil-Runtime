# V1 lean public composition first review

Date: 2026-08-02  
Reviewer: independent Codex Sol high, review-only  
Decision: **direction GO; implementation/Accepted NO-GO — P0=0 / P1=3 / P2=1**

## Confirmed direction

- One public Fabric plus Host/ESP ports preserves the existing single-Bearer
  Runtime ABI and supports multiple Services, links and future controllers.
- Raw MFDT, RRMP and FRAG state machines should not become application APIs.
- Two-instance, bounded execution, restart and sanitizer acceptance are useful
  V1 requirements, not overengineering.
- ADR-0028's eight simultaneous package promotions and large evidence system
  are not required for V1.

## Findings returned for repair

1. The public route for enabling and owning internal reliability engines was
   undefined; current MFDT integration still uses private headers and the
   installed Runtime excludes it.
2. The Fabric tranche had only prose categories, without an exact symbol/type
   allowlist, ownership/lifetime rules, closed status mapping or bounds.
3. Linux/macOS USB was absent from the implementation order while physical USB
   HIL was listed; the existing POSIX adapter is not installed.
4. Negative acceptance said only “fail safely” rather than observable callback,
   mutation, I/O, terminalization, restart and close outcomes.

## Repair location

ADR-0029 now adds the exact first-tranche Fabric allowlist and contract,
requires a small Runtime composition owner before V1 completion, adds the
Linux/macOS USB tranche, and makes the negative outcomes observable. No public
raw reliability-engine API or new plugin framework was added.

Fresh re-review is required before ADR-0029 is marked Accepted or production
implementation starts.
