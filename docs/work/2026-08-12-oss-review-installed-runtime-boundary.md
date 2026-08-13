# OSS review: installed Host Runtime boundary — 2026-08-12

## Scope

The installable `Ninlil::runtime` archive previously reused the mutable
`NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES` integration list. Test-registration
modules appended LAB sources to that list before the public archive was
created, so tests-ON packages contained V1 LAB, C3/C4/C5/C6 LAB, PCP LAB and
SX1262 edge objects even though none was an installed public module.

## Change

- Added `cmake/ninlil_host_runtime_sources.cmake` as the only source authority
  for the installable Host Runtime.
- Kept the accepted Host OpenSSL R7 adapter and conditional public Composition
  implementation, but excluded LAB, simulator, physical-radio and mutable
  private-candidate appends.
- Closed the Host source authority as an exact single CMake list, and made the
  fresh tests-OFF installed-consumer gate compare the complete archive-member
  multiset. This rejects both edits to the authority and direct
  `target_sources(ninlil_runtime ...)` injection, in addition to the existing
  forbidden global-symbol checks.
- Updated the SDK documents to describe the actual installed boundary.

No public header, ABI, wire format, storage format or feature maturity changed.
`ninlil_runtime_private` remains the non-installed integration/test vehicle.

## Verification

- fresh Release tests-OFF build of `Ninlil::runtime`: PASS;
- archive member scan: 38 implementation objects (plus Darwin archive index), zero
  `v1_lab` / `_lab_` / `pcp_lab` / `sx1262` / simulator members;
- global symbol scan: Runtime create/step/destroy, Composition and the accepted
  Host crypto provider present; forbidden LAB/physical prefixes absent;
- fresh tests-OFF installed consumer, SQLite OFF / Domain OFF: PASS, including
  four-Service durable lifecycle, restart, dedupe, query and list;
- fresh tests-OFF installed consumer, Domain ON: PASS with required Domain
  symbols and fail-closed public create behavior;
- fresh ASan/UBSan tests-OFF installed consumer: PASS.
- independent mutations: appending `control_session.c` or
  `logical_session.c` to the Host authority is rejected, and a direct
  `target_sources(ninlil_runtime PRIVATE src/transport/control_session.c)`
  injection is rejected by exact archive-member comparison.

Physical USB/RF HIL is outside this source-boundary change. Independent final
review re-ran both source-authority and direct-target injection negatives and
found no residual defect in the current archive. PR #117 head
`3892766741569c536f4456de0a860090445e8926` completed the integrated remote
matrices, including the
[tests-OFF installed consumer job](https://github.com/Aero123421/Ninlil-Runtime/actions/runs/31614757981/job/94174673801).
The final follow-up commit still requires its own same-SHA remote rerun.
