# V1 USB–radio board owner

## Goal

Close the missing software seam between the private NVB1 USB bridge and the
single-hop SX1262 packet-link without adding another Runtime, Fabric, task,
plugin system or heap owner on the USB board.

## Change

- ADR-0036 now fixes one caller-owned, bounded board owner and its custody
  semantics.
- The owner wires the existing durable provisioner, NVB1 bridge, exact LAB
  binding, NRA1/NRW1/R7 path and SX1262 PHY.
- Controller-to-board traffic is revalidated against an installed binding but
  does not fabricate a second Foundation TxPermit.
- RF-to-Controller traffic retains one receive loan until the Controller
  answers `ACCEPTED_LOCAL`; only that answer commits Receipt correlation.
- A rejected Controller handoff aborts only the pending mapper token, so the
  same logical Receipt can be retried without fencing or losing correlation.
- Capacity remains fixed at the existing two radio pairs. There is no dynamic
  registry, background worker or new public ABI.

## Evidence

- Host vertical simulation: binding install, Application over
  USB→board→SX1262 spy→peer, and APPLIED Receipt over peer→board→USB. The
  Receipt path also rejects the first handoff and accepts its retry.
- The same test passes in Debug and ASan/UBSan builds.
- ESP-IDF v5.5.3 packages the board owner in the all-private component build;
  the archive symbol gate checks the owner entrypoint.
- The combined feature build owns a build-local `sdkconfig`, so a generated
  default smoke config cannot shadow the all-private overlay.

## Remaining boundary

This is a software/target-build candidate. A concrete ESP application still
has to inject the USB stream, durable storage, clock, PCP/HAL and PHY objects,
then physical USB/RF HIL must run. No physical success or field readiness is
claimed by this change.
