# ADR-0037: Three-node automatic Join and relay LAB

- Status: Proposed
- Date: 2026-08-08
- Scope: private ESP32-S3 + SX1262 hardware closure
- Depends on: ADR-0004, ADR-0025, ADR-0034
- Keeps: every installed Runtime, Fabric, wire, storage and Composition ABI

## Context

ADR-0034 intentionally stopped at single-hop V1. RRMP and Production
Attachment have substantially stronger contracts, but neither is connected to
the physical SX1262 receive/forward loop. Building those remaining production
surfaces before proving three radios can autonomously converge would repeat
the project's earlier over-engineering failure.

## Decision

Add one private, host-testable `NJM1` LAB state machine to the existing
`radio_hil_app`. It uses the existing R5/R1/R9 physical path and changes no
portable Core or public API.

The state machine provides automatic discovery, LAB Join, concurrent endpoint
and relay behavior, bounded route learning, metric-based parent selection,
hysteresis, lease expiry, re-Join, opaque small data, ACK and metrics. One
common firmware image is runtime-configured through USB; there are no separate
controller/relay/endpoint binaries.

The exact profile and acceptance are chapter 36. The implementation and UI
must label this `LAB_ONLY` and must not claim Production Attachment, secure
site authorization, legal approval, RF isolation, or RRMP physical acceptance.

## Why not wire all of RRMP first

RRMP requires durable namespace ownership, route authority installation,
authenticated LINK_ACK evidence and an outbound provider. Those contracts are
kept. This LAB does not weaken or imitate them; it answers the smaller physical
question with the existing legal-permit radio edge. After HIL passes, its
single RX/TX owner loop becomes the carrier seam for RRMP rather than a second
public routing system.

## Consequences

- Three boards can close the immediate hardware path with a small isolated
  diff.
- The LAB Join is intentionally disposable and cannot be promoted to FIELD.
- True alternate-relay failover is tested with at least four boards later.
- Adaptive channel, SF, power and scheduling are not added until measured HIL
  data shows which control is needed.
