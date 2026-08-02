# Multi-service node Host acceptance — 2026-07-29

Status: **HOST NORMAL + SANITIZER + ESP32-S3 TARGET BUILD PASS /
PHYSICAL HIL NOT_RUN**

## Purpose

Prove that one physical-node Runtime is not fixed to one application role.
The same Endpoint Runtime must own several independent services and make
progress on inbound commands and outbound facts through one bounded event
loop. A relay role, when enabled, is an independent routing responsibility and
must not replace or suppress these application services.

This acceptance stays inside the Accepted M1a public contract:

- DesiredStateCommand and EventFact are the only enabled public families.
- A current-value or measurement-shaped payload is an EventFact in this test;
  it does not enable a reserved M2 family.
- Query/list polling is the M1a observation API. Native subscription,
  capability discovery/search, selectors, and first-class LatestState or
  MeasurementBatch remain explicit roadmap work.

## One-node service set

The Endpoint Runtime registers all of the following at the same time:

| Service | M1a family and direction | Required behavior |
| --- | --- | --- |
| `display.command` | DesiredState, downlink receiver | Receive UTF-8 plus preset/binary display data and return `VERIFIED` |
| `access.event` | EventFact, uplink sender | Submit an immutable entry/exit event |
| `temperature.telemetry` | EventFact, uplink sender | Submit a periodic sample and a correlated query response |
| `temperature.query` | DesiredState, downlink receiver | Apply a query command without re-entering the Runtime |

The peer Controller Runtime registers the exact complementary service
descriptors. Routing must use the complete service identity; family-only
routing is a failure.

## Host acceptance

A two-peer POSIX Fabric simulation must:

1. register all four services on both peers as applicable;
2. overlap a display command, an access event, a periodic temperature sample,
   and a temperature query in the same progress window;
3. submit the query response only after the callback has returned;
4. deliver every logical item to the matching service callback exactly once,
   while transport retry or duplicate frames remain permitted internally;
5. reach the requested terminal evidence for all transactions;
6. return the same service identities and terminal outcomes through
   `transaction_query` and `transaction_list`;
7. exercise UTF-8 text, a preset number, fixed-width sensor data, and opaque
   binary payloads without application vocabulary entering Portable Core;
8. repeat under ASan/UBSan and with one data loss plus one duplicate injection;
9. keep all queues, services, payloads, and step work within declared finite
   limits.

The test must fail if a callback for one service receives another service's
payload, a sender/receiver direction is reversed, a duplicate causes a second
application effect, or a query callback re-enters Runtime APIs.

## Target and HIL boundary

The same descriptor set and application state machine must compile for the
ESP32-S3 component without a second firmware variant. A physical ESP32-S3 E2E
run remains `NOT_RUN` until hardware is connected. Host simulation and target
compile must never be relabeled as physical evidence.

## Implementation order

1. Add the Host scenario by reusing the existing POSIX loopback harness.
2. Add exact CTest inventory checks and sanitizer coverage.
3. Add the descriptor/state-machine target smoke without application-specific
   code in Portable Core.
4. Run an independent Codex review for routing identity, callback re-entry,
   duplicate effects, and false-green test inventory.
5. Record the exact commands and results here, then update the root completion
   ledger and README state.

## Current evidence

The production-neutral descriptor profile and response-pending state machine
are implemented once in `examples/multi_service_node/`. The Host actual E2E
in `tests/host/runtime_fabric_actual_e2e_test.c` and the ESP32-S3 smoke app
both compile and call that same module. Its manifest explicitly declares
`runtime_role_constraint = NINLIL_MULTI_SERVICE_NODE_ROLE_NEUTRAL` and all four
Services; no single application role is baked into the profile.

The scenario:

- admits the display command, access event, periodic temperature event, and
  temperature query before the same bounded progress loop starts;
- submits the correlated temperature response only after the query callback
  has returned;
- injects one silently lost accepted packet and one duplicated packet;
- requires exact service/payload routing and exactly one application effect
  for display, access, query, periodic temperature, and response;
- queries every origin transaction and lists both Runtime origin domains;
- exercises UTF-8 bytes, a preset number, fixed-width sensor bytes, and opaque
  binary bytes;
- uses distinct entropy streams for the two Runtime identities, preventing a
  false collision between independently generated transaction IDs.

The scenario also exposed and closed a real EventFact/Fabric integration bug:
EventFact carries `NO_DEADLINE` with an all-zero wire deadline epoch, while
ADR-0017 requires the Fabric retry lifetime to use the attempt-admission
trusted clock epoch. `fabric_private_core.c` now performs that exact
family-specific projection without changing the wire deadline fields.

Current normal evidence:

```text
cmake ... -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON ...
cmake --build build/root-multiservice-live \
  --target ninlil_runtime_fabric_actual_e2e_test
./build/root-multiservice-live/ninlil_runtime_fabric_actual_e2e_test
runtime_fabric_actual_e2e_test: PASS
```

CTest exposes the same executable as both `runtime_fabric_actual_e2e` and the
explicit acceptance name `multi_service_node_host_actual_e2e`.

Fresh ASan/UBSan evidence:

```text
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build/root-multiservice-asan --output-on-failure \
  -R '^(runtime_fabric_actual_e2e|multi_service_node_host_actual_e2e)$'
100% tests passed, 0 tests failed out of 2
```

Leak detection is disabled explicitly because this run is on macOS; ASan and
UBSan still fail fast.

ESP-IDF v5.5.3 built the ESP32-S3 smoke app into the final ELF and the ELF
contains the shared profile, validation, response-state, and acceptance
symbols. `app_main` calls the shared target smoke, but no board was flashed in
this tranche. Therefore target compile/link is **PASS** and physical HIL
remains explicitly **NOT_RUN**.

The exact review repairs, fresh commands, and complete evidence are recorded
in `2026-07-29-fabric-multiservice-p1-review-close.md`.
