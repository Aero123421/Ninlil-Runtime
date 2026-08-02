# ADR-0034: V1 functional LAB scope

状態: **ACCEPTED**
- Date: 2026-08-03
- Accepted: 2026-08-03
- Scope: first usable ESP32-S3 + SX1262 release
- Depends on: ADR-0033
- Amends: ADR-0029 section 4 and implementation order; ADR-0032 software acceptance
- Keeps: every existing public type, symbol, wire value and storage value

## Context

ADR-0029 and ADR-0032 made large-data transfer, radio fragmentation, relay and
multi-parent integration simultaneous V1 completion requirements. That is a
sound long-term target, but it couples the first usable single-hop radio SDK to
Production Attachment and four independent reliability engines. The result is
slow to finish and difficult for an OSS adopter to understand.

The first release still must prove the product-neutral path that motivated the
SDK: a Linux/macOS program talks over USB to an ESP32-S3 + SX1262 parent, and a
small ApplicationData item reaches the intended Service on the specified one
of at least two ESP32-S3 + SX1262 peers. A compile-only radio image or raw PHY
test is not that path.

## Decision

### V1 required path

V1 is a **LAB_ONLY functional SDK** with this mandatory vertical slice:

```text
Linux/macOS application
  -> USB parent node
  -> single-hop SX1262
  -> intended peer / intended Runtime Service
  -> delivery result / Receipt back to the application
```

The slice has these fixed bounds:

1. one Controller process, one USB-connected parent and at least two direct RF
   peers in acceptance; public identifiers and dispatch must not assume a
   single peer;
2. one physical node may register multiple Services; no single-role firmware
   restriction is introduced;
3. generic ApplicationData of 1..128 bytes, including arbitrary binary and
   UTF-8 bytes; application vocabulary is outside Ninlil;
4. exact target Runtime and Service selection, message identity, deadline and
   priority are preserved end to end;
5. duplicate RF delivery invokes the target Service at most once;
6. an authenticated success result is required before Application success;
   transmit completion, custody and availability are not success;
7. retry and timeout are bounded and do not loop until idle inside a helper;
8. all RF transmission continues through the existing R1/R2/R5/R9 permit,
   airtime and LBT sole edge; and
9. Linux and macOS are the supported Controller hosts. ESP-IDF 5.5.3 on
   ESP32-S3 is the target firmware platform.

V1 may use an explicitly provisioned LAB identity/session binding. It must not
ship a compiled default shared key, print key material, or label that binding
as Production Attachment. Automated Join, session rotation and field
reassignment remain V2 work. The binding must join the target Runtime ID,
peer Runtime ID, `service_identity_digest`, context/key generation and
attachment-binding digest used by Fabric. Provisioning arrives only over the
trusted-local USB control path and commits the binding to the existing FULL
flash Storage before use. Active keys are copied into owner-confined RAM,
never printed, and zeroized on reprovision/close. Tamper, replay, wrong key and
wrong binding fail closed. After reboot, a durably valid binding is restored
and revalidated or RF application traffic is denied until explicit
reprovisioning; a default/fabricated session is forbidden.

USB is a trusted-local LAB boundary between the Controller host and parent
board, not a cryptographically authenticated network bearer. The authenticated
success in item 6 is the RF peer's APPLIED Receipt; USB only returns that result
to the locally trusted application. V1 makes no claim against a hostile USB
host, cable or local process.

The radio mapping and USB control framing must be specified in a small
follow-up amendment before their implementation is called complete. They may
reuse existing codecs and ports, but must not publish private MFDT, FRAG, RRMP,
Join or radio-driver internals.

ADR-0033's RF publication stop remains binding. Before the V1 path can send
ApplicationData, an Accepted follow-up must define the exact unfragmented
ApplicationData-to-NRW1 SINGLE mapping, RF-safe entropy lifecycle and the
minimal private ESP packet-link adapter owned by Composition. The adapter is
compiled inside the ESP component; it adds no installed public header, CMake
target or direct packet-link API. Portable Runtime and Composition ABI stay
unchanged, and the adapter must not expose raw R1/R2/R5/R9 or private radio
state. Until all three conditions are Accepted and active, registration fails
closed and the RF TX call count is exactly zero.

### V2 work

The following remain implemented and tested private candidates where they
already exist, but are not V1 completion blockers:

- ApplicationData larger than the final V1 mapping maximum and durable
  multi-frame custody;
- compact-radio fragmentation/reassembly;
- relay and two/three-hop forwarding;
- multi-parent, multi-Controller routing and failover;
- the ESP32-S3 Wi-Fi bearer/public facade and physical access-point HIL;
- Production Attachment / automated field Join and key rotation; and
- field SLO, soak, power-cut and production regulatory evidence.

Moving these gates does not delete their code or tests and does not promote a
weaker result to production. It only prevents their simultaneous integration
from blocking the first functional LAB release.

### Public API and composition

No new plugin system, role hierarchy, dependency-injection layer or public
reliability-engine API is added. `ninlil_composition_v1_t` remains the sole
public Runtime/Fabric owner. In V1, `reliability_work` is reserved and reports
zero until a later Accepted amendment activates an internal engine.

ADR-0032 software-acceptance items 2 through 5 become V2 acceptance. Its base
owner, two-instance isolation, terminal capacity, error, close and restart
requirements remain V1 requirements. ADR-0029's mandatory large-data, RF
fragmentation and relay/multi-parent paths likewise move to V2; its public
Fabric, POSIX TLS, POSIX USB and thin-composition decisions remain unchanged.

## Acceptance

V1 software-ready requires:

1. all existing public Host install/consumer, strict-warning and scoped
   sanitizer gates remain green;
2. a Host simulation proves the same multi-Service node concurrently receives
   a command, publishes an event and answers/publishes a measurement;
3. the exact USB-parent-to-single-hop-RF-to-Service path has Host loss,
   duplicate, timeout, tamper, replay, wrong-key, wrong-binding, restart and
   wrong-target tests;
4. the ESP images compile/link from public SDK boundaries with the exact
   XIAO ESP32-S3 + Wio-SX1262 board profile; and
5. README and compatibility state distinguish software-ready from physical
   evidence.

The follow-up mapping must include positive KATs for 1-byte and the final V1
maximum ApplicationData, negative KATs for 0 and one byte above that maximum,
and a byte-budget proof that every mapped request or Receipt NRW1 SINGLE
application body is at most
190 bytes. Its kind-specific exact layout and off-wire derivation must preserve
target, Service, transaction, attempt, generation, deadline, priority and
required-evidence meaning losslessly. If 128 bytes does not fit, a new
amendment reduces this ADR's limit before the feature transitions to
`SPEC_ACCEPTED`; fragmentation is not silently added.

The same mapping amendment must pin `ack_requested=0` for these V1
Application/Receipt frames: Application-level APPLIED Receipt and bounded
Runtime retry are the V1 reliability path, so a second per-frame LINK_ACK is
not silently added. It must calculate every exact sealed outer-frame airtime
with the repository R3 oracle and publish a deterministic schedule. Nominal
request-plus-Receipt airtime for one 10-second window must be at most 6 seconds,
leaving at least 40% for LBT, turn-around and bounded retry. If the final frame
lengths exceed that budget, the V1 rate or payload maximum is reduced before
acceptance rather than accepting an infeasible benchmark.

Final V1 hardware acceptance additionally requires three physical boards and a
Linux or macOS Controller: one USB parent plus two direct RF peers. The run
uses one channel with the recorded LAB profile (SF7, BW 125 kHz, CR 4/5,
8-symbol preamble, channel ID 2, 10 dBm), 32-byte ApplicationData and an
APPLIED Receipt deadline at the end of each window. Each of three consecutive
10-second windows contains exactly 10 submitted ApplicationData items at
fixed one-second offsets from 0 through 9 seconds:

- 4 DesiredState downlinks, two to each peer;
- 3 EventFact uplinks, two from the multi-Service peer and one from the other;
  and
- 3 periodic-measurement EventFact uplinks, two from the multi-Service peer
  and one from the other.

Reverse Receipt traffic and RF retries are additional to those 10 submissions.
All 10 must produce the required APPLIED Receipt before the window deadline.
Retries are allowed, but missing terminal delivery, duplicate Application
invocation and wrong peer/Service delivery are all zero. At least one peer must
simultaneously receive commands, publish events and publish/respond with
measurement data through separate Services in the same firmware. One of that
peer's DesiredState downlinks is an application-level measurement query and
its matching measurement EventFact is one of the three measurement uplinks; no
new public family is introduced.

For peer-to-parent uplinks, receipt authority is the Controller application's
correlated callback result. The parent Runtime may emit APPLIED only after the
USB framing layer returns that result for the exact transaction/attempt and
Service. USB write completion, bytes accepted by a serial ring, or parent-side
receipt of the RF frame is never APPLIED. Timeout, disconnect and a mismatched
USB result remain non-success and follow the bounded retry/terminal policy.

The 20-submissions-per-10-seconds target is a V2 capacity gate. It requires an
Accepted schedule based on final frame lengths and may use two independent
channels/parents or a separately Accepted Receipt aggregation design. V1 does
not claim that capacity from a single SX1262 channel.

The evidence artifact records commit SHA, firmware hashes, board identities,
antenna, distance/attenuation, shield/legal basis, exact frequency/channel,
PHY, power, every message/transaction ID, peer/Service, send/Receipt time,
latency, attempt/retry count and final outcome.

Physical RF HIL may run only in a documented RF-shielded/attenuated setup or
with hardware, frequency, power and operator authority that are legal in the
test jurisdiction. The current LAB profile is not a Japan legal profile.
Until that run, physical USB/RF remains `NOT_RUN`; Host simulation and target
build cannot substitute for it. Legal or production support is never inferred
from LAB HIL.

### Machine-readable state

The compatibility feature ID is `v1-functional-lab-vertical-slice`. Its state
is `PROPOSED` while this ADR or either follow-up mapping/framing decision is
Proposed, `SPEC_ACCEPTED` only after all three are Accepted, `HOST_CANDIDATE`
after software items 1..3 pass, `TARGET_CANDIDATE` after item 4 passes, and
`HIL_VERIFIED` only after the three-board run passes. Its state ceiling is
`HIL_VERIFIED`; a LAB result cannot transition to `RELEASE_SUPPORTED`.

README, this feature row and the V1 roadmap must change in the same commit as
any scope/status transition. This ADR is now the V1 completion-scope authority;
ADR-0029/0032 continue to govern their unchanged public ABI and owner contracts.

## Consequences

- The next implementation is one bounded vertical path, not another framework.
- Applications can validate the SDK on real hardware before V2 reliability
  engines are integrated.
- Existing V2 candidates and tests stay available without becoming public ABI.
- V1 remains honest about its LAB, payload, topology and operational limits.
