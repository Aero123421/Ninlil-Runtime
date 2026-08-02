# ADR-0035: V1 compact radio ApplicationData mapping

- Status: Proposed
- Date: 2026-08-03
- Scope: ADR-0034 single-hop LAB radio path
- Depends on: ADR-0010, ADR-0012, ADR-0013, ADR-0025, ADR-0033,
  ADR-0034
- Keeps: all installed Runtime, Fabric, Composition, wire and storage ABI

## Context

The Fabric logical envelope (`NFL1`) has a 584-byte header. An NRW1 SINGLE
frame can carry at most 190 application-plaintext bytes, so serializing NFL1
verbatim cannot work on SX1262. V1 needs a small, exact projection for 1..128
bytes of product-neutral ApplicationData and an authenticated Receipt without
adding fragmentation, relay or another public transport framework.

The ESP32-S3 also needs entropy after the external SX1262 starts. The existing
ESP entropy adapter owns `bootloader_random_enable()` and is intentionally an
early-boot one-shot. ESP-IDF 5.5.3 requires that source to be disabled before
the ESP RF/ADC subsystems start, and an external SX1262 does not itself enable
the ESP Wi-Fi/Bluetooth entropy source. Keeping that adapter live, or using
unqualified `esp_fill_random()` after shutdown, would therefore be an invalid
composition.

## Decision

### 1. Private boundary only

`NRA1` (Ninlil Radio Application projection version 1) is an encrypted NRW1
SINGLE application body. It is private to the ESP radio packet-link and adds
no installed header, public symbol, CMake target, role, plugin system or
generic transport manager.

The mapping adapter is the only owner allowed to translate between a complete
Fabric message and NRA1. The pure NRA1 codec only packs and parses bytes; it
does not perform identity lookup, authorization, crypto, replay admission,
durability, dispatch or RF transmission.

Only these Fabric kinds are supported by V1:

| Fabric kind | NRA1 kind | V1 result |
| --- | ---: | --- |
| `APPLICATION` | 1 | supported |
| `RECEIPT` | 2 | supported |
| disposition, cancel request/result, custody accepted | — | unsupported; RF TX calls exactly zero |

MFDT, NRW1 START/CONT/FRAG_ACK, relay tuples and Receipt evidence bytes are V2.

### 2. Exact byte layouts

All integers are unsigned big-endian. The four magic bytes are ASCII `NRA1`.
There is no independent minor-version field; changing a byte meaning requires
a new magic.

#### Application body (63..190 bytes)

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 4 | magic `NRA1` |
| 4 | 1 | kind `1` |
| 5 | 1 | service slot in bits 7..3; required-evidence stage in bits 2..0 |
| 6 | 16 | transaction ID |
| 22 | 16 | attempt ID |
| 38 | 16 | family-specific subject |
| 54 | 8 | absolute effect deadline in milliseconds |
| 62 | 1..128 | exact ApplicationData payload; length comes from the authenticated NRW1 body length |

The service slot is 1..31. Required evidence uses the existing exact values
0..4; the V1 functional HIL submissions use `APPLIED=3`. Values 5..7 are
rejected. Transaction and attempt IDs must be non-zero.

The bound Service fixes the family before semantic admission:

- EventFact: subject is the exact non-zero event ID; generation is zero; the
  encoded deadline is `NINLIL_NO_DEADLINE`.
- DesiredState: subject bytes 0..7 are zero and bytes 8..15 are the non-zero
  generation; event ID is zero; the encoded deadline is finite and non-zero.

The codec preserves the 16-byte subject and deadline without guessing the
family. The mapping adapter performs the family-specific checks after resolving
the service slot and before Fabric delivery.

#### Receipt body (46 bytes)

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 4 | magic `NRA1` |
| 4 | 1 | kind `2` |
| 5 | 1 | service slot in bits 7..3; Receipt stage in bits 2..0 |
| 6 | 16 | transaction ID |
| 22 | 16 | attempt ID |
| 38 | 8 | evidence time in milliseconds |

Receipt stage is 1..4. Transaction and attempt IDs must be non-zero. NRA1 V1
Receipt evidence is empty. Timestamp zero remains a valid first instant; its
non-zero clock epoch and trust are supplied by the authenticated binding.

### 3. Lossless off-wire binding

Each LAB peer pair has one non-zero, monotonically replaced
`pair_binding_generation`. It owns one immutable service directory and two
directional child contexts (A-to-B and B-to-A). Each child has its own Hop/E2E
context IDs, keys and counters, but neither direction has an independent slot
namespace or generation. Within the pair generation, service slot 1..31
resolves to one immutable directory row. The row and pair binding together
retain every Foundation field omitted from NRA1:

- the complete source Party, including Runtime/Application IDs and local
  device, installation, site, binding/membership epochs and flags;
- the complete concrete target, including every optional identity, epoch and
  flag;
- complete Service identity, `service_identity_digest`, descriptor revision
  and digest, schema, family, direction and Fabric traffic class;
- deadline clock epoch and evidence grace;
- evidence clock epoch and trust;
- the closed Fabric authority tuple (`authority_id`, `authority_term`,
  `assignment_epoch`) and complete route policy/path selection snapshot;
- the path-policy candidate rank and the Foundation semantic priority. The
  latter is not caller-selected: EventFact is exactly 3 and DesiredState is
  exactly 8, matching `ninlil_rt_v1_semantic_priority_for_family()`; and
- attachment-binding digest, pair/key generation, and both directional Hop
  and E2E context IDs.

The directory is provisioned through the trusted-local USB path and committed
with the keys before it becomes active. ADR-0036 owns the exact byte layout of
the provisioned `binding_payload`; those exact bytes are stored without
re-encoding. Its Hop attachment identity is `SHA-256(binding_payload)`. Fabric
`attachment_binding_digest` and the E2E security identity use ADR-0036's
separate logical projection, which excludes Hop context material and every
secret. Both values are passed through the existing directional R7 binding
digest functions; one digest is never reused across layers. Thus a different
directory, endpoint, priority or authority snapshot cannot decrypt as the
current binding, while Hop-only material cannot change the E2E identity. The
RF adapter remains disabled until ADR-0036 freezes and tests those bytes. There
is no RF slot negotiation and no compiled default row or key. Reprovisioning
replaces all Hop/E2E children together; a stale or wrong binding cannot be
accepted by filling missing fields from current local state.

V1 uses only fresh N6 LAB contexts. After restart, stored binding bytes recover
generation/membership floors but never reactivate keys. A strictly newer
binding resets the dedicated N6 namespace before installing new receiver-owned
allocation namespaces and secrets through ADR-0036's accepted LAB token. N6
then provides every durable TX burn and RX replay admission used by R7. This
prevents key/counter reset without implementing or claiming M5 same-context
resume.

On Application encode, the adapter checks the full Fabric message against the
selected immutable row, computes SHA-256 over the exact payload, and requires
that result to equal the Fabric content digest. On decode it recomputes the
same digest, reconstructs the complete message from the authenticated row and
NRA1 fields, then submits that complete message to Fabric. It never zero-fills
an unknown field or chooses a Service by payload contents.

For a Receipt, the sender must retain the complete outbound correlation before
RF transmission. The lookup key is pair binding generation, original forward
direction, service slot, transaction ID and attempt ID. The authenticated
reverse child context determines the receive direction; the original forward
direction is exactly its opposite, and the slot is resolved in that original
forward directory namespace. A reverse child cannot remap a slot or select a
different generation. The adapter reconstructs all echoed Foundation fields
from that exact durable message and adds the received stage/time. An unknown,
stale, mismatched or already-terminal correlation is rejected and cannot
produce Application success.

### 4. NRW1 and physical path

The complete NRA1 body is passed unchanged as the `app` argument of
`ninlil_r7_frag_prod_tx_single()`. Receive decoding occurs only after
`ninlil_r7_frag_prod_rx_outer()` has authenticated and replay-admitted both
NRW1 layers.

For every V1 Application and Receipt:

- `ack_requested=0`;
- the direct/local outer route tuple is handle 0, generation 0 and remaining
  hops 0;
- directional Hop/E2E context IDs and durable counter/replay state come only
  from the active V1 binding owner and existing N6 engine; and
- every transmit uses the existing R1/R2/R5/R9 permit and physical sole edge.

An NRA1 parse result alone is never authenticated and never authorizes RF TX,
Service dispatch, Receipt application or a counter mutation.

### 5. RF-safe entropy lifecycle

The combined ESP image uses one phase-separated, owner-confined CTR-DRBG:

1. before USB/radio/ADC/Wi-Fi initialization, acquire the existing
   bootloader-RNG adapter and seed the DRBG through its `ninlil_entropy_ops_t`;
2. the seed operation is the only permitted call from the DRBG to that source;
3. retire the bootloader-RNG adapter completely, then initialize SX1262 and
   other peripherals;
4. create Composition with the seeded DRBG's immutable entropy operations;
5. seed from one exact 64-byte boot-source draw; mbedTLS must consume exactly
   48 of those bytes during `mbedtls_ctr_drbg_seed`, with prediction resistance
   disabled;
6. serve only task-owner draws of 1..64 bytes, with at most 1,000,000
   successful draw calls per boot. The mbedTLS reseed interval is `INT_MAX`,
   which is strictly greater than that application cap, so an automatic reseed
   cannot reach the retired callback; ISR and concurrent-owner use are
   forbidden; and
7. if initialization, a draw, the configured request budget, or the DRBG
   invariant fails, return permanent entropy failure and transmit nothing.

The 1,000,001st non-empty draw fails before calling mbedTLS and permanently
retires the DRBG. Zero-length calls are no-ops and do not consume the budget.
That no-op applies only while the provider is live and called by its owner;
after retirement or from a wrong context, a zero-length call also fails closed.
Any unexpected seed-consumption length fails initialization and zeroizes the
whole object. A post-publication mbedTLS draw failure immediately frees and
zeroizes the cryptographic context and marks the provider retired. Its
immutable operations table remains callable only so every later Runtime draw
fails closed instead of dereferencing a cleared callback; `close` then
zeroizes the whole object. There is no fallback entropy or reseed path.

The implementation uses ESP-IDF 5.5.3's bundled mbedTLS CTR-DRBG and zeroizes
its state on close. It retains no callable pointer to a live bootloader entropy
source after startup. A future Wi-Fi composition may replace this contract in
a separate ADR; it does not silently change NRA1.

### 6. Airtime and deterministic V1 schedule

NRW1 SINGLE adds exactly 65 bytes around its application body. The repository
R3 oracle, with SF7, BW 125 kHz, CR 4/5, explicit header, radio CRC enabled,
LDRO off and preamble 8, gives:

| Case | NRA1 body | NRW1 frame | Airtime |
| --- | ---: | ---: | ---: |
| 1-byte ApplicationData | 63 | 128 | 215,296 us |
| 32-byte HIL ApplicationData | 94 | 159 | 256,256 us |
| 128-byte ApplicationData | 190 | 255 | 399,616 us |
| Receipt | 46 | 111 | 189,696 us |

The worst-case nominal request-plus-Receipt pair is 589,312 us. Ten pairs use
5,893,120 us in a 10-second window and satisfy ADR-0034's 6-second limit. The
physical HIL uses the 32-byte case: ten nominal pairs use 4,459,520 us. LBT,
turn-around and retries are not counted as successful nominal airtime and must
stay within the remaining window and existing permit ceilings.

### 7. Failure atomicity

Encode validates the complete input and output capacity before writing any
output byte. Decode publishes output only after complete structural checking.
On failure, caller output bytes/objects and reported length remain unchanged.
Input/output overlap is rejected. There is no heap allocation and no VLA.

## Acceptance

Before this ADR becomes Accepted:

1. byte-exact C KATs cover 1-byte and 128-byte ApplicationData and Receipt;
2. negative tests cover payload 0/129, bad magic/kind/slot/stage, zero IDs,
   wrong fixed length, invalid EventFact/DesiredState projection, aliasing and
   output atomicity;
3. an independent R3 gate recomputes all table values and the 10-pair bound;
4. Host integration covers wrong binding, wrong Service, duplicate/replay,
   tamper, unknown Receipt correlation, timeout and restart with mandatory
   fresh reprovisioning; and
5. the private ESP adapter and phase-separated DRBG compile/link in the pinned
   ESP-IDF 5.5.3 image before the V1 feature may advance beyond
   `SPEC_ACCEPTED`.

Physical RF evidence remains `NOT_RUN` until ADR-0034's three-board procedure
is actually executed.

## Consequences

- The V1 radio path gains one small private body format instead of sending the
  large logical envelope or introducing fragmentation.
- Full identity and Service meaning stay in a durable authenticated binding;
  the wire carries only the fields that vary per message.
- The 128-byte limit fits the existing NRW1 SINGLE ceiling with a measured
  scheduling margin.
- V2 can add fragmentation, relay, multiple parents or Production Attachment
  without changing the installed V1 Runtime/Composition ABI.

## Non-goals

- Automated Join, production identity attachment or key rotation.
- Payloads above 128 bytes, Receipt evidence, dispositions or cancellation.
- Relay, multi-hop, multi-parent, multi-channel scheduling or aggregation.
- Japan legal/field support, physical HIL or production readiness.
