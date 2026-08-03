# MFDT Host four-slot coordinator implementation plan

Date: 2026-07-30  
Status: **IMPLEMENTATION IN PROGRESS / TERMINAL-REPLAY AMENDMENT ACTIVE / NO COMPLETION CLAIM**  
Authority: ADR-0021 Proposed SPEC-ONLY candidate  
Scope: Host reference profile only. The ESP profile remains one active transfer.

## 2026-07-30 terminal-replay amendment（later authority）

The original four-active plan below led to a working four-slot coordinator, but
its exact 262656-byte owner omitted independent storage for retained-terminal
routing and control responses. It therefore could not replay a terminal NRC1
response after process restart, and it could not own a fresh CAPACITY/BUSY
response while all four active slot arenas were occupied.

ADR-0021 now supersedes every older numeric occurrence in this work record with:

| item | amended exact value / rule |
| --- | --- |
| NM30 canonical writer | schema 2, 180 bytes; peer endpoint at 156, owner role at 172, CRC at 176 |
| legacy NM30 schema 1 | validation/accounting/GC only; cold replay and rebind forbidden |
| terminal row / group | 216 / 15272 logical bytes |
| committed / begin+final Host ceiling | 383564 / 433639 logical bytes |
| ESP active+NRC1+terminal-stage reservation | 50291 logical bytes |
| Host control arena | 17920 bytes outside the four active arenas |
| Host owner | `4 * 65536 + 17920 = 280064` bytes |
| terminal catalog | 16 × 64 bytes |
| independent control ownership | one 1024-byte NCL1 outbox, one 15024-byte NRC1 scratch, one 184-byte NM30 scratch |
| full-four behavior | terminal duplicate and fresh pre-admission CAPACITY/BUSY use the control route; active slots/cursor/store remain unchanged |
| rebind | durable peer/role/NRC1 generation exact + fresh non-zero volatile cookie |

The earlier 262656/164/200/15256/383372/433447/50275 values and any design that
borrows an active slot arena for terminal/control traffic are void. The detailed
older text remains below as implementation provenance; it is not current
authority where it conflicts with this amendment.

## Decision

The Host profile is not implemented by changing one MFDT engine from one active
transfer to four. It is implemented by one caller-owned Host coordinator that
owns four single-transfer slots and shares one durable store transaction
authority.

Implementation may proceed only with the following boundaries:

- the existing single-transfer engine behavior remains green;
- the Host owner is exactly 262656 caller-owned bytes;
- the Host store satisfies the 32-key / 383372-byte committed and
  34-row-image / 433447-byte begin+final limits;
- transfer routing is by exact transfer ID and exact peer/session bind;
- one serialized FULL and one unpaid CHUNK_OFFER per peer are enforced across
  all four slots;
- no new symbol enters the public ABI or installed headers;
- the feature remains private, default-OFF, and makes no ADR acceptance,
  release, or HIL claim.

The work is split into A/B/C ownership below so implementation and independent
acceptance can run in parallel without multiple agents editing the same source
authority.

## Audited authority snapshot

This plan was produced against:

- repository HEAD `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`;
- `docs/adr/0021-multi-frame-durable-custody.md` SHA-256
  `3e41c8ab13faef817b58dd6d7f1072be1746acea7898a4c6904434cb063b5a32`;
- `spec/vectors/multi-frame-durable-transfer-spec-v1.json` SHA-256
  `fdd6fb87101bf9241785e5cbc02e5dbf56f83ab01360da140996f183b4a12b50`.

The worktree was shared and dirty during the audit. The hashes above and the
named tests below are the baseline; this record does not claim ownership of
concurrent edits.

Normative anchors in ADR-0021:

- fixed limits: lines 240-260;
- Host four-slot owner and storage profile: lines 269-310;
- restart and GC: lines 939-980;
- source-only private API: lines 1216-1243;
- non-claims: lines 1406-1422.

## Exact Host profile closure

| Invariant | Exact value / behavior |
| --- | --- |
| active slots | 4 total across sender and receiver directions |
| fresh allocation | lowest free slot in `0..3` |
| existing transfer | exact transfer ID routes to its existing slot |
| fifth distinct active transfer | CAPACITY/BUSY, state mutation 0 |
| restart allocation | unsigned lexicographic transfer ID order into slots `0..3` |
| slot workspace | 65536 bytes, 8-byte aligned |
| owner metadata | 512 bytes = 128-byte header + 4 × 96-byte descriptor |
| aggregate owner RAM | 262656 bytes exact |
| FULL parallelism | one RW FULL across the entire coordinator |
| active group | 50075 logical bytes = active 35019 + NRC1 15056 |
| terminal group | 15256 logical bytes = NM30 200 + NRC1 15056 |
| four maximum active | 200300 logical bytes / 8 keys |
| tracked groups | 16 / 32 committed keys |
| committed hard maximum | 383372 logical bytes |
| one serialized FULL staging | 50075 logical bytes / 2 row images |
| begin+final union | 433447 logical bytes / 34 row images |
| scheduler cursor | cyclic `next_slot`, initial and post-restart value 0 |
| peer fence | at most one unpaid CHUNK_OFFER to the same peer |
| fairness | continuously eligible, unblocked slot selected within 4 successful decisions |

The sealed vector requires four successful distinct admissions to slots
`0,1,2,3`, followed by rejection of the fifth with no mutation. Its restart
input order `4,1,3,2` becomes canonical slot order `1,2,3,4`. Its scheduler
trace is `0,1,2,3,0,1,2,3`; with peer assignment `A,B,A,C`, an unpaid offer to
peer A blocks slots 0 and 2 but does not block slot 1.

## Current implementation audit

### Correct baseline that must be preserved

`src/runtime/mfdt_v1/mfdt_v1_engine.c` now deliberately returns an active
maximum of one for every engine. `host_mode` selects Host storage/replay policy;
it no longer aliases four transfers into the one `mfdt_xfer_t` in a workspace.

`tests/runtime/mfdt_v1/mfdt_v1_e2e_test.c` contains
`test_host_single_engine_rejects_cross_transfer_open`. It proves that a second
transfer presented to one occupied Host-mode engine receives CAPACITY/BUSY,
performs no FULL, leaves the incumbent durable bytes unchanged, and preserves
the incumbent NRC1 replay. This test is a freeze gate, not a coordinator test.

The implementation tranche must retain:

```text
one engine == one active transfer
four Host transfers == four coordinator slots
```

### P0 gaps

1. **No Host coordinator exists.** The current spine, runtime seam, and session
   paths own one engine, one workspace, one store, one pipeline, and one armed
   transfer.
2. **The lab store cannot represent the Host profile.**
   `NINLIL_MFDT_V1_LAB_MAX_ROWS` is 16, although 16 retained groups require 32
   committed keys. Its Host value pool is 65536 bytes, although four maximum
   active groups require 200300 logical bytes.
3. **The current lab FULL can expose a partial final view on capacity failure.**
   `mfdt_v1_store.c` applies staged operations sequentially. If an early
   operation succeeds and a later `apply_put` fails, rollback clears only
   staging metadata; it does not restore the already-applied operation.
4. **The engine is hard-bound to lab-store functions.** The repository already
   exposes generic typed `ninlil_storage_ops_t` operations in
   `include/ninlil/platform.h`, including iteration and capacity, but the Host
   engine does not use that boundary.
5. **Restart is caller-seeded one transfer at a time.**
   `ninlil_mfdt_v1_restart_scan_transfer` requires a known transfer ID and role.
   It cannot discover and validate the full four-prefix namespace before
   installing any slot.
6. **The current Host memory evidence is not the normative aggregate.** The
   footprint gate currently reports:

   ```text
   workspace 65536
   lab_store 116496
   engine 112
   pipeline 2208
   spine_ctx 184480
   engine_scratch 50003
   ```

   The 50003-byte active/NRC1 scratch is process-global on Host and allocated
   lazily on ESP. It is outside the 65536-byte slot workspace and therefore
   cannot be counted as an exact 262656-byte Host owner.

### P1 gaps

1. `unpaid_chunk` is local to one engine. It cannot fence two slots addressed
   to the same peer.
2. The pipeline can recurse from manifest completion directly into
   `SEND_CHUNKS` and emit a CHUNK_OFFER without a coordinator scheduling
   decision.
3. The public storage capacity structure reports only entries and bytes. It
   does not prove atomic FULL, snapshot iteration, serialized staging,
   34-row-image union capacity, or the 433447 logical-byte union.
4. The ESP store adapter and runtime seam use process-global binding and
   transaction state. Those globals are not a reusable Host owner boundary.
5. Current contract RED coverage checks the Host slot-count and workspace
   constants, but it does not execute four-slot allocation, deterministic
   restart, exact Host storage ceilings, or cross-slot fairness.
6. The active durable record contains source/target runtime IDs and session
   generation, but a transport session cookie is not a durable slot field.
   Recovery must not invent a peer/session bind or replay wire bytes before the
   caller re-establishes an authenticated session.

## Minimal private design

### Ownership and memory

Add a source-only private Host owner type. It is opaque to callers but has an
exact compile-time size and alignment:

```c
#define NINLIL_MFDT_V1_HOST_SLOT_COUNT       ((size_t)4u)
#define NINLIL_MFDT_V1_HOST_HEADER_BYTES     ((size_t)128u)
#define NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES  ((size_t)96u)
#define NINLIL_MFDT_V1_HOST_METADATA_BYTES   ((size_t)512u)
#define NINLIL_MFDT_V1_HOST_OWNER_BYTES      ((size_t)262656u)

typedef union ninlil_mfdt_v1_host_owner {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_OWNER_BYTES];
} ninlil_mfdt_v1_host_owner_t;
```

Use fixed-size unions internally so platform padding cannot change the
normative header or descriptor size:

```c
typedef union mfdt_host_header {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_HEADER_BYTES];
    struct {
        struct ninlil_mfdt_v1_store_port *store;
        ninlil_mfdt_v1_config_t base_config;
        uint64_t now_ms;
        uint32_t tracked_groups;
        uint32_t committed_keys;
        uint64_t committed_logical_bytes;
        uint8_t active_count;
        uint8_t next_slot;
        uint8_t full_locked;
        uint8_t started;
        uint8_t recovering;
    } f;
} mfdt_host_header_t;

typedef union mfdt_host_slot_desc {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES];
    struct {
        uint8_t transfer_id[16];
        uint8_t peer_endpoint_id[16];
        uint64_t session_cookie;
        uint32_t session_generation;
        uint32_t fulls_this_transfer;
        uint8_t publication_token[16];
        uint8_t upper_dedupe_token[16];
        uint8_t role;
        uint8_t occupied;
        uint8_t bind_valid;
        uint8_t unpaid_chunk_offer;
        uint8_t publication_ready;
        uint8_t handoff_complete;
        uint8_t upper_dedupe_valid;
        uint8_t reserved0;
        uint64_t reserved1;
    } f;
} mfdt_host_slot_desc_t;
```

The exact field set may be reduced during implementation, but it may not grow
outside the 128/96-byte unions. Durable transfer state remains in the slot
arena and store; the descriptor contains coordinator routing state only.

Each 65536-byte slot arena reserves all current engine and pipeline working
state. One workable fixed layout is:

```c
#define MFDT_HOST_ACTIVE_REGION_BYTES   ((size_t)34984u) /* 34983 + pad */
#define MFDT_HOST_NRC1_REGION_BYTES     ((size_t)15024u) /* 15020 + pad */
#define MFDT_HOST_PIPELINE_REGION_BYTES ((size_t)2304u)  /* current size 2208 */
#define MFDT_HOST_ENGINE_REGION_BYTES   ((size_t)256u)   /* current size 112 */
#define MFDT_HOST_TEMP_REGION_BYTES     ((size_t)12968u)

typedef union mfdt_host_slot_arena {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_WORKSPACE_BYTES];
    struct {
        uint8_t active_record[MFDT_HOST_ACTIVE_REGION_BYTES];
        uint8_t nrc1[MFDT_HOST_NRC1_REGION_BYTES];
        uint8_t pipeline[MFDT_HOST_PIPELINE_REGION_BYTES];
        uint8_t engine[MFDT_HOST_ENGINE_REGION_BYTES];
        uint8_t temporary[MFDT_HOST_TEMP_REGION_BYTES];
    } f;
} mfdt_host_slot_arena_t;

typedef struct mfdt_host_owner_layout {
    mfdt_host_header_t header;
    mfdt_host_slot_desc_t slots[4];
    mfdt_host_slot_arena_t arenas[4];
} mfdt_host_owner_layout_t;
```

The active record becomes the canonical in-place engine image. NRC1, engine
control, pipeline control/outbox, and bounded restart scratch are in the same
arena. This removes the 50003-byte process-global engine scratch and avoids
four additional pipelines or engine structs outside the normative owner.

Required compile-time gates:

```c
_Static_assert(NINLIL_MFDT_V1_HOST_HEADER_BYTES +
                   NINLIL_MFDT_V1_HOST_SLOT_COUNT *
                       NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES ==
                   NINLIL_MFDT_V1_HOST_METADATA_BYTES,
               "Host metadata must be exact 512");
_Static_assert(NINLIL_MFDT_V1_HOST_METADATA_BYTES +
                   NINLIL_MFDT_V1_HOST_SLOT_COUNT *
                       NINLIL_MFDT_V1_WORKSPACE_BYTES ==
                   NINLIL_MFDT_V1_HOST_OWNER_BYTES,
               "Host owner must be exact 262656");
_Static_assert(sizeof(ninlil_mfdt_v1_host_owner_t) == 262656u,
               "Host opaque owner size");
_Static_assert(_Alignof(ninlil_mfdt_v1_host_owner_t) >= 8u,
               "Host opaque owner alignment");
_Static_assert(sizeof(mfdt_host_header_t) == 128u,
               "Host header size");
_Static_assert(sizeof(mfdt_host_slot_desc_t) == 96u,
               "Host descriptor size");
_Static_assert(sizeof(mfdt_host_slot_arena_t) == 65536u,
               "Host slot arena size");
_Static_assert(offsetof(mfdt_host_owner_layout_t, arenas) == 512u,
               "Host arena offset");
_Static_assert(sizeof(mfdt_host_owner_layout_t) == 262656u,
               "Host layout size");
_Static_assert(sizeof(ninlil_mfdt_v1_pipeline_t) <=
                   MFDT_HOST_PIPELINE_REGION_BYTES,
               "Pipeline must fit its slot region");
_Static_assert(sizeof(ninlil_mfdt_v1_engine_t) <=
                   MFDT_HOST_ENGINE_REGION_BYTES,
               "Engine must fit its slot region");
```

No `packed` structs are required. All region starts are 8-byte aligned.

The caller keeps both the owner address and referenced store-port address stable
from `host_owner_init` through shutdown. The private API is single-threaded and
non-reentrant: callers serialize owner calls. `full_locked` additionally
fail-closes accidental nested RW FULL entry with BUSY. This is a concurrency
contract, not permission to maintain four independent transaction locks.

### Private generic store port

Do not add fields to the installed `ninlil_storage_ops_t` ABI. Add a private
MFDT adapter that wraps those typed operations plus explicit Host guarantees:

```c
#define NINLIL_MFDT_V1_STORE_ATOMIC_FULL       ((uint32_t)1u << 0)
#define NINLIL_MFDT_V1_STORE_SNAPSHOT_ITER     ((uint32_t)1u << 1)
#define NINLIL_MFDT_V1_STORE_NO_PARTIAL_VIEW   ((uint32_t)1u << 2)

typedef struct ninlil_mfdt_v1_store_guarantees {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t committed_keys_max;
    uint32_t begin_final_row_images_max;
    uint32_t full_ops_max;
    uint32_t reserved0;
    uint64_t committed_logical_bytes_max;
    uint64_t full_staging_logical_bytes_max;
    uint64_t begin_final_union_logical_bytes_max;
} ninlil_mfdt_v1_store_guarantees_t;

typedef struct ninlil_mfdt_v1_store_port {
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle;
    ninlil_mfdt_v1_store_guarantees_t guarantees;
} ninlil_mfdt_v1_store_port_t;
```

`host_owner_init` rejects a provider unless it guarantees at least:

```text
ATOMIC_FULL | SNAPSHOT_ITER | NO_PARTIAL_VIEW
32 committed keys
383372 committed logical bytes
34 begin+final row images
50075 serialized FULL staging logical bytes
433447 begin+final union logical bytes
4 staged operations (normal profile FULLs use at most two row images; the
existing pre-admission cleanup path may issue four deletes)
```

The coordinator still enforces these exact profile ceilings even when the
provider is larger. Raw backend byte capacity is not used as MFDT logical
capacity. A row's logical charge is its canonical value length plus 36 bytes:
20-byte key plus the normative row overhead. Therefore active, NRC1, and NM30
charges remain 35019, 15056, and 200.

The Host reference in-memory provider must stage operations, build and
capacity-check the complete final key set, and validate duplicate/conflicting
operations before publishing any new view. Failure before the publish point
leaves the old view; success publishes the complete new view. A second-op
capacity failure must never leave the first op visible. A two-bank or immutable
descriptor-table implementation is acceptable; physical provider RAM is
outside the exact owner aggregate and must not be misreported as owner RAM.

The generic adapter maps `ninlil_storage_status_t` to private MFDT errors,
serializes one RW FULL, exposes prefix iteration, and keeps COMMIT_UNKNOWN
classification fail-closed. It must not infer atomic/union guarantees from the
four public capacity integers.

### Exact peer/session bind

Use the authenticated peer endpoint identity already owned by the session
layer. Do not add a peer ID, slot index, or scheduler cursor to MFDT wire or
storage.

```c
typedef struct ninlil_mfdt_v1_host_bind {
    uint8_t peer_endpoint_id[16];
    uint32_t session_generation;
    uint64_t session_cookie;
    uint8_t role; /* sender or receiver in this local slot */
} ninlil_mfdt_v1_host_bind_t;
```

Routing order is mandatory:

1. parse and semantically validate the exact transfer ID;
2. search all occupied descriptors for that exact 16-byte ID;
3. if found, require the same peer endpoint, session generation/cookie, and
   role before calling the slot engine;
4. never send a cross-slot BIND52 response;
5. only a fresh OPEN or local sender-open may allocate;
6. allocate the lowest free slot only after store and owner capacity preflight;
7. unknown non-OPEN input does not allocate.

On cold recovery, source/target IDs and durable session generation are validated
from the active record, but no session cookie is invented. A recovered slot is
installed as bind-pending and cannot replay or emit wire traffic until the
session layer supplies a currently authenticated bind that matches the durable
peer identity and generation. A fresh MFN1 transcript remains the session
layer's responsibility.

### Admission preflight

For a fresh transfer, perform all lookups and preflight before changing a
descriptor or calling an engine:

```text
active_count < 4
tracked_groups < 16
committed_keys + 2 <= 32
committed_logical_bytes + 50075 <= 383372
staged row images <= 2
staged logical bytes <= 50075
committed begin view + staged final images <= 34 row images
committed logical begin view + staged logical bytes <= 433447
provider guarantees a later active-erase + NM30-put terminal FULL
```

The store inventory includes retained terminal groups. Terminal groups do not
consume active slots, but they continue to consume two keys and 15256 logical
bytes until eligible GC. Cached counters change only after a successful FULL
publish; recovery recomputes them from the validated snapshot. If any predicate
fails, local sender-open returns `NINLIL_MFDT_V1_ERR_CAPACITY`; receiver OPEN
returns BUSY with `NINLIL_MFDT_V1_REJ_CAPACITY`, `state_mutation=0`, and
`full_count=0`.

### Private coordinator API proposal

The header lives under `src/runtime/mfdt_v1/` and is never installed:

```c
int ninlil_mfdt_v1_host_owner_init(
    ninlil_mfdt_v1_host_owner_t *owner,
    ninlil_mfdt_v1_store_port_t *store,
    const ninlil_mfdt_v1_config_t *base_config);

int ninlil_mfdt_v1_host_owner_recover(
    ninlil_mfdt_v1_host_owner_t *owner);

int ninlil_mfdt_v1_host_owner_start(
    ninlil_mfdt_v1_host_owner_t *owner);

int ninlil_mfdt_v1_host_rebind_recovered(
    ninlil_mfdt_v1_host_owner_t *owner,
    const uint8_t transfer_id[16],
    const ninlil_mfdt_v1_host_bind_t *bind);

int ninlil_mfdt_v1_host_sender_open_with_metadata(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const uint8_t transfer_id[16],
    const uint8_t *content,
    uint32_t content_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata,
    uint64_t request_id,
    uint8_t *slot_out);

int ninlil_mfdt_v1_host_on_wire(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const ninlil_mfdt_v1_wire_view_t *wire,
    ninlil_mfdt_v1_response_t *response,
    uint8_t *slot_out);

int ninlil_mfdt_v1_host_pump_control(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot);

int ninlil_mfdt_v1_host_schedule_one_chunk(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t *selected_slot_out);

int ninlil_mfdt_v1_host_take_outbound_ncl1(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    uint8_t *out,
    size_t cap,
    size_t *out_len);

int ninlil_mfdt_v1_host_tick(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint64_t now_ms);

int ninlil_mfdt_v1_host_gc(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint64_t now_ms);
```

`host_owner_start` closes startup preparation. Owner/core operations after it
must not call the target allocator or libc allocation. A generic external
storage provider may have its own documented allocation behavior; it is not
silently counted as MFDT owner RAM.

The existing single-engine API remains available for the ESP profile and
single-engine tests. A compatibility initializer may wrap the existing lab
store as a private store port, but the four-slot Host owner must not use the
old 16-row/64-KiB lab store.

### Pipeline scheduling boundary

Split pipeline inspection from CHUNK emission:

```c
typedef enum ninlil_mfdt_v1_pipeline_action {
    NINLIL_MFDT_V1_PIPE_ACTION_NONE = 0,
    NINLIL_MFDT_V1_PIPE_ACTION_CONTROL = 1,
    NINLIL_MFDT_V1_PIPE_ACTION_CHUNK = 2
} ninlil_mfdt_v1_pipeline_action_t;

ninlil_mfdt_v1_pipeline_action_t
ninlil_mfdt_v1_pipeline_next_action(
    const ninlil_mfdt_v1_pipeline_t *pipeline);

int ninlil_mfdt_v1_pipeline_pump_control(
    ninlil_mfdt_v1_pipeline_t *pipeline);

int ninlil_mfdt_v1_pipeline_emit_selected_chunk(
    ninlil_mfdt_v1_pipeline_t *pipeline);
```

Manifest completion may move phase to `SEND_CHUNKS`, but it may not recursively
emit a chunk. Only `host_schedule_one_chunk` may:

1. scan at most four slots from `next_slot`;
2. skip non-eligible slots;
3. skip every slot whose exact peer already has an unpaid offer;
4. verify the selected pipeline outbox can accept the frame;
5. emit exactly one CHUNK_OFFER;
6. only after successful enqueue, mark that peer unpaid and advance
   `next_slot=(i+1)%4`.

A matching CHUNK_ACCEPT clears the peer fence. A terminal reject or timeout
state transition that leaves the outstanding CHUNK wait also clears it. A
retry deadline that merely reissues the same outstanding offer does not clear
it. Wrong transfer ID, peer, session bind, request ID, or chunk index never
clears another slot's fence.

### Restart algorithm

Recovery runs before `host_owner_start`:

1. open one read-only snapshot;
2. iterate all keys under `NM3S`, `NM3R`, `NM30`, and `NRC1`;
3. collect at most 16 transfer-group summaries in temporary arena memory;
4. validate key kind/ID, duplicate active sides, active+NM30 BOTH, missing NRC1,
   NRC1 semantics, active semantics, NM30 semantics, group count, keys, logical
   bytes, and Host ceilings;
5. fail closed on any invalid row, fifth active transfer, seventeenth group,
   33rd committed key, or over-bound byte accounting;
6. sort valid active transfer IDs by unsigned bytewise lexicographic order;
7. read each active record into its future slot arena and re-run semantic
   validation;
8. only after every read and validation succeeds, publish descriptors and
   `active_count`, set every recovered slot bind-pending, and set
   `next_slot=0`.

No descriptor, active count, scheduler cursor, outbox, replay state, or caller
visible success changes before step 8. Failure zeroes the candidate owner and
returns CORRUPT/CAPACITY/STORAGE as appropriate. Recovery never silently evicts
an active transfer; GC operates only on eligible terminal groups.

## Parallel implementation ownership

### Tranche A — private store adapter and exact Host provider

Owns:

- new `src/runtime/mfdt_v1/mfdt_v1_store_port.h`;
- new `src/runtime/mfdt_v1/mfdt_v1_store_port.c`;
- new `src/runtime/mfdt_v1/mfdt_v1_host_store.h`;
- new `src/runtime/mfdt_v1/mfdt_v1_host_store.c`;
- new store-focused unit tests only.

Delivers:

- the frozen private store-port signatures and guarantees structure;
- typed generic `ninlil_storage_ops_t` adapter;
- snapshot prefix iteration;
- one serialized FULL;
- true all-or-nothing preflight/publish/rollback;
- 32 committed keys, 383372 committed logical bytes, 50075 staging,
  34-row-image / 433447 begin+final union;
- no append-only pool leak;
- deterministic capacity, IO, and COMMIT_UNKNOWN injection.

Tranche A does not edit the engine, pipeline, coordinator, CMake authority, or
installed headers. The store-port header freezes before tranche B consumes it.

### Tranche B — exact owner, routing, restart, scheduler

Starts against A's frozen private interface. Owns:

- new `src/runtime/mfdt_v1/mfdt_v1_host_coordinator.h`;
- new `src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c`;
- `src/runtime/mfdt_v1/mfdt_v1.h` and engine implementation changes needed to
  use slot-local scratch/store port;
- pipeline header/implementation changes needed to stop at the CHUNK boundary;
- later, and only after the coordinator core is green, session/spine/runtime
  seam integration.

Delivers:

- exact 262656-byte owner and static assertions;
- four one-transfer engines;
- exact TID/bind routing and lowest-free allocation;
- deterministic all-record restart;
- shared FULL lock;
- per-peer unpaid fence and cyclic fairness;
- no owner/core post-start allocation;
- preservation of the single-engine cross-transfer rejection test.

Tranche B does not edit store implementation or CMake/test registration files.

### Tranche C — independent RED, acceptance, sanitizers, packaging

Owns:

- new coordinator/store acceptance test files;
- dedicated RED-to-GREEN runner and mutation fixtures;
- MFDT CTest/source registration authority;
- ASan/UBSan registration;
- installed/private-boundary and ESP component packaging gates.

Delivers:

- RED witnesses before A/B implementation is linked;
- exact normative acceptance after A/B merge;
- single-engine regression suite unchanged;
- tests-OFF/install consumer with no Host private symbols or headers;
- ESP package keeps the one-slot profile and does not accidentally include the
  262656-byte Host coordinator;
- no release/HIL/spec-accepted claim.

A missing header, missing symbol, or link error is not an accepted behavioral
RED. After A freezes the private header, each RED binary must compile and fail
one or more named runtime/compile-time contract assertions. The runner must
also fail if a RED binary crashes without reporting its named witness.

Tranche C is the sole editor of:

- `cmake/ninlil_mfdt_v1_sources.cmake`;
- `cmake/ninlil_mfdt_v1_ctest.cmake`;
- relevant root CMake registration;
- relevant ESP component source lists;
- the new acceptance tools.

This single-owner rule prevents CMake and packaging merge races.

## RED-to-GREEN acceptance matrix

### Memory and boundary

1. `sizeof(host_owner)==262656`, alignment at least 8, arena offset 512,
   header 128, descriptors 96, slot arena 65536.
2. Four engines and four pipelines fit inside the four arenas; no separate
   Host engine scratch, pipeline array, or descriptor allocation exists.
3. Set an MFDT allocator trap immediately after `host_owner_start`; run
   admission, transfer progress, retry, scheduler, restart/rebind, terminal,
   and GC without an allocation.
4. ASan/UBSan proves no arena overlap, misalignment, use-after-reset, or
   cross-slot write.
5. private-default-OFF and install-boundary tests prove no public/installed
   header or symbol change.

### Allocation and routing

1. Admit four distinct transfer IDs and observe slots `0,1,2,3`.
2. Attempt a fifth distinct ID and receive CAPACITY/BUSY with identical owner
   snapshot, slot bytes, cursor, store digest, and FULL count.
3. Route duplicate same ID/same bind to the same slot.
4. Reject same ID/conflicting peer, generation, cookie, or role with no
   cross-slot BIND52 response and no mutation.
5. Reject unknown non-OPEN without allocating.
6. Complete/free slots 1 and 3, then prove the next fresh OPEN chooses slot 1.
7. Mix sender and receiver slots and prove the combined active maximum is four.
8. Keep `test_host_single_engine_rejects_cross_transfer_open` green.

### Restart

1. Insert valid active transfers in scan order `4,1,3,2`; restart assigns
   canonical order `1,2,3,4` to slots `0,1,2,3`.
2. Prove `next_slot=0` after recovery.
3. Five valid active records fail closed; none is truncated or installed.
4. For each semantic mutant class, place one invalid row among otherwise valid
   groups and prove installed slots, cursor, and wire replay remain zero.
5. Cover active+NM30 BOTH, duplicate active sides, missing NRC1, terminal
   missing NRC1, invalid generation, invalid bitmap, invalid retained terminal,
   17 groups, 33 keys, and each byte ceiling plus one.
6. Recovered slots emit nothing before exact authenticated rebind.

### Store capacity and atomic FULL

1. Commit four maximum active groups: 200300 logical bytes / 8 keys.
2. Commit four active plus twelve terminal groups: 383372 / 32 keys.
3. Reject a seventeenth group with zero mutation.
4. Admit exactly 50075 staging and 433447 begin+final union; reject each at
   `+1`.
5. Force capacity failure on the second staged put and prove neither operation
   is visible.
6. Inject failure before publish and observe exact OLD.
7. Inject success and observe exact NEW.
8. Inject COMMIT_UNKNOWN readbacks for OLD, NEW, PARTIAL, BOTH, EXTRA, THIRD,
   and ABSENT; no mixed class produces external success.
9. Prove the shared FULL lock rejects a second slot while one transaction is
   open and is released after success, rollback, and classified failure.
10. Run the same cold-reopen semantic suite through an in-memory typed provider
    and a durable Host provider such as SQLite.

### Scheduler and peer fence

1. Four continuously eligible slots produce
   `0,1,2,3,0,1,2,3`.
2. With peers `A,B,A,C`, one unpaid offer to A skips slots 0 and 2 and selects
   slot 1.
3. A matching CHUNK_ACCEPT releases A; a wrong peer/TID/request/chunk does not.
4. Terminal reject releases the matching peer fence.
5. Timeout that performs a state transition releases it; simple retransmission
   timeout does not.
6. Every continuously eligible unblocked slot is selected within four
   successful scheduling decisions.
7. Manifest completion cannot emit a CHUNK before the coordinator selects it.
8. One scheduling call emits at most one CHUNK and advances the cursor only
   after successful outbox enqueue.

### Integration and packaging

1. Four Host slots carry actual NCL1 frames through the existing bearer worker,
   including two transfers to the same peer and transfers in both directions.
2. Restart/rebind resumes each transfer without cross-slot responses.
3. Terminal retention consumes store budget but not active slot count.
4. Host tests pass with the private feature ON; normal public tests pass with
   it OFF.
5. ESP-IDF compile/map packaging continues to expose one active transfer and
   contains no Host coordinator owner.
6. Physical power-cut HIL remains NOT_RUN unless separately executed on real
   hardware; software GREEN cannot promote ADR-0021 or CU NEW replay policy.

## Merge and handoff order

1. Freeze and review A's private store-port header and guarantees first.
2. Start A implementation, B coordinator implementation, and C RED fixtures
   under the file ownership above.
3. Merge A and run its atomic/capacity tests.
4. Rebase B onto A's frozen port, merge B core, and run the single-engine freeze
   gate plus coordinator tests.
5. Add session/spine/seam binding only after exact owner/routing/restart/RR is
   green.
6. Let C perform the independent full matrix, sanitizers, private/install
   boundary, and ESP packaging.
7. Update work records honestly: implementation GREEN is not SPEC_ACCEPTED,
   RELEASE_SUPPORTED, or physical HIL evidence.

The Host coordinator is ready for implementation when this plan, A's frozen
store interface, and the RED acceptance suite agree on the exact values above.
It is complete only when every RED category is GREEN and the existing
single-engine suite remains GREEN.
