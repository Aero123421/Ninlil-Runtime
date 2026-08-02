# Public Runtime → real Wi-Fi path integration audit

Date: 2026-07-31  
Status: **WPI-1 software path closed; NO-GO for release completion**  
Scope: public Runtime, private Fabric, POSIX TCP/TLS Wi-Fi, ESP adapter

## Outcome

The previously separate Runtime/Fabric and Fabric/Wi-Fi halves are now joined
in one two-process Host acceptance:

`ninlil_submit()` → Runtime scheduler → private Fabric → POSIX Wi-Fi adapter →
real TCP/TLS → peer Runtime → application callback exactly once → reverse
Receipt → originating Runtime target-local `SATISFIED/VERIFIED`.

The joined path passes normal and ASan/UBSan builds and also passes with the
exact static OpenSSL 3.5.7 authority profile.  The executable starts at the
installed public Runtime function signatures, but the Fabric/Wi-Fi composition
is still private/default-OFF test/tool code.  It therefore closes WPI-1 as a
software-path proof, not as an installed Wi-Fi module/package or release
support claim.

WPI-2 through WPI-4 remain open.  In particular, the existing private
10,000-frame run does not yet equal 10,000 public Runtime transactions, and no
physical ESP/AP execution evidence exists.

## Evidence boundary

`tests/host/runtime_fabric_actual_e2e_test.c` starts at the public API and
reaches a real peer Runtime, but uses its local deterministic `pair_link`
implementation rather than the Wi-Fi adapter.

`tests/transport/wifi_v1/wifi_v1_actual_adapter_fabric_e2e_test.c` uses the
production private Fabric and Wi-Fi adapter, but constructs
`ninlil_bearer_message_t`, permit, policy and authority directly.  It does not
call `ninlil_submit()`, run a peer public Runtime, deliver an application
callback, or return a public Receipt.

`tools/wifi_v1_runtime_host_e2e.c` is the joined acceptance owner.  Both roles
create a public Runtime and register the same generic Service.  The client
submits through `ninlil_submit()`; the server callback validates the payload
and returns `VERIFIED`; only the reverse Receipt can satisfy the client query.
The helper never calls the Fabric bearer send API directly and never
synthesizes a Receipt.

`tools/wifi_v1_host_e2e_driver.c` still owns the TLS/session process lifecycle.
`tools/wifi_v1_run_host_e2e.sh` requires exact client and server tokens, so a
missing callback, missing Receipt, duplicate callback, timeout, or one-sided
success cannot soft-pass.

The ESP adapter E2E and pinned compile/link/map evidence use Host fakes or
target build artifacts.  They are not execution through a physical access
point and do not establish HIL.

## Required close

### WPI-1 — joined Host public E2E — CLOSED for software path

The two-process Host acceptance now proves:

- each process creates a Runtime and registers a generic Service;
- the controller calls `ninlil_submit()`;
- Fabric selects the POSIX TCP/TLS Wi-Fi instance;
- the peer Runtime invokes the application callback exactly once;
- the peer returns the required Receipt through the same authenticated path;
- the controller public query reaches target-local `SATISFIED/VERIFIED`.

It uses the actual socket path and has passed the pinned TLS profile.  Public
Wi-Fi module/package installation remains a separate release gate.

### Verification performed on 2026-07-31

- normal focused joined path: client/server exit `0`, exact client/server
  completion tokens present;
- normal registered `wifi_v1_host_e2e`: PASS, 8.54 s;
- ASan/UBSan registered `wifi_v1_host_e2e`: PASS, 10.69 s;
- exact static OpenSSL 3.5.7 authority registered `wifi_v1_host_e2e`: PASS,
  12.55 s with `NINLIL_WIFI_REQUIRE_AUTHORITY=1`;
- strict OpenSSL provenance gate:
  `authority_claim_allowed=true`, `provenance_status=OK`, no dynamic
  SSL/Crypto, exact static archives and source SHA-256.

### WPI-2 — fault and durability matrix

The joined test must cover:

- partial read/write and backpressure;
- disconnect before send acceptance, after transport acceptance, and before
  Receipt;
- duplicate, reordered reconnect input, stale session and wrong peer;
- sender and receiver cold restart;
- durable permit replay rejection;
- service callback exactly-once behavior;
- target-local retry/outcome/evidence after restart;
- 10,000 ordered public transactions without bypassing Runtime admission,
  quota, dedupe or storage.

### WPI-3 — multi-instance composition

Run at least two Wi-Fi link instances and another bearer in one Fabric:

- selection follows policy and stable instance identity;
- one link failure does not mutate the other instance;
- callbacks, storage realms, credentials and driver ownership do not cross;
- hot drain/unregister preserves in-flight transaction semantics.

### WPI-4 — ESP target and physical HIL

Target completion additionally requires:

- direct ESP mbedTLS client/server composition on the accepted raw adapter;
- target-executed Runtime → Fabric → Wi-Fi → peer path;
- real AP association, forced disconnect, reconnect, sleep/wake and peer
  restart;
- heap/pool/stack/watchdog watermark artifacts;
- flash power-cut recovery and a 24-hour soak.

Compile/link/map or Host fake execution remains `TARGET_CANDIDATE` evidence,
not physical HIL.  Until WPI-2 through WPI-4 and public module/package gates
pass, the Wi-Fi feature remains Proposed/private and must not be represented
as `RELEASE_SUPPORTED`.
