# POSIX LAB platform provider set (V1-LAB unit 3)

Factory: `ninlil_posix_lab_platform_create` / `destroy` / `restart`  
Header: `ports/posix/include/ninlil_posix_lab_platform.h`

Composes all eight `ninlil_platform_ops_t` slots for host LAB:

| Provider | Implementation | Notes |
| --- | --- | --- |
| allocator | `platform_basic_fixtures` (promoted) | malloc-backed; fault inject via test accessor |
| execution | `platform_basic_fixtures` | caller-owned context id |
| clock | `platform_basic_fixtures` | simulated trusted clock |
| entropy | `deterministic_entropy` | seeded LAB stream |
| storage | `ninlil_posix_sqlite_storage` | durable POSIX SQLite (unit 1b) |
| bearer | `typed_simulated_bearer` | LAB loopback simulation |
| tx_gate | `typed_simulated_bearer` | paired with bearer |
| origin_authorization | `canonical_origin_authorization` | LAB policy evaluate |

Runtime wiring: pass `ninlil_posix_lab_platform_ops()` to `ninlil_runtime_create`.
`ninlil_runtime_destroy` closes bearer/storage handles; platform `destroy`/`restart`
tears down providers in reverse order (bearer → storage → origin → entropy → clock
→ execution → allocator).

Conformance: `tests/port/v1_posix_provider_conformance_test.c`  
Restart E2E: `tests/runtime/v1_posix_platform_restart_e2e_test.c`
