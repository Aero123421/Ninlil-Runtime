# V1-LAB POSIX platform provider matrix (unit 3)

作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`  
正本 catalog: `include/ninlil/platform.h` `ninlil_platform_ops_t`（8 slots）  
統合 factory: `ports/posix/include/ninlil_posix_lab_platform.h`  
検証: `tests/port/v1_posix_provider_conformance_test.c` / `tests/runtime/v1_posix_platform_restart_e2e_test.c`

凡例:

| Status | 意味 |
| --- | --- |
| **implemented** | POSIX LAB factory + conformance + Runtime 接続済み |
| **V2** | V1 スコープ外 |

## Matrix（`ninlil_platform_ops_t`）

| Provider | Status | Factory / init | Ownership | Shutdown | Restart | Fault / negative test | Target link |
| --- | --- | --- | --- | --- | --- | --- | --- |
| allocator | **implemented** | `ninlil_posix_lab_platform_create`（内部 `ninlil_test_allocator_create`） | platform 所有 | `destroy` 逆順 | `ninlil_posix_lab_platform_restart` | `v1_posix_provider_conformance` fail_next | host CTest |
| execution | **implemented** | 同上 | platform 所有 | 同上 | 同上 | context_id==0 → `runtime_create` reject（model gate） | host CTest |
| clock | **implemented** | 同上 | platform 所有 | 同上 | 同上 | `v1_posix_provider_conformance` script TEMPORARY | host CTest |
| entropy | **implemented** | 同上 | platform 所有 | 同上 | 同上 | `v1_posix_provider_conformance` script PERMANENT | host CTest |
| storage | **implemented** | `ninlil_posix_sqlite_storage_create`（platform 内包） | platform 所有 | 同上 | 同一 DB path で recreate | `posix_sqlite_storage` + `v1_posix_sqlite_restart_e2e` | host CTest |
| bearer | **implemented** | `ninlil_test_bearer_create`（platform 内包） | platform 所有 | 同上 | 同上 | `v1_posix_provider_conformance` raw UNAVAILABLE | host CTest |
| tx_gate | **implemented** | bearer 内 `tx_gate_ops` | platform 所有 | 同上 | 同上 | bearer conformance 経由 | host CTest |
| origin_authorization | **implemented** | `ninlil_test_origin_auth_create` | platform 所有 | 同上 | 同上 | `v1_posix_provider_conformance` evaluate | host CTest |

## Runtime 接続（項目 2 body）

| 経路 | 実装 |
| --- | --- |
| create | `ninlil_runtime_create(config, ninlil_posix_lab_platform_ops(p), &rt)` |
| destroy | `ninlil_runtime_destroy` → `rt_close_ports`（bearer close → storage close） |
| platform shutdown | `ninlil_posix_lab_platform_destroy`（全 provider 逆順解放） |
| restart E2E | `v1_posix_platform_restart_e2e`: create→step→destroy→platform restart→re-create |
