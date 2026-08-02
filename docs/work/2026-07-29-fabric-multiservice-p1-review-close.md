# Fabric and multi-Service P1 review close

Date: 2026-07-29  
Status: **SOURCE FROZEN / HOST + ESP32-S3 TARGET SOFTWARE PASS /
PHYSICAL HIL NOT_RUN**

## Scope

This tranche closes the independent review findings around Fabric deadline
projection, checked time arithmetic, exact Service identity, exact transaction
observation, and the one-node/multiple-Service acceptance.

The shared application example remains outside Portable Core:

- `examples/multi_service_node/multi_service_node_profile.h`
- `examples/multi_service_node/multi_service_node_profile.c`

It uses only Ninlil public types, contains no product-specific vocabulary, and
does not extend the installed Core ABI.

## Closed findings

1. **Retry-cap checked addition before side effects.** A new Fabric attempt
   computes `now + retry_lifetime_ms` with checked addition before route
   notification, RAM reservation, durable PREPARED state, permit consumption,
   or provider I/O. Overflow returns `WOULD_BLOCK`. The mutation fixture proves
   zero storage/provider side effects and proves that the same permit remains
   usable after the clock returns to a representable range.
2. **Retention checked addition before mutation.** Dispatch-release and
   trigger-release retention deadlines use checked addition. Trigger overflow
   returns `PRIVATE_CAPACITY` before terminal revision, durable mutation, or
   provider work; the same terminal revision succeeds after the clock is
   restored.
3. **Family-specific deadline validity.** DesiredState requires a finite
   deadline and non-zero deadline epoch. EventFact requires `NO_DEADLINE` and
   an all-zero wire deadline epoch. Malformed combinations return `CORRUPT`
   before side effects. A valid EventFact retains zero on the wire while the
   private retry lifetime uses the trusted attempt-admission epoch.
4. **Exact complete Service identity.** Callback routing, transaction query,
   and transaction list compare namespace, service ID, schema ID, descriptor
   revision and digest, schema version, and family. A same-service-ID collision
   fixture changes namespace, schema, and digest and must defer; a
   service-ID-only mutation would fail this fixture.
5. **Exact five-transaction observation.** The Host acceptance joins the exact
   transaction IDs to complete Service identities and requires exact terminal
   `SATISFIED / REQUIRED_EVIDENCE_MET` outcomes and evidence. Controller list
   is exactly two transactions and Endpoint list exactly three, with no extra
   row accepted.
6. **Feature-on false-green prevention.** While Domain Schema1 public Runtime
   readiness is false, both `runtime_fabric_actual_e2e` and its
   `multi_service_node_host_actual_e2e` alias are explicitly disabled.
7. **One physical-node, multiple-Service profile.** One role-neutral manifest
   declares four simultaneous Services: two receive and two originate
   capabilities. The shared state machine covers display receipt, access event
   origin, periodic temperature origin, query receipt, pending response,
   failed-admission restoration, and accepted response completion. Host and
   ESP32-S3 compile the same source module.

## Fresh Host evidence

Normal configure/build:

```sh
cmake -S . -B build/fabric-multiservice-p1-normal-20260729a -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON \
  -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON \
  -DNINLIL_ENABLE_SANITIZERS=OFF
cmake --build build/fabric-multiservice-p1-normal-20260729a \
  --target ninlil_fabric_v1_host_acceptance_test \
  ninlil_fabric_v1_lifecycle_test \
  ninlil_runtime_fabric_actual_e2e_test -j4
ctest --test-dir build/fabric-multiservice-p1-normal-20260729a \
  --output-on-failure \
  -R '^(fabric_v1_host_acceptance|fabric_v1_lifecycle|runtime_fabric_actual_e2e|multi_service_node_host_actual_e2e)$'
```

Result: **4/4 PASS**.

Sanitizer configure uses the same command with
`build/fabric-multiservice-p1-asan-20260729a` and
`-DNINLIL_ENABLE_SANITIZERS=ON`. Execution:

```sh
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build/fabric-multiservice-p1-asan-20260729a \
  --output-on-failure \
  -R '^(fabric_v1_host_acceptance|fabric_v1_lifecycle|runtime_fabric_actual_e2e|multi_service_node_host_actual_e2e)$'
```

Result: **4/4 PASS**. Leak detection is disabled on macOS; ASan and UBSan
remain fail-fast.

Complete direct Fabric matrix:

```sh
tools/run_fabric_v1_direct_tests.sh
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
tools/run_fabric_v1_direct_tests.sh --asan
```

Result: **9/9 normal PASS and 9/9 ASan/UBSan PASS**.

## Domain feature-on inventory

```sh
cmake -S . -B build/fabric-multiservice-p1-domain-on-20260729a \
  -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON \
  -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON \
  -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON
cmake --build build/fabric-multiservice-p1-domain-on-20260729a \
  --target ninlil_runtime_fabric_actual_e2e_test -j4
ctest --test-dir build/fabric-multiservice-p1-domain-on-20260729a \
  -N -V \
  -R '^(runtime_fabric_actual_e2e|multi_service_node_host_actual_e2e)$'
```

Result: both named tests are present and **Disabled**.

## ESP32-S3 target software evidence

The local Apple Silicon evidence used ESP-IDF **v5.5.3** and the pinned native
arm64 image
`sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1`.

```sh
docker run --rm -i --platform linux/arm64 --user 0:0 \
  -v "$PWD:/project" -w /project \
  -e CCACHE_DISABLE=1 -e IDF_CCACHE_ENABLE=0 \
  'docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1' \
  bash -lc '. "${IDF_PATH}/export.sh" >/dev/null &&
    idf.py --version &&
    idf.py -C ports/esp-idf/smoke_app \
      -B /project/build/fabric-multiservice-p1-esp-20260729a \
      -D SDKCONFIG=/project/build/fabric-multiservice-p1-esp-20260729a/sdkconfig \
      -D SDKCONFIG_DEFAULTS=/project/ports/esp-idf/smoke_app/sdkconfig.defaults \
      set-target esp32s3 build'
```

Result:

- ESP-IDF identity: **v5.5.3**
- target: **ESP32-S3**
- final ELF: `ninlil_m3_combined_smoke.elf` — **PASS**
- application binary: `0x4b0e0`, smallest partition `0x180000`, 80% free
- final ELF contains
  `ninlil_multi_service_node_profile_init`,
  `ninlil_multi_service_node_profile_validate`,
  `ninlil_multi_service_node_temperature_response_begin`, and
  `ninlil_multi_service_node_acceptance_complete`

`app_main` calls the shared target smoke, but this tranche did not flash or
execute a physical board. ESP target compile/link is **PASS**; physical
ESP32-S3 E2E, RF, and HIL remain **NOT_RUN** and must not be inferred from this
record.
