# Ninlil Runtime

> **Document class:** Informative English overview.
>
> **Normative source:** Japanese specifications and Accepted ADRs under [`docs/`](docs/).
>
> **Translation status:** Synchronized with the Japanese README on 2026-08-12. This file is not a
> normative translation and must not promote compatibility or completion states.

[日本語 README](README.md)

Ninlil Runtime is an embedded communication runtime and C SDK for unreliable, bandwidth-constrained
field networks such as LoRa, Wi-Fi, and USB. It tracks whether application data was received, stored,
and applied instead of treating “sent” as completion.

The portable Core does not contain product-specific vocabulary. It manages communication from bearer,
deadline, destination, required evidence, power, capacity, route, and regulatory constraints.

## Current status

`main` is a **pre-release SDK** with a portable Core, a Host Runtime, and an explicit OSS packaging
boundary.

Available for Host software evaluation:

- Installed public C headers and `Ninlil::runtime` / `Ninlil::fabric_v1` CMake targets.
- Linux/macOS `Ninlil::posix_tls_v1` and `Ninlil::posix_usb_serial_v1` reference ports.
- An optional POSIX SQLite storage port and tests-OFF installed-consumer examples.
- Host software gates for Runtime lifecycle, Fabric forwarding, receipts, retry, and restart behavior.

Not yet proven:

- Production operation, field SLOs, regulatory compliance, or a supported remote release.
- Physical USB/RF, real access-point, flash power-cut, or long-duration HIL acceptance.
- Release-supported public ABIs for the private relay, multi-parent, and multi-frame engines.

The machine-readable state authority is the [compatibility matrix](compatibility-matrix.json).
See the [detailed status ledger](docs/status.md) for evidence and remaining gates. Only
`RELEASE_SUPPORTED` means complete; a Host or target candidate is not physical HIL evidence.

## Focused smoke test

Requirements: Linux or macOS, CMake 3.20 or newer, C11/C++17 compilers, Python 3, Node.js 18 or
newer, OpenSSL 3.x, and SQLite3 development files for this POSIX LAB smoke path.

```bash
git clone https://github.com/Aero123421/Ninlil-Runtime.git
cd Ninlil-Runtime
cmake -S . -B tmp-v1 -DCMAKE_BUILD_TYPE=Debug
cmake --build tmp-v1 --target ninlil_v1_integration_gate_e2e_test --parallel
ctest --test-dir tmp-v1 -R '^v1_integration_gate_e2e$' --output-on-failure
```

This is an entry smoke test, not the full suite and not physical HIL.

## Install and consume

The focused smoke build generates only its requested test target. Use a separate tests-OFF build
for installation:

```bash
cmake -S . -B tmp-install-build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNINLIL_BUILD_TESTS=OFF \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_FABRIC_V1=ON
cmake --build tmp-install-build --parallel
cmake --install tmp-install-build --prefix "$PWD/tmp-install"
```

In a CMake consumer:

```cmake
find_package(Ninlil CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE Ninlil::runtime)
```

The same package can expose `Ninlil::fabric_v1`, `Ninlil::posix_tls_v1`, and
`Ninlil::posix_usb_serial_v1` when they are enabled. See the [Host Runtime SDK](docs/host-runtime-sdk.md)
and [build options](docs/build-options.md) for the supported configuration surface.

## Examples

Start with [`examples/multi_service_node/`](examples/multi_service_node/). It uses only public Ninlil
types to describe four simultaneous Services on one role-neutral node, without product vocabulary.
The current E2E harness is registered under the private Fabric gate.

```bash
cmake -S . -B tmp-generic -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON
cmake --build tmp-generic --target ninlil_runtime_fabric_actual_e2e_test --parallel
ctest --test-dir tmp-generic -R '^multi_service_node_host_actual_e2e$' --output-on-failure
```

The [`examples/v1_lab/`](examples/v1_lab/) programs are historical-label Host simulations for the
private V1 LAB path. They are not generic application templates and do not imply field readiness.

## How it differs from nearby protocols

| Protocol | Ninlil's scope |
| --- | --- |
| MQTT-SN | Ninlil does not replace publish/subscribe; it tracks durable application outcomes and evidence. |
| LoRaWAN | Ninlil does not replace radio networking or join; it manages transactions across available bearers. |
| CoAP | Ninlil does not replace request/response; it owns application transactions across unreliable paths. |
| Zenoh | Ninlil does not replace data-centric pub/sub/query; it focuses on evidence-bearing field transactions. |

## Documentation

- [Documentation index](docs/README.md): reading order and normative-source rules.
- [Current status](docs/status.md): detailed evidence, next gates, and HIL gaps.
- [Host Runtime SDK](docs/host-runtime-sdk.md): build, install, and installed-consumer usage.
- [Build options](docs/build-options.md): all user-facing CMake options and cache variables.
- [SDK distribution manifest](docs/sdk-distribution-manifest.md): install tree and release boundary.
- [Release guide](docs/releasing.md): immutable source identity, SBOM, and attestation flow.
- [Security policy](SECURITY.md): private vulnerability reporting.
- [Contributing](CONTRIBUTING.md): contribution workflow.

## License

Ninlil Runtime is available under the [Apache License 2.0](LICENSE).
