# Build options

> **Document class: Informative user reference.** `CMakeLists.txt` and
> `cmake/ninlil_posix_sqlite_sqlite3.cmake` are the executable source of truth for defaults,
> validation, and target wiring. This table is checked against that 23-entry user-facing surface.
>
> **Translation status:** English original, synchronized 2026-08-12. No Japanese translation is
> maintained; the Japanese [`README.md`](../README.md) links to this reference.

Boolean values are set with `-DNAME=ON` or `-DNAME=OFF`. “top-level” means Ninlil is configured as
the root CMake project; an `add_subdirectory` consumer receives the documented subproject defaults.

| Option / cache variable | Type | Default | Purpose | Constraints and interactions |
| --- | --- | --- | --- | --- |
| `NINLIL_BUILD_TESTS` | BOOL | top-level `ON`; subproject `OFF` | Build CTest gates, private test fixtures, and test examples. | Enabling the suite requires Python 3 and Node.js 18 or newer; individual Host features add their own dependencies. |
| `NINLIL_BUILD_DECODER_FUZZERS` | BOOL | `OFF` | Build six private decoder-boundary libFuzzer executables. | Requires `NINLIL_BUILD_TESTS=ON`, `NINLIL_ENABLE_SANITIZERS=ON`, private R7 FRAG `ON`, and a Clang toolchain that passes an actual `-fsanitize=fuzzer` compile/link probe. A fuzzers-ON/tests-OFF configure or a Clang installation without the runtime is a fatal error. Targets are `EXCLUDE_FROM_ALL`, non-installed, and outside ordinary CTest. |
| `NINLIL_ABI_GOLDEN_ALLOW_MISSING` | BOOL | `OFF` | Allow the ABI golden test to skip a target tuple that has no committed golden manifest. | Maintenance/cross-environment escape hatch only. Enable explicitly only when that environment cannot generate a supported golden; normal development, CI, and release builds must keep it `OFF` and fail closed. |
| `NINLIL_ENABLE_STRICT_WARNINGS` | BOOL | top-level `ON`; subproject `OFF` | Treat supported compiler warnings as errors on Ninlil targets. | Applies through the repository's target helper; it does not change a consumer's unrelated targets. |
| `NINLIL_BUILD_HOST_RUNTIME` | BOOL | top-level `ON`; subproject `OFF` | Build and install the static `Ninlil::runtime` Host SDK target. | Requires the OpenSSL Host crypto adapter; discovered OpenSSL must have major version exactly 3. |
| `NINLIL_BUILD_FABRIC_V1` | BOOL | follows `NINLIL_BUILD_HOST_RUNTIME` | Build and install experimental portable `Ninlil::fabric_v1`. | Required by the public POSIX TLS port; when present, the Host Runtime also includes Composition v1 sources. |
| `NINLIL_BUILD_POSIX_TLS_V1` | BOOL | follows `NINLIL_BUILD_FABRIC_V1` | Build and install experimental Linux/macOS `Ninlil::posix_tls_v1`. | Linux/macOS only; requires `NINLIL_BUILD_FABRIC_V1=ON`, Threads, and OpenSSL `>=3,<4`. |
| `NINLIL_BUILD_POSIX_USB_SERIAL_V1` | BOOL | top-level Linux/macOS `ON`; otherwise `OFF` | Build and install experimental `Ninlil::posix_usb_serial_v1`. | Linux/macOS only; other platforms fail at configure time when explicitly enabled. |
| `NINLIL_BUILD_V1_LAB_CONTROLLER` | BOOL | `OFF` | Build the private Linux/macOS V1 USB Controller diagnostic. | Requires Linux/macOS, Domain schema1 binding `OFF`, and available Host Runtime, Fabric, POSIX SQLite, and POSIX USB targets. |
| `NINLIL_BUILD_POSIX_SQLITE_STORAGE` | BOOL | `ON` | Build the POSIX SQLite storage port when SQLite3 is available. | With `AUTO`, missing SQLite skips only this port. Explicit `STATIC` or `SHARED` selection fails when that library kind is unavailable. |
| `NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING` | BOOL | `OFF` | Enable the private ADR-0022 Domain schema1 format-2 Runtime binding slice. | Mutually incompatible with the V1 LAB Controller diagnostic; this remains a private candidate. |
| `NINLIL_ENABLE_PRIVATE_FABRIC_V1` | BOOL | `OFF` | Enable the private ADR-0017 Fabric/NFL1 source candidate. | Non-installed private target; separate from the public `NINLIL_BUILD_FABRIC_V1` package option. |
| `NINLIL_ENABLE_PRIVATE_WIFI_V1` | BOOL | `OFF` | Enable the private ADR-0018 POSIX/ESP Wi-Fi candidate. | Requires an enabled OpenSSL 3 Host crypto context; the target is non-installed. |
| `NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL` | BOOL | `OFF` | Permit a LAB smoke with an OpenSSL version other than the exact authority build. | LAB-only and mutually exclusive with `NINLIL_WIFI_OPENSSL_AUTHORITY=ON`. |
| `NINLIL_WIFI_OPENSSL_AUTHORITY` | BOOL | `OFF` | Require the pinned static OpenSSL 3.5.7 Wi-Fi Host authority profile. | Requires private Wi-Fi `ON`, unpinned mode `OFF`, and a valid authority root containing the exact static build. |
| `NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT` | PATH | empty | Name the hermetic OpenSSL 3.5.7 static install root used by Wi-Fi authority builds. | Required and canonicalized when `NINLIL_WIFI_OPENSSL_AUTHORITY=ON`; otherwise it does not enable authority by itself. |
| `NINLIL_ENABLE_R7_FRAG_PRIVATE` | BOOL | `OFF` | Build the private NRW1 LINK/FRAG candidate. | Non-installed private implementation; target execution and physical RF evidence remain separate gates. |
| `NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1` | BOOL | `OFF` | Enable the private route-relay and multi-parent Host candidate. | Non-installed private implementation; public ABI and physical multi-node HIL are separate decisions. |
| `NINLIL_ENABLE_MFDT_V1_PRIVATE` | BOOL | `OFF` | Build the private ADR-0021 multi-frame durable transfer candidate. | Sources are added only to `ninlil_runtime_private`, never the installed Host Runtime archive. |
| `NINLIL_ENABLE_SANITIZERS` | BOOL | `OFF` | Build with AddressSanitizer and UndefinedBehaviorSanitizer. | Requires GNU, Clang, or AppleClang; sanitizer archives are verification artifacts, not release artifacts. |
| `NINLIL_ENABLE_TSAN` | BOOL | `OFF` | Instrument private Wi-Fi/Fabric libraries with ThreadSanitizer. | Active only for GNU/Clang on non-Apple platforms and only for the relevant private targets. Use a separate build from ASan/UBSan. |
| `NINLIL_ENABLE_POINTER_COMPARE_SANITIZER` | BOOL | `OFF` | Build with ASan plus pointer-compare checking. | Feature-detected. Unsupported Linux compilers/configurations fail; other unsupported platforms warn and ignore it. Runtime tests set `detect_invalid_pointer_pairs=2`. |
| `NINLIL_SQLITE_LINKAGE` | STRING | `AUTO` | Select the SQLite library kind for the POSIX storage port. | Closed set: `AUTO`, `STATIC`, or `SHARED`. macOS does not support `STATIC` together with `NINLIL_BUILD_TESTS=ON`; explicit unavailable kinds fail closed. |

## Inspect and verify

Configure a build and print its cache to see resolved values:

```bash
cmake -S . -B build
cmake -LAH -N build
```

Check that this table still names exactly the CMake user-facing surface:

```bash
python3 tools/build_options_docs_gate.py check
```
