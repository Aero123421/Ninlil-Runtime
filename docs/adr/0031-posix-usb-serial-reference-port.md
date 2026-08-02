# ADR-0031: POSIX USB serial reference port

- Status: Accepted
- Date: 2026-08-01
- Scope: Linux/macOS Host reference byte-stream port for ADR-0029 item 4
- Depends on: ADR-0003, ADR-0029, `docs/23-usb-radio-boundary.md`
- Review: [independent GO, P0=0 / P1=0 / P2=0](../reviews/2026-08-01-posix-usb-serial-reference-port-review.md)

## Context

ADR-0029 requires an installed Linux/macOS USB serial reference port before
the Runtime composition and ESP-IDF tranches. The repository already contains
a bounded A1 implementation with PTY and deterministic fault tests. V1 does
not need a new serial protocol, discovery service, daemon, or Fabric-specific
adapter; it needs a clean installed surface over the existing portable
`ninlil_byte_stream_t` contract.

## Decision

### 1. One small Host-only package

The CMake target is `Ninlil::posix_usb_serial_v1` and the installed header is
`ninlil/posix_usb_serial_v1.h`. It is experimental under the package 0.x
policy and is supported only on Linux and macOS.

The port depends on the public byte-stream contract and POSIX Threads. It does
not depend on Runtime, Fabric, TLS, radio, framing, assignment, or a product
schema. It owns no hidden thread and performs work only when its caller invokes
an operation.

### 2. Existing production contract becomes public

The existing production symbol names are retained; publishing the port does
not justify a source-breaking rename. The complete public allowlist is:

```text
NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES
NINLIL_POSIX_USB_SERIAL_OBJECT_ALIGN
NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX
ninlil_posix_usb_serial_object_t

ninlil_posix_usb_serial_object_size
ninlil_posix_usb_serial_object_align
ninlil_posix_usb_serial_init
ninlil_posix_usb_serial_init_object
ninlil_posix_usb_serial_open
ninlil_posix_usb_serial_close
ninlil_posix_usb_serial_write
ninlil_posix_usb_serial_read
ninlil_posix_usb_serial_poll
ninlil_posix_usb_serial_link
ninlil_posix_usb_serial_link_generation
ninlil_posix_usb_serial_stats
ninlil_posix_usb_serial_last_error
```

The caller owns the fixed object storage and `ninlil_byte_stream_t` view for
the full open lifetime. Exact operation semantics, owner fencing, bounded
rings, backpressure, structured errors, absolute endpoint path, link-down
handling, explicit close-before-reopen, generation advancement, and bounded
EINTR handling remain the contracts already fixed by `byte_stream.h` and
`docs/23-usb-radio-boundary.md`. Raw write acceptance is not Transport Custody
or an Application Receipt.

The syscall injection table, its setter, forced-generation helper, forced
`fcntl` build macro, and every other test seam remain private. They are absent
from the installed header and are not supported ABI. As with ADR-0029's static
archive rule, the presence of a non-declared implementation symbol in an
archive does not make it public API.

### 3. Installed-package acceptance

Software acceptance requires:

1. A fresh `NINLIL_BUILD_TESTS=OFF` install exports the target and only public
   headers are required by an external C11 consumer.
2. The external consumer uses a real PTY, transfers bytes in both directions,
   observes bounded progress, closes, reopens, and observes a newer non-zero
   link generation without a private hook.
3. The install tree and consumer compile graph contain no private transport
   header, source path, test helper, or syscall seam.
4. Existing focused adapter tests and the installed consumer pass with strict
   warnings; the scoped Host tests also pass under ASan/UBSan where supported.
5. Unsupported platforms do not publish the target.

This PTY evidence proves the software serial path only. Physical Linux USB CDC
and physical macOS USB CDC remain separate HIL results and stay `NOT_RUN` until
actually executed.

## Non-goals

- Device discovery, VID/PID matching, hotplug monitoring, or automatic reopen.
- A background pump, daemon, plugin system, or new persistence schema.
- NCG1/NCL1 framing, Join, assignment, custody, Fabric registration, or
  application semantics.
- Rewriting the existing adapter or duplicating its fault-test matrix in the
  installed consumer.
- Claiming USB-series, ESP USB, physical-device, or field completion from PTY
  tests.

## Consequences

- Host applications gain one installable, product-neutral USB serial port.
- Existing tested code and behavior remain the implementation authority.
- Higher-level composition can add framing and policy later without expanding
  this byte-stream API.
