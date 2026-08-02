# POSIX USB serial reference port review

- Date: 2026-08-01
- Scope: ADR-0031 public/install tranche
- Result: **GO — P0=0 / P1=0 / P2=0**

## Reviewed boundary

- Installed target `Ninlil::posix_usb_serial_v1` and public header
  `ninlil/posix_usb_serial_v1.h`.
- Existing POSIX adapter remains the single implementation authority.
- Syscall injection and forced-generation helpers remain private.
- The external consumer uses only the installed package and a real PTY.

## Evidence

- macOS AppleClang strict normal focused set: 5/5 passed.
- macOS AppleClang ASan/UBSan focused set: passed.
- Fresh tests-OFF installed consumer: bidirectional bytes, close/reopen and
  increasing non-zero link generation passed.
- C and C++ public-header closure passed.
- Two review findings (private-header leak path and stale CMake comment) were
  repaired and re-reviewed.

Linux execution and physical Linux/macOS USB CDC were not run in this review.
They remain CI/HIL gates and are not implied by the PTY result.
