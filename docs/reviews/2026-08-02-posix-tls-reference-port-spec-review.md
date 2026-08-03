# POSIX TLS reference-port specification review

- Date: 2026-08-02
- Subject: ADR-0030 public boundary and implementation readiness
- Reviewer role: independent read-only specification review
- Final verdict: **GO — P0=0 / P1=0 / P2=0**

## Scope

The review covered only the Linux/macOS reference port required by ADR-0029:
one installed target, one public header, real TCP/TLS, and registration with the
public Fabric. It did not re-open ADR-0018 as a whole or add future transport,
discovery, credential-rotation, relay, or physical-HIL requirements.

## Findings and closure

The first review found one P0 and two P1 findings: the static authorization
root and certificate-generation checks were incomplete; Fabric registration,
availability and ownership lifecycles were underspecified; and the existing
private link candidate could report definite failure after a partial positive
TLS write. One package-boundary P2 was also recorded.

ADR-0030 now fixes a trusted static provisioning root, exact local and peer
leaf expectations, a limited static mTLS profile, same-owner Fabric lifecycle,
strict availability epochs, and token-local uncertain-boundary tracking. It
also fixes the OpenSSL and installed-package boundary without publishing the
private umbrella.

A focused re-review found one remaining P1: restart without a valid clean-close
marker and the marker-versus-Storage-close order were ambiguous. The final
text fences every restart without a valid marker, persists the marker before
closing Storage, treats marker commit-unknown as not clean, and requires the
intermediate-stop negative test.

The final closure review reported **P0=0 / P1=0 / P2=0** and authorized changing
ADR-0030 to Accepted.

## Non-claims

This is specification acceptance only. Implementation, Linux CI evidence,
physical access-point testing, ESP32 integration, field evidence, and release
support remain unclaimed until their own acceptance gates pass.
