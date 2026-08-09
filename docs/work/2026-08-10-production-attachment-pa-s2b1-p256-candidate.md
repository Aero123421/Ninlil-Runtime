# PA-S2b1 private ephemeral P-256 candidate

Date: 2026-08-10  
Status: **independent final GO / Host KAT candidate / ESP32-S3 compile-link-stack only; PA-S2 remains open**

The spec-first plan received an independent implementation-plan GO. This
record freezes the resulting independently reviewed candidate; it does not
promote ADR-0023 or complete PA-S2.

## Scope

This tranche extends the existing private PA-S2a owner with only libedhoc's
ephemeral P-256 `MAKE_KEY_PAIR` and `KEY_AGREEMENT` callback path. It remains
default-OFF, uninstalled, and outside the public Runtime archive. It adds no
public header/API/DTO, wire or storage record, credential resolver, local
static-DH operator, EDHOC message owner, Composition/NIAF connection, task,
pump, or LAB dependency.

The existing two 64-byte slots hold a distinct make handle and one
scalar-plus-token backing. Each agreement import gets a fresh four-byte
slot/generation operation handle. The scalar remains private; libedhoc sees
only a separately drawn, non-zero 32-byte token. Two serialized method-3
agreement operations are allowed. Their generations are reserved atomically
with the backing, so unrelated key imports cannot consume them. First
operation destroy retains the backing; second destroy, crypto failure,
repeated operation use, or owner end wipes it. A later PA-S3 owner must call
owner end at terminal exchange exit and on every error, timeout, or
cancellation, but not after an intermediate successful message return.

`ninlil_entropy_ops_t` has no written-length result. Accordingly, a non-OK
entropy result, including a provider that wrote a prefix first, zeroizes the
candidate. An OK result is treated as an exact fill under the existing port
contract; this consumer does not infer a partial OK fill.

## Evidence

- Host OpenSSL 3 independent algorithm KAT uses RFC 9529 section 3 P-256
  `X/G_X`, `Y/G_Y`, `G_XY`, `G_RX`, and `G_IY` values for both method-3 roles
  and both allowed agreement operations.
- Negative Host checks cover zero/order scalar rejection, token zero/scalar
  collision, bounded entropy exhaustion, entropy failure after a written
  prefix, callback reentry, 48-byte private and 32-byte public capacities,
  stale/wrong/simultaneous/third/reused operation handles, invalid `X >= p`,
  non-curve X, failure/early-end zeroization, and output preservation rules.
  Generation checks also cover atomic backing/op1/op2 reservation at the
  24-bit ceiling and an unrelated key import between the two operations.
- Focused normal Host regression passes PA-S1a, PA-S2a/b1, all Production
  Attachment vector/vendor/language/registry gates, fixture freshness,
  private symbol boundary, and markdown links 16/16. The PA-S2b1-OFF
  baseline passes 3/3. ASan/UBSan passes PA-S1a and PA-S2a/b1 2/2.
- ESP-IDF v5.5.3 image
  `espressif/idf@sha256:8ccd4d2ce413889c6c2bba57e986c670302094efb91c913c6091152e317a7805`
  builds the same source for ESP32-S3 with CCM, ChaCha20, Poly1305,
  ChaChaPoly, ECP, ECDH, and secp256r1 enabled. The four private owner symbols
  are `GLOBAL HIDDEN` in the final ELF.
- ESP stack evidence contains 26 PA-S2 source rows. The maximum frame is 336
  bytes (`pa_make_key_pair`) under the 2048-byte ceiling.
- Fresh compile/link-only artifacts (not flashed or executed):
  `build-pa-s2b1-edhoc-optin-final4/ninlil_m3_combined_smoke.elf`, SHA-256
  `601dba687f64ead8d6e50e1ab04ae4f31c59fb764048b8c2ed59cbbd4a16e434`;
  545,328-byte `.bin`, SHA-256
  `8f22a3e995a625115a0a3f797697419d715f0b636b781f7530512ec91aed4d1b`.

## Open evidence

ESP target execution of the P-256 KAT bytes, Host/ESP equality, upstream
opaque-token interoperability, provider-internal mbedTLS/OpenSSL allocation
ceilings, Factory Identity and Site Membership authorities, peer credential
resolution, local static-DH, a terminal/error EDHOC message owner, real
handshake, PA-S2 overall, PA-S3 through PA-S6, availability, Join, and physical
HIL remain open. The fixed opaque token is a candidate bridge for this adopted
libedhoc version, not a general vendor-independent key-handle ABI.

## Final review

The frozen candidate received an independent Codex GPT-5.6 Sol xhigh
read-only review: **GO — P0=0 / P1=0 / P2=0 / P3=0**. The review closed the
generation-reservation boundary, immediate crypto-failure zeroization
evidence, private/default-OFF packaging, final ESP artifact and stack
evidence, non-claim boundary, and Ponytail minimality. See
[the review record](../reviews/2026-08-10-production-attachment-pa-s2b1-review.md).
