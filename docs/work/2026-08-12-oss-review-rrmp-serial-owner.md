# OSS review: RRMP explicit serial owner

Date: 2026-08-12

## Scope and decision

This tranche closes the remaining RRMP process-global ownership part of OR-21.
The private route and multi-parent catalogs no longer resolve a serial domain
through `static ninlil_rrmp_owner_t *g_bound`. Every private catalog and seam
call now receives the existing caller-owned `ninlil_rrmp_owner_t` as its first
argument. No replacement registry, singleton, thread-local, or general context
framework was introduced.

ADR-0019 D19-14 records this serial-domain contract. It requires explicit
owner selection, owner-local reentry rejection, closed NULL/unbound/wrong-owner
behavior without cross-owner mutation, authorization zeroization on failed
authorization and unbind, and complete workspace zeroization on finalization.
All changed function surfaces are private and non-installed. Public ABI,
public symbols, feature defaults, wire bytes, protocol/storage constants,
storage encodings, and release status are unchanged.

## Invariants

- Bind state, authenticated principal/capabilities, and the reentry guard are
  bytes of the selected caller-owned workspace. Two live owners can be
  interleaved without selecting or mutating one another.
- `owner_bind_authorized` clears the owner's prior serial/auth state before an
  authorization attempt, so every failed attempt leaves no stale authority.
  Explicit unbind clears the same state.
- During a same-owner catalog callback, bind and authorized bind fail, while
  unbind and finalization are no-ops. The outer catalog operation retains its
  serial/auth/workspace state; another catalog call on that owner returns the
  existing reentrant status before mutation.
- Finalization outside an entered call clears every byte of the exact owner
  workspace. The measured workspace remains 756,688 bytes.
- The source authority gate requires the explicit owner first argument on all
  23 catalog functions and three private seams, requires explicit unbind, and
  rejects the removed implicit-owner names. Its general mutable-static scan no
  longer exempts the former `g_bound` declaration; its self-test also rejects
  a renamed mutable owner pointer.

## Verification

- The focused serial-owner test and storage callback/reentry test pass in the
  normal and ASan/UBSan profiles. The serial-owner test proves A/B interleave,
  B unbind isolation while A remains authenticated, a B-authority request
  passed with A returning a closed authority/preamble result with both durable
  namespaces unchanged, NULL/unbound rejection, failed-authorization and
  explicit-unbind zeroization, and full owner zeroization after finalization.
  The storage test proves same-owner catalog and lifecycle reentry cannot erase
  the outer operation's authority/workspace or install the nested route.
- The RRMP Host completion matrix passes with the new serial-owner test in all
  four profiles: feature OFF, feature ON, ASan/UBSan, and installed
  tests-OFF boundary.
- In the all-private build, all selected RRMP, Fabric, and private composition
  coverage passes: **34/34**. Three public `composition_v1_*` tests in that
  broad shared profile independently fail during Runtime creation under the
  pre-existing all-private allocator/workspace combination; the same public
  composition tests pass in the normal profile and do not depend on the RRMP
  serial-owner implementation.
- The actual no-flash ESP-IDF 5.5.3 / ESP32-S3 strict build and map proof pass.
  The relevant translation units compile with strict warnings, the final ELF
  and required-symbol/map checks pass, and RRMP BSS is 3,136 bytes against the
  32,768-byte ceiling.
- RRMP resource authority and negative self-test pass with
  `workspace=756688` and `worst_case=1064144`. Frame-stack and storage-ABI
  gates pass.
- Protocol magic registry authority passes with 76 entries, 165 exclusions,
  and 241 candidates; its 20-mutation self-test passes after exact occurrence
  synchronization.
- Source scans find no `g_bound` or `owner_current`, archive/ELF checks find no
  `ninlil_rrmp_owner_current`, and `git diff --check` passes.

## Nonclaims

This closes the RRMP legacy serial-domain owner finding and does not promote
the default-OFF feature. The ESP result is a compile/link/map proof only. No
device flash, physical RF/HIL execution, power-cut campaign, soak run, or
release-support claim was performed. No commit or push was made.
