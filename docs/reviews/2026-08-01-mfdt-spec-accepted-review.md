# MFDT v1 SPEC_ACCEPTED independent review

Date: 2026-08-01  
Scope: ADR-0021 exact design authority and its four independent machine gates  
Verdict: **SPEC_ACCEPTED GO — P0=0 / P1=0 / P2=0**

## Fresh review result

Sol high independently reviewed the current S1–S5 exact design and found no
remaining design P0, P1, or P2. The ten focused specification tests were
10/10 GREEN. The conditional items were limited to promotion mechanics:

- remove the obsolete control-version-3 status seal and publish MFDT as an
  independent private MFDT protocol v1 bound to Accepted base control 1 or 2;
- promote the machine metadata and acceptance seal from Proposed to
  `SPEC_ACCEPTED_DESIGN_AUTHORITY`;
- keep the implementation-only abort reason naming mismatch separate from the
  design verdict and repair it without changing wire values.

These conditions are reflected by the 2026-08-01 promotion work record. The
earlier 2026-07-30 NO-GO remains historical evidence of the defects found in
that snapshot; it is not the current verdict.

## Accepted boundary

ADR-0021 is accepted as a product-neutral design authority. Accepted control
versions remain exactly 1 and 2. MFDT negotiation and messages use the separate
private MFDT v1 domain. Accepted U5/U6 wire and storage files are unchanged.

## Non-claims

- no `RELEASE_SUPPORTED` or default-ON claim;
- no public Runtime ABI or complete public Runtime E2E claim;
- no compact-RF or physical Wi-Fi MFDT mapping claim;
- no ESP execution, physical power-cut, RF, Wi-Fi, or other HIL claim;
- MF-O03, MF-O04, MF-O05, and MF-O08 remain open.
