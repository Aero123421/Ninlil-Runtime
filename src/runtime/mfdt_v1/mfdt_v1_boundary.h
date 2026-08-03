/* SPDX-License-Identifier: Apache-2.0
 * ADR-0021 MFDT private integration boundary notes (not public ABI).
 *
 * SEMANTIC: NOT_PUBLIC_ABI
 * SEMANTIC: NOT_INSTALLED
 * SEMANTIC: NOT_HIL_CLAIM
 *
 * ApplicationData: MFDT may only hand off after content-verified, an upper
 * durable prepare keyed by publication_token, and
 * receiver_commit_publication(). No partial publish. Upper Application
 * Receipt is not claimed by MFDT.
 *
 * NRW1 FRAG (R7): orthogonal carriage candidate. FRAG is not multi-frame
 * durable transfer; MFDT does not call r7_frag public surfaces. When both
 * private options are ON they share no static BSS and no public ABI change.
 *
 * Fabric: MFDT control messages use the exact private TRANSFER_RESERVED
 * Foundation carrier from ADR-0021. Fabric path selection (ADR-0017) is not
 * altered. No public Fabric ABI symbols or public Service registration.
 */
#ifndef NINLIL_MFDT_V1_BOUNDARY_H
#define NINLIL_MFDT_V1_BOUNDARY_H

/* Compile-time boundary markers for packaging / map gates (private only). */
#define NINLIL_MFDT_V1_BOUNDARY_MARKER "ninlil_mfdt_v1_boundary_private_v1"

#endif /* NINLIL_MFDT_V1_BOUNDARY_H */
