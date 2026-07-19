# 30. R6 Secure Compact Radio Wire（NRW1 compact context-handle）

状態: **Normative / Accepted / Stage 9**（independent root QA re-GO 2026-07-19 P0=P1=P2=0; Stage 9 crypto P1 closed in docs）  
（**R6 docs freeze Accepted** — R7 full AEAD codec / M4 handshake 実装 / M5 complete / ESP N6 capacity / Japan legal / RF·USB 実機 HIL / production radio 未完; public ABI 非主張; compile/link ≠ HIL）  
正本 ADR: [ADR-0010](adr/0010-r6-secure-radio-wire.md)（**Accepted**）  
文書: **docs/30** / ADR-**0010**

**SEMANTIC: R6_DOCS_FREEZE_ONLY**  
**SEMANTIC: WIRE_PROFILE_ID_0x11**  
**SEMANTIC: POST_ATTACHMENT_DATA_PROFILE_ONLY**  
**SEMANTIC: PAIRWISE_UNICAST_ONLY_V1**  
**SEMANTIC: KIND_DATA_AND_LINK_ACK_ONLY**  
**SEMANTIC: DIAG_RESERVED_REJECT**  
**SEMANTIC: NO_RELAY_FORWARD_KIND**  
**SEMANTIC: ROUTE_HANDLE_IS_RELAY**  
**SEMANTIC: CONTEXT_ID_BINDS_OFF_WIRE**  
**SEMANTIC: NO_WIRE_DIRECTION_ENUM**  
**SEMANTIC: DIRECTION_CODE_0_IR_1_RI**  
**SEMANTIC: ONE_WAY_CONTEXT_EXACT**  
**SEMANTIC: HOP_DATA_ACK_SEPARATE_CRYPTO_LANES**  
**SEMANTIC: TX_RX_DO_NOT_SHARE_KEY_COUNTER_NS**  
**SEMANTIC: DUAL_ENVELOPE_E2E_OPAQUE_TO_RELAY**  
**SEMANTIC: E2E_SEALED_BLOB_BIT_IDENTICAL_ON_RELAY**  
**SEMANTIC: FORBIDDEN_SINGLE_HOP_AEAD_OVER_APP_PLAINTEXT**  
**SEMANTIC: OUTER_FRAME_CONCAT_AAD19_CT_TAG16**  
**SEMANTIC: E2E_BLOB_CONCAT_AAD14_CT_TAG16**  
**SEMANTIC: OUTER_AAD_BYTES_19**  
**SEMANTIC: E2E_AAD_BYTES_14**  
**SEMANTIC: GCM_TAG_BYTES_16**  
**SEMANTIC: MAX_OUTER_FRAME_255**  
**SEMANTIC: LENGTH_FROM_LORA_PACKET**  
**SEMANTIC: CLOSED_LENGTH_DOMAINS**  
**SEMANTIC: TYPE_LENGTH_SINGLE_66_255**  
**SEMANTIC: TYPE_LENGTH_START_130_255**  
**SEMANTIC: TYPE_LENGTH_CONT_76_255**  
**SEMANTIC: TYPE_LENGTH_FRAG_ACK_79_EXACT**  
**SEMANTIC: ENCODE_CANON_BYTE_EXACT**  
**SEMANTIC: ENVIRONMENT_CODE_LAB_FIELD**  
**SEMANTIC: HKDF_SALT_IS_CONTEXT_BINDING_DIGEST**  
**SEMANTIC: HKDF_LABEL_HOP_DATA_KEY**  
**SEMANTIC: HKDF_LABEL_HOP_DATA_IV**  
**SEMANTIC: HKDF_LABEL_HOP_ACK_KEY**  
**SEMANTIC: HKDF_LABEL_HOP_ACK_IV**  
**SEMANTIC: HKDF_LABEL_E2E_KEY**  
**SEMANTIC: HKDF_LABEL_E2E_IV**  
**SEMANTIC: NONCE_STATIC_IV_XOR_COUNTER_U64**  
**SEMANTIC: RECEIVER_ALLOCATES_INBOUND_CONTEXT_ID**  
**SEMANTIC: NO_CONTEXT_ID_REUSE_IN_MEMBERSHIP_EPOCH**  
**SEMANTIC: NO_SILENT_CONTEXT_REPLACE**  
**SEMANTIC: NO_SAME_KEY_COUNTER_RESET_INSTALL**  
**SEMANTIC: DURABLE_RECORD_KEY_BINDS_LAYER_KIND_DIR_ID_DIGEST_KGEN**  
**SEMANTIC: E2E_SECURITY_ID_NOT_ATTACHMENT**  
**SEMANTIC: HOP_BINDS_ATTACHMENT**  
**SEMANTIC: DURABLE_TX_RESERVED_EXCLUSIVE**  
**SEMANTIC: DURABLE_RX_TRANCHE_AND_SLIDING_64**  
**SEMANTIC: RX_SLIDING64_PSEUDOCODE**  
**SEMANTIC: RX_CHECKED_SATURATING_NEW_THROUGH**  
**SEMANTIC: TX_CHECKED_SATURATING_LIMIT_PLUS_B**  
**SEMANTIC: RX_BOOT_REJECT_THROUGH**  
**SEMANTIC: STORAGE_RESULT_TABLE_CLOSED**  
**SEMANTIC: COMMIT_UNKNOWN_NO_DELIVERY**  
**SEMANTIC: TX_COMMIT_UNKNOWN_BURN_TO_U**  
**SEMANTIC: COUNTER_U64_TERMINAL_MAX**  
**SEMANTIC: BLOCK_SIZE_EXACT_64**  
**SEMANTIC: VALIDATION_ORDER_STRUCT_REPLAY_AEAD_ADMIT_BODY**  
**SEMANTIC: RELAY_E2E_OPEN_FORBIDDEN**  
**SEMANTIC: CELL_64_V1_RESOURCE_PROFILE**  
**SEMANTIC: NO_UNBOUNDED_SESSION_GE**  
**SEMANTIC: NO_SILENT_SESSION_EVICTION**  
**SEMANTIC: CELL_64_TIMERS_EXACT_DEFAULTS**  
**SEMANTIC: TRANSFER_ID_128**  
**SEMANTIC: TRANSFER_HANDLE_SENDER_ENCODER_RULE**  
**SEMANTIC: DECODER_NO_HANDLE_EQ_OBSERVED_COUNTER**  
**SEMANTIC: CONTENT_DIGEST_SHA256_REASSEMBLED**  
**SEMANTIC: FRAG_START_CONT_ACK_TYPES**  
**SEMANTIC: FRAG_ACK_STATUS_CATALOG**  
**SEMANTIC: FRAG_BITMAP_EXACT**  
**SEMANTIC: FRAG_TOMBSTONE_BOUNDED_TTL**  
**SEMANTIC: FRAG_TOMBSTONE_RESERVE_ON_START**  
**SEMANTIC: FRAG_TOMBSTONE_FINGERPRINT**  
**SEMANTIC: FRAG_CONT_NO_FINGERPRINT**  
**SEMANTIC: NO_SENDER_TRANSFER_HANDLE_REUSE_IN_E2E_CTX**  
**SEMANTIC: TOMBSTONE_TTL_LATE_RETRY_MAY_BE_NEW**  
**SEMANTIC: FRAG_COMPLETE_NOT_APP_RECEIPT**  
**SEMANTIC: FRAG_COMPLETE_COMMIT_ORDER_EXACT**  
**SEMANTIC: E2E_SECURITY_EPOCH_GT_0**  
**SEMANTIC: KEY_GENERATION_U64_1_TO_MAX**  
**SEMANTIC: KEY_GENERATION_UINT64_MAX_TERMINAL**  
**SEMANTIC: STORAGE_ABI_PLATFORM_H_MAPPING**  
**SEMANTIC: COMMIT_UNKNOWN_RECOVERY_EXACT**  
**SEMANTIC: RX_BITMAP_UINT64_C1_SHIFT**  
**SEMANTIC: TX_EXCLUSIVE_RESERVATION_CHECKED_FINAL_TRANCHE**  
**SEMANTIC: HA_V1_SINGLE_SEALER_ONLY**  
**SEMANTIC: HA_OWNER_CHANGE_REQUIRES_NEW_E2E_CONTEXT**  
**SEMANTIC: LINK_ACK_REQUIRES_ACK_REQUESTED_BIT**  
**SEMANTIC: LINK_RETRY_GROUP_EXACT**  
**SEMANTIC: LINK_ACK_BITMAP_I_GE_BASE_THEN_ZERO**  
**SEMANTIC: FRAG_ACK_RECEIVER_ONLY**  
**SEMANTIC: FRAG_DUAL_UNIQUE_INDEX_HANDLE_AND_TRANSFER_ID**  
**SEMANTIC: FRAG_CONFLICT_NO_REPLACE_EXISTING**  
**SEMANTIC: CELL_64_NO_SIZEOF_PORTABLE_BYTES**  
**SEMANTIC: PROFILE_CHANGE_REQUIRES_NEW_WIRE_PROFILE_ID**  
**SEMANTIC: FRAME_DIGEST_ALG_1_SHA256_OUTER**  
**SEMANTIC: ENCODE_CANON_BE_ONLY**  
**SEMANTIC: TYPE_FLAGS_LOW_NIBBLE_ZERO**  
**SEMANTIC: RELAY_E2E_STRUCTURAL_ONLY_AFTER_OUTER**  
**SEMANTIC: RELAY_MUST_STRUCTURAL_E2E_HEADER**  
**SEMANTIC: LINK_RETRY_SAME_E2E_BLOB**  
**SEMANTIC: FRAG_E2E_RETRY_FRESH_SEAL**  
**SEMANTIC: FRAG_MAX_OUTER_ATTEMPTS_PER_FRAGMENT_16**  
**SEMANTIC: FRAG_SENDER_TIMING_EXACT**  
**SEMANTIC: TOMBSTONE_VOLATILE_ON_RESTART**  
**SEMANTIC: PERMIT_AFTER_SEAL_EXACT_CANDIDATE**  
**SEMANTIC: SEAL_BURNS_COUNTER_BEFORE_PERMIT**  
**SEMANTIC: PREPARED_CANDIDATE_MAX_ONE_PER_GROUP**  
**SEMANTIC: LINK_GROUP_ABSOLUTE_DEADLINE_IMMUTABLE**  
**SEMANTIC: RECEIVER_ABSOLUTE_DEADLINE_IMMUTABLE**  
**SEMANTIC: FRAG_RECEIVER_TRANSFER_TTL_90000**  
**SEMANTIC: FRAG_PARTIAL_ACK_LIVENESS**  
**SEMANTIC: FRAG_ACK_RX_VALIDATION_CLOSED**  
**SEMANTIC: R7_STATUS_PRESERVING_R5_ISSUE_SEAM**  
**SEMANTIC: R5_ADAPTER_STATIC_INPUTS_ONLY**  
**SEMANTIC: R5_REG_WINDOW_INTERNAL_COPY**  
**SEMANTIC: R5_PROFILE_CLOCK_EPOCH_REQUIRED**  
**SEMANTIC: BIND_COMPARISON_LOCUS_CLOSED**  
**SEMANTIC: ADR0010_SUPERSEDES_R5_RESTART_GEN_BUMP**  
**SEMANTIC: BOOTSTRAP_AFTER_R2_RECOVER_CLOSED**  
**SEMANTIC: EPOCH_CLASS_FOUR_WAY_CLOSED**  
**SEMANTIC: EPOCH_CLASS_A_W1_REPAIR_NO_ADOPT**  
**SEMANTIC: EPOCH_CLASS_B_AUTHORITY_DIVERGENCE**  
**SEMANTIC: EPOCH_CLASS_C_NEW_EPOCH_ADOPT**  
**SEMANTIC: EPOCH_NO_OR_BULK_RECOVER**  
**SEMANTIC: CLOCK_UNCERTAIN_SAME_EPOCH_FRESH_OK**  
**SEMANTIC: CLOCK_FAULT_REQUIRES_FRESH_EPOCH_ADOPT**  
**SEMANTIC: SAMPLE_NO_ROUTINE_STORAGE_RO**  
**SEMANTIC: SAMPLE_USES_RAM_TRUST_MIRROR**  
**SEMANTIC: BASELINE_SNAPSHOT_BOOT_ADOPT_ONLY**  
**SEMANTIC: DRAIN_ALL_QUARANTINED_TERMINAL_OR_STALE**  
**SEMANTIC: DRAIN_FIFO_FULL_CLEAR**  
**SEMANTIC: R1_FIFO_OUT_OF_ORDER_TYPED_CLOSED**  
**SEMANTIC: FIFO_OOO_NO_HINT_PARSE**  
**SEMANTIC: FIFO_OOO_NOT_RETRYABLE_UNCONSUMED**  
**SEMANTIC: R7_TYPED_FIFO_OOO_REFREEZE_BLOCKER**  
**SEMANTIC: PRIVATE_DURABLE_FIFO_HEAD_PROOF_API**  
**SEMANTIC: DRAIN_NO_PREDRAIN_SNAPSHOT_REUSE**  
**SEMANTIC: DRAIN_RETRY_BUDGET_CLOSED**  
**SEMANTIC: DRAIN_NO_SAME_TICK_SPIN**  
**SEMANTIC: RESTART_RECOVER_STORAGE_AFTER_BIND**  
**SEMANTIC: RESTART_EMPTY_OK_PUBLISH_PATH**  
**SEMANTIC: DRAIN_CLOCK_ORDER_RESAMPLE_BEFORE_RECOVER_CLOCK**  
**SEMANTIC: W1_WATERMARK_HELD_UNTIL_ADOPT_DONE**  
**SEMANTIC: TEMP_UNCERTAIN_DISCARD_ALL_VOLATILE**  
**SEMANTIC: CONTEXT_FENCE_STAMP_EPOCH_RECLAIM_CLOSED**  
**SEMANTIC: DURABLE_LANE_RECORD_LAYOUTS_CLOSED**  
**SEMANTIC: DURABLE_NAMESPACE_ALLOCATOR_CLOSED**  
**SEMANTIC: DURABLE_RETIRED_CONTEXT_TOMBSTONE_CLOSED**  
**SEMANTIC: CONTEXT_ID_MONOTONIC_NEXT_FREE**  
**SEMANTIC: CONTEXT_ALLOCATOR_CELL64_BOUNDED**  
**SEMANTIC: RETIRED_GC_ONLY_AFTER_MEMBERSHIP_NAMESPACE**  
**SEMANTIC: FENCE_RECLAIM_VOLATILE_VS_DURABLE_SPLIT**  
**SEMANTIC: EXPORTED_PRIVATE_MODULE_C_API_NOT_OSS_PUBLIC**  
**SEMANTIC: TYPED_W1_ISSUE_RESULT_CLASS_CLOSED**  
**SEMANTIC: ISSUED_PERMIT_GLOBAL_RECONCILE_CLOSED**  
**SEMANTIC: FRAG_ACK_INTENT_STATE_MACHINE_CLOSED**  
**SEMANTIC: FRAG_ACK_SEMANTIC_BURN_LEDGER_RETAINED**  
**SEMANTIC: FRAG_ACK_RETRY_USES_FRAG_RETRY_INTERVAL**  
**SEMANTIC: ACK_RETRY_AT_USES_FRAG_RETRY_INTERVAL_MS_ONLY**  
**SEMANTIC: ACK_LEDGER_NOT_RESET_ON_ACKED_OR_DUPLICATE**  
**SEMANTIC: ACK_SEAL_FAIL_CONSUMES_THEN_RETRY_OR_DROP**  
**SEMANTIC: CELL_TIMER_DOMAIN_TABLE_CLOSED**  
**SEMANTIC: W1_CLOCK_WATERMARK_REGRESSION_CLOSED**  
**SEMANTIC: ISSUE_PROFILE_SAME_SAMPLE_TOCTOU_CLOSED**  
**SEMANTIC: BIND_MISMATCH_AUTHORITY_VS_CANDIDATE_CLOSED**  
**SEMANTIC: PROFILE_MISMATCH_IS_AUTHORITY_DIVERGENCE**  
**SEMANTIC: PERMIT_GEN_BIND_IS_RECONCILE_REQUIRED**  
**SEMANTIC: SAMPLE_COMPARES_DURABLE_LAST_TRUSTED_NOW**  
**SEMANTIC: R5_REQUIRED_CHECKED_ISSUE_ADAPTER**  
**SEMANTIC: R5_ISSUE_ADAPTER_MANDATORY_STATIC_REGISTRY**  
**SEMANTIC: PRIVATE_LOAD_AUTHORITY_CLOCK_BASELINE**  
**SEMANTIC: PRIVATE_ADOPT_ATOMIC_NO_ARM_FENCE**  
**SEMANTIC: ADOPT_SAMPLE_COPYOUT_FULL_OK_ONLY**  
**SEMANTIC: ADOPT_COMMITTED_FROM_DURABLE_PROOF**  
**SEMANTIC: PUBLIC_RECOVER_CLOCK_NO_SAMPLE_VISIBILITY**  
**SEMANTIC: PRIVATE_ADOPT_API_REQUIRED**  
**SEMANTIC: SAMPLE_NO_IMPLICIT_W1_LOAD**  
**SEMANTIC: WATERMARK_INIT_FROM_BASELINE_LOAD**  
**SEMANTIC: SAMPLE_PRIMITIVE_CLOSED_REQUEST_RESULT**  
**SEMANTIC: SAMPLE_DURABLE_RO_OUTCOMES_CLOSED**  
**SEMANTIC: SAMPLE_NO_COLLAPSE_TO_UNBOUND**  
**SEMANTIC: CHECKED_ISSUE_NOT_BEFORE_EXPIRY_EXACT**  
**SEMANTIC: CHECKED_ISSUE_SAME_S_PROFILE_OWNER_R1**  
**SEMANTIC: TERMINAL_PENDING_RX_BEHAVIOR_CLOSED**  
**SEMANTIC: DRAIN_OK_PER_OWNER_DISPOSITION_CLOSED**  
**SEMANTIC: START_RESERVE_FAIL_ACK0_ONLY**  
**SEMANTIC: W1_WATERMARK_RESTART_FROM_DURABLE_META**  
**SEMANTIC: R7_PRIVATE_AUTHORITY_SAMPLE_PRIMITIVE**  
**SEMANTIC: W1_AUTHORITY_EPOCH_ADOPT_CLOSED**  
**SEMANTIC: EPOCH_ADOPT_NO_INFINITE_DROP_LOOP**  
**SEMANTIC: SAMPLE_PRIMITIVE_SOLE_OWNER**  
**SEMANTIC: ISSUE_ORDER_SAMPLE_PROFILE_EPOCH_RW**  
**SEMANTIC: TERMINAL_PENDING_BEFORE_DRAIN**  
**SEMANTIC: U5_GENERATION_ONLY_VIA_DOCS25_L5_L9**  
**SEMANTIC: R2_ISSUE_NO_ALGORITHM_E_FOR_W1**  
**SEMANTIC: R7_PRIVATE_R2_CHECKED_ISSUE_PRIMITIVE**  
**SEMANTIC: L1_EXPORTED_PRIVATE_MODULE_DRAIN_ORCHESTRATION_CLOSED**  
**SEMANTIC: DRAIN_STORAGE_BEFORE_REVOKE_BEFORE_CLOCK**  
**SEMANTIC: DRAIN_NO_COMBINED_RECOVER_WHILE_OUTSTANDING**  
**SEMANTIC: DRAIN_COMMIT_UNKNOWN_REENTRY_CLOSED**  
**SEMANTIC: REVOKE_ALL_CLOCKLESS_UNDER_CLOCK_FENCE**  
**SEMANTIC: TERMINAL_PARTIAL_CANCEL_MATRIX_CLOSED**  
**SEMANTIC: GENERATED_ACK_BURN_LIMITS_CLOSED**  
**SEMANTIC: AUTHORITY_TIME_CLOCK_HANDOFF_CLOSED**  
**SEMANTIC: NOW_MONO_EQ_TRUSTED_SAMPLE_NOW_MS**  
**SEMANTIC: W1_AUTHORITY_CLOCK_DOMAIN_ONLY**  
**SEMANTIC: E2E_ATTEMPT_START_MONO_ONCE**  
**SEMANTIC: CONT_CONFLICT_ABORT_TOMBSTONE**  
**SEMANTIC: COMMIT_UNKNOWN_NAMESPACE_RECOVERY**  
**SEMANTIC: SINGLE_SHARED_STORAGE_HANDLE_PER_NAMESPACE**  
**SEMANTIC: FRAG_START_EXACT_RETRY_NO_MUTATION**  
**SEMANTIC: ENDPOINT_E2E_INGRESS_QUEUE**  
**SEMANTIC: UPPER_TRANSPORT_QUEUE**  
**SEMANTIC: LINK_RETRY_BLOB_COPY_OWN**  
**SEMANTIC: TOMBSTONE_CANONICAL_72B**  
**SEMANTIC: TIMER_MONOTONIC_OWNER_CLOCK**  
**SEMANTIC: LINK_RETRY_ELIGIBLE_AT_MAX**  
**SEMANTIC: CONTEXT_DIGEST_FENCE_ACTIVE_NAMESPACE**  
**SEMANTIC: LINK_ACK_CODE_ACCEPTED_BATCH_ONLY**  
**SEMANTIC: LINK_ACK_BITMAP_RULES**  
**SEMANTIC: LINK_ACK_ROUTE_0_0_REMAINING_0**  
**SEMANTIC: LINK_ACK_TX_GEN_AFTER_DATA_ADMIT**  
**SEMANTIC: LINK_ACK_RX_VALIDATE_SEPARATE**  
**SEMANTIC: LINK_ACK_PAIRS_REVERSE_ACK_LANE_TO_FORWARD_DATA**  
**SEMANTIC: ROUTE_TERMINAL_INVARIANT_REMAINING**  
**SEMANTIC: SINGLE_OPAQUE_APP_BYTES**  
**SEMANTIC: NO_R6_APP_IDENTITY**  
**SEMANTIC: LOGICAL_ENVELOPE_FREEZE_BLOCKER**  
**SEMANTIC: LINK_ACK_HOP_ONLY**  
**SEMANTIC: NO_LINK_ACK_OF_LINK_ACK**  
**SEMANTIC: NO_FRAG_ACK_OF_FRAG_ACK**  
**SEMANTIC: ACK_REQUESTED_FLAG_ON_DATA**  
**SEMANTIC: EGRESS_ACK_POLICY_NOT_BLIND_COPY**  
**SEMANTIC: ROUTE_RECORD_EGRESS_TUPLE_EXACT**  
**SEMANTIC: NEXT_ROUTE_HEADER_SOURCES_EXACT**  
**SEMANTIC: PHY_SNAPSHOT_R7_R9_BLOCKER**  
**SEMANTIC: DOCS25_PERMIT_FENCE_NOT_RESOLVED_BY_R6**  
**SEMANTIC: SAME_CONTEXT_RESUME_NEEDS_M5_FLOOR**  
**SEMANTIC: M4_M5_ATTACHMENT_HANDSHAKE_NOT_COMPLETE**  
**SEMANTIC: M4_JOIN_BOOTSTRAP_SEPARATE_PROFILE**  
**SEMANTIC: PRE_CONTEXT_INSTALL_0x11_APP_TXRX0**  
**SEMANTIC: R7_IMPLEMENTATION_NOT_IN_R6**  
**SEMANTIC: L1_RADIO_COORDINATOR_CLOSED**  
**SEMANTIC: W1_CODEC_NO_R2_R5_COMPILE_DEP**  
**SEMANTIC: W1_IMMUTABLE_CANDIDATE_TYPED_EVENT_ONLY**  
**SEMANTIC: RECOVERY_SERIES_SINGLE_PIPELINE_CLOSED**  
**SEMANTIC: ORDINARY_SAME_EPOCH_CANCEL_CLOCK_NOOP**  
**SEMANTIC: ADOPT_CU_PROPOSED_VS_OLD_BASELINE_CLOSED**  
**SEMANTIC: L1_RESULT_CLASS_SET_CLOSED**  
**SEMANTIC: PROFILE_CLOCK_EPOCH_SIDECAR_SUPERSEDES_WALL_CLOCK**  
**SEMANTIC: NO_JAPAN_LEGAL_CLAIM**  
**SEMANTIC: COMPILE_NE_HIL**  
**SEMANTIC: FRAME_DIGEST_SHA256_ALG_1**  
**SEMANTIC: WIRE_SIZE_SINGLE_EQ_65_PLUS_N**  
**SEMANTIC: WIRE_SIZE_APP16_81**  
**SEMANTIC: WIRE_SIZE_APP24_89**  
**SEMANTIC: WIRE_SIZE_APP32_97**  
**SEMANTIC: LAB_AIRTIME_REF_SF7_BW125**  
**SEMANTIC: CHANNEL_AIRTIME_FRACTION_NOT_LEGAL_DUTY**  
**SEMANTIC: AIRTIME_2CH_IDEAL_EQUAL_SPLIT_RAW**  
**SEMANTIC: GROUP_AND_BEACON_RESERVED_REJECT**  
**SEMANTIC: NO_SYMMETRIC_RX_ONLY_GROUP_KEY**  
**SEMANTIC: ROUTE_LOOKUP_INGRESS_HANDLE_GEN**  
**SEMANTIC: NO_ROUTE_AUTHORITY_IN_HOP_KDF**  
**SEMANTIC: FIELD_CONTEXT_NONEMPTY_AUTHORITY**  
**SEMANTIC: FORBIDDEN_EDITOR_ARTIFACTS**  
**SEMANTIC: ALLOWED_KIND_MASK_EXACT_0x0003**  
**SEMANTIC: INVALID_RADIO_RESPONSE_TX0**  
**SEMANTIC: HA_SINGLE_LINEARIZABLE_E2E_SEALER**  
**SEMANTIC: HA_REWRAP_VS_NEW_SEAL_SEPARATED**  
**SEMANTIC: UNIQUE_SECTION_HEADINGS**
**SEMANTIC: L1_W1_BIDIRECTIONAL_EVENT_SET_CLOSED**  
**SEMANTIC: L1_SOLE_OWNER_AUTHORITY_CLOCK_WATERMARK**  
**SEMANTIC: L1_WATERMARK_HELD_UNTIL_ADOPT_DONE**  
**SEMANTIC: ADOPT_REQUEST_L1_EPOCH_WATERMARK_COPYIN**  
**SEMANTIC: CLASS_D_REQUIRES_BLOCKING_FENCE_CLEAR**  
**SEMANTIC: CLOCK_FAULT_DURABLE_LATCH_RESTART_SURVIVES**  
**SEMANTIC: CLASS_B_BOUNDED_THEN_OPERATOR_RECOVERY**  
**SEMANTIC: CONTEXT_FENCE_DURABLE_TABLE_CLOSED**  
**SEMANTIC: N6_MULTI_KEY_FULL_TXN_CLOSED**  
**SEMANTIC: N6RT_FULL_NS_IDENTITY_NO_U32_TAG**  
**SEMANTIC: N6_VALUE_CRC32C_CANONICAL**  
**SEMANTIC: N6_BOUNDED_GROWTH_NO_PHANTOM_ACTIVE**  
**SEMANTIC: R5_ADAPTER_SINGLE_IN_API_OWNER_ORDER**  
**SEMANTIC: PROFILE_CLOCK_EPOCH_UNIFIED_SOURCE**  
**SEMANTIC: FRAG_ACK_INTENT_BURN_STORAGE_MATRIX_CLOSED**  
**SEMANTIC: QUARANTINED_ISSUED_TERMINAL_OR_STALE_ONLY**  
**SEMANTIC: R7_MATERIALIZATION_REQUIREMENTS_FROZEN_ARTIFACTS_PENDING**  
**SEMANTIC: TX_HOLDS_PEER_RECEIVER_ALLOCATED_CONTEXT_ID**  
**SEMANTIC: PROFILE_READY_GATE_BEFORE_COUNTER_BURN**  
**SEMANTIC: L1_AUTHORITY_CLOCK_DOMAIN_ONLY**  
**SEMANTIC: L1_W1_SEVEN_EVENT_SET_TX_RESULT**  
**SEMANTIC: R2_PRIVATE_ISSUE_COORDINATOR_SINGLE_SAMPLE**  
**SEMANTIC: R5_VALIDATION_CALLBACK_SAME_S**  
**SEMANTIC: PROFILE_ACTIVATION_SAME_S_SNAPSHOT**  
**SEMANTIC: REG_PROFILE_SCHEMA2_AUTHORITY_EPOCH**  
**SEMANTIC: N6AL_OUTBOUND_PEER_NEXT_FLOOR**  
**SEMANTIC: N6_BOOT_EXACT_LANE_TO_N6AL_JOIN**  
**SEMANTIC: N6_NO_RETAINED_UNCOMPACTED**  
**SEMANTIC: N6_NAMESPACE_GC_BOUNDED_BATCH_N32**  
**SEMANTIC: CONSUME_TYPED_REASON_43_45_CLOSED**  
**SEMANTIC: CLOCK_FAULT_FC_BY_R2_SAMPLE**  
**SEMANTIC: ADOPT_CU_PROOF_FIXED_120B_ONLY**  
**SEMANTIC: ESP_STORAGE_CAPACITY_NOT_READY_R6**  
**SEMANTIC: L1_R1_SOLE_PIPELINE_NO_W1_PERMIT**  
**SEMANTIC: N6_EXACT_LANE_SET_HOP2_E2E1**  
**SEMANTIC: N6AL_ACTUAL_SIDE_ONLY**  
**SEMANTIC: N6_CAPACITY_ACTIVE_VS_RETIRED_SPLIT**  
**SEMANTIC: N6HW_NAMESPACE_GLOBAL_NO_CONTEXT_ID**  
**SEMANTIC: N6CF_DURABLE_CONTEXT_FENCE_LAYOUT**  
**SEMANTIC: N6_MULTIKEY_CU_ALL_OLD_OR_ALL_PROPOSED**  
**SEMANTIC: CLOCK_FAULT_SOLE_R2_META_FC**  
**SEMANTIC: PROFILE_AUTHORITY_EPOCH_IN_DOCUMENT**  
**SEMANTIC: ADOPT_CU_EXPLICIT_PROOF_ONLY**  
**SEMANTIC: PRIVATE_PROVE_ADOPT_AUTHORITY_EPOCH**  
**SEMANTIC: INTENT_BURN_CU_STATE_CLOSED**  

## 1. Scope

NRW1 is a **pairwise-unicast dual-envelope** radio wire freeze (docs-only).  
R7 implements codec/AEAD. Handshake remains **unimplemented** (M4/M5).

**POST_ATTACHMENT_DATA_PROFILE_ONLY / M4_JOIN_BOOTSTRAP_SEPARATE_PROFILE:**  
`wire_profile_id=0x11` is the **post-attachment data** profile only. M4 join/bootstrap frames, key exchange, and digest negotiation are a **separate freeze/profile** (not 0x11).

### 1.1 L1 Radio Coordinator vs W1 secure codec (P1(36); closed)

**L1_RADIO_COORDINATOR_CLOSED / W1_CODEC_NO_R2_R5_COMPILE_DEP / L1_W1_SEVEN_EVENT_SET_TX_RESULT / L1_R1_SOLE_PIPELINE_NO_W1_PERMIT / FRAME_READY_L1_OWNS_SEALED_CANDIDATE:**

W1 = secure codec/MAC only. L1 = sole authority for clock sample/baseline/adopt, R2 Permit issue, issued FIFO, drain, and docs/24 R1 sole pipeline (validate → consume → edge). L1 alone invokes docs/24 / R1 sole pipeline `transmit_with_permit` (validate→consume→edge). W1 MUST NOT hold Permit bytes, call R1, or invoke the radio edge. W1 **MUST NOT** sample clock; **MUST NOT** write R2 durable state.

| component | owns | MUST NOT |
| --- | --- | --- |
| **W1** | Seal/Open; after `STAMP_FIELDS` seal; emit W1→L1 events; apply L1→W1 events to local state only | epoch/watermark; sample; issue; drain; Permit; R1/edge; R2/R5 headers; own sealed candidate after FRAME_READY |
| **L1** | stamp; sole R1 caller; emit TX_RESULT / DRAIN_QUARANTINE / OWNER_TERMINAL; **after FRAME_READY branch (exact):** `E2E_BLOB` → own sealed E2E blob **without** Permit; `OUTER_FRAME` → own sealed outer and **only after** successful issue hold Permit | live inside W1 TU; pass Permit body to W1; **MUST NOT** claim Permit solely because FRAME_READY occurred |

#### 1.1.1 Closed L1↔W1 event set — exact 7 events (set-equality; no other Normative events)

**L1_W1_SEVEN_EVENT_ENVELOPE_CLOSED / L1_W1_TOKEN_SCALAR_U64 / L1_W1_W1_RESPONSE_EXACTLY_ONE / L1_W1_TERMINAL_UNIQUENESS / SEAL_FAIL_PHASE_CAUSE_CLOSED / LENGTH_CLASS_CATALOG_CLOSED / L1_W1_LOGICAL_C_HOST_VALUE_ABI:**

**Exact event set (reject any other Normative event name):**  
`1 STAMP_FIELDS` · `2 FRAME_READY` · `3 SEAL_FAIL` · `4 LENGTH_CLASS` · `5 TX_RESULT` · `6 DRAIN_QUARANTINE` · `7 OWNER_TERMINAL`.  
Abolished: `ISSUE_GRANTED`, `TRANSMIT_EDGE`, Permit-body events, wildcard/0/array token forms, owner-wide single aggregate event. **ISSUE_GRANTED and TRANSMIT_EDGE are abolished.**

**Logical C ABI (exact; every event of the 7):**  
Event payload is **in-process logical C host values**, **not** packed/serialized/radio wire bytes. Fixed-width integer fields are portable C `uintN_t` **native host values**. **No C `enum` typed fields** in any event payload — every numeric catalog uses `u8`/`u16`/`u32`/`u64` with closed numeric codes. **MUST NOT** `memcpy` / hash / serialize an event struct as wire. Only NRW1 / FRAG / LINK encoders convert numeric values to **BE** for radio bytes.

**Common envelope (exact ordered fields; every event of the 7):**

**EVENT_COMMON_ENVELOPE_BEGIN**
```text
event_schema    : u16  /* exact 1 */
event_kind      : u8   /* exact 1..7 as table below */
owner_token     : u64  /* nonzero scalar */
candidate_token : u64  /* nonzero scalar */
```
**EVENT_COMMON_ENVELOPE_END**

No token set, no sentinel 0, no multi-token payload. **Owner-wide drain** = emit one `DRAIN_QUARANTINE` **per live (owner_token, candidate_token) pair** (repeated one-event-per-pair); never one event covering a set.

**Per-prep-pair lifecycle (exact; prep pair = (`owner_token`,`candidate_token`)):**
1. Each `STAMP_FIELDS` creates **exactly one** prep pair; L1 emits `STAMP_FIELDS` **exactly once** per candidate_token. Event type set remains the closed **7**; the same event type may be reused on a **distinct** prep pair.  
2. That prep pair receives **exactly one** of `FRAME_READY` | `SEAL_FAIL` | `LENGTH_CLASS` as W1 response (except while burn `COMMIT_UNKNOWN` holds — then **no W1 response** until §9.3 classifies; post-classify response follows **BURN_CU_W1_RESPONSE_CLOSED**, not “always SEAL_FAIL”).  
3. **Borrow-close handshake (exact; STAMP_BORROW_CLOSE_HANDSHAKE / RESPONSE_OBSERVED_PRIORITY):** per-pair event processing is serialized. W1 borrow lifetime (input + exclusive mutable output slot) = STAMP accept → that exactly-one W1 response. **`response_observed=false` is an explicit higher-priority exception everywhere** (including TEMP immediate discard §1.1.1.3 and generic unissued cleanup §15.3.8): latch cancel/freeze only; **MUST NOT** free/mutate input or output slot; **MUST NOT** emit `OWNER_TERMINAL` early; **MUST NOT** start group/issue/new work; W1 **MUST** finish its exactly-one ordinary response. After response, W1 **MUST NOT** access input or output. Three-way cleanup / release tables require `response_observed=true` before releasing any input/output W1 could still borrow. If response never arrives: **bounded sticky quarantine** (no free / no reuse / no UAF); process teardown ends both sides.  
4. **Cancel/drain while response pending (exact override):**  
   - Pending receives **E2E** `FRAME_READY`: **no** new LINK group / HOP; close E2E prep internally (`E2E_TRANSFERRED_CLOSED` not reopened); release output slot **exactly once** after response_observed; close upper owner per exact cancel/drain timing; **no** E2E-pair OWNER_TERMINAL/TX_RESULT.  
   - Pending receives **OUTER** `FRAME_READY`: issue/R1 = **0**; release outer output slot only after response_observed; then DRAIN proof if required and exactly one `OWNER_TERMINAL`.  
   - Pending receives `SEAL_FAIL` / `LENGTH_CLASS`: release output slot after response_observed; then exact terminal path (prep-pair OWNER_TERMINAL; + ACK owner if LOCAL_LINK_ACK pre-group).  
   - **Do not** invent a second response; **do not** reopen `E2E_TRANSFERRED_CLOSED`.  
5. After `SEAL_FAIL` or `LENGTH_CLASS` on a prep pair (and response_observed): L1 emits prep-pair `OWNER_TERMINAL` **exactly once** for that pair; **terminal TX_RESULT forbidden** on that pair (no R1/R2 call). Permit/issue/edge 0 for that pair. Prep-pair terminal is **not** an upper-owner terminal.  
6. After `FRAME_READY` (and response_observed), branch by `frame_layer` (**FRAME_READY_LAYER_BRANCH_CLOSED**; §1.1.1.5):  
   - **`E2E_BLOB`:** E2E prep-pair success only — L1 has sole post-response access to the sealed bytes in its **caller-owned output slot** (`seal_output_token`); **Permit / R1 / TX_RESULT / OWNER_TERMINAL for that E2E pair = 0**. That prep pair transitions exactly once to internal state **`E2E_TRANSFERRED_CLOSED`** (leaves live prep-pair set / drain targets; **no** OWNER_TERMINAL/TX_RESULT event). L1 **MUST** move/adopt that exact output slot into **exactly one** admitted LINK group (if admission fails: §1.1.1.5 pre-group release). Then HOP DATA prep via `STAMP_FIELDS` with **STAMP_SEAL_INPUT_ABI** as **immutable handoff/borrow** of those sealed E2E blob bytes. Slot release is **not** at E2E transfer — only per **E2E_BLOB_RELEASE_TABLE** / Runtime slot registry. **Forbidden: routing `E2E_BLOB` → Permit / R1 / TX_RESULT.**  
   - **`OUTER_FRAME`:** sole air path is OUTER only — L1 may private-issue (R2 diagnostic, not an event) then R1 pipeline → **TX_RESULT only after R1 invoked** (§1.1.2 PRE_R1 / TX tables). After OUTER `FRAME_READY`: zero or more non-terminal `TX_RESULT`; final terminal is **exactly one** of terminal-class `TX_RESULT` **or** `OWNER_TERMINAL` — never both; never two terminals. OUTER output-slot lifetime (**OUTER_OUTPUT_SLOT_RELEASE_TABLE**): retain through issue/R1 as required (including same-Permit retry / drain uncertainty); after edge-invoked terminal R1 return + `TX_RESULT` dispatch release **exactly once**; **MUST NOT** retain old OUTER through ACK wait, fresh HOP retry, or group cleanup.  
   Duplicate W1 response / reopen of `E2E_TRANSFERRED_CLOSED` / double terminal on the same prep pair ⇒ contract violation / CORRUPT path.

| # | direction | event | exact payload | effect |
| ---: | --- | --- | --- | --- |
| 1 | L1→W1 | `STAMP_FIELDS` | common_envelope + §1.1.1.4 exact fields | creates one prep pair; W1 may seal only this pair |
| 2 | W1→L1 | `FRAME_READY` | common_envelope + §1.1.1.5 exact fields | L1 sole owner of sealed candidate (sole post-response access in L1 output slot); **not a fail path**; **branch by frame_layer** (§1.1.1.5) — E2E_BLOB ≠ Permit path |
| 3 | W1→L1 | `SEAL_FAIL` | common_envelope + §1.1.1.1 EVENT_SEAL_FAIL fields | no issue/R1 on that prep pair; then prep-pair OWNER_TERMINAL (+ ACK owner terminal if LOCAL_LINK_ACK pre-group) |
| 4 | W1→L1 | `LENGTH_CLASS` | common_envelope + §1.1.1.2 / §1.1.1.8 fields | fail-only length; not SEAL_FAIL; then prep-pair OWNER_TERMINAL (+ ACK owner terminal if LOCAL_LINK_ACK pre-group) |
| 5 | L1→W1 | `TX_RESULT` | common_envelope + §1.1.2 TX_RESULT-specific fields | **OUTER_FRAME path only**; W1 local cleanup; no R1 |
| 6 | L1→W1 | `DRAIN_QUARANTINE` | common_envelope + §1.1.1.6 exact fields | freeze new work/issue for that pair; **not** early free/terminal |
| 7 | L1→W1 | `OWNER_TERMINAL` | common_envelope + §1.1.1.7 exact fields | prep-pair terminal when no terminal TX_RESULT; not upper-owner terminal |

##### 1.1.1.1 SEAL_FAIL phase × cause (exact)

**SEAL_FAIL_PHASE_CAUSE_CLOSED / SEAL_LAYER_E2E_HOP / SEAL_PHASE_CAUSE_ALLOWED_TABLE:**

**seal_layer (closed u8):** `1 E2E` · `2 HOP`  
**seal_phase (closed u8):**  
`1 PRE_BURN_VALIDATE` · `2 E2E_COUNTER_BURN` · `3 E2E_ENCODE` · `4 E2E_AEAD` · `5 HOP_COUNTER_BURN` · `6 HOP_ENCODE` · `7 HOP_AEAD`

**seal_cause (closed u8):**  
`1 STRUCT_INVALID` · `2 CONTEXT_UNAVAILABLE` · `3 COUNTER_DEFINITE_FAILURE` · `4 COUNTER_CORRUPT` · `5 ENCODE_FAILURE` · `6 AEAD_FAILURE` · `7 OUTPUT_SHAPE` · `8 ALIAS_OR_INTERNAL_CONTRACT`

**Layer binding (exact):** seal_phase `2..4` ⇒ seal_layer **MUST** be `1 E2E`; seal_phase `5..7` ⇒ seal_layer **MUST** be `2 HOP`; seal_phase `1 PRE_BURN_VALIDATE` requires **explicit** seal_layer ∈ {1,2} (no default).

**SEAL_FAIL payload ABI (exact; common envelope carries owner_token/candidate_token only — not repeated here):**

**EVENT_SEAL_FAIL_FIELDS_BEGIN**
```text
seal_layer         : u8   /* 1 E2E | 2 HOP */
seal_phase         : u8   /* 1..7 closed */
seal_cause         : u8   /* 1..8 closed */
burn_state         : u8   /* 0 NONE | 1 E2E | 2 HOP | 3 AMBIGUOUS */
counter_value_or_0 : u64  /* 0 if not a definite consumed counter; else burned counter 1..UINT64_MAX-1 */
e2e_len_valid      : u8   /* 0|1 */
expected_e2e_len   : u16
observed_e2e_len   : u16
outer_len_valid    : u8   /* 0|1 */
expected_outer_len : u16
observed_outer_len : u16
```
**EVENT_SEAL_FAIL_FIELDS_END**

**SEAL_FAIL field rules (exact):**
- PRE_BURN_VALIDATE and E2E/HOP_COUNTER_BURN **definite pre-write** failure (`COUNTER_DEFINITE_FAILURE` or pre-write `COUNTER_CORRUPT`): `burn_state=0 NONE` and `counter_value_or_0=0` (durable counter **not** consumed).
- E2E_ENCODE / E2E_AEAD: `burn_state=1 E2E` and `counter_value_or_0` **equals** the burned E2E counter (∈ 1..UINT64_MAX-1).
- HOP_ENCODE / HOP_AEAD: `burn_state=2 HOP` and `counter_value_or_0` **equals** the burned hop counter for the **prep lane** (**HOP_COUNTER_LANE_CLOSED**): `owner_class≠LOCAL_LINK_ACK` / length_class 1..4 ⇒ **DATA lane**; `owner_class=LOCAL_LINK_ACK` / length_class=5 ⇒ **ACK lane**. Forbidden: blanket “always hop DATA counter”.
- **CU THIRD/CORRUPT provenance** (§9.3 recovery after burn COMMIT_UNKNOWN): `burn_state=3 AMBIGUOUS`, `counter_value_or_0=0` where **0 means “no exact counter identity”** — **not** “durable mutation zero”. Rollback/reuse of the ambiguous write-set is forbidden; namespace/context fence. Forbidden: asserting `NONE` / unmutated durable for CU THIRD.
- Length validity by `seal_layer` only (**SEAL_FAIL_LEN_VALID_BY_LAYER**; both valid=1 forbidden):
  - `seal_layer=E2E` ⇒ `outer_len_valid=0` and `expected_outer_len=observed_outer_len=0`. `e2e_len_valid=1` **iff** both expected and actual E2E sealed-blob lengths are exactly obtainable; else `e2e_len_valid=0` and `expected_e2e_len=observed_e2e_len=0`.
  - `seal_layer=HOP` ⇒ `e2e_len_valid=0` and `expected_e2e_len=observed_e2e_len=0`. `outer_len_valid=1` **iff** both expected and actual final outer lengths are exactly obtainable; else `outer_len_valid=0` and `expected_outer_len=observed_outer_len=0`.
- Unrelated side **MUST NOT** carry non-zero lengths. Forbidden: any “may remain valid on both layers” exception.
- On SEAL_FAIL: L1 releases its `seal_output_token` slot **exactly once** only after `response_observed=true` (slot may be zeroized/unused; W1 never owns the allocator).

**Phase / burn invariants (provenance-closed):**
| seal_phase / provenance | burn_state (u8) | notes |
| ---: | --- | --- |
| PRE_BURN_VALIDATE | 0 NONE | no durable counter burn; counter_value_or_0 = 0 |
| E2E_COUNTER_BURN + COUNTER_DEFINITE_FAILURE / pre-write COUNTER_CORRUPT | 0 NONE | definite fail **before** durable assign; counter not consumed |
| HOP_COUNTER_BURN + COUNTER_DEFINITE_FAILURE / pre-write COUNTER_CORRUPT | 0 NONE | definite fail **before** durable hop assign; lane counter **not** consumed |
| E2E_ENCODE / E2E_AEAD | 1 E2E | E2E durable counter consumed |
| HOP_ENCODE / HOP_AEAD | 2 HOP | hop lane counter consumed (DATA or ACK per matrix) |
| BURN_CU §9.3 THIRD/CORRUPT | 3 AMBIGUOUS | value0 = no exact counter; durable mutation **not** asserted zero; fence |

**Allowed seal_phase × seal_cause (closed; any other pair forbidden):**

| seal_phase | allowed seal_cause (exact set) |
| --- | --- |
| PRE_BURN_VALIDATE | STRUCT_INVALID, CONTEXT_UNAVAILABLE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT |
| E2E_COUNTER_BURN | COUNTER_DEFINITE_FAILURE, COUNTER_CORRUPT |
| E2E_ENCODE | ENCODE_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT |
| E2E_AEAD | AEAD_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT |
| HOP_COUNTER_BURN | COUNTER_DEFINITE_FAILURE, COUNTER_CORRUPT |
| HOP_ENCODE | ENCODE_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT |
| HOP_AEAD | AEAD_FAILURE, OUTPUT_SHAPE, ALIAS_OR_INTERNAL_CONTRACT |

**Cause duty (exact):** `OUTPUT_SHAPE` = NULL pointer / capacity / buffer shape only — **not** numeric length under/over/exact and **not** alias. `ALIAS_OR_INTERNAL_CONTRACT` = alias / ownership / internal contract only (incl. input/output span overlap). **Numeric length under/over/exact mismatch** is **LENGTH_CLASS only** (not SEAL_FAIL). §9.3 CU outcome names (`RETRY_LATER`,`ALL_PROPOSED`,`ALL_OLD`,`THIRD`) are **not** seal_cause values.

**BURN_CU_W1_RESPONSE_CLOSED (post §9.3 classification of burn COMMIT_UNKNOWN; exact):** while burn CU is open, **do not** emit SEAL_FAIL (and emit **no** W1 response). Forbidden: any blanket rule that “classification後必ずSEAL_FAIL”. Cross-check §15.3.7 INTENT_BURN_CU.

| §9.3 class | W1 response (immediate) | L1/W1 next state (exact) |
| --- | --- | --- |
| RETRY_LATER | none | remain BURN_CU; hold resources; TX/ACK 0 |
| ALL_PROPOSED | none | install proposed counter/RAM **exactly once**; E2E→E2E_ENCODE, HOP→HOP_ENCODE; FRAG_ACK intent→INTENT_SEAL; ordinary exactly-one response only after resumed encode/AEAD completes; **FIRST_FRAG_START_TEMPLATE**: inject proven proposed C as u64 BE into output work copy |
| ALL_OLD | none | restore pre-state; retry same preparation burn entry (same template/input); FRAG_ACK→INTENT_RESERVE; no new candidate/token/preparation |
| THIRD/CORRUPT | SEAL_FAIL **exactly once** | active E2E/HOP_COUNTER_BURN, cause COUNTER_CORRUPT, burn_state **AMBIGUOUS** (u8=3), value0 (=no exact counter, not durable-zero), corrupt/namespace fence; no rollback/reuse |

**Next-state (exact closed fail split; SEAL_FAIL_NEXT_STATE_LAYER_SPLIT):**
- **E2E fail** ⇔ (`seal_phase=1 PRE_BURN_VALIDATE` ∧ `seal_layer=E2E`) **or** `seal_phase` ∈ {2,3,4} (**SEAL_FAIL_E2E_DEFINITE_VS_POSTBURN_SPLIT**):  
  - **Pre-burn / definite allocation fail** (`PRE_BURN_VALIDATE` or `E2E_COUNTER_BURN` with `COUNTER_DEFINITE_FAILURE` / pre-write `COUNTER_CORRUPT`; burn_state NONE; burn count/counter mutation 0): terminally fails the owning fragmented transfer or SINGLE; **no** fresh prep, **no** retry; first-START `transfer_handle` remains **unset** (P1-5 / §15.1).  
  - **CU THIRD/CORRUPT** (burn_state AMBIGUOUS): fence + terminal; **no** retry; **no** invented handle.  
  - **Post-burn only** (`E2E_ENCODE` / `E2E_AEAD`, or `E2E_POST_SEAL` LENGTH_CLASS): FRAG may schedule a fresh bounded E2E prep if budget/deadline allow; SINGLE → prep-pair OWNER_TERMINAL (terminal).  
- **HOP fail** ⇔ (`seal_phase=1 PRE_BURN_VALIDATE` ∧ `seal_layer=HOP`) **or** `seal_phase` ∈ {5,6,7}. The **failed HOP prep pair is unusable**. Terminal branch by group existence (**HOP_FAIL_TERMINAL_BY_GROUP_EXISTENCE**):  
  - **`owner_class=LOCAL_LINK_ACK` and pre-group** (`group_deadline_valid=0`; no admitted LINK group): prep-pair terminal **and** ACK owner terminal; **no** LINK group terminal (there is no group). Forbidden: inventing a LINK group for LOCAL_LINK_ACK pre-group fail.  
  - **Any HOP owner with an admitted LINK group** (`group_deadline_valid=1`): **HOP_OUTER_FAIL_SAME_GROUP_STRICT_TERMINAL** — that LINK group is **strict terminal** for seal/encode/AEAD failure replacement — **no** another hop prep, **no** replacement outer, **no** same-group reuse of that failed outer attempt inside the failed group.  
  Durable hop burn presence is **separate:** phase **1 or 5** ⇒ burn_state NONE / counter not consumed; phase **6 or 7** ⇒ HOP durable counter **was** consumed. Forbidden: calling phase **5** “hop prep is burned” as durable-counter language; forbidden blanket “all HOP fail = same LINK group strict terminal” without group-existence check.  
- **LINK_ACK timeout retry after a successful air TX** (Permit consume + TX edge done, then ACK timeout) is **not** seal/encode/AEAD failure replacement: same LINK group + **bit-identical E2E blob** retained; L1 **MAY** open a **fresh HOP prep** with **fresh hop DATA counter** and **fresh outer** (§11.2 / §12 / §15.2 `LINK_RETRY_SAME_E2E_BLOB`). Forbidden wording: “same already-emitted outer”.  
- Later **E2E fragment retry** (budget remains) **MUST** use fresh E2E counter/blob + **new** LINK group.  
- No issue/R1 on any SEAL_FAIL. Partial bytes discarded and zeroized; Permit/issue/TX **0** for the failed prep pair.

##### 1.1.1.2 LENGTH_CLASS catalog (exact; not SEAL_FAIL)

**LENGTH_CLASS_ABI_CLOSED / LENGTH_CLASS_ENUM_CLOSED / CHECK_PHASE_ENUM_CLOSED / LENGTH_PHASE_TABLE_CLOSED:**

**Domains (exact headers; old “E2E PT domain” abolished):**  
`E2E sealed blob domain (bytes)` · `final outer frame domain (bytes)`.

| class | E2E sealed blob domain (bytes) | final outer frame domain (bytes) |
| --- | --- | --- |
| `DATA_SINGLE` | 31..220 | 66..255 |
| `DATA_FRAG_START` | 95..220 | 130..255 |
| `DATA_FRAG_CONT` | 41..220 | 76..255 |
| `DATA_FRAG_ACK` | 44 exact | 79 exact |
| `LINK_ACK` | N/A | 51 exact |

**length_class (closed u8; names match size catalog class column exactly; wire type high-nibble `FRAG_START`/`FRAG_CONT`/`FRAG_ACK` are a distinct frame-type concept and are not length_class tokens):**  
`0 UNCLASSIFIED` · `1 DATA_SINGLE` · `2 DATA_FRAG_START` · `3 DATA_FRAG_CONT` · `4 DATA_FRAG_ACK` · `5 LINK_ACK`

**check_phase (closed u8):**  
`1 E2E_PRE_BURN_COMPUTE` · `2 E2E_POST_SEAL` · `3 OUTER_PRE_BURN_COMPUTE` · `4 OUTER_POST_SEAL`

**LENGTH_CLASS fields:** see §1.1.1.8 exact field block (fixed widths only).

**check_phase table (exact):**

| check_phase | allowed length_class | checked length formula | burn_state | disposition |
| --- | --- | --- | --- | --- |
| E2E_PRE_BURN_COMPUTE | 1..4 or UNCLASSIFIED(0) | 14+PT+16 | NONE | current prep-pair terminal; no counter issue; no same candidate retry |
| E2E_POST_SEAL | 1..4 actual E2E sealed blob | actual sealed blob len | E2E | current prep-pair terminal; FRAG only may open fresh bounded E2E prep; SINGLE terminal |
| OUTER_PRE_BURN_COMPUTE | 1..5 or UNCLASSIFIED(0) | 19+HopPT+16 | NONE | if admitted LINK group: group terminal + no replacement outer; if LOCAL_LINK_ACK pre-group: prep-pair + ACK owner terminal (no group) |
| OUTER_POST_SEAL | 1..5 actual final outer | actual final outer len | HOP | if admitted LINK group: group terminal + no replacement outer; if LOCAL_LINK_ACK pre-group: prep-pair + ACK owner terminal (no group) |

**burn_state** is the **own layer** of the failing check (E2E phases → E2E or NONE; outer phases → HOP or NONE). On LENGTH_CLASS: release L1 output slot after response_observed.

**observed canonicalization (Normative; LENGTH_OBSERVED_CANONICAL_CLOSED):**
- `observed_valid` ∈ {0,1}.
- `observed_valid=0` **iff** the observed length is **unobtainable** (cannot be acquired as a definite byte length for this check — including arithmetic overflow, type unclassifiable, missing buffer, or other acquisition failure).
- `observed_valid=0` ⇒ `observed=0` (canonical zero fill; never leave a stale non-zero observed with valid=0).
- `observed_valid=1` ⇒ `observed` is the **exact computed or measured byte length** for this check (pre-burn formula result or post-seal actual sealed/outer length).
- `ARITHMETIC_OVERFLOW` ⇒ `observed_valid=0` and `observed=0` always.
- `TYPE_UNCLASSIFIABLE` **iff** (`length_class=0` ∧ `expected_min=expected_max=0` ∧ check_phase ∈ {E2E_PRE_BURN_COMPUTE, OUTER_PRE_BURN_COMPUTE}); conversely that triple ⇒ `TYPE_UNCLASSIFIABLE` with `observed_valid=0` and `observed=0`.
- All other causes require `observed_valid=1`, `length_class` ∈ 1..5, and `observed` equal to the exact computed/measured length used for the min/max compare.
- Forbidden: “only sometimes when” `observed_valid=0`; forbidden non-zero `observed` while `observed_valid=0`.

**LINK_ACK** is **forbidden** on E2E check phases (E2E_PRE / E2E_POST).  
Duty separation: SEAL_FAIL never encodes length under/over as primary cause; LENGTH_CLASS never encodes AEAD/encode/struct as primary cause.

##### 1.1.1.3 radio_volatile_work (closed set; CLOCK TEMP/UNCERTAIN discard)

**RADIO_VOLATILE_WORK_CLOSED / TEMP_UNCERTAIN_DISCARD_ALL_VOLATILE / RADIO_VOLATILE_WORK_SET_EQUALITY:**

**Exact closed set (set-equality; no aggregate “forwarding/ingress” token):**
```text
radio_volatile_work = {
  candidate,
  Permit snapshot,
  LINK group,
  prep,
  timer row,
  sealed blob,
  outgoing SINGLE item,
  forwarding queue item,
  endpoint E2E ingress queue item,
  upper-transport queue item,
  fragment sender/reassembly state,
  tombstone/reservation,
  ACK coalesce/control reserve,
  ACK intent/ledger
}
```
**14 members exact.** Ambiguous combined “forwarding/ingress queue item” is **abolished** and split into **forwarding queue item** + **endpoint E2E ingress queue item**. Cross-check §13 resource rows (forwarding queue, endpoint E2E ingress queue, upper-transport queue) and §15.3.3.1 all-owner discard.

On TEMP/CLOCK_UNCERTAIN: discard **every** member of `radio_volatile_work` across **all** owners (not only the failing owner) — **except** where `response_observed=false` holds for a live prep pair (**RESPONSE_OBSERVED_PRIORITY**): then latch freeze only for that pair’s input/output slots; complete W1 response first; free only after response_observed.  
- proven-unissued → immediate discard (subject to response_observed exception)  
- issued/ambiguous → quarantine → global drain §15.3.3 → discard  
- consume+edge done → STALE_NO_RETRY → local ref discard  
**MUST NOT** roll back durable counter/replay/N6/R2 meta on TEMP. Retainable after discard: only higher application owner/data **not yet admitted** into R6. Later same-epoch class-D allows **fresh** burn/stamp/seal/issue only (new tokens/counters); no old candidate/Permit resume.

##### 1.1.1.4 STAMP_FIELDS exact payload (EVENT_STAMP_FIELDS)

**Logical ordered C host-value payload (not serialized radio wire bytes).** Borrow spans: non-NULL pointers + exact `u16` lengths; no LE/BE packing of the event itself.

**EVENT_STAMP_FIELDS_BEGIN**
```text
common_envelope
prep_layer                 : u8  /* 1 E2E | 2 HOP */
owner_class                : u8  /* 1..5 closed below */
stamp_now_mono             : u64 /* accepted R2 sample now_ms only */
enclosing_owner_deadline   : u64
group_deadline_valid       : u8  /* 0|1 */
group_absolute_deadline    : u64 /* meaningful iff group_deadline_valid=1; else 0 */
e2e_attempt_start_valid    : u8  /* 0|1 */
e2e_attempt_start_mono     : u64 /* meaningful iff e2e_attempt_start_valid=1; else 0 */
requested_length_class     : u8  /* 1..5 closed; never 0 */
seal_input_kind            : u8  /* 1 E2E_PLAINTEXT | 2 E2E_BLOB | 3 LINK_ACK_PLAINTEXT | 4 FIRST_FRAG_START_TEMPLATE */
seal_input_token           : u64 /* L1-minted nonzero unique live borrow */
seal_input_len             : u16 /* exact byte length of seal_input_bytes */
seal_input_bytes           : borrowed immutable const uint8_t* /* non-NULL; + seal_input_len */
seal_output_token          : u64 /* L1-minted nonzero unique live output slot */
seal_output_capacity       : u16 /* exact precomputed required sealed output length */
seal_output_bytes          : exclusive mutable borrowed uint8_t* /* non-NULL; capacity bytes */
seal_context_handle        : u64 /* nonzero installed W1 OUTBOUND context handle; never a raw pointer */
outer_ack_requested        : u8  /* 0|1; HOP DATA only meaningful; else 0 */
outer_hop_remaining        : u8  /* HOP DATA only; else 0 */
outer_route_handle         : u16 /* HOP DATA only; else 0 */
outer_route_generation     : u16 /* HOP DATA only; else 0 */
```
**EVENT_STAMP_FIELDS_END**

**owner_class (closed u8):**  
`1 LOCAL_SINGLE` · `2 LOCAL_FRAGMENT` · `3 RELAY_DATA` · `4 LOCAL_FRAG_ACK` · `5 LOCAL_LINK_ACK`

**owner_class × prep_layer × group / seal_input / requested_length_class / lane (exact closed; STAMP_OWNER_PREP_MATRIX_CLOSED; all other combinations STAMP reject before burn):**

| owner_class | prep_layer | group_deadline_valid | seal_input_kind | requested_length_class | hop_counter_lane |
| --- | --- | ---: | --- | --- | --- |
| LOCAL_SINGLE | E2E | 0 | E2E_PLAINTEXT | 1 | N/A |
| LOCAL_SINGLE | HOP | 1 | E2E_BLOB | 1 | DATA |
| LOCAL_FRAGMENT | E2E | 0 | FIRST_FRAG_START_TEMPLATE | 2 | N/A |
| LOCAL_FRAGMENT | E2E | 0 | E2E_PLAINTEXT | 2 | N/A |
| LOCAL_FRAGMENT | E2E | 0 | E2E_PLAINTEXT | 3 | N/A |
| LOCAL_FRAGMENT | HOP | 1 | E2E_BLOB | 2 or 3 | DATA |
| RELAY_DATA | HOP | 1 | E2E_BLOB | 1..4 | DATA |
| LOCAL_FRAG_ACK | E2E | 0 | E2E_PLAINTEXT | 4 | N/A |
| LOCAL_FRAG_ACK | HOP | 1 | E2E_BLOB | 4 | DATA |
| LOCAL_LINK_ACK | HOP | 0 | LINK_ACK_PLAINTEXT | 5 | ACK |

Invalid combination (incl. DATA owner→class5, LOCAL_LINK_ACK→class1..4, E2E prep wrong class/layer, `FIRST_FRAG_START_TEMPLATE` outside first START class2, `E2E_PLAINTEXT` class2 used as first START without prior handle) ⇒ STAMP reject; burn/Seal/Permit/TX **0**; candidate safe terminal. `group_deadline_valid` **MUST** equal the table cell.

**STAMP_SEAL_INPUT_ABI + STAMP_SEAL_OUTPUT_SLOT_ABI (exact):**
- `seal_input_kind` closed: `1 E2E_PLAINTEXT` · `2 E2E_BLOB` · `3 LINK_ACK_PLAINTEXT` · `4 FIRST_FRAG_START_TEMPLATE`.
- `seal_input_token`: L1-minted **u64 nonzero**, unique among live borrows, never reused after release.
- `seal_input_bytes` / `seal_input_len`: borrowed immutable exact span (C: non-NULL `const uint8_t*` + `u16`); length/type-specific domain matches `requested_length_class` and kind.
- **Caller-owned output slot (exact; no ambiguous ownership transfer):** L1 owns the bounded Runtime slot throughout (registry keyed by `seal_output_token`; not implicit malloc/free by W1). W1 receives **exclusive mutable borrow** of `seal_output_bytes` only from STAMP accept until exactly-one W1 response. `seal_output_capacity` = exact precomputed sealed length for this prep. Input and output spans **MUST NOT** overlap/alias.
- `seal_context_handle`: **u64 nonzero** handle (never a pointer) of exactly one live installed W1 OUTBOUND context for layer/direction/context_id/membership_epoch/key_generation/lane; never reused for a different install in Runtime lifetime; W1 validates before burn.
- Exact input mapping:
  - E2E `LOCAL_SINGLE` / CONT / FRAG_ACK / E2E fragment **retry** START → `E2E_PLAINTEXT`; body length/type per class; outer_* all **0**.
  - E2E **first** FRAG_START only → `FIRST_FRAG_START_TEMPLATE` class2: immutable template has `transfer_handle` octets **16..23 exact zero**; after durable burn W1 copies template into **output work** and injects burned `e2e_counter` as **u64 BE** into that copy as `transfer_handle`; **source remains immutable**; Seal that derived final PT. First burn CU `ALL_PROPOSED` injects proven proposed C; `ALL_OLD` retries same template burn entry; `THIRD` fences. E2E START **retry after first** uses `E2E_PLAINTEXT` carrying original **nonzero** `transfer_handle`; fresh `e2e_counter` **MUST NOT** overwrite handle.
  - HOP DATA owners → `E2E_BLOB` exact sealed bytes (local FRAME_READY slot or relay-owned); DATA lane; outer_ack_requested / hop_remaining / route_handle / route_generation **exact**.
  - LOCAL_LINK_ACK HOP → `LINK_ACK_PLAINTEXT` **exact 16 bytes**; ACK lane; `outer_ack_requested=0`, route=0, generation=0, remaining=0.
- W1 **immutable input borrow + exclusive mutable output borrow** lifetime = STAMP accept → that HOP/E2E prep pair’s **exactly one** W1 response; W1 **MUST NOT** retain/free/mutate/alias/re-emit bytes or tokens after response. Cross-check STAMP_BORROW_CLOSE_HANDSHAKE.

**Stamp rules (exact):** `stamp_now_mono` = accepted R2 `now_ms` only; W1 **MUST NOT** carry epoch_id/watermark; unused outer fields **0** when not HOP DATA; `e2e_attempt_start_valid=1` **iff** prep_layer=E2E; stamp before all valid deadlines; E2E and HOP `candidate_token` are distinct and non-reusable across layers.

##### 1.1.1.5 FRAME_READY exact payload (EVENT_FRAME_READY)

**EVENT_FRAME_READY_BEGIN**
```text
common_envelope
frame_layer       : u8   /* 1 E2E_BLOB | 2 OUTER_FRAME */
length_class      : u8   /* 1..5; never 0 UNCLASSIFIED */
burn_state        : u8   /* 1 E2E | 2 HOP */
counter_value     : u64  /* exact domain 1..UINT64_MAX-1; reject 0 and UINT64_MAX */
seal_output_token : u64  /* same STAMP output token; L1 slot registry key */
sealed_len        : u16  /* MUST equal STAMP seal_output_capacity */
```
**EVENT_FRAME_READY_END**

**No `sealed_bytes` pointer / owned-bytes transfer field.** L1 accesses sealed bytes only via its own Runtime slot registry by `seal_output_token` after response. W1 access to the slot ends before response returns. FRAME_READY means L1 has **sole post-response access/ownership** of the sealed content in that L1-owned slot; W1 never owns the allocator slot.

**frame_layer × length_class × burn_state (exact):**

| frame_layer | length_class | burn_state (u8) | domain |
| --- | --- | --- | --- |
| E2E_BLOB | 1..4 | 1 E2E | E2E sealed blob in L1 output slot |
| OUTER_FRAME | 1..5 | 2 HOP | final outer frame in L1 output slot |

**counter_value (exact):** domain **1..UINT64_MAX-1** only; **0** and **UINT64_MAX** are reject (aligned with §9 counter assignable domain).

**Embedded counter binding (exact; FRAME_READY_COUNTER_EMBEDDED_BINDING / HOP_COUNTER_LANE_CLOSED):**
- `frame_layer=E2E_BLOB` ⇒ `counter_value` **MUST** be bit-exact equal to the `e2e_counter` field inside the E2E header of the sealed bytes in the L1 output slot.
- `frame_layer=OUTER_FRAME` and `length_class` ∈ 1..4 ⇒ `counter_value` **MUST** equal hop **DATA** lane `hop_counter` in the outer header.
- `frame_layer=OUTER_FRAME` and `length_class=5` (`LINK_ACK`) / `owner_class=LOCAL_LINK_ACK` ⇒ `counter_value` **MUST** equal hop **ACK** lane counter in the outer header (not DATA lane).
- On mismatch, field-parse failure, or `sealed_len ≠ seal_output_capacity`: **internal contract violation** — Permit/issue/R1/TX_RESULT = **0**; safely terminal that prep pair; zeroize/release L1 output slot **exactly once** after response_observed; **MUST NOT** emit a corrective second FRAME_READY on the same prep pair (**no second FRAME_READY**).

**STAMP→FRAME match (exact; FRAME_STAMP_CROSS_PRODUCT_CLOSED):**
- E2E prep STAMP ⇒ FRAME `E2E_BLOB`; HOP STAMP ⇒ FRAME `OUTER_FRAME`.
- FRAME `length_class` **MUST equal** STAMP `requested_length_class` (exact).
- FRAME `seal_output_token` **MUST equal** STAMP `seal_output_token`; `sealed_len` **MUST equal** STAMP `seal_output_capacity`.
- owner_class / prep_layer / seal_input_kind / hop lane / burn_state **MUST** match STAMP matrix.
- Explicit reject: DATA owner→class5, LOCAL_LINK_ACK→class1..4, E2E owner wrong class/layer, class/layer mismatch. **No** corrective second W1 response.

**Ownership + layer branch (exact; FRAME_READY_LAYER_BRANCH_CLOSED):** L1 sole post-response access **exactly once** at FRAME_READY for that prep pair; W1 **MUST NOT** read/mutate/free/alias/re-emit sealed slot bytes after emit. Payload block **MUST NOT** carry `epoch_id` or `watermark`.  
- **E2E_BLOB** (matched STAMP; embedded equal): L1 sole access to slot; **Permit / R1 / TX_RESULT / OWNER_TERMINAL for that E2E pair = 0**; prep pair → **`E2E_TRANSFERRED_CLOSED`** exactly once (not an event). L1 moves/adopts that exact slot into exactly one admitted LINK group; HOP DATA prep uses `seal_input_kind=E2E_BLOB` (relay same).  
- **OUTER_FRAME** only (matched STAMP; lane-correct embedded counter): private R2 issue (diagnostic) → R1 → `TX_RESULT` (§1.1.2). OUTER output-slot lifetime follows **OUTER_OUTPUT_SLOT_RELEASE_TABLE** (not group cleanup / not ACK wait). Mismatch: prep-pair terminal; admitted group ⇒ group terminal; LOCAL_LINK_ACK pre-group ⇒ ACK owner terminal (no group; **no E2E blob**).

**E2E_BLOB_RELEASE_TABLE (exact; sole release authority for E2E sealed slot; set-equality; requires response_observed=true before any yes):**

| event / state | release L1-owned E2E sealed slot (`seal_output_token`)? |
| --- | --- |
| E2E FRAME_READY sole post-response access / E2E_TRANSFERRED_CLOSED | **no** (slot adopted into LINK group or pre-group path) |
| cancel/drain pending received E2E FRAME_READY (no new LINK/HOP) | **yes, exactly once** after response_observed; close upper owner per cancel/drain |
| LINK group admission / copy-own / deadline checked_add **fail** before admitted group (pre-group fail; no pending W1 borrow) | **yes, exactly once** (then close upper owner internally; HOP STAMP/Permit/TX=0; **no** E2E-pair OWNER_TERMINAL/TX_RESULT) |
| HOP STAMP borrow / HOP OUTER FRAME_READY success | **no** |
| TX_EDGE_DONE with ACK_REQUESTED=1 (pair closed; group WAIT_LINK_ACK) | **no** |
| TX_EDGE_DONE with ACK_REQUESTED=0 until sibling/borrow cleanup complete | **no** until group/sibling cleanup |
| non-terminal R1 retry TX_RESULT (`TX_RETRY_SAME_PERMIT`) | **no** |
| non-terminal quarantine TX_RESULT (`TX_QUARANTINE`) | **no** until drain/proof cleanup |
| LINK_ACK timeout → fresh HOP DATA retry (same group, same blob) | **no** |
| individual OUTER prep terminal without group cleanup complete | **no** |
| LINK group cleanup complete: ACK accepted | **yes, exactly once** |
| LINK group cleanup complete: ack_requested=0 policy success (UNACKED_LINK_SUCCESS) after sibling/borrow cleanup | **yes, exactly once** |
| LINK group cleanup complete: retry exhaustion / drop / drain / cancel / owner terminal | **yes, exactly once** |
| LOCAL_LINK_ACK path | **n/a** (no E2E blob) |
| SEAL_FAIL / LENGTH_CLASS after response_observed | **yes, exactly once** (output slot unused/zeroized) |
| response never arrives (bounded sticky quarantine) | **no free** until process teardown; no reuse / no UAF |

Forbidden: early release on OUTER success terminal alone for **E2E** blob; release while ACK wait/timeout/fresh-HOP retry still needs the **E2E** blob; free while W1 borrow pending (`response_observed=false`); double release; W1 free of L1 slot. OUTER frame slots use **OUTER_OUTPUT_SLOT_RELEASE_TABLE** (distinct).

**OUTER_OUTPUT_SLOT_RELEASE_TABLE (exact; sole release authority for OUTER frame `seal_output_token`; set-equality; requires response_observed=true before any yes):**

| event / state | release L1-owned OUTER sealed slot? |
| --- | --- |
| STAMP accepted / W1 response pending | **no**; if response never arrives: no free until process teardown (sticky quarantine) |
| cancel/drain pending then OUTER FRAME_READY | **yes, exactly once** after response_observed; issue/R1 = **0** |
| OUTER FRAME_READY normal success | **no** — retain for issue/R1 |
| PRE_R1 RETRYABLE_UNISSUED | **no** — retain same slot/candidate |
| PRE_R1 TERMINAL_UNISSUED | **yes, exactly once** after response_observed / safe sibling cleanup |
| PRE_R1 drain classes (CLOCK_PATH_DROP / RECONCILE / AUTHORITY / EPOCH / OPERATOR) | **no** until drain/proof; then **yes, exactly once** with terminal cleanup |
| TX_RETRY_SAME_PERMIT | **no** — retain same exact outer slot |
| TX_QUARANTINE | **no** until drain/proof; then **yes, exactly once** with terminal cleanup |
| TX_EDGE_DONE (ACK0 or ACK1) after synchronous R1 return + TX_RESULT dispatch | **yes, exactly once** (OUTER only; E2E group blob separate per E2E_BLOB_RELEASE_TABLE; ACK1 **MUST NOT** retain old OUTER; ACK timeout fresh HOP allocates **fresh** OUTER slot) |
| TX_STALE_NO_RETRY / EDGE_ERROR after edge | **yes, exactly once** after R1 return + TX_RESULT dispatch |
| LOCAL_LINK_ACK | same pair result rules; **no** E2E blob/group |
| SEAL_FAIL / LENGTH_CLASS / FRAME mismatch after response_observed | **yes, exactly once** |

Forbidden: release during R1 / same-Permit retry / drain uncertainty; retain old OUTER through ACK wait or fresh HOP retry; double release; free while `response_observed=false`.

##### 1.1.1.6 DRAIN_QUARANTINE exact payload (EVENT_DRAIN_QUARANTINE)

**Logical ordered C host-value payload.**  
**EVENT_DRAIN_QUARANTINE_BEGIN**
```text
common_envelope
drain_disposition : u8  /* 1 QUARANTINED exact */
drain_reason      : u8  /* 1 AMBIGUOUS_OR_FENCE | 2 OPERATOR | 3 RECOVERY */
```
**EVENT_DRAIN_QUARANTINE_END**  
Freezes new work/issue for that prep pair only; **MUST NOT** free borrowed inputs or output slots or emit OWNER_TERMINAL until response_observed (§1.1 STAMP_BORROW_CLOSE_HANDSHAKE). After drain/proof completes, emit exactly one `OWNER_TERMINAL` when that is the terminal path.

##### 1.1.1.7 OWNER_TERMINAL exact payload (EVENT_OWNER_TERMINAL)

**EVENT_OWNER_TERMINAL_BEGIN**
```text
common_envelope
terminal_kind : u8  /* 1 TERMINAL | 2 STALE_NO_RETRY */
```
**EVENT_OWNER_TERMINAL_END**

##### 1.1.1.8 LENGTH_CLASS exact payload (EVENT_LENGTH_CLASS)

**EVENT_LENGTH_CLASS_BEGIN**
```text
common_envelope
length_class       : u8  /* 0..5 closed §1.1.1.2 */
check_phase        : u8  /* 1..4 closed */
expected_min       : u16
expected_max       : u16
observed           : u16
observed_valid     : u8  /* 0|1 */
burn_state         : u8  /* 0 NONE | 1 E2E | 2 HOP */
counter_value_or_0 : u64 /* 0 if burn_state=NONE; else exact burned layer/lane counter 1..UINT64_MAX-1 */
length_cause       : u8  /* 1 UNDER_MIN | 2 OVER_MAX | 3 EXACT_MISMATCH | 4 ARITHMETIC_OVERFLOW | 5 TYPE_UNCLASSIFIABLE */
```
**EVENT_LENGTH_CLASS_END**

**LENGTH counter rules (exact):**
- `burn_state=0 NONE` ⇒ `counter_value_or_0=0`.
- `burn_state=1 E2E` or `2 HOP` ⇒ `counter_value_or_0` = exact burned layer/lane counter ∈ **1..UINT64_MAX-1**.
- `0` while burn_state ≠ NONE, `UINT64_MAX`, or mismatch ⇒ invalid event / contract violation.

**FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED (exact):**  
For first `FIRST_FRAG_START_TEMPLATE` only: once a **definite E2E burn** exists, L1 latches `original transfer_handle` **exactly once** from the **response counter** (`FRAME_READY.counter_value` / SEAL_FAIL or LENGTH `counter_value_or_0` when burn_state=E2E) **before** releasing/zeroizing any output slot. Applies to:
- `FRAME_READY` (E2E success),
- post-burn `SEAL_FAIL` (`E2E_ENCODE`/`E2E_AEAD`),
- `E2E_POST_SEAL` `LENGTH_CLASS`.
Later retry uses `E2E_PLAINTEXT` with that original **nonzero** handle; fresh counters **MUST NOT** overwrite it. **Forbidden:** parse a failed/mismatched output slot to recover handle. Pre-burn failure leaves handle **unset** and follows P1-5 terminal. CU AMBIGUOUS **cannot** invent a handle (fence/terminal). For non-first/retry E2E plaintext, response counter never overwrites existing `transfer_handle`.

#### 1.1.2 TX_RESULT + PRE_R1 issue next-action (exact)

**PRE_R1_ISSUE_NEXT_ACTION (closed set-equality vs §15.3.2 L1 result class tokens; R2 private issue diagnostic — not a 7-event):**

| L1 result class (§15.3.2 exact token) | legal phase | event of the 7 | L1 next (exact) |
| --- | --- | --- | --- |
| OK_ISSUED | pre-R1 issue success | **none** | enter R1 sole pipeline on same sealed outer + same Permit |
| RETRYABLE_UNISSUED | pre-R1 issue | **none** | L1 re-enters **issue only** on same sealed candidate (retains sealed outer/output slot; no re-stamp/re-seal) |
| TERMINAL_UNISSUED | pre-R1 issue | OWNER_TERMINAL | drop pair; Permit/TX 0; release outer slot after response_observed/sibling cleanup; **TX_RESULT is forbidden** there |
| CLOCK_PATH_DROP | pre-R1 issue | DRAIN_QUARANTINE then exactly one OWNER_TERMINAL after drain/proof | discard all old volatile **borrow-safe** (response_observed priority); later = fresh burn/stamp/seal/issue; **TX_RESULT is forbidden** |
| RECONCILE_REQUIRED | pre-R1 issue | DRAIN_QUARANTINE then exactly one OWNER_TERMINAL after drain/proof | §15.3.3; no TX_RESULT |
| AUTHORITY_DIVERGENCE | pre-R1 issue | DRAIN_QUARANTINE then exactly one OWNER_TERMINAL after drain/proof | bounded then OPERATOR; no TX_RESULT |
| EPOCH_TRANSITION_REQUIRED | pre-R1 issue | DRAIN_QUARANTINE then exactly one OWNER_TERMINAL after drain/proof | class-C adopt path; no TX_RESULT |
| EPOCH_W1_REPAIR | pre-R1 issue | DRAIN_QUARANTINE then exactly one OWNER_TERMINAL after drain/proof | L1 watermark repair path; no TX_RESULT |
| FIFO_OUT_OF_ORDER | **R1-only** | if illegally surfaced pre-R1: DRAIN_QUARANTINE then OWNER_TERMINAL (contract violation) | **not** a legal pre-R1 issue class; **no** invented TX_RESULT |
| OPERATOR_RECOVERY_REQUIRED | pre-R1 issue | DRAIN_QUARANTINE (sticky) then exactly one OWNER_TERMINAL after drain/proof | operator sticky; TX 0; no TX_RESULT |
| RETRYABLE_PIPELINE | **R1-only** | if illegally surfaced pre-R1: DRAIN_QUARANTINE then OWNER_TERMINAL (contract violation) | **not** a legal pre-R1 issue class; **no** invented TX_RESULT |

No ellipsis/catchall rows. R2 issue/sample/adopt results remain **typed private diagnostic objects** / **separate diagnostic objects** with `result_catalog=R2_PCP`. They are **not** event_kind=5 and **not** one of the 7 events. **No** fake R1 status/stage/reason on issue results. **Forbidden:** any pre-R1 L1 class in the TX_RESULT mapping table.

**TX_RESULT exact form = common envelope (§1.1.1) + TX_RESULT-specific fields only (no re-declare/omit of event_schema/event_kind/owner_token/candidate_token):**

**EVENT_TX_RESULT_BEGIN**
```text
common_envelope,      /* event_schema=1 u16, event_kind=5 u8, owner_token u64, candidate_token u64 */
final_tx_outcome     : u8   /* closed codes below; set-equal live set */
disposition          : u8   /* closed codes below */
consume_invoked      : u8   /* 0|1; whether R1 entered the consume callback (not success/mutation) */
edge_invoked         : u8   /* 0|1; whether R1 entered the edge callback (not success) */
permit_sequence      : u64  /* exact bound issued Permit sequence; domain 1..UINT64_MAX-1 */
retry_eligible       : u8   /* 0|1 */
retry_not_before_ms  : u64  /* authority domain; iff retry_eligible=1 else 0 */
result_catalog       : u8   /* exact 1 = R1_HAL only */
exact_status         : u32  /* NINLIL_RADIO_HAL status; matches radio_hal.h */
stage                : u32  /* NINLIL_RADIO_HAL stage */
reason               : u32  /* NINLIL_RADIO_HAL reason */
```
**EVENT_TX_RESULT_END**  
Logical ordered C host-value payload (not radio bytes). No hints/pointers. No `result_class` field (redundant; abolished). No `permit_sequence_or_0` (abolished). **`result_catalog` MUST be R1_HAL only**; **`R2_PCP` and `NONE` are not permitted** in the TX_RESULT event payload. TX_RESULT event_kind=5 remains OUTER + R1 invoked only (only after **OK_ISSUED**).

**consume_invoked / edge_invoked (exact):**  
- `consume_invoked=1` **iff** R1 entered the consume callback (not whether consume succeeded or mutated durable state).  
- `edge_invoked=1` **iff** R1 entered the edge callback (not whether edge succeeded).  
- `edge_invoked=1` ⇒ `consume_invoked=1` (else invalid → TX_QUARANTINE).  
- Forbidden: merged “0 or 1 per stage” cells.

**permit_sequence (exact):** domain **1..UINT64_MAX-1**. Every valid TX_RESULT is after OK_ISSUED and **MUST** bit-exact equal the bound issued Permit sequence for this owner/candidate. `0`, `UINT64_MAX`, mismatch, or missing Permit ⇒ **invalid event** → TX_QUARANTINE/drain; **no** local release. Forbidden: no-bound/0/normally wording.

**final_tx_outcome (closed u8 live set; dead codes abolished):**  
`1 TX_EDGE_DONE` · `2 TX_RETRY_SAME_PERMIT` · `3 TX_QUARANTINE` · `4 TX_STALE_NO_RETRY`  
Abolished: `TX_DROP_VOLATILE`, `TX_TERMINAL` as local-release after OK_ISSUED, `TX_RETRY_SAME_SEALED_ISSUE` (PRE_R1 only).

**disposition (closed u8 live set):**  
`1 RETAIN_SEALED` · `2 QUARANTINE` · `3 STALE_NO_RETRY`  
Abolished dead codes: `DROP_SEALED`, `TERMINAL` in TX_RESULT disposition catalog.

**Boolean / zero-fill rules (exact):**
- `consume_invoked`/`edge_invoked`/`retry_eligible` ∈ {0,1} only.
- `retry_eligible=1` **iff** `final_tx_outcome=TX_RETRY_SAME_PERMIT` (**RETRY_GATE_OPEN** only); else `retry_eligible=0` and `retry_not_before_ms=0`.
- When `retry_eligible=1`, `retry_not_before_ms` **MUST** equal `permit_tx_retry_at` from **TX_RESULT_RETRY_GATE** below; never a second clock domain.
- Invalid combinations / invalid permit_sequence ⇒ TX_QUARANTINE + drain (safe fail-closed).

**Success tuple canonicalization (exact; TX_RESULT_SUCCESS_TUPLE_CANONICAL):**  
R1 success `out_error` is call-entry unchanged — TX_RESULT **MUST NOT** copy it. On proven consume+edge success, L1 event tuple is **canonical** independent of caller `out_error` initial bytes:  
`exact_status=0` (`NINLIL_RADIO_HAL_OK`) · `stage=10` (`NINLIL_RADIO_HAL_STAGE_EDGE`) · `reason=0` (`NINLIL_RADIO_HAL_REASON_NONE`).  
Edge error remains `status=8` / `stage=10` / `reason=12` (`EDGE_FAIL`). All non-success rows carry/normalize the exact closed R1 tuple defined by their row; no hints.

**TX_RESULT mapping — two-stage closed (exact ordered equality with gate + §15.3.4; no pre-R1; no 0-or-1 cells):**

**Stage 1 — raw R1 tuple:** classify only `exact_status` / `stage` / `reason` / `consume_invoked` / `edge_invoked` (bit-exact HAL).  
**Stage 2 — L1 RETRY_GATE:** applies **only** to raw retryable tuples below; closed/exclusive **RETRY_GATE_OPEN** XOR **RETRY_GATE_CLOSED**. Non-retryable rows do not enter stage 2.

**Raw retryable tuples (exact; docs/24 §10.10 aligned):**
1. **validate HAL16:** `status=11 NOT_BEFORE` · `stage=7 PERMIT_VALIDATE` · `reason=16 NOT_BEFORE` · `consume_invoked=0` · `edge_invoked=0`
2. **consume HAL16:** `status=6 CONSUME_DENIED` · `stage=8 PERMIT_CONSUME` · `reason=16 NOT_BEFORE` · `consume_invoked=1` · `edge_invoked=0` (consume callback entered; PCP9 NOT_BEFORE pre-put)
3. **consume HAL45:** `status=6 CONSUME_DENIED` · `stage=8 PERMIT_CONSUME` · `reason=45 CONSUME_BUSY` · `consume_invoked=1` · `edge_invoked=0`

**TX_RESULT_RETRY_GATE (exact; RETRY_GATE_OPEN / RETRY_GATE_CLOSED exclusive):**
- `calls_used` = full-pipeline R1 call count for this Permit/candidate **including the call that just returned this raw tuple**. OPEN requires **`calls_used < 8`**. When `calls_used=8` (call 8) ⇒ CLOSED.
- `permit_tx_retry_at = checked_add(current_accepted_now_mono, 100)` where `current_accepted_now_mono` is the **sole** accepted R2-authority-domain sample `now_ms` already held by L1 for this decision from `ninlil_r2_private_sample_authority_clock` under §15.3.5 / §11.2.3 (`SAMPLE_TRUSTED_SAME_EPOCH`, same `clock_epoch_id`, fences clear). **MUST NOT** invent a second local/OS mono or alternate sample owner.
- OPEN requires checked_add success **and** `permit_tx_retry_at` **strictly before** all of: Permit expiry; enclosing owner deadline; and if `group_deadline_valid=1`, group absolute deadline.
- Untrusted sample, epoch mismatch, fence set, or checked_add overflow ⇒ CLOSED.
- **OPEN** ⇒ `final_tx_outcome=TX_RETRY_SAME_PERMIT` · `disposition=RETAIN_SEALED` · `retry_eligible=1` · `retry_not_before_ms=permit_tx_retry_at`; L1 re-enters **full R1 pipeline only** on same Permit + same sealed candidate after `retry_not_before_ms`.
- **CLOSED** ⇒ `final_tx_outcome=TX_QUARANTINE` · `disposition=QUARANTINE` · `retry_eligible=0` · `retry_not_before_ms=0`; issued Permit exists ⇒ **no** local TX_TERMINAL/release; enter DRAIN then exactly one OWNER_TERMINAL after proof.

| # | R1 outcome (exact) | exact_status | stage | reason | final_tx_outcome | disposition | consume_invoked | edge_invoked | pair effect | group effect |
| ---: | --- | ---: | ---: | ---: | --- | --- | ---: | ---: | --- | --- |
| 1 | OK: consume success + sole TX edge entered once | 0 OK | 10 EDGE | 0 NONE | TX_EDGE_DONE | STALE_NO_RETRY | 1 | 1 | pair **terminal exactly once** | per **TX_EDGE_DONE_ACK_POLICY** |
| 2 | validate HAL16 NOT_BEFORE RETRY_GATE_OPEN | 11 NOT_BEFORE | 7 PERMIT_VALIDATE | 16 NOT_BEFORE | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 0 | 0 | pair **nonterminal**; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at | unchanged |
| 3 | validate HAL16 NOT_BEFORE RETRY_GATE_CLOSED | 11 NOT_BEFORE | 7 PERMIT_VALIDATE | 16 NOT_BEFORE | TX_QUARANTINE | QUARANTINE | 0 | 0 | pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL | as drain |
| 4 | consume HAL16 NOT_BEFORE RETRY_GATE_OPEN | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 16 NOT_BEFORE | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 1 | 0 | pair **nonterminal**; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at | unchanged |
| 5 | consume HAL16 NOT_BEFORE RETRY_GATE_CLOSED | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 16 NOT_BEFORE | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL | as drain |
| 6 | consume HAL45 CONSUME_BUSY RETRY_GATE_OPEN | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 45 CONSUME_BUSY | TX_RETRY_SAME_PERMIT | RETAIN_SEALED | 1 | 0 | pair **nonterminal**; full R1 only same Permit+sealed; calls_used<8; retry_not_before=permit_tx_retry_at | unchanged |
| 7 | consume HAL45 CONSUME_BUSY RETRY_GATE_CLOSED | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 45 CONSUME_BUSY | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; issued ⇒ drain (never local terminal/release); DRAIN then OWNER_TERMINAL | as drain |
| 8 | EDGE_ERROR after consume success + edge entered | 8 EDGE_ERROR | 10 EDGE | 12 EDGE_FAIL | TX_STALE_NO_RETRY | STALE_NO_RETRY | 1 | 1 | pair terminal | group cleanup §15.3.8; no-drain for that Permit |
| 9 | FIFO HAL43 (consume callback entered) | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 43 FIFO_OUT_OF_ORDER | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; DRAIN + OWNER_TERMINAL after proof | as drain |
| 10 | CLOCK HAL44 (consume callback entered) | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 44 CONSUME_CLOCK_UNCERTAIN | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; global volatile freeze only borrow-safe/drain-safe; DRAIN + OWNER_TERMINAL | as drain |
| 11 | All other failures **before** consume callback entry, excluding exact validate HAL16 rows 2–3 (args/live/time/digest/validate/pre-consume seq/shape/default/EXPIRED at validate etc., not status=11/stage=7/reason=16) | exact closed R1 status/stage/reason for that reject | (as R1) | (as R1) | TX_QUARANTINE | QUARANTINE | 0 | 0 | pair nonterminal quarantine; OK_ISSUED exists ⇒ drain (never local TX_TERMINAL/release) | as drain |
| 12 | All other failures **after** consume callback entry but **before** edge, excluding exact consume HAL16 rows 4–5, consume HAL45 rows 6–7, HAL43 row 9, HAL44 row 10 (CONSUME_FENCED/ERROR, unexpected consume return, post-consume plan fault etc., not tuples 6/8/16, 6/8/45, 6/8/43, 6/8/44) | exact closed R1 status/stage/reason for that reject | (as R1) | (as R1) | TX_QUARANTINE | QUARANTINE | 1 | 0 | pair nonterminal quarantine; drain (never local unissued release) | as drain |

After **OK_ISSUED**, every non-OPEN-retry edge=0 R1 result **MUST** enter `TX_QUARANTINE`/DRAIN (issued existence). Exact same-Permit **RETRY_GATE_OPEN** retries only rows **2** (validate HAL16), **4** (consume HAL16), and **6** (consume HAL45). Clean unissued terminal exists **only** in PRE_R1 (`TERMINAL_UNISSUED` → OWNER_TERMINAL), never as TX_RESULT. A quarantine TX_RESULT (including all **RETRY_GATE_CLOSED** rows) is **nonterminal for pair**, followed by DRAIN and exactly one OWNER_TERMINAL only after cleanup/proof.

**TX_EDGE_DONE_ACK_POLICY (exact):**

| path | TX_EDGE_DONE meaning | group state | E2E slot | OUTER slot |
| --- | --- | --- | --- | --- |
| DATA + outer_ack_requested=1 | terminal-for-pair / **nonterminal-for-group** (never simply “non-terminal”) | WAIT_LINK_ACK; may timeout→fresh HOP DATA; **ACK timer path active** (§11.2) | retain | **release once** after R1 return/TX_RESULT (OUTER_OUTPUT_SLOT_RELEASE_TABLE); fresh HOP gets fresh OUTER |
| DATA + outer_ack_requested=0 | terminal-for-pair; receiver ACK TX **0** | close group as UNACKED_LINK_SUCCESS (**no WAIT_LINK_ACK / no ACK timer / no retry**) after sibling/borrow cleanup | release only after cleanup (E2E table) | **release once** after R1 return/TX_RESULT |
| LOCAL_LINK_ACK | terminal-for-pair | **no group**; close ACK-coalesce owner | n/a | same pair result release rules |

Never call TX_EDGE_DONE simply “non-terminal” without pair/group split. R1 retry TX_RESULT is nonterminal for pair; terminal R1 outcomes close pair.

**Order (exact; sole air path is OUTER only / OUTER sole air path):**  
- **E2E success:** STAMP(E2E) → FRAME_READY(E2E_BLOB) → E2E_TRANSFERRED_CLOSED → LINK attach or pre-group release → HOP STAMP.  
- **OUTER:** STAMP(HOP) → FRAME_READY(OUTER) → PRE_R1_ISSUE_NEXT_ACTION → (if OK_ISSUED) R1 → TX_RESULT.  
- Fail: SEAL_FAIL/LENGTH_CLASS → OWNER_TERMINAL. Forbidden: E2E_BLOB → Permit/R1/TX_RESULT; pre-R1 class as TX_RESULT; pure local seal-fail as TX_RESULT with catalog NONE.

**R7 blocker:** C event bus not implemented. W1 headers/sources MUST NOT `#include` R2/R5.

**PRE_CONTEXT_INSTALL_0x11_APP_TXRX0:** until per-context/layer/direction `traffic_secret32` + matching binding digests + durable TX/RX records are installed, **0x11 application DATA TX and RX = 0** (including LINK_ACK/FRAG that depend on those contexts).

**Not claimed:** R7 full AEAD codec complete, M4/M5 handshake complete, ESP N6 capacity ready, RF/USB 実機 HIL, Japan legal, production radio, docs/25 fence resolution, application identity/dedup, crash-atomic exactly-once delivery.

## 2. Wire profile pin

| wire_profile_id | meaning |
| ---: | --- |
| **0x11** | NRW1 + AES-128-GCM + HKDF-SHA-256 + 128-bit tag + this document’s layouts |

Any other profile byte → **reject**. There is **no minor domain** for this wire_profile_id (do not invent major/minor for NRW1).

## 3. Architecture

1. Dual envelope; app plaintext never in hop PT.  
2. Outer kinds: **DATA** + **LINK_ACK** only (DIAG/group/beacon reserved reject).  
3. Relay = `route_handle != 0` (no RELAY_FORWARD kind).  
4. **ONE_WAY_CONTEXT_EXACT:** contexts are directional; no wire direction enum — direction is off-wire binding.  
5. Length from LoRa packet; closed length domains per type.  
6. Hop one-way context: two crypto **lanes** DATA vs ACK. E2E one-way context: one E2E lane.  
7. HKDF-Extract salt = layer-specific `context_binding_digest32`.  
8. Durable TX (§9) and RX (§10) apply to **every** one-way lane: hop DATA, hop ACK, E2E.

## 4. One-way context model

### 4.1 Direction codes

Handshake fixes **initiator** and **responder** roles for the pairwise membership.  
**DIRECTION_CODE_0_IR_1_RI:**

| direction_code | meaning | TX owner | RX owner |
| ---: | --- | --- | --- |
| **0** | initiator → responder (IR) | initiator | responder |
| **1** | responder → initiator (RI) | responder | initiator |
| other | reject / never install | — | — |

### 4.2 Install sides and uniqueness

Each `hop_context_id` and each `e2e_context_id` represents **exactly one** direction on the wire/lanes.

Install rules (actual local side only; §5.3):

- **Sender** of a direction installs **OUTBOUND_TX** N6AL + **N6TX** lane set for that direction only.  
- **Receiver** of a direction installs **INBOUND_RX** N6AL + **N6RX** lane set for that direction only.  
- **No phantom paired N6AL** for the opposite alloc_side.  
- **Active inbound lookup** is unique within direction-independent `(receiver_node, layer, context_id)` — collision with an active complete set in **either** direction under the same allocator scope → **reject install** (no silent replace).  
- Context-id allocator / no-reuse scope is `(membership_epoch, receiver_node_id, layer_code)` — **not** direction (§5.1).  
- Node ids on install are **canonical** `node_id16` derived from M4-authenticated stable IDs only (§5.3.0).  
- **TX_RX_DO_NOT_SHARE_KEY_COUNTER_NS:** implementations MUST NOT interpret a single key+counter namespace as shared by both TX and RX of a peer pair. Each lane has exactly one TX owner and one peer RX durable replay state.
### 4.3 Hop lanes vs E2E lane

| layer | lanes per one-way context | key/IV/counter |
| --- | --- | --- |
| hop | **DATA** lane + **ACK** lane | separate KEY/IV and separate u64 durable TX/RX per lane |
| e2e | **E2E** lane only | one KEY/IV and one u64 durable TX/RX |

- Outer **DATA** seals/opens with hop **DATA** lane.  
- Outer **LINK_ACK** seals/opens with hop **ACK** lane of the **reverse** direction hop context.  
- **LINK_ACK_PAIRS_REVERSE_ACK_LANE_TO_FORWARD_DATA:** `acked_hop_context_id` MAY name only the forward DATA hop context that handshake **exactly paired** with this reverse ACK-lane context. Unpaired id → reject, no TX.  
- **FRAG_ACK** is carried as E2E type inside outer DATA; it uses the **reverse** E2E context (paired reverse direction). Body references the **forward** `transfer_handle`.

### 4.4 Durable applicability

§9 Durable TX and §10 Durable RX are **Normative for all** of: hop DATA lane, hop ACK lane, E2E lane. Resource accounting (§13) counts each lane’s TX/RX durable state separately where capacity is specified.

## 5. Context lifecycle

### 5.1 Receiver-allocated inbound IDs

**RECEIVER_ALLOCATES_INBOUND_CONTEXT_ID:** the receiver is the sole allocator of inbound `hop_context_id` / `e2e_context_id` values that will appear on air toward that receiver.

**Canonical context-id allocator / no-reuse scope (direction-independent):**  
`(membership_epoch, receiver_node_id, layer_code)`  
Matches active inbound lookup uniqueness `(receiver_node, layer, context_id)`.  
Direction is **not** part of the allocator scope; it appears on lanes / N6RT / N6CF / binding only. Counts and floor on one N6AL span **both** directions under that allocator scope.

Domain:

- id ∈ **1 .. UINT32_MAX-1** (0 and UINT32_MAX reject)  
- active collision with same `(receiver, layer, id)` in either direction → install reject  
- **NO_SILENT_CONTEXT_REPLACE**  
- **NO_CONTEXT_ID_REUSE_IN_MEMBERSHIP_EPOCH:** within the same allocator scope, a numeric id that was ever successfully installed MUST NOT be reused for a different binding/key_generation — durable monotonic `next_free` / `next_free_context_id` (INBOUND synonym) / `peer_next_floor` (OUTBOUND) + N6RT  
- allocator wrap/exhaust → **fail-closed**  
- After a **new** `membership_epoch`, a numeric id MAY appear again only if the old N6AL scope is fully GC-deleted and the install is a true **new context**

### 5.2 New context vs same-context resume

| case | required |
| --- | --- |
| **new / fresh context** | §5.3.1.8 install linearization; fresh receiver-allocated id (or peer-accepted OUTBOUND id); fresh `traffic_secret32`; new durable TX/RX initial; new `key_generation` ∈ **1..UINT64_MAX** strictly > direction N6HW high-water |
| **same-context resume** | **RO / mutation 0 only** — exact durable lanes+N6AL+N6HW + binding/kgen match + **M5 floor proof**; no lane/N6AL/N6HW PUT; no counter/replay reset. **Until M5 floor signature is frozen and materialized, resume = 0** and a new context install is required (**R7/M5 blocker**). |

**KEY_GENERATION_U64_1_TO_MAX / KEY_GENERATION_UINT64_MAX_TERMINAL:** `key_generation` is exact **u64** with domain **1 .. UINT64_MAX**. Value **0** is reject / never install.
`key_generation == UINT64_MAX` is the **namespace terminal** high-water value: it MUST be retained across restart; wrap/reuse of any generation ≤ durable high-water is forbidden; after high-water reaches UINT64_MAX, **install of any further key_generation in that namespace is 0** until a **new membership_epoch / context_id_namespace**. High-water is per N6HW direction scope under the allocator.

**NO_SAME_KEY_COUNTER_RESET_INSTALL:** install that reuses same key/IV (or same key_generation + digest) while resetting durable counters/replay to initial is **forbidden** → fence or reject.

### 5.3 Durable record key and fence

**N6_VALUE_CRC32C_CANONICAL / N6_EXACT_LANE_SET_HOP2_E2E1 / N6AL_ACTUAL_SIDE_ONLY / N6AL_OUTBOUND_PEER_NEXT_FLOOR / N6_NO_RETAINED_UNCOMPACTED / N6_BOOT_EXACT_LANE_TO_N6AL_JOIN / N6_NAMESPACE_GC_LEXICOGRAPHIC_RESCAN / N6CF_DURABLE_CONTEXT_FENCE_LAYOUT / TX_HOLDS_PEER_RECEIVER_ALLOCATED_CONTEXT_ID / N6_CANONICAL_NODE_ID / N6_FRESH_INSTALL_LINEARIZATION:**

CRC32C on every N6 value: Castagnoli poly `0x82f63b78`, init/final XOR `0xffffffff`, u32 BE, coverage = all bytes before the CRC field. Wrong size/CRC/magic/schema/reserved ⇒ CORRUPT fence.

#### 5.3.0 Namespace identity (exact)

| symbol | size | meaning |
| --- | ---: | --- |
| `local_node_id` | 16 | this device **canonical** node id (below) |
| `receiver_node_id` | 16 | canonical id of the node that allocates inbound context ids for this N6AL |
| `layer_code` | 1 | 1=HOP, 2=E2E |
| `direction_code` | 1 | 0=IR, 1=RI — on **lanes / N6RT / N6CF / N6HW** only; **not** on N6AL key |
| `alloc_side` | 1 | 1=INBOUND_RX, 2=OUTBOUND_TX — **only the actual local side stored** |
| `membership_epoch` | 8 BE | ≥ 1 |

**Canonical node ID (exact):**  
`node_id16 = SHA-256( ASCII("NINLIL-R6-NODE-ID-v1") || stable_id_len_u16be || stable_id_bytes )[0..16)`.  
Install **MUST** derive `local_node_id` and every `receiver_node_id` from the **M4-authenticated stable IDs** used by the hop/E2E binding (exact role/direction mapping). IDs are **immutable** for the membership epoch. **Caller-supplied alternate node id forbidden.**

**Fingerprint domain (exact 26 B concat; no direction):**  
`receiver_node_id[16] || layer_code:u8 || membership_epoch:u64 BE || alloc_side:u8`  
`ns_fingerprint12` = SHA-256(that 26-byte domain)[0..12).  
Same formula for N6AL key / lane join / N6RT / N6CF. Direction is **not** in the fingerprint.

**Exact lane set:** HOP = {HOP_DATA=1, HOP_ACK=2} (exactly 2); E2E = {E2E=3} (exactly 1). Fresh install puts **all** lanes of the set in one FULL. Partial set ⇒ CORRUPT. Counts are per context (+1/−1), not per lane.

**Actual-side only (delete always-both-sides):** store **only** the local alloc_side required by install:  
- **Sender** of a direction installs **OUTBOUND_TX** N6AL + N6TX lanes for that direction.  
- **Receiver** of a direction installs **INBOUND_RX** N6AL + N6RX lanes for that direction.  
**Phantom paired N6AL forbidden.** No empty opposite-side N6AL.

**Side rule:** N6TX records use alloc_side=OUTBOUND_TX only. N6RX records use alloc_side=INBOUND_RX only.

#### 5.3.0.1 Canonical lane key (48 B BE)

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 1 | 1 | layer_code |
| 1 | 2 | 1 | kind_or_lane: 1=HOP_DATA, 2=HOP_ACK, 3=E2E |
| 2 | 3 | 1 | direction_code |
| 3 | 4 | 1 | reserved0 = 0 |
| 4 | 8 | 4 | context_id u32 BE ∈ 1..UINT32_MAX-1 |
| 8 | 40 | 32 | binding_digest32 |
| 40 | 48 | 8 | key_generation u64 BE ∈ 1..UINT64_MAX |

#### 5.3.0.2 N6TX value (68 B BE; schema 2) / TX lane value (68 B continuous BE; schema 2)

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 4 | 4 | magic = 0x4E365458 ("N6TX") |
| 4 | 6 | 2 | schema = 2 |
| 6 | 8 | 2 | reserved0 = 0 |
| 8 | 16 | 8 | reserved_exclusive u64 BE (fresh install initial **1**) |
| 16 | 24 | 8 | key_generation u64 BE |
| 24 | 40 | 16 | binding_digest32[0..15] |
| 40 | 48 | 8 | membership_epoch u64 BE |
| 48 | 49 | 1 | alloc_side = 2 (OUTBOUND_TX) |
| 49 | 52 | 3 | reserved1 = 0 |
| 52 | 64 | 12 | ns_fingerprint12 |
| 64 | 68 | 4 | value_crc32c u32 BE; CRC32C(bytes[0..64)) |

Exact size **68**. Coverage **[0,64)**.

#### 5.3.0.3 N6RX value (68 B BE; schema 2)

Same layout as N6TX with magic = 0x4E365258 ("N6RX"), field at 8 = `accept_reserved_through u64 BE` (fresh install initial **0**), alloc_side = 1 (INBOUND_RX). Exact size **68**. Coverage **[0,64)**. Volatile sliding-64 is RAM-only.

#### 5.3.0.4 N6HW key (32 B BE; no context_id) and value (28 B)

**N6HW key (32 B continuous BE):** one record **per direction** under the allocator scope.

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 1 | 1 | rec_kind = 1 (N6HW) |
| 1 | 2 | 1 | layer_code |
| 2 | 3 | 1 | direction_code |
| 3 | 4 | 1 | reserved0 = 0 |
| 4 | 32 | 28 | scope_digest28 = SHA-256(local_node_id[16] \|\| layer_code \|\| direction_code \|\| membership_epoch u64 BE \|\| receiver_node_id[16])[0..28) |

Exact key size **32**.

**N6HW value (28 B continuous BE; schema 1):**

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 4 | 4 | magic = 0x4E364857 ("N6HW") |
| 4 | 6 | 2 | schema = 1 |
| 6 | 8 | 2 | reserved0 = 0 |
| 8 | 16 | 8 | high_water_key_generation u64 BE |
| 16 | 24 | 8 | last_update_authority_now_ms u64 BE |
| 24 | 28 | 4 | value_crc32c; CRC32C(bytes[0..24)) |

Exact size **28**. Coverage **[0,24)**.

#### 5.3.1 Allocator / tombstone / fence / GC

**Capacity (no retained_uncompacted):**

| role | max_active | max_retired_tombstones |
| --- | ---: | ---: |
| hop/E2E controller RX or TX | 128 | 128 |
| endpoint hop/E2E | 8 | 8 |

Admission: `active_count + 1 ≤ max_active`. Retired: `retired_tombstone_count ≤ max_retired_tombstones`. Field `retained_uncompacted_count` is **forbidden**. Counts span **both directions** under one N6AL.

#### 5.3.1.1 N6AL key (24 B BE)

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 1 | 1 | rec_kind = 2 |
| 1 | 2 | 1 | layer_code |
| 2 | 3 | 1 | alloc_side |
| 3 | 4 | 1 | reserved0 = 0 (**not** direction) |
| 4 | 12 | 8 | membership_epoch u64 BE |
| 12 | 24 | 12 | ns_fingerprint12 |

#### 5.3.1.2 N6AL value (56 B BE; schema 2; full receiver_node_id)

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 4 | 4 | magic = 0x4E36414C ("N6AL") |
| 4 | 6 | 2 | schema = 2 |
| 6 | 8 | 2 | reserved0 = 0 |
| 8 | 12 | 4 | next_free_or_peer_floor u32 BE |
| 12 | 14 | 2 | active_count u16 BE |
| 14 | 16 | 2 | retired_tombstone_count u16 BE |
| 16 | 20 | 4 | reserved1 = 0 |
| 20 | 28 | 8 | membership_epoch u64 BE |
| 28 | 36 | 8 | last_alloc_authority_now_ms u64 BE |
| 36 | 52 | 16 | receiver_node_id[16] |
| 52 | 56 | 4 | value_crc32c; CRC32C([0,52)) |

Exact size **56**. Coverage **[0,52)**.

**Boot fingerprint cross-check:** recompute `ns_fingerprint12` = SHA-256(value.receiver_node_id[16] || key.layer_code || key.membership_epoch || key.alloc_side)[0..12). Must equal key.ns_fingerprint12. Full receiver ID byte-for-byte match under fingerprint; mismatch ⇒ CORRUPT.

**INBOUND next_free:** domain 1..UINT32_MAX. Initial on N6AL create: `next_free = 1`. Allocate `id = next_free` then on FULL success `next_free = id + 1`.

**OUTBOUND peer_next_floor:** domain `1 ≤ peer_next_floor ≤ UINT32_MAX` (synonym: `1 ≤ floor ≤ UINT32_MAX`). Initial on N6AL create: `peer_next_floor = 1`. Accept peer `context_id` only if `peer_next_floor ≤ context_id ≤ UINT32_MAX-1` and no live/N6RT conflict under the shared allocator scope (either direction). On FULL success: `peer_next_floor = context_id + 1` (overflow ⇒ fail-closed). Monotonic non-decreasing; gaps burned; tombstone-compact does not lower floor.

#### 5.3.1.3 N6RT key (28 B BE) and value (48 B BE; schema 2)

**N6RT key (28 B continuous BE):**

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 1 | 1 | rec_kind = 3 (N6RT) |
| 1 | 2 | 1 | layer_code |
| 2 | 3 | 1 | direction_code |
| 3 | 4 | 1 | alloc_side |
| 4 | 8 | 4 | context_id u32 BE ∈ 1..UINT32_MAX-1 |
| 8 | 16 | 8 | membership_epoch u64 BE |
| 16 | 28 | 12 | ns_fingerprint12 |

Exact key size **28**.

**N6RT value (48 B continuous BE; schema 2):**

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 4 | 4 | magic = 0x4E365254 ("N6RT") |
| 4 | 6 | 2 | schema = 2 |
| 6 | 8 | 2 | flags **exactly 0x0001** (bit0=lane_records_erased; bits1..15=0) |
| 8 | 12 | 4 | context_id u32 BE |
| 12 | 20 | 8 | membership_epoch u64 BE |
| 20 | 28 | 8 | last_key_generation_high_water u64 BE |
| 28 | 40 | 12 | binding_digest12 |
| 40 | 41 | 1 | alloc_side |
| 41 | 42 | 1 | direction_code |
| 42 | 43 | 1 | layer_code |
| 43 | 44 | 1 | reserved0 = 0 |
| 44 | 48 | 4 | value_crc32c; CRC32C([0,44)) |

Exact size **48**.

#### 5.3.1.4 N6CF key (28 B BE) and value (64 B BE; schema 2)

**N6CF key (28 B continuous BE):**

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 1 | 1 | rec_kind = 4 (N6CF) |
| 1 | 2 | 1 | layer_code |
| 2 | 3 | 1 | direction_code |
| 3 | 4 | 1 | alloc_side |
| 4 | 8 | 4 | context_id u32 BE ∈ 1..UINT32_MAX-1 |
| 8 | 16 | 8 | membership_epoch u64 BE |
| 16 | 28 | 12 | ns_fingerprint12 |

Exact key size **28**.

**N6CF value (64 B continuous BE; schema 2):**

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 4 | 4 | magic = 0x4E364346 ("N6CF") |
| 4 | 6 | 2 | schema = 2 |
| 6 | 8 | 2 | flags **exactly 0x0001** (bit0=fence_active; bits1..15=0) |
| 8 | 12 | 4 | context_id u32 BE |
| 12 | 20 | 8 | membership_epoch u64 BE |
| 20 | 36 | 16 | fence_stamp_epoch_id |
| 36 | 44 | 8 | fence_stamp_now_ms u64 BE |
| 44 | 56 | 12 | binding_digest12 |
| 56 | 57 | 1 | alloc_side |
| 57 | 58 | 1 | direction_code |
| 58 | 59 | 1 | layer_code |
| 59 | 60 | 1 | reason (1=DIGEST 2=KGEN_ROLLBACK 3=CORRUPT 4=MEMBERSHIP 5=OPERATOR; 0 reject) |
| 60 | 64 | 4 | value_crc32c; CRC32C([0,60)) |

Exact size **64**. Coverage **[0,60)**.

#### 5.3.1.5 Boot join and cross-invariants (exact equality)

**Why `ns_fingerprint12` alone cannot detect opposite-side collision:**  
`ns_fingerprint12 = SHA-256(receiver_node_id[16] || layer_code || membership_epoch_be8 || alloc_side)[0..12)` **includes `alloc_side`**. Valid fingerprints for INBOUND vs OUTBOUND under the same receiver/layer/epoch are **always unequal**. Any cross-direction check of the form  
`memcmp(nsfp_a, nsfp_b) == 0 && alloc_side_a != alloc_side_b`  
is **dead / never fires** for correctly encoded records. That check is **non-Normative (forbidden)** as a collision detector.

**Direction-independent allocator scope (collision domain):**  
`(membership_epoch, full receiver_node_id[16], layer_code)`  
with context membership keyed by  
`(membership_epoch, full receiver_node_id[16], layer_code, context_id)`  
— **independent of `direction_code` and `alloc_side`**. Full receiver ID is authoritative; fingerprint is only a durable index/check for a single N6AL key, not a cross-side equality key.

##### Boot assembly order (exact)

1. **Scan and decode** durable records; hold lane/N6RT/N6CF/N6AL/N6HW candidates.  
2. **Exact AL join for each N6AL:** recompute `ns_fingerprint12` from AL value `receiver_node_id` + key `(layer, epoch, alloc_side)`; must equal key fingerprint; epoch key↔value match.  
3. **Lane / N6RT / N6CF accumulator identity (for lane-set assembly only — not for cross-side collision):**  
   exact AL/NS membership =  
   `(ns_fingerprint12, membership_epoch, alloc_side, layer_code, direction_code, context_id)`  
   (equivalently: joined AL handle + `direction_code` + `context_id`).  
   Two lanes with the same `context_id`/`epoch`/`layer` but different `ns_fingerprint12` or `alloc_side` **MUST** accumulate as separate members for set assembly (no merge across NS/side).  
4. **Build complete lane sets only after exact AL join** (step 2–3). Incomplete HOP/E2E sets under a joined AL ⇒ CORRUPT. Orphan lanes with no matching AL ⇒ CORRUPT.  
5. **Context collision under allocator scope (after complete sets exist) — cross-direction conflict:**  
   If two **complete** live lane sets (or live complete set vs N6RT as applicable) share the same  
   `(membership_epoch, full receiver_node_id[16], layer_code, context_id)`  
   with **different** `(alloc_side, direction_code)` pairs that put the same `context_id` live under both directions / both sides of the same receiver scope ⇒ **CORRUPT**.  
   Comparison uses **full receiver_node_id from the joined N6AL**, never `memcmp(nsfp)==0` across opposite `alloc_side`.  
6. **N6HW** join and high-water after AL join (below).

Lane/N6RT/N6CF `direction_code` is free within the shared allocator scope but must be consistent key↔value.

**N6HW join (exact `scope_digest28`; not layer+direction alone):**  
For each N6AL with `receiver_node_id` and for each `direction_code ∈ {0,1}` that has activity under that AL, recompute  
`scope_digest28 = SHA-256(local_node_id[16] || layer_code || direction_code || membership_epoch_be8 || receiver_node_id[16])[0..28)`  
using the **authenticated bound local identity** (§20.4.1) and the AL’s layer/epoch/receiver. Match durable N6HW keys by **byte-exact** `scope_digest28` (plus layer/direction consistency). Layer+direction-only matching is **forbidden**.

**Authenticated local identity (§20.4.1 exact adapter ABI):** identity required for **BOUND** and **every** `boot_scan` including empty storage. Preflight: missing storage/crypto ⇒ `INVALID_STATE` I/O0; missing identity ⇒ `M4_REQUIRED` + `LOCAL_IDENTITY` I/O0. Sole binder `bind_local_identity_accepted`; one-shot `consume`; second/rebind callback 0. Install capsule local id must equal bound id pre-mutation.

| invariant | exact rule |
| --- | --- |
| N6TX / N6RX side | OUTBOUND / INBOUND only as labeled |
| key↔value duplicate fields | context_id, membership_epoch, alloc_side, direction, layer, binding prefix/kgen match across key and value where both carry them |
| lane kgen | lane key kgen == lane value kgen; value binding_digest32[0..15] == key binding_digest32[0..15] |
| N6AL key/value epoch | key.membership_epoch == value.membership_epoch |
| N6AL fingerprint | recomputed from full receiver_node_id + layer + epoch + alloc_side equals key.ns_fingerprint12 |
| N6RT/N6CF identity | key fields match value counterparts; flags exactly 0x0001 |
| lane-set assembly key | exact joined AL + direction + context_id (nsfp+epoch+alloc_side+layer+direction+cid); no cross-NS merge |
| complete sets only after AL join | do not declare complete HOP/E2E sets until exact AL join succeeds for that member |
| active vs N6RT | same assembly identity (joined AL + direction + context_id) cannot be both live complete lane set and N6RT |
| complete HOP set | both DATA+ACK present with equal binding/kgen/epoch/side under same assembly identity |
| active_count | equals # distinct active context_ids with complete exact lane set (either direction) under this N6AL |
| retired_tombstone_count | equals # N6RT under this N6AL |
| floor / next_free | all active/retired context_id < floor/next_free as applicable |
| **context collision (cross side / direction)** | two complete live sets (or live vs retired as specified) with same `(membership_epoch, full receiver_node_id[16], layer_code, context_id)` under the allocator scope — **independent of direction and alloc_side** — ⇒ CORRUPT. Uses full receiver ID after AL join; **forbidden** to require `memcmp(nsfp)==0` across opposite alloc_side |
| role caps | active_count ≤ role max_active; retired ≤ max_retired |
| N6HW presence | N6AL with activity ⇒ exact one-to-one matching N6HW per active direction under recomputed scope_digest28; orphan N6HW (no matching N6AL scope) ⇒ CORRUPT |
| N6HW high_water | high_water ≥ every active lane kgen and every N6RT last_kgen in **that direction** under the N6AL (after exact scope match) |
| duplicate complete set | two complete sets same assembly identity (same joined AL + direction + cid) ⇒ CORRUPT |
| two AL scopes same layer/direction | distinct full receivers remain separate; HW must not attach across scopes |

**Required negative test (host):** valid fingerprints, **opposite `alloc_side`**, **same full `receiver_node_id`**, same `membership_epoch`/`layer_code`/`context_id`, both sides complete live lane sets → boot **CORRUPT**. Must not depend on equal nsfp (which cannot occur for valid opposite-side fingerprints).

Any inequality ⇒ CORRUPT.

#### 5.3.1.6 Context fence reclaim (exact timing)

**N6CF flags must be 0x0001** while fence active.

| condition | reclaim? |
| --- | --- |
| no valid trusted same-epoch sample | **no** |
| TEMP / CLOCK_FAULT / blocking fence | **no** |
| stamp epoch all-zero or stamp epoch ≠ S.epoch | **no compare / no reclaim**; after authority recovery, FULL **restamp** N6CF under current trusted epoch/now then wait full 30000 ms |
| S.epoch == stamp epoch and `S.now >= checked_add(stamp.now, 30000)` | reclaim FULL allowed |
| checked_add overflow | **no reclaim** |

**Fence creation without trusted sample:** store zero stamp epoch/now; unreclaimable until restamp under trusted sample.

**Reclaim FULL success (exact):** put N6RT (flags 0x0001); delete exact lane set for that context; put N6AL′ active−− retired++; delete N6CF; same FULL; CU uses exact old/proposed §9.3 write-set.

#### 5.3.1.7 Namespace GC — restartable lexicographic rescan only

**N6_NAMESPACE_GC_LEXICOGRAPHIC_RESCAN:** durable cursor deleted. Sole mode = restartable lexicographic RO rescan under retirement sticky.

**GC scope (exact):**  
`M = (membership_epoch, layer_code, receiver_node_id, alloc_side)`.  
One N6AL key per M. **No** forced dual alloc_side.

After M4 durable retirement sticky for M:
1. Sticky: no new install under M.
2. **One FULL = one context unit** (mutations ≤ 32): reclaim FULL or **tombstone-compact FULL** (reclaim-compact synonym for retired-only delete N6RT + N6AL′ retired−−) as §5.3.1.6 / compact.
3. Rescan lexicographic; crash ⇒ empty RO rescan; idempotent DELETE PROPOSED.
4. **Final cleanup FULL for M** (after M4 durable namespace retirement sticky): when RO scan proves zero subordinates (no N6TX/N6RX/N6RT/N6CF joining this N6AL) and active=retired=0:
   - DELETE the single N6AL for M
   - DELETE each N6HW whose scope matches this receiver/layer/epoch and direction ∈ {0,1} **that is present** after exact RO scan (0, 1, or 2 keys)
   - Normalized mutation count **1..3** (1 N6AL + 0..2 N6HW). **No** vague W_M / “every direction always”.
   - **Never** delete N6AL while any direction subordinate remains.
5. Join uses fingerprint + epoch + side — not fictional NS prefix.

COMMIT_UNKNOWN on GC FULL: §9.3 same-process; restart = durable rescan only.

#### 5.3.1.8 Fresh-context install linearization (complete; crash-safe)

**N6_FRESH_INSTALL_LINEARIZATION:** sole Normative install path for new contexts. **One** RO snapshot of needed keys, **one** normalized multi-key FULL, then RAM publish only on FULL_OK.

**Prechecks (RO; mutation 0):** capacity; N6AL fingerprint/full-ID collision; live lane complete-set collision on context_id either direction; N6RT/N6CF conflict; floor/next_free admit; candidate `key_generation` **strictly >** direction N6HW high_water (absent N6HW ⇒ high_water treated 0 for compare); role caps; canonical node ids derived as §5.3.0.

**Write-set (exact; max 4 entries HOP / max 3 E2E):**

| path | puts in one FULL |
| --- | --- |
| HOP fresh | exact 2 lane values (N6TX or N6RX) + 1 N6AL put + 1 N6HW put = **4** |
| E2E fresh | exact 1 lane + 1 N6AL + 1 N6HW = **3** |

**Absent N6AL:** create with initial next_free=1 (INBOUND) or peer_floor=1 (OUTBOUND), active_count=0, retired=0, receiver_node_id full, then apply post-image below.  
**Existing N6AL:** load; verify invariants; apply post-image.  
**Per-direction N6HW:** absent ⇒ create high_water=candidate kgen; existing ⇒ put high_water=max(old, candidate kgen); last_update_authority_now_ms = trusted sample now or **0** if policy closed zero when sample unavailable (install requires trusted class-D sample for non-zero stamp; else reject install).

**Post-image N6AL (same FULL):**  
- INBOUND: allocate `id = next_free` (must equal planned context_id); `next_free' = id+1`; `active_count' = active_count+1`; retired unchanged.  
- OUTBOUND: require `peer_next_floor ≤ id ≤ UINT32_MAX-1`; `peer_next_floor' = id+1`; `active_count' = active_count+1`; retired unchanged.  
- `last_alloc_authority_now_ms` = trusted now or closed 0 policy as above.

**Lane initial:** TX `reserved_exclusive=1`; RX `accept_reserved_through=0`; binding/kgen/epoch/fingerprint exact.

**Copy-owned CU write-set:** every put carries old_present/old_bytes and proposed_bytes for §9.3. FULL_OK ⇒ sole RAM publish of new context. Definite fail ⇒ rollback (no RAM publish). COMMIT_UNKNOWN ⇒ fence radio-security NS; recover via §9.3 on that exact write-set; no second burn of floor without recovery class.

**Same-context resume:** not this section — RO/mutation 0 only (§5.2); until M5 floor materializes, resume=0.

### 5.4 E2E security id vs Attachment

E2E is a **separate layer from Attachment** (docs/03).  
**E2E_SECURITY_ID_NOT_ATTACHMENT:** E2E binding uses `e2e_security_id` + `e2e_security_epoch` (or exact synonyms in implementation APIs), **not** `attachment_id` / `attachment_epoch`.  
**E2E_SECURITY_EPOCH_GT_0:** `e2e_security_epoch` is u64 with domain **≥ 1**. Value **0** is reject / never install.  
Parent/Attachment change alone MUST NOT change E2E sealed blob bytes or force E2E rekey.  
E2E rekey/fence on: membership_epoch change, authority_term change, or `e2e_security_epoch` change.  
**HOP_BINDS_ATTACHMENT:** hop binding continues to include Attachment id/epoch.

## 6. Outer AEAD (hop)

### 6.1 Outer AAD — 19 bytes continuous

```text
LAYOUT_OUTER_BEGIN
off  end  sz  field
0    1    1   wire_profile_id = 0x11
1    2    1   kind_flags
2    3    1   hop_remaining
3    7    4   hop_context_id (u32 BE, nonzero)
7    15   8   hop_counter (u64 BE)
15   17   2   route_handle (u16 BE)
17   19   2   route_generation (u16 BE)
LAYOUT_OUTER_END
OUTER_AAD_LEN = 19
```

**kind_flags:**

| bits | meaning |
| --- | --- |
| 7..4 | kind: `1=DATA`, `2=LINK_ACK`; **other including 3+ reject** |
| 3..1 | MUST be 0 |
| 0 | **ACK_REQUESTED** — DATA only (LINK_ACK must have bit0=0) |

### 6.2 Outer frame concat and Seal/Open

**OUTER_FRAME_CONCAT_AAD19_CT_TAG16:**

```text
outer_frame = outer_AAD_19 || hop_CT || hop_TAG_16
/* tag is trailing 16 bytes; never interleaved */
packet_len = |outer_frame| = LoRa PHY payload length
```

AES-128-GCM Seal/Open inputs (hop):

| input | value |
| --- | --- |
| key | hop lane key16 (DATA or ACK) |
| nonce | §8.6 from hop lane iv12 + hop_counter |
| AAD | exact outer_AAD_19 |
| plaintext | HopPT (§6.4) |
| ciphertext+tag | hop_CT \|\| hop_TAG_16 |

### 6.3 Closed length domains

**CLOSED_LENGTH_DOMAINS** — underflow checks before any subtraction.

```text
packet_len = LoRa PHY payload length
if packet_len < 19 + 16: reject
hop_ct_len = packet_len - 19 - 16
```

| kind / e2e type | packet_len | notes |
| --- | --- | --- |
| DATA / SINGLE | **66..255** | min 19+31+16=66; max 255 |
| DATA / FRAG_START | **130..255** | outer 129+S, S≥1 → ≥130 |
| DATA / FRAG_CONT | **76..255** | outer 75+C, C≥1 → ≥76 |
| DATA / FRAG_ACK | **exactly 79** | fixed |
| LINK_ACK | **exactly 51** | HopPT 16 |

**TYPE_LENGTH_SINGLE_66_255 / TYPE_LENGTH_START_130_255 / TYPE_LENGTH_CONT_76_255 / TYPE_LENGTH_FRAG_ACK_79_EXACT**

DATA generic floor before type is known: `hop_ct_len >= 14+16+1` (=31) for types that carry E2E; LINK_ACK hop_ct_len = 16 exact.

### 6.4 Hop plaintext

| kind | HopPT |
| --- | --- |
| DATA | entire `e2e_sealed_blob` (opaque to relays) |
| LINK_ACK | fixed 16B BE layout §11 |

### 6.5 Validation order (hop)

**VALIDATION_ORDER_STRUCT_REPLAY_AEAD_ADMIT_BODY:**

1. Structural parse (profile, lengths, kind, route domain) — **no durable mutation**  
2. Context/route lookup + RX replay **precheck** (counter domain, duplicate, window) — **no durable mutation**  
3. AEAD Open  
4. Durable admission (TX burn already done on seal path; RX accept_reserved + bitmap)  
5. Body processing (LINK_ACK fields / for DATA: relay or endpoint)  

If step 1–4 fails: deliver/ACK/forward **0**.  
Definite storage failure / COMMIT_UNKNOWN / CORRUPT: deliver/ACK/forward **0**.

**RELAY_E2E_STRUCTURAL_ONLY_AFTER_OUTER / RELAY_MUST_STRUCTURAL_E2E_HEADER:** after successful outer hop auth (Open) **and** hop durable RX admission on a relay, the relay **MUST** structurally validate the **visible E2E header** of the sealed blob **before** forward-queue admit, radio forward TX, or LINK_ACK generation:

1. `wire_profile_id == 0x11`  
2. type high nibble ∈ {1,2,3,4} (SINGLE/START/CONT/FRAG_ACK)  
3. type low nibble == 0  
4. `e2e_context_id` ∈ 1..UINT32_MAX-1 (nonzero, not MAX)  
5. `e2e_counter` ∈ 1..UINT64_MAX-1  
6. exact type-specific total length domain (SINGLE/START/CONT/FRAG_ACK packet/HopPT rules in §6.3 / §7)  

Any fail ⇒ **queue admit / forward TX / LINK_ACK / deliver = 0**.  
Relay still **MUST NOT** perform E2E context lookup, E2E replay precheck, E2E Open, or E2E body processing (**RELAY_E2E_OPEN_FORBIDDEN**). Validation is structural-only on the visible header of the already-authenticated outer HopPT.

### 6.6 Route / relay

| route_handle | route_generation | hop_remaining |
| ---: | ---: | --- |
| 0 | 0 | **MUST be 0** |
| ≠0 | ≠0 | **1 ≤ hop_remaining ≤ record.max_hops** |
| else | | reject |

**LINK_ACK_ROUTE_0_0_REMAINING_0:** every LINK_ACK outer MUST have route_handle=0, route_generation=0, hop_remaining=0.

**Route lookup key** = `(ingress_hop_context_id, route_handle, route_generation)`.

**ROUTE_RECORD_EGRESS_TUPLE_EXACT** — route record fields:

| field | role |
| --- | --- |
| egress_peer_id | next hop peer |
| egress_hop_context_id | one-way hop context for egress DATA seal |
| egress_route_handle | next hop’s handle (**0** only when this hop is terminal) |
| egress_route_generation | next hop’s generation (**0** only when this hop is terminal) |
| authority_id / lease_epoch / expiry | active lease binding |
| grant / queue_quota | admission bounds |
| max_hops | remaining upper bound |
| ack_policy | egress ACK_REQUESTED source |

**ROUTE_TERMINAL_INVARIANT_REMAINING** — after successful ingress DATA open, when building the egress outer (relay forward path):

```text
remaining' = ingress hop_remaining - 1   /* require ingress hop_remaining >= 1; else TX0 */
if ingress hop_remaining == 1:
  # terminal hop
  require record.egress_route_handle == 0 AND record.egress_route_generation == 0
  require remaining' == 0
else:  # ingress hop_remaining > 1
  require record.egress_route_handle != 0 AND record.egress_route_generation != 0
  require remaining' >= 1
  require remaining' <= record.max_hops
```

Any mismatch, underflow, expired/fenced lease, or missing route record → **radio TX 0** (no partial forward).

**NEXT_ROUTE_HEADER_SOURCES_EXACT** — forward outer header sources:

| outer field | source |
| --- | --- |
| wire_profile_id | constant 0x11 |
| kind_flags kind | DATA |
| ACK_REQUESTED | **only** `ack_policy` + local admission (**EGRESS_ACK_POLICY_NOT_BLIND_COPY**) |
| hop_remaining | `remaining'` per terminal invariant above |
| hop_context_id | record.egress_hop_context_id |
| hop_counter | egress hop DATA lane TX allocate |
| route_handle / route_generation | record.egress_route_* (must satisfy terminal invariant) |

Active lease/fence/expiry MUST be checked before TX. Invalid/expired/resource → **radio TX 0**.  
Nonzero route handle/generation: local allocator; handle reuse only after retirement; generation wrap → retire all records with that handle, never silent reuse of (handle,gen).

Forward:

1. Open ingress hop (DATA lane); copy E2E blob **bit-identical**.  
2. **RELAY_E2E_OPEN_FORBIDDEN** — relays MUST NOT Open E2E.  
3. Apply **ROUTE_TERMINAL_INVARIANT_REMAINING**; seal fresh egress outer only if invariant holds.  
4. Admit to bounded forward queue before radio TX (overflow → TX 0 / structured RESOURCE).

Unknown/invalid route or context → **INVALID_RADIO_RESPONSE_TX0**.

## 7. E2E AEAD

### 7.1 E2E AAD — 14 bytes continuous

```text
LAYOUT_E2E_BEGIN
off  end  sz  field
0    1    1   wire_profile_id = 0x11
1    2    1   type_flags
2    6    4   e2e_context_id (u32 BE, nonzero)
6    14   8   e2e_counter (u64 BE)
LAYOUT_E2E_END
E2E_AAD_LEN = 14
```

type high nibble: `1=SINGLE`, `2=FRAG_START`, `3=FRAG_CONT`, `4=FRAG_ACK`; other reject (**type=5+ reject**). low nibble MUST be 0 (**TYPE_FLAGS_LOW_NIBBLE_ZERO**); nonzero low nibble → reject.

**E2E_BLOB_CONCAT_AAD14_CT_TAG16:**

```text
if |HopPT| < 14 + 16: reject          /* underflow guard */
e2e_ct_len = |HopPT| - 14 - 16
if e2e_ct_len < 1 for SINGLE: reject
e2e_sealed_blob = e2e_AAD_14 || e2e_CT || e2e_TAG_16
```

AES-128-GCM Seal/Open inputs (E2E): key=e2e_key16, nonce from e2e_iv12+e2e_counter, AAD=e2e_AAD_14, PT=type body.

### 7.2 Endpoint E2E order

Final endpoint only: same validation order as hop for the E2E layer (structural + replay precheck → AEAD → durable admit → body). Relay: E2E open forbidden.

### 7.3 SINGLE — opaque application bytes

**SINGLE_OPAQUE_APP_BYTES** / **NO_R6_APP_IDENTITY**

```text
PT = N opaque application bytes
1 ≤ N ≤ 190   /* N=0 reject */
OUTER_L_SINGLE(N) = 65 + N
```

| N | OUTER_L |
| ---: | ---: |
| 16 | **81** |
| 24 | **89** |
| 32 | **97** |

R6 does **not** provide application identity, idempotency, or dedup.  
**LOGICAL_ENVELOPE_FREEZE_BLOCKER:** future Accepted logical envelope freeze must define at least `transaction_id`, concrete target, authority term + `assignment_epoch`, schema id, content digest. Until then multi-PC downlink-owner dispatch safety is incomplete. Crash-atomic exactly-once is **not** claimed by R6; custody / logical transaction is a future blocker.

## 8. encode_canon, context binding, HKDF

### 8.1 encode_canon

```text
encode_canon = ordered concat:
  fixed integers: BE exact width only (**ENCODE_CANON_BE_ONLY**; LE forbidden)
  opaque: u16be length || bytes (0 ≤ length ≤ field max; length bounds per matrix)
  labels: fixed ASCII, no NUL
```

### 8.2 Environment and FIELD/LAB matrix

`environment_code` u8: `1=LAB`, `2=FIELD`; other reject.  
**ENVIRONMENT_CODE_LAB_FIELD**

| env | site_domain | attachment/stable/authority ids | epochs/term |
| --- | --- | --- | --- |
| FIELD (2) | exact 16, not all-zero | length 1..32 each | all > 0 |
| LAB (1) with controller | length 1..16 domain; ids 1..32 | epochs/term > 0 |
| LAB no-controller | domain length 1..16 | authority id length **0**, term **0**; peer stables 1..32 | membership/attachment epoch > 0 |

### 8.3 Hop binding

**HOP_BINDS_ATTACHMENT**

```text
hop_binding_input = encode_canon(
  "NINLIL-R6-HOP-CTX-v1",
  u8 wire_profile_id,
  u8 environment_code,
  opaque site_domain (max 16),
  u64 membership_epoch,
  opaque attachment_id (max 32),
  u64 attachment_epoch,
  opaque initiator_stable_id (max 32),
  opaque responder_stable_id (max 32),
  opaque controller_authority_id (max 32),
  u64 controller_term,
  u32 hop_context_id,
  u8 direction_code,           /* 0 or 1 only */
  u16 allowed_kind_mask        /* MUST be 0x0003; other reject */
)
hop_context_binding_digest = SHA-256(hop_binding_input)
```

**ALLOWED_KIND_MASK_EXACT_0x0003** (bit0=DATA, bit1=LINK_ACK; reserved bits 0).  
No route/lease generation in hop binding. **NO_ROUTE_AUTHORITY_IN_HOP_KDF**

### 8.4 E2E binding

**E2E_SECURITY_ID_NOT_ATTACHMENT**

```text
e2e_binding_input = encode_canon(
  "NINLIL-R6-E2E-CTX-v1",
  u8 wire_profile_id,
  u8 environment_code,
  opaque site_domain (max 16),
  u64 membership_epoch,
  opaque e2e_security_id (max 32, length 1..32),
  u64 e2e_security_epoch,   /* MUST be >= 1; 0 reject — E2E_SECURITY_EPOCH_GT_0 */
  opaque sender_stable_id (max 32),
  opaque receiver_stable_id (max 32),
  opaque authority_id (max 32),
  u64 authority_term,
  u32 e2e_context_id,
  u8 direction_code
)
/* MUST NOT bind attachment_id, attachment_epoch, route_handle, hop_context_id, parent */
e2e_context_binding_digest = SHA-256(e2e_binding_input)
```

### 8.5 HKDF (exact formulas)

Handshake supplies **per (context_id, layer, direction)** `traffic_secret32` and expected digest.

```text
/* Hop DATA or ACK scopes use hop_context_binding_digest */
PRK_hop = HKDF-Extract(
  salt = hop_context_binding_digest,   /* exactly 32 bytes */
  IKM  = traffic_secret32_hop_direction)

hop_data_key16 = HKDF-Expand(PRK_hop, info = ASCII("NINLIL-R6-HOP-DATA-KEY-v1"), L = 16)
hop_data_iv12  = HKDF-Expand(PRK_hop, info = ASCII("NINLIL-R6-HOP-DATA-IV-v1"),  L = 12)
hop_ack_key16  = HKDF-Expand(PRK_hop, info = ASCII("NINLIL-R6-HOP-ACK-KEY-v1"),  L = 16)
hop_ack_iv12   = HKDF-Expand(PRK_hop, info = ASCII("NINLIL-R6-HOP-ACK-IV-v1"),   L = 12)

/* E2E uses e2e_context_binding_digest */
PRK_e2e = HKDF-Extract(
  salt = e2e_context_binding_digest,
  IKM  = traffic_secret32_e2e_direction)
e2e_key16 = HKDF-Expand(PRK_e2e, info = ASCII("NINLIL-R6-E2E-KEY-v1"), L = 16)
e2e_iv12  = HKDF-Expand(PRK_e2e, info = ASCII("NINLIL-R6-E2E-IV-v1"),  L = 12)
```

ASCII(label) = label bytes, **no NUL**.  
**Derivation input change / cache reuse forbidden:** if salt or IKM or label differs (including 1-bit digest change), implementations MUST recompute and MUST NOT reuse cached KEY/IV. R7 goldens MUST include mutation vectors where changed digests yield different outputs for this suite’s test vectors — **not** a general mathematical claim that every HKDF always avalanche-differs on every 1-bit input change.

### 8.6 Nonce

```text
nonce12 = static_iv12 XOR (0x00000000 || counter_u64_be)
```

### 8.7 Hop DATA vs ACK lanes (crypto)

**HOP_DATA_ACK_SEPARATE_CRYPTO_LANES:** one hop one-way context holds two lanes (DATA, ACK), each with own key/IV and own u64 TX/RX durable state. LINK_ACK uses ACK lane; DATA uses DATA lane.

## 9. Durable TX

Per crypto lane: durable `reserved_exclusive` initial **1**.  
Counters valid **1..UINT64_MAX-1** for assignment; **UINT64_MAX** is not a data counter.  
**BLOCK_SIZE_EXACT_64** (B=64 exact for profile 0x11, not “default”).

Boot: if loaded durable out-of-domain or CORRUPT → **TX 0** for that lane. Else `ram_next = ram_limit = loaded reserved_exclusive`.

### 9.1 Storage ABI mapping (`include/ninlil/platform.h`)

**STORAGE_ABI_PLATFORM_H_MAPPING** — map `ninlil_storage_status_t` from **commit** (and recovery reads as noted) to R6 storage results. Ambiguous statuses MUST NOT be treated as success.

| platform.h status | R6 result |
| --- | --- |
| `NINLIL_STORAGE_OK` on commit | **FULL_OK** |
| `NINLIL_STORAGE_COMMIT_UNKNOWN` on commit | **COMMIT_UNKNOWN** |
| `NINLIL_STORAGE_NO_SPACE`, `NINLIL_STORAGE_IO_ERROR`, `NINLIL_STORAGE_BUSY` on commit (Storage contract: non-commit guarantee) | **DEFINITE_FAILURE** |
| `NINLIL_STORAGE_CORRUPT` | **CORRUPT** |
| On commit: unexpected `NINLIL_STORAGE_NOT_FOUND`, `NINLIL_STORAGE_BUFFER_TOO_SMALL`, `NINLIL_STORAGE_UNSUPPORTED_SCHEMA`, or any unknown status code | **CORRUPT** + fence |

### 9.2 TX exclusive reservation (checked final partial tranche)

**TX_EXCLUSIVE_RESERVATION_CHECKED_FINAL_TRANCHE** / **TX_CHECKED_SATURATING_LIMIT_PLUS_B:**

```text
# durable reserved_exclusive = exclusive next free counter (all C < reserved_exclusive are burned/allocated)
# assignable domain: 1 .. UINT64_MAX-1
# terminal durable value reserved_exclusive == UINT64_MAX means no further assignable counters

allocate_tx_counter():
  if ram_next >= UINT64_MAX:  # not a valid data counter
    TX 0; new context required
  if ram_next == ram_limit:
    # grow exclusive reservation
    if ram_limit >= UINT64_MAX:
      refuse growth; new context
    # max assignable is UINT64_MAX-1; exclusive limit after full burn of all assignable is UINT64_MAX
    room = (UINT64_MAX - 1) - ram_limit + 1   # counters still assignable starting at ram_limit
    if room == 0:
      refuse growth; new context
    grow = min(B, room)
    U = ram_limit + grow
    # U is new exclusive; U may equal UINT64_MAX only after last assignable (UINT64_MAX-1) is included
    assert U > ram_limit and U <= UINT64_MAX
    # FULL durable write reserved_exclusive = U (map via §9.1)
    if FULL_OK:
      ram_limit = U
    elif DEFINITE_FAILURE:
      keep pre-state; no allocate
      return fail
    elif COMMIT_UNKNOWN:
      sticky fence; no allocate until §9.3 recover
      return fail
    else:  # CORRUPT
      context fence; TX 0
      return fail
  C = ram_next
  if C == 0 or C >= UINT64_MAX:
    TX 0
    return fail
  ram_next = C + 1
  # allocate burns C (exclusive semantics)
  return C
```

### 9.3 COMMIT_UNKNOWN recovery (namespace-wide multi-key; Foundation Storage ABI closed)

**COMMIT_UNKNOWN_RECOVERY_EXACT / COMMIT_UNKNOWN_NAMESPACE_RECOVERY / N6_MULTIKEY_CU_ALL_OLD_OR_ALL_PROPOSED / SINGLE_SHARED_STORAGE_HANDLE_PER_NAMESPACE:**

One shared storage handle + writer lease per radio-security namespace. Namespace length+bytes **MUST** differ from Foundation Runtime. Multi-key FULL → COMMIT_UNKNOWN fences entire radio-security namespace until recovery classifies.

**ABI note (`include/ninlil/platform.h`):** `close(user, handle)` and `iter_close` are **void** — call **exactly once** when ownership ends; **no status to inspect**. open/begin/get/put/del/commit/rollback return `ninlil_storage_status_t` and MUST be inspected on every path.

**Ceilings:** max write-set entries N ≤ 32; at most **32** write-set entries; key_len ≤ 255; max value length ≤ 256.

**Write-set normalization:** drop no-op PUT (proposed==old) and DELETE with old_present=0; DELETE requires old_present=1 proposed_present=0; PUT requires proposed_present=1; then 1 ≤ N ≤ 32.

**Per-entry class:** PUT proposed-match→PROPOSED; PUT old-match or (NOT_FOUND∧¬old)→OLD; DELETE NOT_FOUND→PROPOSED; DELETE old-match→OLD; else THIRD. Aggregate: all OLD→ALL_OLD; all PROPOSED→ALL_PROPOSED; any THIRD or mix → CORRUPT.

**get() / output-shape anomalies (exact → CORRUPT fence after void close of handle if needed):**
- OK with length > capacity, length > max value length, or buffer bytes beyond length mutated inconsistently with snap rules
- OK with NULL data pointer when length>0; NOT_FOUND with length!=0 or buffer mutated
- status outside closed Foundation storage status set; unknown status
- key_len/value_len outside declared write-set bounds
These are **not** ALL_OLD/ALL_PROPOSED; classify as THIRD / INVALID → CORRUPT.

```text
# Phases: NEED_CLOSE_OLD → NEED_OPEN → READ_CLASSIFY → RECOVERED | CORRUPT
# Transition NEED_CLOSE_OLD → NEED_OPEN after void close of old handle.

recover_namespace_commit_unknown(entries[0..N-1]):
  if recovery_phase == NEED_CLOSE_OLD:
    assert shared_handle != NULL and no live txn/iter
    h = shared_handle; shared_handle = NULL; recovery_phase = NEED_OPEN
    close(user, h)                    # void; exactly once; no status check
  else:
    assert recovery_phase == NEED_OPEN and shared_handle == NULL

  out_handle = NULL
  st = open(user, namespace, schema, &out_handle)
  if st in {BUSY, IO_ERROR} and out_handle == NULL:
    recovery_phase = NEED_OPEN; return RETRY_LATER
  if st != OK or out_handle == NULL:
    if out_handle != NULL: close(user, out_handle)  # void
    recovery_phase = CORRUPT; return CORRUPT

  recovery_phase = READ_CLASSIFY
  out_txn = NULL
  st = begin(user, out_handle, READ_ONLY, &out_txn)
  if st in {BUSY, IO_ERROR} and out_txn == NULL:
    close(user, out_handle); recovery_phase = NEED_OPEN; return RETRY_LATER
  if st != OK or out_txn == NULL:
    if out_txn != NULL:
      st_rb = rollback(user, out_txn)  # inspect rollback status only
      if st_rb != OK:
        close(user, out_handle)  # void; no status
        recovery_phase = CORRUPT; return CORRUPT
    close(user, out_handle)  # void; no status
    recovery_phase = CORRUPT; return CORRUPT

  classes = []
  for e in entries:
    buf = zeroed(256); snap = copy(buf)
    inout = {data=buf, capacity=256, length=0}
    st = get(user, out_txn, e.key, &inout)
    if st in {BUSY, IO_ERROR} and length==0 and buf==snap:
      st_rb = rollback(user, out_txn)
      close(user, out_handle)
      if st_rb != OK: recovery_phase = CORRUPT; return CORRUPT
      recovery_phase = NEED_OPEN; return RETRY_LATER
    classes.append(classify(e, st, inout, buf, snap))

  st_rb = rollback(user, out_txn)     # exactly once; consumes txn
  if st_rb != OK:
    close(user, out_handle)  # void; no status
    recovery_phase = CORRUPT; return CORRUPT  # non-OK rollback ⇒ CORRUPT fence (close has no status)

  if any THIRD or (OLD in classes and PROPOSED in classes):
    close(user, out_handle); recovery_phase = CORRUPT; return CORRUPT

  outcome = ALL_OLD if all OLD else ALL_PROPOSED
  assert shared_handle == NULL
  shared_handle = out_handle          # install live handle; do not close
  reinit_ram_from_outcome(entries, outcome)
  recovery_phase = RECOVERED
  clear sticky fence after install + RAM reinit
  return outcome
```

**Restart:** no volatile recovery object. Boot open once; scan all N6* records; exact count equality; clear boot fence.

### 9.4 Storage result actions (TX)

**STORAGE_RESULT_TABLE_CLOSED:**

| result | TX action |
| --- | --- |
| **FULL_OK** | proceed with allocation/frame path |
| **DEFINITE_FAILURE** | no frame; keep pre-state |
| **COMMIT_UNKNOWN** | sticky fence; no TX until §9.3 |
| **CORRUPT** | context fence; TX 0 |

## 10. Durable RX (sliding-64 exact)

Per crypto lane: durable `accept_reserved_through` initial **0**.  
B = **64 exact**. Domain of accepted counters: **1..UINT64_MAX-1** (aligned with TX).

Boot: if loaded durable out-of-domain or CORRUPT → **RX 0**. Else:

```text
live_reserved = loaded accept_reserved_through
boot_floor    = loaded accept_reserved_through
ram_highest   = boot_floor
bitmap        = 0   /* 64-bit; bit0 = ram_highest, bit k = ram_highest-k */
```

**RX_SLIDING64_PSEUDOCODE** / **RX_BITMAP_UINT64_C1_SHIFT** (owner-serialized; no races):

```text
on candidate counter c (before AEAD state mutation):
  if c == 0 or c == UINT64_MAX: reject
  if c <= boot_floor: reject
  if c <= ram_highest:
    delta = ram_highest - c
    if delta >= 64: reject
    if (bitmap >> delta) & UINT64_C(1): reject   /* duplicate; R7 vectors delta=31,32,63 */
    # else pending until after AEAD
  # if c > ram_highest: may accept after AEAD

after AEAD success for c:
  if c > live_reserved:
    # RX_CHECKED_SATURATING_NEW_THROUGH
    if c > (UINT64_MAX - 1) - (B - 1):
      new_through = UINT64_MAX - 1
    else:
      new_through = c + B - 1
    assert new_through >= c
    FULL commit accept_reserved_through = new_through  /* §9.1 mapping */
    if COMMIT_UNKNOWN:
      sticky fence; candidate deliver/ACK/forward = 0
      do not mark bitmap for this c
      recover via §9.3 with proposed_U = new_through:
        committed:
          live_reserved = boot_floor = ram_highest = U
          bitmap = 0
          DROP trigger frame (not re-deliver)
        not_committed:
          restore safe pre-state / restart floor (no admit of c)
        CORRUPT: context fence
      return
    if DEFINITE_FAILURE or CORRUPT: return with 0 deliver
    live_reserved = new_through
  # mark with UINT64_C(1) shifts only:
  if c > ram_highest:
    delta = c - ram_highest
    if delta >= 64: bitmap = UINT64_C(1)
    else: bitmap = (bitmap << delta) | UINT64_C(1)
    ram_highest = c
  else:
    delta = ram_highest - c
    bitmap |= (UINT64_C(1) << delta)   /* exact; golden delta 31/32/63 */
  deliver / maybe ACK
```

Fence clear only after authoritative recovery classification and RAM re-init (§9.3).  
Same-context resume needs M5 floor; else new context mandatory.

## 11. LINK_ACK

```text
LAYOUT_LINK_ACK_BEGIN
off  end  sz  field
0    4    4   acked_hop_context_id (u32 BE)
4    12   8   ack_base_counter (u64 BE)
12   14   2   ack_bitmap (u16 BE)
14   15   1   ack_code
15   16   1   reserved0 = 0
LAYOUT_LINK_ACK_END
```

Outer **exactly 51**. route=0/0, remaining=0 (§6.6).  
ack_code only `ACCEPTED_BATCH=0`.

**LINK_ACK_BITMAP_I_GE_BASE_THEN_ZERO / LINK_ACK_BITMAP_RULES:**

```text
ack_base ∈ 1..UINT64_MAX-1
bit0 (LSB) MUST be 1
for each bit index i in 0..15:
  if i >= ack_base:
    bit i MUST be 0
  else:
    counter_i = ack_base - i   /* defined only when i < ack_base */
```

#### 11.1 LINK_ACK TX generation (DATA receiver only)

**LINK_ACK_REQUIRES_ACK_REQUESTED_BIT / LINK_ACK_TX_GEN_AFTER_DATA_ADMIT:**

Outbound ACCEPTED_BATCH is generated **only by the receiver of a forward DATA** outer, and **only if** that DATA outer has **ACK_REQUESTED=1**. If bit0=0 → **LINK_ACK TX 0**.

Additionally, only after **all** of the following on that **DATA**:

1. Structural parse of the forward DATA outer succeeds  
2. Context lookup + hop DATA-lane RX replay precheck succeeds (no durable mutation until after AEAD)  
3. Hop DATA-lane AEAD Open succeeds  
4. Hop DATA-lane durable RX admission succeeds  
5. The exact admitted DATA is enqueued into the **endpoint E2E ingress queue** (endpoint: authenticated hop DATA / E2E sealed blob awaiting endpoint E2E processing — **ENDPOINT_E2E_INGRESS_QUEUE**) or the **bounded relay-forward queue** (relay)  

Every counter placed in an ACK bitmap MUST individually have completed steps 1–5 and have had **ACK_REQUESTED=1**.  
Resource / live-condition / Permit failure → **ACK 0**.  
ACCEPTED_BATCH is **not** custody/application/downstream receipt.  
Generation **MUST NOT** wait for authentication of the yet-unsent LINK_ACK.

#### 11.2 LINK retry group (DATA sender)

**LINK_RETRY_GROUP_EXACT / LINK_RETRY_SAME_E2E_BLOB / LINK_RETRY_BLOB_COPY_OWN / LINK_RETRY_ELIGIBLE_AT_MAX / LINK_GROUP_ABSOLUTE_DEADLINE_IMMUTABLE / TIMER_MONOTONIC_OWNER_CLOCK:**

##### 11.2.1 Outbound owner/deadline matrix (closed)

Every queue/reserve admission below sets its deadline exactly once with checked `admit_mono + profile TTL`; overflow rejects admission, releases nothing as reusable until the failed reservation is unwound, and causes TX 0. A DATA LINK group copy-inherits the exact owner deadline; it never reads a source deadline from wire and never resets the deadline when ownership moves.

| outbound class | owning resource and immutable `enclosing_owner_deadline` | LINK retry group | ownership / release |
| --- | --- | --- | --- |
| local source FRAG_START/CONT | outgoing fragment transfer; `sender_absolute_deadline` | yes | group copy-owns sealed blob; transfer payload/state remains until terminal transfer |
| local source SINGLE | outgoing SINGLE owner; `single_sender_item_deadline` | yes | after successful E2E Seal + group copy-own, release SINGLE payload entry; group reports ACKED/terminal to upper owner |
| relay DATA (opaque SINGLE/FRAG/FRAG_ACK blob) | forwarding queue item; `forward_item_deadline` | yes | relay never uses source sender deadline; dequeue-to-group transfers deadline and copy-owns blob; group completion/fail applies §15.3.8 three-way cleanup before release |
| local fragment receiver FRAG_ACK | control ACK reserve; `min(control_ack_deadline, receiver_absolute_deadline)` for active PARTIAL or `min(control_ack_deadline, tombstone_expiry)` for terminal ACK | yes | group owns sealed ACK blob; ACKED/terminal/deadline applies §15.3.8 three-way cleanup before reserve/blob release |
| local LINK_ACK | ACK coalesce entry; `ack_coalesce_deadline` | **no** (ACK-of-ACK forbidden) | one prepared hop ACK candidate only; sole TX outcome/issue denial/deadline applies §15.3.8 three-way cleanup before release |

`single_sender_item_deadline = checked_add(single_admit_mono, single_sender_item_ttl_ms)`, `forward_item_deadline = checked_add(forward_admit_mono, forward_queue_ttl_ms)`, `control_ack_deadline = checked_add(control_reserve_mono, control_ack_reserve_ttl_ms)`, and `ack_coalesce_deadline = checked_add(coalesce_admit_mono, ack_coalesce_ttl_ms)`. All `*_mono` values and deadlines use the **single R2 authority clock domain** under §11.2.2 / §15.3.5 (`now_mono` is the trusted sample `now_ms` for the owner’s stored `clock_epoch_id`; never a second local/OS clock). Locally generated application replies re-enter as local SINGLE; endpoint ingress/upper-transport receive queues are not outbound owners.

- Group body: **one bit-identical immutable E2E sealed blob** (fixed `e2e_counter`) for the entire group. Link retries MUST **not** change the E2E blob.  
- **Copy-own** that blob (max **220 B**), independent of forward/ingress queues.  
- **Group admission (exactly once):** set `group_start_mono` once;  
  `group_absolute_deadline = checked_add(group_start_mono, link_retry_group_ttl_ms)` (**15000**) once, **immutable**.  
  **Pre-group fail (exact; aligns E2E_BLOB_RELEASE_TABLE):** if LINK group admission / copy-own / deadline `checked_add` **fails before** an admitted group exists ⇒ HOP STAMP/Permit/TX = **0**; release L1-owned E2E sealed blob **exactly once** only after no pending W1 borrow (`response_observed=true`); close upper owner **internally**; **no** E2E-pair `OWNER_TERMINAL`/`TX_RESULT`. Overflow before candidate creation is this same pre-group fail path.
- Each hop air candidate: durable fresh hop counter → outer Seal → digest/airtime → Permit (§15). At most one prepared candidate per group.  
- Hop attempt count: increment only when Permit consume proves success and the sole TX edge is invoked. A definite unconsumed retryable consume result invokes TX **0** and preserves the same exact permit/candidate only as §15.3 permits.  
- Attempts bound: **1 initial + max 3 retries = 4 hop air attempts**.  
- Clocks: single R2 authority clock domain only (§11.2.2); never wall time; never mix a separate local mono with authority `now_ms`. Deep sleep/rollback/epoch change/uncertain sample: fail-closed drop/fence volatile group before TX/ACK/deliver.  
- Per-attempt ACK timers (**only if `outer_ack_requested=1`**; **ACK_REQUESTED0_SKIPS_ACK_TIMER**):  
  - **`outer_ack_requested=1`:** `ack_deadline = checked_add(prior_tx_mono, link_ack_wait_ms)`; `interval_at = checked_add(prior_tx_mono, link_retry_interval_ms)`; `eligible_at = max(ack_deadline, interval_at)` (checked_add overflow ⇒ terminal fail). Next hop TX only if `now_mono >= eligible_at` AND no covering valid LINK_ACK AND `now_mono < group_absolute_deadline` AND `now_mono < enclosing_owner_deadline` AND Permit path succeeds under §15.  
  - **`outer_ack_requested=0`:** **skip** ACK timer / `ack_deadline` / `interval_at` / `eligible_at` computation entirely; timer overflow **cannot** fail that path. Group/enclosing deadlines before TX still apply. On edge success ⇒ **UNACKED_LINK_SUCCESS** after sibling/borrow cleanup; **no WAIT_LINK_ACK / no ACK retry** (TX_EDGE_DONE_ACK_POLICY).  
  The owner class is exactly one row of §11.2.1; the stricter group and enclosing-owner deadline always applies.  
- On group absolute deadline expiry: local fail and cancel unsent retries, then apply §15.3.8: unissued work may be released locally; issued/ambiguous work drains first; consume+edge-done work becomes stale/no-retry. Release the owned blob only after that branch completes.  
- **Valid LINK_ACK** = hop outer admission only (**not** fragment acceptance, not FRAG_ACK, not app receipt). On any valid LINK_ACK (§11.3) covering any pending sibling: group complete and cancel retries. The acknowledged consume+edge-done attempt is irrevocable/stale; any other sibling work still applies §15.3.8 before blob release.  
- Restart does not resume volatile groups. Crash-atomic exactly-once not claimed.


##### 11.2.2 L1 authority-clock domain + watermark (closed)

**L1_AUTHORITY_CLOCK_DOMAIN_ONLY / L1_SOLE_OWNER_AUTHORITY_CLOCK_WATERMARK / NOW_MONO_EQ_TRUSTED_SAMPLE_NOW_MS / W1_CLOCK_WATERMARK_REGRESSION_CLOSED / TIMER_MONOTONIC_OWNER_CLOCK / CELL_TIMER_DOMAIN_TABLE_CLOSED / CLASS_D_REQUIRES_BLOCKING_FENCE_CLEAR / CLOCK_FAULT_DURABLE_LATCH_RESTART_SURVIVES / CLASS_B_BOUNDED_THEN_OPERATOR_RECOVERY / L1_WATERMARK_HELD_UNTIL_ADOPT_DONE:**

Closed contract for **all** CELL_64_V1 timer/deadline rows (§13.1) and every L1-stamped `*_mono` field consumed by W1. **L1 is sole owner** of sample/baseline/adopt, epoch, and watermark. W1 does not store or copy-in epoch/watermark.

1. **One domain:** within one L1-stored `clock_epoch_id` that tracks R2 durable `meta.last_trusted_epoch_id` after each successful adopt, every L1 timestamp and deadline is a value in the **same R2 authority clock** domain that R2 uses for Permit `not_before`/`expiry`.  
2. **Identity:** `now_mono` **means** the `now_ms` of the latest **accepted** typed trusted sample from §11.2.3. No second local/OS mono and **no conversion**.  
3. **Sole-owner watermark (L1):** store `l1_last_accepted_epoch_id` and `l1_last_accepted_now_ms` (historical name `w1_last_accepted_*` means the same L1 fields).  
4. **Restart / cold init (RESTART_RECOVER_STORAGE_AFTER_BIND / BASELINE_SNAPSHOT_BOOT_ADOPT_ONLY):** after R2 storage bind, L1 **MUST** call exported-module `ninlil_pcp_recover_storage` (see §15.3.3 restart table). Then call §11.2.3.1 `ninlil_r2_private_load_authority_clock_baseline` to establish a private typed **baseline snapshot** `{epoch, now, fence_bits, fence_code, published, trusted_baseline_valid, provenance}` **before** any stamp/compare/issue. If unpublished/absent ⇒ no stamp and TX 0 until publish path. If `published=1` but `trusted_baseline_valid=0` (meta_state=2 INITIAL_UNTRUSTED_FENCED) ⇒ **L1 watermark absent**, TX 0 until fresh trusted recover/adopt to state1. Only when `trusted_baseline_valid=1` install **L1** epoch/watermark from snapshot. Never invent from host-time/OS mono. **There is no exported private-module R2/R5 getter for this baseline** and **exported `recover_clock` internal S is invisible** — guessing S from that API is **forbidden**.  
5. **Routine timer samples (SAMPLE_NO_ROUTINE_STORAGE_RO / SAMPLE_USES_RAM_TRUST_MIRROR):** normal §11.2.3 timer/issue samples **MUST NOT** open a storage RO txn each call. L1 compares platform sample **S** against **R2 ram_trust durable mirror** + **L1 watermark copy-in**. Storage RO / baseline load is **only** at boot, after storage recover, after adopt/prove, or when ram_trust invalid.  
6. **Four-way epoch class (EPOCH_CLASS_FOUR_WAY_CLOSED; exact; not OR-bulk):** let `S` = trusted platform sample epoch, `M` = ram_trust/`meta.last_trusted` epoch, `W` = L1 `clock_epoch_id` (absent if watermark_valid=0 / empty). Classify **exactly one**:

| class | exact condition | L1 action | R2 adopt? |
| --- | --- | --- | --- |
| **D** `EPOCH_SAME` | `S == M == W` (all present) + non-regression vs watermark and ram_trust now + **blocking CLOCK/STORAGE/CORRUPT fences clear** | accept; may stamp/advance watermark | **no** |
| **A** `EPOCH_W1_REPAIR` | `S == M` and (`W` absent **or** `W != S`) | freeze; **L1 bootstrap/repair only** from ram_trust/baseline/accepted S; class token name retained | **R2 adopt forbidden** |
| **B** `EPOCH_AUTHORITY_DIVERGENCE` | `S == W` and `S != M` (both S,W present) | freeze; **§15.3.3 drain + reconcile**; budget then `OPERATOR_RECOVERY_REQUIRED` | **not** intentional new-epoch adopt |
| **C** `EPOCH_NEW` | `S != M` and `S != W` (or S trusted and both M,W differ from S in the new-epoch sense) | freeze; **drain then §11.2.3.1 adopt** | **yes** after outstanding 0 |

**MUST NOT** treat A∨B∨C as one bulk “recover/adopt” path (**EPOCH_NO_OR_BULK_RECOVER**).  
7. **Watermark update:** only after class **D** accept: `l1_last_accepted_now_ms = S.now_ms`. TEMP/uncertain/rejected must not advance. On class **A** repair: set L1 from S/ram_trust without adopt. On class **C** adopt success: re-init **only** from private `sample_valid=1` result; **old L1 watermark held until adopt completes** (`L1_WATERMARK_HELD_UNTIL_ADOPT_DONE` synonym `W1_WATERMARK_HELD_UNTIL_ADOPT_DONE`) — never mid-path invent from exported `recover_clock`.  
8. **No cross-clock arithmetic.**  
9. **TEMP / UNCERTAIN vs CLOCK_FAULT (P1(28)):**  
   - **`CLOCK_UNCERTAIN` / TEMP (`CLOCK_UNCERTAIN_SAME_EPOCH_FRESH_OK` / `RADIO_VOLATILE_WORK_CLOSED`):** discard **entire** `radio_volatile_work` set (§1.1.1.3) for **all** owners; TX/ACK/deliver 0; no durable N6/R2 counter rollback. After later **trusted same-epoch** class-D **and fences clear**, only **fresh** burn/stamp/seal/issue (new tokens); no old-work resume.  
   - **`CLOCK_FAULT`** (`CLOCK_FAULT_REQUIRES_FRESH_EPOCH_ADOPT` / `CLOCK_FAULT_DURABLE_LATCH_RESTART_SURVIVES`): discard entire `radio_volatile_work`; **same-epoch resume and same-epoch fresh admission both forbidden** until **fresh-epoch** class-C adopt succeeds **and** durable CLOCK_FAULT latch is cleared. Not `RETRYABLE_UNISSUED`.  
9b. **Class-D requires blocking fence clear (`CLASS_D_REQUIRES_BLOCKING_FENCE_CLEAR`):** even when `S==M==W` and non-regression holds, L1 **MUST NOT** accept class D / stamp / issue while **CLOCK**, **STORAGE**, or **CORRUPT** blocking fence bits (docs/24) are set.  
9c. **CLOCK_FAULT sole durable authority (`CLOCK_FAULT_FC_BY_R2_SAMPLE` / `CLOCK_FAULT_SOLE_R2_META_FC`):** sole durable store = docs/24 R2 meta **CLOCK bit** + **`fence_code` F_c**. No radio-security alternate latch. **R2 private sample (and every R2 entry that can observe CLOCK_FAULT: issue/validate/consume/recover/adopt)** MUST call the same R2 helper that FULL-commits F_c **before** returning CLOCK_FAULT to L1. L1 **never** writes R2 meta. **Three-axis (sample closed):** `business_mutation=BUSINESS_ZERO` always; `durable_meta_mutation`/`txn_provenance` follow helper outcome — F_c FULL_OK → `SAMPLE_CLOCK_FAULT` + `F_C_FULL` + `CLOCK_FENCE_COMMITTED` on **published** meta; F_c COMMIT_UNKNOWN → `SAMPLE_COMMIT_UNKNOWN` + `META_AMBIGUOUS` + `AMBIGUOUS` + storage recover (**MUST NOT** collapse CU to `META_ZERO` or reclassify as `SAMPLE_CLOCK_FAULT`); definite fail → STORAGE/CORRUPT. Issue provenance may include `CLOCK_FENCE_COMMITTED`. Restart: baseline reads meta; same-epoch admit forbidden while CLOCK set. Fresh-epoch adopt / recover from state2: same FULL sets meta_state=1 TRUSTED_BASELINE_PRESENT, writes trusted last_trusted_*=S, clears CLOCK+clock fence_code (preserve stronger STORAGE/CORRUPT). From state1, adopt updates last_trusted and clears CLOCK+code without demoting state.  

**Published-meta CLOCK_FAULT entrypoints** (private sample after published gate, issue, validate, consume, recover paths that classify PERM clock, adopt precheck) MUST call **common helper** `ninlil_r2_private_commit_clock_fault_fence` that FULL-commits CLOCK+F_c on **existing** meta **before** returning CLOCK_FAULT. Helper **MUST NOT** create first meta. **First-publish FENCED** is solely docs/24 §9.2 `publish_initial_meta` P3-FENCED path. Unpublished sample → `SAMPLE_META_UNPUBLISHED` without clock/helper. L1 never writes R2 meta. CU on F_c → COMMIT_UNKNOWN; definite fail → STORAGE/CORRUPT.

9d. **Class-B finite convergence (`CLASS_B_BOUNDED_THEN_OPERATOR_RECOVERY`):** when authority cannot be re-established (`S==W != M`), L1 drain+reconcile uses episode budget (max 8, no same-tick spin). After budget still dual-truth ⇒ **`OPERATOR_RECOVERY_REQUIRED`**, sticky TX 0; **permanent class-B loop forbidden**.  
10. **External route lease** / host-time: unchanged (route TX 0 if external domain; host-time profile window forbidden for R6 0x11).

##### 11.2.3 R7 private authority-clock sample primitive (closed)

**R7_PRIVATE_AUTHORITY_SAMPLE_PRIMITIVE / SAMPLE_PRIMITIVE_CLOSED_REQUEST_RESULT / SAMPLE_DURABLE_RO_OUTCOMES_CLOSED / SAMPLE_NO_COLLAPSE_TO_UNBOUND:**

There is **no** existing exported private-module R5/R2 C API that is sole-owned for L1 timer stamps with typed class + epoch/watermark contract (**EXPORTED_PRIVATE_MODULE_C_API_NOT_OSS_PUBLIC** — names are process-local private modules, not installed OSS public ABI). R7 **MUST** implement:

**Private name:** `ninlil_r2_private_sample_authority_clock` (R2 private module; docs/24 re-freeze required).

**Sole owner:** **L1 private Radio Coordinator** only. W1 codec and other callers **MUST NOT** sample the R2 compliance clock.

**Closed request (L1-supplied copy-in; no implicit L1/W1 object load; `SAMPLE_NO_IMPLICIT_W1_LOAD`):**
```text
request = {
  expected_epoch_id,          /* 16B copy-in; L1 stored clock_epoch_id */
  watermark_valid,            /* 0 | 1 copy-in */
  watermark_epoch_id,         /* 16B copy-in; meaningful iff watermark_valid=1 */
  watermark_now_ms            /* u64 copy-in; meaningful iff watermark_valid=1 */
}
```
The primitive **MUST NOT** reach into caller RAM/L1 structs beyond this explicit **copy-in** `request`. **L1** (sole owner) **MUST** copy expected epoch + watermark fields into `request` at call entry. W1 **MUST NOT** form this request. Durable meta / ram_trust RO is authority state, not an implicit L1 reference.

**Closed result:**
```text
result = {
  typed_class,                /* SAMPLE_* closed enum below — never collapsed */
  sample_epoch_id, sample_now_ms, sample_trust,  /* only if class exposes sample; else zero/ignore */
  meta_published,             /* 0|1 when RO meta path completed OK shape */
  meta_state,                 /* 0 unpublished | 1 TRUSTED_BASELINE_PRESENT | 2 INITIAL_UNTRUSTED_FENCED */
  trusted_baseline_valid,     /* 1 only for a valid state1 trusted baseline; independent of publication */
  meta_last_trusted_epoch_id, meta_last_trusted_now_ms,  /* valid iff trusted_baseline_valid=1; else zero */
  fence_bits, fence_code,     /* docs/24 closed; valid when meta path shape OK */
  business_mutation,          /* closed: BUSINESS_ZERO only on sample (no permit/ISSUED/profile/counter put) */
  durable_meta_mutation,      /* closed: META_ZERO | F_C_FULL | META_AMBIGUOUS */
  txn_provenance,             /* closed: PRECHECK_ZERO | CLOCK_FENCE_COMMITTED | AMBIGUOUS — never bare/open provenance */
  result_catalog = R2_PCP,    /* sample is R2 catalog only */
  exact_status, stage, reason
}
```
Hint-string parse forbidden. TEMP/PERM/unknown **MUST NOT** expose trust/epoch/now for deadline math (docs/24 §3.3).

**Three-axis mutation contract (exact; sample path closed enums):**
- `business_mutation` closed = **`BUSINESS_ZERO` only** (every sample class).
- `durable_meta_mutation` closed = **`META_ZERO` | `F_C_FULL` | `META_AMBIGUOUS`**.
- `txn_provenance` closed = **`PRECHECK_ZERO` | `CLOCK_FENCE_COMMITTED` | `AMBIGUOUS`** (no ambiguous bare provenance outside this set).
- TEMP/UNCERTAIN / unpublished / ordinary no-mutation sample outcomes: **`BUSINESS_ZERO` / `META_ZERO` / `PRECHECK_ZERO`**.
- F_c helper **FULL_OK** → typed_class **`SAMPLE_CLOCK_FAULT`** + **`BUSINESS_ZERO` / `F_C_FULL` / `CLOCK_FENCE_COMMITTED`** on an **already published** meta.
- F_c helper **COMMIT_UNKNOWN** → typed_class **`SAMPLE_COMMIT_UNKNOWN`** + **`BUSINESS_ZERO` / `META_AMBIGUOUS` / `AMBIGUOUS`** + storage recovery; **MUST NOT** collapse CU to `META_ZERO` and **MUST NOT** reclassify as `SAMPLE_CLOCK_FAULT`.
- `SAMPLE_META_UNPUBLISHED`: **`BUSINESS_ZERO` / `META_ZERO` / `PRECHECK_ZERO`**; **MUST NOT** call platform clock; **MUST NOT** create meta.
- **Forbidden:** any blanket non-FULL⇒`META_ZERO` collapse of COMMIT_UNKNOWN or other non-FULL helper outcomes while still claiming a clock-fault latch.

**Contract body (one call; routine path uses ram_trust mirror):**
0. **Published gate (before clock):** if authority meta is unpublished/empty (no KEY_META after clean classify, or published flag 0), return `SAMPLE_META_UNPUBLISHED` **without** calling `clock.now` and without helper. First meta creation is **only** `ninlil_pcp_publish_initial_meta` (docs/24 §9.2).  
1. Invoke R2-bound platform clock once under docs/24 §3. **No second sample.** Call this sample **S**.  
2. **Floor source (closed):**  
   - **Routine** (`SAMPLE_NO_ROUTINE_STORAGE_RO`): use **R2 ram_trust** mirror only when `ram_trust.valid=1` from a prior **trusted** baseline/state1 path (`trusted_baseline_valid=1`); **MUST NOT** `begin(RO)/get(meta)` on the timer hot path. If ram_trust invalid or only state2 published ⇒ `SAMPLE_TRUST_MIRROR_INVALID` → boot/recover baseline path (not silent invent). **Routine must not treat state2 zero epoch as a valid M floor.**  
   - **Boot / post-storage-recover / post-adopt prove only** (`BASELINE_SNAPSHOT_BOOT_ADOPT_ONLY`): may run durable meta RO or `load_authority_clock_baseline` to publish typed snapshot `{epoch, now, fence, published, provenance}` into ram_trust. RO outcomes closed below.  
3. **RO outcomes (boot/recover path only; three-axis exact):**

| RO / precheck outcome (exact) | typed_class | sample fields | business_mutation | durable_meta_mutation | txn_provenance | L1 action |
| --- | --- | --- | --- | --- | --- | --- |
| clock unbound / pcp not ready for sample | `SAMPLE_UNBOUND` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | TX 0; no stamp |
| `BUSY` / `BUSY_OUTSTANDING` | `SAMPLE_BUSY` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | TX 0; bounded retry; **not** UNBOUND |
| `BUSY_REENTRY` | `SAMPLE_REENTRY` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | TX 0; **not** UNBOUND |
| `ALIAS` | `SAMPLE_ALIAS` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | TX 0; **not** UNBOUND |
| `SHUTDOWN` | `SAMPLE_SHUTDOWN` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | TX 0; **not** UNBOUND |
| `STORAGE_IO` definite | `SAMPLE_STORAGE_IO` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | TX 0; **not** UNBOUND |
| `COMMIT_UNKNOWN` / dual-truth (incl. F_c CU) | `SAMPLE_COMMIT_UNKNOWN` | no | BUSINESS_ZERO | META_AMBIGUOUS | AMBIGUOUS | freeze; §15.3.3 storage recover; **not** UNBOUND; **not** SAMPLE_CLOCK_FAULT |
| `CORRUPT` / FOREIGN / I* fail | `SAMPLE_CORRUPT` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | freeze; recover/fence; **not** UNBOUND |
| meta key absent after clean RO | `SAMPLE_META_UNPUBLISHED` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | TX 0 until publish |
| ram_trust invalid on routine path | `SAMPLE_TRUST_MIRROR_INVALID` | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | force baseline load; **not** UNBOUND |

**MUST NOT** map BUSY / STORAGE_IO / COMMIT_UNKNOWN / CORRUPT / ALIAS / REENTRY / SHUTDOWN into `SAMPLE_UNBOUND`. **MUST NOT** map F_c COMMIT_UNKNOWN into `META_ZERO` or `SAMPLE_CLOCK_FAULT`.

4. **Trusted sample + four-way epoch class** (floors = ram_trust or baseline snapshot; request carries L1 copy-in; three-axis exact):

| typed_class | meaning (exact) | sample fields valid | business_mutation | durable_meta_mutation | txn_provenance | L1 action |
| --- | --- | --- | --- | --- | --- | --- |
| `SAMPLE_TRUSTED_SAME_EPOCH` | class **D**: well-formed TRUSTED; `S.epoch == W == M`; non-regression; **blocking fences clear** | yes | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | accept; stamp; advance watermark |
| `SAMPLE_W1_REPAIR` | class **A**: `S.epoch == M` and W absent/mismatch | yes | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | freeze; **L1 bootstrap/repair only**; **R2 adopt forbidden** |
| `SAMPLE_AUTHORITY_DIVERGENCE` | class **B**: `S.epoch == W` and `S.epoch != M` | yes | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | freeze; **drain + reconcile**; budget then `OPERATOR_RECOVERY_REQUIRED` |
| `SAMPLE_EPOCH_TRANSITION_REQUIRED` | class **C**: `S` differs from both W and M (new epoch) | yes (adopt input) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | freeze; drain then **adopt** |
| `SAMPLE_TEMP_UNCERTAIN` | port TEMP or OK+UNCERTAIN | no | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | discard old work; later **same-epoch** trusted class-D ⇒ fresh admission OK |
| `SAMPLE_CLOCK_FAULT` | PERM/ill-formed/unknown; same-epoch regression vs watermark/ram_trust; helper FULL OK | no | BUSINESS_ZERO | F_C_FULL | CLOCK_FENCE_COMMITTED | discard; **same-epoch admission forbidden**; require **fresh-epoch adopt** + durable latch |

5. All 21 §13.1 timers and every L1 `*_mono` stamp **MUST** obtain time only via this primitive (explicit L1 `request` copy-in). W1 never stamps.  
6. **Durable floor compare** uses ram_trust now (routine) or baseline snapshot (boot); regression ⇒ `SAMPLE_CLOCK_FAULT`.

##### 11.2.3.1 Private authority-clock baseline family (load + adopt; one closed contract)

**PRIVATE_LOAD_AUTHORITY_CLOCK_BASELINE / PRIVATE_ADOPT_ATOMIC_NO_ARM_FENCE / adopt sample copy-out FULL_OK only / ADOPT_COMMITTED from durable proof / public recover_clock no sample visibility:**

Exported private-module R2 exposes **no** durable `meta.last_trusted_*` getter and **exported `ninlil_pcp_recover_clock` does not return a sample**. Therefore L1 **MUST NOT** specify `ADOPT_W1_INIT` as using any sample from exported-module `recover_clock` — that API returns **no** sample and that path is **not implementable**. R7 implements **one private family** with closed signatures below.

###### A. Baseline load (restart / post-storage-recover proof; mutation 0)

**Private name:** `ninlil_r2_private_load_authority_clock_baseline`

```text
request = { }   /* pcp identity only */
result = {
  published,                 /* 0 | 1 — KEY_META present after clean RO */
  trusted_baseline_valid,    /* 0 | 1 — independent of published */
  last_trusted_epoch_id,     /* meaningful iff trusted_baseline_valid=1; else 16×0 */
  last_trusted_now_ms,       /* meaningful iff trusted_baseline_valid=1; else 0 */
  fence_bits, fence_code,    /* docs/24 closed codes only */
  meta_state,                /* 1 TRUSTED_BASELINE_PRESENT | 2 INITIAL_UNTRUSTED_FENCED | 0 if unpublished */
  result_catalog = R2_PCP,   /* baseline is R2 catalog only */
  exact_status, stage, reason, provenance
  /* typed baseline snapshot := {epoch, now, fence_bits, fence_code, published, trusted_baseline_valid, meta_state, provenance} */
}
```
Mutation **0**. **Boot / post-storage-recover / post-adopt prove only** — not the timer hot path.

**published vs trusted (exact closed baseline load result rows):**

| case | published | meta_state | trusted_baseline_valid | last_trusted epoch/now | ram_trust.valid | L1 action |
| --- | ---: | ---: | ---: | --- | --- | --- |
| unpublished | 0 | 0 | 0 | zero | 0 | TX 0 until first publish (no KEY_META) |
| state1 TRUSTED_BASELINE_PRESENT | 1 | 1 | 1 | nonzero + shape OK | may set 1 | may install L1 watermark |
| state2 INITIAL_UNTRUSTED_FENCED | 1 | 2 | 0 | zero | ram_trust.valid **must remain 0** | L1 watermark absent; CLOCK fence present; **TX 0** until fresh trusted recover/adopt to state1 |

- recover_storage / baseline **MUST NOT** set ram_trust.valid=1 for state2 or zero epoch.

**MUST NOT** invent from OS mono, exported `recover_clock` invisible S, or discarded samples.

###### B. Atomic adopt + recovery proof (sole 120 B form)

**Private name:** `ninlil_r2_private_adopt_authority_epoch`  
**ADOPT_CU_PROOF_FIXED_120B_ONLY / DURABLE_META_PROOF / PRIVATE_PROVE_ADOPT_AUTHORITY_EPOCH / ADOPT_OLD_PRESENT_FIXED_1:**

**Precondition:** KEY_META **must already exist** as a valid 200 B LE image (shape/CRC/meta_state invariant OK). NOT_FOUND ⇒ **ADOPT_CORRUPT** (not retry). Direct adopt **proposed image is derived only from that exact existing 200 B image** (immutable fields kept; last_trusted/proposed epoch-now; meta_state→1; CLOCK clear per docs/24; CRC recomputed).

```text
request = { pcp; expected_l1_epoch_id[16]; l1_watermark_*; expected_meta_epoch_* }
result = {
  typed_adopt_class, sample_valid, sample_epoch_id[16], sample_now_ms, sample_source,
  /* sample_source closed: ACCEPTED_SAMPLE | DURABLE_META_PROOF | BASELINE_LOAD */
  recovery_proof_valid, recovery_proof[120],
  result_catalog = R2_PCP,   /* adopt/prove is R2 catalog only */
  exact_status, stage, reason, provenance
}
```

**Sole recovery_proof (exactly 120 bytes continuous BE).** Forms of 64/72 B and opaque tokens are **abolished**. `old_present` is **REQUIRED constant 1** (not 0|1). There is **no** old_present=0 proof form and **no** absent-meta adopt path.

| off | end | sz | field |
| ---: | ---: | ---: | --- |
| 0 | 2 | 2 | proof_schema = 1 u16 BE |
| 2 | 4 | 2 | flags/reserved = 0 u16 BE |
| 4 | 20 | 16 | attempt_id nonzero |
| 20 | 36 | 16 | proposed_epoch_id |
| 36 | 44 | 8 | proposed_now_ms u64 BE |
| 44 | 76 | 32 | old_meta_digest |
| 76 | 108 | 32 | proposed_meta_digest |
| 108 | 109 | 1 | old_present = **1** (constant) |
| 109 | 110 | 1 | proposed_present = 1 |
| 110 | 116 | 6 | reserved = 0 |
| 116 | 120 | 4 | proof_crc32c of bytes[0,116) |

**proof_crc32c (exact):** CRC32C Castagnoli poly `0x82f63b78`, init XOR `0xffffffff`, final XOR `0xffffffff`, result stored **u32 BE**, coverage = proof bytes `[0,116)`.

**Digest:** `SHA-256( ASCII("NINLIL-R2-META-V1") || present_byte || meta_bytes_200 )` with present_byte=**1** and meta_bytes_200 = exact stored **200-byte LE** KEY_META after shape/CRC/invariant OK. (Absent present_byte=0 image is **not** used for adopt.)

**Proposed digest image:** derived from the **exact existing valid 200 B LE meta** only (immutable fields kept; last_trusted=proposed; meta_state=1; CLOCK clear; fence_code per docs/24; CRC recomputed). proof proposed_epoch/now MUST match that image.

**Atomic (meta exists):** outstanding gate; sample once S; class C/fresh_epoch or state2→trusted path; RW last_trusted=S, meta_state=1, clear CLOCK/F_c (preserve stronger bits); FULL OK→ADOPT_OK with sample_valid=1 sample_source=**ACCEPTED_SAMPLE**; CU→proof_valid=1 sample_valid=0; hold 120 B proof for prove.

###### C. `ninlil_r2_private_prove_adopt_authority_epoch`

No new sample. `result_catalog=R2_PCP`. Validate proof: schema/flags; **old_present MUST equal 1**; proposed_present=1; proof_crc32c exact Castagnoli parameters above; attempt_id and proposed_epoch/now match proof image on success paths.

**Closed durable load classify (exact; old_present=0 branch deleted):**
1. begin RO; get KEY_META capacity≥200; status/output-shape closed (§9.3).
2. **NOT_FOUND** (clean or not) → **ADOPT_CORRUPT** (meta required).
3. OK + shape/CRC/meta_state invariant fail → ADOPT_CORRUPT.
4. OK + 200 B LE OK → live_digest = SHA-256(domain||1||meta200).
5. live_digest == old_meta_digest → `ADOPT_NOT_COMMITTED_RETRY` (sample_valid=0).
6. live_digest == proposed_meta_digest **and** proposed_epoch/now match image exactly → `ADOPT_COMMITTED` with sample_valid=1, sample_source=**DURABLE_META_PROOF**, sample fields from proposed.
7. else → ADOPT_CORRUPT (THIRD).

**sample_source closed:**
- `ACCEPTED_SAMPLE` — only direct adopt FULL_OK.
- `DURABLE_META_PROOF` — prove when proposed digest matches.
- `BASELINE_LOAD` — baseline API only; never prove.

CU/unknown dual-truth → typed COMMIT_UNKNOWN / storage recover; not silent ADOPT_OK. class A forbidden on adopt prove. Restart: proof gone → baseline only. never publish unaccepted S.

| phase | exact steps | success | failure |
| --- | --- | --- | --- |
| `ADOPT_STOP` | stop issue/TX | — | — |
| `ADOPT_DRAIN` | exported private-module drain to outstanding 0 | outstanding 0 | sticky TX 0 |
| `ADOPT_ATOMIC` | adopt once (existing meta only) | ADOPT_OK | CU hold 120 B proof; NOT_FOUND CORRUPT |
| `ADOPT_PROVE` | prove API | ADOPT_COMMITTED | OLD retry / CORRUPT |
| `ADOPT_INIT` | sample_valid=1: L1 watermark from result | — | invent forbidden |
| `ADOPT_FRESH_ADMISSION` | fences clear + profile ok | resume | TX 0 |

Exact timer-domain/fault-action table (set equality gated; one row per §13.1 timer):

| timer | domain | on epoch change / uncertain / regression |
| --- | --- | --- |
| `link_ack_wait_ms` | R2 authority epoch domain | drop LINK group; TX 0 |
| `link_retry_interval_ms` | R2 authority epoch domain | drop LINK group; TX 0 |
| `link_retry_group_ttl_ms` | R2 authority epoch domain | drop LINK group + three-way cleanup |
| `ack_coalesce_ttl_ms` | R2 authority epoch domain | drop coalesce entry; ACK 0 |
| `e2e_ingress_queue_ttl_ms` | R2 authority epoch domain | drop ingress item; LINK_ACK 0 |
| `upper_transport_queue_ttl_ms` | R2 authority epoch domain | drop upper item; deliver 0 |
| `single_sender_item_ttl_ms` | R2 authority epoch domain | drop SINGLE owner; three-way cleanup |
| `forward_queue_ttl_ms` | R2 authority epoch domain | drop forward item; TX 0 |
| `forward_peer_ttl_ms` | R2 authority epoch domain | drop peer quota; TX 0 |
| `frag_ack_wait_ms` | R2 authority epoch domain | sender transfer terminal path; three-way cleanup |
| `frag_retry_interval_ms` | R2 authority epoch domain | no schedule across epoch |
| `frag_sender_transfer_ttl_ms` | R2 authority epoch domain | drop outgoing transfer; three-way cleanup |
| `frag_receiver_transfer_ttl_ms` | R2 authority epoch domain | drop reassembly/reservation/tombstone/ACK intent |
| `frag_idle_timeout_ms` | R2 authority epoch domain | same as receiver absolute |
| `frag_partial_ack_idle_ms` | R2 authority epoch domain | drop PARTIAL intent; ACK 0 |
| `tombstone_ttl_ms` | R2 authority epoch domain | drop tombstone/reservation |
| `context_fence_ttl_ms` | R2 authority epoch domain | reclaim only under CONTEXT_FENCE_STAMP_EPOCH_RECLAIM_CLOSED |
| `route_lease_check_ms` | R2 authority epoch domain; external lease not same-domain ⇒ route TX 0 | revalidate or TX 0 |
| `control_ack_reserve_ttl_ms` | R2 authority epoch domain | release reserve; ACK 0 |
| `permit_issue_retry_ms` | R2 authority epoch domain | cancel issue retry schedule; three-way cleanup |
| `permit_tx_retry_ms` | R2 authority epoch domain | cancel full-pipeline retry; three-way cleanup |

#### 11.3 LINK_ACK RX validation (DATA sender / pending-owner)

**LINK_ACK_RX_VALIDATE_SEPARATE** — independent of TX-generation; requires **all** of:

1. Structural parse (profile, length 51, route 0/0 remaining 0, ack_code domain)  
2. Reverse hop **ACK-lane** context lookup + RX replay precheck  
3. Hop ACK-lane AEAD Open  
4. Hop ACK-lane durable RX admission of the LINK_ACK’s own hop_counter  
5. **Exact pair:** ACK outer context is the reverse ACK-lane of the handshake pair for `acked_hop_context_id`  
6. Bitmap/base rules (§11); `acked_hop_context_id` names a live peer **DATA** TX lane owned here; `ack_base` ≤ largest allocated DATA counter for that lane  

Only after steps 1–6 may **pending** DATA counters in a retry group mutate.  
Stale/duplicate/unsent-burned bits: no effect (safe).  

**NO_LINK_ACK_OF_LINK_ACK**

## 12. Fragmentation

All multi-byte FRAG/LINK fields are **big-endian** unless noted.

### 12.1 FRAG_START PT

```text
LAYOUT_FRAG_START_BEGIN
off  end  sz  field
0    16   16  transfer_id_128
16   24   8   transfer_handle (u64 BE)
24   28   4   total_len (u32 BE)
28   30   2   frag_count (u16 BE)
30   32   2   continuation_unit (u16 BE) = 180 exact
32   64   32  content_digest (SHA-256)
LAYOUT_FRAG_START_END
/* + first_chunk S bytes */
```

Domains: `1 ≤ S ≤ 126`, `S < total_len ≤ 2048`, `continuation_unit = 180` exact.  
`frag_count = 1 + ceil((total_len - S) / 180)` with `2 ≤ frag_count ≤ 16`.  
Outer total = **129+S** (check 129+S ≤ 255 ⇒ S≤126). Packet domain **130..255**.

**TRANSFER_HANDLE_SENDER_ENCODER_RULE / FIRST_FRAG_START_TEMPLATE_HANDLE_INJECT (exact; same 7 events):**  
- **First** START attempt uses STAMP `seal_input_kind=FIRST_FRAG_START_TEMPLATE` (class2): immutable input template has `transfer_handle` octets **16..23 exact zero**. After durable E2E burn, W1 copies the template into the L1-owned **output work slot** and injects the burned `e2e_counter` as **u64 BE** into that copy as `transfer_handle`, then Seals the derived final PT. Source template remains immutable. handle **0** and **UINT64_MAX** reject after inject.  
- E2E START **retry after first** uses `seal_input_kind=E2E_PLAINTEXT` carrying the original **nonzero** `transfer_handle`; a fresh `e2e_counter` **MUST NOT** overwrite handle.  
**NO_SENDER_TRANSFER_HANDLE_REUSE_IN_E2E_CTX:** sender MUST never reuse a `transfer_handle` **or** a `transfer_id_128` for a **different** transfer within the same `e2e_context_id`.  
**DECODER_NO_HANDLE_EQ_OBSERVED_COUNTER:** decoder MUST NOT require `transfer_handle == observed e2e_counter`.  
Reassembly key = `(e2e_context_id, transfer_handle)`.

**LINK_RETRY_SAME_E2E_BLOB vs FRAG_E2E_RETRY_FRESH_SEAL (layer split — hop outer vs E2E seal are not interchangeable):**

| layer | what is retried | E2E sealed blob / e2e_counter | hop outer DATA counter | attempt accounting |
| --- | --- | --- | --- | --- |
| **LINK retry group** (§11.2) | same hop-delivered frame | **one bit-identical E2E sealed blob** and its **same** `e2e_counter` for the whole group | each air attempt allocates a **fresh hop DATA counter only** | 1 initial + max 3 link retries = 4 hop TX attempts; does **not** consume additional E2E counters |
| **E2E fragment retry** | START or CONT body after link-group failure / FRAG_ACK PARTIAL/loss policy requires fragment retry | MUST **rebuild same fragment plaintext fields** under a **fresh `e2e_counter`** and **fresh E2E Seal/blob**; then start a **new** LINK retry group for that new blob | new group's first attempt + its link retries | counts as a **new fragment-layer attempt** under §12.2 (1+3 per fragment); **reusing a prior E2E blob/counter for end-to-end fragment retry is forbidden** (RX would treat as duplicate / block ACK regeneration) |

START body on E2E fragment retry **retains original `transfer_handle` and `transfer_id_128`** even though the new START uses a new `e2e_counter`. CONT retains original handle. Do not silently multiply or omit either layer's attempt counters.

**CONTENT_DIGEST_SHA256_REASSEMBLED:** `content_digest = SHA-256(exact total_len reassembled bytes)`.

**FRAG_TOMBSTONE_FINGERPRINT:**

```text
start_manifest_fingerprint32 = SHA-256(
  transfer_id_128 || transfer_handle_be64 || total_len_be32 ||
  frag_count_be16 || continuation_unit_be16 || content_digest32 || first_chunk_S_bytes)
```

**FRAG_DUAL_UNIQUE_INDEX_HANDLE_AND_TRANSFER_ID / FRAG_CONFLICT_NO_REPLACE_EXISTING / FRAG_START_EXACT_RETRY_NO_MUTATION:**  
While active or tombstoned, maintain dual unique indexes:

1. `(e2e_context_id, transfer_handle)`  
2. `(e2e_context_id, transfer_id_128)`  

On START that hits an existing active or tombstone entry on **either** index:

**A. Exact same-fingerprint retry** (`start_manifest_fingerprint32` equal):

| state | rules |
| --- | --- |
| **active** | second transfer/reassembly allocation/reservation **0**; **no** reassembly state / bitmap / payload / TTL mutation; **no second** body-state counter mutation. The incoming retry's fresh forward E2E counter was already durably admitted before this body branch. MUST create/refresh the ephemeral current-bitmap PARTIAL intent under §12.2; actual ACK TX remains conditional on a distinct fresh counter in the paired reverse E2E lane, control reserve, owner deadline, and Permit. |
| **terminal** (COMPLETE/ABORT tombstone) | reassembly / re-handoff / upper-queue / tombstone field mutation **0**; **no** TTL extension; **no second** transfer/resource allocation or body-state counter mutation. Forward replay admission remains separate. MAY emit fresh reverse FRAG_ACK with **stored** COMPLETE/ABORT status; it uses a distinct fresh reverse E2E counter and the same permit/reserve rules. |

**B. Non-exact collision** (different fingerprint and/or transfer_id/handle mismatch under dual index):

- **second allocation = 0**  
- MUST **not** replace, overwrite, or rewrite the existing active state or COMPLETE/ABORT tombstone  
- local structured **CONFLICT**  
- if Permit + reverse owner + control reserve: MAY ephemeral reverse FRAG_ACK **ABORT CONFLICT** to the **incoming** handle; else TX 0  
- original tombstone/active remains; exact retries of the **original** manifest still follow branch A  

Exact-retry MUST NOT be classified as CONFLICT.  
Tombstones/START reservations are **volatile** (R6 V1): restart discards them; not crash-atomic exactly-once (**TOMBSTONE_VOLATILE_ON_RESTART**).

### 12.2 FRAG_CONT PT (single definition)

```text
LAYOUT_FRAG_CONT_BEGIN
off  end  sz  field
0    8    8   transfer_handle (u64 BE)
8    10   2   frag_index (u16 BE, 1..frag_count-1)
LAYOUT_FRAG_CONT_END
/* + chunk_bytes C */
```

Outer total **75+C**, `1 ≤ C ≤ 180`. Packet domain **76..255**.  
Canonical offset: `offset = S + (index-1)*180`.  
Non-last C==180; last C==remaining.  
**CONT-before-START:** no active reassembly and no live tombstone for handle → **allocation 0 / drop**. CONT cannot create a transfer.  
Active: duplicate CONT same index+bytes → no bitmap/payload/TTL or second transfer/resource mutation after its fresh forward E2E counter was durably admitted; an optional ACK burns only a distinct fresh paired reverse E2E counter. Different bytes → **CONT_CONFLICT_ABORT_TOMBSTONE** (§12.2b).  
**Live tombstone CONT:** key `(e2e_context_id, transfer_handle)` + valid stored frag_count/index; may emit stored terminal FRAG_ACK; no reassembly/re-handoff. **FRAG_CONT_NO_FINGERPRINT.**

**FRAG_SENDER_TIMING_EXACT / FRAG_MAX_OUTER_ATTEMPTS_PER_FRAGMENT_16 / RECEIVER_ABSOLUTE_DEADLINE_IMMUTABLE / FRAG_RECEIVER_TRANSFER_TTL_90000 / FRAG_PARTIAL_ACK_LIVENESS:**

Sender accounting is **two-layer with explicit preparation burns** (checked fail-closed mono arithmetic on the §11.2.2 authority clock domain; no wall time; no second local clock):

| layer | bound | notes |
| --- | ---: | --- |
| E2E preparation burns per fragment | **4** = 1+3 | successful durable burn consumes a slot even if Seal fails (§15.1) |
| successful E2E Seals per fragment | **≤4** | each Seal starts at most one LINK group |
| hop preparation burns per LINK group | **4** = 1+3 | successful durable hop burn consumes a slot even if outer preparation fails (§15.2) |
| hop air attempts per LINK group | **≤4** | same blob; each requires consume success + sole TX invoke (§15.2–15.3) |
| **FRAG_MAX_OUTER_ATTEMPTS_PER_FRAGMENT** | **16** = 4×4 | bound/accounting only; not TX permission |

**Outgoing transfer admission (once):** as §15.1 — immutable `transfer_start_mono` / `sender_absolute_deadline`; first START `transfer_handle` = first burned E2E counter (never reused on Permit denial).

**Fragment sender state machine (exact):**

1. Admit the outgoing transfer once, reserve its bounded payload/state, and compute the immutable sender deadline. Admission failure ⇒ local structured fail, all radio/FRAG_ACK TX 0.
2. For each required START/CONT, claim E2E preparation `k` in **1..4**, then burn a fresh E2E counter. Attempt creation requires `now_mono < sender_absolute_deadline`. Seal success creates the blob and exactly one LINK retry group. Seal/encode failure consumes preparation `k`, sets `e2e_preparation_terminal_mono` once, starts no LINK group, and enters the bounded retry branch in step 5.
3. A fully validated FRAG_ACK may arrive in **any** active sender state, including before LINK_ACK. COMPLETE/ABORT terminates the transfer and initiates cancellation of all current LINK groups/candidates **only through §15.3.8**. PARTIAL updates only the validated bitmap; if it covers the fragment carried by a current LINK group, end that group as `SUPERSEDED_BY_FRAG_ACK` and run the §15.3.8 cancel matrix: unissued candidate only may local-release; any **issued** Permit requires §15.3.3 closed global reconciliation (local discard of issued Permit alone is forbidden); consume+edge-done becomes stale/no-retry. A PARTIAL not covering that fragment does not stop its group. A later LINK_ACK for a released/superseded group is stale and mutates nothing.
4. After each successful consume+TX, a covering valid LINK_ACK completes the group as `ACKED`. If none arrives by the checked `eligible_at` and fewer than four air attempts were invoked, the same group may create its next fresh **hop** counter/outer candidate while retaining the bit-identical E2E blob. Attempt/preparation-burn exhaustion, group/enclosing deadline, non-retryable Permit issue denial, Permit expiry/plan fence, definite unconsumed non-retryable result, or consume/TX outcome unknown ends the group as `TERMINAL_FAIL`. Set `group_terminal_mono` exactly once, then apply §15.3.8 before releasing its blob/candidate; an issued or ambiguous Permit can never be released locally.
5. On LINK `TERMINAL_FAIL`, create no replacement hop candidate in that group. Let `attempt_terminal_mono` be its `group_terminal_mono`, or `e2e_preparation_terminal_mono` when step 2 failed before a group. If `k < 4`, checked-compute `retry_not_before = max(checked_add(attempt_terminal_mono, frag_retry_interval_ms), checked_add(e2e_attempt_start_mono, frag_retry_interval_ms))`; only after the failed group completes §15.3.8 cleanup, at/after that time, and before the sender deadline may fragment E2E preparation `k+1` be created. Otherwise terminal local fail; release outgoing resources only after all related work completes §15.3.8; FRAG_ACK TX 0.
6. On `ACKED`, set `group_completion_mono` once, checked-compute `frag_ack_deadline = checked_add(group_completion_mono, frag_ack_wait_ms)`, and wait for a fully validated covering FRAG_ACK unless step 3 already supplied it. A validated PARTIAL schedules only missing fragments.
7. If the FRAG_ACK is lost or still non-covering at `frag_ack_deadline`, checked-compute `retry_not_before = max(frag_ack_deadline, checked_add(group_completion_mono, frag_retry_interval_ms), checked_add(e2e_attempt_start_mono, frag_retry_interval_ms))`; retry that missing fragment only as a fresh E2E preparation subject to its `k < 4` and sender deadline.
8. Any checked-add overflow, exhausted E2E preparation budget, or `now_mono >= sender_absolute_deadline` ⇒ terminal local abort/upper structured result, apply §15.3.8 to every related group/candidate/Permit, then release the outgoing transfer state; FRAG_ACK TX 0. The original fragment sender never generates FRAG_ACK.

Temporary Permit issue failure with mutation 0 keeps the same prepared hop candidate only; it neither creates another candidate nor burns another counter. Every fresh forward retry counter is admitted before the receiver body branch; any response uses a separate fresh reverse E2E counter.

**Receiver bounded lifetime:** on first START admission, set `receiver_start_mono` once and  
`receiver_absolute_deadline = checked_add(receiver_start_mono, frag_receiver_transfer_ttl_ms)` with **`frag_receiver_transfer_ttl_ms = 90000`**, immutable.  
Also `idle_deadline = checked_add(receiver_start_mono, frag_idle_timeout_ms)` with **20000**.  
Only a **newly accepted CONT** (new index progress) may refresh  
`idle_deadline = min(receiver_absolute_deadline, checked_add(now_mono, frag_idle_timeout_ms))`.  
Exact START retry / duplicate CONT **must not** extend idle, absolute, or tombstone TTL.  
On `now_mono >= idle_deadline` or `now_mono >= receiver_absolute_deadline` (or checked_add fail-closed): checked-compute `tombstone_expiry = checked_add(terminal_commit_mono, tombstone_ttl_ms)` **before** the atomic ABORT TIMEOUT tombstone commit. Overflow ⇒ fail-closed context/transfer fence, release no reservation as reusable, upper handoff 0, FRAG_ACK TX 0. Otherwise commit the ABORT tombstone first, then optional FRAG_ACK.  
**tombstone_ttl_ms = 90000** so tombstones are not forgotten before the sender horizon (90000). Restart still discards volatile tombstones (not crash-atomic exactly-once).

**FRAG_ACK liveness (receiver):** START accept (always incomplete because `frag_count≥2`) and an active exact-duplicate START/CONT MUST create or refresh a current-bitmap PARTIAL intent. After each newly accepted CONT, branch atomically: if bitmap remains incomplete, create/refresh PARTIAL; if bitmap becomes full, cancel pending PARTIAL and run digest/upper/tombstone COMPLETE-or-ABORT order — PARTIAL generation is forbidden on this full branch. For an incomplete intent, compute `new_due = min(receiver_absolute_deadline, checked_add(now_mono, frag_partial_ack_idle_ms))`; `partial_ack_due = min(existing_pending_due, new_due)` when already pending, otherwise `new_due`. Overflow ⇒ atomic ABORT FENCED tombstone path if its checked expiry succeeds, else context/transfer fence; in both cases upper handoff 0 and ACK TX 0. Gap detection MAY set an earlier due time but never postpone. Exact duplicates do not mutate reassembly/bitmap/payload/idle/absolute TTL or allocate a second transfer/reassembly; their fresh forward E2E counter has already been durably admitted, while an actual ephemeral response legitimately burns a **distinct fresh reverse E2E counter** and requires control reserve + Permit. Every 4 / optional-only PARTIAL generation is **not** sufficient. Reserve/Permit failure ⇒ ACK TX 0 (sender may retry); the intent itself remains governed by its due/owner deadline. Fair delivery: FRAG_ACK-loss paths must not deadlock.

### 12.2b CONT conflict

**CONT_CONFLICT_ABORT_TOMBSTONE:** same `frag_index` with **different bytes** on an active transfer ⇒ first complete §15.3.8 cleanup, then atomically transition that transfer to **ABORT CONFLICT** tombstone and release payload/reassembly, with **no** upper handoff; only after tombstone commit MAY emit optional reverse FRAG_ACK ABORT CONFLICT. Not an ambiguous “abort path”.

### 12.3 FRAG_ACK

PT 14B BE:

```text
LAYOUT_FRAG_ACK_BEGIN
off  end  sz  field
0    8    8   transfer_handle (u64 BE)   /* 8B exact; not u32 */
8    10   2   frag_count (u16 BE)
10   12   2   received_bitmap (u16 BE; bit0=LSB=START/index0)
12   13   1   status
13   14   1   reason
LAYOUT_FRAG_ACK_END
```

Outer **79** exact. Uses **reverse** E2E context (paired).

**FRAG_ACK_RECEIVER_ONLY:** FRAG_ACK may be sealed/TX only by the **fragment receiver** that owns the reverse E2E TX context for that transfer. The original fragment **source sender** MUST NOT generate FRAG_ACK (including on local retry exceed or outgoing resource fail).

Generated FRAG_ACK reverse E2E burns obey §15.3.7 (semantic version max2; transfer aggregate 2×frag_count≤32; budget exhausted ⇒ ACK TX 0 without extending receiver/tombstone TTL).

**FRAG_ACK_RX_VALIDATION_CLOSED** — after reverse E2E structural/auth/durable admission, **before** any outgoing transfer mutation:

1. Reverse E2E context is the exact handshake pair of the saved forward outgoing E2E context  
2. Active outgoing transfer exists with **exact** `transfer_handle`  
3. Saved manifest `frag_count` ∈ 2..16 and wire `frag_count` exact match  
4. Bitmap bits at indices ≥ frag_count are 0  
5. Status table:  
   - PARTIAL: reason NONE, bit0=1, not full  
   - COMPLETE: reason NONE, exact full bitmap `(1<<frag_count)-1`  
   - ABORT: known reason only, bitmap **0**  
6. **frag_count=0 or COMPLETE with empty/wrong bitmap ⇒ reject**  

Unknown/stale/mismatch/malformed ⇒ outgoing transfer/bitmap/retry/completion mutation **0**, structured drop. COMPLETE/ABORT/retry-stop only after full validation.


**FRAG_BITMAP_EXACT** / status catalog:

| status | value | reason | bitmap |
| --- | ---: | --- | --- |
| PARTIAL | 0 | NONE=0 | bit0=1; bits[frag_count..15]=0; not full |
| COMPLETE | 1 | NONE=0 | exactly `(1<<frag_count)-1`; digest verified |
| ABORT | 2 | CONFLICT=1 DIGEST=2 RESOURCE=3 TIMEOUT=4 FENCED=5 | **0** |
| other | | | reject |

**PARTIAL triggers (closed):** after START accepted, after each active exact-duplicate START/CONT, and after **each newly accepted CONT whose resulting bitmap is incomplete**, a current-bitmap intent is required and becomes TX-eligible no later than checked `frag_partial_ack_idle_ms=2000`; an existing earlier due time is never postponed. A newly accepted CONT that makes the bitmap full MUST cancel PARTIAL and enter COMPLETE/ABORT processing. Gap detection MAY make an incomplete intent immediately eligible. “Every 4 fragments” or idle-only generation is forbidden. All actual TX need owner deadline + control reserve + Permit.

**FRAG_COMPLETE_NOT_APP_RECEIPT / FRAG_COMPLETE_COMMIT_ORDER_EXACT:**

For every COMPLETE or ABORT transition (and final full CONT after PARTIAL cancel), first apply the §15.3.8 terminal cancel matrix to pending PARTIAL/reserve/blob/group/candidate/issued Permit. For every COMPLETE or ABORT transition, capture `terminal_commit_mono` and checked-compute `tombstone_expiry = checked_add(terminal_commit_mono, tombstone_ttl_ms)` before the atomic terminal commit. Overflow is fail-closed: context/transfer fence, reservation remains unavailable for reuse, upper handoff 0, FRAG_ACK TX 0. No terminal tombstone may be committed with wrapped, saturated, or post-hoc expiry.

```text
1. Reassembly complete + content_digest match.
2. Reserve/admit **upper-transport queue** item (**UPPER_TRANSPORT_QUEUE**: validated SINGLE or completed reassembly application payload only) WITHOUT exposing it.
3. If step 2 fails **and** a START tombstone reservation / receiver owner already exists: atomically consume reservation into ABORT RESOURCE;
   no handoff; no COMPLETE ACK; may emit FRAG_ACK ABORT RESOURCE only as **owned** reverse ACK (receiver owner present).
4. If step 2 OK: atomic commit COMPLETE tombstone + queue visibility.
5. Only then may emit FRAG_ACK COMPLETE.
```

**ABORT order:** commit ABORT tombstone first; then may emit FRAG_ACK ABORT.

**FRAG_TOMBSTONE_RESERVE_ON_START / START_RESERVE_FAIL_ACK0_ONLY:** admitted START MUST reserve tombstone capacity **before** creating receiver owner state. If reservation fails: **reject START**; reassembly/owner **not** created; **ACK 0** only. Optional unowned ABORT RESOURCE is **forbidden** (same rule as §15.3.7). Dual-index collision ABORT CONFLICT remains charged only to an **existing** bounded owner.  
Tombstone binds `(e2e_context_id, transfer_id_128, transfer_handle, frag_count, status, reason, start_manifest_fingerprint32, expiry)`.

**TOMBSTONE_TTL_LATE_RETRY_MAY_BE_NEW:** on TTL forget, late START may be new under bounds; late CONT still drop.

### 12.4 ACK layering

- **NO_LINK_ACK_OF_LINK_ACK** / **NO_FRAG_ACK_OF_FRAG_ACK**  
- FRAG_ACK is E2E DATA carrier; if outer DATA has ACK_REQUESTED, hop may LINK_ACK that DATA under §11.

## 13. Resources (CELL_64_V1)

**CELL_64_V1_RESOURCE_PROFILE** / **CELL_64_NO_SIZEOF_PORTABLE_BYTES** / **CELL_64_TIMERS_EXACT_DEFAULTS**

Portable accounting rules:

- **Variable-payload queues:** bound by **entries + payload-byte budget** (not `entries×sizeof(entry)`).  
- **State-only tables:** bound by **entries** only (implementation sizeof is local, not a Normative portable byte claim).  
- **Expiring state:** exact **TTL** + explicit transition on expiry.  
- **Canonical accounted bytes** (where stated): exact formula below.  
- **No silent eviction.** Overflow → explicit action in table.

Capacity supports **64 peers** with **current + draining rekey** one-way hop TX/RX contexts.

| item | entries | owned payload / canonical bytes | TTL | overflow action |
| --- | ---: | ---: | ---: | --- |
| pairwise peers | 64 | — | — | join reject RESOURCE |
| hop one-way TX contexts | 128 (64+64) | state-only | `context_fence_ttl_ms` after fence | install reject |
| hop one-way RX contexts | 128 (64+64) | state-only | same | install reject |
| E2E one-way TX / RX (controller) | 128 / 128 | state-only | same | install reject |
| Endpoint hop TX/RX each | 8 | state-only | same | install reject |
| Endpoint E2E TX/RX each | 8 | state-only | same | install reject |
| route records | 128 | state-only | lease/expiry fields | install reject; forward TX 0 |
| **endpoint E2E ingress queue** (auth hop DATA / sealed E2E blob awaiting E2E processing) | 32 | **8192 B** aggregate owned blob payload | `e2e_ingress_queue_ttl_ms` | drop admit; LINK_ACK 0; structured RESOURCE |
| **upper-transport queue** (validated SINGLE or completed reassembly app payload) | 16 | **8192 B** aggregate owned payload | `upper_transport_queue_ttl_ms` | COMPLETE→ABORT RESOURCE path; SINGLE drop + structured RESOURCE |
| outgoing SINGLE owners | 32 | **6080 B** aggregate app payload (32 × max 190 B) | `single_sender_item_ttl_ms` | local structured RESOURCE; Seal/Permit/TX 0 |
| forwarding queue | 64 | **16320 B** aggregate owned blob payload | `forward_queue_ttl_ms` | forward TX 0; LINK_ACK 0; RESOURCE |
| forwarding / ingress peer | 4 | **1020 B** | `forward_peer_ttl_ms` | same |
| LINK pending/retry groups | 64 groups / 256 counters | **copy-own E2E sealed blob ≤220 B each; aggregate ≤14080 B** actual blob bytes (independent of forward/ingress queues) | `link_retry_group_ttl_ms` | no new pending; §15.3.8 cleanup; local RESOURCE |
| LINK pending max attempts | 4 hop air / group | — | — | local fail; §15.3.8 cleanup before blob release |
| global issued Permit FIFO | 8 references | state-only; candidate bytes remain in exact owner/group | exact candidate owner/group deadline | no new issue; FIFO-head scheduler wait |
| ACK coalesce | 32 entries | **32 × 16 B = 512 B** canonical LINK_ACK PT coalesce state | `ack_coalesce_ttl_ms` | no expand; separate ACK or ACK 0 |
| outgoing fragment transfers | 16 | **32768 B** | `frag_sender_transfer_ttl_ms` | local abort + upper structured; FRAG_ACK TX 0 |
| RX reassembly (controller) | 16; max 2/peer | **32768 B** | absolute `frag_receiver_transfer_ttl_ms` + idle `frag_idle_timeout_ms` | FRAG ABORT TIMEOUT/RESOURCE |
| RX reassembly (endpoint) | 2 | **4096 B** | absolute+idle same | same |
| terminal FRAG tombstones + START reservations | 32 | **TOMBSTONE_CANONICAL_72B** = e2e_context_id4 + transfer_id16 + handle8 + frag_count2 + status1 + reason1 + fingerprint32 + expiry_u64_8 (**72 B exact**; START reservation = one future 72 B slot) | `tombstone_ttl_ms`=90000 | START reject; ACK 0 only (no unowned ABORT RESOURCE) |
| control ACK reserve | 8 frames | **8 × 79 B = 632 B** max FRAG_ACK outer budget | `control_ack_reserve_ttl_ms` | non-control cannot use; TX 0 |
| **L1 Seal output slot registry** | **128** live slots max | per-slot capacity **1..255** B; aggregate capacity sum **≤ 32640** B; includes slots later adopted as LINK-group E2E blobs (**do not** double-allocate/count same bytes — ledger ownership moves; LINK group aggregate still applies simultaneously without second ownership of same bytes) | prep-pair lifetime / release tables | claim token+slot **before** STAMP and before any counter burn; capacity/bytes fail ⇒ STAMP/event 0, burn/Seal/Permit/TX 0 + structured RESOURCE; at most **one** output slot per live prep pair; unique nonzero token; release returns capacity |

**TOMBSTONE_VOLATILE_ON_RESTART:** In R6 V1 / profile 0x11, **tombstones and START reservations are volatile** along with queues, LINK retry groups, and reassembly. Owner/process restart discards only volatility that is proven unissued; any issued existence is handled by §15.3.3 before new issue, and consume+edge-done is stale/no-retry (§15.3.8). No volatile state resumes across unknown clock/restart. After restart, a late fresh-E2E START may be treated as **new** under ordinary bounds. Durable crypto state remains governed by §§9–10 only. Crash-atomic exactly-once and application-level dedup are **not** claimed. If authority-clock epoch continuity cannot be proven after sleep/rollback/uncertain sample, expire/drop all volatile state fail-closed before TX/ACK/deliver (§11.2.2).

### 13.1 CELL_64_V1 exact default timers

**PROFILE_CHANGE_REQUIRES_NEW_WIRE_PROFILE_ID:** changing timer values, resource bounds, or overflow actions of profile **0x11 / CELL_64_V1** requires a **new `wire_profile_id`**. A non-wire “accepted vector revision” MUST NOT change wire/state-machine behavior. Additional goldens for 0x11 may only be meaning-preserving.

| timer | value | on expiry |
| --- | ---: | --- |
| `link_ack_wait_ms` | 3000 | per-attempt ACK deadline component of `eligible_at` |
| `link_retry_interval_ms` | 500 | min spacing component of `eligible_at` |
| `link_retry_group_ttl_ms` | 15000 | group absolute fail; §15.3.8 cleanup before blob release |
| `ack_coalesce_ttl_ms` | 200 | flush coalesce or drop expand |
| `e2e_ingress_queue_ttl_ms` | 5000 | drop E2E ingress item; LINK_ACK 0; structured local fail |
| `upper_transport_queue_ttl_ms` | 5000 | drop upper payload; structured local fail |
| `single_sender_item_ttl_ms` | 30000 | local SINGLE fail; §15.3.8 cleanup before payload/candidate release; TX 0 |
| `forward_queue_ttl_ms` | 5000 | drop; TX 0 / RESOURCE |
| `forward_peer_ttl_ms` | 5000 | same |
| `frag_ack_wait_ms` | 5000 | after LINK group success, wait for covering FRAG_ACK |
| `frag_retry_interval_ms` | 500 | min spacing before next E2E fragment attempt |
| `frag_sender_transfer_ttl_ms` | 90000 | sender transfer absolute TTL; §15.3.8 cleanup before outgoing transfer release |
| `frag_receiver_transfer_ttl_ms` | 90000 | receiver absolute transfer deadline from first START |
| `frag_idle_timeout_ms` | 20000 | receiver idle deadline; refresh only on newly accepted CONT; ≤ absolute |
| `frag_partial_ack_idle_ms` | 2000 | checked due for incomplete bitmap after START/incomplete new CONT/active exact duplicate; never postpone |
| `tombstone_ttl_ms` | 90000 | free tombstone slot (volatile; ≥ sender horizon; restart discards) |
| `context_fence_ttl_ms` | 30000 | capacity reclaim after fence |
| `route_lease_check_ms` | 1000 | revalidate lease/expiry |
| `control_ack_reserve_ttl_ms` | 3000 | §15.3.8 cleanup before reserve release |
| `permit_issue_retry_ms` | 100 | positive scheduler backoff; max 8 exact issue calls/candidate |
| `permit_tx_retry_ms` | 100 | positive scheduler backoff; max 8 full transmit pipeline calls/candidate |

### 13.2 Storage capacity preflight (honest; ESP not ready)

**ESP_STORAGE_CAPACITY_NOT_READY_R6 / ESP_CAPACITY_FORMULA_EXACT:**

**Per-opened-namespace capacity ABI (Foundation Storage):** `max_entries`, `used_entries`, `max_bytes`, `used_bytes` for that handle only. Generic per-open capacity **cannot** prove the process-wide minimum of **3** namespaces (Foundation Runtime + PCP + radio-security). Current ESP production configuration **`max_namespaces = 2`** ⇒ R6 full and small profiles are **INSUFFICIENT / NOT READY** on current ESP port; R7 port expansion of namespace count is a hard blocker.

**Frozen record sizes (key+value bytes):**

| record | key B | value B | entry bytes |
| --- | ---: | ---: | ---: |
| N6AL | 24 | 56 | **80** |
| lane (N6TX or N6RX) | 48 | 68 | **116** |
| N6RT | 28 | 48 | **76** |
| N6CF | 28 | 64 | **92** |
| N6HW | 32 | 28 | **60** |

**Variables (radio-security namespace only; sum all peers, layers, epochs, both alloc_sides):**
- `A` = #N6AL keys
- `H` = #active HOP contexts (each has **exactly 2** lane records: DATA+ACK)
- `E` = #active E2E contexts (each has **exactly 1** lane record)
- `F` = #N6CF fence records
- `T` = #retired N6RT tombstones
- `W` = #N6HW records

```text
entries_required = A + 2*H + E + F + T + W
bytes_required   = 80*A + 232*H + 116*E + 92*F + 76*T + 60*W
```
(Note: `232*H` = 2 × 116 lane bytes per HOP context.)

**Post-state admission (exact):** before bind-complete and before any install/replace FULL:
- Let `Δ_entries`, `Δ_bytes` be the net change of the proposed write-set after normalization (puts of new keys +1 entry / +key+value bytes; deletes −1 / −bytes; replaces of equal-size = 0 entry delta; size-changing replace uses new−old bytes).
- Admit only if `used_entries + Δ_entries ≤ max_entries` and `used_bytes + Δ_bytes ≤ max_bytes` on the radio-security namespace handle.
- Also require every multi-key FULL write-set has `1 ≤ N ≤ 32` entries and each key_len≤255, value_len≤256.
- Iterator/RAM: RO GC/boot rescan MUST complete with Foundation iterator ceilings; if port cannot guarantee full-namespace empty-prefix scan within RAM object ceilings, R7 must ship ABI-extension or larger ceilings — otherwise **NOT READY**.

Run capacity preflight before first install; failure is sticky TX/RX 0. This freeze is not product R7/HIL/legal evidence.


## 14. Multi-parent / multi-PC (HA)

**HA_REWRAP_VS_NEW_SEAL_SEPARATED** / **HA_V1_SINGLE_SEALER_ONLY** / **HA_OWNER_CHANGE_REQUIRES_NEW_E2E_CONTEXT:**

1. **Hop rewrap only:** already-sealed E2E blob may be carried bit-identical under a **fresh hop outer** by any authorized hop TX owner. Not a new E2E Seal.  
2. **New E2E Seal (profile 0x11 / V1):** each E2E context has **exactly one** linearizable sealer/counter owner. **Atomic shared allocator enabling multiple sealers is not permitted** in V1.  
3. **Owner unknown / split brain → seal 0.**  
4. **Owner change / failover:** same-context resume is **forbidden**. MUST install a **new E2E context** with fresh `traffic_secret32`, new `key_generation`, and new durable TX/RX state; fence old context.  
5. **`authority_term` change:** new E2E context (same as owner change).  
6. **Restart of the same sealer owner only:** may same-context resume with **M5 floor + exact durable counter/replay restore**.  
7. Independent controllers: different E2E context/key; only upper `transaction_id` may be shared.  
8. Opaque SINGLE alone incomplete for downlink-owner dispatch → envelope blocker.

## 15. Permit pipeline and Seal/counter lifecycle

**PERMIT_AFTER_SEAL_EXACT_CANDIDATE / SEAL_BURNS_COUNTER_BEFORE_PERMIT / PREPARED_CANDIDATE_MAX_ONE_PER_GROUP:**

Existing Foundation Normative (docs/05, docs/23): **exact immutable bytes → digest/length/PHY/airtime → Permit issue → one logical consume authorization → physical TX**. A consume call that definitively returns unconsumed+retryable may retry only under §15.3; successful/unknown consume is never repeated. Therefore **Seal after Permit success is forbidden**.

### 15.1 Fresh E2E attempt (fragment or SINGLE)

Define `checked_add(a,b)` as **checked fail-closed** u64 addition (**not saturating**): if `a > UINT64_MAX - b` then local abort/fail-closed; else `a+b`.

**Outgoing transfer admission (exactly once, before E2E attempt 1):** take a trusted R2 authority sample under §11.2.2 / §15.3.5; set **`transfer_start_mono = sample.now_ms`** once and store `clock_epoch_id = sample.epoch_id`;  
`sender_absolute_deadline = checked_add(transfer_start_mono, frag_sender_transfer_ttl_ms)` exactly once; overflow ⇒ abort, TX 0.  
These are **immutable** across every fragment and every E2E/LINK retry **within that epoch**. Do **not** recompute or reset them on retries. Denied Permit does not pause/reset the absolute deadline. Epoch change/uncertain sample ⇒ §11.2.2 fence/drop (no mono conversion).

This sender deadline exists only for fragmented transfers. A local SINGLE is first copy-admitted to the bounded outgoing SINGLE resource and receives `single_sender_item_deadline` under §11.2.1/§13; it has exactly one E2E preparation per queue admission. Higher-layer retry is a new SINGLE admission with a new counter/context processing attempt.

Before each fresh E2E preparation, claim one bounded preparation slot: max **4 per fragment**, max **1 per SINGLE admission**. **`e2e_attempt_start_mono` (exactly once per preparation slot claim):** immediately before claiming that slot, take one trusted R2 authority-clock sample with `epoch_id ==` the owner’s stored `clock_epoch_id` and set `e2e_attempt_start_mono = sample.now_ms` exactly once for this preparation (same domain as `transfer_start_mono` / `group_completion_mono` / `attempt_terminal_mono` — §11.2.2). Do **not** change `e2e_attempt_start_mono` on burn success/failure, Seal/encode failure, Permit denial, full-pipeline retry, or hop retry. If the sample is temporary/uncertain or epoch mismatches, do not claim the slot; apply §11.2.2 fence/drop and TX/ACK 0. Definite counter-allocation failure terminally fails that owner. After successful durable burn the slot is permanently consumed even if a later preparation step fails:

1. Durable E2E counter **allocate/burn** (§9); on **successful durable burn** increment `e2e_prepare_burn_count`. **Definite counter-allocation failure before durable burn** (phase `E2E_COUNTER_BURN` / pre-write fail): terminally fails the owning fragmented transfer or SINGLE; **no** fresh prep, **no** retry; handle remains **unset**; burn count/counter mutation **0** (set-equal §1.1.1 SEAL_FAIL_E2E_DEFINITE_VS_POSTBURN_SPLIT). CU THIRD/CORRUPT: fence+terminal, no retry, no invented handle.  
2. E2E **Seal** exact sealed blob (output slot); post-burn Seal/encode failure consumes the preparation slot, emits TX 0, and terminally fails this preparation — FRAG may schedule next bounded preparation only on **post-burn** encode/AEAD or E2E_POST_SEAL LENGTH failure when budget/deadline allow; SINGLE fails locally.  
3. LINK group copy-owns the blob and exact owner deadline; only then release the outgoing SINGLE payload entry (FRAG transfer state remains). **E2E FRAME_READY does not enter issue/R1** (§1.1 FRAME_READY_LAYER_BRANCH_CLOSED).  
4. Only then hop/LINK path via **fresh HOP STAMP_FIELDS / OUTER FRAME_READY / issue / R1**  

First START `transfer_handle` = latched first definite burned E2E counter per **FIRST_FRAG_HANDLE_LATCH_RESPONSE_CLOSED** (§1.1.1.8). Permit denial does **not** unburn or reuse that counter.

`e2e_prepare_burn_count` increments on successful durable burn; `e2e_sealed_attempt_count` increments only when a **fresh E2E Seal** is created. Both are bounded by the same owner limit. Permit denial increments neither and never permits an extra burn.

On LINK success then FRAG_ACK loss:  
`retry_not_before = max(frag_ack_deadline, checked_add(group_completion_mono, frag_retry_interval_ms), checked_add(e2e_attempt_start_mono, frag_retry_interval_ms))`  
(any checked_add overflow ⇒ local abort/fail-closed). Retry TX requires `now_mono >= retry_not_before` AND `now_mono < sender_absolute_deadline` AND remaining E2E attempts AND new Permit.

### 15.2 Hop / outer candidate (each LINK air attempt)

**Two success pathways (exact; HOP_OUTER_PATH_CLOSED):**

Before a LINK group creates a DATA hop candidate it requires `hop_prepare_burn_count < 4`.

| path | owner / group | hop counter lane | steps |
| --- | --- | --- | --- |
| **DATA outer** | admitted LINK group; owner_class ∈ {LOCAL_SINGLE, LOCAL_FRAGMENT, RELAY_DATA, LOCAL_FRAG_ACK} HOP | **DATA** | require `hop_prepare_burn_count < 4`; burn DATA lane; Seal outer; `frame_digest = SHA-256(B)` with **frame_digest_algorithm_id = 1**; R3; R5→R2 issue; R1 pipeline; TX edge on consume success |
| **ACK outer** | LOCAL_LINK_ACK pre-group (`group_deadline_valid=0`; **no** LINK group) | **ACK** | burn ACK lane (not DATA); Seal LINK_ACK outer; `frame_digest = SHA-256(B)` with **frame_digest_algorithm_id = 1**; R3; R5→R2 issue; R1 pipeline; **no** group terminal semantics |

DATA path after successful burn increments `hop_prepare_burn_count` permanently. ACK path does **not** invent a LINK group.

Outer Seal, digest, R3, plan construction, or output-shape failure after burn discards the candidate. If an **admitted LINK group** exists: terminally fails that group; no **seal/encode/AEAD failure replacement** in that group (**HOP_OUTER_FAIL_SAME_GROUP_STRICT_TERMINAL**; §1.1.1.1). If **LOCAL_LINK_ACK pre-group** (no LINK group): prep-pair + ACK owner terminal only — **not** group terminal. Phase 6/7 durable hop lane counter was consumed; phase 5 definite burn fail did **not** consume. Later E2E fragment retry requires fresh E2E counter/blob + new LINK group. **LINK_ACK timeout after successful DATA air TX** (consume+edge done, group exists): same LINK group keeps the **bit-identical E2E blob** and **MAY** create a **fresh HOP DATA prep + fresh hop DATA counter + fresh outer** (not “same already-emitted outer”; not a seal-failure replacement; **no** E2E blob release on timeout — E2E_BLOB_RELEASE_TABLE). **TX_EDGE_DONE** pair/group split follows **TX_EDGE_DONE_ACK_POLICY** (§1.1.2): ACK_REQUESTED=1 → WAIT_LINK_ACK retain blob; ACK_REQUESTED=0 → UNACKED_LINK_SUCCESS after sibling/borrow cleanup then release; LOCAL_LINK_ACK → no group. Therefore `hop_air_attempt_count ≤ hop_prepare_burn_count ≤ 4` on DATA path.

Hop attempt count increments only when Permit consume succeeds and the sole TX edge is invoked (not on temporary issue denial or a definite unconsumed retryable consume result).

### 15.3 Prepared candidate rules

- At most **one** prepared hop outer candidate per LINK group or non-retrying LINK_ACK owner.  
- Candidate uses exactly one owner row from §11.2.1 and is bounded by its immutable **enclosing owner deadline**; LINK DATA also obeys its group absolute deadline.  
- Issue and full-pipeline retry counters count the first call and are each exact max **8 calls per candidate**. `calls_used` for R1 **includes the current call**. Every OPEN retry uses a positive fixed backoff, never same-tick spin: `permit_issue_retry_at = checked_add(now_mono, permit_issue_retry_ms)` or `permit_tx_retry_at = checked_add(current_accepted_now_mono, permit_tx_retry_ms)` with `current_accepted_now_mono` the sole accepted R2-authority-domain sample (§15.3.5). Overflow, `calls_used=8` without success, Permit/owner/(valid) group deadline reached, untrusted sample, epoch mismatch, or fence ⇒ for **issued** after OK_ISSUED: **RETRY_GATE_CLOSED** / `TX_QUARANTINE` then DRAIN (never local unissued-style terminal/release); for **unissued** issue path: owner/group terminal per PRE_R1.  
- At most **8 issued Permits globally** (R2 bound). **L1 Radio Coordinator** orders valid issued snapshots by ascending `permit_sequence`; only FIFO head may enter `transmit_with_permit`. Candidate selection before issue is fair round-robin across ready owners, but issued-Permit FIFO takes precedence. Restart reuses no volatile snapshot: new issue remains TX 0 until §15.3.3 exported private-module drain proves R2 outstanding zero, rebuilds R5 without assignment, and the U5 owner completes authenticated SET L0–L4 RESTORE/DUP or L5–L9 APPLY (ARW alone never restores full body). Local discard of an issued Permit (or candidate-only drop while issued may exist) is forbidden.  
- Denied/unconsumed is **not** a sent/air attempt, but the crypto counter and preparation slot remain burned.

#### 15.3.1 R7 private R2 checked-issue primitive (Normative blocker)

**R2_PRIVATE_ISSUE_COORDINATOR_SINGLE_SAMPLE / R5_VALIDATION_CALLBACK_SAME_S / R5_ISSUE_GUARD_WHOLE_PATH / R2_ISSUE_NO_ALGORITHM_E_FOR_W1:**

Sole path: L1 → `ninlil_r5_private_issue_checked_with_owner_epoch` → `ninlil_r2_private_issue_checked_owner_epoch`.

**Closed private issue result:** every return from the R2 checked-issue primitive carries
`result_catalog=R2_PCP` plus exactly one `NINLIL_PCP_*` `exact_status`,
`stage=NINLIL_PCP_STAGE_ISSUE`, the closed issue `reason`, and the **three independent
exact fields** from §15.3.2 (`business_mutation`, `clock_fence_mutation`, `txn_provenance`).
R5 and L1 MUST preserve those typed fields without numeric reinterpretation; R1 HAL values are forbidden in this object. **Sample-path two-axis fields MUST NOT be reused here.**

**Guards:** R5 `in_api` covers static preflight → R2 call → registry insert. R2 `in_api` covers sample → sample/epoch/outstanding gates → (trusted class-D only) internal read-only validation_cb → RW complete. Callback is not R5 public re-entry; it reads only a copy-owned immutable validation context (no activate/replace; **no clock sample** — S already trusted by R2).

**Order (sole; VAL_CLOCK_DROP abolished):**  
(1) R5 static preflight (no sample)  
(2) R5 builds immutable validation context  
(3) R2 samples S **once**  
(4) R2 sample/epoch/outstanding gates (CLOCK_UNCERTAIN/FAULT ⇒ map and return **without** calling validation_cb)  
(5) **Only** trusted class-D: `status = validation_cb(user, &S_view, &static_plan, &out_window);`  
(6) R2 RW ISSUED; no Algorithm E  
(7) R5 registry insert or RECONCILE_REQUIRED  

**validation_cb closed results (sole mapping table; no other Normative callback results):**

| callback result | R2 PCP status | reason | business_mutation | clock_fence_mutation | txn_provenance | L1 class |
| --- | ---: | ---: | --- | --- | --- | --- |
| `VAL_OK` | (proceed RW; pre-RW only — not a terminal issue outcome) | — | — | — | — | (proceed to RW ISSUED; no terminal yet) |
| `VAL_TERMINAL` | `NINLIL_PCP_STRUCT` (3) | `STRUCT_INVALID` (2) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` |
| `VAL_RETRYABLE` | `NINLIL_PCP_CAPACITY` (7) | `CAPACITY` (15) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RETRYABLE_UNISSUED` |
| `VAL_AUTHORITY` | `NINLIL_PCP_PROFILE_MISMATCH` (6) | `PROFILE_MISMATCH` (11) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `AUTHORITY_DIVERGENCE` |
| `VAL_RECONCILE` | `NINLIL_PCP_INVALID_STATE` (2) | `CONTRACT` (28) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` |

Non-OK: `out_window` all zero; RW begin 0; registry mutation 0; axes **BUSINESS_ZERO / META_ZERO / PRECHECK_ZERO**.  
OK window: `not_before=S.now`; all epoch fields = S.epoch; `expiry=min(owner_deadline,checked_add(S.now,60000),profile_expiry_or_max)`; **VAL_OK is pre-RW proceed only** (not a terminal status/reason).  
Unknown callback result / window uninitialized / epoch mismatch / `expiry<=not_before` ⇒ treat as `VAL_RECONCILE` / CONTRACT(28) + BUSINESS_ZERO/META_ZERO/PRECHECK_ZERO → `RECONCILE_REQUIRED`. **`VAL_CLOCK_DROP` is not a Normative result** (absent).

Forbidden: R5 sampling; double sample; raw caller times; Algorithm E; validation_cb before trusted class-D. Unimplemented adapter ⇒ TX 0. **R7 C blocker.**

##### 15.3.1.1 R5 adapter + profile activation (same-S snapshot)

**PROFILE_ACTIVATION_SAME_S_SNAPSHOT / REG_PROFILE_SCHEMA2_AUTHORITY_EPOCH:**

`ninlil_r5_private_activate_profiles_with_authority_epoch` (L1-only) takes `accepted_class_D_snapshot` = exact copy of successful private class-D sample (TRUSTED; fences 0; watermark match) plus `snapshot_id`, `sample_generation`, `l1_issuer_token`. Single-use consume of snapshot_id; forge without L1 token rejected; lifetime = activate call only.

Activate: reg **schema=2** for R6 0x11; `authority_clock_epoch_id == snapshot.epoch_id`; window vs snapshot.now; CRC; no re-tag. **Single-use:** activate consumes snapshot_id; replay same snapshot_id fails. Issue always re-samples S inside R2. profile_clock_epoch_id == S.epoch required on issue path.


#### 15.3.2 Exhaustive issue outcome / provenance matrix (closed)

**TYPED_W1_ISSUE_RESULT_CLASS_CLOSED / L1_RESULT_CLASS_SET_CLOSED (P1(39); sole definition):**

**Closed L1 result class set** (exact; gate set-equality; also §15.4 order + §18 + ADR-0010 must list the same set, no extras):

```text
OK_ISSUED
RETRYABLE_UNISSUED
TERMINAL_UNISSUED
CLOCK_PATH_DROP
RECONCILE_REQUIRED
AUTHORITY_DIVERGENCE
EPOCH_TRANSITION_REQUIRED
EPOCH_W1_REPAIR
FIFO_OUT_OF_ORDER
OPERATOR_RECOVERY_REQUIRED
RETRYABLE_PIPELINE
```

No other L1/W1 issue-pipeline result class tokens are Normative. Hint-string parsing is forbidden. Mapping from bare `NINLIL_R5_PCP` alone is forbidden. There is **no** “known terminal” catchall: every status below is listed. L1 classifies; W1 only emits typed seal/candidate events.

Every accepted R2 row has `stage = NINLIL_PCP_STAGE_ISSUE`. Private issue results carry **three independent exact fields** (not a single hidden mutation bit):

**business_mutation (closed):** `BUSINESS_ZERO` | `ISSUED_FULL` | `BUSINESS_AMBIGUOUS`  
**clock_fence_mutation (closed):** `META_ZERO` | `F_C_FULL` | `META_AMBIGUOUS`  
**txn_provenance (closed):** `PRECHECK_ZERO` | `RW_ABORT_ZERO` | `ISSUED_COMMITTED` | `CLOCK_FENCE_COMMITTED` | `AMBIGUOUS`

**Meaning (exact):**
- `BUSINESS_ZERO` + `META_ZERO` + `PRECHECK_ZERO`/`RW_ABORT_ZERO`: no ISSUED put/commit/registry; no meta F_c write  
- `ISSUED_FULL` + `META_ZERO` + `ISSUED_COMMITTED`: ISSUED record + registry success; no F_c write  
- `BUSINESS_ZERO` + `F_C_FULL` + `CLOCK_FENCE_COMMITTED`: CLOCK_FAULT after common helper FULL OK on published meta; **no** ISSUED put; must not be reported as sole “mutation 0”  
- `BUSINESS_ZERO` + `META_AMBIGUOUS` + `AMBIGUOUS`: F_c COMMIT_UNKNOWN (or unclassifiable meta write)  
- `BUSINESS_AMBIGUOUS` + `META_ZERO` + `AMBIGUOUS`: issue commit/registry dual-truth without proven F_c write  

**Forbidden:** claim business zero while hiding a meta F_c write; claim `PRECHECK_ZERO` with `F_C_FULL`; claim `ISSUED_COMMITTED` with business ≠ `ISSUED_FULL`. Sample-path axes remain separate (§11.2.3).

`OK_ISSUED` requires `ISSUED_FULL` + `ISSUED_COMMITTED`. `AMBIGUOUS` / `META_AMBIGUOUS` / `BUSINESS_AMBIGUOUS` map to `RECONCILE_REQUIRED` (or typed COMMIT_UNKNOWN where status is 11). The normalized issue-stage reason map is closed: `0:NONE, 1:NULL_ARG, 2:{INVALID_STATE(27), CONTRACT(28; callback reconcile exact only)}, 3:STRUCT_INVALID, 4:CLOCK_UNCERTAIN, 5:CLOCK_FAULT, 6:PROFILE_MISMATCH, 7:CAPACITY, 8:SEQ_EXHAUSTED, 9:STORAGE_FENCE, 10:CORRUPT_FENCE, 11:COMMIT_UNKNOWN, 12:STORAGE_IO, 13:STORAGE_IO, 14:BUSY_OUTSTANDING, 15:BUSY_REENTRY, 16:ALIAS, 17:UNBOUND_STORAGE, 18:UNBOUND_CLOCK, 19:UNBOUND_ASSIGNMENT, 20:RECOVER_FAIL, 21:STORAGE_UNSUPPORTED, 22:SHUTDOWN, 23:NONE`. Status **2** terminal is **only** reason **`INVALID_STATE` (27)** + BUSINESS_ZERO/META_ZERO + PRECHECK_ZERO/RW_ABORT_ZERO → `TERMINAL_UNISSUED`. Status **2** + reason **`CONTRACT` (28)** + BUSINESS_ZERO/META_ZERO/PRECHECK_ZERO (VAL_RECONCILE or unknown-callback normalize) → `RECONCILE_REQUIRED` (not terminal). Epoch triple mismatch before R2 issue is `stage=ISSUE/reason=EPOCH_MISMATCH/PRECHECK_ZERO` + BUSINESS_ZERO/META_ZERO. Any other combination is `RECONCILE_REQUIRED`.

| source | exact status / condition | business_mutation | clock_fence_mutation | txn_provenance | L1 result class | action |
| --- | --- | --- | --- | --- | --- | --- |
| R2 private issue | `NINLIL_PCP_OK` (0) + exact valid snapshot + R5 registry insert OK | ISSUED_FULL | META_ZERO | ISSUED_COMMITTED | `OK_ISSUED` | bind; global FIFO enqueue; no further issue |
| R2 private issue | `NINLIL_PCP_OK` (0) + missing/malformed/mismatched snapshot | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | §15.3.3 drain; TX 0 |
| R2 private issue | `NINLIL_PCP_INVALID_ARGUMENT` (1) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate; owner/group terminal |
| R2 private issue | `NINLIL_PCP_INVALID_STATE` (2) + reason `CONTRACT` (28) + BUSINESS_ZERO/META_ZERO/PRECHECK_ZERO (VAL_RECONCILE or unknown callback normalize) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` | drain; **not** status2 terminal |
| R2 private issue | `NINLIL_PCP_INVALID_STATE` (2) + reason `INVALID_STATE` (27) + PRECHECK/RW_ABORT zero | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO/RW_ABORT_ZERO | `TERMINAL_UNISSUED` | drop candidate; **sole** status2 terminal form |
| R2 private issue | `NINLIL_PCP_INVALID_STATE` (2) + business ambiguous | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | drain |
| R2 private issue | `NINLIL_PCP_STRUCT` (3) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_CLOCK_UNCERTAIN` (4) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `CLOCK_PATH_DROP` | discard entire `radio_volatile_work` all owners; later same-epoch class-D **fresh only** |
| R2 private issue | `NINLIL_PCP_CLOCK_FAULT` (5) after helper FULL OK | BUSINESS_ZERO | **F_C_FULL** | **CLOCK_FENCE_COMMITTED** | `CLOCK_PATH_DROP` | discard volatile; same-epoch admit forbidden; fresh-epoch adopt; drain if issued |
| R2 private issue | `NINLIL_PCP_COMMIT_UNKNOWN` (11) from F_c helper only | BUSINESS_ZERO | META_AMBIGUOUS | AMBIGUOUS | `RECONCILE_REQUIRED` | storage recover; do not claim F_c latched |
| R2 private issue | `NINLIL_PCP_COMMIT_UNKNOWN` (11) from ISSUED/registry path | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | drain; no claim issued |
| R2 private issue | `NINLIL_PCP_PROFILE_MISMATCH` (6) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `AUTHORITY_DIVERGENCE` | stop new issue; rebind; drain if issued may exist; TX 0 |
| R2 private issue | `NINLIL_PCP_CAPACITY` (7) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RETRYABLE_UNISSUED` | retain candidate; +100ms; max 8 |
| R2 private issue | `NINLIL_PCP_SEQ_EXHAUSTED` (8) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_STORAGE_FENCE` (9) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` | drain |
| R2 private issue | `NINLIL_PCP_CORRUPT_FENCE` (10) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` | drain |
| R2 private issue | `NINLIL_PCP_STORAGE_IO` (12) + PRECHECK/RW_ABORT zero | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO/RW_ABORT_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_STORAGE_IO` (12) + ambiguous | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | drain |
| R2 private issue | `NINLIL_PCP_BUSY` (13) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RETRYABLE_UNISSUED` | retain; +100ms; max 8 |
| R2 private issue | `NINLIL_PCP_BUSY_OUTSTANDING` (14) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RETRYABLE_UNISSUED` | retain; +100ms; max 8 |
| R2 private issue | `NINLIL_PCP_BUSY_REENTRY` (15) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_ALIAS` (16) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_UNBOUND_STORAGE` (17) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_UNBOUND_CLOCK` (18) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `CLOCK_PATH_DROP` | fence/drop per §11.2.2 |
| R2 private issue | `NINLIL_PCP_UNBOUND_ASSIGNMENT` (19) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `AUTHORITY_DIVERGENCE` | U5/R5 rebind; TX 0; drain if issued may exist |
| R2 private issue | `NINLIL_PCP_RECOVER_FAIL` (20) | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | drain |
| R2 private issue | `NINLIL_PCP_STORAGE_UNSUPPORTED` (21) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_SHUTDOWN` (22) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R2 private issue | `NINLIL_PCP_EMPTY_OK` (23) on issue path | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate (not issue success) |
| R2 private issue | status outside 0..23 / unknown | BUSINESS_AMBIGUOUS | META_AMBIGUOUS | AMBIGUOUS | `RECONCILE_REQUIRED` | storage recover/drain; **MUST NOT** assert META_ZERO |
| R2 private issue | status/reason/output/txn field mismatch | BUSINESS_AMBIGUOUS | META_AMBIGUOUS | AMBIGUOUS | `RECONCILE_REQUIRED` | storage recover/drain; **MUST NOT** assert META_ZERO |
| R5 preflight | `NINLIL_R5_OK` (0) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | — | call private R2 checked issue once |
| R5 preflight | `NINLIL_R5_INVALID_ARGUMENT` (1) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 preflight | `NINLIL_R5_INVALID_STATE` (2) / fence_pending | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` | drain |
| R5 preflight | `NINLIL_R5_STRUCT` (3) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 preflight | `NINLIL_R5_PROFILE_DENIED` (4) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 preflight | `NINLIL_R5_BIND_MISMATCH` (5) + `comparison_locus=CANDIDATE_VS_R5_EXPECTED` + bind_item ∈ {`TX_ID`,`CHANNEL`,`PHY`,`FRAME_DIGEST`,`FRAME_DIGEST_ALG`,`FRAME_LEN`,`AIRTIME`} | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | recompose **this** candidate only; not drain |
| R5 preflight | `NINLIL_R5_BIND_MISMATCH` (5) + `comparison_locus=CANDIDATE_VS_R5_EXPECTED` + bind_item ∈ {`NOT_BEFORE`,`EXPIRY`} pre-commit static | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate; recompute only after new sample |
| R5 preflight | `NINLIL_R5_BIND_MISMATCH` (5) + `comparison_locus=R5_EXPECTED_VS_R2_LIVE` + bind_item `PERMIT_GEN` / assignment_generation | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` | drain if issued may exist; U5/R5 rebind |
| R5 preflight | `NINLIL_R5_BIND_MISMATCH` (5) + `comparison_locus=R5_EXPECTED_VS_R2_LIVE` + bind_item ∈ {`SITE_ID`,`SITE_REV`,`SITE_EPOCH`,`CONTROLLER_TERM`,`ASSIGNMENT_DIGEST`,`HW_ID`,`HW_REV`,`REG_ID`,`REG_REV`} | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `AUTHORITY_DIVERGENCE` | stop issue; rebind/reload |
| R5 adapter | `NINLIL_R5_BIND_MISMATCH` (5) + `comparison_locus=REGISTRY_POSTCOMMIT` | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | drain; never clean unissued |
| R5 preflight | `NINLIL_R5_BIND_MISMATCH` (5) + bind_item `PERMIT_SEQ` or unknown bind_item/locus | BUSINESS_ZERO or BUSINESS_AMBIGUOUS | META_ZERO | PRECHECK_ZERO or AMBIGUOUS | `TERMINAL_UNISSUED` or `RECONCILE_REQUIRED` | exact provenance required; bare business AMBIGUOUS forbidden |
| R5 preflight | `NINLIL_R5_CAPACITY` (6) / registry full before R2 | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RETRYABLE_UNISSUED` | retain; +100ms; max 8 |
| R5 preflight | `NINLIL_R5_BUSY_OUTSTANDING` (7) before R2 | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RETRYABLE_UNISSUED` | retain; +100ms; max 8 |
| R5 preflight | `NINLIL_R5_AIRTIME` (8) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 adapter | bare `NINLIL_R5_PCP` (9) without exact typed R2 result | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | drain; bare collapse forbidden |
| R5 preflight | `NINLIL_R5_REGISTRY_MISS` (10) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `RECONCILE_REQUIRED` | drain |
| R5 preflight | `NINLIL_R5_UNSUPPORTED` (11) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 preflight | `NINLIL_R5_SHUTDOWN` (12) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 preflight | `NINLIL_R5_ALIAS` (13) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 preflight | `NINLIL_R5_BUSY_REENTRY` (14) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `TERMINAL_UNISSUED` | drop candidate |
| R5 preflight | `NINLIL_R5_PROFILE_EXPIRED` (15) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `AUTHORITY_DIVERGENCE` | profile-ready gate; no unlimited counter burn |
| R5 preflight | `NINLIL_R5_PROFILE_NOT_EFFECTIVE` (16) | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `AUTHORITY_DIVERGENCE` | same profile-ready gate |
| R5 preflight/adapter | status outside 0..16 or field mismatch | BUSINESS_AMBIGUOUS | META_AMBIGUOUS | AMBIGUOUS | `RECONCILE_REQUIRED` | storage recover/drain; **MUST NOT** assert META_ZERO |
| epoch precheck | class **A** `S==M`, W mismatch/absent | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `EPOCH_W1_REPAIR` | L1 bootstrap/repair only; **R2 adopt forbidden** |
| epoch precheck | class **B** `S==W != M` | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `AUTHORITY_DIVERGENCE` | drain+reconcile; not adopt |
| epoch precheck | class **C** `S` differs from W and M | BUSINESS_ZERO | META_ZERO | PRECHECK_ZERO | `EPOCH_TRANSITION_REQUIRED` | drain then adopt; no Algorithm E |
| registry insert fail after R2 OK | issued may exist | BUSINESS_AMBIGUOUS | META_ZERO | AMBIGUOUS | `RECONCILE_REQUIRED` | **prevents Algorithm E/R5 registry divergence** by never treating as clean unissued |

`RETRYABLE_UNISSUED` is **only** the exact safe no-mutation transient rows above (CAPACITY, BUSY, BUSY_OUTSTANDING, matching R5 capacity preflight). **CLOCK_UNCERTAIN/TEMP:** discard entire `radio_volatile_work` (§1.1.1.3) across all owners; later class-D = fresh admission only.  
`AUTHORITY_DIVERGENCE` is **not** a candidate-local terminal: live HW/REG/assignment/generation authority is inconsistent with the plan or R2 live bind. Action is stop new issue, authority rebind (and drain if issued may exist), never “drop candidate and retry same authority state forever”.  
**BIND_MISMATCH classification (closed) / BIND_COMPARISON_LOCUS_CLOSED:** branch on exact `status=NINLIL_R5_BIND_MISMATCH` + `reason=BIND_ITEM` + **`comparison_locus`** + `bind_item` + provenance. Hint-string parse forbidden.  
| comparison_locus | meaning | W1 class rule |
| --- | --- | --- |
| `CANDIDATE_VS_R5_EXPECTED` | static candidate vs R5 expected plan (pre-commit) | `TERMINAL_UNISSUED` / recompose candidate |
| `R5_EXPECTED_VS_R2_LIVE` | R5 expected vs R2 durable live bind/generation | `RECONCILE_REQUIRED` or `AUTHORITY_DIVERGENCE` |
| `REGISTRY_POSTCOMMIT` | post R2 OK registry/HAL vs returned window | `RECONCILE_REQUIRED` only |

#### 15.3.3 Issued Permit cleanup / exported-module drain orchestration (closed)

**ISSUED_PERMIT_GLOBAL_RECONCILE_CLOSED / L1_EXPORTED_PRIVATE_MODULE_DRAIN_ORCHESTRATION_CLOSED / U5_GENERATION_ONLY_VIA_DOCS25_L5_L9 / ADR0010_SUPERSEDES_R5_RESTART_GEN_BUMP / EXPORTED_PRIVATE_MODULE_C_API_NOT_OSS_PUBLIC:**

Discarding only a candidate while an issued Permit may still exist is **forbidden**. There is no per-Permit cancel API.

**API naming (P1(26)):** “exported private-module C API” means existing process-local symbols in R2/R5 private modules (e.g. `ninlil_pcp_revoke_all_outstanding`, `ninlil_r5_shutdown`) — **not** installed OSS public ABI headers. Ordinary drain uses those exported module APIs; it is **not** a mandatory private R5 reconciliation seam. Stale name `R7_STATUS_PRESERVING_R5_RECONCILE_SEAM` is **not** Normative.

**Forbidden designs (must not appear as Normative):** R6 independent `permit_bind_generation` G→G+1; R6 `fence_target` / controller-durable generation snapshot ownership; ordinary drain via `ninlil_r5_fence_after_revoke`; deferred ARW generation bump by R6; “mandatory private R5 reconciliation seam” as the only implementable path; treating exported-module APIs as installed OSS public ABI.

**Ordinary issued-Permit drain MUST keep `permit_bind_generation` and U5 ARW bit-exact unchanged.** Assignment first apply/mutation is **only** docs/25 §8.5: exact floor RESTORE/DUP stops at L4 with generation unchanged; only higher valid SET executes L5–L9 and atomically binds permit fence + ARW generation. R6 never independently bumps/defers ARW generation.

**ADR-0010 amendment (P1(21)):** docs/29 §5.1 / ADR-0009 now distinguish LAB standalone assignment fence from R6 restart. W1 ordinary cleanup is §15.3.3 exported private-module drain with **bit-exact** generation（no bump）。実際の assignment mutation だけ docs/25 §8.5 SET L5–L9 が新 generation を決める。R5/W1が独自 `old+1` を選んではならない。

**P1(12)/(33) ordered recover (closed) / DRAIN_STORAGE_BEFORE_REVOKE_BEFORE_CLOCK / DRAIN_NO_COMBINED_RECOVER_WHILE_OUTSTANDING / REVOKE_ALL_CLOCKLESS_UNDER_CLOCK_FENCE / DRAIN_CLOCK_ORDER_RESAMPLE_BEFORE_RECOVER_CLOCK:**

Combined `ninlil_pcp_recover` auto-runs `recover_clock` after storage and can return `BUSY_OUTSTANDING` with old-epoch outstanding — blocking revoke. Also `recover_storage` **may clear RAM CLOCK bit** without making a sample visible. Exact order:

1. **`ninlil_pcp_recover_storage` only** when STORAGE fence / durable ambiguity requires it (never combined recover while outstanding may be >0)  
2. **`revoke_all` → durable outstanding 0** (clockless; allowed under CLOCK fence)  
3. **re-sample + four-way epoch classify** (§11.2.2 class D/A/B/C) using ram_trust mirror after storage rebuild  
4. **RAM arm** only from classify result / baseline snapshot (not from guessed `recover_clock` S)  
5. **only then** if CLOCK fence / class C / CLOCK_FAULT path requires: private adopt and/or exported `recover_clock` (no sample out)

**MUST NOT** call combined `ninlil_pcp_recover` while outstanding may be non-zero.  
**MUST NOT** sticky-fail storage-only when CLOCK remains and outstanding > 0 — proceed to revoke.  
**MUST NOT** run `recover_clock` before outstanding 0 + re-sample/classify.

**DRAIN_RETRY_BUDGET_CLOSED / DRAIN_NO_SAME_TICK_SPIN (P1(31)):**

| budget dimension | exact rule |
| --- | --- |
| per event / pump call | advance **at most one** drain phase (or one typed retry of the **current** phase) |
| per drain episode | max **8** phase-retry attempts total across RECOVER_STORAGE/REVOKE/CLOCK |
| same-tick / tight spin | **forbidden** — next retry only on a later coordinator pump/event |
| budget exceeded | typed **`OPERATOR_RECOVERY_REQUIRED`**; sticky TX 0; no silent continue |
| CLOCK_FAULT / class B/C path | **MUST NOT** use authority-domain timer backoff (`permit_*_retry_ms` / frag timers) to pace drain; drain pacing is episode budget + pump only |

**RESTART_RECOVER_STORAGE_AFTER_BIND / RESTART_EMPTY_OK_PUBLISH_PATH (P1(32)):**

| restart entry | required steps | next |
| --- | --- | --- |
| process restart / cold | R2 bind storage → **`recover_storage` mandatory** | status **OK** ⇒ enter existing drain/rebuild path if outstanding/issued may exist or fences set; else baseline snapshot + TX0 until U5 SET |
| `recover_storage` returns **EMPTY_OK** | **initial publish path** (`publish_initial_meta` / docs/24 empty) — **not** ordinary drain | TX 0 until published + baseline |
| same-process clean skip | may skip reopen **only if** all: live handle proven, last op not COMMIT_UNKNOWN, no STORAGE fence, outstanding already proven 0, no dual-truth flag | otherwise full recover_storage |

**RECOVERY_SERIES_SINGLE_PIPELINE_CLOSED / ORDINARY_SAME_EPOCH_CANCEL_CLOCK_NOOP (P1(37); sole L1 series):**

One linear recovery series (L1 owner; not W1). Phases advance in order; skip only as noted:

| phase | exact steps | result |
| --- | --- | --- |
| `DRAIN_STOP` | L1 stops R1 TX edges and new issue; mark **all** live issued snapshots `QUARANTINED`; quarantine-linked groups/candidates | sticky TX 0 |
| `DRAIN_RECOVER_STORAGE` | **if** restart / COMMIT_UNKNOWN / STORAGE fence / durable ambiguity: `ninlil_pcp_recover_storage` only; copy-own inputs; **else skip** | fail ⇒ sticky TX 0 |
| `DRAIN_REVOKE` | `ninlil_pcp_revoke_all_outstanding` (clockless) until durable outstanding **0**; never invent cancel; never ordinary `fence_after_revoke` | non-OK after budget ⇒ `OPERATOR_RECOVERY_REQUIRED` |
| `DRAIN_CLOCK` | after outstanding 0: four-way classify / boot baseline **or** RAM arm + `recover_clock` / private adopt as class requires; **hold L1 watermark until adopt done** if class C; **ordinary same-epoch cancel / owner deadline drain with class D and no CLOCK fence ⇒ CLOCK stage NOOP** | fail ⇒ sticky TX 0 |
| `DRAIN_BASELINE_INIT` | typed baseline snapshot + L1 epoch/watermark init (class A repair or post-adopt `sample_valid=1` or boot bootstrap); **not** exported `recover_clock` S | fail ⇒ sticky TX 0 |
| `DRAIN_R5_CLEAR` | only after durable outstanding zero: `ninlil_r5_shutdown`; **MUST NOT** before zero | fail ⇒ sticky TX 0 |
| `DRAIN_R5_REBUILD` | init; reload HW+REG; activate; `ninlil_r5_bind_pcp` | fail ⇒ sticky TX 0 |
| `DRAIN_PROFILE_EPOCH` | revalidate active profiles have `profile_clock_epoch_id ==` L1 current epoch; else TX 0 until reload (sidecar; §15.3.1.1 / P1(40)) | no match ⇒ TX 0 |
| `DRAIN_U5_RESUME` | U5 same-gen revalidate/bind or SET L0–L4 RESTORE/DUP / L5–L9 APPLY; ARW alone insufficient; generation bit-exact | no active bind ⇒ TX 0 |
| `DRAIN_OWNER_CLEANUP` | §15.3.3.1 all quarantined issued TERMINAL/STALE; FIFO full clear; unissued by trigger | — |
| `DRAIN_OK` | resume issue only if U5 bind valid + generation bit-exact + profile epoch match | — |

**COMMIT_UNKNOWN re-entry (closed) / DRAIN_COMMIT_UNKNOWN_REENTRY_CLOSED:**

| phase that returned COMMIT_UNKNOWN | re-entry action | fence target |
| --- | --- | --- |
| `DRAIN_RECOVER_STORAGE` | remain/re-enter storage-only; no revoke yet | **NO fence target** |
| `DRAIN_REVOKE` | re-enter storage-only then revoke until OK + outstanding 0 | **NO fence target** |
| `DRAIN_CLOCK` / `DRAIN_BASELINE_INIT` | storage ambiguity → storage-only; else re-enter clock/baseline with outstanding 0; adopt UNKNOWN → proposed/old compare (§11.2.3.1) | **NO fence target** |
| `DRAIN_R5_CLEAR / REBUILD / RESUME` | no R2 durable COMMIT_UNKNOWN ordinary path; failure sticky TX 0 | n/a |

**Crash points:** crash before zero proof ⇒ restart recover_storage→revoke; after zero before shutdown ⇒ empty R5 RAM OK if outstanding 0; crash in RESAMPLE/CLOCK ⇒ re-enter with outstanding 0; never terminal deliver while issued may exist.

| reconcile trigger | phase path | on failure |
| --- | --- | --- |
| issued present/ambiguous; RECONCILE_REQUIRED; terminal with issued; restart before new issue; class B/C; CLOCK_FAULT with issued | `DRAIN_STOP`→storage?→revoke→resample→clock?→…→`DRAIN_OK` | sticky TX 0; generation unchanged |

`advance_expired_heads` alone is **insufficient**. Copy-own reconstruction inputs across retry.

##### 15.3.3.1 Post-`DRAIN_OK` disposition (closed)

**DRAIN_OK_PER_OWNER_DISPOSITION_CLOSED / DRAIN_ALL_QUARANTINED_TERMINAL_OR_STALE / DRAIN_FIFO_FULL_CLEAR / DRAIN_NO_PREDRAIN_SNAPSHOT_REUSE:**

At `DRAIN_OK`:
1. **Global issued FIFO is fully deleted** (all sequences dead).  
2. **Every** QUARANTINED issued owner/group/candidate is **TERMINAL or STALE_NO_RETRY only** (`QUARANTINED_ISSUED_TERMINAL_OR_STALE_ONLY`) — **no** `RETRY_PREP` disposition, **no** reuse of pre-drain Permit/candidate/HAL snapshots.  
3. New work after DRAIN_OK is **fresh admission only** under rebuilt R5/U5 (new counter / new candidate; separate from pre-drain sequences).

| class at DRAIN_OK | disposition | exact steps |
| --- | --- | --- |
| **any QUARANTINED issued** (trigger or unrelated) | `TERMINAL` or `STALE_NO_RETRY` | if consume+edge done ⇒ `STALE_NO_RETRY`; else `TERMINAL` (cancel PARTIAL/reserve/candidate/blob; complete TERMINAL_PENDING tombstone if waiting); **never** resume pre-drain Permit |
| **post-revoke proven never issued** (existence was ambiguous only) | `CANCEL` | unissued cancel; no delivery claim from that Permit |
| **unissued work — trigger-dependent** | see below | never inherits a revoked Permit sequence |

**Unissued work by trigger (closed):**

| trigger that entered drain | unissued candidate/group/blob | action |
| --- | --- | --- |
| owner deadline / cancel / max8 / validate terminal | related unissued | local cancel/release with terminal decision |
| issue RECONCILE / class B authority divergence | related unissued | drop; no auto-retry until authority consistent |
| class C epoch / CLOCK_FAULT adopt path | all volatile unissued | already discarded at freeze; fresh admission only after class D or post-adopt W1 init |
| CLOCK_UNCERTAIN / TEMP (global discard §1.1.1.3) | **all** R6-owned volatile unissued work (all owners) | **globally discarded** before/while drain; unrelated candidate/group/blob **MUST NOT** remain; only pre-admission higher application owner/data outside R6 may remain; after class-D **fresh admission only** |
| restart | all volatile unissued | discarded; TX 0 until drain/U5 path complete |

**MUST NOT:** resume TX on a pre-drain Permit sequence or snapshot.  
**MUST NOT:** leave any QUARANTINED issued without TERMINAL/STALE disposition.  
**MUST NOT:** retain FIFO entries across DRAIN_OK.

#### 15.3.4 R1 full transmit pipeline result matrix (closed)

Callers never invoke `consume` directly and never retry at the consume stage. A retry re-enters the sole full `transmit_with_permit` sequence so validate/time/live/digest checks run again. **Two-stage decision (exact):** (1) raw R1 tuple (status/stage/reason/consume_invoked/edge_invoked); (2) for raw retryable tuples only, L1 **RETRY_GATE_OPEN** XOR **RETRY_GATE_CLOSED** per §1.1.2 **TX_RESULT_RETRY_GATE** (not a second HAL invent). Cross-check §1.1.2 **TX_RESULT mapping** for exact rows: validate HAL16 (`consume_invoked=0`); consume HAL16 (`6/8/16`, `consume_invoked=1`); consume HAL45 (`6/8/45`, `consume_invoked=1`); HAL43/HAL44 (`consume_invoked=1`). R1 entry requires prior **OK_ISSUED**; there is **no** R1 unissued-proven local-terminal branch.

| exact R1 result | action |
| --- | --- |
| `NINLIL_RADIO_HAL_OK` | consume succeeded and sole TX edge was invoked once; increment hop air attempt; candidate/Permit never reusable |
| `NINLIL_RADIO_HAL_NOT_BEFORE` at validate/time (HAL reason **16**), edge invocation 0 | raw retryable tuple (validate HAL16); L1 **RETRY_GATE** OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE (OPEN ⇒ same-Permit full R1 only +100ms; CLOSED ⇒ TX_QUARANTINE/drain) |
| `NINLIL_RADIO_HAL_CONSUME_DENIED` at `PERMIT_CONSUME` with typed reason **16 NOT_BEFORE** only, edge 0 | raw retryable tuple (consume HAL16; consume callback entered); L1 **RETRY_GATE** OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE |
| `NINLIL_RADIO_HAL_CONSUME_DENIED` at `PERMIT_CONSUME` with typed reason **45 CONSUME_BUSY** only, edge 0 | raw retryable tuple (consume HAL45; consume callback entered); L1 **RETRY_GATE** OPEN/CLOSED exclusive per §1.1.2 TX_RESULT_RETRY_GATE |
| `NINLIL_RADIO_HAL_EXPIRED` | **MUST NOT** treat `advance_expired_heads` alone as cleanup; enter §15.3.3 exported private-module drain |
| `NINLIL_RADIO_HAL_CONSUME_DENIED` at `PERMIT_CONSUME` with R1 HAL reason **43** `FIFO_OUT_OF_ORDER` (see §15.3.4.1), edge invocation 0, mutation 0 | **usual retry forbidden**; no same-Permit +100ms path; enter §15.3.3 drain / FIFO reconcile |
| `EDGE_ERROR` after consume success + edge already invoked | consume done and edge invoked ⇒ R5/R2 cleanup already applied for that Permit; **no-drain terminal** for that Permit; owner/LINK group terminal; no same-Permit reuse |
| `NINLIL_RADIO_HAL_CONSUME_FENCED`, `CONSUME_ERROR`, `PERMIT_DENIED`, `PERMIT_ERROR`, `BUSY`, `FRAME_MISMATCH`, `SEQ_REUSE`, `LIVE_MISMATCH`, `UNSUPPORTED`, `SEQ_EXHAUSTED`, invalid/default-deny, any stage/reason/plan-shape mismatch, or unknown with edge invocation 0 | no same-Permit reuse; R1 is entered **only after OK_ISSUED** ⇒ issued existence; **MUST** enter §15.3.3 drain / TX_QUARANTINE path; **no** mutation-0 unissued-proven local-terminal branch in R1 (unissued terminal is PRE_R1 only → OWNER_TERMINAL) |

R1 exposes no retryable consume-unknown/COMMIT_UNKNOWN. R2 durable ambiguity maps to terminal `CONSUME_FENCED` / drain. Generic HAL reason **41** `CONSUME_UNCONSUMED` is **legacy production only** and is **not** the R6 frozen target (see docs/24 §10.10).

##### 15.3.4.1 Two-catalog consume mapping (closed; docs/24 §10.10 sole source)

**CONSUME_TYPED_REASON_43_45_CLOSED / FIFO_OOO_NO_HINT_PARSE / TWO_CATALOG_PCP_VS_HAL:**

Hint parse forbidden. **R2 PCP** and **R1 HAL** are separate namespaces (docs/24 §10.10). Code **16** is R1 HAL `NOT_BEFORE` only — never call it a PCP code.

| R2 PCP reason | R1 HAL reason | L1 class | action |
| ---: | ---: | --- | --- |
| **9** `PCP_REASON_NOT_BEFORE` | **16** `NINLIL_RADIO_HAL_REASON_NOT_BEFORE` | RETRYABLE_PIPELINE | same Permit + same sealed; full R1 only |
| **45** `PCP_REASON_CONSUME_BUSY` | **45** `NINLIL_RADIO_HAL_REASON_CONSUME_BUSY` | RETRYABLE_PIPELINE | same Permit + same sealed; full R1 only |
| **44** `PCP_REASON_CONSUME_CLOCK_UNCERTAIN` | **44** `NINLIL_RADIO_HAL_REASON_CONSUME_CLOCK_UNCERTAIN` | CLOCK_PATH_DROP | discard all old volatile (candidate/Permit/group/prep/timer/blob); keep only higher app owner/data; later = fresh burn/stamp/seal/issue |
| **43** `NINLIL_PCP_REASON_FIFO_OUT_OF_ORDER` / `PCP_REASON_FIFO_OUT_OF_ORDER` | **43** `NINLIL_RADIO_HAL_REASON_FIFO_OUT_OF_ORDER` | FIFO_OUT_OF_ORDER | drain; no usual retry |

Sample-path `PCP_REASON_CLOCK_UNCERTAIN=6` is **not** a consume-path code. Current production HAL 41/42 collapse is legacy only. Until R7 wires HAL 43/44/45 and R2 PCP 43/44/45/9 on consume, R6 TX remains **NOT READY**.

#### 15.3.5 Authority-time clock handoff (closed)

**AUTHORITY_TIME_CLOCK_HANDOFF_CLOSED / W1_CLOCK_WATERMARK_REGRESSION_CLOSED:**

| step | exact rule |
| --- | --- |
| single domain for all CELL timers | every §13.1 timer and every L1-stamped `*_mono` uses R2 authority domain inside one `clock_epoch_id`; no second local/OS mono |
| sample sole owner | only §11.2.3 `ninlil_r2_private_sample_authority_clock` with closed request/result signatures may produce stampable samples |
| now_mono identity | `now_mono` is accepted trusted sample `now_ms`; watermark rules in §11.2.2 |
| sole-owner watermark | L1 updates `l1_last_accepted_now_ms` / `w1_last_accepted_now_ms` only after accepted same-epoch class-D (fences clear); same-epoch regression ⇒ `CLOCK_FAULT` + durable latch |
| owner admission sample | `SAMPLE_TRUSTED_SAME_EPOCH` only; store `clock_epoch_id`; set deadlines as `checked_add(sample.now_ms, ttl)` |
| issue primitive inputs | static candidate + expected epoch + L1 watermark + owner deadline only; R5-internal window after S; same-S not_before/expiry; returned window registry/R1; forbids Algorithm E and pre-sample absolute window compose |
| four-way epoch class | D same+fences clear; A L1 repair no adopt; B authority divergence drain bounded→OPERATOR_RECOVERY; C new-epoch drain+adopt; no OR-bulk recover |
| TEMP/uncertain | discard old work; later same-epoch class-D fresh admission OK |
| regression / CLOCK_FAULT | same-epoch admission forbidden; durable latch survives restart; require fresh-epoch class-C adopt + latch clear; not RETRYABLE_UNISSUED |
| routine sample floors | ram_trust mirror + L1 watermark; no storage RO on timer path; baseline snapshot boot/adopt only |
| route lease external domain | not same domain ⇒ route TX 0; M4 same-domain deadline required |
| cross-epoch / race | R7 vectors: classes A/B/C/D, adopt only C, baseline boot-only RO, L1 watermark held until adopt done, CU token lifetime, durable CLOCK_FAULT latch |

#### 15.3.6 `e2e_attempt_start_mono` (closed)

**E2E_ATTEMPT_START_MONO_ONCE:**

- Set exactly once per fresh E2E preparation slot claim from an **accepted** trusted sample (`epoch_id` match + watermark non-regression) immediately before the claim.  
- Never modified by burn, Seal, Permit denial, or hop retry.  
- Checked retry formulas remain same-domain only:
  - `retry_not_before = max(checked_add(attempt_terminal_mono, frag_retry_interval_ms), checked_add(e2e_attempt_start_mono, frag_retry_interval_ms))`
  - `retry_not_before = max(frag_ack_deadline, checked_add(group_completion_mono, frag_retry_interval_ms), checked_add(e2e_attempt_start_mono, frag_retry_interval_ms))`

#### 15.3.7 Generated ACK intent state machine + burn limits (closed)

**GENERATED_ACK_BURN_LIMITS_CLOSED / FRAG_ACK_INTENT_STATE_MACHINE_CLOSED / FRAG_ACK_SEMANTIC_BURN_LEDGER_RETAINED / FRAG_ACK_RETRY_USES_FRAG_RETRY_INTERVAL:**

**Semantic identity** of a FRAG_ACK intent is the full canonical FRAG_ACK plaintext: `(transfer_handle, frag_count, received_bitmap, status, reason)` — not a shortened `(status,reason,bitmap)` alone.

**Budgets (exact):**
- per semantic identity: successful durable reverse E2E burns **≤ 2**;
- per receiver transfer / tombstone aggregate: reverse burns **≤ `2 * frag_count`** and absolute **≤ 32**;
- state-only counters **MUST NOT** change portable canonical **72 B** tombstone layout.

**`semantic_burn_ledger` (Normative):** for each semantic identity ever burned on a receiver/tombstone owner, store at least `(semantic_identity_digest_or_exact_bytes_ref, burns_used, last_burn_mono)`.  
- **Retain** the ledger until the owning resource expires: active reassembly uses `receiver_absolute_deadline`; terminal tombstone uses `tombstone_expiry`.  
- **INTENT_ACKED / INTENT_DROP clear pending work only** — they **MUST NOT** reset or delete the ledger for that identity.  
- Therefore a later **same** full plaintext duplicate **MUST NOT** reset max2: new burns are admitted only while `burns_used < 2` and aggregate budgets allow.  
- On owner/tombstone expiry or process restart (volatile discard), the ledger is discarded with the owner.

**Exact retry timer:** FRAG_ACK prep/retry positive backoff uses existing **`frag_retry_interval_ms` = 500** (same domain as other W1 timers).  
`ack_intent_retry_at = checked_add(now_mono, frag_retry_interval_ms)` (overflow ⇒ `INTENT_DROP`, ACK TX 0). **Not** `permit_issue_retry_ms` / `permit_tx_retry_ms` (those are Permit pipeline only). **Not** `frag_partial_ack_idle_ms` (that sets first due only).

##### 15.3.7.1 States

| state | meaning |
| --- | --- |
| `INTENT_IDLE` | no pending intent work; ledger for identities may still exist under the owner |
| `INTENT_PENDING` | intent exists; waiting for first due |
| `INTENT_DUE` | `now_mono >= partial_ack_due` (or terminal due) and owner deadlines live |
| `INTENT_RESERVE` | control ACK reserve admitted |
| `INTENT_BURN` | about to / performing durable reverse E2E burn |
| `INTENT_BURN_CU` | durable reverse burn returned COMMIT_UNKNOWN; reserve held; ACK TX 0 |
| `INTENT_SEAL` | post-burn E2E Seal/encode in progress |
| `INTENT_LINK` | LINK group/candidate active for this intent (hop prep ≤ 4; usual LINK group 1) |
| `INTENT_RETRY` | waiting `now_mono >= ack_intent_retry_at` before another burn (ledger not reset) |
| `INTENT_ACKED` | hop success for this intent generation; **pending work cleared**; ledger retained |
| `INTENT_DROP` | give up pending work; ACK TX 0; **MUST NOT** extend receiver/tombstone TTL solely to retry; ledger retained until owner expiry |

##### 15.3.7.2 Closed state × event transition table

| from_state | event | to_state | exact effects |
| --- | --- | --- | --- |
| `INTENT_IDLE` / none | incomplete START/CONT/active exact-duplicate requires PARTIAL, or terminal COMPLETE/ABORT needs ACK after cleanup | `INTENT_PENDING` | create intent; set `partial_ack_due = min(owner_deadline, checked_add(now_mono, frag_partial_ack_idle_ms))` (terminal path may set due=now if immediately eligible); **do not** reset ledger for same identity |
| `INTENT_PENDING` | `now_mono >= partial_ack_due` and deadlines live | `INTENT_DUE` | — |
| `INTENT_PENDING`/`INTENT_DUE`/`INTENT_RETRY` | owner/receiver/tombstone deadline reached or checked-add overflow | `INTENT_DROP` | three-way cleanup on any candidate; ledger retained until owner expiry |
| `INTENT_DUE` | control reserve admit OK | `INTENT_RESERVE` | bind reserve to intent under `control_ack_deadline` ∩ owner deadline |
| `INTENT_DUE` | control reserve fail (capacity/owner) | `INTENT_DROP` | ACK TX 0; **no** unowned ABORT RESOURCE; ledger retained |
| `INTENT_RESERVE` | aggregate or per-identity budget exhausted (`burns_used >= 2` or aggregate full) | `INTENT_DROP` | release reserve; ACK TX 0; no TTL extension |
| `INTENT_RESERVE` | durable reverse E2E burn OK | `INTENT_SEAL` | `burns_used += 1` on ledger; burn consumed even if later Seal fails |
| `INTENT_RESERVE` | durable reverse E2E burn `COMMIT_UNKNOWN` | `INTENT_BURN_CU` | hold reserve; ACK TX 0; ledger unchanged until §9.3 classify |
| `INTENT_RESERVE` | durable reverse E2E burn fail (definite counter fail) | `INTENT_DROP` | release reserve; ACK TX 0; ledger unchanged (no burn charged) |
| `INTENT_BURN_CU` | §9.3 ALL_PROPOSED | `INTENT_SEAL` | charge burns_used exactly once |
| `INTENT_BURN_CU` | §9.3 ALL_OLD | `INTENT_RESERVE` | ledger unchanged; re-burn |
| `INTENT_BURN_CU` | §9.3 THIRD/CORRUPT | `INTENT_DROP` | release; CORRUPT fence |
| `INTENT_BURN_CU` | §9.3 RETRY_LATER | `INTENT_BURN_CU` | hold reserve; TX 0 |
| `INTENT_SEAL` | E2E Seal/encode **success** | `INTENT_LINK` | create at most one LINK group; hop prep ≤ 4 |
| `INTENT_SEAL` | E2E Seal/encode **failure** (post-burn) | `INTENT_RETRY` if `burns_used < 2` and aggregate remaining and deadlines live; else `INTENT_DROP` | burn **already consumed**; set `ack_intent_retry_at = checked_add(now_mono, frag_retry_interval_ms)` on RETRY; release any partial sealed bytes; three-way cleanup if a candidate was partially formed |
| `INTENT_LINK` | covering LINK success (ACKED) | `INTENT_ACKED` | clear **pending** intent/reserve/group work only; **ledger retained** |
| `INTENT_LINK` | LINK `TERMINAL_FAIL` / group deadline / hop prep exhaust | `INTENT_RETRY` if `burns_used < 2` and aggregate remaining and deadlines live; else `INTENT_DROP` | three-way cleanup on group/candidate; `ack_intent_retry_at = checked_add(now_mono, frag_retry_interval_ms)` on RETRY |
| `INTENT_LINK` | owner/tombstone deadline | `INTENT_DROP` | three-way cleanup; ledger retained until expiry discard |
| `INTENT_RETRY` | `now_mono >= ack_intent_retry_at` and deadlines live and budgets allow | `INTENT_DUE` | re-enter reserve→burn path; **same** semantic identity; ledger `burns_used` not reset |
| `INTENT_RETRY` | budget exhausted or deadline | `INTENT_DROP` | ACK TX 0; no TTL extension |
| `INTENT_ACKED` | same full plaintext duplicate refresh | `INTENT_ACKED` (or create new pending only if policy requires re-emit **and** `burns_used < 2`) | **MUST NOT** reset ledger max2; if re-emit needed and budget remains → new `INTENT_PENDING` under same ledger; if budget exhausted → ACK TX 0 without TTL extension |
| any pending | **semantic supersede** (new full plaintext identity) | prior → three-way cleanup then `INTENT_DROP`/`IDLE`; new identity → `INTENT_PENDING` | prior ledger retained until owner expiry; **new** identity gets its own ledger row (burns_used=0); aggregate budget still enforced |
| any | process restart / epoch adopt freeze | discard volatile intent+ledger with owner | fail-closed; no resume |


##### 15.3.7.3 INTENT_BURN / INTENT_BURN_CU × durable storage (closed)

**INTENT_BURN_CU_STATE_CLOSED / BURN_CU_W1_RESPONSE_CLOSED cross-check:**

Same-process recovery object copy-owns `pre_ram_next, pre_ram_limit, proposed_U, candidate_C` (C=pre_ram_limit, U=new exclusive) and lane old/proposed. Post-classify W1 response **MUST** follow §1.1.1.1 **BURN_CU_W1_RESPONSE_CLOSED** (RETRY_LATER/ALL_PROPOSED/ALL_OLD → W1 response none; THIRD/CORRUPT → SEAL_FAIL exactly once). Forbidden: “classification後必ずSEAL_FAIL”.

| from | storage | to | ledger | RAM | reserve | W1 response (cross-check §1.1.1.1) |
| --- | --- | --- | --- | --- | --- | --- |
| RESERVE | FULL OK | SEAL | +1 once | limit=U; assign C; next=C+1 | hold | n/a (not BURN_CU classify) |
| RESERVE | definite fail | DROP | 0 | prestate | release | n/a |
| RESERVE | CU | BURN_CU | 0 | frozen | hold | none while CU open |
| BURN_CU | RETRY_LATER | BURN_CU | 0 | frozen | hold | none |
| BURN_CU | ALL_PROPOSED | SEAL | +1 once | limit=U; C once; next=C+1 | hold | none (resume encode/AEAD then ordinary exactly-one) |
| BURN_CU | ALL_OLD | RESERVE | 0 | restore pre | hold | none (retry same preparation burn entry) |
| BURN_CU | THIRD/CORRUPT | DROP+CORRUPT | 0 | fence | release | SEAL_FAIL exactly once (COUNTER_CORRUPT, burn_state=AMBIGUOUS; value0≠durable-zero) |

**Process restart:** discard all volatile intent/C/proof/ledger/reserve. Load durable floor: `ram_next = ram_limit = durable U`. ACK 0. New burns only with counters ≥ U. ALL_PROPOSED/OLD using pre-crash C is forbidden without live CU object.

MUST NOT ACK TX from BURN_CU. MUST NOT double-charge ledger.

#### 15.3.8 Terminal PARTIAL / resource cancel matrix + TERMINAL_PENDING (closed)

**TERMINAL_PARTIAL_CANCEL_MATRIX_CLOSED / TERMINAL_PENDING_BEFORE_DRAIN:**

**Three-way cleanup (sole rule for every owner/resource/timer/group deadline that would release/discard a candidate):**

1. **Unissued** prepared candidate/blob/group work: local cancel/release with the atomic decision.  
2. **Issued** Permit (or issued existence ambiguous): **§15.3.3 exported private-module drain** — local discard forbidden.  
3. **Consume+edge already done:** irrevocable; mark group/owner **stale/no-retry**; later LINK_ACK mutation 0; no drain required for that Permit.

**TERMINAL_PENDING:** if a receiver terminal (COMPLETE/ABORT*) is ready but an issued Permit still exists for related ACK/DATA work: freeze delivery/TX, enter drain first, and **only after** `DRAIN_OK` (or proven unissued) perform the atomic terminal tombstone commit. Drain failure or restart **MUST NOT** falsely commit/deliver. If unissued: cancel+terminal commit together. If consume+edge already occurred on a related Permit: mark stale/no-retry then commit.

**TERMINAL_PENDING RX behavior (closed) / TERMINAL_PENDING_RX_BEHAVIOR_CLOSED:** while TERMINAL_PENDING is latched for transfer T (same e2e_context + transfer_id/handle):

| RX / timer event during TERMINAL_PENDING(T) | exact behavior |
| --- | --- |
| new START / CONT for **same** T (incl. exact duplicate) | reassembly/bitmap/payload/TTL mutation **0**; **no** second terminal commit; **no** new PARTIAL; ACK TX **0** until terminal commit after drain (or proven unissued); forward hop LINK rules unchanged if outer already admitted |
| new START for **different** transfer T′ | ordinary admission under §12/§13; **not** blocked solely by TERMINAL_PENDING(T); if resource full ⇒ START reject / ACK 0 (no unowned ABORT RESOURCE) |
| CONT for different T′ without active owner | drop; ACK 0 |
| receiver/idle deadline fire for T | **do not** overwrite the pending terminal with ABORT TIMEOUT; remain TERMINAL_PENDING(T); after `DRAIN_OK` commit the **original** COMPLETE/ABORT*; if drain fails sticky, keep freeze (deliver 0) |
| unrelated owner deadlines | follow ordinary §15.3.8; may enter their own drain/TERMINAL_PENDING |
| process restart | volatile discard; issued path §15.3.3; no false COMPLETE/ABORT delivery |

| terminal event | pending PARTIAL intent | reserve / sealed ACK blob / LINK group / unissued candidate | issued Permit | consume+edge already done |
| --- | --- | --- | --- | --- |
| COMPLETE | cancel; commit only after three-way cleanup / TERMINAL_PENDING | unissued cancel/release with commit | §15.3.3 drain before commit | stale/no-retry; then commit |
| ABORT DIGEST | same | same | §15.3.3 drain before commit | stale/no-retry; then commit |
| ABORT RESOURCE | same | same | §15.3.3 drain before commit | stale/no-retry; then commit |
| ABORT CONFLICT | same | same | §15.3.3 drain before commit | stale/no-retry; then commit |
| ABORT TIMEOUT | same | same | §15.3.3 drain before commit | stale/no-retry; then commit |
| ABORT FENCED | same | same | §15.3.3 drain before commit | stale/no-retry; then commit |
| tombstone expiry overflow fence | cancel; no reusable release | cancel; no reusable release | §15.3.3 if issued may exist | irrevocable; TX 0 |
| authority epoch change / uncertain / CLOCK_FAULT | drop intent | drop all volatile RX+TX | §15.3.3 if issued | stale; TX/ACK/deliver 0 |
| owner/process restart | discard volatile | discard volatile | TX 0 until exported private-module drain + U5 resume (§15.3.3) | N/A (volatile) |

COMPLETE/ABORT/PARTIAL-covering **sender** reactions share the same three-way cleanup. Final full CONT cancels PARTIAL then uses this matrix. Terminal ACK only after cleanup on a **new semantic identity** under §15.3.7.

#### 15.3.9 Burn/candidate bound summary

One LINK group: ≤1 live prepared candidate, ≤4 hop burns, ≤4 consume-success+TX air attempts; no unbounded sequence of replacement candidates/counter burns. One fragment: ≤4 E2E burns/Seals; one local SINGLE admission: 1 each. Issue/full-pipeline retries reuse the exact candidate and are max 8 positive-backoff calls, except `CLOCK_PATH_DROP` which must not retain the candidate. Issued cleanup uses §15.3.3 exported private-module drain only (generation unchanged; no `fence_after_revoke` ordinary path). ACK intents obey §15.3.7. All timers obey §11.2.2 domain table.

### 15.4 Order summary (Normative)

```text
# E2E
accepted authority sample (+ watermark) → e2e_attempt_start_mono once → claim prep
  → burn e2e_counter → E2E Seal → (LINK group owns blob)
# hop air
claim prep → burn hop_counter → outer Seal → digest/airtime
  → mandatory ninlil_r5_private_issue_checked_with_owner_epoch → R2 checked-issue (no Algorithm E; same-S; registry insert)
  → [OK_ISSUED: global FIFO]
  → [RETRYABLE_UNISSUED: CAPACITY/BUSY/BUSY_OUTSTANDING only; +100ms; max 8]
  → [CLOCK_PATH_DROP / TEMP: no retain; freeze]
  → [EPOCH_TRANSITION_REQUIRED: §11.2.3.1 drain→private adopt atomic→watermark init→fresh admission]
  → [TERMINAL_UNISSUED: drop candidate]
  → [RECONCILE_REQUIRED: exported private-module drain §15.3.3; generation unchanged]
  → full transmit_with_permit
      → [HAL NOT_BEFORE=16 or HAL CONSUME_BUSY=45 only: same permit; +100ms; max 8]
      → [success: consume + TX once]
      → [EXPIRED/FIFO_OUT_OF_ORDER typed/issued-ambiguous: exported private-module drain]
      → [EDGE_ERROR after edge: no-drain terminal]
# issued cleanup (P1(12) separated recover)
DRAIN_STOP → recover_storage-only? (not combined ninlil_pcp_recover while outstanding may be >0)
  → revoke_all (clockless under CLOCK fence) until durable outstanding 0
  → DRAIN_CLOCK? (recover_clock / private adopt only after zero)
  → only after durable zero: ninlil_r5_shutdown → rebuild profiles/bind_pcp
  → U5 owner revalidate/bind (restart: SET L0-L4 RESTORE/DUP or L5-L9 APPLY; ARW alone insufficient)
# COMMIT_UNKNOWN: per-phase re-entry table; NO fence target
```

All RF TX still: exact B → SHA-256 → R3 → R5/R2 → R1 → R9.  
**PHY_SNAPSHOT_R7_R9_BLOCKER** / **DOCS25_PERMIT_FENCE_NOT_RESOLVED_BY_R6**.

## 16. LAB channel airtime fraction (not legal duty)

**LAB_AIRTIME_REF_SF7_BW125** / **CHANNEL_AIRTIME_FRACTION_NOT_LEGAL_DUTY** / **AIRTIME_2CH_IDEAL_EQUAL_SPLIT_RAW**

Reference PHY: SF7, BW125000, CR 4:5 (`cr=1`), header_implicit=0, crc_on=1, ldro=0, preamble=8.  
Values MUST match `tools/airtime_r3_oracle.py eval` for payload lengths 89 and 51.

| frame | wire | airtime_us |
| --- | ---: | ---: |
| DATA N=24 | 89 | **153856** |
| LINK_ACK | 51 | **102656** |

```text
msg_rate = 2 msg/s; hops = 3 => DATA_tx_rate = 6/s
channel_airtime_fraction_1ch_data = 6 * 153856e-6 = 0.923136
channel_airtime_fraction_2ch_data = 0.461568
channel_airtime_fraction_2ch_1to1_ack = 0.769536
channel_airtime_fraction_2ch_ack_le_data_div4 = 0.538560
```

**2ch numbers are each channel’s ideal raw average under a perfect equal split** of the same offered load. They **do not** include collision, CAD, turnaround, beacon, join, or retry airtime.  
Planning only — **not** Japan/legal duty compliance. 2ch target needs R8 joint control of ACK_REQUESTED ratio, rate, hops, channels, retries.

## 17. Reject summary

profile≠0x11; pre-context-install app TX/RX; length domain fail; reserved kind/type (incl. kind≥3, type≥5, low nibble≠0); route terminal invariant fail; AEAD fail; group/beacon; ACK-of-ACK; counter 0/MAX; mask≠0x0003; env invalid; direction≠0/1; e2e_security_epoch=0; key_generation=0 or namespace terminal exhausted; context collision/reuse/reset; storage fail/unknown/corrupt; START without tombstone reservation; dual-index CONFLICT second alloc; overflow; unpaired ACK; ACK_REQUESTED=0 LINK_ACK; relay E2E open/lookup; unknown → TX0.

## 18. R7 acceptance (required negatives/goldens)
R7 materialization requirements frozen; artifacts pending (not committed in this freeze). (required negatives/goldens)

1. Outer/E2E concat; kind/type catalogs; low nibble 0; encode_canon BE; exact layouts unique in scope  
2. Storage ABI mapping; **namespace-wide COMMIT_UNKNOWN recovery** closed open/begin/get/rollback/close output-shape and cleanup table; one shared radio-security handle; exact namespace distinct from Foundation Runtime  
3. TX final partial tranche; RX `UINT64_C(1)<<delta` (31/32/63); key_generation MAX terminal  
4. HA V1 single sealer; owner change ⇒ new E2E context  
5. **Permit/Seal order:** authority-time sample + e2e_attempt_start_mono once→bounded prep→burn→Seal→digest/airtime→mandatory R5→R2 private checked-issue adapter (`ninlil_r5_private_issue_checked_with_owner_epoch`) calling R2 checked-issue; preserve exact typed status/stage/reason/bind_item/provenance; never Seal after Permit; typed L1 result classes exact set OK_ISSUED/RETRYABLE_UNISSUED/TERMINAL_UNISSUED/CLOCK_PATH_DROP/RECONCILE_REQUIRED/AUTHORITY_DIVERGENCE/EPOCH_TRANSITION_REQUIRED/EPOCH_W1_REPAIR/FIFO_OUT_OF_ORDER/OPERATOR_RECOVERY_REQUIRED/RETRYABLE_PIPELINE; issued cleanup only via exported private-module drain (stop→recover_storage-only?→revoke_all until zero→clock/adopt after zero; never combined ninlil_pcp_recover while outstanding may be >0; COMMIT_UNKNOWN per-phase re-entry NO fence target; shutdown only after zero; U5 owner rebind; generation bit-exact; no fence_after_revoke ordinary path; no R6 G+1; advance_expired alone insufficient); R1 tables with OUT_OF_ORDER reconcile and EDGE_ERROR no-reconcile; positive 100ms/max8; global Permit FIFO; ACK burn limits; terminal PARTIAL cancel matrix; no unbounded counter burn; hop air only on consume-success+TX  
6. LINK same blob vs fresh E2E; group_start_mono + immutable group_absolute_deadline=start+15000; closed source-FRAG/local-SINGLE/relay/FRAG_ACK/LINK_ACK owner matrix; FRAG_ACK-before-LINK_ACK supersede branch; exact sender terminal/retry branches  
7. Exact START/CONT duplicate: forward counter admission vs body mutation vs distinct reverse ACK counter; dual indexes; CONT conflict → ABORT CONFLICT tombstone  
8. Ingress vs upper ownership; LINK copy-own release points  
9. Immutable sender/LINK/receiver deadlines with checked arithmetic; frag_receiver_transfer_ttl_ms=90000; checked tombstone expiry before every terminal commit; tombstone_ttl=90000; idle refresh rules  
10. FRAG_ACK pairing/domain/status validation closed; checked PARTIAL due on START/incomplete CONT/active duplicate; full CONT cancels PARTIAL then COMPLETE/ABORT; every-4/idle-only forbidden; FRAG_ACK-loss no deadlock  
11. Volatile restart discard (queues/retry/reassembly/tombstone/reservation)  
12. CELL_64 full 21-row exact table + exact timer set; profile change ⇒ new wire_profile_id  
13. Gate negatives: duplicate layout BEGIN/END before+after for all six layouts; duplicate H2–H5; full resource/timer/status-table set equality including typed issue/reconcile/cancel/ACK-burn/clock-handoff closed tables; section-scoped enumerated contradiction probes and shadow decoys only (does **not** claim detection of arbitrary natural-language contradictions); docs/25 exact hash; no substring table match; independent human review required  
14. Oracle 89→153856, 51→102656; environment matrix; 0x11 post-attachment only  
15. **R7 materialization requirements frozen; artifacts pending** (`R7_MATERIALIZATION_REQUIREMENTS_FROZEN_ARTIFACTS_PENDING`): R7 **MUST** commit exact `spec/vectors/r7-radio-wire-v1.json` (canonical lowercase hex + stable vector IDs) and generated C fixture. **This R6 freeze does not claim those files exist or are committed.** Mandatory IDs (when materialized) cover hop/E2E binding bytes+digest; HKDF extract/expand PRK/key/IV for DATA/ACK/E2E; nonce at counters 1 and UINT64_MAX-1; all N6 layouts with CRC; SINGLE N=1/16/24/32/190; LINK_ACK; FRAG_START min/max; FRAG_CONT min/max; FRAG_ACK PARTIAL/COMPLETE/ABORT; full outer/E2E AAD, PT, ciphertext, 16B tag, and concatenated frame bytes; N6 1-bit CRC corruption negatives; CLOCK_FAULT durable latch restart; class-B OPERATOR_RECOVERY  
16. Independent oracle (not production codec helpers) **shall** generate vectors twice byte-identically; when artifacts exist, JSON/generated header freshness must match; C production codec/AEAD bridge consumes every vector. Required state vector IDs include `R7-FRAG-FINAL-GOOD`, `R7-FRAG-FINAL-DIGEST-FAIL`, `R7-FRAG-FINAL-RESOURCE-FAIL`, `R7-FRAG-ACK-BEFORE-LINK-ACK`. Negative set flips each authenticated header/body/tag boundary, reserved bit/type/kind, length edge, counter 0/MAX, pairing/bitmap/status, N6 CRC bit-flips, and verifies mutation/delivery/TX 0. Pin known-answer AES-128-GCM, HKDF-SHA-256, and SHA-256 expected bytes — round-trip-only tests are insufficient. **Artifacts pending until R7.**
17. Authority-time: §11.2.3 closed sample request/result; §11.2.3.1 baseline load; §11.2.3.1 atomic private adopt (no arm fence_code); no permanent epoch-mismatch drop loop; mandatory R5 issue adapter; same-S TOCTOU closed
18. **Exported private-module drain orchestration:** no mandatory private R5 drain seam. Process-local exported R2 recover/revoke repeats to typed OK plus durable outstanding zero; only then process-local exported `ninlil_r5_shutdown` clears the volatile registry, profiles/PCP binding rebuild, and the U5 owner decides active assignment. These symbols are not installed OSS public ABI. `permit_bind_generation` and ARW remain bit-exact; exact SET floor match stops at L4, while only a higher valid SET reaches L5–L9. Restart remains TX0 until authenticated SET replay; the R7-private extension is required for checked **issue**, not ordinary drain.
19. Generated ACK burn: FRAG_ACK semantic-version max2; transfer aggregate 2*frag_count≤32; LINK_ACK hop prep max1 consume-on-post-burn-fail; 72 B tombstone layout unchanged  


## 19. Related

[ADR-0010](adr/0010-r6-secure-radio-wire.md) · [03](03-identity-and-join.md) · [05](05-security-and-compliance.md) · [23](23-usb-radio-boundary.md) · [25](25-u5-cell-operating-assignment.md) · [27](27-r3-airtime-calculator.md)

## 20. Chunk D — private N6 durable crypto/context host candidate (Normative; fixed-hash integration GO; R7/production completeではない)

**SEMANTIC: N6_CHUNK_D_PRIVATE_HOST_CANDIDATE**  
**SEMANTIC: N6_PRIVATE_ONLY_NO_PUBLIC_ABI**  
**SEMANTIC: N6_M4_REQUIRED_WITHOUT_AUTHENTICATED_CAPSULE**  
**SEMANTIC: N6_M5_REQUIRED_FOR_SECRET_RESUME**  
**SEMANTIC: N6_BOOT_DORMANT_DURABLE_NO_SECRET**  
**SEMANTIC: N6_NO_OS_WALL_CLOCK**  
**SEMANTIC: N6_ESP_NOT_READY_NAMESPACE_CAPACITY**  
**SEMANTIC: N6_NO_HEAP_NO_VLA**  
**SEMANTIC: N6_FULL_OK_BEFORE_RAM_HANDLE**  

### 20.1 Status / non-claims

Chunk D freezes the **portable private N6 host candidate** and exhaustive host gates. **Host candidate fixed-hash integration GO** (independent re-GO 2026-07-19). It does **not** claim:
- R7 full AEAD wire codec complete
- M4 Attachment handshake production path complete
- M5 floor/resume production path complete
- ESP N6 capacity ready / Japan legal / RF·USB 実機 HIL / production radio complete
- crash-atomic exactly-once delivery

Installed OSS public headers under `include/ninlil/*` remain unchanged. N6 symbols are **production-private** (`src/radio/n6_*`) and MUST NOT appear in installed packages.

### 20.2 Private files (exact)

| path | role |
| --- | --- |
| `src/radio/n6_record_codec.{h,c}` | pure BE codec + CRC32C for N6TX/N6RX/N6HW/N6AL/N6RT/N6CF |
| `src/radio/n6_crypto_provider.h` | crypto ops vtable (SHA-256 / HKDF-SHA-256) |
| `src/radio/n6_crypto_host.c` | host default crypto ops (no public export) |
| `src/radio/n6_context_store.{h,c}` | private N6 state machine + durable install/TX/RX/fence/GC |

**Canonical exact N6 production source set** (single authority, consumed once by host + ESP packaging + testbuild derive):  
`{ n6_record_codec.c, n6_crypto_host.c, n6_context_store.c }` under `cmake/ninlil_runtime_private_sources.cmake`.  
Testbuild (`NINLIL_N6_TEST_BUILD`) **derives from the same source list** and is marked `NINLIL_TEST_ONLY_ARTIFACT` — never installed. No host-only manual injection of `n6_context_store.c` outside that authority. ESP packaging including these files does **not** make ESP N6 ready.

### 20.3 Private API closed set (signatures in `n6_context_store.h`)

`context_pool_bytes` · `init` · `bind_storage` · `bind_crypto` · `bind_authority_stamp` · `bind_local_identity_accepted` · `boot_scan` · `install_hop` · `install_e2e` · `recover_cu` (internal classify; no external classification arg) · `tx_burn` (returns copy-owned TX crypto lease) · `tx_lease_release` · `rx_precheck` (returns AEAD-open ticket materials) · `rx_admit_after_aead` · `rx_abort` · `fence` · `restamp` · `reclaim` · `gc` · `stats` · `last_error` · `shutdown` · `esp_ready` · `state`.

**Production rules:** The **durable install/TX/RX/boot engine compiles in the production private object**. Only fixture authority stamp and FIXTURE_ONLY install-provenance admission are gated by `NINLIL_N6_TEST_BUILD` / test support (separate testbuild TU). **Local identity has no raw fixture bind symbol in core** — tests call the **same** production `bind_local_identity_accepted` with fixture token+ops living only under `tests/support/` (§20.4.1). Production **MUST NOT** export fixture/test-binder symbols and **MUST NOT** provide fake-success or no-op stubs for install/TX/RX that pretend readiness. Without authenticated M4/M5/local-identity inputs, entry points **fail closed at the provenance/secret/identity boundary** (typed status; no half-success). M4 provenance without M4 adapter ⇒ `M4_REQUIRED`. Fence/restamp/reclaim/gc production path ⇒ `M4_REQUIRED` (no bit-flag proof success). Caller-owned pool **1..128** slots (controller ceiling); no heap/VLA. Handles/lease_id/ticket_id nonzero monotonic; no reuse after release/retire. TX/RX counters and accept windows are multi-key **FULL** durable; RAM/output publish only after FULL_OK. TX leases issue one counter at a time from a durable-covered `[ram_next, ram_limit)` window; a FULL block of **64** is reserved only when the window is exhausted. COMMIT_UNKNOWN retains copy-owned write plan; `recover_cu` runs NEED_CLOSE_OLD→NEED_OPEN→READ_CLASSIFY (re-entrant on phase fault), re-reads storage, and computes ALL_OLD/ALL_PROPOSED/MIXED/THIRD internally (NOT_FOUND with `old_present==0` is ALL_OLD side; `old_present==1` is THIRD). ALL_PROPOSED applies copy-owned post-actions (TX next/limit, RX accept_through); install CU never publishes a handle. Authority: production `bind_authority_stamp` is fail-closed without R2 accepted-token verifier (raw boolean / struct fields alone do **not** establish trust). Host fixture stamp injection exists only in the test-build TU. N6 does not call OS time / R2 clock_ops.

**State BOUND (exact):**  
`STATE_BOUND` ⇔ `storage_bound && crypto_bound && local_identity_bound`.  
Bind order among the three is **arbitrary**. Any proper subset leaves the object in **`STATE_INIT`** (not BOUND). There is **no** “empty storage does not require identity” exception — identity is required for BOUND and for every `boot_scan`, including empty storage.

**Provider binding continuity (exact one-shot):** storage, crypto, and accepted local identity are each **one-shot**. After a **successful** bind, a second bind (even with identical ops/token) ⇒ **`INVALID_STATE`** + reason STATE, callback/I/O/mutation **0** (identity token remains **unconsumed**). A **failed first** bind (NULL/bad ABI/etc.) does **not** set the bound flag and **may** be corrected/retried. Storage bind only **copies ops** (open/close call count 0). Crypto bind only **copies ops** (hash/HKDF call count 0). No hot-swap after provider fault: fence → shutdown → fresh init. **Shutdown** closes a live storage handle **exactly once**, then secure-zeros provider ops/user and local identity. **Fence** retains immutable bound local identity; only leases/tickets/traffic secrets are zeroized. Identity material is zeroed only on shutdown/teardown/init pre-zero.

### 20.4 Install capsule / M4 / fixture

Install inputs MUST be an **authenticated provenance capsule** (M4) or an explicit **FIXTURE_ONLY** binder for host tests. Capsule copy-owns: stable IDs, binding digests, `traffic_secret32`, `key_generation`, membership epoch, scope, node IDs.  
**Forbidden:** production install from caller-supplied raw node IDs alone. Missing M4 binder on production provenance ⇒ **`M4_REQUIRED`** (fail-closed).  
FIXTURE_ONLY admission exists only under `NINLIL_N6_TEST_BUILD`.  
RAM usable handle publish **only after** durable multi-key **FULL_OK**. Publish-before-FULL is forbidden.

#### 20.4.1 Authenticated local identity — exact private accepted adapter ABI

**Problem closed:** N6HW `scope_digest28` includes `local_node_id`. Boot (including empty storage) and install must not trust raw caller IDs. A raw `local_identity` struct / `accepted_tag` API is **forbidden**. Existing public M4/R2 ABI is **unchanged**.

##### Exact types (private header)

```
typedef struct ninlil_n6_accepted_local_identity_token
    ninlil_n6_accepted_local_identity_token_t;   /* incomplete */

/* consume status (uint32) */
OK = 0, REJECTED = 1, STALE = 2, INTERNAL = 3

/* claim ABI v1 — exact 24 bytes (not extensible at this version) */
typedef struct ninlil_n6_local_identity_claim {
    uint16_t abi_version;      /* = 1 */
    uint16_t struct_size;      /* == NINLIL_N6_LOCAL_ID_CLAIM_BYTES (24) exactly */
    uint32_t reserved_zero;    /* = 0 */
    uint8_t  local_node_id[16];
} ninlil_n6_local_identity_claim_t;

typedef struct ninlil_n6_local_identity_ops {
    uint16_t abi_version;      /* = 1 */
    uint16_t struct_size;      /* == sizeof(ninlil_n6_local_identity_ops_t) exactly */
    uint32_t reserved_zero;    /* = 0 */
    void    *user;
    uint32_t (*consume)(
        void *user,
        ninlil_n6_accepted_local_identity_token_t *mutable_token,
        ninlil_n6_local_identity_claim_t *claim_out);
} ninlil_n6_local_identity_ops_t;
```

**R6 ABI exactness (this version):** claim and ops shapes are **exact**, not “minimum / forward-extensible.” Accept only  
`claim.struct_size == NINLIL_N6_LOCAL_ID_CLAIM_BYTES` (**24**) and  
`ops.struct_size == sizeof(ninlil_n6_local_identity_ops_t)`.  
**`>=` / `<` acceptance is forbidden.** Any future extension requires a **later accepted ADR**, not silent acceptance of larger sizes now. Undersized and oversized `struct_size` are both reject (callback 0 for ops preflight; after-callback claim shape fail for claim sizes).

Production provider: **M4-owned adapter only**. Fixture provider: **`tests/support/` TEST_ONLY target** that still calls the same production binder. No raw-id tag symbols in production archive/install.

##### Sole production binder

```
ninlil_n6_status_t ninlil_n6_bind_local_identity_accepted(
    ninlil_n6_t *n6,
    const ninlil_n6_local_identity_ops_t *ops,
    ninlil_n6_accepted_local_identity_token_t *mutable_token);
```

| rule | exact |
| --- | --- |
| sole API | Only this binder. **No** raw `ninlil_n6_local_identity_t` / `accepted_tag` / core test bind |
| when allowed | Lifecycle **`STATE_INIT`** and `local_identity_bound == 0` only |
| second / rebind | Second bind (including same ID), or bind at BOUND/BOOTED/DORMANT/READY/CU/FENCED/SHUTDOWN ⇒ **`INVALID_STATE`**, **callback count 0** (no `consume`) |
| identity change | Requires **`shutdown` + fresh `init`** only |
| preflight before callback | State, ops/token non-NULL, ops abi_version/struct_size/reserved_zero, `consume != NULL` — any fail ⇒ no callback; status fail-closed |
| reentry | Under reentry guard; concurrent reentry ⇒ BUSY_REENTRY, callback 0 |
| consume once | On preflight OK: secure-zero claim, call `consume` **exactly once**. **Invocation consumes the token terminally regardless of result**; adapter must issue a **new** token for any retry |
| claim | Zero claim before call; secure-zero claim on all paths after |
| success | status **OK** + claim shape valid (`abi_version==1`, **`struct_size==24`** exact, `reserved_zero==0`, node_id not all-zero) → copy-own **only** `local_node_id[16]`; set `local_identity_bound`; if storage+crypto already bound → **BOUND**; secure-zero claim; do **not** retain token/ops/user |
| claim size reject | `struct_size` **≠ 24** (undersized or oversized, including `>24`) after OK status ⇒ **`M4_REQUIRED`/`LOCAL_IDENTITY`**, mutation 0 |
| ops size reject | `ops.struct_size` **≠** `sizeof(ninlil_n6_local_identity_ops_t)` (under or over) ⇒ preflight **`INVALID_ARGUMENT`/`LOCAL_IDENTITY`**, **callback 0** |
| non-accept | REJECTED/STALE/INTERNAL/unknown/bad shape ⇒ **`M4_REQUIRED`** + reason **`LOCAL_IDENTITY`**, RAM/storage mutation 0, claim zeroed, no bind flag |
| preflight fail without callback | NULL ops/token/bad ABI while INIT unbound ⇒ exactly **`INVALID_ARGUMENT` + reason `LOCAL_IDENTITY`**, **callback 0** (no “may use” ambiguity) |
| claim before callback | Claim buffer **all-zero** before `consume`; production **MUST NOT** pre-fill `abi_version`/`struct_size` (would mask provider defects) |
| shutdown | secure-zero copy-owned id + clear `local_identity_bound`; zero provider ops/user on shutdown path |
| install pre-mutation | capsule `local_node_id` byte-exact equals bound id or reject mutation 0 (`M4_REQUIRED`/`LOCAL_IDENTITY`) |
| test | Fixture ops/token minting only under `tests/support/` TEST_ONLY; **caller-owned reentrant ops** (no shared mutable static user pointer); production nm/strings/install: **no** fixture or raw-id-tag symbols |

##### `boot_scan` preflight (exact; before any storage I/O)

1. Object/reentry as usual.  
2. If `!storage_bound` or `!crypto_bound` ⇒ **`INVALID_STATE`**, storage open/begin/iter call count **exactly 0**.  
3. If `!local_identity_bound` ⇒ **`M4_REQUIRED`** + reason **`LOCAL_IDENTITY`**, open/begin/iter **exactly 0** (applies to **empty and non-empty** storage; **no empty exception**).  
4. Only when all three bound: open storage and scan.  
5. Empty durable success ⇒ **`STATE_BOOTED`**, status **OK**. Non-empty valid without secrets ⇒ DORMANT as before.  

##### Boot workspace / multipass (exact; ESP stack)

`boot_scan` **MUST NOT** place O(N) arrays of AL/HW/RT/lane accumulators on the stack. **No heap, no VLA.**

**C-based global N6 namespace ceilings** (`C = slot_count ∈ 1..128`; checked `u64` counters):

| ceiling | bound | notes |
| --- | --- | --- |
| complete active H+E | **≤ C** | pool actives |
| lane rows L = 2H+E | **≤ 2C** | HOP DATA+ACK / E2E |
| AL A | **≤ 2C** | sides × multi-receiver |
| RT T | **≤ 2C** | retired tombstones |
| CF F | **≤ C** | context fences |
| HW W | **≤ 2A and ≤ 4C** | directions × AL |
| total R = A+L+T+F+W | **≤ 11C** | Pass0 hard row ceiling |
| logical key+value bytes | **≤ 876C** | lane 116 + AL 80 + RT 76 + CF 92 + HW 60 at max mix |

Pins: **C=128 → 1408 rows / 112128 bytes**; **C=8 → 88 / 7008**. Boot cap breach ⇒ **CORRUPT+FENCED**. Write post-image cap breach ⇒ **CAPACITY** mutation 0. **ESP port 32-entry model remains NOT READY** (`esp_ready=0`).

**Exact single-snapshot 4 passes** (happy path I/O: `begin=1`, `iter_open=4`, `iter_close=4`, `rollback=1`):

| pass | work |
| --- | --- |
| **P0** | Census all records: strict unsigned lexicographic increasing keys (duplicate-free; O(1) previous-key scratch), exact decode, key↔value duplicate fields, type+global ceilings, load AL + validate fp/epoch; empty-AL reject |
| **P1** | Lanes exact AL join, active set, floor, live↔live M collision, per-AL active, HW requirements |
| **P2** | RT+CF by **kind byte** (not length — both keys 28 B); RT floor/count/`last_kgen` + create/raise HW req (retired-only scopes); live↔RT M collision; **N6CF requires exact complete live active**, mark once (flags bit7), reject orphan/duplicate CF (coexists until reclaim — do not reject live_hit); AL declared count equality |
| **P3** | HW exact requirement join, highwater ≥ max, required exactly 1, orphan 0, scope-digest collision across different full scopes reject |

`iter_next` ≤ **4×(11C+1)** (**5636** at C=128).

| rule | exact |
| --- | --- |
| pool cell | `union n6_pool_cell { n6_slot_t live; n6_boot_pack_t boot; }`. Access **`cells[i].live`**. **Forbidden:** casting `n6_slot_t*` to an unrelated boot type |
| boot pack | Target ≤ **304 B** (equals live slot): 2×AL compact ≤48 + active ≤40 + 4×HW req ≤40 = **296** (+ pad). Capacity: actives ≤C, AL slots ≤2C, HW req ≤4C |
| size/align | `sizeof(n6_pool_cell_t) == sizeof(n6_slot_t)` (=304); alignment ≤ `NINLIL_N6_OBJECT_ALIGN`. Public pool byte contract unchanged |
| RT/CF dispatch | **Never** by length alone (both 28 B). Dispatch by `rec_kind` + exact type decoder; CF branch must be reachable |
| **snapshot** | **One** storage `open` + **one** shared RO `begin` for all 4 passes. Empty durable is a happy path: still runs all **4** passes then **BOOTED** after rollback (begin1/open4/close4/rollback1) |
| boot scratch | **Per-object** `boot_scratch` inside `ninlil_n6` (bounded under `NINLIL_N6_OBJECT_BYTES`); **not** process-global/file-static. Distinct Runtime objects do not share mutable N6 boot workspace. Same-object concurrent calls remain forbidden (reentry) |
| per pass | `iter_open` → scan → `iter_close` only. **live txn ≤ 1**, **live iter ≤ 1**, **nested = 0** |
| rollback | **Exactly once** at final cleanup. Publish BOOTED/DORMANT only after rollback OK |
| entry (BOUND) | Live slots, leases, tickets, CU all zero; then zero every union cell |
| exit | Zero all cells → empty live canaries; no boot residue; keep bound identity |
| cleanup tree | `iter_close` once if live; `rollback` once; rollback fail → close storage; semantic CORRUPT remains FENCED even if cleanup fails |
| provider shape | `begin`/`iter_open` **non-OK + non-NULL handle** ⇒ consume handle exactly once (`rollback`/`iter_close`) then **CORRUPT/FENCED**. **OK+NULL** ⇒ CORRUPT. Known operational (`IO_ERROR`/`BUSY` → STORAGE; `NO_SPACE`/`BUFFER_TOO_SMALL` → CAPACITY) with NULL handle ⇒ retryable **BOUND** (not fenced). Unknown/invalid status ⇒ CORRUPT. Four pass sites propagate mapped status |
| host/ESP compile | `-Wvla -Werror -Wframe-larger-than=2048 -fstack-usage`; `.su`: `boot_scan` ≤ **1024 B**, every N6 function ≤ **2048 B** |
| heap ban | Reject `malloc`/`calloc`/`realloc`/`free` in N6 TUs |
| object size | `sizeof(ninlil_n6_t)` ≤ `NINLIL_N6_OBJECT_BYTES` |  

##### Forbidden

- Empty-storage identity exemption  
- Raw `local_identity_t` / `accepted_tag` / core fixture bind  
- `consume` on second bind / wrong state  
- Retaining token/ops/user after bind  
- BOUND without identity  

### 20.5 Boot / restart / M5

Durable active records **MUST NOT** store `traffic_secret32`. After `boot_scan`:
- empty success with all binds ⇒ **`BOOTED`**  
- durable complete lanes without RAM secret ⇒ state **`DORMANT_DURABLE_NO_SECRET`**; **no** usable TX/RX handle  
- same-context resume requires M5 floor proof materialization; until then ⇒ **`M5_REQUIRED`** or fence; boot fence clear alone MUST NOT enable send/receive  
- HW/AL join uses §5.3.1.5 (assembly after AL join; collision via full receiver under allocator scope)  
- missing storage/crypto at boot ⇒ **`INVALID_STATE`** I/O0; missing identity ⇒ **`M4_REQUIRED`/`LOCAL_IDENTITY`** I/O0

### 20.6 Authority time

N6 accepts only a **copy-in** of an already-accepted R2 class-D token via `bind_authority_stamp` **after** R2 verifier / opaque accepted-token adapter acceptance. Production without that adapter ⇒ fail-closed (`M4_REQUIRED` / stamp reason). Raw caller-supplied boolean trust fields alone MUST NOT establish authority. Host fixture stamp injection is test-build-only. N6 **MUST NOT** sample OS or host local time itself (no R2 clock_ops call from N6). Epoch mismatch / regression on re-stamp (test path) ⇒ fail-closed.

### 20.7 Durable codec / crypto (cross-ref §5.3 / §8)

Layouts, magics, schemas, CRC32C Castagnoli, and HKDF labels remain exactly §5.3 / §8. Codec rejects wrong magic/schema/reserved/length/CRC. HOP fresh install = exact **2** lanes (DATA+ACK) + N6AL + N6HW. E2E fresh = exact **1** lane + N6AL + N6HW. FULL_OK then RAM handle only.

### 20.8 TX / RX / CU

- **TX:** per-lane `ram_next`/`ram_limit`; FULL grows `reserved_exclusive` by block **64** only when the window is empty; each `tx_burn` issues exactly one non-reusable counter lease (key16/iv12/counter/context/lane) from the covered range. Fail/TEMP/CU ⇒ lease mutation 0. `tx_lease_release` secure-zeros single-use lease.  
- **RX:** `rx_precheck` mutation 0 + single-use ticket with AEAD materials; durable admit FULL only in `rx_admit_after_aead`; abort/admit zeroize ticket; ALL_PROPOSED CU must update RAM `accept_through` (no redelivery).  
- **CU:** on COMMIT_UNKNOWN keep copy-owned old/proposed plan (op/post/slot/lane/candidate); `recover_cu` NEED_CLOSE_OLD→NEED_OPEN→READ_CLASSIFY re-entrant; MIXED/THIRD fence; ALL_PROPOSED apply post-actions + drop tickets; ALL_OLD accept pre-image. No external classification argument.

### 20.9 Fence / restamp / reclaim / GC

Require typed authority/proof arguments. Without proof ⇒ reject. Retire/shutdown/fence paths zeroize secrets and tickets.

### 20.10 ESP constraints (fail-closed)

| constraint | exact |
| --- | --- |
| namespaces required | **≥3** distinct from Foundation Runtime |
| current ESP port max_namespaces | **2** ⇒ **ESP N6 not ready** |
| durability | multi-key FULL + CU classifier required |
| HIL | power-cut / wear HIL not claimed |

`ninlil_n6_esp_ready()` MUST return false until those are closed. Roadmap must not claim ESP N6 ready.

### 20.11 Host completion bar (Chunk D)

Portable private host candidate + exhaustive host gates (codec KAT/faults, HKDF/nonce KAT, install/TX/RX/fence/storage fault sweep, CU classes, boot permutations, alias/reentry/canary, mutation gates, installed-artifact leakage). **Not** production radio complete.

### 20.12 Frozen erratum — RX/TX lane → array index bounds (2026-07-19; Accepted)

**Status:** Normative Accepted erratum to Chunk D host engine behavior.  
**Wire / layout / schema / public ABI / version:** **unchanged** (no NRW1 frame, N6 durable record layout, codec magic/schema, or public Runtime ABI delta).

#### Problem

`n6_lane_idx(lane_kind)` may return **`-1`** for non-catalog `lane_kind`. Call paths that trusted a prior `lane_ok` (or an internal ticket field) and then indexed per-lane RAM arrays (`rx_boot_floor` / `rx_ram_highest` / `rx_bitmap` / `tx_ram_next` / `tx_ram_limit` / related) without an explicit range check were fail-open under:

1. compiler-conservativeness (`-Warray-bounds` / GCC 13 `-O2` cannot always prove `lane_ok ⇒ idx ∈ range`); and  
2. **internal immutable ticket** corruption / future branch mistakes on `ninlil_n6_rx_admit_after_aead`, where the internal token is otherwise treated as authority.

#### Normative rules (exact)

1. **Named private lane-array dimension.** Production source **MUST** define a single private named count (`N6_PRIVATE_NAMED_LANE_COUNT`) for per-lane slot arrays. `rx_boot_floor`, `rx_ram_highest`, `rx_bitmap`, `rx_live_reserved`, `tx_ram_next`, and `tx_ram_limit` **MUST** use that count. Compile-time `_Static_assert` **MUST** prove each array’s element count equals the named count. **Magic bare `3` at those array sites is forbidden.**

2. **Lane → array index range at every boundary.** After every `n6_lane_idx` (or equivalent) conversion, and **before** any per-lane array load/store, code **MUST** range-check the index. Out-of-range **MUST NOT** touch the arrays.

3. **`n6_rx_precheck_window`.** The helper **MUST** reject out-of-range `idx` before reading `rx_boot_floor` / `rx_ram_highest` / `rx_bitmap`.

4. **External / public `rx_precheck`.** After lane catalog/layer checks and `n6_lane_idx`, an explicit range check is **required**. Invalid external lane (including out-of-catalog and cross-layer mismatch already rejected by `lane_ok_for_slot`) **MUST** return **`INVALID_ARGUMENT`**, leave the returned ticket **all-zero**, allocate **no** internal ticket, perform **zero** storage I/O on **all 12 storage operations / 12 counters** (open/close/begin/get/put/**erase**/commit/rollback/iter_open/iter_next/iter_close/capacity — host tests prove every provider counter delta 0), and leave durable snapshot and RAM replay window/bitmap **unmutated**. With all storage call deltas 0, durable mutation is impossible on that path.

5. **`rx_admit_after_aead` (internal authority).**  
   - Immediately after snapshotting the internal token, convert `lane_kind` and range-check.  
   - **Range-invalid internal lane** ⇒ **`CORRUPT`**, enter **fenced** when the existing corrupt path requires fence, **consume/wipe** internal live ticket + caller ticket + local copy, **no** array access, **no** storage I/O, **no** window/bitmap mutation.  
   - After slot acquisition (canary/live/handle checks), re-validate internal `lane_kind` against the slot layer with **`n6_lane_ok_for_slot` (or equivalent)**. Catalog-valid but **cross-layer** internal tokens **MUST** fail the same way: **`CORRUPT` + full ticket wipe + fence + storage I/O 0 + window/bitmap mutation 0**.

6. **`tx_burn`.** After `n6_lane_idx` and **before** any `tx_ram_*` array access, a range guard is **required**. Invalid external lane (out-of-catalog 0/4/255 or catalog-valid cross-layer) **MUST** return **`INVALID_ARGUMENT`**, leave the returned lease **all-zero**, publish **no** lease, perform **zero** storage I/O on **all 12 storage operations / 12 counters** (open/close/begin/get/put/**erase**/commit/rollback/iter_open/iter_next/iter_close/capacity), and leave all per-lane `tx_ram_next` / `tx_ram_limit` arrays **unmutated**.

7. **Full CU plan envelope + array-post integrity (recover path).** Wire / layout / schema / public ABI / version remain **unchanged**. On `recover_cu`, **before any** storage classify I/O (`open` / `begin` / `get` / iterator / capacity used for classify) and **before any** per-lane array post:

   **7a. Plan envelope preflight (all entries).** Production **MUST** reject the live plan unless:
   - `cu.live == 1` and `1 ≤ n_keys ≤ NINLIL_N6_CU_PLAN_MAX_KEYS`;
   - `phase` is a valid live recovery domain (`NEED_CLOSE_OLD` / `NEED_OPEN` / `READ_CLASSIFY`, including the `NONE→NEED_CLOSE_OLD` remap domain);
   - `pending_install` and each entry’s `old_present` are boolean `{0,1}`;
   - each entry `op ∈ {PUT, DELETE}` and `post ∈ {NONE, INSTALL_HANDLE, TX_LIMIT, RX_ACCEPT}` (closed domain — unknown/flip **MUST** fail);
   - each entry `klen ≤ 48`, `old_vlen ≤ 68`, `prop_vlen ≤ 68` (oversize / `SIZE_MAX` **MUST** fail).

   **7b. Array-post integrity (every `TX_LIMIT` / `RX_ACCEPT` entry, all-or-nothing).** Production **MUST** validate **every** such entry **before applying any** post (one failure ⇒ zero posts):
   - `TX_LIMIT` only on `slot.alloc_side == OUTBOUND_TX`; `RX_ACCEPT` only on `INBOUND_RX`;
   - `slot_index` in range; slot live + canary OK; `expected = n6_lane_idx(lane_kind)` in range; `lane_idx == expected`; `n6_lane_ok_for_slot(slot, lane_kind)`;
   - re-encode the canonical lane key from slot+lane: `klen == NINLIL_N6_LANE_KEY_BYTES (48)` and key bytes exact-match the plan key;
   - `op == PUT`, `old_present == 1`, `old_vlen == prop_vlen == 68`;
   - decode `old`/`prop` with the matching TX or RX codec (CRC-valid); both values **MUST** match slot identity (`key_generation`, binding prefix16, `membership_epoch`, `ns_fingerprint12`, `alloc_side`);
   - **TX:** `old.reserved_exclusive == post_u64_b`, `prop.reserved_exclusive == post_u64_a`, and `post_u64_b < post_u64_a`;
   - **RX:** `prop.accept_reserved_through == post_u64_a`, `post_u64_b == 0`, and `old.accept_reserved_through ≤ prop.accept_reserved_through`.

   **7c. Failure contract.** Any 7a/7b mismatch **MUST** force-close storage **once** (if open), enter **FENCED** (wipe CU / tickets / leases / secrets), return **`CORRUPT`**, perform **zero** provider classify I/O relative to the preflight point, and **MUST NOT** apply any array post (including earlier entries). Bare `lane_idx < 3` magic checks are forbidden. Happy-path TX/RX CU `ALL_PROPOSED` posts remain required when 7a/7b pass.

8. **Test-only fault seams.** Seams that inject arbitrary internal `lane_kind` values or mutate individual CU plan fields exist **only** under `NINLIL_N6_TEST_BUILD` and **MUST NOT** appear in tests-OFF production objects, install trees, or archives. Production public/private headers **SHOULD** remain free of new seam declarations when tests can use test-build-only `extern` linkage.

9. **Non-claims.** This erratum does **not** claim R6 product complete, R7 AEAD codec complete, M4/M5, ESP N6 capacity, RF/USB HIL, Japan legal, or production radio. gate PASS ≠ product GO.
